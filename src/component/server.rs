//! Component server: wraps the in-process [`JobRegistry`] behind the v1
//! stdio protocol.
//!
//! The binary entry point (`bitty-execution` with no arguments) calls
//! [`serve_stdio`]. Tests call [`serve`] with explicit streams. The server is
//! deliberately a thin policy-free adapter: Core owns installation, digest
//! verification, capability grants, consent, safe-mode denial, and crash
//! accounting; this process accepts only what the wire schema permits
//! (`Spawn` carries argv exactly once) and delegates every job decision to
//! the already-verified supervisor.
//!
//! # Threading and ordering
//!
//! - The main thread reads requests and never waits for a child.
//! - One monitor thread polls the supervisor's bounded delivery log and
//!   writes `Started`, `Canceled`, and `Exit` frames.
//! - Output callbacks run on the supervisor's drain threads and write
//!   `Output` frames synchronously. A host that stops reading therefore
//!   applies pipe backpressure to the child instead of growing an unbounded
//!   queue.
//! - Every frame for a job is ordered after its `Spawned` reply: the output
//!   gate blocks a drain until the server has written the reply, and the
//!   writer rejects output after that job's `Exit`. `Started` is advisory
//!   and may arrive before or after the first output frame.
//!
//! # Shutdown
//!
//! `Shutdown` (or stdin EOF) immediately terminates every live job through
//! the typed cancel path, waits a bounded [`SHUTDOWN_WAIT`] for the
//! supervisor to observe the kills, writes `ShutdownAck` for an explicit
//! `Shutdown`, and exits. A component that crashes cannot be cleaned up from
//! inside; the Core host client must place it in its own process group/session
//! and kill that group on loss (documented remaining host work).

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use bitty_ipc::IpcError;
use bitty_ipc::execution::EnvPolicy;

use super::descriptor::COMPONENT_NAME;
use super::protocol::{
    CONNECTION_ID, ErrorKind, ExitKind, FrameReader, MAX_CLOSED_JOB_RECORDS, MAX_JOBS,
    MAX_OUTPUT_CHUNK_BYTES, MAX_OUTPUT_READ_BYTES, Message, Stream, TerminateMode,
    TerminateOutcome, WireCancelEffect, WireDeadlineClock, WireEnv, WireKillScope, WireOomGap,
    WireOomVerdict, job_error_correlation, negotiate,
};
use crate::delivery::MAX_EVENT_REPLAY;
use crate::model::{JobEvent, JobId, JobIo, JobKind, JobLifetime, JobSpec, JobState, JobTimeouts};
use crate::oom::{OomEvidence, OomEvidenceGap};
use crate::outcome::{
    CancelMode, CancelOutcome, CancelReceipt, CancelRequest, ExecutionGeneration, ExecutionHandle,
    ExecutionOutcome,
};
use crate::output::{MAX_READ_BYTES, OutputObserver, OutputStream, ReadOutput};
use crate::process_tree::KillScope;
use crate::registry::JobRegistry;

/// Version reported in `HelloAck` and by `--version` (the crate version).
pub use super::COMPONENT_VERSION;

/// Clean shutdown (explicit `Shutdown` or stdin EOF).
pub const SERVER_EXIT_OK: u8 = 0;
/// Handshake or protocol violation; the peer is told why first when the
/// stream still permits a write.
pub const SERVER_EXIT_PROTOCOL: u8 = 3;
/// The server could not start its monitor or writer.
pub const SERVER_EXIT_INTERNAL: u8 = 4;

/// Longest the server waits for killed jobs to be observed as terminal.
pub const SHUTDOWN_WAIT: Duration = Duration::from_secs(5);

/// Delivery-log poll interval for the monitor thread.
const EVENT_POLL: Duration = Duration::from_millis(10);

/// Poll interval while waiting for jobs to reach a terminal state.
const TERMINAL_POLL: Duration = Duration::from_millis(5);

/// Bounded join wait for the monitor thread.
const MONITOR_JOIN_WAIT: Duration = Duration::from_secs(2);

const ERR_HANDSHAKE_REQUIRED: &str = "handshake required";
const ERR_PROTOCOL_VERSION: &str = "protocol version unsupported";
const ERR_COMPONENT_MISMATCH: &str = "component name mismatch";
const ERR_UNEXPECTED_MESSAGE: &str = "unexpected message";
const ERR_FRAME_TOO_LARGE: &str = "frame too large";
const ERR_INVALID_FRAME: &str = "invalid protocol frame";
const ERR_SPAWN_REJECTED: &str = "spawn spec rejected";
const ERR_ENVIRONMENT: &str = "invalid environment";
const ERR_JOB_CAPACITY: &str = "job capacity reached";
const ERR_UNKNOWN_JOB: &str = "unknown job";
const ERR_REQUEST_REJECTED: &str = "request rejected";
const ERR_UNSUPPORTED: &str = "operation unsupported";
const ERR_PTY_HOST_OWNED: &str = "interactive pty jobs are host-owned";
const ERR_INTERNAL: &str = "internal error";
const ERR_SUPERVISOR: &str = "supervisor unavailable";

/// Serves the protocol on stdin/stdout.
#[must_use]
pub fn serve_stdio() -> u8 {
    serve(io::stdin(), io::stdout())
}

/// Serves the protocol on explicit streams (tests and embedders).
///
/// Returns [`SERVER_EXIT_OK`], [`SERVER_EXIT_PROTOCOL`], or
/// [`SERVER_EXIT_INTERNAL`].
pub fn serve<R, W>(input: R, output: W) -> u8
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    let writer = Arc::new(FrameWriter::new(output));
    let mut reader = FrameReader::new(input);

    let hello = match reader.read_message() {
        Ok(Some(Message::Hello {
            min,
            max,
            component,
            version: _,
        })) => {
            if component != COMPONENT_NAME {
                write_connection_error(&writer, ErrorKind::Protocol, ERR_COMPONENT_MISMATCH);
                return SERVER_EXIT_PROTOCOL;
            }
            match negotiate(min, max) {
                Some(protocol) => protocol,
                None => {
                    write_connection_error(&writer, ErrorKind::Protocol, ERR_PROTOCOL_VERSION);
                    return SERVER_EXIT_PROTOCOL;
                }
            }
        }
        Ok(Some(_)) => {
            write_connection_error(&writer, ErrorKind::Protocol, ERR_HANDSHAKE_REQUIRED);
            return SERVER_EXIT_PROTOCOL;
        }
        Ok(None) => return SERVER_EXIT_OK,
        Err(error) => {
            write_wire_error(&writer, &error, CONNECTION_ID);
            return SERVER_EXIT_PROTOCOL;
        }
    };

    if writer
        .write(&Message::HelloAck {
            protocol: hello,
            component: COMPONENT_NAME.to_owned(),
            version: COMPONENT_VERSION.to_owned(),
        })
        .is_err()
    {
        return SERVER_EXIT_INTERNAL;
    }

    let gates = Arc::new(JobGates::new());
    let active = Arc::new(ActiveJobs::default());
    let monitor_stop = Arc::new(AtomicBool::new(false));
    let observer = Arc::new(ComponentOutputObserver {
        writer: Arc::clone(&writer),
        gates: Arc::clone(&gates),
    });
    let registry = JobRegistry::with_capacity(MAX_JOBS).with_output_observer(observer);

    let monitor = {
        let registry = registry.clone();
        let writer = Arc::clone(&writer);
        let gates = Arc::clone(&gates);
        let active = Arc::clone(&active);
        let monitor_stop = Arc::clone(&monitor_stop);
        thread::Builder::new()
            .name("bitty-execution-monitor".to_owned())
            .spawn(move || {
                monitor_events(&registry, &writer, &gates, &active, &monitor_stop);
            })
    };
    let monitor = match monitor {
        Ok(handle) => handle,
        Err(_) => {
            write_connection_error(&writer, ErrorKind::Internal, ERR_INTERNAL);
            return SERVER_EXIT_INTERNAL;
        }
    };

    let mut shutdown_requested = false;
    let mut exit_code = SERVER_EXIT_OK;
    loop {
        match reader.read_message() {
            Ok(Some(message)) => match message {
                Message::Spawn {
                    job,
                    program,
                    args,
                    cwd,
                    env,
                    kind,
                    io,
                    lifetime,
                    hard_ms,
                    idle_ms,
                    retention_ms,
                } => handle_spawn(
                    &writer,
                    &registry,
                    &gates,
                    &active,
                    job,
                    program,
                    args,
                    cwd,
                    env,
                    kind,
                    io,
                    lifetime,
                    hard_ms,
                    idle_ms,
                    retention_ms,
                ),
                Message::Terminate {
                    job,
                    generation,
                    mode,
                    grace_ms,
                } => handle_terminate(&writer, &registry, &active, job, generation, mode, grace_ms),
                Message::ReadOutput {
                    request,
                    job,
                    stream,
                    tail_lines,
                    max_bytes,
                } => handle_read_output(
                    &writer, &registry, &active, request, job, stream, tail_lines, max_bytes,
                ),
                Message::Shutdown => {
                    shutdown_requested = true;
                    break;
                }
                Message::Hello { .. } => {
                    writer
                        .write(&Message::Error {
                            request: CONNECTION_ID,
                            kind: ErrorKind::Protocol,
                            message: ERR_UNEXPECTED_MESSAGE.to_owned(),
                        })
                        .ok();
                    exit_code = SERVER_EXIT_PROTOCOL;
                    break;
                }
                _ => {
                    writer
                        .write(&Message::Error {
                            request: CONNECTION_ID,
                            kind: ErrorKind::Protocol,
                            message: ERR_UNEXPECTED_MESSAGE.to_owned(),
                        })
                        .ok();
                    exit_code = SERVER_EXIT_PROTOCOL;
                    break;
                }
            },
            Ok(None) => break,
            Err(error) => {
                write_wire_error(&writer, &error, CONNECTION_ID);
                exit_code = SERVER_EXIT_PROTOCOL;
                break;
            }
        }
    }

    // Both the explicit Shutdown and a dropped host terminate every live job;
    // only the explicit path can still answer.
    cancel_all(&registry);
    wait_until_idle(&registry, &active, SHUTDOWN_WAIT);
    if shutdown_requested && exit_code == SERVER_EXIT_OK {
        let _ = writer.write(&Message::ShutdownAck);
    }

    monitor_stop.store(true, Ordering::SeqCst);
    gates.stop();
    join_bounded(monitor, MONITOR_JOIN_WAIT);
    exit_code
}

// ── request handlers ────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn handle_spawn<W: Write>(
    writer: &FrameWriter<W>,
    registry: &JobRegistry,
    gates: &JobGates,
    active: &ActiveJobs,
    job: u64,
    program: String,
    args: Vec<String>,
    cwd: Option<String>,
    env: WireEnv,
    kind: super::protocol::SpawnKind,
    io: super::protocol::SpawnIo,
    lifetime: super::protocol::SpawnLifetime,
    hard_ms: u32,
    idle_ms: u32,
    retention_ms: u32,
) {
    active.prune_gone(registry);
    if active.contains(job) {
        write_request_error(
            writer,
            job_error_correlation(job),
            ErrorKind::InvalidRequest,
            ERR_REQUEST_REJECTED,
        );
        return;
    }
    let spec = match build_spec(
        program,
        args,
        cwd,
        env,
        kind,
        io,
        lifetime,
        hard_ms,
        idle_ms,
        retention_ms,
    ) {
        Ok(spec) => spec,
        Err((kind, message)) => {
            write_request_error(writer, job_error_correlation(job), kind, message);
            return;
        }
    };
    let record = match registry.spawn_with_hooks(
        spec,
        |record| gates.insert(record.get(), job),
        |record| gates.remove(record.get()),
    ) {
        Ok(record) => record,
        Err(error) => {
            let (kind, message) = spawn_error(&error);
            write_request_error(writer, job_error_correlation(job), kind, message);
            return;
        }
    };
    let generation = match registry.get(record) {
        Ok(snapshot) => snapshot.generation,
        Err(_) => {
            let _ = registry.cancel(record);
            gates.remove(record.get());
            write_request_error(
                writer,
                job_error_correlation(job),
                ErrorKind::Internal,
                ERR_INTERNAL,
            );
            return;
        }
    };

    // Gate output/exit frames until the reply carrying the generation is on
    // the wire. The drain threads block here, never the main reader.
    // Insert the mapping before releasing the drain gate: the monitor can
    // otherwise observe a fast job's `Exit` before the mapping exists and
    // never mark it exited.
    active.insert(
        job,
        ActiveJob {
            record,
            exited: false,
        },
    );
    // A failed reply leaves the writer failed; the main loop ends when the
    // host closes stdin or the next read/write fails. The gate is released
    // either way so drain threads cannot stay blocked.
    let _ = writer.write(&Message::Spawned {
        job,
        generation: generation.get(),
    });
    gates.publish(record.get());
}

#[allow(clippy::too_many_arguments)]
fn handle_terminate<W: Write>(
    writer: &FrameWriter<W>,
    registry: &JobRegistry,
    active: &ActiveJobs,
    job: u64,
    generation: u64,
    mode: TerminateMode,
    grace_ms: u32,
) {
    let Some(entry) = active.get(job) else {
        write_request_error(
            writer,
            job_error_correlation(job),
            ErrorKind::UnknownJob,
            ERR_UNKNOWN_JOB,
        );
        return;
    };
    let Some(generation) = ExecutionGeneration::from_raw(generation) else {
        write_request_error(
            writer,
            job_error_correlation(job),
            ErrorKind::InvalidRequest,
            ERR_REQUEST_REJECTED,
        );
        return;
    };
    let handle = ExecutionHandle {
        id: entry.record,
        generation,
    };
    let request = match CancelRequest::new(
        handle,
        cancel_mode(mode),
        Duration::from_millis(u64::from(grace_ms)),
    ) {
        Ok(request) => request,
        Err(error) => {
            let (kind, message) = request_error(&error);
            write_request_error(writer, job_error_correlation(job), kind, message);
            return;
        }
    };
    match registry.cancel_typed(request) {
        Ok(CancelReceipt::Accepted) => {}
        Ok(CancelReceipt::Resolved(outcome)) => {
            let _ = writer.write(&Message::Canceled {
                job,
                outcome: terminate_outcome(outcome),
            });
        }
        Err(error) => {
            let (kind, message) = request_error(&error);
            write_request_error(writer, job_error_correlation(job), kind, message);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_read_output<W: Write>(
    writer: &FrameWriter<W>,
    registry: &JobRegistry,
    active: &ActiveJobs,
    request: u64,
    job: u64,
    stream: Stream,
    tail_lines: u32,
    max_bytes: u32,
) {
    let Some(entry) = active.get(job) else {
        write_request_error(writer, request, ErrorKind::UnknownJob, ERR_UNKNOWN_JOB);
        return;
    };
    let mut read = ReadOutput::new(output_stream(stream));
    if tail_lines > 0 {
        read = read.with_tail_lines(tail_lines as usize);
    }
    let cap = if max_bytes == 0 {
        MAX_OUTPUT_READ_BYTES
    } else {
        (max_bytes as usize).min(MAX_OUTPUT_READ_BYTES)
    };
    read = read.with_max_bytes(cap.min(MAX_READ_BYTES));
    match registry.read_output(entry.record, read) {
        Ok(view) => {
            let lines = u32::try_from(view.lines_returned).unwrap_or(u32::MAX);
            let _ = writer.write(&Message::OutputView {
                request,
                job,
                stream,
                data: view.text.into_bytes(),
                total: view.total_bytes,
                dropped: view.dropped_bytes,
                truncated: view.truncated,
                lines,
            });
        }
        Err(error) => {
            let (kind, message) = request_error(&error);
            write_request_error(writer, request, kind, message);
        }
    }
}

// ── spec mapping ────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn build_spec(
    program: String,
    args: Vec<String>,
    cwd: Option<String>,
    env: WireEnv,
    kind: super::protocol::SpawnKind,
    io: super::protocol::SpawnIo,
    lifetime: super::protocol::SpawnLifetime,
    hard_ms: u32,
    idle_ms: u32,
    retention_ms: u32,
) -> Result<JobSpec, (ErrorKind, &'static str)> {
    // Interactive PTY ownership stays with the terminal primitive (the
    // component protocol carries no stdin channel); refuse instead of
    // inheriting the component's session environment.
    if io == super::protocol::SpawnIo::Pty || kind == super::protocol::SpawnKind::Interactive {
        return Err((ErrorKind::Unsupported, ERR_PTY_HOST_OWNED));
    }
    let env = match env {
        WireEnv::Isolated => EnvPolicy::Isolated,
        WireEnv::Explicit(vars) => {
            let pairs = vars
                .into_iter()
                .map(|var| (var.name, var.value))
                .collect::<Vec<_>>();
            EnvPolicy::explicit(pairs).map_err(|error| env_error(&error))?
        }
    };
    let mut timeouts = JobTimeouts::default();
    if hard_ms > 0 {
        timeouts.hard = Some(Duration::from_millis(u64::from(hard_ms)));
    }
    if idle_ms > 0 {
        timeouts.idle = Some(Duration::from_millis(u64::from(idle_ms)));
    }
    if retention_ms > 0 {
        timeouts.retention = Some(Duration::from_millis(u64::from(retention_ms)));
    }
    let spec = JobSpec::new(program, args)
        .with_cwd(cwd)
        .with_env(env)
        .with_kind(job_kind(kind))
        .with_io(job_io(io))
        .with_lifetime(job_lifetime(lifetime))
        .with_timeouts(timeouts);
    spec.validate()
        .map_err(|_| (ErrorKind::InvalidRequest, ERR_SPAWN_REJECTED))?;
    Ok(spec)
}

fn env_error(error: &IpcError) -> (ErrorKind, &'static str) {
    match error {
        IpcError::LimitExceeded { .. } | IpcError::InvalidRequest { .. } => {
            (ErrorKind::InvalidRequest, ERR_ENVIRONMENT)
        }
        _ => (ErrorKind::Internal, ERR_INTERNAL),
    }
}

fn spawn_error(error: &crate::model::JobError) -> (ErrorKind, &'static str) {
    use crate::model::JobError;
    match error {
        JobError::InvalidSpec { .. } => (ErrorKind::InvalidRequest, ERR_SPAWN_REJECTED),
        JobError::RegistryFull { .. } => (ErrorKind::Budget, ERR_JOB_CAPACITY),
        JobError::Unavailable { .. } => (ErrorKind::Internal, ERR_SUPERVISOR),
        JobError::UnknownJob(_) => (ErrorKind::UnknownJob, ERR_UNKNOWN_JOB),
        JobError::Denied { .. } => (ErrorKind::Denied, ERR_REQUEST_REJECTED),
        _ => (ErrorKind::Internal, ERR_INTERNAL),
    }
}

fn request_error(error: &crate::model::JobError) -> (ErrorKind, &'static str) {
    use crate::model::JobError;
    match error {
        JobError::UnknownJob(_) => (ErrorKind::UnknownJob, ERR_UNKNOWN_JOB),
        JobError::InvalidSpec { .. }
        | JobError::InvalidRead { .. }
        | JobError::InvalidCancel { .. }
        | JobError::InvalidCursor { .. }
        | JobError::InvalidPrincipal { .. }
        | JobError::InvalidWrite { .. } => (ErrorKind::InvalidRequest, ERR_REQUEST_REJECTED),
        JobError::RegistryFull { .. }
        | JobError::GrantsFull { .. }
        | JobError::RateLimited { .. }
        | JobError::SignalRateLimited { .. } => (ErrorKind::Budget, ERR_JOB_CAPACITY),
        JobError::Unsupported { .. } => (ErrorKind::Unsupported, ERR_UNSUPPORTED),
        JobError::Denied { .. }
        | JobError::SecureInputDenied { .. }
        | JobError::CommandRiskDenied { .. }
        | JobError::CommandRiskNeedsConsent { .. } => (ErrorKind::Denied, ERR_REQUEST_REJECTED),
        JobError::Unavailable { .. } | JobError::UnknownEvent { .. } => {
            (ErrorKind::Internal, ERR_INTERNAL)
        }
    }
}

fn cancel_mode(mode: TerminateMode) -> CancelMode {
    match mode {
        TerminateMode::Graceful => CancelMode::Graceful,
        TerminateMode::Immediate => CancelMode::Immediate,
        TerminateMode::GracefulThenKill => CancelMode::GracefulThenKill,
    }
}

fn job_kind(kind: super::protocol::SpawnKind) -> JobKind {
    match kind {
        super::protocol::SpawnKind::Command => JobKind::Command,
        super::protocol::SpawnKind::Interactive => JobKind::Interactive,
        super::protocol::SpawnKind::Service => JobKind::Service,
        super::protocol::SpawnKind::Watch => JobKind::Watch,
    }
}

fn job_io(io: super::protocol::SpawnIo) -> JobIo {
    match io {
        super::protocol::SpawnIo::Pipes => JobIo::Pipes,
        super::protocol::SpawnIo::Pty => JobIo::Pty,
    }
}

fn job_lifetime(lifetime: super::protocol::SpawnLifetime) -> JobLifetime {
    match lifetime {
        super::protocol::SpawnLifetime::Agent => JobLifetime::Agent,
        super::protocol::SpawnLifetime::Task => JobLifetime::Task,
        super::protocol::SpawnLifetime::Workspace => JobLifetime::Workspace,
        super::protocol::SpawnLifetime::Detached => JobLifetime::Detached,
    }
}

fn output_stream(stream: Stream) -> OutputStream {
    match stream {
        Stream::Stdout => OutputStream::Stdout,
        Stream::Stderr => OutputStream::Stderr,
    }
}

fn wire_stream(stream: OutputStream) -> Stream {
    match stream {
        OutputStream::Stdout => Stream::Stdout,
        OutputStream::Stderr => Stream::Stderr,
    }
}

fn terminate_outcome(outcome: CancelOutcome) -> TerminateOutcome {
    match outcome {
        CancelOutcome::CancelledBeforeStart => TerminateOutcome::CancelledBeforeStart,
        CancelOutcome::CancelledGracefully => TerminateOutcome::CancelledGracefully,
        CancelOutcome::Killed => TerminateOutcome::Killed,
        CancelOutcome::AlreadyExited => TerminateOutcome::AlreadyExited,
        CancelOutcome::PermissionDenied => TerminateOutcome::PermissionDenied,
        CancelOutcome::StaleGeneration => TerminateOutcome::StaleGeneration,
        CancelOutcome::StillRunning => TerminateOutcome::StillRunning,
        CancelOutcome::Unsupported => TerminateOutcome::Unsupported,
        CancelOutcome::Unknown => TerminateOutcome::Unknown,
    }
}

// ── monitor ─────────────────────────────────────────────────────────────────

fn monitor_events<W: Write>(
    registry: &JobRegistry,
    writer: &FrameWriter<W>,
    gates: &JobGates,
    active: &ActiveJobs,
    stop: &AtomicBool,
) {
    let mut cursor = 0u64;
    while !stop.load(Ordering::SeqCst) {
        let replay = registry.events_since(cursor, MAX_EVENT_REPLAY);
        match replay {
            Ok(replay) => {
                for stored in &replay.events {
                    let event = stored.event();
                    match event {
                        JobEvent::Queued { .. } => {}
                        JobEvent::Started { id, .. } => {
                            if let Some(wire) = gates.resolve(id.get()) {
                                if writer.write(&Message::Started { job: wire }).is_err() {
                                    return;
                                }
                            }
                        }
                        JobEvent::CancelResolved { id, outcome, .. } => {
                            if let Some(wire) = gates.resolve(id.get()) {
                                if writer
                                    .write(&Message::Canceled {
                                        job: wire,
                                        outcome: terminate_outcome(outcome),
                                    })
                                    .is_err()
                                {
                                    return;
                                }
                            }
                        }
                        JobEvent::Stopped { id, .. } => {
                            if let Some(wire) = gates.resolve(id.get()) {
                                let message = exit_message(registry, id, wire);
                                if writer.write_closing(wire, &message).is_err() {
                                    return;
                                }
                                active.mark_exited(wire);
                                gates.remove(id.get());
                            }
                        }
                    }
                }
                cursor = next_cursor(cursor, &replay);
            }
            Err(_) => {
                // A cursor past the head can only follow a logic error; keep
                // the monitor alive and retry from the current head.
                cursor = registry.event_head_seq();
            }
        }
        thread::sleep(EVENT_POLL);
    }
}

fn next_cursor(cursor: u64, replay: &crate::delivery::EventReplay) -> u64 {
    match replay.events.last() {
        Some(last) if last.seq() < replay.next_seq => last.seq().saturating_add(1),
        _ => replay.next_seq.max(cursor),
    }
}

fn exit_message(registry: &JobRegistry, record: JobId, wire: u64) -> Message {
    let snapshot = registry.get(record).ok();
    let state = snapshot.as_ref().map(|snapshot| snapshot.state);
    let (outcome, detail, cancel, clock) = match state {
        Some(JobState::Done(outcome)) => outcome_fields(outcome),
        _ => (
            ExitKind::Unknown,
            0,
            WireCancelEffect::None,
            WireDeadlineClock::None,
        ),
    };
    let (oom, oom_gap) = snapshot
        .as_ref()
        .map_or((WireOomVerdict::Unknown, WireOomGap::None), |snapshot| {
            oom_fields(snapshot.oom_evidence)
        });
    let kill_scope = snapshot
        .as_ref()
        .map_or(WireKillScope::DirectChild, |snapshot| {
            kill_scope(snapshot.kill_scope)
        });
    let index = snapshot.map(|snapshot| snapshot.output).unwrap_or_default();
    Message::Exit {
        job: wire,
        outcome,
        detail,
        cancel,
        clock,
        kill_scope,
        oom,
        oom_gap,
        stdout_total: index.stdout_total_bytes,
        stdout_evicted: index.stdout_dropped_bytes,
        stderr_total: index.stderr_total_bytes,
        stderr_evicted: index.stderr_dropped_bytes,
    }
}

fn outcome_fields(
    outcome: ExecutionOutcome,
) -> (ExitKind, i32, WireCancelEffect, WireDeadlineClock) {
    match outcome {
        ExecutionOutcome::Success => (
            ExitKind::Success,
            0,
            WireCancelEffect::None,
            WireDeadlineClock::None,
        ),
        ExecutionOutcome::ExitCode(code) => (
            ExitKind::ExitCode,
            code,
            WireCancelEffect::None,
            WireDeadlineClock::None,
        ),
        ExecutionOutcome::Signaled(signal) => (
            ExitKind::Signaled,
            signal,
            WireCancelEffect::None,
            WireDeadlineClock::None,
        ),
        ExecutionOutcome::SpawnFailed => (
            ExitKind::SpawnFailed,
            0,
            WireCancelEffect::None,
            WireDeadlineClock::None,
        ),
        ExecutionOutcome::Cancelled(effect) => (
            ExitKind::Cancelled,
            0,
            cancel_effect(effect),
            WireDeadlineClock::None,
        ),
        ExecutionOutcome::TimedOut(clock) => (
            ExitKind::TimedOut,
            0,
            WireCancelEffect::None,
            deadline_clock(clock),
        ),
        ExecutionOutcome::OomKilled => (
            ExitKind::OomKilled,
            0,
            WireCancelEffect::None,
            WireDeadlineClock::None,
        ),
        ExecutionOutcome::SupervisorLost => (
            ExitKind::SupervisorLost,
            0,
            WireCancelEffect::None,
            WireDeadlineClock::None,
        ),
        ExecutionOutcome::Unknown => (
            ExitKind::Unknown,
            0,
            WireCancelEffect::None,
            WireDeadlineClock::None,
        ),
    }
}

fn cancel_effect(effect: crate::outcome::CancelEffect) -> WireCancelEffect {
    match effect {
        crate::outcome::CancelEffect::BeforeStart => WireCancelEffect::BeforeStart,
        crate::outcome::CancelEffect::Graceful => WireCancelEffect::Graceful,
        crate::outcome::CancelEffect::Killed => WireCancelEffect::Killed,
    }
}

fn deadline_clock(clock: crate::outcome::DeadlineClock) -> WireDeadlineClock {
    match clock {
        crate::outcome::DeadlineClock::Hard => WireDeadlineClock::Hard,
        crate::outcome::DeadlineClock::Idle => WireDeadlineClock::Idle,
    }
}

fn kill_scope(scope: KillScope) -> WireKillScope {
    match scope {
        KillScope::DirectChild => WireKillScope::DirectChild,
        KillScope::OwnedTree => WireKillScope::OwnedTree,
    }
}

fn oom_fields(evidence: OomEvidence) -> (WireOomVerdict, WireOomGap) {
    match evidence {
        OomEvidence::OomKilled => (WireOomVerdict::OomKilled, WireOomGap::None),
        OomEvidence::NotOom => (WireOomVerdict::NotOom, WireOomGap::None),
        OomEvidence::Missing(gap) => (WireOomVerdict::Unknown, oom_gap(gap)),
        OomEvidence::Pending | OomEvidence::Tracked => (WireOomVerdict::Unknown, WireOomGap::None),
    }
}

fn oom_gap(gap: OomEvidenceGap) -> WireOomGap {
    match gap {
        OomEvidenceGap::NotConfigured => WireOomGap::NotConfigured,
        OomEvidenceGap::Undelegated => WireOomGap::Undelegated,
        OomEvidenceGap::UnsupportedPlatform => WireOomGap::UnsupportedPlatform,
        OomEvidenceGap::LeafLimit => WireOomGap::LeafLimit,
        OomEvidenceGap::LeafCreateFailed => WireOomGap::LeafCreateFailed,
        OomEvidenceGap::PlacementFailed => WireOomGap::PlacementFailed,
        OomEvidenceGap::CounterUnreadable => WireOomGap::CounterUnreadable,
        OomEvidenceGap::NotStarted => WireOomGap::NotStarted,
    }
}

// ── cleanup ─────────────────────────────────────────────────────────────────

fn cancel_all(registry: &JobRegistry) {
    for snapshot in registry.list() {
        if snapshot.state.is_terminal() {
            continue;
        }
        let _ = registry.cancel_typed(CancelRequest::immediate(snapshot.handle()));
    }
}

fn wait_until_idle(registry: &JobRegistry, active: &ActiveJobs, bound: Duration) {
    let deadline = Instant::now() + bound;
    loop {
        let terminal = registry
            .list()
            .iter()
            .all(|snapshot| snapshot.state.is_terminal());
        if terminal && !active.has_live() {
            return;
        }
        if Instant::now() >= deadline {
            return;
        }
        thread::sleep(TERMINAL_POLL);
    }
}

fn join_bounded(handle: thread::JoinHandle<()>, bound: Duration) {
    let deadline = Instant::now() + bound;
    while !handle.is_finished() {
        if Instant::now() >= deadline {
            return;
        }
        thread::sleep(TERMINAL_POLL);
    }
    let _ = handle.join();
}

// ── shared state ────────────────────────────────────────────────────────────

/// One tracked job, keyed by the host-assigned wire id.
#[derive(Debug, Clone, Copy)]
struct ActiveJob {
    record: JobId,
    /// Set once the terminal `Exit` frame was written. The mapping stays so
    /// the host can still read retained output and receive typed
    /// `AlreadyExited`/`StaleGeneration` answers; the supervisor's own
    /// retention decides when the record becomes unknown.
    exited: bool,
}

#[derive(Default)]
struct ActiveJobs {
    inner: Mutex<BTreeMap<u64, ActiveJob>>,
}

impl ActiveJobs {
    fn contains(&self, wire: u64) -> bool {
        lock(&self.inner).contains_key(&wire)
    }

    fn insert(&self, wire: u64, job: ActiveJob) {
        lock(&self.inner).insert(wire, job);
    }

    fn get(&self, wire: u64) -> Option<ActiveJob> {
        lock(&self.inner).get(&wire).copied()
    }

    fn mark_exited(&self, wire: u64) {
        if let Some(job) = lock(&self.inner).get_mut(&wire) {
            job.exited = true;
        }
    }

    /// Drops mappings whose supervisor record no longer exists (retention
    /// eviction), bounding the table across a long-lived component.
    fn prune_gone(&self, registry: &JobRegistry) {
        lock(&self.inner).retain(|_, job| registry.get(job.record).is_ok());
    }

    fn has_live(&self) -> bool {
        lock(&self.inner).values().any(|job| !job.exited)
    }
}

/// Publication gate keyed by the supervisor's job id.
struct JobGates {
    state: Mutex<GateState>,
    wake: Condvar,
}

#[derive(Default)]
struct GateState {
    jobs: BTreeMap<u64, Gate>,
    removed: BTreeSet<u64>,
    removed_order: VecDeque<u64>,
    waiting: usize,
    stopping: bool,
}

#[derive(Clone, Copy)]
struct Gate {
    wire: u64,
    published: bool,
}

impl JobGates {
    fn new() -> Self {
        Self {
            state: Mutex::new(GateState::default()),
            wake: Condvar::new(),
        }
    }

    fn insert(&self, record: u64, wire: u64) {
        let mut state = lock(&self.state);
        state.removed.remove(&record);
        state.removed_order.retain(|removed| *removed != record);
        state.jobs.insert(
            record,
            Gate {
                wire,
                published: false,
            },
        );
    }

    fn publish(&self, record: u64) {
        let mut state = lock(&self.state);
        if let Some(gate) = state.jobs.get_mut(&record) {
            gate.published = true;
        }
        self.wake.notify_all();
    }

    fn resolve(&self, record: u64) -> Option<u64> {
        let mut state = lock(&self.state);
        loop {
            if state.stopping || state.removed.contains(&record) {
                return None;
            }
            if let Some(gate) = state.jobs.get(&record) {
                if gate.published {
                    return Some(gate.wire);
                }
            }
            state.waiting += 1;
            self.wake.notify_all();
            state = self
                .wake
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
            state.waiting -= 1;
        }
    }

    fn remove(&self, record: u64) {
        let mut state = lock(&self.state);
        state.jobs.remove(&record);
        if state.removed.insert(record) {
            state.removed_order.push_back(record);
        }
        while state.removed_order.len() > MAX_CLOSED_JOB_RECORDS {
            if let Some(expired) = state.removed_order.pop_front() {
                state.removed.remove(&expired);
            }
        }
        self.wake.notify_all();
    }

    fn stop(&self) {
        lock(&self.state).stopping = true;
        self.wake.notify_all();
    }
}

/// Output drain callback: maps the supervisor job id to the wire id and
/// writes one or more `Output` frames.
struct ComponentOutputObserver<W> {
    writer: Arc<FrameWriter<W>>,
    gates: Arc<JobGates>,
}

impl<W: Write + Send + 'static> OutputObserver for ComponentOutputObserver<W> {
    fn on_output(&self, job: JobId, stream: OutputStream, bytes: &[u8]) {
        let Some(wire) = self.gates.resolve(job.get()) else {
            return;
        };
        for chunk in bytes.chunks(MAX_OUTPUT_CHUNK_BYTES) {
            if self
                .writer
                .write_output(wire, wire_stream(stream), chunk)
                .is_err()
            {
                return;
            }
        }
    }
}

// ── writer ──────────────────────────────────────────────────────────────────

/// Serialized, bounded frame writer.
///
/// Every frame is fully encoded before the lock and written with one
/// `write_all` plus flush. Output is rejected once a job's `Exit` frame has
/// been written, so a drain that outlives the bounded join cannot place
/// bytes after the terminal frame.
struct FrameWriter<W> {
    state: Mutex<WriterState<W>>,
}

struct WriterState<W> {
    writer: W,
    failed: bool,
    closed: BTreeSet<u64>,
    order: VecDeque<u64>,
}

impl<W: Write> FrameWriter<W> {
    fn new(writer: W) -> Self {
        Self {
            state: Mutex::new(WriterState {
                writer,
                failed: false,
                closed: BTreeSet::new(),
                order: VecDeque::new(),
            }),
        }
    }

    fn write(&self, message: &Message) -> io::Result<()> {
        let frame = encode(message)?;
        self.write_raw(&frame)
    }

    fn write_output(&self, job: u64, stream: Stream, data: &[u8]) -> io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        if data.len() > MAX_OUTPUT_CHUNK_BYTES {
            // Callers split; a single oversize chunk is a bug, not a peer
            // error.
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "output chunk exceeds the frame bound",
            ));
        }
        let mut state = lock(&self.state);
        if state.failed || state.closed.contains(&job) {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "job closed"));
        }
        let frame = encode(&Message::Output {
            job,
            stream,
            data: data.to_vec(),
        })?;
        write_all(&mut state.writer, &frame)
    }

    fn write_closing(&self, job: u64, message: &Message) -> io::Result<()> {
        let frame = encode(message)?;
        let mut state = lock(&self.state);
        mark_closed(&mut state, job);
        write_all(&mut state.writer, &frame)
    }

    fn write_raw(&self, frame: &[u8]) -> io::Result<()> {
        let mut state = lock(&self.state);
        if state.failed {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "writer failed"));
        }
        write_all(&mut state.writer, frame)
    }
}

fn write_all<W: Write>(writer: &mut W, frame: &[u8]) -> io::Result<()> {
    writer.write_all(frame)?;
    writer.flush()
}

fn encode(message: &Message) -> io::Result<Vec<u8>> {
    super::protocol::encode_frame(message)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))
}

fn mark_closed<W>(state: &mut WriterState<W>, job: u64) {
    if !state.closed.insert(job) {
        return;
    }
    state.order.push_back(job);
    while state.order.len() > MAX_CLOSED_JOB_RECORDS {
        if let Some(oldest) = state.order.pop_front() {
            state.closed.remove(&oldest);
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

// ── diagnostics ─────────────────────────────────────────────────────────────

fn write_request_error<W: Write>(
    writer: &FrameWriter<W>,
    request: u64,
    kind: ErrorKind,
    message: &'static str,
) {
    let _ = writer.write(&Message::Error {
        request,
        kind,
        message: message.to_owned(),
    });
}

fn write_connection_error<W: Write>(
    writer: &FrameWriter<W>,
    kind: ErrorKind,
    message: &'static str,
) {
    write_request_error(writer, CONNECTION_ID, kind, message);
}

fn write_wire_error<W: Write>(
    writer: &FrameWriter<W>,
    error: &super::protocol::WireError,
    request: u64,
) {
    use super::protocol::WireError;
    let message = match error {
        WireError::TooLarge { .. } => ERR_FRAME_TOO_LARGE,
        WireError::EmptyFrame
        | WireError::Truncated
        | WireError::TrailingBytes
        | WireError::UnknownTag(_)
        | WireError::InvalidUtf8
        | WireError::InvalidField(_) => ERR_INVALID_FRAME,
        WireError::Io(_) => return,
    };
    write_request_error(writer, request, ErrorKind::Protocol, message);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_is_accepted_before_the_job_closes() {
        let writer = FrameWriter::new(Vec::new());
        writer
            .write_output(1, Stream::Stdout, b"before")
            .expect("output before close");
    }

    #[test]
    fn output_after_the_terminal_frame_is_rejected() {
        let writer = FrameWriter::new(Vec::new());
        writer
            .write_closing(1, &Message::Started { job: 1 })
            .expect("closing frame");
        assert!(
            writer.write_output(1, Stream::Stdout, b"late").is_err(),
            "output after Exit must be dropped"
        );
        // Another job is unaffected by the first job's close marker.
        writer
            .write_output(2, Stream::Stdout, b"other")
            .expect("other job output");
    }

    #[test]
    fn closed_job_records_stay_bounded() {
        let writer = FrameWriter::new(Vec::new());
        for job in 0..(MAX_CLOSED_JOB_RECORDS as u64 + 8) {
            writer
                .write_closing(job, &Message::Started { job })
                .expect("closing frame");
        }
        let state = lock(&writer.state);
        assert_eq!(state.closed.len(), MAX_CLOSED_JOB_RECORDS);
        assert_eq!(state.order.len(), MAX_CLOSED_JOB_RECORDS);
        assert!(!state.closed.contains(&0), "oldest marker was evicted");
        assert!(state.closed.contains(&(MAX_CLOSED_JOB_RECORDS as u64 + 7)));
    }

    #[test]
    fn supervisor_cannot_start_before_its_gate_is_registered() {
        let gates = JobGates::new();
        let registry = JobRegistry::new();
        let spec = JobSpec::new("/bin/true", Vec::new());
        let event_head_before_hook = std::sync::atomic::AtomicU64::new(u64::MAX);
        let job = registry
            .spawn_with_hooks_and_launcher(
                spec,
                |record| {
                    event_head_before_hook.store(registry.event_head_seq(), Ordering::SeqCst);
                    gates.insert(record.get(), 17);
                },
                |record| gates.remove(record.get()),
                |_, supervisor| {
                    supervisor();
                    Ok(())
                },
            )
            .expect("spawn succeeds");
        assert_eq!(event_head_before_hook.load(Ordering::SeqCst), 0);
        gates.publish(job.get());
        assert_eq!(gates.resolve(job.get()), Some(17));
        let _ = registry.cancel(job);
    }

    #[test]
    fn gate_resolution_waits_until_spawned_is_published() {
        let gates = Arc::new(JobGates::new());
        let waiting = Arc::clone(&gates);
        let resolver = thread::spawn(move || waiting.resolve(7));
        gates.insert(7, 17);
        let mut state = lock(&gates.state);
        while state.waiting == 0 {
            state = gates
                .wake
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
        drop(state);
        gates.publish(7);
        assert_eq!(resolver.join().expect("resolver joins"), Some(17));
    }

    #[test]
    fn removing_a_gate_wakes_waiters_without_publishing() {
        let gates = Arc::new(JobGates::new());
        let waiting = Arc::clone(&gates);
        let resolver = thread::spawn(move || waiting.resolve(7));
        gates.insert(7, 17);
        gates.remove(7);
        assert_eq!(resolver.join().expect("resolver joins"), None);
    }
}
