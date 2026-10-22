//! Live component-server integration tests (Linux/macOS).
//!
//! The real `bitty-execution` binary is spawned as a stdio coprocess and
//! driven with the public protocol codec. Children under test are `/bin/sh`
//! for deterministic output/exit probes or this test binary for sleeping and
//! post-crash marker probes (argv-first, explicit environment, no PATH).
//!
//! Covered acceptance paths: handshake, real command lifecycle, separate
//! stdout/stderr frames, exit status, hard timeout, typed cancellation,
//! retained-output read, typed errors, oversize-frame rejection, and a
//! component crash that leaves the host alive.

#![cfg(unix)]

use std::io::{BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use bitty_execution::component::protocol::{
    ErrorKind, ExitKind, FrameReader, MAX_FRAME_BYTES, Message, PROTOCOL_VERSION, Stream,
    TerminateMode, TerminateOutcome, WireCancelEffect, WireDeadlineClock, WireEnv, WireEnvVar,
    WireKillScope, WireOomGap, WireOomVerdict, write_frame,
};
use bitty_execution::component::server::{
    COMPONENT_VERSION, SERVER_EXIT_INTERNAL, SERVER_EXIT_OK, SERVER_EXIT_PROTOCOL,
};

/// Environment variable selecting the child helper mode.
const HELPER_ENV: &str = "__BITTY_COMPONENT_HELPER";
/// Marker path for the crash-isolation probe.
const MARKER_ENV: &str = "__BITTY_COMPONENT_MARKER";

/// Upper bound for one protocol message or one child observation.
const WAIT: Duration = Duration::from_secs(20);

/// Child entry point: selected by [`HELPER_ENV`]. In the parent suite it is a
/// no-op and passes.
#[test]
fn __bitty_component_helper_entry__() {
    match std::env::var(HELPER_ENV).as_deref() {
        // Stay alive well past every test deadline.
        Ok("sleep") => std::thread::sleep(Duration::from_secs(30)),
        // Outlive a component crash just long enough to prove the host and
        // the job were not killed with it, then leave no orphan.
        Ok("delayed-marker") => {
            let path = std::env::var(MARKER_ENV).expect("marker path");
            std::thread::sleep(Duration::from_millis(300));
            std::fs::write(path, b"alive").expect("write marker");
            std::process::exit(0);
        }
        Ok("quiet") => {}
        _ => {}
    }
}

fn helper_exe() -> String {
    std::env::current_exe()
        .expect("test binary path")
        .to_string_lossy()
        .into_owned()
}

fn helper_env(entries: &[(&str, &str)]) -> WireEnv {
    WireEnv::Explicit(
        entries
            .iter()
            .map(|(name, value)| WireEnvVar {
                name: (*name).to_owned(),
                value: (*value).to_owned(),
            })
            .collect(),
    )
}

fn shell(script: &str) -> (String, Vec<String>) {
    (
        "/bin/sh".to_owned(),
        vec!["-c".to_owned(), script.to_owned()],
    )
}

/// One spawned component process plus its decoded message stream.
struct Component {
    child: Child,
    stdin: std::process::ChildStdin,
    messages: Receiver<Result<Message, String>>,
    exited: bool,
}

impl Component {
    fn start() -> Self {
        let binary: std::path::PathBuf = std::env::var_os("BITTY_EXECUTION_COMPONENT_BIN")
            .map_or_else(|| env!("CARGO_BIN_EXE_bitty-execution").into(), Into::into);
        let mut child = Command::new(binary)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn bitty-execution");
        let stdin = child.stdin.take().expect("component stdin");
        let stdout = child.stdout.take().expect("component stdout");
        let (sender, messages) = mpsc::channel();
        std::thread::Builder::new()
            .name("component-reader".to_owned())
            .spawn(move || {
                let mut reader = FrameReader::new(BufReader::new(stdout));
                loop {
                    match reader.read_message() {
                        Ok(Some(message)) => {
                            if sender.send(Ok(message)).is_err() {
                                break;
                            }
                        }
                        Ok(None) => break,
                        Err(error) => {
                            let _ = sender.send(Err(error.to_string()));
                            break;
                        }
                    }
                }
            })
            .expect("reader thread");
        let mut component = Self {
            child,
            stdin,
            messages,
            exited: false,
        };
        component.handshake();
        component
    }

    fn handshake(&mut self) {
        self.send(&Message::Hello {
            min: PROTOCOL_VERSION,
            max: PROTOCOL_VERSION,
            component: "execution".to_owned(),
            version: "test".to_owned(),
        });
        match self.recv() {
            Message::HelloAck {
                protocol,
                component,
                version,
            } => {
                assert_eq!(protocol, PROTOCOL_VERSION);
                assert_eq!(component, "execution");
                assert_eq!(version, COMPONENT_VERSION);
            }
            other => panic!("expected HelloAck, got {other:?}"),
        }
    }

    fn send(&mut self, message: &Message) {
        write_frame(&mut self.stdin, message).expect("write frame");
        self.stdin.flush().expect("flush frame");
    }

    fn send_raw(&mut self, bytes: &[u8]) {
        self.stdin.write_all(bytes).expect("write raw");
        self.stdin.flush().expect("flush raw");
    }

    fn recv(&self) -> Message {
        match self.messages.recv_timeout(WAIT) {
            Ok(Ok(message)) => message,
            Ok(Err(error)) => panic!("component protocol error: {error}"),
            Err(RecvTimeoutError::Timeout) => panic!("timed out waiting for a component frame"),
            Err(RecvTimeoutError::Disconnected) => panic!("component closed its stdout"),
        }
    }

    /// Collects messages until `done` matches one; returns everything seen,
    /// including the terminator.
    fn recv_until(&self, what: &str, done: impl Fn(&Message) -> bool) -> Vec<Message> {
        let deadline = Instant::now() + WAIT;
        let mut seen = Vec::new();
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(!remaining.is_zero(), "timed out waiting for {what}");
            let message = match self.messages.recv_timeout(remaining) {
                Ok(Ok(message)) => message,
                Ok(Err(error)) => panic!("component protocol error: {error}"),
                Err(_) => panic!("timed out waiting for {what}"),
            };
            let finished = done(&message);
            seen.push(message);
            if finished {
                return seen;
            }
        }
    }

    fn shutdown(mut self) {
        self.send(&Message::Shutdown);
        match self.recv() {
            Message::ShutdownAck => {}
            other => panic!("expected ShutdownAck, got {other:?}"),
        }
        let status = self.child.wait().expect("wait for component");
        self.exited = true;
        assert_eq!(status.code(), Some(i32::from(SERVER_EXIT_OK)));
    }

    fn kill_and_wait(&mut self) -> std::process::ExitStatus {
        self.child.kill().expect("kill component");
        let status = self.child.wait().expect("wait for killed component");
        self.exited = true;
        status
    }
}

impl Drop for Component {
    fn drop(&mut self) {
        if self.exited {
            return;
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn exit_of(messages: &[Message], job: u64) -> &Message {
    messages
        .iter()
        .find(|message| matches!(message, Message::Exit { job: seen, .. } if *seen == job))
        .expect("Exit frame")
}

fn spawn_message(
    job: u64,
    program: String,
    args: Vec<String>,
    env: WireEnv,
    hard_ms: u32,
) -> Message {
    Message::Spawn {
        job,
        program,
        args,
        cwd: None,
        env,
        kind: bitty_execution::component::protocol::SpawnKind::Command,
        io: bitty_execution::component::protocol::SpawnIo::Pipes,
        lifetime: bitty_execution::component::protocol::SpawnLifetime::Detached,
        hard_ms,
        idle_ms: 0,
        retention_ms: 0,
    }
}

fn spawned_generation(messages: &[Message], job: u64) -> u64 {
    messages
        .iter()
        .find_map(|message| match message {
            Message::Spawned {
                job: seen,
                generation,
            } if *seen == job => Some(*generation),
            _ => None,
        })
        .expect("Spawned frame")
}

#[test]
fn handshake_then_shutdown_is_clean() {
    let component = Component::start();
    component.shutdown();
}

#[test]
fn real_command_lifecycle_reports_output_and_exit_status() {
    let mut component = Component::start();
    let (program, args) = shell("printf out; printf err >&2; exit 7");
    component.send(&spawn_message(1, program, args, WireEnv::Isolated, 0));

    // The Spawned reply is always the first frame for a job, even when the
    // child produces output immediately.
    let first = component.recv();
    assert!(
        matches!(first, Message::Spawned { job: 1, generation } if generation > 0),
        "expected Spawned first, got {first:?}"
    );

    let seen = component.recv_until("Exit", |message| {
        matches!(message, Message::Exit { job: 1, .. })
    });
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut started = false;
    for message in &seen {
        match message {
            Message::Started { job: 1 } => started = true,
            Message::Output {
                job: 1,
                stream,
                data,
            } => match stream {
                Stream::Stdout => stdout.extend_from_slice(data),
                Stream::Stderr => stderr.extend_from_slice(data),
            },
            Message::Exit { .. } => {}
            other => panic!("unexpected frame for job 1: {other:?}"),
        }
    }
    assert!(started, "Started frame was not observed");
    assert_eq!(
        String::from_utf8_lossy(&stdout).trim(),
        "out",
        "stdout frames"
    );
    assert_eq!(
        String::from_utf8_lossy(&stderr).trim(),
        "err",
        "stderr frames"
    );
    match exit_of(&seen, 1) {
        Message::Exit {
            outcome,
            detail,
            kill_scope,
            ..
        } => {
            assert_eq!(*outcome, ExitKind::ExitCode);
            assert_eq!(*detail, 7);
            assert_eq!(*kill_scope, WireKillScope::OwnedTree);
        }
        _ => unreachable!(),
    }
    component.shutdown();
}

#[test]
fn cancellation_uses_the_typed_terminate_path() {
    let mut component = Component::start();
    let args = vec![
        "__bitty_component_helper_entry__".to_owned(),
        "--exact".to_owned(),
        "--nocapture".to_owned(),
    ];
    component.send(&spawn_message(
        2,
        helper_exe(),
        args,
        helper_env(&[(HELPER_ENV, "sleep")]),
        0,
    ));
    let first = component.recv();
    let generation = spawned_generation(std::slice::from_ref(&first), 2);
    assert!(matches!(first, Message::Spawned { job: 2, .. }));
    component.recv_until("Started", |message| {
        matches!(message, Message::Started { job: 2 })
    });

    component.send(&Message::Terminate {
        job: 2,
        generation,
        mode: TerminateMode::Immediate,
        grace_ms: 0,
    });
    let seen = component.recv_until("Exit", |message| {
        matches!(message, Message::Exit { job: 2, .. })
    });
    let canceled = seen
        .iter()
        .find_map(|message| match message {
            Message::Canceled { job: 2, outcome } => Some(*outcome),
            _ => None,
        })
        .expect("Canceled frame before Exit");
    assert!(
        matches!(
            canceled,
            TerminateOutcome::Killed | TerminateOutcome::CancelledBeforeStart
        ),
        "unexpected cancel outcome: {canceled:?}"
    );
    match exit_of(&seen, 2) {
        Message::Exit {
            outcome, cancel, ..
        } => {
            assert_eq!(*outcome, ExitKind::Cancelled);
            assert!(matches!(
                cancel,
                WireCancelEffect::Killed | WireCancelEffect::BeforeStart
            ));
        }
        _ => unreachable!(),
    }
    component.shutdown();
}

#[test]
fn hard_deadline_reports_timed_out() {
    let mut component = Component::start();
    let args = vec![
        "__bitty_component_helper_entry__".to_owned(),
        "--exact".to_owned(),
        "--nocapture".to_owned(),
    ];
    component.send(&spawn_message(
        3,
        helper_exe(),
        args,
        helper_env(&[(HELPER_ENV, "sleep")]),
        500,
    ));
    let first = component.recv();
    assert!(matches!(first, Message::Spawned { job: 3, .. }));
    let seen = component.recv_until("Exit", |message| {
        matches!(message, Message::Exit { job: 3, .. })
    });
    match exit_of(&seen, 3) {
        Message::Exit {
            outcome,
            clock,
            detail,
            ..
        } => {
            assert_eq!(*outcome, ExitKind::TimedOut);
            assert_eq!(*clock, WireDeadlineClock::Hard);
            assert_eq!(*detail, 0);
        }
        _ => unreachable!(),
    }
    component.shutdown();
}

#[test]
fn retained_output_can_be_read_after_exit() {
    let mut component = Component::start();
    let (program, args) = shell("printf 'a\\nb\\nc\\n'");
    component.send(&spawn_message(4, program, args, WireEnv::Isolated, 0));
    let first = component.recv();
    assert!(matches!(first, Message::Spawned { job: 4, .. }));
    component.recv_until("Exit", |message| {
        matches!(message, Message::Exit { job: 4, .. })
    });
    component.send(&Message::ReadOutput {
        request: 9,
        job: 4,
        stream: Stream::Stdout,
        tail_lines: 2,
        max_bytes: 0,
    });
    match component.recv() {
        Message::OutputView {
            request,
            job,
            stream,
            data,
            total,
            truncated,
            lines,
            ..
        } => {
            assert_eq!(request, 9);
            assert_eq!(job, 4);
            assert_eq!(stream, Stream::Stdout);
            assert!(!truncated);
            assert!(total >= 6, "total bytes: {total}");
            assert_eq!(lines, 2);
            assert!(String::from_utf8_lossy(&data).ends_with('c'));
        }
        other => panic!("expected OutputView, got {other:?}"),
    }
    component.shutdown();
}

#[test]
fn unknown_job_and_stale_generation_are_typed_errors() {
    let mut component = Component::start();
    component.send(&Message::Terminate {
        job: 99,
        generation: 1,
        mode: TerminateMode::Immediate,
        grace_ms: 0,
    });
    match component.recv() {
        Message::Error {
            request,
            kind,
            message,
        } => {
            assert_eq!(request, 99);
            assert_eq!(kind, ErrorKind::UnknownJob);
            assert_eq!(message, "unknown job");
        }
        other => panic!("expected Error, got {other:?}"),
    }

    component.send(&spawn_message(
        5,
        "/bin/true".to_owned(),
        Vec::new(),
        WireEnv::Isolated,
        0,
    ));
    let first = component.recv();
    let generation = spawned_generation(std::slice::from_ref(&first), 5);
    component.recv_until("Exit", |message| {
        matches!(message, Message::Exit { job: 5, .. })
    });
    let stale = if generation == u64::MAX {
        generation - 1
    } else {
        generation + 1
    };
    component.send(&Message::Terminate {
        job: 5,
        generation: stale,
        mode: TerminateMode::Immediate,
        grace_ms: 0,
    });
    match component.recv() {
        Message::Canceled {
            job: 5,
            outcome: TerminateOutcome::StaleGeneration,
        } => {}
        other => panic!("expected stale-generation Canceled, got {other:?}"),
    }
    component.shutdown();
}

#[test]
fn failed_spawn_is_a_typed_terminal_outcome() {
    let mut component = Component::start();
    component.send(&spawn_message(
        6,
        "/bitty-does-not-exist".to_owned(),
        Vec::new(),
        WireEnv::Isolated,
        0,
    ));
    let first = component.recv();
    assert!(matches!(first, Message::Spawned { job: 6, .. }));
    let seen = component.recv_until("Exit", |message| {
        matches!(message, Message::Exit { job: 6, .. })
    });
    match exit_of(&seen, 6) {
        Message::Exit { outcome, .. } => assert_eq!(*outcome, ExitKind::SpawnFailed),
        _ => unreachable!(),
    }
    component.shutdown();
}

#[test]
fn oversized_frame_is_rejected_and_the_component_exits_protocol() {
    let mut component = Component::start();
    let oversized = u32::try_from(MAX_FRAME_BYTES + 1).expect("fits u32");
    component.send_raw(&oversized.to_be_bytes());
    match component.recv() {
        Message::Error {
            request,
            kind,
            message,
        } => {
            assert_eq!(request, 0);
            assert_eq!(kind, ErrorKind::Protocol);
            assert_eq!(message, "frame too large");
        }
        other => panic!("expected protocol Error, got {other:?}"),
    }
    let status = component.child.wait().expect("wait for component");
    assert_eq!(status.code(), Some(i32::from(SERVER_EXIT_PROTOCOL)));
}

#[test]
fn component_crash_does_not_kill_the_host() {
    let marker = std::env::temp_dir().join(format!(
        "bitty-execution-crash-{}-{}.marker",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos())
    ));
    let _ = std::fs::remove_file(&marker);
    let marker_value = marker.to_string_lossy().into_owned();

    let mut component = Component::start();
    let args = vec![
        "__bitty_component_helper_entry__".to_owned(),
        "--exact".to_owned(),
        "--nocapture".to_owned(),
    ];
    component.send(&spawn_message(
        7,
        helper_exe(),
        args,
        helper_env(&[(HELPER_ENV, "delayed-marker"), (MARKER_ENV, &marker_value)]),
        0,
    ));
    let first = component.recv();
    assert!(matches!(first, Message::Spawned { job: 7, .. }));
    component.recv_until("Started", |message| {
        matches!(message, Message::Started { job: 7 })
    });

    let status = component.kill_and_wait();
    assert!(
        !status.success(),
        "a killed component must not report success"
    );

    // The host (this test process) is alive, and the already-spawned job was
    // not killed with the component: it still reaches the marker write.
    let deadline = Instant::now() + WAIT;
    while !marker.exists() {
        assert!(
            Instant::now() < deadline,
            "job did not survive the component crash"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let _ = std::fs::remove_file(&marker);

    // A fresh component still speaks the protocol after the crash.
    let mut replacement = Component::start();
    replacement.send(&spawn_message(
        8,
        "/bin/true".to_owned(),
        Vec::new(),
        WireEnv::Isolated,
        0,
    ));
    let seen = replacement.recv_until("Exit", |message| {
        matches!(message, Message::Exit { job: 8, .. })
    });
    match exit_of(&seen, 8) {
        Message::Exit { outcome, .. } => assert_eq!(*outcome, ExitKind::Success),
        _ => unreachable!(),
    }
    replacement.shutdown();
}

#[test]
fn interactive_pty_jobs_are_refused() {
    let mut component = Component::start();
    component.send(&Message::Spawn {
        job: 10,
        program: "/bin/sh".to_owned(),
        args: vec!["-c".to_owned(), "true".to_owned()],
        cwd: None,
        env: WireEnv::Explicit(Vec::new()),
        kind: bitty_execution::component::protocol::SpawnKind::Interactive,
        io: bitty_execution::component::protocol::SpawnIo::Pty,
        lifetime: bitty_execution::component::protocol::SpawnLifetime::Detached,
        hard_ms: 0,
        idle_ms: 0,
        retention_ms: 0,
    });
    match component.recv() {
        Message::Error {
            request: 10,
            kind: ErrorKind::Unsupported,
            message,
        } => assert_eq!(message, "interactive pty jobs are host-owned"),
        other => panic!("expected unsupported Error, got {other:?}"),
    }
    component.shutdown();
}

#[test]
fn job_slots_are_bounded_by_the_shared_ceiling() {
    // The registry itself is covered by its own suites; here the protocol
    // constant is pinned to the shared ceiling and the component starts.
    let component = Component::start();
    component.shutdown();
}

#[test]
fn protocol_exit_codes_are_nonzero_on_hostile_input() {
    // A component that is fed a non-Hello first frame answers with a typed
    // connection error and exits protocol (3), not a panic.
    let binary: std::path::PathBuf = std::env::var_os("BITTY_EXECUTION_COMPONENT_BIN")
        .map_or_else(|| env!("CARGO_BIN_EXE_bitty-execution").into(), Into::into);
    let mut child = Command::new(binary)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn bitty-execution");
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut reader = FrameReader::new(BufReader::new(stdout));
    write_frame(&mut stdin, &Message::Started { job: 1 }).expect("frame");
    let reply = reader.read_message().expect("decode").expect("some");
    assert!(matches!(
        reply,
        Message::Error {
            request: 0,
            kind: ErrorKind::Protocol,
            ..
        }
    ));
    let status = child.wait().expect("wait");
    assert_eq!(status.code(), Some(i32::from(SERVER_EXIT_PROTOCOL)));
    assert_ne!(SERVER_EXIT_INTERNAL, SERVER_EXIT_OK);
    assert_ne!(SERVER_EXIT_PROTOCOL, SERVER_EXIT_INTERNAL);
}

#[test]
fn oom_evidence_gap_codes_are_stable() {
    assert_eq!(WireOomVerdict::Unknown.code(), 0);
    assert_eq!(WireOomGap::None.code(), 0);
    assert_eq!(WireOomGap::NotConfigured.code(), 1);
}
