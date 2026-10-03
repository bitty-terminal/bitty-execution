//! CTX-0512 integration: structured outcomes, owned-process-tree kill, the
//! typed cancel protocol, and execution-generation fencing over real
//! process trees.
//!
//! Children are this test binary, selected by an explicit environment
//! variable and reached through argv-first specs. The `fork` modes start a
//! grandchild (the same binary, sleeping) and print its pid, so the probes
//! prove the property the mechanism exists for: the grandchild dies with its
//! job. The only shell use is the Unix "stubborn" job: `/bin/sh` sets
//! `SIGINT`/`SIGTERM` to ignored and `exec`s the helper, which inherits the
//! ignored dispositions, so graceful requests provably do not stop it.
//!
//! Platforms without an owned-tree backend report `KillScope::DirectChild`;
//! the tree assertions then check that honest scope instead of the
//! grandchild. Windows has a kill-only Job Object backend (CTX-0903): kills
//! end the grandchild, graceful requests stay a typed `Unsupported`.

use std::io::Write as _;
use std::time::{Duration, Instant};

use bitty_execution::{
    CancelEffect, CancelMode, CancelOutcome, CancelReceipt, CancelRequest, DeadlineClock,
    ExecutionGeneration, ExecutionHandle, ExecutionOutcome, JobCancel, JobError, JobEvent, JobId,
    JobKind, JobPrincipal, JobRegistry, JobSnapshot, JobSpec, JobState, JobTimeouts, KillScope,
    OutputStream, ProcessTreeBackend, ReadOutput,
};

const HELPER_ENV: &str = "__BITTY_JOB_OUTCOME_HELPER";

/// Upper bound for any single wait in these probes.
const WAIT_BOUND: Duration = Duration::from_secs(20);

/// Pause between polls.
const POLL: Duration = Duration::from_millis(5);

/// Short grace for graceful steps against a job that ignores them.
#[cfg(unix)]
const SHORT_GRACE: Duration = Duration::from_millis(150);

/// POSIX `SIGKILL`.
#[cfg(unix)]
const SIGKILL: i32 = 9;

/// Child entry point: selected by `HELPER_ENV`, a no-op in the parent suite.
#[test]
fn __bitty_job_outcome_helper_entry__() {
    match std::env::var(HELPER_ENV).as_deref() {
        Ok("quiet") => {}
        Ok("exit3") => std::process::exit(3),
        Ok("sleep") => std::thread::sleep(Duration::from_secs(30)),
        Ok("fork") => {
            spawn_grandchild();
            std::thread::sleep(Duration::from_secs(30));
        }
        Ok("fork-exit") => spawn_grandchild(),
        _ => {}
    }
}

/// Starts a sleeping grandchild that inherits this job's stdout/stderr and
/// announces its pid.
// Never waited on by design: the grandchild must outlive this helper so the
// probes can prove the job's tree kill reaches it.
#[allow(clippy::zombie_processes)]
fn spawn_grandchild() {
    let grandchild = std::process::Command::new(std::env::current_exe().expect("exe"))
        .args(["__bitty_job_outcome_helper_entry__", "--nocapture"])
        .env(HELPER_ENV, "sleep")
        .stdin(std::process::Stdio::null())
        .spawn()
        .expect("grandchild");
    println!("grandchild={};", grandchild.id());
    let _ = std::io::stdout().flush();
}

fn helper_exe() -> String {
    std::env::current_exe()
        .expect("test binary path")
        .to_string_lossy()
        .into_owned()
}

fn helper_env(mode: &str) -> bitty_ipc::execution::EnvPolicy {
    bitty_ipc::execution::EnvPolicy::explicit(vec![(HELPER_ENV.to_owned(), mode.to_owned())])
        .expect("explicit env")
}

fn helper_spec(mode: &str) -> JobSpec {
    JobSpec::new(
        helper_exe(),
        vec![
            "__bitty_job_outcome_helper_entry__".to_owned(),
            "--nocapture".to_owned(),
        ],
    )
    .with_env(helper_env(mode))
}

/// A sleeping job that ignores `SIGINT` and `SIGTERM` (see the module docs).
#[cfg(unix)]
fn stubborn_spec() -> JobSpec {
    JobSpec::new(
        "/bin/sh",
        vec![
            "-c".to_owned(),
            "trap '' INT TERM; exec \"$0\" __bitty_job_outcome_helper_entry__ --nocapture"
                .to_owned(),
            helper_exe(),
        ],
    )
    .with_env(helper_env("sleep"))
}

fn tree_backend() -> bool {
    ProcessTreeBackend::detect().kills_owned_tree()
}

/// Whether the tree backend also delivers graceful stop requests (Unix
/// process groups do; Windows Job Objects are kill-only).
fn graceful_backend() -> bool {
    tree_backend() && ProcessTreeBackend::detect() != ProcessTreeBackend::WindowsJobObject
}

fn wait_for(
    registry: &JobRegistry,
    id: JobId,
    what: &str,
    predicate: impl Fn(&JobSnapshot) -> bool,
) -> JobSnapshot {
    let deadline = Instant::now() + WAIT_BOUND;
    loop {
        let snapshot = registry.get(id).expect("job stays tracked");
        if predicate(&snapshot) {
            return snapshot;
        }
        assert!(
            Instant::now() < deadline,
            "job {id} did not reach {what} in time"
        );
        std::thread::sleep(POLL);
    }
}

fn wait_running(registry: &JobRegistry, id: JobId) -> JobSnapshot {
    wait_for(registry, id, "running", |snapshot| {
        snapshot.state == JobState::Running
    })
}

fn wait_terminal(registry: &JobRegistry, id: JobId) -> JobSnapshot {
    wait_for(registry, id, "a terminal state", |snapshot| {
        snapshot.state.is_terminal()
    })
}

/// Waits for the `grandchild=<pid>` line the `fork` modes print.
fn wait_grandchild(registry: &JobRegistry, id: JobId) -> u32 {
    let deadline = Instant::now() + WAIT_BOUND;
    loop {
        let text = registry
            .read_output(id, ReadOutput::new(OutputStream::Stdout))
            .expect("readable")
            .text;
        for part in text.split("grandchild=").skip(1) {
            let Some((digits, _)) = part.split_once(';') else {
                continue;
            };
            if let Ok(pid) = digits.parse() {
                return pid;
            }
        }
        assert!(Instant::now() < deadline, "no grandchild pid announced");
        std::thread::sleep(POLL);
    }
}

/// Whether `pid` still runs. A zombie counts as gone: it already died, and
/// in a container without an init its reap never comes.
#[cfg(unix)]
fn running(pid: u32) -> bool {
    #[cfg(target_os = "linux")]
    {
        match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(stat) => stat
                .rsplit_once(')')
                .and_then(|(_, rest)| rest.split_whitespace().next())
                .is_some_and(|state| state != "Z" && state != "X"),
            Err(_) => false,
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        std::process::Command::new("kill")
            .arg("-0")
            .arg(pid.to_string())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }
}

/// Whether `pid` still runs (an exited process with open handles counts
/// as gone).
///
/// Pid-reuse caveat: nothing pins the grandchild's pid here, so after it
/// dies Windows may recycle it. A recycled pid owned by another user or a
/// protected process answers `PermissionDenied`, which therefore means
/// "not our process": gone. A recycled pid we can open reads as running and
/// fails the bounded wait loudly rather than passing silently.
#[cfg(windows)]
fn running(pid: u32) -> bool {
    match bitty_winjob::process_is_running(pid) {
        Ok(running) => running,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => false,
        Err(error) => panic!("liveness probe for {pid} failed: {error}"),
    }
}

/// Asserts the grandchild is gone when the platform kills owned trees;
/// otherwise asserts the honest direct-child scope.
fn assert_tree_gone(snapshot: &JobSnapshot, grandchild: u32) {
    if !tree_backend() {
        assert_eq!(snapshot.kill_scope, KillScope::DirectChild);
        return;
    }
    assert_eq!(snapshot.kill_scope, KillScope::OwnedTree);
    #[cfg(any(unix, windows))]
    {
        let deadline = Instant::now() + WAIT_BOUND;
        while running(grandchild) {
            assert!(
                Instant::now() < deadline,
                "grandchild {grandchild} survived its job"
            );
            std::thread::sleep(POLL);
        }
    }
    #[cfg(not(any(unix, windows)))]
    let _ = grandchild;
}

/// Cancel answers published for `id`, in order.
fn cancel_answers(registry: &JobRegistry, id: JobId) -> Vec<CancelOutcome> {
    registry
        .drain_events(bitty_execution::MAX_EVENT_REPLAY)
        .into_iter()
        .filter_map(|event| match event {
            JobEvent::CancelResolved {
                id: found, outcome, ..
            } if found == id => Some(outcome),
            _ => None,
        })
        .collect()
}

fn wait_answer(registry: &JobRegistry, id: JobId) -> CancelOutcome {
    let deadline = Instant::now() + WAIT_BOUND;
    loop {
        if let Some(answer) = cancel_answers(registry, id).first() {
            return *answer;
        }
        assert!(Instant::now() < deadline, "no cancel answer for {id}");
        std::thread::sleep(POLL);
    }
}

fn forged(handle: ExecutionHandle) -> ExecutionHandle {
    let other = handle.generation.get().wrapping_add(1).max(1);
    ExecutionHandle {
        id: handle.id,
        generation: ExecutionGeneration::from_raw(other).expect("non-zero"),
    }
}

// ── structured outcomes ─────────────────────────────────────────────────────

#[test]
fn exits_are_structured_outcomes_with_an_honest_kill_scope() {
    let registry = JobRegistry::new();
    let quiet = registry.spawn(helper_spec("quiet")).expect("tracked");
    let exit3 = registry.spawn(helper_spec("exit3")).expect("tracked");
    let quiet = wait_terminal(&registry, quiet);
    let exit3 = wait_terminal(&registry, exit3);
    assert_eq!(quiet.state, JobState::Done(ExecutionOutcome::Success));
    assert_eq!(exit3.state, JobState::Done(ExecutionOutcome::ExitCode(3)));
    let expected = if tree_backend() {
        KillScope::OwnedTree
    } else {
        KillScope::DirectChild
    };
    assert_eq!(quiet.kill_scope, expected);
    assert_eq!(exit3.kill_scope, expected);
}

#[test]
fn every_spawn_mints_its_own_generation() {
    let registry = JobRegistry::new();
    let first = registry.spawn(helper_spec("quiet")).expect("tracked");
    let second = registry.spawn(helper_spec("quiet")).expect("tracked");
    let first = registry.get(first).expect("tracked");
    let second = registry.get(second).expect("tracked");
    assert_ne!(first.generation, second.generation);
    assert_eq!(first.handle().id, first.id);
    assert_eq!(first.handle().generation, first.generation);
    // Another registry (another process, a restart) never shares them.
    let other = JobRegistry::new();
    let twin = other.spawn(helper_spec("quiet")).expect("tracked");
    assert_eq!(twin, first.id, "the ids coincide");
    assert_ne!(
        other.get(twin).expect("tracked").generation,
        first.generation
    );
}

#[test]
fn a_timeout_is_timed_out_and_kills_the_owned_tree() {
    let registry = JobRegistry::new();
    let spec = helper_spec("fork")
        .with_kind(JobKind::Service)
        .with_timeouts(JobTimeouts::default().with_hard(Duration::from_millis(400)));
    let id = registry.spawn(spec).expect("tracked");
    let grandchild = wait_grandchild(&registry, id);
    let stopped = wait_terminal(&registry, id);
    assert_eq!(
        stopped.state,
        JobState::Done(ExecutionOutcome::TimedOut(DeadlineClock::Hard))
    );
    assert_tree_gone(&stopped, grandchild);
}

#[test]
fn a_natural_exit_takes_its_leftover_tree_with_it() {
    let registry = JobRegistry::new();
    let started = Instant::now();
    let id = registry.spawn(helper_spec("fork-exit")).expect("tracked");
    let grandchild = wait_grandchild(&registry, id);
    let stopped = wait_terminal(&registry, id);
    assert_eq!(stopped.state, JobState::Done(ExecutionOutcome::Success));
    assert_tree_gone(&stopped, grandchild);
    if tree_backend() {
        // The grandchild held the job's pipes; killing it with the tree
        // ends the drains at once instead of at the 5 s join bound.
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "the terminal event waited on an escaped pipe holder"
        );
    }
}

#[cfg(unix)]
#[test]
fn an_external_sigkill_is_signaled_never_oom_killed() {
    let registry = JobRegistry::new();
    let owner = JobPrincipal::new("owner-a").expect("principal");
    let id = registry
        .spawn_as(owner.clone(), helper_spec("sleep"))
        .expect("tracked");
    wait_running(&registry, id);
    let delivered = registry.signal_as(&owner, id, bitty_execution::JobSignal::Kill);
    if !tree_backend() {
        assert!(matches!(delivered, Err(JobError::Unsupported { .. })));
        assert_eq!(registry.cancel_as(&owner, id), Ok(JobCancel::Requested));
        return;
    }
    assert_eq!(delivered, Ok(bitty_execution::SignalOutcome::Delivered));
    let stopped = wait_terminal(&registry, id);
    // No per-job OOM evidence exists: a SIGKILL death is never claimed as
    // an OOM kill.
    assert_eq!(
        stopped.state,
        JobState::Done(ExecutionOutcome::Signaled(SIGKILL))
    );
    assert_ne!(stopped.state, JobState::Done(ExecutionOutcome::OomKilled));
}

// ── generation fencing ──────────────────────────────────────────────────────

#[test]
fn the_host_rejects_a_stale_generation() {
    let registry = JobRegistry::new();
    let id = registry.spawn(helper_spec("sleep")).expect("tracked");
    let live = wait_running(&registry, id);
    let stale = CancelRequest::immediate(forged(live.handle()));
    assert_eq!(
        registry.cancel_typed(stale),
        Ok(CancelReceipt::Resolved(CancelOutcome::StaleGeneration))
    );
    // Nothing changed: the job keeps running and no answer was queued.
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(registry.get(id).expect("tracked").state, JobState::Running);
    assert!(cancel_answers(&registry, id).is_empty());

    let current = CancelRequest::immediate(live.handle());
    assert_eq!(registry.cancel_typed(current), Ok(CancelReceipt::Accepted));
    assert_eq!(wait_answer(&registry, id), CancelOutcome::Killed);
    let stopped = wait_terminal(&registry, id);
    assert_eq!(
        stopped.state,
        JobState::Done(ExecutionOutcome::Cancelled(CancelEffect::Killed))
    );

    // The fence runs before the terminal check; a current handle to a
    // finished job is answered on the spot.
    assert_eq!(
        registry.cancel_typed(stale),
        Ok(CancelReceipt::Resolved(CancelOutcome::StaleGeneration))
    );
    assert_eq!(
        registry.cancel_typed(current),
        Ok(CancelReceipt::Resolved(CancelOutcome::AlreadyExited))
    );
    let unknown = ExecutionHandle {
        id: JobId::from_raw(9_999).expect("id"),
        generation: live.generation,
    };
    assert_eq!(
        registry.cancel_typed(CancelRequest::immediate(unknown)),
        Err(JobError::UnknownJob(unknown.id))
    );
}

#[test]
fn an_unauthorized_caller_learns_nothing_from_its_generation() {
    let registry = JobRegistry::new();
    let owner = JobPrincipal::new("owner-a").expect("principal");
    let stranger = JobPrincipal::new("stranger").expect("principal");
    let id = registry
        .spawn_as(owner.clone(), helper_spec("sleep"))
        .expect("tracked");
    let live = wait_running(&registry, id);
    for handle in [live.handle(), forged(live.handle())] {
        let denied = registry.cancel_typed_as(&stranger, CancelRequest::immediate(handle));
        assert!(
            matches!(denied, Err(JobError::Denied { .. })),
            "a stranger is denied before the fence, got {denied:?}"
        );
    }
    assert_eq!(
        registry.cancel_typed_as(&owner, CancelRequest::immediate(forged(live.handle()))),
        Ok(CancelReceipt::Resolved(CancelOutcome::StaleGeneration))
    );
    assert_eq!(
        registry.cancel_typed_as(&owner, CancelRequest::immediate(live.handle())),
        Ok(CancelReceipt::Accepted)
    );
    wait_terminal(&registry, id);
}

// ── typed cancel ────────────────────────────────────────────────────────────

#[test]
fn an_immediate_cancel_kills_the_owned_tree() {
    let registry = JobRegistry::new();
    let id = registry.spawn(helper_spec("fork")).expect("tracked");
    let grandchild = wait_grandchild(&registry, id);
    let live = registry.get(id).expect("tracked");
    assert_eq!(
        registry.cancel_typed(CancelRequest::immediate(live.handle())),
        Ok(CancelReceipt::Accepted)
    );
    assert_eq!(wait_answer(&registry, id), CancelOutcome::Killed);
    let stopped = wait_terminal(&registry, id);
    assert_eq!(
        stopped.state,
        JobState::Done(ExecutionOutcome::Cancelled(CancelEffect::Killed))
    );
    assert_tree_gone(&stopped, grandchild);
}

#[test]
fn a_graceful_cancel_stops_a_cooperative_job() {
    let registry = JobRegistry::new();
    let id = registry.spawn(helper_spec("sleep")).expect("tracked");
    let live = wait_running(&registry, id);
    let request = CancelRequest::new(live.handle(), CancelMode::Graceful, Duration::from_secs(10))
        .expect("request");
    assert_eq!(registry.cancel_typed(request), Ok(CancelReceipt::Accepted));
    let answer = wait_answer(&registry, id);
    if !graceful_backend() {
        // No graceful stop exists here (no tree, or a kill-only Windows
        // Job Object): nothing was sent, the job runs on, and the answer is
        // typed instead of a single-pid kill.
        assert_eq!(answer, CancelOutcome::Unsupported);
        assert_eq!(registry.get(id).expect("tracked").state, JobState::Running);
        assert_eq!(registry.cancel(id), Ok(JobCancel::Requested));
        wait_terminal(&registry, id);
        return;
    }
    // The helper does not handle SIGINT, so the request stops it.
    assert_eq!(answer, CancelOutcome::CancelledGracefully);
    let stopped = wait_terminal(&registry, id);
    assert_eq!(
        stopped.state,
        JobState::Done(ExecutionOutcome::Cancelled(CancelEffect::Graceful))
    );
}

/// Grace configured for the Windows escalation probe: long enough that
/// waiting it out would be unmistakable.
#[cfg(windows)]
const WINDOWS_ESCALATION_GRACE: Duration = Duration::from_secs(10);

/// The kill must land well inside one grace period: Job Objects have no
/// graceful step, so both grace waits are skipped.
#[cfg(windows)]
const WINDOWS_ESCALATION_BOUND: Duration = Duration::from_secs(5);

#[cfg(windows)]
#[test]
fn graceful_then_kill_on_windows_skips_grace_and_kills_the_tree() {
    const { assert!(WINDOWS_ESCALATION_BOUND.as_millis() < WINDOWS_ESCALATION_GRACE.as_millis()) };
    let registry = JobRegistry::new();
    let id = registry.spawn(helper_spec("fork")).expect("tracked");
    let grandchild = wait_grandchild(&registry, id);
    let live = registry.get(id).expect("tracked");
    let request = CancelRequest::new(
        live.handle(),
        CancelMode::GracefulThenKill,
        WINDOWS_ESCALATION_GRACE,
    )
    .expect("request");
    let started = Instant::now();
    assert_eq!(registry.cancel_typed(request), Ok(CancelReceipt::Accepted));
    assert_eq!(wait_answer(&registry, id), CancelOutcome::Killed);
    let stopped = wait_terminal(&registry, id);
    assert!(
        started.elapsed() < WINDOWS_ESCALATION_BOUND,
        "the graceful steps are refused on Windows, so the kill is immediate"
    );
    assert_eq!(
        stopped.state,
        JobState::Done(ExecutionOutcome::Cancelled(CancelEffect::Killed))
    );
    assert_tree_gone(&stopped, grandchild);
}

#[cfg(unix)]
#[test]
fn a_graceful_only_cancel_never_escalates_on_a_stubborn_job() {
    if !tree_backend() {
        return;
    }
    let registry = JobRegistry::new();
    let id = registry.spawn(stubborn_spec()).expect("tracked");
    let live = wait_running(&registry, id);
    let request =
        CancelRequest::new(live.handle(), CancelMode::Graceful, SHORT_GRACE).expect("request");
    assert_eq!(registry.cancel_typed(request), Ok(CancelReceipt::Accepted));
    assert_eq!(wait_answer(&registry, id), CancelOutcome::StillRunning);
    assert_eq!(registry.get(id).expect("tracked").state, JobState::Running);
    assert_eq!(
        registry.cancel_typed(CancelRequest::immediate(live.handle())),
        Ok(CancelReceipt::Accepted)
    );
    assert_eq!(wait_answer(&registry, id), CancelOutcome::Killed);
    wait_terminal(&registry, id);
}

#[cfg(unix)]
#[test]
fn graceful_then_kill_escalates_through_both_grace_periods() {
    if !tree_backend() {
        return;
    }
    let registry = JobRegistry::new();
    let id = registry.spawn(stubborn_spec()).expect("tracked");
    let live = wait_running(&registry, id);
    let request = CancelRequest::new(live.handle(), CancelMode::GracefulThenKill, SHORT_GRACE)
        .expect("request");
    let started = Instant::now();
    assert_eq!(registry.cancel_typed(request), Ok(CancelReceipt::Accepted));
    assert_eq!(wait_answer(&registry, id), CancelOutcome::Killed);
    assert!(
        started.elapsed() >= 2 * SHORT_GRACE,
        "SIGINT and SIGTERM each get their grace before the kill"
    );
    let stopped = wait_terminal(&registry, id);
    assert_eq!(
        stopped.state,
        JobState::Done(ExecutionOutcome::Cancelled(CancelEffect::Killed))
    );
}

#[cfg(unix)]
#[test]
fn a_stronger_request_escalates_the_cancel_in_flight() {
    if !tree_backend() {
        return;
    }
    let registry = JobRegistry::new();
    let id = registry.spawn(stubborn_spec()).expect("tracked");
    let live = wait_running(&registry, id);
    let patient = CancelRequest::new(
        live.handle(),
        CancelMode::Graceful,
        Duration::from_millis(bitty_execution::MAX_CANCEL_GRACE_MS),
    )
    .expect("request");
    let started = Instant::now();
    assert_eq!(registry.cancel_typed(patient), Ok(CancelReceipt::Accepted));
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(
        registry.cancel_typed(CancelRequest::immediate(live.handle())),
        Ok(CancelReceipt::Accepted)
    );
    let stopped = wait_terminal(&registry, id);
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "the kill did not wait out the 60 s grace"
    );
    assert_eq!(
        stopped.state,
        JobState::Done(ExecutionOutcome::Cancelled(CancelEffect::Killed))
    );
    // Both requests are answered by the one executed cancel.
    assert_eq!(cancel_answers(&registry, id), vec![CancelOutcome::Killed]);
}

#[cfg(unix)]
#[test]
fn a_pty_cancel_kills_the_owned_tree() {
    use bitty_execution::JobIo;
    bitty_test_support::require_pty!();
    let registry = JobRegistry::new();
    let spec = helper_spec("fork")
        .with_kind(JobKind::Interactive)
        .with_io(JobIo::Pty);
    let id = registry.spawn(spec).expect("tracked");
    let grandchild = wait_grandchild(&registry, id);
    assert_eq!(registry.cancel(id), Ok(JobCancel::Requested));
    assert_eq!(wait_answer(&registry, id), CancelOutcome::Killed);
    let stopped = wait_terminal(&registry, id);
    assert_eq!(
        stopped.state,
        JobState::Done(ExecutionOutcome::Cancelled(CancelEffect::Killed))
    );
    assert_tree_gone(&stopped, grandchild);
}
