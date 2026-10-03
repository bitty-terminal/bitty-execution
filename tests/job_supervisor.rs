//! CTX-0511 integration: phase-1 job supervisor over real child processes.
//!
//! Every child under test is this test binary, selected by an explicit
//! environment variable and reached through an argv-first job spec:
//! hermetic, portable, and shell-free (no `sh`/`sleep` PATH dependency), so
//! the same file runs on Unix and Windows CI.
//!
//! Hostile probes live here too: unknown ids, duplicate/never-reused ids,
//! quiet and failed spawns, over-bound metadata, and capacity overflow all
//! fail closed instead of leaking a process or growing memory.

use std::time::{Duration, Instant};

use bitty_execution::{
    CancelEffect, DeadlineClock, ExecutionOutcome, JobCancel, JobError, JobEvent, JobId, JobIo,
    JobKind, JobLifetime, JobOrigin, JobRegistry, JobSnapshot, JobSpec, JobState, JobTimeouts,
};
use bitty_test_support::require_pty;

const HELPER_ENV: &str = "__BITTY_JOB_TEST_HELPER";

/// Child entry point: selected by `HELPER_ENV`, runs only in spawned
/// children (the parent suite runs it as a no-op and it passes).
#[test]
fn __bitty_job_helper_entry__() {
    match std::env::var(HELPER_ENV).as_deref() {
        // Exit immediately without emitting anything.
        Ok("quiet") => {}
        // Stay alive well past every test deadline.
        Ok("sleep") => std::thread::sleep(Duration::from_secs(30)),
        // Emit a tick every 50 ms for 15 s.
        Ok("emit") => {
            for _ in 0..300 {
                eprint!("tick");
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        // Announce readiness, then stay alive (interactive PTY shape).
        Ok("pty-hold") => {
            println!("ready");
            std::thread::sleep(Duration::from_secs(30));
        }
        _ => {}
    }
}

fn helper_exe() -> String {
    std::env::current_exe()
        .expect("test binary path")
        .to_string_lossy()
        .into_owned()
}

/// Argv-first spec for the test binary in `mode`, with the explicit
/// environment the closed-env backend requires.
fn helper_spec(mode: &str) -> JobSpec {
    JobSpec::new(
        helper_exe(),
        vec![
            "__bitty_job_helper_entry__".to_owned(),
            "--nocapture".to_owned(),
        ],
    )
    .with_env(
        bitty_ipc::execution::EnvPolicy::explicit(vec![(HELPER_ENV.to_owned(), mode.to_owned())])
            .expect("explicit env"),
    )
}

fn wait_for(
    registry: &JobRegistry,
    id: JobId,
    what: &str,
    predicate: impl Fn(&JobSnapshot) -> bool,
) -> JobSnapshot {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let snapshot = registry.get(id).expect("job stays tracked");
        if predicate(&snapshot) {
            return snapshot;
        }
        assert!(
            Instant::now() < deadline,
            "job {id} did not reach {what} in time"
        );
        std::thread::sleep(Duration::from_millis(5));
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

#[test]
fn quiet_command_completes_and_reports_ordered_lifecycle_events() {
    let registry = JobRegistry::new();
    let id = registry.spawn(helper_spec("quiet")).expect("tracked");
    let snapshot = wait_terminal(&registry, id);
    assert_eq!(snapshot.state, JobState::Done(ExecutionOutcome::Success));
    assert!(snapshot.started_at_ms.is_some());
    assert!(snapshot.finished_at_ms.is_some());

    let events = registry.drain_events(16);
    assert_eq!(events.len(), 3, "{events:?}");
    assert!(matches!(events[0], JobEvent::Queued { id: e, .. } if e == id));
    assert!(matches!(events[1], JobEvent::Started { id: e, .. } if e == id));
    assert!(matches!(
        events[2],
        JobEvent::Stopped {
            id: e,
            outcome: ExecutionOutcome::Success,
            ..
        } if e == id
    ));
    let times: Vec<u64> = events.iter().map(|event| event.at_ms()).collect();
    assert!(times.windows(2).all(|pair| pair[0] <= pair[1]), "{times:?}");
    assert!(registry.drain_events(1).is_empty());
    assert_eq!(registry.events_dropped(), 0);
}

#[test]
fn failed_spawn_is_a_terminal_observation_not_a_lost_job() {
    let registry = JobRegistry::new();
    let spec = JobSpec::new(
        "bitty-ct0511-nonexistent-job-program",
        vec!["--never".to_owned()],
    );
    let id = registry.spawn(spec).expect("tracked");
    let snapshot = wait_terminal(&registry, id);
    assert_eq!(
        snapshot.state,
        JobState::Done(ExecutionOutcome::SpawnFailed)
    );
    assert!(snapshot.started_at_ms.is_none());
    let events = registry.drain_events(16);
    assert!(events.iter().any(|event| matches!(
        event,
        JobEvent::Stopped {
            outcome: ExecutionOutcome::SpawnFailed,
            ..
        }
    )));
}

#[test]
fn service_job_is_never_killed_by_an_implicit_deadline() {
    let registry = JobRegistry::new();
    let spec = helper_spec("sleep")
        .with_kind(JobKind::Service)
        .with_lifetime(JobLifetime::Workspace);
    let id = registry.spawn(spec).expect("tracked");
    wait_running(&registry, id);
    // Quiet services and watches outlive ordinary timeout windows: there is
    // no blanket "background jobs die after N" rule.
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        registry.get(id).expect("tracked").state,
        JobState::Running,
        "a service job must not be killed by an implicit deadline"
    );
    assert_eq!(registry.cancel(id), Ok(JobCancel::Requested));
    let stopped = wait_terminal(&registry, id);
    assert_eq!(
        stopped.state,
        JobState::Done(ExecutionOutcome::Cancelled(CancelEffect::Killed))
    );
}

#[test]
fn hard_timeout_terminates_a_long_job() {
    let registry = JobRegistry::new();
    let spec = helper_spec("sleep")
        .with_kind(JobKind::Service)
        .with_timeouts(JobTimeouts::default().with_hard(Duration::from_millis(60)));
    let id = registry.spawn(spec).expect("tracked");
    let stopped = wait_terminal(&registry, id);
    assert_eq!(
        stopped.state,
        JobState::Done(ExecutionOutcome::TimedOut(DeadlineClock::Hard))
    );
}

#[test]
fn idle_timeout_terminates_a_quiet_job() {
    let registry = JobRegistry::new();
    let spec = helper_spec("sleep")
        .with_kind(JobKind::Watch)
        .with_timeouts(JobTimeouts::default().with_idle(Duration::from_millis(80)));
    let id = registry.spawn(spec).expect("tracked");
    let stopped = wait_terminal(&registry, id);
    assert_eq!(
        stopped.state,
        JobState::Done(ExecutionOutcome::TimedOut(DeadlineClock::Idle))
    );
}

#[test]
fn output_activity_resets_the_idle_deadline() {
    let registry = JobRegistry::new();
    let spec = helper_spec("emit")
        .with_kind(JobKind::Watch)
        .with_timeouts(JobTimeouts::default().with_idle(Duration::from_millis(700)));
    let id = registry.spawn(spec).expect("tracked");
    wait_running(&registry, id);
    // The child emits every 50 ms, so a 700 ms idle window keeps it alive
    // well past its own length.
    std::thread::sleep(Duration::from_millis(600));
    assert_eq!(registry.get(id).expect("tracked").state, JobState::Running);
    assert_eq!(registry.cancel(id), Ok(JobCancel::Requested));
    let stopped = wait_terminal(&registry, id);
    assert_eq!(
        stopped.state,
        JobState::Done(ExecutionOutcome::Cancelled(CancelEffect::Killed))
    );
}

#[test]
fn cancel_is_requested_then_observed_as_a_terminal_state() {
    let registry = JobRegistry::new();
    let id = registry.spawn(helper_spec("sleep")).expect("tracked");
    wait_running(&registry, id);
    assert_eq!(registry.cancel(id), Ok(JobCancel::Requested));
    let stopped = wait_terminal(&registry, id);
    assert_eq!(
        stopped.state,
        JobState::Done(ExecutionOutcome::Cancelled(CancelEffect::Killed))
    );
    // Repeated cancel on a terminal job is reported, never re-run.
    assert_eq!(
        registry.cancel(id),
        Ok(JobCancel::AlreadyStopped(ExecutionOutcome::Cancelled(
            CancelEffect::Killed
        )))
    );
}

#[test]
fn unknown_ids_fail_closed() {
    let registry = JobRegistry::new();
    let unknown = JobId::from_raw(4_242).expect("non-zero");
    assert_eq!(registry.get(unknown), Err(JobError::UnknownJob(unknown)));
    assert_eq!(registry.cancel(unknown), Err(JobError::UnknownJob(unknown)));
}

#[test]
fn ids_are_unique_across_real_jobs() {
    let registry = JobRegistry::new();
    let mut ids = Vec::new();
    for _ in 0..3 {
        let id = registry.spawn(helper_spec("quiet")).expect("tracked");
        wait_terminal(&registry, id);
        assert!(!ids.contains(&id), "id {id} was reused");
        ids.push(id);
    }
    assert!(ids.windows(2).all(|pair| pair[0] < pair[1]));
}

#[test]
fn hostile_specs_are_rejected_without_tracking_anything() {
    let registry = JobRegistry::new();
    let cases = vec![
        JobSpec::new("", Vec::new()),
        JobSpec::new("printf", vec!["bad\0arg".to_owned()]),
        JobSpec::new(
            "printf",
            vec!["x".repeat(bitty_ipc::execution::MAX_EXEC_ARG_BYTES + 1)],
        ),
        JobSpec::new(
            "printf",
            (0..=bitty_ipc::execution::MAX_EXEC_ARGS)
                .map(|i| i.to_string())
                .collect(),
        ),
        // Non-interactive job asking for a PTY and vice versa.
        helper_spec("quiet").with_io(JobIo::Pty),
        helper_spec("quiet").with_kind(JobKind::Interactive),
        helper_spec("quiet").with_timeouts(JobTimeouts::default().with_hard(Duration::ZERO)),
        helper_spec("quiet").with_origin(JobOrigin::panel("panel".repeat(64))),
    ];
    for spec in cases {
        assert!(
            matches!(registry.spawn(spec), Err(JobError::InvalidSpec { .. })),
            "an over-bound spec must fail closed"
        );
    }
    assert!(registry.is_empty());
    assert!(registry.drain_events(16).is_empty());
    assert_eq!(registry.events_dropped(), 0);
}

#[test]
fn bounded_registry_metadata_stays_within_capacity() {
    let registry = JobRegistry::with_capacity(2);
    let first = registry.spawn(helper_spec("quiet")).expect("tracked");
    wait_terminal(&registry, first);
    let second = registry.spawn(helper_spec("quiet")).expect("tracked");
    wait_terminal(&registry, second);

    assert_eq!(registry.list().len(), 2);
    assert_eq!(
        registry.spawn(helper_spec("quiet")),
        Err(JobError::RegistryFull { limit: 2 })
    );
    assert!(registry.list().len() <= registry.capacity());
    // Events for the two completed jobs stay bounded and observable.
    assert!(registry.drain_events(64).len() <= 6);
}

#[test]
fn interactive_pty_job_runs_and_cancels() {
    require_pty!();
    let registry = JobRegistry::new();
    let spec = helper_spec("pty-hold")
        .with_kind(JobKind::Interactive)
        .with_io(JobIo::Pty);
    let id = registry.spawn(spec).expect("tracked");
    wait_running(&registry, id);
    assert_eq!(registry.cancel(id), Ok(JobCancel::Requested));
    let stopped = wait_terminal(&registry, id);
    assert_eq!(
        stopped.state,
        JobState::Done(ExecutionOutcome::Cancelled(CancelEffect::Killed))
    );
}
