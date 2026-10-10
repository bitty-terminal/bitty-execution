//! CTX-0007 conformance: the sidecar-supervision contract against a fake
//! host (execution#14).
//!
//! The fake host below implements [`SidecarSupervisor`] by delegating crash
//! accounting to [`SidecarCrashTracker`]/[`SidecarDeadlineStrikes`] and
//! lifecycle to a [`JobRegistry`], the same composition a Core broker would
//! use when it routes `component/` and `plugin_runtime/spawn.rs` through the
//! seam. Each probe asserts one contract clause: spawn gate, crash latch,
//! bounded deadlines, deadline-strike crash path, legacy cancel, typed
//! cancel with generation fencing, kill scope, and IPC ownership.
//!
//! Real child processes under test are this test binary, selected by an
//! explicit environment variable and reached through argv-first specs:
//! hermetic, portable, and shell-free.

use std::time::{Duration, Instant};

use bitty_execution::{
    CancelOutcome, CancelReceipt, CancelRequest, ExecutionGeneration, ExecutionOutcome, JobCancel,
    JobError, JobId, JobRegistry, JobSnapshot, JobSpec, JobState, KillScope, ProcessTreeBackend,
    SidecarCrashTracker, SidecarDeadlineStrikes, SidecarGate, SidecarIpcProtocol, SidecarPolicy,
    SidecarSupervisor,
};

const HELPER_ENV: &str = "__BITTY_SIDECAR_CONTRACT_HELPER";

/// Child entry point: selected by `HELPER_ENV`, runs only in spawned
/// children (the parent suite runs it as a no-op and it passes).
#[test]
fn __bitty_sidecar_contract_helper_entry__() {
    match std::env::var(HELPER_ENV).as_deref() {
        // Exit immediately without emitting anything.
        Ok("quiet") => {}
        // Stay alive well past every test deadline.
        Ok("sleep") => std::thread::sleep(Duration::from_secs(30)),
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
            "__bitty_sidecar_contract_helper_entry__".to_owned(),
            "--nocapture".to_owned(),
        ],
    )
    .with_env(
        bitty_ipc::execution::EnvPolicy::explicit(vec![(HELPER_ENV.to_owned(), mode.to_owned())])
            .expect("explicit env"),
    )
}

/// Fake host: one supervised sidecar composed of crash accounting plus a job
/// registry, exactly how a Core broker routes one component slot through the
/// seam.
struct FakeSidecarHost {
    policy: SidecarPolicy,
    crashes: SidecarCrashTracker,
    strikes: SidecarDeadlineStrikes,
    registry: JobRegistry,
}

impl FakeSidecarHost {
    fn new() -> Self {
        let policy = SidecarPolicy::core_defaults();
        Self {
            policy,
            crashes: SidecarCrashTracker::with_policy(policy),
            strikes: SidecarDeadlineStrikes::with_policy(policy),
            registry: JobRegistry::new(),
        }
    }
}

impl SidecarSupervisor for FakeSidecarHost {
    fn policy(&self) -> SidecarPolicy {
        self.policy
    }

    fn spawn_gate(&self, now: Instant) -> SidecarGate {
        self.crashes.gate(now)
    }

    fn record_crash(&mut self, now: Instant) -> SidecarGate {
        self.crashes.record_crash(now)
    }

    fn record_deadline_expiry(&mut self) -> bool {
        self.strikes.expire()
    }

    fn note_terminal_frame(&mut self) {
        self.strikes.reset();
    }

    fn cancel_sidecar(
        &self,
        id: JobId,
    ) -> Result<bitty_execution::JobCancel, bitty_execution::JobError> {
        self.registry.cancel(id)
    }

    fn cancel_sidecar_typed(
        &self,
        request: CancelRequest,
    ) -> Result<CancelReceipt, bitty_execution::JobError> {
        self.registry.cancel_typed(request)
    }

    fn kill_scope(&self) -> KillScope {
        KillScope::for_backend(ProcessTreeBackend::detect())
    }
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

#[test]
fn spawn_gate_is_ready_then_backs_off_then_latches() {
    let mut host = FakeSidecarHost::new();
    let t0 = Instant::now();
    assert_eq!(host.spawn_gate(t0), SidecarGate::Ready);
    // Four crashes inside the window: backoff with the doubling delays.
    for (i, expected_secs) in [1, 2, 4, 8].iter().enumerate() {
        let at = t0 + Duration::from_secs(i as u64 * 60);
        assert_eq!(
            host.record_crash(at),
            SidecarGate::Backoff {
                retry_after: Duration::from_secs(*expected_secs)
            },
            "crash {i}"
        );
    }
    // The fifth crash inside five minutes latches unavailable.
    assert_eq!(
        host.record_crash(t0 + Duration::from_secs(4 * 60 + 59)),
        SidecarGate::Unavailable
    );
    assert_eq!(
        host.spawn_gate(t0 + Duration::from_secs(3600)),
        SidecarGate::Unavailable,
        "only a fresh tracker recovers; the gate never reopens by itself"
    );
}

#[test]
fn bounded_deadlines_default_and_clamp_through_the_seam() {
    let host = FakeSidecarHost::new();
    assert_eq!(
        host.effective_deadline(0),
        Duration::from_secs(30),
        "no requested timeout selects the Core default"
    );
    assert_eq!(
        host.effective_deadline(30_000),
        Duration::from_secs(30),
        "the default value is a fixed point"
    );
    assert_eq!(
        host.effective_deadline(u32::MAX),
        Duration::from_secs(300),
        "requests clamp to the Core ceiling"
    );
    assert_eq!(
        host.shutdown_grace(),
        Duration::from_secs(2),
        "stdin-close grace is the Core number"
    );
    assert_eq!(host.policy(), SidecarPolicy::core_defaults());
}

#[test]
fn consecutive_deadline_expiries_take_the_crash_path() {
    let mut host = FakeSidecarHost::new();
    assert!(!host.record_deadline_expiry());
    assert!(!host.record_deadline_expiry());
    host.note_terminal_frame();
    assert!(
        !host.record_deadline_expiry(),
        "a sidecar-produced terminal frame resets the count"
    );
    assert!(!host.record_deadline_expiry());
    assert!(
        host.record_deadline_expiry(),
        "the third consecutive expiry takes the crash path"
    );
}

#[test]
fn legacy_cancel_routes_to_the_registry() {
    let host = FakeSidecarHost::new();
    let id = host.registry.spawn(helper_spec("sleep")).expect("tracked");
    wait_for(&host.registry, id, "running", |snapshot| {
        snapshot.state == JobState::Running
    });
    assert_eq!(host.cancel_sidecar(id), Ok(JobCancel::Requested));
    let stopped = wait_for(&host.registry, id, "a terminal state", |snapshot| {
        snapshot.state.is_terminal()
    });
    assert!(stopped.state.is_terminal());
    // A terminal sidecar observes its stop instead of re-running the kill.
    assert!(matches!(
        host.cancel_sidecar(id),
        Ok(JobCancel::AlreadyStopped(_))
    ));
    let unknown = JobId::from_raw(4_242).expect("non-zero");
    assert_eq!(
        host.cancel_sidecar(unknown),
        Err(JobError::UnknownJob(unknown)),
        "unknown ids fail closed"
    );
}

#[test]
fn typed_cancel_fences_on_the_host_checked_generation() {
    let host = FakeSidecarHost::new();
    let id = host.registry.spawn(helper_spec("sleep")).expect("tracked");
    wait_for(&host.registry, id, "running", |snapshot| {
        snapshot.state == JobState::Running
    });
    let handle = host.registry.get(id).expect("tracked").handle();

    // A stale generation changes nothing.
    let stale_generation =
        ExecutionGeneration::from_raw(handle.generation.get() + 1).expect("non-zero generation");
    let stale = CancelRequest::immediate(bitty_execution::ExecutionHandle {
        id,
        generation: stale_generation,
    });
    assert_eq!(
        host.cancel_sidecar_typed(stale),
        Ok(CancelReceipt::Resolved(CancelOutcome::StaleGeneration))
    );
    assert_eq!(
        host.registry.get(id).expect("tracked").state,
        JobState::Running,
        "a stale cancel must not disturb the sidecar"
    );

    // The current generation is accepted and executed exactly once.
    assert_eq!(
        host.cancel_sidecar_typed(CancelRequest::immediate(handle)),
        Ok(CancelReceipt::Accepted)
    );
    let stopped = wait_for(&host.registry, id, "a terminal state", |snapshot| {
        snapshot.state.is_terminal()
    });
    assert!(stopped.state.is_terminal());

    // A terminal sidecar answers AlreadyExited without touching anything.
    assert_eq!(
        host.cancel_sidecar_typed(CancelRequest::immediate(handle)),
        Ok(CancelReceipt::Resolved(CancelOutcome::AlreadyExited))
    );

    // Unknown ids fail closed.
    let unknown_handle = bitty_execution::ExecutionHandle {
        id: JobId::from_raw(9_119).expect("non-zero"),
        generation: handle.generation,
    };
    assert_eq!(
        host.cancel_sidecar_typed(CancelRequest::immediate(unknown_handle)),
        Err(JobError::UnknownJob(unknown_handle.id))
    );
}

#[test]
fn kill_scope_matches_the_detected_tree_backend() {
    let host = FakeSidecarHost::new();
    let expected = KillScope::for_backend(ProcessTreeBackend::detect());
    assert_eq!(host.kill_scope(), expected);
    // The scope is honest about the platform: a tree backend kills the
    // owned tree, otherwise only the direct child is reachable.
    assert_eq!(
        host.kill_scope() == KillScope::OwnedTree,
        ProcessTreeBackend::detect().kills_owned_tree()
    );
    // A cancelled job really ends: the kill reaches the process.
    let id = host.registry.spawn(helper_spec("sleep")).expect("tracked");
    wait_for(&host.registry, id, "running", |snapshot| {
        snapshot.state == JobState::Running
    });
    assert_eq!(host.cancel_sidecar(id), Ok(JobCancel::Requested));
    let stopped = wait_for(&host.registry, id, "a terminal state", |snapshot| {
        snapshot.state.is_terminal()
    });
    assert!(
        matches!(
            stopped.state,
            JobState::Done(ExecutionOutcome::Cancelled(_))
        ),
        "the kill ends the sidecar with a typed cancel outcome"
    );
}

#[test]
fn component_ipc_protocol_stays_owned_outside_this_repo() {
    assert_eq!(SidecarIpcProtocol::OWNER, "bitty-network");
    assert_eq!(SidecarIpcProtocol::WIRE_CRATE, "bitty-network-wire");
    assert!(
        SidecarIpcProtocol::CARRIER.contains("component"),
        "the carrier names Core's component broker, not this crate"
    );
}
