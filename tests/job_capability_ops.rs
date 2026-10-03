//! CTX-0514 integration: capability-scoped job operations over real processes.
//!
//! Every child under test is this test binary, selected by an explicit
//! environment variable and reached through an argv-first job spec:
//! hermetic, portable, and shell-free (no `sh`/`sleep` PATH dependency), so
//! the same file runs on Unix and Windows CI. The one exception is the Unix
//! signal-storm target: `/bin/sh` ignores `SIGINT` and `exec`s the helper
//! (which inherits the ignored disposition), because signals now really
//! reach the job's owned tree (CTX-0512) and the storm must not end it.
//!
//! Hostile probes live here too: an unauthorized principal that tries to
//! cancel, read, signal, attach, write, grant, or transfer is denied without
//! learning whether the job exists; a forged transfer never moves ownership;
//! a cross-scope attach never observes another principal's job; and a signal
//! storm is rate-limited without disturbing other operations.

use std::time::{Duration, Instant};

use bitty_execution::{
    AttachReceipt, CancelEffect, ExecutionOutcome, JobCancel, JobError, JobGrant, JobId, JobIo,
    JobKind, JobOperation, JobPrincipal, JobRegistry, JobSignal, JobSnapshot, JobSpec, JobState,
    KillScope, OutputStream, ReadOutput, SignalOutcome, TransferReceipt,
};
use bitty_test_support::require_pty;

const HELPER_ENV: &str = "__BITTY_JOB_CAP_HELPER";

/// Child entry point: selected by `HELPER_ENV`, runs only in spawned
/// children (the parent suite runs it as a no-op and it passes).
#[test]
fn __bitty_job_cap_helper_entry__() {
    match std::env::var(HELPER_ENV).as_deref() {
        // Exit immediately without emitting anything.
        Ok("quiet") => {}
        // Stay alive well past every test deadline.
        Ok("sleep") => std::thread::sleep(Duration::from_secs(30)),
        // Echo each stdin line back with a marker prefix, then exit on EOF.
        // The `got:` prefix distinguishes child output from PTY input echo.
        // NOTE: this arm reads the PTY **slave** stdin (what the child sees
        // after the line discipline), so the test child must run under a PTY
        // job (`JobIo::Pty`); a pipe job would see EOF immediately.
        Ok("echo-stdin") => {
            use std::io::BufRead as _;
            let stdin = std::io::stdin();
            for line in stdin.lock().lines() {
                match line {
                    Ok(text) => {
                        println!("got:{text}");
                        use std::io::Write as _;
                        let _ = std::io::stdout().flush();
                    }
                    Err(_) => break,
                }
            }
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
            "__bitty_job_cap_helper_entry__".to_owned(),
            "--nocapture".to_owned(),
        ],
    )
    .with_env(
        bitty_ipc::execution::EnvPolicy::explicit(vec![(HELPER_ENV.to_owned(), mode.to_owned())])
            .expect("explicit env"),
    )
}

/// A sleeping job that survives the signal storm: on Unix `/bin/sh` sets
/// `SIGINT` to ignored and `exec`s the helper; elsewhere no owned tree
/// exists and signals are refused, so the plain helper is enough.
fn storm_target_spec() -> JobSpec {
    #[cfg(unix)]
    {
        JobSpec::new(
            "/bin/sh",
            vec![
                "-c".to_owned(),
                "trap '' INT; exec \"$0\" __bitty_job_cap_helper_entry__ --nocapture".to_owned(),
                helper_exe(),
            ],
        )
        .with_env(
            bitty_ipc::execution::EnvPolicy::explicit(vec![(
                HELPER_ENV.to_owned(),
                "sleep".to_owned(),
            )])
            .expect("explicit env"),
        )
    }
    #[cfg(not(unix))]
    {
        helper_spec("sleep")
    }
}

fn owner(name: &str) -> JobPrincipal {
    JobPrincipal::new(name).expect("valid principal")
}

fn wait_for(
    registry: &JobRegistry,
    principal: &JobPrincipal,
    id: JobId,
    what: &str,
    predicate: impl Fn(&JobSnapshot) -> bool,
) -> JobSnapshot {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let snapshot = registry.get_as(principal, id).expect("job stays tracked");
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

fn wait_running(registry: &JobRegistry, principal: &JobPrincipal, id: JobId) -> JobSnapshot {
    wait_for(registry, principal, id, "running", |snapshot| {
        snapshot.state == JobState::Running
    })
}

fn wait_terminal(registry: &JobRegistry, principal: &JobPrincipal, id: JobId) -> JobSnapshot {
    wait_for(registry, principal, id, "a terminal state", |snapshot| {
        snapshot.state.is_terminal()
    })
}

fn is_denied_for(result: &Result<impl Sized, JobError>, operation: &str) -> bool {
    matches!(
        result,
        Err(JobError::Denied {
            operation: op,
            ..
        }) if op == operation
    )
}

// ── hostile: unauthorized cancel ────────────────────────────────────────────

#[test]
fn unauthorized_cancel_is_denied_and_job_survives() {
    let registry = JobRegistry::new();
    let spawner = owner("owner-a");
    let stranger = owner("stranger");
    let id = registry
        .spawn_as(spawner.clone(), helper_spec("sleep"))
        .expect("tracked");
    wait_running(&registry, &spawner, id);

    let denied = registry.cancel_as(&stranger, id);
    assert!(
        is_denied_for(&denied, "cancel"),
        "stranger cancel must be denied, got {denied:?}"
    );

    // The denied request changed nothing: the job is still running.
    let snapshot = registry.get_as(&spawner, id).expect("tracked");
    assert_eq!(snapshot.state, JobState::Running);

    // The owner path still works.
    assert_eq!(registry.cancel_as(&spawner, id), Ok(JobCancel::Requested));
    let stopped = wait_terminal(&registry, &spawner, id);
    assert_eq!(
        stopped.state,
        JobState::Done(ExecutionOutcome::Cancelled(CancelEffect::Killed))
    );
}

// ── hostile: unauthorized signal ────────────────────────────────────────────

#[test]
fn unauthorized_signal_is_denied() {
    let registry = JobRegistry::new();
    let spawner = owner("owner-a");
    let stranger = owner("stranger");
    let id = registry
        .spawn_as(spawner.clone(), helper_spec("sleep"))
        .expect("tracked");
    wait_running(&registry, &spawner, id);

    let denied = registry.signal_as(&stranger, id, JobSignal::Terminate);
    assert!(
        is_denied_for(&denied, "signal"),
        "stranger signal must be denied, got {denied:?}"
    );
    assert_eq!(registry.cancel_as(&spawner, id), Ok(JobCancel::Requested));
}

// ── hostile: signal storm ───────────────────────────────────────────────────

#[test]
fn signal_storm_is_rate_limited_without_disturbing_other_operations() {
    let registry = JobRegistry::new();
    let spawner = owner("owner-a");
    let id = registry
        .spawn_as(spawner.clone(), storm_target_spec())
        .expect("tracked");
    let live = wait_running(&registry, &spawner, id);

    // The burst budget is consumed by authorized calls, then fails closed.
    // With a Unix owned tree every burst signal is delivered (and ignored by
    // the target); without one, or on a Windows Job Object (kill-only),
    // delivery is refused, which still counts against the budget: the
    // limiter guards the intent path, not just successful deliveries.
    for _ in 0..bitty_execution::MAX_SIGNALS_PER_WINDOW {
        let burst = registry.signal_as(&spawner, id, JobSignal::Interrupt);
        if cfg!(unix) && live.kill_scope == KillScope::OwnedTree {
            assert_eq!(
                burst,
                Ok(SignalOutcome::Delivered),
                "burst reaches the tree"
            );
        } else {
            assert!(
                matches!(burst, Err(JobError::Unsupported { .. })),
                "without a tree the burst is refused, got {burst:?}"
            );
        }
    }
    let limited = registry.signal_as(&spawner, id, JobSignal::Interrupt);
    assert!(
        matches!(limited, Err(JobError::SignalRateLimited { .. })),
        "signal storm must be rate-limited, got {limited:?}"
    );

    // Denied strangers never consume the owner's budget and never pass: the
    // limiter counts authorized calls only, and auth runs before limiting.
    let stranger = owner("stranger");
    let denied = registry.signal_as(&stranger, id, JobSignal::Kill);
    assert!(
        is_denied_for(&denied, "signal"),
        "stranger signal must be denied, got {denied:?}"
    );

    // Other operations are isolated from the signal budget.
    assert!(
        registry.get_as(&spawner, id).is_ok(),
        "observe must survive a signal storm"
    );
    assert_eq!(registry.cancel_as(&spawner, id), Ok(JobCancel::Requested));
}

// ── hostile: cross-principal read ───────────────────────────────────────────

#[test]
fn cross_principal_read_is_denied() {
    let registry = JobRegistry::new();
    let spawner = owner("owner-a");
    let stranger = owner("stranger");
    let id = registry
        .spawn_as(spawner.clone(), helper_spec("quiet"))
        .expect("tracked");
    wait_terminal(&registry, &spawner, id);

    let denied = registry.read_output_as(&stranger, id, ReadOutput::new(OutputStream::Stdout));
    assert!(
        is_denied_for(&denied, "read_output"),
        "stranger read must be denied, got {denied:?}"
    );
    let denied_index = registry.output_index_as(&stranger, id);
    assert!(
        is_denied_for(&denied_index, "read_output"),
        "stranger output index must be denied, got {denied_index:?}"
    );

    // The owner path still reads. The quiet child writes nothing itself,
    // but the test-harness child entry still emits its harness summary line
    // on stdout (like every test-binary child), so assert ownership by
    // readability — not by byte emptiness.
    let view = registry
        .read_output_as(&spawner, id, ReadOutput::new(OutputStream::Stdout))
        .expect("owner reads");
    let _ = view;
    let index = registry.output_index_as(&spawner, id).expect("owner index");
    let _ = index;
}

// ── hostile: denial hides existence ─────────────────────────────────────────

#[test]
fn denial_hides_job_existence_from_unauthorized_principals() {
    let registry = JobRegistry::new();
    let spawner = owner("owner-a");
    let stranger = owner("stranger");
    let id = registry
        .spawn_as(spawner.clone(), helper_spec("quiet"))
        .expect("tracked");
    wait_terminal(&registry, &spawner, id);
    let unknown = JobId::from_raw(9_999).expect("non-zero");

    // A stranger gets the same denial for a real job and a never-issued id:
    // no existence oracle.
    assert!(is_denied_for(&registry.get_as(&stranger, id), "observe"));
    assert!(is_denied_for(
        &registry.get_as(&stranger, unknown),
        "observe"
    ));
    assert!(is_denied_for(
        &registry.cancel_as(&stranger, unknown),
        "cancel"
    ));
    // The stranger's list is empty even though a job exists.
    assert!(registry.list_as(&stranger).is_empty());
    // The owner's list still shows the job.
    assert_eq!(registry.list_as(&spawner).len(), 1);
}

// ── hostile: forged grant and transfer ──────────────────────────────────────

#[test]
fn forged_grant_and_transfer_are_denied() {
    let registry = JobRegistry::new();
    let spawner = owner("owner-a");
    let stranger = owner("stranger");
    let accomplice = owner("accomplice");
    let id = registry
        .spawn_as(spawner.clone(), helper_spec("sleep"))
        .expect("tracked");
    wait_running(&registry, &spawner, id);

    // A stranger cannot grant itself cancel: granting needs `transfer`.
    let forged = registry.grant_as(
        &stranger,
        id,
        JobGrant::new(stranger.clone(), JobOperation::Cancel),
    );
    assert!(
        is_denied_for(&forged, "transfer"),
        "forged grant must be denied, got {forged:?}"
    );
    // A stranger cannot seize ownership either.
    let seized: Result<TransferReceipt, JobError> =
        registry.transfer_as(&stranger, id, accomplice.clone());
    assert!(
        is_denied_for(&seized, "transfer"),
        "forged transfer must be denied, got {seized:?}"
    );

    // Neither forgery conferred anything: the stranger still cannot cancel.
    assert!(is_denied_for(&registry.cancel_as(&stranger, id), "cancel"));
    assert!(is_denied_for(
        &registry.cancel_as(&accomplice, id),
        "cancel"
    ));

    assert_eq!(registry.cancel_as(&spawner, id), Ok(JobCancel::Requested));
}

// ── delegation: grant, use, revoke ──────────────────────────────────────────

#[test]
fn owner_can_delegate_cancel_and_revoke_it() {
    let registry = JobRegistry::new();
    let spawner = owner("owner-a");
    let reviewer = owner("reviewer-b");
    let id = registry
        .spawn_as(spawner.clone(), helper_spec("sleep"))
        .expect("tracked");
    wait_running(&registry, &spawner, id);

    registry
        .grant_as(
            &spawner,
            id,
            JobGrant::new(reviewer.clone(), JobOperation::Cancel),
        )
        .expect("owner delegates cancel");
    assert_eq!(
        registry.cancel_as(&reviewer, id),
        Ok(JobCancel::Requested),
        "delegated cancel must work"
    );
    wait_terminal(&registry, &spawner, id);

    // A fresh job shows revoke takes the right back away.
    let second = registry
        .spawn_as(spawner.clone(), helper_spec("sleep"))
        .expect("tracked");
    wait_running(&registry, &spawner, second);
    registry
        .grant_as(
            &spawner,
            second,
            JobGrant::new(reviewer.clone(), JobOperation::Cancel),
        )
        .expect("delegate again");
    assert!(
        registry
            .revoke_as(
                &spawner,
                second,
                &JobGrant::new(reviewer.clone(), JobOperation::Cancel),
            )
            .expect("revoke"),
        "revoke must report a removed grant"
    );
    assert!(is_denied_for(
        &registry.cancel_as(&reviewer, second),
        "cancel"
    ));
    assert_eq!(
        registry.cancel_as(&spawner, second),
        Ok(JobCancel::Requested)
    );
}

// ── hostile: grant cannot exceed what the granter holds ─────────────────────

#[test]
fn grant_exceeding_held_rights_is_denied() {
    let registry = JobRegistry::new();
    let spawner = owner("owner-a");
    let reviewer = owner("reviewer-b");
    let accomplice = owner("accomplice");
    let id = registry
        .spawn_as(spawner.clone(), helper_spec("sleep"))
        .expect("tracked");
    wait_running(&registry, &spawner, id);

    // The reviewer holds only `observe`: delegating `cancel` must fail.
    registry
        .grant_as(
            &spawner,
            id,
            JobGrant::new(reviewer.clone(), JobOperation::Observe),
        )
        .expect("delegate observe");
    let over_grant = registry.grant_as(
        &reviewer,
        id,
        JobGrant::new(accomplice.clone(), JobOperation::Cancel),
    );
    assert!(
        is_denied_for(&over_grant, "transfer"),
        "over-grant must be denied, got {over_grant:?}"
    );
    assert!(is_denied_for(
        &registry.cancel_as(&accomplice, id),
        "cancel"
    ));

    assert_eq!(registry.cancel_as(&spawner, id), Ok(JobCancel::Requested));
}

// ── transfer moves ownership and fences the old owner ───────────────────────

#[test]
fn transfer_moves_ownership_and_fences_the_old_owner() {
    let registry = JobRegistry::new();
    let previous = owner("owner-a");
    let successor = owner("owner-b");
    let id = registry
        .spawn_as(previous.clone(), helper_spec("sleep"))
        .expect("tracked");
    wait_running(&registry, &previous, id);

    let receipt = registry
        .transfer_as(&previous, id, successor.clone())
        .expect("owner transfers");
    assert_eq!(
        receipt,
        TransferReceipt {
            job: id,
            previous_owner: previous.clone(),
            new_owner: successor.clone(),
        }
    );

    // The old owner is fenced: every operation is now denied.
    assert!(is_denied_for(&registry.get_as(&previous, id), "observe"));
    assert!(is_denied_for(&registry.cancel_as(&previous, id), "cancel"));
    // The successor holds the full set through ownership.
    assert!(
        registry.get_as(&successor, id).is_ok(),
        "successor must observe"
    );
    assert_eq!(
        registry.cancel_as(&successor, id),
        Ok(JobCancel::Requested),
        "successor must cancel"
    );
}

// ── no blanket grant: six of seven is not seven ─────────────────────────────

#[test]
fn no_blanket_grant_covers_the_missing_operation() {
    let registry = JobRegistry::new();
    let spawner = owner("owner-a");
    let delegate = owner("delegate");
    let id = registry
        .spawn_as(spawner.clone(), helper_spec("sleep"))
        .expect("tracked");
    wait_running(&registry, &spawner, id);

    for operation in [
        JobOperation::Observe,
        JobOperation::ReadOutput,
        JobOperation::WriteInput,
        JobOperation::Signal,
        JobOperation::Cancel,
        JobOperation::Attach,
    ] {
        registry
            .grant_as(&spawner, id, JobGrant::new(delegate.clone(), operation))
            .expect("delegate one operation");
    }
    // Six grants do not imply the seventh: `transfer` stays denied.
    let seized: Result<TransferReceipt, JobError> =
        registry.transfer_as(&delegate, id, owner("someone-else"));
    assert!(
        is_denied_for(&seized, "transfer"),
        "missing transfer must stay denied, got {seized:?}"
    );
    // But a granted operation works.
    assert!(
        registry.get_as(&delegate, id).is_ok(),
        "granted observe must work"
    );

    assert_eq!(registry.cancel_as(&spawner, id), Ok(JobCancel::Requested));
}

// ── attach: scoped and liveness-gated ───────────────────────────────────────

#[test]
fn attach_requires_attach_and_a_live_job() {
    let registry = JobRegistry::new();
    let spawner = owner("owner-a");
    let stranger = owner("stranger");
    let id = registry
        .spawn_as(spawner.clone(), helper_spec("sleep"))
        .expect("tracked");
    wait_running(&registry, &spawner, id);

    let denied: Result<AttachReceipt, JobError> = registry.attach_as(&stranger, id, 0);
    assert!(
        is_denied_for(&denied, "attach"),
        "stranger attach must be denied, got {denied:?}"
    );

    let receipt = registry.attach_as(&spawner, id, 0).expect("owner attaches");
    assert_eq!(receipt.job, id);

    // A cursor past the event head fails closed.
    let bad_cursor = registry.attach_as(&spawner, id, u64::MAX);
    assert!(
        matches!(bad_cursor, Err(JobError::InvalidCursor { .. })),
        "over-head attach cursor must fail closed, got {bad_cursor:?}"
    );

    assert_eq!(registry.cancel_as(&spawner, id), Ok(JobCancel::Requested));
    wait_terminal(&registry, &spawner, id);
    let terminal_attach = registry.attach_as(&spawner, id, 0);
    assert!(
        matches!(terminal_attach, Err(JobError::Unsupported { .. })),
        "attach to a terminal job must report unsupported, got {terminal_attach:?}"
    );
}

// ── write_input: PTY delivery proof for the owner, denial for strangers ─────
//
// Live-PTY delivery runs through the same spawned-helper harness the rest
// of the suite uses (no controlling terminal required): the child is this
// test binary in `echo-stdin` mode under a real PTY (`JobIo::Pty`), the
// owner writes one line, and the `got:`-prefixed echo in the bounded output
// store proves the bytes reached child stdin rather than just looping back
// as PTY input echo.
#[cfg(unix)]
#[test]
fn write_input_reaches_a_pty_job_for_the_owner_only() {
    require_pty!();
    let registry = JobRegistry::new();
    let spawner = owner("owner-a");
    let stranger = owner("stranger");
    let spec = helper_spec("echo-stdin")
        .with_kind(JobKind::Interactive)
        .with_io(JobIo::Pty);
    let id = registry.spawn_as(spawner.clone(), spec).expect("tracked");
    wait_running(&registry, &spawner, id);
    // The supervisor publishes the PTY writer half just after marking
    // `Running` (same thread, back-to-back): poll briefly so the write does
    // not race the handoff. A claim during the gap fails closed with
    // `Unsupported` — never a block — so retrying is safe.
    let deadline = Instant::now() + Duration::from_secs(10);
    let written = loop {
        match registry.write_input_as(&spawner, id, b"hello\n") {
            Ok(n) => break n,
            Err(JobError::Unsupported { .. }) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(other) => panic!("owner writes to PTY stdin, got {other:?}"),
        }
    };
    assert_eq!(written, b"hello\n".len());

    // Strangers deny even once the writer half is live (auth before gating).
    let denied = registry.write_input_as(&stranger, id, b"hello\n");
    assert!(
        is_denied_for(&denied, "write_input"),
        "stranger write must be denied, got {denied:?}"
    );

    // A racing claim consumes one write-budget call even when the writer is
    // not yet published (auth passed, the call entered the gate): assert the
    // delivered byte count, not the budget state.

    // The child echoes the line back with its marker prefix, proving the
    // bytes reached stdin (not just the PTY input echo). PTY output carries
    // carriage returns from the line discipline, so match the marker plus
    // the payload loosely rather than byte-exactly.
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let view = registry
            .read_output_as(&spawner, id, ReadOutput::new(OutputStream::Stdout))
            .expect("owner reads");
        if view.text.contains("got:") && view.text.contains("hello") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "PTY child never echoed the written line"
        );
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(registry.cancel_as(&spawner, id), Ok(JobCancel::Requested));
}

// Windows runs the same delivery proof as Unix through the spawned-helper
// harness: the child is this test binary in `echo-stdin` mode under ConPTY
// (`JobIo::Pty`), the owner writes one line, and the `got:`-prefixed echo in
// the bounded output store proves the bytes reached child stdin rather than
// just looping back as PTY input echo. (`more` cannot serve here: it is a
// pager that buffers stdin until EOF or a full screen and emits nothing while
// stdin stays open, so a marker poll against it can never succeed.)
#[cfg(windows)]
#[test]
fn write_input_reaches_a_pty_job_for_the_owner_only() {
    require_pty!();
    let registry = JobRegistry::new();
    let spawner = owner("owner-a");
    let stranger = owner("stranger");
    let spec = helper_spec("echo-stdin")
        .with_kind(JobKind::Interactive)
        .with_io(JobIo::Pty);
    let id = registry.spawn_as(spawner.clone(), spec).expect("tracked");
    wait_running(&registry, &spawner, id);
    // Same writer-half handoff poll as the Unix variant: the supervisor
    // publishes the PTY writer just after marking `Running`, and a claim
    // during the gap fails closed with `Unsupported` — never a block.
    let deadline = Instant::now() + Duration::from_secs(10);
    let written = loop {
        match registry.write_input_as(&spawner, id, b"hello-bitty-write\r\n") {
            Ok(n) => break n,
            Err(JobError::Unsupported { .. }) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(other) => panic!("owner writes to PTY stdin, got {other:?}"),
        }
    };
    assert_eq!(written, b"hello-bitty-write\r\n".len());

    // Strangers deny even once the writer half is live (auth before gating).
    let denied = registry.write_input_as(&stranger, id, b"hello-bitty-write\r\n");
    assert!(
        is_denied_for(&denied, "write_input"),
        "stranger write must be denied, got {denied:?}"
    );

    // The child echoes the line back with its marker prefix, proving the
    // bytes reached stdin (not just the ConPTY input echo, which never
    // carries the `got:` prefix). PTY output carries carriage returns from
    // the line discipline, so match the marker plus the payload loosely
    // rather than byte-exactly. The drain proves delivery first: poll the
    // metadata index until the stdout byte total grows past the startup
    // banner, and only then read the text — otherwise a quiet store is
    // indistinguishable from a store the drain has not fed yet, and the
    // 20 s deadline burns on a scheduling race instead of child progress.
    // A console client gates its reads on our cursor replies: answer each
    // pending DSR with a CPR so a blocked child can proceed (win469d).
    let baseline = registry
        .output_index_as(&spawner, id)
        .expect("owner reads index")
        .stdout_total_bytes;
    let mut baseline = baseline;
    let mut answered = 0usize;
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let view = registry
            .read_output_as(&spawner, id, ReadOutput::new(OutputStream::Stdout))
            .expect("owner reads");
        if view.text.contains("got:") && view.text.contains("hello-bitty-write") {
            break;
        }
        // Answer any pending cursor queries before they can stall the child.
        let requests = view.text.matches("\u{1b}[6n").count();
        if requests > answered {
            answered = requests;
            match registry.write_input_as(&spawner, id, b"\x1b[1;1R") {
                Ok(_) => {}
                Err(JobError::RateLimited { .. }) => {}
                Err(other) => panic!("DSR reply must be accepted, got {other:?}"),
            }
            // A reply does not produce marker bytes by itself, so the
            // settle gate below must not treat the CPR round-trip as child
            // progress: re-baseline to everything observed so far.
            baseline = registry
                .output_index_as(&spawner, id)
                .expect("owner reads index")
                .stdout_total_bytes;
            continue;
        }
        let index = registry
            .output_index_as(&spawner, id)
            .expect("owner reads index");
        if index.stdout_total_bytes > baseline {
            break;
        }
        // Diagnose the ConPTY backend instead of just timing out: report
        // the child lifecycle state plus how many stdout bytes ever landed.
        assert!(
            Instant::now() < deadline,
            "PTY child never echoed the written line (state={:?}, total={} stored={} text_head={:?})",
            registry.get_as(&spawner, id).map(|snapshot| snapshot.state),
            view.total_bytes,
            view.stored_bytes,
            view.text.chars().take(80).collect::<String>(),
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let view = registry
            .read_output_as(&spawner, id, ReadOutput::new(OutputStream::Stdout))
            .expect("owner reads");
        if view.text.contains("got:") && view.text.contains("hello-bitty-write") {
            break;
        }
        // Diagnose the ConPTY backend instead of just timing out: report
        // the child lifecycle state plus how many stdout bytes ever landed.
        assert!(
            Instant::now() < deadline,
            "PTY child never echoed the written line (state={:?}, total={} stored={} text_head={:?})",
            registry.get_as(&spawner, id).map(|snapshot| snapshot.state),
            view.total_bytes,
            view.stored_bytes,
            view.text.chars().take(80).collect::<String>(),
        );
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(registry.cancel_as(&spawner, id), Ok(JobCancel::Requested));
}

// The deadlock regression probe: an authorized write must never wedge the
// registry for other callers. One thread performs the live-PTY write while
// the main thread races `cancel_as`/`get_as` against it; both sides finish
// inside bounded deadlines and the registry stays usable afterwards.
#[test]
fn concurrent_write_races_cancel_and_observe_without_wedging_the_registry() {
    require_pty!();
    let registry = JobRegistry::new();
    let spawner = owner("owner-a");
    #[cfg(unix)]
    let spec = helper_spec("sleep")
        .with_kind(JobKind::Interactive)
        .with_io(JobIo::Pty);
    #[cfg(windows)]
    let spec = {
        use bitty_ipc::execution::EnvPolicy;
        JobSpec::new("powershell.exe".to_owned(), vec!["-NoExit".to_owned()])
            .with_kind(JobKind::Interactive)
            .with_io(JobIo::Pty)
            .with_env(EnvPolicy::explicit(Vec::new()).expect("explicit env"))
    };
    let id = registry.spawn_as(spawner.clone(), spec).expect("tracked");
    wait_running(&registry, &spawner, id);
    // Settle the writer-half handoff before the race so the write exercises
    // the blocking-PTY-write success path (not the starting-gap refusal).
    let publish_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match registry.write_input_as(&spawner, id, b"probe\n") {
            Ok(_) => break,
            Err(JobError::Unsupported { .. }) if Instant::now() < publish_deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(other) => panic!("writer-half handoff never published, got {other:?}"),
        }
    }
    let worker = {
        let registry = registry.clone();
        let spawner = spawner.clone();
        std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                match registry.write_input_as(&spawner, id, b"stress\n") {
                    Ok(_) => return true,
                    Err(JobError::RateLimited { .. }) | Err(JobError::Unsupported { .. })
                        if Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => return false,
                }
            }
        })
    };
    let race_deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let _ = registry.get_as(&spawner, id);
        if worker.is_finished() {
            break;
        }
        assert!(
            Instant::now() < race_deadline,
            "registry wedged: racing get_as never observed the write finish"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    let delivered = worker.join().expect("writer thread joins");
    assert!(delivered, "authorized concurrent write must succeed");
    // The registry is still live for the same job after the race.
    assert!(
        registry.get_as(&spawner, id).is_ok(),
        "registry must stay usable after a racing write"
    );
    assert_eq!(registry.cancel_as(&spawner, id), Ok(JobCancel::Requested));
    let stopped = wait_terminal(&registry, &spawner, id);
    assert_eq!(
        stopped.state,
        JobState::Done(ExecutionOutcome::Cancelled(CancelEffect::Killed))
    );
}

#[test]
fn write_input_to_a_pipes_job_reports_closed_stdin() {
    let registry = JobRegistry::new();
    let spawner = owner("owner-a");
    let id = registry
        .spawn_as(spawner.clone(), helper_spec("sleep"))
        .expect("tracked");
    wait_running(&registry, &spawner, id);

    // Pipe jobs run with closed stdin by design: the authorized call reports
    // the mechanism truth instead of pretending to deliver.
    let closed = registry.write_input_as(&spawner, id, b"hello\n");
    assert!(
        matches!(closed, Err(JobError::Unsupported { .. })),
        "pipes write must report closed stdin, got {closed:?}"
    );

    assert_eq!(registry.cancel_as(&spawner, id), Ok(JobCancel::Requested));
}

// ── signal allow-path: enforcement passes, delivery reaches the tree ─────────

#[test]
fn authorized_signal_on_a_live_job_reaches_its_owned_tree() {
    let registry = JobRegistry::new();
    let spawner = owner("owner-a");
    let id = registry
        .spawn_as(spawner.clone(), helper_spec("sleep"))
        .expect("tracked");
    let live = wait_running(&registry, &spawner, id);

    // The owner holds `signal`, so enforcement passes and the kill reaches
    // the job's owned tree. Without an owned-tree backend delivery is
    // refused (never sent to a single pid) — and never denied.
    let delivered = registry.signal_as(&spawner, id, JobSignal::Kill);
    if live.kill_scope != KillScope::OwnedTree {
        assert!(
            matches!(delivered, Err(JobError::Unsupported { .. })),
            "without a tree the signal is refused, got {delivered:?}"
        );
        assert_eq!(registry.cancel_as(&spawner, id), Ok(JobCancel::Requested));
        return;
    }
    assert_eq!(delivered, Ok(SignalOutcome::Delivered));
    let stopped = wait_terminal(&registry, &spawner, id);
    // Windows has no signals: `TerminateJobObject` ends the tree with the
    // backend's kill exit code (1, as `Child::kill`), never a signal.
    #[cfg(unix)]
    assert!(
        matches!(stopped.state, JobState::Done(ExecutionOutcome::Signaled(_))),
        "an external kill is a signaled outcome, got {:?}",
        stopped.state
    );
    #[cfg(windows)]
    assert_eq!(
        stopped.state,
        JobState::Done(ExecutionOutcome::ExitCode(1)),
        "a Job Object kill is the kill exit code"
    );
    assert_eq!(
        registry.signal_as(&spawner, id, JobSignal::Kill),
        Ok(SignalOutcome::AlreadyStopped(
            stopped.state.outcome().expect("done")
        ))
    );
}

// ── events stay scoped to observable jobs ───────────────────────────────────

#[test]
fn events_since_and_acknowledge_are_scoped_to_observable_jobs() {
    let registry = JobRegistry::new();
    let spawner = owner("owner-a");
    let stranger = owner("stranger");
    let id = registry
        .spawn_as(spawner.clone(), helper_spec("quiet"))
        .expect("tracked");
    wait_terminal(&registry, &spawner, id);

    // A stranger observes nothing: no events, and ack reveals nothing.
    let replay = registry
        .events_since_as(&stranger, 0, 64)
        .expect("scoped replay never fails for strangers");
    assert!(
        replay.events.is_empty(),
        "stranger must see no events, got {:?}",
        replay.events
    );
    let ack_denied = registry.acknowledge_as(&stranger, 1);
    assert!(
        is_denied_for(&ack_denied, "observe"),
        "stranger ack must be denied, got {ack_denied:?}"
    );

    // The owner sees the lifecycle and can close the loop.
    let owned = registry
        .events_since_as(&spawner, 0, 64)
        .expect("owner replays");
    assert!(
        owned.events.iter().any(|stored| stored.job() == id),
        "owner must see the job lifecycle"
    );
    let first_seq = owned.events.first().expect("at least one event").seq();
    assert!(
        registry.acknowledge_as(&spawner, first_seq).is_ok(),
        "owner ack must work"
    );
}

// ── hostile: unauthorized write, attach, grant, and event paths ─────────────

#[test]
fn unauthorized_write_attach_and_grant_are_denied() {
    let registry = JobRegistry::new();
    let spawner = owner("owner-a");
    let stranger = owner("stranger");
    let id = registry
        .spawn_as(spawner.clone(), helper_spec("sleep"))
        .expect("tracked");
    wait_running(&registry, &spawner, id);

    // Every non-granted operation denies with its own operation name, and
    // none of them disturbs the job.
    assert!(is_denied_for(
        &registry.write_input_as(&stranger, id, b"hello\n"),
        "write_input"
    ));
    assert!(is_denied_for(
        &registry.attach_as(&stranger, id, 0),
        "attach"
    ));
    assert!(is_denied_for(
        &registry.grant_as(
            &stranger,
            id,
            JobGrant::new(stranger.clone(), JobOperation::Observe),
        ),
        "transfer"
    ));
    assert!(is_denied_for(
        &registry.revoke_as(
            &stranger,
            id,
            &JobGrant::new(spawner.clone(), JobOperation::Observe),
        ),
        "transfer"
    ));
    assert!(is_denied_for(
        &registry.read_output_as(&stranger, id, ReadOutput::new(OutputStream::Stderr)),
        "read_output"
    ));

    // The job is untouched and the owner path still works.
    assert_eq!(
        registry.get_as(&spawner, id).expect("tracked").state,
        JobState::Running
    );
    assert_eq!(registry.cancel_as(&spawner, id), Ok(JobCancel::Requested));
}

// ── hostile: write_input validation and rate limiting ───────────────────────

#[test]
fn write_input_validation_and_rate_limit_fail_closed() {
    let registry = JobRegistry::new();
    let spawner = owner("owner-a");
    // A pipe job keeps the payload path deterministic: validation runs
    // before backend gating, so over-bound/empty payloads fail as
    // `InvalidWrite` even though the backend would refuse anyway.
    let id = registry
        .spawn_as(spawner.clone(), helper_spec("sleep"))
        .expect("tracked");
    wait_running(&registry, &spawner, id);

    // Empty and over-bound payloads fail closed without spending budget.
    assert!(matches!(
        registry.write_input_as(&spawner, id, b""),
        Err(JobError::InvalidWrite { .. })
    ));
    assert!(matches!(
        registry.write_input_as(
            &spawner,
            id,
            &vec![b'x'; bitty_execution::MAX_WRITE_INPUT_BYTES + 1]
        ),
        Err(JobError::InvalidWrite { .. })
    ));

    // A stranger's over-bound payload still denies (auth before validation):
    // no validation oracle for unauthorized callers.
    let stranger = owner("stranger");
    assert!(is_denied_for(
        &registry.write_input_as(&stranger, id, b""),
        "write_input"
    ));

    assert_eq!(registry.cancel_as(&spawner, id), Ok(JobCancel::Requested));
}

// ── hostile: principal validation edges ─────────────────────────────────────

#[test]
fn principal_validation_edges_fail_closed() {
    // Empty, over-bound, control-byte, and DEL names all fail.
    assert!(matches!(
        JobPrincipal::new(""),
        Err(JobError::InvalidPrincipal { .. })
    ));
    assert!(matches!(
        JobPrincipal::new("p".repeat(bitty_execution::MAX_JOB_PRINCIPAL_BYTES + 1)),
        Err(JobError::InvalidPrincipal { .. })
    ));
    for bad in ["bad\x00name", "bad\x1fname", "bad\x7fname", "line\nbreak"] {
        assert!(
            matches!(
                JobPrincipal::new(bad),
                Err(JobError::InvalidPrincipal { .. })
            ),
            "principal {bad:?} must fail validation"
        );
    }
    // Boundary and printable-ASCII names pass.
    assert!(JobPrincipal::new("p".repeat(bitty_execution::MAX_JOB_PRINCIPAL_BYTES)).is_ok());
    assert!(JobPrincipal::new("owner-a_09.~-+@=").is_ok());

    // Operations have stable wire names and no blanket scope exists.
    for operation in JobOperation::all() {
        assert!(!operation.as_str().is_empty());
        assert_eq!(operation.to_string(), operation.as_str());
    }
    assert_eq!(JobOperation::all().len(), 8);
}

// ── hostile: unknown ids deny identically (no existence oracle) ─────────────

#[test]
fn unknown_ids_deny_identically_for_unauthorized_callers() {
    let registry = JobRegistry::new();
    let spawner = owner("owner-a");
    let stranger = owner("stranger");
    let unknown = JobId::from_raw(9_999).expect("non-zero");
    let id = registry
        .spawn_as(spawner.clone(), helper_spec("quiet"))
        .expect("tracked");
    wait_terminal(&registry, &spawner, id);

    // The stranger cannot distinguish a real job from a never-issued id on
    // any operation: every path denies with the same operation name.
    assert!(is_denied_for(&registry.get_as(&stranger, id), "observe"));
    assert!(is_denied_for(
        &registry.get_as(&stranger, unknown),
        "observe"
    ));
    assert!(is_denied_for(&registry.cancel_as(&stranger, id), "cancel"));
    assert!(is_denied_for(
        &registry.cancel_as(&stranger, unknown),
        "cancel"
    ));
    assert!(is_denied_for(
        &registry.signal_as(&stranger, id, JobSignal::Kill),
        "signal"
    ));
    assert!(is_denied_for(
        &registry.signal_as(&stranger, unknown, JobSignal::Kill),
        "signal"
    ));
    assert!(is_denied_for(
        &registry.read_output_as(&stranger, unknown, ReadOutput::new(OutputStream::Stdout)),
        "read_output"
    ));
    assert!(is_denied_for(
        &registry.write_input_as(&stranger, unknown, b"x"),
        "write_input"
    ));
    assert!(is_denied_for(
        &registry.attach_as(&stranger, unknown, 0),
        "attach"
    ));
    let seized: Result<TransferReceipt, JobError> =
        registry.transfer_as(&stranger, unknown, owner("accomplice"));
    assert!(is_denied_for(&seized, "transfer"));
    // Invalid cursors still fail closed for strangers with scoped replay
    // (an empty view, never an error that leaks the head).
    assert!(
        registry
            .events_since_as(&stranger, 0, 64)
            .expect("scoped")
            .events
            .is_empty()
    );
}
