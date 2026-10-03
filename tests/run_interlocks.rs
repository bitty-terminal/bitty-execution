//! Execution interlock integration: registry gates wired to live paths.
//!
//! Moved registry-interlock half of the Core `run_wiring.rs` suite (CTX-0720):
//!
//! - #1094: the [`JobRegistry`] agent-command boundary admits the adopted
//!   role sandbox gate ([`AgentRole`]/[`SandboxDecl`]) before tracking.
//! - RUN-22 (#1053): the [`JobRegistry`] input boundary re-checks the
//!   recorded echo state and interaction class on every `write_input_as`
//!   dispatch and refuses with a typed denial while the interlock holds.
//! - RUN-23 (#1054): the [`JobRegistry`] agent-command boundary classifies
//!   every `spawn_as`/`spawn_checked_as` argv with [`classify_argv`] and
//!   refuses hard-deny and consent-gated shapes before tracking, threading,
//!   or execution.
//!
//! Spawned children are this test binary (hermetic, argv-first, no shell),
//! following the `job_capability_ops.rs` precedent. Denied or gated spawns
//! never start a process; allowed spawns run the `quiet` child and are
//! cancelled at the end of the test.
//!
//! The panel-lease half (RUN-21) stays in Core with `PanelRuntime` and is
//! not part of this crate.

use std::time::Duration;

use bitty_execution::{
    EchoState, InteractionClass, JobError, JobPrincipal, JobRegistry, JobSpec, OperationIntent,
};

const HELPER_ENV: &str = "__BITTY_RUN_WIRING_HELPER";

/// Child entry point: selected by `HELPER_ENV`, runs only in spawned
/// children (the parent suite runs it as a no-op and it passes).
#[test]
fn __bitty_run_wiring_helper_entry__() {
    match std::env::var(HELPER_ENV).as_deref() {
        Ok("quiet") => {}
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
            "__bitty_run_wiring_helper_entry__".to_owned(),
            "--nocapture".to_owned(),
        ],
    )
    .with_env(
        bitty_ipc::execution::EnvPolicy::explicit(vec![(HELPER_ENV.to_owned(), mode.to_owned())])
            .expect("explicit env"),
    )
}

fn owner(name: &str) -> JobPrincipal {
    JobPrincipal::new(name).expect("valid principal")
}
// ── #1094: role sandbox gate at the spawn boundary ──────────────────────────

#[test]
fn spawn_role_sandbox_gate() {
    use bitty_plugin_host::roles::{AgentRole, SandboxDecl};

    let registry = JobRegistry::with_capacity(8);
    let principal = owner("run-role-owner");
    let sealed = SandboxDecl::sealed();
    // Reviewers never reach the sandbox point.
    let denial = registry
        .spawn_checked_as_with_role(
            principal.clone(),
            helper_spec("quiet"),
            OperationIntent::Execute,
            AgentRole::Reviewer,
            &sealed,
        )
        .expect_err("reviewer spawns nothing");
    assert!(
        matches!(denial, JobError::Denied { .. }),
        "expected Denied, got {denial:?}"
    );
    // Testers claim nothing beyond sealed.
    let net = SandboxDecl::new(false, true, false, true);
    let denial = registry
        .spawn_checked_as_with_role(
            principal.clone(),
            helper_spec("quiet"),
            OperationIntent::Execute,
            AgentRole::Tester,
            &net,
        )
        .expect_err("tester claims no network");
    assert!(
        matches!(denial, JobError::Denied { .. }),
        "expected Denied, got {denial:?}"
    );
    // A commander with a sealed declaration spawns the quiet child.
    let id = registry
        .spawn_checked_as_with_role(
            principal.clone(),
            helper_spec("quiet"),
            OperationIntent::Execute,
            AgentRole::Commander,
            &sealed,
        )
        .expect("commander sealed spawn");
    let _ = registry.cancel_as(&principal, id);
}

// ── RUN-22: sensitive-input interlock at the input boundary ─────────────────

fn tracked_pipe_job(registry: &JobRegistry, principal: &JobPrincipal) -> bitty_execution::JobId {
    registry
        .spawn_as(principal.clone(), helper_spec("quiet"))
        .expect("pipe job tracked")
}

#[test]
fn input_gate_defaults_to_echo_on_safe() {
    let registry = JobRegistry::with_capacity(8);
    let principal = owner("run22-owner");
    let id = tracked_pipe_job(&registry, &principal);
    assert_eq!(
        registry.job_input_gate(id),
        Ok((EchoState::EchoOn, InteractionClass::SafeInteractive))
    );
    let _ = registry.cancel_as(&principal, id);
}

#[test]
fn input_gate_no_echo_denies_write_through_live_registry() {
    let registry = JobRegistry::with_capacity(8);
    let principal = owner("run22-owner");
    let id = tracked_pipe_job(&registry, &principal);
    registry
        .set_job_input_gate(id, EchoState::NoEcho, InteractionClass::SafeInteractive)
        .expect("host records echo loss");
    // The interlock wins over the stale safe label: text plays no role.
    let denial = registry
        .write_input_as(&principal, id, b"password\r")
        .expect_err("no-echo must deny");
    match &denial {
        JobError::SecureInputDenied { denial, .. } => {
            assert_eq!(denial, "target_in_secure_input_mode");
        }
        other => panic!("expected SecureInputDenied, got {other:?}"),
    }
    // The interlock runs before payload validation: even an empty payload
    // reports the gate, never a payload error.
    assert!(
        matches!(
            registry.write_input_as(&principal, id, b""),
            Err(JobError::SecureInputDenied { .. })
        ),
        "gate precedes payload checks"
    );
    // Restoring echo resumes dispatch: the denial suspended nothing else.
    registry
        .set_job_input_gate(id, EchoState::EchoOn, InteractionClass::SafeInteractive)
        .expect("host records echo restore");
    assert!(
        matches!(
            registry.write_input_as(&principal, id, b"echo-back"),
            Err(JobError::Unsupported { .. })
        ),
        "echo-on safe input passes the gate to backend gating (pipe stdin closed)"
    );
    let _ = registry.cancel_as(&principal, id);
}

#[test]
fn input_gate_confirmation_requires_human() {
    let registry = JobRegistry::with_capacity(8);
    let principal = owner("run22-owner");
    let id = tracked_pipe_job(&registry, &principal);
    registry
        .set_job_input_gate(
            id,
            EchoState::EchoOn,
            InteractionClass::PrivilegedConfirmation,
        )
        .expect("host sorts confirmation class");
    let denial = registry
        .write_input_as(&principal, id, b"yes\r")
        .expect_err("privileged confirmation needs a human");
    match &denial {
        JobError::SecureInputDenied { denial, .. } => {
            assert_eq!(denial, "confirmation_requires_human");
        }
        other => panic!("expected SecureInputDenied, got {other:?}"),
    }
    let _ = registry.cancel_as(&principal, id);
}

#[test]
fn input_gate_stale_secret_label_stays_denied_when_echo_on() {
    let registry = JobRegistry::with_capacity(8);
    let principal = owner("run22-owner");
    let id = tracked_pipe_job(&registry, &principal);
    registry
        .set_job_input_gate(id, EchoState::EchoOn, InteractionClass::SecretInput)
        .expect("host records inconsistent label");
    // An inconsistent label refuses rather than guessing safe.
    assert!(
        matches!(
            registry.write_input_as(&principal, id, b"anything"),
            Err(JobError::SecureInputDenied { .. })
        ),
        "stale secret label stays denied"
    );
    let _ = registry.cancel_as(&principal, id);
}

#[test]
fn input_gate_denies_before_existence_leak() {
    let registry = JobRegistry::with_capacity(8);
    let principal = owner("run22-owner");
    let stranger = owner("run22-stranger");
    let id = tracked_pipe_job(&registry, &principal);
    registry
        .set_job_input_gate(id, EchoState::NoEcho, InteractionClass::SecretInput)
        .expect("host records echo loss");
    // Authorization still runs first: an unauthorized caller learns
    // nothing, not even the gate state.
    assert!(
        matches!(
            registry.write_input_as(&stranger, id, b"probe"),
            Err(JobError::Denied { .. })
        ),
        "denied callers must not observe the interlock"
    );
    assert!(
        matches!(
            registry.set_job_input_gate(
                bitty_execution::JobId::from_raw(999_999).expect("nonzero"),
                EchoState::NoEcho,
                InteractionClass::SecretInput
            ),
            Err(JobError::UnknownJob(..))
        ),
        "gate writes to unknown jobs fail"
    );
    let _ = registry.cancel_as(&principal, id);
}

// ── RUN-23: command-risk verdict at the agent-command boundary ──────────────

#[test]
fn risk_escalation_wrapper_denied_before_tracking() {
    let registry = JobRegistry::with_capacity(8);
    let before = registry.len();
    let denial = registry
        .spawn_as(
            owner("run23-owner"),
            JobSpec::new("sudo", vec!["ls".to_owned()]),
        )
        .expect_err("privilege escalation must deny");
    match &denial {
        JobError::CommandRiskDenied { deny, .. } => {
            assert_eq!(deny, "privilege_escalation");
        }
        other => panic!("expected CommandRiskDenied, got {other:?}"),
    }
    assert_eq!(registry.len(), before, "denied spawn tracks nothing");
}

#[test]
fn risk_broad_root_delete_denied_before_tracking() {
    let registry = JobRegistry::with_capacity(8);
    let before = registry.len();
    let denial = registry
        .spawn_checked_as(
            owner("run23-owner"),
            JobSpec::new("rm", vec!["-rf".to_owned(), "/".to_owned()]),
            OperationIntent::Write,
        )
        .expect_err("broad-root recursive force delete must deny");
    match &denial {
        JobError::CommandRiskDenied { deny, .. } => {
            assert_eq!(deny, "broad_root_delete");
        }
        other => panic!("expected CommandRiskDenied, got {other:?}"),
    }
    assert_eq!(registry.len(), before, "denied spawn tracks nothing");
}

#[test]
fn risk_system_config_write_denied_with_declared_intent() {
    let registry = JobRegistry::with_capacity(8);
    let denial = registry
        .spawn_checked_as(
            owner("run23-owner"),
            JobSpec::new("tee", vec!["/etc/hosts".to_owned()]),
            OperationIntent::Write,
        )
        .expect_err("system-config write must deny");
    assert!(
        matches!(
            denial,
            JobError::CommandRiskDenied { ref deny, .. } if deny == "system_config_write"
        ),
        "expected system_config_write deny, got {denial:?}"
    );
}

#[test]
fn risk_narrow_destructive_shape_needs_consent() {
    let registry = JobRegistry::with_capacity(8);
    let before = registry.len();
    // Fail-closed without a ledger: consent-gated shapes refuse (PP-3 open
    // work), so nothing executes on this answer alone.
    let gated = registry
        .spawn_checked_as(
            owner("run23-owner"),
            JobSpec::new("rm", vec!["-rf".to_owned(), "/tmp/scratch".to_owned()]),
            OperationIntent::Write,
        )
        .expect_err("narrow recursive force delete needs consent");
    match &gated {
        JobError::CommandRiskNeedsConsent { tier, .. } => {
            assert_eq!(tier, "restricted");
        }
        other => panic!("expected CommandRiskNeedsConsent, got {other:?}"),
    }
    assert_eq!(registry.len(), before, "gated spawn tracks nothing");
}

#[test]
fn risk_allow_spawns_and_runs_under_declared_intent() {
    let registry = JobRegistry::with_capacity(8);
    let principal = owner("run23-owner");
    // Unknown binaries sort to Standard and proceed under the caller's
    // scope; the hermetic helper child proves the allow path end to end.
    let id = registry
        .spawn_checked_as(
            principal.clone(),
            helper_spec("quiet"),
            OperationIntent::Execute,
        )
        .expect("standard command allowed");
    assert_eq!(registry.len(), 1, "allowed spawn tracks exactly one job");
    let snapshot = registry.get_as(&principal, id).expect("job observable");
    assert_eq!(snapshot.spec.program, helper_exe());
    let _ = registry.cancel_as(&principal, id);
}

#[test]
fn risk_spec_bounds_checked_before_classification() {
    let registry = JobRegistry::with_capacity(8);
    // An empty executable fails CTX-0442 validation before the kernel ever
    // sees it: bounds first, risk second.
    let refused = registry
        .spawn_as(owner("run23-owner"), JobSpec::new("", vec![]))
        .expect_err("empty program must not classify");
    assert!(
        matches!(refused, JobError::InvalidSpec { .. }),
        "expected InvalidSpec, got {refused:?}"
    );
    assert_eq!(registry.len(), 0, "invalid spec tracks nothing");
}
