#![forbid(unsafe_code)]

//! Phase-2 execution supervisor: async jobs plus bounded output,
//! reliable event delivery, capability-scoped operations, persistent
//! metadata with file-held logs, the detached-supervisor contract, and
//! structured outcomes with owned-tree kill and typed cancel
//! (CTX-0511 + CTX-0513 + CTX-0514 + CTX-0516 + CTX-0512).
//!
//! This module is the Core-side foundation of the execution-host boundary
//! (research record 044, captured as DIR-026 in the `bitty-docs` draft
//! `docs/development/execution-host-boundary.md`): a **job** is a
//! first-class, panel-independent object above the PTY/process primitives,
//! and the runtime waits for it — never a model, never a panel, never a
//! polling loop.
//!
//! # What this slice implements
//!
//! - An in-memory, capacity-bounded [`JobRegistry`] with spawn/get/list/
//!   cancel handles and a monotonic [`JobId`] that is never reused.
//! - The spawn-time job model: declared [`JobLifetime`], [`JobKind`],
//!   argv-first execution, closed stdin by default ([`JobIo::Pipes`]) with a
//!   PTY as the explicit interactive opt-in, and separated `hard`/`idle`/
//!   `retention` clocks ([`JobTimeouts`]). No implicit deadline exists for
//!   any kind, so long `Service`/`Watch` jobs are never killed by an
//!   ordinary timeout.
//! - Event-driven lifecycle: one supervisor thread per job observes exit,
//!   cancel, and deadlines, then publishes [`JobEvent`]s into the bounded
//!   two-lane delivery log a runtime can drain or replay across an IPC
//!   disconnect.
//! - Bounded output: per-stream newest-wins byte stores with tail/filter
//!   reads ([`ReadOutput`]) and metadata-only [`OutputIndex`] snapshots, so
//!   raw stdout never grows memory or a database.
//! - Critical/observation delivery: terminal `Stopped` events are
//!   [`EventClass::Critical`] (at-least-once, replayable, acknowledged) and
//!   queue/start notices are [`EventClass::Observation`] (drop-oldest,
//!   UI-only, never a model wake-up).
//! - Capability-scoped operations (CTX-0514): per-principal, per-operation
//!   grants ([`JobPrincipal`], [`JobOperation`]) enforced in-process over
//!   the supervisor handles (`spawn_as`/`get_as`/`list_as`/`read_output_as`/
//!   `output_index_as`/`write_input_as`/`signal_as`/`cancel_as`/`attach_as`/
//!   `grant_as`/`revoke_as`/`transfer_as`/`events_since_as`/
//!   `acknowledge_as`). Deny by default with hidden existence, no
//!   observe/control bundle, no ambient authority; owner/subscriber roles
//!   stay `bitty-ai` coordination re-authorized here, and self-grant
//!   prohibition is the CTX-0524 seam.
//! - Origin is provenance only: [`JobOrigin`] records "started from here"
//!   and no lifecycle path is coupled to it.
//! - Structured outcomes and typed cancel (CTX-0512): terminal states carry
//!   an [`ExecutionOutcome`] (`Success`, `ExitCode`, `Signaled`,
//!   `SpawnFailed`, `Cancelled`, `TimedOut`, `OomKilled`, `SupervisorLost`,
//!   `Unknown`). Kills reach the owned process tree through the
//!   `bitty-pty` boundary ([`bitty_pty::OwnedTree`]: Linux process groups
//!   plus pidfd, macOS process groups plus kqueue, Windows kill-on-close
//!   Job Objects with kill-only delivery) and every snapshot
//!   reports its [`KillScope`]. A [`CancelRequest`] carries the execution
//!   id, the [`ExecutionGeneration`] the host checks, a [`CancelMode`], and
//!   a grace period; the supervisor executes it and publishes one
//!   `JobEvent::CancelResolved` with a typed [`CancelOutcome`].
//! - OOM evidence (CTX-0880, #1537): on Linux, a registry built with
//!   [`JobRegistry::with_job_cgroups`] runs each job in its own cgroup v2
//!   leaf under a dedicated job base inside a cgroup delegated to this
//!   process ([`JobCgroups`]: discovered only as its own cgroup when that is
//!   the cgroup-namespace root or carries systemd's `user.delegate` /
//!   `trusted.delegate` marker, never an ancestor; or configured
//!   explicitly with [`JobCgroups::under`]). The leaf's `memory.events`
//!   `oom_kill` counter is read before the spawn and after the tree is
//!   gone; only an advanced counter plus a `SIGKILL` death the host did not
//!   cause yields `OomKilled` (after a host kill the outcome stays
//!   `Signaled(9)` and the counter survives as evidence). The leader is
//!   placed right after the spawn (no `pre_exec`: `bitty-pty` forbids
//!   `unsafe`), so descendants forked before the placement are not
//!   accounted. Every
//!   snapshot reports [`OomEvidence`]; hosts without delegation, macOS,
//!   and Windows record [`OomEvidence::Missing`] with a typed
//!   [`OomEvidenceGap`] and keep [`OomVerdict::Unknown`]. A signal number
//!   is never evidence.
//!
//! # Deliberate non-goals (sibling tasks own them)
//!
//! - Windows graceful stop: Job Objects carry no polite stop request.
//!   `signal_as(Interrupt | Terminate)` and a `CancelMode::Graceful` cancel
//!   resolve to a typed `Unsupported` (never a single-pid kill); a
//!   `CancelMode::GracefulThenKill` cancel skips both grace periods and
//!   kills the tree at once. A ConPTY child's descendants created before
//!   its post-spawn job assignment escape the tree (CTX-0903 residual gap).
//! - Windows job lifetime: the kill-on-close Job Object handle belongs to
//!   this process, so when it exits or crashes every live job tree dies
//!   with it, `JobLifetime::Detached` and service jobs included; Unix
//!   process groups outlive this process. The divergence is documented,
//!   not resolved (open decision).
//! - Job resource limits (CTX-0519): the per-job cgroup leaf below is an
//!   evidence source only; no `memory.max` or other limit is set on it.
//! - Capability enforcement transport: this task is in-process only, with no
//!   new IPC verbs. The existing IPC scope/auth registry plus the
//!   consent/effect gate stays the transport boundary; these `*_as` methods
//!   are what that boundary calls after authenticating the principal.
//!   Effective-capability intersection and self-grant prohibition across
//!   agent/plugin requests is the CTX-0524 seam (noted, not implemented).
//! - Persistence, restart reconciliation, and the detached supervisor
//!   contract: CTX-0516. [`JobStore`] checkpoints metadata plus the
//!   metadata-only [`OutputIndex`] into a versioned manifest with retained
//!   output spilled to per-job log files held by reference (never raw bytes
//!   in the manifest); [`reconcile`] maps live-at-crash rows onto
//!   [`ResumeDecision::UnknownOutcome`]; [`SupervisorDaemon`] owns one
//!   supervised directory at a time with handoff/adoption and
//!   [`SchedulePolicy`] admission. Grants are re-issued after a restart
//!   (never persisted) and adoption never respawns by itself.
//!
//! # Invariants
//!
//! - AI-agnostic vocabulary: no `AgentId`/`TaskId`/LLM/prompt symbol.
//! - Bounds: program/args/cwd/env reuse the accepted CTX-0442 limits by
//!   delegating to `ExecutionRequest::validate`; registry size, delivery
//!   lanes, output bytes, read shapes, provenance, and deadlines are bounded
//!   or explicit, and overflow fails closed. Critical terminal events have
//!   their own lane so observation pressure can never mask a `Stopped`.
//! - No shell: specs are argv-first and processes are built with
//!   [`std::process::Command`] directly; nothing routes through `bash -c`.
//! - No zombie or wedged child: every supervisor path kills what is left of
//!   the owned tree, reaps the leader, and joins the pipe drains (time-boxed)
//!   before the terminal event, so the output store is quiescent unless a
//!   member escaped the tree (`setsid`/`setpgid`) and still holds a pipe.
//!   A job's own network failure is recorded as the observed outcome plus
//!   retained stderr facts; no separate `network_error` classification is
//!   invented.
//!
//! # Candidate signals (CTX-0678, RUN-20..RUN-23 analysis batch)
//!
//! - Sensitive-input gate ([`automated_input_allowed`]): the observed PTY
//!   echo state is the only signal for OQ-086; no-echo denies automated
//!   input with a typed denial and excludes capture. A verdict-fed sort
//!   (`classify_with_verdict`) composes the OQ-087 answer (SI-5 seam)
//!   without touching dispatch.
//! - Command-risk kernel ([`classify_argv`]): structural argv tiers and
//!   hard-deny classes for OQ-087; shell-AST resolution stays open work.
//!   Verdict projections (`RiskVerdict::tier`,
//!   `RiskVerdict::requires_explicit_decision`) feed the OQ-086 seam.
//! - Detached-supervisor trust boundary: analysis only
//!   (`specifications/run-20-detached-supervisor-trust-boundary.md`); no
//!   daemon code, per the accepted headless/daemon decision.

mod atomic_file;
mod cgroup;
mod claim_lock;
mod command_risk;
mod delivery;
mod model;
mod oom;
mod outcome;
mod output;
mod persistence;
mod process_tree;
mod registry;
mod retention;
mod sensitive_input;
mod sidecar;
mod supervisor;

pub use cgroup::{CgroupUnavailable, JobCgroups, MAX_JOB_CGROUP_LEAVES, MAX_STALE_BASE_SWEEP};
pub use command_risk::{HardDeny, OperationIntent, RiskTier, RiskVerdict, classify_argv};
pub use delivery::{
    DeliveryState, EventClass, EventReplay, MAX_EVENT_REPLAY, MAX_STORED_CRITICAL_EVENTS,
    MAX_STORED_OBSERVATION_EVENTS, StoredEvent,
};
pub use model::{
    AttachReceipt, DEFAULT_RETENTION_TTL, JobCancel, JobError, JobEvent, JobGrant, JobId, JobIo,
    JobKind, JobLifetime, JobOperation, JobOrigin, JobPrincipal, JobSignal, JobSnapshot, JobSpec,
    JobState, JobTimeouts, MAX_GRANTS_PER_JOB, MAX_JOB_ORIGIN_BYTES, MAX_JOB_PRINCIPAL_BYTES,
    MAX_SIGNAL_WINDOW_MS, MAX_SIGNALS_PER_WINDOW, MAX_WRITE_INPUT_BYTES, MAX_WRITE_INPUT_WINDOW_MS,
    MAX_WRITES_PER_WINDOW, SignalOutcome, TransferReceipt,
};
pub use oom::{
    MAX_MEMORY_EVENTS_BYTES, OomEvidence, OomEvidenceGap, OomVerdict, classify_oom,
    parse_oom_kill_count,
};
pub use outcome::{
    CancelEffect, CancelMode, CancelOutcome, CancelReceipt, CancelRequest, DEFAULT_CANCEL_GRACE_MS,
    DeadlineClock, ExecutionGeneration, ExecutionHandle, ExecutionOutcome, ExitObservation,
    MAX_CANCEL_GRACE_MS,
};
pub use output::{
    MAX_OUTPUT_BYTES_PER_JOB, MAX_READ_BYTES, MAX_READ_LINES, OutputFilter, OutputIndex,
    OutputStream, OutputView, ReadOutput,
};
pub use persistence::{
    CheckpointSummary, IdAllocator, JobStore, PersistError, PersistedJob, PersistedStore,
    ReconciledJob, ResumeCursor, ResumeDecision, reconcile,
};
pub use persistence::{
    LOGS_DIR_NAME, MANIFEST_FILE_NAME, MAX_LOG_FILE_BYTES, MAX_MANIFEST_BYTES, MAX_PERSISTED_JOBS,
    PERSIST_FORMAT_VERSION,
};
pub use process_tree::{KillScope, ProcessTreeBackend};
pub use registry::{DEFAULT_MAX_JOBS, JobRegistry, MAX_STORED_JOB_EVENTS};
pub use retention::{MAX_RETENTION_TTL, RetentionError, RetentionPolicy, RetentionTier};
pub use sensitive_input::{
    EchoState, InteractionClass, SecureInputDenial, automated_input_allowed, classify_with_verdict,
    may_capture,
};
pub use sidecar::{
    SidecarCrashTracker, SidecarDeadlineStrikes, SidecarGate, SidecarIpcProtocol, SidecarPolicy,
    SidecarStopOutcome, SidecarSupervisor,
};
pub use supervisor::{
    AdoptedJob, AdoptionKind, DaemonError, HandoffOffer, ScheduleDecision, SchedulePolicy,
    SupervisorDaemon, adoption_plan, clear_handoff, read_handoff, write_handoff,
};
pub use supervisor::{
    CLAIM_LOCK_TIMEOUT_MS, DEFAULT_MAX_RUNNING, HANDOFF_FILE_NAME, MAX_HANDOFF_BYTES,
    MAX_HANDOFF_JOBS, MAX_HEARTBEAT_BYTES, MAX_LOCK_BYTES, MAX_SCHEDULE_RUNNING,
    STALE_HEARTBEAT_MS, SUPERVISOR_CLAIM_NAME, SUPERVISOR_FORMAT_VERSION,
    SUPERVISOR_HEARTBEAT_NAME, SUPERVISOR_LOCK_NAME, SUPERVISOR_LOCK_VERSION,
};
