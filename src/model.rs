//! Job model for the phase-1 execution supervisor (CTX-0511).
//!
//! Pure data and shape validation: identity, spawn-time declarations, the
//! lifecycle state machine, and the bounded observation records. Nothing in
//! this module spawns a process, starts a thread, or reads the clock; the
//! [`registry`](crate::registry) owns supervision.
//!
//! # Boundary
//!
//! The vocabulary is deliberately generic (OQ-061, research 044 §7 §12 §13):
//! jobs carry execution ids, opaque provenance, lifetimes, kinds, and limits;
//! no `AgentId`/`TaskId`/LLM/prompt symbol exists here. Binding jobs to
//! semantic tasks is `bitty-ai` semantics; this side only executes and
//! observes.
//!
//! # Outcomes
//!
//! Terminal states carry the authoritative [`ExecutionOutcome`] (CTX-0512,
//! defined in [`outcome`](crate::outcome) with the typed cancel protocol and
//! execution generations); output retention is CTX-0513; capability
//! enforcement is CTX-0514.

use std::fmt;
use std::num::NonZeroU64;
use std::time::Duration;

use bitty_ipc::execution::{EnvPolicy, ExecutionRequest};

use crate::oom::OomEvidence;
use crate::outcome::{CancelOutcome, ExecutionGeneration, ExecutionHandle, ExecutionOutcome};
use crate::process_tree::KillScope;

/// Maximum provenance bytes for one job origin.
pub const MAX_JOB_ORIGIN_BYTES: usize = 256;

/// Retention applied when a spec does not declare one: a finished record
/// stays observable for this long before it becomes evictable.
///
/// Callers override per job through [`JobTimeouts::retention`]; a zero
/// duration makes a finished record evictable immediately.
pub const DEFAULT_RETENTION_TTL: Duration = Duration::from_secs(60);

// ── identity ────────────────────────────────────────────────────────────────

/// Stable identity of a supervised job.
///
/// Allocated by the [`JobRegistry`](crate::JobRegistry), never chosen by the
/// caller. Ids are unique for the lifetime of the process and are never
/// reused, including after a finished record is evicted: a stale id fails
/// closed as [`JobError::UnknownJob`] instead of pointing at a new job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JobId(NonZeroU64);

impl JobId {
    /// Wraps a raw non-zero id for lookup.
    ///
    /// Returns `None` for zero; the registry never accepts caller-chosen ids
    /// at spawn, so this is a lookup/attribution constructor only.
    #[must_use]
    pub const fn from_raw(raw: u64) -> Option<Self> {
        match NonZeroU64::new(raw) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Raw id value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

impl fmt::Display for JobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "job-{}", self.0.get())
    }
}

// ── spawn-time declarations ─────────────────────────────────────────────────

/// Cleanup lifetime declared at spawn (research 044 §12).
///
/// The caller chooses the lifetime; the host owns the cleanup mechanism. In
/// phase 1 the declaration is recorded and observable, but no agent/task/
/// workspace lifecycle source exists yet to trigger cleanup, so no automatic
/// cancellation is wired (see the module boundary).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum JobLifetime {
    /// Cancel when the owning agent goes away.
    Agent,
    /// Continue while the owning task lives.
    Task,
    /// Continue while the owning workspace lives.
    Workspace,
    /// Continue under the supervisor, independent of any owner.
    #[default]
    Detached,
}

impl JobLifetime {
    /// Stable lowercase wire/display name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Task => "task",
            Self::Workspace => "workspace",
            Self::Detached => "detached",
        }
    }
}

/// What a job is expected to do with its life (research 044 §13).
///
/// `Service` and `Watch` jobs are expected not to exit; the supervisor never
/// infers a hang from a long life and never applies an implicit deadline to
/// any kind. Deadlines exist only when the caller declares them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum JobKind {
    /// An ordinary command expected to finish.
    #[default]
    Command,
    /// An interactive program driven through a PTY.
    Interactive,
    /// A long-running service expected to stay up.
    Service,
    /// A long-running observer expected to stay up.
    Watch,
}

impl JobKind {
    /// Stable lowercase wire/display name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Command => "command",
            Self::Interactive => "interactive",
            Self::Service => "service",
            Self::Watch => "watch",
        }
    }
}

/// The job's I/O backend.
///
/// [`JobIo::Pipes`] is the default and the only backend non-interactive jobs
/// may use: closed stdin (`/dev/null`), piped stdout/stderr. [`JobIo::Pty`]
/// is the explicit interactive opt-in required by
/// [`JobKind::Interactive`], giving the child a controlling terminal with
/// writable input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum JobIo {
    /// Closed stdin plus stdout/stderr pipes (safe default).
    #[default]
    Pipes,
    /// Pseudo-terminal with writable stdin (interactive opt-in only).
    ///
    /// PTY children inherit the session environment by the terminal
    /// primitive's accepted contract (DEC-0017); explicit environment
    /// entries are overrides, never isolation.
    Pty,
}

impl JobIo {
    /// Stable lowercase wire/display name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pipes => "pipes",
            Self::Pty => "pty",
        }
    }
}

/// Separated supervision clocks (research 044 §12).
///
/// There is deliberately no "background jobs die after one hour" rule: every
/// field defaults to `None` (no deadline), and each field means exactly one
/// thing.
///
/// - `hard`: absolute supervision deadline; the supervisor terminates the
///   job when it elapses.
/// - `idle`: no stdout/stderr activity for this long; the supervisor
///   terminates the job when it elapses.
/// - `retention`: how long a finished record stays observable before it
///   becomes evictable; `None` selects [`DEFAULT_RETENTION_TTL`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct JobTimeouts {
    /// Absolute deadline from spawn (`Some(Duration::ZERO)` is rejected).
    pub hard: Option<Duration>,
    /// Output-idle deadline (`Some(Duration::ZERO)` is rejected).
    pub idle: Option<Duration>,
    /// Finished-record retention (`Some(Duration::ZERO)` evicts eagerly).
    pub retention: Option<Duration>,
}

impl JobTimeouts {
    /// Sets the absolute deadline.
    #[must_use]
    pub const fn with_hard(mut self, hard: Duration) -> Self {
        self.hard = Some(hard);
        self
    }

    /// Sets the activity-idle deadline.
    #[must_use]
    pub const fn with_idle(mut self, idle: Duration) -> Self {
        self.idle = Some(idle);
        self
    }

    /// Sets the finished-record retention.
    #[must_use]
    pub const fn with_retention(mut self, retention: Duration) -> Self {
        self.retention = Some(retention);
        self
    }

    /// Retention to apply when the record reaches a terminal state.
    #[must_use]
    pub fn effective_retention(&self) -> Duration {
        self.retention.unwrap_or(DEFAULT_RETENTION_TTL)
    }
}

/// Opaque provenance for a job (research 044 §8).
///
/// An origin panel is "where it was started from", never ownership: jobs do
/// not belong to panels, closing the origin does not end the job, and
/// nothing in the model links a job's lifecycle to this value. It is bounded
/// display/attribution metadata only.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct JobOrigin {
    panel: Option<String>,
}

impl JobOrigin {
    /// No recorded provenance.
    #[must_use]
    pub const fn none() -> Self {
        Self { panel: None }
    }

    /// Provenance naming the panel a job was started from.
    #[must_use]
    pub fn panel(id: impl Into<String>) -> Self {
        Self {
            panel: Some(id.into()),
        }
    }

    /// The recorded panel id, when present.
    #[must_use]
    pub fn panel_id(&self) -> Option<&str> {
        self.panel.as_deref()
    }

    fn validate(&self) -> Result<(), JobError> {
        let Some(panel) = &self.panel else {
            return Ok(());
        };
        if panel.len() > MAX_JOB_ORIGIN_BYTES {
            return Err(JobError::invalid_spec(format!(
                "job origin panel id exceeds {MAX_JOB_ORIGIN_BYTES} bytes"
            )));
        }
        if panel.contains('\0') {
            return Err(JobError::invalid_spec("job origin must not contain NUL"));
        }
        Ok(())
    }
}

/// Bounded spawn-time declaration of one job.
///
/// The argument surface reuses the accepted CTX-0442 bounds and argv-first
/// shape (no shell is ever constructed), and the synchronous per-request
/// deadline does not apply — job deadlines are the supervisor-owned
/// [`JobTimeouts`]. Pipe jobs run with the closed [`EnvPolicy`] like the
/// synchronous surface; PTY jobs inherit the session environment by the
/// accepted terminal contract (DEC-0017) with explicit entries as overrides,
/// so an isolated PTY job is rejected instead of silently inheriting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobSpec {
    /// Executable path or name (argv[0]).
    pub program: String,
    /// Argument vector; never shell-interpreted.
    pub args: Vec<String>,
    /// Working directory; `None` means the platform default.
    pub cwd: Option<String>,
    /// Environment policy (closed for pipes, overrides for PTY jobs).
    pub env: EnvPolicy,
    /// Expected lifecycle shape.
    pub kind: JobKind,
    /// Declared cleanup lifetime.
    pub lifetime: JobLifetime,
    /// I/O backend.
    pub io: JobIo,
    /// Separated supervision clocks.
    pub timeouts: JobTimeouts,
    /// Bounded provenance metadata.
    pub origin: JobOrigin,
}

impl JobSpec {
    /// A pipe-backed `Command` job with isolated environment, no deadlines,
    /// and no provenance.
    #[must_use]
    pub fn new(program: impl Into<String>, args: Vec<String>) -> Self {
        Self {
            program: program.into(),
            args,
            cwd: None,
            env: EnvPolicy::Isolated,
            kind: JobKind::Command,
            lifetime: JobLifetime::Detached,
            io: JobIo::Pipes,
            timeouts: JobTimeouts::default(),
            origin: JobOrigin::none(),
        }
    }

    /// Sets the working directory.
    #[must_use]
    pub fn with_cwd(mut self, cwd: Option<String>) -> Self {
        self.cwd = cwd;
        self
    }

    /// Sets the closed environment policy.
    #[must_use]
    pub fn with_env(mut self, env: EnvPolicy) -> Self {
        self.env = env;
        self
    }

    /// Sets the expected kind.
    #[must_use]
    pub const fn with_kind(mut self, kind: JobKind) -> Self {
        self.kind = kind;
        self
    }

    /// Sets the declared cleanup lifetime.
    #[must_use]
    pub const fn with_lifetime(mut self, lifetime: JobLifetime) -> Self {
        self.lifetime = lifetime;
        self
    }

    /// Sets the I/O backend.
    #[must_use]
    pub const fn with_io(mut self, io: JobIo) -> Self {
        self.io = io;
        self
    }

    /// Sets the separated supervision clocks.
    #[must_use]
    pub const fn with_timeouts(mut self, timeouts: JobTimeouts) -> Self {
        self.timeouts = timeouts;
        self
    }

    /// Sets the provenance metadata.
    #[must_use]
    pub fn with_origin(mut self, origin: JobOrigin) -> Self {
        self.origin = origin;
        self
    }

    /// Validates the spec shape (fail-closed, no side effects).
    ///
    /// # Errors
    ///
    /// Returns [`JobError::InvalidSpec`] when the argv/cwd/env surface
    /// violates the accepted CTX-0442 bounds, when the kind/I/O pair is
    /// inconsistent, when a PTY job declares an isolated environment, when a
    /// hard/idle deadline is zero, or when provenance is over-bound.
    pub fn validate(&self) -> Result<(), JobError> {
        // Reuse the accepted CTX-0442 shape/bounds for program/args/cwd/env
        // instead of re-deriving them. `timeout_ms` of the temporary request
        // stays at its default; job deadlines are supervisor-owned and are
        // not clamped by the synchronous request ceiling.
        let request = ExecutionRequest::new(self.program.clone(), self.args.clone())
            .with_cwd(self.cwd.clone())
            .with_env_policy(self.env.clone());
        request
            .validate()
            .map_err(|error| JobError::invalid_spec(error.to_string()))?;

        match (self.kind == JobKind::Interactive, self.io) {
            (true, JobIo::Pty) | (false, JobIo::Pipes) => {}
            (true, JobIo::Pipes) => {
                return Err(JobError::invalid_spec(
                    "interactive jobs require the PTY io backend (explicit opt-in)",
                ));
            }
            (false, JobIo::Pty) => {
                return Err(JobError::invalid_spec(
                    "only interactive jobs may request the PTY io backend",
                ));
            }
        }
        if self.io == JobIo::Pty && self.env.is_isolated() {
            // `PtyBuilder` inherits the session environment by accepted
            // terminal contract (DEC-0017) and cannot clear it today, so an
            // isolated PTY job cannot be honored; fail closed instead of
            // silently inheriting ambient variables. An explicit policy on a
            // PTY job means "these entries override the inherited session
            // environment", never "closed".
            return Err(JobError::invalid_spec(
                "PTY jobs inherit the session environment; an isolated policy cannot be honored",
            ));
        }
        validate_deadline("hard_timeout", self.timeouts.hard)?;
        validate_deadline("idle_timeout", self.timeouts.idle)?;
        self.origin.validate()?;
        Ok(())
    }
}

fn validate_deadline(name: &str, value: Option<Duration>) -> Result<(), JobError> {
    if matches!(value, Some(duration) if duration.is_zero()) {
        return Err(JobError::invalid_spec(format!("{name} must be non-zero")));
    }
    Ok(())
}

// ── lifecycle ───────────────────────────────────────────────────────────────

/// Lifecycle state of one job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobState {
    /// Accepted and tracked; the supervisor has not started the process yet.
    Queued,
    /// The OS process exists and is being supervised.
    Running,
    /// Terminal state with the authoritative structured outcome.
    Done(ExecutionOutcome),
}

impl JobState {
    /// Whether the state is terminal.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Done(_))
    }

    /// The outcome of a terminal state.
    #[must_use]
    pub const fn outcome(self) -> Option<ExecutionOutcome> {
        match self {
            Self::Done(outcome) => Some(outcome),
            Self::Queued | Self::Running => None,
        }
    }

    /// Stable lowercase class name (`queued`/`running`/`done`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Done(_) => "done",
        }
    }
}

/// One lifecycle observation emitted by the supervisor.
///
/// Events are ordered per job (`Queued` -> `Started` -> `Stopped`) and
/// timestamped with epoch milliseconds; an executed cancel adds exactly one
/// `CancelResolved` (before `Stopped` when the cancel ended the job).
/// Delivery classes, replay, and acknowledgement are CTX-0513's lanes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobEvent {
    /// The job was accepted into the registry with state [`JobState::Queued`].
    Queued {
        /// Job the event belongs to.
        id: JobId,
        /// Event time (epoch milliseconds).
        at_ms: u64,
    },
    /// The process started and the job entered [`JobState::Running`].
    Started {
        /// Job the event belongs to.
        id: JobId,
        /// Event time (epoch milliseconds).
        at_ms: u64,
    },
    /// The host finished executing an accepted cancel request.
    CancelResolved {
        /// Job the event belongs to.
        id: JobId,
        /// Typed result of the executed request.
        outcome: CancelOutcome,
        /// Event time (epoch milliseconds).
        at_ms: u64,
    },
    /// The job reached a terminal state.
    Stopped {
        /// Job the event belongs to.
        id: JobId,
        /// Authoritative structured outcome.
        outcome: ExecutionOutcome,
        /// Event time (epoch milliseconds).
        at_ms: u64,
    },
}

impl JobEvent {
    /// Job the event belongs to.
    #[must_use]
    pub const fn id(self) -> JobId {
        match self {
            Self::Queued { id, .. }
            | Self::Started { id, .. }
            | Self::CancelResolved { id, .. }
            | Self::Stopped { id, .. } => id,
        }
    }

    /// Event time (epoch milliseconds).
    #[must_use]
    pub const fn at_ms(self) -> u64 {
        match self {
            Self::Queued { at_ms, .. }
            | Self::Started { at_ms, .. }
            | Self::CancelResolved { at_ms, .. }
            | Self::Stopped { at_ms, .. } => at_ms,
        }
    }
}

/// Bounded, owned view of one tracked job.
///
/// The snapshot clones the spawn-time spec, so both are bounded by the
/// CTX-0442 argv/cwd/env limits; the registry never retains more specs than
/// its capacity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobSnapshot {
    /// Job identity.
    pub id: JobId,
    /// Current lifecycle state.
    pub state: JobState,
    /// Spawn-time declaration (unchanged after spawn).
    pub spec: JobSpec,
    /// Start time (epoch milliseconds), once started.
    pub started_at_ms: Option<u64>,
    /// Terminal time (epoch milliseconds), once stopped.
    pub finished_at_ms: Option<u64>,
    /// Metadata-only output index (CTX-0513): exact byte totals and
    /// truncation flags; never raw bytes.
    pub output: crate::output::OutputIndex,
    /// Execution generation minted at spawn: with [`JobSnapshot::id`] it
    /// forms the [`ExecutionHandle`] the host checks on cancel.
    pub generation: ExecutionGeneration,
    /// What a kill reaches for this job: [`KillScope::OwnedTree`] once an
    /// owned-tree backend adopted the process, else
    /// [`KillScope::DirectChild`] (the gap is surfaced, never hidden).
    pub kill_scope: KillScope,
    /// OOM evidence (CTX-0880): [`OomEvidence::Tracked`] while the job runs
    /// in its own cgroup leaf, the final reading once it stopped, or
    /// [`OomEvidence::Missing`] with the reason no evidence exists.
    pub oom_evidence: OomEvidence,
}

impl JobSnapshot {
    /// Host handle for this execution (id plus generation).
    #[must_use]
    pub const fn handle(&self) -> ExecutionHandle {
        ExecutionHandle {
            id: self.id,
            generation: self.generation,
        }
    }
}

/// Result of an accepted legacy cancel request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobCancel {
    /// The request was recorded; the supervisor kills the owned tree, emits
    /// `CancelResolved`, and then `Stopped`.
    Requested,
    /// The job was already terminal; nothing changed.
    AlreadyStopped(ExecutionOutcome),
}

// ── capability-scoped operations (CTX-0514) ───────────────────────────────────

/// Maximum bytes for one job principal name.
pub const MAX_JOB_PRINCIPAL_BYTES: usize = 64;

/// Maximum bytes accepted in one `write_input` call.
pub const MAX_WRITE_INPUT_BYTES: usize = 64 * 1024;

/// Maximum `write_input` calls one principal may issue to one job in the
/// current [`MAX_WRITE_INPUT_WINDOW_MS`] window.
pub const MAX_WRITES_PER_WINDOW: u64 = 128;

/// Rate-limit window for `write_input`, in milliseconds.
pub const MAX_WRITE_INPUT_WINDOW_MS: u64 = 1_000;

/// Maximum `signal` calls one principal may issue to one job in the
/// current [`MAX_SIGNAL_WINDOW_MS`] window.
///
/// Signals name kill intents, so the burst budget is tighter than the
/// `write_input` data path; beyond it the call fails closed with
/// [`JobError::SignalRateLimited`] and the job is untouched.
pub const MAX_SIGNALS_PER_WINDOW: u64 = 32;

/// Rate-limit window for `signal`, in milliseconds.
pub const MAX_SIGNAL_WINDOW_MS: u64 = 1_000;

/// Maximum explicit `(principal, operation)` grants tracked on one job.
///
/// Delegation is bounded like every other registry resource: beyond this a
/// grant fails closed with [`JobError::GrantsFull`] and the owner revokes a
/// stale grant (or transfers ownership) first. Ownership itself is implicit
/// and never counts here.
pub const MAX_GRANTS_PER_JOB: usize = 64;

/// A generic execution principal (research 044 §3, repo layout).
///
/// The execution subsystem stays AI-agnostic: this is an opaque caller
/// identity the host authorizes, never an `AgentId`/`TaskId`/LLM symbol.
/// Binding a principal to agent/task semantics is `bitty-ai` coordination;
/// this side only enforces per-principal, per-operation grants.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JobPrincipal(String);

impl JobPrincipal {
    /// Wraps an opaque caller identity.
    ///
    /// # Errors
    ///
    /// Returns [`JobError::InvalidPrincipal`] when `name` is empty,
    /// over-bound, or carries control bytes.
    pub fn new(name: impl Into<String>) -> Result<Self, JobError> {
        let name = name.into();
        if name.is_empty() {
            return Err(JobError::InvalidPrincipal {
                reason: "job principal must not be empty".into(),
            });
        }
        if name.len() > MAX_JOB_PRINCIPAL_BYTES {
            return Err(JobError::InvalidPrincipal {
                reason: format!("job principal exceeds {MAX_JOB_PRINCIPAL_BYTES} bytes"),
            });
        }
        if name.bytes().any(|b| b < 0x20 || b == 0x7F) {
            return Err(JobError::InvalidPrincipal {
                reason: "job principal must not contain control bytes".into(),
            });
        }
        Ok(Self(name))
    }

    /// The opaque identity string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for JobPrincipal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One independently grantable job operation (research 044 §3).
///
/// Every operation is its own capability: holding seven of the eight grants
/// never implies the eighth, and no blanket scope exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JobOperation {
    /// Observe lifecycle state: `get`, `list`, event replay, acknowledge.
    Observe,
    /// Spawn a job under a role-checked sandbox declaration (OQ-057).
    Spawn,
    /// Read retained output bytes and the metadata-only output index.
    ReadOutput,
    /// Write bytes to an interactive job's stdin.
    WriteInput,
    /// Deliver a portable signal request to a live job.
    Signal,
    /// Request job termination (typed cancel executed by the host on the
    /// owned tree, CTX-0512).
    Cancel,
    /// Subscribe to a live job's event cursor (reconnect-aware tail).
    Attach,
    /// Move job ownership (grant delegation plus ownership transfer).
    Transfer,
}

impl JobOperation {
    /// Stable lowercase wire/display name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::Spawn => "spawn",
            Self::ReadOutput => "read_output",
            Self::WriteInput => "write_input",
            Self::Signal => "signal",
            Self::Cancel => "cancel",
            Self::Attach => "attach",
            Self::Transfer => "transfer",
        }
    }

    /// All eight operations in a deterministic order.
    #[must_use]
    pub const fn all() -> &'static [JobOperation] {
        &[
            Self::Observe,
            Self::Spawn,
            Self::ReadOutput,
            Self::WriteInput,
            Self::Signal,
            Self::Cancel,
            Self::Attach,
            Self::Transfer,
        ]
    }
}

impl fmt::Display for JobOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A delegation of one operation on one job to one principal.
///
/// Narrow by construction: exactly one `(principal, operation)` pair. Grants
/// never widen: a principal can delegate only operations it currently holds,
/// and holding every operation but one never implies the missing one.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JobGrant {
    /// Principal the operation is delegated to.
    pub principal: JobPrincipal,
    /// Operation being delegated.
    pub operation: JobOperation,
}

impl JobGrant {
    /// One narrow delegation pair.
    #[must_use]
    pub const fn new(principal: JobPrincipal, operation: JobOperation) -> Self {
        Self {
            principal,
            operation,
        }
    }
}

/// A portable signal request (research 044 §4).
///
/// The host delivers it to the job's owned tree (the whole process group,
/// CTX-0512); jobs without an owned-tree backend refuse delivery with
/// [`JobError::Unsupported`] rather than signal a single pid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JobSignal {
    /// Polite stop request (Unix `SIGINT` intent).
    Interrupt,
    /// Graceful termination request (Unix `SIGTERM` intent).
    Terminate,
    /// Unconditional kill request (Unix `SIGKILL` intent).
    Kill,
}

impl JobSignal {
    /// Stable lowercase wire/display name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Interrupt => "interrupt",
            Self::Terminate => "terminate",
            Self::Kill => "kill",
        }
    }
}

/// Outcome of an authorized `signal` call.
///
/// Terminal jobs observe their outcome exactly like
/// [`JobCancel::AlreadyStopped`]; a live job's tree either received the
/// signal or had no member left to receive it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalOutcome {
    /// The job was already terminal; nothing changed.
    AlreadyStopped(ExecutionOutcome),
    /// The signal reached the job's owned tree.
    Delivered,
    /// The job's tree has no live member left (it is ending); nothing was
    /// delivered and the terminal event follows.
    Gone,
    /// The kernel refused the signal for this job; nothing was delivered.
    PermissionDenied,
}

/// Receipt of an accepted `attach`: which job, from which event cursor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttachReceipt {
    /// Job the caller attached to.
    pub job: JobId,
    /// Event cursor the attach starts from (validated against the head).
    pub from_seq: u64,
}

/// Receipt of an accepted `transfer`: previous and new owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferReceipt {
    /// Job whose ownership moved.
    pub job: JobId,
    /// Owner before the transfer.
    pub previous_owner: JobPrincipal,
    /// Owner after the transfer.
    pub new_owner: JobPrincipal,
}

// ── errors ──────────────────────────────────────────────────────────────────

/// Job registry and job model failures (owned, no upstream type escapes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobError {
    /// The id is not tracked (unknown, evicted, or never issued).
    UnknownJob(JobId),
    /// The spawn-time declaration failed validation; nothing was tracked.
    InvalidSpec {
        /// Owned validation reason.
        reason: String,
    },
    /// The registry is at capacity and no finished record is evictable yet.
    RegistryFull {
        /// Configured capacity.
        limit: usize,
    },
    /// The supervisor could not be started; nothing was tracked.
    Unavailable {
        /// Owned failure reason.
        reason: String,
    },
    /// The output read request was over-bound; nothing was read.
    InvalidRead {
        /// Owned validation reason.
        reason: String,
    },
    /// The replay cursor is past the event head.
    InvalidCursor {
        /// Owned validation reason.
        reason: String,
    },
    /// The event seq is not retained (unknown or already drained).
    UnknownEvent {
        /// The requested seq.
        seq: u64,
    },
    /// The caller is not authorized for this operation on this job.
    Denied {
        /// Operation that was refused.
        operation: String,
        /// Owned denial reason.
        reason: String,
    },
    /// The principal name failed validation; nothing was authorized.
    InvalidPrincipal {
        /// Owned validation reason.
        reason: String,
    },
    /// The `write_input` payload was over-bound; nothing was written.
    InvalidWrite {
        /// Owned validation reason.
        reason: String,
    },
    /// The call rate exceeded the per-operation budget; nothing changed.
    RateLimited {
        /// Operation that was limited.
        operation: String,
        /// Owned limit reason.
        reason: String,
    },
    /// Alias of [`JobError::RateLimited`] kept for the signal path so call
    /// sites read `signal` intent instead of the generic limiter vocabulary.
    SignalRateLimited {
        /// Owned limit reason.
        reason: String,
    },
    /// The operation is not supported for this job's state or backend.
    Unsupported {
        /// Owned reason.
        reason: String,
    },
    /// The cancel request was malformed (over-bound grace); nothing was
    /// recorded.
    InvalidCancel {
        /// Owned validation reason.
        reason: String,
    },
    /// The job's grant table is at capacity; delegate nothing new until the
    /// owner revokes a stale grant (or transfers ownership).
    GrantsFull {
        /// Configured grant capacity per job.
        limit: usize,
    },
    /// The sensitive-input interlock refused automated input: the target
    /// job's observed PTY echo state (or its verdict-fed interaction class)
    /// denies dispatch. Dispatch state is unchanged; retry once the host
    /// observes echo restored (RUN-22, #1053).
    SecureInputDenied {
        /// Stable audit name from [`SecureInputDenial::as_str`].
        denial: String,
        /// Owned denial reason.
        reason: String,
    },
    /// The command-risk kernel hard-denied an agent-command spawn: a
    /// positive structural match blocks dispatch and routes to the consent
    /// surface. Nothing was tracked and no process started (RUN-23, #1054).
    CommandRiskDenied {
        /// Stable audit name from [`HardDeny::as_str`].
        deny: String,
        /// Owned denial reason.
        reason: String,
    },
    /// The command-risk kernel gated an agent-command spawn on explicit
    /// human consent: no consent ledger exists yet (PP-3 open work), so the
    /// spawn fails closed. Nothing was tracked and no process started
    /// (RUN-23, #1054).
    CommandRiskNeedsConsent {
        /// Stable audit name from [`RiskTier::as_str`].
        tier: String,
        /// Owned gating reason.
        reason: String,
    },
}

impl JobError {
    pub(crate) fn invalid_spec(reason: impl Into<String>) -> Self {
        Self::InvalidSpec {
            reason: reason.into(),
        }
    }

    pub(crate) fn invalid_read(reason: impl Into<String>) -> Self {
        Self::InvalidRead {
            reason: reason.into(),
        }
    }

    pub(crate) fn invalid_cursor(reason: impl Into<String>) -> Self {
        Self::InvalidCursor {
            reason: reason.into(),
        }
    }

    pub(crate) fn unknown_event(seq: u64) -> Self {
        Self::UnknownEvent { seq }
    }

    pub(crate) fn denied(operation: JobOperation, reason: impl Into<String>) -> Self {
        Self::Denied {
            operation: operation.as_str().into(),
            reason: reason.into(),
        }
    }

    pub(crate) fn invalid_principal(reason: impl Into<String>) -> Self {
        Self::InvalidPrincipal {
            reason: reason.into(),
        }
    }

    pub(crate) fn invalid_write(reason: impl Into<String>) -> Self {
        Self::InvalidWrite {
            reason: reason.into(),
        }
    }

    pub(crate) fn signal_rate_limited(reason: impl Into<String>) -> Self {
        Self::SignalRateLimited {
            reason: reason.into(),
        }
    }

    pub(crate) fn write_rate_limited(reason: impl Into<String>) -> Self {
        Self::RateLimited {
            operation: JobOperation::WriteInput.as_str().into(),
            reason: reason.into(),
        }
    }

    pub(crate) fn unsupported(reason: impl Into<String>) -> Self {
        Self::Unsupported {
            reason: reason.into(),
        }
    }

    pub(crate) fn secure_input_denied(denial: crate::sensitive_input::SecureInputDenial) -> Self {
        Self::SecureInputDenied {
            denial: denial.as_str().into(),
            reason: denial.to_string(),
        }
    }

    pub(crate) fn command_risk_denied(deny: crate::command_risk::HardDeny) -> Self {
        Self::CommandRiskDenied {
            deny: deny.as_str().into(),
            reason: format!(
                "command hard-denied by risk class {deny}; routed to the consent surface"
            ),
        }
    }

    pub(crate) fn command_risk_needs_consent(tier: crate::command_risk::RiskTier) -> Self {
        Self::CommandRiskNeedsConsent {
            tier: tier.as_str().into(),
            reason: format!(
                "command needs explicit human consent at tier {tier}; no consent ledger exists yet"
            ),
        }
    }
}

impl fmt::Display for JobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownJob(id) => write!(f, "unknown job {id}"),
            Self::InvalidSpec { reason } => write!(f, "invalid job spec: {reason}"),
            Self::RegistryFull { limit } => {
                write!(f, "job registry is full (limit {limit})")
            }
            Self::Unavailable { reason } => write!(f, "job supervisor unavailable: {reason}"),
            Self::InvalidRead { reason } => write!(f, "invalid output read: {reason}"),
            Self::InvalidCursor { reason } => write!(f, "invalid event cursor: {reason}"),
            Self::UnknownEvent { seq } => write!(f, "unknown job event {seq}"),
            Self::Denied { operation, reason } => {
                write!(f, "denied job {operation}: {reason}")
            }
            Self::InvalidPrincipal { reason } => write!(f, "invalid job principal: {reason}"),
            Self::InvalidWrite { reason } => write!(f, "invalid job write: {reason}"),
            Self::RateLimited { operation, reason } => {
                write!(f, "job {operation} rate limited: {reason}")
            }
            Self::SignalRateLimited { reason } => {
                write!(f, "job signal rate limited: {reason}")
            }
            Self::Unsupported { reason } => write!(f, "unsupported job operation: {reason}"),
            Self::InvalidCancel { reason } => write!(f, "invalid cancel request: {reason}"),
            Self::GrantsFull { limit } => {
                write!(f, "job grant table is full (limit {limit})")
            }
            Self::SecureInputDenied { denial, reason } => {
                write!(f, "automated input denied ({denial}): {reason}")
            }
            Self::CommandRiskDenied { deny, reason } => {
                write!(f, "command spawn denied ({deny}): {reason}")
            }
            Self::CommandRiskNeedsConsent { tier, reason } => {
                write!(f, "command spawn needs consent ({tier}): {reason}")
            }
        }
    }
}

impl std::error::Error for JobError {}

#[cfg(test)]
mod tests {
    use super::super::outcome::CancelEffect;
    use super::*;
    use bitty_ipc::execution::{MAX_EXEC_ARG_BYTES, MAX_EXEC_ARGS, MAX_EXEC_ARGS_TOTAL_BYTES};

    fn valid_spec() -> JobSpec {
        JobSpec::new("printf", vec!["hi".to_owned()])
    }

    #[test]
    fn defaults_are_safe_and_deadline_free() {
        let spec = valid_spec();
        assert_eq!(spec.kind, JobKind::Command);
        assert_eq!(spec.io, JobIo::Pipes);
        assert_eq!(spec.lifetime, JobLifetime::Detached);
        assert_eq!(spec.timeouts, JobTimeouts::default());
        assert_eq!(spec.timeouts.hard, None);
        assert_eq!(spec.timeouts.idle, None);
        assert_eq!(spec.timeouts.retention, None);
        assert_eq!(spec.timeouts.effective_retention(), DEFAULT_RETENTION_TTL);
        assert!(spec.env.is_isolated());
        assert_eq!(spec.origin.panel_id(), None);
        assert!(spec.validate().is_ok());
    }

    #[test]
    fn zero_id_is_not_a_job_id() {
        assert_eq!(JobId::from_raw(0), None);
        let id = JobId::from_raw(7).expect("non-zero");
        assert_eq!(id.get(), 7);
        assert_eq!(id.to_string(), "job-7");
        assert_eq!(JobId::from_raw(7), Some(id));
    }

    #[test]
    fn kind_and_io_pair_must_agree() {
        let interactive_pipes = valid_spec().with_kind(JobKind::Interactive);
        assert!(matches!(
            interactive_pipes.validate(),
            Err(JobError::InvalidSpec { .. })
        ));

        let command_pty = valid_spec().with_io(JobIo::Pty);
        assert!(matches!(
            command_pty.validate(),
            Err(JobError::InvalidSpec { .. })
        ));

        let service_pty = valid_spec().with_kind(JobKind::Service).with_io(JobIo::Pty);
        assert!(matches!(
            service_pty.validate(),
            Err(JobError::InvalidSpec { .. })
        ));

        let interactive_pty = valid_spec()
            .with_kind(JobKind::Interactive)
            .with_io(JobIo::Pty)
            .with_env(EnvPolicy::explicit(vec![("TERM".into(), "dumb".into())]).expect("env"));
        assert!(interactive_pty.validate().is_ok());
    }

    #[test]
    fn pty_job_must_declare_explicit_environment() {
        let interactive_pty = valid_spec()
            .with_kind(JobKind::Interactive)
            .with_io(JobIo::Pty);
        assert!(matches!(
            interactive_pty.validate(),
            Err(JobError::InvalidSpec { .. })
        ));
    }

    #[test]
    fn oversized_argv_is_rejected_by_delegated_bounds() {
        let too_many = JobSpec::new(
            "printf",
            (0..=MAX_EXEC_ARGS).map(|i| i.to_string()).collect(),
        );
        assert!(matches!(
            too_many.validate(),
            Err(JobError::InvalidSpec { .. })
        ));

        let oversized_arg = JobSpec::new("printf", vec!["x".repeat(MAX_EXEC_ARG_BYTES + 1)]);
        assert!(matches!(
            oversized_arg.validate(),
            Err(JobError::InvalidSpec { .. })
        ));

        let oversized_total = JobSpec::new(
            "printf",
            (0..8)
                .map(|_| "x".repeat(MAX_EXEC_ARGS_TOTAL_BYTES / 8 + 1))
                .collect(),
        );
        assert!(matches!(
            oversized_total.validate(),
            Err(JobError::InvalidSpec { .. })
        ));
    }

    #[test]
    fn empty_program_is_rejected() {
        let spec = JobSpec::new("", Vec::new());
        assert!(matches!(spec.validate(), Err(JobError::InvalidSpec { .. })));
    }

    #[test]
    fn zero_deadlines_are_rejected_but_zero_retention_is_allowed() {
        let hard_zero =
            valid_spec().with_timeouts(JobTimeouts::default().with_hard(Duration::ZERO));
        assert!(matches!(
            hard_zero.validate(),
            Err(JobError::InvalidSpec { .. })
        ));

        let idle_zero =
            valid_spec().with_timeouts(JobTimeouts::default().with_idle(Duration::ZERO));
        assert!(matches!(
            idle_zero.validate(),
            Err(JobError::InvalidSpec { .. })
        ));

        let retention_zero =
            valid_spec().with_timeouts(JobTimeouts::default().with_retention(Duration::ZERO));
        assert!(retention_zero.validate().is_ok());
        assert_eq!(
            retention_zero.timeouts.effective_retention(),
            Duration::ZERO
        );
    }

    #[test]
    fn origin_is_bounded_and_provenance_only() {
        let spec = valid_spec().with_origin(JobOrigin::panel("panel-7"));
        assert!(spec.validate().is_ok());
        assert_eq!(spec.origin.panel_id(), Some("panel-7"));

        let oversized =
            valid_spec().with_origin(JobOrigin::panel("p".repeat(MAX_JOB_ORIGIN_BYTES + 1)));
        assert!(matches!(
            oversized.validate(),
            Err(JobError::InvalidSpec { .. })
        ));
    }

    #[test]
    fn state_helpers_agree_with_variants() {
        assert!(!JobState::Queued.is_terminal());
        assert!(!JobState::Running.is_terminal());
        assert_eq!(JobState::Queued.outcome(), None);
        let cancelled = ExecutionOutcome::Cancelled(CancelEffect::Killed);
        assert!(JobState::Done(cancelled).is_terminal());
        assert_eq!(JobState::Done(cancelled).outcome(), Some(cancelled));
        assert_eq!(JobState::Done(ExecutionOutcome::Success).as_str(), "done");
        assert_eq!(JobKind::Watch.as_str(), "watch");
        assert_eq!(JobLifetime::Agent.as_str(), "agent");
        assert_eq!(JobIo::Pty.as_str(), "pty");
    }

    #[test]
    fn events_expose_identity_and_time() {
        let id = JobId::from_raw(3).expect("non-zero");
        let queued = JobEvent::Queued { id, at_ms: 10 };
        let stopped = JobEvent::Stopped {
            id,
            outcome: ExecutionOutcome::Success,
            at_ms: 30,
        };
        let resolved = JobEvent::CancelResolved {
            id,
            outcome: CancelOutcome::Killed,
            at_ms: 20,
        };
        assert_eq!(queued.id(), id);
        assert_eq!(queued.at_ms(), 10);
        assert_eq!(resolved.id(), id);
        assert_eq!(resolved.at_ms(), 20);
        assert_eq!(stopped.id(), id);
        assert_eq!(stopped.at_ms(), 30);
    }

    #[test]
    fn error_display_is_owned_and_stable() {
        let id = JobId::from_raw(9).expect("non-zero");
        assert_eq!(JobError::UnknownJob(id).to_string(), "unknown job job-9");
        assert_eq!(
            JobError::RegistryFull { limit: 4 }.to_string(),
            "job registry is full (limit 4)"
        );
        assert!(JobError::invalid_spec("bad").to_string().contains("bad"));
        assert!(
            JobError::invalid_read("bad").to_string().contains("bad"),
            "read errors stay owned and stable"
        );
        assert!(
            JobError::invalid_cursor("bad").to_string().contains("bad"),
            "cursor errors stay owned and stable"
        );
        assert_eq!(
            JobError::unknown_event(42).to_string(),
            "unknown job event 42"
        );
        assert!(
            JobError::denied(JobOperation::Cancel, "no grant")
                .to_string()
                .contains("denied job cancel")
        );
        assert!(
            JobError::invalid_principal("bad")
                .to_string()
                .contains("bad"),
            "principal errors stay owned and stable"
        );
        assert!(
            JobError::invalid_write("bad").to_string().contains("bad"),
            "write errors stay owned and stable"
        );
        assert!(
            JobError::signal_rate_limited("storm")
                .to_string()
                .contains("rate limited"),
            "signal limiter errors stay owned and stable"
        );
        assert!(
            JobError::unsupported("pipes have closed stdin")
                .to_string()
                .contains("unsupported"),
            "unsupported errors stay owned and stable"
        );
        assert_eq!(
            JobError::GrantsFull { limit: 2 }.to_string(),
            "job grant table is full (limit 2)"
        );
    }

    #[test]
    fn principal_names_are_bounded_and_control_free() {
        assert!(JobPrincipal::new("owner-a").is_ok());
        assert!(matches!(
            JobPrincipal::new(""),
            Err(JobError::InvalidPrincipal { .. })
        ));
        assert!(matches!(
            JobPrincipal::new("p".repeat(MAX_JOB_PRINCIPAL_BYTES + 1)),
            Err(JobError::InvalidPrincipal { .. })
        ));
        assert!(matches!(
            JobPrincipal::new("bad\x01name"),
            Err(JobError::InvalidPrincipal { .. })
        ));
        let owner = JobPrincipal::new("owner-a").expect("valid test principal");
        assert_eq!(owner.as_str(), "owner-a");
        assert_eq!(owner.to_string(), "owner-a");
        assert_eq!(JobOperation::Cancel.as_str(), "cancel");
        assert_eq!(JobOperation::Cancel.to_string(), "cancel");
        assert_eq!(JobOperation::Spawn.as_str(), "spawn");
        assert_eq!(JobOperation::all().len(), 8);
        assert_eq!(JobSignal::Kill.as_str(), "kill");
    }
}
