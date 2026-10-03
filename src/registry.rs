//! In-memory job registry and phase-1 supervisor.
//!
//! The registry owns job identity, the bounded record table, the bounded
//! observation event queue, and one supervisor thread per job. It never
//! blocks a caller on a child's lifetime: [`JobRegistry::spawn`] returns the
//! [`JobId`] as soon as the job is tracked, and completion is published as
//! [`JobEvent`]s.
//!
//! Supervisor threads own their child handle; a cancel is a typed request
//! the thread takes and executes (no shared `Child` behind a lock, no
//! cross-thread kill races). Terminating a job kills its owned process tree
//! where a backend exists ([`bitty_pty::OwnedTree`]: process groups on
//! Linux/macOS, Job Objects on Windows) and reports
//! [`KillScope::DirectChild`] where none does (CTX-0512, CTX-0903).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bitty_ipc::execution::EnvPolicy;
use bitty_plugin_host::roles::{AgentRole, SandboxDecl};
use bitty_pty::{LeaderExit, OwnedTree, Pty, PtyBuilder, PtyReader, TreeSignal};

use crate::cgroup::{CgroupSource, CgroupUnavailable, JobAccounting, JobCgroups};
use crate::command_risk::{OperationIntent, RiskVerdict, classify_argv};
use crate::delivery::{DeliveryLog, DeliveryState, EventReplay};
use crate::model::{
    AttachReceipt, JobCancel, JobError, JobEvent, JobGrant, JobId, JobIo, JobOperation,
    JobPrincipal, JobSignal, JobSnapshot, JobSpec, JobState, MAX_GRANTS_PER_JOB,
    MAX_SIGNAL_WINDOW_MS, MAX_SIGNALS_PER_WINDOW, MAX_WRITE_INPUT_BYTES, MAX_WRITE_INPUT_WINDOW_MS,
    MAX_WRITES_PER_WINDOW, SignalOutcome, TransferReceipt,
};
use crate::oom::{OomEvidence, OomEvidenceGap};
use crate::outcome::{
    CancelEffect, CancelMode, CancelOutcome, CancelReceipt, CancelRequest, DeadlineClock,
    ExecutionGeneration, ExecutionHandle, ExecutionOutcome, ExitObservation,
};
use crate::output::{OutputIndex, OutputSink, OutputStream, OutputView, ReadOutput};
use crate::process_tree::KillScope;
use crate::sensitive_input::{EchoState, InteractionClass, automated_input_allowed};

/// Default registry capacity.
///
/// Reuses the accepted CTX-0442 tracked-execution bound
/// (`bitty_ipc::execution::MAX_TRACKED_EXECUTIONS`, 64) so the job table has
/// the same hard ceiling as the synchronous surface. Overflow fails closed;
/// finished records become evictable only after their retention elapses.
pub const DEFAULT_MAX_JOBS: usize = bitty_ipc::execution::MAX_TRACKED_EXECUTIONS;

/// Maximum queued lifecycle events before the oldest is dropped.
///
/// Kept for phase-1 API compatibility: it equals the observation-lane bound,
/// and [`JobRegistry::events_dropped`] now reports the sum of both delivery
/// lanes.
pub const MAX_STORED_JOB_EVENTS: usize = crate::delivery::MAX_STORED_OBSERVATION_EVENTS;

/// Supervisor poll interval (CTX-0445 spawn poll precedent).
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Pipe drain chunk size (8 KiB, the `bitty-pty` read-chunk precedent).
const DRAIN_CHUNK_BYTES: usize = 8 * 1024;

type Shared = Arc<Mutex<RegistryInner>>;

/// Classifies a spawn-time [`JobSpec`] with the command-risk kernel
/// (RUN-23): `argv[0]` is the declared program and the rest are the
/// declared args — both already parsed, never a raw command line, so
/// quoting cannot hide the operation from this layer. Spawn closes stdin
/// (pipe jobs) or opens a fresh PTY master (PTY jobs), so `stdin_piped`
/// is always false: a pipe into a new interpreter cannot exist at spawn
/// time and needs no shell-AST parser here.
fn classify_job_spec(spec: &JobSpec, intent: OperationIntent) -> RiskVerdict {
    let program = spec.program.as_str();
    let mut argv: Vec<&str> = Vec::with_capacity(spec.args.len() + 1);
    argv.push(program);
    argv.extend(spec.args.iter().map(String::as_str));
    classify_argv(&argv, false, intent)
}

/// Whether a spec environment carries no inherited variables (OQ-057).
///
/// Both [`EnvPolicy`] variants are sealed today (`Isolated` runs empty,
/// `Explicit` runs exactly the declared entries); the match stays
/// exhaustive so a future inheriting variant fails closed at compile time
/// instead of silently passing sealed roles.
fn env_policy_is_sealed(policy: &EnvPolicy) -> bool {
    match policy {
        EnvPolicy::Isolated => true,
        EnvPolicy::Explicit { .. } => true,
    }
}

// ── registry ────────────────────────────────────────────────────────────────

/// Bounded in-memory registry of supervised jobs.
///
/// Cheap to clone: every clone shares the same table, event queue, and
/// supervisor threads. All operations are non-blocking with respect to child
/// lifetimes.
#[derive(Clone)]
pub struct JobRegistry {
    shared: Shared,
}

impl fmt::Debug for JobRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner = lock_inner(&self.shared);
        f.debug_struct("JobRegistry")
            .field("capacity", &inner.capacity)
            .field("tracked", &inner.jobs.len())
            .field("events_dropped", &inner.events.dropped())
            .finish()
    }
}

impl Default for JobRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl JobRegistry {
    /// Registry with [`DEFAULT_MAX_JOBS`] capacity.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_MAX_JOBS)
    }

    /// Registry with `capacity` tracked-job slots.
    ///
    /// # Panics
    ///
    /// Panics when `capacity == 0` (a zero-slot registry cannot be used;
    /// `ColdQueue` follows the same rule).
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self::with_worker_spawner(capacity, spawn_worker)
    }

    /// Registry with `capacity` slots whose jobs each run in their own
    /// cgroup v2 leaf under `cgroups` (CTX-0880, #1537).
    ///
    /// Pass [`JobCgroups::discover`] (or [`JobCgroups::under`] for an
    /// injected base). An `Err` keeps the registry fully usable: every job
    /// then records [`OomEvidence::Missing`] with
    /// [`OomEvidenceGap::Undelegated`] (or `UnsupportedPlatform`), and
    /// [`JobRegistry::cgroup_unavailable`] names the reason. OOM is never
    /// claimed without a leaf.
    ///
    /// # Panics
    ///
    /// Panics when `capacity == 0`, like [`JobRegistry::with_capacity`].
    #[must_use]
    pub fn with_job_cgroups(
        capacity: usize,
        cgroups: Result<JobCgroups, CgroupUnavailable>,
    ) -> Self {
        let registry = Self::with_worker_spawner(capacity, spawn_worker);
        // The leaf bound follows the registry's capacity: every tracked job
        // can hold a leaf, and a leak cannot exceed the table size.
        lock_inner(&registry.shared).cgroups = CgroupSource::from_result(
            cgroups.map(|cgroups| Arc::new(cgroups.with_max_leaves(capacity))),
        );
        registry
    }

    /// Registry whose backends start drain workers through `worker_spawner`.
    fn with_worker_spawner(capacity: usize, worker_spawner: WorkerSpawner) -> Self {
        assert!(capacity > 0, "job registry capacity must be > 0");
        Self {
            shared: Arc::new(Mutex::new(RegistryInner {
                capacity,
                next_id: 1,
                jobs: BTreeMap::new(),
                events: DeliveryLog::new(),
                worker_spawner,
                cgroups: CgroupSource::NotConfigured,
            })),
        }
    }

    /// Why per-job cgroup accounting is unavailable, when it was requested
    /// through [`JobRegistry::with_job_cgroups`] and could not be set up.
    #[must_use]
    pub fn cgroup_unavailable(&self) -> Option<CgroupUnavailable> {
        match &lock_inner(&self.shared).cgroups {
            CgroupSource::Unavailable(reason) => Some(*reason),
            CgroupSource::NotConfigured | CgroupSource::Available(_) => None,
        }
    }

    /// The delegated job base holding this registry's per-job leaves.
    #[must_use]
    pub fn job_cgroup_base(&self) -> Option<std::path::PathBuf> {
        match &lock_inner(&self.shared).cgroups {
            CgroupSource::Available(cgroups) => Some(cgroups.base().to_path_buf()),
            CgroupSource::NotConfigured | CgroupSource::Unavailable(_) => None,
        }
    }

    /// Released per-job leaves whose removal has not succeeded yet (a
    /// diagnostic counter; nonzero means a job member outlived its kill).
    #[must_use]
    pub fn unremoved_cgroup_leaves(&self) -> usize {
        match &lock_inner(&self.shared).cgroups {
            CgroupSource::Available(cgroups) => cgroups.unremoved_leaves(),
            CgroupSource::NotConfigured | CgroupSource::Unavailable(_) => 0,
        }
    }

    /// Configured tracked-job capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        lock_inner(&self.shared).capacity
    }

    /// Number of tracked records (live plus retained).
    #[must_use]
    pub fn len(&self) -> usize {
        lock_inner(&self.shared).jobs.len()
    }

    /// Whether no record is tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Validates `spec`, tracks it as [`JobState::Queued`], and starts its
    /// supervisor thread.
    ///
    /// Expired finished records are reclaimed first (each record becomes
    /// evictable after its retention elapses). When the registry is still at
    /// capacity the call fails closed with [`JobError::RegistryFull`]; live
    /// jobs are never evicted.
    ///
    /// # Errors
    ///
    /// Returns [`JobError::InvalidSpec`] when `spec` fails validation (no
    /// process and no thread is started), and [`JobError::Unavailable`] when
    /// the supervisor thread cannot be created (the record is removed again).
    pub fn spawn(&self, spec: JobSpec) -> Result<JobId, JobError> {
        spec.validate()?;
        let (id, control, output) = {
            let mut inner = lock_inner(&self.shared);
            inner.evict_expired(now_ms());
            if inner.jobs.len() >= inner.capacity {
                return Err(JobError::RegistryFull {
                    limit: inner.capacity,
                });
            }
            let id = inner.allocate_id()?;
            let generation = inner.generation_for(id);
            let control = Arc::new(JobControl::new());
            let output = OutputSink::default();
            inner.jobs.insert(
                id,
                JobRecord::unowned(
                    id,
                    generation,
                    spec.clone(),
                    Arc::clone(&control),
                    output.clone(),
                ),
            );
            (id, control, output)
        };
        let shared = Arc::clone(&self.shared);
        thread::Builder::new()
            .name(format!("bitty-job-{}", id.get()))
            .spawn(move || supervise(shared, id, spec, control, output))
            .map_err(|error| {
                let mut inner = lock_inner(&self.shared);
                inner.jobs.remove(&id);
                JobError::Unavailable {
                    reason: format!("supervisor thread failed to start: {error}"),
                }
            })?;
        Ok(id)
    }

    /// Owned snapshot of one tracked job.
    ///
    /// # Errors
    ///
    /// Returns [`JobError::UnknownJob`] when `id` is not tracked (never
    /// issued, or evicted after its retention elapsed).
    pub fn get(&self, id: JobId) -> Result<JobSnapshot, JobError> {
        let inner = lock_inner(&self.shared);
        inner
            .jobs
            .get(&id)
            .map(JobRecord::snapshot)
            .ok_or(JobError::UnknownJob(id))
    }

    /// Owned snapshots of every tracked job, ordered by [`JobId`].
    #[must_use]
    pub fn list(&self) -> Vec<JobSnapshot> {
        lock_inner(&self.shared)
            .jobs
            .values()
            .map(JobRecord::snapshot)
            .collect()
    }

    /// Requests immediate job termination (legacy ambient path).
    ///
    /// Records a [`CancelMode::Immediate`] request for the job's current
    /// generation: the supervisor kills the owned tree, publishes
    /// `CancelResolved`, then `Stopped`. This returns as soon as the request
    /// is recorded, never after the process is gone. Callers holding a
    /// handle use [`JobRegistry::cancel_typed`] instead.
    ///
    /// # Errors
    ///
    /// Returns [`JobError::UnknownJob`] when `id` is not tracked.
    pub fn cancel(&self, id: JobId) -> Result<JobCancel, JobError> {
        let inner = lock_inner(&self.shared);
        let record = inner.jobs.get(&id).ok_or(JobError::UnknownJob(id))?;
        Ok(record.legacy_cancel())
    }

    /// Submits a typed cancel request (ambient host authority, like
    /// [`JobRegistry::cancel`]).
    ///
    /// The host checks the handle's generation itself: a stale generation is
    /// answered with [`CancelOutcome::StaleGeneration`] and nothing changes;
    /// a terminal job answers [`CancelOutcome::AlreadyExited`]. Otherwise
    /// the request is accepted and the supervisor publishes exactly one
    /// `JobEvent::CancelResolved` with the typed result.
    ///
    /// # Errors
    ///
    /// Returns [`JobError::UnknownJob`] when the handle's id is not tracked.
    pub fn cancel_typed(&self, request: CancelRequest) -> Result<CancelReceipt, JobError> {
        let id = request.handle().id;
        let inner = lock_inner(&self.shared);
        let record = inner.jobs.get(&id).ok_or(JobError::UnknownJob(id))?;
        Ok(record.typed_cancel(request))
    }

    // ── capability-scoped operations (CTX-0514) ─────────────────────────────
    //
    // Every `*_as` entry point below enforces one per-principal,
    // per-operation grant at the host before touching job state. The
    // enforcement order is fixed: existence first, then authorization (deny
    // by default, hide existence from unauthorized callers), then validation
    // and rate limiting. A denied caller learns nothing about the job — the
    // same [`JobError::Denied`] shape covers unknown ids for callers without
    // an implicit grant — and no operation ever confers ambient authority:
    // ownership is assigned once at spawn and moves only through `transfer`,
    // and a delegation never widens (a granter can only pass on operations
    // it currently holds).
    //
    // In-process only: no IPC verb is exposed here. The existing IPC
    // scope/auth registry plus the consent/effect gate stays the transport
    // boundary; these methods are what that boundary (or a future wire)
    // calls after authenticating the principal. Role decisions (owner vs.
    // subscriber) stay `bitty-ai` coordination semantics re-authorized here,
    // and self-grant prohibition is the CTX-0524 seam: this layer has no
    // self-grant path (`grant_as`/`transfer_as` both require `transfer`,
    // which only the owner or an explicit delegate holds).

    /// Tracks `spec` as [`JobState::Queued`] owned by `owner`, then starts
    /// its supervisor thread.
    ///
    /// The spawner becomes the job's first owner with the full operation
    /// set; every other principal starts with nothing. All spawn bounds
    /// (capacity, spec validation, supervisor startup) behave exactly like
    /// [`JobRegistry::spawn`].
    ///
    /// Agent-command boundary (RUN-23): the spec is classified with
    /// [`classify_argv`] under [`OperationIntent::Execute`] before anything
    /// is tracked — a hard-deny match fails with
    /// [`JobError::CommandRiskDenied`] and a consent-gated shape fails with
    /// [`JobError::CommandRiskNeedsConsent`], both before any thread or
    /// process starts. Callers with a Tool Bus-declared intent use
    /// [`JobRegistry::spawn_checked_as`] instead. The legacy
    /// [`JobRegistry::spawn`] stays ungated host authority.
    ///
    /// # Errors
    ///
    /// Same failure set as [`JobRegistry::spawn`] (no denial: spawning
    /// confers the first ownership rather than exercising one), plus the
    /// command-risk refusals above.
    pub fn spawn_as(&self, owner: JobPrincipal, spec: JobSpec) -> Result<JobId, JobError> {
        self.spawn_checked_as(owner, spec, OperationIntent::Execute)
    }

    /// Tracks `spec` as [`JobState::Queued`] owned by `owner` after the
    /// command-risk interlock, then starts its supervisor thread.
    ///
    /// Agent-command boundary with explicit Tool Bus-declared `intent`
    /// (RUN-23, #1054): `intent` is declared by the tool schema, never
    /// inferred from bytes, so a read through a mutating-looking path stays
    /// a read. Spawn closes stdin (pipe jobs) or opens a fresh PTY master
    /// (PTY jobs), so `stdin_piped` is always false here: a pipe into a new
    /// interpreter cannot exist at spawn time. A positive hard-deny match
    /// fails with [`JobError::CommandRiskDenied`]; a consent-gated shape
    /// fails with [`JobError::CommandRiskNeedsConsent`] (fail-closed: the
    /// PP-3 consent ledger does not exist yet, so nothing can release it).
    /// Either refusal happens before tracking, threading, or execution.
    ///
    /// # Errors
    ///
    /// [`JobError::InvalidSpec`] when `spec` fails validation,
    /// [`JobError::CommandRiskDenied`] on a hard-deny match,
    /// [`JobError::CommandRiskNeedsConsent`] on a consent-gated shape,
    /// [`JobError::RegistryFull`] at capacity, and [`JobError::Unavailable`]
    /// when the supervisor thread cannot start.
    pub fn spawn_checked_as(
        &self,
        owner: JobPrincipal,
        spec: JobSpec,
        intent: OperationIntent,
    ) -> Result<JobId, JobError> {
        spec.validate()?;
        // Principals are validated at the boundary: a name that fails the
        // model bounds fails here, before anything is tracked. (`JobPrincipal`
        // construction already enforces the bounds; this re-check keeps the
        // registry path honest even if a future constructor relaxes.)
        if owner.as_str().len() > crate::model::MAX_JOB_PRINCIPAL_BYTES {
            return Err(JobError::invalid_principal("job principal exceeds bound"));
        };
        match classify_job_spec(&spec, intent) {
            RiskVerdict::Allow(_) => {}
            RiskVerdict::Deny(deny) => return Err(JobError::command_risk_denied(deny)),
            RiskVerdict::NeedsConsent(tier) => {
                return Err(JobError::command_risk_needs_consent(tier));
            }
        }
        self.spawn_owned(owner, spec)
    }

    /// Tracks `spec` owned by `owner` after the command-risk interlock
    /// *and* the adopted role sandbox gate (OQ-057, #1094), then starts its
    /// supervisor thread.
    ///
    /// `role` must admit the sandbox point for `decl`
    /// ([`AgentRole::check_sandbox_exec`]), and a role requiring a sealed
    /// environment additionally requires a sealed spec environment
    /// ([`env_policy_is_sealed`]): an unsealed spawn for a sealed role
    /// fails with [`JobError::Denied`] (`spawn`) before anything is
    /// tracked. The declaration gate constrains what a spawn may claim;
    /// the sandbox mechanism itself (CRE-5 shell-write closure) stays open
    /// work. Every other refusal matches [`Self::spawn_checked_as`], and
    /// every refusal happens before tracking, threading, or execution.
    ///
    /// # Errors
    ///
    /// [`JobError::Denied`] when the role gate or the environment-seal
    /// cross-check refuses the spawn, plus the [`Self::spawn_checked_as`]
    /// failure set otherwise.
    pub fn spawn_checked_as_with_role(
        &self,
        owner: JobPrincipal,
        spec: JobSpec,
        intent: OperationIntent,
        role: AgentRole,
        decl: &SandboxDecl,
    ) -> Result<JobId, JobError> {
        spec.validate()?;
        if owner.as_str().len() > crate::model::MAX_JOB_PRINCIPAL_BYTES {
            return Err(JobError::invalid_principal("job principal exceeds bound"));
        };
        if let Err(error) = role.check_sandbox_exec(decl) {
            return Err(JobError::denied(JobOperation::Spawn, error.to_string()));
        }
        if role.sandbox().env_sealed() && !env_policy_is_sealed(&spec.env) {
            return Err(JobError::denied(
                JobOperation::Spawn,
                "role requires a sealed environment (OQ-057 adopted)",
            ));
        }
        match classify_job_spec(&spec, intent) {
            RiskVerdict::Allow(_) => {}
            RiskVerdict::Deny(deny) => return Err(JobError::command_risk_denied(deny)),
            RiskVerdict::NeedsConsent(tier) => {
                return Err(JobError::command_risk_needs_consent(tier));
            }
        }
        self.spawn_owned(owner, spec)
    }

    /// Shared owned-spawn body: tracks `spec` owned by `owner` and starts
    /// its supervisor thread. Validation, principal bounds, and the
    /// command-risk interlock all run in the caller
    /// ([`JobRegistry::spawn_checked_as`]) before anything is tracked.
    fn spawn_owned(&self, owner: JobPrincipal, spec: JobSpec) -> Result<JobId, JobError> {
        let (id, control, output) = {
            let mut inner = lock_inner(&self.shared);
            inner.evict_expired(now_ms());
            if inner.jobs.len() >= inner.capacity {
                return Err(JobError::RegistryFull {
                    limit: inner.capacity,
                });
            }
            let id = inner.allocate_id()?;
            let generation = inner.generation_for(id);
            let control = Arc::new(JobControl::new());
            let output = OutputSink::default();
            inner.jobs.insert(
                id,
                JobRecord::owned(
                    id,
                    generation,
                    spec.clone(),
                    Arc::clone(&control),
                    output.clone(),
                    owner,
                ),
            );
            (id, control, output)
        };
        let shared = Arc::clone(&self.shared);
        thread::Builder::new()
            .name(format!("bitty-job-{}", id.get()))
            .spawn(move || supervise(shared, id, spec, control, output))
            .map_err(|error| {
                let mut inner = lock_inner(&self.shared);
                inner.jobs.remove(&id);
                JobError::Unavailable {
                    reason: format!("supervisor thread failed to start: {error}"),
                }
            })?;
        Ok(id)
    }

    /// Owned snapshot of one tracked job, authorized as `principal`.
    ///
    /// # Errors
    ///
    /// Returns [`JobError::Denied`] with operation `observe` when the caller
    /// holds no `observe` grant — including for unknown ids, so a denial
    /// never confirms whether the job exists.
    pub fn get_as(&self, principal: &JobPrincipal, id: JobId) -> Result<JobSnapshot, JobError> {
        let inner = lock_inner(&self.shared);
        let record = inner.jobs.get(&id);
        authorize_observe(&inner, principal, record, id, JobOperation::Observe)?;
        // Authorization passed, so the record exists; the `ok_or` below is
        // unreachable except under a lock race that cannot happen (the
        // record is borrowed from the same guard).
        record
            .map(JobRecord::snapshot)
            .ok_or(JobError::UnknownJob(id))
    }

    /// Owned snapshots of every job `principal` may observe, ordered by
    /// [`JobId`].
    ///
    /// Jobs the caller cannot observe are omitted silently (never an
    /// existence oracle); an unauthorized caller gets an empty list. This
    /// never fails: there is no job to deny on, only a filtered view.
    #[must_use]
    pub fn list_as(&self, principal: &JobPrincipal) -> Vec<JobSnapshot> {
        let inner = lock_inner(&self.shared);
        inner
            .jobs
            .values()
            .filter(|record| record.authorized(principal, JobOperation::Observe))
            .map(JobRecord::snapshot)
            .collect()
    }

    /// Requests job termination as `principal`.
    ///
    /// Same direct-child mechanism and return shape as
    /// [`JobRegistry::cancel`]; enforcement only adds the `cancel` grant
    /// check. Denial leaves the job untouched.
    ///
    /// # Errors
    ///
    /// Returns [`JobError::Denied`] with operation `cancel` when the caller
    /// holds no `cancel` grant (unknown ids deny identically).
    pub fn cancel_as(&self, principal: &JobPrincipal, id: JobId) -> Result<JobCancel, JobError> {
        let inner = lock_inner(&self.shared);
        let record = inner.jobs.get(&id);
        authorize_strict(&inner, principal, record, id, JobOperation::Cancel)?;
        let record = record.ok_or(JobError::UnknownJob(id))?;
        Ok(record.legacy_cancel())
    }

    /// Submits a typed cancel request under the principal's `cancel` grant.
    ///
    /// Enforcement order: existence and authorization first (an unauthorized
    /// caller learns nothing, not even whether its generation is stale), then
    /// the host's generation check, then the terminal check — exactly like
    /// [`JobRegistry::cancel_typed`] afterwards.
    ///
    /// # Errors
    ///
    /// Same denial set as [`JobRegistry::cancel_as`].
    pub fn cancel_typed_as(
        &self,
        principal: &JobPrincipal,
        request: CancelRequest,
    ) -> Result<CancelReceipt, JobError> {
        let id = request.handle().id;
        let inner = lock_inner(&self.shared);
        let record = inner.jobs.get(&id);
        authorize_strict(&inner, principal, record, id, JobOperation::Cancel)?;
        let record = record.ok_or(JobError::UnknownJob(id))?;
        Ok(record.typed_cancel(request))
    }

    /// Reads retained output of one tracked job as `principal` (CTX-0513
    /// shapes, CTX-0514 enforcement).
    ///
    /// # Errors
    ///
    /// Returns [`JobError::Denied`] with operation `read_output` when the
    /// caller holds no `read_output` grant (unknown ids deny identically),
    /// and [`JobError::InvalidRead`] when the request is over-bound.
    pub fn read_output_as(
        &self,
        principal: &JobPrincipal,
        id: JobId,
        read: ReadOutput,
    ) -> Result<OutputView, JobError> {
        let validated = read.validate()?;
        let inner = lock_inner(&self.shared);
        let record = inner.jobs.get(&id);
        authorize_strict(&inner, principal, record, id, JobOperation::ReadOutput)?;
        let record = record.ok_or(JobError::UnknownJob(id))?;
        Ok(record.output.read(&validated))
    }

    /// Metadata-only output index of one tracked job as `principal`.
    ///
    /// # Errors
    ///
    /// Returns [`JobError::Denied`] with operation `read_output` when the
    /// caller holds no `read_output` grant (unknown ids deny identically).
    pub fn output_index_as(
        &self,
        principal: &JobPrincipal,
        id: JobId,
    ) -> Result<OutputIndex, JobError> {
        let inner = lock_inner(&self.shared);
        let record = inner.jobs.get(&id);
        authorize_strict(&inner, principal, record, id, JobOperation::ReadOutput)?;
        let record = record.ok_or(JobError::UnknownJob(id))?;
        Ok(record.output.index())
    }

    /// Records the observed PTY echo state and interaction class for one
    /// tracked job (RUN-22, #1053).
    ///
    /// Host authority (not capability-scoped): the host owns termios
    /// observation — it holds the PTY master side — and reports the slave
    /// `ECHO` bit here via [`EchoState::of_echo_bit`], plus the class it
    /// sorted with [`InteractionClass::classify`] or the verdict-fed
    /// [`classify_with_verdict`](crate::sensitive_input::classify_with_verdict)
    /// (SI-5 seam into the OQ-087 audit). [`JobRegistry::write_input_as`]
    /// re-checks both on every dispatch; a denial changes no dispatch
    /// state and spends no rate budget.
    ///
    /// # Errors
    ///
    /// Returns [`JobError::UnknownJob`] when `id` is not tracked.
    pub fn set_job_input_gate(
        &self,
        id: JobId,
        echo: EchoState,
        class: InteractionClass,
    ) -> Result<(), JobError> {
        let mut inner = lock_inner(&self.shared);
        let record = inner.jobs.get_mut(&id).ok_or(JobError::UnknownJob(id))?;
        record.echo = echo;
        record.interaction = class;
        Ok(())
    }

    /// Reads the recorded input-gate state for one tracked job (RUN-22).
    ///
    /// The check side of [`JobRegistry::set_job_input_gate`]: hosts and
    /// tests observe what the next [`JobRegistry::write_input_as`] will
    /// enforce without dispatching anything.
    ///
    /// # Errors
    ///
    /// Returns [`JobError::UnknownJob`] when `id` is not tracked.
    pub fn job_input_gate(&self, id: JobId) -> Result<(EchoState, InteractionClass), JobError> {
        let inner = lock_inner(&self.shared);
        let record = inner.jobs.get(&id).ok_or(JobError::UnknownJob(id))?;
        Ok((record.echo, record.interaction))
    }

    /// Writes `data` to a live interactive (PTY) job's stdin as `principal`.
    ///
    /// Enforcement order: `write_input` grant, then the sensitive-input
    /// interlock, then payload bound, then the
    /// per-principal rate budget, then backend/state gating. Pipe jobs run
    /// with closed stdin by design, so an authorized write there reports
    /// [`JobError::Unsupported`]; a terminal job reports `Unsupported` as
    /// well (never `Denied`: the caller was authorized, the target is gone).
    ///
    /// Writer-half startup race: the supervisor publishes the PTY writer
    /// half just after marking `Running` (same thread, back-to-back). A
    /// claim that lands in that gap fails closed with `Unsupported` — never
    /// a block — so callers retry once `Running` is observable.
    ///
    /// # Errors
    ///
    /// Returns [`JobError::Denied`] with operation `write_input` for callers
    /// without the grant (unknown ids deny identically),
    /// [`JobError::SecureInputDenied`] while the sensitive-input interlock
    /// holds (no-echo, or a confirmation class the host sorted),
    /// [`JobError::InvalidWrite`] for empty or over-bound payloads,
    /// [`JobError::RateLimited`] once the per-window budget is spent, and
    /// [`JobError::Unsupported`] for pipe backends or terminal jobs.
    pub fn write_input_as(
        &self,
        principal: &JobPrincipal,
        id: JobId,
        data: &[u8],
    ) -> Result<usize, JobError> {
        let mut inner = lock_inner(&self.shared);
        // Authorization first (deny-by-default, existence hidden), then the
        // interlock snapshot from the same borrow: an authorized caller may
        // learn the gate state, and a denied caller learns nothing.
        let gate = inner.jobs.get(&id).map(|record| {
            (
                record.authorized(principal, JobOperation::WriteInput),
                record.echo,
                record.interaction,
            )
        });
        let Some((true, echo, class)) = gate else {
            return Err(JobError::denied(
                JobOperation::WriteInput,
                "caller holds no grant for this operation",
            ));
        };
        // Sensitive-input interlock (RUN-22): the recorded echo state is
        // re-checked on every dispatch, so a no-echo span suspends dispatch
        // for its duration without touching grants or spending budget.
        if let Err(denial) = automated_input_allowed(echo, class) {
            return Err(JobError::secure_input_denied(denial));
        }
        if data.is_empty() {
            return Err(JobError::invalid_write(
                "write_input payload must not be empty",
            ));
        }
        if data.len() > MAX_WRITE_INPUT_BYTES {
            return Err(JobError::invalid_write(format!(
                "write_input payload exceeds {MAX_WRITE_INPUT_BYTES} bytes"
            )));
        }
        let writer = {
            let record = inner.jobs.get_mut(&id).ok_or(JobError::UnknownJob(id))?;
            if record.state.is_terminal() {
                return Err(JobError::unsupported("job is terminal; stdin is closed"));
            }
            if record.spec.io != JobIo::Pty {
                // Pipe jobs run with closed stdin by design (CTX-0511): the
                // caller is authorized, the mechanism truthfully refuses.
                return Err(JobError::unsupported(
                    "pipe jobs run with closed stdin; use a PTY job for input",
                ));
            }
            if !record.write_budget.check() {
                return Err(JobError::write_rate_limited(format!(
                    "write_input budget of {MAX_WRITES_PER_WINDOW} calls per {MAX_WRITE_INPUT_WINDOW_MS} ms spent"
                )));
            }
            match record.pty_writer() {
                Some(writer) => writer,
                None => {
                    // The writer half is gone (taken by a concurrent write or
                    // the backend never published one): fail closed without
                    // spending more budget than the one checked call.
                    return Err(JobError::unsupported(
                        "interactive stdin is unavailable; the job may be starting or stopping",
                    ));
                }
            }
        };
        // The registry guard stays dropped across the blocking PTY write:
        // re-locking the same non-reentrant mutex while the outer guard is
        // alive self-deadlocks and wedges every other registry caller, so the
        // PTY half is released and returned under a fresh guard instead.
        drop(inner);
        let mut outcome = write_to_pty_stdin(writer, data);
        {
            let inner = lock_inner(&self.shared);
            // Re-validate under the fresh guard: the job may have finished
            // while the guard was dropped for PTY I/O. A live record gets
            // its half back; a terminal or evicted one does not — the half
            // drops with the outcome instead of lingering in a dead slot.
            if let Some(record) = inner.jobs.get(&id) {
                if !record.state.is_terminal() {
                    record.return_pty_writer(outcome.ok_writer());
                }
            }
        }
        outcome.into_result()
    }

    /// Delivers a portable signal request as `principal`.
    ///
    /// Enforcement order: `signal` grant, then the per-principal signal
    /// budget, then liveness. A terminal job observes its stop exactly like
    /// [`JobCancel::AlreadyStopped`] (no budget is spent on a job that is
    /// already gone — the call is an observation, not a delivery). A live
    /// job reaches the CTX-0512 typed-signal seam and reports
    /// [`JobError::Unsupported`]: this layer names the intent, the delivery
    /// mechanism owns kill semantics, and no outcome is invented here.
    ///
    /// Denied callers never consume the budget and never disturb the job:
    /// authorization runs before limiting.
    ///
    /// # Errors
    ///
    /// Returns [`JobError::Denied`] with operation `signal` for callers
    /// without the grant (unknown ids deny identically), and
    /// [`JobError::SignalRateLimited`] once the per-window burst budget is
    /// spent.
    pub fn signal_as(
        &self,
        principal: &JobPrincipal,
        id: JobId,
        signal: JobSignal,
    ) -> Result<SignalOutcome, JobError> {
        let tree = {
            let mut inner = lock_inner(&self.shared);
            let authorized = inner
                .jobs
                .get(&id)
                .is_some_and(|record| record.authorized(principal, JobOperation::Signal));
            if !authorized {
                return Err(JobError::denied(
                    JobOperation::Signal,
                    "caller holds no grant for this operation",
                ));
            }
            let record = inner.jobs.get_mut(&id).ok_or(JobError::UnknownJob(id))?;
            if let JobState::Done(outcome) = record.state {
                return Ok(SignalOutcome::AlreadyStopped(outcome));
            }
            if !record.signal_budget.check() {
                return Err(JobError::signal_rate_limited(format!(
                    "signal budget of {MAX_SIGNALS_PER_WINDOW} calls per {MAX_SIGNAL_WINDOW_MS} ms spent"
                )));
            }
            let tree = record.tree.clone().ok_or_else(|| {
                JobError::unsupported(
                    "no owned tree for this job (not started, or no backend on this \
                     platform); a signal is never sent to a single pid",
                )
            })?;
            (tree, Arc::clone(&record.control))
        };
        let (tree, control) = tree;
        // Delivered outside the registry lock; the tree's own lock keeps the
        // signal from racing the leader's reap.
        let signal = match signal {
            JobSignal::Interrupt => TreeSignal::Interrupt,
            JobSignal::Terminate => TreeSignal::Terminate,
            JobSignal::Kill => TreeSignal::Kill,
        };
        if signal == TreeSignal::Kill {
            control.note_host_kill();
        }
        match tree.signal(signal) {
            Ok(()) => Ok(SignalOutcome::Delivered),
            Err(error) => match error.kind() {
                std::io::ErrorKind::NotFound => Ok(SignalOutcome::Gone),
                std::io::ErrorKind::PermissionDenied => Ok(SignalOutcome::PermissionDenied),
                // The tree's backend cannot deliver this signal (graceful
                // signals on Windows Job Objects): typed, never a fallback
                // to a single pid.
                std::io::ErrorKind::Unsupported => Err(JobError::unsupported(format!(
                    "the owned-tree backend cannot deliver {}: {error}",
                    signal.as_str()
                ))),
                _ => Err(JobError::Unavailable {
                    reason: format!("signal delivery failed: {error}"),
                }),
            },
        }
    }

    /// Subscribes `principal` to a live job's event cursor.
    ///
    /// The cursor is the delivery-log `seq` the caller replays from (0
    /// replays from the origin). The receipt echoes the validated `(job,
    /// from_seq)` pair so a reconnecting consumer can page with
    /// [`JobRegistry::events_since_as`]; no subscription state is stored —
    /// the delivery log stays the only event memory.
    ///
    /// # Errors
    ///
    /// Returns [`JobError::Denied`] with operation `attach` for callers
    /// without the grant (unknown ids deny identically),
    /// [`JobError::InvalidCursor`] when `from_seq` is past the event head,
    /// and [`JobError::Unsupported`] when the job is already terminal (there
    /// is nothing live to subscribe to; replay the retained events instead).
    pub fn attach_as(
        &self,
        principal: &JobPrincipal,
        id: JobId,
        from_seq: u64,
    ) -> Result<AttachReceipt, JobError> {
        let inner = lock_inner(&self.shared);
        let record = inner.jobs.get(&id);
        authorize_strict(&inner, principal, record, id, JobOperation::Attach)?;
        let record = record.ok_or(JobError::UnknownJob(id))?;
        if record.state.is_terminal() {
            return Err(JobError::unsupported(
                "job is terminal; replay retained events instead of attaching",
            ));
        }
        if from_seq > inner.events.head_seq() {
            return Err(JobError::invalid_cursor(format!(
                "cursor {from_seq} is past the event head"
            )));
        }
        Ok(AttachReceipt { job: id, from_seq })
    }

    /// Delegates one operation on `id` to `grant.principal`, authorized as
    /// `principal`.
    ///
    /// Delegation requires `transfer`, and the granter can only pass on
    /// operations it currently holds (ownership counts as holding all
    /// seven): a reviewer holding only `observe` cannot conjure `cancel`
    /// for an accomplice, and holding six of seven never implies the
    /// seventh. Grants are per-job, never global, and idempotent (repeating
    /// a grant reports `false` from [`JobRegistry::revoke_as`]'s mirror
    /// only — `grant_as` itself returns `()` either way).
    ///
    /// # Errors
    ///
    /// Returns [`JobError::Denied`] with operation `transfer` when the
    /// caller lacks `transfer` or tries to delegate an operation it does not
    /// hold (unknown ids deny identically), and [`JobError::GrantsFull`]
    /// when the job's grant table is at capacity.
    pub fn grant_as(
        &self,
        principal: &JobPrincipal,
        id: JobId,
        grant: JobGrant,
    ) -> Result<(), JobError> {
        let mut inner = lock_inner(&self.shared);
        let (caller_holds_transfer, granter_holds_delegated) = match inner.jobs.get(&id) {
            Some(record) => (
                record.authorized(principal, JobOperation::Transfer),
                record.authorized(principal, grant.operation),
            ),
            None => (false, false),
        };
        if !caller_holds_transfer {
            return Err(JobError::denied(
                JobOperation::Transfer,
                "caller holds no grant for this operation",
            ));
        }
        if !granter_holds_delegated {
            return Err(JobError::denied(
                JobOperation::Transfer,
                "granter does not hold the delegated operation",
            ));
        }
        let record = inner.jobs.get_mut(&id).ok_or(JobError::UnknownJob(id))?;
        if !record.grants.contains(&grant) && record.grants.len() >= MAX_GRANTS_PER_JOB {
            return Err(JobError::GrantsFull {
                limit: MAX_GRANTS_PER_JOB,
            });
        }
        record.grants.insert(grant);
        Ok(())
    }

    /// Removes one explicit grant, authorized as `principal`.
    ///
    /// Returns `true` when a grant was removed, `false` when none matched
    /// (idempotent: revoking twice is not an error). Removing an ownership
    /// grant is meaningless — ownership is implicit, not a table entry — so
    /// revoking the owner's own pair reports `false`. Transfer of ownership
    /// clears all explicit grants (below): a new owner's authority starts
    /// clean, never inheriting the previous owner's delegations.
    ///
    /// # Errors
    ///
    /// Returns [`JobError::Denied`] with operation `transfer` for callers
    /// without `transfer` (unknown ids deny identically).
    pub fn revoke_as(
        &self,
        principal: &JobPrincipal,
        id: JobId,
        grant: &JobGrant,
    ) -> Result<bool, JobError> {
        let mut inner = lock_inner(&self.shared);
        let authorized = inner
            .jobs
            .get(&id)
            .is_some_and(|record| record.authorized(principal, JobOperation::Transfer));
        if !authorized {
            return Err(JobError::denied(
                JobOperation::Transfer,
                "caller holds no grant for this operation",
            ));
        }
        let record = inner.jobs.get_mut(&id).ok_or(JobError::UnknownJob(id))?;
        Ok(record.grants.remove(grant))
    }

    /// Moves ownership of `id` to `new_owner`, authorized as `principal`.
    ///
    /// The previous owner is fenced immediately: every operation denies
    /// afterwards unless a fresh grant says otherwise. All explicit grants
    /// clear on transfer, so the successor's authority starts from
    /// ownership alone — a delegation the old owner handed out never
    /// survives the move. Transferring to the current owner is a no-op that
    /// still returns a receipt (and still clears stale grants).
    ///
    /// There is no self-grant path here: `transfer_as` requires `transfer`,
    /// which only the owner (or an explicit `transfer` delegate) holds, and
    /// a delegate can only move ownership onward, never mint authority it
    /// does not hold. Broader self-grant prohibition (effective-capability
    /// intersection across agent/plugin requests) is the CTX-0524 seam and
    /// is not implemented in this task.
    ///
    /// Legacy records (spawned through [`JobRegistry::spawn`]) have no
    /// owner: `transfer_as` denies on them, so a scoped caller can never
    /// seize a legacy job and a legacy job never confers scoped ownership.
    ///
    /// # Errors
    ///
    /// Returns [`JobError::Denied`] with operation `transfer` for callers
    /// without `transfer` (unknown ids deny identically).
    pub fn transfer_as(
        &self,
        principal: &JobPrincipal,
        id: JobId,
        new_owner: JobPrincipal,
    ) -> Result<TransferReceipt, JobError> {
        let mut inner = lock_inner(&self.shared);
        let authorized = inner
            .jobs
            .get(&id)
            .is_some_and(|record| record.authorized(principal, JobOperation::Transfer));
        if !authorized {
            return Err(JobError::denied(
                JobOperation::Transfer,
                "caller holds no grant for this operation",
            ));
        }
        let record = inner.jobs.get_mut(&id).ok_or(JobError::UnknownJob(id))?;
        let previous_owner = record.owner.clone().ok_or_else(|| {
            JobError::denied(
                JobOperation::Transfer,
                "legacy job has no owner to transfer from",
            )
        })?;
        record.owner = Some(new_owner.clone());
        record.grants.clear();
        Ok(TransferReceipt {
            job: id,
            previous_owner,
            new_owner,
        })
    }

    /// Replays retained events newer than `since` that belong to jobs
    /// `principal` may observe (CTX-0513 shapes, CTX-0514 scoping).
    ///
    /// Events for jobs the caller cannot observe are filtered out before
    /// the replay bound applies, so a stranger's replay is empty rather
    /// than an oracle. Cursor validation (`InvalidCursor` past the head)
    /// and the `gap` flag behave exactly like
    /// [`JobRegistry::events_since`]; delivery-state marking only touches
    /// returned events.
    ///
    /// # Errors
    ///
    /// Returns [`JobError::InvalidCursor`] when `since` is past the head.
    /// Unauthorized callers get an empty replay, never a denial: there is no
    /// single job to deny on, only a filtered view (mirroring `list_as`).
    pub fn events_since_as(
        &self,
        principal: &JobPrincipal,
        since: u64,
        limit: usize,
    ) -> Result<EventReplay, JobError> {
        let mut inner = lock_inner(&self.shared);
        let head = inner.events.head_seq();
        if since > head {
            return Err(JobError::invalid_cursor(format!(
                "cursor {since} is past the event head"
            )));
        }
        let visible: BTreeSet<JobId> = inner
            .jobs
            .values()
            .filter(|record| record.authorized(principal, JobOperation::Observe))
            .map(|record| record.id)
            .collect();
        let mut replay = inner.events.replay_since(since, limit)?;
        replay
            .events
            .retain(|stored| visible.contains(&stored.job()));
        Ok(replay)
    }

    /// Marks `seq` acknowledged as `principal` (idempotent at-least-once
    /// close-out).
    ///
    /// The caller must hold `observe` on the event's job: acknowledging
    /// another principal's event denies with operation `observe` (unknown
    /// seqs fail closed as [`JobError::UnknownEvent`], which reveals nothing
    /// — the seq space is registry-global, not per-job).
    ///
    /// # Errors
    ///
    /// Returns [`JobError::Denied`] with operation `observe` when the caller
    /// cannot observe the event's job, and [`JobError::UnknownEvent`] when
    /// `seq` is not retained.
    pub fn acknowledge_as(
        &self,
        principal: &JobPrincipal,
        seq: u64,
    ) -> Result<DeliveryState, JobError> {
        let mut inner = lock_inner(&self.shared);
        let target = inner
            .events
            .find(seq)
            .ok_or_else(|| JobError::unknown_event(seq))?;
        let job = target.job();
        let authorized = inner
            .jobs
            .get(&job)
            .is_some_and(|record| record.authorized(principal, JobOperation::Observe));
        if !authorized {
            return Err(JobError::denied(
                JobOperation::Observe,
                "caller cannot observe this job's events",
            ));
        }
        inner.events.acknowledge(seq)
    }

    /// Drains up to `limit` queued lifecycle events in order.
    ///
    /// This is the phase-1 consumption shape, kept unchanged: it removes the
    /// oldest retained events across both delivery lanes in `seq` order.
    /// Consumers that need reconnect replay should use
    /// [`JobRegistry::events_since`] instead, which retains history and
    /// reports delivery states.
    #[must_use]
    pub fn drain_events(&self, limit: usize) -> Vec<JobEvent> {
        lock_inner(&self.shared).events.drain(limit)
    }

    /// Lifecycle events dropped by the bounded delivery lanes so far (both
    /// lanes summed; see [`JobRegistry::observation_dropped`] and
    /// [`JobRegistry::critical_dropped`] for the split).
    #[must_use]
    pub fn events_dropped(&self) -> u64 {
        lock_inner(&self.shared).events.dropped()
    }

    /// Observation events dropped by their lane so far (UI-only lifecycle
    /// notices; never terminal stops).
    #[must_use]
    pub fn observation_dropped(&self) -> u64 {
        lock_inner(&self.shared).events.observation_dropped()
    }

    /// Critical events dropped by their lane so far (terminal stops; the
    /// lane is sized so ordinary observation pressure never drops one).
    #[must_use]
    pub fn critical_dropped(&self) -> u64 {
        lock_inner(&self.shared).events.critical_dropped()
    }

    /// Replays retained events newer than `since` in `seq` order (CTX-0513).
    ///
    /// `since` is an event `seq` (0 replays from the origin); the returned
    /// [`EventReplay::next_seq`] is the cursor for the next call. Replays
    /// mark returned events delivered; the consumer confirms handling with
    /// [`JobRegistry::acknowledge`]. History older than the retained window
    /// sets [`EventReplay::gap`].
    ///
    /// # Errors
    ///
    /// Returns [`JobError::InvalidCursor`] when `since` is past the head.
    pub fn events_since(&self, since: u64, limit: usize) -> Result<EventReplay, JobError> {
        lock_inner(&self.shared).events.replay_since(since, limit)
    }

    /// Marks `seq` acknowledged (idempotent at-least-once close-out).
    ///
    /// # Errors
    ///
    /// Returns [`JobError::UnknownEvent`] when `seq` is not retained
    /// (unknown, or removed by [`JobRegistry::drain_events`]).
    pub fn acknowledge(&self, seq: u64) -> Result<DeliveryState, JobError> {
        lock_inner(&self.shared).events.acknowledge(seq)
    }

    /// Newest retained event `seq` (0 when the log is empty).
    #[must_use]
    pub fn event_head_seq(&self) -> u64 {
        lock_inner(&self.shared).events.head_seq()
    }

    /// Reads retained output of one tracked job (CTX-0513).
    ///
    /// The request is validated fail-closed before anything is read; the
    /// returned view carries truncation honesty flags so callers can
    /// distinguish "the child wrote this much" from "this much survived".
    ///
    /// # Errors
    ///
    /// Returns [`JobError::UnknownJob`] when `id` is not tracked, and
    /// [`JobError::InvalidRead`] when the request is over-bound.
    pub fn read_output(&self, id: JobId, read: ReadOutput) -> Result<OutputView, JobError> {
        let validated = read.validate()?;
        let inner = lock_inner(&self.shared);
        let record = inner.jobs.get(&id).ok_or(JobError::UnknownJob(id))?;
        Ok(record.output.read(&validated))
    }

    /// Metadata-only output index of one tracked job (totals, never bytes).
    ///
    /// # Errors
    ///
    /// Returns [`JobError::UnknownJob`] when `id` is not tracked.
    pub fn output_index(&self, id: JobId) -> Result<OutputIndex, JobError> {
        let inner = lock_inner(&self.shared);
        let record = inner.jobs.get(&id).ok_or(JobError::UnknownJob(id))?;
        Ok(record.output.index())
    }

    /// Evicts finished records whose retention elapsed before `now_ms`,
    /// returning how many were removed.
    ///
    /// [`JobRegistry::spawn`] performs the same reclamation automatically
    /// with the system clock; this explicit form exists for deterministic
    /// callers and tests. Clock skew is saturated, never panicking.
    pub fn sweep(&self, now_ms: u64) -> usize {
        lock_inner(&self.shared).evict_expired(now_ms)
    }
}

// ── registry state ──────────────────────────────────────────────────────────

// ── authorization helpers ─────────────────────────────────────────────────────

/// Sends one `write_input` payload through a claimed PTY stdin half.
///
/// The half is returned to the caller either way (inside the outcome), so
/// the call site can hand it back to the record: a live half stays usable
/// for the next write, a broken one is dropped with the outcome.
fn write_to_pty_stdin(mut writer: PtyStdinWriter, data: &[u8]) -> WriteOutcome {
    use std::io::Write as _;
    let result = writer
        .write_all(data)
        .and_then(|()| writer.flush())
        .map(|()| data.len())
        .map_err(|error| {
            JobError::unsupported(format!("interactive stdin refused the write: {error}"))
        });
    WriteOutcome {
        result,
        writer: Some(writer),
    }
}

/// One `write_input_as` attempt: the result plus the claimed writer half.
///
/// A failed write drops the half with the outcome (the child is gone, so
/// the half is useless); a success returns it for the next call.
struct WriteOutcome {
    result: Result<usize, JobError>,
    writer: Option<PtyStdinWriter>,
}

impl WriteOutcome {
    fn ok_writer(&mut self) -> Option<PtyStdinWriter> {
        if self.result.is_ok() {
            self.writer.take()
        } else {
            None
        }
    }

    fn into_result(self) -> Result<usize, JobError> {
        self.result
    }
}

/// Authorizes `principal` for `operation` on an optionally-present record.
///
/// Deny by default with hidden existence: when the record is missing, or the
/// principal holds no grant, the same `Denied` is returned — never
/// `UnknownJob` — so a denied caller cannot probe whether the id is real.
/// Callers that pass authorization then re-resolve the record and report
/// `UnknownJob` on the unreachable path.
fn authorize_strict(
    #[allow(unused_variables)] inner: &RegistryInner,
    principal: &JobPrincipal,
    record: Option<&JobRecord>,
    id: JobId,
    operation: JobOperation,
) -> Result<(), JobError> {
    let _ = id;
    match record {
        Some(record) if record.authorized(principal, operation) => Ok(()),
        _ => Err(JobError::denied(
            operation,
            "caller holds no grant for this operation",
        )),
    }
}

/// Like [`authorize_strict`] but keyed for `observe` reads.
fn authorize_observe(
    inner: &RegistryInner,
    principal: &JobPrincipal,
    record: Option<&JobRecord>,
    id: JobId,
    operation: JobOperation,
) -> Result<(), JobError> {
    authorize_strict(inner, principal, record, id, operation)
}

fn lock_inner(shared: &Shared) -> MutexGuard<'_, RegistryInner> {
    shared.lock().unwrap_or_else(PoisonError::into_inner)
}

struct RegistryInner {
    capacity: usize,
    next_id: u64,
    jobs: BTreeMap<JobId, JobRecord>,
    events: DeliveryLog,
    /// Starts drain workers; a test seam for spawn failures (CORE-RUN-005).
    worker_spawner: WorkerSpawner,
    /// Where per-job cgroup leaves come from (CTX-0880).
    cgroups: CgroupSource,
}

/// Starts one named worker thread for a job backend.
///
/// Production uses [`spawn_worker`]; the unit tests inject a failing spawner
/// to prove a drain that cannot start never leaves a live, undrained job.
type WorkerSpawner =
    fn(String, Box<dyn FnOnce() + Send + 'static>) -> std::io::Result<thread::JoinHandle<()>>;

/// Default [`WorkerSpawner`]: a named OS thread.
fn spawn_worker(
    name: String,
    work: Box<dyn FnOnce() + Send + 'static>,
) -> std::io::Result<thread::JoinHandle<()>> {
    thread::Builder::new().name(name).spawn(work)
}

impl RegistryInner {
    /// Mints the execution generation for a freshly allocated `id`.
    ///
    /// Random per spawn (the std hasher's OS-seeded keys mixed with the id
    /// and the clock), so a handle minted by another registry, another
    /// process, or before a restart never matches a job here even when the
    /// ids coincide. Stored on the record: it never changes for a job.
    fn generation_for(&self, id: JobId) -> ExecutionGeneration {
        use std::hash::{BuildHasher as _, Hasher as _};
        let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
        hasher.write_u64(id.get());
        hasher.write_u64(now_ms());
        ExecutionGeneration::from_nonzero(
            std::num::NonZeroU64::new(hasher.finish()).unwrap_or(std::num::NonZeroU64::MIN),
        )
    }

    /// Issues the next id. Ids start at 1 and are never reused.
    fn allocate_id(&mut self) -> Result<JobId, JobError> {
        let id = JobId::from_raw(self.next_id).ok_or_else(id_space_exhausted)?;
        self.next_id = self.next_id.checked_add(1).ok_or_else(id_space_exhausted)?;
        Ok(id)
    }

    /// Removes finished records whose retention elapsed.
    fn evict_expired(&mut self, now_ms: u64) -> usize {
        let before = self.jobs.len();
        self.jobs.retain(|_, record| {
            let (JobState::Done(_), Some(finished_at_ms)) = (record.state, record.finished_at_ms)
            else {
                return true;
            };
            let age = Duration::from_millis(now_ms.saturating_sub(finished_at_ms));
            age < record.spec.timeouts.effective_retention()
        });
        before - self.jobs.len()
    }
}

fn id_space_exhausted() -> JobError {
    JobError::Unavailable {
        reason: "job id space exhausted".into(),
    }
}

struct JobRecord {
    id: JobId,
    /// Execution generation minted at spawn (the host's handle fence).
    generation: ExecutionGeneration,
    spec: JobSpec,
    state: JobState,
    started_at_ms: Option<u64>,
    finished_at_ms: Option<u64>,
    control: Arc<JobControl>,
    output: OutputSink,
    /// The adopted owned tree while the job runs (published by the
    /// supervisor at start, cleared at the terminal event); `signal_as`
    /// delivers through it.
    tree: Option<Arc<OwnedTree>>,
    /// What a kill reaches for this job (reported on every snapshot).
    kill_scope: KillScope,
    /// OOM evidence for this job (reported on every snapshot, CTX-0880).
    oom_evidence: OomEvidence,
    /// Owning principal: assigned once at spawn, moves only via `transfer`.
    /// Ownership confers every operation implicitly (never a table entry).
    /// `None` marks a legacy phase-1 record (spawned through [`JobRegistry::spawn`]):
    /// scoped calls deny on it, so the legacy path never confers scoped
    /// authority and scoped ownership never leaks into the legacy path.
    owner: Option<JobPrincipal>,
    /// Explicit per-principal delegations on this job (bounded, per-job).
    grants: BTreeSet<JobGrant>,
    /// Per-principal `write_input` call budgets (bounded, per-job).
    write_budget: RateBudget,
    /// Per-principal `signal` call budgets (bounded, per-job).
    signal_budget: RateBudget,
    /// Live PTY stdin half, published by the supervisor once the PTY backend
    /// starts. `Mutex<Option<...>>` because exactly one `write_input_as`
    /// call may hold it at a time; pipe jobs and pre-start jobs hold `None`.
    pty_stdin: Arc<Mutex<Option<PtyStdinWriter>>>,
    /// Last observed PTY echo state for the sensitive-input interlock
    /// (RUN-22): the host records the slave `termios` `ECHO` bit here, and
    /// [`JobRegistry::write_input_as`] re-checks it on every dispatch.
    /// Defaults to [`EchoState::EchoOn`]; the host sets
    /// [`EchoState::NoEcho`] while a no-echo program reads.
    echo: EchoState,
    /// Interaction class for the sensitive-input interlock (RUN-22): the
    /// host sorts it with [`InteractionClass::classify`] (or the
    /// verdict-fed [`classify_with_verdict`](crate::sensitive_input::classify_with_verdict))
    /// and [`JobRegistry::write_input_as`] enforces it together with
    /// `echo`. Defaults to [`InteractionClass::SafeInteractive`].
    interaction: InteractionClass,
}

impl JobRecord {
    /// Owned record: `owner` holds the full operation set implicitly.
    fn owned(
        id: JobId,
        generation: ExecutionGeneration,
        spec: JobSpec,
        control: Arc<JobControl>,
        output: OutputSink,
        owner: JobPrincipal,
    ) -> Self {
        Self {
            id,
            generation,
            spec,
            state: JobState::Queued,
            started_at_ms: None,
            finished_at_ms: None,
            control,
            output,
            tree: None,
            kill_scope: KillScope::DirectChild,
            oom_evidence: OomEvidence::Pending,
            owner: Some(owner),
            grants: BTreeSet::new(),
            write_budget: RateBudget::new(
                MAX_WRITES_PER_WINDOW,
                Duration::from_millis(MAX_WRITE_INPUT_WINDOW_MS),
            ),
            signal_budget: RateBudget::new(
                MAX_SIGNALS_PER_WINDOW,
                Duration::from_millis(MAX_SIGNAL_WINDOW_MS),
            ),
            pty_stdin: Arc::new(Mutex::new(None)),
            echo: EchoState::EchoOn,
            interaction: InteractionClass::SafeInteractive,
        }
    }

    /// Legacy phase-1 record: no owner, so the ambient `spawn`/`get` path
    /// keeps working. Scoped `*_as` calls deny on these records (there is
    /// no owner to authorize against), which keeps the two APIs from
    /// conferring authority on each other.
    fn unowned(
        id: JobId,
        generation: ExecutionGeneration,
        spec: JobSpec,
        control: Arc<JobControl>,
        output: OutputSink,
    ) -> Self {
        Self {
            id,
            generation,
            spec,
            state: JobState::Queued,
            started_at_ms: None,
            finished_at_ms: None,
            control,
            output,
            tree: None,
            kill_scope: KillScope::DirectChild,
            oom_evidence: OomEvidence::Pending,
            owner: None,
            grants: BTreeSet::new(),
            write_budget: RateBudget::new(
                MAX_WRITES_PER_WINDOW,
                Duration::from_millis(MAX_WRITE_INPUT_WINDOW_MS),
            ),
            signal_budget: RateBudget::new(
                MAX_SIGNALS_PER_WINDOW,
                Duration::from_millis(MAX_SIGNAL_WINDOW_MS),
            ),
            pty_stdin: Arc::new(Mutex::new(None)),
            echo: EchoState::EchoOn,
            interaction: InteractionClass::SafeInteractive,
        }
    }

    /// Host handle for this execution.
    fn handle(&self) -> ExecutionHandle {
        ExecutionHandle {
            id: self.id,
            generation: self.generation,
        }
    }

    /// Legacy cancel: an immediate request for the current generation.
    fn legacy_cancel(&self) -> JobCancel {
        if let JobState::Done(outcome) = self.state {
            return JobCancel::AlreadyStopped(outcome);
        }
        self.control
            .request_cancel(CancelRequest::immediate(self.handle()));
        JobCancel::Requested
    }

    /// Typed cancel after authorization: generation fence, then the
    /// terminal check, then acceptance.
    fn typed_cancel(&self, request: CancelRequest) -> CancelReceipt {
        if request.handle().generation != self.generation {
            return CancelReceipt::Resolved(CancelOutcome::StaleGeneration);
        }
        if self.state.is_terminal() {
            return CancelReceipt::Resolved(CancelOutcome::AlreadyExited);
        }
        self.control.request_cancel(request);
        CancelReceipt::Accepted
    }

    fn authorized(&self, principal: &JobPrincipal, operation: JobOperation) -> bool {
        if self.owner.as_ref() == Some(principal) {
            return true;
        }
        self.grants
            .contains(&JobGrant::new(principal.clone(), operation))
    }

    /// Claims the live PTY stdin half for one `write_input_as` call.
    ///
    /// Returns `None` for pipe jobs, pre-start jobs, or while another write
    /// holds the half (fail-closed, never blocks).
    fn pty_writer(&self) -> Option<PtyStdinWriter> {
        self.pty_stdin.lock().ok()?.take()
    }

    /// Returns a claimed stdin half after the write (or a failed claim).
    fn return_pty_writer(&self, writer: Option<PtyStdinWriter>) {
        // MSRV 1.85 has no let-chains (edition-2024 `let` in `&&` position
        // is 1.88+): nest instead.
        if let Some(writer) = writer {
            if let Ok(mut slot) = self.pty_stdin.lock() {
                *slot = Some(writer);
            }
        }
    }
}

/// The live PTY writer half, published by the supervisor once the PTY
/// backend starts and claimed by one `write_input_as` call at a time.
type PtyStdinWriter = bitty_pty::PtyWriter;

/// Fixed-window per-(job, operation) call budget.
///
/// Counts authorized calls only (denied callers never reach the budget), and
/// resets the window once it elapses. Bounded: two counters plus one
/// timestamp per budget, never a per-call log.
#[derive(Debug)]
struct RateBudget {
    max_calls: u64,
    window: Duration,
    window_start: Instant,
    used: u64,
}

impl RateBudget {
    fn new(max_calls: u64, window: Duration) -> Self {
        Self {
            max_calls,
            window,
            window_start: Instant::now(),
            used: 0,
        }
    }

    /// Records one authorized call; `false` means the budget is spent.
    fn check(&mut self) -> bool {
        let now = Instant::now();
        if now.saturating_duration_since(self.window_start) >= self.window {
            self.window_start = now;
            self.used = 0;
        }
        if self.used >= self.max_calls {
            return false;
        }
        self.used = self.used.saturating_add(1);
        true
    }
}

impl JobRecord {
    fn snapshot(&self) -> JobSnapshot {
        JobSnapshot {
            id: self.id,
            state: self.state,
            spec: self.spec.clone(),
            started_at_ms: self.started_at_ms,
            finished_at_ms: self.finished_at_ms,
            output: self.output.index(),
            generation: self.generation,
            kill_scope: self.kill_scope,
            oom_evidence: self.oom_evidence,
        }
    }
}

/// Shared control surface between the registry and one supervisor thread.
#[derive(Debug)]
struct JobControl {
    /// The strongest pending cancel request; the supervisor takes it.
    cancel: Mutex<Option<CancelRequest>>,
    clock: Arc<ActivityClock>,
    /// Set once the host itself sent `SIGKILL` to the job (an owner's
    /// `signal_as(Kill)`, a cancel, or a deadline): a SIGKILL death is then
    /// the host's kill, never classified as the kernel's OOM kill.
    host_killed: std::sync::atomic::AtomicBool,
}

impl JobControl {
    fn new() -> Self {
        Self {
            cancel: Mutex::new(None),
            clock: Arc::new(ActivityClock::new()),
            host_killed: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Records that the host is about to deliver `SIGKILL` (set before the
    /// delivery, so the exit it causes can never be observed without it).
    fn note_host_kill(&self) {
        self.host_killed.store(true, Ordering::SeqCst);
    }

    /// Whether the host delivered (or attempted) a `SIGKILL`.
    fn host_killed(&self) -> bool {
        self.host_killed.load(Ordering::SeqCst)
    }

    /// Records `request`, coalescing with a pending one: the higher-ranked
    /// mode wins, and on a tie the newer request (its grace) replaces the
    /// older. The supervisor answers every coalesced request with the one
    /// `CancelResolved` it publishes.
    fn request_cancel(&self, request: CancelRequest) {
        let mut pending = self.cancel.lock().unwrap_or_else(PoisonError::into_inner);
        let keep = match *pending {
            Some(current) if current.mode().rank() > request.mode().rank() => current,
            _ => request,
        };
        *pending = Some(keep);
    }

    /// Takes the pending request, if any.
    fn take_cancel(&self) -> Option<CancelRequest> {
        self.cancel
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }
}

/// Monotonic activity clock for the idle deadline.
///
/// Stores the last observed output time as milliseconds since job start;
/// drain threads touch it on every chunk, the supervisor reads it when
/// checking the idle deadline.
#[derive(Debug)]
struct ActivityClock {
    start: Instant,
    last_ms: AtomicU64,
}

impl ActivityClock {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            last_ms: AtomicU64::new(0),
        }
    }

    /// Records activity at `now`.
    fn touch(&self) {
        self.touch_at(Instant::now());
    }

    /// Records activity at an explicit instant (deterministic tests).
    fn touch_at(&self, now: Instant) {
        self.last_ms.store(self.elapsed_ms(now), Ordering::Relaxed);
    }

    /// Time since the last recorded activity.
    fn idle_for(&self, now: Instant) -> Duration {
        let idle_ms = self
            .elapsed_ms(now)
            .saturating_sub(self.last_ms.load(Ordering::Relaxed));
        Duration::from_millis(idle_ms)
    }

    fn elapsed_ms(&self, now: Instant) -> u64 {
        u64::try_from(now.saturating_duration_since(self.start).as_millis()).unwrap_or(u64::MAX)
    }
}

// ── supervision ─────────────────────────────────────────────────────────────

fn supervise(
    shared: Shared,
    id: JobId,
    spec: JobSpec,
    control: Arc<JobControl>,
    output: OutputSink,
) {
    lock_inner(&shared).events.push(JobEvent::Queued {
        id,
        at_ms: now_ms(),
    });
    if control.take_cancel().is_some() {
        resolve_cancel(&shared, id, CancelOutcome::CancelledBeforeStart);
        finish(
            &shared,
            id,
            ExecutionOutcome::Cancelled(CancelEffect::BeforeStart),
            OomEvidence::Missing(OomEvidenceGap::NotStarted),
        );
        return;
    }
    // The stdin channel is published before the backend starts so a racing
    // `write_input_as` either finds it (PTY) or fails closed (pipes), never
    // a stale half from a previous job: ids are never reused.
    let stdin_writer_slot = stdin_slot_handle(&shared, id);
    let (worker_spawner, cgroups, generation) = {
        let inner = lock_inner(&shared);
        let generation = inner
            .jobs
            .get(&id)
            .map_or(0, |record| record.generation.get());
        (inner.worker_spawner, inner.cgroups.clone(), generation)
    };
    // The leaf exists and its starting counter is read before the spawn;
    // the backend moves the leader in right after it (CTX-0880).
    let mut accounting = JobAccounting::prepare(cgroups, id.get(), generation);
    let mut backend = match Backend::start(
        &spec,
        Arc::clone(&control.clock),
        output,
        stdin_writer_slot,
        worker_spawner,
        &mut accounting,
    ) {
        Ok(backend) => backend,
        Err(_) => {
            // Spawn failures are reported as a terminal state, never as a
            // crash: the caller keeps a job id to observe. A start that got
            // as far as a child process already killed and reaped it, so
            // no live job is ever left without its drains (CORE-RUN-005).
            finish(
                &shared,
                id,
                ExecutionOutcome::SpawnFailed,
                accounting.abandon(),
            );
            return;
        }
    };
    mark_running(&shared, id, backend.tree(), accounting.running_evidence());
    let mut accounting = Some(accounting);
    let outcome = watch(&shared, id, &spec, &mut backend, &control, &mut accounting);
    // Paths that ended the job without a natural exit (cancel, deadline)
    // still take the final reading once the tree is gone.
    let evidence = match accounting.take() {
        Some(accounting) => accounting.finish(),
        None => lock_inner(&shared)
            .jobs
            .get(&id)
            .map_or(OomEvidence::Pending, |record| record.oom_evidence),
    };
    // The terminal state is published after the reap and the time-boxed
    // drain join: the output store is quiescent unless a member escaped
    // the owned tree and still holds a pipe.
    finish(&shared, id, outcome, evidence);
}

/// Returns the shared stdin-writer slot for `id` when the job is interactive.
///
/// Pipe jobs (and unknown ids) yield `None`: their `write_input_as` fails
/// closed with `Unsupported`. The slot is empty until the PTY backend takes
/// the writer half and publishes it (see `PtyJob::start`); writers claim it
/// for one call at a time.
fn stdin_slot_handle(shared: &Shared, id: JobId) -> Option<Arc<Mutex<Option<PtyStdinWriter>>>> {
    let inner = lock_inner(shared);
    let record = inner.jobs.get(&id)?;
    (record.spec.io == JobIo::Pty).then(|| Arc::clone(&record.pty_stdin))
}

/// Observes exit, cancel, and deadlines until the job terminates, and
/// returns its authoritative outcome.
///
/// Checks the process first (a job that already exited keeps its own exit
/// outcome, never `Cancelled`), then a pending cancel, then the deadlines.
/// Every path that ends the job has killed what is left of the owned tree
/// and reaped the leader before it returns.
fn watch(
    shared: &Shared,
    id: JobId,
    spec: &JobSpec,
    backend: &mut Backend,
    control: &JobControl,
    accounting: &mut Option<JobAccounting>,
) -> ExecutionOutcome {
    let hard_deadline = spec
        .timeouts
        .hard
        .and_then(|hard| Instant::now().checked_add(hard));
    loop {
        if let Some(exit) = backend.poll_exit() {
            // `poll_exit` returns only after the leader is reaped and the
            // owned tree killed, so the leaf's final `oom_kill` reading is
            // complete. Only a leaf reading yields `OomKilled`; every gap
            // is `Unknown`, so a SIGKILL death is never guessed as OOM.
            let evidence = accounting
                .take()
                .map_or(OomEvidence::Pending, JobAccounting::finish);
            set_oom_evidence(shared, id, evidence);
            let verdict = exit_oom_verdict(evidence, control.host_killed());
            return ExecutionOutcome::classify_exit(exit, verdict);
        }
        if let Some(request) = control.take_cancel() {
            let (resolution, ended) = execute_cancel(backend, control, request);
            resolve_cancel(shared, id, resolution);
            if let Some(outcome) = ended {
                return outcome;
            }
            continue;
        }
        let now = Instant::now();
        let clock = if hard_deadline.is_some_and(|deadline| now >= deadline) {
            Some(DeadlineClock::Hard)
        } else if spec
            .timeouts
            .idle
            .is_some_and(|idle| control.clock.idle_for(now) >= idle)
        {
            Some(DeadlineClock::Idle)
        } else {
            None
        };
        if let Some(clock) = clock {
            // A kill the kernel refuses (never expected for an own child)
            // leaves the leader to the backend's drop path; the deadline
            // fired, so the outcome is `TimedOut` either way.
            control.note_host_kill();
            let _ = backend.kill_and_reap();
            return ExecutionOutcome::TimedOut(clock);
        }
        thread::sleep(POLL_INTERVAL);
    }
}

/// The verdict the outcome classifier gets for a job's exit.
///
/// Only a leaf reading can claim an OOM kill, and only when the host did
/// not send `SIGKILL` itself: after a host kill (owner `signal_as(Kill)`,
/// cancel, or deadline) a SIGKILL death is the host's, so the outcome stays
/// `Signaled(9)` and an advanced counter survives only as the job's
/// [`OomEvidence::OomKilled`] evidence.
fn exit_oom_verdict(evidence: OomEvidence, host_killed: bool) -> crate::oom::OomVerdict {
    if host_killed {
        crate::oom::OomVerdict::Unknown
    } else {
        evidence.verdict()
    }
}

/// How a wait inside a cancel ended.
enum Waited {
    /// The job's process ended (and was reaped).
    Exited,
    /// A stronger cancel request arrived and takes over.
    Escalated(CancelRequest),
    /// The grace period elapsed with the job still running.
    Elapsed,
}

/// Executes one cancel request against the owned tree (the host owns the
/// sequence; callers only read the typed answer).
///
/// Returns the cancel outcome plus the job outcome when the cancel ended
/// the job. `Graceful` sends `SIGINT` and waits; `GracefulThenKill` adds
/// `SIGTERM` and a kill; `Immediate` kills. A stronger request arriving
/// during a wait escalates this one in place, keeping the steps already
/// taken; weaker or equal ones coalesce into it.
fn execute_cancel(
    backend: &mut Backend,
    control: &JobControl,
    first: CancelRequest,
) -> (CancelOutcome, Option<ExecutionOutcome>) {
    let mut request = first;
    let mut sent = 0usize;
    loop {
        let graceful: &[TreeSignal] = match request.mode() {
            CancelMode::Immediate => &[],
            CancelMode::Graceful => &[TreeSignal::Interrupt],
            CancelMode::GracefulThenKill => &[TreeSignal::Interrupt, TreeSignal::Terminate],
        };
        if let Some(&signal) = graceful.get(sent) {
            sent += 1;
            match backend.signal_tree(signal) {
                // An empty group means the tree is already going away: the
                // wait below observes the exit.
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    if request.mode() == CancelMode::Graceful {
                        return (refused_outcome(&error), None);
                    }
                    // Escalating modes go straight to the kill.
                    sent = graceful.len();
                    continue;
                }
            }
            match wait_for_exit(backend, control, request) {
                Waited::Exited => {
                    return (
                        CancelOutcome::CancelledGracefully,
                        Some(ExecutionOutcome::Cancelled(CancelEffect::Graceful)),
                    );
                }
                Waited::Escalated(stronger) => request = stronger,
                Waited::Elapsed => {}
            }
            continue;
        }
        if request.mode() == CancelMode::Graceful {
            return (CancelOutcome::StillRunning, None);
        }
        control.note_host_kill();
        return match backend.kill_and_reap() {
            Ok(_) => (
                CancelOutcome::Killed,
                Some(ExecutionOutcome::Cancelled(CancelEffect::Killed)),
            ),
            Err(error) => (refused_outcome(&error), None),
        };
    }
}

/// Maps a refused signal onto the typed cancel vocabulary.
fn refused_outcome(error: &std::io::Error) -> CancelOutcome {
    match error.kind() {
        std::io::ErrorKind::PermissionDenied => CancelOutcome::PermissionDenied,
        std::io::ErrorKind::Unsupported => CancelOutcome::Unsupported,
        _ => CancelOutcome::Unknown,
    }
}

/// Waits up to the request's grace period for the job to end, watching for
/// an escalating request. A zero grace checks once.
fn wait_for_exit(backend: &mut Backend, control: &JobControl, request: CancelRequest) -> Waited {
    let deadline = Instant::now().checked_add(request.grace());
    loop {
        if backend.poll_exit().is_some() {
            return Waited::Exited;
        }
        if let Some(next) = control.take_cancel() {
            if next.mode().rank() > request.mode().rank() {
                return Waited::Escalated(next);
            }
            // Equal or weaker: coalesced into the running cancel.
        }
        if deadline.is_none_or(|deadline| Instant::now() >= deadline) {
            return Waited::Elapsed;
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn mark_running(
    shared: &Shared,
    id: JobId,
    tree: Option<Arc<OwnedTree>>,
    oom_evidence: OomEvidence,
) {
    let at_ms = now_ms();
    let mut inner = lock_inner(shared);
    if let Some(record) = inner.jobs.get_mut(&id) {
        record.state = JobState::Running;
        record.oom_evidence = oom_evidence;
        record.started_at_ms = Some(at_ms);
        record.kill_scope = if tree.is_some() {
            KillScope::OwnedTree
        } else {
            KillScope::DirectChild
        };
        record.tree = tree;
    }
    inner.events.push(JobEvent::Started { id, at_ms });
}

fn resolve_cancel(shared: &Shared, id: JobId, outcome: CancelOutcome) {
    lock_inner(shared).events.push(JobEvent::CancelResolved {
        id,
        outcome,
        at_ms: now_ms(),
    });
}

/// Records the job's final OOM evidence before its outcome is published.
fn set_oom_evidence(shared: &Shared, id: JobId, evidence: OomEvidence) {
    if let Some(record) = lock_inner(shared).jobs.get_mut(&id) {
        record.oom_evidence = evidence;
    }
}

fn finish(shared: &Shared, id: JobId, outcome: ExecutionOutcome, oom_evidence: OomEvidence) {
    let at_ms = now_ms();
    let mut inner = lock_inner(shared);
    let mut unanswered = None;
    if let Some(record) = inner.jobs.get_mut(&id) {
        record.state = JobState::Done(outcome);
        record.oom_evidence = oom_evidence;
        record.finished_at_ms = Some(at_ms);
        // The leader is reaped: no signal may reach its recycled id.
        record.tree = None;
        // A request accepted while the job was still live but never
        // executed (natural exit, deadline, failed start) still gets its
        // one typed answer.
        unanswered = record.control.take_cancel();
    }
    if unanswered.is_some() {
        inner.events.push(JobEvent::CancelResolved {
            id,
            outcome: CancelOutcome::AlreadyExited,
            at_ms,
        });
    }
    inner.events.push(JobEvent::Stopped { id, outcome, at_ms });
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

// ── process backends ────────────────────────────────────────────────────────

/// Why a backend could not start (CORE-RUN-005).
///
/// The supervisor only needs the fact (the job becomes
/// [`ExecutionOutcome::SpawnFailed`]); the fields are diagnostics the unit
/// tests read to prove a partially started child was killed and reaped.
#[derive(Debug)]
#[cfg_attr(not(test), allow(dead_code))]
struct StartFailure {
    reason: String,
    /// Pid of a partially started child that was killed and reaped before
    /// the failure was reported; `None` when no process was created.
    reaped_pid: Option<u32>,
}

impl StartFailure {
    /// No process was created.
    fn before_spawn(reason: impl fmt::Display) -> Self {
        Self {
            reason: reason.to_string(),
            reaped_pid: None,
        }
    }

    /// The child `pid` existed and the start killed it; `reap` is the
    /// cleanup's reap result. Only a successful reap reports the pid as
    /// reaped: a failed one keeps `reaped_pid: None` and names the cleanup
    /// error, so the failure is never reported as a finished cleanup.
    fn after_cleanup<E: fmt::Display>(
        pid: Option<u32>,
        reap: Result<(), E>,
        reason: impl fmt::Display,
    ) -> Self {
        match reap {
            Ok(()) => Self {
                reason: reason.to_string(),
                reaped_pid: pid,
            },
            Err(error) => Self {
                reason: format!("{reason}; cleanup reap failed: {error}"),
                reaped_pid: None,
            },
        }
    }
}

/// Adopts the owned tree led by a fresh, already-running child (the PTY
/// child), or `None` where no backend exists or adoption failed (the job
/// then reports [`KillScope::DirectChild`]).
fn adopt_tree(leader: Option<u32>) -> Option<Arc<OwnedTree>> {
    leader
        .and_then(|pid| OwnedTree::adopt(pid).ok())
        .map(Arc::new)
}

/// Adopts the owned tree led by a fresh child spawned from an
/// [`OwnedTree::prepare_command`] command. On Windows that child starts
/// suspended; [`OwnedTree::adopt_prepared`] resumes it on every path,
/// including a failed adoption (which then yields `None`, direct-child
/// scope, over a running child).
fn adopt_prepared_tree(leader: u32) -> Option<Arc<OwnedTree>> {
    OwnedTree::adopt_prepared(leader).ok().map(Arc::new)
}

/// Converts a reaped `std` status.
fn observe_std_status(status: std::process::ExitStatus) -> ExitObservation {
    if let Some(code) = status.code() {
        return ExitObservation::Code(code);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt as _;
        if let Some(signal) = status.signal() {
            return ExitObservation::Signal(signal);
        }
    }
    ExitObservation::Unobservable
}

/// Converts a reaped PTY status. The PTY primitive names a terminating
/// signal but not its number, so a signalled PTY child is unobservable here
/// (the owned-tree observer reports the number where it exists).
fn observe_pty_status(status: &bitty_pty::ExitStatus) -> ExitObservation {
    if status.signal().is_some() {
        ExitObservation::Unobservable
    } else if status.is_success() {
        ExitObservation::Code(0)
    } else {
        i32::try_from(status.code()).map_or(ExitObservation::Unobservable, ExitObservation::Code)
    }
}

/// Converts a non-reaping leader observation (`None`: read the reap).
fn observe_leader(exit: LeaderExit) -> Option<ExitObservation> {
    match exit {
        LeaderExit::Exited(code) => Some(ExitObservation::Code(code)),
        LeaderExit::Signaled(signal) => Some(ExitObservation::Signal(signal)),
        LeaderExit::StatusUnavailable => None,
    }
}

enum Backend {
    Pipe(PipeJob),
    Pty(PtyJob),
}

impl Backend {
    fn start(
        spec: &JobSpec,
        clock: Arc<ActivityClock>,
        output: OutputSink,
        stdin_writer_slot: Option<Arc<Mutex<Option<PtyStdinWriter>>>>,
        worker_spawner: WorkerSpawner,
        accounting: &mut JobAccounting,
    ) -> Result<Self, StartFailure> {
        match spec.io {
            JobIo::Pipes => PipeJob::start_placed(spec, clock, output, worker_spawner, accounting)
                .map(Self::Pipe),
            JobIo::Pty => PtyJob::start_placed(
                spec,
                clock,
                output,
                stdin_writer_slot,
                worker_spawner,
                accounting,
            )
            .map(Self::Pty),
        }
    }

    /// The adopted owned tree, if any.
    fn tree(&self) -> Option<Arc<OwnedTree>> {
        match self {
            Self::Pipe(job) => job.tree.clone(),
            Self::Pty(job) => job.tree.clone(),
        }
    }

    /// Non-blocking end observation. Once the process ended, kills what is
    /// left of the owned tree, reaps the leader, and (pipes) joins the
    /// drains, then keeps returning the same observation.
    fn poll_exit(&mut self) -> Option<ExitObservation> {
        match self {
            Self::Pipe(job) => job.poll_exit(),
            Self::Pty(job) => job.poll_exit(),
        }
    }

    /// Delivers a graceful signal to the owned tree.
    ///
    /// Without a tree only [`TreeSignal::Kill`] reaches the direct child;
    /// graceful signals fail with [`std::io::ErrorKind::Unsupported`]
    /// instead of pretending.
    fn signal_tree(&mut self, signal: TreeSignal) -> std::io::Result<()> {
        match self {
            Self::Pipe(job) => job.signal_tree(signal),
            Self::Pty(job) => job.signal_tree(signal),
        }
    }

    /// Kills the owned tree (or the direct child), then reaps the leader.
    ///
    /// # Errors
    ///
    /// Returns the kernel's refusal when neither the tree nor the direct
    /// child could be signalled; nothing is reaped then (a blocking reap of
    /// an unkillable child would wedge the supervisor).
    fn kill_and_reap(&mut self) -> std::io::Result<ExitObservation> {
        match self {
            Self::Pipe(job) => job.kill_and_reap(),
            Self::Pty(job) => job.kill_and_reap(),
        }
    }
}

/// Upper bound on joining drain workers after the reap: a member that
/// escaped the owned tree and still holds a pipe must not wedge the
/// supervisor. Bytes drained so far stay in the store either way.
const DRAIN_JOIN_BOUND: Duration = Duration::from_secs(5);

/// Joins finished drains within [`DRAIN_JOIN_BOUND`]; unfinished ones are
/// detached and keep their bounded store clone until EOF.
fn join_drains(drains: &mut Vec<thread::JoinHandle<()>>) {
    let deadline = Instant::now().checked_add(DRAIN_JOIN_BOUND);
    while !drains.iter().all(thread::JoinHandle::is_finished) {
        if deadline.is_none_or(|deadline| Instant::now() >= deadline) {
            break;
        }
        thread::sleep(Duration::from_millis(1));
    }
    for drain in drains.drain(..) {
        if drain.is_finished() {
            let _ = drain.join();
        }
    }
}

/// Builds the closed-environment pipe command for the job supervisor.
///
/// Argv-only (no shell), ambient environment cleared, explicit variables
/// only, stdin closed, stdout/stderr piped. This is the supervisor-local
/// copy of the constructor the CTX-0442 synchronous provider also owns in
/// Core: the two execution surfaces keep the same argv/closed-env shape
/// without a shared dependency.
fn closed_pipe_command(
    program: &str,
    args: &[String],
    cwd: Option<&str>,
    env: &EnvPolicy,
) -> Command {
    let mut command = Command::new(program);
    command.args(args);
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    command.env_clear();
    if let EnvPolicy::Explicit { vars } = env {
        for var in vars {
            command.env(&var.name, &var.value);
        }
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

/// Pipe-backed job: closed stdin, piped stdout/stderr, bounded drain.
///
/// The child leads its own process group and, where a backend exists, its
/// owned tree is adopted right after the spawn. Each drain thread feeds its
/// stream into the job's bounded output store (newest bytes win, oldest
/// evicted first) and timestamps activity for the idle deadline. Drain
/// handles are joined after the leader is reaped and the rest of the tree
/// is killed, so the store is quiescent before the terminal event.
struct PipeJob {
    child: Child,
    tree: Option<Arc<OwnedTree>>,
    exited: Option<ExitObservation>,
    drains: Vec<thread::JoinHandle<()>>,
}

impl PipeJob {
    /// Spawns the child, adopts its owned tree, then starts one drain worker
    /// per stream.
    ///
    /// A drain worker that cannot start fails the whole start: the tree and
    /// the child are killed and the child reaped first, so the job ends as a
    /// typed [`ExecutionOutcome::SpawnFailed`] instead of a live process
    /// nobody drains (CORE-RUN-005).
    #[cfg(test)]
    fn start(
        spec: &JobSpec,
        clock: Arc<ActivityClock>,
        output: OutputSink,
        worker_spawner: WorkerSpawner,
    ) -> Result<Self, StartFailure> {
        let mut accounting = JobAccounting::prepare(CgroupSource::NotConfigured, 0, 0);
        Self::start_placed(spec, clock, output, worker_spawner, &mut accounting)
    }

    /// Starts the pipe job and moves the leader into the job's cgroup leaf
    /// right after the spawn, before the tree is adopted and the drains run
    /// (the residual placement window is documented in the `cgroup` module).
    fn start_placed(
        spec: &JobSpec,
        clock: Arc<ActivityClock>,
        output: OutputSink,
        worker_spawner: WorkerSpawner,
        accounting: &mut JobAccounting,
    ) -> Result<Self, StartFailure> {
        let mut command =
            closed_pipe_command(&spec.program, &spec.args, spec.cwd.as_deref(), &spec.env);
        OwnedTree::prepare_command(&mut command);
        let mut child = command.spawn().map_err(StartFailure::before_spawn)?;
        let pid = child.id();
        // Placement only writes the pid into the cgroup leaf (Linux); a
        // Windows child is still suspended here, which placement ignores.
        accounting.place(pid);
        let tree = adopt_prepared_tree(pid);
        let mut drains = Vec::new();
        let started = (|| -> std::io::Result<()> {
            if let Some(stdout) = child.stdout.take() {
                drains.push(spawn_stream_drain(
                    stdout,
                    OutputStream::Stdout,
                    Arc::clone(&clock),
                    output.clone(),
                    worker_spawner,
                )?);
            }
            if let Some(stderr) = child.stderr.take() {
                drains.push(spawn_stream_drain(
                    stderr,
                    OutputStream::Stderr,
                    clock,
                    output,
                    worker_spawner,
                )?);
            }
            Ok(())
        })();
        if let Err(error) = started {
            // Kill and reap before reporting: the drains that did start end
            // at EOF once the tree is gone, and a failed spawn already
            // dropped (closed) its pipe. They are detached, never joined, so
            // an escaped member holding a pipe cannot wedge this path.
            let mut job = Self {
                child,
                tree,
                exited: None,
                drains: Vec::new(),
            };
            // An error means the tree may still be alive or unreaped,
            // which the failure must not hide.
            let reap = job.kill_and_reap().map(drop);
            drop(drains);
            return Err(StartFailure::after_cleanup(
                Some(pid),
                reap,
                format!("job drain worker failed to start: {error}"),
            ));
        }
        Ok(Self {
            child,
            tree,
            exited: None,
            drains,
        })
    }

    fn poll_exit(&mut self) -> Option<ExitObservation> {
        if let Some(exit) = self.exited {
            return Some(exit);
        }
        let observed = match &self.tree {
            Some(tree) => match tree.leader_exit() {
                Ok(None) => return None,
                Ok(Some(exit)) => observe_leader(exit),
                // The observer failed: end the job deterministically.
                Err(_) => {
                    let _ = self.kill_and_reap();
                    self.exited = Some(ExitObservation::Unobservable);
                    return self.exited;
                }
            },
            None => match self.child.try_wait() {
                Ok(None) => return None,
                Ok(Some(status)) => {
                    let exit = observe_std_status(status);
                    join_drains(&mut self.drains);
                    self.exited = Some(exit);
                    return self.exited;
                }
                Err(_) => {
                    let _ = self.kill_and_reap();
                    self.exited = Some(ExitObservation::Unobservable);
                    return self.exited;
                }
            },
        };
        // The leader ended on its own: whatever it left behind in its group
        // dies with it, then the (still pinned) leader is reaped.
        let reaped = self.kill_and_reap().ok();
        let exit = observed.or(reaped).unwrap_or(ExitObservation::Unobservable);
        self.exited = Some(exit);
        Some(exit)
    }

    fn signal_tree(&mut self, signal: TreeSignal) -> std::io::Result<()> {
        match (&self.tree, signal) {
            (Some(tree), _) => tree.signal(signal),
            (None, TreeSignal::Kill) => self.child.kill(),
            (None, _) => Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "no owned-tree backend: graceful signals are not delivered",
            )),
        }
    }

    fn kill_and_reap(&mut self) -> std::io::Result<ExitObservation> {
        if let Some(exit) = self.exited {
            return Ok(exit);
        }
        let tree_kill = self.tree.as_ref().map(|tree| tree.signal(TreeSignal::Kill));
        // Always kill the direct child too: a leader that left its group
        // (`setpgid`) is not reached by the group kill, and its unreaped pid
        // cannot be recycled, so this never hits another process. Without
        // it the blocking reap below could wait forever.
        let direct = self.child.kill();
        let tree_ok = matches!(tree_kill, Some(Ok(())))
            || matches!(&tree_kill, Some(Err(e)) if e.kind() == std::io::ErrorKind::NotFound);
        if let Err(error) = direct {
            if !tree_ok && error.kind() == std::io::ErrorKind::PermissionDenied {
                return Err(error);
            }
        }
        let reaped = match &self.tree {
            Some(tree) => tree.retire(|| self.child.wait()),
            None => self.child.wait(),
        };
        let exit = reaped.map_or(ExitObservation::Unobservable, observe_std_status);
        join_drains(&mut self.drains);
        self.exited = Some(exit);
        Ok(exit)
    }
}

/// PTY-backed interactive job: `PtyBuilder` spawn plus a drain thread.
///
/// The PTY primitive inherits the session environment by its accepted
/// terminal contract (DEC-0017) with explicit variables as overrides; the
/// model rejects isolated PTY jobs so no ambient variable can flow in
/// unnoticed. The PTY child is a session leader, so it leads its own owned
/// tree; kills also reach the terminal's foreground job group.
struct PtyJob {
    pty: Pty,
    tree: Option<Arc<OwnedTree>>,
    exited: Option<ExitObservation>,
}

impl PtyJob {
    /// Spawns the PTY child, adopts its owned tree, then starts its drain
    /// worker.
    ///
    /// Like [`PipeJob::start_placed`], a reader or drain that cannot start kills
    /// and reaps the child before the failure is reported (CORE-RUN-005).
    #[cfg(test)]
    fn start(
        spec: &JobSpec,
        clock: Arc<ActivityClock>,
        output: OutputSink,
        stdin_writer_slot: Option<Arc<Mutex<Option<PtyStdinWriter>>>>,
        worker_spawner: WorkerSpawner,
    ) -> Result<Self, StartFailure> {
        let mut accounting = JobAccounting::prepare(CgroupSource::NotConfigured, 0, 0);
        Self::start_placed(
            spec,
            clock,
            output,
            stdin_writer_slot,
            worker_spawner,
            &mut accounting,
        )
    }

    /// Starts the PTY job and moves the PTY leader into the job's cgroup
    /// leaf right after the spawn (see [`PipeJob::start_placed`]).
    fn start_placed(
        spec: &JobSpec,
        clock: Arc<ActivityClock>,
        output: OutputSink,
        stdin_writer_slot: Option<Arc<Mutex<Option<PtyStdinWriter>>>>,
        worker_spawner: WorkerSpawner,
        accounting: &mut JobAccounting,
    ) -> Result<Self, StartFailure> {
        let mut builder = PtyBuilder::new(&spec.program);
        builder = builder.args(spec.args.iter().cloned());
        if let Some(cwd) = &spec.cwd {
            builder = builder.cwd(cwd);
        }
        if let EnvPolicy::Explicit { vars } = &spec.env {
            for var in vars {
                builder = builder.env(&var.name, &var.value);
            }
        }
        let pty = builder.spawn().map_err(StartFailure::before_spawn)?;
        let pid = pty.pid();
        if let Some(pid) = pid {
            accounting.place(pid);
        }
        let tree = adopt_tree(pid);
        let mut job = Self {
            pty,
            tree,
            exited: None,
        };
        let drained = job
            .pty
            .take_reader()
            .map_err(|error| error.to_string())
            .and_then(|reader| {
                spawn_pty_drain(reader, clock, output, worker_spawner)
                    .map_err(|error| format!("job drain worker failed to start: {error}"))
            });
        if let Err(reason) = drained {
            // An error means the tree may still be alive or unreaped,
            // which the failure must not hide.
            let reap = job.kill_and_reap().map(drop);
            return Err(StartFailure::after_cleanup(pid, reap, reason));
        }
        // Publish the writer half into the shared slot (when a scoped job
        // asked for one): `write_input_as` claims it for one call at a time
        // and returns it, so concurrent writers serialize on the slot
        // instead of racing on `take_writer` (which the PTY primitive grants
        // only once). No slot (legacy `spawn` path) keeps the previous
        // behavior — the half is never taken. The publish happens here, on
        // the supervisor thread that owns the PTY handle — never under the
        // registry lock — so there is no lock-ordering hazard.
        if let Some(slot) = stdin_writer_slot {
            // A racing `write_input_as` may claim the slot while it is still
            // `None` (backend starting): that call fails closed with
            // `Unsupported` and retries after `Running` is observable.
            // MSRV 1.85 has no let-chains: nest instead of `&& let`.
            if let Ok(writer) = job.pty.take_writer() {
                if let Ok(mut guard) = slot.lock() {
                    *guard = Some(writer);
                }
            }
        }
        Ok(job)
    }

    fn poll_exit(&mut self) -> Option<ExitObservation> {
        if let Some(exit) = self.exited {
            return Some(exit);
        }
        let observed = match &self.tree {
            Some(tree) => match tree.leader_exit() {
                Ok(None) => return None,
                Ok(Some(exit)) => observe_leader(exit),
                Err(_) => {
                    let _ = self.kill_and_reap();
                    self.exited = Some(ExitObservation::Unobservable);
                    return self.exited;
                }
            },
            None => match self.pty.try_wait() {
                Ok(None) => return None,
                Ok(Some(status)) => {
                    let exit = observe_pty_status(&status);
                    self.exited = Some(exit);
                    return self.exited;
                }
                Err(_) => {
                    let _ = self.kill_and_reap();
                    self.exited = Some(ExitObservation::Unobservable);
                    return self.exited;
                }
            },
        };
        let reaped = self.kill_and_reap().ok();
        let exit = observed.or(reaped).unwrap_or(ExitObservation::Unobservable);
        self.exited = Some(exit);
        Some(exit)
    }

    /// Signals the leader's group and the terminal's foreground job group
    /// (a shell's foreground command leads a group of its own).
    fn signal_tree(&mut self, signal: TreeSignal) -> std::io::Result<()> {
        let Some(tree) = &self.tree else {
            return match signal {
                TreeSignal::Kill => self.pty.kill().map_err(std::io::Error::other),
                _ => Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "no owned-tree backend: graceful signals are not delivered",
                )),
            };
        };
        if let Some(foreground) = self.pty.foreground_pgid() {
            if foreground != tree.leader() {
                let _ = tree.signal_group(foreground, signal);
            }
        }
        tree.signal(signal)
    }

    fn kill_and_reap(&mut self) -> std::io::Result<ExitObservation> {
        if let Some(exit) = self.exited {
            return Ok(exit);
        }
        let exit = match self.tree.clone() {
            Some(tree) => {
                match self.signal_tree(TreeSignal::Kill) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => {
                        // The tree refused: the PTY primitive's own kill of
                        // the direct child is the last resort.
                        if self.pty.kill().is_err() {
                            return Err(error);
                        }
                    }
                }
                tree.retire(|| self.pty.wait())
                    .map_or(ExitObservation::Unobservable, |status| {
                        observe_pty_status(&status)
                    })
            }
            // `shutdown` is kill-then-reap of the direct child.
            None => self
                .pty
                .shutdown()
                .map_or(ExitObservation::Unobservable, |status| {
                    observe_pty_status(&status)
                }),
        };
        self.exited = Some(exit);
        Ok(exit)
    }
}

/// Starts the drain worker for one pipe stream, feeding the bounded store
/// and touching `clock` per chunk (output activity keeps the idle clock
/// honest). The handle is joined after the child is reaped (see
/// [`PipeJob`]); memory stays bounded because the store evicts
/// oldest-first.
///
/// # Errors
///
/// Returns the worker spawn error; the pipe is dropped (closed) with the
/// unstarted closure.
fn spawn_stream_drain(
    mut pipe: impl Read + Send + 'static,
    stream: OutputStream,
    clock: Arc<ActivityClock>,
    output: OutputSink,
    worker_spawner: WorkerSpawner,
) -> std::io::Result<thread::JoinHandle<()>> {
    worker_spawner(
        "bitty-job-drain".into(),
        Box::new(move || {
            let mut chunk = [0u8; DRAIN_CHUNK_BYTES];
            loop {
                match pipe.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        clock.touch();
                        match stream {
                            OutputStream::Stdout => output.push_stdout(&chunk[..n]),
                            OutputStream::Stderr => output.push_stderr(&chunk[..n]),
                        }
                    }
                }
            }
        }),
    )
}

/// Starts the drain worker for a PTY reader, feeding the bounded stdout
/// store and touching `clock` per chunk. Detached: the reader channel is
/// bounded by the `bitty-pty` backpressure contract and ends when the PTY
/// closes. PTY output has no separate stderr: the terminal merges both
/// streams.
///
/// # Errors
///
/// Returns the worker spawn error (the caller kills and reaps the child).
fn spawn_pty_drain(
    reader: PtyReader,
    clock: Arc<ActivityClock>,
    output: OutputSink,
    worker_spawner: WorkerSpawner,
) -> std::io::Result<()> {
    worker_spawner(
        "bitty-job-pty-drain".into(),
        Box::new(move || {
            while let Ok(Some(chunk)) = reader.recv() {
                if !chunk.is_empty() {
                    clock.touch();
                    output.push_stdout(&chunk);
                }
            }
        }),
    )
    .map(drop)
}

// ── tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::super::delivery::MAX_STORED_OBSERVATION_EVENTS;
    use super::super::output::OutputStream;
    use super::*;
    use crate::{DEFAULT_RETENTION_TTL, JobLifetime, JobOrigin, JobTimeouts};
    use std::time::Duration;

    /// A program that cannot exist on any host: spawn always fails, so these
    /// tests observe registry bookkeeping without creating processes.
    const MISSING_PROGRAM: &str = "bitty-ct0511-nonexistent-job-program";

    fn missing_spec() -> JobSpec {
        JobSpec::new(MISSING_PROGRAM, vec!["--never".to_owned()])
    }

    fn wait_for(
        registry: &JobRegistry,
        id: JobId,
        what: &str,
        predicate: impl Fn(&JobSnapshot) -> bool,
    ) -> JobSnapshot {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let snapshot = registry.get(id).expect("job stays tracked");
            if predicate(&snapshot) {
                return snapshot;
            }
            assert!(
                Instant::now() < deadline,
                "job {id} did not reach {what} in time"
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    fn wait_terminal(registry: &JobRegistry, id: JobId) -> JobSnapshot {
        wait_for(registry, id, "a terminal state", |snapshot| {
            snapshot.state.is_terminal()
        })
    }

    #[test]
    fn a_host_kill_is_never_classified_as_an_oom_kill() {
        use crate::ExitObservation;
        let sigkill = ExitObservation::Signal(9);
        let classify = |evidence, host_killed| {
            ExecutionOutcome::classify_exit(sigkill, exit_oom_verdict(evidence, host_killed))
        };
        assert_eq!(
            classify(OomEvidence::OomKilled, false),
            ExecutionOutcome::OomKilled
        );
        assert_eq!(
            classify(OomEvidence::OomKilled, true),
            ExecutionOutcome::Signaled(9)
        );
        assert_eq!(
            classify(OomEvidence::NotOom, false),
            ExecutionOutcome::Signaled(9)
        );
        let control = JobControl::new();
        assert!(!control.host_killed());
        control.note_host_kill();
        assert!(control.host_killed());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_leaf_bound_follows_the_registry_capacity() {
        let root = std::env::temp_dir().join(format!(
            "bitty-ctx0880-leafbound-{}-{}",
            std::process::id(),
            now_ms()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("fake root");
        std::fs::write(root.join("cgroup.subtree_control"), "memory")
            .unwrap_or_else(|error| panic!("fake control in {root:?}: {error}"));
        let capacity = 3;
        let registry = JobRegistry::with_job_cgroups(capacity, JobCgroups::under(&root));
        let bound = match &lock_inner(&registry.shared).cgroups {
            CgroupSource::Available(cgroups) => cgroups.max_leaves(),
            other => panic!("fake base must be available: {other:?}"),
        };
        assert_eq!(bound, capacity);
        let base = registry.job_cgroup_base().expect("base");
        let _ = std::fs::remove_file(base.join("cgroup.subtree_control"));
        drop(registry);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn registry_starts_empty_and_keeps_its_capacity() {
        let registry = JobRegistry::new();
        assert_eq!(registry.capacity(), DEFAULT_MAX_JOBS);
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
        assert!(registry.list().is_empty());
        assert_eq!(registry.events_dropped(), 0);
        assert_eq!(registry.sweep(0), 0);
    }

    #[test]
    fn registry_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<JobRegistry>();
        assert_send_sync::<JobSnapshot>();
        assert_send_sync::<JobSpec>();
    }

    #[test]
    fn unknown_ids_fail_closed() {
        let registry = JobRegistry::new();
        let unknown = JobId::from_raw(9_999).expect("non-zero");
        assert_eq!(registry.get(unknown), Err(JobError::UnknownJob(unknown)));
        assert_eq!(registry.cancel(unknown), Err(JobError::UnknownJob(unknown)));
        assert_eq!(JobId::from_raw(0), None);
    }

    #[test]
    fn quiet_failed_spawn_becomes_a_terminal_observation() {
        let registry = JobRegistry::new();
        let id = registry.spawn(missing_spec()).expect("tracked");
        let snapshot = wait_terminal(&registry, id);
        assert_eq!(
            snapshot.state,
            JobState::Done(ExecutionOutcome::SpawnFailed)
        );
        assert!(snapshot.started_at_ms.is_none());
        assert!(snapshot.finished_at_ms.is_some());
        assert_eq!(snapshot.spec.kind.as_str(), "command");

        let events = registry.drain_events(MAX_STORED_JOB_EVENTS);
        assert_eq!(events.len(), 2, "{events:?}");
        assert!(matches!(events[0], JobEvent::Queued { id: first, .. } if first == id));
        assert!(matches!(
            events[1],
            JobEvent::Stopped {
                id: second,
                outcome: ExecutionOutcome::SpawnFailed,
                ..
            } if second == id
        ));
        assert!(registry.drain_events(1).is_empty());
    }

    #[test]
    fn ids_are_unique_and_never_reused_after_eviction() {
        let registry = JobRegistry::new();
        let mut seen = Vec::new();
        for _ in 0..4 {
            let spec = JobSpec::new(MISSING_PROGRAM, Vec::new())
                .with_timeouts(JobTimeouts::default().with_retention(Duration::ZERO));
            let id = registry.spawn(spec).expect("tracked");
            wait_terminal(&registry, id);
            assert!(!seen.contains(&id), "id {id} was reused");
            seen.push(id);
        }
        assert!(seen.windows(2).all(|pair| pair[0] < pair[1]));
        // Every spawn reclaimed the previous expired record, so only the
        // newest record is still tracked; eviction never resurrects an id.
        assert_eq!(registry.sweep(u64::MAX), 1);
        assert!(registry.is_empty());
        assert_eq!(registry.get(seen[0]), Err(JobError::UnknownJob(seen[0])));
    }

    #[test]
    fn capacity_fails_closed_until_retention_reclaims_space() {
        let registry = JobRegistry::with_capacity(1);
        let first = registry.spawn(missing_spec()).expect("first tracked");
        wait_terminal(&registry, first);
        assert_eq!(
            registry.spawn(missing_spec()),
            Err(JobError::RegistryFull { limit: 1 })
        );

        let reclaiming = JobRegistry::with_capacity(1);
        let spec =
            missing_spec().with_timeouts(JobTimeouts::default().with_retention(Duration::ZERO));
        let first = reclaiming.spawn(spec).expect("first tracked");
        let finished = wait_terminal(&reclaiming, first);
        let second = reclaiming
            .spawn(missing_spec())
            .expect("expired record reclaimed at spawn");
        assert!(second > first);
        assert_eq!(reclaiming.len(), 1);
        assert_eq!(
            finished.state,
            JobState::Done(ExecutionOutcome::SpawnFailed)
        );
    }

    #[test]
    fn sweep_respects_the_retention_window() {
        let registry = JobRegistry::new();
        let id = registry.spawn(missing_spec()).expect("tracked");
        let finished = wait_terminal(&registry, id);
        let finished_at = finished.finished_at_ms.expect("terminal time");
        let retention_ms = u64::try_from(DEFAULT_RETENTION_TTL.as_millis()).expect("fits");
        assert_eq!(registry.sweep(finished_at), 0);
        assert_eq!(registry.sweep(finished_at + retention_ms - 1), 0);
        assert_eq!(registry.sweep(finished_at + retention_ms), 1);
        assert!(registry.is_empty());
        // Clock skew saturates instead of panicking.
        let skewed = JobRegistry::new();
        let id = skewed.spawn(missing_spec()).expect("tracked");
        wait_terminal(&skewed, id);
        assert_eq!(skewed.sweep(0), 0);
        assert_eq!(skewed.len(), 1);
    }

    #[test]
    fn cancel_after_a_terminal_state_reports_it() {
        let registry = JobRegistry::new();
        let id = registry.spawn(missing_spec()).expect("tracked");
        wait_terminal(&registry, id);
        assert_eq!(
            registry.cancel(id),
            Ok(JobCancel::AlreadyStopped(ExecutionOutcome::SpawnFailed))
        );
    }

    #[test]
    fn snapshots_carry_declared_metadata() {
        let registry = JobRegistry::new();
        let spec = missing_spec()
            .with_lifetime(JobLifetime::Workspace)
            .with_origin(JobOrigin::panel("panel-3"));
        let id = registry.spawn(spec).expect("tracked");
        let snapshot = registry.get(id).expect("tracked");
        assert_eq!(snapshot.id, id);
        assert_eq!(snapshot.state, JobState::Queued);
        assert_eq!(snapshot.spec.lifetime, JobLifetime::Workspace);
        assert_eq!(snapshot.spec.origin.panel_id(), Some("panel-3"));
        assert!(snapshot.started_at_ms.is_none());
        assert!(snapshot.finished_at_ms.is_none());
    }

    #[test]
    fn list_never_exceeds_capacity() {
        let registry = JobRegistry::with_capacity(2);
        for _ in 0..2 {
            registry.spawn(missing_spec()).expect("tracked");
        }
        assert_eq!(registry.list().len(), 2);
        assert_eq!(
            registry.spawn(missing_spec()),
            Err(JobError::RegistryFull { limit: 2 })
        );
        assert!(registry.list().len() <= registry.capacity());
    }

    #[test]
    fn observation_lane_drops_oldest_and_counts() {
        let id = JobId::from_raw(1).expect("non-zero");
        let mut log = DeliveryLog::new();
        for at_ms in 1..=(MAX_STORED_OBSERVATION_EVENTS as u64 + 1) {
            log.push(JobEvent::Queued { id, at_ms });
        }
        assert_eq!(log.observation_dropped(), 1);
        assert_eq!(log.critical_dropped(), 0);
        assert_eq!(log.dropped(), 1);
        let drained = log.drain(MAX_STORED_OBSERVATION_EVENTS + 1);
        assert_eq!(drained.len(), MAX_STORED_OBSERVATION_EVENTS);
        assert!(matches!(drained[0], JobEvent::Queued { at_ms: 2, .. }));
        assert!(log.drain(10).is_empty());
    }

    #[test]
    fn snapshots_carry_an_empty_output_index_until_bytes_arrive() {
        let registry = JobRegistry::new();
        let id = registry.spawn(missing_spec()).expect("tracked");
        let snapshot = wait_terminal(&registry, id);
        assert_eq!(snapshot.output, OutputIndex::default());
        assert!(!snapshot.output.is_truncated());
        assert_eq!(
            registry.output_index(id).expect("tracked"),
            OutputIndex::default()
        );
        let read = ReadOutput::new(OutputStream::Stdout)
            .validate()
            .expect("valid");
        let view = registry
            .read_output(id, ReadOutput::new(OutputStream::Stdout))
            .expect("readable");
        assert!(view.text.is_empty());
        assert!(!view.truncated);
        let _ = read;
    }

    #[test]
    fn activity_clock_tracks_idle_gaps() {
        let clock = ActivityClock::new();
        let start = clock.start;
        assert_eq!(clock.idle_for(start), Duration::ZERO);
        clock.touch_at(start + Duration::from_millis(10));
        assert_eq!(
            clock.idle_for(start + Duration::from_millis(30)),
            Duration::from_millis(20)
        );
        clock.touch_at(start + Duration::from_millis(30));
        assert_eq!(
            clock.idle_for(start + Duration::from_millis(30)),
            Duration::ZERO
        );
        assert_eq!(
            clock.idle_for(start + Duration::from_millis(45)),
            Duration::from_millis(15)
        );
    }

    // ── fallible drain workers (CORE-RUN-005, #1526) ────────────────────────

    const HELPER_ENV: &str = "__BITTY_REGISTRY_TEST_HELPER";

    /// Child entry point: selected by `HELPER_ENV`, a no-op in the parent
    /// suite. Children are this test binary, so the probes stay hermetic
    /// and shell-free on every platform.
    #[test]
    fn __bitty_registry_helper_entry__() {
        if std::env::var(HELPER_ENV).as_deref() == Ok("sleep") {
            // Stay alive well past every test deadline.
            thread::sleep(Duration::from_secs(30));
        }
    }

    fn sleeping_helper_spec() -> JobSpec {
        let exe = std::env::current_exe()
            .expect("test binary path")
            .to_string_lossy()
            .into_owned();
        JobSpec::new(
            exe,
            vec![
                "__bitty_registry_helper_entry__".to_owned(),
                "--nocapture".to_owned(),
            ],
        )
        .with_env(
            EnvPolicy::explicit(vec![(HELPER_ENV.to_owned(), "sleep".to_owned())])
                .expect("explicit env"),
        )
    }

    /// A spawner that refuses every worker, like an exhausted thread table.
    fn refuse_every_worker(
        _name: String,
        work: Box<dyn FnOnce() + Send + 'static>,
    ) -> std::io::Result<thread::JoinHandle<()>> {
        drop(work);
        Err(std::io::Error::new(
            std::io::ErrorKind::OutOfMemory,
            "injected worker spawn failure",
        ))
    }

    thread_local! {
        static WORKERS_STARTED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }

    /// Starts the first worker, refuses the rest: the partial-start shape
    /// (stdout drained, stderr drain unavailable).
    ///
    /// `WORKERS_STARTED` is thread-local, so this sequence holds only while
    /// the caller invokes the spawner synchronously on the test thread, as
    /// the direct `PipeJob::start` probe does. A spawner reached through
    /// `supervise` (its own thread) would start from a fresh count.
    fn refuse_after_first_worker(
        name: String,
        work: Box<dyn FnOnce() + Send + 'static>,
    ) -> std::io::Result<thread::JoinHandle<()>> {
        let started = WORKERS_STARTED.with(|count| {
            let started = count.get();
            count.set(started + 1);
            started
        });
        if started == 0 {
            spawn_worker(name, work)
        } else {
            refuse_every_worker(name, work)
        }
    }

    /// The partially started child is gone: killed AND reaped (a zombie
    /// would still own its `/proc` entry). Other platforms rely on the
    /// failure naming the reaped pid.
    fn assert_reaped(failure: &StartFailure) {
        let pid = failure
            .reaped_pid
            .expect("the child existed and its pid is reported");
        assert!(
            failure.reason.contains("drain worker failed to start"),
            "failure names the drain: {}",
            failure.reason
        );
        #[cfg(target_os = "linux")]
        assert!(
            !std::path::Path::new(&format!("/proc/{pid}")).exists(),
            "child {pid} must be killed and reaped, not left running or zombie"
        );
        #[cfg(not(target_os = "linux"))]
        let _ = pid;
    }

    #[test]
    fn a_pipe_drain_that_cannot_start_reaps_the_child() {
        for spawner in [
            refuse_every_worker as WorkerSpawner,
            refuse_after_first_worker,
        ] {
            WORKERS_STARTED.with(|count| count.set(0));
            let failure = match PipeJob::start(
                &sleeping_helper_spec(),
                Arc::new(ActivityClock::new()),
                OutputSink::default(),
                spawner,
            ) {
                Ok(_) => panic!("a missing drain must fail the start"),
                Err(failure) => failure,
            };
            assert_reaped(&failure);
        }
    }

    #[test]
    fn a_pty_drain_that_cannot_start_reaps_the_child() {
        bitty_test_support::require_pty!();
        let spec = sleeping_helper_spec()
            .with_kind(crate::JobKind::Interactive)
            .with_io(JobIo::Pty);
        let failure = match PtyJob::start(
            &spec,
            Arc::new(ActivityClock::new()),
            OutputSink::default(),
            None,
            refuse_every_worker,
        ) {
            Ok(_) => panic!("a missing drain must fail the start"),
            Err(failure) => failure,
        };
        assert_reaped(&failure);
    }

    #[test]
    fn a_failed_cleanup_reap_is_never_reported_as_reaped() {
        let reaped = StartFailure::after_cleanup(Some(7), Ok::<(), String>(()), "drain");
        assert_eq!(reaped.reaped_pid, Some(7));
        let failed = StartFailure::after_cleanup(Some(7), Err("no child"), "drain");
        assert_eq!(failed.reaped_pid, None, "a failed reap names no pid");
        assert!(failed.reason.contains("cleanup reap failed: no child"));
    }

    #[test]
    fn a_job_whose_drains_cannot_start_ends_spawn_failed() {
        let registry = JobRegistry::with_worker_spawner(DEFAULT_MAX_JOBS, refuse_every_worker);
        let started = Instant::now();
        let id = registry.spawn(sleeping_helper_spec()).expect("tracked");
        let snapshot = wait_terminal(&registry, id);
        assert_eq!(
            snapshot.state,
            JobState::Done(ExecutionOutcome::SpawnFailed)
        );
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the start fails fast instead of waiting on the 30 s child"
        );
        let stopped = registry
            .drain_events(MAX_STORED_OBSERVATION_EVENTS)
            .into_iter()
            .filter(|event| matches!(event, JobEvent::Stopped { .. }))
            .count();
        assert_eq!(stopped, 1, "exactly one typed terminal event");
    }
}
