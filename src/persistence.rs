//! Phase-2 persistent job metadata, event cursors, and file-held logs
//! (CTX-0516).
//!
//! The phase-1 registry is in-memory only: a GUI restart loses every job
//! record, every output byte, and every delivery cursor. This module adds the
//! restart-survival contract on top of the public [`JobRegistry`] surface
//! without touching its internals:
//!
//! - [`JobStore`] checkpoints one registry into a directory: a versioned
//!   `jobs.manifest` carrying metadata plus the metadata-only
//!   [`OutputIndex`] totals, with retained output text spilled into
//!   per-job, per-stream log files under `logs/` held **by reference**
//!   (file name only). Raw stdout never enters the manifest — the manifest
//!   stays SQLite-shaped (counts and facts, never bytes) so a future
//!   metadata database can adopt the same rows without growing with output.
//! - [`reconcile`] maps a loaded store onto restart truth: terminal jobs
//!   keep their observed facts, while jobs that were `Queued`/`Running` at
//!   the crash become [`ResumeDecision::UnknownOutcome`] — the supervisor
//!   is gone, so the outcome is unknowable and must never be reported as
//!   `Exited`.
//! - [`ResumeCursor`] and [`IdAllocator`] carry the cross-restart cursors:
//!   the delivery-log head `seq` (so a consumer can detect the restart gap)
//!   and the highest issued id (so post-restart spawns never reuse an id).
//!
//! # Deliberate non-goals
//!
//! - Capability grants are not persisted: [`JobSnapshot`] exposes no
//!   owner/grant table, so adoption starts unauthorized and every grant is
//!   re-issued explicitly after a restart. Silent authority never survives
//!   a crash.
//! - No automatic retry: adoption never respawns a job by itself.
//!   Re-execution stays an explicit primitive (CTX-0511 invariant), and
//!   [`ResumeDecision::UnknownOutcome`] names exactly that.
//! - No database engine: the manifest is a versioned, tab-separated text
//!   file written atomically (temp + fsync + rename, `0600` on Unix,
//!   following the session-save precedent). A future SQLite metadata store
//!   adopts the same row shape; the log files stay files either way.
//! - Structured outcomes (`Success`/`ExitCode`/`SupervisorLost`/...) are
//!   CTX-0512. [`ResumeDecision`] is intentionally coarser: facts survived
//!   versus outcome unknown.
//!
//! [`JobRegistry`]: crate::JobRegistry
//! [`JobSnapshot`]: crate::JobSnapshot

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use bitty_ipc::execution::{EnvPolicy, MAX_EXEC_ARGS, MAX_EXEC_ENV_VARS};

use crate::atomic_file::{self, AtomicWrite};
use crate::model::{JobId, JobIo, JobKind, JobLifetime, JobOrigin, JobSpec, JobState, JobTimeouts};
use crate::outcome::{CancelEffect, DeadlineClock, ExecutionOutcome};
use crate::output::{OutputIndex, OutputStream, ReadOutput};
use crate::registry::DEFAULT_MAX_JOBS;
use crate::{JobRegistry, MAX_READ_BYTES};

/// Manifest format version written by this slice.
///
/// v2 (CTX-0512) stores terminal states as structured
/// [`ExecutionOutcome`] tokens (`done:exit_code=3`, `done:cancelled=killed`,
/// ...). v1 manifests carried the interim four-way stop and are refused as
/// an unsupported version: their `exited` rows lack the exit code v2 needs,
/// and no v1 store was ever written outside tests.
pub const PERSIST_FORMAT_VERSION: u32 = 2;

/// Manifest file name inside a [`JobStore`] directory.
pub const MANIFEST_FILE_NAME: &str = "jobs.manifest";

/// Subdirectory holding per-job spilled log files.
pub const LOGS_DIR_NAME: &str = "logs";

/// Maximum accepted manifest bytes (fail-closed past this).
pub const MAX_MANIFEST_BYTES: usize = 4 * 1024 * 1024;

/// Maximum jobs one checkpoint persists (the registry capacity bound, so a
/// full registry always fits and nothing unbounded is written).
pub const MAX_PERSISTED_JOBS: usize = DEFAULT_MAX_JOBS;

/// Maximum bytes read back from one spilled log file (the read-path bound,
/// so a foreign-modified log cannot grow memory).
pub const MAX_LOG_FILE_BYTES: usize = MAX_READ_BYTES;

/// Magic first field of the manifest header line.
const MANIFEST_MAGIC: &str = "BITTY-JOB-MANIFEST";

/// Sentinel for an absent numeric field.
const NONE_SENTINEL: &str = "-";

/// Failure of a checkpoint, load, or spilled-log read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PersistError {
    /// Filesystem failure with the operation context.
    Io {
        /// What was being attempted.
        context: String,
        /// Underlying error text.
        reason: String,
    },
    /// The manifest or a spilled log is malformed or inconsistent.
    Corrupt {
        /// What failed validation.
        reason: String,
    },
    /// A persisted artifact exceeds its bound; nothing was applied.
    TooLarge {
        /// What exceeded the bound.
        what: String,
        /// Observed size.
        actual: usize,
        /// Enforced bound.
        limit: usize,
    },
    /// The registry changed under a checkpoint (eviction race).
    RegistryChanged {
        /// What changed.
        reason: String,
    },
}

impl PersistError {
    fn io(context: impl Into<String>, error: std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            reason: error.to_string(),
        }
    }

    fn corrupt(reason: impl Into<String>) -> Self {
        Self::Corrupt {
            reason: reason.into(),
        }
    }
}

impl std::fmt::Display for PersistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { context, reason } => write!(f, "job persistence io ({context}): {reason}"),
            Self::Corrupt { reason } => write!(f, "corrupt job manifest: {reason}"),
            Self::TooLarge {
                what,
                actual,
                limit,
            } => {
                write!(f, "job persistence {what} too large ({actual} > {limit})")
            }
            Self::RegistryChanged { reason } => {
                write!(f, "job registry changed during checkpoint: {reason}")
            }
        }
    }
}

impl std::error::Error for PersistError {}

/// One persisted job: spawn-time spec plus terminal truth plus the
/// metadata-only output index plus references to spilled log files.
///
/// Raw output bytes live only in the referenced files under [`LOGS_DIR_NAME`];
/// this record carries counts, never bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedJob {
    /// Job identity (never reused across restarts; see [`IdAllocator`]).
    pub id: JobId,
    /// Lifecycle state observed at checkpoint time.
    pub state: JobState,
    /// Expected lifecycle shape.
    pub kind: JobKind,
    /// Declared cleanup lifetime.
    pub lifetime: JobLifetime,
    /// I/O backend.
    pub io: JobIo,
    /// Executable path or name (argv[0]).
    pub program: String,
    /// Argument vector; never shell-interpreted.
    pub args: Vec<String>,
    /// Working directory; `None` means the platform default.
    pub cwd: Option<String>,
    /// Environment policy (closed for pipes, overrides for PTY jobs).
    pub env: EnvPolicy,
    /// Absolute supervision deadline.
    pub hard_timeout_ms: Option<u64>,
    /// Output-idle deadline.
    pub idle_timeout_ms: Option<u64>,
    /// Finished-record retention.
    pub retention_ms: Option<u64>,
    /// Provenance panel id, when recorded.
    pub origin_panel: Option<String>,
    /// Start time (epoch milliseconds), once started.
    pub started_at_ms: Option<u64>,
    /// Terminal time (epoch milliseconds), once stopped.
    pub finished_at_ms: Option<u64>,
    /// Metadata-only output totals (exact, never bytes).
    pub output: OutputIndex,
    /// Spilled stdout log file name (relative to [`LOGS_DIR_NAME`]), when
    /// retained stdout text survived the checkpoint.
    pub stdout_log: Option<String>,
    /// Spilled stderr log file name (relative to [`LOGS_DIR_NAME`]), when
    /// retained stderr text survived the checkpoint.
    pub stderr_log: Option<String>,
}

impl PersistedJob {
    /// Rebuilds the spawn-time spec for validation or explicit respawn.
    ///
    /// # Errors
    ///
    /// Returns [`PersistError::Corrupt`] when the persisted fields no longer
    /// form a valid spec (foreign-modified manifest or version skew).
    pub fn rebuild_spec(&self) -> Result<JobSpec, PersistError> {
        let timeouts = JobTimeouts {
            hard: self.hard_timeout_ms.map(Duration::from_millis),
            idle: self.idle_timeout_ms.map(Duration::from_millis),
            retention: self.retention_ms.map(Duration::from_millis),
        };
        let origin = match &self.origin_panel {
            Some(panel) => JobOrigin::panel(panel.clone()),
            None => JobOrigin::none(),
        };
        let spec = JobSpec::new(self.program.clone(), self.args.clone())
            .with_cwd(self.cwd.clone())
            .with_env(self.env.clone())
            .with_kind(self.kind)
            .with_lifetime(self.lifetime)
            .with_io(self.io)
            .with_timeouts(timeouts)
            .with_origin(origin);
        spec.validate()
            .map_err(|error| PersistError::corrupt(format!("persisted spec invalid: {error}")))?;
        Ok(spec)
    }
}

/// Cross-restart cursors carried beside the job rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResumeCursor {
    /// Delivery-log head `seq` at checkpoint time: the consumer resumes
    /// replay after this cursor and treats the restart as a gap.
    pub event_head_seq: u64,
    /// Highest job id issued before the restart; post-restart spawns must
    /// stay above it (see [`IdAllocator`]).
    pub max_issued_id: u64,
}

/// A loaded checkpoint: version, cursors, and one row per job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedStore {
    /// Manifest format version that wrote these rows.
    pub version: u32,
    /// Cross-restart cursors.
    pub cursor: ResumeCursor,
    /// One row per persisted job, in id order.
    pub jobs: Vec<PersistedJob>,
}

/// What restart reconciliation decided for one persisted row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResumeDecision {
    /// The job was terminal at checkpoint: its stop, times, output index,
    /// and spilled logs are surviving facts and stay observable.
    TerminalFacts,
    /// The job was `Queued`/`Running` when the supervisor went away: its
    /// outcome is unknowable — the child may have exited, survived, or never
    /// started — and must never be reported as `Exited`. Re-execution, if
    /// wanted, is an explicit new spawn (no automatic retry).
    UnknownOutcome,
}

impl ResumeDecision {
    /// Stable lowercase wire/display name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TerminalFacts => "terminal_facts",
            Self::UnknownOutcome => "unknown_outcome",
        }
    }

    /// Human-readable reason for the decision.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::TerminalFacts => "job was terminal at checkpoint; facts survived",
            Self::UnknownOutcome => {
                "job was live when the supervisor went away; outcome unknowable, never Exited"
            }
        }
    }
}

/// One persisted row plus its restart decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconciledJob {
    /// The persisted row.
    pub record: PersistedJob,
    /// The restart decision for it.
    pub decision: ResumeDecision,
}

impl ReconciledJob {
    /// The outcome restart truth allows for this row: a terminal row keeps
    /// its recorded outcome; a row that was live when the supervisor went
    /// away is [`ExecutionOutcome::SupervisorLost`], never a guessed exit.
    #[must_use]
    pub fn outcome(&self) -> ExecutionOutcome {
        match (self.decision, self.record.state) {
            (ResumeDecision::TerminalFacts, JobState::Done(outcome)) => outcome,
            _ => ExecutionOutcome::SupervisorLost,
        }
    }
}

/// Maps every persisted row onto restart truth.
///
/// Terminal rows keep their facts; live rows become
/// [`ResumeDecision::UnknownOutcome`]. The mapping is total and pure: no
/// I/O, no process inspection, no outcome invented.
#[must_use]
pub fn reconcile(store: &PersistedStore) -> Vec<ReconciledJob> {
    store
        .jobs
        .iter()
        .cloned()
        .map(|record| {
            let decision = if record.state.is_terminal() {
                ResumeDecision::TerminalFacts
            } else {
                ResumeDecision::UnknownOutcome
            };
            ReconciledJob { record, decision }
        })
        .collect()
}

/// Post-restart id allocator seeded above the persisted id space.
///
/// A fresh [`JobRegistry`] restarts its counter at 1, so naive spawns after a
/// restart would reuse ids of adopted rows. Spawns issued through this
/// allocator (seeded from [`ResumeCursor::max_issued_id`]) stay disjoint
/// from every persisted id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdAllocator {
    next: u64,
}

impl IdAllocator {
    /// Seeds the allocator just above the highest pre-restart id.
    #[must_use]
    pub fn resume_from(max_issued_id: u64) -> Self {
        Self {
            next: max_issued_id.saturating_add(1).max(1),
        }
    }

    /// Next fresh id floor (the first id [`IdAllocator::allocate`] yields).
    #[must_use]
    pub const fn floor(self) -> u64 {
        self.next
    }

    /// Issues the next id, or `None` when the id space is exhausted.
    #[must_use]
    pub fn allocate(&mut self) -> Option<JobId> {
        let id = JobId::from_raw(self.next)?;
        self.next = self.next.saturating_add(1).max(1);
        Some(id)
    }
}

/// Summary of one completed checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointSummary {
    /// Jobs persisted.
    pub jobs: usize,
    /// Delivery-log head `seq` at checkpoint time.
    pub event_head_seq: u64,
    /// Highest job id observed.
    pub max_issued_id: u64,
    /// Manifest bytes written.
    pub manifest_bytes: u64,
}

/// File-backed checkpoint store rooted at one directory.
///
/// Layout: `<dir>/jobs.manifest` plus `<dir>/logs/job-<id>.<stream>.log`.
/// The directory is created on first checkpoint; every manifest write is
/// atomic (temp sibling + fsync + rename, `0600` on Unix).
#[derive(Debug, Clone)]
pub struct JobStore {
    dir: PathBuf,
}

impl JobStore {
    /// Store rooted at `dir` (created lazily on checkpoint).
    #[must_use]
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// Root directory of this store.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn manifest_path(&self) -> PathBuf {
        self.dir.join(MANIFEST_FILE_NAME)
    }

    fn logs_dir(&self) -> PathBuf {
        self.dir.join(LOGS_DIR_NAME)
    }

    /// Checkpoints every tracked job of `registry` plus the resume cursors.
    ///
    /// Retained output text is spilled to per-job log files held by
    /// reference; the manifest carries metadata and index totals only.
    /// Stale log files from older checkpoints are removed best-effort so
    /// the directory stays bounded.
    ///
    /// # Errors
    ///
    /// Returns [`PersistError::RegistryChanged`] when a job evicts
    /// mid-checkpoint, [`PersistError::TooLarge`] when the manifest would
    /// exceed its bound, and [`PersistError::Io`] on filesystem failure.
    /// A failed checkpoint leaves the previous manifest untouched (the new
    /// one is fully written before the rename).
    pub fn checkpoint(&self, registry: &JobRegistry) -> Result<CheckpointSummary, PersistError> {
        let snapshots = registry.list();
        if snapshots.len() > MAX_PERSISTED_JOBS {
            return Err(PersistError::TooLarge {
                what: "persisted job rows".into(),
                actual: snapshots.len(),
                limit: MAX_PERSISTED_JOBS,
            });
        }
        fs::create_dir_all(self.logs_dir())
            .map_err(|error| PersistError::io("create job store logs dir", error))?;

        let mut rows: Vec<PersistedJob> = Vec::with_capacity(snapshots.len());
        let mut referenced_logs: Vec<String> = Vec::with_capacity(snapshots.len() * 2);
        for snapshot in &snapshots {
            let stdout_text = read_retained(registry, snapshot.id, OutputStream::Stdout)?;
            let stderr_text = read_retained(registry, snapshot.id, OutputStream::Stderr)?;
            let stdout_log = self.spill_log(
                snapshot.id,
                OutputStream::Stdout,
                &stdout_text,
                &mut referenced_logs,
            )?;
            let stderr_log = self.spill_log(
                snapshot.id,
                OutputStream::Stderr,
                &stderr_text,
                &mut referenced_logs,
            )?;
            rows.push(PersistedJob {
                id: snapshot.id,
                state: snapshot.state,
                kind: snapshot.spec.kind,
                lifetime: snapshot.spec.lifetime,
                io: snapshot.spec.io,
                program: snapshot.spec.program.clone(),
                args: snapshot.spec.args.clone(),
                cwd: snapshot.spec.cwd.clone(),
                env: snapshot.spec.env.clone(),
                hard_timeout_ms: snapshot.spec.timeouts.hard.map(duration_ms).transpose()?,
                idle_timeout_ms: snapshot.spec.timeouts.idle.map(duration_ms).transpose()?,
                retention_ms: snapshot
                    .spec
                    .timeouts
                    .retention
                    .map(duration_ms)
                    .transpose()?,
                origin_panel: snapshot.spec.origin.panel_id().map(str::to_owned),
                started_at_ms: snapshot.started_at_ms,
                finished_at_ms: snapshot.finished_at_ms,
                output: snapshot.output,
                stdout_log,
                stderr_log,
            });
        }

        let event_head_seq = registry.event_head_seq();
        let max_issued_id = snapshots
            .iter()
            .map(|snapshot| snapshot.id.get())
            .max()
            .unwrap_or(0);
        let manifest = encode_manifest(event_head_seq, max_issued_id, &rows)?;
        let manifest_bytes = u64::try_from(manifest.len()).unwrap_or(u64::MAX);
        self.write_manifest(manifest.as_bytes())?;
        self.sweep_stale_logs(&referenced_logs);

        Ok(CheckpointSummary {
            jobs: rows.len(),
            event_head_seq,
            max_issued_id,
            manifest_bytes,
        })
    }

    /// Loads the checkpointed rows and cursors, validating every field.
    ///
    /// # Errors
    ///
    /// Returns [`PersistError::Io`] when the manifest is missing or
    /// unreadable, [`PersistError::TooLarge`] when it exceeds its bound, and
    /// [`PersistError::Corrupt`] when any line is malformed, duplicated, or
    /// fails spec validation. Nothing is partially applied: the error
    /// carries the reason and no rows are returned.
    pub fn load(&self) -> Result<PersistedStore, PersistError> {
        let bytes = fs::read(self.manifest_path())
            .map_err(|error| PersistError::io("read job manifest", error))?;
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(PersistError::TooLarge {
                what: "job manifest".into(),
                actual: bytes.len(),
                limit: MAX_MANIFEST_BYTES,
            });
        }
        let text = String::from_utf8(bytes)
            .map_err(|error| PersistError::corrupt(format!("manifest is not UTF-8: {error}")))?;
        decode_manifest(&text)
    }

    /// Reads back spilled retained text for one persisted row and stream.
    ///
    /// Returns an empty string when the checkpoint held no retained text
    /// for the stream (no log referenced). The read is capped at
    /// [`MAX_LOG_FILE_BYTES`]; a foreign-grown file fails closed.
    ///
    /// # Errors
    ///
    /// Returns [`PersistError::Corrupt`] when a referenced log is missing,
    /// [`PersistError::TooLarge`] when it exceeds its bound, and
    /// [`PersistError::Io`] on filesystem failure.
    pub fn read_spilled(
        &self,
        record: &PersistedJob,
        stream: OutputStream,
    ) -> Result<String, PersistError> {
        let name = match stream {
            OutputStream::Stdout => record.stdout_log.as_ref(),
            OutputStream::Stderr => record.stderr_log.as_ref(),
        };
        let Some(name) = name else {
            return Ok(String::new());
        };
        assert_log_name(name)?;
        let bytes = fs::read(self.logs_dir().join(name))
            .map_err(|error| PersistError::io("read spilled job log", error))?;
        if bytes.len() > MAX_LOG_FILE_BYTES {
            return Err(PersistError::TooLarge {
                what: "spilled job log".into(),
                actual: bytes.len(),
                limit: MAX_LOG_FILE_BYTES,
            });
        }
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    /// Spills retained text to its log file, returning the referenced name.
    ///
    /// Empty text spills nothing and references nothing, so idle jobs leave
    /// no files behind.
    fn spill_log(
        &self,
        id: JobId,
        stream: OutputStream,
        text: &str,
        referenced: &mut Vec<String>,
    ) -> Result<Option<String>, PersistError> {
        if text.is_empty() {
            return Ok(None);
        }
        let name = format!("job-{}.{}.log", id.get(), stream.as_str());
        write_file_atomic(&self.logs_dir().join(&name), text.as_bytes())?;
        referenced.push(name.clone());
        Ok(Some(name))
    }

    /// Atomically replaces the manifest (temp sibling + fsync + rename).
    fn write_manifest(&self, bytes: &[u8]) -> Result<(), PersistError> {
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(PersistError::TooLarge {
                what: "job manifest".into(),
                actual: bytes.len(),
                limit: MAX_MANIFEST_BYTES,
            });
        }
        fs::create_dir_all(&self.dir)
            .map_err(|error| PersistError::io("create job store dir", error))?;
        // Only abandoned temps go (CORE-RUN-004): a concurrent saver's live
        // temp is young and stays, so its rename still lands.
        atomic_file::sweep_abandoned_temps(&self.dir);
        write_file_atomic(&self.manifest_path(), bytes)
    }

    /// Removes log files no current checkpoint references (best-effort:
    /// litter is bounded by one checkpoint's spill, never fatal).
    fn sweep_stale_logs(&self, referenced: &[String]) {
        // Temps of a spill whose writer died stay out of the `.log` rule
        // below; they go once abandoned (CORE-RUN-004).
        atomic_file::sweep_abandoned_temps(&self.logs_dir());
        let Ok(entries) = fs::read_dir(self.logs_dir()) else {
            return;
        };
        for entry in entries.filter_map(Result::ok) {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(".log") && !referenced.iter().any(|keep| keep == &name) {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
}

/// Reads the full retained window of one stream, mapping a mid-checkpoint
/// eviction to [`PersistError::RegistryChanged`].
fn read_retained(
    registry: &JobRegistry,
    id: JobId,
    stream: OutputStream,
) -> Result<String, PersistError> {
    registry
        .read_output(id, ReadOutput::new(stream))
        .map(|view| view.text)
        .map_err(|error| PersistError::RegistryChanged {
            reason: format!("job {id} unreadable during checkpoint: {error}"),
        })
}

/// Converts a timeout duration to whole milliseconds, failing closed past
/// the `u64` range instead of truncating.
fn duration_ms(duration: Duration) -> Result<u64, PersistError> {
    u64::try_from(duration.as_millis()).map_err(|_| PersistError::TooLarge {
        what: "job timeout".into(),
        actual: usize::MAX,
        limit: usize::MAX,
    })
}

/// Writes `bytes` atomically to `path` through a unique temp sibling plus
/// fsync plus rename, `0600` on Unix so job metadata (which may name working
/// directories) is never world-readable in a crash window. Concurrent savers
/// never share a temp name (CORE-RUN-004), so none can unlink or rename
/// another's in-flight file.
fn write_file_atomic(path: &Path, bytes: &[u8]) -> Result<(), PersistError> {
    atomic_file::write_atomic(
        path,
        bytes,
        AtomicWrite {
            owner_only: true,
            sync_parent: true,
        },
    )
    .map_err(|error| PersistError::io("write job store file", error))
}

/// Rejects log file names that are not store-issued (`job-<n>.<stream>.log`),
/// so a foreign-modified manifest can never direct a read outside `logs/`.
fn assert_log_name(name: &str) -> Result<(), PersistError> {
    let valid = name.strip_prefix("job-").is_some_and(|rest| {
        let (digits, suffix) = rest.split_at(rest.find('.').unwrap_or(rest.len()));
        !digits.is_empty()
            && digits.bytes().all(|byte| byte.is_ascii_digit())
            && (suffix == ".stdout.log" || suffix == ".stderr.log")
    });
    if valid {
        Ok(())
    } else {
        Err(PersistError::corrupt(format!(
            "spilled log name escapes the store: {name}"
        )))
    }
}

// ── manifest codec ──────────────────────────────────────────────────────────

/// Escapes one field: backslash, tab, newline, and carriage return are the
/// only bytes with codec meaning, so everything else round-trips verbatim
/// (including UTF-8 and `=`/`,`/`-` sentinels in other positions).
fn escape_field(raw: &str) -> String {
    let mut escaped = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '\t' => escaped.push_str("\\t"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

/// Reverses [`escape_field`]; unknown escapes and a trailing backslash are
/// corrupt, never silently accepted.
fn unescape_field(escaped: &str) -> Result<String, PersistError> {
    let mut raw = String::with_capacity(escaped.len());
    let mut chars = escaped.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            raw.push(ch);
            continue;
        }
        match chars.next() {
            Some('\\') => raw.push('\\'),
            Some('t') => raw.push('\t'),
            Some('n') => raw.push('\n'),
            Some('r') => raw.push('\r'),
            Some(other) => {
                return Err(PersistError::corrupt(format!(
                    "manifest field carries unknown escape: \\{other}"
                )));
            }
            None => {
                return Err(PersistError::corrupt(
                    "manifest field ends in a bare backslash",
                ));
            }
        }
    }
    Ok(raw)
}

/// Encodes one checkpoint as the versioned manifest text.
fn encode_manifest(
    event_head_seq: u64,
    max_issued_id: u64,
    rows: &[PersistedJob],
) -> Result<String, PersistError> {
    let mut text =
        format!("{MANIFEST_MAGIC}\tv{PERSIST_FORMAT_VERSION}\t{event_head_seq}\t{max_issued_id}\n");
    for row in rows {
        encode_row(row, &mut text)?;
    }
    if text.len() > MAX_MANIFEST_BYTES {
        return Err(PersistError::TooLarge {
            what: "job manifest".into(),
            actual: text.len(),
            limit: MAX_MANIFEST_BYTES,
        });
    }
    Ok(text)
}

/// Appends one tab-separated job line.
#[allow(clippy::too_many_lines)]
fn encode_row(row: &PersistedJob, text: &mut String) -> Result<(), PersistError> {
    let mut fields: Vec<String> = vec![
        "job".to_owned(),
        row.id.get().to_string(),
        encode_state(row.state),
        row.kind.as_str().to_owned(),
        row.lifetime.as_str().to_owned(),
        row.io.as_str().to_owned(),
        escape_field(&row.program),
        row.args.len().to_string(),
    ];
    for arg in &row.args {
        fields.push(escape_field(arg));
    }
    match &row.cwd {
        Some(cwd) => {
            fields.push("1".to_owned());
            fields.push(escape_field(cwd));
        }
        None => fields.push("0".to_owned()),
    }
    match &row.env {
        EnvPolicy::Isolated => {
            fields.push("isolated".to_owned());
            fields.push("0".to_owned());
        }
        EnvPolicy::Explicit { vars } => {
            fields.push("explicit".to_owned());
            fields.push(vars.len().to_string());
            for var in vars {
                fields.push(escape_field(&var.name));
                fields.push(escape_field(&var.value));
            }
        }
    }
    fields.push(opt_number(row.hard_timeout_ms));
    fields.push(opt_number(row.idle_timeout_ms));
    fields.push(opt_number(row.retention_ms));
    match &row.origin_panel {
        Some(panel) => {
            fields.push("1".to_owned());
            fields.push(escape_field(panel));
        }
        None => fields.push("0".to_owned()),
    }
    fields.push(opt_number(row.started_at_ms));
    fields.push(opt_number(row.finished_at_ms));
    for total in [
        row.output.stdout_total_bytes,
        row.output.stdout_dropped_bytes,
        row.output.stderr_total_bytes,
        row.output.stderr_dropped_bytes,
    ] {
        fields.push(total.to_string());
    }
    for stored in [
        row.output.stdout_stored_bytes,
        row.output.stderr_stored_bytes,
    ] {
        fields.push(stored.to_string());
    }
    match &row.stdout_log {
        Some(name) => {
            fields.push("1".to_owned());
            fields.push(escape_field(name));
        }
        None => fields.push("0".to_owned()),
    }
    match &row.stderr_log {
        Some(name) => {
            fields.push("1".to_owned());
            fields.push(escape_field(name));
        }
        None => fields.push("0".to_owned()),
    }
    for field in &fields {
        if field.contains('\t') || field.contains('\n') || field.contains('\r') {
            return Err(PersistError::corrupt(
                "manifest field carries a raw separator",
            ));
        }
    }
    text.push_str(&fields.join("\t"));
    text.push('\n');
    Ok(())
}

/// Encodes the lifecycle state (`done` carries its structured outcome;
/// payload-carrying outcomes append `=<value>`).
fn encode_state(state: JobState) -> String {
    match state {
        JobState::Queued => "queued".to_owned(),
        JobState::Running => "running".to_owned(),
        JobState::Done(outcome) => {
            let name = outcome.as_str();
            match outcome {
                ExecutionOutcome::ExitCode(code) => format!("done:{name}={code}"),
                ExecutionOutcome::Signaled(signal) => format!("done:{name}={signal}"),
                ExecutionOutcome::Cancelled(effect) => {
                    format!("done:{name}={}", effect.as_str())
                }
                ExecutionOutcome::TimedOut(clock) => format!("done:{name}={}", clock.as_str()),
                ExecutionOutcome::Success
                | ExecutionOutcome::SpawnFailed
                | ExecutionOutcome::OomKilled
                | ExecutionOutcome::SupervisorLost
                | ExecutionOutcome::Unknown => format!("done:{name}"),
            }
        }
    }
}

/// Encodes an optional epoch/timeout number (`-` for absent).
fn opt_number(value: Option<u64>) -> String {
    value.map_or_else(|| NONE_SENTINEL.to_owned(), |number| number.to_string())
}

/// Parses and fully validates one manifest.
fn decode_manifest(text: &str) -> Result<PersistedStore, PersistError> {
    let mut lines = text.lines();
    let header = lines
        .next()
        .ok_or_else(|| PersistError::corrupt("manifest is empty"))?;
    let (event_head_seq, max_issued_id) = decode_header(header)?;
    let mut jobs: Vec<PersistedJob> = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if jobs.len() >= MAX_PERSISTED_JOBS {
            return Err(PersistError::TooLarge {
                what: "persisted job rows".into(),
                actual: jobs.len() + 1,
                limit: MAX_PERSISTED_JOBS,
            });
        }
        jobs.push(decode_row(line)?);
    }
    let mut seen = jobs.iter().map(|row| row.id).collect::<Vec<_>>();
    seen.sort_unstable();
    seen.dedup();
    if seen.len() != jobs.len() {
        return Err(PersistError::corrupt("manifest carries duplicate job ids"));
    }
    jobs.sort_by_key(|row| row.id);
    Ok(PersistedStore {
        version: PERSIST_FORMAT_VERSION,
        cursor: ResumeCursor {
            event_head_seq,
            max_issued_id,
        },
        jobs,
    })
}

/// Parses the header line (`magic, version, event cursor, id high-water`).
fn decode_header(header: &str) -> Result<(u64, u64), PersistError> {
    let fields: Vec<&str> = header.split('\t').collect();
    let [magic, version, cursor, high_water] = fields.as_slice() else {
        return Err(PersistError::corrupt("manifest header has the wrong shape"));
    };
    if *magic != MANIFEST_MAGIC {
        return Err(PersistError::corrupt("manifest magic mismatch"));
    }
    let expected = format!("v{PERSIST_FORMAT_VERSION}");
    if *version != expected {
        return Err(PersistError::corrupt(format!(
            "unsupported manifest version: {version}"
        )));
    }
    let event_head_seq = parse_number("event cursor", cursor)?;
    let max_issued_id = parse_number("id high-water", high_water)?;
    Ok((event_head_seq, max_issued_id))
}

/// Positional cursor over one job line's fields.
struct Fields<'a> {
    fields: Vec<&'a str>,
    index: usize,
}

impl<'a> Fields<'a> {
    fn new(line: &'a str) -> Self {
        Self {
            fields: line.split('\t').collect(),
            index: 0,
        }
    }

    fn next(&mut self, what: &str) -> Result<&'a str, PersistError> {
        let field = self
            .fields
            .get(self.index)
            .copied()
            .ok_or_else(|| PersistError::corrupt(format!("manifest row misses {what}")))?;
        self.index += 1;
        Ok(field)
    }

    fn end(&self) -> Result<(), PersistError> {
        if self.index == self.fields.len() {
            Ok(())
        } else {
            Err(PersistError::corrupt(
                "manifest row carries trailing fields",
            ))
        }
    }
}

/// Parses one job line, rebuilding and re-validating the spec.
#[allow(clippy::too_many_lines)]
fn decode_row(line: &str) -> Result<PersistedJob, PersistError> {
    let mut fields = Fields::new(line);
    let tag = fields.next("row tag")?;
    if tag != "job" {
        return Err(PersistError::corrupt("manifest row has the wrong tag"));
    }
    let id = JobId::from_raw(parse_number("job id", fields.next("job id")?)?)
        .ok_or_else(|| PersistError::corrupt("job id is zero"))?;
    let state = decode_state(fields.next("job state")?)?;
    let kind = decode_kind(fields.next("job kind")?)?;
    let lifetime = decode_lifetime(fields.next("job lifetime")?)?;
    let io = decode_io(fields.next("job io")?)?;
    let program = unescape_field(fields.next("program")?)?;
    let argc = parse_bounded("arg count", fields.next("arg count")?)?;
    if argc > MAX_EXEC_ARGS {
        return Err(PersistError::corrupt(format!(
            "manifest arg count exceeds bound ({argc} > {MAX_EXEC_ARGS})"
        )));
    }
    let mut args = Vec::with_capacity(argc.min(64));
    for _ in 0..argc {
        args.push(unescape_field(fields.next("job arg")?)?);
    }
    let cwd = decode_optional_string(&mut fields, "cwd")?;
    let env = decode_env(&mut fields)?;
    let hard_timeout_ms = decode_optional_number(&mut fields, "hard timeout")?;
    let idle_timeout_ms = decode_optional_number(&mut fields, "idle timeout")?;
    let retention_ms = decode_optional_number(&mut fields, "retention")?;
    let origin_panel = decode_optional_string(&mut fields, "origin panel")?;
    let started_at_ms = decode_optional_number(&mut fields, "started time")?;
    let finished_at_ms = decode_optional_number(&mut fields, "finished time")?;
    let stdout_total_bytes = parse_number("stdout total", fields.next("stdout total")?)?;
    let stdout_dropped_bytes = parse_number("stdout dropped", fields.next("stdout dropped")?)?;
    let stderr_total_bytes = parse_number("stderr total", fields.next("stderr total")?)?;
    let stderr_dropped_bytes = parse_number("stderr dropped", fields.next("stderr dropped")?)?;
    let stdout_stored_bytes = parse_bounded("stdout stored", fields.next("stdout stored")?)?;
    let stderr_stored_bytes = parse_bounded("stderr stored", fields.next("stderr stored")?)?;
    let stdout_log = decode_optional_string(&mut fields, "stdout log")?;
    let stderr_log = decode_optional_string(&mut fields, "stderr log")?;
    fields.end()?;
    if let Some(name) = &stdout_log {
        assert_log_name(name)?;
    }
    if let Some(name) = &stderr_log {
        assert_log_name(name)?;
    }
    let row = PersistedJob {
        id,
        state,
        kind,
        lifetime,
        io,
        program,
        args,
        cwd,
        env,
        hard_timeout_ms,
        idle_timeout_ms,
        retention_ms,
        origin_panel,
        started_at_ms,
        finished_at_ms,
        output: OutputIndex {
            stdout_total_bytes,
            stdout_stored_bytes,
            stdout_dropped_bytes,
            stderr_total_bytes,
            stderr_stored_bytes,
            stderr_dropped_bytes,
        },
        stdout_log,
        stderr_log,
    };
    // Re-validation keeps a foreign-modified manifest from smuggling an
    // over-bound or inconsistent spec back across a restart.
    row.rebuild_spec()?;
    Ok(row)
}

/// Parses a mandatory decimal number.
fn parse_number(what: &str, raw: &str) -> Result<u64, PersistError> {
    raw.parse::<u64>()
        .map_err(|_| PersistError::corrupt(format!("manifest {what} is not a number: {raw}")))
}

/// Parses a mandatory decimal number that must fit in `usize`.
fn parse_bounded(what: &str, raw: &str) -> Result<usize, PersistError> {
    let value = parse_number(what, raw)?;
    usize::try_from(value)
        .map_err(|_| PersistError::corrupt(format!("manifest {what} exceeds range: {raw}")))
}

/// Parses an optional number (`-` for absent).
fn decode_optional_number(
    fields: &mut Fields<'_>,
    what: &str,
) -> Result<Option<u64>, PersistError> {
    let raw = fields.next(what)?;
    if raw == NONE_SENTINEL {
        return Ok(None);
    }
    parse_number(what, raw).map(Some)
}

/// Parses a presence-flagged optional string (`1` + escaped value, `0` none).
fn decode_optional_string(
    fields: &mut Fields<'_>,
    what: &str,
) -> Result<Option<String>, PersistError> {
    let present = fields.next(what)?;
    match present {
        "0" => Ok(None),
        "1" => unescape_field(fields.next(what)?).map(Some),
        _ => Err(PersistError::corrupt(format!(
            "manifest {what} presence flag is not 0/1"
        ))),
    }
}

/// Parses the environment policy (`isolated` or `explicit` plus pairs).
fn decode_env(fields: &mut Fields<'_>) -> Result<EnvPolicy, PersistError> {
    let kind = fields.next("env kind")?;
    let count = parse_bounded("env count", fields.next("env count")?)?;
    if count > MAX_EXEC_ENV_VARS {
        return Err(PersistError::corrupt(format!(
            "manifest env count exceeds bound ({count})"
        )));
    }
    match kind {
        "isolated" => {
            if count != 0 {
                return Err(PersistError::corrupt("isolated env carries entries"));
            }
            Ok(EnvPolicy::Isolated)
        }
        "explicit" => {
            let mut vars = Vec::with_capacity(count.min(64));
            for _ in 0..count {
                let name = unescape_field(fields.next("env name")?)?;
                let value = unescape_field(fields.next("env value")?)?;
                vars.push((name, value));
            }
            EnvPolicy::explicit(vars)
                .map_err(|error| PersistError::corrupt(format!("persisted env invalid: {error}")))
        }
        _ => Err(PersistError::corrupt("manifest env kind unknown")),
    }
}

/// Parses one structured outcome token (the part after `done:`).
fn decode_outcome(token: &str) -> Result<ExecutionOutcome, PersistError> {
    let unknown = || PersistError::corrupt("manifest terminal outcome unknown");
    let number = |raw: &str| raw.parse::<i32>().map_err(|_| unknown());
    let (name, value) = match token.split_once('=') {
        Some((name, value)) => (name, Some(value)),
        None => (token, None),
    };
    let outcome = match (name, value) {
        ("success", None) => ExecutionOutcome::Success,
        ("exit_code", Some(code)) => ExecutionOutcome::ExitCode(number(code)?),
        ("signaled", Some(signal)) => ExecutionOutcome::Signaled(number(signal)?),
        ("spawn_failed", None) => ExecutionOutcome::SpawnFailed,
        ("cancelled", Some(effect)) => ExecutionOutcome::Cancelled(match effect {
            "before_start" => CancelEffect::BeforeStart,
            "graceful" => CancelEffect::Graceful,
            "killed" => CancelEffect::Killed,
            _ => return Err(unknown()),
        }),
        ("timed_out", Some(clock)) => ExecutionOutcome::TimedOut(match clock {
            "hard" => DeadlineClock::Hard,
            "idle" => DeadlineClock::Idle,
            _ => return Err(unknown()),
        }),
        ("oom_killed", None) => ExecutionOutcome::OomKilled,
        ("supervisor_lost", None) => ExecutionOutcome::SupervisorLost,
        ("unknown", None) => ExecutionOutcome::Unknown,
        _ => return Err(unknown()),
    };
    Ok(outcome)
}

/// Parses the lifecycle state token.
fn decode_state(raw: &str) -> Result<JobState, PersistError> {
    match raw {
        "queued" => Ok(JobState::Queued),
        "running" => Ok(JobState::Running),
        done => {
            let token = done
                .strip_prefix("done:")
                .ok_or_else(|| PersistError::corrupt("manifest job state unknown"))?;
            decode_outcome(token).map(JobState::Done)
        }
    }
}

/// Parses the kind token.
fn decode_kind(raw: &str) -> Result<JobKind, PersistError> {
    match raw {
        "command" => Ok(JobKind::Command),
        "interactive" => Ok(JobKind::Interactive),
        "service" => Ok(JobKind::Service),
        "watch" => Ok(JobKind::Watch),
        _ => Err(PersistError::corrupt("manifest job kind unknown")),
    }
}

/// Parses the lifetime token.
fn decode_lifetime(raw: &str) -> Result<JobLifetime, PersistError> {
    match raw {
        "agent" => Ok(JobLifetime::Agent),
        "task" => Ok(JobLifetime::Task),
        "workspace" => Ok(JobLifetime::Workspace),
        "detached" => Ok(JobLifetime::Detached),
        _ => Err(PersistError::corrupt("manifest job lifetime unknown")),
    }
}

/// Parses the I/O backend token.
fn decode_io(raw: &str) -> Result<JobIo, PersistError> {
    match raw {
        "pipes" => Ok(JobIo::Pipes),
        "pty" => Ok(JobIo::Pty),
        _ => Err(PersistError::corrupt("manifest job io unknown")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_escaping_round_trips_hostile_strings() {
        let hostile = [
            "",
            "-",
            "plain",
            "tab\there",
            "newline\nhere",
            "return\rhere",
            "back\\slash",
            "trailing\\",
            "\\t\\n\\r\\\\",
            "unicode: \u{1f980} \u{4e2d} \u{e9}",
            "panel/repo: feature (1)\twith\ttabs",
            "PATH=/usr/bin:/bin",
            "key=value,with,commas",
        ];
        for raw in hostile {
            assert_eq!(unescape_field(&escape_field(raw)).expect("round-trip"), raw);
        }
    }

    #[test]
    fn unknown_escapes_and_bare_backslash_fail_closed() {
        assert!(unescape_field("ok\\q").is_err());
        assert!(unescape_field("trailing\\").is_err());
        assert!(unescape_field("\\x41").is_err());
    }

    #[test]
    fn state_codec_covers_every_outcome() {
        for outcome in [
            ExecutionOutcome::Success,
            ExecutionOutcome::ExitCode(3),
            ExecutionOutcome::ExitCode(-1_073_741_510),
            ExecutionOutcome::Signaled(9),
            ExecutionOutcome::SpawnFailed,
            ExecutionOutcome::Cancelled(CancelEffect::BeforeStart),
            ExecutionOutcome::Cancelled(CancelEffect::Graceful),
            ExecutionOutcome::Cancelled(CancelEffect::Killed),
            ExecutionOutcome::TimedOut(DeadlineClock::Hard),
            ExecutionOutcome::TimedOut(DeadlineClock::Idle),
            ExecutionOutcome::OomKilled,
            ExecutionOutcome::SupervisorLost,
            ExecutionOutcome::Unknown,
        ] {
            let state = JobState::Done(outcome);
            assert_eq!(decode_state(&encode_state(state)).expect("decode"), state);
        }
        assert_eq!(
            decode_state(&encode_state(JobState::Queued)).expect("decode"),
            JobState::Queued
        );
        assert_eq!(
            decode_state(&encode_state(JobState::Running)).expect("decode"),
            JobState::Running
        );
        for corrupt in [
            "flying",
            "done:exited",
            "done:cancelled",
            "done:exit_code",
            "done:exit_code=x",
            "done:success=0",
            "done:timed_out=forever",
            "done:cancelled=maybe",
            "done:",
        ] {
            assert!(
                decode_state(corrupt).is_err(),
                "{corrupt:?} must be corrupt"
            );
        }
    }

    #[test]
    fn allocator_stays_above_the_persisted_space() {
        let mut allocator = IdAllocator::resume_from(41);
        assert_eq!(allocator.floor(), 42);
        let first = allocator.allocate().expect("id");
        let second = allocator.allocate().expect("id");
        assert_eq!(first.get(), 42);
        assert_eq!(second.get(), 43);
        assert!(first < second);
    }

    #[test]
    fn allocator_from_an_empty_store_starts_at_one() {
        let mut allocator = IdAllocator::resume_from(0);
        assert_eq!(allocator.allocate().expect("id").get(), 1);
    }

    #[test]
    fn reconcile_never_reports_a_live_job_as_exited() {
        let live = PersistedJob {
            id: JobId::from_raw(7).expect("id"),
            state: JobState::Running,
            kind: JobKind::Service,
            lifetime: JobLifetime::Detached,
            io: JobIo::Pipes,
            program: "sleep".to_owned(),
            args: Vec::new(),
            cwd: None,
            env: EnvPolicy::Isolated,
            hard_timeout_ms: None,
            idle_timeout_ms: None,
            retention_ms: None,
            origin_panel: None,
            started_at_ms: Some(1),
            finished_at_ms: None,
            output: OutputIndex::default(),
            stdout_log: None,
            stderr_log: None,
        };
        let mut done = live.clone();
        done.state = JobState::Done(ExecutionOutcome::Success);
        let store = PersistedStore {
            version: PERSIST_FORMAT_VERSION,
            cursor: ResumeCursor {
                event_head_seq: 9,
                max_issued_id: 7,
            },
            jobs: vec![live, done],
        };
        let reconciled = reconcile(&store);
        assert_eq!(reconciled[0].decision, ResumeDecision::UnknownOutcome);
        assert_eq!(reconciled[1].decision, ResumeDecision::TerminalFacts);
    }
}
