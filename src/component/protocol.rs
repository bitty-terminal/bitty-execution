//! Execution component wire protocol v1 (core host <-> `bitty-execution`).
//!
//! The component is a stdio coprocess: the host writes requests to its stdin
//! and reads framed messages from its stdout. stderr stays diagnostic and is
//! never protocol. This module is the authoritative schema and codec; it is
//! hand-written (`std` only), forbids panics on hostile input, and fails
//! closed on every bound.
//!
//! # Framing
//!
//! ```text
//! frame   = length:u32be payload[length]
//! payload = tag:u8 fields...
//! ```
//!
//! `length` is 1..=[`MAX_FRAME_BYTES`]. A larger or zero length is rejected
//! from the four-byte header alone; no payload byte is read or allocated.
//!
//! # Field encoding
//!
//! - Integers are big-endian fixed width (`u8`, `u16`, `u32`, `u64`).
//! - `bool` is one byte, `0x00` or `0x01`; any other value is rejected.
//! - `str` is `len:u32be` + UTF-8 bytes, every length bounded per field.
//! - `bytes` is `len:u32be` + raw bytes, bounded per field.
//! - Lists are `count:u32be` + elements, count bounded per field.
//! - An optional value is `0x00` (absent) or `0x01` followed by the value.
//!
//! # Messages
//!
//! | Tag    | Message        | Fields (in order)                                                                                  | Direction  |
//! |--------|----------------|----------------------------------------------------------------------------------------------------|------------|
//! | `0x01` | `Hello`        | `min:u16 max:u16 component:str version:str`                                                        | host->comp |
//! | `0x02` | `HelloAck`     | `protocol:u16 component:str version:str`                                                           | comp->host |
//! | `0x10` | `Spawn`        | `job:u64 program:str args:list<str> cwd:opt<str> env:u8 envs:list<(str,str)> kind:u8 io:u8 lifetime:u8 hard_ms:u32 idle_ms:u32 retention_ms:u32` | host->comp |
//! | `0x11` | `Terminate`    | `job:u64 generation:u64 mode:u8 grace_ms:u32`                                                       | host->comp |
//! | `0x12` | `ReadOutput`   | `request:u64 job:u64 stream:u8 tail_lines:u32 max_bytes:u32`                                        | host->comp |
//! | `0x3F` | `Shutdown`     | (none)                                                                                             | host->comp |
//! | `0x20` | `Spawned`      | `job:u64 generation:u64`                                                                           | comp->host |
//! | `0x21` | `Started`      | `job:u64`                                                                                          | comp->host |
//! | `0x22` | `Output`       | `job:u64 stream:u8 data:bytes`                                                                     | comp->host |
//! | `0x23` | _reserved_     | not assigned in v1                                                                                 | —          |
//! | `0x24` | `Exit`         | `job:u64 outcome:u8 detail:i32 cancel:u8 clock:u8 kill_scope:u8 oom:u8 oom_gap:u8 stdout_total:u64 stdout_evicted:u64 stderr_total:u64 stderr_evicted:u64` | comp->host |
//! | `0x25` | `Canceled`     | `job:u64 outcome:u8`                                                                               | comp->host |
//! | `0x26` | `OutputView`   | `request:u64 job:u64 stream:u8 data:bytes total:u64 dropped:u64 truncated:bool lines:u32`           | comp->host |
//! | `0x2F` | `Error`        | `request:u64 kind:u8 message:str`                                                                  | comp->host |
//! | `0x3E` | `ShutdownAck`  | (none)                                                                                             | comp->host |
//!
//! `job` is host-assigned and never reused for the component's lifetime. The
//! host may therefore route frames before it has processed `Spawned`; the
//! reply confirms acceptance and carries the execution generation used by
//! `Terminate`. `request` ids are separate, non-zero, and identify one
//! `ReadOutput` exchange. `Error.request == 0` marks a connection-level
//! failure.
//!
//! # Authority and capability boundary
//!
//! This protocol carries **no file operations, no descriptor passing, and no
//! ambient command language**. Program, arguments, working directory,
//! environment, and deadlines appear only inside an explicit `Spawn`; every
//! other message names a job, a stream, or a request id. Error messages are
//! bounded static diagnostics, never echoed argv or paths. The host owns
//! installation, digest verification, capability grants, consent, and
//! safe-mode denial; the component executes exactly what it is handed and
//! never widens it.
//!
//! `SpawnIo::Pty` and `SpawnKind::Interactive` are reserved codes: protocol
//! v1 has no stdin channel, so servers refuse them as unsupported and
//! interactive PTY ownership stays with the terminal primitive.
//!
//! # Bounds
//!
//! [`MAX_FRAME_BYTES`], [`MAX_OUTPUT_CHUNK_BYTES`],
//! [`MAX_OUTPUT_READ_BYTES`], [`MAX_JOBS`], and the `bitty-ipc` argv/env
//! limits are enforced on both encode and decode. Output is written
//! synchronously by the supervisor drain threads, so a host that stops
//! reading applies ordinary pipe backpressure instead of growing an
//! unbounded queue.

use std::fmt;
use std::io::{self, Read, Write};

use crate::component::descriptor::COMPONENT_NAME;
use bitty_ipc::execution::{
    MAX_EXEC_ARG_BYTES, MAX_EXEC_ARGS, MAX_EXEC_ARGS_TOTAL_BYTES, MAX_EXEC_CWD_BYTES,
    MAX_EXEC_ENV_NAME_BYTES, MAX_EXEC_ENV_VALUE_BYTES, MAX_EXEC_ENV_VARS, MAX_EXECUTABLE_BYTES,
    MAX_TRACKED_EXECUTIONS,
};

/// Wire protocol version implemented by this crate.
pub const PROTOCOL_VERSION: u16 = 1;

/// Size of the big-endian `u32` length prefix in front of every payload.
pub const FRAME_HEADER_BYTES: usize = 4;

/// Maximum payload length of one frame (256 KiB, matching the other
/// component codecs).
pub const MAX_FRAME_BYTES: usize = 256 * 1024;

/// Maximum jobs one component process tracks (the shared execution ceiling).
pub const MAX_JOBS: usize = MAX_TRACKED_EXECUTIONS;

/// Maximum bytes carried by one `Output` frame (8 KiB drain chunks fit
/// whole; larger PTY reads are split).
pub const MAX_OUTPUT_CHUNK_BYTES: usize = 16 * 1024;

/// Maximum bytes one `OutputView` frame may carry.
pub const MAX_OUTPUT_READ_BYTES: usize = 240 * 1024;

/// Maximum combined environment name plus value bytes in one `Spawn`.
pub const MAX_ENV_TOTAL_BYTES: usize = 64 * 1024;

/// Maximum component name bytes (`[a-z][a-z0-9-]{0,31}`).
pub const MAX_COMPONENT_NAME_BYTES: usize = 32;

/// Maximum version string bytes in `Hello` / `HelloAck`.
pub const MAX_VERSION_BYTES: usize = 64;

/// Maximum `Error.message` bytes.
pub const MAX_ERROR_MESSAGE_BYTES: usize = 256;

/// Maximum `ReadOutput.tail_lines` value.
pub const MAX_TAIL_LINES: u32 = 10_000;

/// Maximum cancel grace period (matches `MAX_CANCEL_GRACE_MS`).
pub const MAX_CANCEL_GRACE_MS: u32 = 60_000;

/// Maximum jobs whose closed markers are retained to suppress late output.
pub const MAX_CLOSED_JOB_RECORDS: usize = 4096;

// ── tags ────────────────────────────────────────────────────────────────────

/// `Hello` tag.
pub const TAG_HELLO: u8 = 0x01;
/// `HelloAck` tag.
pub const TAG_HELLO_ACK: u8 = 0x02;
/// `Spawn` tag.
pub const TAG_SPAWN: u8 = 0x10;
/// `Terminate` tag.
pub const TAG_TERMINATE: u8 = 0x11;
/// `ReadOutput` tag.
pub const TAG_READ_OUTPUT: u8 = 0x12;
/// `Spawned` tag.
pub const TAG_SPAWNED: u8 = 0x20;
/// `Started` tag.
pub const TAG_STARTED: u8 = 0x21;
/// `Output` tag.
pub const TAG_OUTPUT: u8 = 0x22;
/// `Exit` tag.
pub const TAG_EXIT: u8 = 0x24;
/// `Canceled` tag.
pub const TAG_CANCELED: u8 = 0x25;
/// `OutputView` tag.
pub const TAG_OUTPUT_VIEW: u8 = 0x26;
/// `Error` tag.
pub const TAG_ERROR: u8 = 0x2F;
/// `ShutdownAck` tag.
pub const TAG_SHUTDOWN_ACK: u8 = 0x3E;
/// `Shutdown` tag.
pub const TAG_SHUTDOWN: u8 = 0x3F;

/// Connection-level `Error` frame request id.
pub const CONNECTION_ID: u64 = 0;

// ── closed wire vocabularies ─────────────────────────────────────────────────

/// Expected lifecycle shape of a spawned job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SpawnKind {
    /// Ordinary finite command (code 0).
    Command,
    /// Interactive program driven through a PTY (code 1).
    Interactive,
    /// Long-running service (code 2).
    Service,
    /// Long-running observer (code 3).
    Watch,
}

impl SpawnKind {
    /// Wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Command => 0,
            Self::Interactive => 1,
            Self::Service => 2,
            Self::Watch => 3,
        }
    }

    /// Kind for a wire code, or `None` for an unknown code.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Command),
            1 => Some(Self::Interactive),
            2 => Some(Self::Service),
            3 => Some(Self::Watch),
            _ => None,
        }
    }
}

/// I/O backend of a spawned job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SpawnIo {
    /// Closed stdin plus stdout/stderr pipes (code 0).
    Pipes,
    /// Pseudo-terminal with writable stdin (code 1, interactive opt-in).
    Pty,
}

impl SpawnIo {
    /// Wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Pipes => 0,
            Self::Pty => 1,
        }
    }

    /// Backend for a wire code, or `None` for an unknown code.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Pipes),
            1 => Some(Self::Pty),
            _ => None,
        }
    }
}

/// Declared cleanup lifetime of a spawned job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SpawnLifetime {
    /// Owner-agent lifetime (code 0).
    Agent,
    /// Owner-task lifetime (code 1).
    Task,
    /// Owner-workspace lifetime (code 2).
    Workspace,
    /// Independent of any owner (code 3).
    Detached,
}

impl SpawnLifetime {
    /// Wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Agent => 0,
            Self::Task => 1,
            Self::Workspace => 2,
            Self::Detached => 3,
        }
    }

    /// Lifetime for a wire code, or `None` for an unknown code.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Agent),
            1 => Some(Self::Task),
            2 => Some(Self::Workspace),
            3 => Some(Self::Detached),
            _ => None,
        }
    }
}

/// Environment shape of a `Spawn`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum WireEnv {
    /// Closed environment: the child inherits nothing (code 0).
    #[default]
    Isolated,
    /// Exactly the listed variables (code 1); an empty list is a closed
    /// empty environment.
    Explicit(Vec<WireEnvVar>),
}

impl WireEnv {
    /// Wire code.
    #[must_use]
    pub const fn code(&self) -> u8 {
        match self {
            Self::Isolated => 0,
            Self::Explicit(_) => 1,
        }
    }
}

/// One explicit environment entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WireEnvVar {
    /// Variable name.
    pub name: String,
    /// Variable value.
    pub value: String,
}

/// How a `Terminate` stops the owned process tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TerminateMode {
    /// `SIGINT`, then wait up to the grace; never escalates (code 0).
    Graceful,
    /// Kill the owned tree now (code 1).
    Immediate,
    /// `SIGINT`, wait, `SIGTERM`, wait, then kill (code 2).
    GracefulThenKill,
}

impl TerminateMode {
    /// Wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Graceful => 0,
            Self::Immediate => 1,
            Self::GracefulThenKill => 2,
        }
    }

    /// Mode for a wire code, or `None` for an unknown code.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Graceful),
            1 => Some(Self::Immediate),
            2 => Some(Self::GracefulThenKill),
            _ => None,
        }
    }
}

/// Child stream carried by output frames and reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Stream {
    /// Standard output (code 0).
    Stdout,
    /// Standard error (code 1). PTY jobs merge both streams into stdout.
    Stderr,
}

impl Stream {
    /// Wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Stdout => 0,
            Self::Stderr => 1,
        }
    }

    /// Stream for a wire code, or `None` for an unknown code.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Stdout),
            1 => Some(Self::Stderr),
            _ => None,
        }
    }
}

/// How a job ended (`Exit.outcome`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExitKind {
    /// Exited on its own with status 0 (code 0).
    Success,
    /// Exited on its own with a non-zero status (code 1; `detail` is the code).
    ExitCode,
    /// A signal the host did not send terminated it (code 2; `detail` names it).
    Signaled,
    /// No process was created, or a partial start was cleaned up (code 3).
    SpawnFailed,
    /// A terminate request ended it (code 4; `cancel` names the effect).
    Cancelled,
    /// A supervision deadline ended it (code 5; `clock` names hard or idle).
    TimedOut,
    /// The kernel OOM-killed it from per-job evidence (code 6).
    OomKilled,
    /// The supervisor went away while it ran (code 7).
    SupervisorLost,
    /// The end could not be observed (code 8).
    Unknown,
}

impl ExitKind {
    /// Wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Success => 0,
            Self::ExitCode => 1,
            Self::Signaled => 2,
            Self::SpawnFailed => 3,
            Self::Cancelled => 4,
            Self::TimedOut => 5,
            Self::OomKilled => 6,
            Self::SupervisorLost => 7,
            Self::Unknown => 8,
        }
    }

    /// Kind for a wire code, or `None` for an unknown code.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Success),
            1 => Some(Self::ExitCode),
            2 => Some(Self::Signaled),
            3 => Some(Self::SpawnFailed),
            4 => Some(Self::Cancelled),
            5 => Some(Self::TimedOut),
            6 => Some(Self::OomKilled),
            7 => Some(Self::SupervisorLost),
            8 => Some(Self::Unknown),
            _ => None,
        }
    }
}

/// How an executed terminate request ended a job (`Exit.cancel`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WireCancelEffect {
    /// Not a cancel outcome (code 0).
    None,
    /// Landed before the process existed (code 1).
    BeforeStart,
    /// Exited within a graceful step (code 2).
    Graceful,
    /// The owned tree was killed (code 3).
    Killed,
}

impl WireCancelEffect {
    /// Wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::None => 0,
            Self::BeforeStart => 1,
            Self::Graceful => 2,
            Self::Killed => 3,
        }
    }

    /// Effect for a wire code, or `None` for an unknown code.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::None),
            1 => Some(Self::BeforeStart),
            2 => Some(Self::Graceful),
            3 => Some(Self::Killed),
            _ => None,
        }
    }
}

/// Which deadline ended a job (`Exit.clock`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WireDeadlineClock {
    /// Not a deadline outcome (code 0).
    None,
    /// Hard wall-clock deadline (code 1).
    Hard,
    /// Output-idle deadline (code 2).
    Idle,
}

impl WireDeadlineClock {
    /// Wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Hard => 1,
            Self::Idle => 2,
        }
    }

    /// Clock for a wire code, or `None` for an unknown code.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::None),
            1 => Some(Self::Hard),
            2 => Some(Self::Idle),
            _ => None,
        }
    }
}

/// How much of the owned process tree a kill reaches (`Exit.kill_scope`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WireKillScope {
    /// Direct child only; the orphan gap is surfaced (code 0).
    DirectChild,
    /// Whole owned process tree (code 1).
    OwnedTree,
}

impl WireKillScope {
    /// Wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::DirectChild => 0,
            Self::OwnedTree => 1,
        }
    }

    /// Scope for a wire code, or `None` for an unknown code.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::DirectChild),
            1 => Some(Self::OwnedTree),
            _ => None,
        }
    }
}

/// OOM verdict carried by `Exit` (code 0 unknown, 1 killed, 2 not killed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WireOomVerdict {
    /// No completed reading (code 0).
    Unknown,
    /// The per-job counter advanced (code 1).
    OomKilled,
    /// Both readings exist and the counter did not advance (code 2).
    NotOom,
}

impl WireOomVerdict {
    /// Wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Unknown => 0,
            Self::OomKilled => 1,
            Self::NotOom => 2,
        }
    }

    /// Verdict for a wire code, or `None` for an unknown code.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Unknown),
            1 => Some(Self::OomKilled),
            2 => Some(Self::NotOom),
            _ => None,
        }
    }
}

/// Why OOM evidence is missing (`Exit.oom_gap`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WireOomGap {
    /// Evidence exists, or the verdict is unknown for another reason (code 0).
    None,
    /// No delegated cgroup base (code 1).
    NotConfigured,
    /// Discovery found no delegated cgroup v2 subtree (code 2).
    Undelegated,
    /// The platform has no per-job cgroup mechanism (code 3).
    UnsupportedPlatform,
    /// The bounded leaf count was reached (code 4).
    LeafLimit,
    /// The leaf directory could not be created (code 5).
    LeafCreateFailed,
    /// The leader could not be moved into its leaf (code 6).
    PlacementFailed,
    /// The `memory.events` reading was unusable (code 7).
    CounterUnreadable,
    /// The job never started a process (code 8).
    NotStarted,
}

impl WireOomGap {
    /// Wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::None => 0,
            Self::NotConfigured => 1,
            Self::Undelegated => 2,
            Self::UnsupportedPlatform => 3,
            Self::LeafLimit => 4,
            Self::LeafCreateFailed => 5,
            Self::PlacementFailed => 6,
            Self::CounterUnreadable => 7,
            Self::NotStarted => 8,
        }
    }

    /// Gap for a wire code, or `None` for an unknown code.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::None),
            1 => Some(Self::NotConfigured),
            2 => Some(Self::Undelegated),
            3 => Some(Self::UnsupportedPlatform),
            4 => Some(Self::LeafLimit),
            5 => Some(Self::LeafCreateFailed),
            6 => Some(Self::PlacementFailed),
            7 => Some(Self::CounterUnreadable),
            8 => Some(Self::NotStarted),
            _ => None,
        }
    }
}

/// Typed error category carried by `Error`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// The host's capability/consent gate refused the operation (code 1;
    /// produced by the host, reserved here).
    Denied,
    /// A request was malformed or violated a bound (code 2).
    InvalidRequest,
    /// A capacity or byte budget is exhausted (code 3).
    Budget,
    /// The operation is not supported for this job or platform (code 4).
    Unsupported,
    /// The job id is not tracked (code 5).
    UnknownJob,
    /// The generation is stale for that job (code 6).
    StaleGeneration,
    /// The peer violated the protocol (code 7).
    Protocol,
    /// The component process was lost (code 8; produced by the host).
    ComponentLost,
    /// A host request deadline expired (code 9; produced by the host).
    Timeout,
    /// Internal component failure (code 10).
    Internal,
}

impl ErrorKind {
    /// Wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Denied => 1,
            Self::InvalidRequest => 2,
            Self::Budget => 3,
            Self::Unsupported => 4,
            Self::UnknownJob => 5,
            Self::StaleGeneration => 6,
            Self::Protocol => 7,
            Self::ComponentLost => 8,
            Self::Timeout => 9,
            Self::Internal => 10,
        }
    }

    /// Kind for a wire code, or `None` for an unknown code.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Denied),
            2 => Some(Self::InvalidRequest),
            3 => Some(Self::Budget),
            4 => Some(Self::Unsupported),
            5 => Some(Self::UnknownJob),
            6 => Some(Self::StaleGeneration),
            7 => Some(Self::Protocol),
            8 => Some(Self::ComponentLost),
            9 => Some(Self::Timeout),
            10 => Some(Self::Internal),
            _ => None,
        }
    }

    /// Stable snake_case name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Denied => "denied",
            Self::InvalidRequest => "invalid_request",
            Self::Budget => "budget",
            Self::Unsupported => "unsupported",
            Self::UnknownJob => "unknown_job",
            Self::StaleGeneration => "stale_generation",
            Self::Protocol => "protocol",
            Self::ComponentLost => "component_lost",
            Self::Timeout => "timeout",
            Self::Internal => "internal",
        }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Typed terminate answer carried by `Canceled`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TerminateOutcome {
    /// Landed before the process existed (code 0).
    CancelledBeforeStart,
    /// Exited within a graceful step (code 1).
    CancelledGracefully,
    /// The owned tree was killed (code 2).
    Killed,
    /// Already terminal; nothing changed (code 3).
    AlreadyExited,
    /// The kernel refused the stop signal (code 4).
    PermissionDenied,
    /// The generation does not match the job (code 5).
    StaleGeneration,
    /// A graceful-only request left the job running (code 6).
    StillRunning,
    /// No graceful stop exists on this platform (code 7).
    Unsupported,
    /// The end could not be determined (code 8).
    Unknown,
}

impl TerminateOutcome {
    /// Wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::CancelledBeforeStart => 0,
            Self::CancelledGracefully => 1,
            Self::Killed => 2,
            Self::AlreadyExited => 3,
            Self::PermissionDenied => 4,
            Self::StaleGeneration => 5,
            Self::StillRunning => 6,
            Self::Unsupported => 7,
            Self::Unknown => 8,
        }
    }

    /// Outcome for a wire code, or `None` for an unknown code.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::CancelledBeforeStart),
            1 => Some(Self::CancelledGracefully),
            2 => Some(Self::Killed),
            3 => Some(Self::AlreadyExited),
            4 => Some(Self::PermissionDenied),
            5 => Some(Self::StaleGeneration),
            6 => Some(Self::StillRunning),
            7 => Some(Self::Unsupported),
            8 => Some(Self::Unknown),
            _ => None,
        }
    }
}

// ── messages ────────────────────────────────────────────────────────────────

/// One protocol v1 message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// Handshake offer; must be the first frame (host -> component).
    Hello {
        /// Lowest protocol version the host supports.
        min: u16,
        /// Highest protocol version the host supports.
        max: u16,
        /// Component name the host expects.
        component: String,
        /// Host version string.
        version: String,
    },
    /// Handshake answer (component -> host).
    HelloAck {
        /// Negotiated protocol version.
        protocol: u16,
        /// Component name.
        component: String,
        /// Component version.
        version: String,
    },
    /// Track and start one job (host -> component).
    Spawn {
        /// Host-assigned job id, unique for the component's lifetime.
        job: u64,
        /// Executable path or name (argv[0]).
        program: String,
        /// Argument vector; never shell-interpreted.
        args: Vec<String>,
        /// Working directory; `None` means the platform default.
        cwd: Option<String>,
        /// Environment shape.
        env: WireEnv,
        /// Expected lifecycle shape.
        kind: SpawnKind,
        /// I/O backend.
        io: SpawnIo,
        /// Declared cleanup lifetime.
        lifetime: SpawnLifetime,
        /// Absolute deadline in milliseconds; `0` means none.
        hard_ms: u32,
        /// Output-idle deadline in milliseconds; `0` means none.
        idle_ms: u32,
        /// Finished-record retention in milliseconds; `0` means default.
        retention_ms: u32,
    },
    /// Terminate one job (host -> component).
    Terminate {
        /// Job id from `Spawned`.
        job: u64,
        /// Execution generation from `Spawned`.
        generation: u64,
        /// Stop mode.
        mode: TerminateMode,
        /// Grace per graceful step in milliseconds (0 allowed).
        grace_ms: u32,
    },
    /// Read retained output of one job (host -> component).
    ReadOutput {
        /// Non-zero request id for this exchange.
        request: u64,
        /// Job id.
        job: u64,
        /// Stream to read.
        stream: Stream,
        /// Last N lines; `0` means all retained.
        tail_lines: u32,
        /// Response byte cap; `0` means the protocol maximum.
        max_bytes: u32,
    },
    /// Stop accepting work, terminate all jobs, and exit (host -> component).
    Shutdown,
    /// Job accepted and tracked; the generation fences `Terminate`
    /// (component -> host).
    Spawned {
        /// Host-assigned job id.
        job: u64,
        /// Execution generation.
        generation: u64,
    },
    /// The process exists and is supervised (component -> host).
    Started {
        /// Job id.
        job: u64,
    },
    /// Streamed child output (component -> host).
    Output {
        /// Job id.
        job: u64,
        /// Source stream.
        stream: Stream,
        /// Output bytes (at most [`MAX_OUTPUT_CHUNK_BYTES`]).
        data: Vec<u8>,
    },
    /// Terminal lifecycle answer (component -> host).
    Exit {
        /// Job id.
        job: u64,
        /// How the job ended.
        outcome: ExitKind,
        /// Exit code or signal number for the matching outcome; otherwise 0.
        detail: i32,
        /// Cancel effect when `outcome` is `Cancelled`.
        cancel: WireCancelEffect,
        /// Deadline clock when `outcome` is `TimedOut`.
        clock: WireDeadlineClock,
        /// Kill scope reported by the supervisor.
        kill_scope: WireKillScope,
        /// OOM verdict from per-job evidence.
        oom: WireOomVerdict,
        /// Missing-evidence reason, when any.
        oom_gap: WireOomGap,
        /// Every stdout byte the child wrote.
        stdout_total: u64,
        /// Stdout bytes evicted by the output bound.
        stdout_evicted: u64,
        /// Every stderr byte the child wrote.
        stderr_total: u64,
        /// Stderr bytes evicted by the output bound.
        stderr_evicted: u64,
    },
    /// Typed terminate answer (component -> host).
    Canceled {
        /// Job id.
        job: u64,
        /// Typed result of the executed terminate request.
        outcome: TerminateOutcome,
    },
    /// Retained output answer (component -> host).
    OutputView {
        /// Request id from `ReadOutput`.
        request: u64,
        /// Job id.
        job: u64,
        /// Stream that was read.
        stream: Stream,
        /// Lossy UTF-8 selection, at most [`MAX_OUTPUT_READ_BYTES`].
        data: Vec<u8>,
        /// Every byte the child wrote to this stream.
        total: u64,
        /// Bytes lost to the per-stream bound.
        dropped: u64,
        /// Whether any byte of this stream was lost.
        truncated: bool,
        /// Lines carried by `data`.
        lines: u32,
    },
    /// Typed error (component -> host).
    Error {
        /// Request id, or [`CONNECTION_ID`] for a connection-level failure.
        request: u64,
        /// Error category.
        kind: ErrorKind,
        /// Bounded static diagnostic; never echoed argv or paths.
        message: String,
    },
    /// All jobs stopped; the component exits after this frame
    /// (component -> host).
    ShutdownAck,
}

impl Message {
    /// Wire tag of this message.
    #[must_use]
    pub const fn tag(&self) -> u8 {
        match self {
            Self::Hello { .. } => TAG_HELLO,
            Self::HelloAck { .. } => TAG_HELLO_ACK,
            Self::Spawn { .. } => TAG_SPAWN,
            Self::Terminate { .. } => TAG_TERMINATE,
            Self::ReadOutput { .. } => TAG_READ_OUTPUT,
            Self::Shutdown => TAG_SHUTDOWN,
            Self::Spawned { .. } => TAG_SPAWNED,
            Self::Started { .. } => TAG_STARTED,
            Self::Output { .. } => TAG_OUTPUT,
            Self::Exit { .. } => TAG_EXIT,
            Self::Canceled { .. } => TAG_CANCELED,
            Self::OutputView { .. } => TAG_OUTPUT_VIEW,
            Self::Error { .. } => TAG_ERROR,
            Self::ShutdownAck => TAG_SHUTDOWN_ACK,
        }
    }
}

// ── errors ──────────────────────────────────────────────────────────────────

/// Wire codec failure (owned; no `io::Error` escapes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// The underlying stream failed.
    Io(io::ErrorKind),
    /// A frame exceeds [`MAX_FRAME_BYTES`] (or an encoder field exceeds its
    /// bound).
    TooLarge {
        /// Observed length.
        len: usize,
    },
    /// A zero-length frame.
    EmptyFrame,
    /// A frame ended before a field was complete.
    Truncated,
    /// A frame carried bytes after the last field.
    TrailingBytes,
    /// The tag is not assigned in protocol v1.
    UnknownTag(u8),
    /// A string field is not UTF-8.
    InvalidUtf8,
    /// A field violates its grammar or bound.
    InvalidField(&'static str),
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(kind) => write!(f, "stream i/o error: {kind}"),
            Self::TooLarge { len } => {
                write!(f, "frame is {len} bytes (limit {MAX_FRAME_BYTES})")
            }
            Self::EmptyFrame => f.write_str("empty frame"),
            Self::Truncated => f.write_str("truncated frame"),
            Self::TrailingBytes => f.write_str("trailing bytes after the last field"),
            Self::UnknownTag(tag) => write!(f, "unknown tag 0x{tag:02x}"),
            Self::InvalidUtf8 => f.write_str("string field is not UTF-8"),
            Self::InvalidField(reason) => write!(f, "invalid field: {reason}"),
        }
    }
}

impl std::error::Error for WireError {}

// ── framing ─────────────────────────────────────────────────────────────────

/// Reads length-prefixed frames from a stream.
pub struct FrameReader<R> {
    reader: R,
}

impl<R: Read> FrameReader<R> {
    /// Wraps `reader`.
    pub const fn new(reader: R) -> Self {
        Self { reader }
    }

    /// Reads one frame payload, or `None` at a clean EOF between frames.
    ///
    /// The four-byte header is rejected before any payload allocation or
    /// read when the declared length is zero or over [`MAX_FRAME_BYTES`].
    ///
    /// # Errors
    ///
    /// Returns [`WireError`] for I/O failures, a partial header, an empty or
    /// oversize frame, or a truncated payload.
    pub fn read_frame(&mut self) -> Result<Option<Vec<u8>>, WireError> {
        let mut header = [0u8; FRAME_HEADER_BYTES];
        let mut filled = 0;
        while filled < header.len() {
            match self.reader.read(&mut header[filled..]) {
                Ok(0) if filled == 0 => return Ok(None),
                Ok(0) => return Err(WireError::Truncated),
                Ok(n) => filled += n,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(WireError::Io(error.kind())),
            }
        }
        let len = u32::from_be_bytes(header) as usize;
        if len == 0 {
            return Err(WireError::EmptyFrame);
        }
        if len > MAX_FRAME_BYTES {
            return Err(WireError::TooLarge { len });
        }
        let mut payload = vec![0u8; len];
        self.reader
            .read_exact(&mut payload)
            .map_err(|error| match error.kind() {
                io::ErrorKind::UnexpectedEof => WireError::Truncated,
                kind => WireError::Io(kind),
            })?;
        Ok(Some(payload))
    }

    /// Reads and decodes one message, or `None` at a clean EOF.
    ///
    /// # Errors
    ///
    /// Returns [`WireError`] for framing failures (see
    /// [`FrameReader::read_frame`]) and decode failures.
    pub fn read_message(&mut self) -> Result<Option<Message>, WireError> {
        self.read_frame()?
            .map(|payload| decode_message(&payload))
            .transpose()
    }
}

/// Encodes one complete frame (length prefix included).
///
/// # Errors
///
/// Returns [`WireError`] when a field violates its bound or the payload
/// exceeds [`MAX_FRAME_BYTES`].
pub fn encode_frame(message: &Message) -> Result<Vec<u8>, WireError> {
    let payload = encode_message(message)?;
    let len =
        u32::try_from(payload.len()).map_err(|_| WireError::TooLarge { len: payload.len() })?;
    let mut frame = Vec::with_capacity(FRAME_HEADER_BYTES + payload.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Writes one complete frame in a single `write_all`.
///
/// # Errors
///
/// Returns [`WireError`] for encode or I/O failures.
pub fn write_frame<W: Write>(writer: &mut W, message: &Message) -> Result<(), WireError> {
    let frame = encode_frame(message)?;
    writer
        .write_all(&frame)
        .map_err(|error| WireError::Io(error.kind()))
}

/// Encodes one message payload (tag included, no length prefix).
///
/// # Errors
///
/// Returns [`WireError`] when a field violates its bound or the payload
/// exceeds [`MAX_FRAME_BYTES`].
pub fn encode_message(message: &Message) -> Result<Vec<u8>, WireError> {
    let mut encoder = Encoder::default();
    match message {
        Message::Hello {
            min,
            max,
            component,
            version,
        } => {
            encoder.u8(TAG_HELLO);
            encoder.u16(*min);
            encoder.u16(*max);
            encoder.component_name(component)?;
            encoder.version(version)?;
        }
        Message::HelloAck {
            protocol,
            component,
            version,
        } => {
            encoder.u8(TAG_HELLO_ACK);
            encoder.u16(*protocol);
            encoder.component_name(component)?;
            encoder.version(version)?;
        }
        Message::Spawn {
            job,
            program,
            args,
            cwd,
            env,
            kind,
            io,
            lifetime,
            hard_ms,
            idle_ms,
            retention_ms,
        } => {
            encoder.u8(TAG_SPAWN);
            encoder.u64(*job)?;
            encoder.str_bounded(program, MAX_EXECUTABLE_BYTES, "program")?;
            encoder.args(args)?;
            encoder.opt_str(cwd.as_deref(), MAX_EXEC_CWD_BYTES, "cwd")?;
            encoder.env(env)?;
            encoder.u8(kind.code());
            encoder.u8(io.code());
            encoder.u8(lifetime.code());
            encoder.u32(*hard_ms);
            encoder.u32(*idle_ms);
            encoder.u32(*retention_ms);
        }
        Message::Terminate {
            job,
            generation,
            mode,
            grace_ms,
        } => {
            encoder.u8(TAG_TERMINATE);
            encoder.u64(*job)?;
            encoder.u64(*generation)?;
            encoder.u8(mode.code());
            if *grace_ms > MAX_CANCEL_GRACE_MS {
                return Err(WireError::InvalidField("grace_ms"));
            }
            encoder.u32(*grace_ms);
        }
        Message::ReadOutput {
            request,
            job,
            stream,
            tail_lines,
            max_bytes,
        } => {
            if *tail_lines > MAX_TAIL_LINES {
                return Err(WireError::InvalidField("tail_lines"));
            }
            if *max_bytes as usize > MAX_OUTPUT_READ_BYTES {
                return Err(WireError::InvalidField("max_bytes"));
            }
            encoder.u8(TAG_READ_OUTPUT);
            encoder.u64(*request)?;
            encoder.u64(*job)?;
            encoder.u8(stream.code());
            encoder.u32(*tail_lines);
            encoder.u32(*max_bytes);
        }
        Message::Shutdown => encoder.u8(TAG_SHUTDOWN),
        Message::Spawned { job, generation } => {
            encoder.u8(TAG_SPAWNED);
            encoder.u64(*job)?;
            encoder.u64(*generation)?;
        }
        Message::Started { job } => {
            encoder.u8(TAG_STARTED);
            encoder.u64(*job)?;
        }
        Message::Output { job, stream, data } => {
            if data.len() > MAX_OUTPUT_CHUNK_BYTES {
                return Err(WireError::TooLarge { len: data.len() });
            }
            encoder.u8(TAG_OUTPUT);
            encoder.u64(*job)?;
            encoder.u8(stream.code());
            encoder.bytes(data);
        }
        Message::Exit {
            job,
            outcome,
            detail,
            cancel,
            clock,
            kill_scope,
            oom,
            oom_gap,
            stdout_total,
            stdout_evicted,
            stderr_total,
            stderr_evicted,
        } => {
            encoder.u8(TAG_EXIT);
            encoder.u64(*job)?;
            encoder.u8(outcome.code());
            encoder.u32(u32::from_be_bytes(detail.to_be_bytes()));
            encoder.u8(cancel.code());
            encoder.u8(clock.code());
            encoder.u8(kill_scope.code());
            encoder.u8(oom.code());
            encoder.u8(oom_gap.code());
            encoder.u64(*stdout_total)?;
            encoder.u64(*stdout_evicted)?;
            encoder.u64(*stderr_total)?;
            encoder.u64(*stderr_evicted)?;
        }
        Message::Canceled { job, outcome } => {
            encoder.u8(TAG_CANCELED);
            encoder.u64(*job)?;
            encoder.u8(outcome.code());
        }
        Message::OutputView {
            request,
            job,
            stream,
            data,
            total,
            dropped,
            truncated,
            lines,
        } => {
            if data.len() > MAX_OUTPUT_READ_BYTES {
                return Err(WireError::TooLarge { len: data.len() });
            }
            encoder.u8(TAG_OUTPUT_VIEW);
            encoder.u64(*request)?;
            encoder.u64(*job)?;
            encoder.u8(stream.code());
            encoder.bytes(data);
            encoder.u64(*total)?;
            encoder.u64(*dropped)?;
            encoder.u8(u8::from(*truncated));
            encoder.u32(*lines);
        }
        Message::Error {
            request,
            kind,
            message,
        } => {
            encoder.u8(TAG_ERROR);
            encoder.u64(*request)?;
            encoder.u8(kind.code());
            encoder.diagnostic(message)?;
        }
        Message::ShutdownAck => encoder.u8(TAG_SHUTDOWN_ACK),
    }
    let payload = encoder.finish();
    if payload.len() > MAX_FRAME_BYTES {
        return Err(WireError::TooLarge { len: payload.len() });
    }
    Ok(payload)
}

/// Decodes one message payload (tag included, no length prefix).
///
/// # Errors
///
/// Returns [`WireError`] for an unknown tag, truncation, trailing bytes,
/// invalid UTF-8, unknown enum codes, zero ids, or any bound violation.
pub fn decode_message(payload: &[u8]) -> Result<Message, WireError> {
    let mut decoder = Decoder::new(payload);
    let tag = decoder.u8()?;
    let message = match tag {
        TAG_HELLO => Message::Hello {
            min: decoder.u16()?,
            max: decoder.u16()?,
            component: decoder.component_name()?,
            version: decoder.version()?,
        },
        TAG_HELLO_ACK => Message::HelloAck {
            protocol: decoder.u16()?,
            component: decoder.component_name()?,
            version: decoder.version()?,
        },
        TAG_SPAWN => {
            let job = decoder.id()?;
            let program = decoder.str_bounded(MAX_EXECUTABLE_BYTES, "program")?;
            if program.is_empty() {
                return Err(WireError::InvalidField("program"));
            }
            let args = decoder.args()?;
            let cwd = decoder.opt_str(MAX_EXEC_CWD_BYTES, "cwd")?;
            let env = decoder.env()?;
            let kind_code = decoder.u8()?;
            let io_code = decoder.u8()?;
            let lifetime_code = decoder.u8()?;
            let kind = SpawnKind::from_code(kind_code).ok_or(WireError::InvalidField("kind"))?;
            let io = SpawnIo::from_code(io_code).ok_or(WireError::InvalidField("io"))?;
            let lifetime = SpawnLifetime::from_code(lifetime_code)
                .ok_or(WireError::InvalidField("lifetime"))?;
            Message::Spawn {
                job,
                program,
                args,
                cwd,
                env,
                kind,
                io,
                lifetime,
                hard_ms: decoder.u32()?,
                idle_ms: decoder.u32()?,
                retention_ms: decoder.u32()?,
            }
        }
        TAG_TERMINATE => {
            let job = decoder.id()?;
            let generation = decoder.id()?;
            let mode_code = decoder.u8()?;
            let mode = TerminateMode::from_code(mode_code)
                .ok_or(WireError::InvalidField("terminate mode"))?;
            let grace_ms = decoder.u32()?;
            if grace_ms > MAX_CANCEL_GRACE_MS {
                return Err(WireError::InvalidField("grace_ms"));
            }
            Message::Terminate {
                job,
                generation,
                mode,
                grace_ms,
            }
        }
        TAG_READ_OUTPUT => {
            let request = decoder.id()?;
            let job = decoder.id()?;
            let stream_code = decoder.u8()?;
            let stream = Stream::from_code(stream_code).ok_or(WireError::InvalidField("stream"))?;
            let tail_lines = decoder.u32()?;
            let max_bytes = decoder.u32()?;
            if tail_lines > MAX_TAIL_LINES {
                return Err(WireError::InvalidField("tail_lines"));
            }
            if max_bytes as usize > MAX_OUTPUT_READ_BYTES {
                return Err(WireError::InvalidField("max_bytes"));
            }
            Message::ReadOutput {
                request,
                job,
                stream,
                tail_lines,
                max_bytes,
            }
        }
        TAG_SHUTDOWN => Message::Shutdown,
        TAG_SPAWNED => Message::Spawned {
            job: decoder.id()?,
            generation: decoder.id()?,
        },
        TAG_STARTED => Message::Started { job: decoder.id()? },
        TAG_OUTPUT => {
            let job = decoder.id()?;
            let stream_code = decoder.u8()?;
            let stream = Stream::from_code(stream_code).ok_or(WireError::InvalidField("stream"))?;
            let data = decoder.bytes(MAX_OUTPUT_CHUNK_BYTES)?;
            Message::Output { job, stream, data }
        }
        TAG_EXIT => {
            let job = decoder.id()?;
            let outcome_code = decoder.u8()?;
            let outcome =
                ExitKind::from_code(outcome_code).ok_or(WireError::InvalidField("outcome"))?;
            let detail = i32::from_be_bytes(decoder.u32()?.to_be_bytes());
            let cancel_code = decoder.u8()?;
            let cancel = WireCancelEffect::from_code(cancel_code)
                .ok_or(WireError::InvalidField("cancel effect"))?;
            let clock_code = decoder.u8()?;
            let clock = WireDeadlineClock::from_code(clock_code)
                .ok_or(WireError::InvalidField("deadline clock"))?;
            let kill_code = decoder.u8()?;
            let kill_scope =
                WireKillScope::from_code(kill_code).ok_or(WireError::InvalidField("kill scope"))?;
            let oom_code = decoder.u8()?;
            let oom = WireOomVerdict::from_code(oom_code)
                .ok_or(WireError::InvalidField("oom verdict"))?;
            let gap_code = decoder.u8()?;
            let oom_gap =
                WireOomGap::from_code(gap_code).ok_or(WireError::InvalidField("oom gap"))?;
            Message::Exit {
                job,
                outcome,
                detail,
                cancel,
                clock,
                kill_scope,
                oom,
                oom_gap,
                stdout_total: decoder.u64()?,
                stdout_evicted: decoder.u64()?,
                stderr_total: decoder.u64()?,
                stderr_evicted: decoder.u64()?,
            }
        }
        TAG_CANCELED => {
            let job = decoder.id()?;
            let outcome_code = decoder.u8()?;
            let outcome = TerminateOutcome::from_code(outcome_code)
                .ok_or(WireError::InvalidField("terminate outcome"))?;
            Message::Canceled { job, outcome }
        }
        TAG_OUTPUT_VIEW => {
            let request = decoder.id()?;
            let job = decoder.id()?;
            let stream_code = decoder.u8()?;
            let stream = Stream::from_code(stream_code).ok_or(WireError::InvalidField("stream"))?;
            let data = decoder.bytes(MAX_OUTPUT_READ_BYTES)?;
            let total = decoder.u64()?;
            let dropped = decoder.u64()?;
            let truncated = decoder.bool()?;
            let lines = decoder.u32()?;
            Message::OutputView {
                request,
                job,
                stream,
                data,
                total,
                dropped,
                truncated,
                lines,
            }
        }
        TAG_ERROR => {
            let request = decoder.u64()?;
            let kind_code = decoder.u8()?;
            let kind =
                ErrorKind::from_code(kind_code).ok_or(WireError::InvalidField("error kind"))?;
            Message::Error {
                request,
                kind,
                message: decoder.diagnostic()?,
            }
        }
        TAG_SHUTDOWN_ACK => Message::ShutdownAck,
        other => return Err(WireError::UnknownTag(other)),
    };
    if !decoder.is_empty() {
        return Err(WireError::TrailingBytes);
    }
    Ok(message)
}

/// Component name this binary answers to in `Hello`.
#[must_use]
pub fn expected_component_name() -> &'static str {
    COMPONENT_NAME
}

/// Protocol version range this binary supports.
#[must_use]
pub const fn supported_protocol_range() -> (u16, u16) {
    (PROTOCOL_VERSION, PROTOCOL_VERSION)
}

/// Negotiates `[min, max]` against this component's range.
///
/// Returns the highest overlapping version, or `None` when the ranges do
/// not intersect.
#[must_use]
pub fn negotiate(min: u16, max: u16) -> Option<u16> {
    if min > max {
        return None;
    }
    let low = min.max(PROTOCOL_VERSION);
    let high = max.min(PROTOCOL_VERSION);
    (low <= high).then_some(high)
}

// ── encoder / decoder ───────────────────────────────────────────────────────

#[derive(Default)]
struct Encoder {
    buffer: Vec<u8>,
}

impl Encoder {
    fn u8(&mut self, value: u8) {
        self.buffer.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.buffer.extend_from_slice(&value.to_be_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.buffer.extend_from_slice(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) -> Result<(), WireError> {
        self.buffer.extend_from_slice(&value.to_be_bytes());
        Ok(())
    }

    fn bytes(&mut self, data: &[u8]) {
        self.u32(u32::try_from(data.len()).unwrap_or(u32::MAX));
        self.buffer.extend_from_slice(data);
    }

    fn str_bounded(
        &mut self,
        value: &str,
        max: usize,
        field: &'static str,
    ) -> Result<(), WireError> {
        if value.len() > max {
            return Err(WireError::InvalidField(field));
        }
        self.bytes(value.as_bytes());
        Ok(())
    }

    fn component_name(&mut self, value: &str) -> Result<(), WireError> {
        let bytes = value.as_bytes();
        let valid = !bytes.is_empty()
            && bytes.len() <= MAX_COMPONENT_NAME_BYTES
            && bytes[0].is_ascii_lowercase()
            && bytes
                .iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-');
        if !valid {
            return Err(WireError::InvalidField("component name"));
        }
        self.bytes(bytes);
        Ok(())
    }

    fn version(&mut self, value: &str) -> Result<(), WireError> {
        let valid = !value.is_empty()
            && value.len() <= MAX_VERSION_BYTES
            && value.bytes().all(|b| b.is_ascii_graphic() || b == b' ');
        if !valid {
            return Err(WireError::InvalidField("version"));
        }
        self.bytes(value.as_bytes());
        Ok(())
    }

    fn args(&mut self, args: &[String]) -> Result<(), WireError> {
        if args.len() > MAX_EXEC_ARGS {
            return Err(WireError::InvalidField("args"));
        }
        self.u32(u32::try_from(args.len()).unwrap_or(u32::MAX));
        let mut total = 0usize;
        for arg in args {
            if arg.len() > MAX_EXEC_ARG_BYTES {
                return Err(WireError::InvalidField("arg"));
            }
            total = total.saturating_add(arg.len());
            self.bytes(arg.as_bytes());
        }
        if total > MAX_EXEC_ARGS_TOTAL_BYTES {
            return Err(WireError::InvalidField("args total"));
        }
        Ok(())
    }

    fn opt_str(
        &mut self,
        value: Option<&str>,
        max: usize,
        field: &'static str,
    ) -> Result<(), WireError> {
        match value {
            Some(value) => {
                self.u8(1);
                self.str_bounded(value, max, field)
            }
            None => {
                self.u8(0);
                Ok(())
            }
        }
    }

    fn env(&mut self, env: &WireEnv) -> Result<(), WireError> {
        self.u8(env.code());
        let vars = match env {
            WireEnv::Isolated => return Ok(()),
            WireEnv::Explicit(vars) => vars,
        };
        if vars.len() > MAX_EXEC_ENV_VARS {
            return Err(WireError::InvalidField("env"));
        }
        self.u32(u32::try_from(vars.len()).unwrap_or(u32::MAX));
        let mut total = 0usize;
        for var in vars {
            if var.name.len() > MAX_EXEC_ENV_NAME_BYTES {
                return Err(WireError::InvalidField("env name"));
            }
            if var.value.len() > MAX_EXEC_ENV_VALUE_BYTES {
                return Err(WireError::InvalidField("env value"));
            }
            total = total
                .saturating_add(var.name.len())
                .saturating_add(var.value.len());
            self.bytes(var.name.as_bytes());
            self.bytes(var.value.as_bytes());
        }
        if total > MAX_ENV_TOTAL_BYTES {
            return Err(WireError::InvalidField("env total"));
        }
        Ok(())
    }

    fn diagnostic(&mut self, message: &str) -> Result<(), WireError> {
        let valid = message.len() <= MAX_ERROR_MESSAGE_BYTES
            && !message.is_empty()
            && message.bytes().all(|b| (0x20..=0x7e).contains(&b));
        if !valid {
            return Err(WireError::InvalidField("error message"));
        }
        self.bytes(message.as_bytes());
        Ok(())
    }

    fn finish(self) -> Vec<u8> {
        self.buffer
    }
}

struct Decoder<'a> {
    buffer: &'a [u8],
    position: usize,
}

impl<'a> Decoder<'a> {
    const fn new(buffer: &'a [u8]) -> Self {
        Self {
            buffer,
            position: 0,
        }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], WireError> {
        let end = self.position.checked_add(len).ok_or(WireError::Truncated)?;
        if end > self.buffer.len() {
            return Err(WireError::Truncated);
        }
        let slice = &self.buffer[self.position..end];
        self.position = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take(1)?[0])
    }

    fn bool(&mut self) -> Result<bool, WireError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(WireError::InvalidField("bool")),
        }
    }

    fn u16(&mut self) -> Result<u16, WireError> {
        let bytes: [u8; 2] = self.take(2)?.try_into().map_err(|_| WireError::Truncated)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn u32(&mut self) -> Result<u32, WireError> {
        let bytes: [u8; 4] = self.take(4)?.try_into().map_err(|_| WireError::Truncated)?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, WireError> {
        let bytes: [u8; 8] = self.take(8)?.try_into().map_err(|_| WireError::Truncated)?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn id(&mut self) -> Result<u64, WireError> {
        let id = self.u64()?;
        if id == 0 {
            return Err(WireError::InvalidField("zero id"));
        }
        Ok(id)
    }

    fn bytes(&mut self, max: usize) -> Result<Vec<u8>, WireError> {
        let len = self.u32()? as usize;
        if len > max {
            return Err(WireError::InvalidField("byte length"));
        }
        Ok(self.take(len)?.to_vec())
    }

    fn str_bounded(&mut self, max: usize, field: &'static str) -> Result<String, WireError> {
        let len = self.u32()? as usize;
        if len > max {
            return Err(WireError::InvalidField(field));
        }
        let bytes = self.take(len)?;
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| WireError::InvalidUtf8)
    }

    fn component_name(&mut self) -> Result<String, WireError> {
        let name = self.str_bounded(MAX_COMPONENT_NAME_BYTES, "component name")?;
        let valid = !name.is_empty()
            && name.as_bytes()[0].is_ascii_lowercase()
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !valid {
            return Err(WireError::InvalidField("component name"));
        }
        Ok(name)
    }

    fn version(&mut self) -> Result<String, WireError> {
        let version = self.str_bounded(MAX_VERSION_BYTES, "version")?;
        let valid =
            !version.is_empty() && version.bytes().all(|b| b.is_ascii_graphic() || b == b' ');
        if !valid {
            return Err(WireError::InvalidField("version"));
        }
        Ok(version)
    }

    fn args(&mut self) -> Result<Vec<String>, WireError> {
        let count = self.u32()? as usize;
        if count > MAX_EXEC_ARGS {
            return Err(WireError::InvalidField("args"));
        }
        let mut args = Vec::with_capacity(count);
        let mut total = 0usize;
        for _ in 0..count {
            let arg = self.str_bounded(MAX_EXEC_ARG_BYTES, "arg")?;
            total = total.saturating_add(arg.len());
            args.push(arg);
        }
        if total > MAX_EXEC_ARGS_TOTAL_BYTES {
            return Err(WireError::InvalidField("args total"));
        }
        Ok(args)
    }

    fn opt_str(&mut self, max: usize, field: &'static str) -> Result<Option<String>, WireError> {
        match self.u8()? {
            0 => Ok(None),
            1 => self.str_bounded(max, field).map(Some),
            _ => Err(WireError::InvalidField("option tag")),
        }
    }

    fn env(&mut self) -> Result<WireEnv, WireError> {
        let mode = self.u8()?;
        if mode == 0 {
            return Ok(WireEnv::Isolated);
        }
        if mode != 1 {
            return Err(WireError::InvalidField("env mode"));
        }
        let count = self.u32()? as usize;
        if count > MAX_EXEC_ENV_VARS {
            return Err(WireError::InvalidField("env"));
        }
        let mut vars = Vec::with_capacity(count);
        let mut total = 0usize;
        for _ in 0..count {
            let name = self.str_bounded(MAX_EXEC_ENV_NAME_BYTES, "env name")?;
            let value = self.str_bounded(MAX_EXEC_ENV_VALUE_BYTES, "env value")?;
            total = total.saturating_add(name.len()).saturating_add(value.len());
            vars.push(WireEnvVar { name, value });
        }
        if total > MAX_ENV_TOTAL_BYTES {
            return Err(WireError::InvalidField("env total"));
        }
        Ok(WireEnv::Explicit(vars))
    }

    fn diagnostic(&mut self) -> Result<String, WireError> {
        let message = self.str_bounded(MAX_ERROR_MESSAGE_BYTES, "error message")?;
        let valid = !message.is_empty() && message.bytes().all(|b| (0x20..=0x7e).contains(&b));
        if !valid {
            return Err(WireError::InvalidField("error message"));
        }
        Ok(message)
    }

    fn is_empty(&self) -> bool {
        self.position == self.buffer.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(message: &Message) -> Vec<u8> {
        encode_frame(message).expect("encodes")
    }

    fn roundtrip(message: Message) {
        let encoded = frame(&message);
        let mut reader = FrameReader::new(encoded.as_slice());
        assert_eq!(reader.read_message().expect("decodes"), Some(message));
        assert_eq!(reader.read_message().expect("clean eof"), None);
    }

    fn hello() -> Message {
        Message::Hello {
            min: 1,
            max: 1,
            component: "execution".to_owned(),
            version: "0.0.1".to_owned(),
        }
    }

    fn spawn() -> Message {
        Message::Spawn {
            job: 7,
            program: "/bin/echo".to_owned(),
            args: vec!["hello".to_owned(), "world".to_owned()],
            cwd: Some("/tmp".to_owned()),
            env: WireEnv::Explicit(vec![WireEnvVar {
                name: "LANG".to_owned(),
                value: "C".to_owned(),
            }]),
            kind: SpawnKind::Command,
            io: SpawnIo::Pipes,
            lifetime: SpawnLifetime::Detached,
            hard_ms: 1_000,
            idle_ms: 0,
            retention_ms: 0,
        }
    }

    fn exit() -> Message {
        Message::Exit {
            job: 7,
            outcome: ExitKind::ExitCode,
            detail: 3,
            cancel: WireCancelEffect::None,
            clock: WireDeadlineClock::None,
            kill_scope: WireKillScope::OwnedTree,
            oom: WireOomVerdict::NotOom,
            oom_gap: WireOomGap::None,
            stdout_total: 10,
            stdout_evicted: 0,
            stderr_total: 5,
            stderr_evicted: 0,
        }
    }

    #[test]
    fn every_message_roundtrips() {
        roundtrip(hello());
        roundtrip(Message::HelloAck {
            protocol: 1,
            component: "execution".to_owned(),
            version: "0.0.1".to_owned(),
        });
        roundtrip(spawn());
        roundtrip(Message::Terminate {
            job: 7,
            generation: 2,
            mode: TerminateMode::GracefulThenKill,
            grace_ms: 500,
        });
        roundtrip(Message::ReadOutput {
            request: 9,
            job: 7,
            stream: Stream::Stderr,
            tail_lines: 20,
            max_bytes: 1024,
        });
        roundtrip(Message::Shutdown);
        roundtrip(Message::Spawned {
            job: 7,
            generation: 2,
        });
        roundtrip(Message::Started { job: 7 });
        roundtrip(Message::Output {
            job: 7,
            stream: Stream::Stdout,
            data: b"hello".to_vec(),
        });
        roundtrip(exit());
        roundtrip(Message::Canceled {
            job: 7,
            outcome: TerminateOutcome::Killed,
        });
        roundtrip(Message::OutputView {
            request: 9,
            job: 7,
            stream: Stream::Stdout,
            data: b"tail".to_vec(),
            total: 100,
            dropped: 0,
            truncated: false,
            lines: 1,
        });
        roundtrip(Message::Error {
            request: 9,
            kind: ErrorKind::InvalidRequest,
            message: "spawn spec rejected".to_owned(),
        });
        roundtrip(Message::ShutdownAck);
    }

    #[test]
    fn oversized_frame_is_rejected_from_the_header() {
        let mut stream = Vec::new();
        stream.extend_from_slice(&u32::try_from(MAX_FRAME_BYTES + 1).unwrap().to_be_bytes());
        let mut reader = FrameReader::new(stream.as_slice());
        assert_eq!(
            reader.read_frame(),
            Err(WireError::TooLarge {
                len: MAX_FRAME_BYTES + 1
            })
        );
    }

    #[test]
    fn zero_length_frame_and_partial_header_are_rejected() {
        let mut reader = FrameReader::new([0u8, 0, 0, 0].as_slice());
        assert_eq!(reader.read_frame(), Err(WireError::EmptyFrame));

        let mut reader = FrameReader::new([0u8, 0].as_slice());
        assert_eq!(reader.read_frame(), Err(WireError::Truncated));
    }

    #[test]
    fn truncated_payload_is_rejected() {
        let encoded = frame(&hello());
        let mut reader = FrameReader::new(&encoded[..encoded.len() - 1]);
        assert_eq!(reader.read_frame(), Err(WireError::Truncated));
    }

    #[test]
    fn unknown_tags_and_trailing_bytes_are_rejected() {
        assert_eq!(decode_message(&[0x7f]), Err(WireError::UnknownTag(0x7f)));
        let mut encoded = encode_message(&Message::Started { job: 1 }).unwrap();
        encoded.push(0);
        assert_eq!(decode_message(&encoded), Err(WireError::TrailingBytes));
    }

    #[test]
    fn zero_ids_and_bad_enums_are_rejected() {
        let spawn = spawn();
        let mut encoded = encode_message(&spawn).unwrap();
        // job id sits immediately after the tag in Spawn.
        encoded[1..9].copy_from_slice(&0u64.to_be_bytes());
        assert_eq!(
            decode_message(&encoded),
            Err(WireError::InvalidField("zero id"))
        );

        let mut encoded = encode_message(&Message::Started { job: 1 }).unwrap();
        encoded[1..9].copy_from_slice(&0u64.to_be_bytes());
        assert_eq!(
            decode_message(&encoded),
            Err(WireError::InvalidField("zero id"))
        );

        let mut terminate = encode_message(&Message::Terminate {
            job: 1,
            generation: 1,
            mode: TerminateMode::Immediate,
            grace_ms: 0,
        })
        .unwrap();
        let mode_index = 1 + 8 + 8;
        terminate[mode_index] = 9;
        assert_eq!(
            decode_message(&terminate),
            Err(WireError::InvalidField("terminate mode"))
        );
    }

    #[test]
    fn output_chunk_and_read_bounds_are_enforced() {
        let too_big = Message::Output {
            job: 1,
            stream: Stream::Stdout,
            data: vec![0; MAX_OUTPUT_CHUNK_BYTES + 1],
        };
        assert_eq!(
            encode_message(&too_big),
            Err(WireError::TooLarge {
                len: MAX_OUTPUT_CHUNK_BYTES + 1
            })
        );

        let read_too_big = Message::ReadOutput {
            request: 1,
            job: 1,
            stream: Stream::Stdout,
            tail_lines: 0,
            max_bytes: u32::try_from(MAX_OUTPUT_READ_BYTES + 1).unwrap(),
        };
        assert_eq!(
            encode_message(&read_too_big),
            Err(WireError::InvalidField("max_bytes"))
        );
    }

    #[test]
    fn error_messages_are_bounded_and_ascii() {
        let bad = Message::Error {
            request: 0,
            kind: ErrorKind::Protocol,
            message: "bad\nframe".to_owned(),
        };
        assert_eq!(
            encode_message(&bad),
            Err(WireError::InvalidField("error message"))
        );
        let too_long = Message::Error {
            request: 0,
            kind: ErrorKind::Protocol,
            message: "x".repeat(MAX_ERROR_MESSAGE_BYTES + 1),
        };
        assert_eq!(
            encode_message(&too_long),
            Err(WireError::InvalidField("error message"))
        );
    }

    #[test]
    fn handshake_negotiation_is_exact() {
        assert_eq!(negotiate(1, 1), Some(1));
        assert_eq!(negotiate(0, 1), Some(1));
        assert_eq!(negotiate(1, 9), Some(1));
        assert_eq!(negotiate(2, 9), None);
        assert_eq!(negotiate(2, 1), None);
    }

    #[test]
    fn env_and_args_bounds_are_enforced() {
        let mut vars = Vec::new();
        for index in 0..=MAX_EXEC_ENV_VARS {
            vars.push(WireEnvVar {
                name: format!("V{index}"),
                value: String::new(),
            });
        }
        let over = Message::Spawn {
            job: 1,
            program: "x".to_owned(),
            args: Vec::new(),
            cwd: None,
            env: WireEnv::Explicit(vars),
            kind: SpawnKind::Command,
            io: SpawnIo::Pipes,
            lifetime: SpawnLifetime::Detached,
            hard_ms: 0,
            idle_ms: 0,
            retention_ms: 0,
        };
        assert_eq!(encode_message(&over), Err(WireError::InvalidField("env")));

        let too_many_args = vec!["x".to_owned(); MAX_EXEC_ARGS + 1];
        let over = Message::Spawn {
            job: 1,
            program: "x".to_owned(),
            args: too_many_args,
            cwd: None,
            env: WireEnv::Isolated,
            kind: SpawnKind::Command,
            io: SpawnIo::Pipes,
            lifetime: SpawnLifetime::Detached,
            hard_ms: 0,
            idle_ms: 0,
            retention_ms: 0,
        };
        assert_eq!(encode_message(&over), Err(WireError::InvalidField("args")));
    }
}
