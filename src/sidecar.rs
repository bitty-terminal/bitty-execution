//! Sidecar-supervision contract this repository expects a host to use
//! (execution#14, audit finding F4).
//!
//! Core still runs two process supervisors inside this repository's scope
//! (process ownership, lifetime, cancellation, crash recovery): the native
//! component broker (`crates/bitty-runtime/src/component/`, DIR-030) and the
//! plugin synchronous spawn surface
//! (`crates/bitty-runtime/src/plugin_runtime/spawn.rs`, CTX-0445).
//! `bitty-pty`/`bitty-winjob` are already mechanism-only and stay out of
//! scope. This module publishes the seam those two Core supervisors route
//! through: a spawn gate, typed cancel, bounded deadlines, crash accounting,
//! and kill/reap semantics, following this repository's existing patterns
//! ([`JobRegistry::cancel`](crate::JobRegistry::cancel) /
//! [`cancel_typed`](crate::JobRegistry::cancel_typed),
//! [`CancelRequest`](crate::CancelRequest),
//! [`KillScope::for_backend`](crate::KillScope::for_backend) mapping onto
//! `bitty_pty::TreeBackend`).
//!
//! # What this contract is
//!
//! - [`SidecarPolicy`]: the bounded numbers a host enforces. The defaults
//!   ([`SidecarPolicy::core_defaults`]) are exactly Core's DIR-030 numbers,
//!   each documented with its Core source; a host adopts them instead of
//!   re-deriving its own.
//! - [`SidecarGate`]: whether a sidecar may spawn now. It mirrors
//!   `component/policy.rs` `SpawnGate` (`Ready`, `Backoff { retry_after }`,
//!   `Unavailable`).
//! - [`SidecarCrashTracker`] and [`SidecarDeadlineStrikes`]: crash
//!   accounting. They mirror `component/policy.rs` `CrashTracker`
//!   (`record_crash`, `gate`, `backoff_for`, doubling from the initial delay
//!   to the ceiling, latch after the limit inside the window) and
//!   `DeadlineStrikes` (`expire` trips at the threshold, `reset` on a
//!   component-produced terminal frame). Time is injected (`now: Instant`)
//!   so policy stays deterministic under test, as in Core.
//! - [`SidecarSupervisor`]: the trait a host implements, one instance per
//!   supervised sidecar. A broker multiplexing several sidecars holds one
//!   instance per sidecar, mirroring how Core's broker holds one
//!   per-component slot (`Slot { tracker, .. }`).
//! - [`SidecarStopOutcome`]: how the last process ended (`Exited`, `Killed`,
//!   `Crashed`). It mirrors `component/broker.rs` `StopOutcome`.
//! - [`SidecarIpcProtocol`]: explicit ownership of the component wire
//!   protocol (it travels with `component/` today; see below).
//!
//! # Kill and reap semantics (what the host must guarantee)
//!
//! 1. Kills reach the owned process tree through the `bitty-pty` boundary
//!    (`bitty_pty::OwnedTree`: process groups on Linux/macOS, Job Objects on
//!    Windows), never a single pid where a tree backend exists. The host
//!    reports the scope per sidecar through
//!    [`SidecarSupervisor::kill_scope`], which is
//!    [`KillScope::for_backend`](crate::KillScope::for_backend) over
//!    [`ProcessTreeBackend::detect`](crate::process_tree::ProcessTreeBackend::detect)
//!    unless the host adopted the process some other way; where no backend
//!    exists the scope is [`KillScope::DirectChild`](crate::KillScope) and
//!    the orphan gap is surfaced, never hidden.
//! 2. Only recorded children are ever signaled. Core's broker kills only the
//!    child recorded in the slot (`kill_and_reap` takes the slot, never a
//!    pid), and the spawn surface owns the live child in its cleanup guard
//!    (`PostSpawnChild::new` immediately after `Command::spawn()`); the
//!    contract keeps both rules: no signal ever names a pid the host did not
//!    spawn and still own.
//! 3. Every kill pairs with a reap (`wait`): no zombie on any path, including
//!    error paths (the guard's `abandon`/`Drop` discipline).
//! 4. Shutdown order per sidecar: fail in-flight work with a typed reason,
//!    close stdin, wait up to the shutdown grace, reap exited children,
//!    kill whatever is left (recorded children only), record the outcome.
//!    This is `ComponentBroker::shutdown` phases 1-2 plus
//!    `kill_and_reap(slot, Killed)`.
//! 5. Pipe drains are concurrent and bounded, joined with a bounded timeout;
//!    a hung drain (a grandchild holding the pipe) detaches and keeps
//!    partial output instead of wedging the supervisor
//!    (`drain_bounded_shared` / `join_drain_bounded` with
//!    `SPAWN_DRAIN_JOIN_TIMEOUT`).
//! 6. A timeout is [`ExecutionOutcome::TimedOut`](crate::ExecutionOutcome)
//!    (long-lived supervision) or `Unknown` with timeout evidence (one-shot
//!    spawn), never a success and never an invented exit code.
//! 7. OOM is only asserted from per-job evidence
//!    ([`classify_oom`](crate::oom::classify_oom)); a signal number is never
//!    evidence.
//!
//! # Bounded deadlines
//!
//! Every request carries a Core deadline of
//! [`SidecarPolicy::effective_deadline`] (requested, or the default when
//! none was requested, clamped to the maximum) plus the deadline grace, so
//! the sidecar's own deadline fires first and Core's grace-covered deadline
//! only catches a silent sidecar (`component/broker.rs`
//! `effective_timeout`, `COMPONENT_REQUEST_DEADLINE_GRACE`). Consecutive
//! Core deadline expiries count through
//! [`SidecarSupervisor::record_deadline_expiry`]; reaching the threshold
//! takes the crash path, and any component-produced terminal frame resets
//! the count ([`SidecarSupervisor::note_terminal_frame`]).
//!
//! # Component IPC protocol ownership
//!
//! The native-component wire protocol v1 (`bitty-network-wire`:
//! `PROTOCOL_VERSION = 1`, `MAX_IN_FLIGHT = 64`, `DEFAULT_MAX_BODY_BYTES`
//! of 8 MiB, `MAX_COMPONENT_NAME_BYTES` of 32) is owned by the
//! `bitty-network` repository. It travels with Core's `component/` today
//! (resolution, digest check, `Hello`/`HelloAck` handshake, multiplexed
//! requests), and this repository claims no ownership of the wire bytes:
//! [`SidecarIpcProtocol`] records the owner and the current carrier so the
//! supervision seam never drifts into protocol work. What this repository
//! owns is the supervision mechanics above the wire: spawn gating, bounded
//! deadlines, crash accounting, kill/reap, and recovery.
//!
//! # Migration sketch (doc-level; no Core changes in this task)
//!
//! Core-side rewire happens after 0.0.23. Each Core call site routes through
//! the seam member named here; nothing here spawns a process, binds a
//! socket, or reaps a foreign pid.
//!
//! | Core call site (at audit time) | Routes through |
//! |---|---|
//! | `component/mod.rs` `COMPONENT_BACKOFF_INITIAL/MAX`, `COMPONENT_CRASH_LIMIT/WINDOW` | [`SidecarPolicy::core_defaults`] fields `backoff_initial`, `backoff_max`, `crash_limit`, `crash_window` |
//! | `component/mod.rs` `COMPONENT_REQUEST_DEFAULT/MAX_TIMEOUT`, `COMPONENT_REQUEST_DEADLINE_GRACE`, `COMPONENT_DEADLINE_CRASH_THRESHOLD` | `request_default_timeout`, `request_max_timeout`, `deadline_grace`, `deadline_crash_threshold` |
//! | `component/mod.rs` `COMPONENT_IDLE_TIMEOUT`, `COMPONENT_SHUTDOWN_GRACE`, `COMPONENT_HANDSHAKE_TIMEOUT`, `COMPONENT_MAX_IN_FLIGHT` | `idle_timeout`, `shutdown_grace`, `handshake_timeout`, `max_in_flight` |
//! | `component/policy.rs` `CrashTracker::{gate, record_crash, backoff_for, recent_crashes, is_unavailable}` | [`SidecarSupervisor::spawn_gate`], [`record_crash`](SidecarSupervisor::record_crash), [`SidecarCrashTracker`] |
//! | `component/policy.rs` `DeadlineStrikes::{expire, reset, count}` | [`record_deadline_expiry`](SidecarSupervisor::record_deadline_expiry), [`note_terminal_frame`](SidecarSupervisor::note_terminal_frame), [`SidecarDeadlineStrikes`] |
//! | `component/broker.rs` `effective_timeout`, `effective_max_body_bytes` | [`effective_deadline`](SidecarSupervisor::effective_deadline); the body budget stays wire-owned (DIR-030 D3) and is not re-derived here |
//! | `component/broker.rs` `ComponentBroker::shutdown` (stdin close, grace, reap, kill recorded children) | kill/reap semantics above plus [`shutdown_grace`](SidecarSupervisor::shutdown_grace) and [`kill_scope`](SidecarSupervisor::kill_scope) |
//! | `component/broker.rs` `crash` (fail in-flight with `component_lost`, `kill_and_reap(Crashed)`, `record_crash`, stderr tail) | [`record_crash`](SidecarSupervisor::record_crash), kill/reap semantics, [`Crashed`](SidecarStopOutcome::Crashed) |
//! | `component/broker.rs` `reap` / `kill_and_reap`, `StopOutcome::{Exited, Killed, Crashed}` | kill/reap semantics above, [`SidecarStopOutcome`] |
//! | `component/broker.rs` `submit` refusals `BrokerError::{Backoff, Unavailable, Busy}` | [`SidecarGate::Backoff`], [`SidecarGate::Unavailable`], the host's in-flight bound (`max_in_flight`) |
//! | `plugin_runtime/spawn.rs` `SpawnRequest::validate`, six-gate `dispatch` | the spawn gate ([`spawn_gate`](SidecarSupervisor::spawn_gate)) plus the shape/allowlist gates, which stay host-owned and are not re-derived here |
//! | `plugin_runtime/spawn.rs` `spawn_process` (`closed_pipe_command`, `PostSpawnChild` guard, timeout kill+reap, `Unknown` on timeout) | kill/reap semantics above; timeout maps to [`ExecutionOutcome::TimedOut`](crate::ExecutionOutcome) under supervision |
//! | `plugin_runtime/spawn.rs` `drain_bounded_shared`, `join_drain_bounded` | kill/reap semantics item 5; retained bytes stay behind this repository's bounded output stores |
//! | `plugin_runtime/spawn.rs` `PostSpawnChildOps::{kill_child, wait_child}`, `kill_and_reap` | kill/reap semantics items 2-3 |
//! | Sidecar stop requests (today: broker shutdown paths, spawn timeout kill) | [`cancel_sidecar`](SidecarSupervisor::cancel_sidecar) (legacy ambient, mirrors [`JobRegistry::cancel`](crate::JobRegistry::cancel)) and [`cancel_sidecar_typed`](SidecarSupervisor::cancel_sidecar_typed) (generation-fenced, mirrors [`JobRegistry::cancel_typed`](crate::JobRegistry::cancel_typed)) |
//!
//! # Deliberate non-goals
//!
//! - No Core changes: Core keeps routing until its post-0.0.23 rewire.
//! - No wire-protocol work: framing, handshake bytes, and body budgets stay
//!   `bitty-network`-owned (see above).
//! - No allowlist work: which binaries/verbs may run stays decided by the
//!   host's authorizer seam (`SpawnAuthorizer`), never here.
//! - No automatic respawn: crash accounting gates the next spawn; adoption
//!   never restarts a sidecar by itself (the [`adoption_plan`](crate::adoption_plan)
//!   seam).
//!
//! # Invariants
//!
//! - AI-agnostic vocabulary: names, instants, durations, and counts only.
//! - Bounds: the crash history holds at most the crash limit; overflow fails
//!   closed (latch unavailable) or clamps at construction, mirroring Core.
//! - Time is injected: every gate/accounting method takes `now: Instant`, so
//!   hosts stay deterministic under test.

use std::collections::VecDeque;
use std::fmt;
use std::time::{Duration, Instant};

use crate::model::{JobCancel, JobError, JobId};
use crate::outcome::{CancelReceipt, CancelRequest};
use crate::process_tree::KillScope;

// ── policy ────────────────────────────────────────────────────────────────

/// Bounded supervision numbers a sidecar host enforces.
///
/// Every default is Core's DIR-030 number, documented with its Core source;
/// a host adopts [`SidecarPolicy::core_defaults`] instead of re-deriving its
/// own. Fields are public so a host with an approved reason can tune one
/// number while keeping the rest; construction clamps nothing, and use sites
/// clamp defensively (`crash_limit.max(1)`, threshold `max(1)`), mirroring
/// `CrashTracker::with_policy` / `DeadlineStrikes::with_threshold`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SidecarPolicy {
    /// First restart delay after a crash
    /// (`component/mod.rs` `COMPONENT_BACKOFF_INITIAL`, 1 s).
    pub backoff_initial: Duration,
    /// Restart delay ceiling
    /// (`component/mod.rs` `COMPONENT_BACKOFF_MAX`, 30 s).
    pub backoff_max: Duration,
    /// Crashes inside `crash_window` that latch the sidecar unavailable
    /// (`component/mod.rs` `COMPONENT_CRASH_LIMIT`, 5).
    pub crash_limit: usize,
    /// Sliding window for `crash_limit`
    /// (`component/mod.rs` `COMPONENT_CRASH_WINDOW`, 5 min).
    pub crash_window: Duration,
    /// Consecutive Core deadline expiries that count as one crash
    /// (`component/mod.rs` `COMPONENT_DEADLINE_CRASH_THRESHOLD`, 3).
    pub deadline_crash_threshold: u32,
    /// Core deadline base when a request asks for no timeout
    /// (`component/mod.rs` `COMPONENT_REQUEST_DEFAULT_TIMEOUT`, 30 s).
    pub request_default_timeout: Duration,
    /// Ceiling for a requested timeout; larger requests are clamped
    /// (`component/mod.rs` `COMPONENT_REQUEST_MAX_TIMEOUT`, 300 s).
    pub request_max_timeout: Duration,
    /// Grace added on top of the effective timeout before Core expires a
    /// request, so the sidecar's own deadline fires first
    /// (`component/mod.rs` `COMPONENT_REQUEST_DEADLINE_GRACE`, 5 s).
    pub deadline_grace: Duration,
    /// Grace between closing stdin and killing the recorded child
    /// (`component/mod.rs` `COMPONENT_SHUTDOWN_GRACE`, 2 s).
    pub shutdown_grace: Duration,
    /// Deadline for the `HelloAck` after spawn; a miss counts as a crash
    /// (`component/mod.rs` `COMPONENT_HANDSHAKE_TIMEOUT`, 5 s).
    pub handshake_timeout: Duration,
    /// Idle time with nothing in flight before stdin is closed
    /// (`component/mod.rs` `COMPONENT_IDLE_TIMEOUT`, 60 s).
    pub idle_timeout: Duration,
    /// Requests in flight per sidecar connection (wire protocol limit;
    /// `component/mod.rs` `COMPONENT_MAX_IN_FLIGHT`, 64).
    pub max_in_flight: usize,
}

impl SidecarPolicy {
    /// Core's DIR-030 numbers, the default every host adopts.
    #[must_use]
    pub const fn core_defaults() -> Self {
        Self {
            backoff_initial: Duration::from_secs(1),
            backoff_max: Duration::from_secs(30),
            crash_limit: 5,
            crash_window: Duration::from_secs(5 * 60),
            deadline_crash_threshold: 3,
            request_default_timeout: Duration::from_secs(30),
            request_max_timeout: Duration::from_secs(300),
            deadline_grace: Duration::from_secs(5),
            shutdown_grace: Duration::from_secs(2),
            handshake_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(60),
            max_in_flight: 64,
        }
    }

    /// Core deadline for one request: the requested timeout, or the default
    /// when none was requested (`0`), clamped to the maximum. The result is
    /// forwarded as the wire timeout and the request expires past it plus
    /// the deadline grace. Mirrors `component/broker.rs`
    /// `effective_timeout`.
    #[must_use]
    pub fn effective_deadline(&self, requested_timeout_ms: u32) -> Duration {
        let base = if requested_timeout_ms == 0 {
            self.request_default_timeout
        } else {
            Duration::from_millis(requested_timeout_ms as u64)
        };
        base.min(self.request_max_timeout)
    }

    /// Delay after the `n`-th crash inside the window (`n >= 1`): the
    /// initial delay doubling per crash, capped at the maximum. Mirrors
    /// `component/policy.rs` `CrashTracker::backoff_for`.
    #[must_use]
    pub fn backoff_for(&self, n: usize) -> Duration {
        let shift = (n.saturating_sub(1) as u32).min(16);
        let doubled = self.backoff_initial.saturating_mul(1u32 << shift);
        doubled.min(self.backoff_max)
    }
}

// ── spawn gate ────────────────────────────────────────────────────────────

/// Whether a sidecar may be spawned now. Mirrors `component/policy.rs`
/// `SpawnGate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SidecarGate {
    /// Spawning is allowed.
    Ready,
    /// A crash backoff is running; retry after the given delay.
    Backoff {
        /// Remaining delay before the next spawn attempt is allowed.
        retry_after: Duration,
    },
    /// Too many crashes inside the window: unavailable until the next start
    /// (a fresh [`SidecarCrashTracker`]).
    Unavailable,
}

impl SidecarGate {
    /// Stable lowercase wire/display name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Backoff { .. } => "backoff",
            Self::Unavailable => "unavailable",
        }
    }
}

impl fmt::Display for SidecarGate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ready => f.write_str("ready"),
            Self::Backoff { retry_after } => {
                write!(f, "backoff({} ms)", retry_after.as_millis())
            }
            Self::Unavailable => f.write_str("unavailable"),
        }
    }
}

// ── crash accounting ──────────────────────────────────────────────────────

/// Per-sidecar crash history. Mirrors `component/policy.rs` `CrashTracker`:
/// restart delay doubles per crash inside the window up to the ceiling, and
/// the crash limit inside the window latches the sidecar unavailable. The
/// history holds at most the limit, so memory is bounded.
#[derive(Debug, Clone)]
pub struct SidecarCrashTracker {
    crashes: VecDeque<Instant>,
    next_spawn_at: Option<Instant>,
    unavailable: bool,
    policy: SidecarPolicy,
}

impl SidecarCrashTracker {
    /// Tracker under the [`SidecarPolicy::core_defaults`] numbers.
    #[must_use]
    pub fn new() -> Self {
        Self::with_policy(SidecarPolicy::core_defaults())
    }

    /// Tracker under an explicit policy.
    #[must_use]
    pub fn with_policy(policy: SidecarPolicy) -> Self {
        Self {
            crashes: VecDeque::with_capacity(policy.crash_limit.max(1)),
            next_spawn_at: None,
            unavailable: false,
            policy,
        }
    }

    /// Enforced policy.
    #[must_use]
    pub const fn policy(&self) -> SidecarPolicy {
        self.policy
    }

    /// Record a crash at `now` and return the resulting gate.
    pub fn record_crash(&mut self, now: Instant) -> SidecarGate {
        self.prune(now);
        let limit = self.policy.crash_limit.max(1);
        if self.crashes.len() == limit {
            self.crashes.pop_front();
        }
        self.crashes.push_back(now);
        if self.crashes.len() >= limit {
            self.unavailable = true;
            self.next_spawn_at = None;
            return SidecarGate::Unavailable;
        }
        let delay = self.policy.backoff_for(self.crashes.len());
        self.next_spawn_at = now.checked_add(delay);
        SidecarGate::Backoff { retry_after: delay }
    }

    /// Gate for a spawn attempt at `now`.
    #[must_use]
    pub fn gate(&self, now: Instant) -> SidecarGate {
        if self.unavailable {
            return SidecarGate::Unavailable;
        }
        match self.next_spawn_at {
            Some(at) if now < at => SidecarGate::Backoff {
                retry_after: at.duration_since(now),
            },
            _ => SidecarGate::Ready,
        }
    }

    /// Crashes currently counted inside the window ending at `now`.
    #[must_use]
    pub fn recent_crashes(&self, now: Instant) -> usize {
        self.crashes
            .iter()
            .filter(|at| now.saturating_duration_since(**at) < self.policy.crash_window)
            .count()
    }

    /// Whether the tracker latched unavailable.
    #[must_use]
    pub const fn is_unavailable(&self) -> bool {
        self.unavailable
    }

    /// Delay after the `n`-th crash inside the window under this policy.
    #[must_use]
    pub fn backoff_for(&self, n: usize) -> Duration {
        self.policy.backoff_for(n)
    }

    fn prune(&mut self, now: Instant) {
        while let Some(front) = self.crashes.front() {
            if now.saturating_duration_since(*front) >= self.policy.crash_window {
                self.crashes.pop_front();
            } else {
                break;
            }
        }
    }
}

impl Default for SidecarCrashTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Consecutive Core deadline expiries on one sidecar. Mirrors
/// `component/policy.rs` `DeadlineStrikes`: `expire` counts one expiry and
/// reports when the threshold is reached (the caller then takes the crash
/// path); reaching it resets the count. `reset` runs when any request on
/// the sidecar ends with a sidecar-produced terminal frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SidecarDeadlineStrikes {
    count: u32,
    threshold: u32,
}

impl SidecarDeadlineStrikes {
    /// Counter under the [`SidecarPolicy::core_defaults`] threshold.
    #[must_use]
    pub fn new() -> Self {
        Self::with_policy(SidecarPolicy::core_defaults())
    }

    /// Counter under an explicit policy's threshold.
    #[must_use]
    pub fn with_policy(policy: SidecarPolicy) -> Self {
        Self::with_threshold(policy.deadline_crash_threshold)
    }

    /// Counter with an explicit threshold; `0` behaves as `1`.
    #[must_use]
    pub fn with_threshold(threshold: u32) -> Self {
        Self {
            count: 0,
            threshold: threshold.max(1),
        }
    }

    /// Count one expiry; `true` when the threshold is reached (the counter
    /// resets).
    pub fn expire(&mut self) -> bool {
        self.count = self.count.saturating_add(1);
        if self.count >= self.threshold {
            self.count = 0;
            return true;
        }
        false
    }

    /// A sidecar-produced terminal frame ended a request.
    pub fn reset(&mut self) {
        self.count = 0;
    }

    /// Consecutive expiries counted so far.
    #[must_use]
    pub const fn count(&self) -> u32 {
        self.count
    }
}

impl Default for SidecarDeadlineStrikes {
    fn default() -> Self {
        Self::new()
    }
}

// ── stop outcome ──────────────────────────────────────────────────────────

/// How the last sidecar process ended. Mirrors `component/broker.rs`
/// `StopOutcome`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SidecarStopOutcome {
    /// Exited on its own after stdin close.
    Exited,
    /// Killed (recorded child only) after the grace expired.
    Killed,
    /// Counted as a crash.
    Crashed,
}

impl SidecarStopOutcome {
    /// Stable lowercase wire/display name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exited => "exited",
            Self::Killed => "killed",
            Self::Crashed => "crashed",
        }
    }
}

impl fmt::Display for SidecarStopOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── IPC protocol ownership ────────────────────────────────────────────────

/// Explicit ownership of the native-component wire protocol.
///
/// The wire bytes (`Hello`/`HelloAck` handshake, multiplexed requests,
/// framing) are owned by the `bitty-network` repository and travel with
/// Core's `component/` today; this repository owns only the supervision
/// mechanics above them. The associated constants name the owner and the
/// current carrier so the seam never drifts into protocol work; the numeric
/// wire facts (`PROTOCOL_VERSION = 1`, `MAX_IN_FLIGHT = 64`,
/// `DEFAULT_MAX_BODY_BYTES` of 8 MiB, `MAX_COMPONENT_NAME_BYTES` of 32) are
/// recorded in the module docs as audit-time facts owned elsewhere and are
/// deliberately not re-declared here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SidecarIpcProtocol;

impl SidecarIpcProtocol {
    /// Repository owning the wire protocol definition.
    pub const OWNER: &'static str = "bitty-network";

    /// Crate defining the wire protocol.
    pub const WIRE_CRATE: &'static str = "bitty-network-wire";

    /// Code carrying the protocol today (resolution, digest check,
    /// handshake, multiplexing).
    pub const CARRIER: &'static str = "Core component broker (crates/bitty-runtime/src/component/)";
}

// ── supervisor seam ───────────────────────────────────────────────────────

/// Sidecar-supervision seam a host implements, one instance per supervised
/// sidecar.
///
/// A broker multiplexing several sidecars holds one instance per sidecar,
/// mirroring Core's per-component slot. Pure checks take effect
/// immediately; every refusal leaves no partial state. Stops go through the
/// typed cancel vocabulary: legacy ambient cancel for host-owned paths and
/// generation-fenced typed cancel for handle holders, exactly like
/// [`JobRegistry::cancel`](crate::JobRegistry::cancel) and
/// [`cancel_typed`](crate::JobRegistry::cancel_typed).
pub trait SidecarSupervisor {
    /// Bounded numbers this supervisor enforces.
    fn policy(&self) -> SidecarPolicy;

    /// Whether the sidecar may spawn now (pure; mirrors
    /// `CrashTracker::gate`).
    fn spawn_gate(&self, now: Instant) -> SidecarGate;

    /// Record a crash at `now` and return the resulting gate (mirrors
    /// `CrashTracker::record_crash`).
    fn record_crash(&mut self, now: Instant) -> SidecarGate;

    /// Count one Core deadline expiry; `true` when the threshold is reached
    /// and the caller takes the crash path (mirrors
    /// `DeadlineStrikes::expire`).
    fn record_deadline_expiry(&mut self) -> bool;

    /// A sidecar-produced terminal frame ended a request: the consecutive
    /// expiry count resets (mirrors `DeadlineStrikes::reset`).
    fn note_terminal_frame(&mut self);

    /// Core deadline for a requested timeout: the request, or the default
    /// when none was requested, clamped to the maximum (mirrors
    /// `component/broker.rs` `effective_timeout`).
    fn effective_deadline(&self, requested_timeout_ms: u32) -> Duration {
        self.policy().effective_deadline(requested_timeout_ms)
    }

    /// Grace between closing stdin and killing the recorded child (mirrors
    /// `COMPONENT_SHUTDOWN_GRACE`).
    fn shutdown_grace(&self) -> Duration {
        self.policy().shutdown_grace
    }

    /// Requests immediate sidecar termination (legacy ambient host path).
    /// Records an immediate request for the current generation and returns
    /// as soon as it is recorded, never after the process is gone; callers
    /// holding a handle use
    /// [`cancel_sidecar_typed`](SidecarSupervisor::cancel_sidecar_typed)
    /// instead. Mirrors [`JobRegistry::cancel`](crate::JobRegistry::cancel).
    ///
    /// # Errors
    ///
    /// Returns [`JobError::UnknownJob`] when `id` is not tracked.
    fn cancel_sidecar(&self, id: JobId) -> Result<JobCancel, JobError>;

    /// Submits a typed cancel request. The host checks the handle's
    /// generation itself: a stale generation is answered with
    /// `StaleGeneration` and nothing changes; a terminal sidecar answers
    /// `AlreadyExited`. Otherwise the request is accepted and the
    /// supervisor publishes exactly one `CancelResolved` event with the
    /// typed result. Mirrors
    /// [`JobRegistry::cancel_typed`](crate::JobRegistry::cancel_typed).
    ///
    /// # Errors
    ///
    /// Returns [`JobError::UnknownJob`] when the handle's id is not tracked.
    fn cancel_sidecar_typed(&self, request: CancelRequest) -> Result<CancelReceipt, JobError>;

    /// What a kill reaches for this sidecar:
    /// [`KillScope::OwnedTree`](crate::KillScope) once an owned-tree backend
    /// adopted the process, else
    /// [`KillScope::DirectChild`](crate::KillScope) with the gap surfaced.
    /// Typically [`KillScope::for_backend`](crate::KillScope::for_backend)
    /// over the detected backend.
    fn kill_scope(&self) -> KillScope;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_defaults_are_cores_dir030_numbers() {
        let policy = SidecarPolicy::core_defaults();
        assert_eq!(policy.backoff_initial, Duration::from_secs(1));
        assert_eq!(policy.backoff_max, Duration::from_secs(30));
        assert_eq!(policy.crash_limit, 5);
        assert_eq!(policy.crash_window, Duration::from_secs(5 * 60));
        assert_eq!(policy.deadline_crash_threshold, 3);
        assert_eq!(policy.request_default_timeout, Duration::from_secs(30));
        assert_eq!(policy.request_max_timeout, Duration::from_secs(300));
        assert_eq!(policy.deadline_grace, Duration::from_secs(5));
        assert_eq!(policy.shutdown_grace, Duration::from_secs(2));
        assert_eq!(policy.handshake_timeout, Duration::from_secs(5));
        assert_eq!(policy.idle_timeout, Duration::from_secs(60));
        assert_eq!(policy.max_in_flight, 64);
    }

    #[test]
    fn effective_deadline_defaults_and_clamps_like_the_broker() {
        let policy = SidecarPolicy::core_defaults();
        assert_eq!(
            policy.effective_deadline(0),
            Duration::from_secs(30),
            "no requested timeout selects the default"
        );
        assert_eq!(
            policy.effective_deadline(1),
            Duration::from_millis(1),
            "an explicit timeout passes through"
        );
        assert_eq!(
            policy.effective_deadline(30_000),
            Duration::from_secs(30),
            "the default value is a fixed point"
        );
        assert_eq!(
            policy.effective_deadline(300_000),
            Duration::from_secs(300),
            "the ceiling value is a fixed point"
        );
        assert_eq!(
            policy.effective_deadline(999_000_000),
            Duration::from_secs(300),
            "larger requests clamp to the ceiling"
        );
        assert_eq!(
            policy.effective_deadline(u32::MAX),
            Duration::from_secs(300),
            "the clamp is total"
        );
    }

    #[test]
    fn backoff_doubles_from_one_second_to_thirty() {
        let policy = SidecarPolicy::core_defaults();
        let delays: Vec<u64> = (1..=8).map(|n| policy.backoff_for(n).as_secs()).collect();
        assert_eq!(delays, [1, 2, 4, 8, 16, 30, 30, 30]);
        assert_eq!(policy.backoff_for(usize::MAX), Duration::from_secs(30));
    }

    #[test]
    fn crash_starts_backoff_and_gate_reopens() {
        let t0 = Instant::now();
        let mut tracker = SidecarCrashTracker::new();
        assert_eq!(tracker.gate(t0), SidecarGate::Ready);
        assert_eq!(
            tracker.record_crash(t0),
            SidecarGate::Backoff {
                retry_after: Duration::from_secs(1)
            }
        );
        assert!(matches!(tracker.gate(t0), SidecarGate::Backoff { .. }));
        assert_eq!(
            tracker.gate(t0 + Duration::from_secs(1)),
            SidecarGate::Ready
        );
        let t1 = t0 + Duration::from_secs(2);
        assert_eq!(
            tracker.record_crash(t1),
            SidecarGate::Backoff {
                retry_after: Duration::from_secs(2)
            }
        );
        assert_eq!(tracker.recent_crashes(t1), 2);
        assert!(!tracker.is_unavailable());
    }

    #[test]
    fn five_crashes_in_five_minutes_latch_unavailable() {
        let t0 = Instant::now();
        let mut tracker = SidecarCrashTracker::new();
        for i in 0..4u64 {
            let gate = tracker.record_crash(t0 + Duration::from_secs(i * 60));
            assert!(matches!(gate, SidecarGate::Backoff { .. }), "crash {i}");
        }
        assert_eq!(
            tracker.record_crash(t0 + Duration::from_secs(4 * 60 + 59)),
            SidecarGate::Unavailable
        );
        assert!(tracker.is_unavailable());
        assert_eq!(
            tracker.gate(t0 + Duration::from_secs(3600)),
            SidecarGate::Unavailable,
            "latching survives the window: only a fresh tracker recovers"
        );
    }

    #[test]
    fn crashes_outside_the_window_do_not_count() {
        let t0 = Instant::now();
        let mut tracker = SidecarCrashTracker::new();
        for i in 0..10u64 {
            // One crash every 80 s: never 5 inside any 300 s window.
            let gate = tracker.record_crash(t0 + Duration::from_secs(i * 80));
            assert!(matches!(gate, SidecarGate::Backoff { .. }), "crash {i}");
        }
        assert!(!tracker.is_unavailable());
        assert!(tracker.recent_crashes(t0 + Duration::from_secs(9 * 80)) <= 4);
    }

    #[test]
    fn deadline_strikes_trip_at_threshold_and_reset() {
        let mut strikes = SidecarDeadlineStrikes::new();
        assert_eq!(SidecarPolicy::core_defaults().deadline_crash_threshold, 3);
        assert!(!strikes.expire());
        assert!(!strikes.expire());
        strikes.reset();
        assert_eq!(strikes.count(), 0);
        assert!(!strikes.expire());
        assert!(!strikes.expire());
        assert!(strikes.expire(), "third consecutive expiry trips");
        assert_eq!(strikes.count(), 0, "tripping resets the counter");
        assert!(SidecarDeadlineStrikes::with_threshold(0).expire());
        assert_eq!(
            SidecarDeadlineStrikes::with_policy(SidecarPolicy::core_defaults()).count(),
            0
        );
    }

    #[test]
    fn names_are_stable() {
        assert_eq!(SidecarGate::Ready.as_str(), "ready");
        assert_eq!(
            SidecarGate::Backoff {
                retry_after: Duration::from_secs(1)
            }
            .as_str(),
            "backoff"
        );
        assert_eq!(SidecarGate::Unavailable.as_str(), "unavailable");
        assert_eq!(SidecarGate::Ready.to_string(), "ready");
        assert_eq!(SidecarGate::Unavailable.to_string(), "unavailable");
        assert!(
            SidecarGate::Backoff {
                retry_after: Duration::from_secs(1)
            }
            .to_string()
            .contains("1000")
        );
        assert_eq!(SidecarStopOutcome::Exited.as_str(), "exited");
        assert_eq!(SidecarStopOutcome::Killed.as_str(), "killed");
        assert_eq!(SidecarStopOutcome::Crashed.as_str(), "crashed");
        assert_eq!(SidecarStopOutcome::Crashed.to_string(), "crashed");
    }

    #[test]
    fn ipc_protocol_ownership_is_explicit() {
        assert_eq!(SidecarIpcProtocol::OWNER, "bitty-network");
        assert_eq!(SidecarIpcProtocol::WIRE_CRATE, "bitty-network-wire");
        assert!(
            SidecarIpcProtocol::CARRIER.contains("component"),
            "the carrier names the Core component broker"
        );
    }

    #[test]
    fn tracker_reports_its_policy() {
        let tracker = SidecarCrashTracker::new();
        assert_eq!(tracker.policy(), SidecarPolicy::core_defaults());
        assert_eq!(tracker.backoff_for(1), Duration::from_secs(1));
    }
}
