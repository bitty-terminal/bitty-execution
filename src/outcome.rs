//! Structured execution outcomes, the typed cancel protocol, and execution
//! generations (CTX-0512; execution-host boundary §18, §23).
//!
//! - [`ExecutionOutcome`] is the authoritative way a job ended, never a bare
//!   exit code: a timeout stays [`ExecutionOutcome::TimedOut`] and never
//!   collapses into a failure, and [`ExecutionOutcome::OomKilled`] is only
//!   asserted from per-job evidence ([`OomVerdict::OomKilled`]).
//! - [`CancelRequest`] names the execution id, the execution generation, a
//!   [`CancelMode`], and a grace period. The host executes it — `SIGINT`,
//!   wait, `SIGTERM`, wait, `SIGKILL` of the owned tree, descendant reap —
//!   and answers with a typed [`CancelOutcome`]; a caller never infers "I
//!   sent Ctrl+C, therefore it stopped".
//! - [`ExecutionGeneration`] is the host's handle generation, minted per
//!   spawn and checked by the host itself; it is distinct from any
//!   `bitty-ai` assignment generation, which this crate never sees.

use std::fmt;
use std::num::NonZeroU64;
use std::time::Duration;

use crate::model::{JobError, JobId};
use crate::oom::OomVerdict;

/// Largest grace period a cancel request may carry (60 s). Graceful modes
/// wait at most this long per step, so a `GracefulThenKill` cancel ends
/// within two grace periods plus the kill.
pub const MAX_CANCEL_GRACE_MS: u64 = 60_000;

/// Grace period of [`CancelRequest::graceful_then_kill`] (5 s).
pub const DEFAULT_CANCEL_GRACE_MS: u64 = 5_000;

/// POSIX `SIGKILL`: the only signal the kernel OOM killer delivers.
const SIGKILL_NUMBER: i32 = 9;

/// Which deadline clock ended a job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeadlineClock {
    /// The hard wall-clock deadline elapsed.
    Hard,
    /// No output arrived for the idle deadline.
    Idle,
}

impl DeadlineClock {
    /// Stable lowercase wire/display name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hard => "hard",
            Self::Idle => "idle",
        }
    }
}

/// How an executed cancel ended a job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CancelEffect {
    /// The request landed before the process existed; nothing ran.
    BeforeStart,
    /// The job exited after a graceful stop request (`SIGINT`/`SIGTERM`).
    Graceful,
    /// The host killed the owned tree.
    Killed,
}

impl CancelEffect {
    /// Stable lowercase wire/display name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BeforeStart => "before_start",
            Self::Graceful => "graceful",
            Self::Killed => "killed",
        }
    }
}

/// What the host observed when a job's process ended on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExitObservation {
    /// The process exited with this status code.
    Code(i32),
    /// The process was terminated by this signal number (Unix).
    Signal(i32),
    /// The process is gone but its status could not be observed.
    Unobservable,
}

/// Authoritative structured outcome of one finished execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExecutionOutcome {
    /// The process exited on its own with status 0.
    Success,
    /// The process exited on its own with this non-zero status.
    ExitCode(i32),
    /// A signal the host did not send terminated the process (Unix).
    Signaled(i32),
    /// No process was created, or a partially started one could not be
    /// supervised and was killed and reaped.
    SpawnFailed,
    /// An executed cancel request ended the job.
    Cancelled(CancelEffect),
    /// A deadline ended the job; the host killed the owned tree.
    TimedOut(DeadlineClock),
    /// The kernel OOM-killed the job, determined from per-job evidence.
    OomKilled,
    /// The supervisor that owned the job went away while it ran (restart
    /// reconciliation); how the process ended is not known.
    SupervisorLost,
    /// The host could not observe how the job ended.
    Unknown,
}

impl ExecutionOutcome {
    /// Classifies a natural end (no host cancel, no deadline).
    ///
    /// `OomKilled` needs both a `SIGKILL` death and [`OomVerdict::OomKilled`]
    /// evidence for this job; a `SIGKILL` without that evidence stays
    /// [`ExecutionOutcome::Signaled`], and an unreadable status stays
    /// [`ExecutionOutcome::Unknown`]. Nothing is guessed in either
    /// direction.
    #[must_use]
    pub const fn classify_exit(exit: ExitObservation, oom: OomVerdict) -> Self {
        match exit {
            ExitObservation::Code(0) => Self::Success,
            ExitObservation::Code(code) => Self::ExitCode(code),
            ExitObservation::Signal(SIGKILL_NUMBER) if matches!(oom, OomVerdict::OomKilled) => {
                Self::OomKilled
            }
            ExitObservation::Signal(signal) => Self::Signaled(signal),
            ExitObservation::Unobservable => Self::Unknown,
        }
    }

    /// Whether the job succeeded.
    #[must_use]
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Success)
    }

    /// Stable lowercase class name (payload-free).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::ExitCode(_) => "exit_code",
            Self::Signaled(_) => "signaled",
            Self::SpawnFailed => "spawn_failed",
            Self::Cancelled(_) => "cancelled",
            Self::TimedOut(_) => "timed_out",
            Self::OomKilled => "oom_killed",
            Self::SupervisorLost => "supervisor_lost",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for ExecutionOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExitCode(code) => write!(f, "exit_code({code})"),
            Self::Signaled(signal) => write!(f, "signaled({signal})"),
            Self::Cancelled(effect) => write!(f, "cancelled({})", effect.as_str()),
            Self::TimedOut(clock) => write!(f, "timed_out({})", clock.as_str()),
            other => f.write_str(other.as_str()),
        }
    }
}

/// Execution generation: the host's handle generation, minted per spawn.
///
/// A handle carrying another generation is stale and the host rejects it
/// ([`CancelOutcome::StaleGeneration`]). This is never a `bitty-ai`
/// assignment generation (task/agent ownership).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExecutionGeneration(NonZeroU64);

impl ExecutionGeneration {
    /// Wraps a raw generation; `None` for 0.
    #[must_use]
    pub const fn from_raw(raw: u64) -> Option<Self> {
        match NonZeroU64::new(raw) {
            Some(raw) => Some(Self(raw)),
            None => None,
        }
    }

    /// Raw generation value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// Wraps a non-zero raw generation.
    pub(crate) const fn from_nonzero(raw: NonZeroU64) -> Self {
        Self(raw)
    }
}

impl fmt::Display for ExecutionGeneration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016x}", self.0.get())
    }
}

/// Host handle for one execution: id plus generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExecutionHandle {
    /// Execution (job) id.
    pub id: JobId,
    /// Generation the handle was minted with.
    pub generation: ExecutionGeneration,
}

/// How the host stops a job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CancelMode {
    /// `SIGINT` to the owned tree, then wait up to the grace period; never
    /// escalates. A job still running afterwards keeps running.
    Graceful,
    /// Kill the owned tree now.
    Immediate,
    /// `SIGINT`, wait, `SIGTERM`, wait, then kill the owned tree.
    GracefulThenKill,
}

impl CancelMode {
    /// Stable lowercase wire/display name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Graceful => "graceful",
            Self::Immediate => "immediate",
            Self::GracefulThenKill => "graceful_then_kill",
        }
    }

    /// Escalation rank: a later request with a higher rank upgrades a cancel
    /// already executing; equal or lower ranks coalesce into it.
    pub(crate) const fn rank(self) -> u8 {
        match self {
            Self::Graceful => 0,
            Self::GracefulThenKill => 1,
            Self::Immediate => 2,
        }
    }
}

/// A typed cancel request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CancelRequest {
    handle: ExecutionHandle,
    mode: CancelMode,
    grace: Duration,
}

impl CancelRequest {
    /// Builds a request.
    ///
    /// # Errors
    ///
    /// Returns [`JobError::InvalidCancel`] when `grace` exceeds
    /// [`MAX_CANCEL_GRACE_MS`]. A zero grace is allowed: graceful steps then
    /// only check whether the job already stopped.
    pub fn new(
        handle: ExecutionHandle,
        mode: CancelMode,
        grace: Duration,
    ) -> Result<Self, JobError> {
        if grace > Duration::from_millis(MAX_CANCEL_GRACE_MS) {
            return Err(JobError::InvalidCancel {
                reason: format!("cancel grace exceeds {MAX_CANCEL_GRACE_MS} ms"),
            });
        }
        Ok(Self {
            handle,
            mode,
            grace,
        })
    }

    /// An [`CancelMode::Immediate`] request (no grace).
    #[must_use]
    pub const fn immediate(handle: ExecutionHandle) -> Self {
        Self {
            handle,
            mode: CancelMode::Immediate,
            grace: Duration::ZERO,
        }
    }

    /// A [`CancelMode::GracefulThenKill`] request with
    /// [`DEFAULT_CANCEL_GRACE_MS`].
    #[must_use]
    pub const fn graceful_then_kill(handle: ExecutionHandle) -> Self {
        Self {
            handle,
            mode: CancelMode::GracefulThenKill,
            grace: Duration::from_millis(DEFAULT_CANCEL_GRACE_MS),
        }
    }

    /// Handle the request targets.
    #[must_use]
    pub const fn handle(&self) -> ExecutionHandle {
        self.handle
    }

    /// Requested mode.
    #[must_use]
    pub const fn mode(&self) -> CancelMode {
        self.mode
    }

    /// Grace period per graceful step.
    #[must_use]
    pub const fn grace(&self) -> Duration {
        self.grace
    }
}

/// Typed result of one cancel request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CancelOutcome {
    /// The request landed before the process existed; nothing ran.
    CancelledBeforeStart,
    /// The job exited within a grace period after a graceful stop request.
    CancelledGracefully,
    /// The host killed the owned tree and reaped the job.
    Killed,
    /// The job had already reached a terminal outcome; nothing changed.
    AlreadyExited,
    /// The kernel refused the stop signal; the job keeps running.
    PermissionDenied,
    /// The handle's generation is not the job's; nothing changed.
    StaleGeneration,
    /// A graceful-only request was delivered, but the job still runs after
    /// the grace period (no escalation was asked for).
    StillRunning,
    /// No graceful stop exists for this job on this platform (no owned-tree
    /// backend); nothing was sent. Use an escalating mode to stop it.
    Unsupported,
    /// The host could not determine what the request did.
    Unknown,
}

impl CancelOutcome {
    /// Stable lowercase wire/display name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CancelledBeforeStart => "cancelled_before_start",
            Self::CancelledGracefully => "cancelled_gracefully",
            Self::Killed => "killed",
            Self::AlreadyExited => "already_exited",
            Self::PermissionDenied => "permission_denied",
            Self::StaleGeneration => "stale_generation",
            Self::StillRunning => "still_running",
            Self::Unsupported => "unsupported",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for CancelOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Immediate answer to a cancel request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CancelReceipt {
    /// Accepted: the host executes it and publishes exactly one
    /// `JobEvent::CancelResolved` with the typed outcome. Requests arriving
    /// while a cancel executes coalesce into it (a stronger mode escalates
    /// it), and each accepted request is answered by that one event.
    Accepted,
    /// Answered on the spot without touching the job
    /// ([`CancelOutcome::AlreadyExited`] or
    /// [`CancelOutcome::StaleGeneration`]).
    Resolved(CancelOutcome),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handle() -> ExecutionHandle {
        ExecutionHandle {
            id: JobId::from_raw(1).expect("id"),
            generation: ExecutionGeneration::from_raw(7).expect("generation"),
        }
    }

    #[test]
    fn natural_exits_classify_without_guessing() {
        let unknown = OomVerdict::Unknown;
        assert_eq!(
            ExecutionOutcome::classify_exit(ExitObservation::Code(0), unknown),
            ExecutionOutcome::Success
        );
        assert_eq!(
            ExecutionOutcome::classify_exit(ExitObservation::Code(3), unknown),
            ExecutionOutcome::ExitCode(3)
        );
        assert_eq!(
            ExecutionOutcome::classify_exit(ExitObservation::Signal(15), unknown),
            ExecutionOutcome::Signaled(15)
        );
        assert_eq!(
            ExecutionOutcome::classify_exit(ExitObservation::Unobservable, unknown),
            ExecutionOutcome::Unknown
        );
    }

    #[test]
    fn oom_killed_needs_sigkill_and_per_job_evidence() {
        let sigkill = ExitObservation::Signal(SIGKILL_NUMBER);
        assert_eq!(
            ExecutionOutcome::classify_exit(sigkill, OomVerdict::OomKilled),
            ExecutionOutcome::OomKilled
        );
        // A SIGKILL without evidence is never claimed as OOM.
        for verdict in [OomVerdict::Unknown, OomVerdict::NotOom] {
            assert_eq!(
                ExecutionOutcome::classify_exit(sigkill, verdict),
                ExecutionOutcome::Signaled(SIGKILL_NUMBER)
            );
        }
        // Evidence without a SIGKILL death (a member died, the leader exited)
        // stays the leader's own outcome.
        assert_eq!(
            ExecutionOutcome::classify_exit(ExitObservation::Code(1), OomVerdict::OomKilled),
            ExecutionOutcome::ExitCode(1)
        );
        assert_eq!(
            ExecutionOutcome::classify_exit(ExitObservation::Signal(15), OomVerdict::OomKilled),
            ExecutionOutcome::Signaled(15)
        );
    }

    #[test]
    fn a_timeout_is_never_a_plain_failure() {
        for clock in [DeadlineClock::Hard, DeadlineClock::Idle] {
            let outcome = ExecutionOutcome::TimedOut(clock);
            assert!(!outcome.is_success());
            assert_eq!(outcome.as_str(), "timed_out");
            assert_ne!(outcome, ExecutionOutcome::ExitCode(1));
        }
    }

    #[test]
    fn grace_is_bounded() {
        assert!(
            CancelRequest::new(
                handle(),
                CancelMode::Graceful,
                Duration::from_millis(MAX_CANCEL_GRACE_MS)
            )
            .is_ok()
        );
        assert!(matches!(
            CancelRequest::new(
                handle(),
                CancelMode::Graceful,
                Duration::from_millis(MAX_CANCEL_GRACE_MS + 1)
            ),
            Err(JobError::InvalidCancel { .. })
        ));
        assert!(CancelRequest::new(handle(), CancelMode::GracefulThenKill, Duration::ZERO).is_ok());
        let immediate = CancelRequest::immediate(handle());
        assert_eq!(immediate.mode(), CancelMode::Immediate);
        assert_eq!(immediate.grace(), Duration::ZERO);
        assert_eq!(
            CancelRequest::graceful_then_kill(handle()).grace(),
            Duration::from_millis(DEFAULT_CANCEL_GRACE_MS)
        );
    }

    #[test]
    fn escalation_ranks_order_the_modes() {
        assert!(CancelMode::Graceful.rank() < CancelMode::GracefulThenKill.rank());
        assert!(CancelMode::GracefulThenKill.rank() < CancelMode::Immediate.rank());
    }

    #[test]
    fn generation_zero_is_not_a_generation() {
        assert!(ExecutionGeneration::from_raw(0).is_none());
        assert_eq!(
            ExecutionGeneration::from_raw(9).map(ExecutionGeneration::get),
            Some(9)
        );
    }

    #[test]
    fn names_are_stable() {
        let outcomes = [
            (ExecutionOutcome::Success, "success"),
            (ExecutionOutcome::ExitCode(2), "exit_code"),
            (ExecutionOutcome::Signaled(9), "signaled"),
            (ExecutionOutcome::SpawnFailed, "spawn_failed"),
            (
                ExecutionOutcome::Cancelled(CancelEffect::Killed),
                "cancelled",
            ),
            (ExecutionOutcome::TimedOut(DeadlineClock::Idle), "timed_out"),
            (ExecutionOutcome::OomKilled, "oom_killed"),
            (ExecutionOutcome::SupervisorLost, "supervisor_lost"),
            (ExecutionOutcome::Unknown, "unknown"),
        ];
        for (outcome, name) in outcomes {
            assert_eq!(outcome.as_str(), name);
        }
        assert_eq!(ExecutionOutcome::ExitCode(2).to_string(), "exit_code(2)");
        assert_eq!(
            ExecutionOutcome::Cancelled(CancelEffect::Graceful).to_string(),
            "cancelled(graceful)"
        );
        assert_eq!(
            ExecutionOutcome::TimedOut(DeadlineClock::Hard).to_string(),
            "timed_out(hard)"
        );
        assert_eq!(CancelMode::GracefulThenKill.as_str(), "graceful_then_kill");
        assert_eq!(CancelOutcome::StaleGeneration.as_str(), "stale_generation");
        assert_eq!(CancelEffect::BeforeStart.as_str(), "before_start");
    }
}
