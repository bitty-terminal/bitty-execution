//! OOM determination without cross-platform pretense (RUN-17, #1048).
//!
//! `OomKilled` may be asserted only when it is actually determinable:
//! per-job cgroup `memory.events` on Linux, never a heuristic. Everywhere
//! else — no cgroup, unreadable counter, Windows/macOS — the verdict is
//! [`OomVerdict::Unknown`], never a guessed `NotOom`. This module owns the
//! pure determination half; the structured outcome set stays CTX-0512.
//!
//! The host supplies the counter text; no cgroup path is hardcoded here (the
//! per-job cgroup module `cgroup` reads the leaf's `memory.events` and
//! passes the content in, so this module needs no filesystem access and no
//! syscalls). Every job records [`OomEvidence`] on its snapshot, and a job
//! without evidence names the [`OomEvidenceGap`] (CTX-0880, #1537).

/// Largest `memory.events` text accepted (16 KiB).
///
/// The real file is under a hundred bytes; anything larger is not a
/// `memory.events` payload and fails closed to [`OomVerdict::Unknown`].
pub const MAX_MEMORY_EVENTS_BYTES: usize = 16 * 1024;

/// OOM verdict for one finished job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OomVerdict {
    /// The job's cgroup OOM-kill counter advanced while it ran: the kernel
    /// OOM-killed (a member of) the job.
    OomKilled,
    /// Both counter readings were available and the counter did not advance.
    NotOom,
    /// OOM status is not determinable (no cgroup, missing/unreadable
    /// counter, non-Linux platform). Never a guess in either direction.
    Unknown,
}

impl OomVerdict {
    /// Stable lowercase wire/display name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OomKilled => "oom_killed",
            Self::NotOom => "not_oom",
            Self::Unknown => "unknown",
        }
    }
}

/// Why a job carries no OOM evidence (CTX-0880, #1537).
///
/// Every job either has a cgroup counter reading at both ends or names the
/// reason it does not; a missing cgroup never fails the spawn and never
/// hides behind a silent [`OomVerdict::Unknown`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OomEvidenceGap {
    /// The registry was built without a delegated cgroup base.
    NotConfigured,
    /// Discovery found no usable delegated cgroup v2 subtree (no unified
    /// hierarchy, no `memory` delegation, or not writable).
    Undelegated,
    /// The platform has no per-job cgroup mechanism (macOS, Windows, BSD).
    UnsupportedPlatform,
    /// The bounded count of per-job leaves (live plus not yet removed) was
    /// reached, so this job runs without a leaf.
    LeafLimit,
    /// The per-job leaf directory could not be created.
    LeafCreateFailed,
    /// The job's leader could not be moved into its leaf (for example it
    /// already exited).
    PlacementFailed,
    /// A `memory.events` reading was missing, over-bound, or malformed.
    CounterUnreadable,
    /// The job never started a process (cancelled before start or spawn
    /// failure), so there is nothing to account.
    NotStarted,
}

impl OomEvidenceGap {
    /// Stable lowercase wire/display name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotConfigured => "not_configured",
            Self::Undelegated => "undelegated",
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::LeafLimit => "leaf_limit",
            Self::LeafCreateFailed => "leaf_create_failed",
            Self::PlacementFailed => "placement_failed",
            Self::CounterUnreadable => "counter_unreadable",
            Self::NotStarted => "not_started",
        }
    }
}

impl std::fmt::Display for OomEvidenceGap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// OOM evidence recorded on a job (reported on every snapshot).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OomEvidence {
    /// The job has not reached the point where evidence is decided.
    Pending,
    /// The job runs inside its own cgroup leaf; the verdict is read at exit.
    Tracked,
    /// The leaf's `oom_kill` counter advanced while the job ran.
    OomKilled,
    /// Both counter readings exist and the counter did not advance.
    NotOom,
    /// No evidence exists for this job, for the named reason.
    Missing(OomEvidenceGap),
}

impl OomEvidence {
    /// Maps two-endpoint counter readings onto recorded evidence: a missing
    /// endpoint is [`OomEvidenceGap::CounterUnreadable`], never a guess.
    #[must_use]
    pub const fn from_counts(before: Option<u64>, after: Option<u64>) -> Self {
        match classify_oom(before, after) {
            OomVerdict::OomKilled => Self::OomKilled,
            OomVerdict::NotOom => Self::NotOom,
            OomVerdict::Unknown => Self::Missing(OomEvidenceGap::CounterUnreadable),
        }
    }

    /// The verdict the outcome classifier consumes: only a completed
    /// reading yields [`OomVerdict::OomKilled`] or [`OomVerdict::NotOom`].
    #[must_use]
    pub const fn verdict(self) -> OomVerdict {
        match self {
            Self::OomKilled => OomVerdict::OomKilled,
            Self::NotOom => OomVerdict::NotOom,
            Self::Pending | Self::Tracked | Self::Missing(_) => OomVerdict::Unknown,
        }
    }

    /// Stable lowercase wire/display name (the gap is named separately).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Tracked => "tracked",
            Self::OomKilled => "oom_killed",
            Self::NotOom => "not_oom",
            Self::Missing(_) => "missing",
        }
    }
}

impl std::fmt::Display for OomEvidence {
    /// The stable name; a missing reading also names its gap
    /// (`missing:<gap>`).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing(gap) => write!(f, "{}:{gap}", self.as_str()),
            other => f.write_str(other.as_str()),
        }
    }
}

/// Parses the `oom_kill` counter from cgroup v2 `memory.events` text.
///
/// Returns the counter value, or `None` when the payload is over
/// [`MAX_MEMORY_EVENTS_BYTES`], the line is absent, or the value does not
/// parse. A missing counter is indeterminate, never zero: callers must map
/// `None` to [`OomVerdict::Unknown`], not invent a reading.
#[must_use]
pub fn parse_oom_kill_count(memory_events: &str) -> Option<u64> {
    if memory_events.len() > MAX_MEMORY_EVENTS_BYTES {
        return None;
    }
    for line in memory_events.lines() {
        let mut fields = line.split_ascii_whitespace();
        if fields.next() == Some("oom_kill") {
            return fields.next()?.parse::<u64>().ok();
        }
    }
    None
}

/// Classifies one job from two counter readings.
///
/// - `(Some(before), Some(after))` with `after > before` is
///   [`OomVerdict::OomKilled`]; `after <= before` is [`OomVerdict::NotOom`].
/// - Any missing reading is [`OomVerdict::Unknown`]: OOM is never claimed
///   without both endpoints, and non-OOM is never claimed without evidence.
#[must_use]
pub const fn classify_oom(before: Option<u64>, after: Option<u64>) -> OomVerdict {
    match (before, after) {
        (Some(before), Some(after)) if after > before => OomVerdict::OomKilled,
        (Some(_), Some(_)) => OomVerdict::NotOom,
        _ => OomVerdict::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_EVENTS: &str = "low 0\nhigh 0\nmax 12\n oom 3\noom_kill 2\n";

    #[test]
    fn parses_the_oom_kill_counter() {
        assert_eq!(parse_oom_kill_count(SAMPLE_EVENTS), Some(2));
        assert_eq!(parse_oom_kill_count("oom_kill 0\n"), Some(0));
        // Extra spacing between key and value is tolerated.
        assert_eq!(parse_oom_kill_count("oom_kill    7\n"), Some(7));
    }

    #[test]
    fn missing_or_bad_counters_are_indeterminate() {
        assert_eq!(parse_oom_kill_count("low 0\nhigh 0\n"), None);
        assert_eq!(parse_oom_kill_count(""), None);
        assert_eq!(parse_oom_kill_count("oom_kill lots\n"), None);
        assert_eq!(parse_oom_kill_count("oom_kill\n"), None);
        // A similarly-named key must not match.
        assert_eq!(parse_oom_kill_count("oom_killer 4\n"), None);
        // Over-bound payloads fail closed.
        let big = "a".repeat(MAX_MEMORY_EVENTS_BYTES + 1);
        assert_eq!(parse_oom_kill_count(&big), None);
    }

    #[test]
    fn classification_needs_both_endpoints() {
        assert_eq!(classify_oom(Some(2), Some(3)), OomVerdict::OomKilled);
        assert_eq!(classify_oom(Some(2), Some(2)), OomVerdict::NotOom);
        // Counter resets (after < before) are not OOM evidence either.
        assert_eq!(classify_oom(Some(5), Some(1)), OomVerdict::NotOom);
        assert_eq!(classify_oom(None, Some(3)), OomVerdict::Unknown);
        assert_eq!(classify_oom(Some(2), None), OomVerdict::Unknown);
        assert_eq!(classify_oom(None, None), OomVerdict::Unknown);
    }

    #[test]
    fn evidence_maps_counts_and_never_guesses() {
        assert_eq!(
            OomEvidence::from_counts(Some(0), Some(1)),
            OomEvidence::OomKilled
        );
        assert_eq!(
            OomEvidence::from_counts(Some(1), Some(1)),
            OomEvidence::NotOom
        );
        assert_eq!(
            OomEvidence::from_counts(Some(1), None),
            OomEvidence::Missing(OomEvidenceGap::CounterUnreadable)
        );
        assert_eq!(OomEvidence::OomKilled.verdict(), OomVerdict::OomKilled);
        assert_eq!(OomEvidence::NotOom.verdict(), OomVerdict::NotOom);
        assert_eq!(OomEvidence::Pending.verdict(), OomVerdict::Unknown);
        assert_eq!(OomEvidence::Tracked.verdict(), OomVerdict::Unknown);
        assert_eq!(
            OomEvidence::Missing(OomEvidenceGap::NotConfigured).verdict(),
            OomVerdict::Unknown
        );
        assert_eq!(OomEvidenceGap::LeafLimit.as_str(), "leaf_limit");
        assert_eq!(OomEvidence::Tracked.as_str(), "tracked");
        assert_eq!(OomEvidenceGap::Undelegated.to_string(), "undelegated");
        assert_eq!(OomEvidence::OomKilled.to_string(), "oom_killed");
        assert_eq!(
            OomEvidence::Missing(OomEvidenceGap::PlacementFailed).to_string(),
            "missing:placement_failed"
        );
    }

    #[test]
    fn verdict_names_are_stable() {
        assert_eq!(OomVerdict::OomKilled.as_str(), "oom_killed");
        assert_eq!(OomVerdict::NotOom.as_str(), "not_oom");
        assert_eq!(OomVerdict::Unknown.as_str(), "unknown");
    }
}
