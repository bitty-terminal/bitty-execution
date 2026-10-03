//! Output/artifact retention defaults (RUN-18, #1049).
//!
//! The finished-record TTL (`crate::model::DEFAULT_RETENTION_TTL`, 60 s) already decides
//! when a record becomes evictable, but three retention surfaces had no
//! declared default: the in-memory ring/output bytes, persisted logs, and
//! artifact references (research 044 open item; OQ-059). This module decides
//! them without touching the owned model/registry files:
//!
//! - Every tier defaults to *follow the finished record*: `None` selects the
//!   job's effective retention (`JobTimeouts::effective_retention`), so no
//!   tier outlives the record it annotates and no second clock is invented.
//! - Callers override per tier with an explicit [`Duration`]; `Duration::ZERO`
//!   evicts eagerly, mirroring the finished-record rule.
//! - Explicit values are bounded by [`MAX_RETENTION_TTL`] (30 days) and fail
//!   closed above it; persistence restart reconciliation stays CTX-0516.
//!
//! The helpers here are pure: [`RetentionPolicy::ttl_for`] resolves a tier to
//! one duration and [`RetentionPolicy::evictable`] answers whether a finished
//! record is evictable at `now_ms`, with the same saturating-clock semantics
//! as the registry sweep (`age < ttl` retains).

use std::fmt;
use std::time::Duration;

/// Longest retention TTL any tier accepts (30 days).
///
/// Bounds database/file growth: callers that need longer must page material
/// to external archival, which is outside the supervisor boundary.
pub const MAX_RETENTION_TTL: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// Tier of retained execution material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RetentionTier {
    /// In-memory newest-wins output bytes (the hottest, first to shed).
    Ring,
    /// Persisted per-job logs held by reference (CTX-0516 storage applies
    /// this tier; this crate only declares it).
    PersistedLog,
    /// Artifact references (file-held by reference, never raw bytes in the
    /// database).
    Artifact,
}

impl RetentionTier {
    /// Stable lowercase name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ring => "ring",
            Self::PersistedLog => "persisted_log",
            Self::Artifact => "artifact",
        }
    }
}

impl fmt::Display for RetentionTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Retention policy for the three material tiers.
///
/// Each field is `None` (follow the finished record's effective retention,
/// the default for every tier) or `Some(ttl)` (explicit override;
/// `Duration::ZERO` evicts eagerly).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RetentionPolicy {
    /// In-memory ring/output retention override.
    pub ring: Option<Duration>,
    /// Persisted-log retention override.
    pub persisted_log: Option<Duration>,
    /// Artifact-reference retention override.
    pub artifact: Option<Duration>,
}

impl RetentionPolicy {
    /// Policy where every tier follows the finished record (the default).
    #[must_use]
    pub const fn follow_record() -> Self {
        Self {
            ring: None,
            persisted_log: None,
            artifact: None,
        }
    }

    /// Override the ring tier.
    #[must_use]
    pub const fn with_ring(mut self, ttl: Duration) -> Self {
        self.ring = Some(ttl);
        self
    }

    /// Override the persisted-log tier.
    #[must_use]
    pub const fn with_persisted_log(mut self, ttl: Duration) -> Self {
        self.persisted_log = Some(ttl);
        self
    }

    /// Override the artifact-reference tier.
    #[must_use]
    pub const fn with_artifact(mut self, ttl: Duration) -> Self {
        self.artifact = Some(ttl);
        self
    }

    /// Validates explicit overrides (fail-closed, no side effects).
    ///
    /// # Errors
    ///
    /// Returns [`RetentionError::OverBound`] when any explicit TTL exceeds
    /// [`MAX_RETENTION_TTL`].
    pub fn validate(&self) -> Result<(), RetentionError> {
        for (tier, ttl) in [
            (RetentionTier::Ring, self.ring),
            (RetentionTier::PersistedLog, self.persisted_log),
            (RetentionTier::Artifact, self.artifact),
        ] {
            if let Some(ttl) = ttl {
                if ttl > MAX_RETENTION_TTL {
                    return Err(RetentionError::OverBound { tier, ttl });
                }
            }
        }
        Ok(())
    }

    /// Resolves one tier to a concrete TTL.
    ///
    /// `record_ttl` is the finished record's effective retention (usually
    /// `JobTimeouts::effective_retention`, which falls back to the
    /// 60 s default); `None` tiers follow it.
    #[must_use]
    pub fn ttl_for(&self, tier: RetentionTier, record_ttl: Duration) -> Duration {
        match tier {
            RetentionTier::Ring => self.ring.unwrap_or(record_ttl),
            RetentionTier::PersistedLog => self.persisted_log.unwrap_or(record_ttl),
            RetentionTier::Artifact => self.artifact.unwrap_or(record_ttl),
        }
    }

    /// Whether material finished at `finished_at_ms` is evictable at `now_ms`
    /// under `ttl`.
    ///
    /// Saturates clock skew (never panics); `age < ttl` retains, so a zero
    /// TTL evicts eagerly on the first sweep.
    #[must_use]
    pub const fn evictable(finished_at_ms: u64, now_ms: u64, ttl: Duration) -> bool {
        let age_ms = now_ms.saturating_sub(finished_at_ms);
        age_ms >= ttl.as_millis() as u64
    }
}

/// Retention validation failure (fail-closed, no partial policy).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionError {
    /// An explicit tier TTL exceeds [`MAX_RETENTION_TTL`].
    OverBound {
        /// Tier carrying the over-bound TTL.
        tier: RetentionTier,
        /// Rejected TTL.
        ttl: Duration,
    },
}

impl fmt::Display for RetentionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OverBound { tier, ttl } => write!(
                f,
                "{tier} retention {}s exceeds the maximum {}s",
                ttl.as_secs(),
                MAX_RETENTION_TTL.as_secs()
            ),
        }
    }
}

impl std::error::Error for RetentionError {}

#[cfg(test)]
mod tests {
    use super::super::model::DEFAULT_RETENTION_TTL;
    use super::*;

    #[test]
    fn defaults_follow_the_finished_record() {
        let policy = RetentionPolicy::default();
        assert!(policy.validate().is_ok());
        for tier in [
            RetentionTier::Ring,
            RetentionTier::PersistedLog,
            RetentionTier::Artifact,
        ] {
            assert_eq!(
                policy.ttl_for(tier, DEFAULT_RETENTION_TTL),
                DEFAULT_RETENTION_TTL
            );
        }
    }

    #[test]
    fn explicit_overrides_resolve_per_tier() {
        let policy = RetentionPolicy::follow_record()
            .with_ring(Duration::from_secs(10))
            .with_artifact(Duration::from_secs(3_600));
        assert!(policy.validate().is_ok());
        assert_eq!(
            policy.ttl_for(RetentionTier::Ring, DEFAULT_RETENTION_TTL),
            Duration::from_secs(10)
        );
        assert_eq!(
            policy.ttl_for(RetentionTier::PersistedLog, DEFAULT_RETENTION_TTL),
            DEFAULT_RETENTION_TTL
        );
        assert_eq!(
            policy.ttl_for(RetentionTier::Artifact, DEFAULT_RETENTION_TTL),
            Duration::from_secs(3_600)
        );
    }

    #[test]
    fn over_bound_ttl_fails_closed() {
        let policy =
            RetentionPolicy::follow_record().with_ring(MAX_RETENTION_TTL + Duration::from_secs(1));
        let error = policy.validate().expect_err("over-bound TTL must fail");
        assert_eq!(
            error,
            RetentionError::OverBound {
                tier: RetentionTier::Ring,
                ttl: MAX_RETENTION_TTL + Duration::from_secs(1),
            }
        );
    }

    #[test]
    fn evictable_matches_registry_sweep_semantics() {
        let ttl = Duration::from_secs(60);
        // Zero age retains under a nonzero TTL.
        assert!(!RetentionPolicy::evictable(1_000, 1_000, ttl));
        // Age strictly below the TTL retains; at/above evicts.
        assert!(!RetentionPolicy::evictable(1_000, 60_999, ttl));
        assert!(RetentionPolicy::evictable(1_000, 61_000, ttl));
        // Zero TTL evicts eagerly, even at the same instant.
        assert!(RetentionPolicy::evictable(1_000, 1_000, Duration::ZERO));
        // Clock skew saturates instead of panicking.
        assert!(!RetentionPolicy::evictable(61_000, 1_000, ttl));
    }

    #[test]
    fn tier_names_are_stable() {
        assert_eq!(RetentionTier::Ring.as_str(), "ring");
        assert_eq!(RetentionTier::PersistedLog.as_str(), "persisted_log");
        assert_eq!(RetentionTier::Artifact.as_str(), "artifact");
    }
}
