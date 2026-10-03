//! Critical/observation event delivery with IPC reconnect replay (CTX-0513).
//!
//! The phase-1 queue kept only observations and dropped the oldest silently;
//! a burst could mask a terminal `Stopped` (the CTX-0511 review follow-up).
//! This module replaces it with two bounded lanes and a stable, strictly
//! increasing `seq` cursor in the style of Cursor's SSE `Last-Event-ID`
//! (research 044 §17):
//!
//! - [`EventClass::Critical`] control-plane answers (`Stopped` of any
//!   [`ExecutionOutcome`](crate::ExecutionOutcome), and `CancelResolved` of
//!   any [`CancelOutcome`](crate::CancelOutcome)) ride the critical lane and
//!   are delivered at-least-once: retained under their own bound, replayed
//!   across a
//!   consumer disconnect via [`JobRegistry::events_since`](crate::JobRegistry::events_since),
//!   deduplicated by the consumer on the stable [`StoredEvent::seq`].
//! - [`EventClass::Observation`] lifecycle notices (`Queued`, `Started`)
//!   ride the observation lane and may drop oldest-first (coalesced; UI-only,
//!   never a model wake-up — research 044 §24).
//!
//! Delivery states follow research 044 §16 (`accepted`/`delivered`/
//! `acknowledged`): an event enters the log as [`DeliveryState::Accepted`],
//! a replay marks what it returns [`DeliveryState::Delivered`], and the
//! consumer closes the loop with
//! [`JobRegistry::acknowledge`](crate::JobRegistry::acknowledge).
//! States live only in the delivery log — never in the job record, never on
//! the wire `JobEvent` — so the supervisor API surface is unchanged.
//!
//! # Vocabulary
//!
//! The vocabulary stays generic (OQ-061): seqs, lanes, classes, and delivery
//! states. `exactly-once` is not claimed; the contract is at-least-once
//! delivery plus idempotent handling on stable event ids.

use std::collections::VecDeque;

use crate::model::{JobError, JobEvent, JobId};
#[cfg(test)]
use crate::outcome::{CancelEffect, CancelOutcome, DeadlineClock, ExecutionOutcome};

/// Maximum retained observation events (UI-only lifecycle notices).
pub const MAX_STORED_OBSERVATION_EVENTS: usize = 256;

/// Maximum retained critical events (terminal stops, at-least-once).
pub const MAX_STORED_CRITICAL_EVENTS: usize = 256;

/// Maximum events one [`JobRegistry::events_since`](crate::JobRegistry::events_since)
/// call may return (a reconnect replay bound, not a retention bound).
pub const MAX_EVENT_REPLAY: usize = 512;

/// Delivery class of one stored event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventClass {
    /// Terminal `Stopped` (of any outcome) and `CancelResolved` (of any
    /// cancel outcome): must reach the consumer; replayable across
    /// disconnects; a candidate model wake-up. A caller must never infer
    /// what its cancel did, so the typed answer is never dropped.
    Critical,
    /// `Queued`/`Started` lifecycle notices: coalescible, drop-oldest,
    /// UI-only, never a model wake-up.
    Observation,
}

impl EventClass {
    /// Stable lowercase wire/display name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::Observation => "observation",
        }
    }
}

/// Accepted/delivered/acknowledged tracking for one stored event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeliveryState {
    /// Stored, not yet returned by any replay.
    Accepted,
    /// Returned by at least one replay; awaits consumer ack.
    Delivered,
    /// The consumer confirmed handling; redeliveries stay marked.
    Acknowledged,
}

impl DeliveryState {
    /// Stable lowercase wire/display name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Delivered => "delivered",
            Self::Acknowledged => "acknowledged",
        }
    }
}

/// One stored lifecycle event: stable cursor, lane, delivery state, and the
/// unchanged phase-1 [`JobEvent`] payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredEvent {
    seq: u64,
    class: EventClass,
    state: DeliveryState,
    event: JobEvent,
}

impl StoredEvent {
    /// Stable, strictly increasing replay cursor (starts at 1; 0 means
    /// "from the origin"). Never reused within the process.
    #[must_use]
    pub const fn seq(self) -> u64 {
        self.seq
    }

    /// Delivery lane of this event.
    #[must_use]
    pub const fn class(self) -> EventClass {
        self.class
    }

    /// Current accepted/delivered/acknowledged state.
    #[must_use]
    pub const fn state(self) -> DeliveryState {
        self.state
    }

    /// The lifecycle payload (unchanged phase-1 shape).
    #[must_use]
    pub const fn event(self) -> JobEvent {
        self.event
    }

    /// Job the event belongs to.
    #[must_use]
    pub const fn job(self) -> JobId {
        self.event.id()
    }
}

/// Owned result of one [`JobRegistry::events_since`](crate::JobRegistry::events_since) call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventReplay {
    /// Retained events with `seq > since`, in `seq` order.
    pub events: Vec<StoredEvent>,
    /// Cursor to pass as the next `since` (the head seq, not the count).
    pub next_seq: u64,
    /// Whether history older than the retained window was lost: observation
    /// events before the window are gone, so a cursor at/before the origin
    /// after overflow cannot be served completely.
    pub gap: bool,
}

/// Two-lane bounded delivery log with a stable `seq` cursor.
///
/// Critical and observation events share the cursor sequence (so one cursor
/// orders a reconnect replay) but have independent capacity: observation
/// pressure can never evict a critical terminal `Stopped`. Each lane drops
/// its own oldest at capacity and counts the loss.
#[derive(Debug)]
pub(crate) struct DeliveryLog {
    next_seq: u64,
    critical: VecDeque<StoredEvent>,
    observation: VecDeque<StoredEvent>,
    critical_dropped: u64,
    observation_dropped: u64,
}

impl DeliveryLog {
    pub(crate) fn new() -> Self {
        Self {
            next_seq: 1,
            critical: VecDeque::with_capacity(MAX_STORED_CRITICAL_EVENTS),
            observation: VecDeque::with_capacity(MAX_STORED_OBSERVATION_EVENTS),
            critical_dropped: 0,
            observation_dropped: 0,
        }
    }

    /// Classifies a lifecycle payload: terminal stops and cancel answers are
    /// critical, queue and start notices are observations.
    #[must_use]
    pub(crate) const fn classify(event: JobEvent) -> EventClass {
        match event {
            JobEvent::Stopped { .. } | JobEvent::CancelResolved { .. } => EventClass::Critical,
            JobEvent::Queued { .. } | JobEvent::Started { .. } => EventClass::Observation,
        }
    }

    /// Stores `event` in its lane with the next stable `seq`.
    pub(crate) fn push(&mut self, event: JobEvent) {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1).max(1);
        let (lane, dropped) = match Self::classify(event) {
            EventClass::Critical => (&mut self.critical, &mut self.critical_dropped),
            EventClass::Observation => (&mut self.observation, &mut self.observation_dropped),
        };
        let capacity = match Self::classify(event) {
            EventClass::Critical => MAX_STORED_CRITICAL_EVENTS,
            EventClass::Observation => MAX_STORED_OBSERVATION_EVENTS,
        };
        if lane.len() >= capacity {
            lane.pop_front();
            *dropped = dropped.saturating_add(1);
        }
        lane.push_back(StoredEvent {
            seq,
            class: Self::classify(event),
            state: DeliveryState::Accepted,
            event,
        });
    }

    /// Head cursor: the newest retained `seq` (0 when the log is empty).
    pub(crate) fn head_seq(&self) -> u64 {
        self.next_seq.saturating_sub(1)
    }

    /// Oldest retained `seq` (head + 1 when the log is empty).
    fn oldest_seq(&self) -> u64 {
        let oldest = self
            .critical
            .front()
            .map(|event| event.seq)
            .into_iter()
            .chain(self.observation.front().map(|event| event.seq))
            .min();
        oldest.unwrap_or_else(|| self.head_seq().saturating_add(1))
    }

    /// Merged replay of everything retained with `seq > since`, in `seq`
    /// order; returned events are marked delivered.
    ///
    /// The replay bound (`limit` capped at [`MAX_EVENT_REPLAY`]) limits how
    /// much one call returns, never what is retained: a short call returns
    /// the oldest matching events first and the caller pages with the last
    /// returned `seq`. Callers that need the whole window page; nothing is
    /// lost to a small `limit`.
    pub(crate) fn replay_since(
        &mut self,
        since: u64,
        limit: usize,
    ) -> Result<EventReplay, JobError> {
        if since > self.head_seq() {
            return Err(JobError::invalid_cursor(format!(
                "cursor {since} is past the event head"
            )));
        }
        let take = limit.min(MAX_EVENT_REPLAY);
        let mut merged: Vec<StoredEvent> = self
            .critical
            .iter()
            .chain(self.observation.iter())
            .filter(|event| event.seq > since)
            .copied()
            .collect();
        merged.sort_by_key(|event| event.seq);
        merged.truncate(take);

        // Mark what this replay returns as delivered (unless already acked:
        // redelivery after an ack stays acknowledged).
        for returned in &merged {
            for stored in self.critical.iter_mut().chain(self.observation.iter_mut()) {
                if stored.seq == returned.seq && stored.state == DeliveryState::Accepted {
                    stored.state = DeliveryState::Delivered;
                }
            }
        }
        let marked: Vec<StoredEvent> = merged
            .iter()
            .map(|returned| {
                if returned.state == DeliveryState::Accepted {
                    StoredEvent {
                        state: DeliveryState::Delivered,
                        ..*returned
                    }
                } else {
                    *returned
                }
            })
            .collect();

        let gap = since < self.oldest_seq().saturating_sub(1);
        Ok(EventReplay {
            events: marked,
            next_seq: self.head_seq(),
            gap,
        })
    }

    /// Marks `seq` acknowledged (idempotent); unknown seqs fail closed.
    pub(crate) fn acknowledge(&mut self, seq: u64) -> Result<DeliveryState, JobError> {
        for stored in self.critical.iter_mut().chain(self.observation.iter_mut()) {
            if stored.seq == seq {
                stored.state = DeliveryState::Acknowledged;
                return Ok(DeliveryState::Acknowledged);
            }
        }
        Err(JobError::unknown_event(seq))
    }

    /// Copies the stored event at `seq`, when retained (read-only peek for
    /// scoped acknowledge authorization; never marks delivery).
    pub(crate) fn find(&self, seq: u64) -> Option<StoredEvent> {
        self.critical
            .iter()
            .chain(self.observation.iter())
            .find(|stored| stored.seq == seq)
            .copied()
    }

    pub(crate) fn dropped(&self) -> u64 {
        self.critical_dropped
            .saturating_add(self.observation_dropped)
    }

    pub(crate) fn critical_dropped(&self) -> u64 {
        self.critical_dropped
    }

    pub(crate) fn observation_dropped(&self) -> u64 {
        self.observation_dropped
    }

    /// Drains up to `limit` retained events in `seq` order (oldest first).
    ///
    /// Drain is the phase-1 consumption shape kept for compatibility: it
    /// removes from both lanes in merged order. Retained-state reads
    /// (`JobEvent`) are unchanged; delivery states of drained events are
    /// dropped with them (ack after drain reports unknown, fail-closed).
    pub(crate) fn drain(&mut self, limit: usize) -> Vec<JobEvent> {
        let mut seqs: Vec<u64> = self
            .critical
            .iter()
            .chain(self.observation.iter())
            .map(|event| event.seq)
            .collect();
        seqs.sort_unstable();
        seqs.truncate(limit);
        let mut out = Vec::with_capacity(seqs.len());
        for seq in seqs {
            let from_critical = self.critical.front().is_some_and(|event| event.seq == seq);
            let from_observation = !from_critical
                && self
                    .observation
                    .front()
                    .is_some_and(|event| event.seq == seq);
            if from_critical {
                if let Some(stored) = self.critical.pop_front() {
                    out.push(stored.event);
                }
            } else if from_observation {
                if let Some(stored) = self.observation.pop_front() {
                    out.push(stored.event);
                }
            } else {
                // The head of neither lane carries this seq (interleaved
                // lanes): remove wherever it sits to keep the drain ordered.
                let found = self
                    .critical
                    .iter()
                    .position(|event| event.seq == seq)
                    .map(|index| (true, index))
                    .or_else(|| {
                        self.observation
                            .iter()
                            .position(|event| event.seq == seq)
                            .map(|index| (false, index))
                    });
                if let Some((is_critical, index)) = found {
                    let stored = if is_critical {
                        self.critical.remove(index)
                    } else {
                        self.observation.remove(index)
                    };
                    if let Some(stored) = stored {
                        out.push(stored.event);
                    }
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn queued(id: JobId, at_ms: u64) -> JobEvent {
        JobEvent::Queued { id, at_ms }
    }

    fn started(id: JobId, at_ms: u64) -> JobEvent {
        JobEvent::Started { id, at_ms }
    }

    fn stopped(id: JobId, outcome: ExecutionOutcome, at_ms: u64) -> JobEvent {
        JobEvent::Stopped { id, outcome, at_ms }
    }

    #[test]
    fn lanes_classify_terminal_stops_and_cancel_answers_as_critical() {
        let id = JobId::from_raw(1).expect("id");
        for outcome in [
            ExecutionOutcome::Success,
            ExecutionOutcome::ExitCode(2),
            ExecutionOutcome::Signaled(15),
            ExecutionOutcome::SpawnFailed,
            ExecutionOutcome::Cancelled(CancelEffect::Killed),
            ExecutionOutcome::TimedOut(DeadlineClock::Hard),
            ExecutionOutcome::OomKilled,
            ExecutionOutcome::SupervisorLost,
            ExecutionOutcome::Unknown,
        ] {
            assert_eq!(
                DeliveryLog::classify(stopped(id, outcome, 3)),
                EventClass::Critical
            );
        }
        assert_eq!(
            DeliveryLog::classify(JobEvent::CancelResolved {
                id,
                outcome: CancelOutcome::StillRunning,
                at_ms: 3,
            }),
            EventClass::Critical
        );
        assert_eq!(
            DeliveryLog::classify(queued(id, 1)),
            EventClass::Observation
        );
        assert_eq!(
            DeliveryLog::classify(started(id, 2)),
            EventClass::Observation
        );
        assert_eq!(EventClass::Critical.as_str(), "critical");
        assert_eq!(EventClass::Observation.as_str(), "observation");
        assert_eq!(DeliveryState::Accepted.as_str(), "accepted");
        assert_eq!(DeliveryState::Delivered.as_str(), "delivered");
        assert_eq!(DeliveryState::Acknowledged.as_str(), "acknowledged");
    }

    #[test]
    fn replay_is_ordered_stable_and_marks_delivered() {
        let id = JobId::from_raw(7).expect("id");
        let mut log = DeliveryLog::new();
        log.push(queued(id, 1));
        log.push(started(id, 2));
        log.push(stopped(id, ExecutionOutcome::Success, 3));

        let replay = log.replay_since(0, MAX_EVENT_REPLAY).expect("replay");
        assert_eq!(replay.events.len(), 3);
        assert!(!replay.gap);
        let seqs: Vec<u64> = replay.events.iter().map(|event| event.seq()).collect();
        assert!(seqs.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(
            replay
                .events
                .iter()
                .all(|event| event.state() == DeliveryState::Delivered)
        );

        // A second replay from the same cursor is identical: redelivery is
        // dedupe-safe on stable seqs.
        let again = log.replay_since(0, MAX_EVENT_REPLAY).expect("replay");
        assert_eq!(
            again
                .events
                .iter()
                .map(|event| event.seq())
                .collect::<Vec<_>>(),
            seqs
        );
        assert_eq!(replay.next_seq, log.head_seq());

        // Caught-up consumers replay empty and keep their cursor.
        let caught_up = log
            .replay_since(log.head_seq(), MAX_EVENT_REPLAY)
            .expect("replay");
        assert!(caught_up.events.is_empty());
        assert!(!caught_up.gap);
    }

    #[test]
    fn acknowledge_is_idempotent_and_unknown_fails_closed() {
        let id = JobId::from_raw(7).expect("id");
        let mut log = DeliveryLog::new();
        log.push(queued(id, 1));
        let replay = log.replay_since(0, MAX_EVENT_REPLAY).expect("replay");
        let seq = replay.events[0].seq();
        assert_eq!(
            log.acknowledge(seq).expect("ack"),
            DeliveryState::Acknowledged
        );
        assert_eq!(
            log.acknowledge(seq).expect("ack idempotent"),
            DeliveryState::Acknowledged
        );
        assert!(matches!(
            log.acknowledge(seq + 1_000),
            Err(JobError::UnknownEvent { .. })
        ));
        assert!(matches!(
            log.replay_since(log.head_seq() + 1, MAX_EVENT_REPLAY),
            Err(JobError::InvalidCursor { .. })
        ));
    }

    #[test]
    fn observation_pressure_never_evicts_critical_stops() {
        let mut log = DeliveryLog::new();
        let id = JobId::from_raw(1).expect("id");
        for i in 0..(MAX_STORED_OBSERVATION_EVENTS + MAX_STORED_CRITICAL_EVENTS + 10) {
            log.push(queued(id, i as u64));
        }
        log.push(stopped(id, ExecutionOutcome::Success, 999));
        assert!(log.observation_dropped() > 0);
        assert_eq!(log.critical_dropped(), 0);
        let replay = log.replay_since(0, 8 * MAX_EVENT_REPLAY).expect("replay");
        assert!(replay.gap);
        assert!(
            replay.events.iter().any(|event| matches!(
                event.event(),
                JobEvent::Stopped {
                    outcome: ExecutionOutcome::Success,
                    ..
                }
            )),
            "the terminal stop must survive observation overflow"
        );
    }

    #[test]
    fn drain_keeps_phase1_ordering() {
        let id = JobId::from_raw(3).expect("id");
        let mut log = DeliveryLog::new();
        log.push(queued(id, 1));
        log.push(started(id, 2));
        log.push(stopped(
            id,
            ExecutionOutcome::Cancelled(CancelEffect::Killed),
            3,
        ));
        let drained = log.drain(10);
        assert_eq!(drained.len(), 3);
        assert!(matches!(drained[0], JobEvent::Queued { .. }));
        assert!(matches!(drained[1], JobEvent::Started { .. }));
        assert!(matches!(drained[2], JobEvent::Stopped { .. }));
        assert!(log.drain(10).is_empty());
    }
}
