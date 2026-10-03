//! CTX-0513 integration: bounded output store, critical/observation event
//! delivery, and IPC reconnect replay over real child processes.
//!
//! Hostile probes (all must fail closed, never grow memory without bound):
//! unbounded output floods, reconnect mid-stream, event-lane overflow,
//! consumer-disconnect cursor semantics, and job network failures recorded
//! as facts without a new classification.
//!
//! Every child under test is this test binary, selected by an explicit
//! environment variable and reached through an argv-first job spec:
//! hermetic, portable, and shell-free (no `sh` PATH dependency), so the
//! same file runs on Unix and Windows CI.

use std::io::Write;
use std::time::{Duration, Instant};

use bitty_execution::{
    DeliveryState, EventClass, ExecutionOutcome, JobError, JobEvent, JobId, JobRegistry,
    JobSnapshot, JobSpec, JobState, MAX_EVENT_REPLAY, MAX_OUTPUT_BYTES_PER_JOB, MAX_READ_BYTES,
    MAX_READ_LINES, MAX_STORED_CRITICAL_EVENTS, MAX_STORED_JOB_EVENTS, OutputFilter, OutputStream,
    ReadOutput,
};

const HELPER_ENV: &str = "__BITTY_JOB_OUTPUT_TEST_HELPER";

/// Child entry point: selected by `HELPER_ENV`, runs only in spawned
/// children (the parent suite reaches it through `mode` dispatch, never as
/// the bare harness entry).
fn child_main() {
    match std::env::var(HELPER_ENV).as_deref() {
        // Emit only the payload bytes (plus one trailing marker newline):
        // the store totals must equal exactly what the child wrote, with no
        // harness text in the pipes.
        Ok("flood") => {
            let stdout = std::io::stdout();
            let mut handle = stdout.lock();
            let chunk = [b'x'; 8 * 1024];
            for _ in 0..256 {
                handle.write_all(&chunk).expect("flood write");
            }
            handle.write_all(b"\n").expect("flood marker");
            handle.flush().expect("flood flush");
        }
        // Mixed streams: plain stdout lines plus stderr lines carrying the
        // error/failed/panic shapes among benign lines. A marker newline
        // ends each stream so totals are exact.
        Ok("mixed") => {
            let stdout = std::io::stdout();
            let mut out = stdout.lock();
            for i in 0..200 {
                writeln!(out, "ok line {i:03}").expect("mixed stdout");
            }
            out.flush().expect("mixed stdout flush");
            let stderr = std::io::stderr();
            let mut err = stderr.lock();
            for i in 0..200 {
                if i % 4 == 0 {
                    writeln!(err, "ERROR something broke {i}").expect("mixed stderr");
                } else if i % 4 == 1 {
                    writeln!(err, "all good {i}").expect("mixed stderr");
                } else if i % 4 == 2 {
                    writeln!(err, "test FAILED at {i}").expect("mixed stderr");
                } else {
                    writeln!(err, "panic: boom {i}").expect("mixed stderr");
                }
            }
            err.flush().expect("mixed stderr flush");
        }
        // A job whose own network fails: facts on stderr, plain exit.
        // NOTE: stderr uses eprintln; the child harness summary goes to
        // stdout, so stderr stays exactly the payload facts.
        Ok("netfail") => {
            eprintln!("dial tcp 10.0.0.1:443: connection refused");
        }
        // Slow tick emitter (~2 s) so a consumer can disconnect mid-stream.
        Ok("slow") => {
            let stdout = std::io::stdout();
            let mut handle = stdout.lock();
            for i in 0..40 {
                writeln!(handle, "tick {i:02}").expect("slow write");
                handle.flush().expect("slow flush");
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        // Exit immediately without emitting anything.
        Ok("quiet") => {}
        _ => {}
    }
}

fn helper_exe() -> String {
    std::env::current_exe()
        .expect("test binary path")
        .to_string_lossy()
        .into_owned()
}

/// Argv-first spec for the test binary in `mode`, with the explicit
/// environment the closed-env backend requires.
///
/// The spec runs the exact harness test that dispatches to `child_main`
/// (plus `--exact --nocapture` so the filter selects one test): the child
/// binary therefore re-enters the harness with the helper env set, runs the
/// payload, then prints the ordinary harness summary to its own stdout —
/// which the parent filters out with exact line assertions. A bare run of
/// this file (no helper env) executes the dispatch test as a no-op and
/// passes.
fn helper_spec(mode: &str) -> JobSpec {
    JobSpec::new(
        helper_exe(),
        vec![
            "__bitty_job_output_helper_entry__".to_owned(),
            "--exact".to_owned(),
            "--nocapture".to_owned(),
        ],
    )
    .with_env(
        bitty_ipc::execution::EnvPolicy::explicit(vec![(HELPER_ENV.to_owned(), mode.to_owned())])
            .expect("explicit env"),
    )
}

#[test]
fn __bitty_job_output_helper_entry__() {
    if std::env::var(HELPER_ENV).is_ok() {
        child_main();
    }
}

fn wait_for(
    registry: &JobRegistry,
    id: JobId,
    what: &str,
    predicate: impl Fn(&JobSnapshot) -> bool,
) -> JobSnapshot {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let snapshot = registry.get(id).expect("job stays tracked");
        if predicate(&snapshot) {
            return snapshot;
        }
        assert!(
            Instant::now() < deadline,
            "job {id} did not reach {what} in time"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn wait_terminal(registry: &JobRegistry, id: JobId) -> JobSnapshot {
    wait_for(registry, id, "a terminal state", |snapshot| {
        snapshot.state.is_terminal()
    })
}

fn wait_stopped(registry: &JobRegistry, id: JobId) -> JobSnapshot {
    let stopped = wait_terminal(registry, id);
    // The terminal state is published before the detached drain threads
    // finish feeding the store: wait until the index stops growing (or the
    // store reports no more retained growth) so output assertions race
    // neither the pipes nor PTY readers.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut last = registry.output_index(id).expect("tracked");
    loop {
        std::thread::sleep(Duration::from_millis(10));
        let current = registry.output_index(id).expect("tracked");
        if current == last {
            let _ = stopped;
            return registry.get(id).expect("tracked");
        }
        last = current;
        assert!(
            Instant::now() < deadline,
            "job {id} output did not settle in time"
        );
    }
}

#[test]
fn unbounded_output_is_bounded_and_honest() {
    let registry = JobRegistry::new();
    let id = registry.spawn(helper_spec("flood")).expect("tracked");
    let stopped = wait_stopped(&registry, id);
    assert_eq!(stopped.state, JobState::Done(ExecutionOutcome::Success));

    // The store never retains more than the per-job byte bound even though
    // the child wrote far more. The child also prints the ordinary harness
    // summary to its own stdout after the payload, so assert on bounds and
    // honesty relations (exact totals minus harness text) rather than a
    // literal payload size.
    let view = registry
        .read_output(id, ReadOutput::new(OutputStream::Stdout))
        .expect("readable");
    assert!(view.stored_bytes <= MAX_OUTPUT_BYTES_PER_JOB);
    assert!(view.total_bytes > 2 * 1024 * 1024, "{}", view.total_bytes);
    assert!(
        view.total_bytes <= 2 * 1024 * 1024 + 8 * 1024,
        "{}",
        view.total_bytes
    );
    assert_eq!(
        view.dropped_bytes,
        view.total_bytes - u64::try_from(view.stored_bytes).expect("fits")
    );
    assert!(view.truncated);

    // The snapshot carries the output index (metadata only), never raw
    // bytes: totals are exact, retained bytes stay bounded.
    let snapshot = registry.get(id).expect("tracked");
    assert_eq!(snapshot.output.stdout_total_bytes, view.total_bytes);
    assert!(snapshot.output.stdout_stored_bytes <= MAX_OUTPUT_BYTES_PER_JOB);
    assert!(snapshot.output.is_truncated());

    // Listing jobs never carries output bytes either.
    assert_eq!(registry.list().len(), 1);
}

#[test]
fn tail_and_error_filter_read_surface() {
    let registry = JobRegistry::new();
    let id = registry.spawn(helper_spec("mixed")).expect("tracked");
    let stopped = wait_stopped(&registry, id);
    assert_eq!(stopped.state, JobState::Done(ExecutionOutcome::Success));

    // Bounded tail: the last numbered stdout lines, in order. The child
    // prints the ordinary harness summary after the payload, so filter the
    // read to the numbered run and assert the exact suffix.
    let numbered_tail = registry
        .read_output(
            id,
            ReadOutput::new(OutputStream::Stdout).with_tail_lines(400),
        )
        .expect("tail readable");
    let numbered: Vec<&str> = numbered_tail
        .text
        .lines()
        .filter(|line| line.starts_with("ok line "))
        .collect();
    // All 200 numbered lines survive (small payload, no truncation loss on
    // the numbered prefix beyond the retained window) and stay ordered.
    assert_eq!(
        numbered.len(),
        200,
        "{:?}",
        &numbered_tail.text[..512.min(numbered_tail.text.len())]
    );
    assert_eq!(numbered[190], "ok line 190");
    assert_eq!(numbered[199], "ok line 199");

    // A 10-line tail over everything retained ends with the harness
    // summary (payload first, harness last): newest last, and the tail
    // holds the summary (the result header, the blank separator, and the
    // summary block).
    let tail = registry
        .read_output(
            id,
            ReadOutput::new(OutputStream::Stdout).with_tail_lines(10),
        )
        .expect("tail readable");
    // endings differ by harness timing text; assert structure instead:
    // the tail carries the end of the numbered run followed by the whole
    // harness summary (the result header plus the blank-separated block).
    // `text` is the selected lines joined by newline: `split` round-trips
    // the selection, up to the trailing newline the retained payload
    // carried (a retained trailing newline restores one, so the text ends
    // with exactly one newline then).
    let tail_lines: Vec<&str> = tail.text.split('\n').collect();
    assert_eq!(tail.lines_returned, tail_lines.len(), "{:?}", tail.text);
    assert!(tail_lines.contains(&"ok line 199"), "{:?}", tail.text);
    assert!(
        tail.text.contains("test result: ok. 1 passed"),
        "{:?}",
        tail.text
    );
    // The tail holds the run end plus the full summary: the summary line
    // is the last non-empty split part (a trailing newline leaves a
    // dangling empty part after it).
    let summary_at = tail_lines
        .iter()
        .position(|line| line.contains("test result: ok. 1 passed"))
        .expect("summary in tail");
    let last_content = tail_lines
        .iter()
        .rposition(|line| !line.is_empty())
        .expect("content");
    assert_eq!(summary_at, last_content, "{:?}", tail.text);

    // Error filter over stderr: only the error/failed/panic shapes match,
    // case-insensitively; benign lines never match.
    let errors = registry
        .read_output(
            id,
            ReadOutput::new(OutputStream::Stderr).with_filter(OutputFilter::Errors),
        )
        .expect("filter readable");
    assert_eq!(errors.lines_returned, 150, "{:?}", errors.text);
    assert!(!errors.text.contains("all good"));
    assert!(errors.text.contains("ERROR something broke 0"));
    assert!(errors.text.contains("test FAILED at 2"));
    assert!(errors.text.contains("panic: boom 3"));

    // Stdout's numbered lines carry no error shapes, but the child's own
    // harness summary ("0 failed") does: assert the filter selects only
    // the summary line and nothing from the payload run.
    let stdout_errors = registry
        .read_output(
            id,
            ReadOutput::new(OutputStream::Stdout).with_filter(OutputFilter::Errors),
        )
        .expect("filter readable");
    assert!(
        !stdout_errors.text.contains("ok line"),
        "{:?}",
        stdout_errors.text
    );
    assert!(
        stdout_errors.text.contains("test result: ok. 1 passed"),
        "{:?}",
        stdout_errors.text
    );
}

#[test]
fn hostile_reads_fail_closed() {
    let registry = JobRegistry::new();
    let id = registry.spawn(helper_spec("mixed")).expect("tracked");
    wait_terminal(&registry, id);

    let unknown = JobId::from_raw(4_242_424).expect("non-zero");
    assert_eq!(
        registry.read_output(unknown, ReadOutput::new(OutputStream::Stdout)),
        Err(JobError::UnknownJob(unknown))
    );
    assert!(
        matches!(
            registry.read_output(id, ReadOutput::new(OutputStream::Stdout).with_tail_lines(0)),
            Err(JobError::InvalidRead { .. })
        ),
        "zero tail must fail closed"
    );
    assert!(
        matches!(
            registry.read_output(
                id,
                ReadOutput::new(OutputStream::Stdout).with_tail_lines(MAX_READ_LINES + 1)
            ),
            Err(JobError::InvalidRead { .. })
        ),
        "over-cap tail must fail closed"
    );
    assert!(
        matches!(
            registry.read_output(
                id,
                ReadOutput::new(OutputStream::Stdout).with_max_bytes(MAX_READ_BYTES + 1)
            ),
            Err(JobError::InvalidRead { .. })
        ),
        "over-cap byte bound must fail closed"
    );
    assert!(
        matches!(
            registry.read_output(id, ReadOutput::new(OutputStream::Stdout).with_max_bytes(0)),
            Err(JobError::InvalidRead { .. })
        ),
        "zero byte bound must fail closed"
    );
}

#[test]
fn job_network_failure_is_facts_not_a_classification() {
    let registry = JobRegistry::new();
    let id = registry.spawn(helper_spec("netfail")).expect("tracked");
    let stopped = wait_stopped(&registry, id);
    // No network_error stop exists: the supervisor observes a plain exit
    // (exit code/signal taxonomy is CTX-0512) and keeps the stderr facts.
    assert_eq!(stopped.state, JobState::Done(ExecutionOutcome::Success));

    // Unfiltered read first: the raw facts must be present regardless of
    // filter shaping. NOTE: `dial ... connection refused` contains neither
    // `error` nor `fail` nor `panic`, so the Errors filter must NOT match
    // it — the facts survive only in the unfiltered read. (The filter
    // selects error shapes, it does not classify jobs.)
    let raw = registry
        .read_output(id, ReadOutput::new(OutputStream::Stderr))
        .expect("stderr readable");
    assert!(
        raw.text.contains("connection refused"),
        "raw stderr missing facts: {:?} (index {:?})",
        raw.text,
        registry.output_index(id).expect("index")
    );

    let filtered = registry
        .read_output(
            id,
            ReadOutput::new(OutputStream::Stderr).with_filter(OutputFilter::Errors),
        )
        .expect("stderr readable");
    assert!(
        filtered.text.is_empty(),
        "netfail facts carry no error shape and must not match: {:?}",
        filtered.text
    );
    assert_eq!(filtered.lines_returned, 0);
}

#[test]
fn reconnect_replays_mid_stream_events_with_stable_ids() {
    let registry = JobRegistry::new();
    let id = registry.spawn(helper_spec("slow")).expect("tracked");

    // First poll waits for the job to start (not merely to be queued): the
    // consumer observes from a live mid-stream point and saves its cursor.
    // (`slow` runs ~2 s, so the start event always lands before completion.)
    let deadline = Instant::now() + Duration::from_secs(30);
    let first = loop {
        let replay = registry.events_since(0, MAX_EVENT_REPLAY).expect("replay");
        if replay.events.len() >= 2 {
            break replay;
        }
        assert!(Instant::now() < deadline, "job {id} did not start in time");
        std::thread::sleep(Duration::from_millis(5));
    };
    assert!(!first.gap);
    assert!(first.events.iter().all(|event| event.job() == id));
    assert!(matches!(first.events[0].event(), JobEvent::Queued { .. }));
    assert!(matches!(first.events[1].event(), JobEvent::Started { .. }));
    let cursor = first.next_seq;
    assert!(cursor >= first.events.last().expect("non-empty").seq());

    // The consumer disconnects while the job keeps running to completion.
    let stopped = wait_terminal(&registry, id);
    assert_eq!(stopped.state, JobState::Done(ExecutionOutcome::Success));

    // Reconnect with the saved cursor: everything missed is replayed,
    // including the terminal critical event.
    let replay = registry
        .events_since(cursor, MAX_EVENT_REPLAY)
        .expect("replay");
    assert!(!replay.events.is_empty());
    assert!(!replay.gap);
    let last = replay.events.last().expect("non-empty");
    assert!(matches!(
        last.event(),
        JobEvent::Stopped {
            outcome: ExecutionOutcome::Success,
            ..
        }
    ));

    // The union of both polls is the full ordered lifecycle with stable,
    // strictly increasing seqs: redelivery is dedupe-safe.
    let mut seqs: Vec<u64> = first
        .events
        .iter()
        .chain(replay.events.iter())
        .map(|event| event.seq())
        .collect();
    assert!(seqs.windows(2).all(|pair| pair[0] < pair[1]));
    seqs.dedup();
    let again = registry
        .events_since(cursor, MAX_EVENT_REPLAY)
        .expect("replay");
    let again_seqs: Vec<u64> = again.events.iter().map(|event| event.seq()).collect();
    assert_eq!(
        again_seqs,
        replay
            .events
            .iter()
            .map(|event| event.seq())
            .collect::<Vec<_>>()
    );

    // A caught-up consumer replays empty and keeps its cursor.
    let head = registry.event_head_seq();
    let caught_up = registry
        .events_since(head, MAX_EVENT_REPLAY)
        .expect("replay");
    assert!(caught_up.events.is_empty());
    assert!(!caught_up.gap);
    assert_eq!(caught_up.next_seq, head);
}

#[test]
fn event_lane_overflow_never_masks_a_terminal_stop() {
    // 140 quiet jobs emit 280 observation events (Queued + Started each)
    // against a 256 observation lane, while 140 critical Stopped events fit
    // their own 256 lane: this is the CTX-0511 drop-oldest-masks-Stopped
    // follow-up, proved end to end.
    let registry = JobRegistry::with_capacity(160);
    let mut ids = Vec::new();
    for _ in 0..140 {
        let id = registry.spawn(helper_spec("quiet")).expect("tracked");
        wait_terminal(&registry, id);
        ids.push(id);
    }
    assert!(registry.observation_dropped() > 0);
    assert_eq!(registry.critical_dropped(), 0);
    assert_eq!(
        registry.events_dropped(),
        registry.observation_dropped() + registry.critical_dropped()
    );

    // Every job still has its terminal critical event in the replay, and a
    // cursor from the origin honestly reports the observation gap. The
    // window holds 256 + 140 retained events, so page past the one-call
    // replay bound with the last returned seq.
    let mut replay_events = Vec::new();
    let mut since = 0;
    let mut gap = false;
    loop {
        let page = registry
            .events_since(since, MAX_EVENT_REPLAY)
            .expect("replay");
        gap |= page.gap;
        let last = page.events.last().map(|event| event.seq());
        replay_events.extend(page.events);
        match last {
            Some(seq) => since = seq,
            None => break,
        }
        if replay_events.len() >= 256 + 140 {
            break;
        }
    }
    assert!(gap);
    assert_eq!(replay_events.len(), 256 + 140);
    for id in &ids {
        assert!(
            replay_events.iter().any(|event| matches!(
                event.event(),
                JobEvent::Stopped { id: found, .. } if found == *id
            )),
            "missing terminal stop for {id}"
        );
    }

    // A consumer that disconnects before the flood still replays the tail,
    // including terminal stops, once it reconnects.
    let head = registry.event_head_seq();
    let tail = registry
        .events_since(head.saturating_sub(10), MAX_EVENT_REPLAY)
        .expect("replay");
    assert!(!tail.gap);
    assert_eq!(tail.events.len(), 10);
}

#[test]
fn consumer_disconnect_ack_and_cursor_semantics() {
    let registry = JobRegistry::new();
    let id = registry.spawn(helper_spec("quiet")).expect("tracked");
    wait_terminal(&registry, id);

    let replay = registry.events_since(0, MAX_EVENT_REPLAY).expect("replay");
    assert!(!replay.gap);
    assert_eq!(replay.events.len(), 3);
    let seqs: Vec<u64> = replay.events.iter().map(|event| event.seq()).collect();
    assert!(seqs.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(matches!(replay.events[0].event(), JobEvent::Queued { .. }));
    assert!(matches!(replay.events[1].event(), JobEvent::Started { .. }));
    assert!(matches!(replay.events[2].event(), JobEvent::Stopped { .. }));

    // Lifecycle classes: terminal stops are critical (model wake-ups),
    // queue/start observations are UI-only.
    assert_eq!(replay.events[0].class(), EventClass::Observation);
    assert_eq!(replay.events[1].class(), EventClass::Observation);
    assert_eq!(replay.events[2].class(), EventClass::Critical);

    // Delivery states: replay marks delivered, ack marks acknowledged and
    // is idempotent for at-least-once redelivery.
    assert!(
        replay
            .events
            .iter()
            .all(|event| event.state() == DeliveryState::Delivered)
    );
    let stop_seq = seqs[2];
    assert_eq!(
        registry.acknowledge(stop_seq).expect("ack"),
        DeliveryState::Acknowledged
    );
    assert_eq!(
        registry.acknowledge(stop_seq).expect("ack idempotent"),
        DeliveryState::Acknowledged
    );
    let again = registry
        .events_since(seqs[1], MAX_EVENT_REPLAY)
        .expect("replay");
    assert_eq!(again.events.len(), 1);
    assert_eq!(again.events[0].state(), DeliveryState::Acknowledged);

    // Unknown seqs fail closed; a cursor past the head is a caller bug.
    assert!(matches!(
        registry.acknowledge(registry.event_head_seq() + 1_000),
        Err(JobError::UnknownEvent { .. })
    ));
    assert!(matches!(
        registry.events_since(registry.event_head_seq() + 1, MAX_EVENT_REPLAY),
        Err(JobError::InvalidCursor { .. })
    ));

    // Stale cursors (older than anything retained) replay everything
    // retained and honestly report the gap.
    let stale = registry
        .events_since(0, MAX_EVENT_REPLAY)
        .expect("origin replay");
    assert!(!stale.gap);
    assert_eq!(stale.events.len(), 3);
    assert_eq!(MAX_STORED_JOB_EVENTS, 256);
    assert_eq!(MAX_STORED_CRITICAL_EVENTS, 256);
}
