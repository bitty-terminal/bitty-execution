//! Bounded per-job output store and read surface (CTX-0513).
//!
//! The phase-1 supervisor drained pipes without retaining bytes; this module
//! keeps the most recent payload per stream under a hard byte bound so raw
//! stdout can never grow memory (or a database) without limit. Raw bytes live
//! only here — in memory, per job, evicted with the job record — while
//! [`OutputIndex`] carries metadata-only totals into [`JobSnapshot`](crate::JobSnapshot)
//! (SQLite-style: totals and truncation flags, never the bytes).
//!
//! # Bounds
//!
//! - Each stream (`stdout`/`stderr`) of each job retains at most
//!   [`MAX_OUTPUT_BYTES_PER_JOB`] bytes (newest wins, oldest evicted first).
//! - One `read_output` call returns at most [`MAX_READ_BYTES`] bytes and a
//!   tail of at most [`MAX_READ_LINES`] lines; larger requests fail closed.
//! - A job's whole store is therefore bounded by `2 * MAX_OUTPUT_BYTES_PER_JOB`,
//!   and a registry by `capacity * 2 * MAX_OUTPUT_BYTES_PER_JOB`.
//!
//! # Honesty
//!
//! The store never silently discards: totals count every byte the child
//! wrote, `dropped_bytes` counts what did not fit, and `truncated` is set
//! whenever anything was lost. Reads decode retained bytes lossily as UTF-8
//! (a multi-byte sequence split across two drain chunks decodes as the
//! replacement character); truncation flags describe byte loss, not decoding.
//!
//! # Vocabulary
//!
//! The vocabulary stays generic (OQ-061, research 044 §15): streams,
//! tail/filter shapes, and byte counts. A job's own network failure needs no
//! new classification — it is already observable as the facts this store
//! keeps (stderr text) plus the stop the supervisor observed.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::model::JobError;

/// Maximum retained payload bytes per stream (`stdout`/`stderr`) of one job.
///
/// Newest bytes win: when a chunk would overflow the bound the oldest chunks
/// are evicted first and the loss is counted in `dropped_bytes`.
pub const MAX_OUTPUT_BYTES_PER_JOB: usize = 256 * 1024;

/// Maximum bytes one `read_output` call may return.
pub const MAX_READ_BYTES: usize = 1024 * 1024;

/// Maximum lines one `read_output` tail may request.
pub const MAX_READ_LINES: usize = 10_000;

/// Which child stream to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum OutputStream {
    /// Standard output.
    #[default]
    Stdout,
    /// Standard error.
    Stderr,
}

impl OutputStream {
    /// Stable lowercase wire/display name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
    }
}

/// Line filter shapes for [`ReadOutput`].
///
/// Filters select within retained bytes only; they never recover dropped
/// output and never change the truncation flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum OutputFilter {
    /// Every retained line.
    #[default]
    All,
    /// Lines carrying an error shape (`error`, `fail`/`failed`/`failure`,
    /// `panic`), matched case-insensitively.
    Errors,
}

impl OutputFilter {
    /// Stable lowercase wire/display name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Errors => "errors",
        }
    }

    /// Whether `line` is selected by this filter.
    #[must_use]
    pub fn matches_line(self, line: &str) -> bool {
        match self {
            Self::All => true,
            Self::Errors => {
                let lower = line.to_ascii_lowercase();
                lower.contains("error") || lower.contains("fail") || lower.contains("panic")
            }
        }
    }
}

/// Bounded read request for [`JobRegistry::read_output`](crate::JobRegistry::read_output).
///
/// Defaults read everything retained (up to [`MAX_READ_BYTES`]); narrow with
/// [`ReadOutput::with_tail_lines`], [`ReadOutput::with_filter`], or
/// [`ReadOutput::with_max_bytes`]. Over-bound requests fail closed with
/// [`JobError::InvalidRead`] and read nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadOutput {
    stream: OutputStream,
    tail_lines: Option<usize>,
    filter: OutputFilter,
    max_bytes: Option<usize>,
}

impl ReadOutput {
    /// Reads everything retained from `stream`.
    #[must_use]
    pub const fn new(stream: OutputStream) -> Self {
        Self {
            stream,
            tail_lines: None,
            filter: OutputFilter::All,
            max_bytes: None,
        }
    }

    /// Reads only the last `lines` retained (post-filter) lines.
    #[must_use]
    pub const fn with_tail_lines(mut self, lines: usize) -> Self {
        self.tail_lines = Some(lines);
        self
    }

    /// Selects lines with `filter` before applying the tail.
    #[must_use]
    pub const fn with_filter(mut self, filter: OutputFilter) -> Self {
        self.filter = filter;
        self
    }

    /// Caps the returned text at `max` bytes (cut at a char boundary).
    #[must_use]
    pub const fn with_max_bytes(mut self, max: usize) -> Self {
        self.max_bytes = Some(max);
        self
    }

    /// Stream to read.
    #[must_use]
    pub const fn stream(self) -> OutputStream {
        self.stream
    }

    /// Requested tail length, when set.
    #[must_use]
    pub const fn tail_lines(self) -> Option<usize> {
        self.tail_lines
    }

    /// Line filter.
    #[must_use]
    pub const fn filter(self) -> OutputFilter {
        self.filter
    }

    /// Requested byte cap, when set.
    #[must_use]
    pub const fn max_bytes(self) -> Option<usize> {
        self.max_bytes
    }

    /// Validates the request shape (fail-closed, no side effects).
    pub(crate) fn validate(&self) -> Result<ValidatedRead, JobError> {
        if let Some(lines) = self.tail_lines {
            if lines == 0 || lines > MAX_READ_LINES {
                return Err(JobError::invalid_read(format!(
                    "tail lines must be within 1..={MAX_READ_LINES}"
                )));
            }
        }
        let max_bytes = match self.max_bytes {
            Some(max) if max == 0 || max > MAX_READ_BYTES => {
                return Err(JobError::invalid_read(format!(
                    "max bytes must be within 1..={MAX_READ_BYTES}"
                )));
            }
            Some(max) => max,
            None => MAX_READ_BYTES,
        };
        Ok(ValidatedRead {
            stream: self.stream,
            tail_lines: self.tail_lines,
            filter: self.filter,
            max_bytes,
        })
    }
}

/// A validated [`ReadOutput`]; construction is [`ReadOutput::validate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ValidatedRead {
    pub(crate) stream: OutputStream,
    pub(crate) tail_lines: Option<usize>,
    pub(crate) filter: OutputFilter,
    pub(crate) max_bytes: usize,
}

/// Owned view returned by one `read_output` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputView {
    /// Stream that was read.
    pub stream: OutputStream,
    /// Selected text (lossy UTF-8 over retained bytes, tail/filter/byte-cap
    /// applied).
    pub text: String,
    /// Every byte the child wrote to this stream (retained or not).
    pub total_bytes: u64,
    /// Retained bytes behind this view (before tail/filter selection).
    pub stored_bytes: usize,
    /// `total_bytes - stored_bytes`: bytes lost to the per-stream bound.
    pub dropped_bytes: u64,
    /// Whether any byte of this stream was lost (`dropped_bytes > 0`).
    pub truncated: bool,
    /// Lines carried by [`OutputView::text`].
    pub lines_returned: usize,
    /// Filter that selected the lines.
    pub filter: OutputFilter,
}

/// Metadata-only output index carried by job snapshots.
///
/// Totals are exact over everything the child wrote; only counts cross into
/// snapshots and listings — never raw bytes, so the registry table (and any
/// future metadata database) cannot grow with stdout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OutputIndex {
    /// Every stdout byte the child wrote.
    pub stdout_total_bytes: u64,
    /// Stdout bytes still retained (at most [`MAX_OUTPUT_BYTES_PER_JOB`]).
    pub stdout_stored_bytes: usize,
    /// Stdout bytes evicted by the bound.
    pub stdout_dropped_bytes: u64,
    /// Every stderr byte the child wrote.
    pub stderr_total_bytes: u64,
    /// Stderr bytes still retained (at most [`MAX_OUTPUT_BYTES_PER_JOB`]).
    pub stderr_stored_bytes: usize,
    /// Stderr bytes evicted by the bound.
    pub stderr_dropped_bytes: u64,
}

impl OutputIndex {
    /// Whether any byte of either stream was lost to the bound.
    #[must_use]
    pub const fn is_truncated(self) -> bool {
        self.stdout_dropped_bytes > 0 || self.stderr_dropped_bytes > 0
    }
}

// ── store ───────────────────────────────────────────────────────────────────

/// Retained chunks of one stream; the sum of chunk lengths never exceeds
/// [`MAX_OUTPUT_BYTES_PER_JOB`].
#[derive(Debug, Default)]
struct StreamStore {
    chunks: VecDeque<Vec<u8>>,
    total_bytes: u64,
}

impl StreamStore {
    fn push(&mut self, data: &[u8]) {
        self.total_bytes = self.total_bytes.saturating_add(data.len() as u64);
        if data.is_empty() {
            return;
        }
        self.chunks.push_back(data.to_vec());
        let mut stored = self.retained_len();
        while stored > MAX_OUTPUT_BYTES_PER_JOB {
            match self.chunks.pop_front() {
                Some(evicted) => stored = stored.saturating_sub(evicted.len()),
                None => break,
            }
        }
    }

    fn retained_len(&self) -> usize {
        self.chunks.iter().map(Vec::len).sum()
    }
}

/// Per-job output bytes: two bounded streams behind one lock.
#[derive(Debug, Default)]
struct OutputStore {
    stdout: StreamStore,
    stderr: StreamStore,
}

/// Shared handle between a job record and its drain threads.
///
/// Cheap to clone; every clone feeds or reads the same bounded store. The
/// store dies with the last clone — normally the job record, so eviction
/// reclaims the bytes (a drain that outlives a kill keeps its clone until
/// EOF, still under the per-stream bound).
#[derive(Debug, Clone, Default)]
pub(crate) struct OutputSink {
    inner: Arc<Mutex<OutputStore>>,
}

impl OutputSink {
    fn lock(&self) -> MutexGuard<'_, OutputStore> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn push_stdout(&self, data: &[u8]) {
        self.lock().stdout.push(data);
    }

    pub(crate) fn push_stderr(&self, data: &[u8]) {
        self.lock().stderr.push(data);
    }

    pub(crate) fn index(&self) -> OutputIndex {
        let store = self.lock();
        let stdout_stored = store.stdout.retained_len();
        let stderr_stored = store.stderr.retained_len();
        OutputIndex {
            stdout_total_bytes: store.stdout.total_bytes,
            stdout_stored_bytes: stdout_stored,
            stdout_dropped_bytes: store
                .stdout
                .total_bytes
                .saturating_sub(stdout_stored as u64),
            stderr_total_bytes: store.stderr.total_bytes,
            stderr_stored_bytes: stderr_stored,
            stderr_dropped_bytes: store
                .stderr
                .total_bytes
                .saturating_sub(stderr_stored as u64),
        }
    }

    pub(crate) fn read(&self, read: &ValidatedRead) -> OutputView {
        let store = self.lock();
        let stream_store = match read.stream {
            OutputStream::Stdout => &store.stdout,
            OutputStream::Stderr => &store.stderr,
        };
        let stored_bytes = stream_store.retained_len();
        let total_bytes = stream_store.total_bytes;
        let mut retained: Vec<u8> = Vec::with_capacity(stored_bytes);
        for chunk in &stream_store.chunks {
            retained.extend_from_slice(chunk);
        }
        drop(store);

        let decoded = String::from_utf8_lossy(&retained);
        // Line splitting drops the empty after a trailing newline: a
        // payload ending in "\n" has no extra empty line, and a trailing
        // blank line ("\n\n") keeps one empty line. Tails therefore capture
        // exactly N lines by this same rule. An empty store has no lines
        // at all (not one empty line).
        let mut lines: Vec<&str> = if decoded.is_empty() {
            Vec::new()
        } else {
            let mut split: Vec<&str> = decoded.split('\n').collect();
            if decoded.ends_with('\n') && split.last() == Some(&"") {
                split.pop();
            }
            split
        };
        // A payload that ends mid-line (no trailing newline yet, e.g. a
        // still-running job) keeps its partial last line as a line.
        if read.filter != OutputFilter::All {
            lines.retain(|line| read.filter.matches_line(line));
        }
        if let Some(tail) = read.tail_lines {
            let skip = lines.len().saturating_sub(tail);
            lines.drain(..skip);
            // `text` is the selected lines joined by newline (no trailing
            // newline added, so `split('\n')` on `text` round-trips the
            // selection exactly) and `lines_returned` counts it.
            let mut text = lines.join("\n");
            text = truncate_to_bytes(&text, read.max_bytes).to_owned();
            let dropped_bytes = total_bytes.saturating_sub(stored_bytes as u64);
            // A byte-cap cut can split the text mid-line; count what the
            // caller actually received by re-splitting the cut text.
            let lines_returned = if text.is_empty() {
                0
            } else {
                text.split('\n').count()
            };
            return OutputView {
                stream: read.stream,
                lines_returned,
                text,
                total_bytes,
                stored_bytes,
                dropped_bytes,
                truncated: dropped_bytes > 0,
                filter: read.filter,
            };
        }
        let mut text = lines.join("\n");
        text = truncate_to_bytes(&text, read.max_bytes).to_owned();

        let dropped_bytes = total_bytes.saturating_sub(stored_bytes as u64);
        // `lines_returned` counts what the caller received: re-split the
        // cut text (a byte-cap cut can split the last line, and the join
        // carries no trailing newline, so this round-trips exactly).
        let lines_returned = if text.is_empty() {
            0
        } else {
            text.split('\n').count()
        };
        OutputView {
            stream: read.stream,
            lines_returned,
            text,
            total_bytes,
            stored_bytes,
            dropped_bytes,
            truncated: dropped_bytes > 0,
            filter: read.filter,
        }
    }
}

/// Cuts `text` to `max` bytes at a char boundary (or returns it whole).
fn truncate_to_bytes(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    &text[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_and_filter_names_are_stable() {
        assert_eq!(OutputStream::Stdout.as_str(), "stdout");
        assert_eq!(OutputStream::Stderr.as_str(), "stderr");
        assert_eq!(OutputFilter::All.as_str(), "all");
        assert_eq!(OutputFilter::Errors.as_str(), "errors");
    }

    #[test]
    fn error_filter_selects_shapes_case_insensitively() {
        assert!(OutputFilter::Errors.matches_line("ERROR boom"));
        assert!(OutputFilter::Errors.matches_line("test FAILED at 2"));
        assert!(OutputFilter::Errors.matches_line("failure in module"));
        assert!(OutputFilter::Errors.matches_line("panic: boom"));
        assert!(OutputFilter::Errors.matches_line("Panicked at runtime"));
        assert!(!OutputFilter::Errors.matches_line("ok line 190"));
        assert!(!OutputFilter::Errors.matches_line("all good 1"));
        assert!(OutputFilter::All.matches_line("anything at all"));
    }

    #[test]
    fn over_bound_reads_fail_closed() {
        let tail_zero = ReadOutput::new(OutputStream::Stdout).with_tail_lines(0);
        assert!(matches!(
            tail_zero.validate(),
            Err(JobError::InvalidRead { .. })
        ));
        let tail_huge = ReadOutput::new(OutputStream::Stdout).with_tail_lines(MAX_READ_LINES + 1);
        assert!(matches!(
            tail_huge.validate(),
            Err(JobError::InvalidRead { .. })
        ));
        let bytes_zero = ReadOutput::new(OutputStream::Stdout).with_max_bytes(0);
        assert!(matches!(
            bytes_zero.validate(),
            Err(JobError::InvalidRead { .. })
        ));
        let bytes_huge = ReadOutput::new(OutputStream::Stdout).with_max_bytes(MAX_READ_BYTES + 1);
        assert!(matches!(
            bytes_huge.validate(),
            Err(JobError::InvalidRead { .. })
        ));
        let ok = ReadOutput::new(OutputStream::Stderr)
            .with_tail_lines(MAX_READ_LINES)
            .with_max_bytes(MAX_READ_BYTES)
            .with_filter(OutputFilter::Errors);
        assert!(ok.validate().is_ok());
    }

    #[test]
    fn store_evicts_oldest_and_counts_honestly() {
        let sink = OutputSink::default();
        // Three full-capacity floods: only the newest bound-worth survives.
        let flood = vec![b'f'; MAX_OUTPUT_BYTES_PER_JOB];
        sink.push_stdout(&flood);
        sink.push_stdout(&flood);
        sink.push_stdout(b"tail");
        let index = sink.index();
        assert_eq!(
            index.stdout_total_bytes,
            2 * MAX_OUTPUT_BYTES_PER_JOB as u64 + 4
        );
        assert!(index.stdout_stored_bytes <= MAX_OUTPUT_BYTES_PER_JOB);
        assert_eq!(
            index.stdout_dropped_bytes,
            index.stdout_total_bytes - index.stdout_stored_bytes as u64
        );
        assert!(index.is_truncated());

        let read = ReadOutput::new(OutputStream::Stdout)
            .validate()
            .expect("valid");
        let view = sink.read(&read);
        assert!(view.truncated);
        assert_eq!(view.total_bytes, index.stdout_total_bytes);
        assert!(view.text.ends_with("tail"));
    }

    #[test]
    fn read_applies_filter_then_tail_then_byte_cap() {
        let sink = OutputSink::default();
        for i in 0..20 {
            let line = if i % 2 == 0 {
                format!("ERROR item {i}\n")
            } else {
                format!("ok item {i}\n")
            };
            sink.push_stderr(line.as_bytes());
        }
        let read = ReadOutput::new(OutputStream::Stderr)
            .with_filter(OutputFilter::Errors)
            .with_tail_lines(3)
            .validate()
            .expect("valid");
        let view = sink.read(&read);
        assert_eq!(view.lines_returned, 3);
        assert!(!view.truncated);
        let lines: Vec<&str> = view.text.lines().collect();
        assert_eq!(
            lines,
            vec!["ERROR item 14", "ERROR item 16", "ERROR item 18"]
        );

        let capped = ReadOutput::new(OutputStream::Stderr)
            .with_max_bytes(10)
            .validate()
            .expect("valid");
        let capped_view = sink.read(&capped);
        assert!(capped_view.text.len() <= 10);
    }

    #[test]
    fn empty_store_reads_empty_but_honest() {
        let sink = OutputSink::default();
        let read = ReadOutput::new(OutputStream::Stdout)
            .validate()
            .expect("valid");
        let view = sink.read(&read);
        assert!(view.text.is_empty());
        assert_eq!(view.lines_returned, 0);
        assert_eq!(view.total_bytes, 0);
        assert!(!view.truncated);
        assert!(!sink.index().is_truncated());
    }
}
