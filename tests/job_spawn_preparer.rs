//! CTX-0008: host-owned pre-spawn preparation over real pipe jobs.
//!
//! The host hook is the seam Core uses for inherited OS confinement
//! (CTX-1151). These tests pin the contract: the preparer runs exactly once,
//! its command configuration reaches the child, its guard outlives the spawn,
//! and a refusal fails the job closed before any process exists.

use std::any::Any;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use bitty_execution::{
    ExecutionOutcome, JobId, JobRegistry, JobSnapshot, JobSpec, JobState, OutputStream, ReadOutput,
    SpawnPreparer,
};

const HELPER_ENV: &str = "__BITTY_PREPARER_HELPER";
const MARKER_ENV: &str = "__BITTY_PREPARER_MARKER";
const PREPARED_ENV: &str = "__BITTY_PREPARER_VALUE";

/// Child entry point: selected by `HELPER_ENV`, a no-op in the parent suite.
#[test]
fn __bitty_preparer_helper_entry__() {
    match std::env::var(HELPER_ENV).as_deref() {
        Ok("report") => {
            eprintln!(
                "prepared={}",
                std::env::var(PREPARED_ENV).unwrap_or_else(|_| "<absent>".to_owned())
            );
        }
        Ok("marker") => {
            if let Ok(path) = std::env::var(MARKER_ENV) {
                let _ = std::fs::write(path, b"spawned");
            }
        }
        _ => {}
    }
}

fn helper_spec(mode: &str, env: Vec<(String, String)>) -> JobSpec {
    let exe = std::env::current_exe()
        .expect("test binary path")
        .to_string_lossy()
        .into_owned();
    JobSpec::new(
        exe,
        vec![
            "__bitty_preparer_helper_entry__".to_owned(),
            "--exact".to_owned(),
            "--nocapture".to_owned(),
        ],
    )
    .with_env(
        bitty_ipc::execution::EnvPolicy::explicit(
            std::iter::once((HELPER_ENV.to_owned(), mode.to_owned()))
                .chain(env)
                .collect(),
        )
        .expect("explicit env"),
    )
}

fn wait_terminal(registry: &JobRegistry, id: JobId) -> JobSnapshot {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let snapshot = registry.get(id).expect("job stays tracked");
        if snapshot.state.is_terminal() {
            return snapshot;
        }
        assert!(Instant::now() < deadline, "job {id} did not finish in time");
        std::thread::sleep(Duration::from_millis(5));
    }
}

struct EnvPreparer {
    calls: AtomicUsize,
    guard_dropped: Arc<AtomicBool>,
}

impl EnvPreparer {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            guard_dropped: Arc::new(AtomicBool::new(false)),
        }
    }
}

struct DropGuard(Arc<AtomicBool>);

impl Drop for DropGuard {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

impl SpawnPreparer for EnvPreparer {
    fn prepare(
        &self,
        _spec: &JobSpec,
        command: &mut std::process::Command,
    ) -> Result<Box<dyn Any + Send>, String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        command.env(PREPARED_ENV, "yes");
        Ok(Box::new(DropGuard(Arc::clone(&self.guard_dropped))))
    }
}

#[test]
fn preparer_runs_once_and_its_guard_outlives_the_spawn() {
    let preparer = Arc::new(EnvPreparer::new());
    let registry = JobRegistry::new().with_spawn_preparer(preparer.clone());
    let id = registry
        .spawn(helper_spec("report", Vec::new()))
        .expect("tracked");
    let snapshot = wait_terminal(&registry, id);
    assert_eq!(snapshot.state, JobState::Done(ExecutionOutcome::Success));
    assert_eq!(
        preparer.calls.load(Ordering::SeqCst),
        1,
        "the preparer must run exactly once per job"
    );
    assert!(
        preparer.guard_dropped.load(Ordering::SeqCst),
        "the preparation guard must be released after the spawn"
    );
    let view = registry
        .read_output(id, ReadOutput::new(OutputStream::Stderr))
        .expect("stderr retained");
    assert!(
        view.text.contains("prepared=yes"),
        "the preparer's command configuration must reach the child: {:?}",
        view.text
    );
}

struct RefusingPreparer;

impl SpawnPreparer for RefusingPreparer {
    fn prepare(
        &self,
        _spec: &JobSpec,
        _command: &mut std::process::Command,
    ) -> Result<Box<dyn Any + Send>, String> {
        Err("host preparation refused".to_owned())
    }
}

fn marker_path() -> PathBuf {
    std::env::temp_dir().join(format!(
        "bitty-preparer-marker-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos())
    ))
}

#[test]
fn preparer_refusal_fails_closed_before_any_process() {
    let marker = marker_path();
    let registry = JobRegistry::new().with_spawn_preparer(Arc::new(RefusingPreparer));
    let id = registry
        .spawn(helper_spec(
            "marker",
            vec![(MARKER_ENV.to_owned(), marker.to_string_lossy().into_owned())],
        ))
        .expect("tracked job id");
    let snapshot = wait_terminal(&registry, id);
    assert_eq!(
        snapshot.state,
        JobState::Done(ExecutionOutcome::SpawnFailed),
        "a refused preparation is a terminal spawn failure"
    );
    assert!(
        !marker.exists(),
        "no child may start when the preparer refuses: {}",
        marker.display()
    );
    let _ = std::fs::remove_file(&marker);
}

#[test]
fn no_preparer_keeps_the_current_spawn_path() {
    let registry = JobRegistry::new();
    let id = registry
        .spawn(helper_spec("report", Vec::new()))
        .expect("tracked");
    let snapshot = wait_terminal(&registry, id);
    assert_eq!(snapshot.state, JobState::Done(ExecutionOutcome::Success));
    let view = registry
        .read_output(id, ReadOutput::new(OutputStream::Stderr))
        .expect("stderr retained");
    assert!(
        view.text.contains("prepared=<absent>"),
        "a registry without a preparer must not invent one: {:?}",
        view.text
    );
}
