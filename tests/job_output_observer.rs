//! Output-observer seam (`JobRegistry::with_output_observer`).
//!
//! The executable component streams stdout/stderr from this callback; these
//! probes prove the hook sees every drained byte exactly once and does not
//! change the bounded store's totals.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bitty_execution::{JobRegistry, JobSnapshot, JobSpec, JobState, OutputObserver, OutputStream};

const HELPER_ENV: &str = "__BITTY_OUTPUT_OBSERVER_HELPER";

/// Child entry point selected by [`HELPER_ENV`]; a no-op in the parent suite.
#[test]
fn __bitty_output_observer_helper_entry__() {
    if std::env::var(HELPER_ENV).as_deref() == Ok("emit") {
        println!("observer-stdout");
        eprintln!("observer-stderr");
    }
}

#[derive(Default)]
struct Collector {
    seen: Mutex<Vec<(u64, OutputStream, Vec<u8>)>>,
}

impl OutputObserver for Collector {
    fn on_output(&self, job: bitty_execution::JobId, stream: OutputStream, bytes: &[u8]) {
        self.seen
            .lock()
            .expect("collector lock")
            .push((job.get(), stream, bytes.to_vec()));
    }
}

fn helper_spec() -> JobSpec {
    JobSpec::new(
        std::env::current_exe()
            .expect("test exe")
            .to_string_lossy()
            .into_owned(),
        vec![
            "__bitty_output_observer_helper_entry__".to_owned(),
            "--exact".to_owned(),
            "--nocapture".to_owned(),
        ],
    )
    .with_env(
        bitty_ipc::execution::EnvPolicy::explicit(vec![(HELPER_ENV.to_owned(), "emit".to_owned())])
            .expect("explicit env"),
    )
}

fn wait_terminal(registry: &JobRegistry, id: bitty_execution::JobId) -> JobSnapshot {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let snapshot = registry.get(id).expect("job");
        if snapshot.state.is_terminal() {
            return snapshot;
        }
        assert!(Instant::now() < deadline, "job did not finish in time");
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn observer_sees_every_drained_byte_once() {
    let collector = Arc::new(Collector::default());
    let registry = JobRegistry::new().with_output_observer(collector.clone());
    let id = registry.spawn(helper_spec()).expect("spawn");
    let snapshot = wait_terminal(&registry, id);
    assert!(matches!(snapshot.state, JobState::Done(_)));

    let seen = collector.seen.lock().expect("collector lock");
    let stdout: usize = seen
        .iter()
        .filter(|(job, stream, _)| *job == id.get() && *stream == OutputStream::Stdout)
        .map(|(_, _, bytes)| bytes.len())
        .sum();
    let stderr: usize = seen
        .iter()
        .filter(|(job, stream, _)| *job == id.get() && *stream == OutputStream::Stderr)
        .map(|(_, _, bytes)| bytes.len())
        .sum();
    assert_eq!(stdout as u64, snapshot.output.stdout_total_bytes);
    assert_eq!(stderr as u64, snapshot.output.stderr_total_bytes);
    assert!(
        seen.iter()
            .any(|(_, stream, bytes)| *stream == OutputStream::Stdout
                && String::from_utf8_lossy(bytes).contains("observer-stdout")),
        "stdout marker was not observed"
    );
    assert!(
        seen.iter()
            .any(|(_, stream, bytes)| *stream == OutputStream::Stderr
                && String::from_utf8_lossy(bytes).contains("observer-stderr")),
        "stderr marker was not observed"
    );
    assert!(seen.iter().all(|(job, _, _)| *job == id.get()));
}
