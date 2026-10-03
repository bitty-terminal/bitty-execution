//! Unique-temp atomic writes for execution coordination files
//! (CORE-RUN-004, #1526).
//!
//! Every write stages its bytes in a temp sibling of its own,
//! `<name>.tmp.<pid>.<seq>`, created with `create_new`, then renames it over
//! the target. Two writers of one target — threads of one process or two
//! processes — therefore never share a temp name, so neither can unlink or
//! rename the other's in-flight file. A foreign file squatting on a temp
//! name only costs a retry with the next sequence number.
//!
//! Temp litter comes only from a writer that died between create and
//! rename. [`sweep_abandoned_temps`] removes such siblings once their
//! modification time is older than [`ABANDONED_TEMP_AGE`]; a live writer's
//! temp is never that old, so a sweep never races an in-flight write.

use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

/// Separator between a target file name and a writer's temp nonce.
const TEMP_MARKER: &str = ".tmp.";

/// Age past which a temp sibling is abandoned: its writer crashed between
/// create and rename. Coordination writes are a few kilobytes plus one
/// fsync, so a live temp is orders of magnitude younger than this.
pub(crate) const ABANDONED_TEMP_AGE: Duration = Duration::from_secs(5 * 60);

/// Fresh temp names tried before a write fails. Only foreign files squatting
/// on the naming scheme can collide, so a handful of attempts is plenty.
const MAX_TEMP_ATTEMPTS: u32 = 16;

/// Process-wide temp sequence: with the pid it makes every temp name unique
/// across the threads of this process and across processes.
static NEXT_TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// How an atomic write treats permissions and the parent directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AtomicWrite {
    /// Create the temp (and so the target) as `0600` on Unix, so metadata
    /// never becomes world-readable in a crash window.
    pub(crate) owner_only: bool,
    /// Fsync the parent directory after the rename so the new name itself
    /// is durable.
    pub(crate) sync_parent: bool,
}

/// Writes `bytes` to `path` atomically through a unique temp sibling.
///
/// The temp is created with `create_new`, written, fsynced, and renamed over
/// `path`. On any failure the temp this call created is removed and the
/// previous target content is untouched.
///
/// # Errors
///
/// Returns the underlying I/O error; [`io::ErrorKind::AlreadyExists`] only
/// after [`MAX_TEMP_ATTEMPTS`] consecutive name collisions.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8], options: AtomicWrite) -> io::Result<()> {
    let (temp, mut file) = create_unique_temp(path, options)?;
    let staged = (|| -> io::Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp, path)
    })();
    if let Err(error) = staged {
        let _ = fs::remove_file(&temp);
        return Err(error);
    }
    if options.sync_parent {
        sync_parent_dir(path);
    }
    Ok(())
}

/// Removes abandoned temp siblings from `dir` (see the module docs).
///
/// Best-effort: unreadable directories or entries are skipped. Only names in
/// the temp scheme (`<name>.tmp.<pid>.<seq>`, plus the legacy
/// `<name>.tmp.<pid>`) are considered, so targets and foreign files are
/// never touched. Callers pass directories that only execution coordination
/// writes into. Returns the number of removed temps.
pub(crate) fn sweep_abandoned_temps(dir: &Path) -> usize {
    sweep_abandoned_temps_at(dir, SystemTime::now())
}

/// [`sweep_abandoned_temps`] against an explicit clock (deterministic tests).
///
/// A temp whose modification time lies in the future (clock skew) is never
/// abandoned: the sweep only removes what it can prove is old.
pub(crate) fn sweep_abandoned_temps_at(dir: &Path, now: SystemTime) -> usize {
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.filter_map(Result::ok) {
        if !is_temp_name(&entry.file_name().to_string_lossy()) {
            continue;
        }
        let abandoned = entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .ok()
            .and_then(|modified| now.duration_since(modified).ok())
            .is_some_and(|age| age > ABANDONED_TEMP_AGE);
        if abandoned && fs::remove_file(entry.path()).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// Whether `name` is a temp produced by [`write_atomic`]: a non-empty target
/// name, the marker, then `<pid>.<seq>` (or the legacy `<pid>`) in digits.
fn is_temp_name(name: &str) -> bool {
    let Some(at) = name.rfind(TEMP_MARKER) else {
        return false;
    };
    if at == 0 {
        return false;
    }
    let nonce = &name[at + TEMP_MARKER.len()..];
    let digits = |part: &str| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit());
    match nonce.split_once('.') {
        Some((pid, seq)) => digits(pid) && digits(seq),
        None => digits(nonce),
    }
}

/// `<name>.tmp.` for `path`, or `None` when the path has no file name.
fn temp_prefix(path: &Path) -> Option<String> {
    path.file_name()
        .map(|name| format!("{}{TEMP_MARKER}", name.to_string_lossy()))
}

/// Creates a fresh temp sibling with `create_new`, retrying on collision.
fn create_unique_temp(path: &Path, options: AtomicWrite) -> io::Result<(PathBuf, fs::File)> {
    let prefix = temp_prefix(path).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "atomic write target has no file name",
        )
    })?;
    let pid = std::process::id();
    let mut last_error = None;
    for _ in 0..MAX_TEMP_ATTEMPTS {
        let seq = NEXT_TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let temp = path.with_file_name(format!("{prefix}{pid}.{seq}"));
        match open_new(&temp, options) {
            Ok(file) => return Ok((temp, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                last_error = Some(error);
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_error
        .unwrap_or_else(|| io::Error::new(io::ErrorKind::AlreadyExists, "no unique temp name")))
}

/// Opens `temp` with `create_new` (never truncating or following an
/// existing file).
fn open_new(temp: &Path, options: AtomicWrite) -> io::Result<fs::File> {
    let mut open = fs::OpenOptions::new();
    open.write(true).create_new(true);
    #[cfg(unix)]
    if options.owner_only {
        use std::os::unix::fs::OpenOptionsExt as _;
        open.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = options;
    let file = open.open(temp)?;
    // `mode` is filtered by the umask; pin the exact bits so an unusual
    // umask can never widen or narrow owner-only metadata.
    #[cfg(unix)]
    if options.owner_only {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

/// Best-effort fsync of `path`'s parent directory.
fn sync_parent_dir(path: &Path) {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            if let Ok(dir) = fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

    const WRITERS: usize = 8;
    const WRITES_PER_WRITER: usize = 40;
    const PLAIN: AtomicWrite = AtomicWrite {
        owner_only: false,
        sync_parent: false,
    };

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "bitty-atomic-file-{tag}-{}-{}",
            std::process::id(),
            NEXT_TEMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    fn payload(writer: usize, round: usize) -> String {
        // Distinct, self-describing, and long enough that a torn write or a
        // mixed rename would be visible.
        format!("writer={writer} round={round} ").repeat(64)
    }

    #[test]
    fn concurrent_writers_of_one_target_all_land_intact() {
        let dir = scratch("race");
        let target = dir.join("coordination");
        let barrier = Arc::new(Barrier::new(WRITERS));
        let handles: Vec<_> = (0..WRITERS)
            .map(|writer| {
                let barrier = Arc::clone(&barrier);
                let target = target.clone();
                thread::spawn(move || {
                    barrier.wait();
                    for round in 0..WRITES_PER_WRITER {
                        write_atomic(&target, payload(writer, round).as_bytes(), PLAIN)
                            .expect("every concurrent write lands");
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().expect("writer thread");
        }
        let text = fs::read_to_string(&target).expect("target readable");
        let intact = (0..WRITERS)
            .any(|writer| (0..WRITES_PER_WRITER).any(|round| text == payload(writer, round)));
        assert!(intact, "the final content is exactly one whole write");
        let litter: Vec<_> = fs::read_dir(&dir)
            .expect("dir")
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name != "coordination")
            .collect();
        assert!(litter.is_empty(), "no temp survives a write: {litter:?}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_squatted_temp_name_costs_a_retry_not_a_failure() {
        let dir = scratch("squat");
        let target = dir.join("coordination");
        let pid = std::process::id();
        let next = NEXT_TEMP_SEQ.load(Ordering::Relaxed);
        // Squat on the next few names this process would pick.
        for seq in next..next + 4 {
            fs::write(dir.join(format!("coordination.tmp.{pid}.{seq}")), b"squat").expect("squat");
        }
        write_atomic(&target, b"landed", PLAIN).expect("retries past squatters");
        assert_eq!(fs::read(&target).expect("target"), b"landed");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn sweep_removes_only_abandoned_temps() {
        let dir = scratch("sweep");
        let target = dir.join("coordination");
        let temp = dir.join("coordination.tmp.1.1");
        let legacy = dir.join("manifest.tmp.7");
        let lookalike = dir.join("notes.tmp.backup");
        fs::write(&temp, b"crashed writer").expect("temp");
        fs::write(&legacy, b"old-scheme writer").expect("legacy");
        fs::write(&lookalike, b"not ours").expect("lookalike");
        fs::write(&target, b"live").expect("target");

        // A young temp may belong to a live writer: kept.
        assert_eq!(sweep_abandoned_temps(&dir), 0);
        assert!(temp.exists());

        // Past the abandonment age it is litter: removed. Targets and names
        // outside the temp scheme are never touched.
        let later = SystemTime::now() + ABANDONED_TEMP_AGE + Duration::from_secs(1);
        assert_eq!(sweep_abandoned_temps_at(&dir, later), 2);
        assert!(!temp.exists());
        assert!(!legacy.exists());
        assert!(lookalike.exists());
        assert_eq!(fs::read(&target).expect("target"), b"live");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn temp_names_follow_the_scheme() {
        assert!(is_temp_name("manifest.tmp.12.3"));
        assert!(is_temp_name("manifest.tmp.12"));
        assert!(is_temp_name("job-1.stdout.log.tmp.4.5"));
        assert!(!is_temp_name(".tmp.1.2"));
        assert!(!is_temp_name("manifest"));
        assert!(!is_temp_name("manifest.tmp."));
        assert!(!is_temp_name("manifest.tmp.1.x"));
        assert!(!is_temp_name("manifest.tmp.1.2.3"));
    }

    #[test]
    fn a_failed_rename_leaves_no_temp_and_the_old_target() {
        let dir = scratch("fail");
        // A directory at the target path makes the rename fail after the
        // temp was written.
        let target = dir.join("coordination");
        fs::create_dir_all(target.join("occupied")).expect("blocking dir");
        assert!(write_atomic(&target, b"new", PLAIN).is_err());
        let names: Vec<_> = fs::read_dir(&dir)
            .expect("dir")
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["coordination".to_owned()]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn owner_only_writes_are_0600() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = scratch("mode");
        let target = dir.join("manifest");
        write_atomic(
            &target,
            b"private",
            AtomicWrite {
                owner_only: true,
                sync_parent: true,
            },
        )
        .expect("write");
        let mode = fs::metadata(&target).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = fs::remove_dir_all(&dir);
    }
}
