//! OS-held exclusive lock for supervisor claims (CORE-RUN-003, #1526).
//!
//! Platform split for the claim lock that serializes claim, heartbeat, and
//! release. Every variant is released by the kernel when the holding
//! process exits, so a crash inside the critical section never wedges a
//! directory, and none needs `unsafe`:
//!
//! - Linux/Android: `flock(LOCK_EX | LOCK_NB)` through `rustix`;
//! - macOS/iOS/BSD: `flock` through `nix`;
//! - Windows: an exclusive open (share mode 0) is itself the lock;
//! - anything else fails closed with `Unsupported`.
//!
//! `flock` locks belong to the open file description, so two handles in one
//! process exclude each other as well as two processes do.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

/// Held exclusive lock; dropping it releases the lock.
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
pub(crate) type HeldLock = nix::fcntl::Flock<File>;

/// Held exclusive lock; dropping (closing) it releases the lock.
#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
)))]
pub(crate) type HeldLock = File;

/// Windows `ERROR_SHARING_VIOLATION`: another handle holds the file
/// open without sharing.
#[cfg(windows)]
const ERROR_SHARING_VIOLATION: i32 = 32;

/// Opens (creating when missing, never truncating) the claim-lock file.
/// On Windows the open itself is the lock: share mode 0 denies every
/// other handle until this one closes.
fn open(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        options.share_mode(0);
    }
    options.open(path)
}

/// Takes the exclusive lock once without blocking: `Ok(None)` while
/// another holder has it.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) fn try_lock(path: &Path) -> io::Result<Option<HeldLock>> {
    use rustix::fs::{FlockOperation, flock};
    let file = open(path)?;
    match flock(&file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(Some(file)),
        Err(errno) if errno == rustix::io::Errno::WOULDBLOCK => Ok(None),
        Err(errno) => Err(io::Error::from(errno)),
    }
}

/// Takes the exclusive lock once without blocking: `Ok(None)` while
/// another holder has it.
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
pub(crate) fn try_lock(path: &Path) -> io::Result<Option<HeldLock>> {
    use nix::errno::Errno;
    use nix::fcntl::{Flock, FlockArg};
    let file = open(path)?;
    match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
        Ok(lock) => Ok(Some(lock)),
        Err((_, errno)) if errno == Errno::EWOULDBLOCK => Ok(None),
        Err((_, errno)) => Err(io::Error::from(errno)),
    }
}

/// Takes the exclusive lock once without blocking: `Ok(None)` while
/// another holder has it.
#[cfg(windows)]
pub(crate) fn try_lock(path: &Path) -> io::Result<Option<HeldLock>> {
    match open(path) {
        Ok(file) => Ok(Some(file)),
        Err(error) if error.raw_os_error() == Some(ERROR_SHARING_VIOLATION) => Ok(None),
        Err(error) => Err(error),
    }
}

/// No OS-held lock exists here: claims fail closed rather than fall
/// back to an unserialized check.
#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    windows
)))]
pub(crate) fn try_lock(path: &Path) -> io::Result<Option<HeldLock>> {
    let _ = (path, open);
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "no OS-held claim lock on this platform",
    ))
}
