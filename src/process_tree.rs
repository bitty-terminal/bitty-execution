//! Owned-process-tree kill backends (RUN-17, #1048; mechanism CTX-0512).
//!
//! Cancel must terminate the owned process tree, never a single PID: a job
//! that spawned grandchildren must not leave them behind. The mechanism is
//! platform-split and confined to the `bitty-pty` boundary crate
//! ([`bitty_pty::OwnedTree`]) so the supervisor never branches on
//! `target_os` itself:
//!
//! - Linux: process groups plus pidfd (implemented);
//! - macOS: process groups plus kqueue exit observation (implemented);
//! - Windows: kill-on-close Job Objects through the reviewed `bitty-winjob`
//!   adapter (implemented, CTX-0903). Pipe jobs start suspended and join
//!   their job before they run; ConPTY jobs join right after the spawn, so
//!   a descendant created before that assignment can escape. Only kills
//!   reach the tree: graceful signals are a typed `Unsupported`.
//!
//! This module names the backend and the kill scope it can honor; the
//! supervisor reports the scope per job (`JobSnapshot::kill_scope`).

use std::fmt;

/// Backend that can terminate a job's owned process tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProcessTreeBackend {
    /// Linux process groups plus pidfd.
    LinuxProcessGroup,
    /// macOS process groups plus kqueue/process wait.
    MacosProcessGroup,
    /// Windows Job Objects (pipe and ConPTY jobs). Kill-only: graceful
    /// signals are refused as unsupported.
    WindowsJobObject,
    /// No owned-tree backend on this platform: only the direct child can be
    /// terminated. Callers must surface the gap, never silently single-kill
    /// while claiming tree cleanup.
    Unsupported,
}

impl ProcessTreeBackend {
    /// Backend implemented for the compiling platform (the one
    /// [`bitty_pty::TreeBackend::detect`] runs).
    #[must_use]
    pub const fn detect() -> Self {
        Self::from_tree_backend(bitty_pty::TreeBackend::detect())
    }

    /// Maps the boundary crate's backend onto this vocabulary.
    #[must_use]
    pub const fn from_tree_backend(backend: bitty_pty::TreeBackend) -> Self {
        match backend {
            bitty_pty::TreeBackend::ProcessGroupPidfd => Self::LinuxProcessGroup,
            bitty_pty::TreeBackend::ProcessGroupKqueue => Self::MacosProcessGroup,
            bitty_pty::TreeBackend::JobObject => Self::WindowsJobObject,
            bitty_pty::TreeBackend::Unsupported => Self::Unsupported,
        }
    }

    /// Stable lowercase wire/display name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LinuxProcessGroup => "linux_process_group",
            Self::MacosProcessGroup => "macos_process_group",
            Self::WindowsJobObject => "windows_job_object",
            Self::Unsupported => "unsupported",
        }
    }

    /// Whether this backend can terminate the owned tree (as opposed to the
    /// direct child only).
    #[must_use]
    pub const fn kills_owned_tree(self) -> bool {
        !matches!(self, Self::Unsupported)
    }
}

impl fmt::Display for ProcessTreeBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Kill scope a cancel may request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KillScope {
    /// Terminate the direct child only (fallback where no tree backend
    /// exists; the caller owns the orphan gap).
    DirectChild,
    /// Terminate the whole owned process tree.
    OwnedTree,
}

impl KillScope {
    /// Scope the backend can honor: tree backends take [`KillScope::OwnedTree`],
    /// [`ProcessTreeBackend::Unsupported`] degrades to
    /// [`KillScope::DirectChild`].
    #[must_use]
    pub const fn for_backend(backend: ProcessTreeBackend) -> Self {
        match backend {
            ProcessTreeBackend::Unsupported => Self::DirectChild,
            ProcessTreeBackend::LinuxProcessGroup
            | ProcessTreeBackend::MacosProcessGroup
            | ProcessTreeBackend::WindowsJobObject => Self::OwnedTree,
        }
    }

    /// Stable lowercase name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DirectChild => "direct_child",
            Self::OwnedTree => "owned_tree",
        }
    }
}

impl fmt::Display for KillScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_backend_maps_to_exactly_one_scope() {
        assert_eq!(
            KillScope::for_backend(ProcessTreeBackend::LinuxProcessGroup),
            KillScope::OwnedTree
        );
        assert_eq!(
            KillScope::for_backend(ProcessTreeBackend::MacosProcessGroup),
            KillScope::OwnedTree
        );
        assert_eq!(
            KillScope::for_backend(ProcessTreeBackend::WindowsJobObject),
            KillScope::OwnedTree
        );
        assert_eq!(
            KillScope::for_backend(ProcessTreeBackend::Unsupported),
            KillScope::DirectChild
        );
    }

    #[test]
    fn tree_capability_matches_the_scope_mapping() {
        for backend in [
            ProcessTreeBackend::LinuxProcessGroup,
            ProcessTreeBackend::MacosProcessGroup,
            ProcessTreeBackend::WindowsJobObject,
            ProcessTreeBackend::Unsupported,
        ] {
            assert_eq!(
                backend.kills_owned_tree(),
                KillScope::for_backend(backend) == KillScope::OwnedTree,
                "{backend} capability must agree with its kill scope"
            );
        }
    }

    #[test]
    fn detect_matches_the_compiling_platform() {
        let backend = ProcessTreeBackend::detect();
        #[cfg(target_os = "linux")]
        assert_eq!(backend, ProcessTreeBackend::LinuxProcessGroup);
        #[cfg(target_os = "macos")]
        assert_eq!(backend, ProcessTreeBackend::MacosProcessGroup);
        #[cfg(target_os = "windows")]
        assert_eq!(backend, ProcessTreeBackend::WindowsJobObject);
        assert_eq!(
            backend.kills_owned_tree(),
            bitty_pty::TreeBackend::detect().kills_owned_tree()
        );
    }

    #[test]
    fn every_tree_backend_maps_onto_this_vocabulary() {
        for (tree, expected) in [
            (
                bitty_pty::TreeBackend::ProcessGroupPidfd,
                ProcessTreeBackend::LinuxProcessGroup,
            ),
            (
                bitty_pty::TreeBackend::ProcessGroupKqueue,
                ProcessTreeBackend::MacosProcessGroup,
            ),
            (
                bitty_pty::TreeBackend::JobObject,
                ProcessTreeBackend::WindowsJobObject,
            ),
            (
                bitty_pty::TreeBackend::Unsupported,
                ProcessTreeBackend::Unsupported,
            ),
        ] {
            let mapped = ProcessTreeBackend::from_tree_backend(tree);
            assert_eq!(mapped, expected);
            assert_eq!(mapped.kills_owned_tree(), tree.kills_owned_tree());
        }
    }

    #[test]
    fn names_are_stable() {
        assert_eq!(
            ProcessTreeBackend::LinuxProcessGroup.as_str(),
            "linux_process_group"
        );
        assert_eq!(
            ProcessTreeBackend::MacosProcessGroup.as_str(),
            "macos_process_group"
        );
        assert_eq!(
            ProcessTreeBackend::WindowsJobObject.as_str(),
            "windows_job_object"
        );
        assert_eq!(ProcessTreeBackend::Unsupported.as_str(), "unsupported");
        assert_eq!(KillScope::DirectChild.as_str(), "direct_child");
        assert_eq!(KillScope::OwnedTree.as_str(), "owned_tree");
    }
}
