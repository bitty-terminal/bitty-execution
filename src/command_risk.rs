//! Command-risk classification candidate signal (RUN-23, #1054).
//!
//! Candidate evidence for
//! [OQ-087](https://github.com/bitty-terminal/bitty-docs/blob/main/docs/decisions/open-questions.md):
//! risk tiers, hard-deny classes, and consent-ledger composition for
//! agent-initiated commands, extending Tool Bus validation the way CRA-1
//! through CRA-5 record it.
//!
//! The host (Tool Bus dispatch) owns consent, the ledger, and execution;
//! this module owns only the structural argv kernel: [`classify_argv`]
//! matches a post-parse argument vector against [`HardDeny`] classes and
//! [`RiskTier`] shapes. Matching is structural over `argv` elements —
//! program basename, flags, and path prefixes — never substring search over
//! a raw command line, so quoting cannot hide the operation from this
//! layer. There is deliberately no command-line splitter here: callers must
//! pass an already-parsed `argv`, and resolving pipelines, command
//! substitution, and encodings needs the shell-AST-class parser that stays
//! OQ-087 open work (CRA-2).
//!
//! Fail-closed defaults: empty `argv` cannot be classified and needs
//! consent; positive hard-deny matches deny; destructive shapes need
//! consent; nothing here grants authority — releasing a blocked command
//! needs an explicit human decision recorded in the consent ledger (PP-3),
//! which lives outside this module.

use std::fmt;

/// Risk tier for one agent-initiated command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RiskTier {
    /// Read-only inspection: proceeds under the caller's existing scopes.
    ReadOnly,
    /// Ordinary local command: proceeds under the accepted scope.
    Standard,
    /// State-resetting command (working-state checkout/reset, temporary-file
    /// removal, signalling a known child): proceeds with notify and audit.
    StateResetting,
    /// Destructive or network-egress shape: blocked pending explicit
    /// consent, never executed on this answer alone.
    Restricted,
}

impl RiskTier {
    /// Stable lowercase name for audit records.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::Standard => "standard",
            Self::StateResetting => "state_resetting",
            Self::Restricted => "restricted",
        }
    }
}

impl fmt::Display for RiskTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Hard-deny class: a positive structural match blocks dispatch and routes
/// to the consent surface instead of executing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HardDeny {
    /// Fetched or decoded content piped into a shell interpreter.
    PipeToInterpreter,
    /// Privilege escalation (`sudo`, `doas`, `su`, `runas`, `pkexec`).
    PrivilegeEscalation,
    /// Writes into user credential directories (`~/.ssh`, `~/.gnupg`).
    CredentialDirWrite,
    /// Writes into system configuration (`/etc/`).
    SystemConfigWrite,
    /// Recursive force deletion of a broad root.
    BroadRootDelete,
    /// Raw block-device writes (`dd of=/dev/...` and equivalents).
    BlockDeviceWrite,
}

impl HardDeny {
    /// Stable lowercase name for audit records.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PipeToInterpreter => "pipe_to_interpreter",
            Self::PrivilegeEscalation => "privilege_escalation",
            Self::CredentialDirWrite => "credential_dir_write",
            Self::SystemConfigWrite => "system_config_write",
            Self::BroadRootDelete => "broad_root_delete",
            Self::BlockDeviceWrite => "block_device_write",
        }
    }
}

impl fmt::Display for HardDeny {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What the caller wants to do with the target paths, as declared by the
/// Tool Bus tool schema (TB-3/TB-4): this module never infers intent from
/// bytes. A read through a mutating-looking path (for example
/// `cat ~/.ssh/id_rsa`) stays a read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperationIntent {
    /// Observe only.
    Read,
    /// Create, modify, move, or remove.
    Write,
    /// Start a process or a new interpreter.
    Execute,
}

/// Classification answer for one `argv`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RiskVerdict {
    /// Proceeds under the caller's scopes at the given tier.
    Allow(RiskTier),
    /// Blocked pending an explicit, time-bounded human decision in the
    /// consent ledger; approval cannot widen the caller's scopes.
    NeedsConsent(RiskTier),
    /// Blocked by a hard-deny class; routes to the consent surface.
    Deny(HardDeny),
}

impl RiskVerdict {
    /// Tier carried by an allow or consent-gated answer; [`None`] for a hard
    /// deny, which carries a [`HardDeny`] class instead of a tier.
    #[must_use]
    pub const fn tier(self) -> Option<RiskTier> {
        match self {
            Self::Allow(tier) | Self::NeedsConsent(tier) => Some(tier),
            Self::Deny(_) => None,
        }
    }

    /// True when dispatch needs an explicit human decision recorded in the
    /// consent ledger (PP-3) before anything executes: consent-gated and
    /// hard-denied answers alike. Fail-closed composition input for the
    /// OQ-086 interlock (SI-5 seam); nothing here records or grants.
    #[must_use]
    pub const fn requires_explicit_decision(self) -> bool {
        match self {
            Self::Allow(_) => false,
            Self::NeedsConsent(_) | Self::Deny(_) => true,
        }
    }
}

/// Basename of `argv[0]`: everything from the last `/`, so an absolute
/// tool path cannot dodge the program match.
fn program_basename(argv0: &str) -> &str {
    match argv0.rsplit('/').next() {
        Some(base) if !base.is_empty() => base,
        _ => argv0,
    }
}

/// Normalizes a POSIX-style path for structural prefix/root matching.
///
/// Collapses duplicate slashes, removes `.` segments, resolves `..` segments
/// within the root or `~` anchor, and strips trailing slashes (preserving `/`
/// and `~`). This prevents trivial syntactic forms such as `/etc/`, `//`,
/// `/etc/.`, or `/var/log/..` from bypassing [`BROAD_ROOTS`], [`path_under`],
/// or [`path_under_home`].
fn normalize_posix_path(raw: &str) -> String {
    if raw.is_empty() {
        return String::new();
    }
    let is_abs = raw.starts_with('/');
    let is_home = raw == "~" || raw.starts_with("~/");
    let rest = if is_home {
        raw.strip_prefix('~').unwrap_or("")
    } else {
        raw
    };
    let mut stack: Vec<&str> = Vec::new();
    for part in rest.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if is_abs || is_home || stack.last().is_some_and(|last| *last != "..") {
                    let _ = stack.pop();
                } else {
                    stack.push("..");
                }
            }
            seg => stack.push(seg),
        }
    }
    if is_home {
        if stack.is_empty() {
            "~".to_owned()
        } else {
            format!("~/{}", stack.join("/"))
        }
    } else if is_abs {
        if stack.is_empty() {
            "/".to_owned()
        } else {
            format!("/{}", stack.join("/"))
        }
    } else if stack.is_empty() {
        ".".to_owned()
    } else {
        stack.join("/")
    }
}

/// True when `arg` names a path under one of `prefixes` (exact match or a
/// `/`-bounded child). `~` expands only to the literal home marker the
/// caller resolves; unresolved `~` never matches, so an unexpanded path
/// cannot smuggle a credential write past the check by accident of form.
fn path_under(arg: &str, prefixes: &[&str]) -> bool {
    let normalized = normalize_posix_path(arg);
    prefixes.iter().any(|prefix| {
        if prefix.is_empty() {
            return false;
        }
        normalized == *prefix
            || normalized.starts_with(prefix) && normalized[prefix.len()..].starts_with('/')
    })
}

/// Credential directories: writes here are identity material.
const CREDENTIAL_DIR_PREFIXES: &[&str] = &[".ssh", ".gnupg"];

/// Broad deletion roots: recursive force removal here is never routine.
const BROAD_ROOTS: &[&str] = &[
    "/", "/bin", "/boot", "/etc", "/home", "/root", "/sbin", "/usr", "/var",
];

/// Shell-class interpreters for the pipe-to-interpreter deny.
const INTERPRETERS: &[&str] = &[
    "bash",
    "cmd",
    "dash",
    "fish",
    "node",
    "perl",
    "powershell",
    "pwsh",
    "python",
    "python3",
    "ruby",
    "sh",
    "zsh",
];

/// Escalation wrappers for the privilege-escalation deny.
const ESCALATION_WRAPPERS: &[&str] = &["doas", "pkexec", "runas", "su", "sudo"];

/// Read-only binaries: observation tools with no mutating mode in this
/// kernel's model. `git` is handled separately by subcommand below.
const READ_ONLY_BINARIES: &[&str] = &[
    "cat", "diff", "file", "head", "less", "ls", "more", "stat", "tail", "which",
];

/// Read-only `git` subcommands for the argv-level check.
const READ_ONLY_GIT_SUBCOMMANDS: &[&str] =
    &["blame", "branch", "diff", "fetch", "log", "show", "status"];

/// State-resetting `git` subcommands: notify and audit, still allowed.
const STATE_RESETTING_GIT_SUBCOMMANDS: &[&str] = &["checkout", "clean", "reset", "restore"];

/// Splits `args` at the first `--` option-terminator into `(option_scan_slice, post_ddash_slice)`.
fn split_at_double_dash<'a>(args: &'a [&'a str]) -> (&'a [&'a str], &'a [&'a str]) {
    match args.iter().position(|arg| *arg == "--") {
        Some(idx) => (&args[..idx], &args[idx + 1..]),
        None => (args, &[]),
    }
}

/// True when `args` (before `--`) carry a recursive flag (`-r`/`-R` in a short
/// bundle or `--recursive` / `--recursive=*`).
fn has_recursive_flag(args: &[&str]) -> bool {
    let (before_ddash, _) = split_at_double_dash(args);
    before_ddash.iter().any(|arg| {
        if let Some(bundle) = arg.strip_prefix('-') {
            if !bundle.starts_with('-') {
                return bundle.contains('r') || bundle.contains('R');
            }
            return *arg == "--recursive"
                || arg
                    .strip_prefix("--recursive=")
                    .is_some_and(|val| !matches!(val, "never" | "no" | "false"));
        }
        false
    })
}

/// True when `args` (before `--`) carry a force flag (`-f` in a short bundle or
/// `--force`).
fn has_force_flag(args: &[&str]) -> bool {
    let (before_ddash, _) = split_at_double_dash(args);
    before_ddash.iter().any(|arg| {
        if let Some(bundle) = arg.strip_prefix('-') {
            if !bundle.starts_with('-') {
                return bundle.contains('f');
            }
            return *arg == "--force";
        }
        false
    })
}

/// Classifies one post-parse argument vector.
///
/// `argv[0]` is the program; `stdin_piped` reports a pipe feeding a new
/// interpreter's stdin (the host observes the pipeline shape — this kernel
/// has no shell AST yet); `intent` is the Tool Bus-declared operation.
/// Raw command-line strings must be parsed by the caller first; nothing
/// here splits text into words.
#[must_use]
pub fn classify_argv(argv: &[&str], stdin_piped: bool, intent: OperationIntent) -> RiskVerdict {
    let Some((program, args)) = argv.split_first() else {
        // Nothing to classify: fail closed to consent, never to allow.
        return RiskVerdict::NeedsConsent(RiskTier::Standard);
    };
    let program = program_basename(program);

    if ESCALATION_WRAPPERS.contains(&program) {
        return RiskVerdict::Deny(HardDeny::PrivilegeEscalation);
    }
    if stdin_piped && INTERPRETERS.contains(&program) {
        return RiskVerdict::Deny(HardDeny::PipeToInterpreter);
    }
    if program == "dd" {
        let block_target = args.iter().any(|arg| {
            arg.strip_prefix("of=")
                .is_some_and(|target| normalize_posix_path(target).starts_with("/dev/"))
        });
        if block_target {
            return RiskVerdict::Deny(HardDeny::BlockDeviceWrite);
        }
    }
    if program == "rm" {
        let recursive = has_recursive_flag(args);
        let force = has_force_flag(args);
        let (before_ddash, after_ddash) = split_at_double_dash(args);
        let mut operands = before_ddash
            .iter()
            .copied()
            .filter(|arg| *arg == "-" || !arg.starts_with('-'))
            .chain(after_ddash.iter().copied());
        if recursive && force {
            let broad = operands.any(|target| {
                let normalized = normalize_posix_path(target);
                BROAD_ROOTS.contains(&normalized.as_str())
            });
            if broad {
                return RiskVerdict::Deny(HardDeny::BroadRootDelete);
            }
            return RiskVerdict::NeedsConsent(RiskTier::Restricted);
        }
        return RiskVerdict::Allow(RiskTier::StateResetting);
    }
    if intent == OperationIntent::Write {
        let credential_hit = args.iter().any(|arg| {
            CREDENTIAL_DIR_PREFIXES
                .iter()
                .any(|dir| path_under_home(arg, dir))
        });
        if credential_hit {
            return RiskVerdict::Deny(HardDeny::CredentialDirWrite);
        }
        if args.iter().any(|arg| path_under(arg, &["/etc"])) {
            return RiskVerdict::Deny(HardDeny::SystemConfigWrite);
        }
    }
    if program == "git" {
        let subcommand = args.iter().find(|arg| !arg.starts_with('-'));
        match subcommand {
            Some(sub) if READ_ONLY_GIT_SUBCOMMANDS.contains(sub) => {
                return RiskVerdict::Allow(RiskTier::ReadOnly);
            }
            Some(sub) if STATE_RESETTING_GIT_SUBCOMMANDS.contains(sub) => {
                return RiskVerdict::Allow(RiskTier::StateResetting);
            }
            _ => {}
        }
    }
    if intent == OperationIntent::Read && READ_ONLY_BINARIES.contains(&program) {
        return RiskVerdict::Allow(RiskTier::ReadOnly);
    }
    RiskVerdict::Allow(RiskTier::Standard)
}

/// Matches `~/.ssh`-style credential paths: a literal `~` slash-joined with
/// a credential directory name. Absolute resolved home paths are matched by
/// the host before calling (it knows the home directory); this kernel only
/// recognizes the portable `~` form so an unexpanded literal cannot dodge
/// the check by accident of form.
fn path_under_home(arg: &str, dir: &str) -> bool {
    let normalized = normalize_posix_path(arg);
    let marked = ["~/", dir].concat();
    normalized == marked
        || normalized.starts_with(&marked) && normalized[marked.len()..].starts_with('/')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_argv_needs_consent() {
        assert_eq!(
            classify_argv(&[], false, OperationIntent::Execute),
            RiskVerdict::NeedsConsent(RiskTier::Standard)
        );
    }

    #[test]
    fn escalation_wrappers_are_denied() {
        for wrapper in ["sudo", "doas", "su", "runas", "pkexec", "/usr/bin/sudo"] {
            assert_eq!(
                classify_argv(&[wrapper, "ls"], false, OperationIntent::Execute),
                RiskVerdict::Deny(HardDeny::PrivilegeEscalation),
                "{wrapper} must deny"
            );
        }
    }

    #[test]
    fn piped_interpreter_is_denied() {
        assert_eq!(
            classify_argv(&["bash"], true, OperationIntent::Execute),
            RiskVerdict::Deny(HardDeny::PipeToInterpreter)
        );
        assert_eq!(
            classify_argv(&["/usr/bin/python3"], true, OperationIntent::Execute),
            RiskVerdict::Deny(HardDeny::PipeToInterpreter)
        );
        // Same interpreter without a pipe is an ordinary command.
        assert_eq!(
            classify_argv(&["bash", "--version"], false, OperationIntent::Execute),
            RiskVerdict::Allow(RiskTier::Standard)
        );
    }

    #[test]
    fn broad_root_recursive_force_delete_is_denied() {
        assert_eq!(
            classify_argv(&["rm", "-rf", "/"], false, OperationIntent::Write),
            RiskVerdict::Deny(HardDeny::BroadRootDelete)
        );
        assert_eq!(
            classify_argv(
                &["rm", "--recursive", "--force", "/home"],
                false,
                OperationIntent::Write
            ),
            RiskVerdict::Deny(HardDeny::BroadRootDelete)
        );
    }

    #[test]
    fn narrow_recursive_force_delete_needs_consent() {
        assert_eq!(
            classify_argv(
                &["rm", "-rf", "/tmp/scratch"],
                false,
                OperationIntent::Write
            ),
            RiskVerdict::NeedsConsent(RiskTier::Restricted)
        );
    }

    #[test]
    fn plain_rm_is_state_resetting() {
        assert_eq!(
            classify_argv(&["rm", "stale.log"], false, OperationIntent::Write),
            RiskVerdict::Allow(RiskTier::StateResetting)
        );
    }

    #[test]
    fn block_device_write_is_denied() {
        assert_eq!(
            classify_argv(
                &["dd", "if=image.bin", "of=/dev/sda"],
                false,
                OperationIntent::Write
            ),
            RiskVerdict::Deny(HardDeny::BlockDeviceWrite)
        );
        // Reading from a device is not a block-device write.
        assert_eq!(
            classify_argv(
                &["dd", "if=/dev/sda", "of=dump.bin"],
                false,
                OperationIntent::Read
            ),
            RiskVerdict::Allow(RiskTier::Standard)
        );
    }

    #[test]
    fn credential_dir_write_is_denied_but_read_is_not() {
        assert_eq!(
            classify_argv(
                &["tee", "~/.ssh/authorized_keys"],
                false,
                OperationIntent::Write
            ),
            RiskVerdict::Deny(HardDeny::CredentialDirWrite)
        );
        assert_eq!(
            classify_argv(&["cat", "~/.ssh/id_rsa"], false, OperationIntent::Read),
            RiskVerdict::Allow(RiskTier::ReadOnly)
        );
    }

    #[test]
    fn system_config_write_is_denied() {
        assert_eq!(
            classify_argv(&["tee", "/etc/hosts"], false, OperationIntent::Write),
            RiskVerdict::Deny(HardDeny::SystemConfigWrite)
        );
    }

    #[test]
    fn git_subcommands_sort_into_tiers() {
        assert_eq!(
            classify_argv(&["git", "status"], false, OperationIntent::Read),
            RiskVerdict::Allow(RiskTier::ReadOnly)
        );
        assert_eq!(
            classify_argv(&["git", "reset", "--hard"], false, OperationIntent::Write),
            RiskVerdict::Allow(RiskTier::StateResetting)
        );
        assert_eq!(
            classify_argv(&["git", "push"], false, OperationIntent::Write),
            RiskVerdict::Allow(RiskTier::Standard)
        );
    }

    #[test]
    fn unknown_commands_are_standard_not_denied() {
        assert_eq!(
            classify_argv(&["cargo", "test"], false, OperationIntent::Execute),
            RiskVerdict::Allow(RiskTier::Standard)
        );
    }

    #[test]
    fn verdict_tier_projection_holds() {
        assert_eq!(
            RiskVerdict::Allow(RiskTier::ReadOnly).tier(),
            Some(RiskTier::ReadOnly)
        );
        assert_eq!(
            RiskVerdict::NeedsConsent(RiskTier::Restricted).tier(),
            Some(RiskTier::Restricted)
        );
        assert_eq!(
            RiskVerdict::Deny(HardDeny::PrivilegeEscalation).tier(),
            None
        );
    }

    #[test]
    fn only_allow_avoids_explicit_decision() {
        assert!(!RiskVerdict::Allow(RiskTier::Standard).requires_explicit_decision());
        assert!(RiskVerdict::NeedsConsent(RiskTier::Restricted).requires_explicit_decision());
        assert!(RiskVerdict::Deny(HardDeny::PipeToInterpreter).requires_explicit_decision());
    }

    #[test]
    fn broad_root_delete_normalizes_trailing_slashes_and_dot_segments() {
        for target in ["//", "/etc/", "/etc/.", "/var/log/..", "/usr///"] {
            assert_eq!(
                classify_argv(&["rm", "-rf", target], false, OperationIntent::Write),
                RiskVerdict::Deny(HardDeny::BroadRootDelete),
                "target {target:?} must be denied as BroadRootDelete"
            );
        }
        assert_eq!(
            classify_argv(
                &["rm", "--recursive=always", "-f", "--", "/etc/"],
                false,
                OperationIntent::Write
            ),
            RiskVerdict::Deny(HardDeny::BroadRootDelete)
        );
        // Flags after `--` are positional operands, not flags.
        assert_eq!(
            classify_argv(&["rm", "--", "-rf", "/"], false, OperationIntent::Write),
            RiskVerdict::Allow(RiskTier::StateResetting)
        );
    }
}
