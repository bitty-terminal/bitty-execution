//! Sensitive-input detection candidate signal (RUN-22, #1053).
//!
//! Candidate evidence for
//! [OQ-086](https://github.com/bitty-terminal/bitty-docs/blob/main/docs/decisions/open-questions.md):
//! the kernel PTY no-echo state is the only detection signal, output text
//! heuristics may never authorize automation, and dispatch fails closed with
//! a typed denial while the interlock holds.
//!
//! The host owns termios observation (it holds the PTY master side) and the
//! input dispatch it gates; this module owns only the pure policy kernel:
//! [`EchoState`] carries the observed `ECHO` bit, [`InteractionClass`]
//! sorts the interaction, and [`automated_input_allowed`] answers whether
//! automated input may flow. This module performs no syscalls, reads no
//! device state, and takes no prompt text — text plays no role by
//! construction, so spoofed prompt-looking output cannot change the answer.
//!
//! Fail-closed defaults: no-echo denies automated input for every class,
//! including echo-on classifications computed earlier; an echo-on
//! destructive or privileged confirmation still requires a human; no-echo
//! bytes are never capturable ([`may_capture`]); denial is a typed error,
//! never a silent drop and never a queued replay.

use std::fmt;

use crate::command_risk::RiskVerdict;

/// Observed PTY echo state: the slave `termios` `ECHO` bit as last seen by
/// the host.
///
/// The host maps the bit (`c_lflag & ECHO == 0` means [`NoEcho`](Self::NoEcho));
/// how the change is observed (poller, kernel notification, or another
/// mechanism) stays OQ-086 open work and lives outside this module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EchoState {
    /// Echo on: normal interactive output.
    EchoOn,
    /// Echo off: a program is reading without echo — treat as secret input
    /// until the host observes echo restored.
    NoEcho,
}

impl EchoState {
    /// Maps an observed `ECHO` bit to the state (`true` means echo on).
    #[must_use]
    pub const fn of_echo_bit(echo: bool) -> Self {
        if echo { Self::EchoOn } else { Self::NoEcho }
    }

    /// Stable lowercase name for audit records.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EchoOn => "echo_on",
            Self::NoEcho => "no_echo",
        }
    }
}

impl fmt::Display for EchoState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Interaction class for one automated-input decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InteractionClass {
    /// No-echo secret input: no automated input of any kind, human typing
    /// only.
    SecretInput,
    /// Echo-on destructive or privileged confirmation: no automatic reply,
    /// an explicit human decision is required.
    PrivilegedConfirmation,
    /// Echo-on safe interactive prompt: automated reply is allowed under the
    /// caller's own dispatch authority with audit attribution.
    SafeInteractive,
}

impl InteractionClass {
    /// Stable lowercase name for audit records.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SecretInput => "secret_input",
            Self::PrivilegedConfirmation => "privileged_confirmation",
            Self::SafeInteractive => "safe_interactive",
        }
    }

    /// Sorts one interaction from the observed echo state and the
    /// command-risk answer (`high_risk` comes from the OQ-087 command audit;
    /// this module does not classify commands itself).
    ///
    /// The echo state wins over every other input: no-echo is always
    /// [`SecretInput`](Self::SecretInput), so a stale or spoofed
    /// classification can never open the interlock.
    #[must_use]
    pub const fn classify(echo: EchoState, high_risk: bool) -> Self {
        match echo {
            EchoState::NoEcho => Self::SecretInput,
            EchoState::EchoOn => {
                if high_risk {
                    Self::PrivilegedConfirmation
                } else {
                    Self::SafeInteractive
                }
            }
        }
    }
}

impl fmt::Display for InteractionClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A refused automated-input decision; dispatch state is unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecureInputDenial {
    /// The target PTY is in no-echo mode: dispatch is suspended for the
    /// duration of that state. The caller's grant is unchanged; the human
    /// keyboard path is unaffected.
    TargetInSecureInputMode,
    /// The prompt needs an explicit human decision, not an automated reply.
    ConfirmationRequiresHuman,
}

impl SecureInputDenial {
    /// Stable lowercase name for audit records.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TargetInSecureInputMode => "target_in_secure_input_mode",
            Self::ConfirmationRequiresHuman => "confirmation_requires_human",
        }
    }
}

impl fmt::Display for SecureInputDenial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TargetInSecureInputMode => {
                f.write_str("target terminal is in secure (no-echo) input mode")
            }
            Self::ConfirmationRequiresHuman => {
                f.write_str("confirmation requires an explicit human decision")
            }
        }
    }
}

impl std::error::Error for SecureInputDenial {}

/// Answers whether automated input may be dispatched for one interaction.
///
/// The echo state is re-checked on every call: no-echo denies every class,
/// so a `SafeInteractive` answer computed before echo cleared cannot leak
/// through. Allowed input still requires the caller's own dispatch authority
/// and audit attribution, which the host enforces outside this module.
pub const fn automated_input_allowed(
    echo: EchoState,
    class: InteractionClass,
) -> Result<(), SecureInputDenial> {
    match echo {
        EchoState::NoEcho => Err(SecureInputDenial::TargetInSecureInputMode),
        EchoState::EchoOn => match class {
            InteractionClass::SecretInput => Err(SecureInputDenial::TargetInSecureInputMode),
            InteractionClass::PrivilegedConfirmation => {
                Err(SecureInputDenial::ConfirmationRequiresHuman)
            }
            InteractionClass::SafeInteractive => Ok(()),
        },
    }
}

/// Answers whether input bytes in the observed echo state may be captured
/// into the grid, scrollback, snapshots, traces, or agent observations.
///
/// No-echo bytes are never capturable; a snapshot read sees no content for
/// that span. Capture grants no new data access.
#[must_use]
pub const fn may_capture(echo: EchoState) -> bool {
    match echo {
        EchoState::EchoOn => true,
        EchoState::NoEcho => false,
    }
}

/// Sorts one interaction from the observed echo state and the OQ-087
/// command-risk answer.
///
/// Candidate composition for the SI-5 seam: the verdict feeds the risk flag
/// through [`RiskVerdict::requires_explicit_decision`], and the echo state
/// still wins — no-echo is always [`SecretInput`](InteractionClass::SecretInput)
/// regardless of the verdict. A verdict that needs an explicit decision
/// sorts echo-on input as
/// [`PrivilegedConfirmation`](InteractionClass::PrivilegedConfirmation), so
/// the gate answers with a typed denial until a human decides.
#[must_use]
pub const fn classify_with_verdict(echo: EchoState, verdict: RiskVerdict) -> InteractionClass {
    InteractionClass::classify(echo, verdict.requires_explicit_decision())
}

#[cfg(test)]
mod tests {
    use super::super::command_risk::{HardDeny, RiskTier};
    use super::*;

    #[test]
    fn no_echo_denies_every_class() {
        for class in [
            InteractionClass::SecretInput,
            InteractionClass::PrivilegedConfirmation,
            InteractionClass::SafeInteractive,
        ] {
            assert_eq!(
                automated_input_allowed(EchoState::NoEcho, class),
                Err(SecureInputDenial::TargetInSecureInputMode),
                "no-echo must deny {class}"
            );
        }
    }

    #[test]
    fn echo_on_safe_interactive_is_allowed() {
        assert_eq!(
            automated_input_allowed(EchoState::EchoOn, InteractionClass::SafeInteractive),
            Ok(())
        );
    }

    #[test]
    fn echo_on_privileged_confirmation_requires_human() {
        assert_eq!(
            automated_input_allowed(EchoState::EchoOn, InteractionClass::PrivilegedConfirmation),
            Err(SecureInputDenial::ConfirmationRequiresHuman)
        );
    }

    #[test]
    fn stale_secret_class_stays_denied_when_echo_on() {
        // A SecretInput label without no-echo state is inconsistent input;
        // the gate still refuses rather than guessing it is safe.
        assert_eq!(
            automated_input_allowed(EchoState::EchoOn, InteractionClass::SecretInput),
            Err(SecureInputDenial::TargetInSecureInputMode)
        );
    }

    #[test]
    fn classify_echo_state_wins_over_risk_flag() {
        assert_eq!(
            InteractionClass::classify(EchoState::NoEcho, false),
            InteractionClass::SecretInput
        );
        assert_eq!(
            InteractionClass::classify(EchoState::EchoOn, true),
            InteractionClass::PrivilegedConfirmation
        );
        assert_eq!(
            InteractionClass::classify(EchoState::EchoOn, false),
            InteractionClass::SafeInteractive
        );
    }

    #[test]
    fn no_echo_bytes_are_never_capturable() {
        assert!(!may_capture(EchoState::NoEcho));
        assert!(may_capture(EchoState::EchoOn));
    }

    #[test]
    fn echo_bit_mapping_matches_termios_semantics() {
        assert_eq!(EchoState::of_echo_bit(true), EchoState::EchoOn);
        assert_eq!(EchoState::of_echo_bit(false), EchoState::NoEcho);
    }

    #[test]
    fn denial_names_are_stable() {
        assert_eq!(
            SecureInputDenial::TargetInSecureInputMode.as_str(),
            "target_in_secure_input_mode"
        );
        assert_eq!(
            SecureInputDenial::ConfirmationRequiresHuman.as_str(),
            "confirmation_requires_human"
        );
    }

    #[test]
    fn verdict_bridge_keeps_echo_state_winning() {
        // No-echo denies the shape of every verdict, including plain allow.
        assert_eq!(
            classify_with_verdict(EchoState::NoEcho, RiskVerdict::Allow(RiskTier::ReadOnly)),
            InteractionClass::SecretInput
        );
        assert_eq!(
            classify_with_verdict(
                EchoState::NoEcho,
                RiskVerdict::Deny(HardDeny::PrivilegeEscalation)
            ),
            InteractionClass::SecretInput
        );
    }

    #[test]
    fn verdict_bridge_sorts_echo_on_by_decision_need() {
        assert_eq!(
            classify_with_verdict(EchoState::EchoOn, RiskVerdict::Allow(RiskTier::Standard)),
            InteractionClass::SafeInteractive
        );
        assert_eq!(
            classify_with_verdict(
                EchoState::EchoOn,
                RiskVerdict::NeedsConsent(RiskTier::Restricted)
            ),
            InteractionClass::PrivilegedConfirmation
        );
        assert_eq!(
            classify_with_verdict(
                EchoState::EchoOn,
                RiskVerdict::Deny(HardDeny::PipeToInterpreter)
            ),
            InteractionClass::PrivilegedConfirmation
        );
    }

    #[test]
    fn verdict_bridge_never_auto_allows_gated_verdicts() {
        for verdict in [
            RiskVerdict::NeedsConsent(RiskTier::Restricted),
            RiskVerdict::Deny(HardDeny::BlockDeviceWrite),
        ] {
            let class = classify_with_verdict(EchoState::EchoOn, verdict);
            assert!(
                automated_input_allowed(EchoState::EchoOn, class).is_err(),
                "gated verdict must not auto-allow"
            );
        }
    }
}
