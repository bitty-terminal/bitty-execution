//! `bitty-component.toml` parsing and validation (component descriptor v1).
//!
//! The descriptor is the same closed record Core installs for every native
//! component (DIR-030): one `[component]` table with exactly `name`,
//! `version`, `protocol`, `executable`, and `sha256`. This module parses it
//! with a hand-written, fail-closed reader (no TOML dependency, no escapes,
//! no multi-line values) so the component can validate the descriptor shipped
//! beside it and packaging can validate the canonical repository record
//! before rendering a per-target digest.
//!
//! # Pack policy versus install policy
//!
//! - [`ComponentDescriptor::parse`] accepts the zero-digest sentinel used by
//!   the canonical repository record; packaging replaces it with the real
//!   target digest.
//! - [`ComponentDescriptor::validate_for_install`] refuses the sentinel and
//!   requires the identity of this component (`execution`, protocol 1,
//!   executable `bitty-execution`).
//!
//! Versions are the strict `X.Y.Z` core only. Core's installer accepts full
//! semver; packaging and this component deliberately refuse prerelease or
//! build metadata for the 0.0.x line, matching the other extension
//! packagers.

use std::fmt;

use super::COMPONENT_VERSION;

/// Component name carried by the descriptor, the handshake, and the release
/// layout (`extensions/execution/<version>/`).
pub const COMPONENT_NAME: &str = "execution";

/// Executable base name (no platform suffix in the descriptor).
pub const COMPONENT_EXECUTABLE: &str = "bitty-execution";

/// Lowest wire protocol version this component speaks.
pub const COMPONENT_PROTOCOL_MIN: u16 = 1;

/// Highest wire protocol version this component speaks.
pub const COMPONENT_PROTOCOL_MAX: u16 = 1;

/// Maximum descriptor size accepted from disk or an archive (matches Core's
/// `COMPONENT_DESCRIPTOR_MAX_BYTES`).
pub const MAX_DESCRIPTOR_BYTES: usize = 4096;

/// Parser-valid placeholder digest used by the canonical repository record.
///
/// Packaging renders a per-target copy with the real executable digest; the
/// placeholder itself must never be installed or published.
pub const PLACEHOLDER_SHA256: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

const SHA256_HEX_LEN: usize = 64;

/// Executable base-name prefix every component descriptor must carry.
const EXECUTABLE_PREFIX: &str = "bitty-";

/// A validated `bitty-component.toml` record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentDescriptor {
    /// Component name (`[a-z][a-z0-9-]{0,31}`).
    pub name: String,
    /// Strict `X.Y.Z` version.
    pub version: String,
    /// Lowest supported wire protocol version.
    pub protocol_min: u16,
    /// Highest supported wire protocol version.
    pub protocol_max: u16,
    /// Executable base name (`bitty-<name>`, no path separators).
    pub executable: String,
    /// Lowercase hex SHA-256 of the executable.
    pub sha256: String,
}

/// Descriptor-level validation failure (owned; no TOML type escapes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DescriptorError {
    /// The descriptor exceeds [`MAX_DESCRIPTOR_BYTES`].
    TooLarge {
        /// Observed byte length.
        bytes: usize,
    },
    /// The bytes are not UTF-8.
    NotUtf8,
    /// Malformed descriptor syntax at a 1-based line.
    Syntax {
        /// Line number.
        line: usize,
        /// What was wrong.
        reason: &'static str,
    },
    /// A required key is missing.
    MissingKey(&'static str),
    /// The name violates `[a-z][a-z0-9-]{0,31}`.
    InvalidName,
    /// The version is not strict `X.Y.Z`.
    InvalidVersion,
    /// The executable name is not `bitty-<name>` or contains separators.
    InvalidExecutable,
    /// The digest is not 64 lowercase hex characters.
    InvalidDigest,
    /// `protocol` is not `[min, max]` with `1 <= min <= max`.
    InvalidProtocol,
    /// The record describes a different component.
    IdentityMismatch {
        /// Field that disagreed.
        field: &'static str,
    },
    /// The record still carries the packaging placeholder digest.
    PlaceholderDigest,
}

impl fmt::Display for DescriptorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { bytes } => {
                write!(
                    f,
                    "descriptor is {bytes} bytes (limit {MAX_DESCRIPTOR_BYTES})"
                )
            }
            Self::NotUtf8 => f.write_str("descriptor is not UTF-8"),
            Self::Syntax { line, reason } => write!(f, "descriptor line {line}: {reason}"),
            Self::MissingKey(key) => write!(f, "descriptor is missing '{key}'"),
            Self::InvalidName => f.write_str("component name must match [a-z][a-z0-9-]{0,31}"),
            Self::InvalidVersion => f.write_str("component version must be strict X.Y.Z"),
            Self::InvalidExecutable => {
                f.write_str("executable must be 'bitty-<name>' without path separators")
            }
            Self::InvalidDigest => f.write_str("sha256 must be 64 lowercase hex characters"),
            Self::InvalidProtocol => {
                f.write_str("protocol must be [min, max] with 1 <= min <= max")
            }
            Self::IdentityMismatch { field } => {
                write!(f, "descriptor {field} does not match this component")
            }
            Self::PlaceholderDigest => {
                f.write_str("descriptor still carries the packaging placeholder digest")
            }
        }
    }
}

impl std::error::Error for DescriptorError {}

impl ComponentDescriptor {
    /// Parses descriptor text (fail closed).
    ///
    /// # Errors
    ///
    /// Returns [`DescriptorError`] for oversize input, malformed syntax,
    /// unknown or duplicate keys, invalid field values, or a missing key.
    pub fn parse(text: &str) -> Result<Self, DescriptorError> {
        if text.len() > MAX_DESCRIPTOR_BYTES {
            return Err(DescriptorError::TooLarge { bytes: text.len() });
        }
        let mut in_component = false;
        let mut seen_table = false;
        let mut name = None;
        let mut version = None;
        let mut protocol = None;
        let mut executable = None;
        let mut sha256 = None;
        for (index, raw_line) in text.lines().enumerate() {
            let line_no = index + 1;
            let syntax = |reason| DescriptorError::Syntax {
                line: line_no,
                reason,
            };
            let line = strip_comment(raw_line).map_err(syntax)?.trim();
            if line.is_empty() {
                continue;
            }
            if line.starts_with('[') {
                if line != "[component]" {
                    return Err(syntax("only the [component] table is allowed"));
                }
                if seen_table {
                    return Err(syntax("duplicate [component] table"));
                }
                seen_table = true;
                in_component = true;
                continue;
            }
            if !in_component {
                return Err(syntax("key outside the [component] table"));
            }
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| syntax("expected key = value"))?;
            let key = key.trim();
            let value = value.trim();
            let slot = match key {
                "name" => &mut name,
                "version" => &mut version,
                "executable" => &mut executable,
                "sha256" => &mut sha256,
                "protocol" => {
                    if protocol.is_some() {
                        return Err(syntax("duplicate key"));
                    }
                    protocol = Some(parse_protocol(value).map_err(syntax)?);
                    continue;
                }
                _ => return Err(syntax("unknown key")),
            };
            if slot.is_some() {
                return Err(syntax("duplicate key"));
            }
            *slot = Some(parse_basic_string(value).map_err(syntax)?);
        }
        let name = name.ok_or(DescriptorError::MissingKey("name"))?;
        let version = version.ok_or(DescriptorError::MissingKey("version"))?;
        let (protocol_min, protocol_max) =
            protocol.ok_or(DescriptorError::MissingKey("protocol"))?;
        let executable = executable.ok_or(DescriptorError::MissingKey("executable"))?;
        let sha256 = sha256.ok_or(DescriptorError::MissingKey("sha256"))?;

        validate_component_name(&name)?;
        validate_version(&version)?;
        if protocol_min == 0 || protocol_min > protocol_max {
            return Err(DescriptorError::InvalidProtocol);
        }
        if executable != format!("{EXECUTABLE_PREFIX}{name}") || !is_plain_file_name(&executable) {
            return Err(DescriptorError::InvalidExecutable);
        }
        if sha256.len() != SHA256_HEX_LEN
            || !sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(DescriptorError::InvalidDigest);
        }
        Ok(Self {
            name,
            version,
            protocol_min,
            protocol_max,
            executable,
            sha256,
        })
    }

    /// Parses descriptor bytes, rejecting oversize input and invalid UTF-8.
    ///
    /// # Errors
    ///
    /// Returns [`DescriptorError`] for the same reasons as
    /// [`ComponentDescriptor::parse`], plus [`DescriptorError::NotUtf8`].
    pub fn parse_bytes(bytes: &[u8]) -> Result<Self, DescriptorError> {
        if bytes.len() > MAX_DESCRIPTOR_BYTES {
            return Err(DescriptorError::TooLarge { bytes: bytes.len() });
        }
        let text = std::str::from_utf8(bytes).map_err(|_| DescriptorError::NotUtf8)?;
        Self::parse(text)
    }

    /// Whether the descriptor's protocol range includes `version`.
    #[must_use]
    pub fn supports_protocol(&self, version: u16) -> bool {
        (self.protocol_min..=self.protocol_max).contains(&version)
    }

    /// Whether the digest is the packaging placeholder.
    #[must_use]
    pub fn has_placeholder_digest(&self) -> bool {
        self.sha256 == PLACEHOLDER_SHA256
    }

    /// Validates that this record describes this component (`execution`,
    /// executable `bitty-execution`, protocol 1).
    ///
    /// # Errors
    ///
    /// Returns [`DescriptorError::IdentityMismatch`] naming the first
    /// disagreeing field, or [`DescriptorError::InvalidProtocol`] when the
    /// range excludes protocol version 1.
    pub fn validate_identity(&self) -> Result<(), DescriptorError> {
        if self.name != COMPONENT_NAME {
            return Err(DescriptorError::IdentityMismatch { field: "name" });
        }
        if self.version != COMPONENT_VERSION {
            return Err(DescriptorError::IdentityMismatch { field: "version" });
        }
        if self.executable != COMPONENT_EXECUTABLE {
            return Err(DescriptorError::IdentityMismatch {
                field: "executable",
            });
        }
        if self.protocol_min != COMPONENT_PROTOCOL_MIN
            || self.protocol_max != COMPONENT_PROTOCOL_MAX
        {
            return Err(DescriptorError::InvalidProtocol);
        }
        Ok(())
    }

    /// Validates the record for installation: identity plus a real digest.
    ///
    /// # Errors
    ///
    /// Returns the identity failures of
    /// [`ComponentDescriptor::validate_identity`] and
    /// [`DescriptorError::PlaceholderDigest`] while the sentinel remains.
    pub fn validate_for_install(&self) -> Result<(), DescriptorError> {
        self.validate_identity()?;
        if self.has_placeholder_digest() {
            return Err(DescriptorError::PlaceholderDigest);
        }
        Ok(())
    }
}

/// Validates a component name against `[a-z][a-z0-9-]{0,31}`.
///
/// # Errors
///
/// Returns [`DescriptorError::InvalidName`] when the grammar is violated.
pub fn validate_component_name(name: &str) -> Result<(), DescriptorError> {
    let bytes = name.as_bytes();
    let valid = !bytes.is_empty()
        && bytes.len() <= 32
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-');
    if valid {
        Ok(())
    } else {
        Err(DescriptorError::InvalidName)
    }
}

/// Strict `X.Y.Z` version check: no leading zeros, no prerelease, no build
/// metadata, each part within `u32`.
fn validate_version(version: &str) -> Result<(), DescriptorError> {
    if version.len() > 64 {
        return Err(DescriptorError::InvalidVersion);
    }
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() != 3 {
        return Err(DescriptorError::InvalidVersion);
    }
    for part in parts {
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return Err(DescriptorError::InvalidVersion);
        }
        if part.len() > 1 && part.starts_with('0') {
            return Err(DescriptorError::InvalidVersion);
        }
        if part.len() > 10 || part.parse::<u32>().is_err() {
            return Err(DescriptorError::InvalidVersion);
        }
    }
    Ok(())
}

/// Non-empty, not `.`/`..`, and free of separators, NUL, and controls.
fn is_plain_file_name(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && !value
            .chars()
            .any(|c| c == '/' || c == '\\' || c == ':' || c.is_control() || c.is_whitespace())
}

fn strip_comment(line: &str) -> Result<&str, &'static str> {
    let mut in_string = false;
    for (index, ch) in line.char_indices() {
        match ch {
            '"' => in_string = !in_string,
            '#' if !in_string => return Ok(&line[..index]),
            _ => {}
        }
    }
    if in_string {
        return Err("unterminated string");
    }
    Ok(line)
}

/// `"..."` with no escapes and no embedded quotes.
fn parse_basic_string(value: &str) -> Result<String, &'static str> {
    let inner = value
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .ok_or("expected a double-quoted string")?;
    if inner.contains('"') || inner.contains('\\') {
        return Err("escapes and embedded quotes are not allowed");
    }
    if inner.chars().any(char::is_control) {
        return Err("control characters are not allowed");
    }
    Ok(inner.to_owned())
}

/// `[min, max]` with two unsigned 16-bit integers.
fn parse_protocol(value: &str) -> Result<(u16, u16), &'static str> {
    let inner = value
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .ok_or("protocol must be an array [min, max]")?;
    let mut parts = inner.split(',').map(str::trim);
    let (Some(min), Some(max), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err("protocol must have exactly two entries");
    };
    let parse = |raw: &str| {
        if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
            return Err("protocol entries must be unsigned integers");
        }
        raw.parse::<u16>()
            .map_err(|_| "protocol entry out of range")
    };
    Ok((parse(min)?, parse(max)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn text(name: &str, version: &str, protocol: &str, executable: &str, sha: &str) -> String {
        format!(
            "# record\n[component]\nname = \"{name}\"   # grammar\nversion = \"{version}\"\nprotocol = {protocol}\nexecutable = \"{executable}\"\nsha256 = \"{sha}\"\n"
        )
    }

    #[test]
    fn parses_the_component_record() {
        let descriptor = ComponentDescriptor::parse(&text(
            "execution",
            "0.0.1",
            "[1, 1]",
            "bitty-execution",
            DIGEST,
        ))
        .expect("valid");
        assert_eq!(descriptor.name, "execution");
        assert_eq!(descriptor.version, "0.0.1");
        assert_eq!((descriptor.protocol_min, descriptor.protocol_max), (1, 1));
        assert!(descriptor.supports_protocol(1));
        assert!(!descriptor.has_placeholder_digest());
        descriptor.validate_for_install().expect("installable");
    }

    #[test]
    fn repository_record_uses_the_placeholder_digest() {
        let descriptor = ComponentDescriptor::parse(&text(
            "execution",
            "0.0.1",
            "[1, 1]",
            "bitty-execution",
            PLACEHOLDER_SHA256,
        ))
        .expect("placeholder parses");
        assert!(descriptor.has_placeholder_digest());
        assert_eq!(
            descriptor.validate_for_install(),
            Err(DescriptorError::PlaceholderDigest)
        );
    }

    #[test]
    fn identity_is_checked() {
        let wrong_name =
            ComponentDescriptor::parse(&text("net", "0.0.1", "[1, 1]", "bitty-net", DIGEST))
                .expect("parses");
        assert_eq!(
            wrong_name.validate_identity(),
            Err(DescriptorError::IdentityMismatch { field: "name" })
        );

        let wrong_protocol = ComponentDescriptor::parse(&text(
            "execution",
            "0.0.1",
            "[2, 3]",
            "bitty-execution",
            DIGEST,
        ))
        .expect("parses");
        assert_eq!(
            wrong_protocol.validate_identity(),
            Err(DescriptorError::InvalidProtocol)
        );

        let wrong_version = ComponentDescriptor::parse(&text(
            "execution",
            "9.9.9",
            "[1, 1]",
            "bitty-execution",
            DIGEST,
        ))
        .expect("parses");
        assert_eq!(
            wrong_version.validate_identity(),
            Err(DescriptorError::IdentityMismatch { field: "version" })
        );
    }

    #[test]
    fn rejects_unknown_duplicate_and_missing_keys() {
        let unknown =
            text("execution", "0.0.1", "[1, 1]", "bitty-execution", DIGEST) + "extra = \"x\"\n";
        assert!(matches!(
            ComponentDescriptor::parse(&unknown),
            Err(DescriptorError::Syntax { .. })
        ));

        let duplicate = "[component]\nname = \"execution\"\nname = \"execution\"\n";
        assert!(matches!(
            ComponentDescriptor::parse(duplicate),
            Err(DescriptorError::Syntax { .. })
        ));

        let missing = "[component]\nname = \"execution\"\n";
        assert_eq!(
            ComponentDescriptor::parse(missing),
            Err(DescriptorError::MissingKey("version"))
        );
    }

    #[test]
    fn rejects_invalid_fields() {
        assert_eq!(
            ComponentDescriptor::parse(&text(
                "Execution",
                "0.0.1",
                "[1, 1]",
                "bitty-Execution",
                DIGEST
            )),
            Err(DescriptorError::InvalidName)
        );
        assert_eq!(
            ComponentDescriptor::parse(&text(
                "execution",
                "0.0",
                "[1, 1]",
                "bitty-execution",
                DIGEST
            )),
            Err(DescriptorError::InvalidVersion)
        );
        assert_eq!(
            ComponentDescriptor::parse(&text(
                "execution",
                "00.0.1",
                "[1, 1]",
                "bitty-execution",
                DIGEST
            )),
            Err(DescriptorError::InvalidVersion)
        );
        assert_eq!(
            ComponentDescriptor::parse(&text(
                "execution",
                "0.0.1",
                "[1, 1]",
                "../bitty-execution",
                DIGEST
            )),
            Err(DescriptorError::InvalidExecutable)
        );
        assert_eq!(
            ComponentDescriptor::parse(&text(
                "execution",
                "0.0.1",
                "[2, 1]",
                "bitty-execution",
                DIGEST
            )),
            Err(DescriptorError::InvalidProtocol)
        );
        assert_eq!(
            ComponentDescriptor::parse(&text(
                "execution",
                "0.0.1",
                "[1, 1]",
                "bitty-execution",
                "ABC"
            )),
            Err(DescriptorError::InvalidDigest)
        );
    }

    #[test]
    fn rejects_oversize_and_non_utf8_input() {
        let mut oversize = String::from("#");
        oversize.push_str(&"x".repeat(MAX_DESCRIPTOR_BYTES));
        assert!(matches!(
            ComponentDescriptor::parse(&oversize),
            Err(DescriptorError::TooLarge { .. })
        ));
        assert_eq!(
            ComponentDescriptor::parse_bytes(&[0xff, 0xfe]),
            Err(DescriptorError::NotUtf8)
        );
    }
}
