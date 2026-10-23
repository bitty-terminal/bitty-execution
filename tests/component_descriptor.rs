//! Component descriptor record and binary identity checks.
//!
//! The repository's `bitty-component.toml` is the canonical record packaging
//! renders per target; these tests keep the parser, the record, the crate
//! version, and the binary name in agreement.

use bitty_execution::component::descriptor::{
    COMPONENT_EXECUTABLE, COMPONENT_NAME, COMPONENT_PROTOCOL_MAX, COMPONENT_PROTOCOL_MIN,
    ComponentDescriptor, PLACEHOLDER_SHA256,
};
use bitty_execution::component::server::{
    COMPONENT_VERSION, SERVER_EXIT_INTERNAL, SERVER_EXIT_OK, SERVER_EXIT_PROTOCOL,
};
use bitty_execution::component::{MAX_JOBS, PROTOCOL_VERSION};

const RECORD: &str = include_str!("../bitty-component.toml");

#[test]
fn repository_record_matches_the_component_identity() {
    assert_eq!(COMPONENT_VERSION, env!("CARGO_PKG_VERSION"));
    let descriptor = ComponentDescriptor::parse(RECORD).expect("repository record parses");
    assert_eq!(descriptor.name, COMPONENT_NAME);
    assert_eq!(descriptor.version, COMPONENT_VERSION);
    assert_eq!(
        (descriptor.protocol_min, descriptor.protocol_max),
        (COMPONENT_PROTOCOL_MIN, COMPONENT_PROTOCOL_MAX)
    );
    assert_eq!(descriptor.executable, COMPONENT_EXECUTABLE);
    assert_eq!(descriptor.sha256, PLACEHOLDER_SHA256);
    assert!(descriptor.has_placeholder_digest());
    descriptor
        .validate_identity()
        .expect("identity matches the binary");
    assert_eq!(
        descriptor.validate_for_install(),
        Err(bitty_execution::component::DescriptorError::PlaceholderDigest)
    );
}

#[test]
fn packaged_digest_is_installable() {
    let rendered = RECORD.replace(PLACEHOLDER_SHA256, &"ab".repeat(32));
    let descriptor = ComponentDescriptor::parse(&rendered).expect("rendered record parses");
    descriptor
        .validate_for_install()
        .expect("real digest is installable");
    assert!(!descriptor.has_placeholder_digest());
}

#[test]
fn protocol_and_capacity_claims_are_consistent() {
    assert_eq!(PROTOCOL_VERSION, 2);
    assert_eq!(COMPONENT_PROTOCOL_MIN, PROTOCOL_VERSION);
    assert_eq!(COMPONENT_PROTOCOL_MAX, PROTOCOL_VERSION);
    assert_eq!(MAX_JOBS, bitty_ipc::execution::MAX_TRACKED_EXECUTIONS);
}

#[test]
fn server_exit_codes_are_stable() {
    assert_eq!(SERVER_EXIT_OK, 0);
    assert_eq!(SERVER_EXIT_PROTOCOL, 3);
    assert_eq!(SERVER_EXIT_INTERNAL, 4);
}

#[test]
fn binary_reports_its_version() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bitty-execution"))
        .arg("--version")
        .output()
        .expect("run --version");
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        format!("bitty-execution {COMPONENT_VERSION}")
    );
}

#[test]
fn binary_validates_packaged_and_rejects_placeholder_manifests() {
    let binary = env!("CARGO_BIN_EXE_bitty-execution");
    let path = std::env::temp_dir().join(format!(
        "bitty-execution-manifest-{}-{}.toml",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos())
    ));
    let rendered = RECORD.replace(PLACEHOLDER_SHA256, &"cd".repeat(32));
    std::fs::write(&path, rendered).expect("write rendered descriptor");

    let accepted = std::process::Command::new(binary)
        .arg("--check-manifest")
        .arg(&path)
        .output()
        .expect("run --check-manifest");
    assert!(accepted.status.success(), "{accepted:?}");
    assert!(String::from_utf8_lossy(&accepted.stdout).starts_with("ok execution 0.0.1"));
    let _ = std::fs::remove_file(&path);

    let repository = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("bitty-component.toml");
    let rejected = std::process::Command::new(binary)
        .arg("--check-manifest")
        .arg(repository)
        .output()
        .expect("run --check-manifest on repository record");
    assert_eq!(rejected.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&rejected.stderr).contains("placeholder"),
        "{rejected:?}"
    );
}
