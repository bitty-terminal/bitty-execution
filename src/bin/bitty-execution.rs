//! `bitty-execution` executable component entry point.
//!
//! A bare invocation serves the v2 stdio protocol
//! ([`bitty_execution::component`]); `--version` reports the component
//! version used by the descriptor and release tag, and `--check-manifest`
//! validates a packaged `bitty-component.toml` with the same fail-closed
//! parser the component ships. The binary carries no installer and never
//! publishes itself.

#![forbid(unsafe_code)]

use std::fs::File;
use std::io::Read as _;
use std::process::ExitCode;

use bitty_execution::component::descriptor::{ComponentDescriptor, MAX_DESCRIPTOR_BYTES};
use bitty_execution::component::server::{COMPONENT_VERSION, serve_stdio};

/// Usage refusal (the operator asked for something this binary does not
/// serve); mirrors the other component binaries' `EXIT_REFUSED`.
const EXIT_REFUSED: u8 = 2;

fn usage() {
    eprintln!(
        "usage: bitty-execution [--version | --check-manifest PATH]\n\
         \n\
         With no arguments, serves the execution component protocol v2 on\n\
         stdin/stdout. stderr carries diagnostics only."
    );
}

fn check_manifest(path: &std::ffi::OsStr) -> Result<(), String> {
    let file = File::open(path).map_err(|error| format!("cannot open descriptor: {error}"))?;
    let mut bytes = Vec::new();
    file.take((MAX_DESCRIPTOR_BYTES as u64) + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read descriptor: {error}"))?;
    let descriptor = ComponentDescriptor::parse_bytes(&bytes)
        .map_err(|error| format!("invalid descriptor: {error}"))?;
    descriptor
        .validate_for_install()
        .map_err(|error| format!("invalid descriptor: {error}"))?;
    println!(
        "ok {} {} protocol [{}, {}] {}",
        descriptor.name,
        descriptor.version,
        descriptor.protocol_min,
        descriptor.protocol_max,
        descriptor.executable
    );
    Ok(())
}

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    match (args.next(), args.next(), args.next()) {
        (None, _, _) => ExitCode::from(serve_stdio()),
        (Some(flag), None, _) if flag == "--version" || flag == "-V" => {
            println!("bitty-execution {COMPONENT_VERSION}");
            ExitCode::SUCCESS
        }
        (Some(flag), None, _) if flag == "--help" || flag == "-h" => {
            usage();
            ExitCode::SUCCESS
        }
        (Some(flag), Some(path), None) if flag == "--check-manifest" => {
            match check_manifest(&path) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("bitty-execution: {error}");
                    ExitCode::from(EXIT_REFUSED)
                }
            }
        }
        _ => {
            usage();
            ExitCode::from(EXIT_REFUSED)
        }
    }
}
