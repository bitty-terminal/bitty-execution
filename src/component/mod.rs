//! Executable-component boundary for the execution supervisor.
//!
//! The crate still exposes the in-process [`JobRegistry`](crate::JobRegistry)
//! for Core's linked use; this module adds the installable form required by
//! the component split (bitty#2494): a validated `bitty-component.toml`, a
//! bounded v2 stdio wire protocol, and a server binary wrapping the same
//! supervisor. It carries no installer, no download source, no capability
//! policy, and no platform packaging logic beyond the repository script.
//!
//! ```text
//! Core host client  ──stdio frames──▶  bitty-execution  ──▶  JobRegistry
//!   (remaining work)                    (this module)        (already landed)
//! ```

pub mod descriptor;
pub mod protocol;
pub mod server;

/// Component version reported by `HelloAck`, `--version`, and the descriptor.
pub const COMPONENT_VERSION: &str = env!("CARGO_PKG_VERSION");

pub use descriptor::{
    COMPONENT_EXECUTABLE, COMPONENT_NAME, COMPONENT_PROTOCOL_MAX, COMPONENT_PROTOCOL_MIN,
    ComponentDescriptor, DescriptorError, MAX_DESCRIPTOR_BYTES, PLACEHOLDER_SHA256,
};
pub use protocol::{
    ErrorKind, ExitKind, FrameReader, MAX_FRAME_BYTES, MAX_JOBS, MAX_OUTPUT_CHUNK_BYTES,
    MAX_OUTPUT_READ_BYTES, Message, PROTOCOL_VERSION, Stream, TerminateMode, TerminateOutcome,
    WireError, decode_message, encode_frame, encode_message, negotiate, write_frame,
};
pub use server::{
    SERVER_EXIT_INTERNAL, SERVER_EXIT_OK, SERVER_EXIT_PROTOCOL, SHUTDOWN_WAIT, serve, serve_stdio,
};
