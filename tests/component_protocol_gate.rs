//! Release ABI gate for the executable component (issue #21).
//!
//! The descriptor is a claim about the wire protocol the binary speaks. A
//! descriptor that drifts from the codec either refuses a host that could
//! work or admits a host that will misread every frame. These tests pin both
//! sides:
//!
//! - the repository descriptor declares exactly the codec's supported range;
//! - the codec is compared with Core's shared component ABI
//!   (`bitty-network-wire` v1), which `execution` deliberately does not
//!   claim, so a change on either side fails here instead of silently
//!   changing installability;
//! - a real v1 `Hello` encoded by `bitty-network-wire` is refused before
//!   work is accepted, while a v2 `Hello` completes the handshake.

use std::io::{self, Cursor, Write};
use std::sync::{Arc, Mutex};

use bitty_execution::component::descriptor::ComponentDescriptor;
use bitty_execution::component::protocol::{
    CONNECTION_ID, ErrorKind, FrameReader, Message, PROTOCOL_VERSION, supported_protocol_range,
    write_frame,
};
use bitty_execution::component::server::{
    COMPONENT_VERSION, SERVER_EXIT_OK, SERVER_EXIT_PROTOCOL, serve,
};
use bitty_network_wire::{
    ErrorKind as CoreSharedErrorKind, FrameReader as CoreSharedFrameReader,
    Message as CoreSharedMessage, PROTOCOL_VERSION as CORE_SHARED_PROTOCOL_VERSION,
    write_frame as write_core_shared_frame,
};

const RECORD: &str = include_str!("../bitty-component.toml");

/// Append-only writer shared with the server so the test can inspect the
/// frames it emitted without a real pipe.
#[derive(Clone, Default)]
struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

impl SharedBuffer {
    fn bytes(&self) -> Vec<u8> {
        self.0.lock().expect("shared buffer lock").clone()
    }
}

impl Write for SharedBuffer {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .map_err(|_| io::Error::other("shared buffer poisoned"))?
            .extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn run_server(input: Vec<u8>) -> (u8, Vec<u8>) {
    let writer = SharedBuffer::default();
    let code = serve(Cursor::new(input), writer.clone());
    (code, writer.bytes())
}

fn decode(bytes: &[u8]) -> Vec<Message> {
    let mut reader = FrameReader::new(bytes);
    let mut messages = Vec::new();
    while let Some(message) = reader.read_message().expect("decode emitted frames") {
        messages.push(message);
    }
    messages
}

#[test]
fn descriptor_protocol_gate_matches_the_linked_codec_and_core_shared_abi() {
    let descriptor = ComponentDescriptor::parse(RECORD).expect("repository descriptor parses");
    let (min, max) = supported_protocol_range();

    assert_eq!(
        (descriptor.protocol_min, descriptor.protocol_max),
        (min, max),
        "bitty-component.toml must declare exactly the linked codec's supported range"
    );
    assert_eq!(
        (min, max),
        (PROTOCOL_VERSION, PROTOCOL_VERSION),
        "the descriptor gate must compare against the codec constant the binary links"
    );

    // This assertion is the release gate, not a compatibility claim: when
    // Core's shared component ABI moves, the descriptor decision in issue
    // #21 must be re-evaluated against the new install path.
    assert_eq!(
        CORE_SHARED_PROTOCOL_VERSION, 1,
        "Core's shared component ABI moved to v{CORE_SHARED_PROTOCOL_VERSION}; re-evaluate the \
         execution descriptor, the Core install/inventory gate, and the issue #21 decision"
    );
    assert!(
        !(min..=max).contains(&CORE_SHARED_PROTOCOL_VERSION),
        "execution protocol [{min}, {max}] must not claim Core's shared component ABI \
         v{CORE_SHARED_PROTOCOL_VERSION}; the install gate would then admit a v1 host that \
         cannot decode this component's frames"
    );

    assert_eq!(
        bitty_execution::component::negotiate(
            CORE_SHARED_PROTOCOL_VERSION,
            CORE_SHARED_PROTOCOL_VERSION
        ),
        None,
        "a v1-only handshake must not negotiate"
    );
    assert_eq!(
        bitty_execution::component::negotiate(PROTOCOL_VERSION, PROTOCOL_VERSION),
        Some(PROTOCOL_VERSION),
        "the binary must negotiate its linked protocol"
    );
}

#[test]
fn v1_only_client_is_refused_and_the_v1_codec_reads_component_lost() {
    let mut input = Vec::new();
    write_core_shared_frame(
        &mut input,
        &CoreSharedMessage::Hello {
            min: CORE_SHARED_PROTOCOL_VERSION,
            max: CORE_SHARED_PROTOCOL_VERSION,
            component: "execution".to_owned(),
            version: "core-v1-gate".to_owned(),
        },
    )
    .expect("encode a real v1 hello");

    let (code, output) = run_server(input);

    assert_eq!(code, SERVER_EXIT_PROTOCOL);

    // The component always writes its own v2 frame. A v2 decoder sees the
    // typed connection-level protocol refusal.
    assert_eq!(
        decode(&output),
        vec![Message::Error {
            request: CONNECTION_ID,
            kind: ErrorKind::Protocol,
            message: "protocol version unsupported".to_owned(),
        }],
        "a v2 decoder sees the component's typed protocol refusal"
    );

    // The pinned v1 codec reads the same kind byte as `ComponentLost`, not
    // `Protocol`: v1 code 6 is `Protocol`, v2 code 7 is `Protocol`, and v1
    // code 7 is `ComponentLost`. Pin the actual observation so the docs and
    // the release decision cannot claim a v1 host sees `protocol` (issue
    // #21 review).
    assert_eq!(CoreSharedErrorKind::Protocol.code(), 6);
    assert_eq!(CoreSharedErrorKind::ComponentLost.code(), 7);
    let mut v1 = CoreSharedFrameReader::new(output.as_slice());
    assert_eq!(
        v1.read_message()
            .expect("the real v1 codec decodes the refusal frame"),
        Some(CoreSharedMessage::Error {
            id: CONNECTION_ID,
            kind: CoreSharedErrorKind::ComponentLost,
            message: "protocol version unsupported".to_owned(),
        }),
        "a v1 decoder observes component_lost (code 7), not protocol (code 6)"
    );
    assert_eq!(
        v1.read_message().expect("clean EOF after the refusal"),
        None
    );
}

#[test]
fn a_v2_handshake_is_accepted_and_acknowledged() {
    let mut input = Vec::new();
    write_frame(
        &mut input,
        &Message::Hello {
            min: PROTOCOL_VERSION,
            max: PROTOCOL_VERSION,
            component: "execution".to_owned(),
            version: "gate-v2".to_owned(),
        },
    )
    .expect("encode a v2 hello");

    let (code, output) = run_server(input);

    assert_eq!(code, SERVER_EXIT_OK);
    assert_eq!(
        decode(&output),
        vec![Message::HelloAck {
            protocol: PROTOCOL_VERSION,
            component: "execution".to_owned(),
            version: COMPONENT_VERSION.to_owned(),
        }],
        "the linked protocol must complete the handshake"
    );
}
