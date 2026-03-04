// Copyright (C) 2019-2024 The RustyBGP Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use bytes::BytesMut;
use rustybgp_packet::bgp::{Message, PeerCodecBuilder};
use rustybgp_packet::{BgpError, BgpFramer};

// ─── helpers ────────────────────────────────────────────────────────────────

/// Build a raw BGP KEEPALIVE message (19 bytes).
fn keepalive_bytes() -> Vec<u8> {
    let mut buf = vec![0xff; 16];
    buf.extend_from_slice(&19u16.to_be_bytes());
    buf.push(4); // KEEPALIVE
    buf
}

/// Build a BGP message with given type and body.
fn bgp_msg(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let total = (19 + body.len()) as u16;
    let mut buf = vec![0xff; 16];
    buf.extend_from_slice(&total.to_be_bytes());
    buf.push(msg_type);
    buf.extend_from_slice(body);
    buf
}

fn default_framer() -> BgpFramer {
    BgpFramer::new(PeerCodecBuilder::new().build())
}

// ─── basic framing tests ─────────────────────────────────────────────────────

#[test]
fn framer_empty_buffer() {
    // Empty buffer → Ok(None): not enough bytes for a header
    let mut framer = default_framer();
    let mut buf = BytesMut::new();
    assert!(matches!(framer.try_parse(&mut buf), Ok(None)));
    assert_eq!(buf.len(), 0); // buffer unchanged
}

#[test]
fn framer_incomplete_header() {
    // Partial header (< 19 bytes) → Ok(None)
    let mut framer = default_framer();
    let mut buf = BytesMut::from(&[0xff; 10][..]);
    assert!(matches!(framer.try_parse(&mut buf), Ok(None)));
    assert_eq!(buf.len(), 10); // buffer unchanged
}

#[test]
fn framer_complete_keepalive() {
    // Exactly one complete KEEPALIVE → Ok(Some(Keepalive))
    let mut framer = default_framer();
    let mut buf = BytesMut::from(keepalive_bytes().as_slice());
    let result = framer.try_parse(&mut buf).unwrap();
    assert!(matches!(result, Some(Message::Keepalive)));
    assert_eq!(buf.len(), 0); // consumed
}

#[test]
fn framer_partial_message() {
    // First chunk: only 10 bytes of a 19-byte KEEPALIVE
    let bytes = keepalive_bytes();
    let mut framer = default_framer();
    let mut buf = BytesMut::from(&bytes[..10]);
    assert!(matches!(framer.try_parse(&mut buf), Ok(None)));
    assert_eq!(buf.len(), 10); // not consumed

    // Second chunk: add the remaining 9 bytes
    buf.extend_from_slice(&bytes[10..]);
    let result = framer.try_parse(&mut buf).unwrap();
    assert!(matches!(result, Some(Message::Keepalive)));
    assert_eq!(buf.len(), 0);
}

#[test]
fn framer_two_messages_in_buffer() {
    // Two KEEPALIVEs concatenated in one buffer
    let mut framer = default_framer();
    let mut buf = BytesMut::new();
    buf.extend_from_slice(&keepalive_bytes());
    buf.extend_from_slice(&keepalive_bytes());
    assert_eq!(buf.len(), 38);

    // First parse: consumes one message
    let r1 = framer.try_parse(&mut buf).unwrap();
    assert!(matches!(r1, Some(Message::Keepalive)));
    assert_eq!(buf.len(), 19); // one message remains

    // Second parse: consumes second message
    let r2 = framer.try_parse(&mut buf).unwrap();
    assert!(matches!(r2, Some(Message::Keepalive)));
    assert_eq!(buf.len(), 0);

    // Third parse: empty
    assert!(matches!(framer.try_parse(&mut buf), Ok(None)));
}

#[test]
fn framer_message_then_partial() {
    // One complete KEEPALIVE followed by 5 bytes of another
    let mut framer = default_framer();
    let mut buf = BytesMut::new();
    buf.extend_from_slice(&keepalive_bytes());
    buf.extend_from_slice(&keepalive_bytes()[..5]);
    assert_eq!(buf.len(), 24);

    // First parse: succeeds
    let r1 = framer.try_parse(&mut buf).unwrap();
    assert!(matches!(r1, Some(Message::Keepalive)));
    assert_eq!(buf.len(), 5);

    // Second parse: partial → None
    assert!(matches!(framer.try_parse(&mut buf), Ok(None)));
    assert_eq!(buf.len(), 5); // partial bytes preserved
}

// ─── framing error cases ─────────────────────────────────────────────────────

#[test]
fn framer_header_length_below_minimum() {
    // Header claims length=10 (< minimum 19) → BadMessageLength
    let mut buf: Vec<u8> = vec![0xff; 16];
    buf.extend_from_slice(&10u16.to_be_bytes()); // too short
    buf.push(4); // KEEPALIVE

    let mut framer = default_framer();
    let mut bmut = BytesMut::from(buf.as_slice());
    match framer.try_parse(&mut bmut) {
        Err(rustybgp_packet::Error::Bgp(BgpError::BadMessageLength { .. })) => {}
        other => panic!("expected BadMessageLength, got {:?}", other.map(|_| "ok")),
    }
}

#[test]
fn framer_header_length_exceeds_max() {
    // Header claims length > max_message_length (4096) → BadMessageLength
    let mut buf: Vec<u8> = vec![0xff; 16];
    buf.extend_from_slice(&5000u16.to_be_bytes()); // > 4096
    buf.push(4); // KEEPALIVE

    let mut framer = default_framer();
    let mut bmut = BytesMut::from(buf.as_slice());
    match framer.try_parse(&mut bmut) {
        Err(rustybgp_packet::Error::Bgp(BgpError::BadMessageLength { .. })) => {}
        other => panic!("expected BadMessageLength, got {:?}", other.map(|_| "ok")),
    }
}

#[test]
fn framer_unknown_message_type() {
    // Type=99 → BadMessageType (returned from parse_message)
    let buf = bgp_msg(99, &[]);
    let mut framer = default_framer();
    let mut bmut = BytesMut::from(buf.as_slice());
    match framer.try_parse(&mut bmut) {
        Err(rustybgp_packet::Error::Bgp(BgpError::BadMessageType { .. })) => {}
        other => panic!("expected BadMessageType, got {:?}", other.map(|_| "ok")),
    }
}

// ─── mixed message types ──────────────────────────────────────────────────────

#[test]
fn framer_mixed_message_types() {
    // KEEPALIVE followed by ROUTE-REFRESH for IPv4
    let mut framer = BgpFramer::new(
        PeerCodecBuilder::new()
            .families(vec![rustybgp_packet::Family::IPV4])
            .build(),
    );
    let mut buf = BytesMut::new();

    // KEEPALIVE
    buf.extend_from_slice(&keepalive_bytes());
    // ROUTE-REFRESH for IPv4: AFI=1, reserved=0, SAFI=1
    buf.extend_from_slice(&bgp_msg(5, &[0x00, 0x01, 0x00, 0x01]));

    let m1 = framer.try_parse(&mut buf).unwrap();
    assert!(matches!(m1, Some(Message::Keepalive)));

    let m2 = framer.try_parse(&mut buf).unwrap();
    assert!(matches!(
        m2,
        Some(Message::RouteRefresh { family })
        if family == rustybgp_packet::Family::IPV4
    ));

    assert!(matches!(framer.try_parse(&mut buf), Ok(None)));
}
