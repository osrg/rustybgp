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

use bytes::{BufMut, BytesMut};
use rustybgp_packet::bgp::{Message, PeerCodecBuilder};
use rustybgp_packet::{BgpError, BgpFramer, Family};

// ─── helpers ────────────────────────────────────────────────────────────────

fn bgp_msg(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let total = (19 + body.len()) as u16;
    let mut buf = vec![0xff; 16];
    buf.extend_from_slice(&total.to_be_bytes());
    buf.push(msg_type);
    buf.extend_from_slice(body);
    buf
}

fn default_codec() -> rustybgp_packet::bgp::PeerCodec {
    PeerCodecBuilder::new().build()
}

fn round_trip(msg: &Message) -> Message {
    let mut framer = BgpFramer::new(default_codec());
    let mut buf = BytesMut::new();
    framer.encode_to(msg, &mut buf).unwrap();
    framer.inner_mut().parse_message(&buf).unwrap()
}

// ─── KEEPALIVE ───────────────────────────────────────────────────────────────

#[test]
fn keepalive_parse() {
    // KEEPALIVE: only the 19-byte header, no body
    let buf = bgp_msg(4, &[]);
    let mut codec = default_codec();
    assert!(matches!(
        codec.parse_message(&buf).unwrap(),
        Message::Keepalive
    ));
}

#[test]
fn keepalive_round_trip() {
    match round_trip(&Message::Keepalive) {
        Message::Keepalive => {}
        _ => panic!("expected Keepalive"),
    }
}

// ─── NOTIFICATION ────────────────────────────────────────────────────────────

#[test]
fn notification_parse() {
    // NOTIFICATION: code=1 (Header Error), subcode=2 (Bad Message Length), data=[0x00, 0x13]
    let body: &[u8] = &[0x01, 0x02, 0x00, 0x13];
    let buf = bgp_msg(3, body);
    let mut codec = default_codec();
    match codec.parse_message(&buf).unwrap() {
        Message::Notification {
            code,
            subcode,
            data,
        } => {
            assert_eq!(code, 1);
            assert_eq!(subcode, 2);
            assert_eq!(data, vec![0x00, 0x13]);
        }
        _ => panic!("expected Notification"),
    }
}

#[test]
fn notification_parse_no_data() {
    // NOTIFICATION with no additional data (code=4, Hold Timer Expired)
    let body: &[u8] = &[0x04, 0x00];
    let buf = bgp_msg(3, body);
    let mut codec = default_codec();
    match codec.parse_message(&buf).unwrap() {
        Message::Notification {
            code,
            subcode,
            data,
        } => {
            assert_eq!(code, 4);
            assert_eq!(subcode, 0);
            assert!(data.is_empty());
        }
        _ => panic!("expected Notification"),
    }
}

#[test]
fn notification_round_trip() {
    let original = Message::Notification {
        code: 3,
        subcode: 1,
        data: vec![0xDE, 0xAD, 0xBE, 0xEF],
    };
    match round_trip(&original) {
        Message::Notification {
            code,
            subcode,
            data,
        } => {
            assert_eq!(code, 3);
            assert_eq!(subcode, 1);
            assert_eq!(data, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        }
        _ => panic!("expected Notification"),
    }
}

// ─── BgpError ↔ Notification mapping ─────────────────────────────────────────

#[test]
fn bgerror_from_notification_known_codes() {
    // Verify BgpError::from_notification maps known codes correctly
    assert!(matches!(
        BgpError::from_notification(1, 2, vec![]),
        BgpError::BadMessageLength { .. }
    ));
    assert!(matches!(
        BgpError::from_notification(1, 3, vec![]),
        BgpError::BadMessageType { .. }
    ));
    assert!(matches!(
        BgpError::from_notification(2, 0, vec![]),
        BgpError::OpenMalformed
    ));
    assert!(matches!(
        BgpError::from_notification(2, 4, vec![]),
        BgpError::OpenUnsupportedOptionalParameter { .. }
    ));
    assert!(matches!(
        BgpError::from_notification(3, 1, vec![]),
        BgpError::UpdateMalformedAttributeList
    ));
    assert!(matches!(
        BgpError::from_notification(7, 1, vec![]),
        BgpError::RouteRefreshInvalidLength { .. }
    ));
}

#[test]
fn bgerror_from_notification_unknown_code() {
    let err = BgpError::from_notification(99, 0, vec![0xAB]);
    assert!(matches!(
        err,
        BgpError::Other {
            code: 99,
            subcode: 0,
            ..
        }
    ));
}

#[test]
fn bgerror_notification_code_round_trip() {
    // notification_code/subcode/data round-trips correctly
    let err = BgpError::BadMessageLength {
        data: vec![0x10, 0x00],
    };
    assert_eq!(err.notification_code(), 1);
    assert_eq!(err.notification_subcode(), 2);
    assert_eq!(err.notification_data(), &[0x10, 0x00]);

    let err = BgpError::FsmUnexpectedState { state: 3 };
    assert_eq!(err.notification_code(), 5);
    assert_eq!(err.notification_subcode(), 3);
}

// ─── ROUTE-REFRESH ───────────────────────────────────────────────────────────

#[test]
fn route_refresh_ipv4() {
    // ROUTE-REFRESH: AFI=1 (IPv4), reserved=0, SAFI=1 (unicast)
    let body: &[u8] = &[0x00, 0x01, 0x00, 0x01];
    let buf = bgp_msg(5, body);
    let mut codec = default_codec();
    match codec.parse_message(&buf).unwrap() {
        Message::RouteRefresh { family } => {
            assert_eq!(family, Family::IPV4);
        }
        _ => panic!("expected RouteRefresh"),
    }
}

#[test]
fn route_refresh_ipv6() {
    // ROUTE-REFRESH: AFI=2 (IPv6), reserved=0, SAFI=1 (unicast)
    let body: &[u8] = &[0x00, 0x02, 0x00, 0x01];
    let buf = bgp_msg(5, body);
    let mut codec = default_codec();
    match codec.parse_message(&buf).unwrap() {
        Message::RouteRefresh { family } => {
            assert_eq!(family, Family::IPV6);
        }
        _ => panic!("expected RouteRefresh"),
    }
}

#[test]
fn route_refresh_round_trip() {
    let original = Message::RouteRefresh {
        family: Family::IPV4,
    };
    match round_trip(&original) {
        Message::RouteRefresh { family } => {
            assert_eq!(family, Family::IPV4);
        }
        _ => panic!("expected RouteRefresh"),
    }
}

#[test]
fn route_refresh_too_long() {
    // Extra byte in ROUTE-REFRESH body → RouteRefreshInvalidLength
    let body: &[u8] = &[0x00, 0x01, 0x00, 0x01, 0xFF]; // 5 bytes instead of 4
    let buf = bgp_msg(5, body);
    let mut codec = default_codec();
    match codec.parse_message(&buf) {
        Err(rustybgp_packet::Error::Bgp(BgpError::RouteRefreshInvalidLength { .. })) => {}
        Ok(_) => panic!("expected error"),
        Err(e) => panic!("unexpected error: {}", e),
    }
}

// ─── Header error cases ──────────────────────────────────────────────────────

#[test]
fn bad_message_type() {
    // Type=99 is unknown → BadMessageType
    let buf = bgp_msg(99, &[]);
    let mut codec = default_codec();
    match codec.parse_message(&buf) {
        Err(rustybgp_packet::Error::Bgp(BgpError::BadMessageType { .. })) => {}
        Ok(_) => panic!("expected error"),
        Err(e) => panic!("unexpected error: {}", e),
    }
}

#[test]
fn parse_message_too_short_buffer() {
    // parse_message with a buffer shorter than HEADER_LENGTH (19 bytes)
    // triggers BadMessageLength (buffer is too short even for the header)
    let buf: Vec<u8> = vec![0xff; 10]; // 10 bytes < HEADER_LENGTH=19
    let mut codec = default_codec();
    match codec.parse_message(&buf) {
        Err(rustybgp_packet::Error::Bgp(BgpError::BadMessageLength { .. })) => {}
        Ok(_) => panic!("expected error"),
        Err(e) => panic!("unexpected error: {}", e),
    }
}

#[test]
fn framer_bad_header_length() {
    // BgpFramer detects when the header's length field is below the minimum.
    // parse_message doesn't check the header length field — that's framing's job.
    let mut buf = bytes::BytesMut::with_capacity(19);
    buf.extend_from_slice(&[0xff; 16]);
    buf.extend_from_slice(&10u16.to_be_bytes()); // length field = 10 (< minimum 19)
    buf.put_u8(4); // KEEPALIVE
    let mut framer = BgpFramer::new(PeerCodecBuilder::new().build());
    match framer.try_parse(&mut buf) {
        Err(rustybgp_packet::Error::Bgp(BgpError::BadMessageLength { .. })) => {}
        Ok(_) => panic!("expected error"),
        Err(e) => panic!("unexpected error: {}", e),
    }
}
