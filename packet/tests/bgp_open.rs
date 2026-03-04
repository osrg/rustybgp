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
use rustybgp_packet::bgp::{Capability, Message, Open, PeerCodecBuilder};
use rustybgp_packet::{BgpError, BgpFramer, Family, HoldTime};
use std::net::Ipv4Addr;

// ─── helpers ────────────────────────────────────────────────────────────────

/// Build a raw BGP message: 16-byte marker + 2-byte length + 1-byte type + body.
fn bgp_msg(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let total = (19 + body.len()) as u16;
    let mut buf = vec![0xff; 16];
    buf.extend_from_slice(&total.to_be_bytes());
    buf.push(msg_type);
    buf.extend_from_slice(body);
    buf
}

/// Build a raw BGP OPEN body.
fn open_body(as2: u16, holdtime: u16, router_id: Ipv4Addr, params: &[u8]) -> Vec<u8> {
    let mut body = vec![4u8]; // version
    body.extend_from_slice(&as2.to_be_bytes());
    body.extend_from_slice(&holdtime.to_be_bytes());
    body.extend_from_slice(&u32::from(router_id).to_be_bytes());
    body.push(params.len() as u8);
    body.extend_from_slice(params);
    body
}

/// Wrap capabilities in an optional parameter of type 2 (capability).
fn capability_param(cap_bytes: &[u8]) -> Vec<u8> {
    let mut p = vec![2u8, cap_bytes.len() as u8];
    p.extend_from_slice(cap_bytes);
    p
}

fn default_codec() -> PeerCodecBuilder {
    PeerCodecBuilder::new()
}

// ─── parse tests ────────────────────────────────────────────────────────────

#[test]
fn open_minimal_parse() {
    // OPEN with no optional parameters
    let buf = bgp_msg(1, &open_body(65001, 90, "192.0.2.1".parse().unwrap(), &[]));
    let mut codec = default_codec().build();
    match codec.parse_message(&buf).unwrap() {
        Message::Open(Open {
            as_number,
            holdtime,
            router_id,
            capability,
        }) => {
            assert_eq!(as_number, 65001);
            assert_eq!(holdtime, HoldTime::new(90).unwrap());
            assert_eq!(
                router_id,
                u32::from("192.0.2.1".parse::<Ipv4Addr>().unwrap())
            );
            assert!(capability.is_empty());
        }
        _ => panic!("expected OPEN"),
    }
}

#[test]
fn open_with_multiprotocol_ipv4() {
    // Capability: code=1 (MultiProtocol), len=4, AFI=1 (IPv4), reserved=0, SAFI=1 (unicast)
    let cap: &[u8] = &[0x01, 0x04, 0x00, 0x01, 0x00, 0x01];
    let params = capability_param(cap);
    let buf = bgp_msg(
        1,
        &open_body(65001, 90, "192.0.2.1".parse().unwrap(), &params),
    );

    let mut codec = default_codec().build();
    match codec.parse_message(&buf).unwrap() {
        Message::Open(Open { capability, .. }) => {
            assert_eq!(capability.len(), 1);
            assert!(matches!(
                &capability[0],
                Capability::MultiProtocol(f) if *f == Family::IPV4
            ));
        }
        _ => panic!("expected OPEN"),
    }
}

#[test]
fn open_with_multiprotocol_ipv6() {
    // Capability: code=1 (MultiProtocol), len=4, AFI=2 (IPv6), reserved=0, SAFI=1 (unicast)
    let cap: &[u8] = &[0x01, 0x04, 0x00, 0x02, 0x00, 0x01];
    let params = capability_param(cap);
    let buf = bgp_msg(
        1,
        &open_body(65001, 90, "192.0.2.1".parse().unwrap(), &params),
    );

    let mut codec = default_codec().build();
    match codec.parse_message(&buf).unwrap() {
        Message::Open(Open { capability, .. }) => {
            assert_eq!(capability.len(), 1);
            assert!(matches!(
                &capability[0],
                Capability::MultiProtocol(f) if *f == Family::IPV6
            ));
        }
        _ => panic!("expected OPEN"),
    }
}

#[test]
fn open_with_four_octet_asn() {
    // 4-byte AS: 2-byte field = TRANS_ASN (23456), 4-byte AS in capability
    // Capability: code=65 (4-octet ASN), len=4, ASN=65536
    let four_byte_asn: u32 = 131072; // 2 * 65536
    let mut cap = vec![0x41u8, 0x04]; // code=65, len=4
    cap.extend_from_slice(&four_byte_asn.to_be_bytes());
    let params = capability_param(&cap);
    let buf = bgp_msg(
        1,
        &open_body(23456, 90, "192.0.2.1".parse().unwrap(), &params),
    );

    let mut codec = default_codec().build();
    match codec.parse_message(&buf).unwrap() {
        Message::Open(Open {
            as_number,
            capability,
            ..
        }) => {
            // When 2-byte AS = TRANS_ASN, the 4-byte ASN capability provides the real AS
            assert_eq!(as_number, four_byte_asn);
            assert!(
                capability
                    .iter()
                    .any(|c| matches!(c, Capability::FourOctetAsNumber(n) if *n == four_byte_asn))
            );
        }
        _ => panic!("expected OPEN"),
    }
}

#[test]
fn open_with_route_refresh() {
    // Capability: code=2 (RouteRefresh), len=0
    let cap: &[u8] = &[0x02, 0x00];
    let params = capability_param(cap);
    let buf = bgp_msg(
        1,
        &open_body(65001, 90, "192.0.2.1".parse().unwrap(), &params),
    );

    let mut codec = default_codec().build();
    match codec.parse_message(&buf).unwrap() {
        Message::Open(Open { capability, .. }) => {
            assert!(
                capability
                    .iter()
                    .any(|c| matches!(c, Capability::RouteRefresh))
            );
        }
        _ => panic!("expected OPEN"),
    }
}

// ─── round-trip tests ────────────────────────────────────────────────────────

#[test]
fn open_round_trip_minimal() {
    let original = Message::Open(Open {
        as_number: 65001,
        holdtime: HoldTime::new(90).unwrap(),
        router_id: u32::from("192.0.2.1".parse::<std::net::Ipv4Addr>().unwrap()),
        capability: vec![],
    });

    let mut framer = BgpFramer::new(default_codec().build());
    let mut buf = BytesMut::new();
    framer.encode_to(&original, &mut buf).unwrap();
    let parsed = framer.inner_mut().parse_message(&buf).unwrap();

    match parsed {
        Message::Open(Open {
            as_number,
            holdtime,
            router_id,
            capability,
        }) => {
            assert_eq!(as_number, 65001);
            assert_eq!(holdtime, HoldTime::new(90).unwrap());
            assert_eq!(
                router_id,
                u32::from("192.0.2.1".parse::<Ipv4Addr>().unwrap())
            );
            assert!(capability.is_empty());
        }
        _ => panic!("expected OPEN"),
    }
}

#[test]
fn open_round_trip_with_capabilities() {
    let original = Message::Open(Open {
        as_number: 65001,
        holdtime: HoldTime::new(180).unwrap(),
        router_id: u32::from("10.0.0.1".parse::<std::net::Ipv4Addr>().unwrap()),
        capability: vec![
            Capability::MultiProtocol(Family::IPV4),
            Capability::MultiProtocol(Family::IPV6),
            Capability::RouteRefresh,
            Capability::FourOctetAsNumber(65001),
        ],
    });

    let mut framer = BgpFramer::new(default_codec().build());
    let mut buf = BytesMut::new();
    framer.encode_to(&original, &mut buf).unwrap();
    let parsed = framer.inner_mut().parse_message(&buf).unwrap();

    match parsed {
        Message::Open(Open {
            as_number,
            holdtime,
            capability,
            ..
        }) => {
            assert_eq!(as_number, 65001);
            assert_eq!(holdtime, HoldTime::new(180).unwrap());
            assert!(
                capability
                    .iter()
                    .any(|c| matches!(c, Capability::MultiProtocol(f) if *f == Family::IPV4))
            );
            assert!(
                capability
                    .iter()
                    .any(|c| matches!(c, Capability::MultiProtocol(f) if *f == Family::IPV6))
            );
            assert!(
                capability
                    .iter()
                    .any(|c| matches!(c, Capability::RouteRefresh))
            );
            assert!(
                capability
                    .iter()
                    .any(|c| matches!(c, Capability::FourOctetAsNumber(n) if *n == 65001))
            );
        }
        _ => panic!("expected OPEN"),
    }
}

// ─── error cases ─────────────────────────────────────────────────────────────

#[test]
fn open_too_short() {
    // Message shorter than minimum OPEN length (29 bytes)
    let body: &[u8] = &[4, 0xFD, 0xEA, 0x00, 0x5A]; // partial body
    let buf = bgp_msg(1, body);
    let mut codec = default_codec().build();
    match codec.parse_message(&buf) {
        Err(rustybgp_packet::Error::Bgp(BgpError::BadMessageLength { .. })) => {}
        Ok(_) => panic!("expected error"),
        Err(e) => panic!("unexpected error: {}", e),
    }
}

#[test]
fn open_unacceptable_holdtime() {
    // RFC 4271 §6.2: hold time 1 or 2 is unacceptable
    for bad_holdtime in [1u16, 2u16] {
        let buf = bgp_msg(
            1,
            &open_body(65001, bad_holdtime, "192.0.2.1".parse().unwrap(), &[]),
        );
        let mut codec = default_codec().build();
        match codec.parse_message(&buf) {
            Err(rustybgp_packet::Error::Bgp(BgpError::OpenUnacceptableHoldTime { .. })) => {}
            Ok(_) => panic!("expected error for holdtime={}", bad_holdtime),
            Err(e) => panic!("unexpected error for holdtime={}: {}", bad_holdtime, e),
        }
    }
}

#[test]
fn open_unsupported_optional_parameter() {
    // Parameter type != 2 (not a capability) → error
    let params: &[u8] = &[0x01, 0x02, 0xAB, 0xCD]; // type=1 (unknown), len=2
    let buf = bgp_msg(
        1,
        &open_body(65001, 90, "192.0.2.1".parse().unwrap(), params),
    );
    let mut codec = default_codec().build();
    match codec.parse_message(&buf) {
        Err(rustybgp_packet::Error::Bgp(BgpError::OpenUnsupportedOptionalParameter { .. })) => {}
        Ok(_) => panic!("expected error"),
        Err(e) => panic!("unexpected error: {}", e),
    }
}
