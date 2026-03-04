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

use rustybgp_packet::bgp::{create_channel, Capability, Message, Open, PeerCodecBuilder};
use rustybgp_packet::{BgpError, BgpFramer, Family, HoldTime};
use std::net::Ipv4Addr;

// ─── helpers ────────────────────────────────────────────────────────────────

fn bgp_msg(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let total = (19 + body.len()) as u16;
    let mut buf = vec![0xff; 16];
    buf.extend_from_slice(&total.to_be_bytes());
    buf.push(msg_type);
    buf.extend_from_slice(body);
    buf
}

fn open_body(as2: u16, holdtime: u16, router_id: Ipv4Addr, params: &[u8]) -> Vec<u8> {
    let mut body = vec![4u8];
    body.extend_from_slice(&as2.to_be_bytes());
    body.extend_from_slice(&holdtime.to_be_bytes());
    body.extend_from_slice(&u32::from(router_id).to_be_bytes());
    body.push(params.len() as u8);
    body.extend_from_slice(params);
    body
}

fn capability_param(cap_bytes: &[u8]) -> Vec<u8> {
    let mut p = vec![2u8, cap_bytes.len() as u8];
    p.extend_from_slice(cap_bytes);
    p
}

fn parse_open_caps(cap_bytes: &[u8]) -> Vec<Capability> {
    let params = capability_param(cap_bytes);
    let buf = bgp_msg(
        1,
        &open_body(65001, 90, "192.0.2.1".parse().unwrap(), &params),
    );
    match PeerCodecBuilder::new().build().parse_message(&buf).unwrap() {
        Message::Open(Open { capability, .. }) => capability,
        _ => panic!("expected OPEN"),
    }
}

fn round_trip(msg: &Message) -> Message {
    let mut framer = BgpFramer::new(PeerCodecBuilder::new().build());
    let mut buf = Vec::new();
    framer.encode_to(msg, &mut buf).unwrap();
    framer.inner_mut().parse_message(&buf).unwrap()
}

fn open_with(caps: Vec<Capability>) -> Message {
    Message::Open(Open {
        as_number: 65001,
        holdtime: HoldTime::new(90).unwrap(),
        router_id: u32::from("192.0.2.1".parse::<Ipv4Addr>().unwrap()),
        capability: caps,
    })
}

// ─── GracefulRestart ─────────────────────────────────────────────────────────

fn graceful_restart_bytes(flags: u8, restart_time: u16, families: &[(u16, u8, u8)]) -> Vec<u8> {
    let len = 2 + families.len() as u8 * 4;
    let mut v = vec![64u8, len]; // code=64
    let restart_word = ((flags as u16) << 12) | (restart_time & 0xfff);
    v.extend_from_slice(&restart_word.to_be_bytes());
    for (afi, safi, af_flags) in families {
        v.extend_from_slice(&afi.to_be_bytes());
        v.push(*safi);
        v.push(*af_flags);
    }
    v
}

#[test]
fn capability_graceful_restart_no_families() {
    let cap = graceful_restart_bytes(0x08, 90, &[]);
    let caps = parse_open_caps(&cap);
    assert_eq!(caps.len(), 1);
    assert!(matches!(
        &caps[0],
        Capability::GracefulRestart { flags: 0x08, restart_time: 90, families }
        if families.is_empty()
    ));
}

#[test]
fn capability_graceful_restart_with_families() {
    // R-bit set, time=120, IPv4 unicast with forwarding-state bit
    let cap = graceful_restart_bytes(0x08, 120, &[(1, 1, 0x80)]);
    let caps = parse_open_caps(&cap);
    assert_eq!(caps.len(), 1);
    match &caps[0] {
        Capability::GracefulRestart {
            flags,
            restart_time,
            families,
        } => {
            assert_eq!(*flags, 0x08);
            assert_eq!(*restart_time, 120);
            assert_eq!(families.len(), 1);
            assert_eq!(families[0], (Family::IPV4, 0x80));
        }
        _ => panic!("expected GracefulRestart"),
    }
}

#[test]
fn capability_graceful_restart_round_trip() {
    // Two families: tests the encode length bug fix (families.len()*4+2, not +2 alone)
    let original = open_with(vec![Capability::GracefulRestart {
        flags: 0x08,
        restart_time: 120,
        families: vec![(Family::IPV4, 0x80), (Family::IPV6, 0x00)],
    }]);
    match round_trip(&original) {
        Message::Open(Open { capability, .. }) => {
            assert_eq!(capability.len(), 1);
            match &capability[0] {
                Capability::GracefulRestart {
                    flags,
                    restart_time,
                    families,
                } => {
                    assert_eq!(*flags, 0x08);
                    assert_eq!(*restart_time, 120);
                    assert_eq!(families.len(), 2);
                    assert!(families.contains(&(Family::IPV4, 0x80)));
                    assert!(families.contains(&(Family::IPV6, 0x00)));
                }
                _ => panic!("expected GracefulRestart"),
            }
        }
        _ => panic!("expected OPEN"),
    }
}

#[test]
fn capability_graceful_restart_invalid_len() {
    // len=3 is invalid: must satisfy len % 4 == 2
    let cap: &[u8] = &[64, 3, 0x00, 0x5A, 0x00];
    let params = capability_param(cap);
    let buf = bgp_msg(
        1,
        &open_body(65001, 90, "192.0.2.1".parse().unwrap(), &params),
    );
    match PeerCodecBuilder::new().build().parse_message(&buf) {
        Err(rustybgp_packet::Error::Bgp(BgpError::OpenMalformed)) => {}
        Ok(_) => panic!("expected error"),
        Err(e) => panic!("unexpected error: {}", e),
    }
}

// ─── AddPath ─────────────────────────────────────────────────────────────────

#[test]
fn capability_add_path_round_trip() {
    // mode=3: send+receive
    let original = open_with(vec![Capability::AddPath(vec![(Family::IPV4, 3)])]);
    match round_trip(&original) {
        Message::Open(Open { capability, .. }) => {
            assert_eq!(capability.len(), 1);
            assert!(matches!(
                &capability[0],
                Capability::AddPath(v) if *v == [(Family::IPV4, 3)]
            ));
        }
        _ => panic!("expected OPEN"),
    }
}

#[test]
fn capability_add_path_multiple_families() {
    let original = open_with(vec![Capability::AddPath(vec![
        (Family::IPV4, 1), // receive only
        (Family::IPV6, 2), // send only
    ])]);
    match round_trip(&original) {
        Message::Open(Open { capability, .. }) => {
            assert_eq!(capability.len(), 1);
            match &capability[0] {
                Capability::AddPath(v) => {
                    assert_eq!(v.len(), 2);
                    assert!(v.contains(&(Family::IPV4, 1)));
                    assert!(v.contains(&(Family::IPV6, 2)));
                }
                _ => panic!("expected AddPath"),
            }
        }
        _ => panic!("expected OPEN"),
    }
}

#[test]
fn capability_add_path_invalid_len() {
    // len must be multiple of 4; len=3 is invalid
    let cap: &[u8] = &[69, 3, 0x00, 0x01, 0x01];
    let params = capability_param(cap);
    let buf = bgp_msg(
        1,
        &open_body(65001, 90, "192.0.2.1".parse().unwrap(), &params),
    );
    match PeerCodecBuilder::new().build().parse_message(&buf) {
        Err(rustybgp_packet::Error::Bgp(BgpError::OpenMalformed)) => {}
        Ok(_) => panic!("expected error"),
        Err(e) => panic!("unexpected error: {}", e),
    }
}

// ─── EnhancedRouteRefresh ─────────────────────────────────────────────────────

#[test]
fn capability_enhanced_route_refresh_round_trip() {
    let original = open_with(vec![Capability::EnhancedRouteRefresh]);
    match round_trip(&original) {
        Message::Open(Open { capability, .. }) => {
            assert!(
                capability
                    .iter()
                    .any(|c| matches!(c, Capability::EnhancedRouteRefresh))
            );
        }
        _ => panic!("expected OPEN"),
    }
}

// ─── Fqdn ────────────────────────────────────────────────────────────────────

fn fqdn_bytes(hostname: &str, domain: &str) -> Vec<u8> {
    let mut v = vec![73u8]; // FQDN code
    v.push((2 + hostname.len() + domain.len()) as u8);
    v.push(hostname.len() as u8);
    v.extend_from_slice(hostname.as_bytes());
    v.push(domain.len() as u8);
    v.extend_from_slice(domain.as_bytes());
    v
}

#[test]
fn capability_fqdn_parse() {
    let cap = fqdn_bytes("router1", "example.com");
    let caps = parse_open_caps(&cap);
    assert_eq!(caps.len(), 1);
    assert!(matches!(
        &caps[0],
        Capability::Fqdn { hostname, domain }
        if hostname == "router1" && domain == "example.com"
    ));
}

#[test]
fn capability_fqdn_round_trip() {
    let original = open_with(vec![Capability::Fqdn {
        hostname: "router1".to_string(),
        domain: "example.com".to_string(),
    }]);
    match round_trip(&original) {
        Message::Open(Open { capability, .. }) => {
            assert_eq!(capability.len(), 1);
            assert!(matches!(
                &capability[0],
                Capability::Fqdn { hostname, domain }
                if hostname == "router1" && domain == "example.com"
            ));
        }
        _ => panic!("expected OPEN"),
    }
}

// ─── LongLivedGracefulRestart ─────────────────────────────────────────────────

#[test]
fn capability_llgr_round_trip() {
    let original = open_with(vec![Capability::LongLivedGracefulRestart(vec![(
        Family::IPV4,
        0x80, // forwarding-state bit
        3600, // stale time in seconds
    )])]);
    match round_trip(&original) {
        Message::Open(Open { capability, .. }) => {
            assert_eq!(capability.len(), 1);
            assert!(matches!(
                &capability[0],
                Capability::LongLivedGracefulRestart(v)
                if *v == [(Family::IPV4, 0x80, 3600)]
            ));
        }
        _ => panic!("expected OPEN"),
    }
}

// ─── Unknown capability ───────────────────────────────────────────────────────

#[test]
fn capability_unknown_preserved() {
    // Unrecognized code 200 with 2-byte data is preserved as Unknown
    let cap: &[u8] = &[200, 2, 0xAB, 0xCD];
    let caps = parse_open_caps(cap);
    assert_eq!(caps.len(), 1);
    assert!(matches!(
        &caps[0],
        Capability::Unknown { code: 200, bin }
        if bin == &[0xAB, 0xCD]
    ));
}

// ─── ExtendedNexthop (RFC 8950) ──────────────────────────────────────────────

#[test]
fn capability_extended_nexthop_round_trip() {
    // IPv4 unicast with IPv6 nexthop
    let original = open_with(vec![Capability::ExtendedNexthop(vec![(
        Family::IPV4,
        Family::AFI_IP6,
    )])]);
    match round_trip(&original) {
        Message::Open(Open { capability, .. }) => {
            assert_eq!(capability.len(), 1);
            match &capability[0] {
                Capability::ExtendedNexthop(v) => {
                    assert_eq!(v.len(), 1);
                    assert_eq!(v[0], (Family::IPV4, Family::AFI_IP6));
                }
                _ => panic!("expected ExtendedNexthop"),
            }
        }
        _ => panic!("expected OPEN"),
    }
}

#[test]
fn create_channel_extended_nexthop_bilateral() {
    // Both sides advertise ExtendedNexthop for IPv4 unicast
    let local = vec![
        Capability::MultiProtocol(Family::IPV4),
        Capability::ExtendedNexthop(vec![(Family::IPV4, Family::AFI_IP6)]),
    ];
    let remote = vec![
        Capability::MultiProtocol(Family::IPV4),
        Capability::ExtendedNexthop(vec![(Family::IPV4, Family::AFI_IP6)]),
    ];
    let channels: Vec<_> = create_channel(&local, &remote).collect();
    assert_eq!(channels.len(), 1);
    assert_eq!(channels[0].0, Family::IPV4);
    assert!(
        channels[0].1.extended_nexthop(),
        "extended_nexthop must be true when both sides advertise"
    );
}

#[test]
fn create_channel_extended_nexthop_unilateral() {
    // Only local advertises ExtendedNexthop — should NOT be active
    let local = vec![
        Capability::MultiProtocol(Family::IPV4),
        Capability::ExtendedNexthop(vec![(Family::IPV4, Family::AFI_IP6)]),
    ];
    let remote = vec![Capability::MultiProtocol(Family::IPV4)];
    let channels: Vec<_> = create_channel(&local, &remote).collect();
    assert_eq!(channels.len(), 1);
    assert!(
        !channels[0].1.extended_nexthop(),
        "extended_nexthop must be false when only one side advertises"
    );
}
