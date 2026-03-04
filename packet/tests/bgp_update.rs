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
use rustybgp_packet::bgp::{Attribute, Ipv4Net, Ipv6Net, Message, NlriSet, PeerCodecBuilder};
use rustybgp_packet::{BgpFramer, Family, Nlri, PathNlri};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

// ─── helpers ────────────────────────────────────────────────────────────────

fn ipv4_codec() -> rustybgp_packet::bgp::PeerCodec {
    // keep_aspath/keep_nexthop: preserve attributes as-is for round-trip testing.
    // local_asn is set non-zero so is_ibgp() returns false (avoiding LOCAL_PREF injection).
    PeerCodecBuilder::new()
        .local_asn(65001)
        .keep_aspath(true)
        .keep_nexthop(true)
        .families(vec![Family::IPV4])
        .build()
}

fn ipv6_codec() -> rustybgp_packet::bgp::PeerCodec {
    PeerCodecBuilder::new()
        .local_asn(65001)
        .keep_aspath(true)
        .keep_nexthop(true)
        .families(vec![Family::IPV6])
        .build()
}

/// Minimum valid attributes for an eBGP IPv4 UPDATE.
/// AS_PATH = AS_SEQUENCE [65002] — does not include local_asn 65001, so no loop.
fn ipv4_attrs(nexthop: Ipv4Addr) -> Arc<Vec<Attribute>> {
    Arc::new(vec![
        Attribute::new_with_value(Attribute::ORIGIN, 0).unwrap(), // IGP
        Attribute::new_with_bin(
            Attribute::AS_PATH,
            // AS_SEQUENCE, count=1, ASN=65002
            vec![Attribute::AS_PATH_TYPE_SEQ, 1, 0x00, 0x00, 0xFD, 0xEA],
        )
        .unwrap(),
        Attribute::new_with_bin(Attribute::NEXTHOP, nexthop.octets().to_vec()).unwrap(),
    ])
}

fn ipv4_prefix(addr: &str, mask: u8) -> PathNlri {
    PathNlri::new(Nlri::V4(Ipv4Net {
        addr: addr.parse().unwrap(),
        mask,
    }))
}

fn ipv6_prefix(addr: &str, mask: u8) -> PathNlri {
    PathNlri::new(Nlri::V6(Ipv6Net {
        addr: addr.parse().unwrap(),
        mask,
    }))
}

/// Encode + parse a message and return the parsed result.
fn round_trip(msg: &Message, codec: rustybgp_packet::bgp::PeerCodec) -> Message {
    let mut framer = BgpFramer::new(codec);
    let mut buf = BytesMut::new();
    framer.encode_to(msg, &mut buf).unwrap();
    framer.inner_mut().parse_message(&buf).unwrap()
}

// ─── IPv4 announce / withdraw ────────────────────────────────────────────────

#[test]
fn update_ipv4_announce() {
    let prefix = ipv4_prefix("10.0.0.0", 8);
    let msg = Message::Update {
        reach: Some(NlriSet {
            family: Family::IPV4,
            entries: vec![prefix],
        }),
        attr: ipv4_attrs("192.0.2.254".parse().unwrap()),
        unreach: None,
    };

    match round_trip(&msg, ipv4_codec()) {
        Message::Update { reach, unreach, .. } => {
            assert!(unreach.is_none());
            let s = reach.unwrap();
            assert_eq!(s.family, Family::IPV4);
            assert_eq!(s.entries, vec![prefix]);
        }
        _ => panic!("expected Update"),
    }
}

#[test]
fn update_ipv4_announce_multiple() {
    let prefixes: Vec<PathNlri> = ["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"]
        .iter()
        .map(|s| {
            let parts: Vec<&str> = s.split('/').collect();
            ipv4_prefix(parts[0], parts[1].parse().unwrap())
        })
        .collect();

    let msg = Message::Update {
        reach: Some(NlriSet {
            family: Family::IPV4,
            entries: prefixes.clone(),
        }),
        attr: ipv4_attrs("192.0.2.254".parse().unwrap()),
        unreach: None,
    };

    match round_trip(&msg, ipv4_codec()) {
        Message::Update { reach, .. } => {
            let s = reach.unwrap();
            assert_eq!(s.entries.len(), 3);
            // All prefixes should be present (order may differ for large tables,
            // but for small tables the order is preserved)
            for p in &prefixes {
                assert!(s.entries.contains(p), "missing prefix: {:?}", p);
            }
        }
        _ => panic!("expected Update"),
    }
}

#[test]
fn update_ipv4_withdraw() {
    let prefix = ipv4_prefix("10.0.0.0", 8);
    let msg = Message::Update {
        reach: None,
        attr: Arc::new(Vec::new()),
        unreach: Some(NlriSet {
            family: Family::IPV4,
            entries: vec![prefix],
        }),
    };

    match round_trip(&msg, ipv4_codec()) {
        Message::Update { reach, unreach, .. } => {
            assert!(reach.is_none());
            let s = unreach.unwrap();
            assert_eq!(s.family, Family::IPV4);
            assert_eq!(s.entries, vec![prefix]);
        }
        _ => panic!("expected Update"),
    }
}

// ─── IPv6 MP_REACH / MP_UNREACH ──────────────────────────────────────────────

#[test]
fn update_ipv6_announce() {
    let prefix = ipv6_prefix("2001:db8::", 32);
    let nexthop_bytes: Vec<u8> = "2001:db8::1".parse::<Ipv6Addr>().unwrap().octets().to_vec();

    let msg = Message::Update {
        reach: Some(NlriSet {
            family: Family::IPV6,
            entries: vec![prefix],
        }),
        attr: Arc::new(vec![
            Attribute::new_with_value(Attribute::ORIGIN, 0).unwrap(),
            Attribute::new_with_bin(
                Attribute::AS_PATH,
                vec![Attribute::AS_PATH_TYPE_SEQ, 1, 0x00, 0x00, 0xFD, 0xEA],
            )
            .unwrap(),
            Attribute::new_with_bin(Attribute::NEXTHOP, nexthop_bytes).unwrap(),
        ]),
        unreach: None,
    };

    match round_trip(&msg, ipv6_codec()) {
        Message::Update { reach, unreach, .. } => {
            assert!(unreach.is_none());
            let s = reach.unwrap();
            assert_eq!(s.family, Family::IPV6);
            assert_eq!(s.entries, vec![prefix]);
        }
        _ => panic!("expected Update"),
    }
}

#[test]
fn update_ipv6_withdraw() {
    let prefix = ipv6_prefix("2001:db8::", 32);
    let msg = Message::Update {
        reach: None,
        attr: Arc::new(Vec::new()),
        unreach: Some(NlriSet {
            family: Family::IPV6,
            entries: vec![prefix],
        }),
    };

    match round_trip(&msg, ipv6_codec()) {
        Message::Update { reach, unreach, .. } => {
            assert!(reach.is_none());
            let s = unreach.unwrap();
            assert_eq!(s.family, Family::IPV6);
            assert_eq!(s.entries, vec![prefix]);
        }
        _ => panic!("expected Update"),
    }
}

// ─── End-of-RIB ──────────────────────────────────────────────────────────────

#[test]
fn update_eor_ipv4() {
    let msg = Message::eor(Family::IPV4);
    match round_trip(&msg, ipv4_codec()) {
        Message::Update {
            reach,
            unreach,
            attr,
        } => {
            let s = reach.unwrap();
            assert_eq!(s.family, Family::IPV4);
            assert!(s.entries.is_empty(), "IPv4 EOR must have empty NLRI");
            assert!(unreach.is_none());
            assert!(attr.is_empty());
        }
        _ => panic!("expected Update"),
    }
}

#[test]
fn update_eor_ipv6() {
    let msg = Message::eor(Family::IPV6);
    // IPv6 EOR: MP_UNREACH with empty prefix list.
    // After round-trip, the empty unreach list is normalized to None.
    match round_trip(&msg, ipv6_codec()) {
        Message::Update {
            reach,
            unreach,
            attr,
        } => {
            assert!(reach.is_none());
            // Empty unreach entries become None after parsing
            assert!(unreach.is_none() || unreach.as_ref().map_or(true, |s| s.entries.is_empty()));
            assert!(attr.is_empty());
        }
        _ => panic!("expected Update"),
    }
}

// ─── Attribute tests ─────────────────────────────────────────────────────────

#[test]
fn update_attr_origin_igp() {
    let msg = Message::Update {
        reach: Some(NlriSet {
            family: Family::IPV4,
            entries: vec![ipv4_prefix("10.0.0.0", 8)],
        }),
        attr: ipv4_attrs("192.0.2.254".parse().unwrap()),
        unreach: None,
    };

    match round_trip(&msg, ipv4_codec()) {
        Message::Update { attr, reach, .. } => {
            assert!(!reach.unwrap().entries.is_empty());
            let origin = attr
                .iter()
                .find(|a| a.code() == Attribute::ORIGIN)
                .expect("ORIGIN attribute must be present");
            assert_eq!(origin.value().unwrap(), 0); // 0 = IGP
        }
        _ => panic!("expected Update"),
    }
}

#[test]
fn update_attr_med_dropped_on_encode() {
    // MED (MULTI_EXIT_DESC) is an optional non-transitive attribute.
    // The encoder only includes transitive attributes, so MED is dropped.
    // This is correct BGP behavior: MED is not propagated between ASes.
    let med_value: u32 = 150;
    let mut attrs = (*ipv4_attrs("192.0.2.254".parse().unwrap())).clone();
    attrs.push(Attribute::new_with_value(Attribute::MULTI_EXIT_DESC, med_value).unwrap());

    let msg = Message::Update {
        reach: Some(NlriSet {
            family: Family::IPV4,
            entries: vec![ipv4_prefix("10.0.0.0", 8)],
        }),
        attr: Arc::new(attrs),
        unreach: None,
    };

    match round_trip(&msg, ipv4_codec()) {
        Message::Update { attr, reach, .. } => {
            // Routes should be present (not withdrawn)
            assert!(!reach.unwrap().entries.is_empty());
            // MED is dropped because it's optional non-transitive
            assert!(
                attr.iter()
                    .find(|a| a.code() == Attribute::MULTI_EXIT_DESC)
                    .is_none(),
                "MED must be dropped on encode (non-transitive optional attribute)"
            );
        }
        _ => panic!("expected Update"),
    }
}

#[test]
fn update_attr_community() {
    // Community: 65001:100 = 0xFDE9_0064
    let community: u32 = (65001u32 << 16) | 100;
    let mut attrs = (*ipv4_attrs("192.0.2.254".parse().unwrap())).clone();
    attrs.push(
        Attribute::new_with_bin(Attribute::COMMUNITY, community.to_be_bytes().to_vec()).unwrap(),
    );

    let msg = Message::Update {
        reach: Some(NlriSet {
            family: Family::IPV4,
            entries: vec![ipv4_prefix("10.0.0.0", 8)],
        }),
        attr: Arc::new(attrs),
        unreach: None,
    };

    match round_trip(&msg, ipv4_codec()) {
        Message::Update { attr, reach, .. } => {
            assert!(!reach.unwrap().entries.is_empty());
            let comm = attr
                .iter()
                .find(|a| a.code() == Attribute::COMMUNITY)
                .expect("COMMUNITY attribute must be present");
            let bytes = comm.binary().unwrap();
            assert_eq!(bytes.len(), 4);
            let parsed = u32::from_be_bytes(bytes[..4].try_into().unwrap());
            assert_eq!(parsed, community);
        }
        _ => panic!("expected Update"),
    }
}
