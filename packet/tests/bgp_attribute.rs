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

use rustybgp_packet::bgp::Ipv4Net;
use rustybgp_packet::bgp::{Attribute, Message, NlriSet, PeerCodecBuilder, Update};
use rustybgp_packet::{BgpFramer, Family, Nlri, PathNlri};
use std::net::Ipv4Addr;
use std::sync::Arc;

// ─── helpers ────────────────────────────────────────────────────────────────

fn ipv4_codec() -> rustybgp_packet::bgp::PeerCodec {
    PeerCodecBuilder::new()
        .local_asn(65001)
        .keep_aspath(true)
        .keep_nexthop(true)
        .families(vec![Family::IPV4])
        .build()
}

fn ipv4_prefix(addr: &str, mask: u8) -> PathNlri {
    PathNlri::new(Nlri::V4(Ipv4Net {
        addr: addr.parse().unwrap(),
        mask,
    }))
}

/// Minimum attributes for a valid eBGP IPv4 UPDATE.
fn base_attrs(nexthop: Ipv4Addr) -> Vec<Attribute> {
    vec![
        Attribute::new_with_value(Attribute::ORIGIN, 0).unwrap(),
        Attribute::new_with_bin(
            Attribute::AS_PATH,
            vec![Attribute::AS_PATH_TYPE_SEQ, 1, 0x00, 0x00, 0xFD, 0xEA],
        )
        .unwrap(),
        Attribute::new_with_bin(Attribute::NEXTHOP, nexthop.octets().to_vec()).unwrap(),
    ]
}

fn round_trip(msg: &Message) -> Message {
    let mut framer = BgpFramer::new(ipv4_codec());
    let mut buf = Vec::new();
    framer.encode_to(msg, &mut buf).unwrap();
    framer.inner_mut().parse_message(&buf).unwrap()
}

fn update_with_attrs(attrs: Vec<Attribute>) -> Message {
    Message::Update(Update {
        reach: Some(NlriSet {
            family: Family::IPV4,
            entries: vec![ipv4_prefix("10.0.0.0", 8)],
        }),
        mp_reach: None,
        attr: Arc::new(attrs),
        unreach: None,
        mp_unreach: None,
        nexthop: None,
    })
}

// ─── canonical_flags ─────────────────────────────────────────────────────────

// RFC 4271 flags: TRANSITIVE=0x40, OPTIONAL=0x80
const FLAG_TRANSITIVE: u8 = 0x40;
const FLAG_OPTIONAL: u8 = 0x80;

#[test]
fn canonical_flags_well_known_mandatory() {
    // Well-known mandatory: ORIGIN, AS_PATH, NEXTHOP, LOCAL_PREF, ATOMIC_AGGREGATE
    for code in [
        Attribute::ORIGIN,
        Attribute::AS_PATH,
        Attribute::NEXTHOP,
        Attribute::LOCAL_PREF,
        Attribute::ATOMIC_AGGREGATE,
    ] {
        let f = Attribute::canonical_flags(code).unwrap_or_else(|| panic!("code {} missing", code));
        assert_eq!(
            f & FLAG_TRANSITIVE,
            FLAG_TRANSITIVE,
            "code {} should be TRANSITIVE",
            code
        );
        assert_eq!(f & FLAG_OPTIONAL, 0, "code {} should not be OPTIONAL", code);
    }
}

#[test]
fn canonical_flags_optional_non_transitive() {
    // Optional non-transitive: MED, ORIGINATOR_ID, CLUSTER_LIST, MP_REACH, MP_UNREACH
    for code in [
        Attribute::MULTI_EXIT_DESC,
        Attribute::ORIGINATOR_ID,
        Attribute::CLUSTER_LIST,
        Attribute::MP_REACH,
        Attribute::MP_UNREACH,
    ] {
        let f = Attribute::canonical_flags(code).unwrap_or_else(|| panic!("code {} missing", code));
        assert_eq!(
            f & FLAG_OPTIONAL,
            FLAG_OPTIONAL,
            "code {} should be OPTIONAL",
            code
        );
        assert_eq!(
            f & FLAG_TRANSITIVE,
            0,
            "code {} should not be TRANSITIVE",
            code
        );
    }
}

#[test]
fn canonical_flags_optional_transitive() {
    // Optional transitive: COMMUNITY, AGGREGATOR, EXTENDED_COMMUNITY, AS4_PATH, LARGE_COMMUNITY
    for code in [
        Attribute::COMMUNITY,
        Attribute::AGGREGATOR,
        Attribute::EXTENDED_COMMUNITY,
        Attribute::AS4_PATH,
        Attribute::LARGE_COMMUNITY,
    ] {
        let f = Attribute::canonical_flags(code).unwrap_or_else(|| panic!("code {} missing", code));
        assert_eq!(
            f & FLAG_OPTIONAL,
            FLAG_OPTIONAL,
            "code {} should be OPTIONAL",
            code
        );
        assert_eq!(
            f & FLAG_TRANSITIVE,
            FLAG_TRANSITIVE,
            "code {} should be TRANSITIVE",
            code
        );
    }
}

#[test]
fn canonical_flags_unknown_returns_none() {
    assert_eq!(Attribute::canonical_flags(0), None);
    assert_eq!(Attribute::canonical_flags(100), None);
    assert_eq!(Attribute::canonical_flags(255), None);
}

// ─── constructor tests ────────────────────────────────────────────────────────

#[test]
fn new_with_value_known_code() {
    let a = Attribute::new_with_value(Attribute::ORIGIN, 0).unwrap();
    assert_eq!(a.code(), Attribute::ORIGIN);
    assert_eq!(a.value(), Some(0));
}

#[test]
fn new_with_value_unknown_code_returns_none() {
    assert!(Attribute::new_with_value(255, 0).is_none());
}

#[test]
fn new_with_bin_known_code() {
    let bytes = vec![0xDE, 0xAD];
    let a = Attribute::new_with_bin(Attribute::COMMUNITY, bytes.clone()).unwrap();
    assert_eq!(a.code(), Attribute::COMMUNITY);
    assert_eq!(a.binary(), Some(&bytes));
}

#[test]
fn new_with_bin_unknown_code_returns_none() {
    assert!(Attribute::new_with_bin(200, vec![0x01]).is_none());
}

// ─── round-trip attribute tests ──────────────────────────────────────────────

#[test]
fn attribute_local_pref_round_trip() {
    let mut attrs = base_attrs("192.0.2.1".parse().unwrap());
    attrs.push(Attribute::new_with_value(Attribute::LOCAL_PREF, 200).unwrap());

    match round_trip(&update_with_attrs(attrs)) {
        Message::Update(Update { attr, .. }) => {
            let lp = attr
                .iter()
                .find(|a| a.code() == Attribute::LOCAL_PREF)
                .expect("LOCAL_PREF must be present");
            assert_eq!(lp.value(), Some(200));
        }
        _ => panic!("expected Update"),
    }
}

#[test]
fn attribute_as_path_round_trip() {
    let aspath = vec![
        Attribute::AS_PATH_TYPE_SEQ,
        2,
        0x00,
        0x00,
        0xFD,
        0xEA,
        0x00,
        0x01,
        0x00,
        0x00,
    ];
    let mut attrs = vec![
        Attribute::new_with_value(Attribute::ORIGIN, 0).unwrap(),
        Attribute::new_with_bin(Attribute::AS_PATH, aspath.clone()).unwrap(),
        Attribute::new_with_bin(
            Attribute::NEXTHOP,
            "192.0.2.1".parse::<Ipv4Addr>().unwrap().octets().to_vec(),
        )
        .unwrap(),
    ];
    attrs.push(Attribute::new_with_value(Attribute::LOCAL_PREF, 100).unwrap());

    match round_trip(&update_with_attrs(attrs)) {
        Message::Update(Update { attr, .. }) => {
            let ap = attr
                .iter()
                .find(|a| a.code() == Attribute::AS_PATH)
                .expect("AS_PATH must be present");
            assert_eq!(ap.binary(), Some(&aspath));
        }
        _ => panic!("expected Update"),
    }
}

#[test]
fn attribute_large_community_round_trip() {
    // Large community: ASN=65001, value1=1, value2=2 → 12 bytes
    let lc: Vec<u8> = [65001u32, 1u32, 2u32]
        .iter()
        .flat_map(|v| v.to_be_bytes())
        .collect();
    let mut attrs = base_attrs("192.0.2.1".parse().unwrap());
    attrs.push(Attribute::new_with_bin(Attribute::LARGE_COMMUNITY, lc.clone()).unwrap());

    match round_trip(&update_with_attrs(attrs)) {
        Message::Update(Update { attr, .. }) => {
            let lc_attr = attr
                .iter()
                .find(|a| a.code() == Attribute::LARGE_COMMUNITY)
                .expect("LARGE_COMMUNITY must be present");
            assert_eq!(lc_attr.binary(), Some(&lc));
        }
        _ => panic!("expected Update"),
    }
}

#[test]
fn attribute_extended_community_round_trip() {
    // Extended community: route-target 65001:100
    let ec: Vec<u8> = vec![0x00, 0x02, 0x00, 0x00, 0xFD, 0xE9, 0x00, 0x64];
    let mut attrs = base_attrs("192.0.2.1".parse().unwrap());
    attrs.push(Attribute::new_with_bin(Attribute::EXTENDED_COMMUNITY, ec.clone()).unwrap());

    match round_trip(&update_with_attrs(attrs)) {
        Message::Update(Update { attr, .. }) => {
            let ec_attr = attr
                .iter()
                .find(|a| a.code() == Attribute::EXTENDED_COMMUNITY)
                .expect("EXTENDED_COMMUNITY must be present");
            assert_eq!(ec_attr.binary(), Some(&ec));
        }
        _ => panic!("expected Update"),
    }
}
