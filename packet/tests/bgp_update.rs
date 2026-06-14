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
use rustybgp_packet::bgp::{
    Attribute, Capability, FamilyState, Ipv4Net, Ipv6Net, Message, Nexthop, ParsedMessage,
    ParsedUpdate, PeerCodec, Update,
};
use rustybgp_packet::mup;
use rustybgp_packet::prefix_sid;
use rustybgp_packet::rd::RouteDistinguisher;
use rustybgp_packet::{Family, Nlri, Notification, PathNlri};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

// ─── helpers ────────────────────────────────────────────────────────────────

fn ipv4_codec() -> rustybgp_packet::bgp::PeerCodec {
    let mut c = PeerCodec::new();
    c.set_family(Family::IPV4, Default::default());
    c
}

fn ipv6_codec() -> rustybgp_packet::bgp::PeerCodec {
    let mut c = PeerCodec::new();
    c.set_family(Family::IPV6, Default::default());
    c
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
fn round_trip(msg: &Message, codec: rustybgp_packet::bgp::PeerCodec) -> ParsedMessage {
    let mut framer = codec;
    let mut buf = Vec::new();
    framer.encode_to(msg, &mut buf).unwrap();
    framer.parse_message(&buf).unwrap()
}

// ─── IPv4 announce / withdraw ────────────────────────────────────────────────

#[test]
fn update_ipv4_announce() {
    let prefix = ipv4_prefix("10.0.0.0", 8);
    let msg = Message::Update(Update::Reach {
        family: Family::IPV4,
        entries: vec![prefix.clone()],
        nexthop: None,
        attr: ipv4_attrs("192.0.2.254".parse().unwrap()),
    });

    match round_trip(&msg, ipv4_codec()) {
        ParsedMessage::Update(ParsedUpdate::Routes { reach, unreach, .. }) => {
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

    let msg = Message::Update(Update::Reach {
        family: Family::IPV4,
        entries: prefixes.clone(),
        nexthop: None,
        attr: ipv4_attrs("192.0.2.254".parse().unwrap()),
    });

    match round_trip(&msg, ipv4_codec()) {
        ParsedMessage::Update(ParsedUpdate::Routes { reach, .. }) => {
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
    let msg = Message::Update(Update::Unreach {
        family: Family::IPV4,
        entries: vec![prefix.clone()],
    });

    match round_trip(&msg, ipv4_codec()) {
        ParsedMessage::Update(ParsedUpdate::Routes { reach, unreach, .. }) => {
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

    let msg = Message::Update(Update::Reach {
        family: Family::IPV6,
        entries: vec![prefix.clone()],
        nexthop: None,
        attr: Arc::new(vec![
            Attribute::new_with_value(Attribute::ORIGIN, 0).unwrap(),
            Attribute::new_with_bin(
                Attribute::AS_PATH,
                vec![Attribute::AS_PATH_TYPE_SEQ, 1, 0x00, 0x00, 0xFD, 0xEA],
            )
            .unwrap(),
            Attribute::new_with_bin(Attribute::NEXTHOP, nexthop_bytes).unwrap(),
        ]),
    });

    match round_trip(&msg, ipv6_codec()) {
        ParsedMessage::Update(ParsedUpdate::Routes {
            mp_reach,
            mp_unreach,
            ..
        }) => {
            assert!(mp_unreach.is_none());
            let s = mp_reach.unwrap();
            assert_eq!(s.family, Family::IPV6);
            assert_eq!(s.entries, vec![prefix]);
        }
        _ => panic!("expected Update"),
    }
}

#[test]
fn update_ipv6_withdraw() {
    let prefix = ipv6_prefix("2001:db8::", 32);
    let msg = Message::Update(Update::Unreach {
        family: Family::IPV6,
        entries: vec![prefix.clone()],
    });

    match round_trip(&msg, ipv6_codec()) {
        ParsedMessage::Update(ParsedUpdate::Routes {
            mp_reach,
            mp_unreach,
            ..
        }) => {
            assert!(mp_reach.is_none());
            let s = mp_unreach.unwrap();
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
        ParsedMessage::Update(ParsedUpdate::EndOfRib(family)) => {
            assert_eq!(family, Family::IPV4);
        }
        _ => panic!("expected EndOfRib(IPV4)"),
    }
}

#[test]
fn update_eor_ipv6() {
    let msg = Message::eor(Family::IPV6);
    match round_trip(&msg, ipv6_codec()) {
        ParsedMessage::Update(ParsedUpdate::EndOfRib(family)) => {
            assert_eq!(family, Family::IPV6);
        }
        _ => panic!("expected EndOfRib(IPV6)"),
    }
}

// ─── Attribute tests ─────────────────────────────────────────────────────────

#[test]
fn update_attr_origin_igp() {
    let msg = Message::Update(Update::Reach {
        family: Family::IPV4,
        entries: vec![ipv4_prefix("10.0.0.0", 8)],
        nexthop: None,
        attr: ipv4_attrs("192.0.2.254".parse().unwrap()),
    });

    match round_trip(&msg, ipv4_codec()) {
        ParsedMessage::Update(ParsedUpdate::Routes { attrs, reach, .. }) => {
            assert!(!reach.unwrap().entries.is_empty());
            let origin = attrs
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

    let msg = Message::Update(Update::Reach {
        family: Family::IPV4,
        entries: vec![ipv4_prefix("10.0.0.0", 8)],
        nexthop: None,
        attr: Arc::new(attrs),
    });

    match round_trip(&msg, ipv4_codec()) {
        ParsedMessage::Update(ParsedUpdate::Routes { attrs, reach, .. }) => {
            // Routes should be present (not withdrawn)
            assert!(!reach.unwrap().entries.is_empty());
            // MED is dropped because it's optional non-transitive
            assert!(
                attrs
                    .iter()
                    .find(|a| a.code() == Attribute::MULTI_EXIT_DESC)
                    .is_none(),
                "MED must be dropped on encode (non-transitive optional attribute)"
            );
        }
        _ => panic!("expected Update"),
    }
}

// ─── RFC 8950: IPv4 NLRI with IPv6 Next Hop ─────────────────────────────────

fn ipv4_extended_nexthop_codec() -> PeerCodec {
    let local = vec![
        Capability::MultiProtocol(Family::IPV4),
        Capability::ExtendedNexthop(vec![(Family::IPV4, Family::AFI_IP6)]),
    ];
    PeerCodec::negotiate(&local, &local)
}

#[test]
fn update_ipv4_with_ipv6_nexthop() {
    let prefix = ipv4_prefix("10.0.0.0", 8);
    let nexthop_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();

    let msg = Message::Update(Update::Reach {
        family: Family::IPV4,
        entries: vec![prefix.clone()],
        nexthop: Some(Nexthop::V6(nexthop_v6)),
        attr: Arc::new(vec![
            Attribute::new_with_value(Attribute::ORIGIN, 0).unwrap(),
            Attribute::new_with_bin(
                Attribute::AS_PATH,
                vec![Attribute::AS_PATH_TYPE_SEQ, 1, 0x00, 0x00, 0xFD, 0xEA],
            )
            .unwrap(),
        ]),
    });

    match round_trip(&msg, ipv4_extended_nexthop_codec()) {
        ParsedMessage::Update(ParsedUpdate::Routes {
            reach, mp_reach, ..
        }) => {
            // IPv4 NLRI must come back via mp_reach (not traditional reach)
            assert!(reach.is_none(), "reach must be None for extended nexthop");
            let s = mp_reach.expect("mp_reach must be present");
            assert_eq!(s.family, Family::IPV4);
            assert_eq!(s.entries, vec![prefix]);
            // Nexthop must be the IPv6 address
            assert_eq!(s.nexthop, Some(Nexthop::V6(nexthop_v6)));
        }
        _ => panic!("expected Update"),
    }
}

#[test]
fn update_ipv4_extended_nexthop_withdraw() {
    let prefix = ipv4_prefix("10.0.0.0", 8);
    let msg = Message::Update(Update::Unreach {
        family: Family::IPV4,
        entries: vec![prefix.clone()],
    });

    match round_trip(&msg, ipv4_extended_nexthop_codec()) {
        ParsedMessage::Update(ParsedUpdate::Routes {
            unreach,
            mp_unreach,
            ..
        }) => {
            assert!(unreach.is_none(), "traditional unreach must be None");
            let s = mp_unreach.expect("mp_unreach must be present");
            assert_eq!(s.family, Family::IPV4);
            assert_eq!(s.entries, vec![prefix]);
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

    let msg = Message::Update(Update::Reach {
        family: Family::IPV4,
        entries: vec![ipv4_prefix("10.0.0.0", 8)],
        nexthop: None,
        attr: Arc::new(attrs),
    });

    match round_trip(&msg, ipv4_codec()) {
        ParsedMessage::Update(ParsedUpdate::Routes { attrs, reach, .. }) => {
            assert!(!reach.unwrap().entries.is_empty());
            let comm = attrs
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

// ─── Prefix SID attribute (RFC 8669) ─────────────────────────────────────────

#[test]
fn update_ipv4_with_prefix_sid() {
    let prefix = ipv4_prefix("10.0.0.0", 24);
    // Build a Prefix SID attribute with SRv6 L3 Service TLV containing one
    // Information sub-TLV and one SID Structure sub-sub-TLV.
    let sid = prefix_sid::PrefixSid {
        tlvs: vec![prefix_sid::PrefixSidTlv::Srv6L3Service(
            prefix_sid::Srv6ServiceTlv {
                reserved: 0,
                sub_tlvs: vec![prefix_sid::Srv6ServiceSubTlv::Information(
                    prefix_sid::Srv6InformationSubTlv {
                        sid: "2001:0:5:3::".parse().unwrap(),
                        flags: 0,
                        endpoint_behavior: 19, // End.DT4
                        sub_sub_tlvs: vec![prefix_sid::Srv6ServiceDataSubSubTlv::Structure(
                            prefix_sid::Srv6SidStructureSubSubTlv {
                                locator_block_length: 40,
                                locator_node_length: 24,
                                function_length: 16,
                                argument_length: 0,
                                transposition_length: 16,
                                transposition_offset: 64,
                            },
                        )],
                    },
                )],
            },
        )],
    };
    let sid_bytes = sid.to_vec();

    let msg = Message::Update(Update::Reach {
        family: Family::IPV4,
        entries: vec![prefix.clone()],
        nexthop: None,
        attr: Arc::new(vec![
            Attribute::new_with_value(Attribute::ORIGIN, 0).unwrap(),
            Attribute::new_with_bin(
                Attribute::AS_PATH,
                vec![Attribute::AS_PATH_TYPE_SEQ, 1, 0x00, 0x00, 0xFD, 0xEA],
            )
            .unwrap(),
            Attribute::new_with_bin(
                Attribute::NEXTHOP,
                Ipv4Addr::new(192, 0, 2, 254).octets().to_vec(),
            )
            .unwrap(),
            Attribute::new_with_bin(Attribute::PREFIX_SID, sid_bytes.clone()).unwrap(),
        ]),
    });

    match round_trip(&msg, ipv4_codec()) {
        ParsedMessage::Update(ParsedUpdate::Routes { reach, attrs, .. }) => {
            assert_eq!(reach.unwrap().entries, vec![prefix]);
            let a = attrs
                .iter()
                .find(|a| a.code() == Attribute::PREFIX_SID)
                .expect("PREFIX_SID must be present");
            assert_eq!(a.binary().unwrap(), &sid_bytes);
            // Decoded structure equals the input.
            let decoded = prefix_sid::PrefixSid::decode(a.binary().unwrap()).unwrap();
            assert_eq!(decoded, sid);
        }
        _ => panic!("expected Update"),
    }
}

#[test]
fn update_passes_through_unknown_prefix_sid_tlv() {
    // Receivers must re-advertise TLV types they do not understand.
    let prefix = ipv4_prefix("10.0.0.0", 24);
    let sid = prefix_sid::PrefixSid {
        tlvs: vec![prefix_sid::PrefixSidTlv::Unknown {
            type_id: 0x55,
            value: vec![0xAA, 0xBB, 0xCC],
        }],
    };
    let sid_bytes = sid.to_vec();
    assert_eq!(sid_bytes, vec![0x55, 0x00, 0x03, 0xAA, 0xBB, 0xCC]);

    let msg = Message::Update(Update::Reach {
        family: Family::IPV4,
        entries: vec![prefix.clone()],
        nexthop: None,
        attr: Arc::new(vec![
            Attribute::new_with_value(Attribute::ORIGIN, 0).unwrap(),
            Attribute::new_with_bin(
                Attribute::AS_PATH,
                vec![Attribute::AS_PATH_TYPE_SEQ, 1, 0x00, 0x00, 0xFD, 0xEA],
            )
            .unwrap(),
            Attribute::new_with_bin(
                Attribute::NEXTHOP,
                Ipv4Addr::new(192, 0, 2, 254).octets().to_vec(),
            )
            .unwrap(),
            Attribute::new_with_bin(Attribute::PREFIX_SID, sid_bytes.clone()).unwrap(),
        ]),
    });

    match round_trip(&msg, ipv4_codec()) {
        ParsedMessage::Update(ParsedUpdate::Routes { attrs, .. }) => {
            let a = attrs
                .iter()
                .find(|a| a.code() == Attribute::PREFIX_SID)
                .expect("PREFIX_SID must be present");
            assert_eq!(a.binary().unwrap(), &sid_bytes);
        }
        _ => panic!("expected Update"),
    }
}

// ─── MUP SAFI announce / withdraw ────────────────────────────────────────────

fn ipv4_mup_codec() -> PeerCodec {
    let mut c = PeerCodec::new();
    c.set_family(Family::IPV4_MUP, Default::default());
    c
}

fn ipv6_mup_codec() -> PeerCodec {
    let mut c = PeerCodec::new();
    c.set_family(Family::IPV6_MUP, Default::default());
    c
}

fn mup_rd() -> RouteDistinguisher {
    RouteDistinguisher::TwoOctetAs {
        admin: 65000,
        assigned: 100,
    }
}

#[test]
fn update_ipv4_mup_announce() {
    let nlri = PathNlri::new(Nlri::Mup(mup::MupNlri::InterworkSegmentDiscovery(
        mup::MupInterworkSegmentDiscoveryRoute {
            rd: mup_rd(),
            prefix_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            prefix_len: 24,
        },
    )));
    let nexthop: Ipv4Addr = "10.0.0.1".parse().unwrap();
    let msg = Message::Update(Update::Reach {
        family: Family::IPV4_MUP,
        entries: vec![nlri.clone()],
        nexthop: None,
        attr: Arc::new(vec![
            Attribute::new_with_value(Attribute::ORIGIN, 0).unwrap(),
            Attribute::new_with_bin(
                Attribute::AS_PATH,
                vec![Attribute::AS_PATH_TYPE_SEQ, 1, 0x00, 0x00, 0xFD, 0xEA],
            )
            .unwrap(),
            Attribute::new_with_bin(Attribute::NEXTHOP, nexthop.octets().to_vec()).unwrap(),
        ]),
    });

    match round_trip(&msg, ipv4_mup_codec()) {
        ParsedMessage::Update(ParsedUpdate::Routes {
            mp_reach,
            mp_unreach,
            ..
        }) => {
            assert!(mp_unreach.is_none());
            let s = mp_reach.unwrap();
            assert_eq!(s.family, Family::IPV4_MUP);
            assert_eq!(s.entries, vec![nlri]);
        }
        _ => panic!("expected Update"),
    }
}

#[test]
fn update_ipv6_mup_announce() {
    let nlri = PathNlri::new(Nlri::Mup(mup::MupNlri::DirectSegmentDiscovery(
        mup::MupDirectSegmentDiscoveryRoute {
            rd: mup_rd(),
            address: IpAddr::V6("2001:db8::1".parse().unwrap()),
        },
    )));
    let nexthop_bytes: Vec<u8> = "2001:db8::1".parse::<Ipv6Addr>().unwrap().octets().to_vec();
    let msg = Message::Update(Update::Reach {
        family: Family::IPV6_MUP,
        entries: vec![nlri.clone()],
        nexthop: None,
        attr: Arc::new(vec![
            Attribute::new_with_value(Attribute::ORIGIN, 0).unwrap(),
            Attribute::new_with_bin(
                Attribute::AS_PATH,
                vec![Attribute::AS_PATH_TYPE_SEQ, 1, 0x00, 0x00, 0xFD, 0xEA],
            )
            .unwrap(),
            Attribute::new_with_bin(Attribute::NEXTHOP, nexthop_bytes).unwrap(),
        ]),
    });

    match round_trip(&msg, ipv6_mup_codec()) {
        ParsedMessage::Update(ParsedUpdate::Routes {
            mp_reach,
            mp_unreach,
            ..
        }) => {
            assert!(mp_unreach.is_none());
            let s = mp_reach.unwrap();
            assert_eq!(s.family, Family::IPV6_MUP);
            assert_eq!(s.entries, vec![nlri]);
        }
        _ => panic!("expected Update"),
    }
}

#[test]
fn update_mup_withdraw() {
    let nlri = PathNlri::new(Nlri::Mup(mup::MupNlri::Type2SessionTransformed(
        mup::MupType2SessionTransformedRoute {
            rd: mup_rd(),
            endpoint_address_length: 64,
            endpoint_address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            teid: 0xdead_beef,
        },
    )));
    let msg = Message::Update(Update::Unreach {
        family: Family::IPV4_MUP,
        entries: vec![nlri.clone()],
    });

    match round_trip(&msg, ipv4_mup_codec()) {
        ParsedMessage::Update(ParsedUpdate::Routes {
            mp_reach,
            mp_unreach,
            ..
        }) => {
            assert!(mp_reach.is_none());
            let s = mp_unreach.unwrap();
            assert_eq!(s.family, Family::IPV4_MUP);
            assert_eq!(s.entries, vec![nlri]);
        }
        _ => panic!("expected Update"),
    }
}

#[test]
fn update_mup_with_ext_community() {
    let nlri = PathNlri::new(Nlri::Mup(mup::MupNlri::DirectSegmentDiscovery(
        mup::MupDirectSegmentDiscoveryRoute {
            rd: mup_rd(),
            address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        },
    )));
    // Build EXTENDED_COMMUNITY bytes containing a MUP ext community.
    let mut ec_bytes = Vec::new();
    mup::MupExtended {
        sub_type: mup::EC_SUBTYPE_MUP_DIRECT_SEG,
        segment_id2: 10,
        segment_id4: 20,
    }
    .encode(&mut ec_bytes);
    let nexthop: Ipv4Addr = "10.0.0.1".parse().unwrap();
    let msg = Message::Update(Update::Reach {
        family: Family::IPV4_MUP,
        entries: vec![nlri.clone()],
        nexthop: None,
        attr: Arc::new(vec![
            Attribute::new_with_value(Attribute::ORIGIN, 0).unwrap(),
            Attribute::new_with_bin(
                Attribute::AS_PATH,
                vec![Attribute::AS_PATH_TYPE_SEQ, 1, 0x00, 0x00, 0xFD, 0xEA],
            )
            .unwrap(),
            Attribute::new_with_bin(Attribute::NEXTHOP, nexthop.octets().to_vec()).unwrap(),
            Attribute::new_with_bin(Attribute::EXTENDED_COMMUNITY, ec_bytes.clone()).unwrap(),
        ]),
    });

    match round_trip(&msg, ipv4_mup_codec()) {
        ParsedMessage::Update(ParsedUpdate::Routes {
            mp_reach, attrs, ..
        }) => {
            let s = mp_reach.unwrap();
            assert_eq!(s.entries, vec![nlri]);
            let ec = attrs
                .iter()
                .find(|a| a.code() == Attribute::EXTENDED_COMMUNITY)
                .expect("EXTENDED_COMMUNITY missing");
            assert_eq!(ec.binary().unwrap(), ec_bytes.as_slice());
        }
        _ => panic!("expected Update"),
    }
}

// ─── MP_REACH_NLRI nexthop_len=0 (RFC 8955 §4 / GoBGP issue #3450) ──────────

fn mp_reach_zero_nexthop_update(afi: u16, safi: u8) -> Vec<u8> {
    // Builds a minimal UPDATE with one MP_REACH_NLRI attribute that has
    // nexthop_len=0 and no NLRI entries.
    let attr: Vec<u8> = vec![
        0x80,
        0x0E, // flags=optional|non-transitive, type=MP_REACH_NLRI(14)
        0x05, // attr length = 5
        (afi >> 8) as u8,
        afi as u8, // AFI
        safi,      // SAFI
        0x00,      // nexthop_len = 0
        0x00,      // SNPA count = 0
    ];
    let attr_len = attr.len() as u16;
    let total = 19u16 + 2 + 2 + attr_len;
    let mut buf = vec![0xff; 16];
    buf.extend_from_slice(&total.to_be_bytes());
    buf.push(2); // UPDATE
    buf.extend_from_slice(&0u16.to_be_bytes()); // withdrawn_len
    buf.extend_from_slice(&attr_len.to_be_bytes()); // total_attr_len
    buf.extend_from_slice(&attr);
    buf
}

#[test]
fn mp_reach_zero_nexthop_non_flowspec_is_error() {
    // nexthop_len=0 for IPv4 unicast (non-FlowSpec) must be rejected per
    // RFC 4760 §3 -- BIRD rejects this with bgp_parse_error (GoBGP #3450).
    let buf = mp_reach_zero_nexthop_update(Family::AFI_IP, 1);
    let mut codec = PeerCodec::new();
    codec.set_family(Family::IPV4, FamilyState::default());
    match codec.parse_message(&buf) {
        Err(Notification::UpdateOptionalAttributeError) => {}
        Err(e) => panic!("expected UpdateOptionalAttributeError, got Err({})", e),
        Ok(_) => panic!("expected Err, got Ok"),
    }
}

#[test]
fn mp_reach_zero_nexthop_flowspec_is_ok() {
    // nexthop_len=0 is valid for FlowSpec (RFC 8955 §4).
    let ipv4_flowspec = Family::new((Family::AFI_IP as u32) << 16 | 133);
    let buf = mp_reach_zero_nexthop_update(Family::AFI_IP, 133);
    let mut codec = PeerCodec::new();
    codec.set_family(ipv4_flowspec, FamilyState::default());
    assert!(
        codec.parse_message(&buf).is_ok(),
        "FlowSpec nexthop_len=0 must be accepted"
    );
}

// ─── VPN nexthop round-trip ──────────────────────────────────────────────────

fn vpnv4_codec() -> PeerCodec {
    let caps = vec![Capability::MultiProtocol(Family::IPV4_VPN)];
    PeerCodec::negotiate(&caps, &caps)
}

fn vpnv6_codec() -> PeerCodec {
    let caps = vec![Capability::MultiProtocol(Family::IPV6_VPN)];
    PeerCodec::negotiate(&caps, &caps)
}

#[test]
fn update_vpnv4_nexthop_roundtrip() {
    use rustybgp_packet::mpls::{MplsLabel, MplsLabelStack};
    use rustybgp_packet::vpn::VpnV4Nlri;

    let rd = RouteDistinguisher::TwoOctetAs {
        admin: 65001,
        assigned: 1,
    };
    let prefix = rustybgp_packet::bgp::Ipv4Net {
        addr: "10.0.1.0".parse().unwrap(),
        mask: 24,
    };
    let nlri = PathNlri::new(Nlri::VpnV4(VpnV4Nlri {
        labels: MplsLabelStack::new(vec![MplsLabel::new(100)]),
        rd,
        prefix,
    }));
    let nexthop = Nexthop::V4("192.0.2.1".parse().unwrap());

    let msg = Message::Update(Update::Reach {
        family: Family::IPV4_VPN,
        entries: vec![nlri.clone()],
        nexthop: Some(nexthop),
        attr: Arc::new(vec![
            Attribute::new_with_value(Attribute::ORIGIN, 0).unwrap(),
            Attribute::new_with_bin(
                Attribute::AS_PATH,
                vec![Attribute::AS_PATH_TYPE_SEQ, 1, 0x00, 0x00, 0xFD, 0xEA],
            )
            .unwrap(),
        ]),
    });

    match round_trip(&msg, vpnv4_codec()) {
        ParsedMessage::Update(ParsedUpdate::Routes { mp_reach, .. }) => {
            let r = mp_reach.expect("mp_reach must be present for VPNv4");
            assert_eq!(r.family, Family::IPV4_VPN);
            assert_eq!(
                r.nexthop,
                Some(nexthop),
                "nexthop mismatch after VPN RD strip"
            );
            assert_eq!(r.entries, vec![nlri]);
        }
        _ => panic!("expected Update"),
    }
}

#[test]
fn update_vpnv6_nexthop_roundtrip() {
    use rustybgp_packet::mpls::{MplsLabel, MplsLabelStack};
    use rustybgp_packet::vpn::VpnV6Nlri;

    let rd = RouteDistinguisher::TwoOctetAs {
        admin: 65001,
        assigned: 1,
    };
    let prefix = Ipv6Net {
        addr: "2001:db8:1::".parse().unwrap(),
        mask: 48,
    };
    let nlri = PathNlri::new(Nlri::VpnV6(VpnV6Nlri {
        labels: MplsLabelStack::new(vec![MplsLabel::new(200)]),
        rd,
        prefix,
    }));
    let nexthop = Nexthop::V6("2001:db8::1".parse().unwrap());

    let msg = Message::Update(Update::Reach {
        family: Family::IPV6_VPN,
        entries: vec![nlri.clone()],
        nexthop: Some(nexthop),
        attr: Arc::new(vec![
            Attribute::new_with_value(Attribute::ORIGIN, 0).unwrap(),
            Attribute::new_with_bin(
                Attribute::AS_PATH,
                vec![Attribute::AS_PATH_TYPE_SEQ, 1, 0x00, 0x00, 0xFD, 0xEA],
            )
            .unwrap(),
        ]),
    });

    match round_trip(&msg, vpnv6_codec()) {
        ParsedMessage::Update(ParsedUpdate::Routes { mp_reach, .. }) => {
            let r = mp_reach.expect("mp_reach must be present for VPNv6");
            assert_eq!(r.family, Family::IPV6_VPN);
            assert_eq!(
                r.nexthop,
                Some(nexthop),
                "nexthop mismatch after VPN RD strip"
            );
            assert_eq!(r.entries, vec![nlri]);
        }
        _ => panic!("expected Update"),
    }
}

// ─── encode_to split tests ────────────────────────────────────────────────────

fn check_message_sizes(raw: &[u8]) {
    let mut pos = 0;
    while pos < raw.len() {
        assert!(pos + 19 <= raw.len(), "truncated header at offset {}", pos);
        let msg_len = u16::from_be_bytes([raw[pos + 16], raw[pos + 17]]) as usize;
        assert!(
            msg_len <= 4096,
            "message at offset {} exceeds MAX_LENGTH: {}",
            pos,
            msg_len
        );
        assert!(
            msg_len >= 19,
            "message at offset {} too short: {}",
            pos,
            msg_len
        );
        pos += msg_len;
    }
    assert_eq!(pos, raw.len(), "trailing bytes in encoded buffer");
}

fn decode_all(buf: &mut BytesMut, codec: &mut PeerCodec) -> Vec<ParsedMessage> {
    let mut msgs = Vec::new();
    loop {
        match codec.try_parse(buf) {
            Ok(Some(msg)) => msgs.push(msg),
            Ok(None) => break,
            Err(e) => panic!("parse error: {:?}", e),
        }
    }
    msgs
}

fn assert_encode_decode_splits<F>(
    codec: &mut PeerCodec,
    msg: &Message,
    expected: &[PathNlri],
    collect: F,
) where
    F: Fn(ParsedMessage) -> Option<Vec<PathNlri>>,
{
    let mut raw = Vec::new();
    let wire_count = codec.encode_to(msg, &mut raw).unwrap();
    assert!(
        wire_count > 1,
        "expected split, got wire_count={}",
        wire_count
    );
    check_message_sizes(&raw);
    let mut buf = BytesMut::from(raw.as_slice());
    let all_nlri: Vec<PathNlri> = decode_all(&mut buf, codec)
        .into_iter()
        .filter_map(collect)
        .flatten()
        .collect();
    assert_eq!(all_nlri.len(), expected.len(), "NLRI count mismatch");
    for p in expected {
        assert!(all_nlri.contains(p), "missing NLRI: {:?}", p);
    }
}

fn ipv4_entries(n: u32) -> Vec<PathNlri> {
    (0..n)
        .map(|i| ipv4_prefix(&format!("10.{}.{}.0", i / 256, i % 256), 24))
        .collect()
}

fn ipv4_entries_addpath(n: u32) -> Vec<PathNlri> {
    (0..n)
        .map(|i| PathNlri {
            path_id: i + 1,
            nlri: Nlri::V4(Ipv4Net {
                addr: format!("10.{}.{}.0", i / 256, i % 256).parse().unwrap(),
                mask: 24,
            }),
        })
        .collect()
}

fn ipv6_entries(n: u16) -> Vec<PathNlri> {
    (0..n)
        .map(|i| {
            PathNlri::new(Nlri::V6(Ipv6Net {
                addr: Ipv6Addr::new(0x2001, 0x0db8, i, 0, 0, 0, 0, 0),
                mask: 48,
            }))
        })
        .collect()
}

fn ipv6_entries_addpath(n: u16) -> Vec<PathNlri> {
    (0..n)
        .map(|i| PathNlri {
            path_id: i as u32 + 1,
            nlri: Nlri::V6(Ipv6Net {
                addr: Ipv6Addr::new(0x2001, 0x0db8, i, 0, 0, 0, 0, 0),
                mask: 48,
            }),
        })
        .collect()
}

fn ipv4_addpath_codec() -> PeerCodec {
    let caps = vec![
        Capability::MultiProtocol(Family::IPV4),
        Capability::AddPath(vec![(Family::IPV4, 3)]),
    ];
    PeerCodec::negotiate(&caps, &caps)
}

fn ipv6_addpath_codec() -> PeerCodec {
    let caps = vec![
        Capability::MultiProtocol(Family::IPV6),
        Capability::AddPath(vec![(Family::IPV6, 3)]),
    ];
    PeerCodec::negotiate(&caps, &caps)
}

fn ipv6_attrs_no_nh() -> Arc<Vec<Attribute>> {
    Arc::new(vec![
        Attribute::new_with_value(Attribute::ORIGIN, 0).unwrap(),
        Attribute::new_with_bin(
            Attribute::AS_PATH,
            vec![Attribute::AS_PATH_TYPE_SEQ, 1, 0x00, 0x00, 0xFD, 0xEA],
        )
        .unwrap(),
    ])
}

#[test]
fn encode_to_splits_ipv4_reach() {
    let mut codec = ipv4_codec();
    let entries = ipv4_entries(1500);
    let msg = Message::Update(Update::Reach {
        family: Family::IPV4,
        entries: entries.clone(),
        nexthop: None,
        attr: ipv4_attrs("192.0.2.1".parse().unwrap()),
    });
    assert_encode_decode_splits(&mut codec, &msg, &entries, |m| match m {
        ParsedMessage::Update(ParsedUpdate::Routes { reach: Some(r), .. }) => Some(r.entries),
        _ => None,
    });
}

#[test]
fn encode_to_splits_ipv4_unreach() {
    let mut codec = ipv4_codec();
    let entries = ipv4_entries(1500);
    let msg = Message::Update(Update::Unreach {
        family: Family::IPV4,
        entries: entries.clone(),
    });
    assert_encode_decode_splits(&mut codec, &msg, &entries, |m| match m {
        ParsedMessage::Update(ParsedUpdate::Routes {
            unreach: Some(r), ..
        }) => Some(r.entries),
        _ => None,
    });
}

#[test]
fn encode_to_splits_ipv6_reach() {
    let mut codec = ipv6_codec();
    let entries = ipv6_entries(800);
    let msg = Message::Update(Update::Reach {
        family: Family::IPV6,
        entries: entries.clone(),
        nexthop: Some(Nexthop::V6("2001:db8::1".parse().unwrap())),
        attr: ipv6_attrs_no_nh(),
    });
    assert_encode_decode_splits(&mut codec, &msg, &entries, |m| match m {
        ParsedMessage::Update(ParsedUpdate::Routes {
            mp_reach: Some(r), ..
        }) => Some(r.entries),
        _ => None,
    });
}

#[test]
fn encode_to_splits_ipv6_unreach() {
    let mut codec = ipv6_codec();
    let entries = ipv6_entries(800);
    let msg = Message::Update(Update::Unreach {
        family: Family::IPV6,
        entries: entries.clone(),
    });
    assert_encode_decode_splits(&mut codec, &msg, &entries, |m| match m {
        ParsedMessage::Update(ParsedUpdate::Routes {
            mp_unreach: Some(r),
            ..
        }) => Some(r.entries),
        _ => None,
    });
}

#[test]
fn encode_to_splits_ipv4_reach_addpath() {
    let mut codec = ipv4_addpath_codec();
    let entries = ipv4_entries_addpath(700);
    let msg = Message::Update(Update::Reach {
        family: Family::IPV4,
        entries: entries.clone(),
        nexthop: None,
        attr: ipv4_attrs("192.0.2.1".parse().unwrap()),
    });
    assert_encode_decode_splits(&mut codec, &msg, &entries, |m| match m {
        ParsedMessage::Update(ParsedUpdate::Routes { reach: Some(r), .. }) => Some(r.entries),
        _ => None,
    });
}

#[test]
fn encode_to_splits_ipv4_unreach_addpath() {
    let mut codec = ipv4_addpath_codec();
    let entries = ipv4_entries_addpath(700);
    let msg = Message::Update(Update::Unreach {
        family: Family::IPV4,
        entries: entries.clone(),
    });
    assert_encode_decode_splits(&mut codec, &msg, &entries, |m| match m {
        ParsedMessage::Update(ParsedUpdate::Routes {
            unreach: Some(r), ..
        }) => Some(r.entries),
        _ => None,
    });
}

#[test]
fn encode_to_splits_ipv6_reach_addpath() {
    let mut codec = ipv6_addpath_codec();
    let entries = ipv6_entries_addpath(500);
    let msg = Message::Update(Update::Reach {
        family: Family::IPV6,
        entries: entries.clone(),
        nexthop: Some(Nexthop::V6("2001:db8::1".parse().unwrap())),
        attr: ipv6_attrs_no_nh(),
    });
    assert_encode_decode_splits(&mut codec, &msg, &entries, |m| match m {
        ParsedMessage::Update(ParsedUpdate::Routes {
            mp_reach: Some(r), ..
        }) => Some(r.entries),
        _ => None,
    });
}

#[test]
fn encode_to_splits_ipv6_unreach_addpath() {
    let mut codec = ipv6_addpath_codec();
    let entries = ipv6_entries_addpath(500);
    let msg = Message::Update(Update::Unreach {
        family: Family::IPV6,
        entries: entries.clone(),
    });
    assert_encode_decode_splits(&mut codec, &msg, &entries, |m| match m {
        ParsedMessage::Update(ParsedUpdate::Routes {
            mp_unreach: Some(r),
            ..
        }) => Some(r.entries),
        _ => None,
    });
}
