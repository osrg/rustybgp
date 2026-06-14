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

use rustybgp_packet::bgp::{
    Attribute, Capability, Ipv4Net, Ipv6Net, Message, Nexthop, ParsedMessage, ParsedUpdate,
    PeerCodec, ReachNlri, UnreachNlri, Update,
};
use rustybgp_packet::mup;
use rustybgp_packet::prefix_sid;
use rustybgp_packet::rd::RouteDistinguisher;
use rustybgp_packet::{Family, Nlri, PathNlri};
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
    let msg = Message::Update(Update::Routes {
        reach: Some(ReachNlri {
            family: Family::IPV4,
            entries: vec![prefix.clone()],
            nexthop: None,
        }),
        attr: ipv4_attrs("192.0.2.254".parse().unwrap()),
        unreach: None,
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

    let msg = Message::Update(Update::Routes {
        reach: Some(ReachNlri {
            family: Family::IPV4,
            entries: prefixes.clone(),
            nexthop: None,
        }),
        attr: ipv4_attrs("192.0.2.254".parse().unwrap()),
        unreach: None,
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
    let msg = Message::Update(Update::Routes {
        reach: None,
        attr: Arc::new(Vec::new()),
        unreach: Some(UnreachNlri {
            family: Family::IPV4,
            entries: vec![prefix.clone()],
        }),
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

    let msg = Message::Update(Update::Routes {
        reach: Some(ReachNlri {
            family: Family::IPV6,
            entries: vec![prefix.clone()],
            nexthop: None,
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
    let msg = Message::Update(Update::Routes {
        reach: None,
        attr: Arc::new(Vec::new()),
        unreach: Some(UnreachNlri {
            family: Family::IPV6,
            entries: vec![prefix.clone()],
        }),
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
    let msg = Message::Update(Update::Routes {
        reach: Some(ReachNlri {
            family: Family::IPV4,
            entries: vec![ipv4_prefix("10.0.0.0", 8)],
            nexthop: None,
        }),
        attr: ipv4_attrs("192.0.2.254".parse().unwrap()),
        unreach: None,
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

    let msg = Message::Update(Update::Routes {
        reach: Some(ReachNlri {
            family: Family::IPV4,
            entries: vec![ipv4_prefix("10.0.0.0", 8)],
            nexthop: None,
        }),
        attr: Arc::new(attrs),
        unreach: None,
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

    let msg = Message::Update(Update::Routes {
        reach: Some(ReachNlri {
            family: Family::IPV4,
            entries: vec![prefix.clone()],
            nexthop: Some(Nexthop::V6(nexthop_v6)),
        }),
        attr: Arc::new(vec![
            Attribute::new_with_value(Attribute::ORIGIN, 0).unwrap(),
            Attribute::new_with_bin(
                Attribute::AS_PATH,
                vec![Attribute::AS_PATH_TYPE_SEQ, 1, 0x00, 0x00, 0xFD, 0xEA],
            )
            .unwrap(),
        ]),
        unreach: None,
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
    let msg = Message::Update(Update::Routes {
        reach: None,
        attr: Arc::new(Vec::new()),
        unreach: Some(UnreachNlri {
            family: Family::IPV4,
            entries: vec![prefix.clone()],
        }),
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

    let msg = Message::Update(Update::Routes {
        reach: Some(ReachNlri {
            family: Family::IPV4,
            entries: vec![ipv4_prefix("10.0.0.0", 8)],
            nexthop: None,
        }),
        attr: Arc::new(attrs),
        unreach: None,
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

    let msg = Message::Update(Update::Routes {
        reach: Some(ReachNlri {
            family: Family::IPV4,
            entries: vec![prefix.clone()],
            nexthop: None,
        }),
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
        unreach: None,
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

    let msg = Message::Update(Update::Routes {
        reach: Some(ReachNlri {
            family: Family::IPV4,
            entries: vec![prefix.clone()],
            nexthop: None,
        }),
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
        unreach: None,
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
    let msg = Message::Update(Update::Routes {
        reach: Some(ReachNlri {
            family: Family::IPV4_MUP,
            entries: vec![nlri.clone()],
            nexthop: None,
        }),
        attr: Arc::new(vec![
            Attribute::new_with_value(Attribute::ORIGIN, 0).unwrap(),
            Attribute::new_with_bin(
                Attribute::AS_PATH,
                vec![Attribute::AS_PATH_TYPE_SEQ, 1, 0x00, 0x00, 0xFD, 0xEA],
            )
            .unwrap(),
            Attribute::new_with_bin(Attribute::NEXTHOP, nexthop.octets().to_vec()).unwrap(),
        ]),
        unreach: None,
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
    let msg = Message::Update(Update::Routes {
        reach: Some(ReachNlri {
            family: Family::IPV6_MUP,
            entries: vec![nlri.clone()],
            nexthop: None,
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
    let msg = Message::Update(Update::Routes {
        reach: None,
        attr: Arc::new(Vec::new()),
        unreach: Some(UnreachNlri {
            family: Family::IPV4_MUP,
            entries: vec![nlri.clone()],
        }),
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
    let msg = Message::Update(Update::Routes {
        reach: Some(ReachNlri {
            family: Family::IPV4_MUP,
            entries: vec![nlri.clone()],
            nexthop: None,
        }),
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
        unreach: None,
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
