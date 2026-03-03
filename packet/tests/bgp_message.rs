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
use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

#[test]
fn ipv6_eor() {
    let mut buf = [0xff; 16].to_vec();
    let mut body: Vec<u8> = vec![
        0x00, 0x1e, 0x02, 0x00, 0x00, 0x00, 0x07, 0x90, 0x0f, 0x00, 0x03, 0x00, 0x02, 0x01,
    ];
    buf.append(&mut body);
    let mut codec = PeerCodecBuilder::new().families(vec![Family::IPV6]).build();
    assert!(codec.parse_message(&buf).is_ok());
}

#[test]
fn parse_ipv6_update() {
    use std::io::Read;
    let filename = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/packet/ipv6-update.raw");
    let mut file = std::fs::File::open(filename).unwrap();
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).unwrap();

    let expected: Vec<PathNlri> = vec![
        Nlri::V6(Ipv6Net {
            addr: Ipv6Addr::new(0x2003, 0xde, 0x2016, 0x127, 0, 0, 0, 0),
            mask: 64,
        }),
        Nlri::V6(Ipv6Net {
            addr: Ipv6Addr::new(0x2003, 0xde, 0x2016, 0x124, 0, 0, 0, 0),
            mask: 64,
        }),
        Nlri::V6(Ipv6Net {
            addr: Ipv6Addr::new(0x2003, 0xde, 0x2016, 0x128, 0, 0, 0, 0),
            mask: 63,
        }),
        Nlri::V6(Ipv6Net {
            addr: Ipv6Addr::new(0x2003, 0xde, 0x2016, 0x1ff, 0, 0, 0, 0x12),
            mask: 127,
        }),
    ]
    .into_iter()
    .map(PathNlri::new)
    .collect();

    let mut codec = PeerCodecBuilder::new().families(vec![Family::IPV6]).build();
    let msg = codec.parse_message(&buf).unwrap();
    match msg {
        Message::Update { reach, .. } => {
            let s = reach.unwrap();
            assert_eq!(s.family, Family::IPV6);
            assert_eq!(s.entries.len(), expected.len());
            for (got, want) in s.entries.iter().zip(expected.iter()) {
                assert_eq!(got, want);
            }
        }
        _ => unreachable!(),
    }
}

#[test]
fn build_many_v4_route() {
    let net: Vec<Nlri> = (0..2000u16)
        .map(|i| {
            Nlri::V4(Ipv4Net {
                addr: Ipv4Addr::new(10, ((0xff00 & i) >> 8) as u8, (0xff & i) as u8, 1),
                mask: 32,
            })
        })
        .collect();

    let mut set: HashSet<PathNlri> = net.iter().cloned().map(PathNlri::new).collect();

    let mut msg = Message::Update {
        reach: Some(NlriSet {
            family: Family::IPV4,
            entries: net.iter().cloned().map(PathNlri::new).collect(),
        }),
        attr: Arc::new(vec![
            Attribute::new_with_value(Attribute::ORIGIN, 0).unwrap(),
            Attribute::new_with_bin(Attribute::AS_PATH, vec![2, 1, 1, 0, 0, 0]).unwrap(),
            Attribute::new_with_bin(Attribute::NEXTHOP, vec![0, 0, 0, 0]).unwrap(),
        ]),
        unreach: None,
    };

    let codec = PeerCodecBuilder::new()
        .families(vec![Family::IPV4])
        .keep_aspath(true)
        .build();
    let mut txbuf = BytesMut::with_capacity(4096);
    let mut framer = BgpFramer::new(codec);
    framer.encode_to(&msg, &mut txbuf).unwrap();

    let mut recv = Vec::new();
    loop {
        match framer.try_parse(&mut txbuf).expect("failed to decode") {
            Some(Message::Update { reach, .. }) => recv.append(&mut reach.unwrap().entries),
            Some(_) => {}
            None => break,
        }
    }
    assert_eq!(recv.len(), net.len());
    for n in &recv {
        assert!(set.remove(n));
    }
    assert_eq!(set.len(), 0);

    msg = Message::Update {
        reach: None,
        attr: Arc::new(Vec::new()),
        unreach: Some(NlriSet {
            family: Family::IPV4,
            entries: net.iter().cloned().map(PathNlri::new).collect(),
        }),
    };
    for n in &net {
        set.insert(PathNlri::new(*n));
    }

    framer.encode_to(&msg, &mut txbuf).unwrap();
    let mut withdrawn = Vec::new();
    loop {
        match framer.try_parse(&mut txbuf).expect("failed to decode") {
            Some(Message::Update { unreach, .. }) => {
                withdrawn.append(&mut unreach.unwrap().entries)
            }
            Some(_) => {}
            None => break,
        }
    }
    assert_eq!(withdrawn.len(), net.len());
    for n in &withdrawn {
        assert!(set.remove(n));
    }
    assert_eq!(set.len(), 0);
}

#[test]
fn many_mp_reach() {
    let net: Vec<Nlri> = (0..2000u128)
        .map(|i| {
            Nlri::V6(Ipv6Net {
                addr: Ipv6Addr::from(i),
                mask: 128,
            })
        })
        .collect();

    let mut set: HashSet<PathNlri> = net.iter().cloned().map(PathNlri::new).collect();

    let msg = Message::Update {
        reach: Some(NlriSet {
            family: Family::IPV6,
            entries: net.iter().cloned().map(PathNlri::new).collect(),
        }),
        attr: Arc::new(vec![
            Attribute::new_with_value(Attribute::ORIGIN, 0).unwrap(),
            Attribute::new_with_bin(Attribute::AS_PATH, vec![2, 1, 1, 0, 0, 0]).unwrap(),
            Attribute::new_with_bin(Attribute::NEXTHOP, (0..31).collect::<Vec<u8>>()).unwrap(),
        ]),
        unreach: None,
    };

    let codec = PeerCodecBuilder::new().families(vec![Family::IPV6]).build();
    let mut txbuf = BytesMut::with_capacity(4096);
    let mut framer = BgpFramer::new(codec);
    framer.encode_to(&msg, &mut txbuf).unwrap();

    let mut recv = Vec::new();
    loop {
        match framer.try_parse(&mut txbuf).expect("failed to decode") {
            Some(Message::Update { reach, .. }) => recv.append(&mut reach.unwrap().entries),
            Some(_) => {}
            None => break,
        }
    }
    assert_eq!(recv.len(), net.len());
    for n in &recv {
        assert!(set.remove(n));
    }
    assert_eq!(set.len(), 0);
}

#[test]
fn many_mp_unreach() {
    let net: Vec<Nlri> = (0..2000u128)
        .map(|i| {
            Nlri::V6(Ipv6Net {
                addr: Ipv6Addr::from(i),
                mask: 128,
            })
        })
        .collect();

    let mut set: HashSet<PathNlri> = net.iter().cloned().map(PathNlri::new).collect();

    let msg = Message::Update {
        reach: None,
        attr: Arc::new(Vec::new()),
        unreach: Some(NlriSet {
            family: Family::IPV6,
            entries: net.iter().cloned().map(PathNlri::new).collect(),
        }),
    };

    let codec = PeerCodecBuilder::new().families(vec![Family::IPV6]).build();
    let mut txbuf = BytesMut::with_capacity(4096);
    let mut framer = BgpFramer::new(codec);
    framer.encode_to(&msg, &mut txbuf).unwrap();

    let mut recv = Vec::new();
    loop {
        match framer.try_parse(&mut txbuf).expect("failed to decode") {
            Some(Message::Update { unreach, .. }) => recv.append(&mut unreach.unwrap().entries),
            Some(_) => {}
            None => break,
        }
    }
    assert_eq!(recv.len(), net.len());
    for n in &recv {
        assert!(set.remove(n));
    }
    assert_eq!(set.len(), 0);
}
