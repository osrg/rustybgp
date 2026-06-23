// Copyright (C) 2021 The RustyBGP Authors.
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

use byteorder::{NetworkEndian, WriteBytesExt};
use bytes::{BufMut, BytesMut};
use std::net::{IpAddr, Ipv4Addr};
use tokio_util::codec::{Decoder, Encoder};

use crate::bgp;
use crate::error::Error;

#[allow(dead_code)]
impl Message {
    pub const ROUTE_MONITORING: u8 = 0;
    pub const STATS_REPORTS: u8 = 1;
    pub const PEER_DOWN: u8 = 2;
    pub const PEER_UP: u8 = 3;
    pub const INITIATION: u8 = 4;
    pub const TERMINATION: u8 = 5;
    pub const ROUTE_MIRRORING: u8 = 6;

    /// Per-peer type: Global Instance Peer (RFC 7854 §4.2).
    pub const PEER_TYPE_GLOBAL: u8 = 0;
    /// Per-peer type: Loc-RIB Instance Peer (RFC 9069 §3.1).
    pub const PEER_TYPE_LOC_RIB: u8 = 3;

    /// Per-peer header flag: peer address is IPv6 (RFC 7854 §4.2, V flag).
    pub const PEER_FLAG_IPV6: u8 = 0x80;
    /// Per-peer header flag: Adj-RIB-In post-policy (RFC 7854 §4.2, L flag).
    pub const PEER_FLAG_POST_POLICY: u8 = 0x40;
    /// Per-peer header flag: Adj-RIB-Out direction (RFC 8671 §4.1, O flag).
    pub const PEER_FLAG_ADJ_RIB_OUT: u8 = 0x10;
}

#[derive(Clone)]
pub struct PerPeerHeader {
    /// Peer Type field (RFC 7854 §4.2): 0 = Global, 3 = Loc-RIB (RFC 9069).
    peer_type: u8,
    /// Caller-supplied per-peer flags (L, O, A, …).
    /// The V (IPv6) flag is computed from `remote_addr` at encode time.
    flags: u8,
    pub asn: u32,
    id: Ipv4Addr,
    distinguisher: u64,
    pub remote_addr: IpAddr,
    timestamp: u32,
}

impl PerPeerHeader {
    pub fn new(
        flags: u8,
        asn: u32,
        id: Ipv4Addr,
        distinguisher: u64,
        remote_addr: IpAddr,
        timestamp: u32,
    ) -> Self {
        PerPeerHeader {
            peer_type: Message::PEER_TYPE_GLOBAL,
            flags,
            asn,
            id,
            distinguisher,
            remote_addr,
            timestamp,
        }
    }

    pub fn with_post_policy(self) -> Self {
        PerPeerHeader {
            flags: self.flags | Message::PEER_FLAG_POST_POLICY,
            ..self
        }
    }

    /// Set peer_type to Loc-RIB Instance Peer (RFC 9069 §3.1).
    pub fn with_peer_type(self, peer_type: u8) -> Self {
        PerPeerHeader { peer_type, ..self }
    }

    fn encode(&self, c: &mut BytesMut) -> Result<(), Error> {
        c.put_u8(self.peer_type);
        let wire_flags = self.flags
            | if self.remote_addr.is_ipv6() {
                Message::PEER_FLAG_IPV6
            } else {
                0
            };
        c.put_u8(wire_flags);
        c.put_u64(self.distinguisher);
        Message::encode_ip(c, &self.remote_addr);
        c.put_u32(self.asn);
        c.put_slice(&self.id.octets());
        c.put_u32(self.timestamp);
        c.put_u32(0);
        Ok(())
    }
}

#[allow(dead_code)]
#[derive(Clone)]
pub enum PeerDownReason {
    LocalNotification(bgp::Message),
    LocalFsm(u16),
    RemoteNotification(bgp::Message),
    RemoteUnexpected,
    Deconfigured,
}

impl PeerDownReason {
    fn code(&self) -> u8 {
        match self {
            Self::LocalNotification { .. } => 1,
            Self::LocalFsm { .. } => 2,
            Self::RemoteNotification { .. } => 3,
            Self::RemoteUnexpected { .. } => 4,
            Self::Deconfigured { .. } => 5,
        }
    }

    fn encode(&self, c: &mut BytesMut) -> Result<(), Error> {
        c.put_u8(self.code());
        let mut codec = bgp::PeerCodec::new();
        match self {
            Self::LocalNotification(notification) => {
                let mut buf = bytes::BytesMut::with_capacity(4096);
                codec.encode_to(notification, &mut buf).unwrap();
                c.put_slice(buf.as_ref());
            }
            Self::LocalFsm(code) => {
                c.put_u16(*code);
            }
            Self::RemoteNotification(notification) => {
                let mut buf = bytes::BytesMut::with_capacity(4096);
                codec.encode_to(notification, &mut buf).unwrap();
                c.put_slice(buf.as_ref());
            }
            _ => {}
        }
        Ok(())
    }
}

#[allow(dead_code)]
pub enum Message {
    RouteMonitoring {
        header: PerPeerHeader,
        update: bgp::Message,
        addpath: bool,
    },
    StatsReports,
    PeerDown {
        header: PerPeerHeader,
        reason: PeerDownReason,
    },
    PeerUp {
        header: PerPeerHeader,
        local_addr: IpAddr,
        local_port: u16,
        remote_port: u16,
        local_open: bgp::Message,
        remote_open: bgp::Message,
    },
    Initiation(Vec<(u16, Vec<u8>)>),
    Termination,
    RouteMirroring,
}

impl Message {
    const VERSION: u8 = 3;

    pub const INFO_TYPE_SYSDESCR: u16 = 1;
    pub const INFO_TYPE_SYSNAME: u16 = 2;

    fn code(&self) -> u8 {
        match self {
            Message::RouteMonitoring { .. } => Message::ROUTE_MONITORING,
            Message::StatsReports => Message::STATS_REPORTS,
            Message::PeerDown { .. } => Message::PEER_DOWN,
            Message::PeerUp { .. } => Message::PEER_UP,
            Message::Initiation(_) => Message::INITIATION,
            Message::Termination => Message::TERMINATION,
            Message::RouteMirroring => Message::ROUTE_MIRRORING,
        }
    }

    fn encode_ip(c: &mut BytesMut, addr: &IpAddr) {
        match addr {
            IpAddr::V4(addr) => {
                c.put_slice(&[0; 12]);
                c.put_slice(&addr.octets());
            }
            IpAddr::V6(addr) => c.put_slice(&addr.octets()),
        }
    }
}

pub struct BmpCodec {
    codec: bgp::PeerCodec,
}

impl Default for BmpCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl BmpCodec {
    pub fn new() -> Self {
        BmpCodec {
            codec: bgp::PeerCodec::new(),
        }
    }
}

impl Encoder<&Message> for BmpCodec {
    type Error = Error;

    fn encode(&mut self, item: &Message, c: &mut BytesMut) -> Result<(), Error> {
        let pos_first = c.len();
        c.put_u8(Message::VERSION);
        let pos_len = c.len();
        c.put_u32(0);
        c.put_u8(item.code());

        match item {
            Message::RouteMonitoring {
                header,
                update,
                addpath,
            } => {
                header.encode(c).unwrap();
                let mut buf = bytes::BytesMut::with_capacity(4096);
                let family = match update {
                    bgp::Message::Update(bgp::Update::Reach { family, .. }) => Some(*family),
                    bgp::Message::Update(bgp::Update::Unreach { family, .. }) => Some(*family),
                    bgp::Message::Update(bgp::Update::EndOfRib(family)) => Some(*family),
                    _ => None,
                };
                if let Some(family) = family {
                    self.codec.set_family(
                        family,
                        bgp::FamilyState {
                            addpath_tx: *addpath,
                            ..Default::default()
                        },
                    );
                }
                self.codec.encode_to(update, &mut buf).unwrap();
                c.put_slice(buf.as_ref());
            }
            Message::StatsReports => {}
            Message::PeerDown { header, reason } => {
                header.encode(c).unwrap();
                reason.encode(c).unwrap();
            }
            Message::PeerUp {
                header,
                local_addr,
                local_port,
                remote_port,
                local_open,
                remote_open,
            } => {
                header.encode(c).unwrap();
                Message::encode_ip(c, local_addr);
                c.put_u16(*local_port);
                c.put_u16(*remote_port);
                let mut buf = bytes::BytesMut::with_capacity(4096 * 2);
                // RFC 7854 §4.10: Sent OPEN (local) first, Received OPEN (remote) second.
                self.codec.encode_to(local_open, &mut buf).unwrap();
                self.codec.encode_to(remote_open, &mut buf).unwrap();
                c.put_slice(buf.as_ref());
            }
            Message::Initiation(tlv) => {
                for (t, bin) in tlv {
                    c.put_u16(*t);
                    c.put_u16(bin.len() as u16);
                    c.put_slice(bin);
                }
            }
            Message::Termination => {}
            Message::RouteMirroring => {}
        }

        let len = c.len() - pos_first;
        (&mut c.as_mut()[pos_len..])
            .write_u32::<NetworkEndian>(len as u32)
            .unwrap();

        Ok(())
    }
}

impl Decoder for BmpCodec {
    type Item = Message;
    type Error = Error;

    fn decode(&mut self, _src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::{
        self, Attribute, Family, HoldTime, Ipv4Net, Ipv6Net, Nexthop, Nlri, PathNlri, Update,
    };
    use bytes::BytesMut;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;
    use std::sync::Arc;
    use tokio_util::codec::Encoder;

    fn encode(msg: &Message) -> String {
        let mut codec = BmpCodec::new();
        let mut buf = BytesMut::new();
        codec.encode(msg, &mut buf).unwrap();
        buf.iter().map(|b| format!("{:02x}", b)).collect()
    }

    // PerPeerHeader for a Global IPv4 peer: ASN=65002, BGP-ID=10.0.0.2, addr=192.168.0.1, ts=0.
    fn ipv4_peer_header() -> PerPeerHeader {
        PerPeerHeader::new(
            0,
            65002,
            Ipv4Addr::new(10, 0, 0, 2),
            0,
            IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
            0,
        )
    }

    // PerPeerHeader for a Global IPv6 peer: ASN=65002, BGP-ID=10.0.0.2, addr=2001:db8::1, ts=0.
    fn ipv6_peer_header() -> PerPeerHeader {
        PerPeerHeader::new(
            0,
            65002,
            Ipv4Addr::new(10, 0, 0, 2),
            0,
            IpAddr::V6(Ipv6Addr::from_str("2001:db8::1").unwrap()),
            0,
        )
    }

    // BGP OPEN sent by the local router: AS=65001, hold=90, router-id=10.0.0.1, no caps.
    fn local_open() -> bgp::Message {
        bgp::Message::Open(bgp::Open {
            as_number: 65001,
            holdtime: HoldTime::new(90).unwrap(),
            router_id: u32::from(Ipv4Addr::new(10, 0, 0, 1)),
            capability: vec![],
        })
    }

    // BGP OPEN received from the remote peer: AS=65002, hold=90, router-id=10.0.0.2, no caps.
    fn remote_open() -> bgp::Message {
        bgp::Message::Open(bgp::Open {
            as_number: 65002,
            holdtime: HoldTime::new(90).unwrap(),
            router_id: u32::from(Ipv4Addr::new(10, 0, 0, 2)),
            capability: vec![],
        })
    }

    // Common attrs: ORIGIN IGP + AS_PATH [65001].  NEXTHOP is added by the encoder for IPv4.
    fn basic_attrs() -> Arc<Vec<Attribute>> {
        Arc::new(vec![
            Attribute::new_with_value(Attribute::ORIGIN, 0).unwrap(),
            // AS_PATH: SEQ, count=1, ASN=65001 (4-byte).
            Attribute::new_with_bin(Attribute::AS_PATH, vec![0x02, 0x01, 0x00, 0x00, 0xfd, 0xe9])
                .unwrap(),
        ])
    }

    fn ipv4_reach_update() -> bgp::Message {
        bgp::Message::Update(Update::Reach {
            family: Family::IPV4,
            entries: vec![PathNlri {
                nlri: Nlri::V4(Ipv4Net {
                    addr: Ipv4Addr::new(10, 1, 0, 0),
                    mask: 24,
                }),
                path_id: 0,
            }],
            nexthop: Some(Nexthop::V4(Ipv4Addr::new(192, 168, 0, 1))),
            attr: basic_attrs(),
        })
    }

    fn ipv6_reach_update() -> bgp::Message {
        bgp::Message::Update(Update::Reach {
            family: Family::IPV6,
            entries: vec![PathNlri {
                nlri: Nlri::V6(Ipv6Net {
                    addr: Ipv6Addr::from_str("2001:db8:1::").unwrap(),
                    mask: 48,
                }),
                path_id: 0,
            }],
            nexthop: Some(Nexthop::V6(Ipv6Addr::from_str("2001:db8::1").unwrap())),
            attr: basic_attrs(),
        })
    }

    // --- Initiation ---
    // Reference: GoBGP NewBMPInitiation([SYSDESCR="RustyBGP", SYSNAME="router1"]).
    #[test]
    fn initiation() {
        let msg = Message::Initiation(vec![
            (Message::INFO_TYPE_SYSDESCR, b"RustyBGP".to_vec()),
            (Message::INFO_TYPE_SYSNAME, b"router1".to_vec()),
        ]);
        assert_eq!(
            encode(&msg),
            "030000001d0400010008527573747942475000020007726f7574657231",
        );
    }

    // --- PeerUp IPv4 ---
    // Reference: GoBGP NewBMPPeerUpNotification(ipv4_header, "10.0.0.1", 179, 12345, sent, recv).
    // RFC 7854 §4.10 order: Sent (local) first, Received (remote) second.
    #[test]
    fn peer_up() {
        let msg = Message::PeerUp {
            header: ipv4_peer_header(),
            local_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            local_port: 179,
            remote_port: 12345,
            local_open: local_open(),
            remote_open: remote_open(),
        };
        assert_eq!(
            encode(&msg),
            "030000007e0300000000000000000000000000000000000000000000c0a800010000fdea0a00000200000000000000000000000000000000000000000a00000100b33039ffffffffffffffffffffffffffffffff001d0104fde9005a0a00000100ffffffffffffffffffffffffffffffff001d0104fdea005a0a00000200",
        );
    }

    // --- PeerUp IPv6 ---
    // Reference: GoBGP NewBMPPeerUpNotification(ipv6_header, "2001:db8::2", 179, 12345, sent, recv).
    #[test]
    fn peer_up_ipv6() {
        let msg = Message::PeerUp {
            header: ipv6_peer_header(),
            local_addr: IpAddr::V6(Ipv6Addr::from_str("2001:db8::2").unwrap()),
            local_port: 179,
            remote_port: 12345,
            local_open: local_open(),
            remote_open: remote_open(),
        };
        assert_eq!(
            encode(&msg),
            "030000007e030080000000000000000020010db80000000000000000000000010000fdea0a000002000000000000000020010db800000000000000000000000200b33039ffffffffffffffffffffffffffffffff001d0104fde9005a0a00000100ffffffffffffffffffffffffffffffff001d0104fdea005a0a00000200",
        );
    }

    // --- PeerDown LocalNotification ---
    // Reference: GoBGP NewBMPPeerDownNotification(ipv4_header, REASON_LOCAL_BGP_NOTIFICATION,
    //            CEASE/AdministrativeShutdown NOTIFICATION, nil).
    #[test]
    fn peer_down_local_notification() {
        let notif = bgp::Message::Notification(bgp::Notification::CeaseAdminShutdown);
        let msg = Message::PeerDown {
            header: ipv4_peer_header(),
            reason: PeerDownReason::LocalNotification(notif),
        };
        assert_eq!(
            encode(&msg),
            "03000000460200000000000000000000000000000000000000000000c0a800010000fdea0a000002000000000000000001ffffffffffffffffffffffffffffffff0015030602",
        );
    }

    // --- RouteMonitoring IPv4 Reach (pre-policy) ---
    // Reference: GoBGP NewBMPRouteMonitoring(ipv4_header, ipv4_reach_update).
    #[test]
    fn route_monitoring_ipv4_reach() {
        let msg = Message::RouteMonitoring {
            header: ipv4_peer_header(),
            update: ipv4_reach_update(),
            addpath: false,
        };
        assert_eq!(
            encode(&msg),
            "030000005f0000000000000000000000000000000000000000000000c0a800010000fdea0a0000020000000000000000ffffffffffffffffffffffffffffffff002f02000000144001010040020602010000fde9400304c0a80001180a0100",
        );
    }

    // --- RouteMonitoring IPv4 Reach (post-policy, L flag) ---
    // Reference: GoBGP NewBMPRouteMonitoring(post_policy_header, ipv4_reach_update).
    #[test]
    fn route_monitoring_ipv4_reach_post() {
        let msg = Message::RouteMonitoring {
            header: ipv4_peer_header().with_post_policy(),
            update: ipv4_reach_update(),
            addpath: false,
        };
        assert_eq!(
            encode(&msg),
            "030000005f0000400000000000000000000000000000000000000000c0a800010000fdea0a0000020000000000000000ffffffffffffffffffffffffffffffff002f02000000144001010040020602010000fde9400304c0a80001180a0100",
        );
    }

    // --- RouteMonitoring IPv4 EoR ---
    // Reference: GoBGP NewBMPRouteMonitoring(ipv4_header, empty UPDATE).
    #[test]
    fn route_monitoring_ipv4_eor() {
        let msg = Message::RouteMonitoring {
            header: ipv4_peer_header(),
            update: bgp::Message::Update(Update::EndOfRib(Family::IPV4)),
            addpath: false,
        };
        assert_eq!(
            encode(&msg),
            "03000000470000000000000000000000000000000000000000000000c0a800010000fdea0a0000020000000000000000ffffffffffffffffffffffffffffffff00170200000000",
        );
    }

    // --- RouteMonitoring IPv4 Unreach ---
    // Reference: GoBGP NewBMPRouteMonitoring(ipv4_header, withdrawn 10.1.0.0/24).
    #[test]
    fn route_monitoring_ipv4_unreach() {
        let msg = Message::RouteMonitoring {
            header: ipv4_peer_header(),
            update: bgp::Message::Update(Update::Unreach {
                family: Family::IPV4,
                entries: vec![PathNlri {
                    nlri: Nlri::V4(Ipv4Net {
                        addr: Ipv4Addr::new(10, 1, 0, 0),
                        mask: 24,
                    }),
                    path_id: 0,
                }],
            }),
            addpath: false,
        };
        assert_eq!(
            encode(&msg),
            "030000004b0000000000000000000000000000000000000000000000c0a800010000fdea0a0000020000000000000000ffffffffffffffffffffffffffffffff001b020004180a01000000",
        );
    }

    // --- RouteMonitoring IPv6 Reach ---
    // RustyBGP uses FLAG_EXTENDED (0x90) for MP_REACH_NLRI; GoBGP uses 0x80.
    // All other bytes are identical to GoBGP output.
    #[test]
    fn route_monitoring_ipv6_reach() {
        let msg = Message::RouteMonitoring {
            header: ipv6_peer_header(),
            update: ipv6_reach_update(),
            addpath: false,
        };
        assert_eq!(
            encode(&msg),
            "0300000074000080000000000000000020010db80000000000000000000000010000fdea0a0000020000000000000000ffffffffffffffffffffffffffffffff0044020000002d4001010040020602010000fde9900e001c0002011020010db8000000000000000000000001003020010db80001",
        );
    }

    // --- RouteMonitoring IPv6 EoR ---
    // RustyBGP uses FLAG_EXTENDED (0x90) for MP_UNREACH_NLRI; GoBGP uses 0x80.
    #[test]
    fn route_monitoring_ipv6_eor() {
        let msg = Message::RouteMonitoring {
            header: ipv6_peer_header(),
            update: bgp::Message::Update(Update::EndOfRib(Family::IPV6)),
            addpath: false,
        };
        assert_eq!(
            encode(&msg),
            "030000004e000080000000000000000020010db80000000000000000000000010000fdea0a0000020000000000000000ffffffffffffffffffffffffffffffff001e0200000007900f0003000201",
        );
    }

    // --- RouteMonitoring Loc-RIB (RFC 9069, peer_type=3) ---
    // Reference: GoBGP NewBMPRouteMonitoring(loc_rib_header, ipv4_reach_update).
    // peer_type=3, peer_addr=0.0.0.0, BGP-ID=10.0.0.1, ASN=65001.
    #[test]
    fn route_monitoring_loc_rib() {
        let header = PerPeerHeader::new(
            0,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            0,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            0,
        )
        .with_peer_type(Message::PEER_TYPE_LOC_RIB);
        let msg = Message::RouteMonitoring {
            header,
            update: ipv4_reach_update(),
            addpath: false,
        };
        assert_eq!(
            encode(&msg),
            "030000005f0003000000000000000000000000000000000000000000000000000000fde90a0000010000000000000000ffffffffffffffffffffffffffffffff002f02000000144001010040020602010000fde9400304c0a80001180a0100",
        );
    }
}
