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
        c.put_slice(&[0; 3]);
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
                self.codec.encode_to(remote_open, &mut buf).unwrap();
                self.codec.encode_to(local_open, &mut buf).unwrap();
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
