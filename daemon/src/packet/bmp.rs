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

use crate::error::Error;
use crate::packet::bgp;

#[allow(dead_code)]
impl Message {
    pub(crate) const ROUTE_MONITORING: u8 = 0;
    pub(crate) const STATS_REPORTS: u8 = 1;
    pub(crate) const PEER_DOWN: u8 = 2;
    pub(crate) const PEER_UP: u8 = 3;
    pub(crate) const INITIATION: u8 = 4;
    pub(crate) const TERMINATION: u8 = 6;
    pub(crate) const ROUTE_MIRRORING: u8 = 7;
}

#[derive(Clone)]
pub(crate) struct PerPeerHeader {
    asn: u32,
    id: Ipv4Addr,
    distinguisher: u64,
    remote_addr: IpAddr,
    timestamp: u32,
}

impl PerPeerHeader {
    pub(crate) fn new(
        asn: u32,
        id: Ipv4Addr,
        distinguisher: u64,
        remote_addr: IpAddr,
        timestamp: u32,
    ) -> Self {
        PerPeerHeader {
            asn,
            id,
            distinguisher,
            remote_addr,
            timestamp,
        }
    }

    fn encode(&self, c: &mut BytesMut) -> Result<(), Error> {
        // type
        c.put_u8(0);
        // only adj-in is supported
        let mut flags = 0;
        if self.remote_addr.is_ipv6() {
            flags |= 1;
        }
        c.put_u8(flags);
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
pub(crate) enum PeerDownReason {
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
        match self {
            Self::LocalNotification(notification) => {
                let mut buf = bytes::BytesMut::with_capacity(4096);
                bgp::BgpCodec::new().encode(notification, &mut buf).unwrap();
                c.put_slice(buf.as_ref());
            }
            Self::LocalFsm(code) => {
                c.put_u16(*code);
            }
            Self::RemoteNotification(notification) => {
                let mut buf = bytes::BytesMut::with_capacity(4096);
                bgp::BgpCodec::new().encode(notification, &mut buf).unwrap();
                c.put_slice(buf.as_ref());
            }
            _ => {}
        }
        Ok(())
    }
}

#[allow(dead_code)]
pub(crate) enum Message {
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

    pub(crate) const INFO_TYPE_SYSDESCR: u16 = 1;
    pub(crate) const INFO_TYPE_SYSNAME: u16 = 2;

    fn code(&self) -> u8 {
        match self {
            Message::RouteMonitoring { .. } => Message::ROUTE_MONITORING,
            Message::StatsReports { .. } => Message::STATS_REPORTS,
            Message::PeerDown { .. } => Message::PEER_DOWN,
            Message::PeerUp { .. } => Message::PEER_UP,
            Message::Initiation { .. } => Message::INITIATION,
            Message::Termination { .. } => Message::TERMINATION,
            Message::RouteMirroring { .. } => Message::ROUTE_MIRRORING,
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

pub(crate) struct BmpCodec {
    codec: bgp::BgpCodec,
}

impl BmpCodec {
    pub(crate) fn new() -> Self {
        let codec = bgp::BgpCodec::new().keep_aspath(true).keep_nexthop(true);
        BmpCodec { codec }
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
                if let bgp::Message::Update {
                    reach,
                    unreach,
                    attr: _,
                } = update
                {
                    let family = if let Some((f, _)) = reach {
                        *f
                    } else {
                        unreach.as_ref().unwrap().0
                    };
                    self.codec
                        .channel
                        .insert(family, bgp::Channel::new(family, false, *addpath));
                }
                self.codec.encode(update, &mut buf).unwrap();
                c.put_slice(buf.as_ref());
            }
            Message::StatsReports { .. } => {}
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
                self.codec.encode(remote_open, &mut buf).unwrap();
                self.codec.encode(local_open, &mut buf).unwrap();
                c.put_slice(buf.as_ref());
            }
            Message::Initiation(tlv) => {
                for (t, bin) in tlv {
                    c.put_u16(*t);
                    c.put_u16(bin.len() as u16);
                    c.put_slice(bin);
                }
            }
            Message::Termination { .. } => {}
            Message::RouteMirroring { .. } => {}
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
