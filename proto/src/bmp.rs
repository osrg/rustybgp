// Copyright (C) 2020 The RustyBGP Authors.
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
use failure::Error;
use std::convert::From;
use std::io::{Cursor, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::time::SystemTime;

pub const DEFAULT_PORT: u16 = 11019;

#[derive(Clone)]
struct CommonHeader {
    pub version: u8,
    pub length: u32,
    pub message_type: u8,
}

impl CommonHeader {
    const VERSION: u8 = 3;
    const LENGTH: u32 = 6;

    fn to_bytes(&self, c: &mut Cursor<Vec<u8>>) -> Result<usize, Error> {
        c.write_u8(self.version)?;
        c.write_u32::<NetworkEndian>(self.length)?;
        c.write_u8(self.message_type)?;
        Ok(6)
    }
}

#[derive(Clone)]
pub struct PeerHeader {
    pub peer_type: u8,
    pub flags: u8,
    pub distinguisher: u64,
    pub address: IpAddr,
    pub as_number: u32,
    pub id: Ipv4Addr,
    pub timestamp: SystemTime,
}

impl PeerHeader {
    const FLAG_IPV6: u8 = 1 << 7;

    pub fn new(
        peer_type: u8,
        distinguisher: u64,
        address: IpAddr,
        as_number: u32,
        id: Ipv4Addr,
        timestamp: SystemTime,
    ) -> PeerHeader {
        let flags: u8 = match address {
            IpAddr::V4(_) => 0,
            IpAddr::V6(_) => PeerHeader::FLAG_IPV6,
        };
        PeerHeader {
            peer_type,
            flags,
            distinguisher,
            address,
            as_number,
            id,
            timestamp,
        }
    }

    fn to_bytes(&self, c: &mut Cursor<Vec<u8>>) -> Result<usize, Error> {
        let pos = c.position();
        c.write_u8(self.peer_type)?;
        c.write_u8(self.flags)?;
        c.write_u64::<NetworkEndian>(self.distinguisher)?;
        match self.address {
            IpAddr::V4(addr) => {
                c.set_position(c.position() + 12);
                c.write_u32::<NetworkEndian>(u32::from(addr))?;
            }
            IpAddr::V6(addr) => {
                for i in &addr.octets() {
                    c.write_u8(*i)?;
                }
            }
        }
        c.write_u32::<NetworkEndian>(self.as_number)?;
        c.write_all(&self.id.octets())?;
        let unix = self
            .timestamp
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();
        c.write_u32::<NetworkEndian>(unix.as_secs() as u32)?;
        c.write_u32::<NetworkEndian>(unix.subsec_micros() as u32)?;
        Ok((c.position() - pos) as usize)
    }
}

#[derive(Clone)]
pub struct RouteMonitoring {
    pub peer_header: PeerHeader,
    pub payload: Vec<u8>,
}

impl RouteMonitoring {}

impl BmpMessage for RouteMonitoring {
    fn to_bytes_peer_header(&self, c: &mut Cursor<Vec<u8>>) -> Result<usize, Error> {
        Ok(self.peer_header.to_bytes(c)?)
    }

    fn to_bytes_body(&self, c: &mut Cursor<Vec<u8>>) -> Result<usize, Error> {
        Ok(std::io::copy(&mut Cursor::new(&self.payload), c)? as usize)
    }
}

#[derive(Clone)]
pub struct PeerDownNotification {
    pub peer_header: PeerHeader,

    pub reason: u8,
    pub payload: Vec<u8>,
    pub data: Vec<u8>,
}

impl PeerDownNotification {
    pub const REASON_UNKNOWN: u8 = 0;
    pub const REASON_LOCAL_BGP_NOTIFICATION: u8 = 1;
    pub const REASON_LOCAL_NO_NOTIFICATION: u8 = 2;
    pub const REASON_REMOTE_BGP_NOTIFICATION: u8 = 3;
    pub const REASON_REMOTE_NO_NOTIFICATION: u8 = 4;
    pub const REASON_PEER_DE_CONFIGURED: u8 = 5;
}

impl BmpMessage for PeerDownNotification {
    fn to_bytes_peer_header(&self, c: &mut Cursor<Vec<u8>>) -> Result<usize, Error> {
        Ok(self.peer_header.to_bytes(c)?)
    }

    fn to_bytes_body(&self, c: &mut Cursor<Vec<u8>>) -> Result<usize, Error> {
        let pos = c.position();
        c.write_u8(self.reason)?;

        std::io::copy(&mut Cursor::new(&self.payload), c)?;
        std::io::copy(&mut Cursor::new(&self.data), c)?;

        Ok((c.position() - pos) as usize)
    }
}

#[derive(Clone)]
pub struct PeerUpNotification {
    pub peer_header: PeerHeader,

    pub local_address: IpAddr,
    pub local_port: u16,
    pub remote_port: u16,
    pub sent_open: Vec<u8>,
    pub received_open: Vec<u8>,
}

impl PeerUpNotification {}

impl BmpMessage for PeerUpNotification {
    fn to_bytes_peer_header(&self, c: &mut Cursor<Vec<u8>>) -> Result<usize, Error> {
        Ok(self.peer_header.to_bytes(c)?)
    }

    fn to_bytes_body(&self, c: &mut Cursor<Vec<u8>>) -> Result<usize, Error> {
        let pos = c.position();
        match self.local_address {
            IpAddr::V4(addr) => {
                c.set_position(c.position() + 12);
                c.write_u32::<NetworkEndian>(u32::from(addr))?;
            }
            IpAddr::V6(addr) => {
                for i in &addr.octets() {
                    c.write_u8(*i)?;
                }
            }
        }
        c.write_u16::<NetworkEndian>(self.local_port)?;
        c.write_u16::<NetworkEndian>(self.remote_port)?;

        std::io::copy(&mut Cursor::new(&self.sent_open), c)?;
        std::io::copy(&mut Cursor::new(&self.received_open), c)?;

        Ok((c.position() - pos) as usize)
    }
}

#[derive(Clone)]
pub struct Tlv {
    pub tlv_type: u16,
    pub length: u16,
    pub value: Vec<u8>,
}

impl Tlv {
    fn new(t: u16, v: Vec<u8>) -> Tlv {
        Tlv {
            tlv_type: t,
            length: v.len() as u16,
            value: v,
        }
    }
}

#[derive(Clone)]
pub struct Initiation {
    pub tlv: Vec<Tlv>,
}

impl Initiation {
    pub const TLV_STRING: u16 = 0;
    pub const TLV_SYS_DESCR: u16 = 1;
    pub const TLV_SYS_NAME: u16 = 2;

    pub fn new() -> Self {
        Initiation { tlv: Vec::new() }
    }

    pub fn tlv(mut self, t: u16, v: Vec<u8>) -> Self {
        self.tlv.push(Tlv::new(t, v));
        self
    }
}

impl BmpMessage for Initiation {
    fn to_bytes_body(&self, c: &mut Cursor<Vec<u8>>) -> Result<usize, Error> {
        let pos = c.position();
        for t in &self.tlv {
            c.write_u16::<NetworkEndian>(t.tlv_type)?;
            c.write_u16::<NetworkEndian>(t.length)?;
            std::io::copy(&mut Cursor::new(&t.value), c)?;
        }
        Ok((c.position() - pos) as usize)
    }
}

//pub struct Termination {}

trait BmpMessage {
    fn to_bytes_peer_header(&self, _c: &mut Cursor<Vec<u8>>) -> Result<usize, Error> {
        Ok(0)
    }

    fn to_bytes_body(&self, c: &mut Cursor<Vec<u8>>) -> Result<usize, Error>;
}

fn to_bytes<T: BmpMessage>(m: T, c: &mut Cursor<Vec<u8>>) -> Result<usize, Error> {
    let mut len = m.to_bytes_peer_header(c)?;
    len += m.to_bytes_body(c)?;
    Ok(len as usize)
}

#[derive(Clone)]
pub enum Message {
    RouteMonitoring(RouteMonitoring),
    // StatisticsReport(StatisticsReport),
    PeerDownNotification(PeerDownNotification),
    PeerUpNotification(PeerUpNotification),
    Initiation(Initiation),
    // Termination(Termination),
    // RouteMirroring(RouteMirroring),
}

impl Message {
    const ROUTE_MONITORING: u8 = 0;
    const PEER_DOWN_NOTIFICATION: u8 = 2;
    const PEER_UP_NOTIFICATION: u8 = 3;
    const INITIATION: u8 = 4;

    fn to_type(m: &Message) -> u8 {
        match m {
            Message::RouteMonitoring(_) => Message::ROUTE_MONITORING,
            Message::PeerDownNotification(_) => Message::PEER_DOWN_NOTIFICATION,
            Message::PeerUpNotification(_) => Message::PEER_UP_NOTIFICATION,
            Message::Initiation(_) => Message::INITIATION,
        }
    }

    pub fn to_bytes(self) -> Result<Vec<u8>, Error> {
        let buf: Vec<u8> = Vec::new();
        let mut c = Cursor::new(buf);

        let t = Message::to_type(&self);

        c.set_position(CommonHeader::LENGTH as u64);
        let len = match self {
            Message::RouteMonitoring(m) => to_bytes(m, &mut c),
            Message::PeerDownNotification(m) => to_bytes(m, &mut c),
            Message::PeerUpNotification(m) => to_bytes(m, &mut c),
            Message::Initiation(m) => to_bytes(m, &mut c),
        }?;

        c.set_position(0);
        CommonHeader {
            version: CommonHeader::VERSION,
            length: CommonHeader::LENGTH + len as u32,
            message_type: t,
        }
        .to_bytes(&mut c)?;

        Ok(c.into_inner())
    }
}
