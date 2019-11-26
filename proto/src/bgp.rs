// Copyright (C) 2019 The RustyBGP Authors.
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

use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use failure::Error;
use std::convert::From;
use std::io::{Cursor, Read, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

const AS_TRANS: u16 = 23456;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpNet {
    pub addr: IpAddr,
    pub mask: u8,
}

impl IpNet {
    fn clear_bits(buf: &mut [u8], mask: u8) {
        let rem = mask % 8;
        if rem != 0 {
            let prefix_len = (mask + 7) / 8;
            let mask: u16 = 0xff00 >> rem;
            buf[prefix_len as usize - 1] = buf[prefix_len as usize - 1] & mask as u8;
        }
    }
}

#[derive(Debug)]
pub enum IpNetParseError {
    InvalidFormat { details: String },
    InvalidMask { details: String },
}

impl FromStr for IpNet {
    type Err = IpNetParseError;

    fn from_str(s: &str) -> Result<IpNet, IpNetParseError> {
        let addr_and_mask: Vec<_> = s.split('/').collect();
        if addr_and_mask.len() != 2 {
            return Err(IpNetParseError::InvalidFormat {
                details: "multiple slashes".to_string(),
            });
        }

        let addr = IpAddr::from_str(addr_and_mask[0]);
        let addr = match addr {
            Ok(addr) => addr,
            Err(_) => {
                return Err(IpNetParseError::InvalidFormat {
                    details: "malformed cidr".to_string(),
                })
            }
        };

        let mask = u8::from_str(addr_and_mask[1]);
        let mask = match mask {
            Ok(mask) => mask,
            Err(_) => {
                return Err(IpNetParseError::InvalidFormat {
                    details: "malformed mask".to_string(),
                })
            }
        };

        match addr {
            IpAddr::V4(addr) => {
                if mask > 32 {
                    return Err(IpNetParseError::InvalidMask {
                        details: "mask is too large".to_string(),
                    });
                }
                Ok(IpNet::new(addr.octets(), mask))
            }
            IpAddr::V6(addr) => {
                if mask > 128 {
                    return Err(IpNetParseError::InvalidMask {
                        details: "mask is too large".to_string(),
                    });
                }
                Ok(IpNet::new(addr.octets(), mask))
            }
        }
    }
}

#[test]
fn from_str_ipnet() {
    assert_eq!(
        IpNet::from_str("1.1.1.0/24").unwrap(),
        IpNet::new([1, 1, 1, 0], 24),
    );
}

trait IpNetNew<T>: Sized {
    fn new(_: T, mask: u8) -> IpNet;
}

impl IpNetNew<[u8; 4]> for IpNet {
    fn new(mut octets: [u8; 4], mask: u8) -> IpNet {
        IpNet::clear_bits(&mut octets, mask);
        IpNet {
            addr: IpAddr::from(octets),
            mask: mask,
        }
    }
}

impl IpNetNew<[u8; 16]> for IpNet {
    fn new(mut octets: [u8; 16], mask: u8) -> IpNet {
        IpNet::clear_bits(&mut octets, mask);
        IpNet {
            addr: IpAddr::from(octets),
            mask: mask,
        }
    }
}

#[test]
fn ipnet_oddbits() {
    let mut octests = [1, 0xff, 0xff, 0];
    IpNet::clear_bits(&mut octests, 23);
    assert_eq!(octests[2], 0xfe);
}

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub enum Nlri {
    Ip(IpNet),
}

impl std::string::ToString for Nlri {
    fn to_string(&self) -> String {
        match self {
            Nlri::Ip(net) => format!("{}/{}", net.addr.to_string(), net.mask),
        }
    }
}

#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub enum Family {
    Ipv4Uc,
    Ipv6Uc,

    Unknown(u32),
}

impl From<Family> for u32 {
    fn from(family: Family) -> Self {
        match family {
            Family::Ipv4Uc => Family::IPV4_UC,
            Family::Ipv6Uc => Family::IPV6_UC,
            Family::Unknown(f) => f,
        }
    }
}

impl From<u32> for Family {
    fn from(v: u32) -> Self {
        match v {
            Family::IPV4_UC => Family::Ipv4Uc,
            Family::IPV6_UC => Family::Ipv6Uc,
            _ => Family::Unknown(v),
        }
    }
}

impl Family {
    const AFI_IP: u16 = 1;
    const AFI_IP6: u16 = 2;

    const SAFI_UNICAST: u8 = 1;

    const IPV4_UC: u32 = (Family::AFI_IP as u32) << 16 | Family::SAFI_UNICAST as u32;
    const IPV6_UC: u32 = (Family::AFI_IP6 as u32) << 16 | Family::SAFI_UNICAST as u32;

    fn afi(self) -> u16 {
        let family: u32 = From::from(self);
        (family >> 16) as u16
    }

    fn safi(self) -> u8 {
        let family: u32 = From::from(self);
        (family & 0xff) as u8
    }
}

pub struct OpenMessage {
    pub version: u8,
    pub as_number: u16,
    pub holdtime: u16,
    pub id: Ipv4Addr,
    pub params: Vec<OpenParam>,
    length: usize,
}

impl OpenMessage {
    const VERSION: u8 = 4;
    const HOLDTIME: u16 = 30;

    pub fn new(as_number: u32, id: Ipv4Addr) -> OpenMessage {
        let params = vec![
            OpenParam::CapabilityParam(Capability::RouteRefresh),
            OpenParam::CapabilityParam(Capability::FourOctetAsNumber {
                as_number: as_number,
            }),
            OpenParam::CapabilityParam(Capability::MultiProtocol {
                family: Family::Ipv4Uc,
            }),
        ];

        OpenMessage {
            version: OpenMessage::VERSION,
            as_number: AS_TRANS,
            holdtime: OpenMessage::HOLDTIME,
            id: id,
            params: params,
            length: 0,
        }
    }

    pub fn get_as_number(&self) -> u32 {
        if self.as_number == AS_TRANS {
            for param in &self.params {
                match param {
                    OpenParam::CapabilityParam(cap) => match cap {
                        Capability::FourOctetAsNumber { as_number } => {
                            return *as_number;
                        }
                        _ => {}
                    },
                    _ => {}
                }
            }
        }
        return self.as_number as u32;
    }

    pub fn get_parameters(&self) -> Vec<OpenParam> {
        self.params.iter().cloned().collect()
    }

    pub fn to_bytes(self, c: &mut Cursor<Vec<u8>>) -> Result<usize, Error> {
        c.write_u8(self.version)?;
        c.write_u16::<NetworkEndian>(self.as_number)?;
        c.write_u16::<NetworkEndian>(self.holdtime)?;
        c.write_all(&self.id.octets())?;

        let pos_length = c.position();
        c.write_u8(0)?;

        let mut param_len = 0;
        for param in &self.params {
            param.to_bytes(c).and_then(|n| {
                param_len += n;
                Ok(n)
            })?;
        }

        if param_len != 0 {
            let pos = c.position();
            c.set_position(pos_length);
            c.write_u8(param_len as u8)?;
            c.set_position(pos);
        }

        Ok(10 + param_len)
    }

    pub fn from_bytes(c: &mut Cursor<&[u8]>) -> Result<OpenMessage, Error> {
        let version = c.read_u8()?;
        let as_number = c.read_u16::<NetworkEndian>()?;
        let holdtime = c.read_u16::<NetworkEndian>()?;
        let id: Ipv4Addr = From::from(c.read_u32::<NetworkEndian>()?);

        let mut param_len = c.read_u8()?;
        let mut params: Vec<OpenParam> = Vec::new();
        while param_len > 0 {
            let pos = c.position();
            let mut param = OpenParam::from_bytes(c)?;
            params.append(&mut param);
            let used = c.position() - pos;
            if used > param_len as u64 {
                param_len = 0;
            } else {
                param_len -= used as u8;
            }
        }
        Ok(OpenMessage {
            version,
            as_number,
            holdtime,
            id,
            params,
            length: c.get_ref().len(),
        })
    }
}

pub struct NotificationMessage {
    pub code: u8,
    pub sub_code: u8,
    length: usize,
}

impl NotificationMessage {
    pub fn from_bytes(c: &mut Cursor<&[u8]>) -> Result<NotificationMessage, Error> {
        let code = c.read_u8()?;
        let sub_code = c.read_u8()?;
        let length = c.get_ref().len();
        for _ in 0..length - 2 {
            c.read_u8()?;
        }

        Ok(NotificationMessage {
            code,
            sub_code,
            length,
        })
    }
}

pub struct RouteRefreshMessage {
    pub family: Family,
    pub demarcation: u8,
}

impl RouteRefreshMessage {
    pub fn from_bytes(c: &mut Cursor<&[u8]>) -> Result<RouteRefreshMessage, Error> {
        let afi = c.read_u16::<NetworkEndian>()?;
        let demarcation = c.read_u8()?;
        let safi = c.read_u8()?;

        Ok(RouteRefreshMessage {
            family: Family::from((afi as u32) << 16 | safi as u32),
            demarcation,
        })
    }
}

pub enum Message {
    Open(OpenMessage),
    Update(UpdateMessage),
    Notification(NotificationMessage),
    Keepalive,
    RouteRefresh(RouteRefreshMessage),
    Unknown { length: usize, code: u8 },
}

impl Message {
    const HEADER_LENGTH: u16 = 19;

    const OPEN: u8 = 1;
    const UPDATE: u8 = 2;
    const NOTIFICATION: u8 = 3;
    const KEEPALIVE: u8 = 4;
    const ROUTE_REFRESH: u8 = 5;

    fn to_u8(&self) -> u8 {
        match self {
            Message::Open(_) => Message::OPEN,
            Message::Update(_) => Message::UPDATE,
            Message::Notification(_) => Message::NOTIFICATION,
            Message::Keepalive => Message::KEEPALIVE,
            Message::RouteRefresh(_) => Message::ROUTE_REFRESH,
            Message::Unknown { length: _, code } => *code,
        }
    }

    pub fn length(&self) -> usize {
        let mut len = Message::HEADER_LENGTH as usize;
        match self {
            Message::Open(m) => len += m.length,
            Message::Update(m) => len += m.length,
            Message::Notification(m) => len += m.length,
            Message::RouteRefresh(_) => len += 4,
            Message::Unknown { length, code: _ } => len += length,
            _ => {}
        }
        len
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Message, Error> {
        let buflen = buf.len();
        let mut c = Cursor::new(buf);

        if buflen < Message::HEADER_LENGTH as usize {
            return Err(format_err!("header is too short"));
        }
        c.set_position(16);
        let length = c.read_u16::<NetworkEndian>()?;
        if buflen < length as usize {
            return Err(format_err!("buffer is too short"));
        }

        let code = c.read_u8()?;
        let mut c = Cursor::new(&buf[Message::HEADER_LENGTH as usize..length as usize]);
        match code {
            Message::OPEN => {
                let b = OpenMessage::from_bytes(&mut c)?;
                return Ok(Message::Open(b));
            }
            Message::UPDATE => {
                let b = UpdateMessage::from_bytes(&mut c)?;
                return Ok(Message::Update(b));
            }
            Message::NOTIFICATION => {
                let b = NotificationMessage::from_bytes(&mut c)?;
                return Ok(Message::Notification(b));
            }
            Message::KEEPALIVE => return Ok(Message::Keepalive),
            Message::ROUTE_REFRESH => {
                let b = RouteRefreshMessage::from_bytes(&mut c)?;
                return Ok(Message::RouteRefresh(b));
            }
            _ => {
                let body_length = length - Message::HEADER_LENGTH;
                for _ in 0..body_length {
                    c.read_u8()?;
                }
                return Ok(Message::Unknown {
                    length: body_length as usize,
                    code: code,
                });
            }
        }
    }

    pub fn to_bytes(self) -> Result<Vec<u8>, Error> {
        let buf: Vec<u8> = Vec::new();
        let mut c = Cursor::new(buf);
        c.write(&vec![0xff; 16])?;
        // length: might be update later.
        let pos_length = c.position();
        c.write_u16::<NetworkEndian>(Message::HEADER_LENGTH)?;
        // type
        c.write(&vec![self.to_u8()])?;

        let mut body_length = 0;
        match self {
            Message::Open(b) => match b.to_bytes(&mut c) {
                Ok(n) => body_length += n,
                Err(_) => {}
            },
            _ => {}
        }

        if body_length != 0 {
            let pos = c.position();
            c.set_position(pos_length);
            c.write_u16::<NetworkEndian>(Message::HEADER_LENGTH + body_length as u16)?;
            c.set_position(pos);
        }
        Ok(c.into_inner())
    }
}

#[derive(PartialOrd, PartialEq, Clone, Copy)]
pub enum State {
    Idle,
    Connect,
    Active,
    OpenSent,
    OpenConfirm,
    Established,
}

#[derive(Clone)]
pub struct Segment {
    pub segment_type: u8,
    pub number: Vec<u32>,
}

impl Segment {
    pub fn as_len(&self) -> usize {
        match self.segment_type {
            1 => 1,
            2 => self.number.len(),
            _ => 0,
        }
    }
}

#[derive(Clone)]
pub enum Attribute {
    Origin {
        origin: u8,
    },
    AsPath {
        segments: Vec<Segment>,
    },
    Nexthop {
        nexthop: IpAddr,
    },
    MultiExitDesc {
        descriptor: u32,
    },
    LocalPref {
        preference: u32,
    },
    AtomicAggregate,
    Aggregator {
        four_byte: bool,
        number: u32,
        address: IpAddr,
    },
    Community {
        communities: Vec<u32>,
    },
    OriginatorId {
        address: IpAddr,
    },
    ClusterList {
        addresses: Vec<IpAddr>,
    },
    // MpReach,
    // MpUnreach,
    // ExtendedCommunity,
    // As4Path,
    // As4Aggregator,

    // PmsiTunnel,
    // TunnelEncap,
    // TraficEngineering,
    // IpV6ExtendedCommunity,
    NotSupported {
        attr_flag: u8,
        attr_type: u8,
        attr_len: u16,
        buf: Vec<u8>,
    },
}

impl Attribute {
    pub fn new(c: &mut Cursor<&[u8]>) -> Result<Attribute, Error> {
        const FLAG_EXTENDED: u8 = 1 << 4;

        // flag
        let attr_flag = c.read_u8()?;

        // type
        let attr_type = c.read_u8()?;

        // attribute len
        let mut attr_len = 0;
        if attr_flag & FLAG_EXTENDED != 0 {
            attr_len += c.read_u16::<NetworkEndian>()?
        } else {
            attr_len += c.read_u8()? as u16;
        }

        match attr_type {
            1 => {
                let origin = c.read_u8()?;
                Ok(Attribute::Origin { origin })
            }
            2 => {
                let mut segments: Vec<Segment> = Vec::new();
                while attr_len > 0 {
                    let code = c.read_u8()?;
                    let num = c.read_u8()?;
                    let mut numbers = Vec::new();
                    for _ in 0..num {
                        numbers.push(c.read_u32::<NetworkEndian>()?);
                    }
                    segments.push(Segment {
                        segment_type: code,
                        number: numbers,
                    });
                    let used = (2 + num * 4) as u16;
                    if attr_len < used {
                        attr_len = 0;
                    } else {
                        attr_len -= used;
                    }
                }
                Ok(Attribute::AsPath { segments })
            }
            3 => {
                if attr_len == 4 {
                    let mut buf = [0; 4];
                    c.read_exact(&mut buf)?;
                    return Ok(Attribute::Nexthop {
                        nexthop: IpAddr::from(buf),
                    });
                } else if attr_len == 16 {
                    let mut buf = [0; 16];
                    c.read_exact(&mut buf)?;
                    return Ok(Attribute::Nexthop {
                        nexthop: IpAddr::from(buf),
                    });
                }
                Err(format_err!("invalid attribute length"))
            }
            4 => {
                let descriptor = c.read_u32::<NetworkEndian>()?;
                Ok(Attribute::MultiExitDesc { descriptor })
            }
            5 => {
                let preference = c.read_u32::<NetworkEndian>()?;
                Ok(Attribute::LocalPref { preference })
            }
            6 => Ok(Attribute::AtomicAggregate {}),
            7 => {
                if attr_len == 6 {
                    let number = c.read_u16::<NetworkEndian>()?;
                    let mut buf = [0; 4];
                    c.read_exact(&mut buf)?;
                    return Ok(Attribute::Aggregator {
                        four_byte: false,
                        number: number as u32,
                        address: IpAddr::from(buf),
                    });
                } else if attr_len == 8 {
                    let number = c.read_u32::<NetworkEndian>()?;
                    let mut buf = [0; 4];
                    c.read_exact(&mut buf)?;
                    return Ok(Attribute::Aggregator {
                        four_byte: true,
                        number: number,
                        address: IpAddr::from(buf),
                    });
                }
                Err(format_err!("invalid attribute length"))
            }
            8 => {
                if attr_len % 4 == 0 {
                    let mut communities: Vec<u32> = Vec::new();
                    while attr_len > 0 {
                        communities.push(c.read_u32::<NetworkEndian>()?);
                        attr_len -= 4;
                    }
                    return Ok(Attribute::Community { communities });
                }
                Err(format_err!("invalid attribute length"))
            }
            9 => {
                if attr_len == 4 {
                    let mut buf = [0; 4];
                    c.read_exact(&mut buf)?;
                    return Ok(Attribute::OriginatorId {
                        address: IpAddr::from(buf),
                    });
                }
                Err(format_err!("invalid attribute length"))
            }
            _ => {
                let mut buf: Vec<u8> = Vec::new();
                for _ in 0..attr_len {
                    buf.push(c.read_u8()?);
                }
                Ok(Attribute::NotSupported {
                    attr_flag,
                    attr_type,
                    attr_len,
                    buf,
                })
            }
        }
    }
}

pub struct UpdateMessage {
    pub attrs: Vec<Attribute>,
    pub routes: Vec<Nlri>,
    pub withdrawns: Vec<Nlri>,
    length: usize,
}

impl UpdateMessage {
    pub fn from_bytes(c: &mut Cursor<&[u8]>) -> Result<UpdateMessage, Error> {
        let withdrawn_len = c.read_u16::<NetworkEndian>()?;
        let mut withdrawns: Vec<Nlri> = Vec::new();

        let pos = c.position();
        while c.position() - pos < withdrawn_len as u64 {
            let bit_len = c.read_u8()?;
            let mut addr = [0 as u8; 4];
            for i in 0..(bit_len + 7) / 8 {
                addr[i as usize] = c.read_u8()?;
            }
            withdrawns.push(Nlri::Ip(IpNet::new(addr, bit_len)));
        }

        let attr_len = c.read_u16::<NetworkEndian>()?;
        let mut attrs: Vec<Attribute> = Vec::new();

        let attr_end = c.position() + attr_len as u64;
        while c.position() < attr_end {
            let attr = Attribute::new(c);
            match attr {
                Ok(a) => attrs.push(a),
                Err(_) => break,
            }
        }

        let nlri_len = c.get_ref().len() - c.position() as usize;

        let mut routes: Vec<Nlri> = Vec::new();

        while c.get_ref().len() > c.position() as usize {
            let bit_len = c.read_u8()?;
            let mut addr = [0 as u8; 4];
            for i in 0..(bit_len + 7) / 8 {
                addr[i as usize] = c.read_u8()?;
            }
            routes.push(Nlri::Ip(IpNet::new(addr, bit_len)));
        }
        Ok(UpdateMessage {
            attrs,
            routes,
            withdrawns,
            length: c.get_ref().len(),
        })
    }
}

#[derive(Debug, Clone)]
pub enum OpenParam {
    CapabilityParam(Capability),
    UnknownParam,
}

impl OpenParam {
    pub fn from_bytes(c: &mut Cursor<&[u8]>) -> Result<Vec<OpenParam>, Error> {
        let code = c.read_u8()?;
        let mut len = c.read_u8()?;

        match code {
            2 => {
                let mut r = Vec::new();
                while len > 0 {
                    let pos = c.position();
                    match Capability::from_bytes(c) {
                        Ok(cap) => r.push(OpenParam::CapabilityParam(cap)),
                        Err(err) => return Err(err),
                    }
                    let used = c.position() - pos;
                    if used > len as u64 {
                        len = 0;
                    } else {
                        len -= used as u8;
                    }
                }
                Ok(r)
            }
            _ => {
                for _ in 0..len {
                    c.read_u8()?;
                }
                Ok(vec![OpenParam::UnknownParam])
            }
        }
    }

    pub fn to_bytes(&self, c: &mut Cursor<Vec<u8>>) -> Result<usize, Error> {
        match self {
            OpenParam::CapabilityParam(cap) => {
                c.write_u8(2)?;
                let length_pos = c.position();
                c.write_u8(0)?;
                cap.to_bytes(c).and_then(|n| {
                    let pos = c.position();
                    c.set_position(length_pos);
                    c.write_u8(n as u8)?;
                    c.set_position(pos);
                    Ok(2 + n as usize)
                })
            }
            OpenParam::UnknownParam => Ok(0),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Capability {
    MultiProtocol {
        family: Family,
    },
    RouteRefresh,
    CarryingLabelInfo,
    ExtendedNexthop {
        values: Vec<(Family, Family)>,
    },
    GracefulRestart {
        flags: u8,
        time: u16,
        values: Vec<(Family, u8)>,
    },
    FourOctetAsNumber {
        as_number: u32,
    },
    AddPath {
        values: Vec<(Family, u8)>,
    },
    EnhanshedRouteRefresh,
    LongLivedGracefulRestart {
        values: Vec<(Family, u8, u32)>,
    },
    RouteRefreshCisco,

    Unknown {
        code: u8,
        values: Vec<u8>,
    },
}

impl Capability {
    const MULTI_PROTOCOL: u8 = 1;
    const ROUTE_REFRESH: u8 = 2;
    const CARRYING_LABEL_INFO: u8 = 4;
    const EXTENDED_NEXTHOP: u8 = 5;
    const GRACEFUL_RESTART: u8 = 64;
    const FOUR_OCTET_AS_NUMBER: u8 = 65;
    const ADD_PATH: u8 = 69;
    const ENHANCED_ROUTE_REFRESH: u8 = 70;
    const LONG_LIVED_GRACEFUL_RESTART: u8 = 71;
    const ROUTE_REFRESH_CISCO: u8 = 128;

    pub fn from_bytes(c: &mut Cursor<&[u8]>) -> Result<Capability, Error> {
        let code = c.read_u8()?;
        let mut len = c.read_u8()?;

        match code {
            Capability::MULTI_PROTOCOL => {
                let family = c.read_u32::<NetworkEndian>()?;
                Ok(Capability::MultiProtocol {
                    family: Family::from(family),
                })
            }
            Capability::ROUTE_REFRESH => Ok(Capability::RouteRefresh),
            Capability::CARRYING_LABEL_INFO => Ok(Capability::CarryingLabelInfo),
            Capability::EXTENDED_NEXTHOP => {
                let mut v = Vec::new();
                while len > 0 {
                    v.push((
                        From::from(c.read_u32::<NetworkEndian>()?),
                        From::from(
                            (c.read_u16::<NetworkEndian>()? as u32) << 16
                                | Family::SAFI_UNICAST as u32,
                        ),
                    ));
                    len -= 6;
                }
                Ok(Capability::ExtendedNexthop { values: v })
            }
            Capability::GRACEFUL_RESTART => {
                let mut v = Vec::new();
                let restart = c.read_u16::<NetworkEndian>()?;
                let flags = (restart >> 12) as u8;
                let time = restart & 0xfff;
                len -= 2;
                while len > 0 {
                    let afi = c.read_u16::<NetworkEndian>()? as u32;
                    let safi = c.read_u8()? as u32;
                    v.push((From::from(afi << 16 | safi), c.read_u8()?));
                    len -= 4;
                }
                Ok(Capability::GracefulRestart {
                    flags: flags,
                    time: time,
                    values: v,
                })
            }
            Capability::FOUR_OCTET_AS_NUMBER => {
                let as_number = c.read_u32::<NetworkEndian>()?;
                Ok(Capability::FourOctetAsNumber { as_number })
            }
            Capability::ADD_PATH => {
                let mut v = Vec::new();
                while len > 0 {
                    let afi = c.read_u16::<NetworkEndian>()? as u32;
                    let safi = c.read_u8()? as u32;
                    v.push((From::from(afi << 16 | safi), c.read_u8()?));
                    len -= 4;
                }
                Ok(Capability::AddPath { values: v })
            }
            Capability::ENHANCED_ROUTE_REFRESH => Ok(Capability::EnhanshedRouteRefresh),
            Capability::LONG_LIVED_GRACEFUL_RESTART => {
                let mut v = Vec::new();
                while len > 0 {
                    let afi = c.read_u16::<NetworkEndian>()? as u32;
                    let safi = c.read_u8()? as u32;
                    let flags = c.read_u8()?;
                    let time = (c.read_u8()? as u32) << 16
                        | (c.read_u8()? as u32) << 8
                        | c.read_u8()? as u32;
                    v.push((From::from(afi << 16 | safi), flags, time));
                    len -= 7;
                }
                Ok(Capability::LongLivedGracefulRestart { values: v })
            }
            Capability::ROUTE_REFRESH_CISCO => Ok(Capability::RouteRefreshCisco),
            _ => {
                let mut v = Vec::new();
                for _ in 0..len {
                    v.push(c.read_u8()?);
                }
                Ok(Capability::Unknown {
                    code: code,
                    values: v,
                })
            }
        }
    }

    pub fn to_bytes(&self, c: &mut Cursor<Vec<u8>>) -> Result<usize, Error> {
        let pos = c.position();
        match self {
            Capability::MultiProtocol { family } => {
                c.write_u8(Capability::MULTI_PROTOCOL)?;
                c.write_u8(4)?;
                c.write_u16::<NetworkEndian>(family.afi())?;
                c.write_u8(0)?;
                c.write_u8(family.safi())?;
            }
            Capability::RouteRefresh => {
                c.write_u8(Capability::ROUTE_REFRESH)?;
                c.write_u8(0)?;
            }
            Capability::FourOctetAsNumber { as_number } => {
                c.write_u8(Capability::FOUR_OCTET_AS_NUMBER)?;
                c.write_u8(4)?;
                c.write_u32::<NetworkEndian>(*as_number)?;
            }
            _ => {}
        }
        Ok((c.position() - pos) as usize)
    }
}
