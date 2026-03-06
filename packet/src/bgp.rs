// Copyright (C) 2019-2022 The RustyBGP Authors.
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

use crate::error::{BgpError, Error};
use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use bytes::BufMut;
use fnv::FnvHashMap;
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::convert::Into;
use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;
use std::{fmt, io};

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct Family(u32);

impl Family {
    pub const AFI_IP: u16 = 1;
    pub const AFI_IP6: u16 = 2;

    const SAFI_UNICAST: u8 = 1;

    pub const EMPTY: Family = Family(0);
    pub const IPV4: Family = Family((Family::AFI_IP as u32) << 16 | Family::SAFI_UNICAST as u32);
    pub const IPV6: Family = Family((Family::AFI_IP6 as u32) << 16 | Family::SAFI_UNICAST as u32);

    pub fn new(v: u32) -> Self {
        Family(v)
    }

    pub fn afi(&self) -> u16 {
        (self.0 >> 16) as u16
    }

    pub fn safi(&self) -> u8 {
        (self.0 & 0xff) as u8
    }
}

#[derive(Clone, PartialEq)]
pub enum IpNet {
    V4(Ipv4Net),
    V6(Ipv6Net),
}

impl IpNet {
    pub fn new(prefix: IpAddr, mask: u8) -> Self {
        match prefix {
            IpAddr::V4(addr) => IpNet::V4(Ipv4Net { addr, mask }),
            IpAddr::V6(addr) => IpNet::V6(Ipv6Net { addr, mask }),
        }
    }

    pub fn contains(&self, addr: &IpAddr) -> bool {
        let f = |a: &Vec<u8>, b: &Vec<u8>, mask: u8| {
            let div = (mask >> 3) as usize;

            for i in 0..div {
                if a[i] != b[i] {
                    return false;
                }
            }

            let r = mask & 0x07;
            if r > 0 {
                let bit = 8 - r;
                if a[div] != (b[div] & (0xff >> bit << bit)) {
                    return false;
                }
            }
            true
        };

        match addr {
            IpAddr::V4(addr) => {
                let (prefix_octets, mask) = match self {
                    IpNet::V4(net) => (net.addr.octets().to_vec(), net.mask),
                    _ => return false,
                };
                let addr_octests: Vec<u8> = addr.octets().to_vec();
                f(&prefix_octets, &addr_octests, mask)
            }
            IpAddr::V6(addr) => {
                let (prefix_octets, mask) = match self {
                    IpNet::V6(net) => (net.addr.octets().to_vec(), net.mask),
                    _ => return false,
                };
                let addr_octests: Vec<u8> = addr.octets().to_vec();
                f(&prefix_octets, &addr_octests, mask)
            }
        }
    }
}

impl FromStr for IpNet {
    type Err = Error;

    fn from_str(s: &str) -> Result<IpNet, Error> {
        let addr_and_mask: Vec<_> = s.split('/').collect();
        if addr_and_mask.len() != 2 {
            return Err(Error::InvalidArgument(s.to_string()));
        }

        let addr = IpAddr::from_str(addr_and_mask[0]);
        let addr = match addr {
            Ok(addr) => addr,
            Err(e) => {
                return Err(Error::InvalidArgument(e.to_string()));
            }
        };

        let mask = u8::from_str(addr_and_mask[1]);
        let mask = match mask {
            Ok(mask) => mask,
            Err(e) => {
                return Err(Error::InvalidArgument(e.to_string()));
            }
        };

        match addr {
            IpAddr::V4(addr) => {
                if mask > 32 {
                    return Err(Error::InvalidArgument(format!(
                        "mask is too large: {}",
                        mask
                    )));
                }
                Ok(IpNet::V4(Ipv4Net {
                    addr: addr.octets().into(),
                    mask,
                }))
            }
            IpAddr::V6(addr) => {
                if mask > 128 {
                    return Err(Error::InvalidArgument(format!(
                        "mask is too large: {}",
                        mask
                    )));
                }
                Ok(IpNet::V6(Ipv6Net {
                    addr: addr.octets().into(),
                    mask,
                }))
            }
        }
    }
}

impl fmt::Display for IpNet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpNet::V4(net) => net.fmt(f),
            IpNet::V6(net) => net.fmt(f),
        }
    }
}

#[derive(PartialEq, Eq, Hash, Clone, Debug, Copy)]
pub enum Nlri {
    V4(Ipv4Net),
    V6(Ipv6Net),
    // add more Family here
}

impl Nlri {
    fn encode<B: BufMut>(&self, dst: &mut B) -> Result<u16, ()> {
        match self {
            Nlri::V4(net) => net.encode(dst),
            Nlri::V6(net) => net.encode(dst),
        }
    }
}

impl FromStr for Nlri {
    type Err = Error;

    fn from_str(s: &str) -> Result<Nlri, Error> {
        match IpNet::from_str(s) {
            Ok(n) => match n {
                IpNet::V4(n) => Ok(Nlri::V4(n)),
                IpNet::V6(n) => Ok(Nlri::V6(n)),
            },
            Err(e) => Err(e),
        }
    }
}

impl fmt::Display for Nlri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Nlri::V4(net) => net.fmt(f),
            Nlri::V6(net) => net.fmt(f),
        }
    }
}

/// An NLRI entry with an optional AddPath path identifier (RFC 7911).
/// `path_id` is 0 when AddPath is not negotiated for the address family.
#[derive(PartialEq, Eq, Hash, Clone, Debug, Copy)]
pub struct PathNlri {
    pub path_id: u32,
    pub nlri: Nlri,
}

impl PathNlri {
    pub fn new(nlri: Nlri) -> Self {
        PathNlri { path_id: 0, nlri }
    }
}

/// A set of NLRI entries sharing a common address family (AFI+SAFI).
#[derive(Clone, Debug)]
pub struct NlriSet {
    pub family: Family,
    pub entries: Vec<PathNlri>,
}

impl NlriSet {
    pub fn new(family: Family) -> Self {
        NlriSet {
            family,
            entries: Vec::new(),
        }
    }
}

#[derive(PartialEq, Eq, Hash, Clone, Debug, Copy)]
pub struct Ipv4Net {
    pub addr: Ipv4Addr,
    pub mask: u8,
}

impl Ipv4Net {
    fn decode<T: io::Read>(c: &mut T, len: usize) -> Result<Ipv4Net, Error> {
        let bit_len = c.read_u8()?;
        if len < (bit_len as usize).div_ceil(8) || bit_len > 32 {
            return Err(BgpError::UpdateMalformedAttributeList.into());
        }
        let mut addr = [0_u8; 4];
        for i in 0..bit_len.div_ceil(8) {
            addr[i as usize] = c.read_u8().unwrap();
        }
        Ok(Ipv4Net {
            addr: Ipv4Addr::from(addr),
            mask: bit_len,
        })
    }

    fn encode<B: BufMut>(&self, dst: &mut B) -> Result<u16, ()> {
        let prefix_len = self.mask.div_ceil(8);
        dst.put_u8(self.mask);
        for i in 0..prefix_len {
            dst.put_u8(self.addr.octets()[i as usize]);
        }
        Ok(1 + prefix_len as u16)
    }
}

impl fmt::Display for Ipv4Net {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.mask)
    }
}

#[test]
fn parse_bogus_ipv4net() {
    // try to ipv6 prefix
    let mut buf = vec![128];
    buf.append(&mut Ipv6Addr::from(139930210).octets().to_vec());
    let len = buf.len();
    let mut c = Cursor::new(buf);
    assert!(Ipv4Net::decode(&mut c, len).is_err());
}

#[derive(PartialEq, Eq, Hash, Clone, Debug, Copy)]
pub struct Ipv6Net {
    pub addr: Ipv6Addr,
    pub mask: u8,
}

impl Ipv6Net {
    fn decode<T: io::Read>(c: &mut T, len: usize) -> Result<Ipv6Net, Error> {
        let bit_len = c.read_u8()?;
        if len < (bit_len as usize).div_ceil(8) || bit_len > 128 {
            return Err(BgpError::UpdateMalformedAttributeList.into());
        }
        let mut addr = [0_u8; 16];
        for i in 0..bit_len.div_ceil(8) {
            addr[i as usize] = c.read_u8()?;
        }
        Ok(Ipv6Net {
            addr: Ipv6Addr::from(addr),
            mask: bit_len,
        })
    }

    fn encode<B: BufMut>(&self, dst: &mut B) -> Result<u16, ()> {
        let prefix_len = self.mask.div_ceil(8);
        dst.put_u8(self.mask);
        for i in 0..prefix_len {
            dst.put_u8(self.addr.octets()[i as usize]);
        }
        Ok(1 + prefix_len as u16)
    }
}

impl fmt::Display for Ipv6Net {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.mask)
    }
}

#[test]
fn parse_bogus_ipv6net() {
    // try to ipv6 prefix
    let mut buf = vec![192];
    buf.append(&mut Ipv6Addr::from(139930210).octets().to_vec());
    buf.append(&mut (0..8).collect::<Vec<u8>>());
    let len = buf.len();
    let mut c = Cursor::new(buf);
    assert!(Ipv6Net::decode(&mut c, len).is_err());
}

#[derive(Debug, Clone)]
pub enum Capability {
    MultiProtocol(Family),
    RouteRefresh,
    ExtendedNexthop(Vec<(Family, u16)>),
    //    ExtendedMessage,
    GracefulRestart {
        flags: u8,
        restart_time: u16,
        families: Vec<(Family, u8)>,
    },
    FourOctetAsNumber(u32),
    AddPath(Vec<(Family, u8)>),
    EnhancedRouteRefresh,
    LongLivedGracefulRestart(Vec<(Family, u8, u32)>),
    Fqdn {
        hostname: String,
        domain: String,
    },
    Unknown {
        code: u8,
        bin: Vec<u8>,
    },
}

impl Capability {
    const MULTI_PROTOCOL: u8 = 1;
    const ROUTE_REFRESH: u8 = 2;
    const EXTENDED_NEXTHOP: u8 = 5;
    //    const EXTENDED_MESSAGE: u8 = 6;
    const GRACEFUL_RESTART: u8 = 64;
    const FOUR_OCTET_AS_NUMBER: u8 = 65;
    const ADD_PATH: u8 = 69;
    const ENHANCED_ROUTE_REFRESH: u8 = 70;
    const LONG_LIVED_GRACEFUL_RESTART: u8 = 71;
    const FQDN: u8 = 73;

    const TRANS_ASN: u16 = 23456;
}

impl From<&Capability> for u8 {
    fn from(cap: &Capability) -> u8 {
        match cap {
            Capability::MultiProtocol(_) => Capability::MULTI_PROTOCOL,
            Capability::RouteRefresh => Capability::ROUTE_REFRESH,
            Capability::ExtendedNexthop(_) => Capability::EXTENDED_NEXTHOP,
            Capability::GracefulRestart { .. } => Capability::GRACEFUL_RESTART,
            Capability::FourOctetAsNumber(_) => Capability::FOUR_OCTET_AS_NUMBER,
            Capability::AddPath(_) => Capability::ADD_PATH,
            Capability::EnhancedRouteRefresh => Capability::ENHANCED_ROUTE_REFRESH,
            Capability::LongLivedGracefulRestart(_) => Capability::LONG_LIVED_GRACEFUL_RESTART,
            Capability::Fqdn { .. } => Capability::FQDN,
            Capability::Unknown { code, bin: _ } => *code,
        }
    }
}

impl Capability {
    fn encode<B: BufMut + AsMut<[u8]>>(&self, c: &mut B) -> Result<u8, ()> {
        let head = c.as_mut().len();
        c.put_u8(self.into());
        match self {
            Capability::MultiProtocol(family) => {
                c.put_u8(4);
                c.put_u16(family.afi());
                c.put_u8(0);
                c.put_u8(family.safi());
            }
            Capability::RouteRefresh => {
                c.put_u8(0);
            }
            Capability::ExtendedNexthop(v) => {
                c.put_u8(v.len() as u8 * 6);
                for (family, afi) in v {
                    let Family(f) = family;
                    c.put_u32(*f);
                    c.put_u16(*afi);
                }
            }
            Capability::GracefulRestart {
                flags,
                restart_time,
                families,
            } => {
                c.put_u8(families.len() as u8 * 4 + 2);
                c.put_u16((*flags as u16) << 12 | *restart_time);
                for (family, af_flags) in families {
                    c.put_u16(family.afi());
                    c.put_u8(family.safi());
                    c.put_u8(*af_flags);
                }
            }
            Capability::FourOctetAsNumber(as_number) => {
                c.put_u8(4);
                c.put_u32(*as_number);
            }
            Capability::AddPath(v) => {
                c.put_u8(v.len() as u8 * 4);
                for (family, mode) in v {
                    c.put_u16(family.afi());
                    c.put_u8(family.safi());
                    c.put_u8(*mode);
                }
            }
            Capability::EnhancedRouteRefresh => {
                c.put_u8(0);
            }
            Capability::LongLivedGracefulRestart(v) => {
                c.put_u8(v.len() as u8 * 7);
                for (family, flags, time) in v {
                    c.put_u16(family.afi());
                    c.put_u8(family.safi());
                    c.put_u8(*flags);
                    c.put_u8((*time >> 16) as u8);
                    c.put_u8((*time >> 8) as u8);
                    c.put_u8(*time as u8);
                }
            }
            Capability::Fqdn { hostname, domain } => {
                c.put_u8((2 + hostname.len() + domain.len()) as u8);
                c.put_u8(hostname.len() as u8);
                c.put_slice(hostname.to_ascii_lowercase().as_bytes());
                c.put_u8(domain.len() as u8);
                c.put_slice(domain.to_ascii_lowercase().as_bytes());
            }
            Capability::Unknown { code: _, bin } => {
                c.put_u8(bin.len() as u8);
                for v in bin {
                    c.put_u8(*v);
                }
            }
        }
        Ok((c.as_mut().len() - head) as u8)
    }

    fn decode(code: u8, c: &mut dyn io::Read, len: u8) -> Result<Self, ()> {
        match code {
            Self::MULTI_PROTOCOL => {
                if len != 4 {
                    return Err(());
                }
                Ok(Capability::MultiProtocol(Family(
                    c.read_u32::<NetworkEndian>().map_err(|_| ())?,
                )))
            }
            Self::ROUTE_REFRESH => {
                if len != 0 {
                    return Err(());
                }
                Ok(Capability::RouteRefresh)
            }
            Self::EXTENDED_NEXTHOP => {
                if !len.is_multiple_of(6) {
                    return Err(());
                }
                let mut v = Vec::new();
                for _ in 0..len / 6 {
                    let family = Family(c.read_u32::<NetworkEndian>().map_err(|_| ())?);
                    let afi = c.read_u16::<NetworkEndian>().map_err(|_| ())?;
                    if family.afi() != Family::AFI_IP || afi != Family::AFI_IP6 {
                        continue;
                    }
                    v.push((family, afi));
                }
                Ok(Capability::ExtendedNexthop(v))
            }
            Self::GRACEFUL_RESTART => {
                if len % 4 != 2 {
                    return Err(());
                }
                let restart = c.read_u16::<NetworkEndian>().map_err(|_| ())?;
                let flags = (restart >> 12) as u8;
                let time = restart & 0xfff;
                let mut v = Vec::new();
                for _ in 0..(len - 2) / 4 {
                    let afi = c.read_u16::<NetworkEndian>().map_err(|_| ())? as u32;
                    let safi = c.read_u8().map_err(|_| ())? as u32;
                    let af_flag = c.read_u8().map_err(|_| ())?;
                    v.push((Family(afi << 16 | safi), af_flag));
                }
                Ok(Capability::GracefulRestart {
                    flags,
                    restart_time: time,
                    families: v,
                })
            }
            Self::FOUR_OCTET_AS_NUMBER => {
                if len != 4 {
                    return Err(());
                }
                Ok(Capability::FourOctetAsNumber(
                    c.read_u32::<NetworkEndian>().map_err(|_| ())?,
                ))
            }
            Self::ADD_PATH => {
                if !len.is_multiple_of(4) {
                    return Err(());
                }
                let mut v = Vec::new();
                for _ in 0..len / 4 {
                    let afi = c.read_u16::<NetworkEndian>().map_err(|_| ())? as u32;
                    let safi = c.read_u8().map_err(|_| ())? as u32;
                    let val = c.read_u8().map_err(|_| ())?;
                    if val > 3 {
                        continue;
                    }
                    v.push((Family(afi << 16 | safi), val));
                }
                Ok(Capability::AddPath(v))
            }
            Self::ENHANCED_ROUTE_REFRESH => {
                if len != 0 {
                    return Err(());
                }
                Ok(Capability::EnhancedRouteRefresh)
            }
            Self::LONG_LIVED_GRACEFUL_RESTART => {
                if !len.is_multiple_of(7) {
                    return Err(());
                }
                let mut v = Vec::new();
                for _ in 0..len / 7 {
                    let afi = c.read_u16::<NetworkEndian>().map_err(|_| ())? as u32;
                    let safi = c.read_u8().map_err(|_| ())? as u32;
                    let flags = c.read_u8().map_err(|_| ())?;
                    let time = (c.read_u8().map_err(|_| ())? as u32) << 16
                        | (c.read_u8().map_err(|_| ())? as u32) << 8
                        | c.read_u8().map_err(|_| ())? as u32;
                    v.push((Family(afi << 16 | safi), flags, time));
                }
                Ok(Capability::LongLivedGracefulRestart(v))
            }
            Self::FQDN => {
                if len < 1 {
                    return Err(());
                }
                let hostlen = c.read_u8().map_err(|_| ())?;
                let mut h = Vec::new();
                for _ in 0..hostlen {
                    h.push(c.read_u8().map_err(|_| ())?);
                }
                let host = String::from_utf8(h).unwrap_or_default();
                let domainlen = c.read_u8().map_err(|_| ())?;
                let mut d = Vec::new();
                for _ in 0..domainlen {
                    d.push(c.read_u8().map_err(|_| ())?);
                }
                let domain = String::from_utf8(d).unwrap_or_default();
                Ok(Capability::Fqdn {
                    hostname: host,
                    domain,
                })
            }
            _ => {
                let mut bin = Vec::with_capacity(len as usize);
                for _ in 0..len {
                    bin.push(c.read_u8().map_err(|_| ())?);
                }
                Ok(Capability::Unknown { code, bin })
            }
        }
    }
}

pub struct AsPathIter<'a> {
    cur: Cursor<&'a Vec<u8>>,
    len: u64,
}

impl<'a> AsPathIter<'a> {
    pub fn new(attr: &'a Attribute) -> AsPathIter<'a> {
        AsPathIter {
            cur: Cursor::new(attr.binary().unwrap()),
            len: attr.binary().unwrap().len() as u64,
        }
    }
}

impl<'a> Iterator for AsPathIter<'a> {
    type Item = Vec<u32>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.cur.position() < self.len {
            let _ = self.cur.read_u8().ok()?;
            let n = self.cur.read_u8().ok()?;
            let mut v = Vec::new();
            for _ in 0..n {
                v.push(self.cur.read_u32::<NetworkEndian>().ok()?);
            }
            return Some(v);
        }
        None
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
enum AttributeData {
    Val(u32),
    Bin(Vec<u8>),
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct Attribute {
    code: u8,
    flags: u8,
    data: AttributeData,
}

impl Attribute {
    pub const ORIGIN_INCOMPLETE: u8 = 2;
    const FLAG_EXTENDED: u8 = 1 << 4;
    // const FLAG_PARTIAL: u8 = 1 << 5;
    const FLAG_TRANSITIVE: u8 = 1 << 6;
    const FLAG_OPTIONAL: u8 = 1 << 7;

    pub const ORIGIN: u8 = 1;
    pub const AS_PATH: u8 = 2;
    pub const NEXTHOP: u8 = 3;
    pub const MULTI_EXIT_DESC: u8 = 4;
    pub const LOCAL_PREF: u8 = 5;
    pub const ATOMIC_AGGREGATE: u8 = 6;
    pub const AGGREGATOR: u8 = 7;
    pub const COMMUNITY: u8 = 8;
    pub const ORIGINATOR_ID: u8 = 9;
    pub const CLUSTER_LIST: u8 = 10;
    pub const MP_REACH: u8 = 14;
    pub const MP_UNREACH: u8 = 15;
    pub const EXTENDED_COMMUNITY: u8 = 16;
    pub const AS4_PATH: u8 = 17;
    pub const AS4_AGGREGATOR: u8 = 18;
    pub const AIGP: u8 = 26;
    pub const LARGE_COMMUNITY: u8 = 32;

    pub const AS_PATH_TYPE_SET: u8 = 1;
    pub const AS_PATH_TYPE_SEQ: u8 = 2;
    pub const AS_PATH_TYPE_CONFED_SEQ: u8 = 3;
    pub const AS_PATH_TYPE_CONFED_SET: u8 = 4;

    pub const DEFAULT_LOCAL_PREF: u32 = 100;

    pub fn code(&self) -> u8 {
        self.code
    }

    pub fn flags(&self) -> u8 {
        self.flags
    }

    pub fn new_with_value(code: u8, val: u32) -> Option<Self> {
        Some(Attribute {
            flags: Self::canonical_flags(code)?,
            code,
            data: AttributeData::Val(val),
        })
    }

    pub fn empty_as_path() -> Self {
        Attribute {
            flags: Self::FLAG_TRANSITIVE,
            code: Self::AS_PATH,
            data: AttributeData::Bin(Vec::new()),
        }
    }

    pub fn new_with_bin(code: u8, bin: Vec<u8>) -> Option<Self> {
        Some(Attribute {
            flags: Self::canonical_flags(code)?,
            code,
            data: AttributeData::Bin(bin),
        })
    }

    pub fn value(&self) -> Option<u32> {
        match self.data {
            AttributeData::Val(v) => Some(v),
            AttributeData::Bin(_) => None,
        }
    }

    pub fn binary(&self) -> Option<&Vec<u8>> {
        match &self.data {
            AttributeData::Val(_) => None,
            AttributeData::Bin(v) => Some(v),
        }
    }

    /// Returns the RFC-specified flags for a well-known attribute code, or `None` for unknown codes.
    pub fn canonical_flags(code: u8) -> Option<u8> {
        match code {
            Self::ORIGIN => Some(Self::FLAG_TRANSITIVE),
            Self::AS_PATH => Some(Self::FLAG_TRANSITIVE),
            Self::NEXTHOP => Some(Self::FLAG_TRANSITIVE),
            Self::MULTI_EXIT_DESC => Some(Self::FLAG_OPTIONAL),
            Self::LOCAL_PREF => Some(Self::FLAG_TRANSITIVE),
            Self::ATOMIC_AGGREGATE => Some(Self::FLAG_TRANSITIVE),
            Self::AGGREGATOR => Some(Self::FLAG_TRANSITIVE | Self::FLAG_OPTIONAL),
            Self::COMMUNITY => Some(Self::FLAG_TRANSITIVE | Self::FLAG_OPTIONAL),
            Self::ORIGINATOR_ID => Some(Self::FLAG_OPTIONAL),
            Self::CLUSTER_LIST => Some(Self::FLAG_OPTIONAL),
            Self::MP_REACH => Some(Self::FLAG_OPTIONAL),
            Self::MP_UNREACH => Some(Self::FLAG_OPTIONAL),
            Self::EXTENDED_COMMUNITY => Some(Self::FLAG_TRANSITIVE | Self::FLAG_OPTIONAL),
            Self::AS4_PATH => Some(Self::FLAG_TRANSITIVE | Self::FLAG_OPTIONAL),
            Self::AS4_AGGREGATOR => Some(Self::FLAG_TRANSITIVE | Self::FLAG_OPTIONAL),
            Self::AIGP => Some(Self::FLAG_TRANSITIVE | Self::FLAG_OPTIONAL),
            Self::LARGE_COMMUNITY => Some(Self::FLAG_TRANSITIVE | Self::FLAG_OPTIONAL),
            _ => None,
        }
    }

    fn decode(code: u8, flags: u8, c: &mut dyn io::Read, len: u16) -> Result<Self, ()> {
        let data = match code {
            Self::ORIGIN => {
                if len != 1 {
                    return Err(());
                }
                AttributeData::Val(c.read_u8().unwrap() as u32)
            }
            Self::MULTI_EXIT_DESC | Self::LOCAL_PREF | Self::ORIGINATOR_ID => {
                if len != 4 {
                    return Err(());
                }
                AttributeData::Val(c.read_u32::<NetworkEndian>().unwrap())
            }
            _ => {
                let mut b = Vec::with_capacity(len.into());
                for _ in 0..len {
                    b.push(c.read_u8().unwrap());
                }
                AttributeData::Bin(b)
            }
        };
        Ok(Attribute { code, flags, data })
    }

    pub fn as_path_length(&self) -> usize {
        assert_eq!(self.code, Attribute::AS_PATH);
        let buf = self.binary().unwrap();
        let len = buf.len() as u64;
        let mut c = Cursor::new(buf);
        let mut aslen = 0;
        while c.position() < len {
            let t = c.read_u8().unwrap();
            let l = c.read_u8().unwrap();

            match t {
                Attribute::AS_PATH_TYPE_SET => aslen += 1,
                Attribute::AS_PATH_TYPE_SEQ => aslen += l,
                Attribute::AS_PATH_TYPE_CONFED_SEQ => {}
                Attribute::AS_PATH_TYPE_CONFED_SET => {}
                _ => unreachable!(),
            }

            c.set_position(c.position() + l as u64 * 4);
        }
        aslen as usize
    }

    fn as_path_count(&self, asn: u32) -> Result<usize, Error> {
        let mut num = 0;

        let buf = self.binary().unwrap();
        let len = buf.len() as u64;
        let mut c = Cursor::new(buf);

        while c.position() < len {
            let _type = c.read_u8()?;
            let l = c.read_u8()?;

            for _ in 0..l {
                let n = c.read_u32::<NetworkEndian>()?;
                if n == asn {
                    num += 1;
                }
            }
        }

        Ok(num)
    }

    pub fn as_path_prepend(&self, as_number: u32) -> Attribute {
        assert_eq!(self.code, Attribute::AS_PATH);
        let buf = self.binary().unwrap();
        let len = buf.len() as u64;

        let data = if len != 0 && buf[0] == Attribute::AS_PATH_TYPE_SEQ && buf[1] < 255 {
            let mut new_buf = Vec::with_capacity(len as usize + 4);
            new_buf.put_u8(buf[0]);
            new_buf.put_u8(buf[1] + 1);
            new_buf.put_u32(as_number);
            new_buf.put(&buf[2..]);
            AttributeData::Bin(new_buf)
        } else if len == 0 {
            let mut new_buf = Vec::with_capacity(6);
            new_buf.put_u8(Attribute::AS_PATH_TYPE_SEQ);
            new_buf.put_u8(1);
            new_buf.put_u32(as_number);
            AttributeData::Bin(new_buf)
        } else {
            let mut new_buf = Vec::with_capacity(len as usize + 6);
            new_buf.put_u8(Attribute::AS_PATH_TYPE_SEQ);
            new_buf.put_u8(1);
            new_buf.put_u32(as_number);
            new_buf.put(&buf[..]);
            AttributeData::Bin(new_buf)
        };
        Attribute {
            code: self.code,
            flags: self.flags,
            data,
        }
    }

    pub fn as_path_origin(&self) -> Option<u32> {
        let buf = self.binary().unwrap();
        let len = buf.len() as u64;
        let mut c = Cursor::new(buf);

        if len < 2 {
            return None;
        }
        let mut t = 0;
        let mut num = 0;
        let mut asn = 0;
        while c.position() < len {
            t = c.read_u8().unwrap();
            num = c.read_u8().unwrap();
            for i in 0..num {
                let n = c.read_u32::<NetworkEndian>().unwrap();
                if i == num - 1 {
                    asn = n;
                }
            }
        }
        if t == Attribute::AS_PATH_TYPE_SEQ && num > 0 {
            Some(asn)
        } else {
            None
        }
    }

    pub fn nexthop_update(&self, addr: IpAddr) -> Attribute {
        assert_eq!(self.code, Attribute::NEXTHOP);
        match addr {
            IpAddr::V4(addr) => Attribute {
                code: self.code,
                flags: self.flags,
                data: AttributeData::Bin(addr.octets().to_vec()),
            },
            IpAddr::V6(addr) => Attribute {
                code: self.code,
                flags: self.flags,
                data: AttributeData::Bin(addr.octets().to_vec()),
            },
        }
    }

    pub fn export<B: BufMut + AsMut<[u8]>>(
        &self,
        code: u8,
        dst: Option<&mut B>,
        family: Family,
        codec: &PeerCodec,
    ) -> (u16, Option<Attribute>) {
        match code {
            Attribute::AS_PATH => {
                let n = if codec.keep_aspath {
                    self.clone()
                } else {
                    self.as_path_prepend(codec.local_asn)
                };
                let l = if let Some(dst) = dst {
                    n.encode(dst).unwrap()
                } else {
                    0
                };
                (l, Some(n))
            }
            Attribute::NEXTHOP => {
                if family != Family::IPV4 {
                    return (0, None);
                }
                let n = if codec.keep_nexthop {
                    self.clone()
                } else {
                    self.nexthop_update(codec.local_addr)
                };
                let l = if let Some(dst) = dst {
                    n.encode(dst).unwrap()
                } else {
                    0
                };
                (l, Some(n))
            }
            _ => {
                let l = if let Some(dst) = dst {
                    self.encode(dst).unwrap()
                } else {
                    0
                };
                (l, None)
            }
        }
    }

    fn encode<B: BufMut + AsMut<[u8]>>(&self, dst: &mut B) -> Result<u16, ()> {
        let pos_head = dst.as_mut().len();
        match self.code {
            Attribute::ORIGIN => {
                dst.put_u8(self.flags);
                dst.put_u8(self.code);
                dst.put_u8(1);
                dst.put_u8(self.value().unwrap() as u8);
            }
            Attribute::MULTI_EXIT_DESC | Attribute::LOCAL_PREF | Attribute::ORIGINATOR_ID => {
                dst.put_u8(self.flags);
                dst.put_u8(self.code);
                dst.put_u8(4);
                dst.put_u32(self.value().unwrap());
            }
            _ => {
                let bin = self.binary().unwrap();
                let flags = if bin.len() > 255 {
                    self.flags | Attribute::FLAG_EXTENDED
                } else {
                    self.flags
                };
                dst.put_u8(flags);
                dst.put_u8(self.code);
                if flags & Attribute::FLAG_EXTENDED > 0 {
                    dst.put_u16(bin.len() as u16);
                } else {
                    dst.put_u8(bin.len() as u8);
                }
                dst.put_slice(bin);
            }
        }

        Ok((dst.as_mut().len() - pos_head) as u16)
    }
}

/// BGP Hold Time (RFC 4271 §4.2): must be zero (disabled) or at least three seconds.
/// Values 1 and 2 are invalid per RFC 4271 §6.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HoldTime(u16);

impl HoldTime {
    /// Hold timer disabled (value 0).
    pub const DISABLED: HoldTime = HoldTime(0);

    /// Returns `Some(HoldTime)` if `secs` is 0 or ≥ 3, `None` for 1 or 2.
    pub fn new(secs: u16) -> Option<Self> {
        match secs {
            1 | 2 => None,
            _ => Some(HoldTime(secs)),
        }
    }

    pub fn is_disabled(self) -> bool {
        self.0 == 0
    }

    pub fn seconds(self) -> u16 {
        self.0
    }
}

impl std::fmt::Display for HoldTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// BGP OPEN message body (RFC 4271 §4.2).
#[derive(Clone)]
pub struct Open {
    pub as_number: u32,
    pub holdtime: HoldTime,
    /// BGP Identifier (RFC 6286): a 32-bit value, not necessarily a valid IPv4 address.
    pub router_id: u32,
    pub capability: Vec<Capability>,
}

/// BGP UPDATE message body (RFC 4271 §4.3, RFC 4760 §3).
#[derive(Clone)]
pub struct Update {
    /// Traditional BGP NLRI field (IPv4 unicast via legacy encoding).
    pub reach: Option<NlriSet>,
    /// MP_REACH_NLRI attribute (non-IPv4, or IPv4 via RFC 8950 Extended Nexthop).
    pub mp_reach: Option<NlriSet>,
    /// Traditional Withdrawn Routes field (IPv4 unicast via legacy encoding).
    pub unreach: Option<NlriSet>,
    /// MP_UNREACH_NLRI attribute (non-IPv4, or IPv4 via RFC 8950 Extended Nexthop).
    pub mp_unreach: Option<NlriSet>,
    pub attr: Arc<Vec<Attribute>>,
}

#[derive(Clone)]
pub enum Message {
    Open(Open),
    Update(Update),
    /// BGP NOTIFICATION message (RFC 4271 §4.5).
    /// Uses the typed `BgpError` to represent the error code/subcode.
    Notification(BgpError),
    Keepalive,
    RouteRefresh {
        family: Family,
    },
}

impl Message {
    pub(crate) const HEADER_LENGTH: u16 = 19;

    const MAX_LENGTH: usize = 4096;
    const MAX_EXTENDED_LENGTH: usize = 65535;

    const OPEN: u8 = 1;
    const UPDATE: u8 = 2;
    const NOTIFICATION: u8 = 3;
    const KEEPALIVE: u8 = 4;
    const ROUTE_REFRESH: u8 = 5;

    pub fn eor(family: Family) -> Message {
        if family == Family::IPV4 {
            Message::Update(Update {
                reach: Some(NlriSet::new(Family::IPV4)),
                mp_reach: None,
                attr: Arc::new(Vec::new()),
                unreach: None,
                mp_unreach: None,
            })
        } else {
            Message::Update(Update {
                reach: None,
                mp_reach: None,
                attr: Arc::new(Vec::new()),
                unreach: None,
                mp_unreach: Some(NlriSet::new(family)),
            })
        }
    }
}

pub struct Channel {
    family: Family,
    addpath: u8,
    extended_nexthop: bool,
}

impl Channel {
    pub fn addpath_rx(&self) -> bool {
        self.addpath & 0x1 > 0
    }

    pub fn addpath_tx(&self) -> bool {
        self.addpath & 0x2 > 0
    }

    pub fn extended_nexthop(&self) -> bool {
        self.extended_nexthop
    }

    pub fn set_extended_nexthop(&mut self, enabled: bool) {
        assert!(
            !enabled || self.family.afi() == Family::AFI_IP,
            "extended nexthop only valid for IPv4 families"
        );
        self.extended_nexthop = enabled;
    }

    pub fn new(family: Family, rx: bool, tx: bool) -> Self {
        let mut addpath = 0;
        if rx {
            addpath |= 0x1;
        }
        if tx {
            addpath |= 0x2;
        }
        Channel {
            family,
            addpath,
            extended_nexthop: false,
        }
    }
}

pub fn create_channel(
    local: &[Capability],
    remote: &[Capability],
) -> impl Iterator<Item = (Family, Channel)> {
    let f = |v: &[Capability]| -> FnvHashMap<Family, Channel> {
        let mut h = FnvHashMap::default();
        for c in v {
            if let Capability::MultiProtocol(f) = c {
                h.insert(
                    *f,
                    Channel {
                        family: *f,
                        addpath: 0,
                        extended_nexthop: false,
                    },
                );
            }
        }
        for c in v {
            if let Capability::AddPath(v) = c {
                for (f, mode) in v {
                    if let Some(fc) = h.get_mut(f) {
                        fc.addpath = *mode;
                    }
                }
            }
        }
        for c in v {
            if let Capability::ExtendedNexthop(v) = c {
                for (f, nexthop_afi) in v {
                    assert!(
                        f.afi() == Family::AFI_IP,
                        "RFC 8950: extended nexthop only valid for IPv4 families"
                    );
                    if *nexthop_afi == Family::AFI_IP6
                        && let Some(fc) = h.get_mut(f)
                    {
                        fc.extended_nexthop = true;
                    }
                }
            }
        }
        h
    };
    let mut l = f(local);
    f(remote).into_iter().filter_map(move |(f, rc)| {
        l.remove(&f).map(|lc| {
            (
                f,
                Channel {
                    family: f,
                    addpath: {
                        let rx = u8::from(lc.addpath & 0x1 > 0 && rc.addpath & 0x2 > 0);
                        let tx = u8::from(lc.addpath & 0x2 > 0 && rc.addpath & 0x1 > 0);
                        rx | (tx << 1)
                    },
                    extended_nexthop: lc.extended_nexthop & rc.extended_nexthop,
                },
            )
        })
    })
}

pub struct PeerCodecBuilder {
    local_asn: u32,
    remote_asn: u32,
    local_addr: IpAddr,
    extended_length: bool,
    keep_aspath: bool,
    keep_nexthop: bool,
    family: Vec<Family>,
}

impl Default for PeerCodecBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerCodecBuilder {
    pub fn new() -> Self {
        PeerCodecBuilder {
            local_asn: 0,
            remote_asn: 0,
            local_addr: IpAddr::V4(Ipv4Addr::from(0)),
            extended_length: false,
            keep_aspath: false,
            keep_nexthop: false,
            family: Vec::new(),
        }
    }

    pub fn build(&mut self) -> PeerCodec {
        let channel = self
            .family
            .iter()
            .map(|f| (*f, Channel::new(*f, false, false)))
            .collect();
        PeerCodec {
            local_asn: self.local_asn,
            remote_asn: self.remote_asn,
            local_addr: self.local_addr,
            extended_length: self.extended_length,
            keep_aspath: self.keep_aspath,
            keep_nexthop: self.keep_nexthop,
            channel,
        }
    }

    pub fn local_asn(&mut self, asn: u32) -> &mut Self {
        self.local_asn = asn;
        self
    }

    pub fn local_addr(&mut self, local_addr: IpAddr) -> &mut Self {
        self.local_addr = local_addr;
        self
    }

    pub fn keep_aspath(&mut self, y: bool) -> &mut Self {
        self.keep_aspath = y;
        self
    }

    pub fn keep_nexthop(&mut self, y: bool) -> &mut Self {
        self.keep_nexthop = y;
        self
    }

    pub fn families(&mut self, v: Vec<Family>) -> &mut Self {
        self.family = v;
        self
    }
}

pub struct PeerCodec {
    extended_length: bool,
    local_asn: u32,
    remote_asn: u32,
    local_addr: IpAddr,
    keep_aspath: bool,
    keep_nexthop: bool,
    pub channel: FnvHashMap<Family, Channel>,
}

impl PeerCodec {
    pub fn max_message_length(&self) -> usize {
        if self.extended_length {
            Message::MAX_EXTENDED_LENGTH
        } else {
            Message::MAX_LENGTH
        }
    }

    fn is_ibgp(&self) -> bool {
        self.local_asn == self.remote_asn
    }

    fn mp_reach_encode<B: BufMut + AsMut<[u8]>>(
        &self,
        buf_head: usize,
        attrs: Arc<Vec<Attribute>>,
        dst: &mut B,
        reach: &NlriSet,
        reach_idx: &mut usize,
    ) -> Result<u16, ()> {
        let family = &reach.family;
        let nets = &reach.entries;
        let is_extended = self
            .channel
            .get(family)
            .is_some_and(|c| c.extended_nexthop());
        // RFC 8950: extended nexthop requires IPv6 local address
        assert!(
            !is_extended || matches!(self.local_addr, IpAddr::V6(_)) || self.keep_nexthop,
            "extended nexthop requires IPv6 local address"
        );
        let pos_head = dst.as_mut().len();
        // always use extended length
        dst.put_u8(
            Attribute::canonical_flags(Attribute::MP_REACH).unwrap() | Attribute::FLAG_EXTENDED,
        );
        dst.put_u8(Attribute::MP_REACH);
        let pos_bin = dst.as_mut().len();
        dst.put_u16(0);
        dst.put_u16(family.afi());
        dst.put_u8(family.safi());
        if self.keep_nexthop {
            let mut addr = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0).octets();
            for a in &*attrs {
                if a.code() == Attribute::NEXTHOP {
                    if let Some(b) = a.binary() {
                        addr[0..b.len()].clone_from_slice(&b[..]);
                    }
                    break;
                }
            }
            dst.put_u8(addr.len() as u8);
            dst.put_slice(&addr);
        } else {
            match self.local_addr {
                IpAddr::V6(addr) => {
                    let addr = addr.octets();
                    dst.put_u8(addr.len() as u8);
                    dst.put_slice(&addr);
                }
                IpAddr::V4(addr) => {
                    let addr = addr.octets();
                    dst.put_u8(addr.len() as u8);
                    dst.put_slice(&addr);
                }
            };
        }
        // padding
        dst.put_u8(0);
        let addpath = self.channel.get(family).is_some_and(|c| c.addpath_tx());
        let max_len = 1 + 16 + if addpath { 4 } else { 0 };
        for (i, item) in nets.iter().enumerate().skip(*reach_idx) {
            let PathNlri {
                nlri: net,
                path_id: id,
            } = item;
            if buf_head + self.max_message_length() > dst.as_mut().len() + max_len {
                if addpath {
                    dst.put_u32(*id);
                }
                net.encode(dst).unwrap();
                *reach_idx = i;
            } else {
                break;
            }
        }
        let mp_len = (dst.as_mut().len() - pos_head) as u16;
        (&mut dst.as_mut()[pos_bin..])
            .write_u16::<NetworkEndian>(mp_len - 4)
            .unwrap();

        Ok(mp_len)
    }

    fn mp_unreach_encode<B: BufMut + AsMut<[u8]>>(
        &self,
        buf_head: usize,
        _: Arc<Vec<Attribute>>,
        dst: &mut B,
        unreach: &NlriSet,
        unreach_idx: &mut usize,
    ) -> Result<u16, ()> {
        let family = &unreach.family;
        let nets = &unreach.entries;
        let pos_head = dst.as_mut().len();
        // always use extended length
        dst.put_u8(
            Attribute::canonical_flags(Attribute::MP_UNREACH).unwrap() | Attribute::FLAG_EXTENDED,
        );
        dst.put_u8(Attribute::MP_UNREACH);
        let pos_bin = dst.as_mut().len();
        dst.put_u16(0);
        dst.put_u16(family.afi());
        dst.put_u8(family.safi());
        let addpath = self.channel.get(family).is_some_and(|c| c.addpath_tx());
        let max_len = 1 + 16 + if addpath { 4 } else { 0 };
        for (i, item) in nets.iter().enumerate().skip(*unreach_idx) {
            let PathNlri {
                nlri: net,
                path_id: id,
            } = item;
            if buf_head + self.max_message_length() > dst.as_mut().len() + max_len {
                if addpath {
                    dst.put_u32(*id);
                }
                net.encode(dst).unwrap();
                *unreach_idx = i;
            } else {
                break;
            }
        }
        let mp_len = (dst.as_mut().len() - pos_head) as u16;
        (&mut dst.as_mut()[pos_bin..])
            .write_u16::<NetworkEndian>(mp_len - 4)
            .unwrap();
        Ok(mp_len)
    }

    fn do_encode<B: BufMut + AsMut<[u8]>>(
        &mut self,
        item: &Message,
        dst: &mut B,
        reach_idx: &mut usize,
    ) -> Result<(), Error> {
        let pos_head = dst.as_mut().len();
        dst.put_u64(u64::MAX);
        dst.put_u64(u64::MAX);
        // updated later
        let pos_header_len = dst.as_mut().len();
        dst.put_u16(Message::HEADER_LENGTH);

        match item {
            Message::Open(Open {
                as_number,
                holdtime,
                router_id,
                capability,
            }) => {
                let trans_asn = if *as_number > u16::MAX as u32 {
                    Capability::TRANS_ASN
                } else {
                    *as_number as u16
                };
                dst.put_u8(Message::OPEN);
                dst.put_u8(4); // BGP version is always 4
                dst.put_u16(trans_asn);
                dst.put_u16(holdtime.seconds());
                dst.put_u32(*router_id);
                let op_param_len_pos = dst.as_mut().len();
                dst.put_u8(0);
                dst.put_u8(2); // capability parameter type
                let param_len_pos = dst.as_mut().len();
                dst.put_u8(0);

                let mut cap_len = 0;
                for cap in capability {
                    cap_len += cap.encode(dst).unwrap();
                }

                (&mut dst.as_mut()[param_len_pos..])
                    .write_u8(cap_len)
                    .unwrap();
                (&mut dst.as_mut()[op_param_len_pos..])
                    .write_u8(cap_len + 2_u8)
                    .unwrap();
            }
            Message::Update(Update {
                reach,
                mp_reach,
                attr,
                unreach,
                mp_unreach,
            }) => {
                let attrs = attr.clone();
                // Use family from whichever NlriSet is present for addpath lookup
                let family = reach
                    .as_ref()
                    .or(unreach.as_ref())
                    .map_or(Family::IPV4, |s| s.family);
                let addpath = self.channel.get(&family).is_some_and(|c| c.addpath_tx());
                dst.put_u8(Message::UPDATE);
                let pos_withdrawn_len = dst.as_mut().len();
                dst.put_u16(0);
                let mut withdrawn_len = 0;
                // Traditional IPv4 withdrawn routes
                if let Some(unreach) = unreach {
                    let max_len = 5 + if addpath { 4 } else { 0 };
                    for (i, item) in unreach.entries.iter().enumerate().skip(*reach_idx) {
                        if pos_head + self.max_message_length() > dst.as_mut().len() + max_len {
                            if addpath {
                                dst.put_u32(item.path_id);
                            }
                            withdrawn_len += item.nlri.encode(dst).unwrap();
                            *reach_idx = i;
                        } else {
                            break;
                        }
                    }
                }
                if withdrawn_len != 0 {
                    (&mut dst.as_mut()[pos_withdrawn_len..])
                        .write_u16::<NetworkEndian>(withdrawn_len)
                        .unwrap();
                }
                let pos_attr_len = dst.as_mut().len();
                dst.put_u16(0);
                // Like BIRD, for simplicity, MP_REACH/MP_UNREACH attribute isn't ordered.
                // BIRD encodes MP_REACH/MP_UNREACH first and then the rest.
                // RustyBGP encode MP_REACH/MP_UNREACH last.
                let mut attr_len = 0;
                let attr_family = mp_reach
                    .as_ref()
                    .or(mp_unreach.as_ref())
                    .map_or(family, |s| s.family);
                let mut has_as_path = false;
                for a in &*attrs {
                    if a.flags & Attribute::FLAG_TRANSITIVE > 0 {
                        let code = a.code();
                        if code == Attribute::AS_PATH {
                            has_as_path = true;
                        }
                        // RFC 8950: nexthop is carried inside MP_REACH_NLRI
                        if code == Attribute::NEXTHOP && mp_reach.is_some() {
                            continue;
                        }
                        let (n, _) = a.export(code, Some(dst), attr_family, self);
                        attr_len += n;
                    }
                }
                // Ensure AS_PATH is present (mandatory for eBGP UPDATEs).
                // Locally-originated routes may lack AS_PATH; create one
                // with the local ASN prepended. Skip for End-of-RIB markers
                // (empty UPDATEs with no NLRI).
                let has_nlri =
                    reach.as_ref().is_some_and(|r| !r.entries.is_empty()) || mp_reach.is_some();
                if !has_as_path && has_nlri {
                    let empty = Attribute::empty_as_path();
                    let (n, _) = empty.export(Attribute::AS_PATH, Some(dst), attr_family, self);
                    attr_len += n;
                }
                // MP_REACH_NLRI attribute
                if let Some(mp_reach) = mp_reach {
                    attr_len += self
                        .mp_reach_encode(pos_head, attr.clone(), dst, mp_reach, reach_idx)
                        .unwrap();
                }
                // MP_UNREACH_NLRI attribute
                if let Some(mp_unreach) = mp_unreach {
                    attr_len += self
                        .mp_unreach_encode(pos_head, attr.clone(), dst, mp_unreach, reach_idx)
                        .unwrap();
                }

                (&mut dst.as_mut()[pos_attr_len..])
                    .write_u16::<NetworkEndian>(attr_len)
                    .unwrap();

                // Traditional IPv4 NLRI
                if let Some(reach) = reach {
                    let max_len = 5 + if addpath { 4 } else { 0 };
                    for (i, item) in reach.entries.iter().enumerate().skip(*reach_idx) {
                        if pos_head + self.max_message_length() > dst.as_mut().len() + max_len {
                            if addpath {
                                dst.put_u32(item.path_id);
                            }
                            let _ = item.nlri.encode(dst);
                            *reach_idx = i;
                        } else {
                            break;
                        }
                    }
                }
            }
            Message::Notification(err) => {
                dst.put_u8(Message::NOTIFICATION);
                dst.put_u8(err.notification_code());
                dst.put_u8(err.notification_subcode());
                dst.put_slice(err.notification_data());
            }
            Message::Keepalive => {
                dst.put_u8(Message::KEEPALIVE);
            }
            Message::RouteRefresh {
                family: Family(family),
            } => {
                dst.put_u8(Message::ROUTE_REFRESH);
                dst.put_u32(*family);
            }
        }

        let pos_end = dst.as_mut().len();
        (&mut dst.as_mut()[pos_header_len..])
            .write_u16::<NetworkEndian>((pos_end - pos_head) as u16)?;

        Ok(())
    }

    fn decode_nlri<T: io::Read>(
        &self,
        chan: &Channel,
        c: &mut T,
        mut len: usize,
    ) -> Result<PathNlri, Error> {
        let malformed: Error = BgpError::UpdateMalformedAttributeList.into();
        let id = if chan.addpath_rx() {
            if len < 4 {
                return Err(malformed);
            }
            if let Ok(id) = c.read_u32::<NetworkEndian>() {
                len -= 4;
                id
            } else {
                return Err(malformed);
            }
        } else {
            0
        };
        match chan.family {
            Family::IPV4 => match Ipv4Net::decode(c, len) {
                Ok(net) => Ok(PathNlri {
                    nlri: Nlri::V4(net),
                    path_id: id,
                }),
                Err(err) => Err(err),
            },
            Family::IPV6 => match Ipv6Net::decode(c, len) {
                Ok(net) => Ok(PathNlri {
                    nlri: Nlri::V6(net),
                    path_id: id,
                }),
                Err(err) => Err(err),
            },
            _ => Err(malformed),
        }
    }
    pub fn parse_message(&mut self, buf: &[u8]) -> Result<Message, Error> {
        if buf.len() < Message::HEADER_LENGTH as usize {
            return Err(BgpError::BadMessageLength { data: vec![] }.into());
        }
        let code = buf[18];
        let header_len_error: Error = BgpError::BadMessageLength {
            data: (buf[16..18]).to_vec(),
        }
        .into();

        match code {
            Message::OPEN => {
                const MINIMUM_OPEN_LENGTH: usize = 29;
                let malformed: Error = BgpError::OpenMalformed.into();
                if buf.len() < MINIMUM_OPEN_LENGTH {
                    return Err(header_len_error);
                }
                let mut c = Cursor::new(&buf);
                c.set_position(Message::HEADER_LENGTH.into());
                let version = c.read_u8().unwrap();
                // BGP version must be 4 (RFC 4271 §4.2)
                if version != 4 {
                    return Err(BgpError::OpenMalformed.into());
                }
                let mut as_number = c.read_u16::<NetworkEndian>().unwrap() as u32;
                let raw_holdtime = c.read_u16::<NetworkEndian>().unwrap();
                let holdtime =
                    HoldTime::new(raw_holdtime).ok_or(BgpError::OpenUnacceptableHoldTime {
                        data: raw_holdtime.to_be_bytes().to_vec(),
                    })?;
                let router_id = c.read_u32::<NetworkEndian>().unwrap();
                let param_len = c.read_u8().unwrap();
                if buf.len() < MINIMUM_OPEN_LENGTH + param_len as usize {
                    return Err(malformed);
                }
                let param_end = c.position() + param_len as u64;
                let mut cap = Vec::new();
                while c.position() < param_end {
                    if param_end < c.position() + 2 {
                        return Err(malformed);
                    }
                    let op_type = c.read_u8().unwrap();
                    let op_len = c.read_u8().unwrap();
                    if param_end < c.position() + op_len as u64 {
                        return Err(malformed);
                    }
                    if op_type == 2 {
                        let op_end = c.position() + op_len as u64;
                        while c.position() < op_end {
                            if op_end < c.position() + 2 {
                                return Err(malformed);
                            }
                            let cap_type = c.read_u8().unwrap();
                            let cap_len = c.read_u8().unwrap();

                            if op_end < c.position() + cap_len as u64 {
                                return Err(malformed);
                            }
                            match Capability::decode(cap_type, &mut c, cap_len) {
                                Ok(decoded) => {
                                    if let Capability::FourOctetAsNumber(asn) = &decoded {
                                        self.remote_asn = *asn;
                                    }
                                    cap.push(decoded);
                                }
                                Err(_) => {
                                    return Err(malformed);
                                }
                            }
                        }
                    } else {
                        return Err(BgpError::OpenUnsupportedOptionalParameter {
                            data: buf[c.position() as usize - 2
                                ..c.position() as usize + op_len as usize]
                                .to_vec(),
                        }
                        .into());
                    }
                }
                if as_number == Capability::TRANS_ASN as u32 {
                    as_number = self.remote_asn;
                } else {
                    self.remote_asn = as_number;
                }

                Ok(Message::Open(Open {
                    as_number,
                    holdtime,
                    router_id,
                    capability: cap,
                }))
            }
            Message::UPDATE => {
                const MINIMUM_UPDATE_LENGTH: usize = 23;
                let malformed = || Error::from(BgpError::UpdateMalformedAttributeList);
                let reach_family = Family::IPV4;
                let unreach_family = Family::IPV4;
                let mut mp_reach_family = Family::IPV4;
                let mut mp_unreach_family = Family::IPV4;
                let mut attr = Vec::new();
                let mut reach = Vec::new();
                let mut unreach = Vec::new();
                let mut mp_reach_entries: Vec<PathNlri> = Vec::new();
                let mut mp_unreach_entries: Vec<PathNlri> = Vec::new();
                let mut mp_reach_attr = None;
                let mut mp_unreach_attr = None;
                if buf.len() < MINIMUM_UPDATE_LENGTH {
                    return Err(header_len_error);
                }
                let mut c = Cursor::new(&buf);
                c.set_position(Message::HEADER_LENGTH.into());
                let withdrawn_len = c.read_u16::<NetworkEndian>().unwrap();
                if buf.len() < (withdrawn_len as usize + MINIMUM_UPDATE_LENGTH) {
                    return Err(malformed());
                }
                c.set_position(c.position() + withdrawn_len as u64);
                let attr_len = c.read_u16::<NetworkEndian>()?;
                if buf.len() < (withdrawn_len + attr_len + MINIMUM_UPDATE_LENGTH as u16).into() {
                    return Err(malformed());
                }
                let mut seen = FnvHashMap::default();
                let attr_end = c.position() + attr_len as u64;
                let mut pre_code = 0;
                let mut unsorted = false;
                let mut error_withdraw = false;
                let mut attr_idx = 0;
                let reach_len = buf.len() as u64 - attr_end;
                while c.position() < attr_end {
                    if attr_end < c.position() + 2 {
                        break;
                    }
                    let flags = c.read_u8().unwrap();
                    let code = c.read_u8().unwrap();
                    if code < pre_code {
                        unsorted = true;
                    }
                    pre_code = code;
                    let alen = if flags & Attribute::FLAG_EXTENDED != 0 {
                        if attr_end < c.position() + 2 {
                            break;
                        }
                        c.read_u16::<NetworkEndian>().unwrap()
                    } else {
                        if attr_end < c.position() + 1 {
                            break;
                        }
                        c.read_u8().unwrap() as u16
                    };
                    if attr_end < c.position() + alen as u64 {
                        break;
                    }
                    match seen.entry(code) {
                        Occupied(_) => {
                            if code == Attribute::MP_REACH || code == Attribute::MP_UNREACH {
                                return Err(malformed());
                            } else {
                                c.set_position(c.position() + alen as u64);
                                continue;
                            }
                        }
                        Vacant(v) => {
                            v.insert(attr_idx);
                        }
                    }
                    match Attribute::canonical_flags(code) {
                        Some(expected_flags) => {
                            if (flags ^ expected_flags)
                                & (Attribute::FLAG_TRANSITIVE | Attribute::FLAG_OPTIONAL)
                                > 0
                            {
                                // FIXME: handle aigp case
                                c.set_position(c.position() + alen as u64);
                                error_withdraw = true;
                                continue;
                            } else {
                                let cur = c.position();
                                match Attribute::decode(code, flags, &mut c, alen) {
                                    Ok(a) => {
                                        if code == Attribute::MP_REACH {
                                            mp_reach_attr = Some(a);
                                        } else if code == Attribute::MP_UNREACH {
                                            mp_unreach_attr = Some(a);
                                        } else {
                                            attr.push(a);
                                            attr_idx += 1;
                                        }
                                    }
                                    Err(_) => {
                                        error_withdraw = true;
                                        c.set_position(cur + alen as u64);
                                        continue;
                                    }
                                }
                            }
                        }
                        None => {
                            if flags & Attribute::FLAG_OPTIONAL == 0 {
                                error_withdraw = true;
                            }
                            c.set_position(c.position() + alen as u64);
                        }
                    }
                }

                // v4 eor
                if reach_len == 0 && attr_len == 0 && withdrawn_len == 0 {
                    return Ok(Message::Update(Update {
                        reach: Some(NlriSet::new(Family::IPV4)),
                        mp_reach: None,
                        attr: Arc::new(Vec::new()),
                        unreach: None,
                        mp_unreach: None,
                    }));
                }

                if reach_len != 0 || mp_reach_attr.is_some() {
                    if !seen.contains_key(&Attribute::ORIGIN)
                        || !seen.contains_key(&Attribute::AS_PATH)
                    {
                        error_withdraw = true;
                    }

                    if !error_withdraw && !seen.contains_key(&Attribute::NEXTHOP) && reach_len != 0
                    {
                        error_withdraw = true;
                    }

                    if !error_withdraw {
                        match attr[*seen.get(&Attribute::AS_PATH).unwrap()]
                            .as_path_count(self.local_asn)
                        {
                            Ok(v) => {
                                if v > 0 {
                                    error_withdraw = true
                                }
                            }
                            Err(_) => error_withdraw = true,
                        }
                    }
                }

                if c.position() != attr_end {
                    error_withdraw = true;
                    c.set_position(attr_end);
                }

                if (c.position() as usize) < buf.len() {
                    let chan = self.channel.get(&Family::IPV4).ok_or_else(malformed)?;
                    while (c.position() as usize) < buf.len() {
                        let rest = buf.len() - c.position() as usize;

                        match self.decode_nlri(chan, &mut c, rest) {
                            Ok(net) => reach.push(net),
                            Err(err) => return Err(err),
                        }
                    }
                }

                if 0 < withdrawn_len {
                    let chan = self.channel.get(&Family::IPV4).ok_or_else(malformed)?;
                    c.set_position(Message::HEADER_LENGTH as u64 + 2);
                    let withdrawn_end = c.position() + withdrawn_len as u64;
                    while c.position() < withdrawn_end {
                        let rest = withdrawn_end - c.position();
                        match self.decode_nlri(chan, &mut c, rest as usize) {
                            Ok(net) => unreach.push(net),
                            Err(err) => return Err(err),
                        }
                    }
                }

                if attr_len > 0 && !seen.contains_key(&Attribute::LOCAL_PREF) && self.is_ibgp() {
                    unsorted = true;
                    attr.push(
                        Attribute::new_with_value(
                            Attribute::LOCAL_PREF,
                            Attribute::DEFAULT_LOCAL_PREF,
                        )
                        .unwrap(),
                    );
                }

                if unsorted {
                    attr.sort_unstable_by_key(|a| a.code());
                }

                if error_withdraw {
                    unreach.append(&mut reach);
                }

                if let Some(a) = mp_reach_attr {
                    let err: Error = BgpError::UpdateOptionalAttributeError.into();
                    let buf = a.binary().unwrap();
                    if buf.len() < 5 {
                        return Err(err);
                    }
                    let mut c = Cursor::new(buf);
                    let afi = c.read_u16::<NetworkEndian>().unwrap();
                    match afi {
                        Family::AFI_IP | Family::AFI_IP6 => {}
                        _ => return Err(err),
                    }
                    let safi = c.read_u8().unwrap();
                    mp_reach_family = Family((afi as u32) << 16 | safi as u32);
                    let chan = self.channel.get(&mp_reach_family).ok_or_else(malformed)?;
                    let nexthop_len = c.read_u8().unwrap();
                    if buf.len() < 5 + nexthop_len as usize {
                        return Err(err);
                    }
                    let mut data = Vec::with_capacity(nexthop_len as usize);
                    match nexthop_len {
                        4 | 16 | 32 => {
                            for _ in 0..nexthop_len {
                                data.push(c.read_u8().unwrap());
                            }
                            let na = Attribute {
                                code: Attribute::NEXTHOP,
                                flags: Attribute::canonical_flags(Attribute::NEXTHOP).unwrap(),
                                data: AttributeData::Bin(data),
                            };
                            attr.insert(0, na);
                        }
                        _ => return Err(err),
                    }
                    c.read_u8().unwrap();
                    while c.position() < buf.len() as u64 {
                        let rest = buf.len() - c.position() as usize;
                        match self.decode_nlri(chan, &mut c, rest) {
                            Ok(net) => mp_reach_entries.push(net),
                            Err(err) => return Err(err),
                        }
                    }
                }

                if let Some(a) = mp_unreach_attr {
                    let err: Error = BgpError::UpdateOptionalAttributeError.into();
                    let buf = a.binary().unwrap();
                    if buf.len() < 3 {
                        return Err(err);
                    }
                    let mut c = Cursor::new(buf);
                    let afi = c.read_u16::<NetworkEndian>().unwrap();
                    match afi {
                        Family::AFI_IP | Family::AFI_IP6 => {}
                        _ => return Err(err),
                    }
                    let safi = c.read_u8().unwrap();
                    mp_unreach_family = Family((afi as u32) << 16 | safi as u32);
                    let chan = self.channel.get(&mp_unreach_family).ok_or_else(malformed)?;
                    while c.position() < buf.len() as u64 {
                        let rest = buf.len() - c.position() as usize;
                        match self.decode_nlri(chan, &mut c, rest) {
                            Ok(net) => mp_unreach_entries.push(net),
                            Err(err) => return Err(err),
                        }
                    }
                }

                Ok(Message::Update(Update {
                    reach: if reach.is_empty() {
                        None
                    } else {
                        Some(NlriSet {
                            family: reach_family,
                            entries: reach,
                        })
                    },
                    mp_reach: if mp_reach_entries.is_empty() {
                        None
                    } else {
                        Some(NlriSet {
                            family: mp_reach_family,
                            entries: mp_reach_entries,
                        })
                    },
                    attr: Arc::new(attr),
                    unreach: if unreach.is_empty() {
                        None
                    } else {
                        Some(NlriSet {
                            family: unreach_family,
                            entries: unreach,
                        })
                    },
                    mp_unreach: if mp_unreach_entries.is_empty() {
                        None
                    } else {
                        Some(NlriSet {
                            family: mp_unreach_family,
                            entries: mp_unreach_entries,
                        })
                    },
                }))
            }
            Message::NOTIFICATION => {
                const MINIMUM_NOTIFICATION_LENGTH: usize = Message::HEADER_LENGTH as usize + 2;
                if buf.len() < MINIMUM_NOTIFICATION_LENGTH {
                    return Err(header_len_error);
                }
                let mut c = Cursor::new(&buf);
                c.set_position(Message::HEADER_LENGTH.into());
                let code = c.read_u8().unwrap();
                let subcode = c.read_u8().unwrap();

                Ok(Message::Notification(BgpError::from_notification(
                    code,
                    subcode,
                    buf[c.position() as usize..].to_vec(),
                )))
            }
            Message::KEEPALIVE => Ok(Message::Keepalive),
            Message::ROUTE_REFRESH => {
                const ROUTE_REFRESH_LENGTH: usize = Message::HEADER_LENGTH as usize + 4;
                if buf.len() < ROUTE_REFRESH_LENGTH {
                    return Err(header_len_error);
                }
                if ROUTE_REFRESH_LENGTH < buf.len() {
                    return Err(BgpError::RouteRefreshInvalidLength { data: buf.to_vec() }.into());
                }
                let mut c = Cursor::new(&buf);
                c.set_position(Message::HEADER_LENGTH.into());
                Ok(Message::RouteRefresh {
                    family: Family(c.read_u32::<NetworkEndian>().unwrap()),
                })
            }
            _ => Err(BgpError::BadMessageType { data: vec![code] }.into()),
        }
    }

    pub fn encode_to<B: BufMut + AsMut<[u8]>>(
        &mut self,
        msg: &Message,
        dst: &mut B,
    ) -> Result<(), Error> {
        let mut done_idx = 0;
        match msg {
            Message::Update(Update {
                reach,
                mp_reach,
                unreach,
                mp_unreach,
                ..
            }) => {
                // Determine the number of iterations needed for splitting large route sets.
                // reach and unreach use the traditional IPv4 field and may need splitting.
                // mp_reach and mp_unreach go into path attributes and are encoded as a whole.
                let n = std::cmp::max(
                    reach.as_ref().map_or(0, |s| s.entries.len()),
                    unreach.as_ref().map_or(0, |s| s.entries.len()),
                );
                let mp_n = std::cmp::max(
                    mp_reach.as_ref().map_or(0, |s| s.entries.len()),
                    mp_unreach.as_ref().map_or(0, |s| s.entries.len()),
                );
                let total = std::cmp::max(n.max(1), mp_n.max(1));
                loop {
                    self.do_encode(msg, dst, &mut done_idx)?;
                    done_idx += 1;
                    if total == 0 || done_idx >= total {
                        break;
                    }
                }
                Ok(())
            }
            _ => self.do_encode(msg, dst, &mut done_idx),
        }
    }
}
