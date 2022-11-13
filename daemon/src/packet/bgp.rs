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

use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use bytes::{BufMut, BytesMut};
use fnv::FnvHashMap;
use once_cell::sync::Lazy;
use prost::Message as ProstMessage;
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::convert::{Into, TryFrom};
use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;
use std::{fmt, io};
use tokio_util::codec::{Decoder, Encoder};

use crate::api;
use crate::config;
use crate::error::Error;
use crate::proto;

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub(crate) struct Family(u32);

impl Family {
    const AFI_IP: u16 = 1;
    const AFI_IP6: u16 = 2;

    const SAFI_UNICAST: u8 = 1;

    pub(crate) const EMPTY: Family = Family(0);
    pub(crate) const IPV4: Family =
        Family((Family::AFI_IP as u32) << 16 | Family::SAFI_UNICAST as u32);
    pub(crate) const IPV6: Family =
        Family((Family::AFI_IP6 as u32) << 16 | Family::SAFI_UNICAST as u32);

    pub(crate) fn afi(&self) -> u16 {
        (self.0 >> 16) as u16
    }

    pub(crate) fn safi(&self) -> u8 {
        (self.0 & 0xff) as u8
    }
}

impl From<&api::Family> for Family {
    fn from(f: &api::Family) -> Self {
        Family((f.afi as u32) << 16 | f.safi as u32)
    }
}

impl From<Family> for api::Family {
    fn from(f: Family) -> Self {
        api::Family {
            afi: f.afi() as i32,
            safi: f.safi() as i32,
        }
    }
}

impl TryFrom<&config::gen::AfiSafiType> for Family {
    type Error = ();

    fn try_from(f: &config::gen::AfiSafiType) -> Result<Self, Self::Error> {
        match f {
            config::gen::AfiSafiType::Ipv4Unicast => Ok(Family::IPV4),
            config::gen::AfiSafiType::Ipv6Unicast => Ok(Family::IPV6),
            _ => Err(()),
        }
    }
}

#[derive(Clone, PartialEq)]
pub(crate) enum IpNet {
    V4(Ipv4Net),
    V6(Ipv6Net),
}

impl IpNet {
    pub(crate) fn new(prefix: IpAddr, mask: u8) -> Self {
        match prefix {
            IpAddr::V4(addr) => IpNet::V4(Ipv4Net { addr, mask }),
            IpAddr::V6(addr) => IpNet::V6(Ipv6Net { addr, mask }),
        }
    }

    pub(crate) fn contains(&self, addr: &IpAddr) -> bool {
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
pub(crate) enum Net {
    V4(Ipv4Net),
    V6(Ipv6Net),
    // add more Family here
}

impl Net {
    fn encode(&self, dst: &mut BytesMut) -> Result<u16, ()> {
        match self {
            Net::V4(net) => net.encode(dst),
            Net::V6(net) => net.encode(dst),
        }
    }
}

impl FromStr for Net {
    type Err = Error;

    fn from_str(s: &str) -> Result<Net, Error> {
        match IpNet::from_str(s) {
            Ok(n) => match n {
                IpNet::V4(n) => Ok(Net::V4(n)),
                IpNet::V6(n) => Ok(Net::V6(n)),
            },
            Err(e) => Err(e),
        }
    }
}

impl fmt::Display for Net {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Net::V4(net) => net.fmt(f),
            Net::V6(net) => net.fmt(f),
        }
    }
}

impl From<&Net> for prost_types::Any {
    fn from(f: &Net) -> Self {
        let (prefix, mask) = match f {
            Net::V4(n) => (n.addr.to_string(), n.mask),
            Net::V6(n) => (n.addr.to_string(), n.mask),
        };
        proto::to_any(
            api::IpAddressPrefix {
                prefix,
                prefix_len: mask as u32,
            },
            "IPAddressPrefix",
        )
    }
}

impl TryFrom<prost_types::Any> for Net {
    type Error = Error;

    fn try_from(a: prost_types::Any) -> Result<Self, Self::Error> {
        if a.type_url == proto::type_url("IPAddressPrefix") {
            let n = api::IpAddressPrefix::decode(&*a.value)
                .map_err(|e| Error::InvalidArgument(e.to_string()))?;
            return Net::from_str(&format!("{}/{}", n.prefix, n.prefix_len));
        }
        Err(Error::InvalidArgument(format!(
            "unknown type url {}",
            a.type_url
        )))
    }
}

#[derive(PartialEq, Eq, Hash, Clone, Debug, Copy)]
pub(crate) struct Ipv4Net {
    pub(crate) addr: Ipv4Addr,
    pub(crate) mask: u8,
}

impl Ipv4Net {
    fn decode<T: io::Read>(c: &mut T, len: usize) -> Result<Ipv4Net, Error> {
        let bit_len = c.read_u8()?;
        if len < ((bit_len as usize + 7) / 8) || bit_len > 32 {
            return Err(Error::InvalidMessageFormat {
                code: 3,
                subcode: 1,
                data: Vec::new(),
            });
        }
        let mut addr = [0_u8; 4];
        for i in 0..(bit_len + 7) / 8 {
            addr[i as usize] = c.read_u8().unwrap();
        }
        Ok(Ipv4Net {
            addr: Ipv4Addr::from(addr),
            mask: bit_len,
        })
    }

    fn encode(&self, dst: &mut BytesMut) -> Result<u16, ()> {
        let head_pos = dst.len();
        let prefix_len = (self.mask + 7) / 8;
        dst.put_u8(self.mask);
        for i in 0..prefix_len {
            dst.put_u8(self.addr.octets()[i as usize]);
        }
        Ok((dst.len() - head_pos) as u16)
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
pub(crate) struct Ipv6Net {
    pub(crate) addr: Ipv6Addr,
    pub(crate) mask: u8,
}

impl Ipv6Net {
    fn decode<T: io::Read>(c: &mut T, len: usize) -> Result<Ipv6Net, Error> {
        let bit_len = c.read_u8()?;
        if len < ((bit_len as usize + 7) / 8) || bit_len > 128 {
            return Err(Error::InvalidMessageFormat {
                code: 3,
                subcode: 1,
                data: Vec::new(),
            });
        }
        let mut addr = [0_u8; 16];
        for i in 0..(bit_len + 7) / 8 {
            addr[i as usize] = c.read_u8()?;
        }
        Ok(Ipv6Net {
            addr: Ipv6Addr::from(addr),
            mask: bit_len,
        })
    }

    fn encode(&self, dst: &mut BytesMut) -> Result<u16, ()> {
        let head_pos = dst.len();
        let prefix_len = (self.mask + 7) / 8;
        dst.put_u8(self.mask);
        for i in 0..prefix_len {
            dst.put_u8(self.addr.octets()[i as usize]);
        }
        Ok((dst.len() - head_pos) as u16)
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
pub(crate) enum Capability {
    MultiProtocol(Family),
    RouteRefresh,
    ExtendedNexthop(Vec<(Family, u16)>),
    //    ExtendedMessage,
    GracefulRestart(u8, u16, Vec<(Family, u8)>),
    FourOctetAsNumber(u32),
    AddPath(Vec<(Family, u8)>),
    EnhanshedRouteRefresh,
    LongLivedGracefulRestart(Vec<(Family, u8, u32)>),
    Fqdn(String, String),
    Unknown { code: u8, bin: Vec<u8> },
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
            Capability::GracefulRestart(..) => Capability::GRACEFUL_RESTART,
            Capability::FourOctetAsNumber(_) => Capability::FOUR_OCTET_AS_NUMBER,
            Capability::AddPath(_) => Capability::ADD_PATH,
            Capability::EnhanshedRouteRefresh => Capability::ENHANCED_ROUTE_REFRESH,
            Capability::LongLivedGracefulRestart(_) => Capability::LONG_LIVED_GRACEFUL_RESTART,
            Capability::Fqdn(..) => Capability::FQDN,
            Capability::Unknown { code, bin: _ } => *code,
        }
    }
}

impl From<&Capability> for prost_types::Any {
    fn from(cap: &Capability) -> Self {
        let name = match CAP_DESCS.get(&(cap.into())) {
            Some(desc) => desc.url,
            None => "UnknownCapability",
        };

        match cap {
            Capability::MultiProtocol(family) => proto::to_any(
                api::MultiProtocolCapability {
                    family: Some(api::Family::from(*family)),
                },
                name,
            ),
            Capability::RouteRefresh => proto::to_any(api::RouteRefreshCapability {}, name),
            Capability::ExtendedNexthop(v) => proto::to_any(
                api::ExtendedNexthopCapability {
                    tuples: v
                        .iter()
                        .map(|(family, afi)| api::ExtendedNexthopCapabilityTuple {
                            nlri_family: Some((*family).into()),
                            nexthop_family: Some(api::Family {
                                afi: *afi as i32,
                                safi: Family::SAFI_UNICAST as i32,
                            }),
                        })
                        .collect(),
                },
                name,
            ),
            Capability::GracefulRestart(flags, time, v) => proto::to_any(
                api::GracefulRestartCapability {
                    flags: *flags as u32,
                    time: *time as u32,
                    tuples: v
                        .iter()
                        .map(|(family, flags)| api::GracefulRestartCapabilityTuple {
                            flags: *flags as u32,
                            family: Some((*family).into()),
                        })
                        .collect(),
                },
                name,
            ),
            Capability::FourOctetAsNumber(asn) => {
                proto::to_any(api::FourOctetAsnCapability { asn: *asn }, name)
            }
            Capability::AddPath(v) => proto::to_any(
                api::AddPathCapability {
                    tuples: v
                        .iter()
                        .map(|(family, mode)| api::AddPathCapabilityTuple {
                            family: Some((*family).into()),
                            mode: *mode as i32,
                        })
                        .collect(),
                },
                name,
            ),
            Capability::EnhanshedRouteRefresh => {
                proto::to_any(api::EnhancedRouteRefreshCapability {}, name)
            }
            Capability::LongLivedGracefulRestart(v) => proto::to_any(
                api::LongLivedGracefulRestartCapability {
                    tuples: v
                        .iter()
                        .map(
                            |(family, flags, time)| api::LongLivedGracefulRestartCapabilityTuple {
                                family: Some((*family).into()),
                                flags: *flags as u32,
                                time: *time as u32,
                            },
                        )
                        .collect(),
                },
                name,
            ),
            Capability::Fqdn(host, domain) => proto::to_any(
                api::FqdnCapability {
                    host_name: host.to_string(),
                    domain_name: domain.to_string(),
                },
                name,
            ),
            Capability::Unknown { code, bin } => proto::to_any(
                api::UnknownCapability {
                    code: (*code as u32),
                    value: bin.to_owned(),
                },
                name,
            ),
        }
    }
}

impl Capability {
    fn encode(&self, c: &mut BytesMut) -> Result<u8, ()> {
        let head = c.len();
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
            Capability::GracefulRestart(flags, time, v) => {
                c.put_u8(v.len() as u8 + 2);
                c.put_u16((*flags as u16) << 12 | *time as u16);
                for (family, af_flags) in v {
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
            Capability::EnhanshedRouteRefresh => {
                c.put_u8(0);
            }
            Capability::LongLivedGracefulRestart(v) => {
                c.put_u8(v.len() as u8 * 7);
                for (family, flags, time) in v {
                    c.put_u16(family.afi());
                    c.put_u8(family.safi());
                    c.put_u8(*flags);
                    c.put_u32(*time);
                }
            }
            Capability::Fqdn(host, domain) => {
                c.put_u8((2 + host.len() + domain.len()) as u8);
                c.put_u8(host.len() as u8);
                c.put_slice(
                    ascii::AsciiStr::from_ascii(&host.to_ascii_lowercase())
                        .unwrap()
                        .as_bytes(),
                );
                c.put_u8(domain.len() as u8);
                c.put_slice(
                    ascii::AsciiStr::from_ascii(&domain.to_ascii_lowercase())
                        .unwrap()
                        .as_bytes(),
                );
            }
            Capability::Unknown { code: _, bin } => {
                c.put_u8(bin.len() as u8);
                for v in bin {
                    c.put_u8(*v);
                }
            }
        }
        Ok((c.len() - head) as u8)
    }
}

struct CapDesc {
    code: u8,
    url: &'static str,
    decode: fn(s: &mut Codec, c: &mut dyn io::Read, len: u8) -> Result<Capability, ()>,
}

static CAP_DESCS: Lazy<FnvHashMap<u8, CapDesc>> = Lazy::new(|| {
    vec![
        CapDesc {
            code: Capability::MULTI_PROTOCOL,
            url: "MultiProtocolCapability",
            decode: (|_s, c, len| {
                if len != 4 {
                    return Err(());
                }
                Ok(Capability::MultiProtocol(Family(
                    c.read_u32::<NetworkEndian>().unwrap(),
                )))
            }),
        },
        CapDesc {
            code: Capability::ROUTE_REFRESH,
            url: "RouteRefreshCapability",
            decode: (|_s, _c, len| {
                if len != 0 {
                    return Err(());
                }
                Ok(Capability::RouteRefresh {})
            }),
        },
        CapDesc {
            code: Capability::EXTENDED_NEXTHOP,
            url: "ExtendedNexthopCapability",
            decode: (|_s, c, len| {
                if len % 6 != 0 {
                    return Err(());
                }
                let mut v = Vec::new();
                for _ in 0..len / 6 {
                    let family = Family(c.read_u32::<NetworkEndian>().unwrap());
                    let afi = c.read_u16::<NetworkEndian>().unwrap();
                    if family.afi() != Family::AFI_IP || afi != Family::AFI_IP6 {
                        continue;
                    }
                    v.push((family, afi));
                }
                Ok(Capability::ExtendedNexthop(v))
            }),
        },
        CapDesc {
            code: Capability::GRACEFUL_RESTART,
            url: "GracefulRestartCapability",
            decode: (|_s, c, len| {
                if len % 4 != 2 {
                    return Err(());
                }
                let restart = c.read_u16::<NetworkEndian>().unwrap();
                let flags = (restart >> 12) as u8;
                let time = restart & 0xfff;
                let mut v = Vec::new();
                for _ in 0..(len - 2) / 4 {
                    let afi = c.read_u16::<NetworkEndian>().unwrap() as u32;
                    let safi = c.read_u8().unwrap() as u32;
                    let af_flag = c.read_u8().unwrap();
                    v.push((Family(afi << 16 | safi), af_flag));
                }
                Ok(Capability::GracefulRestart(flags, time, v))
            }),
        },
        CapDesc {
            code: Capability::FOUR_OCTET_AS_NUMBER,
            url: "FourOctetASNCapability",
            decode: (|s, c, len| {
                if len != 4 {
                    return Err(());
                }
                let remote_as = c.read_u32::<NetworkEndian>().unwrap();
                s.remote_asn = remote_as;
                Ok(Capability::FourOctetAsNumber(remote_as))
            }),
        },
        CapDesc {
            code: Capability::ADD_PATH,
            url: "AddPathCapability",
            decode: (|_s, c, len| {
                if len % 4 != 0 {
                    return Err(());
                }
                let mut v = Vec::new();
                for _ in 0..len / 4 {
                    let afi = c.read_u16::<NetworkEndian>().unwrap() as u32;
                    let safi = c.read_u8().unwrap() as u32;
                    let val = c.read_u8().unwrap();
                    if val > 3 {
                        continue;
                    }
                    v.push((Family(afi << 16 | safi), val));
                }
                Ok(Capability::AddPath(v))
            }),
        },
        CapDesc {
            code: Capability::ENHANCED_ROUTE_REFRESH,
            url: "EnhancedRouteRefreshCapability",
            decode: (|_s, _c, len| {
                if len != 0 {
                    return Err(());
                }
                Ok(Capability::EnhanshedRouteRefresh {})
            }),
        },
        CapDesc {
            code: Capability::LONG_LIVED_GRACEFUL_RESTART,
            url: "LongLivedGracefulRestartCapability",
            decode: (|_s, c, len| {
                if len % 7 != 0 {
                    return Err(());
                }
                let mut v = Vec::new();
                for _ in 0..len / 7 {
                    let afi = c.read_u16::<NetworkEndian>().unwrap() as u32;
                    let safi = c.read_u8().unwrap() as u32;
                    let flags = c.read_u8().unwrap();
                    let time = (c.read_u8().unwrap() as u32) << 16
                        | (c.read_u8().unwrap() as u32) << 8
                        | c.read_u8().unwrap() as u32;
                    v.push((Family(afi << 16 | safi), flags, time));
                }
                Ok(Capability::LongLivedGracefulRestart(v))
            }),
        },
        CapDesc {
            code: Capability::FQDN,
            url: "FqdnCapability",
            decode: (|_s, c, len| {
                if len < 1 {
                    return Err(());
                }
                let hostlen = c.read_u8().unwrap();
                let mut h = Vec::new();
                for _ in 0..hostlen {
                    h.push(c.read_u8().unwrap());
                }
                let host = ascii::AsciiString::from_ascii(h).unwrap().to_string();

                let domainlen = c.read_u8().unwrap();
                let mut d = Vec::new();
                for _ in 0..domainlen {
                    d.push(c.read_u8().unwrap());
                }
                let domain = ascii::AsciiString::from_ascii(d).unwrap().to_string();
                Ok(Capability::Fqdn(host, domain))
            }),
        },
    ]
    .into_iter()
    .map(|x| (x.code, x))
    .collect()
});

pub(crate) struct AsPathIter<'a> {
    cur: Cursor<&'a Vec<u8>>,
    len: u64,
}

impl<'a> AsPathIter<'a> {
    pub(crate) fn new(attr: &'a Attribute) -> AsPathIter<'a> {
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
pub(crate) struct Attribute {
    code: u8,
    flags: u8,
    data: AttributeData,
}

impl Attribute {
    pub(crate) const ORIGIN_INCOMPLETE: u8 = 2;
    const FLAG_EXTENDED: u8 = 1 << 4;
    // const FLAG_PARTIAL: u8 = 1 << 5;
    const FLAG_TRANSITIVE: u8 = 1 << 6;
    const FLAG_OPTIONAL: u8 = 1 << 7;

    pub(crate) const ORIGIN: u8 = 1;
    pub(crate) const AS_PATH: u8 = 2;
    pub(crate) const NEXTHOP: u8 = 3;
    pub(crate) const MULTI_EXIT_DESC: u8 = 4;
    pub(crate) const LOCAL_PREF: u8 = 5;
    pub(crate) const ATOMIC_AGGREGATE: u8 = 6;
    pub(crate) const AGGREGATOR: u8 = 7;
    pub(crate) const COMMUNITY: u8 = 8;
    pub(crate) const ORIGINATOR_ID: u8 = 9;
    pub(crate) const CLUSTER_LIST: u8 = 10;
    pub(crate) const MP_REACH: u8 = 14;
    pub(crate) const MP_UNREACH: u8 = 15;
    pub(crate) const EXTENDED_COMMUNITY: u8 = 16;
    pub(crate) const AS4_PATH: u8 = 17;
    pub(crate) const AS4_AGGREGATOR: u8 = 18;
    pub(crate) const AIGP: u8 = 26;
    pub(crate) const LARGE_COMMUNITY: u8 = 32;

    pub(crate) const AS_PATH_TYPE_SET: u8 = 1;
    pub(crate) const AS_PATH_TYPE_SEQ: u8 = 2;
    pub(crate) const AS_PATH_TYPE_CONFED_SEQ: u8 = 3;
    pub(crate) const AS_PATH_TYPE_CONFED_SET: u8 = 4;

    pub(crate) const DEFAULT_LOCAL_PREF: u32 = 100;

    pub(crate) fn code(&self) -> u8 {
        self.code
    }

    pub(crate) fn new_with_value(code: u8, val: u32) -> Option<Self> {
        ATTR_DESCS.get(&code).map(|desc| Attribute {
            code: desc.code,
            flags: desc.flags,
            data: AttributeData::Val(val),
        })
    }

    pub(crate) fn new_with_bin(code: u8, bin: Vec<u8>) -> Option<Self> {
        ATTR_DESCS.get(&code).map(|desc| Attribute {
            code: desc.code,
            flags: desc.flags,
            data: AttributeData::Bin(bin),
        })
    }

    pub(crate) fn value(&self) -> Option<u32> {
        match self.data {
            AttributeData::Val(v) => Some(v),
            AttributeData::Bin(_) => None,
        }
    }

    pub(crate) fn binary(&self) -> Option<&Vec<u8>> {
        match &self.data {
            AttributeData::Val(_) => None,
            AttributeData::Bin(v) => Some(v),
        }
    }

    pub(crate) fn as_path_length(&self) -> usize {
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

    pub(crate) fn as_path_prepend(&self, as_number: u32) -> Attribute {
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
        } else {
            let mut new_buf = Vec::with_capacity(len as usize + 6);
            new_buf.put_u8(Attribute::AS_PATH_TYPE_SEQ);
            new_buf.put_u8(1);
            new_buf.put_u32(as_number);
            new_buf.put(&buf[4..]);
            AttributeData::Bin(new_buf)
        };
        Attribute {
            code: self.code,
            flags: self.flags,
            data,
        }
    }

    pub(crate) fn as_path_origin(&self) -> Option<u32> {
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

    pub(crate) fn nexthop_update(&self, addr: IpAddr) -> Attribute {
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

    pub(crate) fn export(
        &self,
        code: u8,
        dst: Option<&mut BytesMut>,
        family: Family,
        codec: &Codec,
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

    fn encode(&self, dst: &mut BytesMut) -> Result<u16, ()> {
        let pos_head = dst.len();
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

        Ok((dst.len() - pos_head) as u16)
    }
}

impl From<&Attribute> for prost_types::Any {
    fn from(a: &Attribute) -> Self {
        let name = match ATTR_DESCS.get(&a.code) {
            Some(desc) => desc.url,
            None => "UnknownAttribute",
        };
        match a.code {
            Attribute::ORIGIN => proto::to_any(
                api::OriginAttribute {
                    origin: a.value().unwrap(),
                },
                name,
            ),
            Attribute::AS_PATH => {
                let mut c = Cursor::new(a.binary().unwrap());
                let mut segments = Vec::new();
                while c.position() < c.get_ref().len() as u64 {
                    let code = c.read_u8().unwrap();
                    let mut num = Vec::new();
                    for _ in 0..c.read_u8().unwrap() {
                        num.push(c.read_u32::<NetworkEndian>().unwrap());
                    }
                    segments.push(api::AsSegment {
                        r#type: code as i32,
                        numbers: num,
                    });
                }
                proto::to_any(api::AsPathAttribute { segments }, name)
            }
            Attribute::NEXTHOP => {
                let buf = a.binary().unwrap();
                let buflen = buf.len();
                let mut c = Cursor::new(buf);
                let next_hop = if buflen == 16 {
                    Ipv6Addr::from(c.read_u128::<NetworkEndian>().unwrap()).to_string()
                } else {
                    Ipv4Addr::from(c.read_u32::<NetworkEndian>().unwrap()).to_string()
                };
                proto::to_any(api::NextHopAttribute { next_hop }, name)
            }
            Attribute::MULTI_EXIT_DESC => proto::to_any(
                api::MultiExitDiscAttribute {
                    med: a.value().unwrap(),
                },
                name,
            ),
            Attribute::LOCAL_PREF => proto::to_any(
                api::LocalPrefAttribute {
                    local_pref: a.value().unwrap(),
                },
                name,
            ),
            Attribute::ATOMIC_AGGREGATE => proto::to_any(api::AtomicAggregateAttribute {}, name),
            Attribute::AGGREGATOR => {
                let mut c = Cursor::new(a.binary().unwrap());
                let (asn, addr) = match c.get_ref().len() {
                    6 => (
                        c.read_u16::<NetworkEndian>().unwrap() as u32,
                        Ipv4Addr::from(c.read_u32::<NetworkEndian>().unwrap()),
                    ),
                    8 => (
                        c.read_u32::<NetworkEndian>().unwrap() as u32,
                        Ipv4Addr::from(c.read_u32::<NetworkEndian>().unwrap()),
                    ),
                    _ => unreachable!("corrupted"),
                };
                proto::to_any(
                    api::AggregatorAttribute {
                        asn,
                        address: addr.to_string(),
                    },
                    name,
                )
            }
            Attribute::COMMUNITY => {
                let buf = a.binary().unwrap();
                let count = buf.len() / 4;
                let mut c = Cursor::new(buf);
                let mut values = Vec::with_capacity(count);
                for _ in 0..count {
                    values.push(c.read_u32::<NetworkEndian>().unwrap());
                }
                proto::to_any(
                    api::CommunitiesAttribute {
                        communities: values,
                    },
                    name,
                )
            }
            Attribute::ORIGINATOR_ID => proto::to_any(
                api::OriginatorIdAttribute {
                    id: Ipv4Addr::from(a.value().unwrap()).to_string(),
                },
                name,
            ),
            Attribute::CLUSTER_LIST => {
                let mut c = Cursor::new(a.binary().unwrap());
                let mut ids = Vec::new();
                for _ in 0..c.get_ref().len() / 4 {
                    ids.push(Ipv4Addr::from(c.read_u32::<NetworkEndian>().unwrap()).to_string());
                }
                proto::to_any(api::ClusterListAttribute { ids }, name)
            }
            Attribute::LARGE_COMMUNITY => {
                let mut c = Cursor::new(a.binary().unwrap());
                let mut v = Vec::new();
                for _ in 0..c.get_ref().len() / 12 {
                    let global_admin = c.read_u32::<NetworkEndian>().unwrap();
                    let local_data1 = c.read_u32::<NetworkEndian>().unwrap();
                    let local_data2 = c.read_u32::<NetworkEndian>().unwrap();
                    v.push(api::LargeCommunity {
                        global_admin,
                        local_data1,
                        local_data2,
                    });
                }
                proto::to_any(api::LargeCommunitiesAttribute { communities: v }, name)
            }
            _ => proto::to_any(
                api::UnknownAttribute {
                    flags: a.flags as u32,
                    r#type: a.code as u32,
                    value: a.binary().unwrap().to_owned(),
                },
                name,
            ),
        }
    }
}

impl TryFrom<prost_types::Any> for Attribute {
    type Error = Error;

    fn try_from(a: prost_types::Any) -> Result<Self, Self::Error> {
        if a.type_url == proto::type_url("OriginAttribute") {
            let a = api::OriginAttribute::decode(&*a.value)
                .map_err(|e| Error::InvalidArgument(e.to_string()))?;
            Ok(Attribute::new_with_value(Attribute::ORIGIN, a.origin).unwrap())
        } else if a.type_url == proto::type_url("AsPathAttribute") {
            let a = api::AsPathAttribute::decode(&*a.value)
                .map_err(|e| Error::InvalidArgument(e.to_string()))?;
            let mut c = Cursor::new(Vec::new());
            for s in a.segments {
                let _ = c.write_u8(s.r#type as u8);
                let _ = c.write_u8(s.numbers.len() as u8);
                for n in s.numbers {
                    let _ = c.write_u32::<NetworkEndian>(n);
                }
            }
            Ok(Attribute::new_with_bin(Attribute::AS_PATH, c.into_inner()).unwrap())
        } else if a.type_url == proto::type_url("NextHopAttribute") {
            let a = api::NextHopAttribute::decode(&*a.value)
                .map_err(|e| Error::InvalidArgument(e.to_string()))?;
            let addr =
                IpAddr::from_str(&a.next_hop).map_err(|e| Error::InvalidArgument(e.to_string()))?;
            let bin = match addr {
                IpAddr::V4(addr) => addr.octets().to_vec(),
                IpAddr::V6(addr) => addr.octets().to_vec(),
            };
            Ok(Attribute::new_with_bin(Attribute::NEXTHOP, bin).unwrap())
        } else if a.type_url == proto::type_url("MultiExitDiscAttribute") {
            let a = api::MultiExitDiscAttribute::decode(&*a.value)
                .map_err(|e| Error::InvalidArgument(e.to_string()))?;
            Ok(Attribute::new_with_value(Attribute::MULTI_EXIT_DESC, a.med).unwrap())
        } else if a.type_url == proto::type_url("LocalPrefAttribute") {
            let a = api::LocalPrefAttribute::decode(&*a.value)
                .map_err(|e| Error::InvalidArgument(e.to_string()))?;
            Ok(Attribute::new_with_value(Attribute::LOCAL_PREF, a.local_pref).unwrap())
        } else if a.type_url == proto::type_url("AtomicAggregateAttribute") {
            Ok(Attribute::new_with_bin(Attribute::ATOMIC_AGGREGATE, Vec::new()).unwrap())
        } else if a.type_url == proto::type_url("AggregatorAttribute") {
            let a = api::AggregatorAttribute::decode(&*a.value)
                .map_err(|e| Error::InvalidArgument(e.to_string()))?;
            let mut c = Cursor::new(Vec::new());
            let addr = Ipv4Addr::from_str(&a.address)
                .map_err(|e| Error::InvalidArgument(e.to_string()))?;
            let _ = c.write_u32::<NetworkEndian>(a.asn);
            let _ = c.write_u32::<NetworkEndian>(addr.into());
            Ok(Attribute::new_with_bin(Attribute::AGGREGATOR, c.into_inner()).unwrap())
        } else if a.type_url == proto::type_url("CommunitiesAttribute") {
            let a = api::CommunitiesAttribute::decode(&*a.value)
                .map_err(|e| Error::InvalidArgument(e.to_string()))?;
            let mut c = Cursor::new(Vec::new());
            for v in a.communities {
                let _ = c.write_u32::<NetworkEndian>(v);
            }
            Ok(Attribute::new_with_bin(Attribute::COMMUNITY, c.into_inner()).unwrap())
        } else if a.type_url == proto::type_url("OriginatorIdAttribute") {
            let a = api::OriginatorIdAttribute::decode(&*a.value)
                .map_err(|e| Error::InvalidArgument(e.to_string()))?;
            let mut c = Cursor::new(Vec::new());
            let addr =
                Ipv4Addr::from_str(&a.id).map_err(|e| Error::InvalidArgument(e.to_string()))?;
            let _ = c.write_u32::<NetworkEndian>(addr.into());
            Ok(Attribute::new_with_bin(Attribute::ORIGINATOR_ID, c.into_inner()).unwrap())
        } else if a.type_url == proto::type_url("ClusterListAttribute") {
            let a = api::ClusterListAttribute::decode(&*a.value)
                .map_err(|e| Error::InvalidArgument(e.to_string()))?;
            let mut c = Cursor::new(Vec::new());
            for v in a.ids {
                let addr =
                    Ipv4Addr::from_str(&v).map_err(|e| Error::InvalidArgument(e.to_string()))?;
                let _ = c.write_u32::<NetworkEndian>(addr.into());
            }
            Ok(Attribute::new_with_bin(Attribute::CLUSTER_LIST, c.into_inner()).unwrap())
        } else if a.type_url == proto::type_url("LargeCommunitiesAttribute") {
            let a = api::LargeCommunitiesAttribute::decode(&*a.value)
                .map_err(|e| Error::InvalidArgument(e.to_string()))?;
            let mut c = Cursor::new(Vec::new());
            for v in a.communities {
                let _ = c.write_u32::<NetworkEndian>(v.global_admin);
                let _ = c.write_u32::<NetworkEndian>(v.local_data1);
                let _ = c.write_u32::<NetworkEndian>(v.local_data2);
            }
            Ok(Attribute::new_with_bin(Attribute::LARGE_COMMUNITY, c.into_inner()).unwrap())
        } else if a.type_url == proto::type_url("MpReachNLRIAttribute") {
            let a = api::MpReachNlriAttribute::decode(&*a.value)
                .map_err(|e| Error::InvalidArgument(e.to_string()))?;
            let mut v = Vec::new();
            // FIXME: only simple nexthop is supported
            if let Some(n) = a.next_hops.into_iter().next() {
                if let Ok(n) = n.parse::<Ipv4Addr>() {
                    v.append(&mut n.octets().to_vec());
                } else if let Ok(n) = n.parse::<Ipv6Addr>() {
                    v.append(&mut n.octets().to_vec());
                } else {
                    return Err(Error::InvalidArgument("invalid nexthop".to_string()));
                }
            }
            Ok(Attribute::new_with_bin(Attribute::MP_REACH, v).unwrap())
        } else {
            Err(Error::InvalidArgument(format!(
                "unknown type url {}",
                a.type_url
            )))
        }
    }
}

struct AttrDesc {
    code: u8,
    flags: u8,
    url: &'static str,
    decode: fn(s: &AttrDesc, c: &mut dyn io::Read, len: u16) -> Result<Attribute, ()>,
}

impl AttrDesc {
    fn decode_u32(&self, c: &mut dyn io::Read, len: u16) -> Result<Attribute, ()> {
        if len != 4 {
            return Err(());
        }
        Ok(Attribute {
            code: self.code,
            flags: self.flags,
            data: AttributeData::Val(c.read_u32::<NetworkEndian>().unwrap() as u32),
        })
    }

    fn decode_binary(&self, c: &mut dyn io::Read, len: u16) -> Result<Attribute, ()> {
        let mut b = Vec::with_capacity(len.into());
        for _i in 0..len {
            let v = c.read_u8().unwrap();
            b.push(v);
        }
        Ok(Attribute {
            code: self.code,
            flags: self.flags,
            data: AttributeData::Bin(b),
        })
    }
}

static ATTR_DESCS: Lazy<FnvHashMap<u8, AttrDesc>> = Lazy::new(|| {
    vec![
        AttrDesc {
            code: Attribute::ORIGIN,
            flags: Attribute::FLAG_TRANSITIVE,
            url: "OriginAttribute",
            decode: (|s, c, len| {
                if len != 1 {
                    return Err(());
                }
                Ok(Attribute {
                    code: s.code,
                    flags: s.flags,
                    data: AttributeData::Val(c.read_u8().unwrap() as u32),
                })
            }),
        },
        AttrDesc {
            code: Attribute::AS_PATH,
            flags: Attribute::FLAG_TRANSITIVE,
            url: "AsPathAttribute",
            decode: AttrDesc::decode_binary,
        },
        AttrDesc {
            code: Attribute::NEXTHOP,
            flags: Attribute::FLAG_TRANSITIVE,
            url: "NextHopAttribute",
            decode: AttrDesc::decode_binary,
        },
        AttrDesc {
            code: Attribute::MULTI_EXIT_DESC,
            flags: Attribute::FLAG_OPTIONAL,
            url: "MultiExitDiscAttribute",
            decode: AttrDesc::decode_u32,
        },
        AttrDesc {
            code: Attribute::LOCAL_PREF,
            flags: Attribute::FLAG_TRANSITIVE,
            url: "LocalPrefAttribute",
            decode: AttrDesc::decode_u32,
        },
        AttrDesc {
            code: Attribute::ATOMIC_AGGREGATE,
            flags: Attribute::FLAG_TRANSITIVE,
            url: "AtomicAggregateAttribute",
            decode: AttrDesc::decode_binary,
        },
        AttrDesc {
            code: Attribute::AGGREGATOR,
            flags: Attribute::FLAG_TRANSITIVE | Attribute::FLAG_OPTIONAL,
            url: "AggregatorAttribute",
            decode: AttrDesc::decode_binary,
        },
        AttrDesc {
            code: Attribute::COMMUNITY,
            flags: Attribute::FLAG_TRANSITIVE | Attribute::FLAG_OPTIONAL,
            url: "CommunitiesAttribute",
            decode: AttrDesc::decode_binary,
        },
        AttrDesc {
            code: Attribute::ORIGINATOR_ID,
            flags: Attribute::FLAG_OPTIONAL,
            url: "OriginatorIdAttribute",
            decode: AttrDesc::decode_u32,
        },
        AttrDesc {
            code: Attribute::CLUSTER_LIST,
            flags: Attribute::FLAG_OPTIONAL,
            url: "OriginatorIdAttribute",
            decode: AttrDesc::decode_binary,
        },
        AttrDesc {
            code: Attribute::MP_REACH,
            flags: Attribute::FLAG_OPTIONAL,
            url: "",
            decode: AttrDesc::decode_binary,
        },
        AttrDesc {
            code: Attribute::MP_UNREACH,
            flags: Attribute::FLAG_OPTIONAL,
            url: "",
            decode: AttrDesc::decode_binary,
        },
        AttrDesc {
            code: Attribute::EXTENDED_COMMUNITY,
            flags: Attribute::FLAG_TRANSITIVE | Attribute::FLAG_OPTIONAL,
            url: "ExtendedCommunitiesAttribute",
            decode: AttrDesc::decode_binary,
        },
        AttrDesc {
            code: Attribute::AS4_PATH,
            flags: Attribute::FLAG_TRANSITIVE | Attribute::FLAG_OPTIONAL,
            url: "",
            decode: AttrDesc::decode_binary,
        },
        AttrDesc {
            code: Attribute::AS4_AGGREGATOR,
            flags: Attribute::FLAG_TRANSITIVE | Attribute::FLAG_OPTIONAL,
            url: "",
            decode: AttrDesc::decode_binary,
        },
        AttrDesc {
            code: Attribute::AIGP,
            flags: Attribute::FLAG_TRANSITIVE | Attribute::FLAG_OPTIONAL,
            url: "AigpAttribute",
            decode: AttrDesc::decode_binary,
        },
        AttrDesc {
            code: Attribute::LARGE_COMMUNITY,
            flags: Attribute::FLAG_TRANSITIVE | Attribute::FLAG_OPTIONAL,
            url: "LargeCommunitiesAttribute",
            decode: AttrDesc::decode_binary,
        },
    ]
    .into_iter()
    .map(|x| (x.code, x))
    .collect()
});

#[derive(Clone)]
pub(crate) enum Message {
    Open {
        version: u8,
        as_number: u32,
        holdtime: u16,
        router_id: Ipv4Addr,
        capability: Vec<Capability>,
    },
    Update {
        reach: Option<(Family, Vec<(Net, u32)>)>,
        unreach: Option<(Family, Vec<(Net, u32)>)>,
        attr: Arc<Vec<Attribute>>,
    },
    Notification {
        code: u8,
        subcode: u8,
        data: Vec<u8>,
    },
    Keepalive,
    RouteRefresh {
        family: Family,
    },
}

impl Message {
    const HEADER_LENGTH: u16 = 19;

    const MAX_LENGTH: usize = 4096;
    const MAX_EXTENDED_LENGTH: usize = 65535;

    const OPEN: u8 = 1;
    const UPDATE: u8 = 2;
    const NOTIFICATION: u8 = 3;
    const KEEPALIVE: u8 = 4;
    const ROUTE_REFRESH: u8 = 5;

    pub(crate) fn eor(family: Family) -> Message {
        if family == Family::IPV4 {
            Message::Update {
                reach: Some((Family::IPV4, Vec::new())),
                attr: Arc::new(Vec::new()),
                unreach: None,
            }
        } else {
            Message::Update {
                reach: None,
                attr: Arc::new(Vec::new()),
                unreach: Some((family, Vec::new())),
            }
        }
    }
}

pub(crate) struct Channel {
    family: Family,
    addpath: u8,
    extended_nexthop: bool,
}

impl Channel {
    pub(crate) fn addpath_rx(&self) -> bool {
        self.addpath & 0x1 > 0
    }

    pub(crate) fn addpath_tx(&self) -> bool {
        self.addpath & 0x2 > 0
    }

    pub(crate) fn new(family: Family, rx: bool, tx: bool) -> Self {
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

pub(crate) fn create_channel(
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
        h
    };
    let mut l = f(local);
    f(remote).into_iter().filter_map(move |(f, rc)| {
        l.remove(&f).map(|lc| {
            (
                f,
                Channel {
                    family: f,
                    addpath: u8::from(lc.addpath & 0x1 > 0 && rc.addpath & 0x2 > 0),
                    extended_nexthop: lc.extended_nexthop & rc.extended_nexthop,
                },
            )
        })
    })
}

pub(crate) struct CodecBuilder {
    local_asn: u32,
    remote_asn: u32,
    local_addr: IpAddr,
    extended_length: bool,
    keep_aspath: bool,
    keep_nexthop: bool,
    family: Vec<Family>,
}

impl CodecBuilder {
    pub(crate) fn new() -> Self {
        CodecBuilder {
            local_asn: 0,
            remote_asn: 0,
            local_addr: IpAddr::V4(Ipv4Addr::from(0)),
            extended_length: false,
            keep_aspath: false,
            keep_nexthop: false,
            family: Vec::new(),
        }
    }

    pub(crate) fn build(&mut self) -> Codec {
        let channel = self
            .family
            .iter()
            .map(|f| (*f, Channel::new(*f, false, false)))
            .collect();
        Codec {
            local_asn: self.local_asn,
            remote_asn: self.remote_asn,
            local_addr: self.local_addr,
            extended_length: self.extended_length,
            keep_aspath: self.keep_aspath,
            keep_nexthop: self.keep_nexthop,
            channel,
        }
    }

    pub(crate) fn local_asn(&mut self, asn: u32) -> &mut Self {
        self.local_asn = asn;
        self
    }

    pub(crate) fn local_addr(&mut self, local_addr: IpAddr) -> &mut Self {
        self.local_addr = local_addr;
        self
    }

    pub(crate) fn keep_aspath(&mut self, y: bool) -> &mut Self {
        self.keep_aspath = y;
        self
    }

    pub(crate) fn keep_nexthop(&mut self, y: bool) -> &mut Self {
        self.keep_nexthop = y;
        self
    }

    #[cfg(test)]
    fn families(&mut self, v: Vec<Family>) -> &mut Self {
        self.family = v;
        self
    }
}

pub(crate) struct Codec {
    extended_length: bool,
    local_asn: u32,
    remote_asn: u32,
    local_addr: IpAddr,
    keep_aspath: bool,
    keep_nexthop: bool,
    pub(crate) channel: FnvHashMap<Family, Channel>,
}

impl Codec {
    fn max_message_length(&self) -> usize {
        if self.extended_length {
            Message::MAX_EXTENDED_LENGTH
        } else {
            Message::MAX_LENGTH
        }
    }

    fn is_ibgp(&self) -> bool {
        self.local_asn == self.remote_asn
    }

    fn mp_reach_encode(
        &self,
        buf_head: usize,
        attrs: Arc<Vec<Attribute>>,
        dst: &mut BytesMut,
        reach: &(Family, Vec<(Net, u32)>),
        reach_idx: &mut usize,
    ) -> Result<u16, ()> {
        let (family, nets) = reach;
        let desc = ATTR_DESCS.get(&Attribute::MP_REACH).unwrap();
        let pos_head = dst.len();
        // always use extended length
        dst.put_u8(desc.flags | Attribute::FLAG_EXTENDED);
        dst.put_u8(desc.code);
        let pos_bin = dst.len();
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
        let addpath = self.channel.get(family).map_or(false, |c| c.addpath_tx());
        let max_len = 1 + 16 + if addpath { 4 } else { 0 };
        for (i, item) in nets.iter().enumerate().skip(*reach_idx) {
            let (net, id) = item;
            if buf_head + self.max_message_length() > dst.len() + max_len {
                if addpath {
                    dst.put_u32(*id);
                }
                net.encode(dst).unwrap();
                *reach_idx = i;
            } else {
                break;
            }
        }
        let mp_len = (dst.len() - pos_head) as u16;
        (&mut dst.as_mut()[pos_bin..])
            .write_u16::<NetworkEndian>(mp_len - 4)
            .unwrap();

        Ok(mp_len as u16)
    }

    fn mp_unreach_encode(
        &self,
        buf_head: usize,
        _: Arc<Vec<Attribute>>,
        dst: &mut BytesMut,
        unreach: &(Family, Vec<(Net, u32)>),
        unreach_idx: &mut usize,
    ) -> Result<u16, ()> {
        let (family, nets) = unreach;
        let desc = ATTR_DESCS.get(&Attribute::MP_UNREACH).unwrap();
        let pos_head = dst.len();
        // always use extended length
        dst.put_u8(desc.flags | Attribute::FLAG_EXTENDED);
        dst.put_u8(desc.code);
        let pos_bin = dst.len();
        dst.put_u16(0);
        dst.put_u16(family.afi());
        dst.put_u8(family.safi());
        let addpath = self.channel.get(family).map_or(false, |c| c.addpath_tx());
        let max_len = 1 + 16 + if addpath { 4 } else { 0 };
        for (i, item) in nets.iter().enumerate().skip(*unreach_idx) {
            let (net, id) = item;
            if buf_head + self.max_message_length() > dst.len() + max_len {
                if addpath {
                    dst.put_u32(*id);
                }
                net.encode(dst).unwrap();
                *unreach_idx = i;
            } else {
                break;
            }
        }
        let mp_len = (dst.len() - pos_head) as u16;
        (&mut dst.as_mut()[pos_bin..])
            .write_u16::<NetworkEndian>(mp_len - 4)
            .unwrap();
        Ok(mp_len as u16)
    }

    fn do_encode(
        &mut self,
        item: &Message,
        dst: &mut BytesMut,
        reach_idx: &mut usize,
    ) -> Result<(), Error> {
        dst.reserve(dst.len() + self.max_message_length());
        let pos_head = dst.len();
        dst.put_u64(u64::MAX);
        dst.put_u64(u64::MAX);
        // updated later
        let pos_header_len = dst.len();
        dst.put_u16(Message::HEADER_LENGTH);

        match item {
            Message::Open {
                version,
                as_number,
                holdtime,
                router_id,
                capability,
            } => {
                let trans_asn = if *as_number > u16::MAX as u32 {
                    Capability::TRANS_ASN
                } else {
                    *as_number as u16
                };
                dst.put_u8(Message::OPEN);
                dst.put_u8(*version);
                dst.put_u16(trans_asn);
                dst.put_u16(*holdtime);
                dst.put_u32(u32::from(*router_id));
                let op_param_len_pos = dst.len();
                dst.put_u8(0);
                dst.put_u8(2); // capability parameter type
                let param_len_pos = dst.len();
                dst.put_u8(0);

                let mut cap_len = 0;
                for cap in capability {
                    cap_len += cap.encode(dst).unwrap();
                }

                (&mut dst.as_mut()[param_len_pos..])
                    .write_u8(cap_len as u8)
                    .unwrap();
                (&mut dst.as_mut()[op_param_len_pos..])
                    .write_u8(cap_len + 2_u8)
                    .unwrap();
            }
            Message::Update {
                reach,
                attr,
                unreach,
            } => {
                let attrs = attr.clone();
                let family = if let Some(reach) = reach {
                    reach.0
                } else {
                    unreach.as_ref().unwrap().0
                };
                let addpath = self.channel.get(&family).map_or(false, |c| c.addpath_tx());
                dst.put_u8(Message::UPDATE);
                let pos_withdrawn_len = dst.len();
                dst.put_u16(0);
                let mut withdrawn_len = 0;
                if family == Family::IPV4 {
                    if let Some(unreach) = unreach {
                        let max_len = 5 + if addpath { 4 } else { 0 };
                        for (i, item) in unreach.1.iter().enumerate().skip(*reach_idx) {
                            if pos_head + self.max_message_length() > dst.len() + max_len {
                                if addpath {
                                    dst.put_u32(item.1);
                                }
                                withdrawn_len += item.0.encode(dst).unwrap();
                                *reach_idx = i;
                            } else {
                                break;
                            }
                        }
                    }
                }
                if withdrawn_len != 0 {
                    (&mut dst.as_mut()[pos_withdrawn_len..])
                        .write_u16::<NetworkEndian>(withdrawn_len)
                        .unwrap();
                }
                let pos_attr_len = dst.len();
                dst.put_u16(0);
                // Like BIRD, for simplicity, MP_REACH/MP_UNREACH attribute isn't ordered.
                // BIRD encodes MP_REACH/MP_UNREACH first and then the rest.
                // RustyBGP encode MP_REACH/MP_UNREACH last.
                let mut attr_len = 0;
                for a in &*attrs {
                    if a.flags & Attribute::FLAG_TRANSITIVE > 0 {
                        let code = a.code();
                        let (n, _) = a.export(code, Some(dst), family, self);
                        attr_len += n;
                    }
                }
                if family != Family::IPV4 {
                    if let Some(reach) = reach {
                        attr_len += self
                            .mp_reach_encode(pos_head, attr.clone(), dst, reach, reach_idx)
                            .unwrap();
                    } else if let Some(unreach) = unreach {
                        attr_len += self
                            .mp_unreach_encode(pos_head, attr.clone(), dst, unreach, reach_idx)
                            .unwrap();
                    }
                }

                (&mut dst.as_mut()[pos_attr_len..])
                    .write_u16::<NetworkEndian>(attr_len)
                    .unwrap();

                if family == Family::IPV4 {
                    let max_len = 5 + if addpath { 4 } else { 0 };
                    for (i, item) in reach
                        .as_ref()
                        .map_or(&Vec::new(), |(_, reach)| reach)
                        .iter()
                        .enumerate()
                        .skip(*reach_idx)
                    {
                        if pos_head + self.max_message_length() > dst.len() + max_len {
                            if addpath {
                                dst.put_u32(item.1);
                            }
                            let _ = item.0.encode(dst);
                            *reach_idx = i;
                        } else {
                            break;
                        }
                    }
                }
            }
            Message::Notification {
                code,
                subcode,
                data,
            } => {
                dst.put_u8(Message::NOTIFICATION);
                dst.put_u8(*code);
                dst.put_u8(*subcode);
                dst.put_slice(data);
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

        let pos_end = dst.len();
        (&mut dst.as_mut()[pos_header_len..])
            .write_u16::<NetworkEndian>((pos_end - pos_head) as u16)?;

        Ok(())
    }

    fn decode_nlri<T: io::Read>(
        &self,
        chan: &Channel,
        c: &mut T,
        mut len: usize,
    ) -> Result<(Net, u32), Error> {
        let malformed = Error::InvalidMessageFormat {
            code: 3,
            subcode: 1,
            data: vec![],
        };
        let id = if chan.addpath_rx() {
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
                Ok(net) => Ok((Net::V4(net), id)),
                Err(err) => Err(err),
            },
            Family::IPV6 => match Ipv6Net::decode(c, len) {
                Ok(net) => Ok((Net::V6(net), id)),
                Err(err) => Err(err),
            },
            _ => Err(malformed),
        }
    }
}

impl Encoder<&Message> for Codec {
    type Error = Error;

    fn encode(&mut self, item: &Message, dst: &mut BytesMut) -> Result<(), Error> {
        let mut done_idx = 0;
        match item {
            Message::Update { reach, unreach, .. } => {
                assert!(!(reach.is_some() && unreach.is_some()));
                let n = std::cmp::max(
                    reach.as_ref().map_or(0, |(_, x)| x.len()),
                    unreach.as_ref().map_or(0, |(_, x)| x.len()),
                );
                loop {
                    self.do_encode(item, dst, &mut done_idx)?;
                    done_idx += 1;
                    if n == 0 || done_idx == n {
                        break;
                    }
                }
                Ok(())
            }
            _ => self.do_encode(item, dst, &mut done_idx),
        }
    }
}

impl Decoder for Codec {
    type Item = Message;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let buffer_len = src.len();
        if buffer_len < Message::HEADER_LENGTH as usize {
            return Ok(None);
        }
        let message_len = (&src[16..18]).read_u16::<NetworkEndian>().unwrap() as usize;
        if (message_len < Message::HEADER_LENGTH as usize)
            || (message_len > self.max_message_length())
        {
            return Err(Error::InvalidMessageFormat {
                code: 1,
                subcode: 2,
                data: (src[16..18]).to_vec(),
            });
        }

        if buffer_len < message_len {
            return Ok(None);
        }
        let code = src[18];
        let buf = src.split_to(message_len).freeze();
        let header_len_error = Error::InvalidMessageFormat {
            code: 1,
            subcode: 2,
            data: (buf[16..18]).to_vec(),
        };

        match code {
            Message::OPEN => {
                const MINIMUM_OPEN_LENGTH: usize = 29;
                let malformed = Error::InvalidMessageFormat {
                    code: 2,
                    subcode: 0,
                    data: vec![],
                };
                if buf.len() < MINIMUM_OPEN_LENGTH {
                    return Err(header_len_error);
                }
                let mut c = Cursor::new(&buf);
                c.set_position(Message::HEADER_LENGTH.into());
                let version = c.read_u8().unwrap();
                let mut as_number = c.read_u16::<NetworkEndian>().unwrap() as u32;
                let holdtime = c.read_u16::<NetworkEndian>().unwrap();
                let router_id: Ipv4Addr = From::from(c.read_u32::<NetworkEndian>().unwrap());
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
                            match CAP_DESCS.get(&cap_type) {
                                Some(desc) => {
                                    let decode = desc.decode;
                                    match decode(self, &mut c, cap_len) {
                                        Ok(c) => cap.push(c),
                                        Err(_) => {
                                            return Err(malformed);
                                        }
                                    }
                                }
                                None => {
                                    let mut bin = Vec::with_capacity(cap_len as usize);
                                    for _ in 0..cap_len {
                                        bin.push(c.read_u8().unwrap());
                                    }
                                    cap.push(Capability::Unknown {
                                        code: cap_type,
                                        bin,
                                    });
                                }
                            }
                        }
                    } else {
                        return Err(Error::InvalidMessageFormat {
                            code: 2,
                            subcode: 4,
                            data: buf[c.position() as usize - 2
                                ..c.position() as usize + op_len as usize]
                                .to_vec(),
                        });
                    }
                }
                if as_number == Capability::TRANS_ASN as u32 {
                    as_number = self.remote_asn;
                } else {
                    self.remote_asn = as_number;
                }

                Ok(Some(Message::Open {
                    version,
                    as_number,
                    holdtime,
                    router_id,
                    capability: cap,
                }))
            }
            Message::UPDATE => {
                const MINIMUM_UPDATE_LENGTH: usize = 23;
                let malformed = || Error::InvalidMessageFormat {
                    code: 3,
                    subcode: 1,
                    data: vec![],
                };
                let mut reach_family = Family::IPV4;
                let mut unreach_family = Family::IPV4;
                let mut attr = Vec::new();
                let mut reach = Vec::new();
                let mut unreach = Vec::new();
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
                    match ATTR_DESCS.get(&code) {
                        Some(desc) => {
                            if (flags ^ desc.flags)
                                & (Attribute::FLAG_TRANSITIVE | Attribute::FLAG_OPTIONAL)
                                > 0
                            {
                                // FIXME: handle aigp case
                                c.set_position(c.position() + alen as u64);
                                error_withdraw = true;
                                continue;
                            } else {
                                let cur = c.position();
                                let f = desc.decode;
                                match f(desc, &mut c, alen) {
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
                                c.set_position(c.position() + alen as u64);
                            } else {
                                c.set_position(c.position() + alen as u64);
                            }
                        }
                    }
                }

                // should we handle this case?
                if reach_len > 0 && mp_reach_attr.is_some()
                    || withdrawn_len > 0 && mp_unreach_attr.is_some()
                {
                    return Err(malformed());
                }

                // v4 eor
                if reach_len == 0 && attr_len == 0 && withdrawn_len == 0 {
                    return Ok(Some(Message::Update {
                        reach: Some((Family::IPV4, Vec::new())),
                        unreach: None,
                        attr: Arc::new(Vec::new()),
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
                    let err = Error::InvalidMessageFormat {
                        code: 3,
                        subcode: 9,
                        data: vec![],
                    };
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
                    reach_family = Family((afi as u32) << 16 | safi as u32);
                    let chan = self.channel.get(&reach_family).ok_or_else(malformed)?;
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
                                flags: ATTR_DESCS.get(&Attribute::NEXTHOP).unwrap().flags,
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
                            Ok(net) => reach.push(net),
                            Err(err) => return Err(err),
                        }
                    }
                }

                if let Some(a) = mp_unreach_attr {
                    let err = Error::InvalidMessageFormat {
                        code: 3,
                        subcode: 9,
                        data: vec![],
                    };
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
                    unreach_family = Family((afi as u32) << 16 | safi as u32);
                    let chan = self.channel.get(&unreach_family).ok_or_else(malformed)?;
                    while c.position() < buf.len() as u64 {
                        let rest = buf.len() - c.position() as usize;
                        match self.decode_nlri(chan, &mut c, rest) {
                            Ok(net) => unreach.push(net),
                            Err(err) => return Err(err),
                        }
                    }
                }

                Ok(Some(Message::Update {
                    reach: if reach.is_empty() {
                        None
                    } else {
                        Some((reach_family, reach))
                    },
                    attr: Arc::new(attr),
                    unreach: if unreach.is_empty() {
                        None
                    } else {
                        Some((unreach_family, unreach))
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

                Ok(Some(Message::Notification {
                    code,
                    subcode,
                    data: buf[c.position() as usize..].to_vec(),
                }))
            }
            Message::KEEPALIVE => Ok(Some(Message::Keepalive)),
            Message::ROUTE_REFRESH => {
                const ROUTE_REFRESH_LENGTH: usize = Message::HEADER_LENGTH as usize + 4;
                if buf.len() < ROUTE_REFRESH_LENGTH {
                    return Err(header_len_error);
                }
                if ROUTE_REFRESH_LENGTH < buf.len() {
                    return Err(Error::InvalidMessageFormat {
                        code: 7,
                        subcode: 1,
                        data: buf.to_vec(),
                    });
                }
                let mut c = Cursor::new(&buf);
                c.set_position(Message::HEADER_LENGTH.into());
                Ok(Some(Message::RouteRefresh {
                    family: Family(c.read_u32::<NetworkEndian>().unwrap()),
                }))
            }
            _ => Err(Error::InvalidMessageFormat {
                code: 1,
                subcode: 3,
                data: vec![code],
            }),
        }
    }
}

#[test]
fn ipv6_eor() {
    let mut buf = [0xff; 16].to_vec();
    let mut body: Vec<u8> = vec![
        0x00, 0x1e, 0x02, 0x00, 0x00, 0x00, 0x07, 0x90, 0x0f, 0x00, 0x03, 0x00, 0x02, 0x01,
    ];
    buf.append(&mut body);
    let mut b = BytesMut::from(&buf[..]);
    let mut codec = CodecBuilder::new().families(vec![Family::IPV6]).build();
    let ret = codec.decode(&mut b);
    assert!(ret.is_ok());
}

#[test]
fn parse_ipv6_update() {
    use std::io::Read;
    let path = std::env::current_dir().unwrap();
    let filename = path.to_str().unwrap().to_owned() + "/tests/packet/ipv6-update.raw";
    let mut file = std::fs::File::open(filename).unwrap();
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).unwrap();
    let nlri: Vec<(Net, u32)> = vec![
        Net::V6(Ipv6Net {
            addr: Ipv6Addr::new(0x2003, 0xde, 0x2016, 0x127, 0, 0, 0, 0),
            mask: 64,
        }),
        Net::V6(Ipv6Net {
            addr: Ipv6Addr::new(0x2003, 0xde, 0x2016, 0x124, 0, 0, 0, 0),
            mask: 64,
        }),
        Net::V6(Ipv6Net {
            addr: Ipv6Addr::new(0x2003, 0xde, 0x2016, 0x128, 0, 0, 0, 0),
            mask: 63,
        }),
        Net::V6(Ipv6Net {
            addr: Ipv6Addr::new(0x2003, 0xde, 0x2016, 0x1ff, 0, 0, 0, 0x12),
            mask: 127,
        }),
    ]
    .into_iter()
    .map(|n| (n, 0))
    .collect();
    let mut b = BytesMut::from(&buf[..]);
    let mut codec = CodecBuilder::new().families(vec![Family::IPV6]).build();
    let msg = codec.decode(&mut b).unwrap();
    match msg.unwrap() {
        Message::Update {
            reach,
            attr: _,
            unreach: _,
        } => {
            let (family, reach) = reach.unwrap();
            assert_eq!(family, Family::IPV6);
            assert_eq!(nlri.len(), reach.len());

            for i in 0..reach.len() {
                assert_eq!(reach[i], nlri[i]);
            }
        }
        _ => assert!(false),
    }
}

#[test]
fn build_many_v4_route() {
    let mut net = Vec::new();
    for i in 0..2000u16 {
        net.push(Net::V4(Ipv4Net {
            addr: Ipv4Addr::new(10, ((0xff00 & i) >> 8) as u8, (0xff & i) as u8, 1),
            mask: 32,
        }));
    }

    let reach: Vec<(Net, u32)> = net.iter().cloned().map(|n| (n, 0)).collect();
    let mut msg = Message::Update {
        reach: Some((Family::IPV4, reach)),
        attr: Arc::new(vec![
            Attribute::new_with_value(Attribute::ORIGIN, 0).unwrap(),
            Attribute::new_with_bin(Attribute::AS_PATH, vec![2, 1, 1, 0, 0, 0]).unwrap(),
            Attribute::new_with_bin(Attribute::NEXTHOP, vec![0, 0, 0, 0]).unwrap(),
        ]),
        unreach: None,
    };
    let mut set = fnv::FnvHashSet::default();
    for n in &net {
        set.insert((*n, 0));
    }

    let mut codec = CodecBuilder::new()
        .families(vec![Family::IPV4])
        .keep_aspath(true)
        .build();
    let mut txbuf = bytes::BytesMut::with_capacity(4096);
    codec.encode(&msg, &mut txbuf).unwrap();
    let mut recv = Vec::new();
    loop {
        match codec.decode(&mut txbuf) {
            Ok(m) => match m {
                Some(m) => match m {
                    Message::Update { reach, .. } => {
                        recv.append(&mut reach.unwrap().1);
                    }
                    _ => {}
                },
                None => break,
            },
            Err(_) => panic!("failed to decode"),
        }
    }
    assert_eq!(recv.len(), net.len());

    for n in &recv {
        let b = set.remove(n);
        assert!(b);
    }
    assert_eq!(set.len(), 0);

    let unreach = net.iter().cloned().map(|n| (n, 0)).collect();
    msg = Message::Update {
        reach: None,
        attr: Arc::new(Vec::new()),
        unreach: Some((Family::IPV4, unreach)),
    };

    for n in &net {
        set.insert((*n, 0));
    }

    let mut withdrawn = Vec::new();
    codec.encode(&msg, &mut txbuf).unwrap();
    loop {
        match codec.decode(&mut txbuf) {
            Ok(m) => match m {
                Some(m) => match m {
                    Message::Update { unreach, .. } => {
                        withdrawn.append(&mut unreach.unwrap().1);
                    }
                    _ => {}
                },
                None => break,
            },
            Err(_) => panic!("failed to decode"),
        }
    }
    assert_eq!(withdrawn.len(), net.len());
    for n in &withdrawn {
        let b = set.remove(n);
        assert!(b);
    }
    assert_eq!(set.len(), 0);
}

#[test]
fn many_mp_reach() {
    let net: Vec<Net> = (0..2000u128)
        .map(|i| {
            Net::V6(Ipv6Net {
                addr: Ipv6Addr::from(i),
                mask: 128,
            })
        })
        .collect();

    let reach = net.iter().cloned().map(|n| (n, 0)).collect();
    let mut set = fnv::FnvHashSet::default();
    for n in &net {
        set.insert((*n, 0));
    }

    let msg = Message::Update {
        reach: Some((Family::IPV6, reach)),
        attr: Arc::new(vec![
            Attribute::new_with_value(Attribute::ORIGIN, 0).unwrap(),
            Attribute::new_with_bin(Attribute::AS_PATH, vec![2, 1, 1, 0, 0, 0]).unwrap(),
            Attribute::new_with_bin(Attribute::NEXTHOP, (0..31).collect::<Vec<u8>>()).unwrap(),
        ]),
        unreach: None,
    };

    let mut codec = CodecBuilder::new().families(vec![Family::IPV6]).build();
    let mut txbuf = bytes::BytesMut::with_capacity(4096);
    codec.encode(&msg, &mut txbuf).unwrap();
    let mut recv = Vec::new();
    loop {
        match codec.decode(&mut txbuf) {
            Ok(m) => match m {
                Some(m) => match m {
                    Message::Update { reach, .. } => {
                        recv.append(&mut reach.unwrap().1);
                    }
                    _ => {}
                },
                None => break,
            },
            Err(e) => panic!("failed to decode {}", e),
        }
    }
    assert_eq!(recv.len(), net.len());

    for n in &recv {
        let b = set.remove(n);
        assert!(b);
    }
    assert_eq!(set.len(), 0);
}

#[test]
fn many_mp_unreach() {
    let net: Vec<Net> = (0..2000u128)
        .map(|i| {
            Net::V6(Ipv6Net {
                addr: Ipv6Addr::from(i),
                mask: 128,
            })
        })
        .collect();

    let unreach = net.iter().cloned().map(|n| (n, 0)).collect();
    let mut set = fnv::FnvHashSet::default();
    for n in &net {
        set.insert((*n, 0));
    }

    let msg = Message::Update {
        reach: None,
        attr: Arc::new(Vec::new()),
        unreach: Some((Family::IPV6, unreach)),
    };

    let mut codec = CodecBuilder::new().families(vec![Family::IPV6]).build();
    let mut txbuf = bytes::BytesMut::with_capacity(4096);
    codec.encode(&msg, &mut txbuf).unwrap();
    let mut recv = Vec::new();
    loop {
        match codec.decode(&mut txbuf) {
            Ok(m) => match m {
                Some(m) => match m {
                    Message::Update { unreach, .. } => {
                        recv.append(&mut unreach.unwrap().1);
                    }
                    _ => {}
                },
                None => break,
            },
            Err(e) => panic!("failed to decode {}", e),
        }
    }
    assert_eq!(recv.len(), net.len());

    for n in &recv {
        let b = set.remove(n);
        assert!(b);
    }
    assert_eq!(set.len(), 0);
}
