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

use crate::error::Error;
use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use bytes::{BufMut, BytesMut};
use fnv::FnvHashMap;
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::convert::Into;
use std::io::Cursor;
use std::marker::PhantomData;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;
use std::{fmt, io};
use thiserror::Error;

/// Typed BGP NOTIFICATION content (RFC 4271 §4.5, RFC 6608 §3, RFC 7313 §5).
/// Represents the error code, subcode, and data of a BGP NOTIFICATION message.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Notification {
    // Code 1: Message Header Error
    #[error("header error: bad message length")]
    BadMessageLength { data: Vec<u8> },
    #[error("header error: bad message type")]
    BadMessageType { data: Vec<u8> },

    // Code 2: OPEN Message Error
    #[error("open error: malformed")]
    OpenMalformed,
    #[error("open error: unsupported optional parameter")]
    OpenUnsupportedOptionalParameter { data: Vec<u8> },
    #[error("open error: unacceptable hold time")]
    OpenUnacceptableHoldTime { data: Vec<u8> },

    // Code 3: UPDATE Message Error
    #[error("update error: malformed attribute list")]
    UpdateMalformedAttributeList,
    #[error("update error: optional attribute error")]
    UpdateOptionalAttributeError,

    // Code 5: FSM Error
    #[error("FSM error: unexpected state {state}")]
    FsmUnexpectedState { state: u8 },

    // Code 7: ROUTE-REFRESH Message Error
    #[error("route-refresh error: invalid message length")]
    RouteRefreshInvalidLength { data: Vec<u8> },

    // Catch-all for received NOTIFICATION messages
    #[error("notification code={code} subcode={subcode}")]
    Other {
        code: u8,
        subcode: u8,
        data: Vec<u8>,
    },
}

impl Notification {
    /// Returns the BGP NOTIFICATION error code.
    pub fn notification_code(&self) -> u8 {
        match self {
            Self::BadMessageLength { .. } | Self::BadMessageType { .. } => 1,
            Self::OpenMalformed
            | Self::OpenUnsupportedOptionalParameter { .. }
            | Self::OpenUnacceptableHoldTime { .. } => 2,
            Self::UpdateMalformedAttributeList | Self::UpdateOptionalAttributeError => 3,
            Self::FsmUnexpectedState { .. } => 5,
            Self::RouteRefreshInvalidLength { .. } => 7,
            Self::Other { code, .. } => *code,
        }
    }

    /// Returns the BGP NOTIFICATION subcode.
    pub fn notification_subcode(&self) -> u8 {
        match self {
            Self::BadMessageLength { .. } => 2,
            Self::BadMessageType { .. } => 3,
            Self::OpenMalformed => 0,
            Self::OpenUnsupportedOptionalParameter { .. } => 4,
            Self::OpenUnacceptableHoldTime { .. } => 6,
            Self::UpdateMalformedAttributeList => 1,
            Self::UpdateOptionalAttributeError => 9,
            Self::FsmUnexpectedState { state } => *state,
            Self::RouteRefreshInvalidLength { .. } => 1,
            Self::Other { subcode, .. } => *subcode,
        }
    }

    /// Returns the BGP NOTIFICATION data.
    pub fn notification_data(&self) -> &[u8] {
        match self {
            Self::BadMessageLength { data }
            | Self::BadMessageType { data }
            | Self::OpenUnsupportedOptionalParameter { data }
            | Self::OpenUnacceptableHoldTime { data }
            | Self::RouteRefreshInvalidLength { data }
            | Self::Other { data, .. } => data,
            _ => &[],
        }
    }

    /// Returns true if this is a CEASE Hard Reset (RFC 8538 §3: code 6, subcode 9).
    /// Hard Reset terminates GR even when the N-bit is negotiated.
    pub fn is_hard_reset(&self) -> bool {
        matches!(
            self,
            Self::Other {
                code: 6,
                subcode: 9,
                ..
            }
        )
    }

    /// Constructs a `Notification` from a received NOTIFICATION message.
    pub fn from_notification(code: u8, subcode: u8, data: Vec<u8>) -> Self {
        match (code, subcode) {
            (1, 2) => Self::BadMessageLength { data },
            (1, 3) => Self::BadMessageType { data },
            (2, 0) => Self::OpenMalformed,
            (2, 4) => Self::OpenUnsupportedOptionalParameter { data },
            (2, 6) => Self::OpenUnacceptableHoldTime { data },
            (3, 1) => Self::UpdateMalformedAttributeList,
            (3, 9) => Self::UpdateOptionalAttributeError,
            (5, state) => Self::FsmUnexpectedState { state },
            (7, 1) => Self::RouteRefreshInvalidLength { data },
            _ => Self::Other {
                code,
                subcode,
                data,
            },
        }
    }
}

trait ParseContext: 'static {
    fn truncated() -> Notification;
}

struct UpdateCtx;
impl ParseContext for UpdateCtx {
    fn truncated() -> Notification {
        Notification::UpdateMalformedAttributeList
    }
}

/// A cursor over a byte slice that returns `Notification` directly on truncation,
/// eliminating the need to map `io::Error` in the BGP parse path.
struct BgpReader<'a, C: ParseContext> {
    buf: &'a [u8],
    pos: usize,
    _marker: PhantomData<C>,
}

impl<'a, C: ParseContext> BgpReader<'a, C> {
    fn new(buf: &'a [u8]) -> Self {
        BgpReader {
            buf,
            pos: 0,
            _marker: PhantomData,
        }
    }

    fn read_u8(&mut self) -> Result<u8, Notification> {
        match self.buf.get(self.pos) {
            Some(&v) => {
                self.pos += 1;
                Ok(v)
            }
            None => Err(C::truncated()),
        }
    }

    fn read_u32_be(&mut self) -> Result<u32, Notification> {
        if self.pos + 4 > self.buf.len() {
            return Err(C::truncated());
        }
        let v = u32::from_be_bytes([
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    fn remaining_len(&self) -> usize {
        self.buf.len() - self.pos
    }
}

impl<'a, C: ParseContext> io::Read for BgpReader<'a, C> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let available = self.buf.len() - self.pos;
        let n = buf.len().min(available);
        buf[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        if n < buf.len() {
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "not enough bytes",
            ))
        } else {
            Ok(n)
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct Family(u32);

impl Family {
    pub const AFI_IP: u16 = 1;
    pub const AFI_IP6: u16 = 2;

    const SAFI_UNICAST: u8 = 1;
    const SAFI_MUP: u8 = 85;
    const SAFI_MPLS_VPN: u8 = 128;
    const SAFI_MPLS_VPN6: u8 = 129;

    pub const EMPTY: Family = Family(0);
    pub const IPV4: Family = Family((Family::AFI_IP as u32) << 16 | Family::SAFI_UNICAST as u32);
    pub const IPV6: Family = Family((Family::AFI_IP6 as u32) << 16 | Family::SAFI_UNICAST as u32);
    pub const IPV4_MUP: Family = Family((Family::AFI_IP as u32) << 16 | Family::SAFI_MUP as u32);
    pub const IPV6_MUP: Family = Family((Family::AFI_IP6 as u32) << 16 | Family::SAFI_MUP as u32);
    pub const IPV4_VPN: Family =
        Family((Family::AFI_IP as u32) << 16 | Family::SAFI_MPLS_VPN as u32);
    pub const IPV6_VPN: Family =
        Family((Family::AFI_IP6 as u32) << 16 | Family::SAFI_MPLS_VPN6 as u32);

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

#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub enum Nlri {
    V4(Ipv4Net),
    V6(Ipv6Net),
    Mup(crate::mup::MupNlri),
    VpnV4(crate::vpn::VpnV4Nlri),
    VpnV6(crate::vpn::VpnV6Nlri),
}

impl Nlri {
    fn encode<B: BufMut>(&self, dst: &mut B) -> Result<u16, ()> {
        match self {
            Nlri::V4(net) => net.encode(dst),
            Nlri::V6(net) => net.encode(dst),
            Nlri::Mup(m) => Ok(m.encode(dst)),
            Nlri::VpnV4(n) => Ok(n.encode(dst)),
            Nlri::VpnV6(n) => Ok(n.encode(dst)),
        }
    }

    /// Encode this NLRI into its BGP wire format (prefix-length byte followed
    /// by the significant address bytes).
    pub fn encode_to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let _ = self.encode(&mut buf);
        buf
    }

    // Add a new match arm here when introducing a new SAFI.
    fn decode<C: ParseContext>(
        family: Family,
        c: &mut BgpReader<C>,
        len: usize,
    ) -> Result<Nlri, Notification> {
        match family {
            Family::IPV4 => Ipv4Net::decode(c, len).map(Nlri::V4),
            Family::IPV6 => Ipv6Net::decode(c, len).map(Nlri::V6),
            Family::IPV4_MUP | Family::IPV6_MUP => crate::mup::MupNlri::decode(family, c, len)
                .map(Nlri::Mup)
                .map_err(|_| Notification::UpdateMalformedAttributeList),
            Family::IPV4_VPN => crate::vpn::VpnV4Nlri::decode(c, len)
                .map(Nlri::VpnV4)
                .map_err(|_| Notification::UpdateMalformedAttributeList),
            Family::IPV6_VPN => crate::vpn::VpnV6Nlri::decode(c, len)
                .map(Nlri::VpnV6)
                .map_err(|_| Notification::UpdateMalformedAttributeList),
            _ => Err(Notification::UpdateMalformedAttributeList),
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
            Nlri::Mup(m) => m.fmt(f),
            Nlri::VpnV4(n) => n.fmt(f),
            Nlri::VpnV6(n) => n.fmt(f),
        }
    }
}

/// An NLRI entry with an optional AddPath path identifier (RFC 7911).
/// `path_id` is 0 when AddPath is not negotiated for the address family.
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct PathNlri {
    pub path_id: u32,
    pub nlri: Nlri,
}

impl PathNlri {
    pub fn new(nlri: Nlri) -> Self {
        PathNlri { path_id: 0, nlri }
    }
}

/// Withdrawn (unreachable) NLRIs sharing a common address family (AFI+SAFI).
#[derive(Clone, Debug)]
pub struct UnreachNlri {
    pub family: Family,
    pub entries: Vec<PathNlri>,
}

impl UnreachNlri {
    pub fn new(family: Family) -> Self {
        UnreachNlri {
            family,
            entries: Vec::new(),
        }
    }
}

/// BGP nexthop address, parsed from NEXT_HOP attribute (type 3)
/// or MP_REACH_NLRI nexthop field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Nexthop {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
    /// IPv6 global + link-local (RFC 2545, 32-byte MP_REACH nexthop).
    V6LinkLocal(Ipv6Addr, Ipv6Addr),
}

impl Nexthop {
    /// Parse nexthop from raw bytes (4, 16, or 32 bytes).
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        match b.len() {
            4 => Some(Nexthop::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]))),
            16 => {
                let arr: [u8; 16] = b.try_into().ok()?;
                Some(Nexthop::V6(Ipv6Addr::from(arr)))
            }
            32 => {
                let global: [u8; 16] = b[..16].try_into().ok()?;
                let ll: [u8; 16] = b[16..32].try_into().ok()?;
                let ll_addr = Ipv6Addr::from(ll);
                if ll_addr.is_unspecified() {
                    Some(Nexthop::V6(Ipv6Addr::from(global)))
                } else {
                    Some(Nexthop::V6LinkLocal(Ipv6Addr::from(global), ll_addr))
                }
            }
            _ => None,
        }
    }

    /// Serialize to bytes for wire encoding.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Nexthop::V4(addr) => addr.octets().to_vec(),
            Nexthop::V6(addr) => addr.octets().to_vec(),
            Nexthop::V6LinkLocal(global, ll) => {
                let mut v = Vec::with_capacity(32);
                v.extend_from_slice(&global.octets());
                v.extend_from_slice(&ll.octets());
                v
            }
        }
    }

    /// Return the primary (global) IP address for forwarding decisions.
    pub fn addr(&self) -> IpAddr {
        match self {
            Nexthop::V4(a) => IpAddr::V4(*a),
            Nexthop::V6(a) | Nexthop::V6LinkLocal(a, _) => IpAddr::V6(*a),
        }
    }
}

impl fmt::Display for Nexthop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Nexthop::V4(a) => write!(f, "{}", a),
            Nexthop::V6(a) => write!(f, "{}", a),
            Nexthop::V6LinkLocal(g, ll) => write!(f, "{} (link-local {})", g, ll),
        }
    }
}

#[derive(PartialEq, Eq, Hash, Clone, Debug, Copy)]
pub struct Ipv4Net {
    pub addr: Ipv4Addr,
    pub mask: u8,
}

impl Ipv4Net {
    fn decode<C: ParseContext>(c: &mut BgpReader<C>, len: usize) -> Result<Ipv4Net, Notification> {
        let bit_len = c.read_u8()?;
        if len < (bit_len as usize).div_ceil(8) || bit_len > 32 {
            return Err(Notification::UpdateMalformedAttributeList);
        }
        let mut addr = [0_u8; 4];
        for i in 0..bit_len.div_ceil(8) {
            addr[i as usize] = c.read_u8()?;
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
    let mut c = BgpReader::<UpdateCtx>::new(&buf);
    assert!(Ipv4Net::decode(&mut c, len).is_err());
}

#[derive(PartialEq, Eq, Hash, Clone, Debug, Copy)]
pub struct Ipv6Net {
    pub addr: Ipv6Addr,
    pub mask: u8,
}

impl Ipv6Net {
    fn decode<C: ParseContext>(c: &mut BgpReader<C>, len: usize) -> Result<Ipv6Net, Notification> {
        let bit_len = c.read_u8()?;
        if len < (bit_len as usize).div_ceil(8) || bit_len > 128 {
            return Err(Notification::UpdateMalformedAttributeList);
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
    let mut c = BgpReader::<UpdateCtx>::new(&buf);
    assert!(Ipv6Net::decode(&mut c, len).is_err());
}

#[test]
fn nlri_decode_ipv4() {
    let buf = vec![24, 10, 0, 0];
    let len = buf.len();
    let mut c = BgpReader::<UpdateCtx>::new(&buf);
    assert_eq!(
        Nlri::decode(Family::IPV4, &mut c, len).unwrap(),
        Nlri::V4(Ipv4Net {
            addr: Ipv4Addr::new(10, 0, 0, 0),
            mask: 24,
        }),
    );
}

#[test]
fn nlri_decode_ipv6() {
    let buf = vec![32, 0x20, 0x01, 0x0d, 0xb8];
    let len = buf.len();
    let mut c = BgpReader::<UpdateCtx>::new(&buf);
    assert_eq!(
        Nlri::decode(Family::IPV6, &mut c, len).unwrap(),
        Nlri::V6(Ipv6Net {
            addr: Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0),
            mask: 32,
        }),
    );
}

#[test]
fn nlri_decode_unsupported_family() {
    let buf = vec![24, 10, 0, 0];
    let len = buf.len();
    let mut c = BgpReader::<UpdateCtx>::new(&buf);
    let mup_ipv4 = Family::new((Family::AFI_IP as u32) << 16 | 85);
    assert!(Nlri::decode(mup_ipv4, &mut c, len).is_err());
}

#[derive(Debug, Clone, PartialEq)]
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
                    if val == 0 || val > 3 {
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
                if len < 2 {
                    return Err(());
                }
                let hostlen = c.read_u8().map_err(|_| ())?;
                // Validate total length: 1 (hostlen) + hostlen + 1 (domainlen) + domainlen
                if hostlen as u64 + 2 > len as u64 {
                    return Err(());
                }
                let mut h = Vec::new();
                for _ in 0..hostlen {
                    h.push(c.read_u8().map_err(|_| ())?);
                }
                let host = String::from_utf8(h).unwrap_or_default();
                let domainlen = c.read_u8().map_err(|_| ())?;
                if 2u64 + hostlen as u64 + domainlen as u64 > len as u64 {
                    return Err(());
                }
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
    pub const PREFIX_SID: u8 = 40;

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
            Self::PREFIX_SID => Some(Self::FLAG_TRANSITIVE | Self::FLAG_OPTIONAL),
            _ => None,
        }
    }

    fn decode(code: u8, flags: u8, c: &mut dyn io::Read, len: u16) -> Result<Self, ()> {
        let data = match code {
            Self::ORIGIN => {
                if len != 1 {
                    return Err(());
                }
                AttributeData::Val(c.read_u8().map_err(|_| ())? as u32)
            }
            Self::MULTI_EXIT_DESC | Self::LOCAL_PREF | Self::ORIGINATOR_ID => {
                if len != 4 {
                    return Err(());
                }
                AttributeData::Val(c.read_u32::<NetworkEndian>().map_err(|_| ())?)
            }
            _ => {
                let mut b = Vec::with_capacity(len.into());
                for _ in 0..len {
                    b.push(c.read_u8().map_err(|_| ())?);
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

    pub fn as_path_count(&self, asn: u32) -> Result<usize, Error> {
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

    /// Prepend `as_number` to the AS_CONFED_SEQUENCE segment of this AS_PATH.
    ///
    /// Used when advertising to a Confed-eBGP peer (RFC 5065 §5.1): the local
    /// Member-AS is added to the front of the confederation path so that other
    /// members can detect loops.
    pub fn as_path_prepend_confed(&self, as_number: u32) -> Attribute {
        assert_eq!(self.code, Attribute::AS_PATH);
        let buf = self.binary().unwrap();
        let len = buf.len() as u64;

        let data = if len != 0 && buf[0] == Attribute::AS_PATH_TYPE_CONFED_SEQ && buf[1] < 255 {
            let mut new_buf = Vec::with_capacity(len as usize + 4);
            new_buf.put_u8(buf[0]);
            new_buf.put_u8(buf[1] + 1);
            new_buf.put_u32(as_number);
            new_buf.put(&buf[2..]);
            AttributeData::Bin(new_buf)
        } else if len == 0 {
            let mut new_buf = Vec::with_capacity(6);
            new_buf.put_u8(Attribute::AS_PATH_TYPE_CONFED_SEQ);
            new_buf.put_u8(1);
            new_buf.put_u32(as_number);
            AttributeData::Bin(new_buf)
        } else {
            let mut new_buf = Vec::with_capacity(len as usize + 6);
            new_buf.put_u8(Attribute::AS_PATH_TYPE_CONFED_SEQ);
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

    /// Remove all AS_CONFED_SEQUENCE and AS_CONFED_SET segments from this AS_PATH.
    ///
    /// Used when advertising to an external eBGP peer (RFC 5065 §5.1): confed
    /// segments are internal and must not leak outside the confederation.
    pub fn as_path_strip_confed(&self) -> Attribute {
        assert_eq!(self.code, Attribute::AS_PATH);
        let buf = self.binary().unwrap();
        let len = buf.len() as u64;
        let mut c = Cursor::new(buf);
        let mut new_buf: Vec<u8> = Vec::with_capacity(len as usize);

        while c.position() < len {
            let seg_type = c.read_u8().unwrap();
            let seg_len = c.read_u8().unwrap();
            let seg_bytes = seg_len as usize * 4;
            let start = c.position() as usize;
            c.set_position(c.position() + seg_bytes as u64);
            if seg_type != Attribute::AS_PATH_TYPE_CONFED_SEQ
                && seg_type != Attribute::AS_PATH_TYPE_CONFED_SET
            {
                new_buf.put_u8(seg_type);
                new_buf.put_u8(seg_len);
                new_buf.put(&buf[start..start + seg_bytes]);
            }
        }
        Attribute {
            code: self.code,
            flags: self.flags,
            data: AttributeData::Bin(new_buf),
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

    pub(crate) fn encode_wire<B: BufMut + AsMut<[u8]>>(&self, dst: &mut B) -> u16 {
        self.encode(dst).unwrap()
    }

    /// Encode this attribute into its BGP wire format.
    pub fn encode_to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let _ = self.encode(&mut buf);
        buf
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

/// BGP UPDATE message body (RFC 4271 §4.3, RFC 4760 §3) — send path.
///
/// `Routes.reach.family` determines encoding: `IPV4` -> traditional NLRI + NEXTHOP attribute
/// (unless RFC 8950 extended nexthop is negotiated); any other family -> MP_REACH_NLRI.
/// Same rule applies for `unreach`.
#[derive(Clone)]
pub enum Update {
    /// Route announcements and/or withdrawals.
    Routes {
        /// Reachable NLRIs with nexthop.
        reach: Option<ReachNlri>,
        /// Withdrawn NLRIs.
        unreach: Option<UnreachNlri>,
        attr: Arc<Vec<Attribute>>,
    },
    /// End-of-RIB marker for `family` (RFC 4724 §2).
    EndOfRib(Family),
}

/// A BGP message (unified send/receive type after validation).
#[derive(Clone)]
pub enum Message {
    Open(Open),
    Update(Update),
    Notification(Notification),
    Keepalive,
    RouteRefresh { family: Family },
}

/// A set of reachable NLRIs together with the nexthop used to reach them.
/// Used for both traditional IPv4 NLRI (nexthop from NEXTHOP attribute)
/// and MP_REACH_NLRI (nexthop embedded in the attribute).
#[derive(Clone, Debug)]
pub struct ReachNlri {
    pub family: Family,
    pub entries: Vec<PathNlri>,
    /// `None` only for AFIs that carry no nexthop (e.g. Flowspec, RFC 5575 §4).
    pub nexthop: Option<Nexthop>,
}

/// One attribute that could not be parsed (RFC 7606).
/// The caller uses `attr_flags` to determine the RFC 7606 action:
/// optional + transitive -> discard; otherwise -> treat-as-withdraw.
#[derive(Clone, Debug)]
pub struct AttributeError {
    pub attr_code: u8,
    pub attr_flags: u8,
}

/// A parsed BGP UPDATE message (receive path).
// Routes carries 6 Options/Vecs whose metadata is on the stack (209 bytes), while EndOfRib is 4
// bytes.  The Vec/UnreachNlri contents are already heap-allocated, so boxing Routes would only add
// one extra heap allocation per UPDATE without reducing heap pressure.
#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
pub enum ParsedUpdate {
    /// Route announcements and/or withdrawals with optional attribute errors.
    Routes {
        /// Traditional IPv4 NLRI with nexthop from NEXTHOP attribute (legacy encoding).
        reach: Option<ReachNlri>,
        /// MP_REACH_NLRI with embedded nexthop (non-IPv4 or RFC 8950 IPv4).
        mp_reach: Option<ReachNlri>,
        /// Traditional IPv4 Withdrawn Routes (legacy encoding).
        unreach: Option<UnreachNlri>,
        /// MP_UNREACH_NLRI (non-IPv4 or RFC 8950 IPv4).
        mp_unreach: Option<UnreachNlri>,
        attrs: Vec<Attribute>,
        /// Attributes that failed to parse; see RFC 7606 for handling.
        error_attrs: Vec<AttributeError>,
    },
    /// End-of-RIB marker for `family` (RFC 4724).
    EndOfRib(Family),
}

/// Fatal parse error: the session must send this NOTIFICATION and close.
#[derive(Debug)]
pub struct ParseError {
    pub notification: Notification,
}

impl From<Notification> for ParseError {
    fn from(n: Notification) -> Self {
        ParseError { notification: n }
    }
}

/// A received BGP message (decode path).  Pass to `validate_message` to obtain
/// normalized send-path `Message`s with RFC 7606 error handling applied.
#[derive(Clone)]
pub enum ParsedMessage {
    Open(Open),
    Update(ParsedUpdate),
    Notification(Notification),
    Keepalive,
    RouteRefresh { family: Family },
}

/// Validate a parsed BGP message and normalize it into send-path `Message`s.
///
/// Returns `Err(Notification)` when the session must send that `Notification`
/// and close.  Returns `Ok(iter)` otherwise; the iterator yields the resulting
/// `Message`s (normally 1, 2 for a multi-family UPDATE, 0 for discard-only
/// attribute errors with no NLRIs).
pub fn validate_message(msg: ParsedMessage) -> Result<impl Iterator<Item = Message>, Notification> {
    let msgs: Vec<Message> = match msg {
        ParsedMessage::Open(open) => vec![Message::Open(open)],
        ParsedMessage::Update(update) => validate_update(update)?,
        ParsedMessage::Notification(n) => vec![Message::Notification(n)],
        ParsedMessage::Keepalive => vec![Message::Keepalive],
        ParsedMessage::RouteRefresh { family } => vec![Message::RouteRefresh { family }],
    };
    Ok(msgs.into_iter())
}

fn validate_update(update: ParsedUpdate) -> Result<Vec<Message>, Notification> {
    match update {
        ParsedUpdate::EndOfRib(family) => Ok(vec![Message::Update(Update::EndOfRib(family))]),
        ParsedUpdate::Routes {
            reach,
            mp_reach,
            unreach,
            mp_unreach,
            attrs,
            error_attrs,
        } => {
            // RFC 7606: classify each attribute error.
            // Optional non-transitive: attribute discard (already absent from attrs).
            // Well-known or optional transitive: treat-as-withdraw.
            let treat_as_withdraw = error_attrs.iter().any(|e| {
                let optional = e.attr_flags & Attribute::FLAG_OPTIONAL != 0;
                let transitive = e.attr_flags & Attribute::FLAG_TRANSITIVE != 0;
                !optional || transitive
            });

            if treat_as_withdraw {
                let empty = Arc::new(Vec::new());
                let mut msgs: Vec<Message> = Vec::new();
                // Convert announced NLRIs to withdrawals.
                for r in reach.into_iter().chain(mp_reach) {
                    msgs.push(Message::Update(Update::Routes {
                        reach: None,
                        unreach: Some(UnreachNlri {
                            family: r.family,
                            entries: r.entries,
                        }),
                        attr: empty.clone(),
                    }));
                }
                // Pass through any withdrawals already in the UPDATE.
                for u in unreach.into_iter().chain(mp_unreach) {
                    msgs.push(Message::Update(Update::Routes {
                        reach: None,
                        unreach: Some(u),
                        attr: empty.clone(),
                    }));
                }
                return Ok(msgs);
            }

            // Normal path: attribute-discard errors are already absent from attrs.
            let attr = Arc::new(attrs);
            let mut msgs: Vec<Message> = Vec::new();

            // Traditional IPv4 reach/unreach.
            if reach.is_some() || unreach.is_some() {
                msgs.push(Message::Update(Update::Routes {
                    reach,
                    unreach,
                    attr: attr.clone(),
                }));
            }

            // MP_REACH/MP_UNREACH: non-IPv4 or RFC 8950 IPv4.
            if mp_reach.is_some() || mp_unreach.is_some() {
                msgs.push(Message::Update(Update::Routes {
                    reach: mp_reach,
                    unreach: mp_unreach,
                    attr,
                }));
            }

            Ok(msgs)
        }
    }
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
        Message::Update(Update::EndOfRib(family))
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
                    // RFC 8950: extended nexthop is only valid for IPv4 families;
                    // skip (don't panic) if a peer advertises it for other AFIs.
                    if f.afi() != Family::AFI_IP {
                        continue;
                    }
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
    extended_length: bool,
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
            extended_length: false,
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
            extended_length: self.extended_length,
            channel,
        }
    }

    pub fn families(&mut self, v: Vec<Family>) -> &mut Self {
        self.family = v;
        self
    }
}

pub struct PeerCodec {
    extended_length: bool,
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

    fn mp_reach_encode<B: BufMut + AsMut<[u8]>>(
        &self,
        buf_head: usize,
        dst: &mut B,
        reach: &ReachNlri,
        reach_idx: &mut usize,
    ) -> Result<u16, ()> {
        let family = &reach.family;
        let nets = &reach.entries;
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
        // Attribute transformation (nexthop rewrite) is applied by PeerExportContext
        // before routes enter PendingTx, so the nexthop here is already the export
        // nexthop.  VPN families prefix the nexthop with an 8-byte zero RD (RFC 4364
        // §4.3.2); other families pad IPv4 to 16 bytes for MP_REACH.
        let nh_bytes = reach.nexthop.map(|nh| nh.to_bytes()).unwrap_or_default();
        let padded = if matches!(family, &Family::IPV4_VPN | &Family::IPV6_VPN) {
            let mut v = vec![0u8; 8];
            v.extend_from_slice(&nh_bytes);
            v
        } else if nh_bytes.len() < 16 {
            let mut v = vec![0u8; 16];
            v[..nh_bytes.len()].copy_from_slice(&nh_bytes);
            v
        } else {
            nh_bytes
        };
        dst.put_u8(padded.len() as u8);
        dst.put_slice(&padded);
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
        unreach: &UnreachNlri,
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
            Message::Update(update) => match update {
                Update::Routes {
                    reach,
                    unreach,
                    attr,
                } => {
                    let attrs = attr.clone();
                    let family = reach
                        .as_ref()
                        .map(|r| r.family)
                        .or_else(|| unreach.as_ref().map(|u| u.family))
                        .unwrap_or(Family::IPV4);
                    let addpath = self.channel.get(&family).is_some_and(|c| c.addpath_tx());
                    // RFC 8950: IPv4 uses MP_REACH_NLRI when extended nexthop is negotiated.
                    let ipv4_via_mp = self
                        .channel
                        .get(&Family::IPV4)
                        .is_some_and(|c| c.extended_nexthop());
                    dst.put_u8(Message::UPDATE);
                    let pos_withdrawn_len = dst.as_mut().len();
                    dst.put_u16(0);
                    let mut withdrawn_len = 0;
                    // Traditional IPv4 withdrawn routes (only when not using MP for IPv4)
                    if let Some(unreach) = &unreach
                        && unreach.family == Family::IPV4
                        && !ipv4_via_mp
                    {
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
                    let mut attr_len = 0;
                    let mut has_as_path = false;
                    for a in &*attrs {
                        if a.flags & Attribute::FLAG_TRANSITIVE > 0 {
                            if a.code() == Attribute::AS_PATH {
                                has_as_path = true;
                            }
                            attr_len += a.encode_wire(dst);
                        }
                    }
                    // NEXTHOP attribute for traditional IPv4 reach (not used when RFC 8950 active).
                    if let Some(r) = &reach
                        && r.family == Family::IPV4
                        && !ipv4_via_mp
                        && !r.entries.is_empty()
                        && let Some(nh) = r.nexthop
                        && let IpAddr::V4(v4) = nh.addr()
                    {
                        let nh_attr =
                            Attribute::new_with_bin(Attribute::NEXTHOP, v4.octets().to_vec())
                                .unwrap();
                        attr_len += nh_attr.encode_wire(dst);
                    }
                    let has_nlri = reach.as_ref().is_some_and(|r| !r.entries.is_empty());
                    if !has_as_path && has_nlri {
                        attr_len += Attribute::empty_as_path().encode_wire(dst);
                    }
                    // MP_REACH_NLRI (non-IPv4, or IPv4 with RFC 8950 extended nexthop)
                    if let Some(r) = &reach
                        && (r.family != Family::IPV4 || ipv4_via_mp)
                    {
                        attr_len += self.mp_reach_encode(pos_head, dst, r, reach_idx).unwrap();
                    }
                    // MP_UNREACH_NLRI (non-IPv4, or IPv4 with RFC 8950 extended nexthop)
                    if let Some(u) = &unreach
                        && (u.family != Family::IPV4 || ipv4_via_mp)
                    {
                        attr_len += self
                            .mp_unreach_encode(pos_head, attr.clone(), dst, u, reach_idx)
                            .unwrap();
                    }
                    (&mut dst.as_mut()[pos_attr_len..])
                        .write_u16::<NetworkEndian>(attr_len)
                        .unwrap();
                    // Traditional IPv4 NLRI (not used when RFC 8950 active)
                    if let Some(r) = reach
                        && r.family == Family::IPV4
                        && !ipv4_via_mp
                    {
                        let max_len = 5 + if addpath { 4 } else { 0 };
                        for (i, item) in r.entries.iter().enumerate().skip(*reach_idx) {
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
                Update::EndOfRib(family) => {
                    dst.put_u8(Message::UPDATE);
                    // No withdrawn routes
                    dst.put_u16(0);
                    let pos_attr_len = dst.as_mut().len();
                    dst.put_u16(0);
                    let mut attr_len = 0u16;
                    if *family != Family::IPV4 {
                        // Non-IPv4 EOR: empty MP_UNREACH_NLRI (RFC 4724 §2).
                        let empty = UnreachNlri::new(*family);
                        attr_len += self
                            .mp_unreach_encode(
                                pos_head,
                                Arc::new(Vec::new()),
                                dst,
                                &empty,
                                reach_idx,
                            )
                            .unwrap();
                    }
                    // IPv4 EOR: all-zero length fields, no attributes, no NLRI.
                    (&mut dst.as_mut()[pos_attr_len..])
                        .write_u16::<NetworkEndian>(attr_len)
                        .unwrap();
                }
            },
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

    fn decode_nlri<C: ParseContext>(
        &self,
        chan: &Channel,
        c: &mut BgpReader<C>,
        mut len: usize,
    ) -> Result<PathNlri, Notification> {
        let id = if chan.addpath_rx() {
            if len < 4 {
                return Err(Notification::UpdateMalformedAttributeList);
            }
            let id = c.read_u32_be()?;
            len -= 4;
            id
        } else {
            0
        };
        Nlri::decode(chan.family, c, len).map(|nlri| PathNlri { path_id: id, nlri })
    }
    pub fn parse_message(&mut self, buf: &[u8]) -> Result<ParsedMessage, Notification> {
        if buf.len() < Message::HEADER_LENGTH as usize {
            return Err(Notification::BadMessageLength { data: vec![] });
        }
        let code = buf[18];
        let header_len_error = Notification::BadMessageLength {
            data: (buf[16..18]).to_vec(),
        };

        match code {
            Message::OPEN => {
                const MINIMUM_OPEN_LENGTH: usize = 29;
                if buf.len() < MINIMUM_OPEN_LENGTH {
                    return Err(header_len_error);
                }
                let mut c = Cursor::new(&buf);
                c.set_position(Message::HEADER_LENGTH.into());
                let version = c.read_u8().unwrap();
                // BGP version must be 4 (RFC 4271 §4.2)
                if version != 4 {
                    return Err(Notification::OpenMalformed);
                }
                let mut as_number = c.read_u16::<NetworkEndian>().unwrap() as u32;
                let raw_holdtime = c.read_u16::<NetworkEndian>().unwrap();
                let holdtime =
                    HoldTime::new(raw_holdtime).ok_or(Notification::OpenUnacceptableHoldTime {
                        data: raw_holdtime.to_be_bytes().to_vec(),
                    })?;
                let router_id = c.read_u32::<NetworkEndian>().unwrap();
                let param_len = c.read_u8().unwrap();
                if buf.len() < MINIMUM_OPEN_LENGTH + param_len as usize {
                    return Err(Notification::OpenMalformed);
                }
                let param_end = c.position() + param_len as u64;
                let mut four_octet_asn: u32 = 0;
                let mut cap = Vec::new();
                while c.position() < param_end {
                    if param_end < c.position() + 2 {
                        return Err(Notification::OpenMalformed);
                    }
                    let op_type = c.read_u8().unwrap();
                    let op_len = c.read_u8().unwrap();
                    if param_end < c.position() + op_len as u64 {
                        return Err(Notification::OpenMalformed);
                    }
                    if op_type == 2 {
                        let op_end = c.position() + op_len as u64;
                        while c.position() < op_end {
                            if op_end < c.position() + 2 {
                                return Err(Notification::OpenMalformed);
                            }
                            let cap_type = c.read_u8().unwrap();
                            let cap_len = c.read_u8().unwrap();

                            if op_end < c.position() + cap_len as u64 {
                                return Err(Notification::OpenMalformed);
                            }
                            match Capability::decode(cap_type, &mut c, cap_len) {
                                Ok(decoded) => {
                                    if let Capability::FourOctetAsNumber(asn) = &decoded {
                                        four_octet_asn = *asn;
                                    }
                                    cap.push(decoded);
                                }
                                Err(_) => {
                                    return Err(Notification::OpenMalformed);
                                }
                            }
                        }
                    } else {
                        return Err(Notification::OpenUnsupportedOptionalParameter {
                            data: buf[c.position() as usize - 2
                                ..c.position() as usize + op_len as usize]
                                .to_vec(),
                        });
                    }
                }
                if as_number == Capability::TRANS_ASN as u32 {
                    as_number = four_octet_asn;
                }

                Ok(ParsedMessage::Open(Open {
                    as_number,
                    holdtime,
                    router_id,
                    capability: cap,
                }))
            }
            Message::UPDATE => {
                const MINIMUM_UPDATE_LENGTH: usize = 23;
                let malformed = || Notification::UpdateMalformedAttributeList;
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
                let mut reach_nexthop: Option<Nexthop> = None;
                let mut mp_nexthop: Option<Nexthop> = None;
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
                let attr_len = c
                    .read_u16::<NetworkEndian>()
                    .map_err(|_| Notification::UpdateMalformedAttributeList)?;
                if buf.len() < (withdrawn_len + attr_len + MINIMUM_UPDATE_LENGTH as u16).into() {
                    return Err(malformed());
                }
                let mut seen = FnvHashMap::default();
                let attr_end = c.position() + attr_len as u64;
                let mut pre_code = 0;
                let mut unsorted = false;
                let mut error_attrs: Vec<AttributeError> = Vec::new();
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
                                error_attrs.push(AttributeError {
                                    attr_code: code,
                                    attr_flags: flags,
                                });
                                continue;
                            } else {
                                let cur = c.position();
                                match Attribute::decode(code, flags, &mut c, alen) {
                                    Ok(a) => {
                                        if code == Attribute::MP_REACH {
                                            mp_reach_attr = Some(a);
                                        } else if code == Attribute::MP_UNREACH {
                                            mp_unreach_attr = Some(a);
                                        } else if code == Attribute::NEXTHOP {
                                            reach_nexthop =
                                                a.binary().and_then(|b| Nexthop::from_bytes(b));
                                        } else {
                                            attr.push(a);
                                            attr_idx += 1;
                                        }
                                    }
                                    Err(_) => {
                                        error_attrs.push(AttributeError {
                                            attr_code: code,
                                            attr_flags: flags,
                                        });
                                        c.set_position(cur + alen as u64);
                                        continue;
                                    }
                                }
                            }
                        }
                        None => {
                            if flags & Attribute::FLAG_OPTIONAL == 0 {
                                error_attrs.push(AttributeError {
                                    attr_code: code,
                                    attr_flags: flags,
                                });
                            }
                            c.set_position(c.position() + alen as u64);
                        }
                    }
                }

                // v4 eor
                if reach_len == 0 && attr_len == 0 && withdrawn_len == 0 {
                    return Ok(ParsedMessage::Update(ParsedUpdate::EndOfRib(Family::IPV4)));
                }

                if reach_len != 0 || mp_reach_attr.is_some() {
                    if !seen.contains_key(&Attribute::ORIGIN)
                        || !seen.contains_key(&Attribute::AS_PATH)
                    {
                        error_attrs.push(AttributeError {
                            attr_code: Attribute::ORIGIN,
                            attr_flags: Attribute::FLAG_TRANSITIVE,
                        });
                    }

                    if error_attrs.is_empty() && reach_nexthop.is_none() && reach_len != 0 {
                        error_attrs.push(AttributeError {
                            attr_code: Attribute::NEXTHOP,
                            attr_flags: Attribute::FLAG_TRANSITIVE,
                        });
                    }
                }

                if c.position() != attr_end {
                    error_attrs.push(AttributeError {
                        attr_code: 0,
                        attr_flags: 0,
                    });
                    c.set_position(attr_end);
                }

                if (c.position() as usize) < buf.len() {
                    let chan = self.channel.get(&Family::IPV4).ok_or_else(malformed)?;
                    let mut reader = BgpReader::<UpdateCtx>::new(&buf[c.position() as usize..]);
                    while reader.remaining_len() > 0 {
                        let rest = reader.remaining_len();
                        reach.push(self.decode_nlri(chan, &mut reader, rest)?);
                    }
                }

                if 0 < withdrawn_len {
                    let chan = self.channel.get(&Family::IPV4).ok_or_else(malformed)?;
                    let start = Message::HEADER_LENGTH as usize + 2;
                    let mut reader =
                        BgpReader::<UpdateCtx>::new(&buf[start..start + withdrawn_len as usize]);
                    while reader.remaining_len() > 0 {
                        let rest = reader.remaining_len();
                        unreach.push(self.decode_nlri(chan, &mut reader, rest)?);
                    }
                }

                if unsorted {
                    attr.sort_unstable_by_key(|a| a.code());
                }

                if let Some(a) = mp_reach_attr {
                    let err = Notification::UpdateOptionalAttributeError;
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
                        // Flowspec and similar AFIs carry no nexthop (RFC 5575 §4).
                        0 => {}
                        4 | 16 | 32 => {
                            for _ in 0..nexthop_len {
                                data.push(c.read_u8().unwrap());
                            }
                            mp_nexthop = Nexthop::from_bytes(&data);
                        }
                        // VPN nexthop (RFC 4364 §4.3.2): 8-byte RD (must be 0) + IP address.
                        12 | 24 => {
                            for _ in 0..8 {
                                c.read_u8().unwrap();
                            }
                            for _ in 0..(nexthop_len - 8) {
                                data.push(c.read_u8().unwrap());
                            }
                            mp_nexthop = Nexthop::from_bytes(&data);
                        }
                        _ => return Err(err),
                    }
                    c.read_u8().unwrap();
                    let mut reader = BgpReader::<UpdateCtx>::new(&buf[c.position() as usize..]);
                    while reader.remaining_len() > 0 {
                        let rest = reader.remaining_len();
                        mp_reach_entries.push(self.decode_nlri(chan, &mut reader, rest)?);
                    }
                }

                let mp_unreach_present = mp_unreach_attr.is_some();
                if let Some(a) = mp_unreach_attr {
                    let err = Notification::UpdateOptionalAttributeError;
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
                    let mut reader = BgpReader::<UpdateCtx>::new(&buf[c.position() as usize..]);
                    while reader.remaining_len() > 0 {
                        let rest = reader.remaining_len();
                        mp_unreach_entries.push(self.decode_nlri(chan, &mut reader, rest)?);
                    }
                }

                // non-IPv4 EOR: MP_UNREACH_NLRI with no NLRIs and no other content (RFC 4724 §2)
                if mp_unreach_entries.is_empty()
                    && mp_unreach_present
                    && reach.is_empty()
                    && mp_reach_entries.is_empty()
                    && unreach.is_empty()
                    && attr.is_empty()
                    && error_attrs.is_empty()
                {
                    return Ok(ParsedMessage::Update(ParsedUpdate::EndOfRib(
                        mp_unreach_family,
                    )));
                }

                Ok(ParsedMessage::Update(ParsedUpdate::Routes {
                    reach: if reach.is_empty() {
                        None
                    } else {
                        Some(ReachNlri {
                            family: reach_family,
                            entries: reach,
                            nexthop: reach_nexthop,
                        })
                    },
                    mp_reach: if mp_reach_entries.is_empty() {
                        None
                    } else {
                        Some(ReachNlri {
                            family: mp_reach_family,
                            entries: mp_reach_entries,
                            nexthop: mp_nexthop,
                        })
                    },
                    attrs: attr,
                    unreach: if unreach.is_empty() {
                        None
                    } else {
                        Some(UnreachNlri {
                            family: unreach_family,
                            entries: unreach,
                        })
                    },
                    mp_unreach: if mp_unreach_entries.is_empty() {
                        None
                    } else {
                        Some(UnreachNlri {
                            family: mp_unreach_family,
                            entries: mp_unreach_entries,
                        })
                    },
                    error_attrs,
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

                Ok(ParsedMessage::Notification(
                    Notification::from_notification(
                        code,
                        subcode,
                        buf[c.position() as usize..].to_vec(),
                    ),
                ))
            }
            Message::KEEPALIVE => Ok(ParsedMessage::Keepalive),
            Message::ROUTE_REFRESH => {
                const ROUTE_REFRESH_LENGTH: usize = Message::HEADER_LENGTH as usize + 4;
                if buf.len() < ROUTE_REFRESH_LENGTH {
                    return Err(header_len_error);
                }
                if ROUTE_REFRESH_LENGTH < buf.len() {
                    return Err(Notification::RouteRefreshInvalidLength { data: buf.to_vec() });
                }
                let mut c = Cursor::new(&buf);
                c.set_position(Message::HEADER_LENGTH.into());
                Ok(ParsedMessage::RouteRefresh {
                    family: Family(c.read_u32::<NetworkEndian>().unwrap()),
                })
            }
            _ => Err(Notification::BadMessageType { data: vec![code] }),
        }
    }

    pub fn encode_to<B: BufMut + AsMut<[u8]>>(
        &mut self,
        msg: &Message,
        dst: &mut B,
    ) -> Result<(), Error> {
        let mut done_idx = 0;
        match msg {
            Message::Update(Update::Routes { reach, unreach, .. }) => {
                // Determine the number of iterations needed for splitting large route sets.
                let total = std::cmp::max(
                    reach.as_ref().map_or(0, |s| s.entries.len()).max(1),
                    unreach.as_ref().map_or(0, |s| s.entries.len()).max(1),
                );
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

    /// Try to parse one complete BGP message from a stream buffer.
    /// Returns `Ok(None)` if there are not enough bytes yet.
    pub fn try_parse(&mut self, src: &mut BytesMut) -> Result<Option<ParsedMessage>, Notification> {
        let buffer_len = src.len();
        if buffer_len < Message::HEADER_LENGTH as usize {
            return Ok(None);
        }
        let message_len = (&src[16..18]).read_u16::<NetworkEndian>().unwrap() as usize;
        if message_len < Message::HEADER_LENGTH as usize || message_len > self.max_message_length()
        {
            return Err(Notification::BadMessageLength {
                data: src[16..18].to_vec(),
            });
        }
        if buffer_len < message_len {
            return Ok(None);
        }
        let buf = src.split_to(message_len);
        Ok(Some(self.parse_message(&buf)?))
    }
}

#[cfg(test)]
mod confed_as_path_tests {
    use super::*;

    fn as_path(data: Vec<u8>) -> Attribute {
        Attribute::new_with_bin(Attribute::AS_PATH, data).unwrap()
    }

    fn seg_bytes(seg_type: u8, asns: &[u32]) -> Vec<u8> {
        let mut v = vec![seg_type, asns.len() as u8];
        for &a in asns {
            v.extend_from_slice(&a.to_be_bytes());
        }
        v
    }

    #[test]
    fn as_path_prepend_confed_to_empty() {
        let result = Attribute::empty_as_path().as_path_prepend_confed(65001);
        let buf = result.binary().unwrap();
        assert_eq!(
            buf,
            &seg_bytes(Attribute::AS_PATH_TYPE_CONFED_SEQ, &[65001])
        );
    }

    #[test]
    fn as_path_prepend_confed_extends_existing() {
        let input = as_path(seg_bytes(Attribute::AS_PATH_TYPE_CONFED_SEQ, &[65002]));
        let result = input.as_path_prepend_confed(65001);
        let buf = result.binary().unwrap();
        assert_eq!(
            buf,
            &seg_bytes(Attribute::AS_PATH_TYPE_CONFED_SEQ, &[65001, 65002])
        );
    }

    #[test]
    fn as_path_prepend_confed_full_segment_creates_new() {
        let full: Vec<u32> = (0..255).map(|i| 65000 + i).collect();
        let input = as_path(seg_bytes(Attribute::AS_PATH_TYPE_CONFED_SEQ, &full));
        let result = input.as_path_prepend_confed(65001);
        let buf = result.binary().unwrap();
        let mut expected = seg_bytes(Attribute::AS_PATH_TYPE_CONFED_SEQ, &[65001]);
        expected.extend_from_slice(&seg_bytes(Attribute::AS_PATH_TYPE_CONFED_SEQ, &full));
        assert_eq!(buf, &expected);
    }

    #[test]
    fn as_path_prepend_confed_over_seq_segment() {
        let input = as_path(seg_bytes(Attribute::AS_PATH_TYPE_SEQ, &[65100]));
        let result = input.as_path_prepend_confed(65001);
        let buf = result.binary().unwrap();
        let mut expected = seg_bytes(Attribute::AS_PATH_TYPE_CONFED_SEQ, &[65001]);
        expected.extend_from_slice(&seg_bytes(Attribute::AS_PATH_TYPE_SEQ, &[65100]));
        assert_eq!(buf, &expected);
    }

    #[test]
    fn as_path_strip_confed_removes_confed_segments() {
        let mut data = seg_bytes(Attribute::AS_PATH_TYPE_CONFED_SEQ, &[65001]);
        data.extend_from_slice(&seg_bytes(Attribute::AS_PATH_TYPE_SEQ, &[65100]));
        data.extend_from_slice(&seg_bytes(Attribute::AS_PATH_TYPE_CONFED_SET, &[65050]));
        data.extend_from_slice(&seg_bytes(Attribute::AS_PATH_TYPE_SEQ, &[65200]));
        let result = as_path(data).as_path_strip_confed();
        let buf = result.binary().unwrap();
        let mut expected = seg_bytes(Attribute::AS_PATH_TYPE_SEQ, &[65100]);
        expected.extend_from_slice(&seg_bytes(Attribute::AS_PATH_TYPE_SEQ, &[65200]));
        assert_eq!(buf, &expected);
    }

    #[test]
    fn as_path_strip_confed_only_confed_gives_empty() {
        let mut data = seg_bytes(Attribute::AS_PATH_TYPE_CONFED_SEQ, &[65001]);
        data.extend_from_slice(&seg_bytes(Attribute::AS_PATH_TYPE_CONFED_SET, &[65050]));
        let result = as_path(data).as_path_strip_confed();
        assert!(result.binary().unwrap().is_empty());
    }
}

#[cfg(test)]
mod notification_tests {
    use super::*;

    #[test]
    fn hard_reset_is_cease_subcode_9() {
        let err = Notification::Other {
            code: 6,
            subcode: 9,
            data: vec![],
        };
        assert!(err.is_hard_reset());
    }

    #[test]
    fn cease_other_subcodes_are_not_hard_reset() {
        for subcode in [0u8, 1, 2, 3, 4, 5, 6, 7, 8] {
            let err = Notification::Other {
                code: 6,
                subcode,
                data: vec![],
            };
            assert!(
                !err.is_hard_reset(),
                "subcode {subcode} should not be hard reset"
            );
        }
    }

    #[test]
    fn non_cease_codes_are_not_hard_reset() {
        for code in [1u8, 2, 3, 5, 7] {
            let err = Notification::Other {
                code,
                subcode: 9,
                data: vec![],
            };
            assert!(
                !err.is_hard_reset(),
                "code {code} subcode 9 should not be hard reset"
            );
        }
    }
}
