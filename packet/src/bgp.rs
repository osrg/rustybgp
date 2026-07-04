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
use fnv::{FnvHashMap, FnvHashSet};

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
    #[error("open error: unsupported version number")]
    OpenUnsupportedVersionNumber { data: Vec<u8> },
    #[error("open error: bad peer AS")]
    OpenBadPeerAs,
    #[error("open error: bad BGP identifier")]
    OpenBadBgpIdentifier,
    #[error("open error: unsupported optional parameter")]
    OpenUnsupportedOptionalParameter { data: Vec<u8> },
    #[error("open error: unsupported capability")]
    OpenUnsupportedCapability { data: Vec<u8> },
    #[error("open error: unacceptable hold time")]
    OpenUnacceptableHoldTime { data: Vec<u8> },

    // Code 3: UPDATE Message Error
    #[error("update error: malformed attribute list")]
    UpdateMalformedAttributeList,
    #[error("update error: unrecognized well-known attribute")]
    UpdateUnrecognizedWellKnownAttribute { data: Vec<u8> },
    #[error("update error: missing well-known attribute")]
    UpdateMissingWellKnownAttribute { data: Vec<u8> },
    #[error("update error: attribute flags error")]
    UpdateAttributeFlagsError { data: Vec<u8> },
    #[error("update error: attribute length error")]
    UpdateAttributeLengthError { data: Vec<u8> },
    #[error("update error: invalid origin attribute")]
    UpdateInvalidOriginAttribute { data: Vec<u8> },
    #[error("update error: invalid next hop attribute")]
    UpdateInvalidNextHopAttribute { data: Vec<u8> },
    #[error("update error: optional attribute error")]
    UpdateOptionalAttributeError,
    #[error("update error: invalid network field")]
    UpdateInvalidNetworkField,
    #[error("update error: malformed AS path")]
    UpdateMalformedAsPath,

    // Code 4: Hold Timer Expired
    #[error("hold timer expired")]
    HoldTimerExpired,

    // Code 5: FSM Error
    #[error("FSM error: unexpected state {state}")]
    FsmUnexpectedState { state: u8 },

    // Code 6: Cease (RFC 4486)
    #[error("cease: maximum number of prefixes reached")]
    CeaseMaxPrefixReached,
    #[error("cease: administrative shutdown")]
    CeaseAdminShutdown,
    #[error("cease: peer deconfigured")]
    CeasePeerDeconfigured,
    #[error("cease: administrative reset")]
    CeaseAdministrativeReset,
    #[error("cease: connection rejected")]
    CeaseConnectionRejected,
    #[error("cease: other configuration change")]
    CeaseOtherConfigurationChange,
    #[error("cease: connection collision resolution")]
    CeaseConnectionCollision,
    #[error("cease: out of resources")]
    CeaseOutOfResources,
    #[error("cease: hard reset")]
    CeaseHardReset,

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
            | Self::OpenUnsupportedVersionNumber { .. }
            | Self::OpenBadPeerAs
            | Self::OpenBadBgpIdentifier
            | Self::OpenUnsupportedOptionalParameter { .. }
            | Self::OpenUnsupportedCapability { .. }
            | Self::OpenUnacceptableHoldTime { .. } => 2,
            Self::UpdateMalformedAttributeList
            | Self::UpdateUnrecognizedWellKnownAttribute { .. }
            | Self::UpdateMissingWellKnownAttribute { .. }
            | Self::UpdateAttributeFlagsError { .. }
            | Self::UpdateAttributeLengthError { .. }
            | Self::UpdateInvalidOriginAttribute { .. }
            | Self::UpdateInvalidNextHopAttribute { .. }
            | Self::UpdateOptionalAttributeError
            | Self::UpdateInvalidNetworkField
            | Self::UpdateMalformedAsPath => 3,
            Self::HoldTimerExpired => 4,
            Self::FsmUnexpectedState { .. } => 5,
            Self::CeaseMaxPrefixReached
            | Self::CeaseAdminShutdown
            | Self::CeasePeerDeconfigured
            | Self::CeaseAdministrativeReset
            | Self::CeaseConnectionRejected
            | Self::CeaseOtherConfigurationChange
            | Self::CeaseConnectionCollision
            | Self::CeaseOutOfResources
            | Self::CeaseHardReset => 6,
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
            Self::OpenUnsupportedVersionNumber { .. } => 1,
            Self::OpenBadPeerAs => 2,
            Self::OpenBadBgpIdentifier => 3,
            Self::OpenUnsupportedOptionalParameter { .. } => 4,
            Self::OpenUnsupportedCapability { .. } => 7,
            Self::OpenUnacceptableHoldTime { .. } => 6,
            Self::UpdateMalformedAttributeList => 1,
            Self::UpdateUnrecognizedWellKnownAttribute { .. } => 2,
            Self::UpdateMissingWellKnownAttribute { .. } => 3,
            Self::UpdateAttributeFlagsError { .. } => 4,
            Self::UpdateAttributeLengthError { .. } => 5,
            Self::UpdateInvalidOriginAttribute { .. } => 6,
            Self::UpdateInvalidNextHopAttribute { .. } => 8,
            Self::UpdateOptionalAttributeError => 9,
            Self::UpdateInvalidNetworkField => 10,
            Self::UpdateMalformedAsPath => 11,
            Self::HoldTimerExpired => 0,
            Self::FsmUnexpectedState { state } => *state,
            Self::CeaseMaxPrefixReached => 1,
            Self::CeaseAdminShutdown => 2,
            Self::CeasePeerDeconfigured => 3,
            Self::CeaseAdministrativeReset => 4,
            Self::CeaseConnectionRejected => 5,
            Self::CeaseOtherConfigurationChange => 6,
            Self::CeaseConnectionCollision => 7,
            Self::CeaseOutOfResources => 8,
            Self::CeaseHardReset => 9,
            Self::RouteRefreshInvalidLength { .. } => 1,
            Self::Other { subcode, .. } => *subcode,
        }
    }

    /// Returns the BGP NOTIFICATION data.
    pub fn notification_data(&self) -> &[u8] {
        match self {
            Self::BadMessageLength { data }
            | Self::BadMessageType { data }
            | Self::OpenUnsupportedVersionNumber { data }
            | Self::OpenUnsupportedOptionalParameter { data }
            | Self::OpenUnsupportedCapability { data }
            | Self::OpenUnacceptableHoldTime { data }
            | Self::UpdateUnrecognizedWellKnownAttribute { data }
            | Self::UpdateMissingWellKnownAttribute { data }
            | Self::UpdateAttributeFlagsError { data }
            | Self::UpdateAttributeLengthError { data }
            | Self::UpdateInvalidOriginAttribute { data }
            | Self::UpdateInvalidNextHopAttribute { data }
            | Self::RouteRefreshInvalidLength { data }
            | Self::Other { data, .. } => data,
            _ => &[],
        }
    }

    /// Returns true if this is a CEASE Hard Reset (RFC 8538 §3: code 6, subcode 9).
    /// Hard Reset terminates GR even when the N-bit is negotiated.
    pub fn is_hard_reset(&self) -> bool {
        matches!(self, Self::CeaseHardReset)
    }

    /// Constructs a `Notification` from a received NOTIFICATION message.
    pub fn from_notification(code: u8, subcode: u8, data: Vec<u8>) -> Self {
        match (code, subcode) {
            (1, 2) => Self::BadMessageLength { data },
            (1, 3) => Self::BadMessageType { data },
            (2, 0) => Self::OpenMalformed,
            (2, 1) => Self::OpenUnsupportedVersionNumber { data },
            (2, 2) => Self::OpenBadPeerAs,
            (2, 3) => Self::OpenBadBgpIdentifier,
            (2, 4) => Self::OpenUnsupportedOptionalParameter { data },
            (2, 7) => Self::OpenUnsupportedCapability { data },
            (2, 6) => Self::OpenUnacceptableHoldTime { data },
            (3, 1) => Self::UpdateMalformedAttributeList,
            (3, 2) => Self::UpdateUnrecognizedWellKnownAttribute { data },
            (3, 3) => Self::UpdateMissingWellKnownAttribute { data },
            (3, 4) => Self::UpdateAttributeFlagsError { data },
            (3, 5) => Self::UpdateAttributeLengthError { data },
            (3, 6) => Self::UpdateInvalidOriginAttribute { data },
            (3, 8) => Self::UpdateInvalidNextHopAttribute { data },
            (3, 9) => Self::UpdateOptionalAttributeError,
            (3, 10) => Self::UpdateInvalidNetworkField,
            (3, 11) => Self::UpdateMalformedAsPath,
            (4, _) => Self::HoldTimerExpired,
            (5, state) => Self::FsmUnexpectedState { state },
            (6, 1) => Self::CeaseMaxPrefixReached,
            (6, 2) => Self::CeaseAdminShutdown,
            (6, 3) => Self::CeasePeerDeconfigured,
            (6, 4) => Self::CeaseAdministrativeReset,
            (6, 5) => Self::CeaseConnectionRejected,
            (6, 6) => Self::CeaseOtherConfigurationChange,
            (6, 7) => Self::CeaseConnectionCollision,
            (6, 8) => Self::CeaseOutOfResources,
            (6, 9) => Self::CeaseHardReset,
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
    pub const AFI_L2VPN: u16 = 25;
    pub const AFI_LS: u16 = 16388;

    const SAFI_UNICAST: u8 = 1;
    const SAFI_MULTICAST: u8 = 2;
    const SAFI_LABELED_UNICAST: u8 = 4;
    const SAFI_EVPN: u8 = 70;
    const SAFI_LS: u8 = 71;
    const SAFI_MUP: u8 = 85;
    const SAFI_MPLS_VPN: u8 = 128;
    const SAFI_SR_POLICY: u8 = 73;
    const SAFI_FLOWSPEC: u8 = 133;
    const SAFI_FLOWSPEC_VPN: u8 = 134;
    const SAFI_RTC: u8 = 132;

    pub const EMPTY: Family = Family::new(0, 0);
    pub const IPV4: Family = Family::new(Family::AFI_IP, Family::SAFI_UNICAST);
    pub const IPV6: Family = Family::new(Family::AFI_IP6, Family::SAFI_UNICAST);
    pub const IPV4_MC: Family = Family::new(Family::AFI_IP, Family::SAFI_MULTICAST);
    pub const IPV6_MC: Family = Family::new(Family::AFI_IP6, Family::SAFI_MULTICAST);
    pub const IPV4_MPLS: Family = Family::new(Family::AFI_IP, Family::SAFI_LABELED_UNICAST);
    pub const IPV6_MPLS: Family = Family::new(Family::AFI_IP6, Family::SAFI_LABELED_UNICAST);
    pub const LS: Family = Family::new(Family::AFI_LS, Family::SAFI_LS);
    pub const IPV4_MUP: Family = Family::new(Family::AFI_IP, Family::SAFI_MUP);
    pub const IPV6_MUP: Family = Family::new(Family::AFI_IP6, Family::SAFI_MUP);
    pub const IPV4_VPN: Family = Family::new(Family::AFI_IP, Family::SAFI_MPLS_VPN);
    pub const IPV6_VPN: Family = Family::new(Family::AFI_IP6, Family::SAFI_MPLS_VPN);
    pub const IPV4_FLOWSPEC: Family = Family::new(Family::AFI_IP, Family::SAFI_FLOWSPEC);
    pub const IPV6_FLOWSPEC: Family = Family::new(Family::AFI_IP6, Family::SAFI_FLOWSPEC);
    pub const IPV4_FLOWSPEC_VPN: Family = Family::new(Family::AFI_IP, Family::SAFI_FLOWSPEC_VPN);
    pub const IPV6_FLOWSPEC_VPN: Family = Family::new(Family::AFI_IP6, Family::SAFI_FLOWSPEC_VPN);
    pub const IPV4_SRPOLICY: Family = Family::new(Family::AFI_IP, Family::SAFI_SR_POLICY);
    pub const IPV6_SRPOLICY: Family = Family::new(Family::AFI_IP6, Family::SAFI_SR_POLICY);
    pub const L2VPN_EVPN: Family = Family::new(Family::AFI_L2VPN, Family::SAFI_EVPN);
    pub const RTC: Family = Family::new(Family::AFI_IP, Family::SAFI_RTC);

    pub const fn new(afi: u16, safi: u8) -> Self {
        Family((afi as u32) << 16 | safi as u32)
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
    LabeledV4(crate::labeled::LabeledV4Nlri),
    LabeledV6(crate::labeled::LabeledV6Nlri),
    FlowspecV4(crate::flowspec::FlowspecV4Nlri),
    FlowspecV6(crate::flowspec::FlowspecV6Nlri),
    FlowspecVpnV4(crate::flowspec::FlowspecVpnV4Nlri),
    FlowspecVpnV6(crate::flowspec::FlowspecVpnV6Nlri),
    Ls(crate::ls::BgpLsNlri),
    SrPolicy(crate::sr_policy::SrPolicyNlri),
    Evpn(crate::evpn::EvpnNlri),
    Rtc(crate::rtc::RtcNlri),
}

impl Nlri {
    pub(crate) fn encode<B: BufMut>(&self, dst: &mut B) -> Result<u16, ()> {
        match self {
            Nlri::V4(net) => net.encode(dst),
            Nlri::V6(net) => net.encode(dst),
            Nlri::Mup(m) => Ok(m.encode(dst)),
            Nlri::VpnV4(n) => Ok(n.encode(dst)),
            Nlri::VpnV6(n) => Ok(n.encode(dst)),
            Nlri::LabeledV4(n) => Ok(n.encode(dst)),
            Nlri::LabeledV6(n) => Ok(n.encode(dst)),
            Nlri::FlowspecV4(n) => {
                n.encode(dst);
                Ok(0)
            }
            Nlri::FlowspecV6(n) => {
                n.encode(dst);
                Ok(0)
            }
            Nlri::FlowspecVpnV4(n) => {
                n.encode(dst);
                Ok(0)
            }
            Nlri::FlowspecVpnV6(n) => {
                n.encode(dst);
                Ok(0)
            }
            Nlri::Ls(n) => {
                n.encode(dst);
                Ok(0)
            }
            Nlri::SrPolicy(n) => {
                n.encode(dst);
                Ok(0)
            }
            Nlri::Evpn(n) => {
                n.encode(dst);
                Ok(0)
            }
            Nlri::Rtc(n) => {
                n.encode(dst);
                Ok(0)
            }
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
        is_reach: bool,
    ) -> Result<Nlri, Notification> {
        match family {
            Family::IPV4 | Family::IPV4_MC => Ipv4Net::decode(c, len).map(Nlri::V4),
            Family::IPV6 | Family::IPV6_MC => Ipv6Net::decode(c, len).map(Nlri::V6),
            Family::IPV4_MUP | Family::IPV6_MUP => crate::mup::MupNlri::decode(family, c, len)
                .map(Nlri::Mup)
                .map_err(|_| Notification::UpdateMalformedAttributeList),
            Family::IPV4_VPN => crate::vpn::VpnV4Nlri::decode(c, len)
                .map(Nlri::VpnV4)
                .map_err(|_| Notification::UpdateMalformedAttributeList),
            Family::IPV6_VPN => crate::vpn::VpnV6Nlri::decode(c, len)
                .map(Nlri::VpnV6)
                .map_err(|_| Notification::UpdateMalformedAttributeList),
            Family::IPV4_MPLS => crate::labeled::LabeledV4Nlri::decode(c, len, is_reach)
                .map(Nlri::LabeledV4)
                .map_err(|_| Notification::UpdateMalformedAttributeList),
            Family::IPV6_MPLS => crate::labeled::LabeledV6Nlri::decode(c, len, is_reach)
                .map(Nlri::LabeledV6)
                .map_err(|_| Notification::UpdateMalformedAttributeList),
            Family::IPV4_FLOWSPEC => crate::flowspec::FlowspecV4Nlri::decode(c, len)
                .map(Nlri::FlowspecV4)
                .map_err(|_| Notification::UpdateMalformedAttributeList),
            Family::IPV6_FLOWSPEC => crate::flowspec::FlowspecV6Nlri::decode(c, len)
                .map(Nlri::FlowspecV6)
                .map_err(|_| Notification::UpdateMalformedAttributeList),
            Family::IPV4_FLOWSPEC_VPN => crate::flowspec::FlowspecVpnV4Nlri::decode(c, len)
                .map(Nlri::FlowspecVpnV4)
                .map_err(|_| Notification::UpdateMalformedAttributeList),
            Family::IPV6_FLOWSPEC_VPN => crate::flowspec::FlowspecVpnV6Nlri::decode(c, len)
                .map(Nlri::FlowspecVpnV6)
                .map_err(|_| Notification::UpdateMalformedAttributeList),
            Family::LS => crate::ls::BgpLsNlri::decode(c)
                .map(Nlri::Ls)
                .ok_or(Notification::UpdateMalformedAttributeList),
            Family::IPV4_SRPOLICY | Family::IPV6_SRPOLICY => {
                crate::sr_policy::SrPolicyNlri::decode(c)
                    .map(Nlri::SrPolicy)
                    .map_err(|_| Notification::UpdateMalformedAttributeList)
            }
            Family::L2VPN_EVPN => crate::evpn::EvpnNlri::decode(c)
                .map(Nlri::Evpn)
                .map_err(|_| Notification::UpdateMalformedAttributeList),
            Family::RTC => crate::rtc::RtcNlri::decode(c)
                .map(Nlri::Rtc)
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
            Nlri::LabeledV4(n) => n.fmt(f),
            Nlri::LabeledV6(n) => n.fmt(f),
            Nlri::FlowspecV4(n) => n.fmt(f),
            Nlri::FlowspecV6(n) => n.fmt(f),
            Nlri::FlowspecVpnV4(n) => n.fmt(f),
            Nlri::FlowspecVpnV6(n) => n.fmt(f),
            Nlri::Ls(n) => n.fmt(f),
            Nlri::SrPolicy(n) => n.fmt(f),
            Nlri::Evpn(n) => n.fmt(f),
            Nlri::Rtc(n) => n.fmt(f),
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

#[derive(Debug, Clone, PartialEq)]
pub enum Capability {
    MultiProtocol(Family),
    RouteRefresh,
    ExtendedNexthop(Vec<(Family, u16)>),
    ExtendedMessage,
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
    const EXTENDED_MESSAGE: u8 = 6;
    const GRACEFUL_RESTART: u8 = 64;
    pub const FOUR_OCTET_AS_NUMBER: u8 = 65;
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
            Capability::ExtendedMessage => Capability::EXTENDED_MESSAGE,
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
            Capability::ExtendedMessage => {
                c.put_u8(0);
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
            Self::EXTENDED_MESSAGE => {
                if len != 0 {
                    return Err(());
                }
                Ok(Capability::ExtendedMessage)
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
    /// Raw bytes for an unknown optional attribute (RFC 4271 §5.1.4).
    Opaque(Vec<u8>),
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct Attribute {
    code: u8,
    flags: u8,
    data: AttributeData,
}

impl Attribute {
    pub const ORIGIN_INCOMPLETE: u8 = 2;
    pub(crate) const FLAG_EXTENDED: u8 = 1 << 4;
    pub const FLAG_PARTIAL: u8 = 1 << 5;
    pub(crate) const FLAG_TRANSITIVE: u8 = 1 << 6;
    pub(crate) const FLAG_OPTIONAL: u8 = 1 << 7;

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
    pub const LS: u8 = 29;
    pub const TUNNEL_ENCAP: u8 = 23;

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
            AttributeData::Bin(_) | AttributeData::Opaque(_) => None,
        }
    }

    pub fn binary(&self) -> Option<&Vec<u8>> {
        match &self.data {
            AttributeData::Val(_) => None,
            AttributeData::Bin(v) | AttributeData::Opaque(v) => Some(v),
        }
    }

    /// Constructs an opaque attribute from raw wire bytes.
    /// Used to preserve unknown optional transitive attributes (RFC 4271 §5.1.4).
    /// Unlike `new_with_bin`, `flags` is stored as-is without consulting `canonical_flags`.
    pub fn new_opaque(code: u8, flags: u8, data: Vec<u8>) -> Self {
        Attribute {
            code,
            flags,
            data: AttributeData::Opaque(data),
        }
    }

    /// Returns true if this attribute was received as an unknown opaque blob.
    pub fn is_opaque(&self) -> bool {
        matches!(self.data, AttributeData::Opaque(_))
    }

    /// Returns true if the TRANSITIVE flag is set in the wire flags.
    pub fn is_transitive(&self) -> bool {
        self.flags & Self::FLAG_TRANSITIVE != 0
    }

    /// Returns a clone of this attribute with the PARTIAL bit set.
    /// Used when forwarding an unrecognized optional transitive attribute.
    pub fn with_partial_bit(&self) -> Self {
        Attribute {
            code: self.code,
            flags: self.flags | Self::FLAG_PARTIAL,
            data: self.data.clone(),
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
            Self::AIGP => Some(Self::FLAG_OPTIONAL),
            Self::LARGE_COMMUNITY => Some(Self::FLAG_TRANSITIVE | Self::FLAG_OPTIONAL),
            Self::PREFIX_SID => Some(Self::FLAG_TRANSITIVE | Self::FLAG_OPTIONAL),
            Self::LS => Some(Self::FLAG_OPTIONAL),
            Self::TUNNEL_ENCAP => Some(Self::FLAG_TRANSITIVE | Self::FLAG_OPTIONAL),
            _ => None,
        }
    }

    fn decode(
        code: u8,
        flags: u8,
        c: &mut dyn io::Read,
        len: u16,
        two_byte_as: bool,
    ) -> Result<Self, ()> {
        let data = match code {
            Self::ORIGIN => {
                if len != 1 {
                    return Err(());
                }
                let val = c.read_u8().map_err(|_| ())? as u32;
                // RFC 4271 §4.3: valid values are 0 (IGP), 1 (EGP), 2 (INCOMPLETE)
                if val > Self::ORIGIN_INCOMPLETE as u32 {
                    return Err(());
                }
                AttributeData::Val(val)
            }
            Self::MULTI_EXIT_DESC | Self::LOCAL_PREF | Self::ORIGINATOR_ID => {
                if len != 4 {
                    return Err(());
                }
                AttributeData::Val(c.read_u32::<NetworkEndian>().map_err(|_| ())?)
            }
            Self::AS_PATH => {
                let mut b = vec![0u8; len as usize];
                c.read_exact(&mut b).map_err(|_| ())?;
                if two_byte_as {
                    // RFC 6793 §4.2.3: an OLD BGP speaker encodes each AS as two
                    // octets. Up-convert to the canonical four-octet internal
                    // representation used everywhere else in this codebase;
                    // AS_TRANS (23456) is preserved as-is here and resolved
                    // later by reconciling with AS4_PATH.
                    let mut out = Vec::with_capacity(b.len() * 2);
                    let mut pos = 0usize;
                    while pos < b.len() {
                        if pos + 2 > b.len() {
                            return Err(());
                        }
                        let seg_type = b[pos];
                        let seg_count = b[pos + 1] as usize;
                        if !(Self::AS_PATH_TYPE_SET..=Self::AS_PATH_TYPE_CONFED_SET)
                            .contains(&seg_type)
                        {
                            return Err(());
                        }
                        let seg_end = pos + 2 + seg_count * 2;
                        if seg_end > b.len() {
                            return Err(());
                        }
                        out.push(seg_type);
                        out.push(b[pos + 1]);
                        for i in 0..seg_count {
                            let start = pos + 2 + i * 2;
                            let as2 = u16::from_be_bytes([b[start], b[start + 1]]);
                            out.extend_from_slice(&(as2 as u32).to_be_bytes());
                        }
                        pos = seg_end;
                    }
                    AttributeData::Bin(out)
                } else {
                    // RFC 4271 §4.3: validate segment structure.
                    // Each segment: 1-byte type (1-4), 1-byte count, count*4 bytes of 4-octet ASNs.
                    let mut pos = 0usize;
                    while pos < b.len() {
                        if pos + 2 > b.len() {
                            return Err(());
                        }
                        let seg_type = b[pos];
                        let seg_count = b[pos + 1] as usize;
                        if !(Self::AS_PATH_TYPE_SET..=Self::AS_PATH_TYPE_CONFED_SET)
                            .contains(&seg_type)
                        {
                            return Err(());
                        }
                        pos += 2 + seg_count * 4;
                        if pos > b.len() {
                            return Err(());
                        }
                    }
                    AttributeData::Bin(b)
                }
            }
            Self::ATOMIC_AGGREGATE => {
                // RFC 4271 §5.1.6: ATOMIC_AGGREGATE has zero-length value
                if len != 0 {
                    return Err(());
                }
                AttributeData::Bin(vec![])
            }
            Self::AGGREGATOR => {
                // RFC 4271 §5.1.7: 2-octet ASN (6 bytes) or 4-octet ASN (8 bytes, RFC 6793 §4.2.3).
                // Always canonicalized to the 8-byte (four-octet ASN) internal form,
                // matching the AS_PATH up-conversion above.
                if len != 6 && len != 8 {
                    return Err(());
                }
                let mut b = vec![0u8; len as usize];
                c.read_exact(&mut b).map_err(|_| ())?;
                if len == 6 {
                    let asn = u16::from_be_bytes([b[0], b[1]]) as u32;
                    let mut out = Vec::with_capacity(8);
                    out.extend_from_slice(&asn.to_be_bytes());
                    out.extend_from_slice(&b[2..]);
                    AttributeData::Bin(out)
                } else {
                    AttributeData::Bin(b)
                }
            }
            Self::COMMUNITY => {
                // RFC 1997 §4: each community value is 4 octets
                if !len.is_multiple_of(4) {
                    return Err(());
                }
                let mut b = vec![0u8; len as usize];
                c.read_exact(&mut b).map_err(|_| ())?;
                AttributeData::Bin(b)
            }
            Self::EXTENDED_COMMUNITY => {
                // RFC 4360 §4: each extended community value is 8 octets
                if !len.is_multiple_of(8) {
                    return Err(());
                }
                let mut b = vec![0u8; len as usize];
                c.read_exact(&mut b).map_err(|_| ())?;
                AttributeData::Bin(b)
            }
            Self::CLUSTER_LIST => {
                // RFC 4456 §8: each cluster ID is 4 octets
                if !len.is_multiple_of(4) {
                    return Err(());
                }
                let mut b = vec![0u8; len as usize];
                c.read_exact(&mut b).map_err(|_| ())?;
                AttributeData::Bin(b)
            }
            Self::LARGE_COMMUNITY => {
                // RFC 8092 §2: each large community value is 12 octets
                if !len.is_multiple_of(12) {
                    return Err(());
                }
                let mut b = vec![0u8; len as usize];
                c.read_exact(&mut b).map_err(|_| ())?;
                AttributeData::Bin(b)
            }
            Self::AS4_PATH => {
                // RFC 6793 §6: malformed if the length is not a multiple of two
                // or too small to carry at least one AS number, or any segment
                // has a zero/inconsistent length or an undefined segment type.
                // Always four-octet-per-AS; there is no two-octet AS4_PATH form.
                if !len.is_multiple_of(2) || len < 6 {
                    return Err(());
                }
                let mut b = vec![0u8; len as usize];
                c.read_exact(&mut b).map_err(|_| ())?;
                let mut pos = 0usize;
                while pos < b.len() {
                    if pos + 2 > b.len() {
                        return Err(());
                    }
                    let seg_type = b[pos];
                    let seg_count = b[pos + 1] as usize;
                    if !(Self::AS_PATH_TYPE_SET..=Self::AS_PATH_TYPE_CONFED_SET).contains(&seg_type)
                        || seg_count == 0
                    {
                        return Err(());
                    }
                    pos += 2 + seg_count * 4;
                    if pos > b.len() {
                        return Err(());
                    }
                }
                AttributeData::Bin(b)
            }
            Self::AS4_AGGREGATOR => {
                // RFC 6793 §6: malformed if the length is not 8.
                if len != 8 {
                    return Err(());
                }
                let mut b = vec![0u8; len as usize];
                c.read_exact(&mut b).map_err(|_| ())?;
                AttributeData::Bin(b)
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

    /// Returns true if any AS number in this (canonical four-octet) AS_PATH
    /// exceeds the two-octet range. RFC 6793 §4.2.2: only in that case does an
    /// OLD BGP speaker also need an accompanying AS4_PATH attribute.
    fn as_path_has_wide_as(&self) -> bool {
        assert_eq!(self.code, Attribute::AS_PATH);
        let buf = self.binary().unwrap();
        let mut pos = 0usize;
        while pos < buf.len() {
            let seg_count = buf[pos + 1] as usize;
            for i in 0..seg_count {
                let start = pos + 2 + i * 4;
                let asn = u32::from_be_bytes(buf[start..start + 4].try_into().unwrap());
                if asn > u16::MAX as u32 {
                    return true;
                }
            }
            pos += 2 + seg_count * 4;
        }
        false
    }

    /// Down-converts this (canonical four-octet) AS_PATH to the two-octet wire
    /// form sent to an OLD BGP speaker (RFC 6793 §4.2.2), substituting
    /// AS_TRANS (23456) for any AS number that doesn't fit in two octets.
    fn as_path_downgrade_2byte(&self) -> Vec<u8> {
        assert_eq!(self.code, Attribute::AS_PATH);
        let buf = self.binary().unwrap();
        let mut out = Vec::with_capacity(buf.len());
        let mut pos = 0usize;
        while pos < buf.len() {
            let seg_type = buf[pos];
            let seg_count = buf[pos + 1] as usize;
            out.push(seg_type);
            out.push(buf[pos + 1]);
            for i in 0..seg_count {
                let start = pos + 2 + i * 4;
                let asn = u32::from_be_bytes(buf[start..start + 4].try_into().unwrap());
                let as2 = if asn > u16::MAX as u32 {
                    Capability::TRANS_ASN
                } else {
                    asn as u16
                };
                out.extend_from_slice(&as2.to_be_bytes());
            }
            pos += 2 + seg_count * 4;
        }
        out
    }

    /// Counts the AS hops in a (canonical four-octet) AS_PATH/AS4_PATH value,
    /// per the RFC 4271 §9.1.2.2 convention also used by RFC 6793 §4.2.3:
    /// AS_SET counts as one hop regardless of its member count, AS_SEQUENCE
    /// entries count individually, and AS_CONFED_SEQUENCE/AS_CONFED_SET do
    /// not count at all.
    fn count_as_hops(bin: &[u8]) -> usize {
        let mut pos = 0usize;
        let mut count = 0usize;
        while pos < bin.len() {
            let seg_type = bin[pos];
            let seg_count = bin[pos + 1] as usize;
            match seg_type {
                Self::AS_PATH_TYPE_SET => count += 1,
                Self::AS_PATH_TYPE_SEQ => count += seg_count,
                _ => {}
            }
            pos += 2 + seg_count * 4;
        }
        count
    }

    /// Copies the leading `n` AS hops from a (canonical four-octet) AS_PATH
    /// value, using the same hop-counting convention as `count_as_hops`.
    /// AS_CONFED_SEQUENCE/AS_CONFED_SET segments are always carried through in
    /// full while still accumulating hops, since confederation boundaries
    /// (RFC 5065) are orthogonal to the OLD/NEW BGP speaker boundary.
    fn as_path_take_prefix(bin: &[u8], mut n: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut pos = 0usize;
        while n > 0 && pos < bin.len() {
            let seg_type = bin[pos];
            let seg_count = bin[pos + 1] as usize;
            let seg_end = pos + 2 + seg_count * 4;
            match seg_type {
                Self::AS_PATH_TYPE_SEQ => {
                    let take = seg_count.min(n);
                    out.push(seg_type);
                    out.push(take as u8);
                    out.extend_from_slice(&bin[pos + 2..pos + 2 + take * 4]);
                    n -= take;
                }
                Self::AS_PATH_TYPE_SET => {
                    out.extend_from_slice(&bin[pos..seg_end]);
                    n -= 1;
                }
                _ => {
                    out.extend_from_slice(&bin[pos..seg_end]);
                }
            }
            pos = seg_end;
        }
        out
    }

    /// Reconstructs the true AS_PATH from a received two-octet-derived
    /// AS_PATH and its accompanying AS4_PATH (RFC 6793 §4.2.3): if `as_path`
    /// has fewer AS hops than `as4_path`, `as4_path` is ignored; otherwise the
    /// leading `len(as_path) - len(as4_path)` hops of `as_path` are prepended
    /// to `as4_path`.
    fn as_path_reconcile(as_path: &[u8], as4_path: &[u8]) -> Vec<u8> {
        let as_path_count = Self::count_as_hops(as_path);
        let as4_path_count = Self::count_as_hops(as4_path);
        if as_path_count < as4_path_count {
            return as_path.to_vec();
        }
        let mut merged = Self::as_path_take_prefix(as_path, as_path_count - as4_path_count);
        merged.extend_from_slice(as4_path);
        merged
    }

    /// Returns the aggregating router's AS number from a (canonical
    /// eight-byte) AGGREGATOR attribute.
    fn aggregator_asn(&self) -> u32 {
        assert_eq!(self.code, Attribute::AGGREGATOR);
        let buf = self.binary().unwrap();
        u32::from_be_bytes(buf[..4].try_into().unwrap())
    }

    /// Down-converts this (canonical eight-byte) AGGREGATOR to the six-byte
    /// wire form sent to an OLD BGP speaker (RFC 6793 §4.2.2), substituting
    /// AS_TRANS (23456) when the aggregating AS doesn't fit in two octets.
    fn aggregator_downgrade_2byte(&self) -> Vec<u8> {
        assert_eq!(self.code, Attribute::AGGREGATOR);
        let buf = self.binary().unwrap();
        let asn = self.aggregator_asn();
        let as2 = if asn > u16::MAX as u32 {
            Capability::TRANS_ASN
        } else {
            asn as u16
        };
        let mut out = Vec::with_capacity(6);
        out.extend_from_slice(&as2.to_be_bytes());
        out.extend_from_slice(&buf[4..8]);
        out
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
    /// Route announcement: NLRIs with their nexthop and path attributes.
    Reach {
        family: Family,
        entries: Vec<PathNlri>,
        /// `None` only for AFIs that carry no nexthop (e.g. Flowspec).
        nexthop: Option<Nexthop>,
        attr: Arc<Vec<Attribute>>,
    },
    /// Route withdrawal.
    Unreach {
        family: Family,
        entries: Vec<PathNlri>,
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
/// `is_ebgp` must be `true` when the message was received from a non-confederation
/// eBGP peer.  When true, LOCAL_PREF, ORIGINATOR_ID, and CLUSTER_LIST are silently
/// discarded per RFC 4271 §5.1.5 and RFC 4456 §8.
///
/// Returns `Err(Notification)` when the session must send that `Notification`
/// and close.  Returns `Ok(iter)` otherwise; the iterator yields the resulting
/// `Message`s (normally 1, 2 for a multi-family UPDATE, 0 for discard-only
/// attribute errors with no NLRIs).
pub fn validate_message(
    msg: ParsedMessage,
    is_ebgp: bool,
) -> Result<impl Iterator<Item = Message>, Notification> {
    let msgs: Vec<Message> = match msg {
        ParsedMessage::Open(open) => vec![Message::Open(open)],
        ParsedMessage::Update(update) => validate_update(update, is_ebgp)?,
        ParsedMessage::Notification(n) => vec![Message::Notification(n)],
        ParsedMessage::Keepalive => vec![Message::Keepalive],
        ParsedMessage::RouteRefresh { family } => vec![Message::RouteRefresh { family }],
    };
    Ok(msgs.into_iter())
}

fn validate_update(update: ParsedUpdate, is_ebgp: bool) -> Result<Vec<Message>, Notification> {
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
            // RFC 4271 §6.3 / BIRD+FRR practice: missing well-known mandatory
            // attributes are treated as withdraw (session-drop per RFC 4271 §6.3,
            // but both BIRD and FRR use treat-as-withdraw for operability).
            // Malformed well-known attrs are already in error_attrs and trigger
            // treat-as-withdraw through the check below; only absent attrs need
            // the missing-mandatory path here.
            // NEXTHOP is extracted into reach.nexthop (from the NEXTHOP attribute
            // for traditional IPv4, or from MP_REACH_NLRI for other families) and
            // never appears in attrs, so its presence is checked via the ReachNlri.
            // RFC 8955 §4: Flowspec routes carry no nexthop in MP_REACH_NLRI.
            let mp_reach_missing_nexthop = mp_reach.as_ref().is_some_and(|r| {
                r.nexthop.is_none()
                    && !matches!(
                        r.family,
                        Family::IPV4_FLOWSPEC
                            | Family::IPV6_FLOWSPEC
                            | Family::IPV4_FLOWSPEC_VPN
                            | Family::IPV6_FLOWSPEC_VPN
                    )
            });
            let missing_mandatory = (reach.is_some() || mp_reach.is_some())
                && (!attrs.iter().any(|a| a.code() == Attribute::ORIGIN)
                    || !attrs.iter().any(|a| a.code() == Attribute::AS_PATH)
                    || reach.as_ref().is_some_and(|r| r.nexthop.is_none())
                    || mp_reach_missing_nexthop);

            // RFC 7606: classify each attribute error.
            // Optional non-transitive: attribute discard (already absent from attrs).
            // Well-known or optional transitive: treat-as-withdraw.
            let treat_as_withdraw = missing_mandatory
                || error_attrs.iter().any(|e| {
                    let optional = e.attr_flags & Attribute::FLAG_OPTIONAL != 0;
                    let transitive = e.attr_flags & Attribute::FLAG_TRANSITIVE != 0;
                    !optional || transitive
                });

            if treat_as_withdraw {
                let mut msgs: Vec<Message> = Vec::new();
                // Convert announced NLRIs to withdrawals.
                for r in reach.into_iter().chain(mp_reach) {
                    msgs.push(Message::Update(Update::Unreach {
                        family: r.family,
                        entries: r.entries,
                    }));
                }
                // Pass through any withdrawals already in the UPDATE.
                for u in unreach.into_iter().chain(mp_unreach) {
                    msgs.push(Message::Update(Update::Unreach {
                        family: u.family,
                        entries: u.entries,
                    }));
                }
                return Ok(msgs);
            }

            // RFC 4271 §5.1.5, RFC 4456 §8: discard iBGP-only attributes received
            // from non-confederation eBGP peers.
            let attrs: Vec<Attribute> = if is_ebgp {
                attrs
                    .into_iter()
                    .filter(|a| {
                        !matches!(
                            a.code(),
                            Attribute::LOCAL_PREF
                                | Attribute::ORIGINATOR_ID
                                | Attribute::CLUSTER_LIST
                        )
                    })
                    .collect()
            } else {
                attrs
            };

            // Normal path: attribute-discard errors are already absent from attrs.
            let attr = Arc::new(attrs);
            let mut msgs: Vec<Message> = Vec::new();

            if let Some(r) = reach {
                msgs.push(Message::Update(Update::Reach {
                    family: r.family,
                    entries: r.entries,
                    nexthop: r.nexthop,
                    attr: attr.clone(),
                }));
            }
            if let Some(u) = unreach {
                msgs.push(Message::Update(Update::Unreach {
                    family: u.family,
                    entries: u.entries,
                }));
            }
            if let Some(r) = mp_reach {
                msgs.push(Message::Update(Update::Reach {
                    family: r.family,
                    entries: r.entries,
                    nexthop: r.nexthop,
                    attr,
                }));
            }
            if let Some(u) = mp_unreach {
                msgs.push(Message::Update(Update::Unreach {
                    family: u.family,
                    entries: u.entries,
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

/// Per-family negotiated ADD-PATH capability state.
#[derive(Default)]
pub struct FamilyState {
    pub addpath_rx: bool,
    pub addpath_tx: bool,
}

pub struct PeerCodec {
    pub extended_length: bool,
    extended_nexthop: bool,
    families: FnvHashMap<Family, FamilyState>,
    /// RFC 6793: the peer did not negotiate the Four-Octet AS Number
    /// capability (i.e. it is an OLD BGP speaker in RFC 6793 terms).
    /// AS_PATH/AGGREGATOR are exchanged in two-octet-ASN wire form with
    /// AS4_PATH/AS4_AGGREGATOR carrying the real four-octet AS numbers.
    pub two_byte_as: bool,
}

impl Default for PeerCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerCodec {
    pub fn new() -> Self {
        PeerCodec {
            extended_length: false,
            extended_nexthop: false,
            families: FnvHashMap::default(),
            two_byte_as: false,
        }
    }

    /// Build a `PeerCodec` from the capabilities advertised by both sides.
    pub fn negotiate(local: &[Capability], remote: &[Capability]) -> Self {
        struct Raw {
            addpath: u8,
            extended_nexthop: bool,
        }
        let parse = |v: &[Capability]| -> FnvHashMap<Family, Raw> {
            let mut h: FnvHashMap<Family, Raw> = FnvHashMap::default();
            for c in v {
                if let Capability::MultiProtocol(f) = c {
                    h.insert(
                        *f,
                        Raw {
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
        let mut lmap = parse(local);
        let mut families = FnvHashMap::default();
        let mut extended_nexthop = false;
        for (f, rc) in parse(remote) {
            if let Some(lc) = lmap.remove(&f) {
                let addpath_rx = lc.addpath & 0x1 > 0 && rc.addpath & 0x2 > 0;
                let addpath_tx = lc.addpath & 0x2 > 0 && rc.addpath & 0x1 > 0;
                if lc.extended_nexthop && rc.extended_nexthop {
                    extended_nexthop = true;
                }
                families.insert(
                    f,
                    FamilyState {
                        addpath_rx,
                        addpath_tx,
                    },
                );
            }
        }
        let has = |v: &[Capability]| v.iter().any(|c| matches!(c, Capability::ExtendedMessage));
        let has_as4 = |v: &[Capability]| {
            v.iter()
                .any(|c| matches!(c, Capability::FourOctetAsNumber(_)))
        };
        PeerCodec {
            extended_length: has(local) && has(remote),
            extended_nexthop,
            families,
            // RFC 6793 SS4.1: both sides must advertise and receive the
            // capability for the session to use four-octet AS numbers.
            two_byte_as: !(has_as4(local) && has_as4(remote)),
        }
    }

    /// Returns true if `family` was negotiated for this session.
    pub fn has_family(&self, family: Family) -> bool {
        self.families.contains_key(&family)
    }

    /// Returns the ADD-PATH state for `family`, or `None` if not negotiated.
    pub fn family_state(&self, family: Family) -> Option<&FamilyState> {
        self.families.get(&family)
    }

    /// Insert or update a family entry (used by MRT/BMP encoders).
    pub fn set_family(&mut self, family: Family, state: FamilyState) {
        self.families.insert(family, state);
    }

    /// Iterate over all negotiated families.
    pub fn families_iter(&self) -> impl Iterator<Item = Family> + '_ {
        self.families.keys().copied()
    }

    pub fn max_message_length(&self) -> usize {
        if self.extended_length {
            Message::MAX_EXTENDED_LENGTH
        } else {
            Message::MAX_LENGTH
        }
    }

    // Encodes MP_REACH_NLRI for `entries` (already sliced to the current start).
    // Returns (attr_bytes_written, n_nlri_encoded).
    fn mp_reach_encode<B: BufMut + AsMut<[u8]>>(
        &self,
        buf_head: usize,
        dst: &mut B,
        family: &Family,
        entries: &[PathNlri],
        nexthop: &Option<Nexthop>,
    ) -> (u16, usize) {
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
        let nh_bytes = nexthop.map(|nh| nh.to_bytes()).unwrap_or_default();
        if matches!(
            *family,
            Family::IPV4_FLOWSPEC
                | Family::IPV6_FLOWSPEC
                | Family::IPV4_FLOWSPEC_VPN
                | Family::IPV6_FLOWSPEC_VPN
        ) {
            // Flowspec carries no nexthop (RFC 8955 §4): nexthop_len=0.
            dst.put_u8(0);
        } else if matches!(family, &Family::IPV4_VPN | &Family::IPV6_VPN) {
            dst.put_u8(8 + nh_bytes.len() as u8);
            dst.put_bytes(0, 8); // 8-byte zero RD (RFC 4364 §4.3.2)
            dst.put_slice(&nh_bytes);
        } else if nh_bytes.len() < 16
            && !matches!(
                family,
                &Family::IPV4_SRPOLICY
                    | &Family::IPV6_SRPOLICY
                    | &Family::IPV4_MC
                    | &Family::IPV6_MC
                    | &Family::L2VPN_EVPN
            )
        {
            // Pad IPv4 nexthop to 16 bytes for RFC 8950 extended-nexthop families.
            // SR Policy and multicast use the nexthop as-is (RFC 4760 requires 4-byte
            // IPv4 nexthop for AFI=1 multicast; SR Policy follows the same rule).
            dst.put_u8(16);
            dst.put_slice(&nh_bytes);
            dst.put_bytes(0, 16 - nh_bytes.len());
        } else {
            dst.put_u8(nh_bytes.len() as u8);
            dst.put_slice(&nh_bytes);
        }
        // SNPA padding
        dst.put_u8(0);
        let addpath = self.families.get(family).is_some_and(|s| s.addpath_tx);
        // EVPN NLRIs are up to 60 bytes (Type-5 with IPv6: 2+58).
        let max_len = if *family == Family::L2VPN_EVPN {
            60 + if addpath { 4 } else { 0 }
        } else {
            1 + 16 + if addpath { 4 } else { 0 }
        };
        let mut n_encoded = 0;
        for item in entries {
            if buf_head + self.max_message_length() > dst.as_mut().len() + max_len {
                if addpath {
                    dst.put_u32(item.path_id);
                }
                item.nlri.encode(dst).unwrap();
                n_encoded += 1;
            } else {
                break;
            }
        }
        let mp_len = (dst.as_mut().len() - pos_head) as u16;
        (&mut dst.as_mut()[pos_bin..])
            .write_u16::<NetworkEndian>(mp_len - 4)
            .unwrap();
        (mp_len, n_encoded)
    }

    // Encodes MP_UNREACH_NLRI for `entries` (already sliced to the current start).
    // Returns (attr_bytes_written, n_nlri_encoded).
    fn mp_unreach_encode<B: BufMut + AsMut<[u8]>>(
        &self,
        buf_head: usize,
        dst: &mut B,
        family: &Family,
        entries: &[PathNlri],
    ) -> (u16, usize) {
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
        let addpath = self.families.get(family).is_some_and(|s| s.addpath_tx);
        let max_len = 1 + 16 + if addpath { 4 } else { 0 };
        let mut n_encoded = 0;
        for item in entries {
            if buf_head + self.max_message_length() > dst.as_mut().len() + max_len {
                if addpath {
                    dst.put_u32(item.path_id);
                }
                item.nlri.encode(dst).unwrap();
                n_encoded += 1;
            } else {
                break;
            }
        }
        let mp_len = (dst.as_mut().len() - pos_head) as u16;
        (&mut dst.as_mut()[pos_bin..])
            .write_u16::<NetworkEndian>(mp_len - 4)
            .unwrap();
        (mp_len, n_encoded)
    }

    // Encodes one wire BGP message starting at `start` (index into the entries
    // slice for Reach/Unreach).  Returns the new start position (start +
    // n_encoded), or 0 for message types that have no entries.
    fn do_encode<B: BufMut + AsMut<[u8]>>(
        &mut self,
        item: &Message,
        dst: &mut B,
        start: usize,
    ) -> Result<usize, Error> {
        let pos_head = dst.as_mut().len();
        dst.put_u64(u64::MAX);
        dst.put_u64(u64::MAX);
        // updated later
        let pos_header_len = dst.as_mut().len();
        dst.put_u16(Message::HEADER_LENGTH);

        let n_encoded = match item {
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
                if !capability.is_empty() {
                    dst.put_u8(2); // capability parameter type
                    let param_len_pos = dst.as_mut().len();
                    dst.put_u8(0);
                    let mut cap_len = 0u8;
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
                0
            }
            Message::Update(Update::Reach {
                family,
                entries,
                nexthop,
                attr,
            }) => {
                let addpath = self.families.get(family).is_some_and(|s| s.addpath_tx);
                // RFC 8950: IPv4 uses MP_REACH_NLRI when extended nexthop is negotiated.
                let ipv4_via_mp = self.extended_nexthop;
                dst.put_u8(Message::UPDATE);
                // No withdrawn routes in a Reach message.
                dst.put_u16(0);
                let pos_attr_len = dst.as_mut().len();
                dst.put_u16(0);
                let mut attr_len: u16 = 0;

                // Write path attributes.  The export layer (export_attrs) is
                // responsible for attribute selection; encode everything given.
                // NEXTHOP is written below for traditional IPv4.
                // MP_REACH/MP_UNREACH are synthesized below for MP paths.
                for a in attr.as_ref() {
                    if !self.two_byte_as {
                        attr_len += a.encode_wire(dst);
                        continue;
                    }
                    match a.code() {
                        Attribute::AS_PATH => {
                            // RFC 6793 §4.2.2: send AS_PATH in two-octet-ASN
                            // wire form to an OLD BGP speaker, with a
                            // companion AS4_PATH carrying the real
                            // four-octet AS numbers whenever one doesn't fit
                            // in two octets.
                            let downgraded = Attribute::new_with_bin(
                                Attribute::AS_PATH,
                                a.as_path_downgrade_2byte(),
                            )
                            .unwrap();
                            attr_len += downgraded.encode_wire(dst);
                            if a.as_path_has_wide_as() {
                                let stripped = a.as_path_strip_confed();
                                let as4_path = Attribute::new_with_bin(
                                    Attribute::AS4_PATH,
                                    stripped.binary().unwrap().clone(),
                                )
                                .unwrap();
                                attr_len += as4_path.encode_wire(dst);
                            }
                        }
                        Attribute::AGGREGATOR => {
                            // RFC 6793 §4.2.2: likewise for AGGREGATOR/AS4_AGGREGATOR.
                            let downgraded = Attribute::new_with_bin(
                                Attribute::AGGREGATOR,
                                a.aggregator_downgrade_2byte(),
                            )
                            .unwrap();
                            attr_len += downgraded.encode_wire(dst);
                            if a.aggregator_asn() > u16::MAX as u32 {
                                let as4_aggregator = Attribute::new_with_bin(
                                    Attribute::AS4_AGGREGATOR,
                                    a.binary().unwrap().clone(),
                                )
                                .unwrap();
                                attr_len += as4_aggregator.encode_wire(dst);
                            }
                        }
                        _ => {
                            attr_len += a.encode_wire(dst);
                        }
                    }
                }

                if *family == Family::IPV4 && !ipv4_via_mp {
                    // Traditional IPv4: NEXTHOP attribute + NLRI section after attrs.
                    if !entries[start..].is_empty()
                        && let Some(nh) = nexthop
                        && let IpAddr::V4(v4) = nh.addr()
                    {
                        let nh_attr =
                            Attribute::new_with_bin(Attribute::NEXTHOP, v4.octets().to_vec())
                                .unwrap();
                        attr_len += nh_attr.encode_wire(dst);
                    }
                    (&mut dst.as_mut()[pos_attr_len..])
                        .write_u16::<NetworkEndian>(attr_len)
                        .unwrap();
                    let max_len = 5 + if addpath { 4 } else { 0 };
                    let mut count = 0;
                    for item in &entries[start..] {
                        if pos_head + self.max_message_length() > dst.as_mut().len() + max_len {
                            if addpath {
                                dst.put_u32(item.path_id);
                            }
                            item.nlri.encode(dst).unwrap();
                            count += 1;
                        } else {
                            break;
                        }
                    }
                    count
                } else {
                    // MP_REACH_NLRI (non-IPv4 or IPv4 with RFC 8950 extended nexthop).
                    let (mp_len, count) =
                        self.mp_reach_encode(pos_head, dst, family, &entries[start..], nexthop);
                    attr_len += mp_len;
                    (&mut dst.as_mut()[pos_attr_len..])
                        .write_u16::<NetworkEndian>(attr_len)
                        .unwrap();
                    count
                }
            }
            Message::Update(Update::Unreach { family, entries }) => {
                let addpath = self.families.get(family).is_some_and(|s| s.addpath_tx);
                // RFC 8950: IPv4 uses MP_UNREACH_NLRI when extended nexthop is negotiated.
                let ipv4_via_mp = self.extended_nexthop;
                dst.put_u8(Message::UPDATE);

                if *family == Family::IPV4 && !ipv4_via_mp {
                    // Traditional IPv4 withdrawn routes section.
                    let pos_withdrawn_len = dst.as_mut().len();
                    dst.put_u16(0);
                    let max_len = 5 + if addpath { 4 } else { 0 };
                    let mut withdrawn_len: u16 = 0;
                    let mut count = 0;
                    for item in &entries[start..] {
                        if pos_head + self.max_message_length() > dst.as_mut().len() + max_len {
                            if addpath {
                                dst.put_u32(item.path_id);
                                withdrawn_len += 4;
                            }
                            withdrawn_len += item.nlri.encode(dst).unwrap();
                            count += 1;
                        } else {
                            break;
                        }
                    }
                    (&mut dst.as_mut()[pos_withdrawn_len..])
                        .write_u16::<NetworkEndian>(withdrawn_len)
                        .unwrap();
                    // Empty path attributes section.
                    dst.put_u16(0);
                    count
                } else {
                    // MP_UNREACH_NLRI.
                    dst.put_u16(0); // withdrawn routes length = 0
                    let pos_attr_len = dst.as_mut().len();
                    dst.put_u16(0);
                    let (mp_len, count) =
                        self.mp_unreach_encode(pos_head, dst, family, &entries[start..]);
                    (&mut dst.as_mut()[pos_attr_len..])
                        .write_u16::<NetworkEndian>(mp_len)
                        .unwrap();
                    count
                }
            }
            Message::Update(Update::EndOfRib(family)) => {
                dst.put_u8(Message::UPDATE);
                // No withdrawn routes.
                dst.put_u16(0);
                let pos_attr_len = dst.as_mut().len();
                dst.put_u16(0);
                let mut attr_len = 0u16;
                if *family != Family::IPV4 {
                    // Non-IPv4 EOR: empty MP_UNREACH_NLRI (RFC 4724 §2).
                    let (mp_len, _) = self.mp_unreach_encode(pos_head, dst, family, &[]);
                    attr_len += mp_len;
                }
                // IPv4 EOR: all-zero length fields, no attributes, no NLRI.
                (&mut dst.as_mut()[pos_attr_len..])
                    .write_u16::<NetworkEndian>(attr_len)
                    .unwrap();
                0
            }
            Message::Notification(err) => {
                dst.put_u8(Message::NOTIFICATION);
                dst.put_u8(err.notification_code());
                dst.put_u8(err.notification_subcode());
                dst.put_slice(err.notification_data());
                0
            }
            Message::Keepalive => {
                dst.put_u8(Message::KEEPALIVE);
                0
            }
            Message::RouteRefresh {
                family: Family(family),
            } => {
                dst.put_u8(Message::ROUTE_REFRESH);
                dst.put_u32(*family);
                0
            }
        };

        let pos_end = dst.as_mut().len();
        (&mut dst.as_mut()[pos_header_len..])
            .write_u16::<NetworkEndian>((pos_end - pos_head) as u16)?;

        Ok(start + n_encoded)
    }

    fn decode_nlri<C: ParseContext>(
        family: Family,
        addpath_rx: bool,
        is_reach: bool,
        c: &mut BgpReader<C>,
        mut len: usize,
    ) -> Result<PathNlri, Notification> {
        let id = if addpath_rx {
            if len < 4 {
                return Err(Notification::UpdateMalformedAttributeList);
            }
            let id = c.read_u32_be()?;
            len -= 4;
            id
        } else {
            0
        };
        Nlri::decode(family, c, len, is_reach).map(|nlri| PathNlri { path_id: id, nlri })
    }
    fn decode_nlri_list(
        family: Family,
        addpath_rx: bool,
        is_reach: bool,
        buf: &[u8],
    ) -> Result<Vec<PathNlri>, Notification> {
        let mut reader = BgpReader::<UpdateCtx>::new(buf);
        let mut entries = Vec::new();
        while reader.remaining_len() > 0 {
            let rest = reader.remaining_len();
            entries.push(Self::decode_nlri(
                family,
                addpath_rx,
                is_reach,
                &mut reader,
                rest,
            )?);
        }
        Ok(entries)
    }

    /// Reconstructs AS_PATH and AGGREGATOR from AS4_PATH/AS4_AGGREGATOR
    /// received from an OLD BGP speaker (RFC 6793 §4.2.3), removing the
    /// AS4_* attributes from `attrs` once consumed. No-op if neither is
    /// present.
    fn reconcile_as4(attrs: &mut Vec<Attribute>) {
        let as4_path = attrs
            .iter()
            .position(|a| a.code() == Attribute::AS4_PATH)
            .map(|i| attrs.remove(i));
        let as4_aggregator = attrs
            .iter()
            .position(|a| a.code() == Attribute::AS4_AGGREGATOR)
            .map(|i| attrs.remove(i));

        // RFC 6793 §4.2.3: if both AGGREGATOR and AS4_AGGREGATOR are present
        // and AGGREGATOR's AS number is not AS_TRANS, the aggregation
        // happened at an OLD router with a genuine two-octet AS, so both
        // AS4_AGGREGATOR and AS4_PATH are untrustworthy and ignored.
        let mut ignore_as4_path = false;
        if let Some(as4_aggregator) = as4_aggregator
            && let Some(idx) = attrs.iter().position(|a| a.code() == Attribute::AGGREGATOR)
        {
            if attrs[idx].aggregator_asn() == Capability::TRANS_ASN as u32 {
                let bin = as4_aggregator.binary().unwrap().clone();
                attrs[idx] = Attribute::new_with_bin(Attribute::AGGREGATOR, bin).unwrap();
            } else {
                ignore_as4_path = true;
            }
        }

        if !ignore_as4_path
            && let Some(as4_path) = as4_path
            && let Some(idx) = attrs.iter().position(|a| a.code() == Attribute::AS_PATH)
        {
            let merged = Attribute::as_path_reconcile(
                attrs[idx].binary().unwrap(),
                as4_path.binary().unwrap(),
            );
            attrs[idx] = Attribute::new_with_bin(Attribute::AS_PATH, merged).unwrap();
        }
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
                    // data: 2-octet max supported version (RFC 4271 §6.2)
                    return Err(Notification::OpenUnsupportedVersionNumber {
                        data: 4u16.to_be_bytes().to_vec(),
                    });
                }
                let mut as_number = c.read_u16::<NetworkEndian>().unwrap() as u32;
                let raw_holdtime = c.read_u16::<NetworkEndian>().unwrap();
                let holdtime =
                    HoldTime::new(raw_holdtime).ok_or(Notification::OpenUnacceptableHoldTime {
                        data: raw_holdtime.to_be_bytes().to_vec(),
                    })?;
                let router_id = c.read_u32::<NetworkEndian>().unwrap();
                // BGP Identifier must be a valid unicast address (RFC 4271 §6.2)
                let router_id_addr = Ipv4Addr::from(router_id);
                if router_id_addr.is_unspecified()
                    || router_id_addr.is_broadcast()
                    || router_id_addr.is_multicast()
                {
                    return Err(Notification::OpenBadBgpIdentifier);
                }
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
                let mut attr = Vec::new();
                let mut reach = Vec::new();
                let mut unreach = Vec::new();
                let mut mp_reach_attr = None;
                let mut mp_unreach_attr = None;
                let mut reach_nexthop: Option<Nexthop> = None;
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
                let mut seen = FnvHashSet::default();
                let attr_end = c.position() + attr_len as u64;
                let mut error_attrs: Vec<AttributeError> = Vec::new();
                let reach_len = buf.len() as u64 - attr_end;
                while c.position() < attr_end {
                    if attr_end < c.position() + 2 {
                        break;
                    }
                    let flags = c.read_u8().unwrap();
                    let code = c.read_u8().unwrap();
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
                    if !seen.insert(code) {
                        if code == Attribute::MP_REACH || code == Attribute::MP_UNREACH {
                            return Err(malformed());
                        }
                        c.set_position(c.position() + alen as u64);
                        continue;
                    }
                    match Attribute::canonical_flags(code) {
                        Some(expected_flags) => {
                            if (flags ^ expected_flags)
                                & (Attribute::FLAG_TRANSITIVE | Attribute::FLAG_OPTIONAL)
                                > 0
                            {
                                c.set_position(c.position() + alen as u64);
                                error_attrs.push(AttributeError {
                                    attr_code: code,
                                    attr_flags: flags,
                                });
                                continue;
                            } else {
                                let cur = c.position();
                                match Attribute::decode(code, flags, &mut c, alen, self.two_byte_as)
                                {
                                    Ok(a) => {
                                        if code == Attribute::MP_REACH {
                                            mp_reach_attr = Some(a);
                                        } else if code == Attribute::MP_UNREACH {
                                            mp_unreach_attr = Some(a);
                                        } else if code == Attribute::NEXTHOP {
                                            reach_nexthop =
                                                a.binary().and_then(|b| Nexthop::from_bytes(b));
                                        } else if (code == Attribute::AS4_PATH
                                            || code == Attribute::AS4_AGGREGATOR)
                                            && !self.two_byte_as
                                        {
                                            // RFC 6793 §6: a NEW BGP speaker that
                                            // receives AS4_PATH/AS4_AGGREGATOR from
                                            // another NEW speaker must discard it.
                                        } else {
                                            attr.push(a);
                                        }
                                    }
                                    Err(_) => {
                                        // RFC 6793 §6: malformed AS4_PATH/AS4_AGGREGATOR
                                        // are discarded outright, not treated as a
                                        // generic (possibly treat-as-withdraw) error.
                                        if code != Attribute::AS4_PATH
                                            && code != Attribute::AS4_AGGREGATOR
                                        {
                                            error_attrs.push(AttributeError {
                                                attr_code: code,
                                                attr_flags: flags,
                                            });
                                        }
                                        c.set_position(cur + alen as u64);
                                        continue;
                                    }
                                }
                            }
                        }
                        None => {
                            if flags & Attribute::FLAG_OPTIONAL == 0 {
                                // Unknown well-known: treat-as-withdraw (RFC 4271 §6.3).
                                error_attrs.push(AttributeError {
                                    attr_code: code,
                                    attr_flags: flags,
                                });
                                c.set_position(c.position() + alen as u64);
                            } else if flags & Attribute::FLAG_TRANSITIVE != 0 {
                                // Unknown optional transitive: store as opaque blob (RFC 4271 §5.1.4).
                                let pos = c.position() as usize;
                                let end = pos + alen as usize;
                                if end > c.get_ref().len() {
                                    return Err(malformed());
                                }
                                let raw = (*c.get_ref())[pos..end].to_vec();
                                c.set_position(end as u64);
                                attr.push(Attribute::new_opaque(code, flags, raw));
                            } else {
                                // Unknown optional non-transitive: silently discard (RFC 4271 §5.1.4).
                                c.set_position(c.position() + alen as u64);
                            }
                        }
                    }
                }

                // v4 eor
                if reach_len == 0 && attr_len == 0 && withdrawn_len == 0 {
                    return Ok(ParsedMessage::Update(ParsedUpdate::EndOfRib(Family::IPV4)));
                }

                if reach_len != 0 || mp_reach_attr.is_some() {
                    if !seen.contains(&Attribute::ORIGIN) || !seen.contains(&Attribute::AS_PATH) {
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
                    let addpath_rx = self
                        .families
                        .get(&Family::IPV4)
                        .ok_or_else(malformed)?
                        .addpath_rx;
                    reach = Self::decode_nlri_list(
                        Family::IPV4,
                        addpath_rx,
                        true,
                        &buf[c.position() as usize..],
                    )?;
                }

                if 0 < withdrawn_len {
                    let addpath_rx = self
                        .families
                        .get(&Family::IPV4)
                        .ok_or_else(malformed)?
                        .addpath_rx;
                    let start = Message::HEADER_LENGTH as usize + 2;
                    unreach = Self::decode_nlri_list(
                        Family::IPV4,
                        addpath_rx,
                        false,
                        &buf[start..start + withdrawn_len as usize],
                    )?;
                }

                let mp_reach: Option<(Family, Vec<PathNlri>, Option<Nexthop>)> = if let Some(a) =
                    mp_reach_attr
                {
                    let err = Notification::UpdateOptionalAttributeError;
                    let buf = a.binary().unwrap();
                    if buf.len() < 5 {
                        return Err(err);
                    }
                    let mut c = Cursor::new(buf);
                    let afi = c.read_u16::<NetworkEndian>().unwrap();
                    let safi = c.read_u8().unwrap();
                    let family = Family((afi as u32) << 16 | safi as u32);
                    let addpath_rx = self.families.get(&family).ok_or_else(malformed)?.addpath_rx;
                    let nexthop_len = c.read_u8().unwrap();
                    if buf.len() < 5 + nexthop_len as usize {
                        return Err(err);
                    }
                    let mut data = Vec::with_capacity(nexthop_len as usize);
                    let nexthop = match nexthop_len {
                        // FlowSpec carries no nexthop (RFC 8955 §4). Any other
                        // family with nexthop_len=0 is malformed.
                        0 if matches!(
                            family,
                            Family::IPV4_FLOWSPEC
                                | Family::IPV6_FLOWSPEC
                                | Family::IPV4_FLOWSPEC_VPN
                                | Family::IPV6_FLOWSPEC_VPN
                        ) =>
                        {
                            None
                        }
                        0 => return Err(err),
                        4 | 16 | 32 => {
                            let pos = c.position() as usize;
                            data.extend_from_slice(&buf[pos..pos + nexthop_len as usize]);
                            c.set_position(pos as u64 + nexthop_len as u64);
                            Nexthop::from_bytes(&data)
                        }
                        // VPN nexthop (RFC 4364 §4.3.2): 8-byte RD (must be 0) + IP address.
                        12 | 24 => {
                            let pos = c.position() as usize;
                            data.extend_from_slice(&buf[pos + 8..pos + nexthop_len as usize]);
                            c.set_position(pos as u64 + nexthop_len as u64);
                            Nexthop::from_bytes(&data)
                        }
                        _ => return Err(err),
                    };
                    c.read_u8().unwrap();
                    let entries = Self::decode_nlri_list(
                        family,
                        addpath_rx,
                        true,
                        &buf[c.position() as usize..],
                    )?;
                    Some((family, entries, nexthop))
                } else {
                    None
                };

                let mp_unreach: Option<(Family, Vec<PathNlri>)> = if let Some(a) = mp_unreach_attr {
                    let err = Notification::UpdateOptionalAttributeError;
                    let buf = a.binary().unwrap();
                    if buf.len() < 3 {
                        return Err(err);
                    }
                    let mut c = Cursor::new(buf);
                    let afi = c.read_u16::<NetworkEndian>().unwrap();
                    let safi = c.read_u8().unwrap();
                    let family = Family((afi as u32) << 16 | safi as u32);
                    let addpath_rx = self.families.get(&family).ok_or_else(malformed)?.addpath_rx;
                    let entries = Self::decode_nlri_list(
                        family,
                        addpath_rx,
                        false,
                        &buf[c.position() as usize..],
                    )?;
                    Some((family, entries))
                } else {
                    None
                };

                // non-IPv4 EOR: MP_UNREACH_NLRI with no NLRIs and no other content (RFC 4724 §2)
                if let Some((family, entries)) = &mp_unreach
                    && entries.is_empty()
                    && reach.is_empty()
                    && mp_reach.as_ref().is_none_or(|(_, e, _)| e.is_empty())
                    && unreach.is_empty()
                    && attr.is_empty()
                    && error_attrs.is_empty()
                {
                    return Ok(ParsedMessage::Update(ParsedUpdate::EndOfRib(*family)));
                }

                if self.two_byte_as {
                    Self::reconcile_as4(&mut attr);
                }

                Ok(ParsedMessage::Update(ParsedUpdate::Routes {
                    reach: (!reach.is_empty()).then_some(ReachNlri {
                        family: Family::IPV4,
                        entries: reach,
                        nexthop: reach_nexthop,
                    }),
                    mp_reach: mp_reach.filter(|(_, entries, _)| !entries.is_empty()).map(
                        |(family, entries, nexthop)| ReachNlri {
                            family,
                            entries,
                            nexthop,
                        },
                    ),
                    attrs: attr,
                    unreach: (!unreach.is_empty()).then_some(UnreachNlri {
                        family: Family::IPV4,
                        entries: unreach,
                    }),
                    mp_unreach: mp_unreach
                        .filter(|(_, entries)| !entries.is_empty())
                        .map(|(family, entries)| UnreachNlri { family, entries }),
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
            Message::KEEPALIVE => {
                if buf.len() != Message::HEADER_LENGTH as usize {
                    return Err(header_len_error);
                }
                Ok(ParsedMessage::Keepalive)
            }
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

    /// Encode `msg` into `dst`, splitting into multiple wire UPDATE messages
    /// if entries exceed the per-message size limit.  Returns the number of
    /// wire messages written (always >= 1).
    pub fn encode_to<B: BufMut + AsMut<[u8]>>(
        &mut self,
        msg: &Message,
        dst: &mut B,
    ) -> Result<usize, Error> {
        let total = match msg {
            Message::Update(Update::Reach { entries, .. }) => entries.len(),
            Message::Update(Update::Unreach { entries, .. }) => entries.len(),
            _ => 0,
        };
        if total == 0 {
            self.do_encode(msg, dst, 0)?;
            return Ok(1);
        }
        let mut start = 0;
        let mut wire_count = 0;
        while start < total {
            let end = self.do_encode(msg, dst, start)?;
            wire_count += 1;
            if end <= start {
                break; // safety guard: no progress
            }
            start = end;
        }
        Ok(wire_count)
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
        assert!(Notification::CeaseHardReset.is_hard_reset());
        // from_notification maps (6,9) to CeaseHardReset
        assert!(Notification::from_notification(6, 9, vec![]).is_hard_reset());
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

#[cfg(test)]
mod nlri_tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn build_update_with_attr(attr_type: u8, attr_value: &[u8]) -> Vec<u8> {
        let mut attr = Vec::new();
        attr.push(0x80u8);
        attr.push(attr_type);
        attr.push(attr_value.len() as u8);
        attr.extend_from_slice(attr_value);
        let attr_len = attr.len() as u16;
        let total_len = (16u16 + 2 + 1 + 2 + 2 + attr_len).to_be_bytes();
        let mut msg = Vec::new();
        msg.extend_from_slice(&[0xFF; 16]);
        msg.extend_from_slice(&total_len);
        msg.push(0x02);
        msg.extend_from_slice(&[0x00, 0x00]);
        msg.extend_from_slice(&attr_len.to_be_bytes());
        msg.extend_from_slice(&attr);
        msg
    }

    #[test]
    fn parse_bogus_ipv4net() {
        let mut buf = vec![128];
        buf.append(&mut Ipv6Addr::from(139930210).octets().to_vec());
        let len = buf.len();
        let mut c = BgpReader::<UpdateCtx>::new(&buf);
        assert!(Ipv4Net::decode(&mut c, len).is_err());
    }

    #[test]
    fn parse_bogus_ipv6net() {
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
            Nlri::decode(Family::IPV4, &mut c, len, true).unwrap(),
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
            Nlri::decode(Family::IPV6, &mut c, len, true).unwrap(),
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
        assert!(Nlri::decode(Family::IPV4_MUP, &mut c, len, true).is_err());
    }

    #[test]
    fn parse_message_rejects_unnegotiated_family_mp_reach() {
        let mut codec = PeerCodec::new();
        let attr_value = [
            0x00, 0x19, // AFI=25 (L2VPN)
            0x46, // SAFI=70 (EVPN)
            0x04, 0xc0, 0xa8, 0x01, 0x01, 0x00,
        ];
        let msg = build_update_with_attr(0x0E, &attr_value);
        assert_eq!(
            codec.parse_message(&msg).err(),
            Some(Notification::UpdateMalformedAttributeList)
        );
    }

    #[test]
    fn parse_message_rejects_unnegotiated_family_mp_unreach() {
        let mut codec = PeerCodec::new();
        let attr_value = [
            0x00, 0x19, // AFI=25 (L2VPN)
            0x46, // SAFI=70 (EVPN)
        ];
        let msg = build_update_with_attr(0x0F, &attr_value);
        assert_eq!(
            codec.parse_message(&msg).err(),
            Some(Notification::UpdateMalformedAttributeList)
        );
    }
}

#[cfg(test)]
mod attribute_tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    fn ipv4_codec() -> PeerCodec {
        let mut c = PeerCodec::new();
        c.set_family(Family::IPV4, FamilyState::default());
        c
    }

    fn ipv4_prefix(addr: &str, mask: u8) -> PathNlri {
        PathNlri::new(Nlri::V4(Ipv4Net {
            addr: addr.parse().unwrap(),
            mask,
        }))
    }

    fn base_attrs(nexthop: Ipv4Addr) -> Vec<Attribute> {
        vec![
            Attribute::new_with_value(Attribute::ORIGIN, 0).unwrap(),
            Attribute::new_with_bin(
                Attribute::AS_PATH,
                vec![Attribute::AS_PATH_TYPE_SEQ, 1, 0x00, 0x00, 0xFD, 0xEA],
            )
            .unwrap(),
            Attribute::new_with_bin(Attribute::NEXTHOP, nexthop.octets().to_vec()).unwrap(),
        ]
    }

    fn round_trip(msg: &Message) -> ParsedMessage {
        let mut framer = ipv4_codec();
        let mut buf = Vec::new();
        framer.encode_to(msg, &mut buf).unwrap();
        framer.parse_message(&buf).unwrap()
    }

    fn update_with_attrs(attrs: Vec<Attribute>) -> Message {
        Message::Update(Update::Reach {
            family: Family::IPV4,
            entries: vec![ipv4_prefix("10.0.0.0", 8)],
            nexthop: None,
            attr: Arc::new(attrs),
        })
    }

    const FLAG_TRANSITIVE: u8 = 0x40;
    const FLAG_OPTIONAL: u8 = 0x80;

    #[test]
    fn canonical_flags_well_known_mandatory() {
        for code in [
            Attribute::ORIGIN,
            Attribute::AS_PATH,
            Attribute::NEXTHOP,
            Attribute::LOCAL_PREF,
            Attribute::ATOMIC_AGGREGATE,
        ] {
            let f =
                Attribute::canonical_flags(code).unwrap_or_else(|| panic!("code {} missing", code));
            assert_eq!(
                f & FLAG_TRANSITIVE,
                FLAG_TRANSITIVE,
                "code {} should be TRANSITIVE",
                code
            );
            assert_eq!(f & FLAG_OPTIONAL, 0, "code {} should not be OPTIONAL", code);
        }
    }

    #[test]
    fn canonical_flags_optional_non_transitive() {
        for code in [
            Attribute::MULTI_EXIT_DESC,
            Attribute::ORIGINATOR_ID,
            Attribute::CLUSTER_LIST,
            Attribute::MP_REACH,
            Attribute::MP_UNREACH,
        ] {
            let f =
                Attribute::canonical_flags(code).unwrap_or_else(|| panic!("code {} missing", code));
            assert_eq!(
                f & FLAG_OPTIONAL,
                FLAG_OPTIONAL,
                "code {} should be OPTIONAL",
                code
            );
            assert_eq!(
                f & FLAG_TRANSITIVE,
                0,
                "code {} should not be TRANSITIVE",
                code
            );
        }
    }

    #[test]
    fn canonical_flags_optional_transitive() {
        for code in [
            Attribute::COMMUNITY,
            Attribute::AGGREGATOR,
            Attribute::EXTENDED_COMMUNITY,
            Attribute::AS4_PATH,
            Attribute::LARGE_COMMUNITY,
        ] {
            let f =
                Attribute::canonical_flags(code).unwrap_or_else(|| panic!("code {} missing", code));
            assert_eq!(
                f & FLAG_OPTIONAL,
                FLAG_OPTIONAL,
                "code {} should be OPTIONAL",
                code
            );
            assert_eq!(
                f & FLAG_TRANSITIVE,
                FLAG_TRANSITIVE,
                "code {} should be TRANSITIVE",
                code
            );
        }
    }

    #[test]
    fn canonical_flags_unknown_returns_none() {
        assert_eq!(Attribute::canonical_flags(0), None);
        assert_eq!(Attribute::canonical_flags(100), None);
        assert_eq!(Attribute::canonical_flags(255), None);
    }

    #[test]
    fn new_with_value_known_code() {
        let a = Attribute::new_with_value(Attribute::ORIGIN, 0).unwrap();
        assert_eq!(a.code(), Attribute::ORIGIN);
        assert_eq!(a.value(), Some(0));
    }

    #[test]
    fn new_with_value_unknown_code_returns_none() {
        assert!(Attribute::new_with_value(255, 0).is_none());
    }

    #[test]
    fn new_with_bin_known_code() {
        let bytes = vec![0xDE, 0xAD];
        let a = Attribute::new_with_bin(Attribute::COMMUNITY, bytes.clone()).unwrap();
        assert_eq!(a.code(), Attribute::COMMUNITY);
        assert_eq!(a.binary(), Some(&bytes));
    }

    #[test]
    fn new_with_bin_unknown_code_returns_none() {
        assert!(Attribute::new_with_bin(200, vec![0x01]).is_none());
    }

    #[test]
    fn attribute_local_pref_round_trip() {
        let mut attrs = base_attrs("192.0.2.1".parse().unwrap());
        attrs.push(Attribute::new_with_value(Attribute::LOCAL_PREF, 200).unwrap());
        match round_trip(&update_with_attrs(attrs)) {
            ParsedMessage::Update(ParsedUpdate::Routes { attrs, .. }) => {
                let lp = attrs
                    .iter()
                    .find(|a| a.code() == Attribute::LOCAL_PREF)
                    .expect("LOCAL_PREF must be present");
                assert_eq!(lp.value(), Some(200));
            }
            _ => panic!("expected Update"),
        }
    }

    #[test]
    fn attribute_as_path_round_trip() {
        let aspath = vec![
            Attribute::AS_PATH_TYPE_SEQ,
            2,
            0x00,
            0x00,
            0xFD,
            0xEA,
            0x00,
            0x01,
            0x00,
            0x00,
        ];
        let attrs = vec![
            Attribute::new_with_value(Attribute::ORIGIN, 0).unwrap(),
            Attribute::new_with_bin(Attribute::AS_PATH, aspath.clone()).unwrap(),
            Attribute::new_with_bin(
                Attribute::NEXTHOP,
                "192.0.2.1".parse::<Ipv4Addr>().unwrap().octets().to_vec(),
            )
            .unwrap(),
            Attribute::new_with_value(Attribute::LOCAL_PREF, 100).unwrap(),
        ];
        match round_trip(&update_with_attrs(attrs)) {
            ParsedMessage::Update(ParsedUpdate::Routes { attrs, .. }) => {
                let ap = attrs
                    .iter()
                    .find(|a| a.code() == Attribute::AS_PATH)
                    .expect("AS_PATH must be present");
                assert_eq!(ap.binary(), Some(&aspath));
            }
            _ => panic!("expected Update"),
        }
    }

    #[test]
    fn attribute_large_community_round_trip() {
        let lc: Vec<u8> = [65001u32, 1u32, 2u32]
            .iter()
            .flat_map(|v| v.to_be_bytes())
            .collect();
        let mut attrs = base_attrs("192.0.2.1".parse().unwrap());
        attrs.push(Attribute::new_with_bin(Attribute::LARGE_COMMUNITY, lc.clone()).unwrap());
        match round_trip(&update_with_attrs(attrs)) {
            ParsedMessage::Update(ParsedUpdate::Routes { attrs, .. }) => {
                let lc_attr = attrs
                    .iter()
                    .find(|a| a.code() == Attribute::LARGE_COMMUNITY)
                    .expect("LARGE_COMMUNITY must be present");
                assert_eq!(lc_attr.binary(), Some(&lc));
            }
            _ => panic!("expected Update"),
        }
    }

    #[test]
    fn attribute_extended_community_round_trip() {
        let ec: Vec<u8> = vec![0x00, 0x02, 0x00, 0x00, 0xFD, 0xE9, 0x00, 0x64];
        let mut attrs = base_attrs("192.0.2.1".parse().unwrap());
        attrs.push(Attribute::new_with_bin(Attribute::EXTENDED_COMMUNITY, ec.clone()).unwrap());
        match round_trip(&update_with_attrs(attrs)) {
            ParsedMessage::Update(ParsedUpdate::Routes { attrs, .. }) => {
                let ec_attr = attrs
                    .iter()
                    .find(|a| a.code() == Attribute::EXTENDED_COMMUNITY)
                    .expect("EXTENDED_COMMUNITY must be present");
                assert_eq!(ec_attr.binary(), Some(&ec));
            }
            _ => panic!("expected Update"),
        }
    }
}

#[cfg(test)]
mod capability_tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn bgp_msg(msg_type: u8, body: &[u8]) -> Vec<u8> {
        let total = (19 + body.len()) as u16;
        let mut buf = vec![0xff; 16];
        buf.extend_from_slice(&total.to_be_bytes());
        buf.push(msg_type);
        buf.extend_from_slice(body);
        buf
    }

    fn open_body(as2: u16, holdtime: u16, router_id: Ipv4Addr, params: &[u8]) -> Vec<u8> {
        let mut body = vec![4u8];
        body.extend_from_slice(&as2.to_be_bytes());
        body.extend_from_slice(&holdtime.to_be_bytes());
        body.extend_from_slice(&u32::from(router_id).to_be_bytes());
        body.push(params.len() as u8);
        body.extend_from_slice(params);
        body
    }

    fn capability_param(cap_bytes: &[u8]) -> Vec<u8> {
        let mut p = vec![2u8, cap_bytes.len() as u8];
        p.extend_from_slice(cap_bytes);
        p
    }

    fn parse_open_caps(cap_bytes: &[u8]) -> Vec<Capability> {
        let params = capability_param(cap_bytes);
        let buf = bgp_msg(
            1,
            &open_body(65001, 90, "192.0.2.1".parse().unwrap(), &params),
        );
        match PeerCodec::new().parse_message(&buf).unwrap() {
            ParsedMessage::Open(Open { capability, .. }) => capability,
            _ => panic!("expected OPEN"),
        }
    }

    fn round_trip(msg: &Message) -> ParsedMessage {
        let mut framer = PeerCodec::new();
        let mut buf = Vec::new();
        framer.encode_to(msg, &mut buf).unwrap();
        framer.parse_message(&buf).unwrap()
    }

    fn open_with(caps: Vec<Capability>) -> Message {
        Message::Open(Open {
            as_number: 65001,
            holdtime: HoldTime::new(90).unwrap(),
            router_id: u32::from("192.0.2.1".parse::<Ipv4Addr>().unwrap()),
            capability: caps,
        })
    }

    fn graceful_restart_bytes(flags: u8, restart_time: u16, families: &[(u16, u8, u8)]) -> Vec<u8> {
        let len = 2 + families.len() as u8 * 4;
        let mut v = vec![64u8, len];
        let restart_word = ((flags as u16) << 12) | (restart_time & 0xfff);
        v.extend_from_slice(&restart_word.to_be_bytes());
        for (afi, safi, af_flags) in families {
            v.extend_from_slice(&afi.to_be_bytes());
            v.push(*safi);
            v.push(*af_flags);
        }
        v
    }

    #[test]
    fn capability_graceful_restart_no_families() {
        let cap = graceful_restart_bytes(0x08, 90, &[]);
        let caps = parse_open_caps(&cap);
        assert_eq!(caps.len(), 1);
        assert!(matches!(
            &caps[0],
            Capability::GracefulRestart { flags: 0x08, restart_time: 90, families }
            if families.is_empty()
        ));
    }

    #[test]
    fn capability_graceful_restart_with_families() {
        let cap = graceful_restart_bytes(0x08, 120, &[(1, 1, 0x80)]);
        let caps = parse_open_caps(&cap);
        assert_eq!(caps.len(), 1);
        match &caps[0] {
            Capability::GracefulRestart {
                flags,
                restart_time,
                families,
            } => {
                assert_eq!(*flags, 0x08);
                assert_eq!(*restart_time, 120);
                assert_eq!(families.len(), 1);
                assert_eq!(families[0], (Family::IPV4, 0x80));
            }
            _ => panic!("expected GracefulRestart"),
        }
    }

    #[test]
    fn capability_graceful_restart_round_trip() {
        let original = open_with(vec![Capability::GracefulRestart {
            flags: 0x08,
            restart_time: 120,
            families: vec![(Family::IPV4, 0x80), (Family::IPV6, 0x00)],
        }]);
        match round_trip(&original) {
            ParsedMessage::Open(Open { capability, .. }) => {
                assert_eq!(capability.len(), 1);
                match &capability[0] {
                    Capability::GracefulRestart {
                        flags,
                        restart_time,
                        families,
                    } => {
                        assert_eq!(*flags, 0x08);
                        assert_eq!(*restart_time, 120);
                        assert_eq!(families.len(), 2);
                        assert!(families.contains(&(Family::IPV4, 0x80)));
                        assert!(families.contains(&(Family::IPV6, 0x00)));
                    }
                    _ => panic!("expected GracefulRestart"),
                }
            }
            _ => panic!("expected OPEN"),
        }
    }

    #[test]
    fn capability_graceful_restart_invalid_len() {
        let cap: &[u8] = &[64, 3, 0x00, 0x5A, 0x00];
        let params = capability_param(cap);
        let buf = bgp_msg(
            1,
            &open_body(65001, 90, "192.0.2.1".parse().unwrap(), &params),
        );
        match PeerCodec::new().parse_message(&buf) {
            Err(Notification::OpenMalformed) => {}
            Ok(_) => panic!("expected error"),
            Err(e) => panic!("unexpected error: {}", e),
        }
    }

    #[test]
    fn capability_add_path_round_trip() {
        let original = open_with(vec![Capability::AddPath(vec![(Family::IPV4, 3)])]);
        match round_trip(&original) {
            ParsedMessage::Open(Open { capability, .. }) => {
                assert_eq!(capability.len(), 1);
                assert!(matches!(
                    &capability[0],
                    Capability::AddPath(v) if *v == [(Family::IPV4, 3)]
                ));
            }
            _ => panic!("expected OPEN"),
        }
    }

    #[test]
    fn capability_add_path_multiple_families() {
        let original = open_with(vec![Capability::AddPath(vec![
            (Family::IPV4, 1),
            (Family::IPV6, 2),
        ])]);
        match round_trip(&original) {
            ParsedMessage::Open(Open { capability, .. }) => {
                assert_eq!(capability.len(), 1);
                match &capability[0] {
                    Capability::AddPath(v) => {
                        assert_eq!(v.len(), 2);
                        assert!(v.contains(&(Family::IPV4, 1)));
                        assert!(v.contains(&(Family::IPV6, 2)));
                    }
                    _ => panic!("expected AddPath"),
                }
            }
            _ => panic!("expected OPEN"),
        }
    }

    #[test]
    fn capability_add_path_invalid_len() {
        let cap: &[u8] = &[69, 3, 0x00, 0x01, 0x01];
        let params = capability_param(cap);
        let buf = bgp_msg(
            1,
            &open_body(65001, 90, "192.0.2.1".parse().unwrap(), &params),
        );
        match PeerCodec::new().parse_message(&buf) {
            Err(Notification::OpenMalformed) => {}
            Ok(_) => panic!("expected error"),
            Err(e) => panic!("unexpected error: {}", e),
        }
    }

    #[test]
    fn capability_enhanced_route_refresh_round_trip() {
        let original = open_with(vec![Capability::EnhancedRouteRefresh]);
        match round_trip(&original) {
            ParsedMessage::Open(Open { capability, .. }) => {
                assert!(
                    capability
                        .iter()
                        .any(|c| matches!(c, Capability::EnhancedRouteRefresh))
                );
            }
            _ => panic!("expected OPEN"),
        }
    }

    fn fqdn_bytes(hostname: &str, domain: &str) -> Vec<u8> {
        let mut v = vec![73u8];
        v.push((2 + hostname.len() + domain.len()) as u8);
        v.push(hostname.len() as u8);
        v.extend_from_slice(hostname.as_bytes());
        v.push(domain.len() as u8);
        v.extend_from_slice(domain.as_bytes());
        v
    }

    #[test]
    fn capability_fqdn_parse() {
        let cap = fqdn_bytes("router1", "example.com");
        let caps = parse_open_caps(&cap);
        assert_eq!(caps.len(), 1);
        assert!(matches!(
            &caps[0],
            Capability::Fqdn { hostname, domain }
            if hostname == "router1" && domain == "example.com"
        ));
    }

    #[test]
    fn capability_fqdn_round_trip() {
        let original = open_with(vec![Capability::Fqdn {
            hostname: "router1".to_string(),
            domain: "example.com".to_string(),
        }]);
        match round_trip(&original) {
            ParsedMessage::Open(Open { capability, .. }) => {
                assert_eq!(capability.len(), 1);
                assert!(matches!(
                    &capability[0],
                    Capability::Fqdn { hostname, domain }
                    if hostname == "router1" && domain == "example.com"
                ));
            }
            _ => panic!("expected OPEN"),
        }
    }

    #[test]
    fn capability_llgr_round_trip() {
        let original = open_with(vec![Capability::LongLivedGracefulRestart(vec![(
            Family::IPV4,
            0x80,
            3600,
        )])]);
        match round_trip(&original) {
            ParsedMessage::Open(Open { capability, .. }) => {
                assert_eq!(capability.len(), 1);
                assert!(matches!(
                    &capability[0],
                    Capability::LongLivedGracefulRestart(v)
                    if *v == [(Family::IPV4, 0x80, 3600)]
                ));
            }
            _ => panic!("expected OPEN"),
        }
    }

    #[test]
    fn negotiate_addpath_rx_only() {
        let local = vec![
            Capability::MultiProtocol(Family::IPV4),
            Capability::AddPath(vec![(Family::IPV4, 1)]),
        ];
        let remote = vec![
            Capability::MultiProtocol(Family::IPV4),
            Capability::AddPath(vec![(Family::IPV4, 2)]),
        ];
        let codec = PeerCodec::negotiate(&local, &remote);
        assert_eq!(codec.families_iter().count(), 1);
        let s = codec.family_state(Family::IPV4).unwrap();
        assert!(s.addpath_rx);
        assert!(!s.addpath_tx);
    }

    #[test]
    fn negotiate_addpath_tx_only() {
        let local = vec![
            Capability::MultiProtocol(Family::IPV4),
            Capability::AddPath(vec![(Family::IPV4, 2)]),
        ];
        let remote = vec![
            Capability::MultiProtocol(Family::IPV4),
            Capability::AddPath(vec![(Family::IPV4, 1)]),
        ];
        let codec = PeerCodec::negotiate(&local, &remote);
        assert_eq!(codec.families_iter().count(), 1);
        let s = codec.family_state(Family::IPV4).unwrap();
        assert!(!s.addpath_rx);
        assert!(s.addpath_tx);
    }

    #[test]
    fn negotiate_addpath_both() {
        let local = vec![
            Capability::MultiProtocol(Family::IPV4),
            Capability::AddPath(vec![(Family::IPV4, 3)]),
        ];
        let remote = vec![
            Capability::MultiProtocol(Family::IPV4),
            Capability::AddPath(vec![(Family::IPV4, 3)]),
        ];
        let codec = PeerCodec::negotiate(&local, &remote);
        assert_eq!(codec.families_iter().count(), 1);
        let s = codec.family_state(Family::IPV4).unwrap();
        assert!(s.addpath_rx);
        assert!(s.addpath_tx);
    }

    #[test]
    fn negotiate_addpath_no_match() {
        let local = vec![
            Capability::MultiProtocol(Family::IPV4),
            Capability::AddPath(vec![(Family::IPV4, 1)]),
        ];
        let remote = vec![
            Capability::MultiProtocol(Family::IPV4),
            Capability::AddPath(vec![(Family::IPV4, 1)]),
        ];
        let codec = PeerCodec::negotiate(&local, &remote);
        assert_eq!(codec.families_iter().count(), 1);
        let s = codec.family_state(Family::IPV4).unwrap();
        assert!(!s.addpath_rx);
        assert!(!s.addpath_tx);
    }

    #[test]
    fn negotiate_addpath_mismatched_family() {
        let local = vec![
            Capability::MultiProtocol(Family::IPV4),
            Capability::MultiProtocol(Family::IPV6),
            Capability::AddPath(vec![(Family::IPV4, 3)]),
        ];
        let remote = vec![
            Capability::MultiProtocol(Family::IPV4),
            Capability::MultiProtocol(Family::IPV6),
            Capability::AddPath(vec![(Family::IPV6, 3)]),
        ];
        let codec = PeerCodec::negotiate(&local, &remote);
        assert_eq!(codec.families_iter().count(), 2);
        for f in [Family::IPV4, Family::IPV6] {
            let s = codec.family_state(f).unwrap();
            assert!(!s.addpath_rx);
            assert!(!s.addpath_tx);
        }
    }

    #[test]
    fn capability_unknown_preserved() {
        let cap: &[u8] = &[200, 2, 0xAB, 0xCD];
        let caps = parse_open_caps(cap);
        assert_eq!(caps.len(), 1);
        assert!(matches!(
            &caps[0],
            Capability::Unknown { code: 200, bin }
            if bin == &[0xAB, 0xCD]
        ));
    }

    #[test]
    fn capability_extended_nexthop_round_trip() {
        let original = open_with(vec![Capability::ExtendedNexthop(vec![(
            Family::IPV4,
            Family::AFI_IP6,
        )])]);
        match round_trip(&original) {
            ParsedMessage::Open(Open { capability, .. }) => {
                assert_eq!(capability.len(), 1);
                match &capability[0] {
                    Capability::ExtendedNexthop(v) => {
                        assert_eq!(v.len(), 1);
                        assert_eq!(v[0], (Family::IPV4, Family::AFI_IP6));
                    }
                    _ => panic!("expected ExtendedNexthop"),
                }
            }
            _ => panic!("expected OPEN"),
        }
    }

    #[test]
    fn negotiate_extended_nexthop_bilateral() {
        let local = vec![
            Capability::MultiProtocol(Family::IPV4),
            Capability::ExtendedNexthop(vec![(Family::IPV4, Family::AFI_IP6)]),
        ];
        let remote = vec![
            Capability::MultiProtocol(Family::IPV4),
            Capability::ExtendedNexthop(vec![(Family::IPV4, Family::AFI_IP6)]),
        ];
        let codec = PeerCodec::negotiate(&local, &remote);
        assert_eq!(codec.families_iter().count(), 1);
        assert!(codec.has_family(Family::IPV4));
    }

    #[test]
    fn negotiate_extended_nexthop_unilateral() {
        let local = vec![
            Capability::MultiProtocol(Family::IPV4),
            Capability::ExtendedNexthop(vec![(Family::IPV4, Family::AFI_IP6)]),
        ];
        let remote = vec![Capability::MultiProtocol(Family::IPV4)];
        let codec = PeerCodec::negotiate(&local, &remote);
        assert_eq!(codec.families_iter().count(), 1);
    }
}

#[cfg(test)]
mod framer_tests {
    use super::*;
    use bytes::BytesMut;

    fn keepalive_bytes() -> Vec<u8> {
        let mut buf = vec![0xff; 16];
        buf.extend_from_slice(&19u16.to_be_bytes());
        buf.push(4);
        buf
    }

    fn bgp_msg(msg_type: u8, body: &[u8]) -> Vec<u8> {
        let total = (19 + body.len()) as u16;
        let mut buf = vec![0xff; 16];
        buf.extend_from_slice(&total.to_be_bytes());
        buf.push(msg_type);
        buf.extend_from_slice(body);
        buf
    }

    fn default_framer() -> PeerCodec {
        PeerCodec::new()
    }

    #[test]
    fn framer_empty_buffer() {
        let mut framer = default_framer();
        let mut buf = BytesMut::new();
        assert!(matches!(framer.try_parse(&mut buf), Ok(None)));
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn framer_incomplete_header() {
        let mut framer = default_framer();
        let mut buf = BytesMut::from(&[0xff; 10][..]);
        assert!(matches!(framer.try_parse(&mut buf), Ok(None)));
        assert_eq!(buf.len(), 10);
    }

    #[test]
    fn framer_complete_keepalive() {
        let mut framer = default_framer();
        let mut buf = BytesMut::from(keepalive_bytes().as_slice());
        let result = framer.try_parse(&mut buf).unwrap();
        assert!(matches!(result, Some(ParsedMessage::Keepalive)));
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn framer_partial_message() {
        let bytes = keepalive_bytes();
        let mut framer = default_framer();
        let mut buf = BytesMut::from(&bytes[..10]);
        assert!(matches!(framer.try_parse(&mut buf), Ok(None)));
        assert_eq!(buf.len(), 10);
        buf.extend_from_slice(&bytes[10..]);
        let result = framer.try_parse(&mut buf).unwrap();
        assert!(matches!(result, Some(ParsedMessage::Keepalive)));
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn framer_two_messages_in_buffer() {
        let mut framer = default_framer();
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&keepalive_bytes());
        buf.extend_from_slice(&keepalive_bytes());
        assert_eq!(buf.len(), 38);
        let r1 = framer.try_parse(&mut buf).unwrap();
        assert!(matches!(r1, Some(ParsedMessage::Keepalive)));
        assert_eq!(buf.len(), 19);
        let r2 = framer.try_parse(&mut buf).unwrap();
        assert!(matches!(r2, Some(ParsedMessage::Keepalive)));
        assert_eq!(buf.len(), 0);
        assert!(matches!(framer.try_parse(&mut buf), Ok(None)));
    }

    #[test]
    fn framer_message_then_partial() {
        let mut framer = default_framer();
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&keepalive_bytes());
        buf.extend_from_slice(&keepalive_bytes()[..5]);
        assert_eq!(buf.len(), 24);
        let r1 = framer.try_parse(&mut buf).unwrap();
        assert!(matches!(r1, Some(ParsedMessage::Keepalive)));
        assert_eq!(buf.len(), 5);
        assert!(matches!(framer.try_parse(&mut buf), Ok(None)));
        assert_eq!(buf.len(), 5);
    }

    #[test]
    fn framer_header_length_below_minimum() {
        let mut buf: Vec<u8> = vec![0xff; 16];
        buf.extend_from_slice(&10u16.to_be_bytes());
        buf.push(4);
        let mut framer = default_framer();
        let mut bmut = BytesMut::from(buf.as_slice());
        match framer.try_parse(&mut bmut) {
            Err(Notification::BadMessageLength { .. }) => {}
            other => panic!("expected BadMessageLength, got {:?}", other.map(|_| "ok")),
        }
    }

    #[test]
    fn framer_header_length_exceeds_max() {
        let mut buf: Vec<u8> = vec![0xff; 16];
        buf.extend_from_slice(&5000u16.to_be_bytes());
        buf.push(4);
        let mut framer = default_framer();
        let mut bmut = BytesMut::from(buf.as_slice());
        match framer.try_parse(&mut bmut) {
            Err(Notification::BadMessageLength { .. }) => {}
            other => panic!("expected BadMessageLength, got {:?}", other.map(|_| "ok")),
        }
    }

    #[test]
    fn framer_unknown_message_type() {
        let buf = bgp_msg(99, &[]);
        let mut framer = default_framer();
        let mut bmut = BytesMut::from(buf.as_slice());
        match framer.try_parse(&mut bmut) {
            Err(Notification::BadMessageType { .. }) => {}
            other => panic!("expected BadMessageType, got {:?}", other.map(|_| "ok")),
        }
    }

    #[test]
    fn framer_mixed_message_types() {
        let mut framer = {
            let mut c = PeerCodec::new();
            c.set_family(Family::IPV4, FamilyState::default());
            c
        };
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&keepalive_bytes());
        buf.extend_from_slice(&bgp_msg(5, &[0x00, 0x01, 0x00, 0x01]));
        let m1 = framer.try_parse(&mut buf).unwrap();
        assert!(matches!(m1, Some(ParsedMessage::Keepalive)));
        let m2 = framer.try_parse(&mut buf).unwrap();
        assert!(matches!(
            m2,
            Some(ParsedMessage::RouteRefresh { family }) if family == Family::IPV4
        ));
        assert!(matches!(framer.try_parse(&mut buf), Ok(None)));
    }

    fn extended_framer() -> PeerCodec {
        let cap = vec![
            Capability::MultiProtocol(Family::IPV4),
            Capability::FourOctetAsNumber(65001),
            Capability::ExtendedMessage,
        ];
        PeerCodec::negotiate(&cap, &cap)
    }

    #[test]
    fn framer_extended_accepts_large_message() {
        let mut framer = extended_framer();
        assert!(framer.extended_length);
        let body = vec![0u8; 5000 - 19];
        let buf = bgp_msg(3, &body);
        let mut bmut = BytesMut::from(buf.as_slice());
        if let Err(Notification::BadMessageLength { .. }) = framer.try_parse(&mut bmut) {
            panic!("extended framer must not reject messages <= 65535 bytes")
        }
    }

    #[test]
    fn framer_default_rejects_large_message() {
        let body = vec![0u8; 5000 - 19];
        let buf = bgp_msg(4, &body);
        let mut framer = default_framer();
        let mut bmut = BytesMut::from(buf.as_slice());
        match framer.try_parse(&mut bmut) {
            Err(Notification::BadMessageLength { .. }) => {}
            other => panic!(
                "default framer must reject messages > 4096 bytes, got {:?}",
                other.map(|_| "ok")
            ),
        }
    }
}

#[cfg(test)]
mod message_tests {
    use super::*;
    use bytes::BytesMut;
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
        let mut codec = {
            let mut c = PeerCodec::new();
            c.set_family(Family::IPV6, Default::default());
            c
        };
        assert!(codec.parse_message(&buf).is_ok());
    }

    #[test]
    fn parse_ipv6_update() {
        let buf: &[u8] = &[
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0x00, 0x70, 0x02, 0x00, 0x00, 0x00, 0x59, 0x40, 0x01, 0x01, 0x02, 0x40,
            0x02, 0x00, 0x80, 0x04, 0x04, 0x00, 0x00, 0x00, 0x14, 0x40, 0x05, 0x04, 0x00, 0x00,
            0x00, 0x64, 0x80, 0x0e, 0x41, 0x00, 0x02, 0x01, 0x10, 0x20, 0x03, 0x00, 0xde, 0x20,
            0x16, 0x01, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x15, 0x00, 0x40, 0x20,
            0x03, 0x00, 0xde, 0x20, 0x16, 0x01, 0x27, 0x40, 0x20, 0x03, 0x00, 0xde, 0x20, 0x16,
            0x01, 0x24, 0x3f, 0x20, 0x03, 0x00, 0xde, 0x20, 0x16, 0x01, 0x28, 0x7f, 0x20, 0x03,
            0x00, 0xde, 0x20, 0x16, 0x01, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12,
        ];
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
        let mut codec = {
            let mut c = PeerCodec::new();
            c.set_family(Family::IPV6, Default::default());
            c
        };
        let msg = codec.parse_message(buf).unwrap();
        match msg {
            ParsedMessage::Update(ParsedUpdate::Routes { mp_reach, .. }) => {
                let s = mp_reach.unwrap();
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
        let mut msg = Message::Update(Update::Reach {
            family: Family::IPV4,
            entries: net.iter().cloned().map(PathNlri::new).collect(),
            nexthop: None,
            attr: Arc::new(vec![
                Attribute::new_with_value(Attribute::ORIGIN, 0).unwrap(),
                Attribute::new_with_bin(Attribute::AS_PATH, vec![2, 1, 1, 0, 0, 0]).unwrap(),
                Attribute::new_with_bin(Attribute::NEXTHOP, vec![0, 0, 0, 0]).unwrap(),
            ]),
        });
        let codec = {
            let mut c = PeerCodec::new();
            c.set_family(Family::IPV4, Default::default());
            c
        };
        let mut txbuf = BytesMut::with_capacity(4096);
        let mut framer = codec;
        framer.encode_to(&msg, &mut txbuf).unwrap();
        let mut recv = Vec::new();
        loop {
            match framer.try_parse(&mut txbuf).expect("failed to decode") {
                Some(ParsedMessage::Update(ParsedUpdate::Routes { reach, .. })) => {
                    recv.append(&mut reach.unwrap().entries)
                }
                Some(_) => {}
                None => break,
            }
        }
        assert_eq!(recv.len(), net.len());
        for n in &recv {
            assert!(set.remove(n));
        }
        assert_eq!(set.len(), 0);
        msg = Message::Update(Update::Unreach {
            family: Family::IPV4,
            entries: net.iter().cloned().map(PathNlri::new).collect(),
        });
        for n in &net {
            set.insert(PathNlri::new(n.clone()));
        }
        framer.encode_to(&msg, &mut txbuf).unwrap();
        let mut withdrawn = Vec::new();
        loop {
            match framer.try_parse(&mut txbuf).expect("failed to decode") {
                Some(ParsedMessage::Update(ParsedUpdate::Routes { unreach, .. })) => {
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
        let msg = Message::Update(Update::Reach {
            family: Family::IPV6,
            entries: net.iter().cloned().map(PathNlri::new).collect(),
            nexthop: None,
            attr: Arc::new(vec![
                Attribute::new_with_value(Attribute::ORIGIN, 0).unwrap(),
                Attribute::new_with_bin(Attribute::AS_PATH, vec![2, 1, 1, 0, 0, 0]).unwrap(),
                Attribute::new_with_bin(Attribute::NEXTHOP, (0..31).collect::<Vec<u8>>()).unwrap(),
            ]),
        });
        let codec = {
            let mut c = PeerCodec::new();
            c.set_family(Family::IPV6, Default::default());
            c
        };
        let mut txbuf = BytesMut::with_capacity(4096);
        let mut framer = codec;
        framer.encode_to(&msg, &mut txbuf).unwrap();
        let mut recv = Vec::new();
        loop {
            match framer.try_parse(&mut txbuf).expect("failed to decode") {
                Some(ParsedMessage::Update(ParsedUpdate::Routes { mp_reach, .. })) => {
                    recv.append(&mut mp_reach.unwrap().entries)
                }
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
        let msg = Message::Update(Update::Unreach {
            family: Family::IPV6,
            entries: net.iter().cloned().map(PathNlri::new).collect(),
        });
        let codec = {
            let mut c = PeerCodec::new();
            c.set_family(Family::IPV6, Default::default());
            c
        };
        let mut txbuf = BytesMut::with_capacity(4096);
        let mut framer = codec;
        framer.encode_to(&msg, &mut txbuf).unwrap();
        let mut recv = Vec::new();
        loop {
            match framer.try_parse(&mut txbuf).expect("failed to decode") {
                Some(ParsedMessage::Update(ParsedUpdate::Routes { mp_unreach, .. })) => {
                    recv.append(&mut mp_unreach.unwrap().entries)
                }
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
    fn negotiate_extended_message_both_sides() {
        let cap = vec![
            Capability::MultiProtocol(Family::IPV4),
            Capability::FourOctetAsNumber(65001),
            Capability::ExtendedMessage,
        ];
        let codec = PeerCodec::negotiate(&cap, &cap);
        assert!(
            codec.extended_length,
            "extended_length must be true when both sides advertise ExtendedMessage"
        );
    }

    #[test]
    fn negotiate_extended_message_one_side_only() {
        let local = vec![
            Capability::MultiProtocol(Family::IPV4),
            Capability::FourOctetAsNumber(65001),
            Capability::ExtendedMessage,
        ];
        let remote = vec![
            Capability::MultiProtocol(Family::IPV4),
            Capability::FourOctetAsNumber(65002),
        ];
        let codec = PeerCodec::negotiate(&local, &remote);
        assert!(
            !codec.extended_length,
            "extended_length must be false when only one side advertises ExtendedMessage"
        );
    }
}

#[cfg(test)]
mod misc_tests {
    use super::*;
    use bytes::{BufMut, BytesMut};

    fn bgp_msg(msg_type: u8, body: &[u8]) -> Vec<u8> {
        let total = (19 + body.len()) as u16;
        let mut buf = vec![0xff; 16];
        buf.extend_from_slice(&total.to_be_bytes());
        buf.push(msg_type);
        buf.extend_from_slice(body);
        buf
    }

    fn default_codec() -> PeerCodec {
        PeerCodec::new()
    }

    fn round_trip(msg: &Message) -> ParsedMessage {
        let mut framer = default_codec();
        let mut buf = BytesMut::new();
        framer.encode_to(msg, &mut buf).unwrap();
        framer.parse_message(&buf).unwrap()
    }

    #[test]
    fn keepalive_parse() {
        let buf = bgp_msg(4, &[]);
        let mut codec = default_codec();
        assert!(matches!(
            codec.parse_message(&buf).unwrap(),
            ParsedMessage::Keepalive
        ));
    }

    #[test]
    fn keepalive_round_trip() {
        match round_trip(&Message::Keepalive) {
            ParsedMessage::Keepalive => {}
            _ => panic!("expected Keepalive"),
        }
    }

    #[test]
    fn keepalive_with_extra_body_is_error() {
        let buf = bgp_msg(4, &[0x00]);
        let mut codec = default_codec();
        match codec.parse_message(&buf) {
            Err(Notification::BadMessageLength { .. }) => {}
            other => panic!("expected BadMessageLength, got {:?}", other.err()),
        }
    }

    #[test]
    fn notification_parse() {
        let body: &[u8] = &[0x01, 0x02, 0x00, 0x13];
        let buf = bgp_msg(3, body);
        let mut codec = default_codec();
        match codec.parse_message(&buf).unwrap() {
            ParsedMessage::Notification(err) => {
                assert_eq!(err.notification_code(), 1);
                assert_eq!(err.notification_subcode(), 2);
                assert_eq!(err.notification_data(), &[0x00u8, 0x13]);
            }
            _ => panic!("expected Notification"),
        }
    }

    #[test]
    fn notification_parse_no_data() {
        let body: &[u8] = &[0x04, 0x00];
        let buf = bgp_msg(3, body);
        let mut codec = default_codec();
        match codec.parse_message(&buf).unwrap() {
            ParsedMessage::Notification(err) => {
                assert_eq!(err.notification_code(), 4);
                assert_eq!(err.notification_subcode(), 0);
                assert!(err.notification_data().is_empty());
            }
            _ => panic!("expected Notification"),
        }
    }

    #[test]
    fn notification_round_trip() {
        let original = Message::Notification(Notification::BadMessageLength {
            data: vec![0xDE, 0xAD, 0xBE, 0xEF],
        });
        match round_trip(&original) {
            ParsedMessage::Notification(err) => {
                assert_eq!(err.notification_code(), 1);
                assert_eq!(err.notification_subcode(), 2);
                assert_eq!(err.notification_data(), &[0xDEu8, 0xAD, 0xBE, 0xEF]);
            }
            _ => panic!("expected Notification"),
        }
    }

    #[test]
    fn bgerror_from_notification_known_codes() {
        assert!(matches!(
            Notification::from_notification(1, 2, vec![]),
            Notification::BadMessageLength { .. }
        ));
        assert!(matches!(
            Notification::from_notification(1, 3, vec![]),
            Notification::BadMessageType { .. }
        ));
        assert!(matches!(
            Notification::from_notification(2, 0, vec![]),
            Notification::OpenMalformed
        ));
        assert!(matches!(
            Notification::from_notification(2, 4, vec![]),
            Notification::OpenUnsupportedOptionalParameter { .. }
        ));
        assert!(matches!(
            Notification::from_notification(2, 6, vec![]),
            Notification::OpenUnacceptableHoldTime { .. }
        ));
        assert!(matches!(
            Notification::from_notification(3, 1, vec![]),
            Notification::UpdateMalformedAttributeList
        ));
        assert!(matches!(
            Notification::from_notification(7, 1, vec![]),
            Notification::RouteRefreshInvalidLength { .. }
        ));
    }

    #[test]
    fn bgerror_from_notification_unknown_code() {
        let err = Notification::from_notification(99, 0, vec![0xAB]);
        assert!(matches!(
            err,
            Notification::Other {
                code: 99,
                subcode: 0,
                ..
            }
        ));
    }

    #[test]
    fn bgerror_notification_code_round_trip() {
        let err = Notification::BadMessageLength {
            data: vec![0x10, 0x00],
        };
        assert_eq!(err.notification_code(), 1);
        assert_eq!(err.notification_subcode(), 2);
        assert_eq!(err.notification_data(), &[0x10, 0x00]);
        let err = Notification::FsmUnexpectedState { state: 3 };
        assert_eq!(err.notification_code(), 5);
        assert_eq!(err.notification_subcode(), 3);
    }

    #[test]
    fn route_refresh_ipv4() {
        let body: &[u8] = &[0x00, 0x01, 0x00, 0x01];
        let buf = bgp_msg(5, body);
        let mut codec = default_codec();
        match codec.parse_message(&buf).unwrap() {
            ParsedMessage::RouteRefresh { family } => {
                assert_eq!(family, Family::IPV4);
            }
            _ => panic!("expected RouteRefresh"),
        }
    }

    #[test]
    fn route_refresh_ipv6() {
        let body: &[u8] = &[0x00, 0x02, 0x00, 0x01];
        let buf = bgp_msg(5, body);
        let mut codec = default_codec();
        match codec.parse_message(&buf).unwrap() {
            ParsedMessage::RouteRefresh { family } => {
                assert_eq!(family, Family::IPV6);
            }
            _ => panic!("expected RouteRefresh"),
        }
    }

    #[test]
    fn route_refresh_round_trip() {
        let original = Message::RouteRefresh {
            family: Family::IPV4,
        };
        match round_trip(&original) {
            ParsedMessage::RouteRefresh { family } => {
                assert_eq!(family, Family::IPV4);
            }
            _ => panic!("expected RouteRefresh"),
        }
    }

    #[test]
    fn route_refresh_too_long() {
        let body: &[u8] = &[0x00, 0x01, 0x00, 0x01, 0xFF];
        let buf = bgp_msg(5, body);
        let mut codec = default_codec();
        match codec.parse_message(&buf) {
            Err(Notification::RouteRefreshInvalidLength { .. }) => {}
            Ok(_) => panic!("expected error"),
            Err(e) => panic!("unexpected error: {}", e),
        }
    }

    #[test]
    fn bad_message_type() {
        let buf = bgp_msg(99, &[]);
        let mut codec = default_codec();
        match codec.parse_message(&buf) {
            Err(Notification::BadMessageType { .. }) => {}
            Ok(_) => panic!("expected error"),
            Err(e) => panic!("unexpected error: {}", e),
        }
    }

    #[test]
    fn parse_message_too_short_buffer() {
        let buf: Vec<u8> = vec![0xff; 10];
        let mut codec = default_codec();
        match codec.parse_message(&buf) {
            Err(Notification::BadMessageLength { .. }) => {}
            Ok(_) => panic!("expected error"),
            Err(e) => panic!("unexpected error: {}", e),
        }
    }

    #[test]
    fn framer_bad_header_length() {
        let mut buf = BytesMut::with_capacity(19);
        buf.extend_from_slice(&[0xff; 16]);
        buf.extend_from_slice(&10u16.to_be_bytes());
        buf.put_u8(4);
        let mut framer = PeerCodec::new();
        match framer.try_parse(&mut buf) {
            Err(Notification::BadMessageLength { .. }) => {}
            Ok(_) => panic!("expected error"),
            Err(e) => panic!("unexpected error: {}", e),
        }
    }
}

#[cfg(test)]
mod open_tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn bgp_msg(msg_type: u8, body: &[u8]) -> Vec<u8> {
        let total = (19 + body.len()) as u16;
        let mut buf = vec![0xff; 16];
        buf.extend_from_slice(&total.to_be_bytes());
        buf.push(msg_type);
        buf.extend_from_slice(body);
        buf
    }

    fn open_body(as2: u16, holdtime: u16, router_id: Ipv4Addr, params: &[u8]) -> Vec<u8> {
        let mut body = vec![4u8];
        body.extend_from_slice(&as2.to_be_bytes());
        body.extend_from_slice(&holdtime.to_be_bytes());
        body.extend_from_slice(&u32::from(router_id).to_be_bytes());
        body.push(params.len() as u8);
        body.extend_from_slice(params);
        body
    }

    fn capability_param(cap_bytes: &[u8]) -> Vec<u8> {
        let mut p = vec![2u8, cap_bytes.len() as u8];
        p.extend_from_slice(cap_bytes);
        p
    }

    fn default_codec() -> PeerCodec {
        PeerCodec::new()
    }

    #[test]
    fn open_minimal_parse() {
        let buf = bgp_msg(1, &open_body(65001, 90, "192.0.2.1".parse().unwrap(), &[]));
        let mut codec = default_codec();
        match codec.parse_message(&buf).unwrap() {
            ParsedMessage::Open(Open {
                as_number,
                holdtime,
                router_id,
                capability,
            }) => {
                assert_eq!(as_number, 65001);
                assert_eq!(holdtime, HoldTime::new(90).unwrap());
                assert_eq!(
                    router_id,
                    u32::from("192.0.2.1".parse::<Ipv4Addr>().unwrap())
                );
                assert!(capability.is_empty());
            }
            _ => panic!("expected OPEN"),
        }
    }

    #[test]
    fn open_with_multiprotocol_ipv4() {
        let cap: &[u8] = &[0x01, 0x04, 0x00, 0x01, 0x00, 0x01];
        let params = capability_param(cap);
        let buf = bgp_msg(
            1,
            &open_body(65001, 90, "192.0.2.1".parse().unwrap(), &params),
        );
        let mut codec = default_codec();
        match codec.parse_message(&buf).unwrap() {
            ParsedMessage::Open(Open { capability, .. }) => {
                assert_eq!(capability.len(), 1);
                assert!(
                    matches!(&capability[0], Capability::MultiProtocol(f) if *f == Family::IPV4)
                );
            }
            _ => panic!("expected OPEN"),
        }
    }

    #[test]
    fn open_with_multiprotocol_ipv6() {
        let cap: &[u8] = &[0x01, 0x04, 0x00, 0x02, 0x00, 0x01];
        let params = capability_param(cap);
        let buf = bgp_msg(
            1,
            &open_body(65001, 90, "192.0.2.1".parse().unwrap(), &params),
        );
        let mut codec = default_codec();
        match codec.parse_message(&buf).unwrap() {
            ParsedMessage::Open(Open { capability, .. }) => {
                assert_eq!(capability.len(), 1);
                assert!(
                    matches!(&capability[0], Capability::MultiProtocol(f) if *f == Family::IPV6)
                );
            }
            _ => panic!("expected OPEN"),
        }
    }

    #[test]
    fn open_with_four_octet_asn() {
        let four_byte_asn: u32 = 131072;
        let mut cap = vec![0x41u8, 0x04];
        cap.extend_from_slice(&four_byte_asn.to_be_bytes());
        let params = capability_param(&cap);
        let buf = bgp_msg(
            1,
            &open_body(23456, 90, "192.0.2.1".parse().unwrap(), &params),
        );
        let mut codec = default_codec();
        match codec.parse_message(&buf).unwrap() {
            ParsedMessage::Open(Open {
                as_number,
                capability,
                ..
            }) => {
                assert_eq!(as_number, four_byte_asn);
                assert!(
                    capability.iter().any(
                        |c| matches!(c, Capability::FourOctetAsNumber(n) if *n == four_byte_asn)
                    )
                );
            }
            _ => panic!("expected OPEN"),
        }
    }

    #[test]
    fn open_with_route_refresh() {
        let cap: &[u8] = &[0x02, 0x00];
        let params = capability_param(cap);
        let buf = bgp_msg(
            1,
            &open_body(65001, 90, "192.0.2.1".parse().unwrap(), &params),
        );
        let mut codec = default_codec();
        match codec.parse_message(&buf).unwrap() {
            ParsedMessage::Open(Open { capability, .. }) => {
                assert!(
                    capability
                        .iter()
                        .any(|c| matches!(c, Capability::RouteRefresh))
                );
            }
            _ => panic!("expected OPEN"),
        }
    }

    #[test]
    fn open_round_trip_minimal() {
        let original = Message::Open(Open {
            as_number: 65001,
            holdtime: HoldTime::new(90).unwrap(),
            router_id: u32::from("192.0.2.1".parse::<std::net::Ipv4Addr>().unwrap()),
            capability: vec![],
        });
        let mut framer = default_codec();
        let mut buf = Vec::new();
        framer.encode_to(&original, &mut buf).unwrap();
        let parsed = framer.parse_message(&buf).unwrap();
        match parsed {
            ParsedMessage::Open(Open {
                as_number,
                holdtime,
                router_id,
                capability,
            }) => {
                assert_eq!(as_number, 65001);
                assert_eq!(holdtime, HoldTime::new(90).unwrap());
                assert_eq!(
                    router_id,
                    u32::from("192.0.2.1".parse::<Ipv4Addr>().unwrap())
                );
                assert!(capability.is_empty());
            }
            _ => panic!("expected OPEN"),
        }
    }

    #[test]
    fn open_round_trip_with_capabilities() {
        let original = Message::Open(Open {
            as_number: 65001,
            holdtime: HoldTime::new(180).unwrap(),
            router_id: u32::from("10.0.0.1".parse::<std::net::Ipv4Addr>().unwrap()),
            capability: vec![
                Capability::MultiProtocol(Family::IPV4),
                Capability::MultiProtocol(Family::IPV6),
                Capability::RouteRefresh,
                Capability::FourOctetAsNumber(65001),
            ],
        });
        let mut framer = default_codec();
        let mut buf = Vec::new();
        framer.encode_to(&original, &mut buf).unwrap();
        let parsed = framer.parse_message(&buf).unwrap();
        match parsed {
            ParsedMessage::Open(Open {
                as_number,
                holdtime,
                capability,
                ..
            }) => {
                assert_eq!(as_number, 65001);
                assert_eq!(holdtime, HoldTime::new(180).unwrap());
                assert!(
                    capability
                        .iter()
                        .any(|c| matches!(c, Capability::MultiProtocol(f) if *f == Family::IPV4))
                );
                assert!(
                    capability
                        .iter()
                        .any(|c| matches!(c, Capability::MultiProtocol(f) if *f == Family::IPV6))
                );
                assert!(
                    capability
                        .iter()
                        .any(|c| matches!(c, Capability::RouteRefresh))
                );
                assert!(
                    capability
                        .iter()
                        .any(|c| matches!(c, Capability::FourOctetAsNumber(n) if *n == 65001))
                );
            }
            _ => panic!("expected OPEN"),
        }
    }

    #[test]
    fn open_too_short() {
        let body: &[u8] = &[4, 0xFD, 0xEA, 0x00, 0x5A];
        let buf = bgp_msg(1, body);
        let mut codec = default_codec();
        match codec.parse_message(&buf) {
            Err(Notification::BadMessageLength { .. }) => {}
            Ok(_) => panic!("expected error"),
            Err(e) => panic!("unexpected error: {}", e),
        }
    }

    #[test]
    fn open_unacceptable_holdtime() {
        for bad_holdtime in [1u16, 2u16] {
            let buf = bgp_msg(
                1,
                &open_body(65001, bad_holdtime, "192.0.2.1".parse().unwrap(), &[]),
            );
            let mut codec = default_codec();
            match codec.parse_message(&buf) {
                Err(Notification::OpenUnacceptableHoldTime { .. }) => {}
                Ok(_) => panic!("expected error for holdtime={}", bad_holdtime),
                Err(e) => panic!("unexpected error for holdtime={}: {}", bad_holdtime, e),
            }
        }
    }

    #[test]
    fn open_unsupported_optional_parameter() {
        let params: &[u8] = &[0x01, 0x02, 0xAB, 0xCD];
        let buf = bgp_msg(
            1,
            &open_body(65001, 90, "192.0.2.1".parse().unwrap(), params),
        );
        let mut codec = default_codec();
        match codec.parse_message(&buf) {
            Err(Notification::OpenUnsupportedOptionalParameter { .. }) => {}
            Ok(_) => panic!("expected error"),
            Err(e) => panic!("unexpected error: {}", e),
        }
    }
}

#[cfg(test)]
mod update_tests {
    use super::*;
    use crate::mup;
    use crate::prefix_sid;
    use crate::rd::RouteDistinguisher;
    use bytes::BytesMut;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;

    fn ipv4_codec() -> PeerCodec {
        let mut c = PeerCodec::new();
        c.set_family(Family::IPV4, Default::default());
        c
    }

    fn ipv6_codec() -> PeerCodec {
        let mut c = PeerCodec::new();
        c.set_family(Family::IPV6, Default::default());
        c
    }

    fn ipv4_attrs(nexthop: Ipv4Addr) -> Arc<Vec<Attribute>> {
        Arc::new(vec![
            Attribute::new_with_value(Attribute::ORIGIN, 0).unwrap(),
            Attribute::new_with_bin(
                Attribute::AS_PATH,
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

    fn round_trip(msg: &Message, codec: PeerCodec) -> ParsedMessage {
        let mut framer = codec;
        let mut buf = Vec::new();
        framer.encode_to(msg, &mut buf).unwrap();
        framer.parse_message(&buf).unwrap()
    }

    fn ipv6_attrs_no_nh() -> Arc<Vec<Attribute>> {
        Arc::new(vec![
            Attribute::new_with_value(Attribute::ORIGIN, 0).unwrap(),
            Attribute::new_with_bin(
                Attribute::AS_PATH,
                vec![Attribute::AS_PATH_TYPE_SEQ, 1, 0x00, 0x00, 0xFD, 0xEA],
            )
            .unwrap(),
        ])
    }

    #[test]
    fn update_ipv4_announce() {
        let prefix = ipv4_prefix("10.0.0.0", 8);
        let msg = Message::Update(Update::Reach {
            family: Family::IPV4,
            entries: vec![prefix.clone()],
            nexthop: None,
            attr: ipv4_attrs("192.0.2.254".parse().unwrap()),
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
        let msg = Message::Update(Update::Reach {
            family: Family::IPV4,
            entries: prefixes.clone(),
            nexthop: None,
            attr: ipv4_attrs("192.0.2.254".parse().unwrap()),
        });
        match round_trip(&msg, ipv4_codec()) {
            ParsedMessage::Update(ParsedUpdate::Routes { reach, .. }) => {
                let s = reach.unwrap();
                assert_eq!(s.entries.len(), 3);
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
        let msg = Message::Update(Update::Unreach {
            family: Family::IPV4,
            entries: vec![prefix.clone()],
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

    #[test]
    fn update_ipv6_announce() {
        let prefix = ipv6_prefix("2001:db8::", 32);
        let nexthop_bytes: Vec<u8> = "2001:db8::1".parse::<Ipv6Addr>().unwrap().octets().to_vec();
        let msg = Message::Update(Update::Reach {
            family: Family::IPV6,
            entries: vec![prefix.clone()],
            nexthop: None,
            attr: Arc::new(vec![
                Attribute::new_with_value(Attribute::ORIGIN, 0).unwrap(),
                Attribute::new_with_bin(
                    Attribute::AS_PATH,
                    vec![Attribute::AS_PATH_TYPE_SEQ, 1, 0x00, 0x00, 0xFD, 0xEA],
                )
                .unwrap(),
                Attribute::new_with_bin(Attribute::NEXTHOP, nexthop_bytes).unwrap(),
            ]),
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
        let msg = Message::Update(Update::Unreach {
            family: Family::IPV6,
            entries: vec![prefix.clone()],
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

    #[test]
    fn update_ipv6_dual_nexthop_roundtrip() {
        let prefix = ipv6_prefix("2001:db8::", 32);
        let global: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let link_local: Ipv6Addr = "fe80::1".parse().unwrap();
        let nexthop = Nexthop::V6LinkLocal(global, link_local);
        let msg = Message::Update(Update::Reach {
            family: Family::IPV6,
            entries: vec![prefix.clone()],
            nexthop: Some(nexthop),
            attr: ipv6_attrs_no_nh(),
        });
        match round_trip(&msg, ipv6_codec()) {
            ParsedMessage::Update(ParsedUpdate::Routes { mp_reach, .. }) => {
                let r = mp_reach.expect("mp_reach must be present");
                assert_eq!(r.family, Family::IPV6);
                assert_eq!(r.entries, vec![prefix]);
                assert_eq!(r.nexthop, Some(nexthop), "dual nexthop must round-trip");
            }
            _ => panic!("expected Update"),
        }
    }

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

    #[test]
    fn update_attr_origin_igp() {
        let msg = Message::Update(Update::Reach {
            family: Family::IPV4,
            entries: vec![ipv4_prefix("10.0.0.0", 8)],
            nexthop: None,
            attr: ipv4_attrs("192.0.2.254".parse().unwrap()),
        });
        match round_trip(&msg, ipv4_codec()) {
            ParsedMessage::Update(ParsedUpdate::Routes { attrs, reach, .. }) => {
                assert!(!reach.unwrap().entries.is_empty());
                let origin = attrs
                    .iter()
                    .find(|a| a.code() == Attribute::ORIGIN)
                    .expect("ORIGIN attribute must be present");
                assert_eq!(origin.value().unwrap(), 0);
            }
            _ => panic!("expected Update"),
        }
    }

    #[test]
    fn update_attr_med_preserved_on_encode() {
        let med_value: u32 = 150;
        let mut attrs = (*ipv4_attrs("192.0.2.254".parse().unwrap())).clone();
        attrs.push(Attribute::new_with_value(Attribute::MULTI_EXIT_DESC, med_value).unwrap());
        let msg = Message::Update(Update::Reach {
            family: Family::IPV4,
            entries: vec![ipv4_prefix("10.0.0.0", 8)],
            nexthop: None,
            attr: Arc::new(attrs),
        });
        match round_trip(&msg, ipv4_codec()) {
            ParsedMessage::Update(ParsedUpdate::Routes { attrs, reach, .. }) => {
                assert!(!reach.unwrap().entries.is_empty());
                assert!(attrs.iter().any(
                    |a| a.code() == Attribute::MULTI_EXIT_DESC && a.value() == Some(med_value)
                ));
            }
            _ => panic!("expected Update"),
        }
    }

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
        let msg = Message::Update(Update::Reach {
            family: Family::IPV4,
            entries: vec![prefix.clone()],
            nexthop: Some(Nexthop::V6(nexthop_v6)),
            attr: Arc::new(vec![
                Attribute::new_with_value(Attribute::ORIGIN, 0).unwrap(),
                Attribute::new_with_bin(
                    Attribute::AS_PATH,
                    vec![Attribute::AS_PATH_TYPE_SEQ, 1, 0x00, 0x00, 0xFD, 0xEA],
                )
                .unwrap(),
            ]),
        });
        match round_trip(&msg, ipv4_extended_nexthop_codec()) {
            ParsedMessage::Update(ParsedUpdate::Routes {
                reach, mp_reach, ..
            }) => {
                assert!(reach.is_none());
                let s = mp_reach.expect("mp_reach must be present");
                assert_eq!(s.family, Family::IPV4);
                assert_eq!(s.entries, vec![prefix]);
                assert_eq!(s.nexthop, Some(Nexthop::V6(nexthop_v6)));
            }
            _ => panic!("expected Update"),
        }
    }

    #[test]
    fn update_ipv4_extended_nexthop_withdraw() {
        let prefix = ipv4_prefix("10.0.0.0", 8);
        let msg = Message::Update(Update::Unreach {
            family: Family::IPV4,
            entries: vec![prefix.clone()],
        });
        match round_trip(&msg, ipv4_extended_nexthop_codec()) {
            ParsedMessage::Update(ParsedUpdate::Routes {
                unreach,
                mp_unreach,
                ..
            }) => {
                assert!(unreach.is_none());
                let s = mp_unreach.expect("mp_unreach must be present");
                assert_eq!(s.family, Family::IPV4);
                assert_eq!(s.entries, vec![prefix]);
            }
            _ => panic!("expected Update"),
        }
    }

    #[test]
    fn update_attr_community() {
        let community: u32 = (65001u32 << 16) | 100;
        let mut attrs = (*ipv4_attrs("192.0.2.254".parse().unwrap())).clone();
        attrs.push(
            Attribute::new_with_bin(Attribute::COMMUNITY, community.to_be_bytes().to_vec())
                .unwrap(),
        );
        let msg = Message::Update(Update::Reach {
            family: Family::IPV4,
            entries: vec![ipv4_prefix("10.0.0.0", 8)],
            nexthop: None,
            attr: Arc::new(attrs),
        });
        match round_trip(&msg, ipv4_codec()) {
            ParsedMessage::Update(ParsedUpdate::Routes { attrs, reach, .. }) => {
                assert!(!reach.unwrap().entries.is_empty());
                let comm = attrs
                    .iter()
                    .find(|a| a.code() == Attribute::COMMUNITY)
                    .expect("COMMUNITY must be present");
                let bytes = comm.binary().unwrap();
                assert_eq!(bytes.len(), 4);
                let parsed = u32::from_be_bytes(bytes[..4].try_into().unwrap());
                assert_eq!(parsed, community);
            }
            _ => panic!("expected Update"),
        }
    }

    #[test]
    fn update_ipv4_with_prefix_sid() {
        let prefix = ipv4_prefix("10.0.0.0", 24);
        let sid = prefix_sid::PrefixSid {
            tlvs: vec![prefix_sid::PrefixSidTlv::Srv6L3Service(
                prefix_sid::Srv6ServiceTlv {
                    reserved: 0,
                    sub_tlvs: vec![prefix_sid::Srv6ServiceSubTlv::Information(
                        prefix_sid::Srv6InformationSubTlv {
                            sid: "2001:0:5:3::".parse().unwrap(),
                            flags: 0,
                            endpoint_behavior: 19,
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
        let msg = Message::Update(Update::Reach {
            family: Family::IPV4,
            entries: vec![prefix.clone()],
            nexthop: None,
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
        });
        match round_trip(&msg, ipv4_codec()) {
            ParsedMessage::Update(ParsedUpdate::Routes { reach, attrs, .. }) => {
                assert_eq!(reach.unwrap().entries, vec![prefix]);
                let a = attrs
                    .iter()
                    .find(|a| a.code() == Attribute::PREFIX_SID)
                    .expect("PREFIX_SID must be present");
                assert_eq!(a.binary().unwrap(), &sid_bytes);
                let decoded = prefix_sid::PrefixSid::decode(a.binary().unwrap()).unwrap();
                assert_eq!(decoded, sid);
            }
            _ => panic!("expected Update"),
        }
    }

    #[test]
    fn update_passes_through_unknown_prefix_sid_tlv() {
        let prefix = ipv4_prefix("10.0.0.0", 24);
        let sid = prefix_sid::PrefixSid {
            tlvs: vec![prefix_sid::PrefixSidTlv::Unknown {
                type_id: 0x55,
                value: vec![0xAA, 0xBB, 0xCC],
            }],
        };
        let sid_bytes = sid.to_vec();
        assert_eq!(sid_bytes, vec![0x55, 0x00, 0x03, 0xAA, 0xBB, 0xCC]);
        let msg = Message::Update(Update::Reach {
            family: Family::IPV4,
            entries: vec![prefix.clone()],
            nexthop: None,
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
        let msg = Message::Update(Update::Reach {
            family: Family::IPV4_MUP,
            entries: vec![nlri.clone()],
            nexthop: None,
            attr: Arc::new(vec![
                Attribute::new_with_value(Attribute::ORIGIN, 0).unwrap(),
                Attribute::new_with_bin(
                    Attribute::AS_PATH,
                    vec![Attribute::AS_PATH_TYPE_SEQ, 1, 0x00, 0x00, 0xFD, 0xEA],
                )
                .unwrap(),
                Attribute::new_with_bin(Attribute::NEXTHOP, nexthop.octets().to_vec()).unwrap(),
            ]),
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
        let msg = Message::Update(Update::Reach {
            family: Family::IPV6_MUP,
            entries: vec![nlri.clone()],
            nexthop: None,
            attr: Arc::new(vec![
                Attribute::new_with_value(Attribute::ORIGIN, 0).unwrap(),
                Attribute::new_with_bin(
                    Attribute::AS_PATH,
                    vec![Attribute::AS_PATH_TYPE_SEQ, 1, 0x00, 0x00, 0xFD, 0xEA],
                )
                .unwrap(),
                Attribute::new_with_bin(Attribute::NEXTHOP, nexthop_bytes).unwrap(),
            ]),
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
        let msg = Message::Update(Update::Unreach {
            family: Family::IPV4_MUP,
            entries: vec![nlri.clone()],
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
        let mut ec_bytes = Vec::new();
        mup::MupExtended {
            sub_type: mup::EC_SUBTYPE_MUP_DIRECT_SEG,
            segment_id2: 10,
            segment_id4: 20,
        }
        .encode(&mut ec_bytes);
        let nexthop: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let msg = Message::Update(Update::Reach {
            family: Family::IPV4_MUP,
            entries: vec![nlri.clone()],
            nexthop: None,
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

    fn mp_reach_zero_nexthop_update(afi: u16, safi: u8) -> Vec<u8> {
        let attr: Vec<u8> = vec![
            0x80,
            0x0E,
            0x05,
            (afi >> 8) as u8,
            afi as u8,
            safi,
            0x00,
            0x00,
        ];
        let attr_len = attr.len() as u16;
        let total = 19u16 + 2 + 2 + attr_len;
        let mut buf = vec![0xff; 16];
        buf.extend_from_slice(&total.to_be_bytes());
        buf.push(2);
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&attr_len.to_be_bytes());
        buf.extend_from_slice(&attr);
        buf
    }

    #[test]
    fn mp_reach_zero_nexthop_non_flowspec_is_error() {
        let buf = mp_reach_zero_nexthop_update(Family::AFI_IP, 1);
        let mut codec = PeerCodec::new();
        codec.set_family(Family::IPV4, FamilyState::default());
        match codec.parse_message(&buf) {
            Err(Notification::UpdateOptionalAttributeError) => {}
            Err(e) => panic!("expected UpdateOptionalAttributeError, got Err({})", e),
            Ok(_) => panic!("expected Err, got Ok"),
        }
    }

    #[test]
    fn mp_reach_zero_nexthop_flowspec_is_ok() {
        let buf = mp_reach_zero_nexthop_update(Family::AFI_IP, 133);
        let mut codec = PeerCodec::new();
        codec.set_family(Family::IPV4_FLOWSPEC, FamilyState::default());
        assert!(
            codec.parse_message(&buf).is_ok(),
            "FlowSpec nexthop_len=0 must be accepted"
        );
    }

    #[test]
    fn duplicate_non_mp_attr_is_skipped() {
        let community: [u8; 7] = [0xC0, 0x08, 0x04, 0xFD, 0xE9, 0x00, 0x64];
        let mut attr_bytes: Vec<u8> = Vec::new();
        attr_bytes.extend_from_slice(&[0x40, 0x01, 0x01, 0x00]);
        attr_bytes.extend_from_slice(&[0x40, 0x02, 0x06, 0x02, 0x01, 0x00, 0x00, 0xFD, 0xEA]);
        attr_bytes.extend_from_slice(&[0x40, 0x03, 0x04, 0xC0, 0x00, 0x02, 0x01]);
        attr_bytes.extend_from_slice(&community);
        attr_bytes.extend_from_slice(&community);
        let attr_len = attr_bytes.len() as u16;
        let nlri: [u8; 2] = [0x08, 0x0A];
        let total = 19u16 + 2 + 2 + attr_len + nlri.len() as u16;
        let mut buf = vec![0xffu8; 16];
        buf.extend_from_slice(&total.to_be_bytes());
        buf.push(2);
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&attr_len.to_be_bytes());
        buf.extend_from_slice(&attr_bytes);
        buf.extend_from_slice(&nlri);
        let mut codec = ipv4_codec();
        match codec.parse_message(&buf) {
            Ok(ParsedMessage::Update(ParsedUpdate::Routes { attrs, reach, .. })) => {
                assert!(reach.is_some());
                let count = attrs
                    .iter()
                    .filter(|a| a.code() == Attribute::COMMUNITY)
                    .count();
                assert_eq!(count, 1, "duplicate COMMUNITY must be skipped");
            }
            Ok(_) => panic!("expected Routes"),
            Err(e) => panic!("unexpected parse error: {}", e),
        }
    }

    #[test]
    fn duplicate_mp_reach_is_error() {
        let mp_reach: Vec<u8> = {
            let mut v = vec![0x80, 0x0E, 0x15, 0x00, 0x02, 0x01, 0x10];
            v.extend_from_slice(&[0u8; 16]);
            v.push(0x00);
            v
        };
        let attr_len = (mp_reach.len() * 2) as u16;
        let total = 19u16 + 2 + 2 + attr_len;
        let mut buf = vec![0xffu8; 16];
        buf.extend_from_slice(&total.to_be_bytes());
        buf.push(2);
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&attr_len.to_be_bytes());
        buf.extend_from_slice(&mp_reach);
        buf.extend_from_slice(&mp_reach);
        let mut codec = ipv6_codec();
        match codec.parse_message(&buf) {
            Err(Notification::UpdateMalformedAttributeList) => {}
            Err(e) => panic!("expected UpdateMalformedAttributeList, got {}", e),
            Ok(_) => panic!("expected Err, got Ok"),
        }
    }

    fn vpnv4_codec() -> PeerCodec {
        let caps = vec![Capability::MultiProtocol(Family::IPV4_VPN)];
        PeerCodec::negotiate(&caps, &caps)
    }

    fn vpnv6_codec() -> PeerCodec {
        let caps = vec![Capability::MultiProtocol(Family::IPV6_VPN)];
        PeerCodec::negotiate(&caps, &caps)
    }

    #[test]
    fn update_vpnv4_nexthop_roundtrip() {
        use crate::mpls::{MplsLabel, MplsLabelStack};
        use crate::vpn::VpnV4Nlri;
        let rd = RouteDistinguisher::TwoOctetAs {
            admin: 65001,
            assigned: 1,
        };
        let prefix = Ipv4Net {
            addr: "10.0.1.0".parse().unwrap(),
            mask: 24,
        };
        let nlri = PathNlri::new(Nlri::VpnV4(VpnV4Nlri {
            labels: MplsLabelStack::new(vec![MplsLabel::new(100)]),
            rd,
            prefix,
        }));
        let nexthop = Nexthop::V4("192.0.2.1".parse().unwrap());
        let msg = Message::Update(Update::Reach {
            family: Family::IPV4_VPN,
            entries: vec![nlri.clone()],
            nexthop: Some(nexthop),
            attr: Arc::new(vec![
                Attribute::new_with_value(Attribute::ORIGIN, 0).unwrap(),
                Attribute::new_with_bin(
                    Attribute::AS_PATH,
                    vec![Attribute::AS_PATH_TYPE_SEQ, 1, 0x00, 0x00, 0xFD, 0xEA],
                )
                .unwrap(),
            ]),
        });
        match round_trip(&msg, vpnv4_codec()) {
            ParsedMessage::Update(ParsedUpdate::Routes { mp_reach, .. }) => {
                let r = mp_reach.expect("mp_reach must be present for VPNv4");
                assert_eq!(r.family, Family::IPV4_VPN);
                assert_eq!(r.nexthop, Some(nexthop));
                assert_eq!(r.entries, vec![nlri]);
            }
            _ => panic!("expected Update"),
        }
    }

    #[test]
    fn update_vpnv6_nexthop_roundtrip() {
        use crate::mpls::{MplsLabel, MplsLabelStack};
        use crate::vpn::VpnV6Nlri;
        let rd = RouteDistinguisher::TwoOctetAs {
            admin: 65001,
            assigned: 1,
        };
        let prefix = Ipv6Net {
            addr: "2001:db8:1::".parse().unwrap(),
            mask: 48,
        };
        let nlri = PathNlri::new(Nlri::VpnV6(VpnV6Nlri {
            labels: MplsLabelStack::new(vec![MplsLabel::new(200)]),
            rd,
            prefix,
        }));
        let nexthop = Nexthop::V6("2001:db8::1".parse().unwrap());
        let msg = Message::Update(Update::Reach {
            family: Family::IPV6_VPN,
            entries: vec![nlri.clone()],
            nexthop: Some(nexthop),
            attr: Arc::new(vec![
                Attribute::new_with_value(Attribute::ORIGIN, 0).unwrap(),
                Attribute::new_with_bin(
                    Attribute::AS_PATH,
                    vec![Attribute::AS_PATH_TYPE_SEQ, 1, 0x00, 0x00, 0xFD, 0xEA],
                )
                .unwrap(),
            ]),
        });
        match round_trip(&msg, vpnv6_codec()) {
            ParsedMessage::Update(ParsedUpdate::Routes { mp_reach, .. }) => {
                let r = mp_reach.expect("mp_reach must be present for VPNv6");
                assert_eq!(r.family, Family::IPV6_VPN);
                assert_eq!(r.nexthop, Some(nexthop));
                assert_eq!(r.entries, vec![nlri]);
            }
            _ => panic!("expected Update"),
        }
    }

    fn check_message_sizes(raw: &[u8]) {
        let mut pos = 0;
        while pos < raw.len() {
            assert!(pos + 19 <= raw.len(), "truncated header at offset {}", pos);
            let msg_len = u16::from_be_bytes([raw[pos + 16], raw[pos + 17]]) as usize;
            assert!(
                msg_len <= 4096,
                "message at offset {} exceeds MAX_LENGTH: {}",
                pos,
                msg_len
            );
            assert!(
                msg_len >= 19,
                "message at offset {} too short: {}",
                pos,
                msg_len
            );
            pos += msg_len;
        }
        assert_eq!(pos, raw.len(), "trailing bytes in encoded buffer");
    }

    fn decode_all(buf: &mut BytesMut, codec: &mut PeerCodec) -> Vec<ParsedMessage> {
        let mut msgs = Vec::new();
        loop {
            match codec.try_parse(buf) {
                Ok(Some(msg)) => msgs.push(msg),
                Ok(None) => break,
                Err(e) => panic!("parse error: {:?}", e),
            }
        }
        msgs
    }

    fn assert_encode_decode_splits<F>(
        codec: &mut PeerCodec,
        msg: &Message,
        expected: &[PathNlri],
        collect: F,
    ) where
        F: Fn(ParsedMessage) -> Option<Vec<PathNlri>>,
    {
        let mut raw = Vec::new();
        let wire_count = codec.encode_to(msg, &mut raw).unwrap();
        assert!(
            wire_count > 1,
            "expected split, got wire_count={}",
            wire_count
        );
        check_message_sizes(&raw);
        let mut buf = BytesMut::from(raw.as_slice());
        let all_nlri: Vec<PathNlri> = decode_all(&mut buf, codec)
            .into_iter()
            .filter_map(collect)
            .flatten()
            .collect();
        assert_eq!(all_nlri.len(), expected.len(), "NLRI count mismatch");
        for p in expected {
            assert!(all_nlri.contains(p), "missing NLRI: {:?}", p);
        }
    }

    fn ipv4_entries(n: u32) -> Vec<PathNlri> {
        (0..n)
            .map(|i| ipv4_prefix(&format!("10.{}.{}.0", i / 256, i % 256), 24))
            .collect()
    }

    fn ipv4_entries_addpath(n: u32) -> Vec<PathNlri> {
        (0..n)
            .map(|i| PathNlri {
                path_id: i + 1,
                nlri: Nlri::V4(Ipv4Net {
                    addr: format!("10.{}.{}.0", i / 256, i % 256).parse().unwrap(),
                    mask: 24,
                }),
            })
            .collect()
    }

    fn ipv6_entries(n: u16) -> Vec<PathNlri> {
        (0..n)
            .map(|i| {
                PathNlri::new(Nlri::V6(Ipv6Net {
                    addr: Ipv6Addr::new(0x2001, 0x0db8, i, 0, 0, 0, 0, 0),
                    mask: 48,
                }))
            })
            .collect()
    }

    fn ipv6_entries_addpath(n: u16) -> Vec<PathNlri> {
        (0..n)
            .map(|i| PathNlri {
                path_id: i as u32 + 1,
                nlri: Nlri::V6(Ipv6Net {
                    addr: Ipv6Addr::new(0x2001, 0x0db8, i, 0, 0, 0, 0, 0),
                    mask: 48,
                }),
            })
            .collect()
    }

    fn ipv4_addpath_codec() -> PeerCodec {
        let caps = vec![
            Capability::MultiProtocol(Family::IPV4),
            Capability::AddPath(vec![(Family::IPV4, 3)]),
        ];
        PeerCodec::negotiate(&caps, &caps)
    }

    fn ipv6_addpath_codec() -> PeerCodec {
        let caps = vec![
            Capability::MultiProtocol(Family::IPV6),
            Capability::AddPath(vec![(Family::IPV6, 3)]),
        ];
        PeerCodec::negotiate(&caps, &caps)
    }

    #[test]
    fn encode_to_splits_ipv4_reach() {
        let mut codec = ipv4_codec();
        let entries = ipv4_entries(1500);
        let msg = Message::Update(Update::Reach {
            family: Family::IPV4,
            entries: entries.clone(),
            nexthop: None,
            attr: ipv4_attrs("192.0.2.1".parse().unwrap()),
        });
        assert_encode_decode_splits(&mut codec, &msg, &entries, |m| match m {
            ParsedMessage::Update(ParsedUpdate::Routes { reach: Some(r), .. }) => Some(r.entries),
            _ => None,
        });
    }

    #[test]
    fn encode_to_splits_ipv4_unreach() {
        let mut codec = ipv4_codec();
        let entries = ipv4_entries(1500);
        let msg = Message::Update(Update::Unreach {
            family: Family::IPV4,
            entries: entries.clone(),
        });
        assert_encode_decode_splits(&mut codec, &msg, &entries, |m| match m {
            ParsedMessage::Update(ParsedUpdate::Routes {
                unreach: Some(r), ..
            }) => Some(r.entries),
            _ => None,
        });
    }

    #[test]
    fn encode_to_splits_ipv6_reach() {
        let mut codec = ipv6_codec();
        let entries = ipv6_entries(800);
        let msg = Message::Update(Update::Reach {
            family: Family::IPV6,
            entries: entries.clone(),
            nexthop: Some(Nexthop::V6("2001:db8::1".parse().unwrap())),
            attr: ipv6_attrs_no_nh(),
        });
        assert_encode_decode_splits(&mut codec, &msg, &entries, |m| match m {
            ParsedMessage::Update(ParsedUpdate::Routes {
                mp_reach: Some(r), ..
            }) => Some(r.entries),
            _ => None,
        });
    }

    #[test]
    fn encode_to_splits_ipv6_unreach() {
        let mut codec = ipv6_codec();
        let entries = ipv6_entries(800);
        let msg = Message::Update(Update::Unreach {
            family: Family::IPV6,
            entries: entries.clone(),
        });
        assert_encode_decode_splits(&mut codec, &msg, &entries, |m| match m {
            ParsedMessage::Update(ParsedUpdate::Routes {
                mp_unreach: Some(r),
                ..
            }) => Some(r.entries),
            _ => None,
        });
    }

    #[test]
    fn encode_to_splits_ipv4_reach_addpath() {
        let mut codec = ipv4_addpath_codec();
        let entries = ipv4_entries_addpath(700);
        let msg = Message::Update(Update::Reach {
            family: Family::IPV4,
            entries: entries.clone(),
            nexthop: None,
            attr: ipv4_attrs("192.0.2.1".parse().unwrap()),
        });
        assert_encode_decode_splits(&mut codec, &msg, &entries, |m| match m {
            ParsedMessage::Update(ParsedUpdate::Routes { reach: Some(r), .. }) => Some(r.entries),
            _ => None,
        });
    }

    #[test]
    fn encode_to_splits_ipv4_unreach_addpath() {
        let mut codec = ipv4_addpath_codec();
        let entries = ipv4_entries_addpath(700);
        let msg = Message::Update(Update::Unreach {
            family: Family::IPV4,
            entries: entries.clone(),
        });
        assert_encode_decode_splits(&mut codec, &msg, &entries, |m| match m {
            ParsedMessage::Update(ParsedUpdate::Routes {
                unreach: Some(r), ..
            }) => Some(r.entries),
            _ => None,
        });
    }

    #[test]
    fn encode_to_splits_ipv6_reach_addpath() {
        let mut codec = ipv6_addpath_codec();
        let entries = ipv6_entries_addpath(500);
        let msg = Message::Update(Update::Reach {
            family: Family::IPV6,
            entries: entries.clone(),
            nexthop: Some(Nexthop::V6("2001:db8::1".parse().unwrap())),
            attr: ipv6_attrs_no_nh(),
        });
        assert_encode_decode_splits(&mut codec, &msg, &entries, |m| match m {
            ParsedMessage::Update(ParsedUpdate::Routes {
                mp_reach: Some(r), ..
            }) => Some(r.entries),
            _ => None,
        });
    }

    #[test]
    fn encode_to_splits_ipv6_unreach_addpath() {
        let mut codec = ipv6_addpath_codec();
        let entries = ipv6_entries_addpath(500);
        let msg = Message::Update(Update::Unreach {
            family: Family::IPV6,
            entries: entries.clone(),
        });
        assert_encode_decode_splits(&mut codec, &msg, &entries, |m| match m {
            ParsedMessage::Update(ParsedUpdate::Routes {
                mp_unreach: Some(r),
                ..
            }) => Some(r.entries),
            _ => None,
        });
    }

    fn raw_update_with_attrs(attr_bytes: &[u8]) -> Vec<u8> {
        let nlri: &[u8] = &[0x08, 0x0A];
        let attr_len = attr_bytes.len() as u16;
        let total = 19u16 + 2 + 2 + attr_len + nlri.len() as u16;
        let mut buf = vec![0xffu8; 16];
        buf.extend_from_slice(&total.to_be_bytes());
        buf.push(2);
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&attr_len.to_be_bytes());
        buf.extend_from_slice(attr_bytes);
        buf.extend_from_slice(nlri);
        buf
    }

    fn base_attrs_without_origin() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&[0x40, 0x02, 0x06, 0x02, 0x01, 0x00, 0x00, 0xFD, 0xEA]);
        v.extend_from_slice(&[0x40, 0x03, 0x04, 0xC0, 0x00, 0x02, 0x01]);
        v
    }

    #[test]
    fn invalid_origin_value_treat_as_withdraw() {
        let mut attr_bytes = Vec::new();
        attr_bytes.extend_from_slice(&[0x40, 0x01, 0x01, 0x03]);
        attr_bytes.extend_from_slice(&base_attrs_without_origin());
        let buf = raw_update_with_attrs(&attr_bytes);
        let parsed = ipv4_codec()
            .parse_message(&buf)
            .expect("parse must not fail");
        let msgs: Vec<Message> = validate_message(parsed, false).unwrap().collect();
        assert_eq!(msgs.len(), 1);
        assert!(matches!(&msgs[0], Message::Update(Update::Unreach { .. })));
    }

    #[test]
    fn malformed_community_length_treat_as_withdraw() {
        let mut attr_bytes = Vec::new();
        attr_bytes.extend_from_slice(&[0x40, 0x01, 0x01, 0x00]);
        attr_bytes.extend_from_slice(&base_attrs_without_origin());
        attr_bytes.extend_from_slice(&[0xC0, 0x08, 0x03, 0xFD, 0xE9, 0x00]);
        let buf = raw_update_with_attrs(&attr_bytes);
        let parsed = ipv4_codec()
            .parse_message(&buf)
            .expect("parse must not fail");
        let msgs: Vec<Message> = validate_message(parsed, false).unwrap().collect();
        assert_eq!(msgs.len(), 1);
        assert!(matches!(&msgs[0], Message::Update(Update::Unreach { .. })));
    }

    #[test]
    fn malformed_aggregator_length_treat_as_withdraw() {
        let mut attr_bytes = Vec::new();
        attr_bytes.extend_from_slice(&[0x40, 0x01, 0x01, 0x00]);
        attr_bytes.extend_from_slice(&base_attrs_without_origin());
        attr_bytes.extend_from_slice(&[0xC0, 0x07, 0x03, 0x00, 0x01, 0x00]);
        let buf = raw_update_with_attrs(&attr_bytes);
        let parsed = ipv4_codec()
            .parse_message(&buf)
            .expect("parse must not fail");
        let msgs: Vec<Message> = validate_message(parsed, false).unwrap().collect();
        assert_eq!(msgs.len(), 1);
        assert!(matches!(&msgs[0], Message::Update(Update::Unreach { .. })));
    }

    #[test]
    fn malformed_cluster_list_length_discarded() {
        let mut attr_bytes = Vec::new();
        attr_bytes.extend_from_slice(&[0x40, 0x01, 0x01, 0x00]);
        attr_bytes.extend_from_slice(&base_attrs_without_origin());
        attr_bytes.extend_from_slice(&[0x80, 0x0A, 0x03, 0x00, 0x00, 0x01]);
        let buf = raw_update_with_attrs(&attr_bytes);
        let parsed = ipv4_codec()
            .parse_message(&buf)
            .expect("parse must not fail");
        let msgs: Vec<Message> = validate_message(parsed, false).unwrap().collect();
        assert_eq!(msgs.len(), 1);
        assert!(matches!(&msgs[0], Message::Update(Update::Reach { .. })));
        if let Message::Update(Update::Reach { attr, .. }) = &msgs[0] {
            assert!(attr.iter().all(|a| a.code() != Attribute::CLUSTER_LIST));
        }
    }

    #[test]
    fn malformed_aspath_truncated_segment_treat_as_withdraw() {
        let as_path_data: Vec<u8> = vec![0x02, 0x02, 0x00, 0x00, 0xFD, 0xEA];
        let mut attr_bytes = Vec::new();
        attr_bytes.extend_from_slice(&[0x40, 0x01, 0x01, 0x00]);
        attr_bytes.push(0x40);
        attr_bytes.push(0x02);
        attr_bytes.push(as_path_data.len() as u8);
        attr_bytes.extend_from_slice(&as_path_data);
        attr_bytes.extend_from_slice(&[0x40, 0x03, 0x04, 0xC0, 0x00, 0x02, 0x01]);
        let buf = raw_update_with_attrs(&attr_bytes);
        let parsed = ipv4_codec()
            .parse_message(&buf)
            .expect("parse must not fail");
        let msgs: Vec<Message> = validate_message(parsed, false).unwrap().collect();
        assert_eq!(msgs.len(), 1);
        assert!(matches!(&msgs[0], Message::Update(Update::Unreach { .. })));
    }

    #[test]
    fn malformed_aspath_invalid_segment_type_treat_as_withdraw() {
        let as_path_data: Vec<u8> = vec![0x05, 0x01, 0x00, 0x00, 0xFD, 0xEA];
        let mut attr_bytes = Vec::new();
        attr_bytes.extend_from_slice(&[0x40, 0x01, 0x01, 0x00]);
        attr_bytes.push(0x40);
        attr_bytes.push(0x02);
        attr_bytes.push(as_path_data.len() as u8);
        attr_bytes.extend_from_slice(&as_path_data);
        attr_bytes.extend_from_slice(&[0x40, 0x03, 0x04, 0xC0, 0x00, 0x02, 0x01]);
        let buf = raw_update_with_attrs(&attr_bytes);
        let parsed = ipv4_codec()
            .parse_message(&buf)
            .expect("parse must not fail");
        let msgs: Vec<Message> = validate_message(parsed, false).unwrap().collect();
        assert_eq!(msgs.len(), 1);
        assert!(matches!(&msgs[0], Message::Update(Update::Unreach { .. })));
    }

    fn raw_update_with_ibgp_attrs() -> Vec<u8> {
        let mut attr_bytes = Vec::new();
        attr_bytes.extend_from_slice(&[0x40, 0x01, 0x01, 0x00]);
        attr_bytes.extend_from_slice(&base_attrs_without_origin());
        attr_bytes.extend_from_slice(&[0x40, 0x05, 0x04, 0x00, 0x00, 0x00, 0x64]);
        attr_bytes.extend_from_slice(&[0x80, 0x09, 0x04, 0xC0, 0x00, 0x02, 0x01]);
        attr_bytes.extend_from_slice(&[0x80, 0x0A, 0x04, 0x00, 0x00, 0x00, 0x01]);
        raw_update_with_attrs(&attr_bytes)
    }

    #[test]
    fn ebgp_discards_local_pref_originator_id_cluster_list() {
        let buf = raw_update_with_ibgp_attrs();
        let parsed = ipv4_codec()
            .parse_message(&buf)
            .expect("parse must not fail");
        let msgs: Vec<Message> = validate_message(parsed, true).unwrap().collect();
        assert_eq!(msgs.len(), 1);
        assert!(matches!(&msgs[0], Message::Update(Update::Reach { .. })));
        if let Message::Update(Update::Reach { attr, .. }) = &msgs[0] {
            assert!(attr.iter().all(|a| !matches!(
                a.code(),
                Attribute::LOCAL_PREF | Attribute::ORIGINATOR_ID | Attribute::CLUSTER_LIST
            )));
        }
    }

    #[test]
    fn ibgp_retains_local_pref_originator_id_cluster_list() {
        let buf = raw_update_with_ibgp_attrs();
        let parsed = ipv4_codec()
            .parse_message(&buf)
            .expect("parse must not fail");
        let msgs: Vec<Message> = validate_message(parsed, false).unwrap().collect();
        assert_eq!(msgs.len(), 1);
        if let Message::Update(Update::Reach { attr, .. }) = &msgs[0] {
            assert!(attr.iter().any(|a| a.code() == Attribute::LOCAL_PREF));
            assert!(attr.iter().any(|a| a.code() == Attribute::ORIGINATOR_ID));
            assert!(attr.iter().any(|a| a.code() == Attribute::CLUSTER_LIST));
        }
    }

    fn raw_ipv6_mpreach_update() -> Vec<u8> {
        let mut attr_bytes: Vec<u8> = Vec::new();
        attr_bytes.extend_from_slice(&[0x40, 0x01, 0x01, 0x00]);
        attr_bytes.extend_from_slice(&[0x40, 0x02, 0x06, 0x02, 0x01, 0x00, 0x00, 0xfd, 0xea]);
        let mp: &[u8] = &[
            0x00, 0x02, 0x01, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x20, 0x01, 0x0d, 0xb8,
        ];
        attr_bytes.push(0x80);
        attr_bytes.push(0x0e);
        attr_bytes.push(mp.len() as u8);
        attr_bytes.extend_from_slice(mp);
        let attr_len = attr_bytes.len() as u16;
        let total = 19u16 + 2 + 2 + attr_len;
        let mut buf = vec![0xffu8; 16];
        buf.extend_from_slice(&total.to_be_bytes());
        buf.push(2);
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&attr_len.to_be_bytes());
        buf.extend_from_slice(&attr_bytes);
        buf
    }

    #[test]
    fn missing_origin_treat_as_withdraw() {
        let mut attr_bytes: Vec<u8> = Vec::new();
        attr_bytes.extend_from_slice(&[0x40, 0x02, 0x06, 0x02, 0x01, 0x00, 0x00, 0xfd, 0xea]);
        attr_bytes.extend_from_slice(&[0x40, 0x03, 0x04, 0xc0, 0x00, 0x02, 0x01]);
        let buf = raw_update_with_attrs(&attr_bytes);
        let parsed = ipv4_codec().parse_message(&buf).expect("parse ok");
        let msgs: Vec<Message> = validate_message(parsed, false).unwrap().collect();
        assert_eq!(msgs.len(), 1);
        assert!(matches!(&msgs[0], Message::Update(Update::Unreach { .. })));
    }

    #[test]
    fn missing_aspath_treat_as_withdraw() {
        let mut attr_bytes: Vec<u8> = Vec::new();
        attr_bytes.extend_from_slice(&[0x40, 0x01, 0x01, 0x00]);
        attr_bytes.extend_from_slice(&[0x40, 0x03, 0x04, 0xc0, 0x00, 0x02, 0x01]);
        let buf = raw_update_with_attrs(&attr_bytes);
        let parsed = ipv4_codec().parse_message(&buf).expect("parse ok");
        let msgs: Vec<Message> = validate_message(parsed, false).unwrap().collect();
        assert_eq!(msgs.len(), 1);
        assert!(matches!(&msgs[0], Message::Update(Update::Unreach { .. })));
    }

    #[test]
    fn missing_nexthop_ipv4_treat_as_withdraw() {
        let mut attr_bytes: Vec<u8> = Vec::new();
        attr_bytes.extend_from_slice(&[0x40, 0x01, 0x01, 0x00]);
        attr_bytes.extend_from_slice(&[0x40, 0x02, 0x06, 0x02, 0x01, 0x00, 0x00, 0xfd, 0xea]);
        let buf = raw_update_with_attrs(&attr_bytes);
        let parsed = ipv4_codec().parse_message(&buf).expect("parse ok");
        let msgs: Vec<Message> = validate_message(parsed, false).unwrap().collect();
        assert_eq!(msgs.len(), 1);
        assert!(matches!(&msgs[0], Message::Update(Update::Unreach { .. })));
    }

    #[test]
    fn missing_nexthop_attr_with_mpreach_ok() {
        let buf = raw_ipv6_mpreach_update();
        let parsed = ipv6_codec().parse_message(&buf).expect("parse ok");
        let msgs: Vec<Message> = validate_message(parsed, false).unwrap().collect();
        assert_eq!(msgs.len(), 1);
        assert!(matches!(&msgs[0], Message::Update(Update::Reach { .. })));
    }

    #[test]
    fn flowspec_ipv4_no_nexthop_accepted() {
        let flowspec_nlri: &[u8] = &[0x03, 0x01, 0x08, 0x0a];
        let mp: Vec<u8> = {
            let mut v = Vec::new();
            v.extend_from_slice(&[0x00, 0x01]);
            v.push(133);
            v.push(0x00);
            v.push(0x00);
            v.extend_from_slice(flowspec_nlri);
            v
        };
        let mut attr_bytes: Vec<u8> = Vec::new();
        attr_bytes.extend_from_slice(&[0x40, 0x01, 0x01, 0x00]);
        attr_bytes.extend_from_slice(&[0x40, 0x02, 0x00]);
        attr_bytes.push(0x80);
        attr_bytes.push(0x0e);
        attr_bytes.push(mp.len() as u8);
        attr_bytes.extend_from_slice(&mp);
        let attr_len = attr_bytes.len() as u16;
        let total = 19u16 + 2 + 2 + attr_len;
        let mut buf = vec![0xffu8; 16];
        buf.extend_from_slice(&total.to_be_bytes());
        buf.push(2);
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&attr_len.to_be_bytes());
        buf.extend_from_slice(&attr_bytes);
        let mut codec = PeerCodec::new();
        codec.set_family(Family::IPV4_FLOWSPEC, Default::default());
        let parsed = codec.parse_message(&buf).expect("parse ok");
        let msgs: Vec<Message> = validate_message(parsed, false).unwrap().collect();
        assert_eq!(msgs.len(), 1);
        assert!(matches!(&msgs[0], Message::Update(Update::Reach { .. })));
    }

    fn update_with_unknown_optional_attrs() -> Vec<u8> {
        let attrs: &[u8] = &[
            0x40, 0x01, 0x01, 0x00, 0x40, 0x02, 0x00, 0x40, 0x03, 0x04, 0x0a, 0x00, 0x00, 0x01,
            0xC0, 0xC8, 0x03, 0x01, 0x02, 0x03, 0x80, 0xC9, 0x03, 0x04, 0x05, 0x06,
        ];
        let nlri: &[u8] = &[0x18, 0x0a, 0x01, 0x02];
        let attr_len = attrs.len() as u16;
        let total = 19u16 + 2 + 2 + attr_len + nlri.len() as u16;
        let mut buf = vec![0xffu8; 16];
        buf.extend_from_slice(&total.to_be_bytes());
        buf.push(2);
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&attr_len.to_be_bytes());
        buf.extend_from_slice(attrs);
        buf.extend_from_slice(nlri);
        buf
    }

    fn update_with_aigp(aigp_flags: u8) -> Vec<u8> {
        let aigp_value: Vec<u8> = vec![1, 0, 11, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut attrs: Vec<u8> = vec![
            0x40, 0x01, 0x01, 0x00, 0x40, 0x02, 0x00, 0x40, 0x03, 0x04, 0x0a, 0x00, 0x00, 0x01,
        ];
        attrs.push(aigp_flags);
        attrs.push(Attribute::AIGP);
        attrs.push(aigp_value.len() as u8);
        attrs.extend_from_slice(&aigp_value);
        let nlri: &[u8] = &[0x18, 0x0a, 0x01, 0x02];
        let attr_len = attrs.len() as u16;
        let total = 19u16 + 2 + 2 + attr_len + nlri.len() as u16;
        let mut buf = vec![0xffu8; 16];
        buf.extend_from_slice(&total.to_be_bytes());
        buf.push(2);
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&attr_len.to_be_bytes());
        buf.extend_from_slice(&attrs);
        buf.extend_from_slice(nlri);
        buf
    }

    #[test]
    fn aigp_with_correct_flags_is_accepted() {
        let mut codec = ipv4_codec();
        let buf = update_with_aigp(0x80);
        let parsed = codec.parse_message(&buf).expect("parse ok");
        let msgs: Vec<Message> = validate_message(parsed, false).unwrap().collect();
        assert!(
            msgs.iter()
                .any(|m| matches!(m, Message::Update(Update::Reach { .. })))
        );
    }

    #[test]
    fn aigp_with_wrong_flags_treat_as_withdraw() {
        let mut codec = ipv4_codec();
        let buf = update_with_aigp(0xC0);
        let parsed = codec.parse_message(&buf).expect("parse ok");
        let msgs: Vec<Message> = validate_message(parsed, false).unwrap().collect();
        assert!(
            msgs.iter()
                .all(|m| matches!(m, Message::Update(Update::Unreach { .. })))
        );
    }

    #[test]
    fn unknown_optional_transitive_attr_is_stored() {
        let mut codec = ipv4_codec();
        let buf = update_with_unknown_optional_attrs();
        let parsed = codec.parse_message(&buf).expect("parse ok");
        let msgs: Vec<Message> = validate_message(parsed, false).unwrap().collect();
        let attr = match &msgs[0] {
            Message::Update(Update::Reach { attr, .. }) => attr,
            _ => panic!("expected Reach message"),
        };
        let opaque = attr.iter().find(|a| a.code() == 200);
        assert!(
            opaque.is_some(),
            "unknown optional transitive attr must be stored"
        );
        let opaque = opaque.unwrap();
        assert!(opaque.is_opaque());
        assert_eq!(opaque.binary().unwrap(), &vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn unknown_optional_non_transitive_attr_is_discarded() {
        let mut codec = ipv4_codec();
        let buf = update_with_unknown_optional_attrs();
        let parsed = codec.parse_message(&buf).expect("parse ok");
        let msgs: Vec<Message> = validate_message(parsed, false).unwrap().collect();
        let attr = match &msgs[0] {
            Message::Update(Update::Reach { attr, .. }) => attr,
            _ => panic!("expected Reach message"),
        };
        assert!(attr.iter().all(|a| a.code() != 201));
    }
}

/// RFC 6793 (BGP Support for Four-octet AS Number Space) interop tests:
/// `PeerCodec::two_byte_as` handling, AS_PATH/AGGREGATOR two-octet wire form,
/// and AS4_PATH/AS4_AGGREGATOR reconciliation.
///
/// AS_PATH/AS4_PATH/AGGREGATOR/AS4_AGGREGATOR wire vectors below (the
/// `GOBGP_*` constants) are generated from GoBGP's packet library as an
/// independent reference implementation; see `packet/tests/gen/two_byte_as`.
#[cfg(test)]
mod two_byte_as_tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    fn ipv4_codec() -> PeerCodec {
        let mut c = PeerCodec::new();
        c.set_family(Family::IPV4, Default::default());
        c
    }

    fn ipv4_codec_2byte_as() -> PeerCodec {
        let mut c = ipv4_codec();
        c.two_byte_as = true;
        c
    }

    fn round_trip(msg: &Message, codec: PeerCodec) -> ParsedMessage {
        let mut framer = codec;
        let mut buf = Vec::new();
        framer.encode_to(msg, &mut buf).unwrap();
        framer.parse_message(&buf).unwrap()
    }

    fn seg_bytes(seg_type: u8, asns: &[u32]) -> Vec<u8> {
        let mut v = vec![seg_type, asns.len() as u8];
        for &a in asns {
            v.extend_from_slice(&a.to_be_bytes());
        }
        v
    }

    fn attr_tlv(flags: u8, code: u8, value: &[u8]) -> Vec<u8> {
        let mut v = vec![flags, code, value.len() as u8];
        v.extend_from_slice(value);
        v
    }

    fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    fn ipv4_prefix(addr: &str, mask: u8) -> PathNlri {
        PathNlri::new(Nlri::V4(Ipv4Net {
            addr: addr.parse().unwrap(),
            mask,
        }))
    }

    fn origin_and_nexthop() -> Vec<u8> {
        let mut v = vec![0x40, Attribute::ORIGIN, 0x01, 0x00];
        v.extend_from_slice(&attr_tlv(
            0x40,
            Attribute::NEXTHOP,
            &[0xC0, 0x00, 0x02, 0x01],
        ));
        v
    }

    fn raw_update_with_attrs(attr_bytes: &[u8]) -> Vec<u8> {
        let nlri: &[u8] = &[0x08, 0x0A];
        let attr_len = attr_bytes.len() as u16;
        let total = 19u16 + 2 + 2 + attr_len + nlri.len() as u16;
        let mut buf = vec![0xffu8; 16];
        buf.extend_from_slice(&total.to_be_bytes());
        buf.push(2);
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&attr_len.to_be_bytes());
        buf.extend_from_slice(attr_bytes);
        buf.extend_from_slice(nlri);
        buf
    }

    fn parse_attrs_2byte_as(attr_bytes: &[u8]) -> Vec<Attribute> {
        let buf = raw_update_with_attrs(attr_bytes);
        match ipv4_codec_2byte_as().parse_message(&buf).unwrap() {
            ParsedMessage::Update(ParsedUpdate::Routes { attrs, .. }) => attrs,
            _ => panic!("expected Update::Routes"),
        }
    }

    fn aggregator_bin(asn: u32, addr: Ipv4Addr) -> Vec<u8> {
        let mut v = asn.to_be_bytes().to_vec();
        v.extend_from_slice(&addr.octets());
        v
    }

    // --- GoBGP-generated wire vectors (regenerate via `go run
    // ./two_byte_as` in packet/tests/gen if the scenarios below change) ---

    // AS_PATH (2-octet) SEQ: 65000, 4000, AS_TRANS, AS_TRANS, 40001
    const GOBGP_AS2_65000_4000_TRANS_TRANS_40001: &[u8] = &[
        0x02, 0x05, 0xfd, 0xe8, 0x0f, 0xa0, 0x5b, 0xa0, 0x5b, 0xa0, 0x9c, 0x41,
    ];
    // AS4_PATH SEQ: 400000, 300000, 40001
    const GOBGP_AS4_400000_300000_40001: &[u8] = &[
        0x02, 0x03, 0x00, 0x06, 0x1a, 0x80, 0x00, 0x04, 0x93, 0xe0, 0x00, 0x00, 0x9c, 0x41,
    ];
    // four-octet AS_PATH SEQ 65000,4000,400000,300000,40001, as AS4_PATH-shaped value bytes
    const GOBGP_AS4_65000_4000_400000_300000_40001: &[u8] = &[
        0x02, 0x05, 0x00, 0x00, 0xfd, 0xe8, 0x00, 0x00, 0x0f, 0xa0, 0x00, 0x06, 0x1a, 0x80, 0x00,
        0x04, 0x93, 0xe0, 0x00, 0x00, 0x9c, 0x41,
    ];
    // AS_PATH (2-octet) SEQ: 65000, AS_TRANS
    const GOBGP_AS2_65000_TRANS: &[u8] = &[0x02, 0x02, 0xfd, 0xe8, 0x5b, 0xa0];
    // AS4_PATH SEQ: 65000, 400000
    const GOBGP_AS4_65000_400000: &[u8] =
        &[0x02, 0x02, 0x00, 0x00, 0xfd, 0xe8, 0x00, 0x06, 0x1a, 0x80];
    // AS4_PATH SEQ: 65000, 400000, 300000
    const GOBGP_AS4_65000_400000_300000: &[u8] = &[
        0x02, 0x03, 0x00, 0x00, 0xfd, 0xe8, 0x00, 0x06, 0x1a, 0x80, 0x00, 0x04, 0x93, 0xe0,
    ];
    // AS_PATH (2-octet): SET{65010, 65020}, SEQ[AS_TRANS]
    const GOBGP_AS2_SET_65010_65020_SEQ_TRANS: &[u8] =
        &[0x01, 0x02, 0xfd, 0xf2, 0xfd, 0xfc, 0x02, 0x01, 0x5b, 0xa0];
    // AS4_PATH SEQ: 500000
    const GOBGP_AS4_500000: &[u8] = &[0x02, 0x01, 0x00, 0x07, 0xa1, 0x20];
    // AS_PATH (2-octet): CONFED_SEQ[65001], SEQ[65000, AS_TRANS]
    const GOBGP_AS2_CONFEDSEQ_65001_SEQ_65000_TRANS: &[u8] =
        &[0x03, 0x01, 0xfd, 0xe9, 0x02, 0x02, 0xfd, 0xe8, 0x5b, 0xa0];
    // AS4_PATH SEQ: 600000
    const GOBGP_AS4_600000: &[u8] = &[0x02, 0x01, 0x00, 0x09, 0x27, 0xc0];
    // AGGREGATOR (2-octet): AS_TRANS, 198.51.100.1
    const GOBGP_AGGREGATOR_TRANS_198_51_100_1: &[u8] = &[0x5b, 0xa0, 0xc6, 0x33, 0x64, 0x01];
    // AGGREGATOR (2-octet): 65055, 198.51.100.1
    const GOBGP_AGGREGATOR_65055_198_51_100_1: &[u8] = &[0xfe, 0x1f, 0xc6, 0x33, 0x64, 0x01];
    // AS4_AGGREGATOR: 400000, 198.51.100.1
    const GOBGP_AS4_AGGREGATOR_400000_198_51_100_1: &[u8] =
        &[0x00, 0x06, 0x1a, 0x80, 0xc6, 0x33, 0x64, 0x01];

    // --- negotiate() ---

    #[test]
    fn negotiate_two_byte_as_when_remote_lacks_capability() {
        let local = [Capability::FourOctetAsNumber(65001)];
        let remote = [];
        assert!(PeerCodec::negotiate(&local, &remote).two_byte_as);
    }

    #[test]
    fn negotiate_four_byte_as_when_both_sides_have_capability() {
        let local = [Capability::FourOctetAsNumber(65001)];
        let remote = [Capability::FourOctetAsNumber(400000)];
        assert!(!PeerCodec::negotiate(&local, &remote).two_byte_as);
    }

    // --- decode / reconcile (RFC 6793 §4.2.3) ---

    #[test]
    fn reconcile_takes_leading_hops_when_as_path_longer() {
        let mut attr_bytes = origin_and_nexthop();
        attr_bytes.extend_from_slice(&attr_tlv(
            0x40,
            Attribute::AS_PATH,
            GOBGP_AS2_65000_4000_TRANS_TRANS_40001,
        ));
        attr_bytes.extend_from_slice(&attr_tlv(
            0xC0,
            Attribute::AS4_PATH,
            GOBGP_AS4_400000_300000_40001,
        ));
        let attrs = parse_attrs_2byte_as(&attr_bytes);
        assert!(attrs.iter().all(|a| a.code() != Attribute::AS4_PATH));
        let as_path = attrs
            .iter()
            .find(|a| a.code() == Attribute::AS_PATH)
            .unwrap();
        // The leading 2 hops are taken as a new SEQ segment (count=2) and the
        // AS4_PATH segment (count=3) is appended as-is -- RFC 6793 §4.2.3
        // prepends "AS numbers and path segments", it does not require
        // merging adjacent same-type segments into one (matching BIRD's
        // as_path_merge, a plain concatenation).
        let mut expected = seg_bytes(Attribute::AS_PATH_TYPE_SEQ, &[65000, 4000]);
        expected.extend_from_slice(&seg_bytes(
            Attribute::AS_PATH_TYPE_SEQ,
            &[400000, 300000, 40001],
        ));
        assert_eq!(as_path.binary().unwrap(), &expected);
    }

    #[test]
    fn reconcile_equal_hop_counts_uses_as4_path_directly() {
        let mut attr_bytes = origin_and_nexthop();
        attr_bytes.extend_from_slice(&attr_tlv(0x40, Attribute::AS_PATH, GOBGP_AS2_65000_TRANS));
        attr_bytes.extend_from_slice(&attr_tlv(0xC0, Attribute::AS4_PATH, GOBGP_AS4_65000_400000));
        let attrs = parse_attrs_2byte_as(&attr_bytes);
        let as_path = attrs
            .iter()
            .find(|a| a.code() == Attribute::AS_PATH)
            .unwrap();
        assert_eq!(
            as_path.binary().unwrap(),
            &seg_bytes(Attribute::AS_PATH_TYPE_SEQ, &[65000, 400000])
        );
    }

    #[test]
    fn as4_path_ignored_when_longer_than_as_path() {
        let mut attr_bytes = origin_and_nexthop();
        attr_bytes.extend_from_slice(&attr_tlv(0x40, Attribute::AS_PATH, GOBGP_AS2_65000_TRANS));
        attr_bytes.extend_from_slice(&attr_tlv(
            0xC0,
            Attribute::AS4_PATH,
            GOBGP_AS4_65000_400000_300000,
        ));
        let attrs = parse_attrs_2byte_as(&attr_bytes);
        assert!(attrs.iter().all(|a| a.code() != Attribute::AS4_PATH));
        let as_path = attrs
            .iter()
            .find(|a| a.code() == Attribute::AS_PATH)
            .unwrap();
        // AS_TRANS (23456) is left unresolved: AS4_PATH was ignored (RFC 6793 §4.2.3).
        assert_eq!(
            as_path.binary().unwrap(),
            &seg_bytes(Attribute::AS_PATH_TYPE_SEQ, &[65000, 23456])
        );
    }

    #[test]
    fn as_set_counts_as_one_hop() {
        let mut attr_bytes = origin_and_nexthop();
        attr_bytes.extend_from_slice(&attr_tlv(
            0x40,
            Attribute::AS_PATH,
            GOBGP_AS2_SET_65010_65020_SEQ_TRANS,
        ));
        attr_bytes.extend_from_slice(&attr_tlv(0xC0, Attribute::AS4_PATH, GOBGP_AS4_500000));
        let attrs = parse_attrs_2byte_as(&attr_bytes);
        let as_path = attrs
            .iter()
            .find(|a| a.code() == Attribute::AS_PATH)
            .unwrap();
        let mut expected = seg_bytes(Attribute::AS_PATH_TYPE_SET, &[65010, 65020]);
        expected.extend_from_slice(&seg_bytes(Attribute::AS_PATH_TYPE_SEQ, &[500000]));
        assert_eq!(as_path.binary().unwrap(), &expected);
    }

    #[test]
    fn confed_segment_carried_through_without_consuming_hop_budget() {
        let mut attr_bytes = origin_and_nexthop();
        attr_bytes.extend_from_slice(&attr_tlv(
            0x40,
            Attribute::AS_PATH,
            GOBGP_AS2_CONFEDSEQ_65001_SEQ_65000_TRANS,
        ));
        attr_bytes.extend_from_slice(&attr_tlv(0xC0, Attribute::AS4_PATH, GOBGP_AS4_600000));
        let attrs = parse_attrs_2byte_as(&attr_bytes);
        let as_path = attrs
            .iter()
            .find(|a| a.code() == Attribute::AS_PATH)
            .unwrap();
        let mut expected = seg_bytes(Attribute::AS_PATH_TYPE_CONFED_SEQ, &[65001]);
        expected.extend_from_slice(&seg_bytes(Attribute::AS_PATH_TYPE_SEQ, &[65000]));
        expected.extend_from_slice(&seg_bytes(Attribute::AS_PATH_TYPE_SEQ, &[600000]));
        assert_eq!(as_path.binary().unwrap(), &expected);
    }

    #[test]
    fn aggregator_reconciled_when_as_trans() {
        let mut attr_bytes = origin_and_nexthop();
        attr_bytes.extend_from_slice(&attr_tlv(0x40, Attribute::AS_PATH, GOBGP_AS2_65000_TRANS));
        attr_bytes.extend_from_slice(&attr_tlv(
            0xC0,
            Attribute::AGGREGATOR,
            GOBGP_AGGREGATOR_TRANS_198_51_100_1,
        ));
        attr_bytes.extend_from_slice(&attr_tlv(
            0xC0,
            Attribute::AS4_AGGREGATOR,
            GOBGP_AS4_AGGREGATOR_400000_198_51_100_1,
        ));
        let attrs = parse_attrs_2byte_as(&attr_bytes);
        assert!(attrs.iter().all(|a| a.code() != Attribute::AS4_AGGREGATOR));
        let agg = attrs
            .iter()
            .find(|a| a.code() == Attribute::AGGREGATOR)
            .unwrap();
        assert_eq!(
            agg.binary().unwrap(),
            &aggregator_bin(400000, Ipv4Addr::new(198, 51, 100, 1))
        );
    }

    #[test]
    fn aggregator_not_as_trans_ignores_as4_aggregator_and_as4_path() {
        let mut attr_bytes = origin_and_nexthop();
        attr_bytes.extend_from_slice(&attr_tlv(0x40, Attribute::AS_PATH, GOBGP_AS2_65000_TRANS));
        attr_bytes.extend_from_slice(&attr_tlv(
            0xC0,
            Attribute::AGGREGATOR,
            GOBGP_AGGREGATOR_65055_198_51_100_1,
        ));
        attr_bytes.extend_from_slice(&attr_tlv(
            0xC0,
            Attribute::AS4_AGGREGATOR,
            GOBGP_AS4_AGGREGATOR_400000_198_51_100_1,
        ));
        attr_bytes.extend_from_slice(&attr_tlv(0xC0, Attribute::AS4_PATH, GOBGP_AS4_65000_400000));
        let attrs = parse_attrs_2byte_as(&attr_bytes);
        assert!(attrs.iter().all(|a| a.code() != Attribute::AS4_AGGREGATOR));
        assert!(attrs.iter().all(|a| a.code() != Attribute::AS4_PATH));
        let agg = attrs
            .iter()
            .find(|a| a.code() == Attribute::AGGREGATOR)
            .unwrap();
        assert_eq!(
            agg.binary().unwrap(),
            &aggregator_bin(65055, Ipv4Addr::new(198, 51, 100, 1))
        );
        // RFC 6793 §4.2.3: AS_PATH reconciliation is skipped too in this case.
        let as_path = attrs
            .iter()
            .find(|a| a.code() == Attribute::AS_PATH)
            .unwrap();
        assert_eq!(
            as_path.binary().unwrap(),
            &seg_bytes(Attribute::AS_PATH_TYPE_SEQ, &[65000, 23456])
        );
    }

    #[test]
    fn malformed_as4_path_discarded_not_treat_as_withdraw() {
        let mut attr_bytes = origin_and_nexthop();
        attr_bytes.extend_from_slice(&attr_tlv(0x40, Attribute::AS_PATH, GOBGP_AS2_65000_TRANS));
        // RFC 6793 §6: length 7 is not a multiple of two -> malformed.
        attr_bytes.extend_from_slice(&attr_tlv(
            0xC0,
            Attribute::AS4_PATH,
            &[0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00],
        ));
        let buf = raw_update_with_attrs(&attr_bytes);
        let parsed = ipv4_codec_2byte_as()
            .parse_message(&buf)
            .expect("parse must not fail");
        let msgs: Vec<Message> = validate_message(parsed, false).unwrap().collect();
        assert_eq!(msgs.len(), 1);
        // RFC 6793 §6 mandates plain attribute discard, not treat-as-withdraw.
        match &msgs[0] {
            Message::Update(Update::Reach { attr, .. }) => {
                assert!(attr.iter().all(|a| a.code() != Attribute::AS4_PATH));
                let as_path = attr
                    .iter()
                    .find(|a| a.code() == Attribute::AS_PATH)
                    .unwrap();
                assert_eq!(
                    as_path.binary().unwrap(),
                    &seg_bytes(Attribute::AS_PATH_TYPE_SEQ, &[65000, 23456])
                );
            }
            _ => panic!("expected Reach message"),
        }
    }

    #[test]
    fn malformed_as4_aggregator_discarded_not_treat_as_withdraw() {
        let mut attr_bytes = origin_and_nexthop();
        attr_bytes.extend_from_slice(&attr_tlv(0x40, Attribute::AS_PATH, GOBGP_AS2_65000_TRANS));
        // RFC 6793 §6: AS4_AGGREGATOR length must be exactly 8.
        attr_bytes.extend_from_slice(&attr_tlv(0xC0, Attribute::AS4_AGGREGATOR, &[0u8; 7]));
        let buf = raw_update_with_attrs(&attr_bytes);
        let parsed = ipv4_codec_2byte_as()
            .parse_message(&buf)
            .expect("parse must not fail");
        let msgs: Vec<Message> = validate_message(parsed, false).unwrap().collect();
        assert_eq!(msgs.len(), 1);
        assert!(matches!(&msgs[0], Message::Update(Update::Reach { .. })));
    }

    #[test]
    fn as4_path_from_as4_capable_peer_is_discarded() {
        let mut attr_bytes = origin_and_nexthop();
        attr_bytes.extend_from_slice(&attr_tlv(
            0x40,
            Attribute::AS_PATH,
            &seg_bytes(Attribute::AS_PATH_TYPE_SEQ, &[65000]),
        ));
        attr_bytes.extend_from_slice(&attr_tlv(
            0xC0,
            Attribute::AS4_PATH,
            GOBGP_AS4_400000_300000_40001,
        ));
        let buf = raw_update_with_attrs(&attr_bytes);
        // A plain (AS4-capable, two_byte_as == false) session.
        match ipv4_codec().parse_message(&buf).unwrap() {
            ParsedMessage::Update(ParsedUpdate::Routes { attrs, .. }) => {
                assert!(attrs.iter().all(|a| a.code() != Attribute::AS4_PATH));
                let as_path = attrs
                    .iter()
                    .find(|a| a.code() == Attribute::AS_PATH)
                    .unwrap();
                assert_eq!(
                    as_path.binary().unwrap(),
                    &seg_bytes(Attribute::AS_PATH_TYPE_SEQ, &[65000])
                );
            }
            _ => panic!("expected Update::Routes"),
        }
    }

    // --- encode (RFC 6793 §4.2.2) ---

    #[test]
    fn encode_writes_downgraded_as_path_and_as4_path() {
        let attr = Arc::new(vec![
            Attribute::new_with_value(Attribute::ORIGIN, 0).unwrap(),
            Attribute::new_with_bin(
                Attribute::AS_PATH,
                seg_bytes(
                    Attribute::AS_PATH_TYPE_SEQ,
                    &[65000, 4000, 400000, 300000, 40001],
                ),
            )
            .unwrap(),
        ]);
        let msg = Message::Update(Update::Reach {
            family: Family::IPV4,
            entries: vec![ipv4_prefix("10.0.0.0", 8)],
            nexthop: None,
            attr,
        });
        let mut buf = Vec::new();
        ipv4_codec_2byte_as().encode_to(&msg, &mut buf).unwrap();
        assert!(contains_subsequence(
            &buf,
            &attr_tlv(
                0x40,
                Attribute::AS_PATH,
                GOBGP_AS2_65000_4000_TRANS_TRANS_40001
            )
        ));
        assert!(contains_subsequence(
            &buf,
            &attr_tlv(
                0xC0,
                Attribute::AS4_PATH,
                GOBGP_AS4_65000_4000_400000_300000_40001
            )
        ));
    }

    #[test]
    fn encode_omits_as4_path_when_no_wide_as() {
        let attr = Arc::new(vec![
            Attribute::new_with_value(Attribute::ORIGIN, 0).unwrap(),
            Attribute::new_with_bin(
                Attribute::AS_PATH,
                seg_bytes(Attribute::AS_PATH_TYPE_SEQ, &[65000, 4000]),
            )
            .unwrap(),
        ]);
        let msg = Message::Update(Update::Reach {
            family: Family::IPV4,
            entries: vec![ipv4_prefix("10.0.0.0", 8)],
            nexthop: None,
            attr,
        });
        let mut buf = Vec::new();
        ipv4_codec_2byte_as().encode_to(&msg, &mut buf).unwrap();
        assert!(!contains_subsequence(&buf, &[0xC0, Attribute::AS4_PATH]));
    }

    #[test]
    fn encode_writes_downgraded_aggregator_and_as4_aggregator() {
        let attr = Arc::new(vec![
            Attribute::new_with_value(Attribute::ORIGIN, 0).unwrap(),
            Attribute::new_with_bin(
                Attribute::AS_PATH,
                seg_bytes(Attribute::AS_PATH_TYPE_SEQ, &[65000]),
            )
            .unwrap(),
            Attribute::new_with_bin(
                Attribute::AGGREGATOR,
                aggregator_bin(400000, Ipv4Addr::new(198, 51, 100, 1)),
            )
            .unwrap(),
        ]);
        let msg = Message::Update(Update::Reach {
            family: Family::IPV4,
            entries: vec![ipv4_prefix("10.0.0.0", 8)],
            nexthop: None,
            attr,
        });
        let mut buf = Vec::new();
        ipv4_codec_2byte_as().encode_to(&msg, &mut buf).unwrap();
        assert!(contains_subsequence(
            &buf,
            &attr_tlv(
                0xC0,
                Attribute::AGGREGATOR,
                GOBGP_AGGREGATOR_TRANS_198_51_100_1
            )
        ));
        assert!(contains_subsequence(
            &buf,
            &attr_tlv(
                0xC0,
                Attribute::AS4_AGGREGATOR,
                GOBGP_AS4_AGGREGATOR_400000_198_51_100_1
            )
        ));
    }

    #[test]
    fn encode_omits_as4_aggregator_when_as_fits_two_bytes() {
        let attr = Arc::new(vec![
            Attribute::new_with_value(Attribute::ORIGIN, 0).unwrap(),
            Attribute::new_with_bin(
                Attribute::AS_PATH,
                seg_bytes(Attribute::AS_PATH_TYPE_SEQ, &[65000]),
            )
            .unwrap(),
            Attribute::new_with_bin(
                Attribute::AGGREGATOR,
                aggregator_bin(65055, Ipv4Addr::new(198, 51, 100, 1)),
            )
            .unwrap(),
        ]);
        let msg = Message::Update(Update::Reach {
            family: Family::IPV4,
            entries: vec![ipv4_prefix("10.0.0.0", 8)],
            nexthop: None,
            attr,
        });
        let mut buf = Vec::new();
        ipv4_codec_2byte_as().encode_to(&msg, &mut buf).unwrap();
        assert!(!contains_subsequence(
            &buf,
            &[0xC0, Attribute::AS4_AGGREGATOR]
        ));
    }

    // --- full pipeline round trip ---

    #[test]
    fn round_trip_through_two_byte_as_session_preserves_as_path() {
        let attr = Arc::new(vec![
            Attribute::new_with_value(Attribute::ORIGIN, 0).unwrap(),
            Attribute::new_with_bin(
                Attribute::AS_PATH,
                seg_bytes(
                    Attribute::AS_PATH_TYPE_SEQ,
                    &[65000, 4000, 400000, 300000, 40001],
                ),
            )
            .unwrap(),
        ]);
        let msg = Message::Update(Update::Reach {
            family: Family::IPV4,
            entries: vec![ipv4_prefix("10.0.0.0", 8)],
            nexthop: None,
            attr,
        });
        match round_trip(&msg, ipv4_codec_2byte_as()) {
            ParsedMessage::Update(ParsedUpdate::Routes { attrs, .. }) => {
                assert!(attrs.iter().all(|a| a.code() != Attribute::AS4_PATH));
                let as_path = attrs
                    .iter()
                    .find(|a| a.code() == Attribute::AS_PATH)
                    .unwrap();
                assert_eq!(
                    as_path.binary().unwrap(),
                    &seg_bytes(
                        Attribute::AS_PATH_TYPE_SEQ,
                        &[65000, 4000, 400000, 300000, 40001]
                    )
                );
            }
            _ => panic!("expected Update::Routes"),
        }
    }

    #[test]
    fn round_trip_through_two_byte_as_session_preserves_aggregator() {
        let attr = Arc::new(vec![
            Attribute::new_with_value(Attribute::ORIGIN, 0).unwrap(),
            Attribute::new_with_bin(
                Attribute::AS_PATH,
                seg_bytes(Attribute::AS_PATH_TYPE_SEQ, &[65000]),
            )
            .unwrap(),
            Attribute::new_with_bin(
                Attribute::AGGREGATOR,
                aggregator_bin(400000, Ipv4Addr::new(198, 51, 100, 1)),
            )
            .unwrap(),
        ]);
        let msg = Message::Update(Update::Reach {
            family: Family::IPV4,
            entries: vec![ipv4_prefix("10.0.0.0", 8)],
            nexthop: None,
            attr,
        });
        match round_trip(&msg, ipv4_codec_2byte_as()) {
            ParsedMessage::Update(ParsedUpdate::Routes { attrs, .. }) => {
                assert!(attrs.iter().all(|a| a.code() != Attribute::AS4_AGGREGATOR));
                let agg = attrs
                    .iter()
                    .find(|a| a.code() == Attribute::AGGREGATOR)
                    .unwrap();
                assert_eq!(
                    agg.binary().unwrap(),
                    &aggregator_bin(400000, Ipv4Addr::new(198, 51, 100, 1))
                );
            }
            _ => panic!("expected Update::Routes"),
        }
    }
}
