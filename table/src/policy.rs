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

use fnv::FnvHashMap;
use ip_network_table_deps_treebitmap::IpLookupTable;
use regex::Regex;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::{Arc, LazyLock};

use rustybgp_packet::{self as packet, Attribute, bgp};

use crate::{RpkiTable, RpkiValidationState, Source, TableError};

#[derive(Clone, PartialEq)]
pub struct Prefix {
    pub net: packet::IpNet,
    pub min_length: u8,
    pub max_length: u8,
}

type SingleMatchRegex = (Regex, fn(s: &regex::Captures) -> Option<SingleAsPathMatch>);

static SINGLE_MATCH_REGEX: LazyLock<Vec<SingleMatchRegex>> = LazyLock::new(|| {
    vec![
        (
            Regex::new(r"^_([0-9]+)_$").unwrap(),
            (|m| SingleAsPathMatch::parse_single(m).map(SingleAsPathMatch::Include)),
        ),
        (
            Regex::new(r"^\^([0-9]+)_$").unwrap(),
            (|m| SingleAsPathMatch::parse_single(m).map(SingleAsPathMatch::LeftMost)),
        ),
        (
            Regex::new(r"^_([0-9]+)\$$").unwrap(),
            (|m| SingleAsPathMatch::parse_single(m).map(SingleAsPathMatch::Origin)),
        ),
        (
            Regex::new(r"^\^([0-9]+)\$$").unwrap(),
            (|m| SingleAsPathMatch::parse_single(m).map(SingleAsPathMatch::Only)),
        ),
        (
            Regex::new(r"^_([0-9]+)-([0-9]+)_$").unwrap(),
            (|m| {
                SingleAsPathMatch::parse_double(m)
                    .map(|(a, b)| SingleAsPathMatch::RangeInclude(a, b))
            }),
        ),
        (
            Regex::new(r"^\^([0-9]+)-([0-9]+)_$").unwrap(),
            (|m| {
                SingleAsPathMatch::parse_double(m)
                    .map(|(a, b)| SingleAsPathMatch::RangeLeftMost(a, b))
            }),
        ),
        (
            Regex::new(r"^_([0-9]+)-([0-9]+)\$$").unwrap(),
            (|m| {
                SingleAsPathMatch::parse_double(m)
                    .map(|(a, b)| SingleAsPathMatch::RangeOrigin(a, b))
            }),
        ),
        (
            Regex::new(r"^\^([0-9]+)-([0-9]+)\$$").unwrap(),
            (|m| {
                SingleAsPathMatch::parse_double(m).map(|(a, b)| SingleAsPathMatch::RangeOnly(a, b))
            }),
        ),
    ]
});

#[derive(Clone, PartialEq, Debug)]
pub enum SingleAsPathMatch {
    Include(u32),
    LeftMost(u32),
    Origin(u32),
    Only(u32),
    RangeInclude(u32, u32),
    RangeLeftMost(u32, u32),
    RangeOrigin(u32, u32),
    RangeOnly(u32, u32),
}

impl SingleAsPathMatch {
    pub(crate) fn new(s: &str) -> Option<Self> {
        for (r, f) in &*SINGLE_MATCH_REGEX {
            if let Some(c) = r.captures(s) {
                return f(&c);
            }
        }
        None
    }

    fn parse_single(caps: &regex::Captures) -> Option<u32> {
        if caps.len() != 2 {
            return None;
        }
        caps[1].parse::<u32>().ok()
    }

    fn parse_double(caps: &regex::Captures) -> Option<(u32, u32)> {
        if caps.len() != 3 {
            return None;
        }
        let a = caps[1].parse::<u32>().ok()?;
        let b = caps[2].parse::<u32>().ok()?;
        Some((a, b))
    }

    fn is_match(&self, attr: &Attribute) -> bool {
        let mut i = packet::bgp::AsPathIter::new(attr);
        match self {
            SingleAsPathMatch::Include(val) => {
                for v in i {
                    for asn in v {
                        if asn == *val {
                            return true;
                        }
                    }
                }
            }
            SingleAsPathMatch::RangeInclude(min, max) => {
                for v in i {
                    for asn in v {
                        if asn >= *min && asn <= *max {
                            return true;
                        }
                    }
                }
            }
            SingleAsPathMatch::LeftMost(val) => {
                if let Some(v) = i.next() {
                    return !v.is_empty() && v[0] == *val;
                }
            }
            SingleAsPathMatch::RangeLeftMost(min, max) => {
                if let Some(v) = i.next() {
                    return !v.is_empty() && v[0] >= *min && v[0] <= *max;
                }
            }
            SingleAsPathMatch::Origin(val) => {
                let v: Vec<Vec<u32>> = i.collect();
                return !v.is_empty() && v[v.len() - 1][v[v.len() - 1].len() - 1] == *val;
            }
            SingleAsPathMatch::RangeOrigin(min, max) => {
                let v: Vec<Vec<u32>> = i.collect();
                return !v.is_empty()
                    && v[v.len() - 1][v[v.len() - 1].len() - 1] >= *min
                    && v[v.len() - 1][v[v.len() - 1].len() - 1] <= *max;
            }
            SingleAsPathMatch::Only(val) => {
                let v: Vec<Vec<u32>> = i.collect();
                return v.len() == 1 && v[0].len() == 1 && v[0][0] == *val;
            }
            SingleAsPathMatch::RangeOnly(min, max) => {
                let v: Vec<Vec<u32>> = i.collect();
                return v.len() == 1 && v[0].len() == 1 && v[0][0] >= *min && v[0][0] <= *max;
            }
        }
        false
    }
}

impl fmt::Display for SingleAsPathMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SingleAsPathMatch::Include(v) => write!(f, "_{}_", v),
            SingleAsPathMatch::LeftMost(v) => write!(f, "^{}_", v),
            SingleAsPathMatch::Origin(v) => write!(f, "_{}$", v),
            SingleAsPathMatch::Only(v) => write!(f, "^{}$", v),
            SingleAsPathMatch::RangeInclude(min, max) => write!(f, "_{}-{}_", min, max),
            SingleAsPathMatch::RangeLeftMost(min, max) => write!(f, "^{}-{}_", min, max),
            SingleAsPathMatch::RangeOrigin(min, max) => write!(f, "_{}-{}$", min, max),
            SingleAsPathMatch::RangeOnly(min, max) => write!(f, "^{}-{}$", min, max),
        }
    }
}

enum WellKnownCommunity {
    GracefulShutdown,
    AcceptOwn,
    LlgrStale,
    NoLlgr,
    Blackhole,
    NoExport,
    NoAdvertise,
    NoExportSubconfed,
    NoPeer,
}

impl FromStr for WellKnownCommunity {
    type Err = TableError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "graceful-shutdown" => Ok(WellKnownCommunity::GracefulShutdown),
            "accept-own" => Ok(WellKnownCommunity::AcceptOwn),
            "llgr-stale" => Ok(WellKnownCommunity::LlgrStale),
            "no-llgr" => Ok(WellKnownCommunity::NoLlgr),
            "blackhole" => Ok(WellKnownCommunity::Blackhole),
            "no-export" => Ok(WellKnownCommunity::NoExport),
            "no-advertise" => Ok(WellKnownCommunity::NoAdvertise),
            "no-export-subconfed" => Ok(WellKnownCommunity::NoExportSubconfed),
            "no-peer" => Ok(WellKnownCommunity::NoPeer),
            _ => Err(TableError::InvalidArgument(format!(
                "unknown community {}",
                s
            ))),
        }
    }
}

impl From<WellKnownCommunity> for u32 {
    fn from(c: WellKnownCommunity) -> Self {
        match c {
            WellKnownCommunity::GracefulShutdown => 0xffff_0000,
            WellKnownCommunity::AcceptOwn => 0xffff_0001,
            WellKnownCommunity::LlgrStale => 0xffff_0006,
            WellKnownCommunity::NoLlgr => 0xffff_0007,
            WellKnownCommunity::Blackhole => 0xffff_029a,
            WellKnownCommunity::NoExport => 0xffff_ff01,
            WellKnownCommunity::NoAdvertise => 0xffff_ff02,
            WellKnownCommunity::NoExportSubconfed => 0xffff_ff03,
            WellKnownCommunity::NoPeer => 0xffff_ff04,
        }
    }
}

fn parse_community(s: &str) -> Result<Regex, TableError> {
    if let Ok(v) = s.parse::<u32>() {
        return Regex::new(&format!("^{}:{}$", v >> 16, v & 0xffff))
            .map_err(|_| TableError::InvalidArgument(format!("invalid regex {}", s)));
    }
    let r = Regex::new(r"(\d+.)*\d+:\d+").unwrap();
    if r.is_match(s) {
        return Regex::new(&format!("^{}$", s))
            .map_err(|_| TableError::InvalidArgument(format!("invalid regex {}", s)));
    }
    if let Ok(c) = WellKnownCommunity::from_str(&s.to_string().to_lowercase()) {
        let v = c as u32;
        return Regex::new(&format!("^{}:{}$", v >> 16, v & 0xffff))
            .map_err(|_| TableError::InvalidArgument(format!("invalid regex {}", s)));
    }
    Regex::new(s).map_err(|_| TableError::InvalidArgument(format!("invalid regex {}", s)))
}

#[derive(Clone, PartialEq)]
pub enum MatchOption {
    Any,
    All,
    Invert,
}

impl TryFrom<i32> for MatchOption {
    type Error = TableError;
    fn try_from(o: i32) -> Result<Self, Self::Error> {
        match o {
            0 => return Ok(MatchOption::Any),
            1 => return Ok(MatchOption::All),
            2 => return Ok(MatchOption::Invert),
            _ => {}
        }
        Err(TableError::InvalidArgument(
            "invalid match option".to_string(),
        ))
    }
}

impl From<&MatchOption> for i32 {
    fn from(my: &MatchOption) -> Self {
        match my {
            MatchOption::Any => 0,
            MatchOption::All => 1,
            MatchOption::Invert => 2,
        }
    }
}

#[derive(Clone, Copy)]
pub enum Comparison {
    Eq,
    Ge,
    Le,
}

impl From<Comparison> for i32 {
    fn from(c: Comparison) -> i32 {
        match c {
            Comparison::Eq => 0,
            Comparison::Ge => 1,
            Comparison::Le => 2,
        }
    }
}

impl From<i32> for Comparison {
    fn from(l: i32) -> Self {
        match l {
            0 => Comparison::Eq,
            1 => Comparison::Ge,
            2 => Comparison::Le,
            _ => Comparison::Eq,
        }
    }
}

#[derive(Clone)]
pub enum Condition {
    Prefix(String, MatchOption, Arc<PrefixSet>),
    Neighbor(String, MatchOption, Arc<NeighborSet>),
    AsPath(String, MatchOption, Arc<AsPathSet>),
    Community(String, MatchOption, Arc<CommunitySet>),
    Nexthop(Vec<IpAddr>),
    ExtCommunity(String, MatchOption, Arc<ExtCommunitySet>),
    AsPathLength(Comparison, u32),
    Rpki(RpkiValidationState),
    LargeCommunity(String, MatchOption, Arc<LargeCommunitySet>),
    LocalPrefEq(u32),
    MedEq(u32),
    /// BGP ORIGIN value: 0=IGP, 1=EGP, 2=Incomplete
    Origin(u8),
    RouteType(RouteType),
    CommunityCount(Comparison, u32),
    AfiSafiIn(Vec<bgp::Family>),
}

#[derive(Clone, Copy, PartialEq)]
pub enum RouteType {
    Internal,
    External,
    Local,
}

impl Condition {
    fn evalute(
        &self,
        source: &Arc<Source>,
        net: &packet::Nlri,
        attr: &Arc<Vec<packet::Attribute>>,
        nexthop: Option<&bgp::Nexthop>,
        peer_addr: IpAddr,
        rpki: Option<&RpkiTable>,
    ) -> bool {
        match self {
            Condition::Prefix(_name, opt, set) => {
                match net {
                    packet::Nlri::V4(n) => {
                        if let Some(zero) = set.zero
                            && zero.0 <= n.mask
                            && n.mask <= zero.1
                        {
                            return *opt == MatchOption::Any;
                        }
                        if let Some((_, _, p)) = set.v4.longest_match(n.addr)
                            && p.min_length <= n.mask
                            && n.mask <= p.max_length
                        {
                            return *opt == MatchOption::Any;
                        }
                        return !(*opt == MatchOption::Any);
                    }
                    packet::Nlri::V6(n) => {
                        if let Some(zero6) = set.zero6
                            && zero6.0 <= n.mask
                            && n.mask <= zero6.1
                        {
                            return *opt == MatchOption::Any;
                        }
                        if let Some((_, _, p)) = set.v6.longest_match(n.addr)
                            && p.min_length <= n.mask
                            && n.mask <= p.max_length
                        {
                            return *opt == MatchOption::Any;
                        }
                        return !(*opt == MatchOption::Any);
                    }
                    packet::Nlri::Mup(_) => {}
                    packet::Nlri::VpnV4(_) | packet::Nlri::VpnV6(_) => {}
                    packet::Nlri::LabeledV4(_) | packet::Nlri::LabeledV6(_) => {}
                    packet::Nlri::FlowspecV4(_)
                    | packet::Nlri::FlowspecV6(_)
                    | packet::Nlri::FlowspecVpnV4(_)
                    | packet::Nlri::FlowspecVpnV6(_)
                    | packet::Nlri::Ls(_)
                    | packet::Nlri::SrPolicy(_)
                    | packet::Nlri::Evpn(_)
                    | packet::Nlri::Rtc(_) => {}
                };
            }
            Condition::AsPath(_name, opt, set) => {
                if let Some(a) = attr.iter().find(|a| a.code() == packet::Attribute::AS_PATH) {
                    for set in &set.single_sets {
                        if set.is_match(a) {
                            return *opt == MatchOption::Any;
                        }
                    }
                }
                return !(*opt == MatchOption::Any);
            }
            Condition::Neighbor(_name, opt, set) => {
                let mut found = false;
                for n in &set.sets {
                    if n.contains(&peer_addr) {
                        found = true;
                        break;
                    }
                }
                if *opt == MatchOption::Invert {
                    found = !found;
                }
                return found;
            }
            Condition::AsPathLength(c, v) => {
                if let Some(a) = attr.iter().find(|a| a.code() == packet::Attribute::AS_PATH) {
                    let l = a.as_path_length() as u32;
                    match c {
                        Comparison::Eq => {
                            return l == *v;
                        }
                        Comparison::Ge => {
                            return l >= *v;
                        }
                        Comparison::Le => {
                            return l <= *v;
                        }
                    }
                }
                return false;
            }
            Condition::Rpki(expected) => {
                return rpki
                    .and_then(|r| r.validate(source, net, attr))
                    .is_some_and(|v| v.state == *expected);
            }
            Condition::LocalPrefEq(v) => {
                return attr
                    .iter()
                    .find(|a| a.code() == packet::Attribute::LOCAL_PREF)
                    .and_then(|a| a.value())
                    == Some(*v);
            }
            Condition::MedEq(v) => {
                return attr
                    .iter()
                    .find(|a| a.code() == packet::Attribute::MULTI_EXIT_DESC)
                    .and_then(|a| a.value())
                    == Some(*v);
            }
            Condition::Origin(v) => {
                return attr
                    .iter()
                    .find(|a| a.code() == packet::Attribute::ORIGIN)
                    .and_then(|a| a.value())
                    == Some(*v as u32);
            }
            Condition::RouteType(rt) => {
                return match rt {
                    RouteType::Local => source.is_local(),
                    RouteType::Internal => {
                        !source.is_local() && source.remote_asn == source.local_asn
                    }
                    RouteType::External => {
                        !source.is_local() && source.remote_asn != source.local_asn
                    }
                };
            }
            Condition::CommunityCount(cmp, v) => {
                let count = communities_from_attr(attr).len() as u32;
                return match cmp {
                    Comparison::Eq => count == *v,
                    Comparison::Ge => count >= *v,
                    Comparison::Le => count <= *v,
                };
            }
            Condition::AfiSafiIn(families) => {
                return families.contains(&nlri_family(net));
            }
            Condition::Community(_name, opt, set) => {
                let communities = communities_from_attr(attr);
                let strs: Vec<String> = communities
                    .iter()
                    .map(|c| format!("{}:{}", c >> 16, c & 0xffff))
                    .collect();
                return match_string_set(&strs, &set.sets, opt);
            }
            Condition::Nexthop(nexthops) => {
                return nexthop.is_some_and(|nh| nexthops.contains(&nh.addr()));
            }
            Condition::ExtCommunity(_name, opt, set) => {
                let communities = ext_communities_from_attr(attr);
                let strs: Vec<String> = communities
                    .iter()
                    .filter_map(ext_community_to_string)
                    .collect();
                return match_string_set(&strs, &set.sets, opt);
            }
            Condition::LargeCommunity(_name, opt, set) => {
                let communities = large_communities_from_attr(attr);
                let strs: Vec<String> = communities
                    .iter()
                    .map(|(ga, ld1, ld2)| format!("{}:{}:{}", ga, ld1, ld2))
                    .collect();
                return match_string_set(&strs, &set.sets, opt);
            }
        }
        false
    }
}

fn match_string_set(strs: &[String], patterns: &[Regex], opt: &MatchOption) -> bool {
    match opt {
        MatchOption::Any => strs.iter().any(|s| patterns.iter().any(|r| r.is_match(s))),
        MatchOption::All => patterns.iter().all(|r| strs.iter().any(|s| r.is_match(s))),
        MatchOption::Invert => !strs.iter().any(|s| patterns.iter().any(|r| r.is_match(s))),
    }
}

fn ext_community_to_string(c: &[u8; 8]) -> Option<String> {
    match (c[0], c[1]) {
        (0x00, 0x02) | (0x00, 0x03) => {
            let prefix = if c[1] == 0x02 { "rt" } else { "soo" };
            let asn = u16::from_be_bytes([c[2], c[3]]);
            let local = u32::from_be_bytes([c[4], c[5], c[6], c[7]]);
            Some(format!("{}:{}:{}", prefix, asn, local))
        }
        (0x02, 0x02) | (0x02, 0x03) => {
            let prefix = if c[1] == 0x02 { "rt" } else { "soo" };
            let asn = u32::from_be_bytes([c[2], c[3], c[4], c[5]]);
            let local = u16::from_be_bytes([c[6], c[7]]);
            Some(format!("{}:{}:{}", prefix, asn, local))
        }
        (0x01, 0x02) | (0x01, 0x03) => {
            let prefix = if c[1] == 0x02 { "rt" } else { "soo" };
            let addr = Ipv4Addr::new(c[2], c[3], c[4], c[5]);
            let local = u16::from_be_bytes([c[6], c[7]]);
            Some(format!("{}:{}:{}", prefix, addr, local))
        }
        (0x03, 0x0c) => {
            let tunnel_type = u16::from_be_bytes([c[6], c[7]]);
            Some(format!("encap:{}", tunnel_type))
        }
        (0x40, 0x04) => {
            let asn = u16::from_be_bytes([c[2], c[3]]);
            let bw = f32::from_bits(u32::from_be_bytes([c[4], c[5], c[6], c[7]]));
            Some(format!("lb:{}:{}", asn, bw))
        }
        (0x43, 0x00) => {
            let state = match c[7] {
                0 => "valid",
                1 => "not-found",
                2 => "invalid",
                _ => return None,
            };
            Some(format!("validation:{}", state))
        }
        _ => None,
    }
}

fn nlri_family(net: &packet::Nlri) -> bgp::Family {
    use packet::mup::MupNlri;
    match net {
        packet::Nlri::V4(_) => bgp::Family::IPV4,
        packet::Nlri::V6(_) => bgp::Family::IPV6,
        packet::Nlri::Mup(m) => {
            let is_ipv4 = match m {
                MupNlri::InterworkSegmentDiscovery(r) => r.prefix_addr.is_ipv4(),
                MupNlri::DirectSegmentDiscovery(r) => r.address.is_ipv4(),
                MupNlri::Type1SessionTransformed(r) => r.prefix_addr.is_ipv4(),
                MupNlri::Type2SessionTransformed(r) => r.endpoint_address.is_ipv4(),
            };
            if is_ipv4 {
                bgp::Family::IPV4_MUP
            } else {
                bgp::Family::IPV6_MUP
            }
        }
        packet::Nlri::VpnV4(_) => bgp::Family::IPV4_VPN,
        packet::Nlri::VpnV6(_) => bgp::Family::IPV6_VPN,
        packet::Nlri::LabeledV4(_) => bgp::Family::IPV4_MPLS,
        packet::Nlri::LabeledV6(_) => bgp::Family::IPV6_MPLS,
        packet::Nlri::FlowspecV4(_) => bgp::Family::IPV4_FLOWSPEC,
        packet::Nlri::FlowspecV6(_) => bgp::Family::IPV6_FLOWSPEC,
        packet::Nlri::FlowspecVpnV4(_) => bgp::Family::IPV4_FLOWSPEC_VPN,
        packet::Nlri::FlowspecVpnV6(_) => bgp::Family::IPV6_FLOWSPEC_VPN,
        packet::Nlri::Ls(_) => bgp::Family::LS,
        packet::Nlri::SrPolicy(n) => {
            if n.endpoint.is_ipv4() {
                bgp::Family::IPV4_SRPOLICY
            } else {
                bgp::Family::IPV6_SRPOLICY
            }
        }
        packet::Nlri::Evpn(_) => bgp::Family::L2VPN_EVPN,
        packet::Nlri::Rtc(_) => bgp::Family::RTC,
    }
}

#[derive(PartialEq, Clone, Copy, Debug)]
pub enum Disposition {
    Pass,
    Accept,
    Reject,
}

impl From<Disposition> for i32 {
    fn from(d: Disposition) -> i32 {
        match d {
            Disposition::Pass => 0,
            Disposition::Accept => 1,
            Disposition::Reject => 2,
        }
    }
}

/// Policy action to modify the nexthop of a route.
#[derive(Clone, Debug, PartialEq)]
pub enum NexthopAction {
    /// Set nexthop to a specific address.
    Address(IpAddr),
    /// Set nexthop to self (the local router's address).
    PeerSelf,
    /// Set nexthop to the peer's address.
    PeerAddress,
    /// Leave nexthop unchanged.
    Unchanged,
}

#[derive(Clone, Debug, PartialEq)]
pub enum CommunityActionType {
    Add,
    Remove,
    Replace,
}

/// Action to add, remove, or replace standard BGP communities (RFC 1997).
#[derive(Clone, Debug)]
pub struct CommunityAction {
    pub action_type: CommunityActionType,
    /// Community values in numeric form (high-16 << 16 | low-16).
    pub communities: Vec<u32>,
}

fn communities_from_attr(attrs: &[packet::Attribute]) -> Vec<u32> {
    attrs
        .iter()
        .find(|a| a.code() == packet::Attribute::COMMUNITY)
        .and_then(|a| a.binary())
        .map(|bin| {
            bin.chunks(4)
                .filter_map(|c| c.try_into().ok().map(|b: [u8; 4]| u32::from_be_bytes(b)))
                .collect()
        })
        .unwrap_or_default()
}

fn communities_to_attr(communities: Vec<u32>) -> Option<packet::Attribute> {
    if communities.is_empty() {
        return None;
    }
    let mut bin = Vec::with_capacity(communities.len() * 4);
    for c in communities {
        bin.extend_from_slice(&c.to_be_bytes());
    }
    packet::Attribute::new_with_bin(packet::Attribute::COMMUNITY, bin)
}

fn ext_communities_from_attr(attrs: &[packet::Attribute]) -> Vec<[u8; 8]> {
    attrs
        .iter()
        .find(|a| a.code() == packet::Attribute::EXTENDED_COMMUNITY)
        .and_then(|a| a.binary())
        .map(|bin| bin.chunks(8).filter_map(|c| c.try_into().ok()).collect())
        .unwrap_or_default()
}

fn ext_communities_to_attr(communities: Vec<[u8; 8]>) -> Option<packet::Attribute> {
    if communities.is_empty() {
        return None;
    }
    let mut bin = Vec::with_capacity(communities.len() * 8);
    for c in communities {
        bin.extend_from_slice(&c);
    }
    packet::Attribute::new_with_bin(packet::Attribute::EXTENDED_COMMUNITY, bin)
}

fn large_communities_from_attr(attrs: &[packet::Attribute]) -> Vec<(u32, u32, u32)> {
    attrs
        .iter()
        .find(|a| a.code() == packet::Attribute::LARGE_COMMUNITY)
        .and_then(|a| a.binary())
        .map(|bin| {
            bin.chunks(12)
                .filter_map(|c| {
                    if c.len() == 12 {
                        let ga = u32::from_be_bytes([c[0], c[1], c[2], c[3]]);
                        let ld1 = u32::from_be_bytes([c[4], c[5], c[6], c[7]]);
                        let ld2 = u32::from_be_bytes([c[8], c[9], c[10], c[11]]);
                        Some((ga, ld1, ld2))
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

fn large_communities_to_attr(communities: Vec<(u32, u32, u32)>) -> Option<packet::Attribute> {
    if communities.is_empty() {
        return None;
    }
    let mut bin = Vec::with_capacity(communities.len() * 12);
    for (ga, ld1, ld2) in communities {
        bin.extend_from_slice(&ga.to_be_bytes());
        bin.extend_from_slice(&ld1.to_be_bytes());
        bin.extend_from_slice(&ld2.to_be_bytes());
    }
    packet::Attribute::new_with_bin(packet::Attribute::LARGE_COMMUNITY, bin)
}

/// Action to set the LOCAL_PREF attribute to a fixed value.
#[derive(Clone, Debug, PartialEq)]
pub struct LocalPrefAction {
    pub value: u32,
}

#[derive(Clone, Debug, PartialEq)]
pub enum MedActionType {
    /// Add the signed value to the existing MED (clamped to [0, u32::MAX]).
    Mod,
    /// Set the MED to the given value regardless of any existing MED.
    Replace,
}

/// Action to modify or replace the MULTI_EXIT_DISC (MED) attribute.
#[derive(Clone, Debug)]
pub struct MedAction {
    pub action_type: MedActionType,
    /// For Mod: signed delta. For Replace: the new MED value (must be >= 0).
    pub value: i64,
}

/// Action to prepend an ASN to the AS_PATH attribute N times.
#[derive(Clone, Debug)]
pub struct AsPrependAction {
    /// ASN to prepend. Ignored when use_left_most is true.
    pub asn: u32,
    /// Number of times to prepend.
    pub repeat: u32,
    /// If true, prepend the leftmost existing ASN in the path instead of asn.
    pub use_left_most: bool,
}

/// Action to add, remove, or replace BGP extended communities (RFC 4360).
/// Each community is stored as its 8-byte wire-format representation.
#[derive(Clone, Debug)]
pub struct ExtCommunityAction {
    pub action_type: CommunityActionType,
    pub communities: Vec<[u8; 8]>,
}

/// Action to add, remove, or replace BGP large communities (RFC 8092).
/// Each community is a (global_administrator, local_data_1, local_data_2) triple.
#[derive(Clone, Debug)]
pub struct LargeCommunityAction {
    pub action_type: CommunityActionType,
    pub communities: Vec<(u32, u32, u32)>,
}

/// Action to overwrite the ORIGIN attribute (RFC 4271 section 5.1.1).
/// origin: 0=IGP, 1=EGP, 2=Incomplete
#[derive(Clone, Debug, PartialEq)]
pub struct OriginAction {
    pub origin: u8,
}

/// Actions applied to a route when a policy statement matches.
#[derive(Clone, Default)]
pub struct Actions {
    pub nexthop: Option<NexthopAction>,
    pub community: Option<CommunityAction>,
    pub local_pref: Option<LocalPrefAction>,
    pub med: Option<MedAction>,
    pub as_prepend: Option<AsPrependAction>,
    pub ext_community: Option<ExtCommunityAction>,
    pub large_community: Option<LargeCommunityAction>,
    pub origin: Option<OriginAction>,
}

#[derive(Clone)]
pub struct Statement {
    pub name: Arc<str>,
    // ALL the conditions are matched, the action will be executed.
    pub conditions: Vec<Condition>,
    pub disposition: Option<Disposition>,
    pub actions: Actions,
}

impl Statement {
    #[allow(clippy::too_many_arguments)]
    fn apply(
        &self,
        source: &Arc<Source>,
        net: &packet::Nlri,
        attr: &mut Arc<Vec<packet::Attribute>>,
        nexthop: &mut Option<bgp::Nexthop>,
        local_addr: IpAddr,
        peer_addr: IpAddr,
        rpki: Option<&RpkiTable>,
    ) -> Disposition {
        let matched = self
            .conditions
            .iter()
            .all(|c| c.evalute(source, net, attr, nexthop.as_ref(), peer_addr, rpki));
        if !matched {
            return Disposition::Pass;
        }

        if let Some(action) = &self.actions.nexthop {
            match action {
                NexthopAction::Address(addr) => {
                    *nexthop = Some(match addr {
                        IpAddr::V4(v4) => bgp::Nexthop::V4(*v4),
                        IpAddr::V6(v6) => bgp::Nexthop::V6(*v6),
                    });
                }
                NexthopAction::PeerSelf => {
                    *nexthop = Some(match local_addr {
                        IpAddr::V4(v4) => bgp::Nexthop::V4(v4),
                        IpAddr::V6(v6) => bgp::Nexthop::V6(v6),
                    });
                }
                NexthopAction::PeerAddress => {
                    *nexthop = Some(match peer_addr {
                        IpAddr::V4(v4) => bgp::Nexthop::V4(v4),
                        IpAddr::V6(v6) => bgp::Nexthop::V6(v6),
                    });
                }
                NexthopAction::Unchanged => {}
            }
        }

        if let Some(action) = &self.actions.community {
            let attrs = Arc::make_mut(attr);
            let existing = communities_from_attr(attrs);
            let new_communities = match action.action_type {
                CommunityActionType::Add => {
                    let mut result = existing;
                    result.extend_from_slice(&action.communities);
                    result
                }
                CommunityActionType::Remove => existing
                    .into_iter()
                    .filter(|c| !action.communities.contains(c))
                    .collect(),
                CommunityActionType::Replace => action.communities.clone(),
            };
            attrs.retain(|a| a.code() != packet::Attribute::COMMUNITY);
            if let Some(new_attr) = communities_to_attr(new_communities) {
                attrs.push(new_attr);
            }
        }

        if let Some(action) = &self.actions.local_pref {
            let attrs = Arc::make_mut(attr);
            attrs.retain(|a| a.code() != packet::Attribute::LOCAL_PREF);
            if let Some(new_attr) =
                packet::Attribute::new_with_value(packet::Attribute::LOCAL_PREF, action.value)
            {
                attrs.push(new_attr);
            }
        }

        if let Some(action) = &self.actions.med {
            let attrs = Arc::make_mut(attr);
            let current = attrs
                .iter()
                .find(|a| a.code() == packet::Attribute::MULTI_EXIT_DESC)
                .and_then(|a| a.value())
                .unwrap_or(0);
            let new_med = match action.action_type {
                MedActionType::Mod => {
                    (current as i64 + action.value).clamp(0, u32::MAX as i64) as u32
                }
                MedActionType::Replace => action.value.clamp(0, u32::MAX as i64) as u32,
            };
            attrs.retain(|a| a.code() != packet::Attribute::MULTI_EXIT_DESC);
            if let Some(new_attr) =
                packet::Attribute::new_with_value(packet::Attribute::MULTI_EXIT_DESC, new_med)
            {
                attrs.push(new_attr);
            }
        }

        if let Some(action) = &self.actions.as_prepend
            && action.repeat > 0
        {
            let attrs = Arc::make_mut(attr);
            let existing = attrs
                .iter()
                .find(|a| a.code() == packet::Attribute::AS_PATH)
                .cloned()
                .unwrap_or_else(packet::Attribute::empty_as_path);
            let asn = if action.use_left_most {
                bgp::AsPathIter::new(&existing)
                    .next()
                    .and_then(|seg| seg.first().copied())
                    .unwrap_or(action.asn)
            } else {
                action.asn
            };
            let mut new_as_path = existing;
            for _ in 0..action.repeat {
                new_as_path = new_as_path.as_path_prepend(asn);
            }
            attrs.retain(|a| a.code() != packet::Attribute::AS_PATH);
            attrs.push(new_as_path);
        }

        if let Some(action) = &self.actions.ext_community {
            let attrs = Arc::make_mut(attr);
            let existing = ext_communities_from_attr(attrs);
            let new_communities = match action.action_type {
                CommunityActionType::Add => {
                    let mut result = existing;
                    result.extend_from_slice(&action.communities);
                    result
                }
                CommunityActionType::Remove => existing
                    .into_iter()
                    .filter(|c| !action.communities.contains(c))
                    .collect(),
                CommunityActionType::Replace => action.communities.clone(),
            };
            attrs.retain(|a| a.code() != packet::Attribute::EXTENDED_COMMUNITY);
            if let Some(new_attr) = ext_communities_to_attr(new_communities) {
                attrs.push(new_attr);
            }
        }

        if let Some(action) = &self.actions.large_community {
            let attrs = Arc::make_mut(attr);
            let existing = large_communities_from_attr(attrs);
            let new_communities = match action.action_type {
                CommunityActionType::Add => {
                    let mut result = existing;
                    result.extend_from_slice(&action.communities);
                    result
                }
                CommunityActionType::Remove => existing
                    .into_iter()
                    .filter(|c| !action.communities.contains(c))
                    .collect(),
                CommunityActionType::Replace => action.communities.clone(),
            };
            attrs.retain(|a| a.code() != packet::Attribute::LARGE_COMMUNITY);
            if let Some(new_attr) = large_communities_to_attr(new_communities) {
                attrs.push(new_attr);
            }
        }

        if let Some(action) = &self.actions.origin {
            let attrs = Arc::make_mut(attr);
            attrs.retain(|a| a.code() != packet::Attribute::ORIGIN);
            if let Some(new_attr) =
                packet::Attribute::new_with_value(packet::Attribute::ORIGIN, action.origin as u32)
            {
                attrs.push(new_attr);
            }
        }

        self.disposition.unwrap_or(Disposition::Pass)
    }
}

pub struct PrefixConfig {
    pub ip_prefix: String,
    pub mask_length_min: u8,
    pub mask_length_max: u8,
}

pub enum DefinedSetConfig {
    Prefix {
        name: String,
        prefixes: Vec<PrefixConfig>,
    },
    Neighbor {
        name: String,
        neighbors: Vec<String>,
    },
    AsPath {
        name: String,
        patterns: Vec<String>,
    },
    Community {
        name: String,
        patterns: Vec<String>,
    },
    ExtCommunity {
        name: String,
        patterns: Vec<String>,
    },
    LargeCommunity {
        name: String,
        patterns: Vec<String>,
    },
}

pub enum ConditionConfig {
    PrefixSet(String, MatchOption),
    NeighborSet(String, MatchOption),
    AsPathSet(String, MatchOption),
    CommunitySet(String, MatchOption),
    ExtCommunitySet(String, MatchOption),
    LargeCommunitySet(String, MatchOption),
    AsPathLength(Comparison, u32),
    Nexthop(Vec<IpAddr>),
    Rpki(RpkiValidationState),
    LocalPrefEq(u32),
    MedEq(u32),
    /// BGP ORIGIN value: 0=IGP, 1=EGP, 2=Incomplete
    Origin(u8),
    RouteType(RouteType),
    CommunityCount(Comparison, u32),
    AfiSafiIn(Vec<bgp::Family>),
}

/// True if `c` and `cfg` are the same condition kind, ignoring the match
/// set/value carried by each. Mirrors GoBGP's `Statement.mod()`, which removes
/// a condition by kind rather than by exact value.
fn condition_kind_matches(c: &Condition, cfg: &ConditionConfig) -> bool {
    matches!(
        (c, cfg),
        (Condition::Prefix(..), ConditionConfig::PrefixSet(..))
            | (Condition::Neighbor(..), ConditionConfig::NeighborSet(..))
            | (Condition::AsPath(..), ConditionConfig::AsPathSet(..))
            | (Condition::Community(..), ConditionConfig::CommunitySet(..))
            | (Condition::Nexthop(..), ConditionConfig::Nexthop(..))
            | (
                Condition::ExtCommunity(..),
                ConditionConfig::ExtCommunitySet(..)
            )
            | (
                Condition::AsPathLength(..),
                ConditionConfig::AsPathLength(..)
            )
            | (Condition::Rpki(..), ConditionConfig::Rpki(..))
            | (
                Condition::LargeCommunity(..),
                ConditionConfig::LargeCommunitySet(..)
            )
            | (Condition::LocalPrefEq(..), ConditionConfig::LocalPrefEq(..))
            | (Condition::MedEq(..), ConditionConfig::MedEq(..))
            | (Condition::Origin(..), ConditionConfig::Origin(..))
            | (Condition::RouteType(..), ConditionConfig::RouteType(..))
            | (
                Condition::CommunityCount(..),
                ConditionConfig::CommunityCount(..)
            )
            | (Condition::AfiSafiIn(..), ConditionConfig::AfiSafiIn(..))
    )
}

pub enum DefinedSetRef<'a> {
    Prefix(&'a str, &'a PrefixSet),
    Neighbor(&'a str, &'a NeighborSet),
    AsPath(&'a str, &'a AsPathSet),
    Community(&'a str, &'a CommunitySet),
    ExtCommunity(&'a str, &'a ExtCommunitySet),
    LargeCommunity(&'a str, &'a LargeCommunitySet),
}

pub struct PrefixSet {
    pub v4: IpLookupTable<Ipv4Addr, Prefix>,
    pub v6: IpLookupTable<Ipv6Addr, Prefix>,
    pub zero: Option<(u8, u8)>,
    pub zero6: Option<(u8, u8)>,
}

pub struct NeighborSet {
    pub sets: Vec<packet::IpNet>,
}

pub struct AsPathSet {
    pub single_sets: Vec<SingleAsPathMatch>,
    pub sets: Vec<Regex>,
}

pub struct CommunitySet {
    pub sets: Vec<Regex>,
}

pub struct ExtCommunitySet {
    pub sets: Vec<Regex>,
}

pub struct LargeCommunitySet {
    pub sets: Vec<Regex>,
}

#[derive(Clone)]
pub struct Policy {
    pub name: Arc<str>,
    pub statements: Vec<Arc<Statement>>,
}

impl Policy {
    #[allow(clippy::too_many_arguments)]
    fn apply(
        &self,
        source: &Arc<Source>,
        net: &packet::Nlri,
        attr: &mut Arc<Vec<packet::Attribute>>,
        nexthop: &mut Option<bgp::Nexthop>,
        local_addr: IpAddr,
        peer_addr: IpAddr,
        rpki: Option<&RpkiTable>,
    ) -> Disposition {
        for statement in &self.statements {
            let d = statement.apply(source, net, attr, nexthop, local_addr, peer_addr, rpki);
            if d != Disposition::Pass {
                return d;
            }
        }
        Disposition::Pass
    }
}

pub struct PolicyAssignment {
    pub name: Arc<str>,
    pub disposition: Disposition,
    pub policies: Vec<Arc<Policy>>,
    /// True if any statement in any policy contains `Condition::Rpki`.
    /// Used to skip `RpkiTable` reads in the hot path when RPKI is unused.
    pub needs_rpki: bool,
}

impl PolicyAssignment {
    fn compute_needs_rpki(policies: &[Arc<Policy>]) -> bool {
        policies.iter().any(|p| {
            p.statements
                .iter()
                .any(|s| s.conditions.iter().any(|c| matches!(c, Condition::Rpki(_))))
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn apply(
        &self,
        source: &Arc<Source>,
        net: &packet::Nlri,
        attr: &mut Arc<Vec<packet::Attribute>>,
        nexthop: &mut Option<bgp::Nexthop>,
        local_addr: IpAddr,
        peer_addr: IpAddr,
        rpki: Option<&RpkiTable>,
    ) -> Disposition {
        for policy in &self.policies {
            let d = policy.apply(source, net, attr, nexthop, local_addr, peer_addr, rpki);
            if d != Disposition::Pass {
                return d;
            }
        }
        self.disposition
    }

    /// Returns a copy of this assignment with `policy_names` removed.
    pub fn without_policies(&self, policy_names: &[String]) -> Arc<PolicyAssignment> {
        let policies: Vec<Arc<Policy>> = self
            .policies
            .iter()
            .filter(|p| !policy_names.iter().any(|n| n == p.name.as_ref()))
            .cloned()
            .collect();
        let needs_rpki = Self::compute_needs_rpki(&policies);
        Arc::new(PolicyAssignment {
            name: self.name.clone(),
            disposition: self.disposition,
            policies,
            needs_rpki,
        })
    }
}

/// Apply import policy to a received route.
///
/// Returns `(filtered, post_policy_attr)`.  When not filtered, `post_policy_attr` reflects
/// any attribute modifications made by the policy; if the policy made no changes it is the
/// same `Arc` as `attrs` (only the reference count increases).
/// Pass `rpki: None` to skip RPKI validation (e.g. in tests or when no RTR session is active).
pub fn apply_import(
    policy: &PolicyAssignment,
    rpki: Option<&RpkiTable>,
    source: &Arc<Source>,
    net: &packet::Nlri,
    attrs: &Arc<Vec<packet::Attribute>>,
    nexthop: &mut Option<bgp::Nexthop>,
) -> (bool, Arc<Vec<packet::Attribute>>) {
    let mut attr = Arc::clone(attrs);
    let filtered = policy.apply(
        source,
        net,
        &mut attr,
        nexthop,
        source.local_addr,
        source.remote_addr,
        rpki,
    ) == Disposition::Reject;
    (filtered, attr)
}

/// Apply export policy to a route being advertised to a peer.
///
/// Returns the `Disposition` from the policy chain.
/// Pass `rpki: None` to skip RPKI validation (e.g. in tests or when no RTR session is active).
#[allow(clippy::too_many_arguments)]
pub fn apply_export(
    policy: &PolicyAssignment,
    rpki: Option<&RpkiTable>,
    source: &Arc<Source>,
    net: &packet::Nlri,
    attr: &mut Arc<Vec<packet::Attribute>>,
    nexthop: &mut Option<bgp::Nexthop>,
    local_addr: IpAddr,
    peer_addr: IpAddr,
) -> Disposition {
    policy.apply(source, net, attr, nexthop, local_addr, peer_addr, rpki)
}

#[derive(Clone, Copy, PartialEq)]
pub enum PolicyDirection {
    Import,
    Export,
}

#[derive(Default)]
pub struct PolicyTable {
    prefix_sets: FnvHashMap<Arc<str>, Arc<PrefixSet>>,
    neighbor_sets: FnvHashMap<Arc<str>, Arc<NeighborSet>>,
    aspath_sets: FnvHashMap<Arc<str>, Arc<AsPathSet>>,
    community_sets: FnvHashMap<Arc<str>, Arc<CommunitySet>>,
    ext_community_sets: FnvHashMap<Arc<str>, Arc<ExtCommunitySet>>,
    large_community_sets: FnvHashMap<Arc<str>, Arc<LargeCommunitySet>>,

    statements: FnvHashMap<Arc<str>, Arc<Statement>>,
    policies: FnvHashMap<Arc<str>, Arc<Policy>>,

    assignment_import: Option<Arc<PolicyAssignment>>,
    assignment_export: Option<Arc<PolicyAssignment>>,
}

impl PolicyTable {
    pub fn new() -> Self {
        Default::default()
    }

    /// Resolve `policy_names` against this table and build a new `PolicyAssignment`.
    /// When `existing` is given, its policies are appended after validating there is
    /// no name collision (used by `AddPolicyAssignment` semantics, which accumulate
    /// across repeated calls rather than replacing). Shared by the global-assignment
    /// path (`add_assignment`) and the per-peer path in the daemon crate.
    #[allow(clippy::too_many_arguments)]
    pub fn build_assignment(
        &self,
        existing: Option<&PolicyAssignment>,
        name: &str,
        direction: PolicyDirection,
        default_action: Disposition,
        policy_names: Vec<String>,
    ) -> Result<Arc<PolicyAssignment>, TableError> {
        let mut v = Vec::new();
        for pname in &policy_names {
            match self.policies.get(pname.as_str()) {
                Some(p) => v.push(p.clone()),
                None => {
                    return Err(TableError::InvalidArgument(format!(
                        "{} policy isn't found",
                        pname
                    )));
                }
            }
        }

        if direction == PolicyDirection::Import {
            for policy in &v {
                for stmt in &policy.statements {
                    if stmt.actions.nexthop.is_some() {
                        return Err(TableError::InvalidArgument(format!(
                            "statement '{}' sets nexthop, which is not allowed in import policy",
                            stmt.name
                        )));
                    }
                }
            }
        }

        if let Some(old) = existing {
            for p0 in &old.policies {
                if let Some(p) = v.iter().find(|p1| p0.name == p1.name) {
                    return Err(TableError::InvalidArgument(format!(
                        "{} policy already exists",
                        p.name
                    )));
                }
            }
            v.extend(old.policies.iter().cloned());
        }
        let needs_rpki = PolicyAssignment::compute_needs_rpki(&v);
        Ok(Arc::new(PolicyAssignment {
            name: Arc::from(name),
            policies: v,
            disposition: default_action,
            needs_rpki,
        }))
    }

    /// Returns true if `name` is referenced by either global assignment (import or export).
    pub fn policy_in_use_globally(&self, name: &str) -> bool {
        [&self.assignment_import, &self.assignment_export]
            .iter()
            .any(|a| {
                a.as_ref()
                    .is_some_and(|a| a.policies.iter().any(|p| p.name.as_ref() == name))
            })
    }

    pub fn add_assignment(
        &mut self,
        name: &str,
        direction: PolicyDirection,
        default_action: Disposition,
        policy_names: Vec<String>,
    ) -> Result<(PolicyDirection, Arc<PolicyAssignment>), TableError> {
        let slot = match direction {
            PolicyDirection::Import => &self.assignment_import,
            PolicyDirection::Export => &self.assignment_export,
        };
        let n = self.build_assignment(
            slot.as_deref(),
            name,
            direction,
            default_action,
            policy_names,
        )?;
        match direction {
            PolicyDirection::Import => self.assignment_import = Some(n.clone()),
            PolicyDirection::Export => self.assignment_export = Some(n.clone()),
        }
        Ok((direction, n))
    }

    /// `direction`: 0=unspecified (both), 1=import, 2=export.
    pub fn iter_assignments(
        &self,
        direction: i32,
    ) -> impl Iterator<Item = (i32, &PolicyAssignment)> + '_ {
        let mut v: Vec<(i32, &PolicyAssignment)> = Vec::with_capacity(2);
        if direction != 2
            && let Some(a) = self.assignment_import.as_ref()
        {
            v.push((1, a));
        }
        if direction != 1
            && let Some(a) = self.assignment_export.as_ref()
        {
            v.push((2, a));
        }
        v.into_iter()
    }

    /// If no policy named `name` exists, creates it. Otherwise appends the
    /// given statements to it (GoBGP `Policy.Add` semantics: plain
    /// concatenation, no dedup) unless the existing policy is in use -- see
    /// the note on `delete_defined_set` for why appending to an in-use policy
    /// can't propagate to assignments built before the merge. The daemon
    /// crate additionally checks per-peer references before calling this,
    /// since `PolicyTable` has no visibility into per-peer state.
    pub fn add_policy(
        &mut self,
        name: &str,
        statement_names: Vec<String>,
    ) -> Result<(), TableError> {
        let mut v = Vec::new();
        for sname in &statement_names {
            match self.statements.get(sname.as_str()) {
                Some(st) => v.push(st.clone()),
                None => {
                    return Err(TableError::InvalidArgument(format!(
                        "{} statement isn't found",
                        sname
                    )));
                }
            }
        }
        match self.policies.get(name) {
            None => {
                self.policies.insert(
                    Arc::from(name),
                    Arc::new(Policy {
                        name: Arc::from(name),
                        statements: v,
                    }),
                );
            }
            Some(existing) => {
                if self.policy_in_use_globally(name) {
                    return Err(TableError::StillInUse(name.to_string()));
                }
                let mut new = (**existing).clone();
                new.statements.extend(v);
                self.policies.insert(new.name.clone(), Arc::new(new));
            }
        }
        Ok(())
    }

    /// If no defined-set named `set`'s name exists, creates it. Otherwise merges
    /// (GoBGP `Append` semantics: values are unioned, no dedup) unless the
    /// existing set is in use -- see the note on `delete_defined_set` for why
    /// merging into an in-use set can't propagate to statements built before
    /// the merge. To replace an in-use set wholesale instead, use
    /// `replace_defined_set` (mirrors `AddDefinedSetRequest.replace`).
    pub fn add_defined_set(&mut self, set: DefinedSetConfig) -> Result<(), TableError> {
        match set {
            DefinedSetConfig::Prefix { name, prefixes } => {
                let mut zero = None;
                let mut zero6 = None;
                let mut new_v4 = Vec::new();
                let mut new_v6 = Vec::new();
                for p in &prefixes {
                    let net = packet::IpNet::from_str(&p.ip_prefix).map_err(|_| {
                        TableError::InvalidArgument(format!(
                            "invalid prefix format {:?}",
                            p.ip_prefix
                        ))
                    })?;
                    let prefix = Prefix {
                        net: net.clone(),
                        min_length: p.mask_length_min,
                        max_length: p.mask_length_max,
                    };
                    match &net {
                        packet::IpNet::V4(n) => {
                            if n.addr == Ipv4Addr::new(0, 0, 0, 0) && n.mask == 0 {
                                zero = Some((prefix.min_length, prefix.max_length));
                            } else {
                                new_v4.push((n.addr, n.mask as u32, prefix));
                            }
                        }
                        packet::IpNet::V6(n) => {
                            if n.addr == Ipv6Addr::UNSPECIFIED && n.mask == 0 {
                                zero6 = Some((prefix.min_length, prefix.max_length));
                            } else {
                                new_v6.push((n.addr, n.mask as u32, prefix));
                            }
                        }
                    }
                }
                match self.prefix_sets.get(name.as_str()) {
                    None => {
                        if new_v4.is_empty()
                            && new_v6.is_empty()
                            && zero.is_none()
                            && zero6.is_none()
                        {
                            return Err(TableError::InvalidArgument(
                                "empty prefix defined-type".to_string(),
                            ));
                        }
                        let mut v4 = IpLookupTable::new();
                        let mut v6 = IpLookupTable::new();
                        for (addr, mask, p) in new_v4 {
                            v4.insert(addr, mask, p);
                        }
                        for (addr, mask, p) in new_v6 {
                            v6.insert(addr, mask, p);
                        }
                        self.prefix_sets.insert(
                            Arc::from(name.as_str()),
                            Arc::new(PrefixSet {
                                v4,
                                v6,
                                zero,
                                zero6,
                            }),
                        );
                    }
                    Some(existing) => {
                        self.reject_if_prefix_set_in_use(&name)?;
                        let mut v4 = IpLookupTable::new();
                        let mut v6 = IpLookupTable::new();
                        for (addr, mask, p) in existing.v4.iter() {
                            v4.insert(addr, mask, p.clone());
                        }
                        for (addr, mask, p) in existing.v6.iter() {
                            v6.insert(addr, mask, p.clone());
                        }
                        for (addr, mask, p) in new_v4 {
                            v4.insert(addr, mask, p);
                        }
                        for (addr, mask, p) in new_v6 {
                            v6.insert(addr, mask, p);
                        }
                        let zero = zero.or(existing.zero);
                        let zero6 = zero6.or(existing.zero6);
                        self.prefix_sets.insert(
                            Arc::from(name.as_str()),
                            Arc::new(PrefixSet {
                                v4,
                                v6,
                                zero,
                                zero6,
                            }),
                        );
                    }
                }
                Ok(())
            }
            DefinedSetConfig::Neighbor { name, neighbors } => {
                let mut new_v = Vec::with_capacity(neighbors.len());
                for n in &neighbors {
                    let addr = packet::IpNet::from_str(n).map_err(|_| {
                        TableError::InvalidArgument(format!("invalid neighbor format {:?}", n))
                    })?;
                    new_v.push(addr);
                }
                let sets = match self.neighbor_sets.get(name.as_str()) {
                    None => {
                        if new_v.is_empty() {
                            return Err(TableError::InvalidArgument(
                                "empty neighbor defined-type".to_string(),
                            ));
                        }
                        new_v
                    }
                    Some(existing) => {
                        for stmt in self.statements.values() {
                            if stmt
                                .conditions
                                .iter()
                                .any(|c| matches!(c, Condition::Neighbor(n, ..) if n == &name))
                            {
                                return Err(TableError::StillInUse(name));
                            }
                        }
                        let mut sets = existing.sets.clone();
                        sets.extend(new_v);
                        sets
                    }
                };
                self.neighbor_sets
                    .insert(Arc::from(name.as_str()), Arc::new(NeighborSet { sets }));
                Ok(())
            }
            DefinedSetConfig::AsPath { name, patterns } => {
                let mut new_single = Vec::with_capacity(patterns.len());
                let mut new_regex = Vec::with_capacity(patterns.len());
                for n in &patterns {
                    if let Some(m) = SingleAsPathMatch::new(n) {
                        new_single.push(m);
                    } else if let Ok(r) = Regex::new(&n.replace('_', "(^|[,{}() ]|$)")) {
                        new_regex.push(r);
                    } else {
                        return Err(TableError::InvalidArgument(format!(
                            "invalid aspath format {:?}",
                            n
                        )));
                    }
                }
                let (single_sets, sets) = match self.aspath_sets.get(name.as_str()) {
                    None => {
                        if new_single.is_empty() && new_regex.is_empty() {
                            return Err(TableError::InvalidArgument(
                                "empty aspath defined-type".to_string(),
                            ));
                        }
                        (new_single, new_regex)
                    }
                    Some(existing) => {
                        for stmt in self.statements.values() {
                            if stmt
                                .conditions
                                .iter()
                                .any(|c| matches!(c, Condition::AsPath(n, ..) if n == &name))
                            {
                                return Err(TableError::StillInUse(name));
                            }
                        }
                        let mut single_sets = existing.single_sets.clone();
                        single_sets.extend(new_single);
                        let mut sets = existing.sets.to_vec();
                        sets.extend(new_regex);
                        (single_sets, sets)
                    }
                };
                self.aspath_sets.insert(
                    Arc::from(name.as_str()),
                    Arc::new(AsPathSet { single_sets, sets }),
                );
                Ok(())
            }
            DefinedSetConfig::Community { name, patterns } => {
                let mut new_v = Vec::with_capacity(patterns.len());
                for n in &patterns {
                    new_v.push(parse_community(n).map_err(|_| {
                        TableError::InvalidArgument(format!("invalid community format {:?}", n))
                    })?);
                }
                let sets = match self.community_sets.get(name.as_str()) {
                    None => {
                        if new_v.is_empty() {
                            return Err(TableError::InvalidArgument(
                                "empty community defined-type".to_string(),
                            ));
                        }
                        new_v
                    }
                    Some(existing) => {
                        for stmt in self.statements.values() {
                            if stmt
                                .conditions
                                .iter()
                                .any(|c| matches!(c, Condition::Community(n, ..) if n == &name))
                            {
                                return Err(TableError::StillInUse(name));
                            }
                        }
                        let mut sets = existing.sets.to_vec();
                        sets.extend(new_v);
                        sets
                    }
                };
                self.community_sets
                    .insert(Arc::from(name.as_str()), Arc::new(CommunitySet { sets }));
                Ok(())
            }
            DefinedSetConfig::ExtCommunity { name, patterns } => {
                let mut new_v = Vec::with_capacity(patterns.len());
                for n in &patterns {
                    new_v.push(Regex::new(n).map_err(|_| {
                        TableError::InvalidArgument(format!("invalid ext-community regex {:?}", n))
                    })?);
                }
                let sets =
                    match self.ext_community_sets.get(name.as_str()) {
                        None => {
                            if new_v.is_empty() {
                                return Err(TableError::InvalidArgument(
                                    "empty ext-community defined-type".to_string(),
                                ));
                            }
                            new_v
                        }
                        Some(existing) => {
                            for stmt in self.statements.values() {
                                if stmt.conditions.iter().any(
                                    |c| matches!(c, Condition::ExtCommunity(n, ..) if n == &name),
                                ) {
                                    return Err(TableError::StillInUse(name));
                                }
                            }
                            let mut sets = existing.sets.to_vec();
                            sets.extend(new_v);
                            sets
                        }
                    };
                self.ext_community_sets
                    .insert(Arc::from(name.as_str()), Arc::new(ExtCommunitySet { sets }));
                Ok(())
            }
            DefinedSetConfig::LargeCommunity { name, patterns } => {
                let mut new_v = Vec::with_capacity(patterns.len());
                for n in &patterns {
                    new_v.push(Regex::new(n).map_err(|_| {
                        TableError::InvalidArgument(format!(
                            "invalid large-community regex {:?}",
                            n
                        ))
                    })?);
                }
                let sets = match self.large_community_sets.get(name.as_str()) {
                    None => {
                        if new_v.is_empty() {
                            return Err(TableError::InvalidArgument(
                                "empty large-community defined-type".to_string(),
                            ));
                        }
                        new_v
                    }
                    Some(existing) => {
                        for stmt in self.statements.values() {
                            if stmt.conditions.iter().any(
                                |c| matches!(c, Condition::LargeCommunity(n, ..) if n == &name),
                            ) {
                                return Err(TableError::StillInUse(name));
                            }
                        }
                        let mut sets = existing.sets.to_vec();
                        sets.extend(new_v);
                        sets
                    }
                };
                self.large_community_sets.insert(
                    Arc::from(name.as_str()),
                    Arc::new(LargeCommunitySet { sets }),
                );
                Ok(())
            }
        }
    }

    fn reject_if_prefix_set_in_use(&self, name: &str) -> Result<(), TableError> {
        for stmt in self.statements.values() {
            if stmt
                .conditions
                .iter()
                .any(|c| matches!(c, Condition::Prefix(n, ..) if n == name))
            {
                return Err(TableError::StillInUse(name.to_string()));
            }
        }
        Ok(())
    }

    /// Unconditionally replaces the named defined-set (mirrors
    /// `AddDefinedSetRequest.replace`), or creates it if absent. Rejects an
    /// in-use target for the same reason `delete_defined_set`/the merge path of
    /// `add_defined_set` do.
    pub fn replace_defined_set(&mut self, set: DefinedSetConfig) -> Result<(), TableError> {
        match &set {
            DefinedSetConfig::Prefix { name, .. } => self.reject_if_prefix_set_in_use(name)?,
            DefinedSetConfig::Neighbor { name, .. } => {
                for stmt in self.statements.values() {
                    if stmt
                        .conditions
                        .iter()
                        .any(|c| matches!(c, Condition::Neighbor(n, ..) if n == name))
                    {
                        return Err(TableError::StillInUse(name.clone()));
                    }
                }
            }
            DefinedSetConfig::AsPath { name, .. } => {
                for stmt in self.statements.values() {
                    if stmt
                        .conditions
                        .iter()
                        .any(|c| matches!(c, Condition::AsPath(n, ..) if n == name))
                    {
                        return Err(TableError::StillInUse(name.clone()));
                    }
                }
            }
            DefinedSetConfig::Community { name, .. } => {
                for stmt in self.statements.values() {
                    if stmt
                        .conditions
                        .iter()
                        .any(|c| matches!(c, Condition::Community(n, ..) if n == name))
                    {
                        return Err(TableError::StillInUse(name.clone()));
                    }
                }
            }
            DefinedSetConfig::ExtCommunity { name, .. } => {
                for stmt in self.statements.values() {
                    if stmt
                        .conditions
                        .iter()
                        .any(|c| matches!(c, Condition::ExtCommunity(n, ..) if n == name))
                    {
                        return Err(TableError::StillInUse(name.clone()));
                    }
                }
            }
            DefinedSetConfig::LargeCommunity { name, .. } => {
                for stmt in self.statements.values() {
                    if stmt
                        .conditions
                        .iter()
                        .any(|c| matches!(c, Condition::LargeCommunity(n, ..) if n == name))
                    {
                        return Err(TableError::StillInUse(name.clone()));
                    }
                }
            }
        }
        match &set {
            DefinedSetConfig::Prefix { name, .. } => {
                self.prefix_sets.remove(name.as_str());
            }
            DefinedSetConfig::Neighbor { name, .. } => {
                self.neighbor_sets.remove(name.as_str());
            }
            DefinedSetConfig::AsPath { name, .. } => {
                self.aspath_sets.remove(name.as_str());
            }
            DefinedSetConfig::Community { name, .. } => {
                self.community_sets.remove(name.as_str());
            }
            DefinedSetConfig::ExtCommunity { name, .. } => {
                self.ext_community_sets.remove(name.as_str());
            }
            DefinedSetConfig::LargeCommunity { name, .. } => {
                self.large_community_sets.remove(name.as_str());
            }
        }
        self.add_defined_set(set)
    }

    pub fn iter_defined_sets(&self) -> impl Iterator<Item = DefinedSetRef<'_>> + '_ {
        self.prefix_sets
            .iter()
            .map(|(name, s)| DefinedSetRef::Prefix(name, s))
            .chain(
                self.neighbor_sets
                    .iter()
                    .map(|(name, s)| DefinedSetRef::Neighbor(name, s)),
            )
            .chain(
                self.aspath_sets
                    .iter()
                    .map(|(name, s)| DefinedSetRef::AsPath(name, s)),
            )
            .chain(
                self.community_sets
                    .iter()
                    .map(|(name, s)| DefinedSetRef::Community(name, s)),
            )
            .chain(
                self.ext_community_sets
                    .iter()
                    .map(|(name, s)| DefinedSetRef::ExtCommunity(name, s)),
            )
            .chain(
                self.large_community_sets
                    .iter()
                    .map(|(name, s)| DefinedSetRef::LargeCommunity(name, s)),
            )
    }

    /// If no statement named `name` exists, creates it. Otherwise merges
    /// (GoBGP `Statement.mod(ADD, ...)` semantics: each condition/action/
    /// disposition *kind* is added if not already set on the existing
    /// statement, and errors if it is) unless the existing statement is in
    /// use -- see the note on `delete_defined_set` for why merging into an
    /// in-use statement can't propagate to policies built before the merge.
    pub fn add_statement(
        &mut self,
        name: &str,
        conditions: Vec<ConditionConfig>,
        disposition: Option<Disposition>,
        actions: Actions,
    ) -> Result<(), TableError> {
        let mut v = Vec::new();
        for cond in conditions {
            match cond {
                ConditionConfig::PrefixSet(set_name, opt) => {
                    if opt == MatchOption::All {
                        return Err(TableError::InvalidArgument(
                            "prefix-set can't have all match option".to_string(),
                        ));
                    }
                    match self.prefix_sets.get(set_name.as_str()) {
                        Some(set) => v.push(Condition::Prefix(set_name, opt, set.clone())),
                        None => {
                            return Err(TableError::InvalidArgument(format!(
                                "{} prefix-set isn't found",
                                set_name
                            )));
                        }
                    }
                }
                ConditionConfig::NeighborSet(set_name, opt) => {
                    if opt == MatchOption::All {
                        return Err(TableError::InvalidArgument(
                            "neighbor-set can't have all match option".to_string(),
                        ));
                    }
                    match self.neighbor_sets.get(set_name.as_str()) {
                        Some(set) => v.push(Condition::Neighbor(set_name, opt, set.clone())),
                        None => {
                            return Err(TableError::InvalidArgument(format!(
                                "{} neighbor-set isn't found",
                                set_name
                            )));
                        }
                    }
                }
                ConditionConfig::AsPathSet(set_name, opt) => {
                    match self.aspath_sets.get(set_name.as_str()) {
                        Some(set) => v.push(Condition::AsPath(set_name, opt, set.clone())),
                        None => {
                            return Err(TableError::InvalidArgument(format!(
                                "{} aspath-set isn't found",
                                set_name
                            )));
                        }
                    }
                }
                ConditionConfig::CommunitySet(set_name, opt) => {
                    match self.community_sets.get(set_name.as_str()) {
                        Some(set) => v.push(Condition::Community(set_name, opt, set.clone())),
                        None => {
                            return Err(TableError::InvalidArgument(format!(
                                "{} community-set isn't found",
                                set_name
                            )));
                        }
                    }
                }
                ConditionConfig::ExtCommunitySet(set_name, opt) => {
                    match self.ext_community_sets.get(set_name.as_str()) {
                        Some(set) => v.push(Condition::ExtCommunity(set_name, opt, set.clone())),
                        None => {
                            return Err(TableError::InvalidArgument(format!(
                                "{} ext-community-set isn't found",
                                set_name
                            )));
                        }
                    }
                }
                ConditionConfig::LargeCommunitySet(set_name, opt) => {
                    match self.large_community_sets.get(set_name.as_str()) {
                        Some(set) => v.push(Condition::LargeCommunity(set_name, opt, set.clone())),
                        None => {
                            return Err(TableError::InvalidArgument(format!(
                                "{} large-community-set isn't found",
                                set_name
                            )));
                        }
                    }
                }
                ConditionConfig::AsPathLength(cmp, length) => {
                    v.push(Condition::AsPathLength(cmp, length));
                }
                ConditionConfig::Nexthop(nexthops) => {
                    v.push(Condition::Nexthop(nexthops));
                }
                ConditionConfig::Rpki(state) => {
                    v.push(Condition::Rpki(state));
                }
                ConditionConfig::LocalPrefEq(val) => {
                    v.push(Condition::LocalPrefEq(val));
                }
                ConditionConfig::MedEq(val) => {
                    v.push(Condition::MedEq(val));
                }
                ConditionConfig::Origin(val) => {
                    v.push(Condition::Origin(val));
                }
                ConditionConfig::RouteType(rt) => {
                    v.push(Condition::RouteType(rt));
                }
                ConditionConfig::CommunityCount(cmp, count) => {
                    v.push(Condition::CommunityCount(cmp, count));
                }
                ConditionConfig::AfiSafiIn(families) => {
                    v.push(Condition::AfiSafiIn(families));
                }
            }
        }
        let Some(existing) = self.statements.get(name) else {
            let s = Statement {
                name: Arc::from(name),
                conditions: v,
                disposition,
                actions,
            };
            self.statements.insert(s.name.clone(), Arc::new(s));
            return Ok(());
        };

        for policy in self.policies.values() {
            if policy.statements.iter().any(|s| s.name.as_ref() == name) {
                return Err(TableError::StillInUse(name.to_string()));
            }
        }

        let mut new = (**existing).clone();
        for cond in v {
            if new
                .conditions
                .iter()
                .any(|c| std::mem::discriminant(c) == std::mem::discriminant(&cond))
            {
                return Err(TableError::InvalidArgument(format!(
                    "condition is already set in statement {}",
                    name
                )));
            }
            new.conditions.push(cond);
        }

        if disposition.is_some() {
            if new.disposition.is_some() {
                return Err(TableError::InvalidArgument(format!(
                    "route action is already set in statement {}",
                    name
                )));
            }
            new.disposition = disposition;
        }

        macro_rules! add_action {
            ($field:ident, $label:literal) => {
                if actions.$field.is_some() {
                    if new.actions.$field.is_some() {
                        return Err(TableError::InvalidArgument(format!(
                            "{} action is already set in statement {}",
                            $label, name
                        )));
                    }
                    new.actions.$field = actions.$field;
                }
            };
        }
        add_action!(nexthop, "nexthop");
        add_action!(community, "community");
        add_action!(local_pref, "local-pref");
        add_action!(med, "med");
        add_action!(as_prepend, "as-prepend");
        add_action!(ext_community, "ext-community");
        add_action!(large_community, "large-community");
        add_action!(origin, "origin");

        self.statements.insert(new.name.clone(), Arc::new(new));
        Ok(())
    }

    pub fn iter_statements(&self, name: String) -> impl Iterator<Item = &Statement> + '_ {
        self.statements
            .iter()
            .filter(move |(sname, _)| name.is_empty() || name.as_str() == sname.as_ref())
            .map(|(_, s)| s.as_ref())
    }

    pub fn iter_policies(&self, name: String) -> impl Iterator<Item = &Policy> + '_ {
        self.policies
            .iter()
            .filter(move |(pname, _)| name.is_empty() || name.as_str() == pname.as_ref())
            .map(|(_, p)| p.as_ref())
    }

    /// `all=true` deletes the single named defined-set entirely (after an in-use
    /// check). `all=false` removes only the given elements from it; elements not
    /// currently present are silently ignored (GoBGP `DefinedSet.Remove` semantics).
    /// Either way, an in-use defined-set is rejected: RustyBGP's `Statement`/`Policy`
    /// hold their own `Arc` clones of referenced defined-sets/statements, so a
    /// partial edit here would not propagate to objects built before the edit.
    pub fn delete_defined_set(
        &mut self,
        set: DefinedSetConfig,
        all: bool,
    ) -> Result<(), TableError> {
        match set {
            DefinedSetConfig::Prefix { name, prefixes } => {
                for stmt in self.statements.values() {
                    if stmt
                        .conditions
                        .iter()
                        .any(|c| matches!(c, Condition::Prefix(n, ..) if n == &name))
                    {
                        return Err(TableError::StillInUse(name));
                    }
                }
                if all {
                    if self.prefix_sets.remove(name.as_str()).is_none() {
                        return Err(TableError::NotFound);
                    }
                    return Ok(());
                }
                let existing = self
                    .prefix_sets
                    .get(name.as_str())
                    .ok_or(TableError::NotFound)?;
                let mut zero = existing.zero;
                let mut zero6 = existing.zero6;
                let mut v4 = IpLookupTable::new();
                let mut v6 = IpLookupTable::new();
                for (addr, mask, p) in existing.v4.iter() {
                    v4.insert(addr, mask, p.clone());
                }
                for (addr, mask, p) in existing.v6.iter() {
                    v6.insert(addr, mask, p.clone());
                }
                for p in &prefixes {
                    let net = packet::IpNet::from_str(&p.ip_prefix).map_err(|_| {
                        TableError::InvalidArgument(format!(
                            "invalid prefix format {:?}",
                            p.ip_prefix
                        ))
                    })?;
                    let candidate = Prefix {
                        net: net.clone(),
                        min_length: p.mask_length_min,
                        max_length: p.mask_length_max,
                    };
                    match &net {
                        packet::IpNet::V4(n) => {
                            if n.addr == Ipv4Addr::new(0, 0, 0, 0) && n.mask == 0 {
                                if zero == Some((candidate.min_length, candidate.max_length)) {
                                    zero = None;
                                }
                            } else if v4.exact_match(n.addr, n.mask as u32) == Some(&candidate) {
                                v4.remove(n.addr, n.mask as u32);
                            }
                        }
                        packet::IpNet::V6(n) => {
                            if n.addr == Ipv6Addr::UNSPECIFIED && n.mask == 0 {
                                if zero6 == Some((candidate.min_length, candidate.max_length)) {
                                    zero6 = None;
                                }
                            } else if v6.exact_match(n.addr, n.mask as u32) == Some(&candidate) {
                                v6.remove(n.addr, n.mask as u32);
                            }
                        }
                    }
                }
                self.prefix_sets.insert(
                    Arc::from(name.as_str()),
                    Arc::new(PrefixSet {
                        v4,
                        v6,
                        zero,
                        zero6,
                    }),
                );
                Ok(())
            }
            DefinedSetConfig::Neighbor { name, neighbors } => {
                for stmt in self.statements.values() {
                    if stmt
                        .conditions
                        .iter()
                        .any(|c| matches!(c, Condition::Neighbor(n, ..) if n == &name))
                    {
                        return Err(TableError::StillInUse(name));
                    }
                }
                if all {
                    if self.neighbor_sets.remove(name.as_str()).is_none() {
                        return Err(TableError::NotFound);
                    }
                    return Ok(());
                }
                let existing = self
                    .neighbor_sets
                    .get(name.as_str())
                    .ok_or(TableError::NotFound)?;
                let mut sets = existing.sets.clone();
                for n in &neighbors {
                    let addr = packet::IpNet::from_str(n).map_err(|_| {
                        TableError::InvalidArgument(format!("invalid neighbor format {:?}", n))
                    })?;
                    sets.retain(|s| s != &addr);
                }
                self.neighbor_sets
                    .insert(Arc::from(name.as_str()), Arc::new(NeighborSet { sets }));
                Ok(())
            }
            DefinedSetConfig::AsPath { name, patterns } => {
                for stmt in self.statements.values() {
                    if stmt
                        .conditions
                        .iter()
                        .any(|c| matches!(c, Condition::AsPath(n, ..) if n == &name))
                    {
                        return Err(TableError::StillInUse(name));
                    }
                }
                if all {
                    if self.aspath_sets.remove(name.as_str()).is_none() {
                        return Err(TableError::NotFound);
                    }
                    return Ok(());
                }
                let existing = self
                    .aspath_sets
                    .get(name.as_str())
                    .ok_or(TableError::NotFound)?;
                let mut single_sets = existing.single_sets.clone();
                let mut sets: Vec<Regex> = existing.sets.to_vec();
                for n in &patterns {
                    if let Some(m) = SingleAsPathMatch::new(n) {
                        single_sets.retain(|s| s != &m);
                    } else if let Ok(r) = Regex::new(&n.replace('_', "(^|[,{}() ]|$)")) {
                        sets.retain(|s| s.as_str() != r.as_str());
                    } else {
                        return Err(TableError::InvalidArgument(format!(
                            "invalid aspath format {:?}",
                            n
                        )));
                    }
                }
                self.aspath_sets.insert(
                    Arc::from(name.as_str()),
                    Arc::new(AsPathSet { single_sets, sets }),
                );
                Ok(())
            }
            DefinedSetConfig::Community { name, patterns } => {
                for stmt in self.statements.values() {
                    if stmt
                        .conditions
                        .iter()
                        .any(|c| matches!(c, Condition::Community(n, ..) if n == &name))
                    {
                        return Err(TableError::StillInUse(name));
                    }
                }
                if all {
                    if self.community_sets.remove(name.as_str()).is_none() {
                        return Err(TableError::NotFound);
                    }
                    return Ok(());
                }
                let existing = self
                    .community_sets
                    .get(name.as_str())
                    .ok_or(TableError::NotFound)?;
                let mut sets: Vec<Regex> = existing.sets.to_vec();
                for n in &patterns {
                    let r = parse_community(n)?;
                    sets.retain(|s| s.as_str() != r.as_str());
                }
                self.community_sets
                    .insert(Arc::from(name.as_str()), Arc::new(CommunitySet { sets }));
                Ok(())
            }
            DefinedSetConfig::ExtCommunity { name, patterns } => {
                for stmt in self.statements.values() {
                    if stmt
                        .conditions
                        .iter()
                        .any(|c| matches!(c, Condition::ExtCommunity(n, ..) if n == &name))
                    {
                        return Err(TableError::StillInUse(name));
                    }
                }
                if all {
                    if self.ext_community_sets.remove(name.as_str()).is_none() {
                        return Err(TableError::NotFound);
                    }
                    return Ok(());
                }
                let existing = self
                    .ext_community_sets
                    .get(name.as_str())
                    .ok_or(TableError::NotFound)?;
                let mut sets: Vec<Regex> = existing.sets.to_vec();
                for n in &patterns {
                    let r = Regex::new(n).map_err(|_| {
                        TableError::InvalidArgument(format!("invalid ext-community regex {:?}", n))
                    })?;
                    sets.retain(|s| s.as_str() != r.as_str());
                }
                self.ext_community_sets
                    .insert(Arc::from(name.as_str()), Arc::new(ExtCommunitySet { sets }));
                Ok(())
            }
            DefinedSetConfig::LargeCommunity { name, patterns } => {
                for stmt in self.statements.values() {
                    if stmt
                        .conditions
                        .iter()
                        .any(|c| matches!(c, Condition::LargeCommunity(n, ..) if n == &name))
                    {
                        return Err(TableError::StillInUse(name));
                    }
                }
                if all {
                    if self.large_community_sets.remove(name.as_str()).is_none() {
                        return Err(TableError::NotFound);
                    }
                    return Ok(());
                }
                let existing = self
                    .large_community_sets
                    .get(name.as_str())
                    .ok_or(TableError::NotFound)?;
                let mut sets: Vec<Regex> = existing.sets.to_vec();
                for n in &patterns {
                    let r = Regex::new(n).map_err(|_| {
                        TableError::InvalidArgument(format!(
                            "invalid large-community regex {:?}",
                            n
                        ))
                    })?;
                    sets.retain(|s| s.as_str() != r.as_str());
                }
                self.large_community_sets.insert(
                    Arc::from(name.as_str()),
                    Arc::new(LargeCommunitySet { sets }),
                );
                Ok(())
            }
        }
    }

    /// `all=true` deletes the single named statement entirely (after an in-use
    /// check). `all=false` removes only the given condition/action/disposition
    /// *kinds* from it (GoBGP `Statement.Remove` matches by kind, not value; it
    /// errors if a requested kind isn't currently set). Either way, an in-use
    /// statement (referenced by a `Policy`) is rejected -- see the note on
    /// `delete_defined_set` for why partial edits can't propagate to policies
    /// built before the edit.
    pub fn delete_statement(
        &mut self,
        name: &str,
        all: bool,
        conditions: Vec<ConditionConfig>,
        disposition: Option<Disposition>,
        actions: Actions,
    ) -> Result<(), TableError> {
        for policy in self.policies.values() {
            if policy.statements.iter().any(|s| s.name.as_ref() == name) {
                return Err(TableError::StillInUse(name.to_string()));
            }
        }
        if all {
            if self.statements.remove(name).is_none() {
                return Err(TableError::NotFound);
            }
            return Ok(());
        }

        let existing = self.statements.get(name).ok_or(TableError::NotFound)?;
        let mut new = (**existing).clone();

        for cfg in &conditions {
            let idx = new
                .conditions
                .iter()
                .position(|c| condition_kind_matches(c, cfg))
                .ok_or_else(|| {
                    TableError::InvalidArgument(format!(
                        "condition isn't set in statement {}",
                        name
                    ))
                })?;
            new.conditions.remove(idx);
        }

        if disposition.is_some() {
            if new.disposition.is_none() {
                return Err(TableError::InvalidArgument(format!(
                    "route action isn't set in statement {}",
                    name
                )));
            }
            new.disposition = None;
        }

        macro_rules! remove_action {
            ($field:ident, $label:literal) => {
                if actions.$field.is_some() {
                    if new.actions.$field.is_none() {
                        return Err(TableError::InvalidArgument(format!(
                            "{} action isn't set in statement {}",
                            $label, name
                        )));
                    }
                    new.actions.$field = None;
                }
            };
        }
        remove_action!(nexthop, "nexthop");
        remove_action!(community, "community");
        remove_action!(local_pref, "local-pref");
        remove_action!(med, "med");
        remove_action!(as_prepend, "as-prepend");
        remove_action!(ext_community, "ext-community");
        remove_action!(large_community, "large-community");
        remove_action!(origin, "origin");

        self.statements.insert(new.name.clone(), Arc::new(new));
        Ok(())
    }

    /// `all=true` deletes the single named policy entirely (after an in-use
    /// check covering global import/export assignments; the daemon crate checks
    /// per-peer assignments before calling this). `all=false` removes only the
    /// given statement names from the policy. Both branches are rejected if the
    /// policy is in use -- see the note on `delete_defined_set`.
    // Returns updated (import_assignment, export_assignment) after removing the policy.
    #[allow(clippy::type_complexity)]
    pub fn delete_policy(
        &mut self,
        name: &str,
        preserve_statements: bool,
        all: bool,
        statement_names: Vec<String>,
    ) -> Result<(Option<Arc<PolicyAssignment>>, Option<Arc<PolicyAssignment>>), TableError> {
        if self.policy_in_use_globally(name) {
            return Err(TableError::StillInUse(name.to_string()));
        }

        if all {
            let policy = self.policies.remove(name).ok_or(TableError::NotFound)?;
            if !preserve_statements {
                for stmt in &policy.statements {
                    let still_used = self
                        .policies
                        .values()
                        .any(|p| p.statements.iter().any(|s| s.name == stmt.name));
                    if !still_used {
                        self.statements.remove(stmt.name.as_ref());
                    }
                }
            }
            return Ok((
                self.assignment_import.clone(),
                self.assignment_export.clone(),
            ));
        }

        let existing = self.policies.get(name).ok_or(TableError::NotFound)?;
        let removed: Vec<Arc<Statement>> = existing
            .statements
            .iter()
            .filter(|s| {
                statement_names
                    .iter()
                    .any(|n| n.as_str() == s.name.as_ref())
            })
            .cloned()
            .collect();
        let mut new = (**existing).clone();
        new.statements.retain(|s| {
            !statement_names
                .iter()
                .any(|n| n.as_str() == s.name.as_ref())
        });
        self.policies.insert(new.name.clone(), Arc::new(new));

        if !preserve_statements {
            for stmt in &removed {
                let still_used = self
                    .policies
                    .values()
                    .any(|p| p.statements.iter().any(|s| s.name == stmt.name));
                if !still_used {
                    self.statements.remove(stmt.name.as_ref());
                }
            }
        }

        Ok((
            self.assignment_import.clone(),
            self.assignment_export.clone(),
        ))
    }

    // Returns the updated assignment after removing policies (or None if all=true).
    pub fn delete_policy_assignment(
        &mut self,
        direction: PolicyDirection,
        policy_names: &[String],
        all: bool,
    ) -> Result<Option<Arc<PolicyAssignment>>, TableError> {
        let field = match direction {
            PolicyDirection::Import => &mut self.assignment_import,
            PolicyDirection::Export => &mut self.assignment_export,
        };
        if all {
            *field = None;
            return Ok(None);
        }
        let old = field.as_ref().ok_or(TableError::NotFound)?;
        let updated = old.without_policies(policy_names);
        *field = Some(updated.clone());
        Ok(Some(updated))
    }

    // Replaces the assignment for direction entirely.
    pub fn set_policy_assignment(
        &mut self,
        name: &str,
        direction: PolicyDirection,
        default_action: Disposition,
        policy_names: Vec<String>,
    ) -> Result<Arc<PolicyAssignment>, TableError> {
        let assignment =
            self.build_assignment(None, name, direction, default_action, policy_names)?;
        match direction {
            PolicyDirection::Import => self.assignment_import = Some(assignment.clone()),
            PolicyDirection::Export => self.assignment_export = Some(assignment.clone()),
        }
        Ok(assignment)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PeerRole, Source, Table};
    use rustybgp_packet::bgp;
    use std::net::{IpAddr, Ipv4Addr};

    fn source() -> Arc<Source> {
        Arc::new(Source::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 254)),
            65001,
            65000,
            Ipv4Addr::new(0, 0, 0, 1),
            PeerRole::Ebgp,
        ))
    }

    fn nlri() -> packet::Nlri {
        packet::Nlri::V4(bgp::Ipv4Net {
            addr: Ipv4Addr::new(10, 0, 0, 0),
            mask: 24,
        })
    }

    fn nh() -> Option<bgp::Nexthop> {
        Some(bgp::Nexthop::V4(Ipv4Addr::new(10, 0, 0, 1)))
    }

    fn local_addr() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 254))
    }

    fn attrs_with_community(communities: &[u32]) -> Arc<Vec<packet::Attribute>> {
        let mut bin = Vec::with_capacity(communities.len() * 4);
        for c in communities {
            bin.extend_from_slice(&c.to_be_bytes());
        }
        Arc::new(vec![
            packet::Attribute::new_with_bin(packet::Attribute::COMMUNITY, bin).unwrap(),
        ])
    }

    fn get_communities(attrs: &[packet::Attribute]) -> Vec<u32> {
        communities_from_attr(attrs)
    }

    fn make_assignment(action: CommunityAction) -> Arc<PolicyAssignment> {
        let mut ptable = PolicyTable::new();
        ptable
            .add_statement(
                "st1",
                vec![],
                Some(Disposition::Accept),
                Actions {
                    community: Some(action),
                    ..Default::default()
                },
            )
            .unwrap();
        ptable.add_policy("pol1", vec!["st1".to_string()]).unwrap();
        let (_, assignment) = ptable
            .add_assignment(
                "ribs",
                PolicyDirection::Export,
                Disposition::Accept,
                vec!["pol1".to_string()],
            )
            .unwrap();
        assignment
    }

    #[test]
    fn community_add_to_existing() {
        let assignment = make_assignment(CommunityAction {
            action_type: CommunityActionType::Add,
            communities: vec![0xFDE8_0064], // 65000:100
        });

        let s = source();
        let net = nlri();
        // Route already carries 65000:200
        let mut attr = attrs_with_community(&[0xFDE8_00C8]);
        let mut nexthop = nh();
        Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut attr,
            &mut nexthop,
            local_addr(),
            s.remote_addr,
            None,
        );

        let result = get_communities(&attr);
        assert!(
            result.contains(&0xFDE8_00C8),
            "original community preserved"
        );
        assert!(result.contains(&0xFDE8_0064), "new community added");
    }

    #[test]
    fn community_add_to_empty() {
        let assignment = make_assignment(CommunityAction {
            action_type: CommunityActionType::Add,
            communities: vec![0xFDE8_0064],
        });

        let s = source();
        let net = nlri();
        let mut attr = Arc::new(vec![]);
        let mut nexthop = nh();
        Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut attr,
            &mut nexthop,
            local_addr(),
            s.remote_addr,
            None,
        );

        let result = get_communities(&attr);
        assert_eq!(result, vec![0xFDE8_0064]);
    }

    #[test]
    fn community_remove() {
        let assignment = make_assignment(CommunityAction {
            action_type: CommunityActionType::Remove,
            communities: vec![0xFDE8_0064], // remove 65000:100
        });

        let s = source();
        let net = nlri();
        let mut attr = attrs_with_community(&[0xFDE8_0064, 0xFDE8_00C8]);
        let mut nexthop = nh();
        Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut attr,
            &mut nexthop,
            local_addr(),
            s.remote_addr,
            None,
        );

        let result = get_communities(&attr);
        assert!(!result.contains(&0xFDE8_0064), "65000:100 removed");
        assert!(result.contains(&0xFDE8_00C8), "65000:200 preserved");
    }

    #[test]
    fn community_remove_all_produces_no_attr() {
        let assignment = make_assignment(CommunityAction {
            action_type: CommunityActionType::Remove,
            communities: vec![0xFDE8_0064],
        });

        let s = source();
        let net = nlri();
        let mut attr = attrs_with_community(&[0xFDE8_0064]);
        let mut nexthop = nh();
        Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut attr,
            &mut nexthop,
            local_addr(),
            s.remote_addr,
            None,
        );

        assert!(
            !attr
                .iter()
                .any(|a| a.code() == packet::Attribute::COMMUNITY),
            "COMMUNITY attribute absent when all removed"
        );
    }

    #[test]
    fn community_replace() {
        let assignment = make_assignment(CommunityAction {
            action_type: CommunityActionType::Replace,
            communities: vec![0xFDE8_0064], // replace with 65000:100
        });

        let s = source();
        let net = nlri();
        let mut attr = attrs_with_community(&[0xFDE8_00C8, 0xFDE8_012C]);
        let mut nexthop = nh();
        Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut attr,
            &mut nexthop,
            local_addr(),
            s.remote_addr,
            None,
        );

        let result = get_communities(&attr);
        assert_eq!(result, vec![0xFDE8_0064], "communities replaced");
    }

    fn make_local_pref_assignment(value: u32) -> Arc<PolicyAssignment> {
        let mut ptable = PolicyTable::new();
        ptable
            .add_statement(
                "st1",
                vec![],
                Some(Disposition::Accept),
                Actions {
                    local_pref: Some(LocalPrefAction { value }),
                    ..Default::default()
                },
            )
            .unwrap();
        ptable.add_policy("pol1", vec!["st1".to_string()]).unwrap();
        let (_, assignment) = ptable
            .add_assignment(
                "ribs",
                PolicyDirection::Export,
                Disposition::Accept,
                vec!["pol1".to_string()],
            )
            .unwrap();
        assignment
    }

    fn get_local_pref(attrs: &[packet::Attribute]) -> Option<u32> {
        attrs
            .iter()
            .find(|a| a.code() == packet::Attribute::LOCAL_PREF)
            .and_then(|a| a.value())
    }

    #[test]
    fn local_pref_set_replaces_existing() {
        let assignment = make_local_pref_assignment(200);

        let s = source();
        let net = nlri();
        let mut attr = Arc::new(vec![
            packet::Attribute::new_with_value(packet::Attribute::LOCAL_PREF, 100).unwrap(),
        ]);
        let mut nexthop = nh();
        Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut attr,
            &mut nexthop,
            local_addr(),
            s.remote_addr,
            None,
        );

        assert_eq!(get_local_pref(&attr), Some(200));
        assert_eq!(
            attr.iter()
                .filter(|a| a.code() == packet::Attribute::LOCAL_PREF)
                .count(),
            1,
            "only one LOCAL_PREF attribute"
        );
    }

    #[test]
    fn local_pref_set_adds_when_absent() {
        let assignment = make_local_pref_assignment(150);

        let s = source();
        let net = nlri();
        let mut attr = Arc::new(vec![]);
        let mut nexthop = nh();
        Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut attr,
            &mut nexthop,
            local_addr(),
            s.remote_addr,
            None,
        );

        assert_eq!(get_local_pref(&attr), Some(150));
    }

    fn make_med_assignment(action_type: MedActionType, value: i64) -> Arc<PolicyAssignment> {
        let mut ptable = PolicyTable::new();
        ptable
            .add_statement(
                "st1",
                vec![],
                Some(Disposition::Accept),
                Actions {
                    med: Some(MedAction { action_type, value }),
                    ..Default::default()
                },
            )
            .unwrap();
        ptable.add_policy("pol1", vec!["st1".to_string()]).unwrap();
        let (_, assignment) = ptable
            .add_assignment(
                "ribs",
                PolicyDirection::Export,
                Disposition::Accept,
                vec!["pol1".to_string()],
            )
            .unwrap();
        assignment
    }

    fn get_med(attrs: &[packet::Attribute]) -> Option<u32> {
        attrs
            .iter()
            .find(|a| a.code() == packet::Attribute::MULTI_EXIT_DESC)
            .and_then(|a| a.value())
    }

    fn attrs_with_med(med: u32) -> Arc<Vec<packet::Attribute>> {
        Arc::new(vec![
            packet::Attribute::new_with_value(packet::Attribute::MULTI_EXIT_DESC, med).unwrap(),
        ])
    }

    #[test]
    fn med_replace_existing() {
        let assignment = make_med_assignment(MedActionType::Replace, 300);
        let s = source();
        let net = nlri();
        let mut attr = attrs_with_med(100);
        let mut nexthop = nh();
        Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut attr,
            &mut nexthop,
            local_addr(),
            s.remote_addr,
            None,
        );
        assert_eq!(get_med(&attr), Some(300));
    }

    #[test]
    fn med_replace_absent() {
        let assignment = make_med_assignment(MedActionType::Replace, 100);
        let s = source();
        let net = nlri();
        let mut attr = Arc::new(vec![]);
        let mut nexthop = nh();
        Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut attr,
            &mut nexthop,
            local_addr(),
            s.remote_addr,
            None,
        );
        assert_eq!(get_med(&attr), Some(100));
    }

    #[test]
    fn med_mod_add() {
        let assignment = make_med_assignment(MedActionType::Mod, 50);
        let s = source();
        let net = nlri();
        let mut attr = attrs_with_med(200);
        let mut nexthop = nh();
        Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut attr,
            &mut nexthop,
            local_addr(),
            s.remote_addr,
            None,
        );
        assert_eq!(get_med(&attr), Some(250));
    }

    #[test]
    fn med_mod_subtract() {
        let assignment = make_med_assignment(MedActionType::Mod, -50);
        let s = source();
        let net = nlri();
        let mut attr = attrs_with_med(200);
        let mut nexthop = nh();
        Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut attr,
            &mut nexthop,
            local_addr(),
            s.remote_addr,
            None,
        );
        assert_eq!(get_med(&attr), Some(150));
    }

    #[test]
    fn med_mod_clamp_to_zero() {
        let assignment = make_med_assignment(MedActionType::Mod, -200);
        let s = source();
        let net = nlri();
        let mut attr = attrs_with_med(100);
        let mut nexthop = nh();
        Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut attr,
            &mut nexthop,
            local_addr(),
            s.remote_addr,
            None,
        );
        assert_eq!(get_med(&attr), Some(0));
    }

    fn make_as_prepend_assignment(
        asn: u32,
        repeat: u32,
        use_left_most: bool,
    ) -> Arc<PolicyAssignment> {
        let mut ptable = PolicyTable::new();
        ptable
            .add_statement(
                "st1",
                vec![],
                Some(Disposition::Accept),
                Actions {
                    as_prepend: Some(AsPrependAction {
                        asn,
                        repeat,
                        use_left_most,
                    }),
                    ..Default::default()
                },
            )
            .unwrap();
        ptable.add_policy("pol1", vec!["st1".to_string()]).unwrap();
        let (_, assignment) = ptable
            .add_assignment(
                "ribs",
                PolicyDirection::Export,
                Disposition::Accept,
                vec!["pol1".to_string()],
            )
            .unwrap();
        assignment
    }

    fn as_path_attr(asns: &[u32]) -> packet::Attribute {
        let mut attr = packet::Attribute::empty_as_path();
        for &asn in asns.iter().rev() {
            attr = attr.as_path_prepend(asn);
        }
        attr
    }

    fn get_as_path(attrs: &[packet::Attribute]) -> Vec<u32> {
        attrs
            .iter()
            .find(|a| a.code() == packet::Attribute::AS_PATH)
            .map(|a| bgp::AsPathIter::new(a).flatten().collect())
            .unwrap_or_default()
    }

    #[test]
    fn as_prepend_once() {
        let assignment = make_as_prepend_assignment(65100, 1, false);
        let s = source();
        let net = nlri();
        let mut attr = Arc::new(vec![as_path_attr(&[65001, 65002])]);
        let mut nexthop = nh();
        Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut attr,
            &mut nexthop,
            local_addr(),
            s.remote_addr,
            None,
        );
        assert_eq!(get_as_path(&attr), vec![65100, 65001, 65002]);
    }

    #[test]
    fn as_prepend_multiple() {
        let assignment = make_as_prepend_assignment(65100, 3, false);
        let s = source();
        let net = nlri();
        let mut attr = Arc::new(vec![as_path_attr(&[65001])]);
        let mut nexthop = nh();
        Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut attr,
            &mut nexthop,
            local_addr(),
            s.remote_addr,
            None,
        );
        assert_eq!(get_as_path(&attr), vec![65100, 65100, 65100, 65001]);
    }

    #[test]
    fn as_prepend_use_left_most() {
        let assignment = make_as_prepend_assignment(0, 1, true);
        let s = source();
        let net = nlri();
        let mut attr = Arc::new(vec![as_path_attr(&[65001, 65002])]);
        let mut nexthop = nh();
        Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut attr,
            &mut nexthop,
            local_addr(),
            s.remote_addr,
            None,
        );
        assert_eq!(get_as_path(&attr), vec![65001, 65001, 65002]);
    }

    #[test]
    fn as_prepend_to_empty_path() {
        let assignment = make_as_prepend_assignment(65100, 2, false);
        let s = source();
        let net = nlri();
        let mut attr = Arc::new(vec![]);
        let mut nexthop = nh();
        Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut attr,
            &mut nexthop,
            local_addr(),
            s.remote_addr,
            None,
        );
        assert_eq!(get_as_path(&attr), vec![65100, 65100]);
    }

    fn make_ext_community_assignment(action: ExtCommunityAction) -> Arc<PolicyAssignment> {
        let mut ptable = PolicyTable::new();
        ptable
            .add_statement(
                "st1",
                vec![],
                Some(Disposition::Accept),
                Actions {
                    ext_community: Some(action),
                    ..Default::default()
                },
            )
            .unwrap();
        ptable.add_policy("pol1", vec!["st1".to_string()]).unwrap();
        let (_, assignment) = ptable
            .add_assignment(
                "ribs",
                PolicyDirection::Export,
                Disposition::Accept,
                vec!["pol1".to_string()],
            )
            .unwrap();
        assignment
    }

    fn get_ext_communities(attrs: &[packet::Attribute]) -> Vec<[u8; 8]> {
        ext_communities_from_attr(attrs)
    }

    // rt:65001:100 in two-octet-AS wire format: type=0x00, sub=0x02, ASN=65001, val=100
    const RT_65001_100: [u8; 8] = [0x00, 0x02, 0xFD, 0xE9, 0x00, 0x00, 0x00, 0x64];
    // rt:65001:200
    const RT_65001_200: [u8; 8] = [0x00, 0x02, 0xFD, 0xE9, 0x00, 0x00, 0x00, 0xC8];
    // soo:65002:100: type=0x00, sub=0x03, ASN=65002, val=100
    const SOO_65002_100: [u8; 8] = [0x00, 0x03, 0xFD, 0xEA, 0x00, 0x00, 0x00, 0x64];

    fn attrs_with_ext_community(communities: &[[u8; 8]]) -> Arc<Vec<packet::Attribute>> {
        let mut bin = Vec::with_capacity(communities.len() * 8);
        for c in communities {
            bin.extend_from_slice(c);
        }
        Arc::new(vec![
            packet::Attribute::new_with_bin(packet::Attribute::EXTENDED_COMMUNITY, bin).unwrap(),
        ])
    }

    #[test]
    fn ext_community_add() {
        let assignment = make_ext_community_assignment(ExtCommunityAction {
            action_type: CommunityActionType::Add,
            communities: vec![RT_65001_100],
        });
        let s = source();
        let net = nlri();
        let mut attr = attrs_with_ext_community(&[SOO_65002_100]);
        let mut nexthop = nh();
        Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut attr,
            &mut nexthop,
            local_addr(),
            s.remote_addr,
            None,
        );
        let result = get_ext_communities(&attr);
        assert!(result.contains(&SOO_65002_100), "original preserved");
        assert!(result.contains(&RT_65001_100), "new added");
    }

    #[test]
    fn ext_community_remove() {
        let assignment = make_ext_community_assignment(ExtCommunityAction {
            action_type: CommunityActionType::Remove,
            communities: vec![RT_65001_100],
        });
        let s = source();
        let net = nlri();
        let mut attr = attrs_with_ext_community(&[RT_65001_100, RT_65001_200]);
        let mut nexthop = nh();
        Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut attr,
            &mut nexthop,
            local_addr(),
            s.remote_addr,
            None,
        );
        let result = get_ext_communities(&attr);
        assert!(!result.contains(&RT_65001_100), "removed");
        assert!(result.contains(&RT_65001_200), "other preserved");
    }

    #[test]
    fn ext_community_replace() {
        let assignment = make_ext_community_assignment(ExtCommunityAction {
            action_type: CommunityActionType::Replace,
            communities: vec![RT_65001_100],
        });
        let s = source();
        let net = nlri();
        let mut attr = attrs_with_ext_community(&[SOO_65002_100, RT_65001_200]);
        let mut nexthop = nh();
        Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut attr,
            &mut nexthop,
            local_addr(),
            s.remote_addr,
            None,
        );
        let result = get_ext_communities(&attr);
        assert_eq!(result, vec![RT_65001_100]);
    }

    fn make_large_community_assignment(action: LargeCommunityAction) -> Arc<PolicyAssignment> {
        let mut ptable = PolicyTable::new();
        ptable
            .add_statement(
                "st1",
                vec![],
                Some(Disposition::Accept),
                Actions {
                    large_community: Some(action),
                    ..Default::default()
                },
            )
            .unwrap();
        ptable.add_policy("pol1", vec!["st1".to_string()]).unwrap();
        let (_, assignment) = ptable
            .add_assignment(
                "ribs",
                PolicyDirection::Export,
                Disposition::Accept,
                vec!["pol1".to_string()],
            )
            .unwrap();
        assignment
    }

    fn get_large_communities(attrs: &[packet::Attribute]) -> Vec<(u32, u32, u32)> {
        large_communities_from_attr(attrs)
    }

    fn attrs_with_large_community(communities: &[(u32, u32, u32)]) -> Arc<Vec<packet::Attribute>> {
        let mut bin = Vec::with_capacity(communities.len() * 12);
        for (ga, ld1, ld2) in communities {
            bin.extend_from_slice(&ga.to_be_bytes());
            bin.extend_from_slice(&ld1.to_be_bytes());
            bin.extend_from_slice(&ld2.to_be_bytes());
        }
        Arc::new(vec![
            packet::Attribute::new_with_bin(packet::Attribute::LARGE_COMMUNITY, bin).unwrap(),
        ])
    }

    #[test]
    fn large_community_add() {
        let assignment = make_large_community_assignment(LargeCommunityAction {
            action_type: CommunityActionType::Add,
            communities: vec![(65000, 1, 100)],
        });
        let s = source();
        let net = nlri();
        let mut attr = attrs_with_large_community(&[(65000, 1, 200)]);
        let mut nexthop = nh();
        Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut attr,
            &mut nexthop,
            local_addr(),
            s.remote_addr,
            None,
        );
        let result = get_large_communities(&attr);
        assert!(result.contains(&(65000, 1, 200)), "original preserved");
        assert!(result.contains(&(65000, 1, 100)), "new added");
    }

    #[test]
    fn large_community_remove() {
        let assignment = make_large_community_assignment(LargeCommunityAction {
            action_type: CommunityActionType::Remove,
            communities: vec![(65000, 1, 100)],
        });
        let s = source();
        let net = nlri();
        let mut attr = attrs_with_large_community(&[(65000, 1, 100), (65000, 1, 200)]);
        let mut nexthop = nh();
        Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut attr,
            &mut nexthop,
            local_addr(),
            s.remote_addr,
            None,
        );
        let result = get_large_communities(&attr);
        assert!(!result.contains(&(65000, 1, 100)), "removed");
        assert!(result.contains(&(65000, 1, 200)), "other preserved");
    }

    #[test]
    fn large_community_replace() {
        let assignment = make_large_community_assignment(LargeCommunityAction {
            action_type: CommunityActionType::Replace,
            communities: vec![(65001, 2, 50)],
        });
        let s = source();
        let net = nlri();
        let mut attr = attrs_with_large_community(&[(65000, 1, 100), (65000, 1, 200)]);
        let mut nexthop = nh();
        Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut attr,
            &mut nexthop,
            local_addr(),
            s.remote_addr,
            None,
        );
        assert_eq!(get_large_communities(&attr), vec![(65001, 2, 50)]);
    }

    fn make_origin_assignment(origin: u8) -> Arc<PolicyAssignment> {
        let mut ptable = PolicyTable::new();
        ptable
            .add_statement(
                "st1",
                vec![],
                Some(Disposition::Accept),
                Actions {
                    origin: Some(OriginAction { origin }),
                    ..Default::default()
                },
            )
            .unwrap();
        ptable.add_policy("pol1", vec!["st1".to_string()]).unwrap();
        let (_, assignment) = ptable
            .add_assignment(
                "ribs",
                PolicyDirection::Export,
                Disposition::Accept,
                vec!["pol1".to_string()],
            )
            .unwrap();
        assignment
    }

    fn get_origin(attrs: &[packet::Attribute]) -> Option<u8> {
        attrs
            .iter()
            .find(|a| a.code() == packet::Attribute::ORIGIN)
            .and_then(|a| a.value())
            .map(|v| v as u8)
    }

    #[test]
    fn origin_set_igp() {
        let assignment = make_origin_assignment(0); // IGP
        let s = source();
        let net = nlri();
        let mut attr = Arc::new(vec![
            packet::Attribute::new_with_value(packet::Attribute::ORIGIN, 2).unwrap(), // Incomplete
        ]);
        let mut nexthop = nh();
        Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut attr,
            &mut nexthop,
            local_addr(),
            s.remote_addr,
            None,
        );
        assert_eq!(get_origin(&attr), Some(0));
    }

    #[test]
    fn origin_set_incomplete() {
        let assignment = make_origin_assignment(2); // Incomplete
        let s = source();
        let net = nlri();
        let mut attr = Arc::new(vec![
            packet::Attribute::new_with_value(packet::Attribute::ORIGIN, 0).unwrap(), // IGP
        ]);
        let mut nexthop = nh();
        Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut attr,
            &mut nexthop,
            local_addr(),
            s.remote_addr,
            None,
        );
        assert_eq!(get_origin(&attr), Some(2));
        assert_eq!(
            attr.iter()
                .filter(|a| a.code() == packet::Attribute::ORIGIN)
                .count(),
            1,
            "only one ORIGIN attribute"
        );
    }

    fn make_condition_assignment(conditions: Vec<ConditionConfig>) -> Arc<PolicyAssignment> {
        let mut ptable = PolicyTable::new();
        ptable
            .add_statement(
                "st1",
                conditions,
                Some(Disposition::Reject),
                Actions::default(),
            )
            .unwrap();
        ptable.add_policy("p1", vec!["st1".to_string()]).unwrap();
        ptable
            .add_assignment(
                "global",
                PolicyDirection::Import,
                Disposition::Accept,
                vec!["p1".to_string()],
            )
            .unwrap();
        ptable.assignment_import.unwrap()
    }

    #[test]
    fn local_pref_eq_match() {
        let assignment = make_condition_assignment(vec![ConditionConfig::LocalPrefEq(200)]);
        let s = source();
        let net = nlri();
        let mut attr = Arc::new(vec![
            packet::Attribute::new_with_value(packet::Attribute::LOCAL_PREF, 200).unwrap(),
        ]);
        let mut nexthop = nh();
        let d = Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut attr,
            &mut nexthop,
            local_addr(),
            s.remote_addr,
            None,
        );
        assert_eq!(d, Disposition::Reject);
    }

    #[test]
    fn local_pref_eq_no_match() {
        let assignment = make_condition_assignment(vec![ConditionConfig::LocalPrefEq(200)]);
        let s = source();
        let net = nlri();
        let mut attr = Arc::new(vec![
            packet::Attribute::new_with_value(packet::Attribute::LOCAL_PREF, 100).unwrap(),
        ]);
        let mut nexthop = nh();
        let d = Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut attr,
            &mut nexthop,
            local_addr(),
            s.remote_addr,
            None,
        );
        assert_eq!(d, Disposition::Accept);
    }

    #[test]
    fn med_eq_match() {
        let assignment = make_condition_assignment(vec![ConditionConfig::MedEq(50)]);
        let s = source();
        let net = nlri();
        let mut attr = Arc::new(vec![
            packet::Attribute::new_with_value(packet::Attribute::MULTI_EXIT_DESC, 50).unwrap(),
        ]);
        let mut nexthop = nh();
        let d = Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut attr,
            &mut nexthop,
            local_addr(),
            s.remote_addr,
            None,
        );
        assert_eq!(d, Disposition::Reject);
    }

    #[test]
    fn med_eq_no_match() {
        let assignment = make_condition_assignment(vec![ConditionConfig::MedEq(50)]);
        let s = source();
        let net = nlri();
        let mut attr = Arc::new(vec![
            packet::Attribute::new_with_value(packet::Attribute::MULTI_EXIT_DESC, 99).unwrap(),
        ]);
        let mut nexthop = nh();
        let d = Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut attr,
            &mut nexthop,
            local_addr(),
            s.remote_addr,
            None,
        );
        assert_eq!(d, Disposition::Accept);
    }

    #[test]
    fn origin_condition_match() {
        // BGP ORIGIN 1 = EGP
        let assignment = make_condition_assignment(vec![ConditionConfig::Origin(1)]);
        let s = source();
        let net = nlri();
        let mut attr = Arc::new(vec![
            packet::Attribute::new_with_value(packet::Attribute::ORIGIN, 1).unwrap(),
        ]);
        let mut nexthop = nh();
        let d = Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut attr,
            &mut nexthop,
            local_addr(),
            s.remote_addr,
            None,
        );
        assert_eq!(d, Disposition::Reject);
    }

    #[test]
    fn origin_condition_no_match() {
        // condition is EGP, route has IGP
        let assignment = make_condition_assignment(vec![ConditionConfig::Origin(1)]);
        let s = source();
        let net = nlri();
        let mut attr = Arc::new(vec![
            packet::Attribute::new_with_value(packet::Attribute::ORIGIN, 0).unwrap(),
        ]);
        let mut nexthop = nh();
        let d = Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut attr,
            &mut nexthop,
            local_addr(),
            s.remote_addr,
            None,
        );
        assert_eq!(d, Disposition::Accept);
    }

    #[test]
    fn route_type_local_matches() {
        let assignment =
            make_condition_assignment(vec![ConditionConfig::RouteType(RouteType::Local)]);
        let s = Source::local();
        let net = nlri();
        let mut attr = Arc::new(vec![]);
        let mut nexthop = nh();
        let d = Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut attr,
            &mut nexthop,
            local_addr(),
            s.remote_addr,
            None,
        );
        assert_eq!(d, Disposition::Reject);
    }

    #[test]
    fn route_type_local_no_match_for_peer() {
        let assignment =
            make_condition_assignment(vec![ConditionConfig::RouteType(RouteType::Local)]);
        let s = source(); // remote peer, not local
        let net = nlri();
        let mut attr = Arc::new(vec![]);
        let mut nexthop = nh();
        let d = Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut attr,
            &mut nexthop,
            local_addr(),
            s.remote_addr,
            None,
        );
        assert_eq!(d, Disposition::Accept);
    }

    #[test]
    fn route_type_external_matches() {
        let assignment =
            make_condition_assignment(vec![ConditionConfig::RouteType(RouteType::External)]);
        // source() has remote_asn=65001, local_asn=65000 => external
        let s = source();
        let net = nlri();
        let mut attr = Arc::new(vec![]);
        let mut nexthop = nh();
        let d = Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut attr,
            &mut nexthop,
            local_addr(),
            s.remote_addr,
            None,
        );
        assert_eq!(d, Disposition::Reject);
    }

    #[test]
    fn community_count_eq_match() {
        let assignment =
            make_condition_assignment(vec![ConditionConfig::CommunityCount(Comparison::Eq, 2)]);
        let s = source();
        let net = nlri();
        let mut attr = attrs_with_community(&[0x00010001, 0x00010002]);
        let mut nexthop = nh();
        let d = Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut attr,
            &mut nexthop,
            local_addr(),
            s.remote_addr,
            None,
        );
        assert_eq!(d, Disposition::Reject);
    }

    #[test]
    fn community_count_eq_no_match() {
        let assignment =
            make_condition_assignment(vec![ConditionConfig::CommunityCount(Comparison::Eq, 2)]);
        let s = source();
        let net = nlri();
        let mut attr = attrs_with_community(&[0x00010001]);
        let mut nexthop = nh();
        let d = Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut attr,
            &mut nexthop,
            local_addr(),
            s.remote_addr,
            None,
        );
        assert_eq!(d, Disposition::Accept);
    }

    #[test]
    fn community_count_ge_match() {
        let assignment =
            make_condition_assignment(vec![ConditionConfig::CommunityCount(Comparison::Ge, 2)]);
        let s = source();
        let net = nlri();
        let mut attr = attrs_with_community(&[0x00010001, 0x00010002, 0x00010003]);
        let mut nexthop = nh();
        let d = Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut attr,
            &mut nexthop,
            local_addr(),
            s.remote_addr,
            None,
        );
        assert_eq!(d, Disposition::Reject);
    }

    #[test]
    fn afi_safi_in_ipv4_match() {
        let assignment =
            make_condition_assignment(vec![ConditionConfig::AfiSafiIn(vec![bgp::Family::IPV4])]);
        let s = source();
        let net = nlri(); // V4
        let mut attr = Arc::new(vec![]);
        let mut nexthop = nh();
        let d = Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut attr,
            &mut nexthop,
            local_addr(),
            s.remote_addr,
            None,
        );
        assert_eq!(d, Disposition::Reject);
    }

    #[test]
    fn afi_safi_in_ipv4_no_match_for_ipv6() {
        let assignment =
            make_condition_assignment(vec![ConditionConfig::AfiSafiIn(vec![bgp::Family::IPV6])]);
        let s = source();
        let net = nlri(); // V4
        let mut attr = Arc::new(vec![]);
        let mut nexthop = nh();
        let d = Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut attr,
            &mut nexthop,
            local_addr(),
            s.remote_addr,
            None,
        );
        assert_eq!(d, Disposition::Accept);
    }

    #[test]
    fn route_type_internal_matches() {
        let assignment =
            make_condition_assignment(vec![ConditionConfig::RouteType(RouteType::Internal)]);
        // same ASN => internal
        let s = Arc::new(Source::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 254)),
            65000,
            65000,
            Ipv4Addr::new(0, 0, 0, 1),
            PeerRole::Ibgp,
        ));
        let net = nlri();
        let mut attr = Arc::new(vec![]);
        let mut nexthop = nh();
        let d = Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut attr,
            &mut nexthop,
            local_addr(),
            s.remote_addr,
            None,
        );
        assert_eq!(d, Disposition::Reject);
    }

    fn make_ext_community_condition_assignment(
        set_name: &str,
        patterns: Vec<String>,
        opt: MatchOption,
    ) -> Arc<PolicyAssignment> {
        let mut ptable = PolicyTable::new();
        ptable
            .add_defined_set(DefinedSetConfig::ExtCommunity {
                name: set_name.to_string(),
                patterns,
            })
            .unwrap();
        ptable
            .add_statement(
                "st1",
                vec![ConditionConfig::ExtCommunitySet(set_name.to_string(), opt)],
                Some(Disposition::Reject),
                Actions::default(),
            )
            .unwrap();
        ptable.add_policy("p1", vec!["st1".to_string()]).unwrap();
        ptable
            .add_assignment(
                "global",
                PolicyDirection::Import,
                Disposition::Accept,
                vec!["p1".to_string()],
            )
            .unwrap();
        ptable.assignment_import.unwrap()
    }

    fn attrs_with_ext_community_bytes(bytes: &[[u8; 8]]) -> Arc<Vec<packet::Attribute>> {
        let mut bin = Vec::with_capacity(bytes.len() * 8);
        for b in bytes {
            bin.extend_from_slice(b);
        }
        Arc::new(vec![
            packet::Attribute::new_with_bin(packet::Attribute::EXTENDED_COMMUNITY, bin).unwrap(),
        ])
    }

    fn rt_bytes(asn: u16, local: u32) -> [u8; 8] {
        let mut b = [0u8; 8];
        b[0] = 0x00;
        b[1] = 0x02;
        b[2] = (asn >> 8) as u8;
        b[3] = asn as u8;
        b[4] = (local >> 24) as u8;
        b[5] = (local >> 16) as u8;
        b[6] = (local >> 8) as u8;
        b[7] = local as u8;
        b
    }

    #[test]
    fn ext_community_set_any_match() {
        let assignment = make_ext_community_condition_assignment(
            "ec1",
            vec!["^rt:65000:100$".to_string()],
            MatchOption::Any,
        );
        let s = source();
        let net = nlri();
        let mut attr = attrs_with_ext_community_bytes(&[rt_bytes(65000, 100)]);
        let mut nexthop = nh();
        let d = Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut attr,
            &mut nexthop,
            local_addr(),
            s.remote_addr,
            None,
        );
        assert_eq!(d, Disposition::Reject);
    }

    #[test]
    fn ext_community_set_any_no_match() {
        let assignment = make_ext_community_condition_assignment(
            "ec1",
            vec!["^rt:65000:100$".to_string()],
            MatchOption::Any,
        );
        let s = source();
        let net = nlri();
        let mut attr = attrs_with_ext_community_bytes(&[rt_bytes(65001, 100)]);
        let mut nexthop = nh();
        let d = Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut attr,
            &mut nexthop,
            local_addr(),
            s.remote_addr,
            None,
        );
        assert_eq!(d, Disposition::Accept);
    }

    fn make_large_community_condition_assignment(
        set_name: &str,
        patterns: Vec<String>,
        opt: MatchOption,
    ) -> Arc<PolicyAssignment> {
        let mut ptable = PolicyTable::new();
        ptable
            .add_defined_set(DefinedSetConfig::LargeCommunity {
                name: set_name.to_string(),
                patterns,
            })
            .unwrap();
        ptable
            .add_statement(
                "st1",
                vec![ConditionConfig::LargeCommunitySet(
                    set_name.to_string(),
                    opt,
                )],
                Some(Disposition::Reject),
                Actions::default(),
            )
            .unwrap();
        ptable.add_policy("p1", vec!["st1".to_string()]).unwrap();
        ptable
            .add_assignment(
                "global",
                PolicyDirection::Import,
                Disposition::Accept,
                vec!["p1".to_string()],
            )
            .unwrap();
        ptable.assignment_import.unwrap()
    }

    fn attrs_with_large_community_tuples(
        communities: &[(u32, u32, u32)],
    ) -> Arc<Vec<packet::Attribute>> {
        let mut bin = Vec::with_capacity(communities.len() * 12);
        for (ga, ld1, ld2) in communities {
            bin.extend_from_slice(&ga.to_be_bytes());
            bin.extend_from_slice(&ld1.to_be_bytes());
            bin.extend_from_slice(&ld2.to_be_bytes());
        }
        Arc::new(vec![
            packet::Attribute::new_with_bin(packet::Attribute::LARGE_COMMUNITY, bin).unwrap(),
        ])
    }

    #[test]
    fn large_community_set_any_match() {
        let assignment = make_large_community_condition_assignment(
            "lc1",
            vec!["^65000:1:100$".to_string()],
            MatchOption::Any,
        );
        let s = source();
        let net = nlri();
        let mut attr = attrs_with_large_community_tuples(&[(65000, 1, 100)]);
        let mut nexthop = nh();
        let d = Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut attr,
            &mut nexthop,
            local_addr(),
            s.remote_addr,
            None,
        );
        assert_eq!(d, Disposition::Reject);
    }

    #[test]
    fn large_community_set_any_no_match() {
        let assignment = make_large_community_condition_assignment(
            "lc1",
            vec!["^65000:1:100$".to_string()],
            MatchOption::Any,
        );
        let s = source();
        let net = nlri();
        let mut attr = attrs_with_large_community_tuples(&[(65001, 1, 100)]);
        let mut nexthop = nh();
        let d = Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut attr,
            &mut nexthop,
            local_addr(),
            s.remote_addr,
            None,
        );
        assert_eq!(d, Disposition::Accept);
    }

    fn make_nexthop_condition_assignment(nexthops: Vec<IpAddr>) -> Arc<PolicyAssignment> {
        let mut ptable = PolicyTable::new();
        ptable
            .add_statement(
                "s1",
                vec![ConditionConfig::Nexthop(nexthops)],
                Some(Disposition::Accept),
                Actions::default(),
            )
            .unwrap();
        ptable.add_policy("p1", vec!["s1".to_string()]).unwrap();
        ptable
            .add_assignment(
                "a1",
                PolicyDirection::Import,
                Disposition::Reject,
                vec!["p1".to_string()],
            )
            .unwrap()
            .1
    }

    #[test]
    fn nexthop_condition_match() {
        let assignment =
            make_nexthop_condition_assignment(vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))]);
        let s = source();
        let net = nlri();
        let mut attr = Arc::new(vec![]);
        let mut nexthop = Some(bgp::Nexthop::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let d = Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut attr,
            &mut nexthop,
            local_addr(),
            s.remote_addr,
            None,
        );
        assert_eq!(d, Disposition::Accept);
    }

    #[test]
    fn nexthop_condition_no_match() {
        let assignment =
            make_nexthop_condition_assignment(vec![IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1))]);
        let s = source();
        let net = nlri();
        let mut attr = Arc::new(vec![]);
        let mut nexthop = Some(bgp::Nexthop::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let d = Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut attr,
            &mut nexthop,
            local_addr(),
            s.remote_addr,
            None,
        );
        assert_eq!(d, Disposition::Reject);
    }

    #[test]
    fn nexthop_condition_multiple_match() {
        let assignment = make_nexthop_condition_assignment(vec![
            IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        ]);
        let s = source();
        let net = nlri();
        let mut attr = Arc::new(vec![]);
        let mut nexthop = Some(bgp::Nexthop::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let d = Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut attr,
            &mut nexthop,
            local_addr(),
            s.remote_addr,
            None,
        );
        assert_eq!(d, Disposition::Accept);
    }

    // --- apply_import ---

    fn import_source(addr: u8) -> Arc<Source> {
        Arc::new(Source::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, addr)),
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            65001,
            65000,
            Ipv4Addr::new(10, 0, 0, addr),
            PeerRole::Ebgp,
        ))
    }

    fn reject_all_import_policy() -> Arc<PolicyAssignment> {
        let mut ptable = PolicyTable::new();
        ptable
            .add_defined_set(DefinedSetConfig::Prefix {
                name: "all".to_string(),
                prefixes: vec![PrefixConfig {
                    ip_prefix: "0.0.0.0/0".to_string(),
                    mask_length_min: 0,
                    mask_length_max: 32,
                }],
            })
            .unwrap();
        ptable
            .add_statement(
                "reject-all",
                vec![ConditionConfig::PrefixSet(
                    "all".to_string(),
                    MatchOption::Any,
                )],
                Some(Disposition::Reject),
                Actions::default(),
            )
            .unwrap();
        ptable
            .add_policy("reject-policy", vec!["reject-all".to_string()])
            .unwrap();
        let (_, assignment) = ptable
            .add_assignment(
                "global",
                PolicyDirection::Import,
                Disposition::Accept,
                vec!["reject-policy".to_string()],
            )
            .unwrap();
        assignment
    }

    fn make_nexthop_assignment(nh_action: NexthopAction) -> Arc<PolicyAssignment> {
        let mut ptable = PolicyTable::new();
        ptable
            .add_statement(
                "st1",
                vec![],
                Some(Disposition::Accept),
                Actions {
                    nexthop: Some(nh_action),
                    ..Default::default()
                },
            )
            .unwrap();
        ptable.add_policy("pol1", vec!["st1".to_string()]).unwrap();
        let (_, assignment) = ptable
            .add_assignment(
                "ribs",
                PolicyDirection::Export,
                Disposition::Accept,
                vec!["pol1".to_string()],
            )
            .unwrap();
        assignment
    }

    #[test]
    fn nexthop_peer_address_action() {
        let peer_addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let assignment = make_nexthop_assignment(NexthopAction::PeerAddress);

        let s = Arc::new(Source::new(
            peer_addr,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 254)),
            65001,
            65000,
            Ipv4Addr::new(0, 0, 0, 1),
            PeerRole::Ebgp,
        ));
        let net = nlri();
        let mut attr = Arc::new(vec![]);
        let mut nexthop = nh(); // original nexthop: 10.0.0.1
        Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut attr,
            &mut nexthop,
            local_addr(),
            s.remote_addr,
            None,
        );
        assert_eq!(
            nexthop,
            Some(bgp::Nexthop::V4(Ipv4Addr::new(192, 168, 1, 1))),
            "nexthop should be set to peer address"
        );
    }

    #[test]
    fn ext_community_4octet_as_rt_soo_to_string() {
        let make = |asn: u32, local: u16, subtype: u8| -> [u8; 8] {
            let mut c = [0u8; 8];
            c[0] = 0x02;
            c[1] = subtype;
            c[2..6].copy_from_slice(&asn.to_be_bytes());
            c[6] = (local >> 8) as u8;
            c[7] = local as u8;
            c
        };
        // rt with 4-octet ASN
        assert_eq!(
            ext_community_to_string(&make(131072, 100, 0x02)),
            Some("rt:131072:100".to_string())
        );
        // soo with 4-octet ASN
        assert_eq!(
            ext_community_to_string(&make(131072, 200, 0x03)),
            Some("soo:131072:200".to_string())
        );
        // ASN at boundary (65536 = just above u16::MAX)
        assert_eq!(
            ext_community_to_string(&make(65536, 1, 0x02)),
            Some("rt:65536:1".to_string())
        );
    }

    #[test]
    fn ext_community_lb_to_string() {
        let make = |asn: u16, bw: f32| -> [u8; 8] {
            let mut c = [0u8; 8];
            c[0] = 0x40;
            c[1] = 0x04;
            c[2] = (asn >> 8) as u8;
            c[3] = asn as u8;
            c[4..8].copy_from_slice(&bw.to_bits().to_be_bytes());
            c
        };
        assert_eq!(
            ext_community_to_string(&make(65001, 100.0)),
            Some("lb:65001:100".to_string())
        );
        assert_eq!(
            ext_community_to_string(&make(100, 1.5)),
            Some("lb:100:1.5".to_string())
        );
        // Unknown subtype (0x40, 0x05) -> None
        let mut bad = make(65001, 100.0);
        bad[1] = 0x05;
        assert_eq!(ext_community_to_string(&bad), None);
    }

    #[test]
    fn ext_community_validation_to_string() {
        let make = |state: u8| -> [u8; 8] {
            let mut c = [0u8; 8];
            c[0] = 0x43;
            c[1] = 0x00;
            c[7] = state;
            c
        };
        assert_eq!(
            ext_community_to_string(&make(0)),
            Some("validation:valid".to_string())
        );
        assert_eq!(
            ext_community_to_string(&make(1)),
            Some("validation:not-found".to_string())
        );
        assert_eq!(
            ext_community_to_string(&make(2)),
            Some("validation:invalid".to_string())
        );
        // Unknown state value -> None
        assert_eq!(ext_community_to_string(&make(3)), None);
    }

    #[test]
    fn ext_community_encap_to_string() {
        // VXLAN encap (tunnel type 8)
        let c: [u8; 8] = [0x03, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08];
        assert_eq!(ext_community_to_string(&c), Some("encap:8".to_string()));
        // L2TPv3 (tunnel type 1)
        let c: [u8; 8] = [0x03, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        assert_eq!(ext_community_to_string(&c), Some("encap:1".to_string()));
        // Unknown subtype (type 0x03, subtype != 0x0c) -> None
        let c: [u8; 8] = [0x03, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08];
        assert_eq!(ext_community_to_string(&c), None);
    }

    #[test]
    fn prefix_set_ipv6_match() {
        use std::net::Ipv6Addr;
        let mut ptable = PolicyTable::new();
        ptable
            .add_defined_set(DefinedSetConfig::Prefix {
                name: "ipv6-set".to_string(),
                prefixes: vec![PrefixConfig {
                    ip_prefix: "2001:db8::/32".to_string(),
                    mask_length_min: 32,
                    mask_length_max: 128,
                }],
            })
            .unwrap();
        ptable
            .add_statement(
                "st1",
                vec![ConditionConfig::PrefixSet(
                    "ipv6-set".to_string(),
                    MatchOption::Any,
                )],
                Some(Disposition::Reject),
                Actions::default(),
            )
            .unwrap();
        ptable.add_policy("p1", vec!["st1".to_string()]).unwrap();
        let (_, assignment) = ptable
            .add_assignment(
                "global",
                PolicyDirection::Import,
                Disposition::Accept,
                vec!["p1".to_string()],
            )
            .unwrap();

        let src = import_source(1);

        // 2001:db8::1/48 should match (within 2001:db8::/32)
        let matched_net = packet::Nlri::V6(bgp::Ipv6Net {
            addr: Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0),
            mask: 48,
        });
        let attr = Arc::new(vec![]);
        let mut nh = Some(bgp::Nexthop::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)));
        let (filtered, _) = apply_import(&assignment, None, &src, &matched_net, &attr, &mut nh);
        assert!(
            filtered,
            "2001:db8::/48 should be rejected by ipv6 prefix set"
        );

        // 2001:db9::/32 should not match
        let no_match_net = packet::Nlri::V6(bgp::Ipv6Net {
            addr: Ipv6Addr::new(0x2001, 0x0db9, 0, 0, 0, 0, 0, 0),
            mask: 32,
        });
        let attr2 = Arc::new(vec![]);
        let mut nh2 = Some(bgp::Nexthop::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)));
        let (filtered2, _) = apply_import(&assignment, None, &src, &no_match_net, &attr2, &mut nh2);
        assert!(!filtered2, "2001:db9::/32 should not match ipv6 prefix set");
    }

    #[test]
    fn apply_import_rejected_by_policy() {
        use rustybgp_packet as packet;
        let policy = reject_all_import_policy();
        let attrs = Arc::new(vec![
            packet::Attribute::new_with_value(packet::Attribute::ORIGIN, 0).unwrap(),
        ]);
        let mut nh = Some(bgp::Nexthop::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let net = "10.0.0.0/24".parse().unwrap();
        let src = import_source(1);
        let (filtered, _) = apply_import(&policy, None, &src, &net, &attrs, &mut nh);
        assert!(filtered);
    }

    fn two_prefix_set() -> DefinedSetConfig {
        DefinedSetConfig::Prefix {
            name: "ps1".to_string(),
            prefixes: vec![
                PrefixConfig {
                    ip_prefix: "10.0.0.0/24".to_string(),
                    mask_length_min: 24,
                    mask_length_max: 24,
                },
                PrefixConfig {
                    ip_prefix: "10.1.0.0/24".to_string(),
                    mask_length_min: 24,
                    mask_length_max: 24,
                },
            ],
        }
    }

    fn prefix_set_by_name<'a>(ptable: &'a PolicyTable, name: &str) -> &'a PrefixSet {
        ptable
            .iter_defined_sets()
            .find_map(|r| match r {
                DefinedSetRef::Prefix(n, s) if n == name => Some(s),
                _ => None,
            })
            .unwrap()
    }

    #[test]
    fn delete_defined_set_all_true_removes_named_set() {
        let mut ptable = PolicyTable::new();
        ptable.add_defined_set(two_prefix_set()).unwrap();

        ptable
            .delete_defined_set(
                DefinedSetConfig::Prefix {
                    name: "ps1".to_string(),
                    prefixes: vec![],
                },
                true,
            )
            .unwrap();

        assert!(ptable.iter_defined_sets().next().is_none());
    }

    #[test]
    fn delete_defined_set_all_true_rejects_when_in_use() {
        let mut ptable = PolicyTable::new();
        ptable.add_defined_set(two_prefix_set()).unwrap();
        ptable
            .add_statement(
                "st1",
                vec![ConditionConfig::PrefixSet(
                    "ps1".to_string(),
                    MatchOption::Any,
                )],
                Some(Disposition::Reject),
                Actions::default(),
            )
            .unwrap();

        let result = ptable.delete_defined_set(
            DefinedSetConfig::Prefix {
                name: "ps1".to_string(),
                prefixes: vec![],
            },
            true,
        );
        assert!(matches!(result, Err(TableError::StillInUse(_))));
    }

    #[test]
    fn delete_defined_set_all_false_removes_only_given_prefix() {
        let mut ptable = PolicyTable::new();
        ptable.add_defined_set(two_prefix_set()).unwrap();

        ptable
            .delete_defined_set(
                DefinedSetConfig::Prefix {
                    name: "ps1".to_string(),
                    prefixes: vec![PrefixConfig {
                        ip_prefix: "10.0.0.0/24".to_string(),
                        mask_length_min: 24,
                        mask_length_max: 24,
                    }],
                },
                false,
            )
            .unwrap();

        let set = prefix_set_by_name(&ptable, "ps1");
        assert!(set.v4.exact_match(Ipv4Addr::new(10, 0, 0, 0), 24).is_none());
        assert!(set.v4.exact_match(Ipv4Addr::new(10, 1, 0, 0), 24).is_some());
    }

    #[test]
    fn delete_defined_set_all_false_rejects_when_in_use() {
        let mut ptable = PolicyTable::new();
        ptable.add_defined_set(two_prefix_set()).unwrap();
        ptable
            .add_statement(
                "st1",
                vec![ConditionConfig::PrefixSet(
                    "ps1".to_string(),
                    MatchOption::Any,
                )],
                Some(Disposition::Reject),
                Actions::default(),
            )
            .unwrap();

        let result = ptable.delete_defined_set(
            DefinedSetConfig::Prefix {
                name: "ps1".to_string(),
                prefixes: vec![PrefixConfig {
                    ip_prefix: "10.0.0.0/24".to_string(),
                    mask_length_min: 24,
                    mask_length_max: 24,
                }],
            },
            false,
        );
        assert!(matches!(result, Err(TableError::StillInUse(_))));
    }

    fn two_condition_statement() -> (&'static str, Vec<ConditionConfig>) {
        (
            "st1",
            vec![
                ConditionConfig::PrefixSet("ps1".to_string(), MatchOption::Any),
                ConditionConfig::LocalPrefEq(100),
            ],
        )
    }

    #[test]
    fn delete_statement_all_false_removes_only_given_condition_kind() {
        let mut ptable = PolicyTable::new();
        ptable.add_defined_set(two_prefix_set()).unwrap();
        let (name, conditions) = two_condition_statement();
        ptable
            .add_statement(
                name,
                conditions,
                Some(Disposition::Reject),
                Actions::default(),
            )
            .unwrap();

        ptable
            .delete_statement(
                name,
                false,
                vec![ConditionConfig::LocalPrefEq(0)],
                None,
                Actions::default(),
            )
            .unwrap();

        let stmt = ptable.statements.get(name).unwrap();
        assert_eq!(stmt.conditions.len(), 1);
        assert!(matches!(stmt.conditions[0], Condition::Prefix(..)));
    }

    #[test]
    fn delete_statement_all_false_errors_when_kind_not_set() {
        let mut ptable = PolicyTable::new();
        ptable
            .add_statement("st1", vec![], Some(Disposition::Reject), Actions::default())
            .unwrap();

        let result = ptable.delete_statement(
            "st1",
            false,
            vec![ConditionConfig::LocalPrefEq(0)],
            None,
            Actions::default(),
        );
        assert!(matches!(result, Err(TableError::InvalidArgument(_))));
    }

    #[test]
    fn delete_statement_rejects_when_in_use() {
        let mut ptable = PolicyTable::new();
        ptable
            .add_statement("st1", vec![], Some(Disposition::Reject), Actions::default())
            .unwrap();
        ptable.add_policy("pol1", vec!["st1".to_string()]).unwrap();

        for all in [true, false] {
            let result = ptable.delete_statement("st1", all, vec![], None, Actions::default());
            assert!(matches!(result, Err(TableError::StillInUse(_))));
        }
    }

    #[test]
    fn delete_policy_all_false_removes_only_given_statement() {
        let mut ptable = PolicyTable::new();
        ptable
            .add_statement("st1", vec![], Some(Disposition::Reject), Actions::default())
            .unwrap();
        ptable
            .add_statement("st2", vec![], Some(Disposition::Accept), Actions::default())
            .unwrap();
        ptable
            .add_policy("pol1", vec!["st1".to_string(), "st2".to_string()])
            .unwrap();

        ptable
            .delete_policy("pol1", false, false, vec!["st1".to_string()])
            .unwrap();

        let pol = ptable.policies.get("pol1").unwrap();
        assert_eq!(pol.statements.len(), 1);
        assert_eq!(pol.statements[0].name.as_ref(), "st2");
        assert!(
            !ptable.statements.contains_key("st1"),
            "st1 is now unused and should be pruned"
        );
        assert!(ptable.statements.contains_key("st2"));
    }

    #[test]
    fn delete_policy_all_false_preserve_statements_keeps_unused_statement() {
        let mut ptable = PolicyTable::new();
        ptable
            .add_statement("st1", vec![], Some(Disposition::Reject), Actions::default())
            .unwrap();
        ptable.add_policy("pol1", vec!["st1".to_string()]).unwrap();

        ptable
            .delete_policy("pol1", true, false, vec!["st1".to_string()])
            .unwrap();

        assert!(ptable.statements.contains_key("st1"));
    }

    #[test]
    fn delete_policy_rejects_partial_when_in_use() {
        let mut ptable = PolicyTable::new();
        ptable
            .add_statement("st1", vec![], Some(Disposition::Reject), Actions::default())
            .unwrap();
        ptable.add_policy("pol1", vec!["st1".to_string()]).unwrap();
        ptable
            .add_assignment(
                "global",
                PolicyDirection::Export,
                Disposition::Accept,
                vec!["pol1".to_string()],
            )
            .unwrap();

        let result = ptable.delete_policy("pol1", false, false, vec!["st1".to_string()]);
        assert!(matches!(result, Err(TableError::StillInUse(_))));
    }

    fn one_prefix_set(name: &str, ip_prefix: &str) -> DefinedSetConfig {
        DefinedSetConfig::Prefix {
            name: name.to_string(),
            prefixes: vec![PrefixConfig {
                ip_prefix: ip_prefix.to_string(),
                mask_length_min: 24,
                mask_length_max: 24,
            }],
        }
    }

    #[test]
    fn add_defined_set_merges_into_existing() {
        let mut ptable = PolicyTable::new();
        ptable
            .add_defined_set(one_prefix_set("ps1", "10.0.0.0/24"))
            .unwrap();
        ptable
            .add_defined_set(one_prefix_set("ps1", "10.1.0.0/24"))
            .unwrap();

        let set = prefix_set_by_name(&ptable, "ps1");
        assert!(set.v4.exact_match(Ipv4Addr::new(10, 0, 0, 0), 24).is_some());
        assert!(set.v4.exact_match(Ipv4Addr::new(10, 1, 0, 0), 24).is_some());
    }

    #[test]
    fn add_defined_set_rejects_merge_when_in_use() {
        let mut ptable = PolicyTable::new();
        ptable
            .add_defined_set(one_prefix_set("ps1", "10.0.0.0/24"))
            .unwrap();
        ptable
            .add_statement(
                "st1",
                vec![ConditionConfig::PrefixSet(
                    "ps1".to_string(),
                    MatchOption::Any,
                )],
                Some(Disposition::Reject),
                Actions::default(),
            )
            .unwrap();

        let result = ptable.add_defined_set(one_prefix_set("ps1", "10.1.0.0/24"));
        assert!(matches!(result, Err(TableError::StillInUse(_))));
    }

    #[test]
    fn replace_defined_set_overwrites_existing() {
        let mut ptable = PolicyTable::new();
        ptable
            .add_defined_set(one_prefix_set("ps1", "10.0.0.0/24"))
            .unwrap();

        ptable
            .replace_defined_set(one_prefix_set("ps1", "10.1.0.0/24"))
            .unwrap();

        let set = prefix_set_by_name(&ptable, "ps1");
        assert!(set.v4.exact_match(Ipv4Addr::new(10, 0, 0, 0), 24).is_none());
        assert!(set.v4.exact_match(Ipv4Addr::new(10, 1, 0, 0), 24).is_some());
    }

    #[test]
    fn replace_defined_set_rejects_when_in_use() {
        let mut ptable = PolicyTable::new();
        ptable
            .add_defined_set(one_prefix_set("ps1", "10.0.0.0/24"))
            .unwrap();
        ptable
            .add_statement(
                "st1",
                vec![ConditionConfig::PrefixSet(
                    "ps1".to_string(),
                    MatchOption::Any,
                )],
                Some(Disposition::Reject),
                Actions::default(),
            )
            .unwrap();

        let result = ptable.replace_defined_set(one_prefix_set("ps1", "10.1.0.0/24"));
        assert!(matches!(result, Err(TableError::StillInUse(_))));
        let set = prefix_set_by_name(&ptable, "ps1");
        assert!(
            set.v4.exact_match(Ipv4Addr::new(10, 0, 0, 0), 24).is_some(),
            "rejected replace must leave the original set intact"
        );
    }

    #[test]
    fn add_statement_merges_new_condition_kind() {
        let mut ptable = PolicyTable::new();
        ptable
            .add_statement(
                "st1",
                vec![ConditionConfig::LocalPrefEq(100)],
                Some(Disposition::Reject),
                Actions::default(),
            )
            .unwrap();

        ptable
            .add_statement(
                "st1",
                vec![ConditionConfig::MedEq(50)],
                None,
                Actions::default(),
            )
            .unwrap();

        let stmt = ptable.statements.get("st1").unwrap();
        assert_eq!(stmt.conditions.len(), 2);
    }

    #[test]
    fn add_statement_errors_when_kind_already_set() {
        let mut ptable = PolicyTable::new();
        ptable
            .add_statement(
                "st1",
                vec![ConditionConfig::LocalPrefEq(100)],
                Some(Disposition::Reject),
                Actions::default(),
            )
            .unwrap();

        let result = ptable.add_statement(
            "st1",
            vec![ConditionConfig::LocalPrefEq(200)],
            None,
            Actions::default(),
        );
        assert!(matches!(result, Err(TableError::InvalidArgument(_))));
    }

    #[test]
    fn add_statement_rejects_merge_when_in_use() {
        let mut ptable = PolicyTable::new();
        ptable
            .add_statement("st1", vec![], Some(Disposition::Reject), Actions::default())
            .unwrap();
        ptable.add_policy("pol1", vec!["st1".to_string()]).unwrap();

        let result = ptable.add_statement(
            "st1",
            vec![ConditionConfig::LocalPrefEq(100)],
            None,
            Actions::default(),
        );
        assert!(matches!(result, Err(TableError::StillInUse(_))));
    }

    #[test]
    fn add_policy_appends_statements() {
        let mut ptable = PolicyTable::new();
        ptable
            .add_statement("st1", vec![], Some(Disposition::Reject), Actions::default())
            .unwrap();
        ptable
            .add_statement("st2", vec![], Some(Disposition::Accept), Actions::default())
            .unwrap();
        ptable.add_policy("pol1", vec!["st1".to_string()]).unwrap();

        ptable.add_policy("pol1", vec!["st2".to_string()]).unwrap();

        let pol = ptable.policies.get("pol1").unwrap();
        assert_eq!(pol.statements.len(), 2);
    }

    #[test]
    fn add_policy_rejects_merge_when_in_use() {
        let mut ptable = PolicyTable::new();
        ptable
            .add_statement("st1", vec![], Some(Disposition::Reject), Actions::default())
            .unwrap();
        ptable
            .add_statement("st2", vec![], Some(Disposition::Accept), Actions::default())
            .unwrap();
        ptable.add_policy("pol1", vec!["st1".to_string()]).unwrap();
        ptable
            .add_assignment(
                "global",
                PolicyDirection::Export,
                Disposition::Accept,
                vec!["pol1".to_string()],
            )
            .unwrap();

        let result = ptable.add_policy("pol1", vec!["st2".to_string()]);
        assert!(matches!(result, Err(TableError::StillInUse(_))));
    }

    #[test]
    fn iter_assignments_unspecified_direction_returns_both() {
        let mut ptable = PolicyTable::new();
        ptable
            .add_statement("st1", vec![], Some(Disposition::Reject), Actions::default())
            .unwrap();
        ptable.add_policy("pol1", vec!["st1".to_string()]).unwrap();
        ptable
            .add_assignment(
                "global",
                PolicyDirection::Import,
                Disposition::Accept,
                vec!["pol1".to_string()],
            )
            .unwrap();
        ptable
            .add_assignment(
                "global",
                PolicyDirection::Export,
                Disposition::Accept,
                vec!["pol1".to_string()],
            )
            .unwrap();

        let dirs: Vec<i32> = ptable.iter_assignments(0).map(|(dir, _)| dir).collect();
        assert_eq!(dirs.len(), 2, "unspecified direction must return both");
        assert!(dirs.contains(&1), "import missing");
        assert!(dirs.contains(&2), "export missing");
    }

    #[test]
    fn iter_assignments_import_direction_excludes_export() {
        let mut ptable = PolicyTable::new();
        ptable
            .add_statement("st1", vec![], Some(Disposition::Reject), Actions::default())
            .unwrap();
        ptable.add_policy("pol1", vec!["st1".to_string()]).unwrap();
        ptable
            .add_assignment(
                "global",
                PolicyDirection::Import,
                Disposition::Accept,
                vec!["pol1".to_string()],
            )
            .unwrap();
        ptable
            .add_assignment(
                "global",
                PolicyDirection::Export,
                Disposition::Accept,
                vec!["pol1".to_string()],
            )
            .unwrap();

        let dirs: Vec<i32> = ptable.iter_assignments(1).map(|(dir, _)| dir).collect();
        assert_eq!(dirs, vec![1]);
    }
}
