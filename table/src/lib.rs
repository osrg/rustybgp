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
use once_cell::sync::Lazy;
use patricia_tree::PatriciaMap;
use regex::Regex;
use std::collections::{hash_map::Entry::Occupied, hash_map::Entry::Vacant};
use std::convert::{Into, TryFrom};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr};
use std::ops::AddAssign;
use std::str::FromStr;
use std::sync::Arc;
use std::time::SystemTime;

use bytes::BytesMut;
use rustybgp_packet::{self as packet, Attribute, Family, bgp};

#[derive(Debug, thiserror::Error)]
pub enum TableError {
    #[error("argument is incorrect")]
    InvalidArgument(String),
    #[error("entity already exists")]
    AlreadyExists(String),
}

#[derive(Clone, Copy, PartialEq)]
pub enum RpkiValidationState {
    NotFound,
    Valid,
    Invalid,
}

pub enum RpkiValidationReason {
    None,
    Asn,
    Length,
}

#[derive(Clone, Copy, PartialEq)]
pub enum TableType {
    Global,
    AdjIn,
    AdjOut,
}

pub struct DestinationEntry {
    pub net: packet::Nlri,
    pub paths: Vec<PathEntry>,
}

pub struct PathEntry {
    pub id: u32,
    pub timestamp: SystemTime,
    pub attr: Arc<Vec<packet::Attribute>>,
    pub validation: Option<RpkiValidation>,
}

pub struct RpkiValidation {
    pub state: RpkiValidationState,
    pub reason: RpkiValidationReason,
    pub matched: Vec<(packet::IpNet, Roa)>,
    pub unmatched_asn: Vec<(packet::IpNet, Roa)>,
    pub unmatched_length: Vec<(packet::IpNet, Roa)>,
}

struct PathAttribute {
    attr: Arc<Vec<Attribute>>,
}

impl PathAttribute {
    fn new(attr: Arc<Vec<packet::Attribute>>) -> Self {
        PathAttribute { attr }
    }

    fn attr_local_preference(&self) -> u32 {
        match self
            .attr
            .iter()
            .find(|a| a.code() == packet::Attribute::LOCAL_PREF)
        {
            Some(attr) => attr.value().unwrap(),
            None => packet::Attribute::DEFAULT_LOCAL_PREF,
        }
    }

    fn attr_origin(&self) -> u8 {
        match self
            .attr
            .iter()
            .find(|a| a.code() == packet::Attribute::ORIGIN)
        {
            Some(attr) => attr.value().unwrap() as u8,
            None => packet::Attribute::ORIGIN_INCOMPLETE,
        }
    }

    #[allow(dead_code)]
    fn attr_med(&self) -> u32 {
        match self
            .attr
            .iter()
            .find(|a| a.code() == packet::Attribute::MULTI_EXIT_DESC)
        {
            Some(attr) => attr.value().unwrap(),
            None => 0,
        }
    }

    fn attr_originator_id(&self) -> Option<u32> {
        self.attr
            .iter()
            .find(|a| a.code() == packet::Attribute::ORIGINATOR_ID)
            .map(|attr| attr.value().unwrap())
    }

    fn attr_as_path_length(&self) -> usize {
        match self
            .attr
            .iter()
            .find(|a| a.code() == packet::Attribute::AS_PATH)
        {
            Some(attr) => attr.as_path_length(),
            None => 0,
        }
    }
}

struct Path {
    source: Arc<Source>,
    id: u32,
    pa: PathAttribute,
    timestamp: SystemTime,
    flags: u8,
}

impl Path {
    const FLAG_FILTERED: u8 = 1 << 0;

    fn is_filtered(&self) -> bool {
        self.flags & Path::FLAG_FILTERED != 0
    }
}

struct Destination {
    entry: Vec<Path>,
}

impl Destination {
    fn new() -> Self {
        Destination { entry: Vec::new() }
    }
}

#[derive(Default, Clone, Debug)]
pub struct RoutingTableState {
    pub num_destination: usize,
    pub num_path: usize,
    pub num_accepted: usize,
}

impl AddAssign for RoutingTableState {
    fn add_assign(&mut self, other: Self) {
        *self = Self {
            num_destination: self.num_destination + other.num_destination,
            num_path: self.num_path + other.num_path,
            num_accepted: self.num_accepted + other.num_accepted,
        }
    }
}

pub struct Reach {
    pub source: Arc<Source>,
    pub family: Family,
    pub net: packet::PathNlri,
    pub attr: Arc<Vec<packet::Attribute>>,
}

impl From<Reach> for bgp::Message {
    fn from(c: Reach) -> bgp::Message {
        bgp::Message::Update(bgp::Update {
            reach: Some(packet::bgp::NlriSet {
                family: c.family,
                entries: vec![c.net],
            }),
            mp_reach: None,
            attr: c.attr,
            unreach: None,
            mp_unreach: None,
        })
    }
}

#[derive(Clone)]
pub struct Change {
    pub source: Arc<Source>,
    pub family: Family,
    pub net: packet::Nlri,
    pub attr: Arc<Vec<packet::Attribute>>,
}

impl From<Change> for bgp::Message {
    fn from(c: Change) -> bgp::Message {
        // Extended nexthop (RFC 8950) reach/mp_reach routing is handled
        // at the daemon tx path, not in this conversion.
        bgp::Message::Update(bgp::Update {
            reach: Some(packet::bgp::NlriSet {
                family: c.family,
                entries: vec![packet::bgp::PathNlri::new(c.net)],
            }),
            mp_reach: None,
            attr: c.attr,
            unreach: None,
            mp_unreach: None,
        })
    }
}

#[derive(PartialEq)]
enum PeerType {
    Ibgp,
    Ebgp,
}

pub struct Source {
    pub remote_addr: IpAddr,
    pub local_addr: IpAddr,
    pub remote_asn: u32,
    pub local_asn: u32,
    pub router_id: u32,
    pub uptime: u64,
    rs_client: bool,
}

impl Hash for Source {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.remote_addr.hash(state);
    }
}

impl Source {
    pub fn new(
        remote_addr: IpAddr,
        local_addr: IpAddr,
        remote_asn: u32,
        local_asn: u32,
        router_id: Ipv4Addr,
        uptime: u64,
        rs_client: bool,
    ) -> Self {
        Source {
            remote_addr,
            local_addr,
            remote_asn,
            local_asn,
            router_id: router_id.into(),
            uptime,
            rs_client,
        }
    }

    fn peer_type(&self) -> PeerType {
        if self.remote_asn == self.local_asn {
            PeerType::Ibgp
        } else {
            PeerType::Ebgp
        }
    }
}

pub struct RoutingTable {
    global: FnvHashMap<Family, FnvHashMap<packet::Nlri, Destination>>,
    route_stats: FnvHashMap<IpAddr, FnvHashMap<Family, (u64, u64)>>,
    rpki: RpkiTable,
}

impl Default for RoutingTable {
    fn default() -> Self {
        Self::new()
    }
}

impl RoutingTable {
    pub fn new() -> Self {
        RoutingTable {
            global: vec![(Family::EMPTY, FnvHashMap::default())]
                .into_iter()
                .collect(),
            route_stats: FnvHashMap::default(),
            rpki: RpkiTable::new(),
        }
    }

    pub fn best(&self, family: &Family) -> Vec<Change> {
        match self.global.get(family) {
            Some(t) => {
                let mut v = Vec::with_capacity(t.len());
                for (n, dst) in t {
                    let r = &dst.entry[0];
                    v.push(Change {
                        source: r.source.clone(),
                        family: *family,
                        net: *n,
                        attr: r.pa.attr.clone(),
                    });
                }
                v
            }
            None => Vec::new(),
        }
    }

    pub fn state(&self, family: Family) -> RoutingTableState {
        match self.global.get(&family) {
            Some(t) => {
                let num_path = t.values().flat_map(|x| x.entry.iter()).count();
                RoutingTableState {
                    num_destination: t.len(),
                    num_path,
                    num_accepted: num_path,
                }
            }

            None => RoutingTableState::default(),
        }
    }

    pub fn peer_stats(
        &self,
        peer_addr: &IpAddr,
    ) -> Option<impl Iterator<Item = (Family, (u64, u64))> + '_> {
        self.route_stats
            .get(peer_addr)
            .map(|m| m.iter().map(|(x, y)| (*x, *y)))
    }

    pub fn iter_reach(&self, family: Family) -> impl Iterator<Item = Reach> + '_ {
        self.global
            .get(&family)
            .unwrap_or_else(|| self.global.get(&Family::EMPTY).unwrap())
            .iter()
            .flat_map(move |(net, dst)| {
                dst.entry.iter().map(move |e| Reach {
                    source: e.source.clone(),
                    family,
                    net: packet::bgp::PathNlri {
                        nlri: *net,
                        path_id: e.id,
                    },
                    attr: e.pa.attr.clone(),
                })
            })
    }

    pub fn iter_destinations(
        &self,
        table_type: TableType,
        family: Family,
        peer_addr: Option<IpAddr>,
        prefixes: Vec<packet::Nlri>,
        export_policy: Option<Arc<PolicyAssignment>>,
    ) -> impl Iterator<Item = DestinationEntry> + '_ {
        self.global
            .get(&family)
            .unwrap_or_else(|| self.global.get(&Family::EMPTY).unwrap())
            .iter()
            .filter(move |(net, _dst)| {
                prefixes.is_empty() || {
                    let mut found = false;
                    for prefix in &prefixes {
                        if *net == prefix {
                            found = true;
                            break;
                        }
                    }
                    found
                }
            })
            .map(move |(net, dst)| DestinationEntry {
                net: *net,
                paths: dst
                    .entry
                    .iter()
                    .enumerate()
                    .filter(|(i, p)| {
                        if table_type == TableType::AdjIn {
                            return p.source.remote_addr == peer_addr.unwrap();
                        } else if table_type == TableType::AdjOut {
                            return *i == 0 && p.source.remote_addr != peer_addr.unwrap();
                        }
                        true
                    })
                    .filter_map(|(_, p)| {
                        if table_type == TableType::AdjOut {
                            let codec = bgp::PeerCodecBuilder::new()
                                .local_asn(p.source.local_asn)
                                .local_addr(p.source.local_addr)
                                .keep_aspath(p.source.rs_client)
                                .keep_nexthop(p.source.rs_client)
                                .build();
                            let attr = Arc::new(
                                p.pa.attr
                                    .iter()
                                    .cloned()
                                    .map(|a| {
                                        let (_, m) = a.export(
                                            a.code(),
                                            None::<&mut BytesMut>,
                                            family,
                                            &codec,
                                        );
                                        if let Some(m) = m { m } else { a }
                                    })
                                    .collect::<Vec<packet::Attribute>>(),
                            );
                            if let Some(pa) = &export_policy {
                                if self.apply_policy(pa, &p.source, net, &attr)
                                    == Disposition::Reject
                                {
                                    None
                                } else {
                                    Some((p, attr))
                                }
                            } else {
                                Some((p, attr))
                            }
                        } else {
                            Some((p, p.pa.attr.clone()))
                        }
                    })
                    .map(|(p, attr)| {
                        let validation = self.rpki.validate(family, &p.source, net, &attr);
                        PathEntry {
                            id: if table_type == TableType::AdjOut {
                                0
                            } else {
                                p.id
                            },
                            timestamp: p.timestamp,
                            attr,
                            validation,
                        }
                    })
                    .collect(),
            })
            .filter(|d| !d.paths.is_empty())
    }

    pub fn insert(
        &mut self,
        source: Arc<Source>,
        family: Family,
        net: packet::Nlri,
        remote_id: u32,
        attr: Arc<Vec<packet::Attribute>>,
        filtered: bool,
    ) -> Option<Change> {
        let mut replaced = false;
        let mut best_changed = false;
        let flags = if filtered { Path::FLAG_FILTERED } else { 0 };
        let mut old_filtered = false;

        let path = Path {
            source: source.clone(),
            id: remote_id,
            pa: PathAttribute::new(attr),
            timestamp: SystemTime::now(),
            flags,
        };

        let rt = self.global.entry(family).or_default();
        let dst = rt.entry(net).or_insert_with(Destination::new);
        for i in 0..dst.entry.len() {
            if Arc::ptr_eq(&dst.entry[i].source, &source) && dst.entry[i].id == remote_id {
                replaced = true;
                old_filtered = dst.entry.remove(i).is_filtered();
                best_changed = i == 0;
                break;
            }
        }
        let (received, accepted) = self
            .route_stats
            .entry(source.remote_addr)
            .or_default()
            .entry(family)
            .or_insert((0, 0));
        if replaced {
            if old_filtered && !filtered {
                *accepted += 1;
            }
            if !old_filtered && filtered {
                *accepted -= 1;
            }
        } else {
            *received += 1;
            if !filtered {
                *accepted += 1;
            }
        }

        let mut idx = 0;
        for _ in 0..dst.entry.len() {
            let a = &dst.entry[idx];

            // local prefecence
            if path.pa.attr_local_preference() > a.pa.attr_local_preference() {
                break;
            }

            if path.pa.attr_as_path_length() < a.pa.attr_as_path_length() {
                break;
            }

            if path.pa.attr_origin() < a.pa.attr_origin() {
                break;
            }

            // external prefer
            if path.source.peer_type() == PeerType::Ebgp && a.source.peer_type() == PeerType::Ibgp {
                break;
            }

            let f = |p: &Path| match p.pa.attr_originator_id() {
                Some(v) => v,
                None => p.source.router_id,
            };
            if f(&path) < f(a) {
                break;
            }

            idx += 1;
        }

        dst.entry.insert(idx, path);
        for i in 0..dst.entry.len() {
            if !dst.entry[i].is_filtered() {
                if idx == i {
                    best_changed = true;
                }
                break;
            }
        }

        if best_changed {
            let best = &dst.entry[0];
            return Some(Change {
                source: best.source.clone(),
                family,
                net,
                attr: best.pa.attr.clone(),
            });
        }
        None
    }

    pub fn remove(
        &mut self,
        source: Arc<Source>,
        family: Family,
        net: packet::Nlri,
        remote_id: u32,
    ) -> Option<Change> {
        let rt = self.global.get_mut(&family)?;
        let dst = rt.get_mut(&net)?;
        let mut was_best = true;
        for i in 0..dst.entry.len() {
            if Arc::ptr_eq(&dst.entry[i].source, &source) && dst.entry[i].id == remote_id {
                let (received, accepted) = self
                    .route_stats
                    .get_mut(&source.remote_addr)
                    .unwrap()
                    .get_mut(&family)
                    .unwrap();
                *received -= 1;
                if !dst.entry.remove(i).is_filtered() {
                    *accepted -= 1;
                }

                if dst.entry.is_empty() {
                    rt.remove(&net);
                    // withdraw
                    return Some(Change {
                        source: source.clone(),
                        family,
                        net,
                        attr: Arc::new(Vec::new()),
                    });
                }
                if was_best {
                    let best = &dst.entry[0];
                    return Some(Change {
                        source: best.source.clone(),
                        family,
                        net,
                        attr: best.pa.attr.clone(),
                    });
                }
                break;
            }
            if was_best && !dst.entry[i].is_filtered() {
                was_best = false;
            }
        }
        None
    }

    pub fn drop(&mut self, source: Arc<Source>) -> Vec<Change> {
        let mut advertise = Vec::new();
        self.route_stats.remove(&source.remote_addr);
        for (family, rt) in self.global.iter_mut() {
            rt.retain(|net, dst| {
                for i in 0..dst.entry.len() {
                    let e = &dst.entry[i];
                    if Arc::ptr_eq(&e.source, &source) {
                        dst.entry.remove(i);
                        if i == 0 && !dst.entry.is_empty() {
                            let best = &dst.entry[0];
                            advertise.push(Change {
                                source: best.source.clone(),
                                family: *family,
                                net: *net,
                                attr: best.pa.attr.clone(),
                            });
                        }
                        break;
                    }
                }
                if dst.entry.is_empty() {
                    advertise.push(Change {
                        source: source.clone(),
                        family: *family,
                        net: *net,
                        attr: Arc::new(Vec::new()),
                    });
                }
                !dst.entry.is_empty()
            });
        }
        advertise
    }

    pub fn iter_roa(&self, family: Family) -> impl Iterator<Item = (packet::IpNet, &Roa)> + '_ {
        self.rpki
            .roas
            .get(&family)
            .unwrap()
            .iter()
            .flat_map(|(n, e)| {
                let net = RpkiTable::key_to_addr(n);
                e.iter().map(move |r| (net.clone(), r.as_ref()))
            })
    }

    pub fn rpki_state(&self, addr: &IpAddr) -> RpkiTableState {
        let mut state = RpkiTableState::default();
        for (family, roas) in self.rpki.roas.iter() {
            let mut records = 0;
            let mut prefixes = 0;
            for (_, e) in roas.iter() {
                for r in e {
                    if &*r.source == addr {
                        prefixes += 1;
                    }
                }
                if prefixes != 0 {
                    records += 1;
                }
            }
            match *family {
                Family::IPV4 => {
                    state.num_records_v4 += records;
                    state.num_prefixes_v4 += prefixes;
                }
                Family::IPV6 => {
                    state.num_records_v6 += records;
                    state.num_prefixes_v6 += prefixes;
                }
                _ => {}
            }
        }
        state
    }
    pub fn rpki_drop(&mut self, source: Arc<IpAddr>) {
        for (_, roa) in self.rpki.roas.iter_mut() {
            let mut empty = Vec::new();
            for (n, e) in roa.iter_mut() {
                let mut i = 0;
                while i != e.len() {
                    if Arc::ptr_eq(&e[i].source, &source) {
                        e.remove(i);
                    } else {
                        i += 1;
                    }
                }
                if e.is_empty() {
                    empty.push(n);
                }
            }
            for n in empty {
                roa.remove(n);
            }
        }
    }

    pub fn roa_insert(&mut self, net: packet::IpNet, roa: Arc<Roa>) {
        let (family, mut key, mask) = match net {
            packet::IpNet::V4(net) => (Family::IPV4, net.addr.octets().to_vec(), net.mask),
            packet::IpNet::V6(net) => (Family::IPV6, net.addr.octets().to_vec(), net.mask),
        };
        key.push(mask);
        match self.rpki.roas.get_mut(&family).unwrap().get_mut(&key) {
            Some(entry) => {
                for e in entry.iter() {
                    if Arc::ptr_eq(&e.source, &roa.source)
                        && e.max_length == roa.max_length
                        && e.as_number == roa.as_number
                    {
                        return;
                    }
                }
                entry.push(roa);
            }
            None => {
                self.rpki
                    .roas
                    .get_mut(&family)
                    .unwrap()
                    .insert(key, vec![roa]);
            }
        }
    }

    pub fn apply_policy(
        &self,
        assignment: &PolicyAssignment,
        source: &Arc<Source>,
        net: &packet::Nlri,
        attr: &Arc<Vec<packet::Attribute>>,
    ) -> Disposition {
        assignment.apply(&self.rpki, source, net, attr)
    }
}

#[test]
fn drop() {
    let s1 = Arc::new(Source::new(
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 2)),
        1,
        2,
        Ipv4Addr::new(1, 1, 1, 1),
        0,
        false,
    ));
    let s2 = Arc::new(Source::new(
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 2)),
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 2)),
        1,
        2,
        Ipv4Addr::new(1, 1, 1, 2),
        0,
        false,
    ));

    let n1 = packet::Nlri::V4(packet::bgp::Ipv4Net {
        addr: Ipv4Addr::new(1, 0, 0, 0),
        mask: 24,
    });
    let n2 = packet::Nlri::V4(packet::bgp::Ipv4Net {
        addr: Ipv4Addr::new(2, 0, 0, 0),
        mask: 24,
    });
    let n3 = packet::Nlri::V4(packet::bgp::Ipv4Net {
        addr: Ipv4Addr::new(3, 0, 0, 0),
        mask: 24,
    });

    let mut rt = RoutingTable::new();
    let family = Family::IPV4;
    let attrs = Arc::new(Vec::new());

    rt.insert(s1.clone(), family, n1, 0, attrs.clone(), false);
    rt.insert(s2, family, n1, 0, attrs.clone(), false);
    rt.insert(s1.clone(), family, n2, 0, attrs.clone(), false);
    rt.insert(s1.clone(), family, n3, 0, attrs.clone(), false);

    assert_eq!(rt.global.get(&family).unwrap().len(), 3);
    rt.drop(s1);
    assert_eq!(rt.global.get(&family).unwrap().len(), 1);
}

#[derive(Clone)]
pub struct Prefix {
    pub net: packet::IpNet,
    pub min_length: u8,
    pub max_length: u8,
}

type SingleMatchRegex = (Regex, fn(s: &regex::Captures) -> Option<SingleAsPathMatch>);

static SINGLE_MATCH_REGEX: Lazy<Vec<SingleMatchRegex>> = Lazy::new(|| {
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
    fn new(s: &str) -> Option<Self> {
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

#[test]
fn single_aspath_match() {
    assert_eq!(
        SingleAsPathMatch::LeftMost(65100),
        SingleAsPathMatch::new("^65100_").unwrap()
    );
    assert_eq!(
        SingleAsPathMatch::Origin(65100),
        SingleAsPathMatch::new("_65100$").unwrap()
    );
    assert_eq!(
        SingleAsPathMatch::Include(65100),
        SingleAsPathMatch::new("_65100_").unwrap()
    );
    assert_eq!(
        SingleAsPathMatch::Only(65100),
        SingleAsPathMatch::new("^65100$").unwrap(),
    );
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
    // ExtendedCommunity,
    AsPathLength(Comparison, u32),
    Rpki(RpkiValidationState),
    // RouteType(u32),
    // LargeCommunity,
    // AfiSafiIn(Vec<bgp::Family>),
}

impl Condition {
    fn evalute(
        &self,
        source: &Arc<Source>,
        net: &packet::Nlri,
        attr: &Arc<Vec<packet::Attribute>>,
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
                            && p.max_length <= n.mask
                        {
                            return *opt == MatchOption::Any;
                        }
                        return !(*opt == MatchOption::Any);
                    }
                    packet::Nlri::V6(_) => {}
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
                    if n.contains(&source.remote_addr) {
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
            Condition::Rpki(_) => {
                return false;
            }
            _ => {}
        }
        false
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

#[derive(Clone)]
pub struct Statement {
    pub name: Arc<str>,
    // ALL the conditions are matched, the action will be executed.
    pub conditions: Vec<Condition>,
    pub disposition: Option<Disposition>,
    // pub route_action: Action,
}

impl Statement {
    fn apply(
        &self,
        source: &Arc<Source>,
        net: &packet::Nlri,
        attr: &Arc<Vec<packet::Attribute>>,
    ) -> Disposition {
        let mut result = true;
        // if any in the conditions returns false, this statement becomes false.
        for condition in &self.conditions {
            if !condition.evalute(source, net, attr) {
                result = false;
                break;
            }
        }

        if result && let Some(disposition) = &self.disposition {
            return *disposition;
        }
        Disposition::Pass
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
}

pub enum ConditionConfig {
    PrefixSet(String, MatchOption),
    NeighborSet(String, MatchOption),
    AsPathSet(String, MatchOption),
    CommunitySet(String, MatchOption),
    AsPathLength(Comparison, u32),
    Nexthop(Vec<IpAddr>),
    Rpki(RpkiValidationState),
}

pub enum DefinedSetRef<'a> {
    Prefix(&'a str, &'a PrefixSet),
    Neighbor(&'a str, &'a NeighborSet),
    AsPath(&'a str, &'a AsPathSet),
    Community(&'a str, &'a CommunitySet),
}

pub struct PrefixSet {
    pub v4: IpLookupTable<Ipv4Addr, Prefix>,
    pub zero: Option<(u8, u8)>,
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

#[derive(Clone)]
pub struct Policy {
    pub name: Arc<str>,
    pub statements: Vec<Arc<Statement>>,
}

impl Policy {
    fn apply(
        &self,
        source: &Arc<Source>,
        net: &packet::Nlri,
        attr: &Arc<Vec<packet::Attribute>>,
    ) -> Disposition {
        for statement in &self.statements {
            let r = statement.apply(source, net, attr);
            if r != Disposition::Pass {
                return r;
            }
        }
        Disposition::Pass
    }
}

pub struct PolicyAssignment {
    pub name: Arc<str>,
    pub disposition: Disposition,
    pub policies: Vec<Arc<Policy>>,
}

impl PolicyAssignment {
    fn apply(
        &self,
        _rpki: &RpkiTable,
        source: &Arc<Source>,
        net: &packet::Nlri,
        attr: &Arc<Vec<packet::Attribute>>,
    ) -> Disposition {
        for policy in &self.policies {
            let r = policy.apply(source, net, attr);
            if r != Disposition::Pass {
                return r;
            }
        }
        self.disposition
    }
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

    statements: FnvHashMap<Arc<str>, Arc<Statement>>,
    policies: FnvHashMap<Arc<str>, Arc<Policy>>,

    assignment_import: Option<Arc<PolicyAssignment>>,
    assignment_export: Option<Arc<PolicyAssignment>>,
}

impl PolicyTable {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn add_assignment(
        &mut self,
        name: &str,
        direction: PolicyDirection,
        default_action: Disposition,
        policy_names: Vec<String>,
    ) -> Result<(PolicyDirection, Arc<PolicyAssignment>), TableError> {
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

        let m = match direction {
            PolicyDirection::Import => &mut self.assignment_import,
            PolicyDirection::Export => &mut self.assignment_export,
        };

        let name: Arc<str> = Arc::from(name);
        if let Some(old) = m.take() {
            for p0 in &old.policies {
                if let Some(p) = v.iter().find(|p1| p0.name == p1.name) {
                    return Err(TableError::InvalidArgument(format!(
                        "{} policy already exists",
                        p.name
                    )));
                }
            }
            v.append(&mut old.policies.to_owned());
        }
        let n = Arc::new(PolicyAssignment {
            name,
            policies: v,
            disposition: default_action,
        });
        m.replace(n.clone());
        Ok((direction, n))
    }

    pub fn iter_assignments(
        &self,
        direction: i32,
    ) -> impl Iterator<Item = (i32, &PolicyAssignment)> + '_ {
        let mut v: Vec<(i32, &PolicyAssignment)> = Vec::with_capacity(2);
        if direction != 2 {
            if let Some(a) = self.assignment_import.as_ref() {
                v.push((1, a));
            }
        } else if direction != 1
            && let Some(a) = self.assignment_export.as_ref()
        {
            v.push((2, a));
        }
        v.into_iter()
    }

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
        let name: Arc<str> = Arc::from(name);
        match self.policies.entry(name.clone()) {
            Occupied(_) => Err(TableError::AlreadyExists(format!("{}", name))),
            Vacant(e) => {
                e.insert(Arc::new(Policy {
                    name,
                    statements: v,
                }));
                Ok(())
            }
        }
    }

    pub fn add_defined_set(&mut self, set: DefinedSetConfig) -> Result<(), TableError> {
        match set {
            DefinedSetConfig::Prefix { name, prefixes } => {
                let arc_name: Arc<str> = Arc::from(name.as_str());
                if let Vacant(e) = self.prefix_sets.entry(arc_name.clone()) {
                    let mut zero = None;
                    let mut v = IpLookupTable::new();
                    for p in &prefixes {
                        match packet::IpNet::from_str(&p.ip_prefix) {
                            Ok(n) => {
                                let prefix = Prefix {
                                    net: n,
                                    min_length: p.mask_length_min,
                                    max_length: p.mask_length_max,
                                };

                                match &prefix.net {
                                    packet::IpNet::V4(net) => {
                                        if net.addr == Ipv4Addr::new(0, 0, 0, 0) && net.mask == 0 {
                                            zero = Some((prefix.min_length, prefix.max_length));
                                        } else {
                                            v.insert(net.addr, net.mask as u32, prefix);
                                        }
                                    }
                                    packet::IpNet::V6(_) => {}
                                }
                            }
                            Err(_) => {
                                return Err(TableError::InvalidArgument(format!(
                                    "invalid prefix format {:?}",
                                    p.ip_prefix
                                )));
                            }
                        }
                    }
                    if v.is_empty() && zero.is_none() {
                        return Err(TableError::InvalidArgument(
                            "empty prefix defined-type".to_string(),
                        ));
                    } else {
                        e.insert(Arc::new(PrefixSet { v4: v, zero }));
                        return Ok(());
                    }
                }
                Err(TableError::AlreadyExists(name))
            }
            DefinedSetConfig::Neighbor { name, neighbors } => {
                let arc_name: Arc<str> = Arc::from(name.as_str());
                let mut v = Vec::with_capacity(neighbors.len());
                for n in &neighbors {
                    match packet::IpNet::from_str(n) {
                        Ok(addr) => {
                            v.push(addr);
                        }
                        Err(_) => {
                            return Err(TableError::InvalidArgument(format!(
                                "invalid neighbor format {:?}",
                                n
                            )));
                        }
                    }
                }
                if v.is_empty() {
                    return Err(TableError::InvalidArgument(
                        "empty neighbor defined-type".to_string(),
                    ));
                } else if let Vacant(e) = self.neighbor_sets.entry(arc_name) {
                    e.insert(Arc::new(NeighborSet { sets: v }));
                    return Ok(());
                }
                Err(TableError::AlreadyExists(name))
            }
            DefinedSetConfig::AsPath { name, patterns } => {
                let arc_name: Arc<str> = Arc::from(name.as_str());
                let mut v0 = Vec::with_capacity(patterns.len());
                let mut v1 = Vec::with_capacity(patterns.len());
                for n in &patterns {
                    if let Some(n) = SingleAsPathMatch::new(n) {
                        v0.push(n);
                    } else if let Ok(n) = Regex::new(&n.replace('_', "(^|[,{}() ]|$)")) {
                        v1.push(n);
                    } else {
                        return Err(TableError::InvalidArgument(format!(
                            "invalid aspath format {:?}",
                            n
                        )));
                    }
                }
                if !v0.is_empty() || !v1.is_empty() {
                    if let Vacant(e) = self.aspath_sets.entry(arc_name) {
                        e.insert(Arc::new(AsPathSet {
                            single_sets: v0,
                            sets: v1,
                        }));
                        return Ok(());
                    }
                } else {
                    return Err(TableError::InvalidArgument(
                        "empty aspath defined-type".to_string(),
                    ));
                }
                Err(TableError::AlreadyExists(name))
            }
            DefinedSetConfig::Community { name, patterns } => {
                let arc_name: Arc<str> = Arc::from(name.as_str());
                let mut v = Vec::with_capacity(patterns.len());
                for n in &patterns {
                    if let Ok(n) = parse_community(n) {
                        v.push(n);
                    } else {
                        return Err(TableError::InvalidArgument(format!(
                            "invalid community format {:?}",
                            n
                        )));
                    }
                }
                if v.is_empty() {
                    return Err(TableError::InvalidArgument(
                        "empty community defined-type".to_string(),
                    ));
                } else if let Vacant(e) = self.community_sets.entry(arc_name) {
                    e.insert(Arc::new(CommunitySet { sets: v }));
                    return Ok(());
                }
                Err(TableError::AlreadyExists(name))
            }
        }
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
    }

    pub fn add_statement(
        &mut self,
        name: &str,
        conditions: Vec<ConditionConfig>,
        disposition: Option<Disposition>,
    ) -> Result<(), TableError> {
        if self.statements.contains_key(name) {
            return Err(TableError::AlreadyExists(name.to_string()));
        }
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
                ConditionConfig::AsPathLength(cmp, length) => {
                    v.push(Condition::AsPathLength(cmp, length));
                }
                ConditionConfig::Nexthop(nexthops) => {
                    v.push(Condition::Nexthop(nexthops));
                }
                ConditionConfig::Rpki(state) => {
                    v.push(Condition::Rpki(state));
                }
            }
        }
        let s = Statement {
            name: Arc::from(name),
            conditions: v,
            disposition,
        };
        self.statements.insert(s.name.clone(), Arc::new(s));
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
}

#[derive(Clone)]
pub struct Roa {
    pub max_length: u8,
    pub as_number: u32,
    pub source: Arc<IpAddr>,
}

impl Roa {
    pub fn new(max_length: u8, as_number: u32, source: Arc<IpAddr>) -> Self {
        Roa {
            max_length,
            as_number,
            source,
        }
    }
}

#[derive(Default)]
pub struct RpkiTableState {
    pub num_records_v4: u32,
    pub num_records_v6: u32,
    pub num_prefixes_v4: u32,
    pub num_prefixes_v6: u32,
}

#[derive(Default)]
pub struct RpkiTable {
    roas: FnvHashMap<Family, PatriciaMap<Vec<Arc<Roa>>>>,
}

impl RpkiTable {
    fn new() -> Self {
        let roas: FnvHashMap<Family, PatriciaMap<_>> = vec![
            (Family::IPV4, PatriciaMap::default()),
            (Family::IPV6, PatriciaMap::default()),
        ]
        .drain(..)
        .collect();
        RpkiTable { roas }
    }

    fn key_to_addr(mut key: Vec<u8>) -> packet::IpNet {
        let mask = key.pop().unwrap();
        let prefix = match key.len() {
            4 => {
                let mut octets = [0_u8; 4];
                octets.clone_from_slice(&key[..]);
                IpAddr::from(octets)
            }
            16 => {
                let mut octets = [0_u8; 16];
                octets.clone_from_slice(&key[..]);
                IpAddr::from(octets)
            }
            _ => panic!(""),
        };
        packet::IpNet::new(prefix, mask)
    }

    fn validate(
        &self,
        family: Family,
        source: &Arc<Source>,
        net: &packet::Nlri,
        attr: &Arc<Vec<packet::Attribute>>,
    ) -> Option<RpkiValidation> {
        match self.roas.get(&family) {
            None => None,
            Some(m) => {
                if m.is_empty() {
                    return None;
                }
                let mut result = RpkiValidation {
                    state: RpkiValidationState::NotFound,
                    reason: RpkiValidationReason::None,
                    matched: Vec::new(),
                    unmatched_asn: Vec::new(),
                    unmatched_length: Vec::new(),
                };
                let asn =
                    if let Some(a) = attr.iter().find(|a| a.code() == packet::Attribute::AS_PATH) {
                        match a.as_path_origin() {
                            Some(asn) => asn,
                            None => source.local_asn,
                        }
                    } else {
                        source.local_asn
                    };
                let (mut addr, mask) = match net {
                    packet::Nlri::V4(net) => (net.addr.octets().to_vec(), net.mask),
                    packet::Nlri::V6(net) => (net.addr.octets().to_vec(), net.mask),
                };
                addr.drain((mask.div_ceil(8)) as usize..);
                for (ipnet, entry) in m.iter_prefix(&addr) {
                    let ipnet = RpkiTable::key_to_addr(ipnet);
                    for roa in entry {
                        if mask <= roa.max_length {
                            if roa.as_number != 0 && roa.as_number == asn {
                                result.matched.push((ipnet.clone(), roa.as_ref().clone()));
                            } else {
                                result
                                    .unmatched_asn
                                    .push((ipnet.clone(), roa.as_ref().clone()));
                            }
                        } else {
                            result
                                .unmatched_length
                                .push((ipnet.clone(), roa.as_ref().clone()));
                        }
                    }
                }
                if !result.matched.is_empty() {
                    result.state = RpkiValidationState::Valid;
                } else if !result.unmatched_asn.is_empty() {
                    result.state = RpkiValidationState::Invalid;
                    result.reason = RpkiValidationReason::Asn;
                } else if !result.unmatched_length.is_empty() {
                    result.state = RpkiValidationState::Invalid;
                    result.reason = RpkiValidationReason::Length;
                }

                Some(result)
            }
        }
    }
}
