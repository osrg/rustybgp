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
use std::sync::LazyLock;
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
    /// Remote peer's inbound path ID (from the sending peer's Add-Path).
    id: u32,
    /// Stable outbound path ID assigned locally for Add-Path TX.
    local_path_id: u32,
    nexthop: bgp::Nexthop,
    pa: PathAttribute,
    timestamp: SystemTime,
    flags: u8,
}

impl Path {
    const FLAG_FILTERED: u8 = 1 << 0;

    fn is_filtered(&self) -> bool {
        self.flags & Path::FLAG_FILTERED != 0
    }

    fn originator_id(&self) -> u32 {
        self.pa
            .attr_originator_id()
            .unwrap_or(self.source.router_id)
    }
}

impl Ord for Path {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Higher LOCAL_PREF is better (reverse order)
        self.pa
            .attr_local_preference()
            .cmp(&other.pa.attr_local_preference())
            .reverse()
            // Shorter AS path is better
            .then_with(|| {
                self.pa
                    .attr_as_path_length()
                    .cmp(&other.pa.attr_as_path_length())
            })
            // Lower origin is better (IGP=0 < EGP=1 < Incomplete=2)
            .then_with(|| self.pa.attr_origin().cmp(&other.pa.attr_origin()))
            // eBGP preferred over iBGP
            .then_with(|| self.source.peer_type().cmp(&other.source.peer_type()))
            // Lower originator ID / router ID is better
            .then_with(|| self.originator_id().cmp(&other.originator_id()))
    }
}

impl PartialOrd for Path {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Path {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == std::cmp::Ordering::Equal
    }
}

impl Eq for Path {}

/// Maximum number of paths stored per prefix per destination.
/// Limits memory usage when Add-Path peers advertise many path IDs.
const MAX_PATHS_PER_DESTINATION: usize = 32;

struct Destination {
    entry: Vec<Path>,
    next_path_id: u32,
}

impl Destination {
    fn new() -> Self {
        Destination {
            entry: Vec::new(),
            next_path_id: 1,
        }
    }

    fn alloc_path_id(&mut self) -> u32 {
        if self.entry.is_empty() {
            // Fast path: when there are no active paths, just reset to 1.
            self.next_path_id = 1;
        }

        loop {
            let id = self.next_path_id;
            // Advance and maintain the original wrap/skip-0 behavior.
            self.next_path_id = self.next_path_id.wrapping_add(1);
            if self.next_path_id == 0 {
                self.next_path_id = 1;
            }

            // Ensure we do not reuse an ID that is still in use by an active path.
            if !self.entry.iter().any(|p| p.local_path_id == id) {
                return id;
            }
        }
    }

    fn unfiltered_best(&self) -> Option<&Path> {
        self.entry.iter().find(|p| !p.is_filtered())
    }

    fn unfiltered_all(&self) -> Vec<&Path> {
        self.entry.iter().filter(|p| !p.is_filtered()).collect()
    }
}

/// Snapshot of a path in the top-N used for diffing before/after mutations.
struct TopNEntry {
    source: Arc<Source>,
    nexthop: bgp::Nexthop,
    attr: Arc<Vec<packet::Attribute>>,
    local_path_id: u32,
}

fn same_top_entry(a: &TopNEntry, b: &Path) -> bool {
    (Arc::ptr_eq(&a.source, &b.source) && Arc::ptr_eq(&a.attr, &b.pa.attr))
        || (Arc::ptr_eq(&a.source, &b.source) && a.attr.as_ref() == b.pa.attr.as_ref())
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
            nexthop: None,
        })
    }
}

#[derive(Clone)]
pub struct Change {
    pub source: Arc<Source>,
    pub family: Family,
    pub net: packet::Nlri,
    pub nexthop: bgp::Nexthop,
    pub attr: Arc<Vec<packet::Attribute>>,
    /// Stable per-path identifier for Add-Path TX. 0 when Add-Path is not used.
    pub path_id: u32,
    /// 1-based rank within the top-N (1 = best). Peers use this to filter
    /// changes that exceed their effective send_max.
    pub rank: usize,
    /// Previous 1-based rank before this change (0 = path was not previously present).
    pub old_rank: usize,
}

impl From<Change> for bgp::Message {
    fn from(c: Change) -> bgp::Message {
        // Extended nexthop (RFC 8950) reach/mp_reach routing is handled
        // at the daemon tx path, not in this conversion.
        bgp::Message::Update(bgp::Update {
            reach: Some(packet::bgp::NlriSet {
                family: c.family,
                entries: vec![packet::bgp::PathNlri {
                    nlri: c.net,
                    path_id: c.path_id,
                }],
            }),
            mp_reach: None,
            attr: c.attr,
            unreach: None,
            mp_unreach: None,
            nexthop: None,
        })
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum PeerType {
    Ebgp,
    Ibgp,
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
    /// Per-peer per-family maximum prefix limits.
    prefix_limits: FnvHashMap<IpAddr, FnvHashMap<Family, u32>>,
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
            prefix_limits: FnvHashMap::default(),
            rpki: RpkiTable::new(),
        }
    }

    pub fn set_prefix_limit(&mut self, peer: IpAddr, family: Family, max: u32) {
        self.prefix_limits
            .entry(peer)
            .or_default()
            .insert(family, max);
    }

    pub fn remove_prefix_limits(&mut self, peer: &IpAddr) {
        self.prefix_limits.remove(peer);
    }

    pub fn best(&self, family: &Family) -> Vec<Change> {
        match self.global.get(family) {
            Some(t) => {
                let mut v = Vec::with_capacity(t.len());
                for (net, dst) in t {
                    for (i, p) in dst.unfiltered_all().iter().enumerate() {
                        v.push(Change {
                            source: p.source.clone(),
                            family: *family,
                            net: *net,
                            nexthop: p.nexthop,
                            attr: p.pa.attr.clone(),
                            path_id: p.local_path_id,
                            rank: i + 1,
                            old_rank: 0,
                        });
                    }
                }
                v
            }
            None => Vec::new(),
        }
    }

    pub fn state(&self, family: Family) -> RoutingTableState {
        match self.global.get(&family) {
            Some(t) => {
                let entries = t.values().flat_map(|x| x.entry.iter());
                let mut num_path = 0;
                let mut num_accepted = 0;
                for p in entries {
                    num_path += 1;
                    if !p.is_filtered() {
                        num_accepted += 1;
                    }
                }
                RoutingTableState {
                    num_destination: t.len(),
                    num_path,
                    num_accepted,
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
                paths: {
                    let best = dst.unfiltered_best().map(|p| p as *const Path);
                    dst.entry
                        .iter()
                        .enumerate()
                        .filter(|(_, p)| {
                            if table_type == TableType::AdjIn {
                                return p.source.remote_addr == peer_addr.unwrap();
                            } else if table_type == TableType::AdjOut {
                                return best == Some(*p as *const Path)
                                    && p.source.remote_addr != peer_addr.unwrap();
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
                                    let mut nh = p.nexthop;
                                    if self.apply_policy(
                                        pa,
                                        &p.source,
                                        net,
                                        &attr,
                                        &mut nh,
                                        p.source.local_addr,
                                    ) == Disposition::Reject
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
                        .collect()
                },
            })
            .filter(|d| !d.paths.is_empty())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert(
        &mut self,
        source: Arc<Source>,
        family: Family,
        net: packet::Nlri,
        remote_id: u32,
        nexthop: bgp::Nexthop,
        attr: Arc<Vec<packet::Attribute>>,
        filtered: bool,
    ) -> Vec<Change> {
        // Enforce per-peer per-family prefix limit
        if let Some(limit) = self
            .prefix_limits
            .get(&source.remote_addr)
            .and_then(|m| m.get(&family))
        {
            let received = self
                .route_stats
                .get(&source.remote_addr)
                .and_then(|m| m.get(&family))
                .map_or(0, |(r, _)| *r);
            if received >= *limit as u64 {
                // Still count as received so the stat reflects wire traffic
                let (rx, _) = self
                    .route_stats
                    .entry(source.remote_addr)
                    .or_default()
                    .entry(family)
                    .or_insert((0, 0));
                *rx += 1;
                eprintln!(
                    "prefix limit ({}) reached for peer {} family {:?}, dropping route",
                    limit, source.remote_addr, family
                );
                return Vec::new();
            }
        }

        let mut replaced = None;
        let flags = if filtered { Path::FLAG_FILTERED } else { 0 };

        let rt = self.global.entry(family).or_default();
        let dst = rt.entry(net).or_insert_with(Destination::new);

        // Snapshot all unfiltered paths before modification
        let old_top: Vec<TopNEntry> = dst
            .unfiltered_all()
            .iter()
            .map(|p| TopNEntry {
                source: p.source.clone(),
                nexthop: p.nexthop,
                attr: p.pa.attr.clone(),
                local_path_id: p.local_path_id,
            })
            .collect();

        for i in 0..dst.entry.len() {
            if Arc::ptr_eq(&dst.entry[i].source, &source) && dst.entry[i].id == remote_id {
                replaced = Some(dst.entry.remove(i));
                break;
            }
        }

        // Reject new paths (not replacements) when the per-prefix limit is reached.
        // Check before allocating a path ID to avoid wasting IDs on dropped paths.
        if replaced.is_none() && dst.entry.len() >= MAX_PATHS_PER_DESTINATION {
            // Still count the route as received so stats reflect actual wire traffic.
            let (received, _accepted) = self
                .route_stats
                .entry(source.remote_addr)
                .or_default()
                .entry(family)
                .or_insert((0, 0));
            *received += 1;
            eprintln!(
                "add-path: per-prefix path limit ({}) reached for {:?}, dropping path from {}",
                MAX_PATHS_PER_DESTINATION, net, source.remote_addr
            );
            return Vec::new();
        }

        // Reuse the old stable path ID on replacement; allocate a new one otherwise.
        let local_path_id = if let Some(ref old) = replaced {
            old.local_path_id
        } else {
            dst.alloc_path_id()
        };

        let path = Path {
            source: source.clone(),
            id: remote_id,
            local_path_id,
            nexthop,
            pa: PathAttribute::new(attr),
            timestamp: SystemTime::now(),
            flags,
        };

        let (received, accepted) = self
            .route_stats
            .entry(source.remote_addr)
            .or_default()
            .entry(family)
            .or_insert((0, 0));

        if let Some(ref old) = replaced {
            match (old.is_filtered(), filtered) {
                (true, false) => *accepted += 1,
                (false, true) => *accepted -= 1,
                _ => {}
            }
        } else {
            *received += 1;
            if !filtered {
                *accepted += 1;
            }
        }

        let idx = dst.entry.partition_point(|a| path.cmp(a).is_ge());
        dst.entry.insert(idx, path);

        // Compare old vs new unfiltered paths and emit changes for each affected rank
        Self::diff_top_n(dst, &old_top, family, net)
    }

    pub fn remove(
        &mut self,
        source: Arc<Source>,
        family: Family,
        net: packet::Nlri,
        remote_id: u32,
    ) -> Vec<Change> {
        let Some(rt) = self.global.get_mut(&family) else {
            return Vec::new();
        };
        let Some(dst) = rt.get_mut(&net) else {
            return Vec::new();
        };

        let Some(i) = dst
            .entry
            .iter()
            .position(|e| Arc::ptr_eq(&e.source, &source) && e.id == remote_id)
        else {
            return Vec::new();
        };

        // Snapshot all unfiltered paths before removal
        let old_top: Vec<TopNEntry> = dst
            .unfiltered_all()
            .iter()
            .map(|p| TopNEntry {
                source: p.source.clone(),
                nexthop: p.nexthop,
                attr: p.pa.attr.clone(),
                local_path_id: p.local_path_id,
            })
            .collect();

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
            // Withdraw all previously-advertised paths using their stable IDs
            return old_top
                .iter()
                .enumerate()
                .map(|(i, e)| Change {
                    source: e.source.clone(),
                    family,
                    net,
                    nexthop: e.nexthop,
                    attr: Arc::new(Vec::new()),
                    path_id: e.local_path_id,
                    rank: i + 1,
                    old_rank: i + 1,
                })
                .collect();
        }

        Self::diff_top_n(dst, &old_top, family, net)
    }

    /// Compare old path snapshot against the current destination state and
    /// produce `Change` entries for paths that were added, removed, or modified.
    /// Uses stable `local_path_id` rather than positional rank.
    fn diff_top_n(
        dst: &Destination,
        old_top: &[TopNEntry],
        family: Family,
        net: packet::Nlri,
    ) -> Vec<Change> {
        let new_top = dst.unfiltered_all();
        let mut changes = Vec::new();

        // Withdraw: paths in old_top whose local_path_id is absent from new_top
        for (i, old) in old_top.iter().enumerate() {
            let still_present = new_top.iter().any(|p| p.local_path_id == old.local_path_id);
            if !still_present {
                changes.push(Change {
                    source: old.source.clone(),
                    family,
                    net,
                    nexthop: old.nexthop,
                    attr: Arc::new(Vec::new()),
                    path_id: old.local_path_id,
                    rank: i + 1,
                    old_rank: i + 1,
                });
            }
        }

        // Advertise: paths in new_top that are new or have changed attributes
        for (i, p) in new_top.iter().enumerate() {
            let rank = i + 1;
            let old_entry = old_top.iter().find(|o| o.local_path_id == p.local_path_id);
            match old_entry {
                None => {
                    // Newly entered top-N — advertise
                    changes.push(Change {
                        source: p.source.clone(),
                        family,
                        net,
                        nexthop: p.nexthop,
                        attr: p.pa.attr.clone(),
                        path_id: p.local_path_id,
                        rank,
                        old_rank: 0,
                    });
                }
                Some(_) => {
                    let old_rank = old_top
                        .iter()
                        .position(|o| o.local_path_id == p.local_path_id)
                        .unwrap()
                        + 1;
                    if !same_top_entry(&old_top[old_rank - 1], p) || rank != old_rank {
                        // Attributes changed or rank shifted — re-advertise so
                        // peers whose send_max window now includes (or excludes)
                        // this path can update accordingly.
                        changes.push(Change {
                            source: p.source.clone(),
                            family,
                            net,
                            nexthop: p.nexthop,
                            attr: p.pa.attr.clone(),
                            path_id: p.local_path_id,
                            rank,
                            old_rank,
                        });
                    }
                }
            }
        }

        changes
    }

    pub fn drop(&mut self, source: Arc<Source>) -> Vec<Change> {
        let mut advertise = Vec::new();
        self.route_stats.remove(&source.remote_addr);
        self.prefix_limits.remove(&source.remote_addr);
        for (family, rt) in self.global.iter_mut() {
            rt.retain(|net, dst| {
                let old_top: Vec<TopNEntry> = dst
                    .unfiltered_all()
                    .iter()
                    .map(|p| TopNEntry {
                        source: p.source.clone(),
                        nexthop: p.nexthop,
                        attr: p.pa.attr.clone(),
                        local_path_id: p.local_path_id,
                    })
                    .collect();

                dst.entry.retain(|e| !Arc::ptr_eq(&e.source, &source));

                if dst.entry.is_empty() {
                    // Withdraw all previously-advertised paths using their stable IDs
                    for (i, e) in old_top.iter().enumerate() {
                        advertise.push(Change {
                            source: e.source.clone(),
                            family: *family,
                            net: *net,
                            nexthop: e.nexthop,
                            attr: Arc::new(Vec::new()),
                            path_id: e.local_path_id,
                            rank: i + 1,
                            old_rank: i + 1,
                        });
                    }
                    return false;
                }

                advertise.extend(Self::diff_top_n(dst, &old_top, *family, *net));
                true
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
        nexthop: &mut bgp::Nexthop,
        local_addr: IpAddr,
    ) -> Disposition {
        assignment.apply(&self.rpki, source, net, attr, nexthop, local_addr)
    }
}

#[derive(Clone)]
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

/// Policy action to modify the nexthop of a route.
#[derive(Clone, Debug, PartialEq)]
pub enum NexthopAction {
    /// Set nexthop to a specific address.
    Address(IpAddr),
    /// Set nexthop to self (the local router's address).
    PeerSelf,
    /// Leave nexthop unchanged.
    Unchanged,
}

/// Actions applied to a route when a policy statement matches.
#[derive(Clone, Default)]
pub struct Actions {
    pub nexthop: Option<NexthopAction>,
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
    fn apply(
        &self,
        source: &Arc<Source>,
        net: &packet::Nlri,
        attr: &Arc<Vec<packet::Attribute>>,
        nexthop: &mut bgp::Nexthop,
        local_addr: IpAddr,
    ) -> Disposition {
        let matched = self.conditions.iter().all(|c| c.evalute(source, net, attr));
        if !matched {
            return Disposition::Pass;
        }

        if let Some(action) = &self.actions.nexthop {
            *nexthop = match action {
                NexthopAction::Address(addr) => match addr {
                    IpAddr::V4(v4) => bgp::Nexthop::V4(*v4),
                    IpAddr::V6(v6) => bgp::Nexthop::V6(*v6),
                },
                NexthopAction::PeerSelf => match local_addr {
                    IpAddr::V4(v4) => bgp::Nexthop::V4(v4),
                    IpAddr::V6(v6) => bgp::Nexthop::V6(v6),
                },
                NexthopAction::Unchanged => *nexthop,
            };
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
        nexthop: &mut bgp::Nexthop,
        local_addr: IpAddr,
    ) -> Disposition {
        for statement in &self.statements {
            let d = statement.apply(source, net, attr, nexthop, local_addr);
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
}

impl PolicyAssignment {
    fn apply(
        &self,
        _rpki: &RpkiTable,
        source: &Arc<Source>,
        net: &packet::Nlri,
        attr: &Arc<Vec<packet::Attribute>>,
        nexthop: &mut bgp::Nexthop,
        local_addr: IpAddr,
    ) -> Disposition {
        for policy in &self.policies {
            let d = policy.apply(source, net, attr, nexthop, local_addr);
            if d != Disposition::Pass {
                return d;
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
        actions: Actions,
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
            actions,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn source(addr: u8, remote_asn: u32, local_asn: u32, router_id: u8) -> Arc<Source> {
        Arc::new(Source::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, addr)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 254)),
            remote_asn,
            local_asn,
            Ipv4Addr::new(0, 0, 0, router_id),
            0,
            false,
        ))
    }

    fn nlri(a: u8, b: u8, c: u8, d: u8, mask: u8) -> packet::Nlri {
        packet::Nlri::V4(packet::bgp::Ipv4Net {
            addr: Ipv4Addr::new(a, b, c, d),
            mask,
        })
    }

    fn nh() -> bgp::Nexthop {
        bgp::Nexthop::V4(Ipv4Addr::new(10, 0, 0, 1))
    }

    fn empty_attrs() -> Arc<Vec<packet::Attribute>> {
        Arc::new(Vec::new())
    }

    fn attrs_with_local_pref(val: u32) -> Arc<Vec<packet::Attribute>> {
        Arc::new(vec![
            packet::Attribute::new_with_value(packet::Attribute::LOCAL_PREF, val).unwrap(),
        ])
    }

    fn attrs_with_origin(val: u32) -> Arc<Vec<packet::Attribute>> {
        Arc::new(vec![
            packet::Attribute::new_with_value(packet::Attribute::ORIGIN, val).unwrap(),
        ])
    }

    fn attrs_with_as_path_len(len: u8) -> Arc<Vec<packet::Attribute>> {
        // Build AS_PATH binary: type=SEQ, count=len, then len * 4 bytes (dummy ASNs)
        let mut bin = Vec::new();
        bin.push(packet::Attribute::AS_PATH_TYPE_SEQ);
        bin.push(len);
        for i in 0..len as u32 {
            bin.extend_from_slice(&(65000 + i).to_be_bytes());
        }
        Arc::new(vec![
            packet::Attribute::new_with_bin(packet::Attribute::AS_PATH, bin).unwrap(),
        ])
    }

    // --- drop ---

    #[test]
    fn drop_source() {
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

        let n1 = nlri(1, 0, 0, 0, 24);
        let n2 = nlri(2, 0, 0, 0, 24);
        let n3 = nlri(3, 0, 0, 0, 24);

        let mut rt = RoutingTable::new();
        let family = Family::IPV4;
        let attrs = Arc::new(Vec::new());

        rt.insert(s1.clone(), family, n1, 0, nh(), attrs.clone(), false);
        rt.insert(s2, family, n1, 0, nh(), attrs.clone(), false);
        rt.insert(s1.clone(), family, n2, 0, nh(), attrs.clone(), false);
        rt.insert(s1.clone(), family, n3, 0, nh(), attrs.clone(), false);

        assert_eq!(rt.global.get(&family).unwrap().len(), 3);
        rt.drop(s1);
        assert_eq!(rt.global.get(&family).unwrap().len(), 1);
    }

    // --- single_aspath_match ---

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

    // --- insert basic ---

    #[test]
    fn insert_single() {
        let mut rt = RoutingTable::new();
        let change = rt.insert(
            source(1, 65001, 65000, 1),
            Family::IPV4,
            nlri(10, 0, 0, 0, 24),
            0,
            nh(),
            empty_attrs(),
            false,
        );
        assert!(!change.is_empty());
    }

    #[test]
    fn insert_same_nlri_no_best_change() {
        let mut rt = RoutingTable::new();
        let net = nlri(10, 0, 0, 0, 24);
        // Insert with router_id=1 (lower, so this is best)
        rt.insert(
            source(1, 65001, 65000, 1),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            false,
        );
        // Insert with router_id=2 (higher, won't become best) → emits rank=2
        let change = rt.insert(
            source(2, 65002, 65000, 2),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            false,
        );
        assert_eq!(change.len(), 1);
        assert_eq!(change[0].rank, 2);
    }

    // --- best path selection ---

    /// Find the Change whose source matches the given address.
    fn find_change_for(changes: Vec<Change>, addr: Ipv4Addr) -> Change {
        let target = IpAddr::V4(addr);
        changes
            .into_iter()
            .find(|c| c.source.remote_addr == target)
            .expect("expected a Change for the given source")
    }

    #[test]
    fn best_path_local_pref() {
        let mut rt = RoutingTable::new();
        let net = nlri(10, 0, 0, 0, 24);
        rt.insert(
            source(1, 65001, 65000, 1),
            Family::IPV4,
            net,
            0,
            nh(),
            attrs_with_local_pref(100),
            false,
        );
        let changes = rt.insert(
            source(2, 65002, 65000, 2),
            Family::IPV4,
            net,
            0,
            nh(),
            attrs_with_local_pref(200),
            false,
        );
        // Higher local_pref wins → best path changes; stable IDs produce
        // a withdraw for the old best + an advertise for the new best.
        let adv = find_change_for(changes, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(
            adv.source.remote_addr,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        );
    }

    #[test]
    fn best_path_as_path_length() {
        let mut rt = RoutingTable::new();
        let net = nlri(10, 0, 0, 0, 24);
        rt.insert(
            source(1, 65001, 65000, 1),
            Family::IPV4,
            net,
            0,
            nh(),
            attrs_with_as_path_len(3),
            false,
        );
        let changes = rt.insert(
            source(2, 65002, 65000, 2),
            Family::IPV4,
            net,
            0,
            nh(),
            attrs_with_as_path_len(1),
            false,
        );
        // Shorter AS path wins
        let adv = find_change_for(changes, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(
            adv.source.remote_addr,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        );
    }

    #[test]
    fn best_path_origin() {
        let mut rt = RoutingTable::new();
        let net = nlri(10, 0, 0, 0, 24);
        // Insert with ORIGIN=Incomplete(2), router_id=1
        rt.insert(
            source(1, 65001, 65000, 1),
            Family::IPV4,
            net,
            0,
            nh(),
            attrs_with_origin(2),
            false,
        );
        // Insert with ORIGIN=IGP(0), router_id=2
        let changes = rt.insert(
            source(2, 65002, 65000, 2),
            Family::IPV4,
            net,
            0,
            nh(),
            attrs_with_origin(0),
            false,
        );
        // IGP (lower origin value) wins
        let adv = find_change_for(changes, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(
            adv.source.remote_addr,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        );
    }

    #[test]
    fn best_path_ebgp_over_ibgp() {
        let mut rt = RoutingTable::new();
        let net = nlri(10, 0, 0, 0, 24);
        // iBGP peer (remote_asn == local_asn), router_id=1 (lower)
        rt.insert(
            source(1, 65000, 65000, 1),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            false,
        );
        // eBGP peer (remote_asn != local_asn), router_id=2 (higher)
        let changes = rt.insert(
            source(2, 65001, 65000, 2),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            false,
        );
        // eBGP wins even though router_id is higher
        let adv = find_change_for(changes, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(
            adv.source.remote_addr,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        );
    }

    #[test]
    fn best_path_router_id() {
        let mut rt = RoutingTable::new();
        let net = nlri(10, 0, 0, 0, 24);
        // router_id=10
        rt.insert(
            source(1, 65001, 65000, 10),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            false,
        );
        // router_id=5 (lower wins)
        let changes = rt.insert(
            source(2, 65002, 65000, 5),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            false,
        );
        let adv = find_change_for(changes, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(
            adv.source.remote_addr,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        );
    }

    // --- remove ---

    #[test]
    fn remove_best_path() {
        let mut rt = RoutingTable::new();
        let net = nlri(10, 0, 0, 0, 24);
        let s1 = source(1, 65001, 65000, 1);
        let s2 = source(2, 65002, 65000, 2);
        rt.insert(s1.clone(), Family::IPV4, net, 0, nh(), empty_attrs(), false);
        rt.insert(s2.clone(), Family::IPV4, net, 0, nh(), empty_attrs(), false);
        // Remove best (router_id=1) → s2 promoted to best
        let changes = rt.remove(s1, Family::IPV4, net, 0);
        let adv = find_change_for(changes, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(
            adv.source.remote_addr,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        );
    }

    #[test]
    fn remove_non_best_path() {
        let mut rt = RoutingTable::new();
        let net = nlri(10, 0, 0, 0, 24);
        let s1 = source(1, 65001, 65000, 1);
        let s2 = source(2, 65002, 65000, 2);
        rt.insert(s1.clone(), Family::IPV4, net, 0, nh(), empty_attrs(), false);
        rt.insert(s2.clone(), Family::IPV4, net, 0, nh(), empty_attrs(), false);
        // Remove non-best (router_id=2) → withdrawal for the removed path
        let change = rt.remove(s2, Family::IPV4, net, 0);
        assert_eq!(change.len(), 1);
        assert!(change[0].attr.is_empty()); // withdrawal
    }

    #[test]
    fn remove_last_path() {
        let mut rt = RoutingTable::new();
        let net = nlri(10, 0, 0, 0, 24);
        let s1 = source(1, 65001, 65000, 1);
        rt.insert(s1.clone(), Family::IPV4, net, 0, nh(), empty_attrs(), false);
        let change = rt.remove(s1, Family::IPV4, net, 0);
        let change = change.into_iter().next().unwrap();
        // Withdrawal: empty attrs
        assert!(change.attr.is_empty());
    }

    // --- filtered ---

    #[test]
    fn filtered_path_no_change() {
        let mut rt = RoutingTable::new();
        let net = nlri(10, 0, 0, 0, 24);
        // Only filtered path → no Change (no unfiltered best)
        let change = rt.insert(
            source(1, 65001, 65000, 1),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            true,
        );
        assert!(change.is_empty());

        // Unfiltered path added → Change points to the unfiltered path
        let s2 = source(2, 65002, 65000, 2);
        let change = rt.insert(s2.clone(), Family::IPV4, net, 0, nh(), empty_attrs(), false);
        let change = change.into_iter().next().unwrap();
        assert!(Arc::ptr_eq(&change.source, &s2));
    }

    // A2: filtered at head, insert unfiltered behind existing unfiltered best
    #[test]
    fn filtered_head_insert_unfiltered_non_best() {
        let mut rt = RoutingTable::new();
        let net = nlri(10, 0, 0, 0, 24);
        // filtered path at head (router_id=1)
        rt.insert(
            source(1, 65001, 65000, 1),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            true,
        );
        // unfiltered best (router_id=2)
        let s2 = source(2, 65002, 65000, 2);
        let change = rt.insert(s2.clone(), Family::IPV4, net, 0, nh(), empty_attrs(), false);
        let change = change.into_iter().next().unwrap();
        assert!(Arc::ptr_eq(&change.source, &s2));
        // another unfiltered but worse (router_id=3) → emits rank=2 (filtered paths skipped)
        let change = rt.insert(
            source(3, 65003, 65000, 3),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            false,
        );
        assert_eq!(change.len(), 1);
        assert_eq!(change[0].rank, 2);
    }

    // B1: replace filtered path at index 0 → unfiltered best unchanged
    #[test]
    fn replace_filtered_head_no_best_change() {
        let mut rt = RoutingTable::new();
        let net = nlri(10, 0, 0, 0, 24);
        let s1 = source(1, 65001, 65000, 1);
        // filtered at head
        rt.insert(s1.clone(), Family::IPV4, net, 0, nh(), empty_attrs(), true);
        // unfiltered best
        rt.insert(
            source(2, 65002, 65000, 2),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            false,
        );
        // replace the filtered head with updated attrs (still filtered) → no best change
        let change = rt.insert(
            s1,
            Family::IPV4,
            net,
            0,
            nh(),
            attrs_with_local_pref(200),
            true,
        );
        assert!(change.is_empty());
    }

    // B2: replace unfiltered best with filtered → best changes to another unfiltered
    #[test]
    fn replace_unfiltered_best_changes() {
        let mut rt = RoutingTable::new();
        let net = nlri(10, 0, 0, 0, 24);
        let s1 = source(1, 65001, 65000, 1);
        // filtered at head (router_id=3, won't be best)
        rt.insert(
            source(3, 65003, 65000, 3),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            true,
        );
        // unfiltered best (router_id=1)
        rt.insert(s1.clone(), Family::IPV4, net, 0, nh(), empty_attrs(), false);
        // another unfiltered (router_id=2)
        let s2 = source(2, 65002, 65000, 2);
        rt.insert(s2.clone(), Family::IPV4, net, 0, nh(), empty_attrs(), false);
        // replace s1 as filtered → s2 becomes unfiltered best
        let changes = rt.insert(s1, Family::IPV4, net, 0, nh(), empty_attrs(), true);
        let adv = find_change_for(changes, Ipv4Addr::new(10, 0, 0, 2));
        assert!(Arc::ptr_eq(&adv.source, &s2));
    }

    // B3: replace unfiltered non-best → no best change
    #[test]
    fn replace_unfiltered_non_best_no_change() {
        let mut rt = RoutingTable::new();
        let net = nlri(10, 0, 0, 0, 24);
        // filtered at head
        rt.insert(
            source(3, 65003, 65000, 3),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            true,
        );
        // unfiltered best (router_id=1)
        rt.insert(
            source(1, 65001, 65000, 1),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            false,
        );
        // unfiltered non-best (router_id=2)
        let s2 = source(2, 65002, 65000, 2);
        rt.insert(s2.clone(), Family::IPV4, net, 0, nh(), empty_attrs(), false);
        // replace s2 with different attrs → still non-best, but attrs changed so re-advertised
        let change = rt.insert(
            s2,
            Family::IPV4,
            net,
            0,
            nh(),
            attrs_with_local_pref(50),
            false,
        );
        assert_eq!(change.len(), 1);
        assert_eq!(change[0].rank, 2);
    }

    #[test]
    fn filtered_path_peer_stats() {
        let mut rt = RoutingTable::new();
        let net = nlri(10, 0, 0, 0, 24);
        let s1 = source(1, 65001, 65000, 1);
        rt.insert(s1.clone(), Family::IPV4, net, 0, nh(), empty_attrs(), true);
        // peer_stats tracks (received, accepted) — filtered path: received=1, accepted=0
        let stats: Vec<_> = rt.peer_stats(&s1.remote_addr).unwrap().collect();
        assert_eq!(stats.len(), 1);
        let (_, (received, accepted)) = stats[0];
        assert_eq!(received, 1);
        assert_eq!(accepted, 0);
    }

    // --- best() ---

    #[test]
    fn best_returns_all_prefixes() {
        let mut rt = RoutingTable::new();
        let s1 = source(1, 65001, 65000, 1);
        rt.insert(
            s1.clone(),
            Family::IPV4,
            nlri(10, 0, 0, 0, 24),
            0,
            nh(),
            empty_attrs(),
            false,
        );
        rt.insert(
            s1.clone(),
            Family::IPV4,
            nlri(10, 0, 1, 0, 24),
            0,
            nh(),
            empty_attrs(),
            false,
        );
        rt.insert(
            s1.clone(),
            Family::IPV4,
            nlri(10, 0, 2, 0, 24),
            0,
            nh(),
            empty_attrs(),
            false,
        );
        let best = rt.best(&Family::IPV4);
        assert_eq!(best.len(), 3);
    }

    // --- policy ---

    #[test]
    fn policy_prefix_reject() {
        let rt = RoutingTable::new();
        let mut ptable = PolicyTable::new();

        ptable
            .add_defined_set(DefinedSetConfig::Prefix {
                name: "ps1".to_string(),
                prefixes: vec![PrefixConfig {
                    ip_prefix: "10.0.0.0/24".to_string(),
                    mask_length_min: 24,
                    mask_length_max: 24,
                }],
            })
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
        ptable.add_policy("pol1", vec!["st1".to_string()]).unwrap();
        let (_, assignment) = ptable
            .add_assignment(
                "global",
                PolicyDirection::Import,
                Disposition::Accept,
                vec!["pol1".to_string()],
            )
            .unwrap();

        let s = source(1, 65001, 65000, 1);
        let net = nlri(10, 0, 0, 0, 24);
        let result = rt.apply_policy(
            &assignment,
            &s,
            &net,
            &empty_attrs(),
            &mut nh(),
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        );
        assert_eq!(result, Disposition::Reject);
    }

    #[test]
    fn policy_default_accept() {
        let rt = RoutingTable::new();
        let mut ptable = PolicyTable::new();

        ptable
            .add_defined_set(DefinedSetConfig::Prefix {
                name: "ps1".to_string(),
                prefixes: vec![PrefixConfig {
                    ip_prefix: "10.0.0.0/24".to_string(),
                    mask_length_min: 24,
                    mask_length_max: 24,
                }],
            })
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
        ptable.add_policy("pol1", vec!["st1".to_string()]).unwrap();
        let (_, assignment) = ptable
            .add_assignment(
                "global",
                PolicyDirection::Import,
                Disposition::Accept,
                vec!["pol1".to_string()],
            )
            .unwrap();

        let s = source(1, 65001, 65000, 1);
        // Different prefix → no match → default disposition (Accept)
        let net = nlri(192, 168, 0, 0, 24);
        let result = rt.apply_policy(
            &assignment,
            &s,
            &net,
            &empty_attrs(),
            &mut nh(),
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        );
        assert_eq!(result, Disposition::Accept);
    }

    #[test]
    fn policy_nexthop_action_address() {
        let rt = RoutingTable::new();
        let mut ptable = PolicyTable::new();

        ptable
            .add_defined_set(DefinedSetConfig::Prefix {
                name: "ps1".to_string(),
                prefixes: vec![PrefixConfig {
                    ip_prefix: "10.0.0.0/24".to_string(),
                    mask_length_min: 24,
                    mask_length_max: 24,
                }],
            })
            .unwrap();
        ptable
            .add_statement(
                "st1",
                vec![ConditionConfig::PrefixSet(
                    "ps1".to_string(),
                    MatchOption::Any,
                )],
                Some(Disposition::Accept),
                Actions {
                    nexthop: Some(NexthopAction::Address(IpAddr::V4(Ipv4Addr::new(
                        192, 168, 1, 1,
                    )))),
                },
            )
            .unwrap();
        ptable.add_policy("pol1", vec!["st1".to_string()]).unwrap();
        let (_, assignment) = ptable
            .add_assignment(
                "global",
                PolicyDirection::Export,
                Disposition::Accept,
                vec!["pol1".to_string()],
            )
            .unwrap();

        let s = source(1, 65001, 65000, 1);
        let net = nlri(10, 0, 0, 0, 24);
        let mut nexthop = bgp::Nexthop::V4(Ipv4Addr::new(10, 0, 0, 1));
        let result = rt.apply_policy(
            &assignment,
            &s,
            &net,
            &empty_attrs(),
            &mut nexthop,
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        );
        assert_eq!(result, Disposition::Accept);
        assert_eq!(nexthop, bgp::Nexthop::V4(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn policy_nexthop_action_self() {
        let rt = RoutingTable::new();
        let mut ptable = PolicyTable::new();

        ptable
            .add_defined_set(DefinedSetConfig::Prefix {
                name: "ps1".to_string(),
                prefixes: vec![PrefixConfig {
                    ip_prefix: "10.0.0.0/24".to_string(),
                    mask_length_min: 24,
                    mask_length_max: 24,
                }],
            })
            .unwrap();
        ptable
            .add_statement(
                "st1",
                vec![ConditionConfig::PrefixSet(
                    "ps1".to_string(),
                    MatchOption::Any,
                )],
                Some(Disposition::Accept),
                Actions {
                    nexthop: Some(NexthopAction::PeerSelf),
                },
            )
            .unwrap();
        ptable.add_policy("pol1", vec!["st1".to_string()]).unwrap();
        let (_, assignment) = ptable
            .add_assignment(
                "global",
                PolicyDirection::Export,
                Disposition::Accept,
                vec!["pol1".to_string()],
            )
            .unwrap();

        let s = source(1, 65001, 65000, 1);
        let net = nlri(10, 0, 0, 0, 24);
        let local_addr = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1));
        let mut nexthop = bgp::Nexthop::V4(Ipv4Addr::new(10, 0, 0, 1));
        let result = rt.apply_policy(
            &assignment,
            &s,
            &net,
            &empty_attrs(),
            &mut nexthop,
            local_addr,
        );
        assert_eq!(result, Disposition::Accept);
        assert_eq!(nexthop, bgp::Nexthop::V4(Ipv4Addr::new(172, 16, 0, 1)));
    }

    #[test]
    fn policy_nexthop_no_match_unchanged() {
        let rt = RoutingTable::new();
        let mut ptable = PolicyTable::new();

        ptable
            .add_defined_set(DefinedSetConfig::Prefix {
                name: "ps1".to_string(),
                prefixes: vec![PrefixConfig {
                    ip_prefix: "10.0.0.0/24".to_string(),
                    mask_length_min: 24,
                    mask_length_max: 24,
                }],
            })
            .unwrap();
        ptable
            .add_statement(
                "st1",
                vec![ConditionConfig::PrefixSet(
                    "ps1".to_string(),
                    MatchOption::Any,
                )],
                Some(Disposition::Accept),
                Actions {
                    nexthop: Some(NexthopAction::Address(IpAddr::V4(Ipv4Addr::new(
                        192, 168, 1, 1,
                    )))),
                },
            )
            .unwrap();
        ptable.add_policy("pol1", vec!["st1".to_string()]).unwrap();
        let (_, assignment) = ptable
            .add_assignment(
                "global",
                PolicyDirection::Export,
                Disposition::Accept,
                vec!["pol1".to_string()],
            )
            .unwrap();

        let s = source(1, 65001, 65000, 1);
        // Different prefix → no match → nexthop should not change
        let net = nlri(192, 168, 0, 0, 24);
        let original = bgp::Nexthop::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut nexthop = original;
        let _result = rt.apply_policy(
            &assignment,
            &s,
            &net,
            &empty_attrs(),
            &mut nexthop,
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        );
        assert_eq!(nexthop, original);
    }

    // --- Ord regression: higher-priority attribute must win ---

    #[test]
    fn best_path_local_pref_over_router_id() {
        // Regression: previously, a path losing on LOCAL_PREF could still
        // win on router_id due to missing "lose" checks in the comparison loop.
        let mut rt = RoutingTable::new();
        let net = nlri(10, 0, 0, 0, 24);
        // s1: local_pref=200, router_id=2
        let s1 = source(1, 65001, 65000, 2);
        rt.insert(
            s1.clone(),
            Family::IPV4,
            net,
            0,
            nh(),
            attrs_with_local_pref(200),
            false,
        );
        // s2: local_pref=50, router_id=1 (better router_id, worse local_pref)
        let s2 = source(2, 65002, 65000, 1);
        let change = rt.insert(
            s2,
            Family::IPV4,
            net,
            0,
            nh(),
            attrs_with_local_pref(50),
            false,
        );
        // s1 must remain best (higher local_pref wins over lower router_id)
        // s2 enters as rank=2
        assert_eq!(change.len(), 1);
        assert_eq!(change[0].rank, 2);
    }

    #[test]
    fn replace_unfiltered_to_filtered_withdraws() {
        let mut rt = RoutingTable::new();
        let net = nlri(10, 0, 0, 0, 24);
        let s1 = source(1, 65001, 65000, 1);
        // Insert unfiltered path
        let change = rt.insert(s1.clone(), Family::IPV4, net, 0, nh(), empty_attrs(), false);
        assert!(!change.is_empty());
        // Replace with filtered → no unfiltered best remains → withdraw
        let change = rt.insert(s1, Family::IPV4, net, 0, nh(), empty_attrs(), true);
        let change = change
            .into_iter()
            .next()
            .expect("should return withdrawal Change");
        assert!(change.attr.is_empty());
    }

    #[test]
    fn withdraw_source_is_old_best() {
        // When all paths become filtered, the withdrawal source must be the
        // old unfiltered best's source, not the inserting peer's source.
        let mut rt = RoutingTable::new();
        let net = nlri(10, 0, 0, 0, 24);
        let s1 = source(1, 65001, 65000, 1);
        // s1 is unfiltered best
        rt.insert(s1.clone(), Family::IPV4, net, 0, nh(), empty_attrs(), false);
        // s2 inserts a filtered path
        let s2 = source(2, 65002, 65000, 2);
        rt.insert(s2.clone(), Family::IPV4, net, 0, nh(), empty_attrs(), true);
        // s1 gets replaced as filtered → all filtered → withdrawal
        let change = rt
            .insert(s1.clone(), Family::IPV4, net, 0, nh(), empty_attrs(), true)
            .into_iter()
            .next()
            .expect("should return withdrawal");
        assert!(change.attr.is_empty());
        // withdrawal source must be s1 (old best), not the inserting peer
        assert!(Arc::ptr_eq(&change.source, &s1));
    }

    // --- best() with filtered head ---

    #[test]
    fn best_skips_filtered_paths() {
        let mut rt = RoutingTable::new();
        let net = nlri(10, 0, 0, 0, 24);
        // filtered path (better router_id)
        rt.insert(
            source(1, 65001, 65000, 1),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            true,
        );
        // unfiltered path
        let s2 = source(2, 65002, 65000, 2);
        rt.insert(s2.clone(), Family::IPV4, net, 0, nh(), empty_attrs(), false);
        let bests = rt.best(&Family::IPV4);
        assert_eq!(bests.len(), 1);
        assert!(Arc::ptr_eq(&bests[0].source, &s2));
    }

    #[test]
    fn best_skips_all_filtered_destination() {
        let mut rt = RoutingTable::new();
        let net = nlri(10, 0, 0, 0, 24);
        rt.insert(
            source(1, 65001, 65000, 1),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            true,
        );
        let bests = rt.best(&Family::IPV4);
        assert!(bests.is_empty());
    }

    // --- remove() with filtered head ---

    #[test]
    fn remove_best_with_filtered_head() {
        let mut rt = RoutingTable::new();
        let net = nlri(10, 0, 0, 0, 24);
        let attrs = attrs_with_local_pref(100);
        // filtered at head
        rt.insert(
            source(1, 65001, 65000, 1),
            Family::IPV4,
            net,
            0,
            nh(),
            attrs.clone(),
            true,
        );
        // unfiltered best (router_id=2)
        let s2 = source(2, 65002, 65000, 2);
        rt.insert(s2.clone(), Family::IPV4, net, 0, nh(), attrs.clone(), false);
        // unfiltered non-best (router_id=3)
        let s3 = source(3, 65003, 65000, 3);
        rt.insert(s3.clone(), Family::IPV4, net, 0, nh(), attrs.clone(), false);
        // remove s2 (best) → s3 becomes new best
        let changes = rt.remove(s2, Family::IPV4, net, 0);
        let adv = find_change_for(changes, Ipv4Addr::new(10, 0, 0, 3));
        assert!(Arc::ptr_eq(&adv.source, &s3));
    }

    #[test]
    fn remove_last_unfiltered_withdraws() {
        let mut rt = RoutingTable::new();
        let net = nlri(10, 0, 0, 0, 24);
        // filtered path
        rt.insert(
            source(1, 65001, 65000, 1),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            true,
        );
        // only unfiltered path
        let s2 = source(2, 65002, 65000, 2);
        rt.insert(s2.clone(), Family::IPV4, net, 0, nh(), empty_attrs(), false);
        // remove s2 → all filtered → withdrawal
        let change = rt
            .remove(s2, Family::IPV4, net, 0)
            .into_iter()
            .next()
            .expect("should return withdrawal");
        assert!(change.attr.is_empty());
    }

    // --- drop() with filtered head ---

    #[test]
    fn drop_best_with_filtered_head() {
        let mut rt = RoutingTable::new();
        let net = nlri(10, 0, 0, 0, 24);
        let attrs = attrs_with_local_pref(100);
        // filtered at head
        rt.insert(
            source(1, 65001, 65000, 1),
            Family::IPV4,
            net,
            0,
            nh(),
            attrs.clone(),
            true,
        );
        // unfiltered best
        let s2 = source(2, 65002, 65000, 2);
        rt.insert(s2.clone(), Family::IPV4, net, 0, nh(), attrs.clone(), false);
        // unfiltered non-best
        let s3 = source(3, 65003, 65000, 3);
        rt.insert(s3.clone(), Family::IPV4, net, 0, nh(), attrs.clone(), false);
        // drop s2 → s3 becomes new best (withdraw old + advertise new)
        let changes = rt.drop(s2);
        let adv = find_change_for(changes, Ipv4Addr::new(10, 0, 0, 3));
        assert!(Arc::ptr_eq(&adv.source, &s3));
    }

    #[test]
    fn drop_filtered_no_change() {
        let mut rt = RoutingTable::new();
        let net = nlri(10, 0, 0, 0, 24);
        // filtered path from s1
        let s1 = source(1, 65001, 65000, 1);
        rt.insert(s1.clone(), Family::IPV4, net, 0, nh(), empty_attrs(), true);
        // unfiltered best from s2
        let s2 = source(2, 65002, 65000, 2);
        rt.insert(s2, Family::IPV4, net, 0, nh(), empty_attrs(), false);
        // drop s1 (filtered) → no best change
        let changes = rt.drop(s1);
        assert!(changes.is_empty());
    }

    // --- iter_destinations AdjOut with filtered head ---

    #[test]
    fn adj_out_skips_filtered_head() {
        let mut rt = RoutingTable::new();
        let net = nlri(10, 0, 0, 0, 24);
        let attrs = attrs_with_local_pref(100);
        // filtered path with better router_id → sorts at index 0
        rt.insert(
            source(1, 65001, 65000, 1),
            Family::IPV4,
            net,
            0,
            nh(),
            attrs.clone(),
            true,
        );
        // unfiltered path → should be the AdjOut best
        let s2 = source(2, 65002, 65000, 2);
        rt.insert(s2.clone(), Family::IPV4, net, 0, nh(), attrs.clone(), false);

        // peer_addr=10.0.0.99 (different from both sources)
        let peer_addr = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99)));
        let dsts: Vec<_> = rt
            .iter_destinations(TableType::AdjOut, Family::IPV4, peer_addr, vec![], None)
            .collect();
        assert_eq!(dsts.len(), 1);
        assert_eq!(dsts[0].paths.len(), 1);
        // attr should be non-empty (not a withdrawal / not filtered path)
        assert!(!dsts[0].paths[0].attr.is_empty());
    }

    #[test]
    fn adj_out_skips_all_filtered_destination() {
        let mut rt = RoutingTable::new();
        let net = nlri(10, 0, 0, 0, 24);
        // only filtered paths
        rt.insert(
            source(1, 65001, 65000, 1),
            Family::IPV4,
            net,
            0,
            nh(),
            attrs_with_local_pref(100),
            true,
        );

        let peer_addr = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99)));
        let dsts: Vec<_> = rt
            .iter_destinations(TableType::AdjOut, Family::IPV4, peer_addr, vec![], None)
            .collect();
        // no unfiltered best → destination should be filtered out
        assert!(dsts.is_empty());
    }

    // --- state() counts ---

    #[test]
    fn state_counts_filtered_as_not_accepted() {
        let mut rt = RoutingTable::new();
        let net = nlri(10, 0, 0, 0, 24);
        // 1 filtered path
        rt.insert(
            source(1, 65001, 65000, 1),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            true,
        );
        // 1 unfiltered path
        rt.insert(
            source(2, 65002, 65000, 2),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            false,
        );
        let s = rt.state(Family::IPV4);
        assert_eq!(s.num_destination, 1);
        assert_eq!(s.num_path, 2);
        assert_eq!(s.num_accepted, 1);
    }

    // --- stable path IDs ---

    #[test]
    fn stable_id_new_best_no_churn() {
        // Inserting a new best should re-advertise the old path at its new rank.
        let mut rt = RoutingTable::new();
        let net = nlri(10, 0, 0, 0, 24);
        let s1 = source(1, 65001, 65000, 10); // router_id=10
        let s2 = source(2, 65002, 65000, 5); // router_id=5, better

        // Insert s1 → best, path_id=1
        let changes = rt.insert(s1.clone(), Family::IPV4, net, 0, nh(), empty_attrs(), false);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].path_id, 1);

        // Insert s2 → new best (lower router_id); s1 rank shifts 1→2
        let changes = rt.insert(s2.clone(), Family::IPV4, net, 0, nh(), empty_attrs(), false);
        assert_eq!(changes.len(), 2);
        // s2 is the new best at rank 1
        let s2_change = changes.iter().find(|c| c.path_id == 2).unwrap();
        assert_eq!(s2_change.rank, 1);
        assert!(Arc::ptr_eq(&s2_change.source, &s2));
        // s1 is re-advertised at rank 2 so peers can update their view
        let s1_change = changes.iter().find(|c| c.path_id == 1).unwrap();
        assert_eq!(s1_change.rank, 2);
        assert!(Arc::ptr_eq(&s1_change.source, &s1));
    }

    #[test]
    fn stable_id_preserved_on_replacement() {
        // Replacing a path's attributes preserves its stable local_path_id.
        let mut rt = RoutingTable::new();
        let net = nlri(10, 0, 0, 0, 24);
        let s1 = source(1, 65001, 65000, 1);

        let changes = rt.insert(s1.clone(), Family::IPV4, net, 0, nh(), empty_attrs(), false);
        let original_id = changes[0].path_id;

        // Replace with new attributes
        let changes = rt.insert(
            s1.clone(),
            Family::IPV4,
            net,
            0,
            nh(),
            attrs_with_local_pref(200),
            false,
        );
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].path_id, original_id); // same stable ID
    }

    #[test]
    fn stable_id_withdraw_uses_original_id() {
        // When a path is removed, the withdrawal uses its original ID.
        let mut rt = RoutingTable::new();
        let net = nlri(10, 0, 0, 0, 24);

        let s1 = source(1, 65001, 65000, 1); // best (router_id=1)
        let s2 = source(2, 65002, 65000, 2);
        rt.insert(s1.clone(), Family::IPV4, net, 0, nh(), empty_attrs(), false);
        rt.insert(s2.clone(), Family::IPV4, net, 0, nh(), empty_attrs(), false);

        // Remove s1 → withdraw should carry s1's path_id (1)
        let changes = rt.remove(s1, Family::IPV4, net, 0);
        let withdrawal = changes.iter().find(|c| c.attr.is_empty());
        assert!(withdrawal.is_some());
        assert_eq!(withdrawal.unwrap().path_id, 1);
    }

    #[test]
    fn stable_id_best_uses_stored_ids() {
        let mut rt = RoutingTable::new();
        let net = nlri(10, 0, 0, 0, 24);
        let s1 = source(1, 65001, 65000, 1);
        let s2 = source(2, 65002, 65000, 2);

        rt.insert(s1.clone(), Family::IPV4, net, 0, nh(), empty_attrs(), false);
        rt.insert(s2.clone(), Family::IPV4, net, 0, nh(), empty_attrs(), false);

        let best = rt.best(&Family::IPV4);
        assert_eq!(best.len(), 2);
        // IDs should be stable (1 and 2), not re-computed from rank
        let ids: Vec<u32> = best.iter().map(|c| c.path_id).collect();
        assert!(ids.contains(&1));
        assert!(ids.contains(&2));
    }
}
