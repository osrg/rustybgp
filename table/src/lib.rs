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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
    /// True when this path is marked stale during Graceful Restart (RFC 4724).
    pub stale: bool,
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

/// A path snapshot shared outside the table crate.
/// All fields are Arc-backed so cloning is cheap.
#[derive(Clone)]
pub struct Path {
    pub local_path_id: u32,
    pub source: Arc<Source>,
    pub nexthop: bgp::Nexthop,
    pub attr: Arc<Vec<packet::Attribute>>,
}

struct RibEntry {
    path: Path,
    /// Remote peer's inbound path ID (from the sending peer's Add-Path).
    id: u32,
    timestamp: SystemTime,
    flags: u8,
}

impl RibEntry {
    const FLAG_FILTERED: u8 = 1 << 0;

    fn is_filtered(&self) -> bool {
        self.flags & RibEntry::FLAG_FILTERED != 0
    }

    fn originator_id(&self) -> u32 {
        PathAttribute::new(self.path.attr.clone())
            .attr_originator_id()
            .unwrap_or(self.path.source.router_id)
    }
}

impl Ord for RibEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let self_pa = PathAttribute::new(self.path.attr.clone());
        let other_pa = PathAttribute::new(other.path.attr.clone());
        // Higher LOCAL_PREF is better (reverse order)
        self_pa
            .attr_local_preference()
            .cmp(&other_pa.attr_local_preference())
            .reverse()
            // Shorter AS path is better
            .then_with(|| {
                self_pa
                    .attr_as_path_length()
                    .cmp(&other_pa.attr_as_path_length())
            })
            // Lower origin is better (IGP=0 < EGP=1 < Incomplete=2)
            .then_with(|| self_pa.attr_origin().cmp(&other_pa.attr_origin()))
            // eBGP preferred over iBGP
            .then_with(|| {
                self.path
                    .source
                    .peer_type()
                    .cmp(&other.path.source.peer_type())
            })
            // Non-stale is better than stale (false < true, and Less = better here)
            .then_with(|| {
                self.path
                    .source
                    .is_stale()
                    .cmp(&other.path.source.is_stale())
            })
            // Lower originator ID / router ID is better
            .then_with(|| self.originator_id().cmp(&other.originator_id()))
    }
}

impl PartialOrd for RibEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for RibEntry {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == std::cmp::Ordering::Equal
    }
}

impl Eq for RibEntry {}

struct Destination {
    entry: Vec<RibEntry>,
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
            if !self.entry.iter().any(|p| p.path.local_path_id == id) {
                return id;
            }
        }
    }

    fn unfiltered_iter(&self) -> impl Iterator<Item = &RibEntry> + '_ {
        self.entry.iter().filter(|p| !p.is_filtered())
    }

    fn unfiltered_best(&self) -> Option<&RibEntry> {
        self.unfiltered_iter().next()
    }
}

#[derive(Default, Clone, Debug)]
pub struct TableState {
    pub num_destination: usize,
    pub num_path: usize,
    pub num_accepted: usize,
}

impl AddAssign for TableState {
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

/// Result of a single `Table::insert()` or `Table::remove()` operation.
///
/// Non-Add-Path peers can skip processing when `best_changed` is false.
/// Add-Path peers can skip when `any_changed` is false.
#[derive(Clone)]
pub struct NlriChange {
    pub family: Family,
    pub net: packet::Nlri,

    // Non-Add-Path peers use the following two fields only.
    /// True when the best path changed. Non-Add-Path peers skip if false.
    pub best_changed: bool,

    // Add-Path peers use the following three fields.
    /// True when any path change may affect what is advertised to peers.
    /// Add-Path peers skip if false.
    pub any_changed: bool,
    /// local_path_id of the path that was replaced (same id, new attrs).
    /// Used by Add-Path peers to detect re-advertisement needs.
    pub replaced_path_id: Option<u32>,
    /// All current unfiltered paths sorted by preference. Shared via Arc.
    pub current_paths: Arc<Vec<Path>>,
}

impl NlriChange {
    /// Best path after mutation. None when all paths filtered or prefix gone.
    pub fn new_best(&self) -> Option<&Path> {
        self.current_paths.first()
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
    stale: AtomicBool,
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
            stale: AtomicBool::new(false),
        }
    }

    pub fn mark_stale(&self) {
        self.stale.store(true, Ordering::Relaxed);
    }

    pub fn is_stale(&self) -> bool {
        self.stale.load(Ordering::Relaxed)
    }

    fn peer_type(&self) -> PeerType {
        if self.remote_asn == self.local_asn {
            PeerType::Ibgp
        } else {
            PeerType::Ebgp
        }
    }
}

/// Per-family routing table slot.
///
/// `deferring` is set while the local speaker is in Restarting Speaker mode
/// (RFC 4724 §4.2): best-path selection is suppressed for this family until
/// EOR has been received from all helper peers or the deferral timer fires.
#[derive(Default)]
pub struct Rib {
    pub deferring: bool,
    destinations: FnvHashMap<packet::Nlri, Destination>,
}

pub struct Table {
    ribs: FnvHashMap<Family, Rib>,
    route_stats: FnvHashMap<IpAddr, FnvHashMap<Family, (u64, u64)>>,
    rpki: RpkiTable,
}

impl Default for Table {
    fn default() -> Self {
        Self::new()
    }
}

impl Table {
    pub fn new() -> Self {
        Table {
            ribs: vec![(Family::EMPTY, Rib::default())].into_iter().collect(),
            route_stats: FnvHashMap::default(),
            rpki: RpkiTable::new(),
        }
    }

    /// Returns all current unfiltered paths grouped by destination.
    /// Each tuple is (nlri, paths_sorted_by_preference).
    pub fn best_paths(&self, family: &Family) -> Vec<(packet::Nlri, Vec<Path>)> {
        let Some(t) = self.ribs.get(family) else {
            return Vec::new();
        };
        t.destinations
            .iter()
            .filter_map(|(net, dst)| {
                let paths: Vec<Path> = dst.unfiltered_iter().map(|e| e.path.clone()).collect();
                (!paths.is_empty()).then_some((*net, paths))
            })
            .collect()
    }

    pub fn state(&self, family: Family) -> TableState {
        match self.ribs.get(&family) {
            Some(t) => {
                let entries = t.destinations.values().flat_map(|x| x.entry.iter());
                let mut num_path = 0;
                let mut num_accepted = 0;
                for p in entries {
                    num_path += 1;
                    if !p.is_filtered() {
                        num_accepted += 1;
                    }
                }
                TableState {
                    num_destination: t.destinations.len(),
                    num_path,
                    num_accepted,
                }
            }

            None => TableState::default(),
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
        self.ribs
            .get(&family)
            .unwrap_or_else(|| self.ribs.get(&Family::EMPTY).unwrap())
            .destinations
            .iter()
            .flat_map(move |(net, dst)| {
                dst.entry.iter().map(move |e| Reach {
                    source: e.path.source.clone(),
                    family,
                    net: packet::bgp::PathNlri {
                        nlri: *net,
                        path_id: e.id,
                    },
                    attr: e.path.attr.clone(),
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
        self.ribs
            .get(&family)
            .unwrap_or_else(|| self.ribs.get(&Family::EMPTY).unwrap())
            .destinations
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
                    let best = dst.unfiltered_best().map(|p| p as *const RibEntry);
                    dst.entry
                        .iter()
                        .enumerate()
                        .filter(|(_, p)| {
                            if table_type == TableType::AdjIn {
                                return p.path.source.remote_addr == peer_addr.unwrap();
                            } else if table_type == TableType::AdjOut {
                                return best == Some(*p as *const RibEntry)
                                    && p.path.source.remote_addr != peer_addr.unwrap();
                            }
                            true
                        })
                        .filter_map(|(_, p)| {
                            if table_type == TableType::AdjOut {
                                let codec = bgp::PeerCodecBuilder::new()
                                    .local_asn(p.path.source.local_asn)
                                    .local_addr(p.path.source.local_addr)
                                    .keep_aspath(p.path.source.rs_client)
                                    .keep_nexthop(p.path.source.rs_client)
                                    .build();
                                let attr = Arc::new(
                                    p.path
                                        .attr
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
                                    let mut nh = p.path.nexthop;
                                    if self.apply_policy(
                                        pa,
                                        &p.path.source,
                                        net,
                                        &attr,
                                        &mut nh,
                                        p.path.source.local_addr,
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
                                Some((p, p.path.attr.clone()))
                            }
                        })
                        .map(|(p, attr)| {
                            let validation = self.rpki.validate(family, &p.path.source, net, &attr);
                            PathEntry {
                                id: if table_type == TableType::AdjOut {
                                    0
                                } else {
                                    p.id
                                },
                                timestamp: p.timestamp,
                                attr,
                                validation,
                                stale: p.path.source.is_stale(),
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
        prefix_limit: Option<(u32, &Arc<AtomicU64>)>,
    ) -> Option<NlriChange> {
        let flags = if filtered { RibEntry::FLAG_FILTERED } else { 0 };

        let rt = self.ribs.entry(family).or_default();
        let deferring = rt.deferring;
        let dst = rt.destinations.entry(net).or_insert_with(Destination::new);

        // Single pass: compute old_best_id, find replaced index, check peer_has_path.
        let mut old_best_id: Option<u32> = None;
        let mut replaced_idx: Option<usize> = None;
        let mut peer_has_path = false;
        for (i, e) in dst.entry.iter().enumerate() {
            if old_best_id.is_none() && !e.is_filtered() {
                old_best_id = Some(e.path.local_path_id);
            }
            // Match by remote_addr + path_id, not by Arc identity.  This correctly
            // replaces a stale path from a previous session (different Source Arc but
            // same peer) when the peer reconnects after GR and re-sends the same route.
            // For non-GR sessions there is at most one Source per remote_addr in the
            // RIB, so the result is identical to an Arc::ptr_eq check.
            if e.path.source.remote_addr == source.remote_addr && e.id == remote_id {
                replaced_idx = Some(i);
            } else if e.path.source.remote_addr == source.remote_addr {
                // Count peer paths that are NOT the one being replaced.
                peer_has_path = true;
            }
        }
        let replaced = replaced_idx.map(|i| dst.entry.remove(i));
        // A prefix is "new" for this peer when neither a replacement was found nor
        // does the peer have any other path for this prefix (including Add-Path paths
        // with different path IDs).  This correctly counts unique prefixes per peer.
        let is_new = replaced.is_none() && !peer_has_path;

        // Get mutable stats entry once for this (peer, family).
        let (received, accepted) = self
            .route_stats
            .entry(source.remote_addr)
            .or_default()
            .entry(family)
            .or_insert((0, 0));

        // 3. Check the per-peer prefix limit for new prefixes.
        //    Replacements and additional Add-Path paths for an already-known prefix
        //    are always accepted regardless of the limit.
        #[allow(clippy::collapsible_if)]
        if is_new {
            if let Some((max, counter)) = prefix_limit {
                if counter.load(Ordering::Relaxed) >= max as u64 {
                    // Do not count in received: the path is not stored in the
                    // Adj-RIB-In (received reflects Adj-RIB-In current state).
                    eprintln!(
                        "prefix limit ({}) reached for peer {} family {:?}, dropping route",
                        max, source.remote_addr, family
                    );
                    return None;
                }
            }
        }

        // 4. Build and insert the path.
        let local_path_id = replaced
            .as_ref()
            .map_or_else(|| dst.alloc_path_id(), |old| old.path.local_path_id);

        let entry = RibEntry {
            path: Path {
                local_path_id,
                source: source.clone(),
                nexthop,
                attr,
            },
            id: remote_id,
            timestamp: SystemTime::now(),
            flags,
        };

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

        let idx = dst.entry.partition_point(|a| entry.cmp(a).is_ge());
        dst.entry.insert(idx, entry);

        // 5. Increment prefix counter after successful insert of a new prefix.
        #[allow(clippy::collapsible_if)]
        if is_new {
            if let Some((_, counter)) = prefix_limit {
                counter.fetch_add(1, Ordering::Relaxed);
            }
        }

        // During Restarting Speaker deferral, routes are accumulated but
        // best-path changes are suppressed; end_deferral() emits them all at once.
        if deferring {
            return None;
        }

        // Compute change flags.
        let new_best_id = dst.unfiltered_best().map(|p| p.path.local_path_id);
        let replaced_was_best = replaced
            .as_ref()
            .is_some_and(|r| Some(r.path.local_path_id) == old_best_id && !r.is_filtered());
        let best_changed = old_best_id != new_best_id || replaced_was_best;
        let any_changed = !filtered || replaced.as_ref().is_some_and(|r| !r.is_filtered());
        if !best_changed && !any_changed {
            return None;
        }
        let replaced_path_id = replaced.as_ref().map(|r| r.path.local_path_id);

        let current_paths = Arc::new(dst.unfiltered_iter().map(|e| e.path.clone()).collect());

        Some(NlriChange {
            family,
            net,
            best_changed,
            any_changed,
            replaced_path_id,
            current_paths,
        })
    }

    /// Set the deferral flag for `family`: best-path changes from `insert()` are
    /// suppressed until `end_deferral()` is called.
    pub fn start_deferral(&mut self, family: Family) {
        self.ribs.entry(family).or_default().deferring = true;
    }

    /// Clear the deferral flag for `family` and return one NlriChange per
    /// destination with all current unfiltered paths ready for distribution.
    pub fn end_deferral(&mut self, family: Family) -> Vec<NlriChange> {
        if let Some(ft) = self.ribs.get_mut(&family) {
            ft.deferring = false;
        }
        self.best_paths(&family)
            .into_iter()
            .map(|(net, paths)| NlriChange {
                family,
                net,
                best_changed: true,
                any_changed: true,
                replaced_path_id: None,
                current_paths: Arc::new(paths),
            })
            .collect()
    }

    pub fn remove(
        &mut self,
        source: Arc<Source>,
        family: Family,
        net: packet::Nlri,
        remote_id: u32,
        prefix_counter: Option<&Arc<AtomicU64>>,
    ) -> Option<NlriChange> {
        let rt = self.ribs.get_mut(&family)?;
        let dst = rt.destinations.get_mut(&net)?;
        let i = dst
            .entry
            .iter()
            .position(|e| Arc::ptr_eq(&e.path.source, &source) && e.id == remote_id)?;

        // Capture old best path id and whether the removed path was unfiltered.
        let old_best_id: Option<u32> = dst.unfiltered_best().map(|p| p.path.local_path_id);
        let was_unfiltered = !dst.entry[i].is_filtered();

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

        // Decrement prefix counter if this peer has no more paths for this prefix.
        let peer_still_has_path = dst
            .entry
            .iter()
            .any(|p| p.path.source.remote_addr == source.remote_addr);
        #[allow(clippy::collapsible_if)]
        if !peer_still_has_path {
            if let Some(counter) = prefix_counter {
                counter.fetch_sub(1, Ordering::Relaxed);
            }
        }

        if dst.entry.is_empty() {
            rt.destinations.remove(&net);
            return if was_unfiltered {
                Some(NlriChange {
                    family,
                    net,
                    best_changed: true,
                    any_changed: true,
                    replaced_path_id: None,
                    current_paths: Arc::new(vec![]),
                })
            } else {
                None
            };
        }

        let new_best_id = dst.unfiltered_best().map(|p| p.path.local_path_id);
        let best_changed = old_best_id != new_best_id;
        let any_changed = was_unfiltered;

        if !best_changed && !any_changed {
            return None;
        }

        let current_paths = Arc::new(dst.unfiltered_iter().map(|e| e.path.clone()).collect());

        Some(NlriChange {
            family,
            net,
            best_changed,
            any_changed,
            replaced_path_id: None,
            current_paths,
        })
    }

    pub fn drop(&mut self, addr: IpAddr, family: Family) -> Vec<NlriChange> {
        let mut changes = Vec::new();
        if let Some(fm) = self.route_stats.get_mut(&addr) {
            fm.remove(&family);
            if fm.is_empty() {
                self.route_stats.remove(&addr);
            }
        }
        if let Some(rt) = self.ribs.get_mut(&family) {
            rt.destinations.retain(|net, dst| {
                if !dst.entry.iter().any(|e| e.path.source.remote_addr == addr) {
                    return true;
                }
                let old_best_id = dst.unfiltered_best().map(|e| e.path.local_path_id);
                let removed_any_unfiltered = dst
                    .entry
                    .iter()
                    .any(|e| e.path.source.remote_addr == addr && !e.is_filtered());

                dst.entry.retain(|e| e.path.source.remote_addr != addr);

                if !removed_any_unfiltered {
                    return !dst.entry.is_empty();
                }

                if dst.entry.is_empty() {
                    changes.push(NlriChange {
                        family,
                        net: *net,
                        best_changed: true,
                        any_changed: true,
                        replaced_path_id: None,
                        current_paths: Arc::new(vec![]),
                    });
                    return false;
                }

                let new_best_id = dst.unfiltered_best().map(|e| e.path.local_path_id);
                let current_paths = Arc::new(
                    dst.entry
                        .iter()
                        .filter(|e| !e.is_filtered())
                        .map(|e| e.path.clone())
                        .collect(),
                );
                changes.push(NlriChange {
                    family,
                    net: *net,
                    best_changed: old_best_id != new_best_id,
                    any_changed: true,
                    replaced_path_id: None,
                    current_paths,
                });
                true
            });
        }
        changes
    }

    /// Remove only stale paths from `addr` in `family` and re-run best-path
    /// selection.  Used by GR helpers after EOR or deferral timer expiry, where
    /// the peer may have already sent fresh routes in the new session that must
    /// not be disturbed.
    pub fn drop_stale(
        &mut self,
        addr: IpAddr,
        family: Family,
        prefix_counter: Option<&Arc<AtomicU64>>,
    ) -> Vec<NlriChange> {
        let mut changes = Vec::new();
        if let Some(rt) = self.ribs.get_mut(&family) {
            rt.destinations.retain(|net, dst| {
                if !dst
                    .entry
                    .iter()
                    .any(|e| e.path.source.remote_addr == addr && e.path.source.is_stale())
                {
                    return true;
                }

                let old_best_id = dst.unfiltered_best().map(|e| e.path.local_path_id);
                let removed_any_unfiltered = dst.entry.iter().any(|e| {
                    e.path.source.remote_addr == addr
                        && e.path.source.is_stale()
                        && !e.is_filtered()
                });

                dst.entry
                    .retain(|e| !(e.path.source.remote_addr == addr && e.path.source.is_stale()));

                // Decrement prefix counter if peer has no more paths for this prefix.
                let peer_still_has_path =
                    dst.entry.iter().any(|p| p.path.source.remote_addr == addr);
                #[allow(clippy::collapsible_if)]
                if !peer_still_has_path {
                    if let Some(counter) = prefix_counter {
                        counter.fetch_sub(1, Ordering::Relaxed);
                    }
                }

                if !removed_any_unfiltered {
                    return !dst.entry.is_empty();
                }

                if dst.entry.is_empty() {
                    changes.push(NlriChange {
                        family,
                        net: *net,
                        best_changed: true,
                        any_changed: true,
                        replaced_path_id: None,
                        current_paths: Arc::new(vec![]),
                    });
                    return false;
                }

                let new_best_id = dst.unfiltered_best().map(|e| e.path.local_path_id);
                let current_paths = Arc::new(
                    dst.entry
                        .iter()
                        .filter(|e| !e.is_filtered())
                        .map(|e| e.path.clone())
                        .collect(),
                );
                changes.push(NlriChange {
                    family,
                    net: *net,
                    best_changed: old_best_id != new_best_id,
                    any_changed: true,
                    replaced_path_id: None,
                    current_paths,
                });
                true
            });
        }
        changes
    }

    /// Mark all paths from `addr` in `family` as stale and re-run best-path
    /// selection.  Returns one NlriChange per destination that changed.
    pub fn restale(&mut self, addr: IpAddr, family: Family) -> Vec<NlriChange> {
        let mut changes = Vec::new();
        if let Some(rt) = self.ribs.get_mut(&family) {
            for (net, dst) in rt.destinations.iter_mut() {
                if !dst.entry.iter().any(|p| p.path.source.remote_addr == addr) {
                    continue;
                }
                let old_best_id = dst.unfiltered_best().map(|e| e.path.local_path_id);
                // Track whether any unfiltered path from addr exists (any rank may shift).
                let any_unfiltered_from_addr = dst
                    .entry
                    .iter()
                    .any(|e| e.path.source.remote_addr == addr && !e.is_filtered());
                for p in dst.entry.iter() {
                    if p.path.source.remote_addr == addr {
                        p.path.source.mark_stale();
                    }
                }
                dst.entry.sort_unstable();
                let new_best_id = dst.unfiltered_best().map(|e| e.path.local_path_id);
                let best_changed = old_best_id != new_best_id;
                // Emit NlriChange when best changed (non-Add-Path) or any unfiltered
                // path from addr existed (Add-Path peers may need rank-boundary updates).
                if best_changed || any_unfiltered_from_addr {
                    let current_paths = Arc::new(
                        dst.entry
                            .iter()
                            .filter(|e| !e.is_filtered())
                            .map(|e| e.path.clone())
                            .collect(),
                    );
                    changes.push(NlriChange {
                        family,
                        net: *net,
                        best_changed,
                        any_changed: any_unfiltered_from_addr,
                        replaced_path_id: None,
                        current_paths,
                    });
                }
            }
        }
        changes
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
                    packet::Nlri::Mup(_) => {}
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
                    packet::Nlri::Mup(_) => return None,
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

    /// Flat list of (nlri, path, rank) from best_paths(), sorted by nlri then rank.
    /// Replaces old rt.best() which returned a flat Vec<Change>.
    fn flat_best(rt: &Table, family: &Family) -> Vec<(packet::Nlri, Path, usize)> {
        let mut result = Vec::new();
        for (net, paths) in rt.best_paths(family) {
            for (i, path) in paths.into_iter().enumerate() {
                result.push((net, path, i + 1));
            }
        }
        result
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

        let mut rt = Table::new();
        let family = Family::IPV4;
        let attrs = Arc::new(Vec::new());

        rt.insert(s1.clone(), family, n1, 0, nh(), attrs.clone(), false, None);
        rt.insert(s2, family, n1, 0, nh(), attrs.clone(), false, None);
        rt.insert(s1.clone(), family, n2, 0, nh(), attrs.clone(), false, None);
        rt.insert(s1.clone(), family, n3, 0, nh(), attrs.clone(), false, None);

        assert_eq!(rt.ribs.get(&family).unwrap().destinations.len(), 3);
        rt.drop(s1.remote_addr, family);
        assert_eq!(rt.ribs.get(&family).unwrap().destinations.len(), 1);
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
        let mut rt = Table::new();
        let update = rt.insert(
            source(1, 65001, 65000, 1),
            Family::IPV4,
            nlri(10, 0, 0, 0, 24),
            0,
            nh(),
            empty_attrs(),
            false,
            None,
        );
        assert!(update.as_ref().unwrap().any_changed);
        assert!(update.as_ref().unwrap().best_changed);
    }

    #[test]
    fn insert_same_nlri_no_best_change() {
        let mut rt = Table::new();
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
            None,
        );
        // Insert with router_id=2 (higher, won't become best)
        let update = rt.insert(
            source(2, 65002, 65000, 2),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            false,
            None,
        );
        // Best did not change; second path entered current_paths at index 1
        assert!(!update.as_ref().unwrap().best_changed);
        assert!(update.as_ref().unwrap().any_changed);
        assert_eq!(update.as_ref().unwrap().current_paths.len(), 2);
    }

    // --- best path selection ---

    #[test]
    fn best_path_local_pref() {
        let mut rt = Table::new();
        let net = nlri(10, 0, 0, 0, 24);
        rt.insert(
            source(1, 65001, 65000, 1),
            Family::IPV4,
            net,
            0,
            nh(),
            attrs_with_local_pref(100),
            false,
            None,
        );
        let update = rt.insert(
            source(2, 65002, 65000, 2),
            Family::IPV4,
            net,
            0,
            nh(),
            attrs_with_local_pref(200),
            false,
            None,
        );
        // Higher local_pref wins → best changes to source 2
        assert!(update.as_ref().unwrap().best_changed);
        let best = update.as_ref().unwrap().new_best().unwrap();
        assert_eq!(
            best.source.remote_addr,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        );
    }

    #[test]
    fn best_path_as_path_length() {
        let mut rt = Table::new();
        let net = nlri(10, 0, 0, 0, 24);
        rt.insert(
            source(1, 65001, 65000, 1),
            Family::IPV4,
            net,
            0,
            nh(),
            attrs_with_as_path_len(3),
            false,
            None,
        );
        let update = rt.insert(
            source(2, 65002, 65000, 2),
            Family::IPV4,
            net,
            0,
            nh(),
            attrs_with_as_path_len(1),
            false,
            None,
        );
        // Shorter AS path wins
        assert!(update.as_ref().unwrap().best_changed);
        let best = update.as_ref().unwrap().new_best().unwrap();
        assert_eq!(
            best.source.remote_addr,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        );
    }

    #[test]
    fn best_path_origin() {
        let mut rt = Table::new();
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
            None,
        );
        // Insert with ORIGIN=IGP(0), router_id=2
        let update = rt.insert(
            source(2, 65002, 65000, 2),
            Family::IPV4,
            net,
            0,
            nh(),
            attrs_with_origin(0),
            false,
            None,
        );
        // IGP (lower origin value) wins
        assert!(update.as_ref().unwrap().best_changed);
        let best = update.as_ref().unwrap().new_best().unwrap();
        assert_eq!(
            best.source.remote_addr,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        );
    }

    #[test]
    fn best_path_ebgp_over_ibgp() {
        let mut rt = Table::new();
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
            None,
        );
        // eBGP peer (remote_asn != local_asn), router_id=2 (higher)
        let update = rt.insert(
            source(2, 65001, 65000, 2),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            false,
            None,
        );
        // eBGP wins even though router_id is higher
        assert!(update.as_ref().unwrap().best_changed);
        let best = update.as_ref().unwrap().new_best().unwrap();
        assert_eq!(
            best.source.remote_addr,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        );
    }

    #[test]
    fn best_path_router_id() {
        let mut rt = Table::new();
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
            None,
        );
        // router_id=5 (lower wins)
        let update = rt.insert(
            source(2, 65002, 65000, 5),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            false,
            None,
        );
        assert!(update.as_ref().unwrap().best_changed);
        let best = update.as_ref().unwrap().new_best().unwrap();
        assert_eq!(
            best.source.remote_addr,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        );
    }

    // --- remove ---

    #[test]
    fn remove_best_path() {
        let mut rt = Table::new();
        let net = nlri(10, 0, 0, 0, 24);
        let s1 = source(1, 65001, 65000, 1);
        let s2 = source(2, 65002, 65000, 2);
        rt.insert(
            s1.clone(),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            false,
            None,
        );
        rt.insert(
            s2.clone(),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            false,
            None,
        );
        // Remove best (router_id=1) → s2 promoted to best
        let update = rt.remove(s1, Family::IPV4, net, 0, None);
        assert!(update.as_ref().unwrap().best_changed);
        let best = update.as_ref().unwrap().new_best().unwrap();
        assert_eq!(
            best.source.remote_addr,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        );
    }

    #[test]
    fn remove_non_best_path() {
        let mut rt = Table::new();
        let net = nlri(10, 0, 0, 0, 24);
        let s1 = source(1, 65001, 65000, 1);
        let s2 = source(2, 65002, 65000, 2);
        rt.insert(
            s1.clone(),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            false,
            None,
        );
        rt.insert(
            s2.clone(),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            false,
            None,
        );
        // Remove non-best (router_id=2) → best unchanged, s1 still best
        let update = rt.remove(s2, Family::IPV4, net, 0, None);
        assert!(!update.as_ref().unwrap().best_changed);
        assert!(update.as_ref().unwrap().any_changed);
        let best = update.as_ref().unwrap().new_best().unwrap();
        assert_eq!(
            best.source.remote_addr,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
        );
    }

    #[test]
    fn remove_last_path() {
        let mut rt = Table::new();
        let net = nlri(10, 0, 0, 0, 24);
        let s1 = source(1, 65001, 65000, 1);
        rt.insert(
            s1.clone(),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            false,
            None,
        );
        let update = rt.remove(s1, Family::IPV4, net, 0, None);
        // Withdrawal: best gone
        assert!(update.as_ref().unwrap().best_changed);
        assert!(update.as_ref().unwrap().new_best().is_none());
    }

    // --- filtered ---

    #[test]
    fn filtered_path_no_change() {
        let mut rt = Table::new();
        let net = nlri(10, 0, 0, 0, 24);
        // Only filtered path → no best change, no any_changed
        let update = rt.insert(
            source(1, 65001, 65000, 1),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            true,
            None,
        );
        assert!(update.is_none(), "filtered-only insert must be a no-op");

        // Unfiltered path added → best changes, new_best points to the unfiltered path
        let s2 = source(2, 65002, 65000, 2);
        let update = rt.insert(
            s2.clone(),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            false,
            None,
        );
        assert!(update.as_ref().unwrap().best_changed);
        let best = update.as_ref().unwrap().new_best().unwrap();
        assert!(Arc::ptr_eq(&best.source, &s2));
    }

    // A2: filtered at head, insert unfiltered behind existing unfiltered best
    #[test]
    fn filtered_head_insert_unfiltered_non_best() {
        let mut rt = Table::new();
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
            None,
        );
        // unfiltered best (router_id=2)
        let s2 = source(2, 65002, 65000, 2);
        let update = rt.insert(
            s2.clone(),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            false,
            None,
        );
        assert!(update.as_ref().unwrap().best_changed);
        let best = update.as_ref().unwrap().new_best().unwrap();
        assert!(Arc::ptr_eq(&best.source, &s2));
        // another unfiltered but worse (router_id=3) → best unchanged, but any_changed
        let update = rt.insert(
            source(3, 65003, 65000, 3),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            false,
            None,
        );
        assert!(!update.as_ref().unwrap().best_changed);
        assert!(update.as_ref().unwrap().any_changed);
        assert_eq!(update.as_ref().unwrap().current_paths.len(), 2);
    }

    // B1: replace filtered path at index 0 → unfiltered best unchanged
    #[test]
    fn replace_filtered_head_no_best_change() {
        let mut rt = Table::new();
        let net = nlri(10, 0, 0, 0, 24);
        let s1 = source(1, 65001, 65000, 1);
        // filtered at head
        rt.insert(
            s1.clone(),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            true,
            None,
        );
        // unfiltered best
        rt.insert(
            source(2, 65002, 65000, 2),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            false,
            None,
        );
        // replace the filtered head with updated attrs (still filtered) → no best change, no any_changed
        let update = rt.insert(
            s1,
            Family::IPV4,
            net,
            0,
            nh(),
            attrs_with_local_pref(200),
            true,
            None,
        );
        assert!(
            update.is_none(),
            "filtered-to-filtered replace must be a no-op"
        );
    }

    // B2: replace unfiltered best with filtered → best changes to another unfiltered
    #[test]
    fn replace_unfiltered_best_changes() {
        let mut rt = Table::new();
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
            None,
        );
        // unfiltered best (router_id=1)
        rt.insert(
            s1.clone(),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            false,
            None,
        );
        // another unfiltered (router_id=2)
        let s2 = source(2, 65002, 65000, 2);
        rt.insert(
            s2.clone(),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            false,
            None,
        );
        // replace s1 as filtered → s2 becomes unfiltered best
        let update = rt.insert(s1, Family::IPV4, net, 0, nh(), empty_attrs(), true, None);
        assert!(update.as_ref().unwrap().best_changed);
        let best = update.as_ref().unwrap().new_best().unwrap();
        assert!(Arc::ptr_eq(&best.source, &s2));
    }

    // B3: replace unfiltered non-best → no best change, but any_changed
    #[test]
    fn replace_unfiltered_non_best_no_change() {
        let mut rt = Table::new();
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
            None,
        );
        // unfiltered best (router_id=1)
        let s1 = source(1, 65001, 65000, 1);
        rt.insert(
            s1.clone(),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            false,
            None,
        );
        // unfiltered non-best (router_id=2)
        let s2 = source(2, 65002, 65000, 2);
        rt.insert(
            s2.clone(),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            false,
            None,
        );
        // replace s2 with different attrs → still non-best
        let update = rt.insert(
            s2,
            Family::IPV4,
            net,
            0,
            nh(),
            attrs_with_local_pref(50),
            false,
            None,
        );
        assert!(!update.as_ref().unwrap().best_changed);
        assert!(update.as_ref().unwrap().any_changed);
        // s1 is still best
        let best = update.as_ref().unwrap().new_best().unwrap();
        assert!(Arc::ptr_eq(&best.source, &s1));
    }

    #[test]
    fn filtered_path_peer_stats() {
        let mut rt = Table::new();
        let net = nlri(10, 0, 0, 0, 24);
        let s1 = source(1, 65001, 65000, 1);
        rt.insert(
            s1.clone(),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            true,
            None,
        );
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
        let mut rt = Table::new();
        let s1 = source(1, 65001, 65000, 1);
        rt.insert(
            s1.clone(),
            Family::IPV4,
            nlri(10, 0, 0, 0, 24),
            0,
            nh(),
            empty_attrs(),
            false,
            None,
        );
        rt.insert(
            s1.clone(),
            Family::IPV4,
            nlri(10, 0, 1, 0, 24),
            0,
            nh(),
            empty_attrs(),
            false,
            None,
        );
        rt.insert(
            s1.clone(),
            Family::IPV4,
            nlri(10, 0, 2, 0, 24),
            0,
            nh(),
            empty_attrs(),
            false,
            None,
        );
        assert_eq!(flat_best(&rt, &Family::IPV4).len(), 3);
    }

    // --- policy ---

    #[test]
    fn policy_prefix_reject() {
        let rt = Table::new();
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
                "ribs",
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
        let rt = Table::new();
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
                "ribs",
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
        let rt = Table::new();
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
                "ribs",
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
        let rt = Table::new();
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
                "ribs",
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
        let rt = Table::new();
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
                "ribs",
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
        let mut rt = Table::new();
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
            None,
        );
        // s2: local_pref=50, router_id=1 (better router_id, worse local_pref)
        let s2 = source(2, 65002, 65000, 1);
        let update = rt.insert(
            s2,
            Family::IPV4,
            net,
            0,
            nh(),
            attrs_with_local_pref(50),
            false,
            None,
        );
        // s1 must remain best (higher local_pref wins over lower router_id)
        // s2 enters as a new current path, best unchanged
        assert!(!update.as_ref().unwrap().best_changed);
        assert!(update.as_ref().unwrap().any_changed);
        let best = update.as_ref().unwrap().new_best().unwrap();
        assert!(Arc::ptr_eq(&best.source, &s1));
    }

    #[test]
    fn replace_unfiltered_to_filtered_withdraws() {
        let mut rt = Table::new();
        let net = nlri(10, 0, 0, 0, 24);
        let s1 = source(1, 65001, 65000, 1);
        // Insert unfiltered path
        let update = rt.insert(
            s1.clone(),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            false,
            None,
        );
        assert!(update.as_ref().unwrap().best_changed);
        // Replace with filtered → no unfiltered best remains → best_changed, new_best=None
        let update = rt.insert(s1, Family::IPV4, net, 0, nh(), empty_attrs(), true, None);
        assert!(update.as_ref().unwrap().best_changed);
        assert!(update.as_ref().unwrap().new_best().is_none());
    }

    #[test]
    fn withdraw_source_is_old_best() {
        // When all paths become filtered, the update should indicate best_changed and new_best=None.
        let mut rt = Table::new();
        let net = nlri(10, 0, 0, 0, 24);
        let s1 = source(1, 65001, 65000, 1);
        // s1 is unfiltered best
        rt.insert(
            s1.clone(),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            false,
            None,
        );
        // s2 inserts a filtered path
        let s2 = source(2, 65002, 65000, 2);
        rt.insert(
            s2.clone(),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            true,
            None,
        );
        // s1 gets replaced as filtered → all filtered → withdrawal
        let update = rt.insert(
            s1.clone(),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            true,
            None,
        );
        assert!(update.as_ref().unwrap().best_changed);
        assert!(update.as_ref().unwrap().new_best().is_none());
    }

    // --- best() with filtered head ---

    #[test]
    fn best_skips_filtered_paths() {
        let mut rt = Table::new();
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
            None,
        );
        // unfiltered path
        let s2 = source(2, 65002, 65000, 2);
        rt.insert(
            s2.clone(),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            false,
            None,
        );
        let bests = flat_best(&rt, &Family::IPV4);
        assert_eq!(bests.len(), 1);
        assert!(Arc::ptr_eq(&bests[0].1.source, &s2));
    }

    #[test]
    fn best_skips_all_filtered_destination() {
        let mut rt = Table::new();
        let net = nlri(10, 0, 0, 0, 24);
        rt.insert(
            source(1, 65001, 65000, 1),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            true,
            None,
        );
        assert!(rt.best_paths(&Family::IPV4).is_empty());
    }

    // --- remove() with filtered head ---

    #[test]
    fn remove_best_with_filtered_head() {
        let mut rt = Table::new();
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
            None,
        );
        // unfiltered best (router_id=2)
        let s2 = source(2, 65002, 65000, 2);
        rt.insert(
            s2.clone(),
            Family::IPV4,
            net,
            0,
            nh(),
            attrs.clone(),
            false,
            None,
        );
        // unfiltered non-best (router_id=3)
        let s3 = source(3, 65003, 65000, 3);
        rt.insert(
            s3.clone(),
            Family::IPV4,
            net,
            0,
            nh(),
            attrs.clone(),
            false,
            None,
        );
        // remove s2 (best) → s3 becomes new best
        let update = rt.remove(s2, Family::IPV4, net, 0, None);
        assert!(update.as_ref().unwrap().best_changed);
        let best = update.as_ref().unwrap().new_best().unwrap();
        assert!(Arc::ptr_eq(&best.source, &s3));
    }

    #[test]
    fn remove_last_unfiltered_withdraws() {
        let mut rt = Table::new();
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
            None,
        );
        // only unfiltered path
        let s2 = source(2, 65002, 65000, 2);
        rt.insert(
            s2.clone(),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            false,
            None,
        );
        // remove s2 → all filtered → withdrawal (best_changed=true, new_best=None)
        let update = rt.remove(s2, Family::IPV4, net, 0, None);
        assert!(update.as_ref().unwrap().best_changed);
        assert!(update.as_ref().unwrap().new_best().is_none());
    }

    // --- drop() with filtered head ---

    #[test]
    fn drop_best_with_filtered_head() {
        let mut rt = Table::new();
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
            None,
        );
        // unfiltered best
        let s2 = source(2, 65002, 65000, 2);
        rt.insert(
            s2.clone(),
            Family::IPV4,
            net,
            0,
            nh(),
            attrs.clone(),
            false,
            None,
        );
        // unfiltered non-best
        let s3 = source(3, 65003, 65000, 3);
        rt.insert(
            s3.clone(),
            Family::IPV4,
            net,
            0,
            nh(),
            attrs.clone(),
            false,
            None,
        );
        // drop s2 → s3 becomes new best
        let changes = rt.drop(s2.remote_addr, Family::IPV4);
        assert_eq!(changes.len(), 1);
        assert!(changes[0].best_changed);
        let best = changes[0].new_best().unwrap();
        assert!(Arc::ptr_eq(&best.source, &s3));
    }

    #[test]
    fn drop_filtered_no_change() {
        let mut rt = Table::new();
        let net = nlri(10, 0, 0, 0, 24);
        // filtered path from s1
        let s1 = source(1, 65001, 65000, 1);
        rt.insert(
            s1.clone(),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            true,
            None,
        );
        // unfiltered best from s2
        let s2 = source(2, 65002, 65000, 2);
        rt.insert(s2, Family::IPV4, net, 0, nh(), empty_attrs(), false, None);
        // drop s1 (filtered) → no best change
        let changes = rt.drop(s1.remote_addr, Family::IPV4);
        assert!(changes.is_empty());
    }

    // --- iter_destinations AdjOut with filtered head ---

    #[test]
    fn adj_out_skips_filtered_head() {
        let mut rt = Table::new();
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
            None,
        );
        // unfiltered path → should be the AdjOut best
        let s2 = source(2, 65002, 65000, 2);
        rt.insert(
            s2.clone(),
            Family::IPV4,
            net,
            0,
            nh(),
            attrs.clone(),
            false,
            None,
        );

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
        let mut rt = Table::new();
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
            None,
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
        let mut rt = Table::new();
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
            None,
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
            None,
        );
        let s = rt.state(Family::IPV4);
        assert_eq!(s.num_destination, 1);
        assert_eq!(s.num_path, 2);
        assert_eq!(s.num_accepted, 1);
    }

    // --- stable path IDs ---

    #[test]
    fn stable_id_new_best_no_churn() {
        // Inserting a new best should update best and current_paths correctly.
        let mut rt = Table::new();
        let net = nlri(10, 0, 0, 0, 24);
        let s1 = source(1, 65001, 65000, 10); // router_id=10
        let s2 = source(2, 65002, 65000, 5); // router_id=5, better

        // Insert s1 → best, local_path_id=1
        let update = rt.insert(
            s1.clone(),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            false,
            None,
        );
        assert!(update.as_ref().unwrap().best_changed);
        let best = update.as_ref().unwrap().new_best().unwrap();
        assert_eq!(best.local_path_id, 1);

        // Insert s2 → new best (lower router_id)
        let update = rt.insert(
            s2.clone(),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            false,
            None,
        );
        assert!(update.as_ref().unwrap().best_changed);
        assert_eq!(update.as_ref().unwrap().current_paths.len(), 2);
        // s2 is the new best (rank 0 in current_paths)
        assert_eq!(
            update.as_ref().unwrap().new_best().unwrap().local_path_id,
            2
        );
        assert!(Arc::ptr_eq(
            &update.as_ref().unwrap().new_best().unwrap().source,
            &s2
        ));
        // s1 is at index 1 in current_paths
        let s1_path = update
            .as_ref()
            .unwrap()
            .current_paths
            .iter()
            .find(|p| p.local_path_id == 1)
            .unwrap();
        assert!(Arc::ptr_eq(&s1_path.source, &s1));
    }

    #[test]
    fn stable_id_preserved_on_replacement() {
        // Replacing a path's attributes preserves its stable local_path_id.
        let mut rt = Table::new();
        let net = nlri(10, 0, 0, 0, 24);
        let s1 = source(1, 65001, 65000, 1);

        let update = rt.insert(
            s1.clone(),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            false,
            None,
        );
        let original_id = update.as_ref().unwrap().new_best().unwrap().local_path_id;

        // Replace with new attributes
        let update = rt.insert(
            s1.clone(),
            Family::IPV4,
            net,
            0,
            nh(),
            attrs_with_local_pref(200),
            false,
            None,
        );
        // Same path_id preserved, replaced_path_id indicates what was replaced
        assert_eq!(update.as_ref().unwrap().replaced_path_id, Some(original_id));
        let best = update.as_ref().unwrap().new_best().unwrap();
        assert_eq!(best.local_path_id, original_id);
    }

    #[test]
    fn stable_id_withdraw_uses_original_id() {
        // When a path is removed, the update indicates best_changed and the new best.
        let mut rt = Table::new();
        let net = nlri(10, 0, 0, 0, 24);

        let s1 = source(1, 65001, 65000, 1); // best (router_id=1)
        let s2 = source(2, 65002, 65000, 2);
        let u1 = rt.insert(
            s1.clone(),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            false,
            None,
        );
        let s1_id = u1.as_ref().unwrap().new_best().unwrap().local_path_id;
        rt.insert(
            s2.clone(),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            false,
            None,
        );

        // Remove s1 → s2 becomes new best; s1_id was the old best
        let update = rt.remove(s1, Family::IPV4, net, 0, None);
        assert!(update.as_ref().unwrap().best_changed);
        // s1_id (1) is no longer in current_paths
        assert!(
            !update
                .as_ref()
                .unwrap()
                .current_paths
                .iter()
                .any(|p| p.local_path_id == s1_id)
        );
        // s2 is the new best
        let best = update.as_ref().unwrap().new_best().unwrap();
        assert_eq!(best.local_path_id, 2);
    }

    #[test]
    fn stable_id_best_uses_stored_ids() {
        let mut rt = Table::new();
        let net = nlri(10, 0, 0, 0, 24);
        let s1 = source(1, 65001, 65000, 1);
        let s2 = source(2, 65002, 65000, 2);

        rt.insert(
            s1.clone(),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            false,
            None,
        );
        rt.insert(
            s2.clone(),
            Family::IPV4,
            net,
            0,
            nh(),
            empty_attrs(),
            false,
            None,
        );

        let best = flat_best(&rt, &Family::IPV4);
        assert_eq!(best.len(), 2);
        // IDs should be stable (1 and 2), not re-computed from rank
        let ids: Vec<u32> = best.iter().map(|(_, p, _)| p.local_path_id).collect();
        assert!(ids.contains(&1));
        assert!(ids.contains(&2));
    }

    // --- GR stale ---

    #[test]
    fn mark_stale_sets_flag() {
        let s = source(1, 65001, 65000, 1);
        assert!(!s.is_stale());
        s.mark_stale();
        assert!(s.is_stale());
    }

    #[test]
    fn stale_routes_still_returned_by_best() {
        let mut rt = Table::new();
        let net = nlri(10, 0, 0, 0, 24);
        let s = source(1, 65001, 65000, 1);
        rt.insert(
            s.clone(),
            Family::IPV4,
            net,
            0,
            nh(),
            attrs_with_origin(0),
            false,
            None,
        );

        s.mark_stale();

        let best = flat_best(&rt, &Family::IPV4);
        assert_eq!(best.len(), 1);
        assert!(best[0].1.source.is_stale());
    }

    #[test]
    fn fresh_and_stale_compete_in_best_path() {
        // Simulate GR: existing route is marked stale, then a fresh route arrives
        // from a different peer. The fresh peer has a higher router_id (worse
        // tie-breaker) but must win because non-stale beats stale.
        let mut rt = Table::new();
        let net = nlri(10, 0, 0, 0, 24);
        let stale_src = source(1, 65001, 65000, 1); // router_id=1 (better tie-breaker)
        let fresh_src = source(2, 65002, 65000, 2); // router_id=2 (worse tie-breaker)

        rt.insert(
            stale_src.clone(),
            Family::IPV4,
            net,
            0,
            nh(),
            attrs_with_origin(0),
            false,
            None,
        );

        // Mark stale before the fresh route arrives (as GR does after session drop)
        stale_src.mark_stale();

        rt.insert(
            fresh_src.clone(),
            Family::IPV4,
            net,
            0,
            nh(),
            attrs_with_origin(0),
            false,
            None,
        );

        let best = flat_best(&rt, &Family::IPV4);
        assert_eq!(best.len(), 2);
        // rank=1 (best) should be the fresh source despite worse router_id
        let winner = best.iter().find(|(_, _, r)| *r == 1).unwrap();
        assert!(!winner.1.source.is_stale());
        let loser = best.iter().find(|(_, _, r)| *r == 2).unwrap();
        assert!(loser.1.source.is_stale());
    }

    #[test]
    fn drop_stale_source_removes_routes() {
        let mut rt = Table::new();
        let net = nlri(10, 0, 0, 0, 24);
        let s = source(1, 65001, 65000, 1);
        rt.insert(
            s.clone(),
            Family::IPV4,
            net,
            0,
            nh(),
            attrs_with_origin(0),
            false,
            None,
        );

        s.mark_stale();
        assert_eq!(flat_best(&rt, &Family::IPV4).len(), 1);

        rt.drop(s.remote_addr, Family::IPV4);
        assert!(rt.best_paths(&Family::IPV4).is_empty());
    }

    // --- drop_stale ---

    #[test]
    fn drop_stale_removes_only_stale_paths_keeps_fresh() {
        // fresh_src and stale_src have routes for the same prefix.
        // drop_stale should remove the stale route but leave the fresh one.
        let mut rt = Table::new();
        let net = nlri(10, 0, 0, 0, 24);
        let stale_src = source(1, 65001, 65000, 1);
        let fresh_src = source(2, 65001, 65000, 2);

        rt.insert(
            stale_src.clone(),
            Family::IPV4,
            net,
            0,
            nh(),
            attrs_with_origin(0),
            false,
            None,
        );
        rt.insert(
            fresh_src.clone(),
            Family::IPV4,
            net,
            0,
            nh(),
            attrs_with_origin(0),
            false,
            None,
        );

        stale_src.mark_stale();
        let changes = rt.drop_stale(stale_src.remote_addr, Family::IPV4, None);

        // The stale path is gone but the fresh one remains as rank=1.
        let best = flat_best(&rt, &Family::IPV4);
        assert_eq!(best.len(), 1);
        assert_eq!(best[0].2, 1);
        assert_eq!(best[0].1.source.remote_addr, fresh_src.remote_addr);

        // A path-change event is emitted because the best path shifted.
        assert!(!changes.is_empty());
    }

    #[test]
    fn drop_stale_removes_route_when_no_fresh_alternative() {
        // Only one source; after mark_stale, drop_stale removes it completely.
        let mut rt = Table::new();
        let net = nlri(10, 0, 0, 0, 24);
        let s = source(1, 65001, 65000, 1);
        rt.insert(
            s.clone(),
            Family::IPV4,
            net,
            0,
            nh(),
            attrs_with_origin(0),
            false,
            None,
        );

        s.mark_stale();
        rt.drop_stale(s.remote_addr, Family::IPV4, None);
        assert!(rt.best_paths(&Family::IPV4).is_empty());
    }

    #[test]
    fn drop_stale_leaves_fresh_routes_untouched() {
        // Source has fresh (not stale) routes; drop_stale must not remove them.
        let mut rt = Table::new();
        let net = nlri(10, 0, 0, 0, 24);
        let s = source(1, 65001, 65000, 1);
        rt.insert(
            s.clone(),
            Family::IPV4,
            net,
            0,
            nh(),
            attrs_with_origin(0),
            false,
            None,
        );

        let changes = rt.drop_stale(s.remote_addr, Family::IPV4, None);
        assert!(changes.is_empty());
        assert_eq!(flat_best(&rt, &Family::IPV4).len(), 1);
    }

    // --- restale ---

    #[test]
    fn restale_demotes_stale_when_fresh_alternative_exists() {
        // stale source has lower router_id (normally wins), fresh source has higher.
        // After mark_stale + restale(), fresh must be rank=1.
        let mut rt = Table::new();
        let net = nlri(10, 0, 0, 0, 24);
        let stale_src = source(1, 65001, 65000, 1); // router_id 1 (better without stale)
        let fresh_src = source(2, 65001, 65000, 2); // router_id 2 (worse without stale)

        rt.insert(
            stale_src.clone(),
            Family::IPV4,
            net,
            0,
            nh(),
            attrs_with_origin(0),
            false,
            None,
        );
        rt.insert(
            fresh_src.clone(),
            Family::IPV4,
            net,
            0,
            nh(),
            attrs_with_origin(0),
            false,
            None,
        );

        // Without stale, stale_src wins (lower router_id).
        let best = flat_best(&rt, &Family::IPV4);
        assert!(
            best.iter()
                .find(|(_, _, r)| *r == 1)
                .unwrap()
                .1
                .source
                .remote_addr
                == stale_src.remote_addr
        );

        let changes = rt.restale(stale_src.remote_addr, Family::IPV4);

        // restale() must emit changes: old rank-1 (stale) loses to fresh.
        assert!(!changes.is_empty());

        let best = flat_best(&rt, &Family::IPV4);
        let winner = best.iter().find(|(_, _, r)| *r == 1).unwrap();
        assert_eq!(winner.1.source.remote_addr, fresh_src.remote_addr);
        let loser = best.iter().find(|(_, _, r)| *r == 2).unwrap();
        assert_eq!(loser.1.source.remote_addr, stale_src.remote_addr);
    }

    /// GR helper: when the same peer reconnects after a session drop and re-sends
    /// the same NLRI with the same path_id, the stale path from the old session
    /// must be replaced by the fresh path (not accumulated alongside it).
    ///
    /// Concretely: the replacement check uses remote_addr + path_id, not Arc
    /// identity, so a fresh Source (new session) correctly supersedes the stale
    /// Source (old session) for the same (peer, path_id) pair.
    #[test]
    fn gr_fresh_path_replaces_stale_on_reconnect() {
        let mut rt = Table::new();
        let net = nlri(10, 0, 0, 0, 24);

        // Session 1: insert a path, then mark it stale (simulating TCP drop + GR).
        let s1 = source(1, 65001, 65000, 1);
        rt.insert(
            s1.clone(),
            Family::IPV4,
            net,
            0, // remote_id / path_id
            nh(),
            attrs_with_origin(0),
            false,
            None,
        );
        s1.mark_stale();

        // Verify: one stale path in the table.
        {
            let best = flat_best(&rt, &Family::IPV4);
            assert_eq!(best.len(), 1);
            assert!(best[0].1.source.is_stale());
        }

        // Session 2: same peer re-establishes and re-sends the same NLRI (id=0).
        // A new Source object is created for the new session.
        let s2 = source(1, 65001, 65000, 1); // same remote_addr, different Arc
        assert!(
            !Arc::ptr_eq(&s1, &s2),
            "precondition: different Arc objects"
        );

        let update = rt.insert(
            s2.clone(),
            Family::IPV4,
            net,
            0, // same remote_id as session 1
            nh(),
            attrs_with_origin(0),
            false,
            None,
        );

        // The stale path from session 1 must be replaced, not accumulated.
        // After insert, there should be exactly one path for this NLRI.
        let best = flat_best(&rt, &Family::IPV4);
        assert_eq!(
            best.len(),
            1,
            "stale path must be replaced, not accumulated alongside fresh path"
        );
        assert!(
            !best[0].1.source.is_stale(),
            "surviving path must be the fresh one"
        );
        assert!(
            Arc::ptr_eq(&best[0].1.source, &s2),
            "surviving path must belong to session 2"
        );

        // NlriChange must signal a best-path change (old stale -> new fresh).
        let update = update.expect("insert of fresh path must produce NlriChange");
        assert!(update.best_changed);
    }

    /// GR helper, Add-Path: only the path with a matching remote_id is replaced;
    /// stale paths with other path_ids survive until drop_stale.
    #[test]
    fn gr_fresh_path_replaces_only_matching_path_id() {
        let mut rt = Table::new();
        let net = nlri(10, 0, 0, 0, 24);

        // Session 1: insert two Add-Path paths (id=1 and id=2), then go stale.
        let s1 = source(1, 65001, 65000, 1);
        rt.insert(
            s1.clone(),
            Family::IPV4,
            net,
            1,
            nh(),
            attrs_with_origin(0),
            false,
            None,
        );
        rt.insert(
            s1.clone(),
            Family::IPV4,
            net,
            2,
            nh(),
            attrs_with_origin(0),
            false,
            None,
        );
        s1.mark_stale();
        assert_eq!(flat_best(&rt, &Family::IPV4).len(), 2);

        // Session 2: re-sends only id=1.
        let s2 = source(1, 65001, 65000, 1);
        rt.insert(
            s2.clone(),
            Family::IPV4,
            net,
            1,
            nh(),
            attrs_with_origin(0),
            false,
            None,
        );

        // id=1 replaced (now fresh), id=2 still stale.
        let best = flat_best(&rt, &Family::IPV4);
        assert_eq!(best.len(), 2, "id=1 replaced + id=2 still stale = 2 paths");
        let fresh: Vec<_> = best.iter().filter(|e| !e.1.source.is_stale()).collect();
        let stale: Vec<_> = best.iter().filter(|e| e.1.source.is_stale()).collect();
        assert_eq!(fresh.len(), 1);
        assert_eq!(stale.len(), 1);
        assert!(Arc::ptr_eq(&fresh[0].1.source, &s2));
    }

    #[test]
    fn restale_no_alternative_keeps_stale_as_best() {
        // Only one source; after mark_stale + restale(), it stays as rank=1.
        let mut rt = Table::new();
        let net = nlri(10, 0, 0, 0, 24);
        let src = source(1, 65001, 65000, 1);

        rt.insert(
            src.clone(),
            Family::IPV4,
            net,
            0,
            nh(),
            attrs_with_origin(0),
            false,
            None,
        );

        let changes = rt.restale(src.remote_addr, Family::IPV4);

        // best_changed=false (sole path stays rank-1), but any_changed=true so
        // Add-Path peers can diff and confirm no boundary shift occurred.
        assert_eq!(changes.len(), 1);
        assert!(!changes[0].best_changed);
        assert!(changes[0].any_changed);

        let best = flat_best(&rt, &Family::IPV4);
        assert_eq!(best.len(), 1);
        assert_eq!(best[0].2, 1);
        assert!(best[0].1.source.is_stale());
    }

    // ---- Selection Deferral (RFC 4724 section 4.1) ----

    #[test]
    fn deferral_suppresses_insert_changes() {
        // While deferring, insert() stores the route but returns no changes.
        let mut rt = Table::new();
        let net = nlri(10, 0, 0, 0, 24);
        let src = source(1, 65001, 65000, 1);

        rt.start_deferral(Family::IPV4);

        let update = rt.insert(src, Family::IPV4, net, 0, nh(), empty_attrs(), false, None);
        assert!(update.is_none(), "deferral must suppress insert changes");
        assert!(
            rt.ribs.get(&Family::IPV4).unwrap().deferring,
            "deferring flag must be set"
        );
    }

    #[test]
    fn deferral_does_not_affect_other_families() {
        // Deferring IPv4 must not suppress IPv6 inserts.
        let mut rt = Table::new();
        let net6 = packet::Nlri::V6(packet::bgp::Ipv6Net {
            addr: std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
            mask: 32,
        });
        let src = source(1, 65001, 65000, 1);

        rt.start_deferral(Family::IPV4);

        let nh6 = bgp::Nexthop::V6(std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        let update = rt.insert(src, Family::IPV6, net6, 0, nh6, empty_attrs(), false, None);
        assert!(
            update.as_ref().unwrap().best_changed || update.as_ref().unwrap().any_changed,
            "IPv6 insert must not be suppressed"
        );
    }

    #[test]
    fn end_deferral_returns_accumulated_routes() {
        // Routes inserted during deferral are returned by end_deferral().
        let mut rt = Table::new();
        let n1 = nlri(10, 0, 0, 0, 24);
        let n2 = nlri(10, 0, 1, 0, 24);
        let src = source(1, 65001, 65000, 1);

        rt.start_deferral(Family::IPV4);

        // Both inserts are suppressed.
        {
            let u = rt.insert(
                src.clone(),
                Family::IPV4,
                n1,
                0,
                nh(),
                empty_attrs(),
                false,
                None,
            );
            assert!(u.is_none());
        }
        {
            let u = rt.insert(src, Family::IPV4, n2, 0, nh(), empty_attrs(), false, None);
            assert!(u.is_none());
        }

        // end_deferral clears flag and returns all accumulated best paths.
        let changes = rt.end_deferral(Family::IPV4);
        assert_eq!(changes.len(), 2);
        assert!(changes.iter().all(|c| c.best_changed));
        assert!(changes.iter().all(|c| c.any_changed));
        assert!(changes.iter().all(|c| c.new_best().is_some()));
        assert!(
            !rt.ribs.get(&Family::IPV4).unwrap().deferring,
            "deferring flag must be cleared"
        );
    }

    #[test]
    fn end_deferral_on_non_deferred_family_is_noop() {
        // end_deferral on a family that was never deferred returns empty.
        let mut rt = Table::new();
        let changes = rt.end_deferral(Family::IPV4);
        assert!(changes.is_empty());
    }

    #[test]
    fn insert_after_end_deferral_distributes_normally() {
        // After deferral ends, subsequent inserts produce changes as usual.
        let mut rt = Table::new();
        let net = nlri(10, 0, 0, 0, 24);
        let src = source(1, 65001, 65000, 1);

        rt.start_deferral(Family::IPV4);
        rt.end_deferral(Family::IPV4);

        let update = rt.insert(src, Family::IPV4, net, 0, nh(), empty_attrs(), false, None);
        assert!(
            update.as_ref().unwrap().best_changed || update.as_ref().unwrap().any_changed,
            "insert after end_deferral must produce changes"
        );
    }
}
