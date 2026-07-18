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
use patricia_tree::PatriciaMap;
use std::collections::HashSet;
use std::convert::Into;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr};
use std::ops::AddAssign;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};

use rustybgp_packet::{self as packet, Attribute, Family, bgp};

#[derive(Debug, thiserror::Error)]
pub enum TableError {
    #[error("argument is incorrect")]
    InvalidArgument(String),
    #[error("entity already exists")]
    AlreadyExists(String),
    #[error("entity not found")]
    NotFound,
    #[error("entity still in use")]
    StillInUse(String),
}

/// VRF (Virtual Routing and Forwarding) instance for BGP/MPLS IP VPN (RFC 4364).
///
/// Routes received from peers are imported when their extended communities
/// contain at least one RT that matches `import_rt`.  Routes injected via
/// the API are exported to the global VPN table with `rd`, `label`, and
/// the `export_rt` set attached as extended communities.
#[derive(Clone, Debug)]
pub struct Vrf {
    pub name: String,
    pub rd: packet::rd::RouteDistinguisher,
    /// Each entry is the 8-byte wire encoding of a Route Target extended
    /// community (type/sub-type + value).  Stored as raw bytes for O(1)
    /// lookup against the extended communities of incoming VPN routes.
    pub import_rt: HashSet<[u8; 8]>,
    pub export_rt: Vec<[u8; 8]>,
    pub label: packet::mpls::MplsLabel,
    /// Linux routing table ID for kernel FIB integration.  Zero means no
    /// kernel table is associated with this VRF.
    pub id: u32,
}

impl Vrf {
    /// Returns true when at least one RT in `attrs` extended communities
    /// matches this VRF's import_rt set.
    pub fn can_import(&self, attrs: &[Attribute]) -> bool {
        for attr in attrs {
            if attr.code() == Attribute::EXTENDED_COMMUNITY {
                let Some(data) = attr.binary() else {
                    continue;
                };
                for chunk in data.chunks_exact(8) {
                    let bytes: [u8; 8] = chunk.try_into().unwrap();
                    if self.import_rt.contains(&bytes) {
                        return true;
                    }
                }
            }
        }
        false
    }
}

/// Strip the VPN envelope from a VPNv4/VPNv6 NLRI, returning the plain
/// IPv4/IPv6 prefix as seen inside the VRF.
pub fn vpn_to_local_nlri(nlri: &packet::Nlri) -> Option<packet::Nlri> {
    match nlri {
        packet::Nlri::VpnV4(v) => Some(packet::Nlri::V4(v.prefix)),
        packet::Nlri::VpnV6(v) => Some(packet::Nlri::V6(v.prefix)),
        _ => None,
    }
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

/// Identifies which routing table to query and, for per-peer tables,
/// which peer to scope the query to.
#[derive(Clone, Copy)]
pub enum TableQuery {
    /// The global RIB: best paths selected from all peers.
    Global,
    /// Adj-RIB-In for the given peer: all paths received from that peer.
    AdjIn(IpAddr),
    /// Route Server local-RIB view for the given RS client: the best path
    /// from all RS-client peers excluding `peer` itself, with pre-import-policy
    /// attributes (equivalent to GoBGP TABLE_TYPE_LOCAL with an RS client address).
    RsLocal(IpAddr),
}

/// Controls how a prefix in a query is matched against RIB entries.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LookupType {
    /// Exact prefix match only.
    Exact,
    /// The RIB entry is equally or more specific than the query prefix
    /// (i.e. the RIB prefix is contained within the query prefix).
    Longer,
    /// The RIB entry is equally or less specific than the query prefix
    /// (i.e. the RIB prefix contains the query prefix).
    Shorter,
}

/// A prefix together with the match semantics to apply when filtering RIB entries.
#[derive(Clone)]
pub struct PrefixFilter {
    pub prefix: packet::Nlri,
    pub lookup_type: LookupType,
}

/// Returns true when `supernet` contains `subnet` (i.e. `subnet` is equally or
/// more specific than `supernet`).  Mixed address families always return false.
fn nlri_contains(supernet: &packet::Nlri, subnet: &packet::Nlri) -> bool {
    match (supernet, subnet) {
        (packet::Nlri::V4(sup), packet::Nlri::V4(sub)) => {
            if sup.mask > sub.mask {
                return false;
            }
            if sup.mask == 0 {
                return true;
            }
            let shift = 32 - u32::from(sup.mask);
            u32::from(sup.addr) >> shift == u32::from(sub.addr) >> shift
        }
        (packet::Nlri::V6(sup), packet::Nlri::V6(sub)) => {
            if sup.mask > sub.mask {
                return false;
            }
            if sup.mask == 0 {
                return true;
            }
            let shift = 128 - u32::from(sup.mask);
            u128::from(sup.addr) >> shift == u128::from(sub.addr) >> shift
        }
        _ => false,
    }
}

pub struct DestinationEntry {
    pub net: packet::Nlri,
    pub paths: Vec<PathEntry>,
}

/// A read-only snapshot of one BGP path, returned by [`Table::destinations`]
/// for gRPC `ListPath` responses and similar inspection APIs.
///
/// Contains display fields (timestamp, RPKI validation, policy state) that are
/// not needed for route distribution.  The nexthop is intentionally absent; it
/// is embedded in the serialised UPDATE attributes for the API response.
pub struct PathEntry {
    pub source: Arc<Source>,
    /// AddPath path identifier received from the peer (0 when AddPath is not in use).
    /// AddPath path identifier received from the peer (0 when AddPath is not in use).
    pub remote_path_id: u32,
    pub timestamp: u32,
    pub attr: Arc<Vec<packet::Attribute>>,
    pub validation: Option<RpkiValidation>,
    /// True when this path is marked stale during Graceful Restart (RFC 4724).
    pub stale: bool,
    /// True when this path was suppressed by import/export policy.
    /// Only present when the caller requested filtered paths.
    pub filtered: bool,
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

    fn attr_originator_id(&self) -> Option<u32> {
        self.attr
            .iter()
            .find(|a| a.code() == packet::Attribute::ORIGINATOR_ID)
            .map(|attr| attr.value().unwrap())
    }

    fn attr_cluster_list_length(&self) -> usize {
        self.attr
            .iter()
            .find(|a| a.code() == packet::Attribute::CLUSTER_LIST)
            .and_then(|a| a.binary())
            .map(|b| b.len() / 4)
            .unwrap_or(0)
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
/// A BGP path distributed to peer TX queues via [`NlriChange`].
///
/// Contains the fields needed to encode a BGP UPDATE message for a neighbour.
/// Display-only metadata (timestamp, RPKI validation, policy filter state) is
/// kept in [`PathEntry`], which is built on demand for read-path APIs.
pub struct Path {
    pub local_path_id: u32,
    pub source: Arc<Source>,
    pub nexthop: Option<bgp::Nexthop>,
    pub attr: Arc<Vec<packet::Attribute>>,
}

struct RibEntry {
    path: Path,
    /// Pre-import-policy attributes received from the peer (Adj-RIB-In view).
    ///
    /// When import policy does not modify attributes this Arc points to the same
    /// allocation as `path.attr`, so storing it costs only a reference-count
    /// increment.
    original_attr: Arc<Vec<packet::Attribute>>,
    remote_path_id: u32,
    timestamp: u32,
    flags: u8,
}

/// Returns true if `attrs` contains the LLGR_STALE well-known community (0xFFFF0006).
fn has_llgr_stale_community(attrs: &[packet::Attribute]) -> bool {
    const LLGR_STALE: u32 = 0xffff_0006;
    attrs
        .iter()
        .find(|a| a.code() == packet::Attribute::COMMUNITY)
        .and_then(|a| a.binary())
        .is_some_and(|bin| {
            bin.chunks(4)
                .any(|c| c.try_into().ok().map(u32::from_be_bytes) == Some(LLGR_STALE))
        })
}

/// Returns true if `attrs` contains the NO_LLGR well-known community (0xFFFF0007).
pub fn has_no_llgr_community(attrs: &[packet::Attribute]) -> bool {
    const NO_LLGR: u32 = 0xffff_0007;
    attrs
        .iter()
        .find(|a| a.code() == packet::Attribute::COMMUNITY)
        .and_then(|a| a.binary())
        .is_some_and(|bin| {
            bin.chunks(4)
                .any(|c| c.try_into().ok().map(u32::from_be_bytes) == Some(NO_LLGR))
        })
}

impl RibEntry {
    const FLAG_FILTERED: u8 = 1 << 0;
    const FLAG_NEXTHOP_INVALID: u8 = 1 << 1;

    fn is_filtered(&self) -> bool {
        self.flags & RibEntry::FLAG_FILTERED != 0
    }

    fn is_nexthop_invalid(&self) -> bool {
        self.flags & RibEntry::FLAG_NEXTHOP_INVALID != 0
    }

    fn set_nexthop_invalid(&mut self, invalid: bool) {
        if invalid {
            self.flags |= RibEntry::FLAG_NEXTHOP_INVALID;
        } else {
            self.flags &= !RibEntry::FLAG_NEXTHOP_INVALID;
        }
    }

    /// True if this entry is in the LLGR stale period: either the source was
    /// marked LLGR stale by the helper, or the received attributes carry the
    /// LLGR_STALE community (0xFFFF0006) propagated from another helper.
    fn is_llgr_stale(&self) -> bool {
        self.path.source.is_llgr_stale() || has_llgr_stale_community(&self.path.attr)
    }

    fn originator_id(&self) -> u32 {
        PathAttribute::new(self.path.attr.clone())
            .attr_originator_id()
            .unwrap_or(self.path.source.router_id)
    }
}

/// Compare two EVPN Type-2 (MAC/IP Advertisement) RibEntries.
///
/// MAC Mobility extended community (type=0x06, subtype=0x00) takes priority
/// over the standard BGP best-path algorithm: the entry with the higher
/// sequence number wins regardless of other attributes.  When one entry
/// carries the community and the other does not, the one with mobility wins
/// (it represents a more recent MAC move).  Equal or absent mobility falls
/// through to the standard RibEntry ordering.
/// Compare two EVPN Type-2 (MAC/IP Advertisement) RibEntries.
///
/// MAC Mobility extended community (type=0x06, subtype=0x00) takes priority
/// over the standard BGP best-path algorithm: the entry with the higher
/// sequence number wins regardless of other attributes.  When one entry
/// carries the community and the other does not, the one with mobility wins
/// (it represents a more recent MAC move).  Equal or absent mobility falls
/// through to the standard RibEntry ordering.
///
/// Ordering follows the same convention as RibEntry::Ord: Less means "self
/// is better" (sorts first in the destination list).
fn evpn_type2_cmp(a: &RibEntry, b: &RibEntry) -> std::cmp::Ordering {
    let a_mm = packet::evpn::mac_mobility(a.path.attr.as_ref());
    let b_mm = packet::evpn::mac_mobility(b.path.attr.as_ref());
    match (a_mm, b_mm) {
        (Some((a_seq, _)), Some((b_seq, _))) => {
            // Higher sequence is better; reverse so that a better entry sorts as Less.
            a_seq.cmp(&b_seq).reverse().then_with(|| a.cmp(b))
        }
        // Entry with MAC Mobility is a more recent advertisement and wins.
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => a.cmp(b),
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
            // eBGP preferred over iBGP (ConfedEbgp treated as iBGP per RFC 5065 §9)
            .then_with(|| {
                other
                    .path
                    .source
                    .role
                    .prefers_over_ibgp()
                    .cmp(&self.path.source.role.prefers_over_ibgp())
            })
            // Non-stale is better than stale (false < true, and Less = better here)
            .then_with(|| {
                self.path
                    .source
                    .is_stale()
                    .cmp(&other.path.source.is_stale())
            })
            // LLGR stale is worse than GR stale (RFC 9494)
            .then_with(|| self.is_llgr_stale().cmp(&other.is_llgr_stale()))
            // Shorter CLUSTER_LIST is better (RFC 4456 s9)
            .then_with(|| {
                self_pa
                    .attr_cluster_list_length()
                    .cmp(&other_pa.attr_cluster_list_length())
            })
            // Lower originator ID / router ID is better (RFC 4456 s9)
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

/// Bitmap-based allocator for per-Rib destination IDs.
///
/// Bit i set = local ID i is in use (same convention as BIRD's hmap).
/// Allocates the lowest free local ID in O(1) via `u64::trailing_ones()`
/// and packs `shard_idx` into bits [31:24] of the returned dest_id so
/// that dest_ids are globally unique across all shards.
/// `dealloc` accepts the full combined dest_id and strips the shard bits
/// internally; callers need not know the encoding.
struct IdAllocator {
    bits: Vec<u64>,
    shard_idx: u32,
}

impl IdAllocator {
    fn new(shard_idx: u32) -> Self {
        debug_assert!(
            shard_idx < 256,
            "shard_idx must fit in bits [31:24] (max 255)"
        );
        IdAllocator {
            bits: Vec::new(),
            shard_idx,
        }
    }

    fn alloc(&mut self) -> u32 {
        for (i, word) in self.bits.iter_mut().enumerate() {
            if *word != u64::MAX {
                let bit = word.trailing_ones();
                *word |= 1u64 << bit;
                let local_id = i as u32 * 64 + bit;
                debug_assert!(
                    local_id < (1 << 24),
                    "local dest_id overflow (> 16M routes per shard)"
                );
                return (self.shard_idx << 24) | local_id;
            }
        }
        let i = self.bits.len();
        self.bits.push(1);
        let local_id = i as u32 * 64;
        debug_assert!(
            local_id < (1 << 24),
            "local dest_id overflow (> 16M routes per shard)"
        );
        (self.shard_idx << 24) | local_id
    }

    fn dealloc(&mut self, id: u32) {
        let local_id = id & 0x00FF_FFFF;
        let i = (local_id / 64) as usize;
        let bit = local_id % 64;
        self.bits[i] &= !(1u64 << bit);
        while self.bits.last() == Some(&0) {
            self.bits.pop();
        }
    }
}

struct Destination {
    entry: Vec<RibEntry>,
    next_path_id: u32,
    /// Stable per-Rib integer ID assigned at insertion, freed at removal.
    id: u32,
}

impl Destination {
    fn with_id(id: u32) -> Self {
        Destination {
            entry: Vec::new(),
            next_path_id: 1,
            id,
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
        self.entry
            .iter()
            .filter(|p| !p.is_filtered() && !p.is_nexthop_invalid())
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

/// Per-peer, per-family prefix counters in the Rib.
///
/// GoBGP API naming : received  / accepted
/// OpenConfig YANG  : received-pre-policy / received
#[derive(Default, Clone, Debug)]
pub struct PrefixStats {
    /// Unique prefixes received from this peer (pre import-policy).
    pub received: u64,
    /// Prefixes that passed import policy.
    pub accepted: u64,
}

pub struct Reach {
    pub source: Arc<Source>,
    pub family: Family,
    pub net: packet::PathNlri,
    pub attr: Arc<Vec<packet::Attribute>>,
    pub nexthop: Option<bgp::Nexthop>,
    pub timestamp: u32,
}

impl From<Reach> for bgp::Message {
    fn from(c: Reach) -> bgp::Message {
        bgp::Message::Update(bgp::Update::Reach {
            family: c.family,
            entries: vec![c.net],
            nexthop: c.nexthop,
            attr: c.attr,
        })
    }
}

/// Return value of `Rib::insert()`.
pub enum InsertResult {
    /// No routing change; caller need not act.
    NoChange,
    /// Per-peer prefix limit (RFC 4486 §2) exceeded; caller must send CEASE
    /// NOTIFICATION (Error Code 6, Subcode 1) and close the session.
    PrefixLimitExceeded,
    /// Routing table changed; caller should distribute the update.
    Changed(NlriChange),
}

impl InsertResult {
    /// Returns a reference to the inner `NlriChange` if this is `Changed`,
    /// or `None` otherwise.  Mirrors `Option::as_ref` for ergonomic test code.
    pub fn as_changed(&self) -> Option<&NlriChange> {
        match self {
            Self::Changed(c) => Some(c),
            _ => None,
        }
    }
}

/// One path entry returned by [`Table::collect_adj_in_paths`].
pub type SoftResetPath = (
    Family,
    packet::Nlri,
    u32,
    Option<bgp::Nexthop>,
    Arc<Source>,
    Arc<Vec<packet::Attribute>>,
    u32,
);

/// Result of a single `Table::insert()` or `Table::remove()` operation.
///
/// Non-Add-Path peers can skip processing when `best_changed` is false.
/// Add-Path peers can skip when `any_changed` is false.
#[derive(Clone)]
pub struct NlriChange {
    pub family: Family,
    pub net: packet::Nlri,
    /// Stable integer ID for the Destination within its Rib.
    /// Used by ExportMap as a cheap u32 key instead of hashing Nlri.
    pub dest_id: u32,

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

    /// All paths tied with the best through BGP decision steps 1-6
    /// (LocalPref, AS_PATH length, Origin, eBGP/iBGP, stale, CLUSTER_LIST
    /// length), excluding the final router-id tiebreaker.
    ///
    /// Returns an empty slice when there are no paths.  Used to build the
    /// ECMP nexthop set for kernel FIB installation.
    pub fn ecmp_paths(&self) -> Vec<&Path> {
        let Some(best) = self.current_paths.first() else {
            return vec![];
        };
        let best_pa = PathAttribute::new(best.attr.clone());
        let key = (
            best_pa.attr_local_preference(),
            best_pa.attr_as_path_length(),
            best_pa.attr_origin(),
            best.source.role.prefers_over_ibgp(),
            best.source.is_stale(),
            best_pa.attr_cluster_list_length(),
        );
        self.current_paths
            .iter()
            .take_while(|p| {
                let pa = PathAttribute::new(p.attr.clone());
                (
                    pa.attr_local_preference(),
                    pa.attr_as_path_length(),
                    pa.attr_origin(),
                    p.source.role.prefers_over_ibgp(),
                    p.source.is_stale(),
                    pa.attr_cluster_list_length(),
                ) == key
            })
            .collect()
    }
}

/// Per-session peer role used for best-path selection, adj-out filtering,
/// and attribute export decisions.
///
/// The ordering (Ebgp < RsClient < Ibgp < IbgpRrClient < ConfedEbgp) is
/// intentionally NOT the best-path ordering; use `prefers_over_ibgp()`
/// for the RFC 4271 "prefer eBGP over iBGP" tie-breaker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerRole {
    /// External BGP peer (different AS, outside any confederation).
    Ebgp,
    /// Route-server client (eBGP, RS isolation applies).
    RsClient,
    /// Internal BGP peer (same AS).
    Ibgp,
    /// Internal BGP peer that is a route-reflector client.
    IbgpRrClient,
    /// eBGP session between two member-ASes within the same confederation.
    /// Keeps LOCAL_PREF and uses AS_CONFED_SEQUENCE; treated as iBGP for
    /// the best-path eBGP-over-iBGP preference step (RFC 5065 §9).
    ConfedEbgp,
}

impl PeerRole {
    /// Returns true when this role is preferred over iBGP in the best-path
    /// eBGP-over-iBGP tie-breaker (RFC 4271 §9.1.2.2 step (e)).
    ///
    /// ConfedEbgp returns false: RFC 5065 §9 prohibits confederation eBGP
    /// from being preferred over iBGP in this step.
    pub(crate) fn prefers_over_ibgp(self) -> bool {
        matches!(self, PeerRole::Ebgp | PeerRole::RsClient)
    }
}

pub struct Source {
    pub remote_addr: IpAddr,
    pub local_addr: IpAddr,
    pub remote_asn: u32,
    pub local_asn: u32,
    pub router_id: u32,
    pub role: PeerRole,
    stale: AtomicBool,
    llgr_stale: AtomicBool,
}

impl Hash for Source {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.remote_addr.hash(state);
    }
}

/// Canonical source for locally-injected routes (add_path gRPC API).
/// All clones share the same allocation, enabling O(1) pointer-based
/// identity checks via Source::is_local().
static LOCAL_SOURCE: LazyLock<Arc<Source>> = LazyLock::new(|| {
    Arc::new(Source {
        remote_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        local_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        remote_asn: 0,
        local_asn: 0,
        router_id: 0,
        role: PeerRole::Ibgp,
        stale: AtomicBool::new(false),
        llgr_stale: AtomicBool::new(false),
    })
});

/// Canonical source for kernel-redistributed routes (static, connected, etc.).
/// Distinct from LOCAL_SOURCE so kernel routes and gRPC-injected routes can be
/// distinguished and withdrawn independently.
static KERNEL_SOURCE: LazyLock<Arc<Source>> = LazyLock::new(|| {
    Arc::new(Source {
        remote_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        local_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        remote_asn: 0,
        local_asn: 0,
        router_id: 0,
        role: PeerRole::Ibgp,
        stale: AtomicBool::new(false),
        llgr_stale: AtomicBool::new(false),
    })
});

impl Source {
    pub fn local() -> Arc<Self> {
        Arc::clone(&LOCAL_SOURCE)
    }

    pub fn is_local(&self) -> bool {
        std::ptr::eq(self as *const Source, Arc::as_ptr(&LOCAL_SOURCE))
    }

    pub fn kernel() -> Arc<Self> {
        Arc::clone(&KERNEL_SOURCE)
    }

    pub fn is_kernel(&self) -> bool {
        std::ptr::eq(self as *const Source, Arc::as_ptr(&KERNEL_SOURCE))
    }

    pub fn new(
        remote_addr: IpAddr,
        local_addr: IpAddr,
        remote_asn: u32,
        local_asn: u32,
        router_id: Ipv4Addr,
        role: PeerRole,
    ) -> Self {
        Source {
            remote_addr,
            local_addr,
            remote_asn,
            local_asn,
            router_id: router_id.into(),
            role,
            stale: AtomicBool::new(false),
            llgr_stale: AtomicBool::new(false),
        }
    }

    pub fn is_rr_client(&self) -> bool {
        matches!(self.role, PeerRole::IbgpRrClient)
    }

    pub fn is_rs_client(&self) -> bool {
        matches!(self.role, PeerRole::RsClient)
    }

    pub fn mark_stale(&self) {
        debug_assert!(!self.is_local() && !self.is_kernel());
        self.stale.store(true, Ordering::Relaxed);
    }

    pub fn is_stale(&self) -> bool {
        self.stale.load(Ordering::Relaxed)
    }

    pub fn mark_llgr_stale(&self) {
        debug_assert!(!self.is_local() && !self.is_kernel());
        self.llgr_stale.store(true, Ordering::Relaxed);
    }

    pub fn clear_llgr_stale(&self) {
        self.llgr_stale.store(false, Ordering::Relaxed);
    }

    pub fn is_llgr_stale(&self) -> bool {
        self.llgr_stale.load(Ordering::Relaxed)
    }
}

/// Per-family routing table slot.
///
/// `deferring` is set while the local speaker is in Restarting Speaker mode
/// (RFC 4724 §4.2): best-path selection is suppressed for this family until
/// EOR has been received from all helper peers or the deferral timer fires.
pub struct Rib {
    pub deferring: bool,
    destinations: FnvHashMap<packet::Nlri, Destination>,
    id_allocator: IdAllocator,
}

impl Rib {
    fn new(shard_idx: u32) -> Self {
        Rib {
            deferring: false,
            destinations: FnvHashMap::default(),
            id_allocator: IdAllocator::new(shard_idx),
        }
    }
}

/// Maximum number of RIB shards.
///
/// dest_id packs shard_idx into bits [31:24], so at most 256 distinct shard
/// indices (0-255) can be represented without overlapping the local-id field.
/// Capping at 255 keeps shard_idx safely within one byte.
pub const MAX_NUM_SHARDS: usize = 255;

pub struct Table {
    ribs: FnvHashMap<Family, Rib>,
    route_stats: FnvHashMap<IpAddr, FnvHashMap<Family, PrefixStats>>,
    shard_idx: u32,
}

impl Default for Table {
    fn default() -> Self {
        Self::new(0)
    }
}

impl Table {
    /// Returns one [`NlriChange`] per destination in the Loc-RIB for `family`.
    ///
    /// Each change has `best_changed` and `any_changed` set to `true` so that
    /// callers treating it as a fresh event (initial dump, route refresh) will
    /// unconditionally advertise every prefix.
    fn collect_loc_rib_paths_impl(&self, family: &Family, max_paths: usize) -> Vec<NlriChange> {
        let Some(t) = self.ribs.get(family) else {
            return Vec::new();
        };
        t.destinations
            .iter()
            .filter_map(|(net, dst)| {
                let paths: Vec<Path> = dst
                    .unfiltered_iter()
                    .take(max_paths)
                    .map(|e| e.path.clone())
                    .collect();
                if paths.is_empty() {
                    return None;
                }
                Some(NlriChange {
                    family: *family,
                    net: net.clone(),
                    dest_id: dst.id,
                    best_changed: true,
                    any_changed: true,
                    replaced_path_id: None,
                    current_paths: Arc::new(paths),
                })
            })
            .collect()
    }

    pub fn collect_loc_rib_paths(&self, family: &Family) -> Vec<NlriChange> {
        self.collect_loc_rib_paths_impl(family, usize::MAX)
    }

    pub fn collect_loc_rib_paths_limited(
        &self,
        family: &Family,
        max_paths: usize,
    ) -> Vec<NlriChange> {
        self.collect_loc_rib_paths_impl(family, max_paths)
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
    ) -> Option<impl Iterator<Item = (Family, &PrefixStats)> + '_> {
        self.route_stats
            .get(peer_addr)
            .map(|m| m.iter().map(|(f, s)| (*f, s)))
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
                        nlri: net.clone(),
                        path_id: e.remote_path_id,
                    },
                    attr: e.original_attr.clone(),
                    nexthop: e.path.nexthop,
                    timestamp: e.timestamp,
                })
            })
    }

    /// Post-import-policy Adj-RIB-In snapshot: filtered entries are excluded
    /// and `path.attr` (post-policy attributes) is returned.
    pub fn iter_reach_post(&self, family: Family) -> impl Iterator<Item = Reach> + '_ {
        self.ribs
            .get(&family)
            .unwrap_or_else(|| self.ribs.get(&Family::EMPTY).unwrap())
            .destinations
            .iter()
            .flat_map(move |(net, dst)| {
                dst.entry
                    .iter()
                    .filter(|e| !e.is_filtered())
                    .map(move |e| Reach {
                        source: e.path.source.clone(),
                        family,
                        net: packet::bgp::PathNlri {
                            nlri: net.clone(),
                            path_id: e.remote_path_id,
                        },
                        attr: e.path.attr.clone(),
                        nexthop: e.path.nexthop,
                        timestamp: e.timestamp,
                    })
            })
    }

    pub fn families(&self) -> impl Iterator<Item = Family> + '_ {
        self.ribs.keys().filter(|f| **f != Family::EMPTY).copied()
    }

    /// Collects paths from `peer` across the RIB.
    ///
    /// The returned tuples carry the pre-import-policy attributes
    /// (`original_attr`) so the caller can re-apply the current import policy
    /// and re-insert with [`Table::insert`].
    ///
    /// When `family` is `Some(f)` only paths for that address family are
    /// returned; `None` returns paths from all families.
    ///
    /// When `include_stale` is false, stale paths (held during GR helper mode)
    /// are excluded.  Soft reset IN uses `false` because re-applying policy to
    /// stale routes has no practical effect and would cause spurious churn.
    /// RTC filter construction uses `true` when the peer is reconnecting so
    /// that the pre-GR RT interests continue to gate VPN advertisement until
    /// a fresh RTC End-of-RIB arrives (RFC 4684 ss.5-6).
    pub fn collect_adj_in_paths(
        &self,
        peer: std::net::IpAddr,
        family: Option<Family>,
        include_stale: bool,
    ) -> Vec<SoftResetPath> {
        let mut out = Vec::new();
        for (fam, rib) in &self.ribs {
            if *fam == Family::EMPTY {
                continue;
            }
            if let Some(filter) = family
                && *fam != filter
            {
                continue;
            }
            for (net, dst) in &rib.destinations {
                for entry in &dst.entry {
                    if entry.path.source.remote_addr != peer {
                        continue;
                    }
                    if !include_stale && entry.path.source.is_stale() {
                        continue;
                    }
                    out.push((
                        *fam,
                        net.clone(),
                        entry.remote_path_id,
                        entry.path.nexthop,
                        Arc::clone(&entry.path.source),
                        Arc::clone(&entry.original_attr),
                        entry.timestamp,
                    ));
                }
            }
        }
        out
    }

    /// Returns paths in the global RIB for the given destination.
    ///
    /// When `enable_filtered` is false only unfiltered (policy-accepted) paths
    /// are returned.  When true all paths are returned and those suppressed by
    /// import policy have `filtered` set to true.
    fn global_paths(dst: &Destination, enable_filtered: bool) -> Vec<PathEntry> {
        dst.entry
            .iter()
            .filter(|p| enable_filtered || !p.is_filtered())
            .map(|p| PathEntry {
                source: p.path.source.clone(),
                remote_path_id: p.remote_path_id,
                timestamp: p.timestamp,
                attr: p.path.attr.clone(),
                validation: None,
                stale: p.path.source.is_stale(),
                filtered: p.is_filtered(),
            })
            .collect()
    }

    /// Returns paths received from `peer` (Adj-RIB-In view).
    ///
    /// When `enable_filtered` is false only unfiltered paths are returned.
    /// When true all paths from that peer are returned and those suppressed by
    /// import policy have `filtered` set to true.
    fn adj_in_paths(dst: &Destination, peer: IpAddr, enable_filtered: bool) -> Vec<PathEntry> {
        dst.entry
            .iter()
            .filter(|p| p.path.source.remote_addr == peer)
            .filter(|p| enable_filtered || !p.is_filtered())
            .map(|p| PathEntry {
                source: p.path.source.clone(),
                remote_path_id: p.remote_path_id,
                timestamp: p.timestamp,
                attr: p.original_attr.clone(),
                validation: None,
                stale: p.path.source.is_stale(),
                filtered: p.is_filtered(),
            })
            .collect()
    }

    /// Returns the RS local-RIB best path for `peer`: the best path from all
    /// RS-client peers excluding `peer` itself.
    ///
    /// Uses pre-import-policy attributes (`original_attr`) so callers see what
    /// the originating peer actually sent, mirroring GoBGP's rsRib behaviour.
    fn rs_local_paths(dst: &Destination, peer: IpAddr) -> Vec<PathEntry> {
        let best = dst
            .entry
            .iter()
            .filter(|e| {
                e.path.source.is_rs_client()
                    && e.path.source.remote_addr != peer
                    && !e.is_filtered()
            })
            .max();
        best.into_iter()
            .map(|p| PathEntry {
                source: p.path.source.clone(),
                remote_path_id: 0,
                timestamp: p.timestamp,
                attr: p.original_attr.clone(),
                validation: None,
                stale: p.path.source.is_stale(),
                filtered: false,
            })
            .collect()
    }

    /// Iterates destinations matching `query` and `prefixes` for the given `family`.
    ///
    /// When `prefixes` is empty all destinations are returned; otherwise only
    /// destinations matching at least one `PrefixFilter` are included.
    /// `LookupType::Exact` requires an identical prefix; `Longer` returns
    /// entries that are equally or more specific; `Shorter` returns entries
    /// that are equally or less specific.
    pub fn destinations(
        &self,
        query: TableQuery,
        family: Family,
        prefixes: Vec<PrefixFilter>,
        enable_filtered: bool,
    ) -> impl Iterator<Item = DestinationEntry> + '_ {
        self.ribs
            .get(&family)
            .unwrap_or_else(|| self.ribs.get(&Family::EMPTY).unwrap())
            .destinations
            .iter()
            .filter(move |(net, _)| {
                prefixes.is_empty()
                    || prefixes.iter().any(|f| match f.lookup_type {
                        LookupType::Exact => **net == f.prefix,
                        LookupType::Longer => nlri_contains(&f.prefix, net),
                        LookupType::Shorter => nlri_contains(net, &f.prefix),
                    })
            })
            .map(move |(net, dst)| {
                let paths = match query {
                    TableQuery::Global => Self::global_paths(dst, enable_filtered),
                    TableQuery::AdjIn(peer) => Self::adj_in_paths(dst, peer, enable_filtered),
                    TableQuery::RsLocal(peer) => Self::rs_local_paths(dst, peer),
                };
                DestinationEntry {
                    net: net.clone(),
                    paths,
                }
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
        nexthop: Option<bgp::Nexthop>,
        attr: Arc<Vec<packet::Attribute>>,
        original_attr: Option<Arc<Vec<packet::Attribute>>>,
        filtered: bool,
        nexthop_invalid: bool,
        prefix_limit: Option<(u32, &Arc<AtomicU64>)>,
        timestamp: u32,
    ) -> InsertResult {
        let flags = if filtered { RibEntry::FLAG_FILTERED } else { 0 }
            | if nexthop_invalid {
                RibEntry::FLAG_NEXTHOP_INVALID
            } else {
                0
            };

        let shard_idx = self.shard_idx;
        let rt = self
            .ribs
            .entry(family)
            .or_insert_with(|| Rib::new(shard_idx));
        let deferring = rt.deferring;
        let id_alloc = &mut rt.id_allocator;
        let dst = rt
            .destinations
            .entry(net.clone())
            .or_insert_with(|| Destination::with_id(id_alloc.alloc()));

        // Capture the current best's (source, attr, nexthop) before any modification.
        // Comparing it with the post-insertion best detects all best-path changes:
        // new path wins, old best replaced (same local_path_id, new attrs), or
        // old best displaced by a different path after attribute update.
        // Both source and attr are needed: paths may share the same attr Arc when
        // attrs.clone() is used within one UPDATE message (same allocation, same ptr),
        // so attr alone cannot distinguish a different path becoming best.
        // The nexthop is compared too because it lives in a separate Path field, not
        // in attr: without it a re-advertisement that changes only the nexthop of an
        // interned (shared-Arc) attr set would compare equal and be suppressed.
        let old_best_key = dst.unfiltered_best().map(|p| {
            (
                Arc::as_ptr(&p.path.source),
                Arc::as_ptr(&p.path.attr),
                p.path.nexthop,
            )
        });

        // Single pass: find replaced index, check peer_has_path.
        let mut replaced_idx: Option<usize> = None;
        let mut peer_has_path = false;
        for (i, e) in dst.entry.iter().enumerate() {
            // Match by remote_addr + path_id, not by Arc identity.  This correctly
            // replaces a stale path from a previous session (different Source Arc but
            // same peer) when the peer reconnects after GR and re-sends the same route.
            // For non-GR sessions there is at most one Source per remote_addr in the
            // RIB, so the result is identical to an Arc::ptr_eq check.
            if e.path.source.remote_addr == source.remote_addr && e.remote_path_id == remote_id {
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

        // 3. Check the per-peer prefix limit and increment counter for new prefixes.
        //    Replacements and additional Add-Path paths for an already-known prefix
        //    are always accepted regardless of the limit.
        if is_new && let Some((max, counter)) = prefix_limit {
            if counter.load(Ordering::Relaxed) >= max as u64 {
                return InsertResult::PrefixLimitExceeded;
            }
            counter.fetch_add(1, Ordering::Relaxed);
        }

        // 4. Build and insert the path.
        let local_path_id = replaced
            .as_ref()
            .map_or_else(|| dst.alloc_path_id(), |old| old.path.local_path_id);

        let original_attr = original_attr.unwrap_or_else(|| Arc::clone(&attr));

        let entry = RibEntry {
            path: Path {
                local_path_id,
                source: source.clone(),
                nexthop,
                attr,
            },
            original_attr,
            remote_path_id: remote_id,
            timestamp,
            flags,
        };

        let stats = self
            .route_stats
            .entry(source.remote_addr)
            .or_default()
            .entry(family)
            .or_default();

        if let Some(ref old) = replaced {
            match (old.is_filtered(), filtered) {
                (true, false) => stats.accepted += 1,
                (false, true) => stats.accepted -= 1,
                _ => {}
            }
        } else if is_new {
            // First path for this prefix from this peer: count the prefix.
            stats.received += 1;
            if !filtered {
                stats.accepted += 1;
            }
        } else {
            // Add-Path: additional path for an already-counted prefix.
            // received stays unchanged; accepted tracks unfiltered paths.
            if !filtered {
                stats.accepted += 1;
            }
        }

        let idx = if matches!(
            &net,
            packet::Nlri::Evpn(packet::evpn::EvpnNlri::MacIpAdvertisement(_))
        ) {
            dst.entry
                .partition_point(|a| evpn_type2_cmp(&entry, a).is_ge())
        } else {
            dst.entry.partition_point(|a| entry.cmp(a).is_ge())
        };
        dst.entry.insert(idx, entry);

        // During Restarting Speaker deferral, routes are accumulated but
        // best-path changes are suppressed; end_deferral() emits them all at once.
        if deferring {
            return InsertResult::NoChange;
        }

        // Compute change flags.
        let new_best_key = dst.unfiltered_best().map(|p| {
            (
                Arc::as_ptr(&p.path.source),
                Arc::as_ptr(&p.path.attr),
                p.path.nexthop,
            )
        });
        let best_changed = old_best_key != new_best_key;
        let any_changed = !filtered || replaced.as_ref().is_some_and(|r| !r.is_filtered());
        if !best_changed && !any_changed {
            return InsertResult::NoChange;
        }
        let replaced_path_id = replaced.as_ref().map(|r| r.path.local_path_id);

        let current_paths = Arc::new(dst.unfiltered_iter().map(|e| e.path.clone()).collect());
        let dest_id = dst.id;

        InsertResult::Changed(NlriChange {
            family,
            net,
            dest_id,
            best_changed,
            any_changed,
            replaced_path_id,
            current_paths,
        })
    }

    /// Set the deferral flag for `family`: best-path changes from `insert()` are
    /// suppressed until `end_deferral()` is called.
    pub fn start_deferral(&mut self, family: Family) {
        let shard_idx = self.shard_idx;
        self.ribs
            .entry(family)
            .or_insert_with(|| Rib::new(shard_idx))
            .deferring = true;
    }

    /// Clear the deferral flag for `family` and return one NlriChange per
    /// destination with all current unfiltered paths ready for distribution.
    pub fn end_deferral(&mut self, family: Family) -> Vec<NlriChange> {
        if let Some(ft) = self.ribs.get_mut(&family) {
            ft.deferring = false;
        }
        self.collect_loc_rib_paths(&family)
    }

    /// Returns the nexthop currently stored for the given (remote_addr, family, net, path_id).
    /// Used by callers to look up the old nexthop before calling insert() so they can
    /// unregister it from NHT tracking when the path is replaced.
    pub fn lookup_nexthop(
        &self,
        remote_addr: IpAddr,
        family: Family,
        net: &packet::Nlri,
        path_id: u32,
    ) -> Option<bgp::Nexthop> {
        self.ribs
            .get(&family)?
            .destinations
            .get(net)?
            .entry
            .iter()
            .find(|e| e.path.source.remote_addr == remote_addr && e.remote_path_id == path_id)
            .and_then(|e| e.path.nexthop)
    }

    /// Returns the routing change (if any) and the nexthop of the removed path.
    /// The nexthop is used by the caller to unregister NHT tracking.
    pub fn remove(
        &mut self,
        source: Arc<Source>,
        family: Family,
        net: packet::Nlri,
        remote_id: u32,
        prefix_counter: Option<&Arc<AtomicU64>>,
    ) -> (Option<NlriChange>, Option<bgp::Nexthop>) {
        let Some(rt) = self.ribs.get_mut(&family) else {
            return (None, None);
        };
        let Some(dst) = rt.destinations.get_mut(&net) else {
            return (None, None);
        };
        let dst_id = dst.id;
        // Match by remote_addr + path_id, not by Arc identity.  This correctly
        // removes a stale path from a previous GR session (different Source Arc
        // but same peer) when the peer reconnects and sends a WITHDRAW.
        let Some(i) = dst.entry.iter().position(|e| {
            e.path.source.remote_addr == source.remote_addr && e.remote_path_id == remote_id
        }) else {
            return (None, None);
        };

        // Capture (source, attr, nexthop) before removal for best_changed detection.
        let old_best_key = dst.unfiltered_best().map(|p| {
            (
                Arc::as_ptr(&p.path.source),
                Arc::as_ptr(&p.path.attr),
                p.path.nexthop,
            )
        });
        let was_unfiltered = !dst.entry[i].is_filtered();

        let removed = dst.entry.remove(i);
        let removed_nexthop = removed.path.nexthop;
        let removed_was_unfiltered = !removed.is_filtered();

        // Decrement prefix counter if this peer has no more paths for this prefix.
        let peer_still_has_path = dst
            .entry
            .iter()
            .any(|p| p.path.source.remote_addr == source.remote_addr);

        let stats = self
            .route_stats
            .get_mut(&source.remote_addr)
            .unwrap()
            .get_mut(&family)
            .unwrap();
        if !peer_still_has_path {
            // Last path for this prefix: decrement the prefix counter.
            stats.received -= 1;
            if !peer_still_has_path && let Some(counter) = prefix_counter {
                counter.fetch_sub(1, Ordering::Relaxed);
            }
        }
        if removed_was_unfiltered {
            stats.accepted -= 1;
        }

        if dst.entry.is_empty() {
            rt.id_allocator.dealloc(dst_id);
            rt.destinations.remove(&net);
            let change = if was_unfiltered {
                Some(NlriChange {
                    family,
                    net,
                    dest_id: dst_id,
                    best_changed: true,
                    any_changed: true,
                    replaced_path_id: None,
                    current_paths: Arc::new(vec![]),
                })
            } else {
                None
            };
            return (change, removed_nexthop);
        }

        let new_best_key = dst.unfiltered_best().map(|p| {
            (
                Arc::as_ptr(&p.path.source),
                Arc::as_ptr(&p.path.attr),
                p.path.nexthop,
            )
        });
        let best_changed = old_best_key != new_best_key;
        let any_changed = was_unfiltered;

        if !best_changed && !any_changed {
            return (None, removed_nexthop);
        }

        let current_paths = Arc::new(dst.unfiltered_iter().map(|e| e.path.clone()).collect());

        (
            Some(NlriChange {
                family,
                net,
                dest_id: dst_id,
                best_changed,
                any_changed,
                replaced_path_id: None,
                current_paths,
            }),
            removed_nexthop,
        )
    }

    /// Returns routing changes and the nexthops of all removed paths (for NHT unregistration).
    pub fn drop(&mut self, addr: IpAddr, family: Family) -> (Vec<NlriChange>, Vec<IpAddr>) {
        let mut changes = Vec::new();
        let mut removed_nexthops: Vec<IpAddr> = Vec::new();
        if let Some(fm) = self.route_stats.get_mut(&addr) {
            fm.remove(&family);
            if fm.is_empty() {
                self.route_stats.remove(&addr);
            }
        }
        if let Some(rt) = self.ribs.get_mut(&family) {
            let mut freed_ids = Vec::new();
            rt.destinations.retain(|net, dst| {
                if !dst.entry.iter().any(|e| e.path.source.remote_addr == addr) {
                    return true;
                }
                let old_best_id = dst.unfiltered_best().map(|e| e.path.local_path_id);
                let removed_any_unfiltered = dst.entry.iter().any(|e| {
                    e.path.source.remote_addr == addr && !e.is_filtered() && !e.is_nexthop_invalid()
                });

                // Collect nexthops before removing entries.
                for e in dst.entry.iter() {
                    if e.path.source.remote_addr == addr
                        && let Some(nh) = e.path.nexthop
                    {
                        removed_nexthops.push(nh.addr());
                    }
                }
                dst.entry.retain(|e| e.path.source.remote_addr != addr);

                if !removed_any_unfiltered {
                    if dst.entry.is_empty() {
                        freed_ids.push(dst.id);
                    }
                    return !dst.entry.is_empty();
                }

                if dst.entry.is_empty() {
                    changes.push(NlriChange {
                        family,
                        net: net.clone(),
                        dest_id: dst.id,
                        best_changed: true,
                        any_changed: true,
                        replaced_path_id: None,
                        current_paths: Arc::new(vec![]),
                    });
                    freed_ids.push(dst.id);
                    return false;
                }

                let new_best_id = dst.unfiltered_best().map(|e| e.path.local_path_id);
                let current_paths =
                    Arc::new(dst.unfiltered_iter().map(|e| e.path.clone()).collect());
                changes.push(NlriChange {
                    family,
                    net: net.clone(),
                    dest_id: dst.id,
                    best_changed: old_best_id != new_best_id,
                    any_changed: true,
                    replaced_path_id: None,
                    current_paths,
                });
                true
            });
            for id in freed_ids {
                rt.id_allocator.dealloc(id);
            }
        }
        (changes, removed_nexthops)
    }

    /// Remove only stale paths from `addr` in `family` and re-run best-path
    /// selection.  Used by GR helpers after EOR or deferral timer expiry, where
    /// the peer may have already sent fresh routes in the new session that must
    /// not be disturbed.
    ///
    /// Returns routing changes and the nexthops of all removed paths (for NHT
    /// unregistration).
    pub fn drop_stale(
        &mut self,
        addr: IpAddr,
        family: Family,
        prefix_counter: Option<&Arc<AtomicU64>>,
    ) -> (Vec<NlriChange>, Vec<IpAddr>) {
        let mut changes = Vec::new();
        let mut removed_nexthops: Vec<IpAddr> = Vec::new();
        if let Some(rt) = self.ribs.get_mut(&family) {
            let mut freed_ids = Vec::new();
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
                        && !e.is_nexthop_invalid()
                });

                // Collect nexthops before removing.
                for e in dst.entry.iter() {
                    if e.path.source.remote_addr == addr
                        && e.path.source.is_stale()
                        && let Some(nh) = e.path.nexthop
                    {
                        removed_nexthops.push(nh.addr());
                    }
                }
                dst.entry
                    .retain(|e| !(e.path.source.remote_addr == addr && e.path.source.is_stale()));

                // Decrement prefix counter if peer has no more paths for this prefix.
                let peer_still_has_path =
                    dst.entry.iter().any(|p| p.path.source.remote_addr == addr);
                if !peer_still_has_path && let Some(counter) = prefix_counter {
                    counter.fetch_sub(1, Ordering::Relaxed);
                }

                if !removed_any_unfiltered {
                    if dst.entry.is_empty() {
                        freed_ids.push(dst.id);
                    }
                    return !dst.entry.is_empty();
                }

                if dst.entry.is_empty() {
                    changes.push(NlriChange {
                        family,
                        net: net.clone(),
                        dest_id: dst.id,
                        best_changed: true,
                        any_changed: true,
                        replaced_path_id: None,
                        current_paths: Arc::new(vec![]),
                    });
                    freed_ids.push(dst.id);
                    return false;
                }

                let new_best_id = dst.unfiltered_best().map(|e| e.path.local_path_id);
                let current_paths =
                    Arc::new(dst.unfiltered_iter().map(|e| e.path.clone()).collect());
                changes.push(NlriChange {
                    family,
                    net: net.clone(),
                    dest_id: dst.id,
                    best_changed: old_best_id != new_best_id,
                    any_changed: true,
                    replaced_path_id: None,
                    current_paths,
                });
                true
            });
            for id in freed_ids {
                rt.id_allocator.dealloc(id);
            }
        }
        (changes, removed_nexthops)
    }

    /// Remove LLGR stale routes for `addr` in `family` when the LLGR stale
    /// timer expires. Mirrors `drop_stale()` but checks `is_llgr_stale()`.
    pub fn drop_llgr_stale(
        &mut self,
        addr: IpAddr,
        family: Family,
        prefix_counter: Option<&Arc<AtomicU64>>,
    ) -> (Vec<NlriChange>, Vec<IpAddr>) {
        let mut changes = Vec::new();
        let mut removed_nexthops: Vec<IpAddr> = Vec::new();
        if let Some(rt) = self.ribs.get_mut(&family) {
            let mut freed_ids = Vec::new();
            rt.destinations.retain(|net, dst| {
                if !dst
                    .entry
                    .iter()
                    .any(|e| e.path.source.remote_addr == addr && e.is_llgr_stale())
                {
                    return true;
                }

                let old_best_id = dst.unfiltered_best().map(|e| e.path.local_path_id);
                let removed_any_unfiltered = dst.entry.iter().any(|e| {
                    e.path.source.remote_addr == addr
                        && e.is_llgr_stale()
                        && !e.is_filtered()
                        && !e.is_nexthop_invalid()
                });

                for e in dst.entry.iter() {
                    if e.path.source.remote_addr == addr
                        && e.is_llgr_stale()
                        && let Some(nh) = e.path.nexthop
                    {
                        removed_nexthops.push(nh.addr());
                    }
                }
                dst.entry
                    .retain(|e| !(e.path.source.remote_addr == addr && e.is_llgr_stale()));

                let peer_still_has_path =
                    dst.entry.iter().any(|p| p.path.source.remote_addr == addr);
                if !peer_still_has_path && let Some(counter) = prefix_counter {
                    counter.fetch_sub(1, Ordering::Relaxed);
                }

                if !removed_any_unfiltered {
                    if dst.entry.is_empty() {
                        freed_ids.push(dst.id);
                    }
                    return !dst.entry.is_empty();
                }

                if dst.entry.is_empty() {
                    changes.push(NlriChange {
                        family,
                        net: net.clone(),
                        dest_id: dst.id,
                        best_changed: true,
                        any_changed: true,
                        replaced_path_id: None,
                        current_paths: Arc::new(vec![]),
                    });
                    freed_ids.push(dst.id);
                    return false;
                }

                let new_best_id = dst.unfiltered_best().map(|e| e.path.local_path_id);
                let current_paths =
                    Arc::new(dst.unfiltered_iter().map(|e| e.path.clone()).collect());
                changes.push(NlriChange {
                    family,
                    net: net.clone(),
                    dest_id: dst.id,
                    best_changed: old_best_id != new_best_id,
                    any_changed: true,
                    replaced_path_id: None,
                    current_paths,
                });
                true
            });
            for id in freed_ids {
                rt.id_allocator.dealloc(id);
            }
        }
        (changes, removed_nexthops)
    }

    /// Update the nexthop-invalid flag for all paths whose nexthop equals `addr`.
    ///
    /// When `reachable` is false, those paths are excluded from best-path
    /// selection as if they were import-filtered.  When `reachable` is true,
    /// the flag is cleared and they become eligible again.
    ///
    /// Returns one `NlriChange` per destination where the flag changed.
    pub fn update_nexthop_validity(&mut self, addr: IpAddr, reachable: bool) -> Vec<NlriChange> {
        let mut changes = Vec::new();
        for (family, rt) in &mut self.ribs {
            for (net, dst) in &mut rt.destinations {
                // Phase 1: capture best before modification.
                let old_best_key = dst
                    .entry
                    .iter()
                    .find(|p| !p.is_filtered() && !p.is_nexthop_invalid())
                    .map(|p| {
                        (
                            Arc::as_ptr(&p.path.source),
                            Arc::as_ptr(&p.path.attr),
                            p.path.nexthop,
                        )
                    });

                // Phase 2: update flags for matching entries.
                let mut any_changed = false;
                for entry in &mut dst.entry {
                    if entry.path.nexthop.map(|nh| nh.addr()) == Some(addr) {
                        let now_invalid = !reachable;
                        if entry.is_nexthop_invalid() != now_invalid {
                            entry.set_nexthop_invalid(now_invalid);
                            any_changed = true;
                        }
                    }
                }
                if !any_changed {
                    continue;
                }

                // Phase 3: compute change after modification.
                let new_best_key = dst
                    .entry
                    .iter()
                    .find(|p| !p.is_filtered() && !p.is_nexthop_invalid())
                    .map(|p| {
                        (
                            Arc::as_ptr(&p.path.source),
                            Arc::as_ptr(&p.path.attr),
                            p.path.nexthop,
                        )
                    });
                let best_changed = old_best_key != new_best_key;
                let current_paths =
                    Arc::new(dst.unfiltered_iter().map(|e| e.path.clone()).collect());
                changes.push(NlriChange {
                    family: *family,
                    net: net.clone(),
                    dest_id: dst.id,
                    best_changed,
                    any_changed: true,
                    replaced_path_id: None,
                    current_paths,
                });
            }
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
                        net: net.clone(),
                        dest_id: dst.id,
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

    /// Mark the source for `addr` as LLGR stale in `family`.
    ///
    /// Sets `source.mark_llgr_stale()` on all paths from `addr`, re-sorts
    /// affected destinations, and returns best-path changes for distribution.
    /// Mirrors `restale()` but for the LLGR stale flag.
    ///
    /// The caller must also call `drop_no_llgr()` for the same addr/family to
    /// delete paths that carry the NO_LLGR community (RFC 9494 §4.2 MUST).
    pub fn restale_llgr(&mut self, addr: IpAddr, family: Family) -> Vec<NlriChange> {
        let mut changes = Vec::new();
        if let Some(rt) = self.ribs.get_mut(&family) {
            for (net, dst) in rt.destinations.iter_mut() {
                if !dst.entry.iter().any(|p| p.path.source.remote_addr == addr) {
                    continue;
                }
                let old_best_id = dst.unfiltered_best().map(|e| e.path.local_path_id);
                let any_unfiltered_from_addr = dst
                    .entry
                    .iter()
                    .any(|e| e.path.source.remote_addr == addr && !e.is_filtered());
                for p in dst.entry.iter() {
                    if p.path.source.remote_addr == addr {
                        p.path.source.mark_llgr_stale();
                    }
                }
                dst.entry.sort_unstable();
                let new_best_id = dst.unfiltered_best().map(|e| e.path.local_path_id);
                let best_changed = old_best_id != new_best_id;
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
                        net: net.clone(),
                        dest_id: dst.id,
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

    /// Remove routes from `addr` in `family` that carry the NO_LLGR community
    /// (0xFFFF0007).  Called together with `restale_llgr()` when the LLGR stale
    /// period begins (RFC 9494 §4.2 MUST).
    pub fn drop_no_llgr(
        &mut self,
        addr: IpAddr,
        family: Family,
        prefix_counter: Option<&Arc<AtomicU64>>,
    ) -> (Vec<NlriChange>, Vec<IpAddr>) {
        let mut changes = Vec::new();
        let mut removed_nexthops: Vec<IpAddr> = Vec::new();
        if let Some(rt) = self.ribs.get_mut(&family) {
            let mut freed_ids = Vec::new();
            rt.destinations.retain(|net, dst| {
                if !dst.entry.iter().any(|e| {
                    e.path.source.remote_addr == addr && has_no_llgr_community(&e.path.attr)
                }) {
                    return true;
                }

                let old_best_id = dst.unfiltered_best().map(|e| e.path.local_path_id);
                let removed_any_unfiltered = dst.entry.iter().any(|e| {
                    e.path.source.remote_addr == addr
                        && has_no_llgr_community(&e.path.attr)
                        && !e.is_filtered()
                        && !e.is_nexthop_invalid()
                });

                for e in dst.entry.iter() {
                    if e.path.source.remote_addr == addr
                        && has_no_llgr_community(&e.path.attr)
                        && let Some(nh) = e.path.nexthop
                    {
                        removed_nexthops.push(nh.addr());
                    }
                }
                dst.entry.retain(|e| {
                    !(e.path.source.remote_addr == addr && has_no_llgr_community(&e.path.attr))
                });

                let peer_still_has_path =
                    dst.entry.iter().any(|p| p.path.source.remote_addr == addr);
                if !peer_still_has_path && let Some(counter) = prefix_counter {
                    counter.fetch_sub(1, Ordering::Relaxed);
                }

                if !removed_any_unfiltered {
                    if dst.entry.is_empty() {
                        freed_ids.push(dst.id);
                    }
                    return !dst.entry.is_empty();
                }

                if dst.entry.is_empty() {
                    changes.push(NlriChange {
                        family,
                        net: net.clone(),
                        dest_id: dst.id,
                        best_changed: true,
                        any_changed: true,
                        replaced_path_id: None,
                        current_paths: Arc::new(vec![]),
                    });
                    freed_ids.push(dst.id);
                    return false;
                }

                let new_best_id = dst.unfiltered_best().map(|e| e.path.local_path_id);
                let current_paths =
                    Arc::new(dst.unfiltered_iter().map(|e| e.path.clone()).collect());
                changes.push(NlriChange {
                    family,
                    net: net.clone(),
                    dest_id: dst.id,
                    best_changed: old_best_id != new_best_id,
                    any_changed: true,
                    replaced_path_id: None,
                    current_paths,
                });
                true
            });
            for id in freed_ids {
                rt.id_allocator.dealloc(id);
            }
        }
        (changes, removed_nexthops)
    }

    pub fn new(shard_idx: u32) -> Self {
        Table {
            ribs: vec![(Family::EMPTY, Rib::new(shard_idx))]
                .into_iter()
                .collect(),
            route_stats: FnvHashMap::default(),
            shard_idx,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn apply_policy(
        assignment: &PolicyAssignment,
        source: &Arc<Source>,
        net: &packet::Nlri,
        attr: &mut Arc<Vec<packet::Attribute>>,
        nexthop: &mut Option<bgp::Nexthop>,
        local_addr: IpAddr,
        peer_addr: IpAddr,
        rpki: Option<&RpkiTable>,
        original_nexthop: Option<bgp::Nexthop>,
        is_confed: bool,
    ) -> Disposition {
        assignment.apply(
            source,
            net,
            attr,
            nexthop,
            original_nexthop,
            is_confed,
            local_addr,
            peer_addr,
            rpki,
        )
    }
}

pub mod policy;
pub use policy::*;

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

#[derive(Default, Clone)]
pub struct RpkiTable {
    roas: FnvHashMap<Family, PatriciaMap<Vec<Arc<Roa>>>>,
}

impl RpkiTable {
    pub fn new() -> Self {
        let roas: FnvHashMap<Family, PatriciaMap<_>> = vec![
            (Family::IPV4, PatriciaMap::default()),
            (Family::IPV6, PatriciaMap::default()),
        ]
        .drain(..)
        .collect();
        RpkiTable { roas }
    }

    fn key_to_addr(mut key: Vec<u8>) -> packet::IpNet {
        let mask = key
            .pop()
            .expect("RPKI trie key must end with a prefix-length byte");
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
            n => {
                unreachable!("RPKI trie key address length must be 4 (IPv4) or 16 (IPv6), got {n}")
            }
        };
        packet::IpNet::new(prefix, mask)
    }

    pub fn validate(
        &self,
        source: &Arc<Source>,
        net: &packet::Nlri,
        attr: &Arc<Vec<packet::Attribute>>,
    ) -> Option<RpkiValidation> {
        let (family, addr_bytes, mask) = match net {
            packet::Nlri::V4(n) => (Family::IPV4, n.addr.octets().to_vec(), n.mask),
            packet::Nlri::V6(n) => (Family::IPV6, n.addr.octets().to_vec(), n.mask),
            _ => return None,
        };
        let m = self.roas.get(&family)?;
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
        let asn = if let Some(a) = attr.iter().find(|a| a.code() == packet::Attribute::AS_PATH) {
            match a.as_path_origin() {
                Some(asn) => asn,
                None => source.local_asn,
            }
        } else {
            source.local_asn
        };
        let mut addr = addr_bytes;
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

    pub fn insert(&mut self, net: packet::IpNet, roa: Arc<Roa>) {
        let (family, mut key, mask) = match net {
            packet::IpNet::V4(net) => (Family::IPV4, net.addr.octets().to_vec(), net.mask),
            packet::IpNet::V6(net) => (Family::IPV6, net.addr.octets().to_vec(), net.mask),
        };
        key.push(mask);
        match self.roas.get_mut(&family).unwrap().get_mut(&key) {
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
                self.roas.get_mut(&family).unwrap().insert(key, vec![roa]);
            }
        }
    }

    pub fn remove(&mut self, net: packet::IpNet, roa: &Roa) {
        let (family, mut key, mask) = match net {
            packet::IpNet::V4(n) => (Family::IPV4, n.addr.octets().to_vec(), n.mask),
            packet::IpNet::V6(n) => (Family::IPV6, n.addr.octets().to_vec(), n.mask),
        };
        key.push(mask);
        let trie = self.roas.get_mut(&family).unwrap();
        let is_empty = if let Some(entry) = trie.get_mut(&key) {
            entry.retain(|e| {
                !(Arc::ptr_eq(&e.source, &roa.source)
                    && e.max_length == roa.max_length
                    && e.as_number == roa.as_number)
            });
            entry.is_empty()
        } else {
            false
        };
        if is_empty {
            trie.remove(key);
        }
    }

    pub fn drop_source(&mut self, source: Arc<IpAddr>) {
        for roa in self.roas.values_mut() {
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

    pub fn state(&self, addr: &IpAddr) -> RpkiTableState {
        let mut state = RpkiTableState::default();
        for (family, roas) in self.roas.iter() {
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

    pub fn iter(&self, family: Family) -> impl Iterator<Item = (packet::IpNet, &Roa)> + '_ {
        self.roas.get(&family).unwrap().iter().flat_map(|(n, e)| {
            let net = RpkiTable::key_to_addr(n);
            e.iter().map(move |r| (net.clone(), r.as_ref()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(addr: u8, remote_asn: u32, local_asn: u32, router_id: u8) -> Arc<Source> {
        let role = if remote_asn == local_asn {
            PeerRole::Ibgp
        } else {
            PeerRole::Ebgp
        };
        Arc::new(Source::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, addr)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 254)),
            remote_asn,
            local_asn,
            Ipv4Addr::new(0, 0, 0, router_id),
            role,
        ))
    }

    fn nlri(a: u8, b: u8, c: u8, d: u8, mask: u8) -> packet::Nlri {
        packet::Nlri::V4(packet::bgp::Ipv4Net {
            addr: Ipv4Addr::new(a, b, c, d),
            mask,
        })
    }

    fn nh() -> Option<bgp::Nexthop> {
        Some(bgp::Nexthop::V4(Ipv4Addr::new(10, 0, 0, 1)))
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

    /// Flat list of (nlri, path, rank) from collect_loc_rib_paths(), sorted by nlri then rank.
    /// Replaces old rt.best() which returned a flat Vec<Change>.
    fn flat_best(rt: &Table, family: &Family) -> Vec<(packet::Nlri, Path, usize)> {
        let mut result = Vec::new();
        for change in rt.collect_loc_rib_paths(family) {
            for (i, path) in change.current_paths.iter().cloned().enumerate() {
                result.push((change.net.clone(), path, i + 1));
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
            PeerRole::Ebgp,
        ));
        let s2 = Arc::new(Source::new(
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 2)),
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 2)),
            1,
            2,
            Ipv4Addr::new(1, 1, 1, 2),
            PeerRole::Ebgp,
        ));

        let n1 = nlri(1, 0, 0, 0, 24);
        let n2 = nlri(2, 0, 0, 0, 24);
        let n3 = nlri(3, 0, 0, 0, 24);

        let mut rt = Table::new(0);
        let family = Family::IPV4;
        let attrs = Arc::new(Vec::new());

        rt.insert(
            s1.clone(),
            family,
            n1.clone(),
            0,
            nh(),
            attrs.clone(),
            None,
            false,
            false,
            None,
            0u32,
        );
        rt.insert(
            s2,
            family,
            n1.clone(),
            0,
            nh(),
            attrs.clone(),
            None,
            false,
            false,
            None,
            0u32,
        );
        rt.insert(
            s1.clone(),
            family,
            n2.clone(),
            0,
            nh(),
            attrs.clone(),
            None,
            false,
            false,
            None,
            0u32,
        );
        rt.insert(
            s1.clone(),
            family,
            n3.clone(),
            0,
            nh(),
            attrs.clone(),
            None,
            false,
            false,
            None,
            0u32,
        );

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
        let mut rt = Table::new(0);
        let update = rt.insert(
            source(1, 65001, 65000, 1),
            Family::IPV4,
            nlri(10, 0, 0, 0, 24),
            0,
            nh(),
            empty_attrs(),
            None,
            false,
            false,
            None,
            0u32,
        );
        assert!(update.as_changed().unwrap().any_changed);
        assert!(update.as_changed().unwrap().best_changed);
    }

    #[test]
    fn insert_same_nlri_no_best_change() {
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        // Insert with router_id=1 (lower, so this is best)
        rt.insert(
            source(1, 65001, 65000, 1),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            false,
            false,
            None,
            0u32,
        );
        // Insert with router_id=2 (higher, won't become best)
        let update = rt.insert(
            source(2, 65002, 65000, 2),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            false,
            false,
            None,
            0u32,
        );
        // Best did not change; second path entered current_paths at index 1
        assert!(!update.as_changed().unwrap().best_changed);
        assert!(update.as_changed().unwrap().any_changed);
        assert_eq!(update.as_changed().unwrap().current_paths.len(), 2);
    }

    // Regression: a re-advertisement that changes only the nexthop of an
    // otherwise identical path (same source, same attr Arc, same route key)
    // must be detected as a best-path change, not suppressed. Mirrors GoBGP
    // #3496, where Path.Equal compared an attributes hash that excluded the
    // MP_REACH nexthop and wrongly suppressed such re-advertisements. Here the
    // attr Arc is shared across inserts (the interned-attr case) so the only
    // difference the change detector can see is the separate nexthop field.
    #[test]
    fn insert_nexthop_only_change_is_best_change() {
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        let attr = attrs_with_local_pref(100);
        let src = source(1, 65001, 65000, 1);
        let nh1 = Some(bgp::Nexthop::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let nh2 = Some(bgp::Nexthop::V4(Ipv4Addr::new(10, 0, 0, 2)));

        rt.insert(
            src.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh1,
            attr.clone(),
            None,
            false,
            false,
            None,
            0u32,
        );

        // Same source, same attr Arc, same route key; only the nexthop changed.
        let update = rt.insert(
            src.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh2,
            attr.clone(),
            None,
            false,
            false,
            None,
            0u32,
        );
        assert!(
            update.as_changed().unwrap().best_changed,
            "nexthop-only change must be a best-path change"
        );
        assert_eq!(
            update.as_changed().unwrap().new_best().unwrap().nexthop,
            nh2
        );

        // Identical re-add (nexthop unchanged too): best must not change.
        let update = rt.insert(
            src.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh2,
            attr.clone(),
            None,
            false,
            false,
            None,
            0u32,
        );
        assert!(
            !update.as_changed().unwrap().best_changed,
            "identical re-add must not be a best-path change"
        );
    }

    // --- best path selection ---

    #[test]
    fn best_path_local_pref() {
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        rt.insert(
            source(1, 65001, 65000, 1),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            attrs_with_local_pref(100),
            None,
            false,
            false,
            None,
            0u32,
        );
        let update = rt.insert(
            source(2, 65002, 65000, 2),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            attrs_with_local_pref(200),
            None,
            false,
            false,
            None,
            0u32,
        );
        // Higher local_pref wins → best changes to source 2
        assert!(update.as_changed().unwrap().best_changed);
        let best = update.as_changed().unwrap().new_best().unwrap();
        assert_eq!(
            best.source.remote_addr,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        );
    }

    #[test]
    fn best_path_as_path_length() {
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        rt.insert(
            source(1, 65001, 65000, 1),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            attrs_with_as_path_len(3),
            None,
            false,
            false,
            None,
            0u32,
        );
        let update = rt.insert(
            source(2, 65002, 65000, 2),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            attrs_with_as_path_len(1),
            None,
            false,
            false,
            None,
            0u32,
        );
        // Shorter AS path wins
        assert!(update.as_changed().unwrap().best_changed);
        let best = update.as_changed().unwrap().new_best().unwrap();
        assert_eq!(
            best.source.remote_addr,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        );
    }

    #[test]
    fn best_path_origin() {
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        // Insert with ORIGIN=Incomplete(2), router_id=1
        rt.insert(
            source(1, 65001, 65000, 1),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            attrs_with_origin(2),
            None,
            false,
            false,
            None,
            0u32,
        );
        // Insert with ORIGIN=IGP(0), router_id=2
        let update = rt.insert(
            source(2, 65002, 65000, 2),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            attrs_with_origin(0),
            None,
            false,
            false,
            None,
            0u32,
        );
        // IGP (lower origin value) wins
        assert!(update.as_changed().unwrap().best_changed);
        let best = update.as_changed().unwrap().new_best().unwrap();
        assert_eq!(
            best.source.remote_addr,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        );
    }

    #[test]
    fn best_path_ebgp_over_ibgp() {
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        // iBGP peer (remote_asn == local_asn), router_id=1 (lower)
        rt.insert(
            source(1, 65000, 65000, 1),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            false,
            false,
            None,
            0u32,
        );
        // eBGP peer (remote_asn != local_asn), router_id=2 (higher)
        let update = rt.insert(
            source(2, 65001, 65000, 2),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            false,
            false,
            None,
            0u32,
        );
        // eBGP wins even though router_id is higher
        assert!(update.as_changed().unwrap().best_changed);
        let best = update.as_changed().unwrap().new_best().unwrap();
        assert_eq!(
            best.source.remote_addr,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        );
    }

    #[test]
    fn best_path_router_id() {
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        // router_id=10
        rt.insert(
            source(1, 65001, 65000, 10),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            false,
            false,
            None,
            0u32,
        );
        // router_id=5 (lower wins)
        let update = rt.insert(
            source(2, 65002, 65000, 5),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            false,
            false,
            None,
            0u32,
        );
        assert!(update.as_changed().unwrap().best_changed);
        let best = update.as_changed().unwrap().new_best().unwrap();
        assert_eq!(
            best.source.remote_addr,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        );
    }

    fn attrs_with_cluster_list(ids: &[u8]) -> Arc<Vec<packet::Attribute>> {
        // Each id is used as the last octet of a 4-byte cluster ID (0.0.0.id).
        let bytes: Vec<u8> = ids.iter().flat_map(|&id| [0u8, 0, 0, id]).collect();
        Arc::new(vec![
            packet::Attribute::new_with_bin(packet::Attribute::CLUSTER_LIST, bytes).unwrap(),
        ])
    }

    #[test]
    fn best_path_shorter_cluster_list_wins() {
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        // Two hops in CLUSTER_LIST — inserted first
        rt.insert(
            source(1, 65001, 65000, 1),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            attrs_with_cluster_list(&[1, 2]),
            None,
            false,
            false,
            None,
            0u32,
        );
        // One hop in CLUSTER_LIST — shorter wins
        let update = rt.insert(
            source(2, 65001, 65000, 2),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            attrs_with_cluster_list(&[1]),
            None,
            false,
            false,
            None,
            0u32,
        );
        assert!(update.as_changed().unwrap().best_changed);
        let best = update.as_changed().unwrap().new_best().unwrap();
        assert_eq!(
            best.source.remote_addr,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        );
    }

    #[test]
    fn best_path_no_cluster_list_beats_one_hop() {
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        // One hop in CLUSTER_LIST
        rt.insert(
            source(1, 65001, 65000, 1),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            attrs_with_cluster_list(&[1]),
            None,
            false,
            false,
            None,
            0u32,
        );
        // No CLUSTER_LIST (length 0) — wins
        let update = rt.insert(
            source(2, 65001, 65000, 2),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            false,
            false,
            None,
            0u32,
        );
        assert!(update.as_changed().unwrap().best_changed);
        let best = update.as_changed().unwrap().new_best().unwrap();
        assert_eq!(
            best.source.remote_addr,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        );
    }

    #[test]
    fn best_path_equal_cluster_list_falls_through_to_originator_id() {
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        // Same CLUSTER_LIST length (1), higher ORIGINATOR_ID
        rt.insert(
            source(1, 65001, 65000, 1),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            {
                let mut attrs = (*attrs_with_cluster_list(&[99])).clone();
                attrs.push(
                    packet::Attribute::new_with_value(
                        packet::Attribute::ORIGINATOR_ID,
                        u32::from(Ipv4Addr::new(0, 0, 0, 10)),
                    )
                    .unwrap(),
                );
                Arc::new(attrs)
            },
            None,
            false,
            false,
            None,
            0u32,
        );
        // Same CLUSTER_LIST length (1), lower ORIGINATOR_ID — wins
        let update = rt.insert(
            source(2, 65001, 65000, 2),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            {
                let mut attrs = (*attrs_with_cluster_list(&[99])).clone();
                attrs.push(
                    packet::Attribute::new_with_value(
                        packet::Attribute::ORIGINATOR_ID,
                        u32::from(Ipv4Addr::new(0, 0, 0, 5)),
                    )
                    .unwrap(),
                );
                Arc::new(attrs)
            },
            None,
            false,
            false,
            None,
            0u32,
        );
        assert!(update.as_changed().unwrap().best_changed);
        let best = update.as_changed().unwrap().new_best().unwrap();
        assert_eq!(
            best.source.remote_addr,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        );
    }

    // --- remove ---

    #[test]
    fn remove_best_path() {
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        let s1 = source(1, 65001, 65000, 1);
        let s2 = source(2, 65002, 65000, 2);
        rt.insert(
            s1.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            false,
            false,
            None,
            0u32,
        );
        rt.insert(
            s2.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            false,
            false,
            None,
            0u32,
        );
        // Remove best (router_id=1) → s2 promoted to best
        let (update, _) = rt.remove(s1, Family::IPV4, net, 0, None);
        assert!(update.as_ref().unwrap().best_changed);
        let best = update.as_ref().unwrap().new_best().unwrap();
        assert_eq!(
            best.source.remote_addr,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        );
    }

    #[test]
    fn remove_non_best_path() {
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        let s1 = source(1, 65001, 65000, 1);
        let s2 = source(2, 65002, 65000, 2);
        rt.insert(
            s1.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            false,
            false,
            None,
            0u32,
        );
        rt.insert(
            s2.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            false,
            false,
            None,
            0u32,
        );
        // Remove non-best (router_id=2) → best unchanged, s1 still best
        let (update, _) = rt.remove(s2, Family::IPV4, net, 0, None);
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
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        let s1 = source(1, 65001, 65000, 1);
        rt.insert(
            s1.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            false,
            false,
            None,
            0u32,
        );
        let (update, _) = rt.remove(s1, Family::IPV4, net, 0, None);
        // Withdrawal: best gone
        assert!(update.as_ref().unwrap().best_changed);
        assert!(update.as_ref().unwrap().new_best().is_none());
    }

    // --- filtered ---

    #[test]
    fn filtered_path_no_change() {
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        // Only filtered path → no best change, no any_changed
        let update = rt.insert(
            source(1, 65001, 65000, 1),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            true,
            false,
            None,
            0u32,
        );
        assert!(
            update.as_changed().is_none(),
            "filtered-only insert must be a no-op"
        );

        // Unfiltered path added → best changes, new_best points to the unfiltered path
        let s2 = source(2, 65002, 65000, 2);
        let update = rt.insert(
            s2.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            false,
            false,
            None,
            0u32,
        );
        assert!(update.as_changed().unwrap().best_changed);
        let best = update.as_changed().unwrap().new_best().unwrap();
        assert!(Arc::ptr_eq(&best.source, &s2));
    }

    // A2: filtered at head, insert unfiltered behind existing unfiltered best
    #[test]
    fn filtered_head_insert_unfiltered_non_best() {
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        // filtered path at head (router_id=1)
        rt.insert(
            source(1, 65001, 65000, 1),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            true,
            false,
            None,
            0u32,
        );
        // unfiltered best (router_id=2)
        let s2 = source(2, 65002, 65000, 2);
        let update = rt.insert(
            s2.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            false,
            false,
            None,
            0u32,
        );
        assert!(update.as_changed().unwrap().best_changed);
        let best = update.as_changed().unwrap().new_best().unwrap();
        assert!(Arc::ptr_eq(&best.source, &s2));
        // another unfiltered but worse (router_id=3) → best unchanged, but any_changed
        let update = rt.insert(
            source(3, 65003, 65000, 3),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            false,
            false,
            None,
            0u32,
        );
        assert!(!update.as_changed().unwrap().best_changed);
        assert!(update.as_changed().unwrap().any_changed);
        assert_eq!(update.as_changed().unwrap().current_paths.len(), 2);
    }

    // B1: replace filtered path at index 0 → unfiltered best unchanged
    #[test]
    fn replace_filtered_head_no_best_change() {
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        let s1 = source(1, 65001, 65000, 1);
        // filtered at head
        rt.insert(
            s1.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            true,
            false,
            None,
            0u32,
        );
        // unfiltered best
        rt.insert(
            source(2, 65002, 65000, 2),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            false,
            false,
            None,
            0u32,
        );
        // replace the filtered head with updated attrs (still filtered) → no best change, no any_changed
        let update = rt.insert(
            s1,
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            attrs_with_local_pref(200),
            None,
            true,
            false,
            None,
            0u32,
        );
        assert!(
            update.as_changed().is_none(),
            "filtered-to-filtered replace must be a no-op"
        );
    }

    // B2: replace unfiltered best with filtered → best changes to another unfiltered
    #[test]
    fn replace_unfiltered_best_changes() {
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        let s1 = source(1, 65001, 65000, 1);
        // filtered at head (router_id=3, won't be best)
        rt.insert(
            source(3, 65003, 65000, 3),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            true,
            false,
            None,
            0u32,
        );
        // unfiltered best (router_id=1)
        rt.insert(
            s1.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            false,
            false,
            None,
            0u32,
        );
        // another unfiltered (router_id=2)
        let s2 = source(2, 65002, 65000, 2);
        rt.insert(
            s2.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            false,
            false,
            None,
            0u32,
        );
        // replace s1 as filtered → s2 becomes unfiltered best
        let update = rt.insert(
            s1,
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            true,
            false,
            None,
            0u32,
        );
        assert!(update.as_changed().unwrap().best_changed);
        let best = update.as_changed().unwrap().new_best().unwrap();
        assert!(Arc::ptr_eq(&best.source, &s2));
    }

    // B2b: replace unfiltered best with worse attrs → another path becomes best
    #[test]
    fn replace_unfiltered_best_with_worse_attrs_changes_best() {
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        let s1 = source(1, 65001, 65000, 1);
        let s2 = source(2, 65002, 65000, 2);

        // s1 is best (local_pref=200 wins over s2's local_pref=100)
        rt.insert(
            s1.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            attrs_with_local_pref(200),
            None,
            false,
            false,
            None,
            0u32,
        );
        rt.insert(
            s2.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            attrs_with_local_pref(100),
            None,
            false,
            false,
            None,
            0u32,
        );

        // Replace s1 with worse attrs (local_pref=50) → s2 (local_pref=100) becomes best.
        let update = rt.insert(
            s1,
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            attrs_with_local_pref(50),
            None,
            false,
            false,
            None,
            0u32,
        );

        let update = update
            .as_changed()
            .expect("replacement must produce NlriChange");
        assert!(
            update.best_changed,
            "best must change when attrs demote the old best"
        );
        let best = update.new_best().unwrap();
        assert!(Arc::ptr_eq(&best.source, &s2), "s2 must be the new best");
    }

    // B3: replace unfiltered non-best → no best change, but any_changed
    #[test]
    fn replace_unfiltered_non_best_no_change() {
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        // filtered at head
        rt.insert(
            source(3, 65003, 65000, 3),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            true,
            false,
            None,
            0u32,
        );
        // unfiltered best (router_id=1)
        let s1 = source(1, 65001, 65000, 1);
        rt.insert(
            s1.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            false,
            false,
            None,
            0u32,
        );
        // unfiltered non-best (router_id=2)
        let s2 = source(2, 65002, 65000, 2);
        rt.insert(
            s2.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            false,
            false,
            None,
            0u32,
        );
        // replace s2 with different attrs → still non-best
        let update = rt.insert(
            s2,
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            attrs_with_local_pref(50),
            None,
            false,
            false,
            None,
            0u32,
        );
        assert!(!update.as_changed().unwrap().best_changed);
        assert!(update.as_changed().unwrap().any_changed);
        // s1 is still best
        let best = update.as_changed().unwrap().new_best().unwrap();
        assert!(Arc::ptr_eq(&best.source, &s1));
    }

    #[test]
    fn filtered_path_peer_stats() {
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        let s1 = source(1, 65001, 65000, 1);
        rt.insert(
            s1.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            true,
            false,
            None,
            0u32,
        );
        // filtered path: received=1, accepted=0
        let stats: Vec<_> = rt.peer_stats(&s1.remote_addr).unwrap().collect();
        assert_eq!(stats.len(), 1);
        let (_, s) = stats[0];
        assert_eq!(s.received, 1);
        assert_eq!(s.accepted, 0);
    }

    #[test]
    fn addpath_peer_stats_counts_prefixes_not_paths() {
        // Add-Path: two paths (path_id=1, path_id=2) for the same prefix from
        // the same peer must count as received=1, not received=2.
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        let src = source(1, 65001, 65000, 1);

        // First path (path_id=1): new prefix -> received++, accepted++
        rt.insert(
            src.clone(),
            Family::IPV4,
            net.clone(),
            1,
            nh(),
            empty_attrs(),
            None,
            false,
            false,
            None,
            0u32,
        );
        // Second path (path_id=2): same prefix, additional Add-Path path.
        // received must NOT increment again.
        rt.insert(
            src.clone(),
            Family::IPV4,
            net.clone(),
            2,
            nh(),
            empty_attrs(),
            None,
            false,
            false,
            None,
            0u32,
        );

        let stats: Vec<_> = rt.peer_stats(&src.remote_addr).unwrap().collect();
        let (_, s) = stats[0];
        assert_eq!(
            s.received, 1,
            "two Add-Path paths for same prefix must count as one received"
        );
        assert_eq!(
            s.accepted, 2,
            "each unfiltered path contributes to accepted"
        );
    }

    #[test]
    fn addpath_remove_last_path_decrements_received() {
        // Removing the last path for a prefix must decrement received.
        // Removing one of two Add-Path paths must NOT decrement received.
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        let src = source(1, 65001, 65000, 1);

        rt.insert(
            src.clone(),
            Family::IPV4,
            net.clone(),
            1,
            nh(),
            empty_attrs(),
            None,
            false,
            false,
            None,
            0u32,
        );
        rt.insert(
            src.clone(),
            Family::IPV4,
            net.clone(),
            2,
            nh(),
            empty_attrs(),
            None,
            false,
            false,
            None,
            0u32,
        );

        // Remove path_id=1: path_id=2 still exists -> received must stay 1
        rt.remove(src.clone(), Family::IPV4, net.clone(), 1, None);
        let stats: Vec<_> = rt.peer_stats(&src.remote_addr).unwrap().collect();
        let (_, s) = stats[0];
        assert_eq!(
            s.received, 1,
            "received must stay 1 while a path for the prefix remains"
        );
        assert_eq!(s.accepted, 1);

        // Remove path_id=2: no more paths -> received must drop to 0
        rt.remove(src.clone(), Family::IPV4, net, 2, None);
        let stats: Vec<_> = rt.peer_stats(&src.remote_addr).unwrap().collect();
        let (_, s) = stats[0];
        assert_eq!(
            s.received, 0,
            "received must drop to 0 when last path is removed"
        );
        assert_eq!(s.accepted, 0);
    }

    // --- best() ---

    #[test]
    fn best_returns_all_prefixes() {
        let mut rt = Table::new(0);
        let s1 = source(1, 65001, 65000, 1);
        rt.insert(
            s1.clone(),
            Family::IPV4,
            nlri(10, 0, 0, 0, 24),
            0,
            nh(),
            empty_attrs(),
            None,
            false,
            false,
            None,
            0u32,
        );
        rt.insert(
            s1.clone(),
            Family::IPV4,
            nlri(10, 0, 1, 0, 24),
            0,
            nh(),
            empty_attrs(),
            None,
            false,
            false,
            None,
            0u32,
        );
        rt.insert(
            s1.clone(),
            Family::IPV4,
            nlri(10, 0, 2, 0, 24),
            0,
            nh(),
            empty_attrs(),
            None,
            false,
            false,
            None,
            0u32,
        );
        assert_eq!(flat_best(&rt, &Family::IPV4).len(), 3);
    }

    // --- policy ---

    #[test]
    fn policy_prefix_reject() {
        let _rt = Table::new(0);
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
        let result = Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut empty_attrs(),
            &mut nh(),
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            s.remote_addr,
            None,
            None,
            false,
        );
        assert_eq!(result, Disposition::Reject);
    }

    #[test]
    fn policy_default_accept() {
        let _rt = Table::new(0);
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
        let result = Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut empty_attrs(),
            &mut nh(),
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            s.remote_addr,
            None,
            None,
            false,
        );
        assert_eq!(result, Disposition::Accept);
    }

    #[test]
    fn policy_nexthop_action_address() {
        let _rt = Table::new(0);
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
                    ..Actions::default()
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
        let mut nexthop = Some(bgp::Nexthop::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let result = Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut empty_attrs(),
            &mut nexthop,
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            s.remote_addr,
            None,
            None,
            false,
        );
        assert_eq!(result, Disposition::Accept);
        assert_eq!(
            nexthop,
            Some(bgp::Nexthop::V4(Ipv4Addr::new(192, 168, 1, 1)))
        );
    }

    #[test]
    fn policy_nexthop_action_self() {
        let _rt = Table::new(0);
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
                    ..Actions::default()
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
        let mut nexthop = Some(bgp::Nexthop::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let result = Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut empty_attrs(),
            &mut nexthop,
            local_addr,
            s.remote_addr,
            None,
            None,
            false,
        );
        assert_eq!(result, Disposition::Accept);
        assert_eq!(
            nexthop,
            Some(bgp::Nexthop::V4(Ipv4Addr::new(172, 16, 0, 1)))
        );
    }

    #[test]
    fn policy_nexthop_no_match_unchanged() {
        let _rt = Table::new(0);
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
                    ..Actions::default()
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
        let original = Some(bgp::Nexthop::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let mut nexthop = original;
        let _result = Table::apply_policy(
            &assignment,
            &s,
            &net,
            &mut empty_attrs(),
            &mut nexthop,
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            s.remote_addr,
            None,
            None,
            false,
        );
        assert_eq!(nexthop, original);
    }

    #[test]
    fn import_policy_with_nexthop_action_is_rejected() {
        // Nexthop rewriting in import policy is not allowed: the pre-policy
        // nexthop is stored in Path.nexthop rather than in the attribute list,
        // so a nexthop-set action would bypass Adj-RIB-In recording.
        let mut ptable = PolicyTable::new();
        ptable
            .add_statement(
                "st1",
                vec![],
                Some(Disposition::Accept),
                Actions {
                    nexthop: Some(NexthopAction::Address(IpAddr::V4(Ipv4Addr::new(
                        192, 168, 1, 1,
                    )))),
                    ..Actions::default()
                },
            )
            .unwrap();
        ptable.add_policy("pol1", vec!["st1".to_string()]).unwrap();
        let result = ptable.add_assignment(
            "ribs",
            PolicyDirection::Import,
            Disposition::Accept,
            vec!["pol1".to_string()],
        );
        assert!(
            result.is_err(),
            "import policy with nexthop action must be rejected"
        );
    }

    // --- Ord regression: higher-priority attribute must win ---

    #[test]
    fn best_path_local_pref_over_router_id() {
        // Regression: previously, a path losing on LOCAL_PREF could still
        // win on router_id due to missing "lose" checks in the comparison loop.
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        // s1: local_pref=200, router_id=2
        let s1 = source(1, 65001, 65000, 2);
        rt.insert(
            s1.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            attrs_with_local_pref(200),
            None,
            false,
            false,
            None,
            0u32,
        );
        // s2: local_pref=50, router_id=1 (better router_id, worse local_pref)
        let s2 = source(2, 65002, 65000, 1);
        let update = rt.insert(
            s2,
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            attrs_with_local_pref(50),
            None,
            false,
            false,
            None,
            0u32,
        );
        // s1 must remain best (higher local_pref wins over lower router_id)
        // s2 enters as a new current path, best unchanged
        assert!(!update.as_changed().unwrap().best_changed);
        assert!(update.as_changed().unwrap().any_changed);
        let best = update.as_changed().unwrap().new_best().unwrap();
        assert!(Arc::ptr_eq(&best.source, &s1));
    }

    #[test]
    fn replace_unfiltered_to_filtered_withdraws() {
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        let s1 = source(1, 65001, 65000, 1);
        // Insert unfiltered path
        let update = rt.insert(
            s1.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            false,
            false,
            None,
            0u32,
        );
        assert!(update.as_changed().unwrap().best_changed);
        // Replace with filtered → no unfiltered best remains → best_changed, new_best=None
        let update = rt.insert(
            s1,
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            true,
            false,
            None,
            0u32,
        );
        assert!(update.as_changed().unwrap().best_changed);
        assert!(update.as_changed().unwrap().new_best().is_none());
    }

    #[test]
    fn withdraw_source_is_old_best() {
        // When all paths become filtered, the update should indicate best_changed and new_best=None.
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        let s1 = source(1, 65001, 65000, 1);
        // s1 is unfiltered best
        rt.insert(
            s1.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            false,
            false,
            None,
            0u32,
        );
        // s2 inserts a filtered path
        let s2 = source(2, 65002, 65000, 2);
        rt.insert(
            s2.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            true,
            false,
            None,
            0u32,
        );
        // s1 gets replaced as filtered → all filtered → withdrawal
        let update = rt.insert(
            s1.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            true,
            false,
            None,
            0u32,
        );
        assert!(update.as_changed().unwrap().best_changed);
        assert!(update.as_changed().unwrap().new_best().is_none());
    }

    // --- best() with filtered head ---

    #[test]
    fn best_skips_filtered_paths() {
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        // filtered path (better router_id)
        rt.insert(
            source(1, 65001, 65000, 1),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            true,
            false,
            None,
            0u32,
        );
        // unfiltered path
        let s2 = source(2, 65002, 65000, 2);
        rt.insert(
            s2.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            false,
            false,
            None,
            0u32,
        );
        let bests = flat_best(&rt, &Family::IPV4);
        assert_eq!(bests.len(), 1);
        assert!(Arc::ptr_eq(&bests[0].1.source, &s2));
    }

    #[test]
    fn best_skips_all_filtered_destination() {
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        rt.insert(
            source(1, 65001, 65000, 1),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            true,
            false,
            None,
            0u32,
        );
        assert!(rt.collect_loc_rib_paths(&Family::IPV4).is_empty());
    }

    // --- remove() with filtered head ---

    #[test]
    fn remove_best_with_filtered_head() {
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        // Each peer produces its own Arc<Vec<Attribute>> (realistic: separate UPDATE messages).
        // filtered at head
        rt.insert(
            source(1, 65001, 65000, 1),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            attrs_with_local_pref(100),
            None,
            true,
            false,
            None,
            0u32,
        );
        // unfiltered best (router_id=2)
        let s2 = source(2, 65002, 65000, 2);
        rt.insert(
            s2.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            attrs_with_local_pref(100),
            None,
            false,
            false,
            None,
            0u32,
        );
        // unfiltered non-best (router_id=3)
        let s3 = source(3, 65003, 65000, 3);
        rt.insert(
            s3.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            attrs_with_local_pref(100),
            None,
            false,
            false,
            None,
            0u32,
        );
        // remove s2 (best) → s3 becomes new best
        let (update, _) = rt.remove(s2, Family::IPV4, net, 0, None);
        assert!(update.as_ref().unwrap().best_changed);
        let best = update.as_ref().unwrap().new_best().unwrap();
        assert!(Arc::ptr_eq(&best.source, &s3));
    }

    #[test]
    fn remove_last_unfiltered_withdraws() {
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        // filtered path
        rt.insert(
            source(1, 65001, 65000, 1),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            true,
            false,
            None,
            0u32,
        );
        // only unfiltered path
        let s2 = source(2, 65002, 65000, 2);
        rt.insert(
            s2.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            false,
            false,
            None,
            0u32,
        );
        // remove s2 → all filtered → withdrawal (best_changed=true, new_best=None)
        let (update, _) = rt.remove(s2, Family::IPV4, net, 0, None);
        assert!(update.as_ref().unwrap().best_changed);
        assert!(update.as_ref().unwrap().new_best().is_none());
    }

    // --- drop() with filtered head ---

    #[test]
    fn drop_best_with_filtered_head() {
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        let attrs = attrs_with_local_pref(100);
        // filtered at head
        rt.insert(
            source(1, 65001, 65000, 1),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            attrs.clone(),
            None,
            true,
            false,
            None,
            0u32,
        );
        // unfiltered best
        let s2 = source(2, 65002, 65000, 2);
        rt.insert(
            s2.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            attrs.clone(),
            None,
            false,
            false,
            None,
            0u32,
        );
        // unfiltered non-best
        let s3 = source(3, 65003, 65000, 3);
        rt.insert(
            s3.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            attrs.clone(),
            None,
            false,
            false,
            None,
            0u32,
        );
        // drop s2 → s3 becomes new best
        let (changes, _) = rt.drop(s2.remote_addr, Family::IPV4);
        assert_eq!(changes.len(), 1);
        assert!(changes[0].best_changed);
        let best = changes[0].new_best().unwrap();
        assert!(Arc::ptr_eq(&best.source, &s3));
    }

    #[test]
    fn drop_filtered_no_change() {
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        // filtered path from s1
        let s1 = source(1, 65001, 65000, 1);
        rt.insert(
            s1.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            true,
            false,
            None,
            0u32,
        );
        // unfiltered best from s2
        let s2 = source(2, 65002, 65000, 2);
        rt.insert(
            s2,
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            false,
            false,
            None,
            0u32,
        );
        // drop s1 (filtered) → no best change
        let (changes, _) = rt.drop(s1.remote_addr, Family::IPV4);
        assert!(changes.is_empty());
    }

    // --- state() counts ---

    #[test]
    fn state_counts_filtered_as_not_accepted() {
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        // 1 filtered path
        rt.insert(
            source(1, 65001, 65000, 1),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            true,
            false,
            None,
            0u32,
        );
        // 1 unfiltered path
        rt.insert(
            source(2, 65002, 65000, 2),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            false,
            false,
            None,
            0u32,
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
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        let s1 = source(1, 65001, 65000, 10); // router_id=10
        let s2 = source(2, 65002, 65000, 5); // router_id=5, better

        // Insert s1 → best, local_path_id=1
        let update = rt.insert(
            s1.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            false,
            false,
            None,
            0u32,
        );
        assert!(update.as_changed().unwrap().best_changed);
        let best = update.as_changed().unwrap().new_best().unwrap();
        assert_eq!(best.local_path_id, 1);

        // Insert s2 → new best (lower router_id)
        let update = rt.insert(
            s2.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            false,
            false,
            None,
            0u32,
        );
        assert!(update.as_changed().unwrap().best_changed);
        assert_eq!(update.as_changed().unwrap().current_paths.len(), 2);
        // s2 is the new best (rank 0 in current_paths)
        assert_eq!(
            update
                .as_changed()
                .unwrap()
                .new_best()
                .unwrap()
                .local_path_id,
            2
        );
        assert!(Arc::ptr_eq(
            &update.as_changed().unwrap().new_best().unwrap().source,
            &s2
        ));
        // s1 is at index 1 in current_paths
        let s1_path = update
            .as_changed()
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
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        let s1 = source(1, 65001, 65000, 1);

        let update = rt.insert(
            s1.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            false,
            false,
            None,
            0u32,
        );
        let original_id = update
            .as_changed()
            .unwrap()
            .new_best()
            .unwrap()
            .local_path_id;

        // Replace with new attributes
        let update = rt.insert(
            s1.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            attrs_with_local_pref(200),
            None,
            false,
            false,
            None,
            0u32,
        );
        // Same path_id preserved, replaced_path_id indicates what was replaced
        assert_eq!(
            update.as_changed().unwrap().replaced_path_id,
            Some(original_id)
        );
        let best = update.as_changed().unwrap().new_best().unwrap();
        assert_eq!(best.local_path_id, original_id);
    }

    #[test]
    fn stable_id_withdraw_uses_original_id() {
        // When a path is removed, the update indicates best_changed and the new best.
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);

        let s1 = source(1, 65001, 65000, 1); // best (router_id=1)
        let s2 = source(2, 65002, 65000, 2);
        let u1 = rt.insert(
            s1.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            false,
            false,
            None,
            0u32,
        );
        let s1_id = u1.as_changed().unwrap().new_best().unwrap().local_path_id;
        rt.insert(
            s2.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            false,
            false,
            None,
            0u32,
        );

        // Remove s1 → s2 becomes new best; s1_id was the old best
        let (update, _) = rt.remove(s1, Family::IPV4, net, 0, None);
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
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        let s1 = source(1, 65001, 65000, 1);
        let s2 = source(2, 65002, 65000, 2);

        rt.insert(
            s1.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            false,
            false,
            None,
            0u32,
        );
        rt.insert(
            s2.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            false,
            false,
            None,
            0u32,
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
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        let s = source(1, 65001, 65000, 1);
        rt.insert(
            s.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            attrs_with_origin(0),
            None,
            false,
            false,
            None,
            0u32,
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
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        let stale_src = source(1, 65001, 65000, 1); // router_id=1 (better tie-breaker)
        let fresh_src = source(2, 65002, 65000, 2); // router_id=2 (worse tie-breaker)

        rt.insert(
            stale_src.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            attrs_with_origin(0),
            None,
            false,
            false,
            None,
            0u32,
        );

        // Mark stale before the fresh route arrives (as GR does after session drop)
        stale_src.mark_stale();

        rt.insert(
            fresh_src.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            attrs_with_origin(0),
            None,
            false,
            false,
            None,
            0u32,
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
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        let s = source(1, 65001, 65000, 1);
        rt.insert(
            s.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            attrs_with_origin(0),
            None,
            false,
            false,
            None,
            0u32,
        );

        s.mark_stale();
        assert_eq!(flat_best(&rt, &Family::IPV4).len(), 1);

        rt.drop(s.remote_addr, Family::IPV4);
        assert!(rt.collect_loc_rib_paths(&Family::IPV4).is_empty());
    }

    // --- drop_stale ---

    #[test]
    fn drop_stale_removes_only_stale_paths_keeps_fresh() {
        // fresh_src and stale_src have routes for the same prefix.
        // drop_stale should remove the stale route but leave the fresh one.
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        let stale_src = source(1, 65001, 65000, 1);
        let fresh_src = source(2, 65001, 65000, 2);

        rt.insert(
            stale_src.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            attrs_with_origin(0),
            None,
            false,
            false,
            None,
            0u32,
        );
        rt.insert(
            fresh_src.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            attrs_with_origin(0),
            None,
            false,
            false,
            None,
            0u32,
        );

        stale_src.mark_stale();
        let (changes, _) = rt.drop_stale(stale_src.remote_addr, Family::IPV4, None);

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
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        let s = source(1, 65001, 65000, 1);
        rt.insert(
            s.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            attrs_with_origin(0),
            None,
            false,
            false,
            None,
            0u32,
        );

        s.mark_stale();
        rt.drop_stale(s.remote_addr, Family::IPV4, None);
        assert!(rt.collect_loc_rib_paths(&Family::IPV4).is_empty());
    }

    #[test]
    fn drop_stale_leaves_fresh_routes_untouched() {
        // Source has fresh (not stale) routes; drop_stale must not remove them.
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        let s = source(1, 65001, 65000, 1);
        rt.insert(
            s.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            attrs_with_origin(0),
            None,
            false,
            false,
            None,
            0u32,
        );

        let (changes, _) = rt.drop_stale(s.remote_addr, Family::IPV4, None);
        assert!(changes.is_empty());
        assert_eq!(flat_best(&rt, &Family::IPV4).len(), 1);
    }

    // --- restale ---

    #[test]
    fn restale_demotes_stale_when_fresh_alternative_exists() {
        // stale source has lower router_id (normally wins), fresh source has higher.
        // After mark_stale + restale(), fresh must be rank=1.
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        let stale_src = source(1, 65001, 65000, 1); // router_id 1 (better without stale)
        let fresh_src = source(2, 65001, 65000, 2); // router_id 2 (worse without stale)

        rt.insert(
            stale_src.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            attrs_with_origin(0),
            None,
            false,
            false,
            None,
            0u32,
        );
        rt.insert(
            fresh_src.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            attrs_with_origin(0),
            None,
            false,
            false,
            None,
            0u32,
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
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);

        // Session 1: insert a path, then mark it stale (simulating TCP drop + GR).
        let s1 = source(1, 65001, 65000, 1);
        rt.insert(
            s1.clone(),
            Family::IPV4,
            net.clone(),
            0, // remote_id / path_id
            nh(),
            attrs_with_origin(0),
            None,
            false,
            false,
            None,
            0u32,
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
            net.clone(),
            0, // same remote_id as session 1
            nh(),
            attrs_with_origin(0),
            None,
            false,
            false,
            None,
            0u32,
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
        let update = update
            .as_changed()
            .expect("insert of fresh path must produce NlriChange");
        assert!(update.best_changed);
    }

    /// GR helper: when the peer reconnects and sends a WITHDRAW for a route
    /// that is still in the RIB as a stale path from the old session, the
    /// stale path must be removed even though the Source Arc differs.
    #[test]
    fn gr_withdraw_removes_stale_path_from_prior_session() {
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);

        // Session 1: insert path, then mark stale.
        let s1 = source(1, 65001, 65000, 1);
        rt.insert(
            s1.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            attrs_with_origin(0),
            None,
            false,
            false,
            None,
            0u32,
        );
        s1.mark_stale();

        // Session 2 establishes (new Source Arc, same remote_addr).
        let s2 = source(1, 65001, 65000, 1);
        assert!(
            !Arc::ptr_eq(&s1, &s2),
            "precondition: different Arc objects"
        );

        // Session 2 sends WITHDRAW (id=0) for the same prefix.
        let (update, _) = rt.remove(s2, Family::IPV4, net, 0, None);

        // The stale path must be removed.
        assert!(
            update.is_some(),
            "WITHDRAW of stale path must produce NlriChange"
        );
        assert!(
            rt.collect_loc_rib_paths(&Family::IPV4).is_empty(),
            "RIB must be empty after withdraw"
        );
    }

    /// GR helper, Add-Path: only the path with a matching remote_id is replaced;
    /// stale paths with other path_ids survive until drop_stale.
    #[test]
    fn gr_fresh_path_replaces_only_matching_path_id() {
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);

        // Session 1: insert two Add-Path paths (id=1 and id=2), then go stale.
        let s1 = source(1, 65001, 65000, 1);
        rt.insert(
            s1.clone(),
            Family::IPV4,
            net.clone(),
            1,
            nh(),
            attrs_with_origin(0),
            None,
            false,
            false,
            None,
            0u32,
        );
        rt.insert(
            s1.clone(),
            Family::IPV4,
            net.clone(),
            2,
            nh(),
            attrs_with_origin(0),
            None,
            false,
            false,
            None,
            0u32,
        );
        s1.mark_stale();
        assert_eq!(flat_best(&rt, &Family::IPV4).len(), 2);

        // Session 2: re-sends only id=1.
        let s2 = source(1, 65001, 65000, 1);
        rt.insert(
            s2.clone(),
            Family::IPV4,
            net.clone(),
            1,
            nh(),
            attrs_with_origin(0),
            None,
            false,
            false,
            None,
            0u32,
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
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        let src = source(1, 65001, 65000, 1);

        rt.insert(
            src.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            attrs_with_origin(0),
            None,
            false,
            false,
            None,
            0u32,
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
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        let src = source(1, 65001, 65000, 1);

        rt.start_deferral(Family::IPV4);

        let update = rt.insert(
            src,
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            false,
            false,
            None,
            0u32,
        );
        assert!(
            update.as_changed().is_none(),
            "deferral must suppress insert changes"
        );
        assert!(
            rt.ribs.get(&Family::IPV4).unwrap().deferring,
            "deferring flag must be set"
        );
    }

    #[test]
    fn deferral_does_not_affect_other_families() {
        // Deferring IPv4 must not suppress IPv6 inserts.
        let mut rt = Table::new(0);
        let net6 = packet::Nlri::V6(packet::bgp::Ipv6Net {
            addr: std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
            mask: 32,
        });
        let src = source(1, 65001, 65000, 1);

        rt.start_deferral(Family::IPV4);

        let nh6 = Some(bgp::Nexthop::V6(std::net::Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0, 0, 0, 1,
        )));
        let update = rt.insert(
            src,
            Family::IPV6,
            net6,
            0,
            nh6,
            empty_attrs(),
            None,
            false,
            false,
            None,
            0u32,
        );
        assert!(
            update.as_changed().unwrap().best_changed || update.as_changed().unwrap().any_changed,
            "IPv6 insert must not be suppressed"
        );
    }

    #[test]
    fn end_deferral_returns_accumulated_routes() {
        // Routes inserted during deferral are returned by end_deferral().
        let mut rt = Table::new(0);
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
                None,
                false,
                false,
                None,
                0u32,
            );
            assert!(u.as_changed().is_none());
        }
        {
            let u = rt.insert(
                src,
                Family::IPV4,
                n2,
                0,
                nh(),
                empty_attrs(),
                None,
                false,
                false,
                None,
                0u32,
            );
            assert!(u.as_changed().is_none());
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
        let mut rt = Table::new(0);
        let changes = rt.end_deferral(Family::IPV4);
        assert!(changes.is_empty());
    }

    #[test]
    fn insert_after_end_deferral_distributes_normally() {
        // After deferral ends, subsequent inserts produce changes as usual.
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        let src = source(1, 65001, 65000, 1);

        rt.start_deferral(Family::IPV4);
        rt.end_deferral(Family::IPV4);

        let update = rt.insert(
            src,
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            false,
            false,
            None,
            0u32,
        );
        assert!(
            update.as_changed().unwrap().best_changed || update.as_changed().unwrap().any_changed,
            "insert after end_deferral must produce changes"
        );
    }

    // --- prefix_limit ---

    #[test]
    fn prefix_limit_blocks_new_prefix_when_exceeded() {
        // A fresh prefix must be rejected when the counter is already at max.
        let mut rt = Table::new(0);
        let src = source(1, 65001, 65000, 1);
        let counter = Arc::new(AtomicU64::new(1));
        let max: u32 = 1;
        let pl = Some((max, &counter));

        let net = nlri(10, 0, 0, 0, 24);
        let result = rt.insert(
            src,
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            false,
            false,
            pl,
            0u32,
        );
        assert!(
            matches!(result, InsertResult::PrefixLimitExceeded),
            "insert must return PrefixLimitExceeded when counter >= max"
        );
        // Route must not be stored.
        assert!(rt.collect_loc_rib_paths(&Family::IPV4).is_empty());
        // Counter must not be incremented further.
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn prefix_limit_allows_replacement_when_exceeded() {
        // Replacing an existing path for the same peer/path_id is always
        // allowed even when the counter is at max.
        let mut rt = Table::new(0);
        let src = source(1, 65001, 65000, 1);
        let counter = Arc::new(AtomicU64::new(0));
        let max: u32 = 1;

        // Insert first prefix (counter 0 → 1).
        let net1 = nlri(10, 0, 0, 0, 24);
        rt.insert(
            src.clone(),
            Family::IPV4,
            net1.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            false,
            false,
            Some((max, &counter)),
            0u32,
        );
        assert_eq!(counter.load(Ordering::Relaxed), 1);

        // Re-insert the same prefix (replacement, not new) must succeed even though counter == max.
        let result = rt.insert(
            src,
            Family::IPV4,
            net1,
            0,
            nh(),
            empty_attrs(),
            None,
            false,
            false,
            Some((max, &counter)),
            0u32,
        );
        assert!(
            !matches!(result, InsertResult::PrefixLimitExceeded),
            "replacement of existing prefix must not be blocked by prefix limit"
        );
        // Counter unchanged (replacement, not new).
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn prefix_limit_increments_counter_for_new_prefixes() {
        // Each genuinely new prefix increments the counter.
        let mut rt = Table::new(0);
        let src = source(1, 65001, 65000, 1);
        let counter = Arc::new(AtomicU64::new(0));
        let max: u32 = 3;

        for (i, net) in [
            nlri(10, 0, 0, 0, 24),
            nlri(10, 0, 1, 0, 24),
            nlri(10, 0, 2, 0, 24),
        ]
        .into_iter()
        .enumerate()
        {
            let result = rt.insert(
                src.clone(),
                Family::IPV4,
                net,
                0,
                nh(),
                empty_attrs(),
                None,
                false,
                false,
                Some((max, &counter)),
                0u32,
            );
            assert!(
                !matches!(result, InsertResult::PrefixLimitExceeded),
                "prefix {} must be accepted",
                i + 1
            );
            assert_eq!(counter.load(Ordering::Relaxed), (i + 1) as u64);
        }

        // Fourth prefix must be rejected.
        let net_extra = nlri(10, 0, 3, 0, 24);
        let result = rt.insert(
            src,
            Family::IPV4,
            net_extra,
            0,
            nh(),
            empty_attrs(),
            None,
            false,
            false,
            Some((max, &counter)),
            0u32,
        );
        assert!(matches!(result, InsertResult::PrefixLimitExceeded));
        assert_eq!(counter.load(Ordering::Relaxed), 3);
    }

    // --- destinations() / TableQuery tests ---

    /// Insert a path from `src` for `net` into `rt` with no filtering.
    fn insert_path(rt: &mut Table, src: &Arc<Source>, net: &packet::Nlri) {
        rt.insert(
            src.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            false,
            false,
            None,
            0u32,
        );
    }

    #[test]
    fn destinations_global_returns_all_paths() {
        let s1 = source(1, 65001, 65000, 1);
        let s2 = source(2, 65002, 65000, 2);
        let n1 = nlri(10, 0, 0, 0, 24);
        let n2 = nlri(10, 0, 1, 0, 24);

        let mut rt = Table::new(0);
        insert_path(&mut rt, &s1, &n1);
        insert_path(&mut rt, &s2, &n2);

        let dests: Vec<_> = rt
            .destinations(TableQuery::Global, Family::IPV4, vec![], false)
            .collect();
        assert_eq!(dests.len(), 2);
        assert!(dests.iter().all(|d| !d.paths.is_empty()));
    }

    #[test]
    fn destinations_adj_in_filters_by_peer() {
        let s1 = source(1, 65001, 65000, 1);
        let s2 = source(2, 65002, 65000, 2);
        let n1 = nlri(10, 0, 0, 0, 24);

        let mut rt = Table::new(0);
        insert_path(&mut rt, &s1, &n1);
        insert_path(&mut rt, &s2, &n1);

        let peer1 = s1.remote_addr;
        let dests: Vec<_> = rt
            .destinations(TableQuery::AdjIn(peer1), Family::IPV4, vec![], false)
            .collect();

        assert_eq!(dests.len(), 1);
        assert_eq!(dests[0].paths.len(), 1);
        assert_eq!(dests[0].paths[0].source.remote_addr, peer1);
    }

    fn exact(net: packet::Nlri) -> PrefixFilter {
        PrefixFilter {
            prefix: net,
            lookup_type: LookupType::Exact,
        }
    }

    fn longer(net: packet::Nlri) -> PrefixFilter {
        PrefixFilter {
            prefix: net,
            lookup_type: LookupType::Longer,
        }
    }

    fn shorter(net: packet::Nlri) -> PrefixFilter {
        PrefixFilter {
            prefix: net,
            lookup_type: LookupType::Shorter,
        }
    }

    #[test]
    fn destinations_prefix_filter_exact_returns_only_matching() {
        let s1 = source(1, 65001, 65000, 1);
        let n1 = nlri(10, 0, 0, 0, 24);
        let n2 = nlri(10, 0, 1, 0, 24);
        let n3 = nlri(10, 0, 2, 0, 24);

        let mut rt = Table::new(0);
        insert_path(&mut rt, &s1, &n1);
        insert_path(&mut rt, &s1, &n2);
        insert_path(&mut rt, &s1, &n3);

        let dests: Vec<_> = rt
            .destinations(
                TableQuery::Global,
                Family::IPV4,
                vec![exact(n2.clone())],
                false,
            )
            .collect();

        assert_eq!(dests.len(), 1);
        assert_eq!(dests[0].net, n2);
    }

    #[test]
    fn destinations_prefix_filter_empty_returns_all() {
        let s1 = source(1, 65001, 65000, 1);
        let n1 = nlri(10, 0, 0, 0, 24);
        let n2 = nlri(10, 0, 1, 0, 24);

        let mut rt = Table::new(0);
        insert_path(&mut rt, &s1, &n1);
        insert_path(&mut rt, &s1, &n2);

        let dests: Vec<_> = rt
            .destinations(TableQuery::Global, Family::IPV4, vec![], false)
            .collect();
        assert_eq!(dests.len(), 2);
    }

    #[test]
    fn destinations_prefix_filter_longer_returns_more_specific() {
        let s1 = source(1, 65001, 65000, 1);
        // supernet: 10.0.0.0/16
        let super16 = nlri(10, 0, 0, 0, 16);
        // contained: 10.0.1.0/24 and 10.0.2.0/24
        let sub24a = nlri(10, 0, 1, 0, 24);
        let sub24b = nlri(10, 0, 2, 0, 24);
        // outside: 10.1.0.0/24
        let other = nlri(10, 1, 0, 0, 24);

        let mut rt = Table::new(0);
        insert_path(&mut rt, &s1, &super16);
        insert_path(&mut rt, &s1, &sub24a);
        insert_path(&mut rt, &s1, &sub24b);
        insert_path(&mut rt, &s1, &other);

        // Longer query against 10.0.0.0/16: should return /16, /24, /24 inside it.
        let mut nets: Vec<_> = rt
            .destinations(
                TableQuery::Global,
                Family::IPV4,
                vec![longer(super16.clone())],
                false,
            )
            .map(|d| d.net)
            .collect();
        nets.sort_by_key(|n| n.to_string());

        assert_eq!(nets.len(), 3);
        assert!(nets.contains(&super16));
        assert!(nets.contains(&sub24a));
        assert!(nets.contains(&sub24b));
        assert!(!nets.contains(&other));
    }

    #[test]
    fn destinations_prefix_filter_shorter_returns_less_specific() {
        let s1 = source(1, 65001, 65000, 1);
        let super16 = nlri(10, 0, 0, 0, 16);
        let sub24 = nlri(10, 0, 1, 0, 24);
        let other = nlri(10, 1, 0, 0, 24);

        let mut rt = Table::new(0);
        insert_path(&mut rt, &s1, &super16);
        insert_path(&mut rt, &s1, &sub24);
        insert_path(&mut rt, &s1, &other);

        // Shorter query against 10.0.1.0/24: should return /24 itself and /16 (less specific).
        let mut nets: Vec<_> = rt
            .destinations(
                TableQuery::Global,
                Family::IPV4,
                vec![shorter(sub24.clone())],
                false,
            )
            .map(|d| d.net)
            .collect();
        nets.sort_by_key(|n| n.to_string());

        assert_eq!(nets.len(), 2);
        assert!(nets.contains(&super16));
        assert!(nets.contains(&sub24));
        assert!(!nets.contains(&other));
    }

    fn insert_filtered_path(rt: &mut Table, src: &Arc<Source>, net: &packet::Nlri) {
        rt.insert(
            src.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            empty_attrs(),
            None,
            true, // filtered = true
            false,
            None,
            0u32,
        );
    }

    #[test]
    fn destinations_enable_filtered_false_excludes_filtered_paths() {
        let s1 = source(1, 65001, 65000, 1);
        let n1 = nlri(10, 0, 0, 0, 24);

        let mut rt = Table::new(0);
        insert_filtered_path(&mut rt, &s1, &n1);

        // Without enable_filtered the destination has no unfiltered paths and is omitted.
        let dests: Vec<_> = rt
            .destinations(TableQuery::Global, Family::IPV4, vec![], false)
            .collect();
        assert!(dests.is_empty());
    }

    #[test]
    fn destinations_enable_filtered_true_includes_filtered_paths() {
        let s1 = source(1, 65001, 65000, 1);
        let n1 = nlri(10, 0, 0, 0, 24);
        let n2 = nlri(10, 0, 1, 0, 24);

        let mut rt = Table::new(0);
        insert_path(&mut rt, &s1, &n1); // unfiltered
        insert_filtered_path(&mut rt, &s1, &n2); // filtered

        let dests: Vec<_> = rt
            .destinations(TableQuery::Global, Family::IPV4, vec![], true)
            .collect();

        assert_eq!(dests.len(), 2);
        let d1 = dests.iter().find(|d| d.net == n1).unwrap();
        let d2 = dests.iter().find(|d| d.net == n2).unwrap();
        assert!(!d1.paths[0].filtered);
        assert!(d2.paths[0].filtered);
    }

    // --- Adj-RIB-In (original_attr) tests ---

    #[test]
    fn adj_in_returns_original_attr_not_post_policy() {
        // Simulate import policy that modifies LOCAL_PREF:
        //   original (pre-policy) = 100, post-policy = 200.
        // destinations(AdjIn) must expose the original; Global exposes post-policy.
        let s1 = source(1, 65001, 65000, 1);
        let n1 = nlri(10, 0, 0, 0, 24);
        let post_policy = attrs_with_local_pref(200);
        let original = attrs_with_local_pref(100);

        let mut rt = Table::new(0);
        rt.insert(
            s1.clone(),
            Family::IPV4,
            n1.clone(),
            0,
            nh(),
            post_policy.clone(),
            Some(original.clone()),
            false,
            false,
            None,
            0u32,
        );

        let peer = s1.remote_addr;

        let global: Vec<_> = rt
            .destinations(TableQuery::Global, Family::IPV4, vec![], false)
            .collect();
        assert_eq!(global.len(), 1);
        assert_eq!(global[0].paths[0].attr, post_policy);

        let adj_in: Vec<_> = rt
            .destinations(TableQuery::AdjIn(peer), Family::IPV4, vec![], false)
            .collect();
        assert_eq!(adj_in.len(), 1);
        assert_eq!(adj_in[0].paths[0].attr, original);
    }

    #[test]
    fn adj_in_no_policy_attr_unchanged() {
        // When no policy modifies attrs, original_attr == post-policy attr.
        // Both Global and AdjIn views return the same content.
        let s1 = source(1, 65001, 65000, 1);
        let n1 = nlri(10, 0, 0, 0, 24);
        let attr = attrs_with_local_pref(100);

        let mut rt = Table::new(0);
        // Pass None for original_attr: the insert() body falls back to Arc::clone(&attr).
        rt.insert(
            s1.clone(),
            Family::IPV4,
            n1.clone(),
            0,
            nh(),
            attr.clone(),
            None,
            false,
            false,
            None,
            0u32,
        );

        let peer = s1.remote_addr;

        let global: Vec<_> = rt
            .destinations(TableQuery::Global, Family::IPV4, vec![], false)
            .collect();
        let adj_in: Vec<_> = rt
            .destinations(TableQuery::AdjIn(peer), Family::IPV4, vec![], false)
            .collect();

        assert_eq!(global[0].paths[0].attr, attr);
        assert_eq!(adj_in[0].paths[0].attr, attr);
    }

    #[test]
    fn iter_reach_returns_original_attr() {
        // iter_reach() is used by BMP RouteMonitoring and must carry pre-policy attrs.
        let s1 = source(1, 65001, 65000, 1);
        let n1 = nlri(10, 0, 0, 0, 24);
        let post_policy = attrs_with_local_pref(200);
        let original = attrs_with_local_pref(100);

        let mut rt = Table::new(0);
        rt.insert(
            s1.clone(),
            Family::IPV4,
            n1.clone(),
            0,
            nh(),
            post_policy,
            Some(original.clone()),
            false,
            false,
            None,
            0u32,
        );

        let reaches: Vec<_> = rt.iter_reach(Family::IPV4).collect();
        assert_eq!(reaches.len(), 1);
        assert_eq!(reaches[0].attr, original);
    }

    // --- Vrf::can_import ---

    fn make_vrf(import_rts: Vec<[u8; 8]>) -> Vrf {
        Vrf {
            name: "test".to_string(),
            rd: packet::rd::RouteDistinguisher::TwoOctetAs {
                admin: 65000,
                assigned: 1,
            },
            import_rt: import_rts.into_iter().collect(),
            export_rt: Vec::new(),
            label: packet::mpls::MplsLabel::new(16),
            id: 0,
        }
    }

    fn ext_community_attr(rts: &[[u8; 8]]) -> packet::Attribute {
        let mut data = Vec::with_capacity(rts.len() * 8);
        for rt in rts {
            data.extend_from_slice(rt);
        }
        packet::Attribute::new_with_bin(packet::Attribute::EXTENDED_COMMUNITY, data).unwrap()
    }

    #[test]
    fn can_import_matching_rt() {
        let rt: [u8; 8] = [0x00, 0x02, 0xfd, 0xe8, 0x00, 0x00, 0x00, 0x64];
        let vrf = make_vrf(vec![rt]);
        let attrs = vec![ext_community_attr(&[rt])];
        assert!(vrf.can_import(&attrs));
    }

    #[test]
    fn can_import_no_match() {
        let rt_import: [u8; 8] = [0x00, 0x02, 0xfd, 0xe8, 0x00, 0x00, 0x00, 0x64];
        let rt_other: [u8; 8] = [0x00, 0x02, 0xfd, 0xe8, 0x00, 0x00, 0x00, 0x65];
        let vrf = make_vrf(vec![rt_import]);
        let attrs = vec![ext_community_attr(&[rt_other])];
        assert!(!vrf.can_import(&attrs));
    }

    #[test]
    fn can_import_multiple_rts_one_matches() {
        let rt_a: [u8; 8] = [0x00, 0x02, 0xfd, 0xe8, 0x00, 0x00, 0x00, 0x01];
        let rt_b: [u8; 8] = [0x00, 0x02, 0xfd, 0xe8, 0x00, 0x00, 0x00, 0x02];
        let vrf = make_vrf(vec![rt_b]);
        // path carries both RT A and RT B; RT B matches
        let attrs = vec![ext_community_attr(&[rt_a, rt_b])];
        assert!(vrf.can_import(&attrs));
    }

    #[test]
    fn can_import_empty_import_rt() {
        let rt: [u8; 8] = [0x00, 0x02, 0xfd, 0xe8, 0x00, 0x00, 0x00, 0x64];
        let vrf = make_vrf(vec![]);
        let attrs = vec![ext_community_attr(&[rt])];
        assert!(!vrf.can_import(&attrs));
    }

    #[test]
    fn can_import_no_ext_community_attr() {
        let rt: [u8; 8] = [0x00, 0x02, 0xfd, 0xe8, 0x00, 0x00, 0x00, 0x64];
        let vrf = make_vrf(vec![rt]);
        let attrs: Vec<packet::Attribute> = vec![];
        assert!(!vrf.can_import(&attrs));
    }

    // --- vpn_to_local_nlri ---

    #[test]
    fn vpn_to_local_nlri_v4() {
        use std::net::Ipv4Addr;
        let prefix = packet::bgp::Ipv4Net {
            addr: Ipv4Addr::new(10, 0, 1, 0),
            mask: 24,
        };
        let rd = packet::rd::RouteDistinguisher::TwoOctetAs {
            admin: 65000,
            assigned: 100,
        };
        let labels = packet::mpls::MplsLabelStack::new(vec![packet::mpls::MplsLabel::new(16)]);
        let vpn = packet::Nlri::VpnV4(packet::vpn::VpnV4Nlri { prefix, rd, labels });
        let local = vpn_to_local_nlri(&vpn).unwrap();
        assert_eq!(local, packet::Nlri::V4(prefix));
    }

    #[test]
    fn vpn_to_local_nlri_non_vpn_returns_none() {
        use std::net::Ipv4Addr;
        let plain = packet::Nlri::V4(packet::bgp::Ipv4Net {
            addr: Ipv4Addr::new(10, 0, 0, 0),
            mask: 8,
        });
        assert!(vpn_to_local_nlri(&plain).is_none());
    }

    fn rs_source(addr: u8, remote_asn: u32) -> Arc<Source> {
        Arc::new(Source::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, addr)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 254)),
            remote_asn,
            65000,
            Ipv4Addr::new(0, 0, 0, addr),
            PeerRole::RsClient,
        ))
    }

    #[test]
    fn rs_local_returns_other_rs_client_best_path() {
        let peer1 = rs_source(1, 65001);
        let peer2 = rs_source(2, 65002);
        let n1 = nlri(10, 0, 1, 0, 24);

        let mut rt = Table::new(0);
        insert_path(&mut rt, &peer2, &n1);

        let peer1_addr = peer1.remote_addr;
        let dests: Vec<_> = rt
            .destinations(TableQuery::RsLocal(peer1_addr), Family::IPV4, vec![], false)
            .collect();
        assert_eq!(dests.len(), 1);
        assert_eq!(dests[0].paths.len(), 1);
        assert_eq!(dests[0].paths[0].source.remote_addr, peer2.remote_addr);
    }

    #[test]
    fn rs_local_excludes_queried_peer_own_paths() {
        let peer1 = rs_source(1, 65001);
        let peer2 = rs_source(2, 65002);
        let n1 = nlri(10, 0, 1, 0, 24);

        let mut rt = Table::new(0);
        insert_path(&mut rt, &peer1, &n1);
        insert_path(&mut rt, &peer2, &n1);

        // RsLocal(peer1) must not include peer1's own path.
        let peer1_addr = peer1.remote_addr;
        let dests: Vec<_> = rt
            .destinations(TableQuery::RsLocal(peer1_addr), Family::IPV4, vec![], false)
            .collect();
        assert_eq!(dests.len(), 1);
        assert_eq!(dests[0].paths.len(), 1);
        assert_eq!(dests[0].paths[0].source.remote_addr, peer2.remote_addr);
    }

    #[test]
    fn rs_local_excludes_non_rs_client_paths() {
        // peer1 is RS client; peer2 is a regular eBGP peer (rs_client=false).
        let peer1 = rs_source(1, 65001);
        let peer2 = source(2, 65002, 65000, 2); // rs_client=false
        let n1 = nlri(10, 0, 1, 0, 24);

        let mut rt = Table::new(0);
        insert_path(&mut rt, &peer2, &n1);

        // RsLocal(peer1) must not include non-RS-client peer2's path.
        let peer1_addr = peer1.remote_addr;
        let dests: Vec<_> = rt
            .destinations(TableQuery::RsLocal(peer1_addr), Family::IPV4, vec![], false)
            .collect();
        assert_eq!(dests.len(), 0);
    }

    #[test]
    fn rs_local_empty_when_no_other_rs_clients() {
        let peer1 = rs_source(1, 65001);
        let n1 = nlri(10, 0, 1, 0, 24);

        let mut rt = Table::new(0);
        insert_path(&mut rt, &peer1, &n1);

        let peer1_addr = peer1.remote_addr;
        let dests: Vec<_> = rt
            .destinations(TableQuery::RsLocal(peer1_addr), Family::IPV4, vec![], false)
            .collect();
        assert_eq!(dests.len(), 0, "no other RS clients -> empty result");
    }

    #[test]
    fn rs_local_uses_original_attr() {
        let peer1 = rs_source(1, 65001);
        let peer2 = rs_source(2, 65002);
        let n1 = nlri(10, 0, 1, 0, 24);

        // Insert peer2's path; original_attr differs from post-import attr.
        let original = attrs_with_local_pref(200);
        let post_import = attrs_with_local_pref(100);
        let mut rt = Table::new(0);
        rt.insert(
            peer2.clone(),
            Family::IPV4,
            n1.clone(),
            0,
            nh(),
            post_import.clone(),
            Some(original.clone()),
            false,
            false,
            None,
            0u32,
        );

        let peer1_addr = peer1.remote_addr;
        let dests: Vec<_> = rt
            .destinations(TableQuery::RsLocal(peer1_addr), Family::IPV4, vec![], false)
            .collect();
        assert_eq!(dests.len(), 1);
        // RsLocal must expose original_attr (pre-import-policy), not post-import.
        assert_eq!(dests[0].paths[0].attr, original);
    }

    fn make_nlri_change(paths: Vec<Path>) -> NlriChange {
        NlriChange {
            family: Family::IPV4,
            net: nlri(10, 0, 0, 0, 24),
            dest_id: 1,
            best_changed: true,
            any_changed: true,
            replaced_path_id: None,
            current_paths: Arc::new(paths),
        }
    }

    fn path_with_nh(src: Arc<Source>, nexthop_addr: u8, attr: Arc<Vec<packet::Attribute>>) -> Path {
        Path {
            local_path_id: 0,
            source: src,
            nexthop: Some(bgp::Nexthop::V4(Ipv4Addr::new(10, 0, 0, nexthop_addr))),
            attr,
        }
    }

    #[test]
    fn ecmp_paths_empty_when_no_paths() {
        let change = make_nlri_change(vec![]);
        assert!(change.ecmp_paths().is_empty());
    }

    #[test]
    fn ecmp_paths_single_path() {
        let src = source(1, 65001, 65000, 1);
        let change = make_nlri_change(vec![path_with_nh(src, 1, empty_attrs())]);
        assert_eq!(change.ecmp_paths().len(), 1);
    }

    #[test]
    fn ecmp_paths_two_equal_paths() {
        // Two iBGP paths with identical attributes differ only in router-id
        // (captured in source.router_id) -- both should be ECMP candidates.
        let src1 = source(1, 65000, 65000, 1);
        let src2 = source(2, 65000, 65000, 2);
        let attr = empty_attrs();
        let change = make_nlri_change(vec![
            path_with_nh(src1, 1, attr.clone()),
            path_with_nh(src2, 2, attr.clone()),
        ]);
        assert_eq!(change.ecmp_paths().len(), 2);
    }

    #[test]
    fn ecmp_paths_stops_at_lower_local_pref() {
        // First path has LocalPref 200, second has 100 -- only the first is ECMP.
        let src1 = source(1, 65000, 65000, 1);
        let src2 = source(2, 65000, 65000, 2);
        let change = make_nlri_change(vec![
            path_with_nh(src1, 1, attrs_with_local_pref(200)),
            path_with_nh(src2, 2, attrs_with_local_pref(100)),
        ]);
        assert_eq!(change.ecmp_paths().len(), 1);
    }

    #[test]
    fn ecmp_paths_stops_at_longer_as_path() {
        let src1 = source(1, 65001, 65000, 1);
        let src2 = source(2, 65002, 65000, 2);
        let change = make_nlri_change(vec![
            path_with_nh(src1, 1, attrs_with_as_path_len(1)),
            path_with_nh(src2, 2, attrs_with_as_path_len(2)),
        ]);
        assert_eq!(change.ecmp_paths().len(), 1);
    }

    // --- EVPN Type-2 best-path selection ---

    fn evpn_type2_nlri(etag: u32) -> packet::Nlri {
        use packet::evpn::{Esi, EvpnNlri, MacIpAdvertisement};
        use packet::rd::RouteDistinguisher;
        packet::Nlri::Evpn(EvpnNlri::MacIpAdvertisement(MacIpAdvertisement {
            rd: RouteDistinguisher::TwoOctetAs {
                admin: 1,
                assigned: 1,
            },
            esi: Esi::ZERO,
            etag,
            mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            ip: None,
            label1: 100,
            label2: None,
        }))
    }

    fn attrs_with_mac_mobility(seq: u32) -> Arc<Vec<packet::Attribute>> {
        // Extended Community: type=0x06 (EVPN), subtype=0x00 (MAC Mobility),
        // flags=0x00 (non-sticky), reserved=0x00, seq (4 bytes big-endian).
        let mut ec = vec![0x06u8, 0x00, 0x00, 0x00];
        ec.extend_from_slice(&seq.to_be_bytes());
        Arc::new(vec![
            packet::Attribute::new_with_bin(packet::Attribute::EXTENDED_COMMUNITY, ec).unwrap(),
        ])
    }

    fn evpn_insert(
        rt: &mut Table,
        src: &Arc<Source>,
        net: &packet::Nlri,
        attrs: Arc<Vec<packet::Attribute>>,
    ) {
        rt.insert(
            src.clone(),
            Family::L2VPN_EVPN,
            net.clone(),
            0,
            nh(),
            attrs,
            None,
            false,
            false,
            None,
            0u32,
        );
    }

    #[test]
    fn evpn_type2_higher_mac_mobility_seq_wins() {
        let src1 = source(1, 65001, 65000, 1);
        let src2 = source(2, 65002, 65000, 2);
        let net = evpn_type2_nlri(0);
        let mut rt = Table::new(0);
        // src1 advertises seq=1, src2 advertises seq=5; src2 should win.
        evpn_insert(&mut rt, &src1, &net, attrs_with_mac_mobility(1));
        evpn_insert(&mut rt, &src2, &net, attrs_with_mac_mobility(5));
        let dests: Vec<_> = rt
            .destinations(TableQuery::Global, Family::L2VPN_EVPN, vec![], false)
            .collect();
        assert_eq!(dests.len(), 1);
        let best_src = dests[0].paths[0].source.remote_addr;
        assert_eq!(best_src, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
    }

    #[test]
    fn evpn_type2_with_mobility_beats_without() {
        let src1 = source(1, 65001, 65000, 1);
        let src2 = source(2, 65002, 65000, 2);
        let net = evpn_type2_nlri(0);
        let mut rt = Table::new(0);
        // src1 has no MAC Mobility, src2 has seq=1; src2 wins.
        evpn_insert(&mut rt, &src1, &net, empty_attrs());
        evpn_insert(&mut rt, &src2, &net, attrs_with_mac_mobility(1));
        let dests: Vec<_> = rt
            .destinations(TableQuery::Global, Family::L2VPN_EVPN, vec![], false)
            .collect();
        assert_eq!(dests.len(), 1);
        let best_src = dests[0].paths[0].source.remote_addr;
        assert_eq!(best_src, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
    }

    #[test]
    fn evpn_type2_equal_seq_falls_through_to_standard() {
        // Both have seq=3; standard BGP best-path (router-id) decides.
        // Lower router-id wins in iBGP (both are iBGP peers here).
        let src1 = source(1, 65000, 65000, 1); // router_id = 0.0.0.1
        let src2 = source(2, 65000, 65000, 2); // router_id = 0.0.0.2
        let net = evpn_type2_nlri(0);
        let mut rt = Table::new(0);
        evpn_insert(&mut rt, &src1, &net, attrs_with_mac_mobility(3));
        evpn_insert(&mut rt, &src2, &net, attrs_with_mac_mobility(3));
        let dests: Vec<_> = rt
            .destinations(TableQuery::Global, Family::L2VPN_EVPN, vec![], false)
            .collect();
        assert_eq!(dests.len(), 1);
        // src1 has lower router-id, so it should win.
        let best_src = dests[0].paths[0].source.remote_addr;
        assert_eq!(best_src, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn evpn_type2_no_mobility_uses_standard_best_path() {
        // Neither path has MAC Mobility; standard BGP best-path applies.
        let src1 = source(1, 65000, 65000, 1);
        let src2 = source(2, 65000, 65000, 2);
        let net = evpn_type2_nlri(0);
        let mut rt = Table::new(0);
        evpn_insert(&mut rt, &src1, &net, empty_attrs());
        evpn_insert(&mut rt, &src2, &net, empty_attrs());
        let dests: Vec<_> = rt
            .destinations(TableQuery::Global, Family::L2VPN_EVPN, vec![], false)
            .collect();
        assert_eq!(dests.len(), 1);
        let best_src = dests[0].paths[0].source.remote_addr;
        assert_eq!(best_src, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    }

    // -------------------------------------------------------------------------
    // collect_adj_in_paths
    // -------------------------------------------------------------------------

    fn insert_for_family(rt: &mut Table, src: &Arc<Source>, family: Family, a: u8) {
        rt.insert(
            src.clone(),
            family,
            nlri(a, 0, 0, 0, 8),
            0,
            nh(),
            empty_attrs(),
            None,
            false,
            false,
            None,
            0u32,
        );
    }

    #[test]
    fn collect_adj_in_paths_no_family_filter_returns_all_families() {
        let peer_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let s = source(1, 65001, 65000, 1);
        let mut rt = Table::new(0);
        insert_for_family(&mut rt, &s, Family::IPV4, 1);
        insert_for_family(&mut rt, &s, Family::RTC, 2);

        let paths = rt.collect_adj_in_paths(peer_addr, None, false);
        assert_eq!(paths.len(), 2);
    }

    #[test]
    fn collect_adj_in_paths_family_filter_returns_only_matching_family() {
        let peer_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let s = source(1, 65001, 65000, 1);
        let mut rt = Table::new(0);
        insert_for_family(&mut rt, &s, Family::IPV4, 1);
        insert_for_family(&mut rt, &s, Family::RTC, 2);

        let paths = rt.collect_adj_in_paths(peer_addr, Some(Family::RTC), false);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].0, Family::RTC);
    }

    #[test]
    fn collect_adj_in_paths_stale_excluded_when_include_stale_false() {
        let peer_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let s_fresh = source(1, 65001, 65000, 1);
        let s_stale = source(1, 65001, 65000, 1);
        s_stale.mark_stale();

        let mut rt = Table::new(0);
        insert_for_family(&mut rt, &s_fresh, Family::RTC, 1);
        insert_for_family(&mut rt, &s_stale, Family::RTC, 2);

        let paths = rt.collect_adj_in_paths(peer_addr, Some(Family::RTC), false);
        assert_eq!(paths.len(), 1);
        assert!(!paths[0].4.is_stale());
    }

    #[test]
    fn collect_adj_in_paths_stale_included_when_include_stale_true() {
        let peer_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let s_fresh = source(1, 65001, 65000, 1);
        let s_stale = source(1, 65001, 65000, 1);
        s_stale.mark_stale();

        let mut rt = Table::new(0);
        insert_for_family(&mut rt, &s_fresh, Family::RTC, 1);
        insert_for_family(&mut rt, &s_stale, Family::RTC, 2);

        let paths = rt.collect_adj_in_paths(peer_addr, Some(Family::RTC), true);
        assert_eq!(paths.len(), 2);
        let stale_count = paths.iter().filter(|p| p.4.is_stale()).count();
        assert_eq!(stale_count, 1);
    }

    // =========================================================================
    // restale_llgr / drop_no_llgr / drop_llgr_stale tests
    // =========================================================================

    fn community_attr(community: u32) -> packet::Attribute {
        packet::Attribute::new_with_bin(
            packet::Attribute::COMMUNITY,
            community.to_be_bytes().to_vec(),
        )
        .unwrap()
    }

    fn attrs_with_no_llgr() -> Arc<Vec<packet::Attribute>> {
        Arc::new(vec![community_attr(0xffff_0007)])
    }

    fn attrs_with_llgr_stale() -> Arc<Vec<packet::Attribute>> {
        Arc::new(vec![community_attr(0xffff_0006)])
    }

    fn insert_with_attrs(
        rt: &mut Table,
        source: &Arc<Source>,
        net: &packet::Nlri,
        attrs: Arc<Vec<packet::Attribute>>,
    ) {
        rt.insert(
            source.clone(),
            Family::IPV4,
            net.clone(),
            0,
            nh(),
            attrs,
            None,
            false,
            false,
            None,
            0u32,
        );
    }

    // --- restale_llgr ---

    #[test]
    fn restale_llgr_sets_source_flag() {
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        let s = source(1, 65001, 65000, 1);
        insert_with_attrs(&mut rt, &s, &net, attrs_with_origin(0));

        assert!(!s.is_llgr_stale());
        rt.restale_llgr(s.remote_addr, Family::IPV4);
        assert!(s.is_llgr_stale());
    }

    #[test]
    fn restale_llgr_keeps_routes() {
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        let s = source(1, 65001, 65000, 1);
        insert_with_attrs(&mut rt, &s, &net, attrs_with_origin(0));

        rt.restale_llgr(s.remote_addr, Family::IPV4);

        assert_eq!(flat_best(&rt, &Family::IPV4).len(), 1);
    }

    #[test]
    fn restale_llgr_emits_change_when_best_demoted() {
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        // s1 has lower router-id so it wins the tiebreak before marking.
        let s1 = source(1, 65001, 65000, 1);
        let s2 = source(2, 65002, 65000, 2);
        // Equal local-pref: LLGR stale flag becomes the tiebreaker.
        insert_with_attrs(&mut rt, &s1, &net, attrs_with_local_pref(100));
        insert_with_attrs(&mut rt, &s2, &net, attrs_with_local_pref(100));

        let changes = rt.restale_llgr(s1.remote_addr, Family::IPV4);

        assert!(!changes.is_empty());
        assert!(changes[0].best_changed);
        let best = flat_best(&rt, &Family::IPV4);
        assert_eq!(best[0].1.source.remote_addr, s2.remote_addr);
    }

    // --- drop_no_llgr ---

    #[test]
    fn drop_no_llgr_removes_no_llgr_routes() {
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        let s = source(1, 65001, 65000, 1);
        insert_with_attrs(&mut rt, &s, &net, attrs_with_no_llgr());

        let (changes, nexthops) = rt.drop_no_llgr(s.remote_addr, Family::IPV4, None);

        assert!(flat_best(&rt, &Family::IPV4).is_empty());
        assert_eq!(changes.len(), 1);
        assert!(changes[0].current_paths.is_empty());
        assert_eq!(nexthops.len(), 1);
    }

    #[test]
    fn drop_no_llgr_keeps_normal_routes() {
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        let s = source(1, 65001, 65000, 1);
        insert_with_attrs(&mut rt, &s, &net, attrs_with_origin(0));

        let (changes, nexthops) = rt.drop_no_llgr(s.remote_addr, Family::IPV4, None);

        assert_eq!(flat_best(&rt, &Family::IPV4).len(), 1);
        assert!(changes.is_empty());
        assert!(nexthops.is_empty());
    }

    #[test]
    fn drop_no_llgr_keeps_other_peer_no_llgr_route() {
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        let s1 = source(1, 65001, 65000, 1);
        let s2 = source(2, 65002, 65000, 2);
        insert_with_attrs(&mut rt, &s1, &net, attrs_with_no_llgr());
        insert_with_attrs(&mut rt, &s2, &net, attrs_with_origin(0));

        rt.drop_no_llgr(s1.remote_addr, Family::IPV4, None);

        let best = flat_best(&rt, &Family::IPV4);
        assert_eq!(best.len(), 1);
        assert_eq!(best[0].1.source.remote_addr, s2.remote_addr);
    }

    #[test]
    fn drop_llgr_stale_removes_llgr_stale_routes() {
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        let s = source(1, 65001, 65000, 1);
        insert_with_attrs(&mut rt, &s, &net, attrs_with_origin(0));
        s.mark_llgr_stale();

        let (changes, _) = rt.drop_llgr_stale(s.remote_addr, Family::IPV4, None);

        assert!(flat_best(&rt, &Family::IPV4).is_empty());
        assert_eq!(changes.len(), 1);
        assert!(changes[0].current_paths.is_empty());
    }

    #[test]
    fn drop_llgr_stale_keeps_routes_from_other_peer() {
        // drop_llgr_stale only removes routes from the target addr;
        // routes from other peers (even if they carry LLGR_STALE community)
        // are not touched.
        let mut rt = Table::new(0);
        let net = nlri(10, 0, 0, 0, 24);
        let s1 = source(1, 65001, 65000, 1);
        let s2 = source(2, 65002, 65000, 2);
        s1.mark_llgr_stale();
        insert_with_attrs(&mut rt, &s1, &net, attrs_with_origin(0));
        insert_with_attrs(&mut rt, &s2, &net, attrs_with_llgr_stale());

        rt.drop_llgr_stale(s1.remote_addr, Family::IPV4, None);

        // s2's route stays because drop_llgr_stale filters by source.remote_addr == addr.
        let best = flat_best(&rt, &Family::IPV4);
        assert_eq!(best.len(), 1);
        assert_eq!(best[0].1.source.remote_addr, s2.remote_addr);
    }

    #[test]
    fn drop_llgr_stale_no_routes_is_noop() {
        let mut rt = Table::new(0);
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let (changes, nexthops) = rt.drop_llgr_stale(addr, Family::IPV4, None);
        assert!(changes.is_empty());
        assert!(nexthops.is_empty());
    }

    // ---- IdAllocator dest_id lifecycle tests ----

    #[test]
    fn id_allocator_alloc_sequential() {
        let mut alloc = IdAllocator::new(0);
        assert_eq!(alloc.alloc(), 0);
        assert_eq!(alloc.alloc(), 1);
        assert_eq!(alloc.alloc(), 2);
    }

    #[test]
    fn id_allocator_dealloc_reuses_lowest_free_id() {
        let mut alloc = IdAllocator::new(0);
        let id0 = alloc.alloc();
        let id1 = alloc.alloc();
        let _id2 = alloc.alloc();
        // Free id0; the next alloc must return the lowest free slot.
        alloc.dealloc(id0);
        assert_eq!(alloc.alloc(), id0);
        // Free id1; next alloc returns id1 (lower than id2+1).
        alloc.dealloc(id1);
        assert_eq!(alloc.alloc(), id1);
    }

    #[test]
    fn id_allocator_encodes_shard_idx_in_high_bits() {
        let shard: u32 = 5;
        let mut alloc = IdAllocator::new(shard);
        let id = alloc.alloc();
        assert_eq!(id >> 24, shard, "shard_idx must occupy bits [31:24]");
        assert_eq!(id & 0x00FF_FFFF, 0, "first local_id must be 0");
        // dealloc accepts the full combined id.
        alloc.dealloc(id);
        assert_eq!(alloc.alloc(), id, "freed id must be reused");
    }

    #[test]
    fn remove_last_path_frees_dest_id_for_reuse() {
        // Removing the last path from a destination must deallocate its dest_id
        // so that subsequent inserts can reuse it (lowest-free allocation).
        let s1 = source(1, 65001, 65000, 1);
        let n1 = nlri(10, 0, 0, 0, 24);
        let n2 = nlri(10, 0, 1, 0, 24);
        let n3 = nlri(10, 0, 2, 0, 24);

        let mut rt = Table::new(0);
        insert_path(&mut rt, &s1, &n1); // dest_id = 0
        insert_path(&mut rt, &s1, &n2); // dest_id = 1

        let id_n1 = rt
            .collect_loc_rib_paths_limited(&Family::IPV4, 1)
            .into_iter()
            .find(|c| c.net == n1)
            .expect("n1 must be in RIB")
            .dest_id;

        // Remove all paths for n1; its dest_id must be freed.
        rt.remove(s1.clone(), Family::IPV4, n1, 0, None);

        // Insert n3: must receive the freed dest_id (lowest free = id_n1).
        insert_path(&mut rt, &s1, &n3);
        let id_n3 = rt
            .collect_loc_rib_paths_limited(&Family::IPV4, 1)
            .into_iter()
            .find(|c| c.net == n3)
            .expect("n3 must be in RIB")
            .dest_id;

        assert_eq!(id_n3, id_n1, "dest_id must be recycled after remove");
    }

    #[test]
    fn drop_peer_routes_frees_dest_ids_for_reuse() {
        // Dropping all routes from a peer must free their dest_ids.
        let s1 = source(1, 65001, 65000, 1);
        let s2 = source(2, 65002, 65000, 2);
        let n1 = nlri(10, 0, 0, 0, 24);
        let n2 = nlri(10, 0, 1, 0, 24);
        let n3 = nlri(10, 0, 2, 0, 24);

        let mut rt = Table::new(0);
        insert_path(&mut rt, &s1, &n1); // dest_id = 0
        insert_path(&mut rt, &s1, &n2); // dest_id = 1

        // Drop all routes from s1; dest_ids 0 and 1 must be freed.
        rt.drop(s1.remote_addr, Family::IPV4);

        // Insert n3 via s2: must reuse the lowest freed id (0).
        insert_path(&mut rt, &s2, &n3);
        let id_n3 = rt
            .collect_loc_rib_paths_limited(&Family::IPV4, 1)
            .into_iter()
            .next()
            .expect("n3 must be in RIB")
            .dest_id;

        assert_eq!(
            id_n3 & 0x00FF_FFFF,
            0,
            "lowest freed local_id must be reused"
        );
    }
}
