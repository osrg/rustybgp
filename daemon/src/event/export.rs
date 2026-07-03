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

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use fnv::{FnvHashMap, FnvHashSet};
use tokio::sync::mpsc;

use rustybgp_packet::{self as packet, Family, bgp};
use rustybgp_table as table;
use table::PeerRole;

use super::*;

/// Carries pre-collected BMP subscriber senders for one export invocation.
///
/// Build once per `handle_prefix_update()` call when subscribers exist, then
/// pass as `Option<&BmpAdjOut>` into `process_nlri_change()`.  Routes that are
/// skipped (same best, filtered by RTC, etc.) never reach this struct.
pub(super) struct BmpAdjOut {
    senders: Vec<mpsc::UnboundedSender<crate::table_manager::BgpEvent>>,
    peer_addr: IpAddr,
    peer_asn: u32,
    peer_id: u32,
    addpath: bool,
    timestamp: u32,
}

impl BmpAdjOut {
    pub(super) fn new(
        senders: Vec<mpsc::UnboundedSender<crate::table_manager::BgpEvent>>,
        peer_addr: IpAddr,
        peer_asn: u32,
        peer_id: u32,
        addpath: bool,
    ) -> Self {
        BmpAdjOut {
            senders,
            peer_addr,
            peer_asn,
            peer_id,
            addpath,
            timestamp: crate::proto::unix_secs(),
        }
    }

    fn send(
        &self,
        post: bool,
        family: Family,
        nlri: packet::Nlri,
        path_id: u32,
        attrs: Option<Arc<Vec<packet::Attribute>>>,
        nexthop: Option<bgp::Nexthop>,
    ) {
        use crate::table_manager::{AdjRibOutChange, BgpEvent};
        let change = AdjRibOutChange {
            peer_addr: self.peer_addr,
            peer_asn: self.peer_asn,
            peer_id: self.peer_id,
            family,
            addpath: self.addpath,
            nlri: packet::PathNlri { path_id, nlri },
            attrs,
            nexthop,
            timestamp: self.timestamp,
        };
        if post {
            for tx in &self.senders {
                let _ = tx.send(BgpEvent::AdjRibOutPost(change.clone()));
            }
        } else {
            for tx in &self.senders {
                let _ = tx.send(BgpEvent::AdjRibOutPre(change.clone()));
            }
        }
    }

    /// Notify pre-policy (after echo-prevention / split-horizon, before export policy).
    /// `route` is None for withdrawals.
    pub(super) fn pre(
        &self,
        family: Family,
        nlri: packet::Nlri,
        path_id: u32,
        route: Option<(Arc<Vec<packet::Attribute>>, Option<bgp::Nexthop>)>,
    ) {
        let (attrs, nh) = match route {
            Some((a, nh)) => (Some(a), nh),
            None => (None, None),
        };
        self.send(false, family, nlri, path_id, attrs, nh);
    }

    /// Notify post-policy (after export policy and nexthop/attr rewrite).
    /// `route` is None for withdrawals.
    pub(super) fn post(
        &self,
        family: Family,
        nlri: packet::Nlri,
        path_id: u32,
        route: Option<(Arc<Vec<packet::Attribute>>, Option<bgp::Nexthop>)>,
    ) {
        let (attrs, nh) = match route {
            Some((a, nh)) => (Some(a), nh),
            None => (None, None),
        };
        self.send(true, family, nlri, path_id, attrs, nh);
    }
}

/// Per-family inner map.  Two variants to avoid per-dest HashSet allocations
/// in the common non-Add-Path case.
#[derive(Clone)]
enum FamilyMap {
    /// Non-Add-Path: set of dest_ids that have been sent (path_id is always 0).
    Plain(FnvHashSet<u32>),
    /// Add-Path: dest_id -> set of path_ids that have been sent.
    AddPath(FnvHashMap<u32, FnvHashSet<u32>>),
}

#[derive(Clone)]
pub(super) struct ExportMap {
    // family -> FamilyMap
    //
    // Using dest_id (u32) as the key instead of Nlri reduces hashing cost on
    // the hot path.  Nlri is not stored here; withdrawals always obtain it from
    // NlriChange (update.net), so do_route_refresh does not need to snapshot it.
    advertised: FnvHashMap<Family, FamilyMap>,
}

impl Default for ExportMap {
    fn default() -> Self {
        Self::new([])
    }
}

impl ExportMap {
    /// Create an ExportMap with the given families pre-configured for Add-Path.
    ///
    /// Families in `addpath_families` start in `AddPath` mode; all others start
    /// in `Plain` mode and are initialized lazily on first `mark_sent`.
    /// Called from `on_established()` once per session with the set of families
    /// whose `effective_max > 1`.
    pub(super) fn new(addpath_families: impl IntoIterator<Item = Family>) -> Self {
        let advertised = addpath_families
            .into_iter()
            .map(|f| (f, FamilyMap::AddPath(FnvHashMap::default())))
            .collect();
        ExportMap { advertised }
    }

    pub(super) fn mark_sent(&mut self, family: Family, dest_id: u32, path_id: u32) {
        match self
            .advertised
            .entry(family)
            .or_insert_with(|| FamilyMap::Plain(FnvHashSet::default()))
        {
            FamilyMap::Plain(s) => {
                s.insert(dest_id);
            }
            FamilyMap::AddPath(m) => {
                m.entry(dest_id).or_default().insert(path_id);
            }
        }
    }

    pub(super) fn mark_withdrawn(&mut self, family: Family, dest_id: u32, path_id: u32) {
        match self.advertised.get_mut(&family) {
            Some(FamilyMap::Plain(s)) => {
                s.remove(&dest_id);
            }
            Some(FamilyMap::AddPath(m)) => {
                if let Some(ids) = m.get_mut(&dest_id) {
                    ids.remove(&path_id);
                    if ids.is_empty() {
                        m.remove(&dest_id);
                    }
                }
            }
            None => {}
        }
    }

    pub(super) fn was_sent(&self, family: Family, dest_id: u32) -> bool {
        match self.advertised.get(&family) {
            Some(FamilyMap::Plain(s)) => s.contains(&dest_id),
            Some(FamilyMap::AddPath(m)) => m.contains_key(&dest_id),
            None => false,
        }
    }

    pub(super) fn contains_path(&self, family: Family, dest_id: u32, path_id: u32) -> bool {
        match self.advertised.get(&family) {
            Some(FamilyMap::Plain(s)) => s.contains(&dest_id),
            Some(FamilyMap::AddPath(m)) => {
                m.get(&dest_id).is_some_and(|ids| ids.contains(&path_id))
            }
            None => false,
        }
    }

    pub(super) fn sent_path_ids(&self, family: Family, dest_id: u32) -> FnvHashSet<u32> {
        match self.advertised.get(&family) {
            Some(FamilyMap::Plain(s)) => {
                if s.contains(&dest_id) {
                    let mut ids = FnvHashSet::default();
                    ids.insert(0u32);
                    ids
                } else {
                    FnvHashSet::default()
                }
            }
            Some(FamilyMap::AddPath(m)) => m.get(&dest_id).cloned().unwrap_or_default(),
            None => FnvHashSet::default(),
        }
    }
}

/// Session-level peer export information.
///
/// Groups `PeerRole`, `local_asn`, `local_addr`, and `link_addr` so that
/// attribute transformation and route filtering decisions have a single source
/// of truth.  Built once in `PeerSession::new()` and stored as a field.
pub(super) struct PeerExportContext {
    pub(super) role: PeerRole,
    pub(super) local_asn: u32,
    pub(super) local_addr: IpAddr,
    pub(super) link_addr: Option<Ipv6Addr>,
    /// Confederation Identifier (0 = not in a confederation).
    pub(super) confederation_id: u32,
}

impl PeerExportContext {
    /// Build a `PeerCodec` for wire encoding.
    ///
    /// The codec handles only wire framing; all attribute transformation and
    /// loop detection is handled in the daemon.
    pub(super) fn build_codec(&self) -> bgp::PeerCodec {
        bgp::PeerCodec::new()
    }

    /// Apply pre-policy defaults for export, run before `apply_export()`.
    ///
    /// Clears a received MED for eBGP peers (RFC 4271 §5.1.4: MED "must not
    /// ... propagate to other neighboring ASes") and defaults the nexthop
    /// (see `export_nexthop`: self-nexthop for eBGP/ConfedEbgp; local
    /// address when no nexthop is stored, e.g. a locally-originated route).
    /// Both must run *before* export policy -- not folded into the
    /// post-policy `export_attrs` -- so that `set-med` / `set-nexthop`
    /// export policy actions are not silently discarded by a later,
    /// unconditional rewrite. FRR does the same for MED in the same order:
    /// `subgroup_announce_check()` zeroes MED for eBGP peers before applying
    /// the outbound route-map, so a route-map `set metric` still lands on
    /// the wire. GoBGP does the same for nexthop: `prePolicyFilterpath` runs
    /// `UpdatePathAttrs` (which forces self-nexthop) before `ApplyPolicy`.
    ///
    /// `nexthop` must hold the genuine, as-received value on entry: this
    /// call overwrites it with the default, so callers must snapshot the
    /// route's original nexthop beforehand and pass that snapshot into
    /// `apply_export()` as `original_nexthop`, used only by
    /// `NexthopAction::Unchanged` to restore the genuine original instead of
    /// confirming the default just applied here (mirrors GoBGP's
    /// `options.OldNextHop`, captured before `UpdatePathAttrs` runs).
    pub(super) fn pre_policy_defaults(
        &self,
        attr: &mut Arc<Vec<packet::Attribute>>,
        nexthop: &mut Option<bgp::Nexthop>,
        family: Family,
        is_local: bool,
    ) {
        if self.role == PeerRole::Ebgp
            && attr
                .iter()
                .any(|a| a.code() == packet::Attribute::MULTI_EXIT_DESC)
        {
            Arc::make_mut(attr).retain(|a| a.code() != packet::Attribute::MULTI_EXIT_DESC);
        }

        self.export_nexthop(nexthop, family, is_local);
    }

    /// Apply per-peer attribute transformation to outgoing route attributes.
    ///
    /// eBGP: prepend `local_asn` to AS_PATH (adding a synthetic segment for
    /// locally-originated routes); strip LOCAL_PREF (RFC 4271 §5.1.5) and
    /// ORIGINATOR_ID / CLUSTER_LIST (RFC 4456 §8, iBGP-only attributes).
    /// iBGP / iBGP-RR-client: no AS_PATH prepend; LOCAL_PREF injected with
    /// default value (100) if absent (RFC 4271 §5.1.5 requires LOCAL_PREF in
    /// all UPDATE messages to internal peers).
    /// RS client: pass through unchanged.
    ///
    /// MED and nexthop are intentionally not handled here: unlike LOCAL_PREF,
    /// an eBGP export policy may legitimately set them for the direct peer
    /// (RFC 4271 §5.1.4, and third-party nexthop respectively), so their
    /// defaults must be applied before export policy runs -- see
    /// `pre_policy_defaults`, called earlier in the export pipeline --
    /// rather than here, after policy has already run.
    pub(super) fn export_attrs(
        &self,
        attrs: &Arc<Vec<bgp::Attribute>>,
    ) -> Arc<Vec<bgp::Attribute>> {
        let exported = match self.role {
            PeerRole::RsClient => attrs.clone(),
            PeerRole::Ibgp | PeerRole::IbgpRrClient => {
                inject_local_pref_if_absent(Arc::clone(attrs))
            }
            PeerRole::ConfedEbgp => {
                // Prepend local Member-AS to AS_CONFED_SEQUENCE; retain LOCAL_PREF.
                let has_as_path = attrs.iter().any(|a| a.code() == bgp::Attribute::AS_PATH);
                let mut new_attrs: Vec<bgp::Attribute> = attrs
                    .iter()
                    .map(|a| {
                        if a.code() == bgp::Attribute::AS_PATH {
                            a.as_path_prepend_confed(self.local_asn)
                        } else {
                            a.clone()
                        }
                    })
                    .collect();
                if !has_as_path {
                    new_attrs.push(
                        bgp::Attribute::empty_as_path().as_path_prepend_confed(self.local_asn),
                    );
                }
                Arc::new(new_attrs)
            }
            PeerRole::Ebgp => {
                // Strip any CONFED segments, then prepend the externally visible AS number
                // (confederation_id when inside a confederation, local_asn otherwise).
                let prepend_asn = if self.confederation_id != 0 {
                    self.confederation_id
                } else {
                    self.local_asn
                };
                let has_as_path = attrs.iter().any(|a| a.code() == bgp::Attribute::AS_PATH);
                let mut new_attrs: Vec<bgp::Attribute> = attrs
                    .iter()
                    .filter(|a| {
                        !matches!(
                            a.code(),
                            bgp::Attribute::LOCAL_PREF
                                | bgp::Attribute::ORIGINATOR_ID
                                | bgp::Attribute::CLUSTER_LIST
                                | bgp::Attribute::AIGP
                        )
                    })
                    .map(|a| {
                        if a.code() == bgp::Attribute::AS_PATH {
                            a.as_path_strip_confed().as_path_prepend(prepend_asn)
                        } else {
                            a.clone()
                        }
                    })
                    .collect();
                if !has_as_path {
                    new_attrs.push(bgp::Attribute::empty_as_path().as_path_prepend(prepend_asn));
                }
                Arc::new(new_attrs)
            }
        };

        // RFC 4271 §5.1.4: apply opaque attr policy uniformly across all roles.
        // Unknown optional transitive attrs are forwarded with PARTIAL bit set;
        // unknown optional non-transitive attrs are discarded.
        // Skip the allocation when no opaque attrs are present (common case).
        if !exported.iter().any(|a| a.is_opaque()) {
            return exported;
        }
        Arc::new(
            exported
                .iter()
                .filter_map(|a| {
                    if !a.is_opaque() {
                        Some(a.clone())
                    } else if a.is_transitive() {
                        Some(a.with_partial_bit())
                    } else {
                        None
                    }
                })
                .collect(),
        )
    }

    /// Compute the default per-peer nexthop for an outgoing route.
    ///
    /// eBGP / ConfedEbgp: self-nexthop (local_addr, with link-local for IPv6
    /// when available). iBGP / iBGP-RR-client / RS client: pass through
    /// unchanged. No stored nexthop (e.g. a locally-originated route):
    /// self-nexthop for any role, except Flowspec (RFC 8955 §4 carries no
    /// nexthop).
    ///
    /// `is_local` (`Source::is_local()`): for a locally-injected route (e.g.
    /// via the `AddPath` gRPC API) with an explicit, non-unspecified nexthop,
    /// that value is honored for *any* role instead of being forced to self
    /// -- an unspecified nexthop (`0.0.0.0`/`::`, a common "let the router
    /// fill this in" sentinel) still gets the self-nexthop default. Mirrors
    /// GoBGP's `UpdatePathAttrs`: `!path.IsLocal() || nexthop.IsUnspecified()`
    /// for eBGP and `path.IsLocal() && nexthop.IsUnspecified()` for iBGP --
    /// both reduce to the same "local + unspecified -> self, local + explicit
    /// -> keep" rule, which is what this function implements directly.
    ///
    /// Called only from `pre_policy_defaults`, i.e. before export policy
    /// runs, so that a `set-nexthop` export policy action can override this
    /// default rather than being clobbered by it afterward.
    fn export_nexthop(&self, nexthop: &mut Option<bgp::Nexthop>, family: Family, is_local: bool) {
        let local = || match self.local_addr {
            IpAddr::V4(v4) => bgp::Nexthop::V4(v4),
            IpAddr::V6(v6) => {
                if let Some(ll) = self.link_addr {
                    bgp::Nexthop::V6LinkLocal(v6, ll)
                } else {
                    bgp::Nexthop::V6(v6)
                }
            }
        };
        let is_flowspec = matches!(
            family,
            Family::IPV4_FLOWSPEC
                | Family::IPV6_FLOWSPEC
                | Family::IPV4_FLOWSPEC_VPN
                | Family::IPV6_FLOWSPEC_VPN
        );
        *nexthop = match (self.role, *nexthop) {
            // Flowspec carries no nexthop (RFC 8955 §4): preserve None.
            (_, None) if is_flowspec => None,
            // No stored nexthop for non-Flowspec (e.g. locally originated RTC):
            // use per-peer local address.
            (_, None) => Some(local()),
            // Locally-injected route with an explicit nexthop: honor it,
            // regardless of peer role.
            (_, Some(nh)) if is_local && !nh.addr().is_unspecified() => Some(nh),
            // Locally-injected route with an unspecified (0.0.0.0/::) nexthop:
            // fill in self, regardless of peer role.
            (_, Some(_)) if is_local => Some(local()),
            (PeerRole::RsClient | PeerRole::Ibgp | PeerRole::IbgpRrClient, Some(nh)) => Some(nh),
            (PeerRole::ConfedEbgp | PeerRole::Ebgp, Some(_)) => Some(local()),
        };
    }
}

/// Abstraction over the output of `process_nlri_change()`.
///
/// `PendingTx` implements this for the normal send path.  `AdjOutSink`
/// implements it to collect a snapshot for adj-out display without sending.
pub(super) trait NlriSink {
    fn reach(
        &mut self,
        dest_id: u32,
        nlri: packet::Nlri,
        path_id: u32,
        nexthop: Option<bgp::Nexthop>,
        attr: Arc<Vec<packet::Attribute>>,
        source: &Arc<table::Source>,
    );
    fn unreach(&mut self, dest_id: u32, nlri: packet::Nlri, path_id: u32);
}

impl NlriSink for crate::peer_tx::PendingTx {
    fn reach(
        &mut self,
        dest_id: u32,
        nlri: packet::Nlri,
        path_id: u32,
        nexthop: Option<bgp::Nexthop>,
        attr: Arc<Vec<packet::Attribute>>,
        _source: &Arc<table::Source>,
    ) {
        crate::peer_tx::PendingTx::reach(self, dest_id, nlri, path_id, nexthop, attr);
    }
    fn unreach(&mut self, dest_id: u32, nlri: packet::Nlri, path_id: u32) {
        crate::peer_tx::PendingTx::unreach(self, dest_id, nlri, path_id);
    }
}

/// `NlriSink` that collects adj-out paths for display.
///
/// Uses a fresh `ExportMap` (empty = nothing previously sent), so
/// `process_nlri_change()` treats every visible path as new and calls
/// `reach()` for each one; `unreach()` is never called.
#[derive(Default)]
pub(super) struct AdjOutSink {
    pub(super) destinations: Vec<table::DestinationEntry>,
    /// net -> index into `destinations` for O(1) lookup on duplicate nets.
    index: FnvHashMap<packet::Nlri, usize>,
}

impl NlriSink for AdjOutSink {
    fn reach(
        &mut self,
        _dest_id: u32,
        nlri: packet::Nlri,
        _path_id: u32,
        _nexthop: Option<bgp::Nexthop>,
        attr: Arc<Vec<packet::Attribute>>,
        source: &Arc<table::Source>,
    ) {
        let entry = table::PathEntry {
            source: Arc::clone(source),
            remote_path_id: 0,
            timestamp: 0u32,
            attr,
            validation: None,
            stale: source.is_stale(),
            filtered: false,
        };
        if let Some(&i) = self.index.get(&nlri) {
            self.destinations[i].paths.push(entry);
        } else {
            let i = self.destinations.len();
            self.index.insert(nlri.clone(), i);
            self.destinations.push(table::DestinationEntry {
                net: nlri,
                paths: vec![entry],
            });
        }
    }

    fn unreach(&mut self, _dest_id: u32, _nlri: packet::Nlri, _path_id: u32) {
        // Snapshot mode: ExportMap is always empty so this is never called.
    }
}

type GroupedAttrKey = (Arc<Vec<packet::Attribute>>, Option<bgp::Nexthop>);

/// `NlriSink` that groups routes by (attr, nexthop) directly, bypassing the
/// per-NLRI HashMap in `PendingTx`.
///
/// Used during `on_established` initial advertisement where no unreach can
/// occur (export_map is empty).  Routes are collected into groups and
/// converted to `bgp::Message` via `into_messages()`, then passed to
/// `PendingTx::buffer_messages()`.
pub(super) struct GroupedSink {
    addpath_tx: bool,
    grouped: FnvHashMap<GroupedAttrKey, Vec<packet::PathNlri>>,
}

impl GroupedSink {
    pub(super) fn new(addpath_tx: bool) -> Self {
        GroupedSink {
            addpath_tx,
            grouped: FnvHashMap::default(),
        }
    }

    pub(super) fn into_messages(self, family: bgp::Family) -> Vec<bgp::Message> {
        self.grouped
            .into_iter()
            .map(|((attr, nexthop), entries)| {
                bgp::Message::Update(bgp::Update::Reach {
                    family,
                    entries,
                    nexthop,
                    attr,
                })
            })
            .collect()
    }
}

impl NlriSink for GroupedSink {
    fn reach(
        &mut self,
        _dest_id: u32,
        nlri: packet::Nlri,
        path_id: u32,
        nexthop: Option<bgp::Nexthop>,
        attr: Arc<Vec<packet::Attribute>>,
        _source: &Arc<table::Source>,
    ) {
        let key = packet::PathNlri {
            path_id: if self.addpath_tx { path_id } else { 0 },
            nlri,
        };
        self.grouped.entry((attr, nexthop)).or_default().push(key);
    }

    fn unreach(&mut self, _dest_id: u32, _nlri: packet::Nlri, _path_id: u32) {
        // Initial dump: export_map is empty so this is never called.
    }
}

/// Core routing-update logic shared by handle_prefix_update() and unit tests.
///
/// Computes which BGP messages to send based on `update` and the peer's
/// current `export_map`, then queues them into `pending`.
///
/// - Non-Add-Path (effective_max == 1): O(1) skip when `best_changed` is false;
///   otherwise sends a single UPDATE or WITHDRAW.
/// - Add-Path (effective_max > 1): diffs `current_paths[..effective_max]` against
///   `export_map` to produce per-path_id UPDATEs and WITHDRAWs, including
///   send_max boundary crossings in both directions.
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub(super) fn process_nlri_change<S: NlriSink>(
    update: &table::NlriChange,
    effective_max: usize,
    remote_addr: IpAddr,
    export_map: &mut ExportMap,
    sink: &mut S,
    export_ctx: &PeerExportContext,
    export_policy: Option<&table::PolicyAssignment>,
    cluster_id: Option<Ipv4Addr>,
    rpki: Option<&table::RpkiTable>,
    bmp: Option<&BmpAdjOut>,
    rtc_filter: Option<&crate::rtc::RtcFilter>,
) {
    if effective_max == 1 {
        // Non-Add-Path fast path: O(1) skip when best unchanged.
        if !update.best_changed {
            return;
        }
        // Compute the best path visible to this peer: None if no best exists,
        // the best originated from this peer (echo prevention), or the best is
        // suppressed by split-horizon.
        let visible_best = update.new_best().and_then(|best| {
            if best.source.remote_addr == remote_addr {
                return None;
            }
            if ibgp_split_horizon_suppress(&best.source, export_ctx.role, cluster_id) {
                return None;
            }
            if rs_isolation_suppress(&best.source, export_ctx.role) {
                return None;
            }
            Some(best)
        });
        // BMP Adj-RIB-Out pre-policy: what would be exported before per-peer policy.
        if let Some(bmp) = bmp {
            bmp.pre(
                update.family,
                update.net.clone(),
                0,
                visible_best.map(|b| (Arc::clone(&b.attr), b.nexthop)),
            );
        }
        // Apply the RTC filter and export policy to the visible best; a
        // rejected best is treated as if no best exists (withdraw if
        // previously advertised).
        let policy_result = visible_best.and_then(|best| {
            if rtc_filter.is_some_and(|f| !f.allows(&best.attr)) {
                return None;
            }
            let original_nexthop = best.nexthop;
            let mut nexthop = best.nexthop;
            let mut attr = Arc::clone(&best.attr);
            export_ctx.pre_policy_defaults(
                &mut attr,
                &mut nexthop,
                update.family,
                best.source.is_local(),
            );
            if export_policy.is_some_and(|policy| {
                table::apply_export(
                    policy,
                    rpki,
                    &best.source,
                    &update.net,
                    &mut attr,
                    &mut nexthop,
                    original_nexthop,
                    export_ctx.role == PeerRole::ConfedEbgp,
                    export_ctx.local_addr,
                    remote_addr,
                ) == table::Disposition::Reject
            }) {
                return None;
            }
            // RR reflection: add ORIGINATOR_ID and prepend CLUSTER_LIST.
            if let Some(cid) = cluster_id
                && is_ibgp_learned(&best.source)
            {
                attr = rr_reflect_attrs(&attr, best.source.router_id, cid);
            }
            Some((best, attr, nexthop))
        });
        match policy_result {
            None => {
                // BMP post-policy Withdraw: always emit so the receiver can track
                // routes blocked by export policy (not gated by was_sent).
                if let Some(bmp) = bmp {
                    bmp.post(update.family, update.net.clone(), 0, None);
                }
                if export_map.was_sent(update.family, update.dest_id) {
                    export_map.mark_withdrawn(update.family, update.dest_id, 0);
                    sink.unreach(update.dest_id, update.net.clone(), 0);
                }
            }
            Some((best, attr, nexthop)) => {
                export_map.mark_sent(update.family, update.dest_id, 0);
                let attr = if best.source.is_llgr_stale() {
                    with_llgr_stale_community(&attr)
                } else {
                    attr
                };
                let attr = export_ctx.export_attrs(&attr);
                // BMP post-policy Reach: use the fully-rewritten attr/nexthop.
                if let Some(bmp) = bmp {
                    bmp.post(
                        update.family,
                        update.net.clone(),
                        0,
                        Some((Arc::clone(&attr), nexthop)),
                    );
                }
                sink.reach(
                    update.dest_id,
                    update.net.clone(),
                    0,
                    nexthop,
                    attr,
                    &best.source,
                );
            }
        }
    } else {
        // Add-Path: compare current_paths[..effective_max] vs export_map.
        if !update.any_changed {
            return;
        }
        // Build the effective top-N after echo prevention, split horizon, and
        // export policy.  Store post-policy (attr, nexthop) so that
        // export_attrs can be applied in one step below.
        let current_top_n: Vec<(
            u32,
            Arc<Vec<packet::Attribute>>,
            Option<bgp::Nexthop>,
            Arc<table::Source>,
        )> = update
            .current_paths
            .iter()
            .filter(|p| p.source.remote_addr != remote_addr)
            .filter(|p| !ibgp_split_horizon_suppress(&p.source, export_ctx.role, cluster_id))
            .filter(|p| !rs_isolation_suppress(&p.source, export_ctx.role))
            .take(effective_max)
            .filter_map(|path| {
                if rtc_filter.is_some_and(|f| !f.allows(&path.attr)) {
                    return None;
                }
                let original_nexthop = path.nexthop;
                let mut nexthop = path.nexthop;
                let mut attr = Arc::clone(&path.attr);
                export_ctx.pre_policy_defaults(
                    &mut attr,
                    &mut nexthop,
                    update.family,
                    path.source.is_local(),
                );
                if export_policy.is_some_and(|policy| {
                    table::apply_export(
                        policy,
                        rpki,
                        &path.source,
                        &update.net,
                        &mut attr,
                        &mut nexthop,
                        original_nexthop,
                        export_ctx.role == PeerRole::ConfedEbgp,
                        export_ctx.local_addr,
                        remote_addr,
                    ) == table::Disposition::Reject
                }) {
                    return None;
                }
                // RR reflection: add ORIGINATOR_ID and prepend CLUSTER_LIST.
                if let Some(cid) = cluster_id
                    && is_ibgp_learned(&path.source)
                {
                    attr = rr_reflect_attrs(&attr, path.source.router_id, cid);
                }
                if path.source.is_llgr_stale() {
                    attr = with_llgr_stale_community(&attr);
                }
                Some((path.local_path_id, attr, nexthop, Arc::clone(&path.source)))
            })
            .collect();

        // Withdraw paths that were sent but are no longer in top-N
        // (including paths pushed out by send_max boundary or policy).
        let sent_ids = export_map.sent_path_ids(update.family, update.dest_id);
        let current_ids: FnvHashSet<u32> =
            current_top_n.iter().map(|(pid, _, _, _)| *pid).collect();
        for &pid in sent_ids.difference(&current_ids) {
            export_map.mark_withdrawn(update.family, update.dest_id, pid);
            if let Some(bmp) = bmp {
                bmp.post(update.family, update.net.clone(), pid, None);
            }
            sink.unreach(update.dest_id, update.net.clone(), pid);
        }

        // Advertise paths that are new or whose attributes were replaced.
        for (pid, attr, nexthop, source) in &current_top_n {
            let already_sent = export_map.contains_path(update.family, update.dest_id, *pid);
            let was_replaced = update.replaced_path_id == Some(*pid);
            if !already_sent || was_replaced {
                export_map.mark_sent(update.family, update.dest_id, *pid);
                let attr = export_ctx.export_attrs(attr);
                let nexthop = *nexthop;
                if let Some(bmp) = bmp {
                    bmp.post(
                        update.family,
                        update.net.clone(),
                        *pid,
                        Some((Arc::clone(&attr), nexthop)),
                    );
                }
                sink.reach(
                    update.dest_id,
                    update.net.clone(),
                    *pid,
                    nexthop,
                    attr,
                    source,
                );
            }
        }
    }
}

/// Build reflected attribute set for an RR (RFC 4456 §8).
///
/// Sets ORIGINATOR_ID to `source_router_id` if absent, and prepends
/// `cluster_id` to CLUSTER_LIST (creating the attribute if absent).
pub(super) fn rr_reflect_attrs(
    attrs: &Arc<Vec<packet::Attribute>>,
    source_router_id: u32,
    cluster_id: Ipv4Addr,
) -> Arc<Vec<packet::Attribute>> {
    let has_originator = attrs
        .iter()
        .any(|a| a.code() == packet::Attribute::ORIGINATOR_ID);

    let cid_bytes = u32::from(cluster_id).to_be_bytes();
    let new_cluster_list: Vec<u8> = {
        let mut v = cid_bytes.to_vec();
        if let Some(existing) = attrs
            .iter()
            .find(|a| a.code() == packet::Attribute::CLUSTER_LIST)
            .and_then(|a| a.binary())
        {
            v.extend_from_slice(existing);
        }
        v
    };

    let mut new_attrs: Vec<packet::Attribute> = attrs
        .iter()
        .filter(|a| a.code() != packet::Attribute::CLUSTER_LIST)
        .cloned()
        .collect();

    if !has_originator
        && let Some(a) =
            packet::Attribute::new_with_value(packet::Attribute::ORIGINATOR_ID, source_router_id)
    {
        new_attrs.push(a);
    }
    if let Some(a) =
        packet::Attribute::new_with_bin(packet::Attribute::CLUSTER_LIST, new_cluster_list)
    {
        new_attrs.push(a);
    }
    Arc::new(new_attrs)
}

/// Return `attr` with the LLGR_STALE well-known community (0xFFFF0006) present.
///
/// If the community is already present (e.g. route relayed from another LLGR
/// helper), returns a clone of the original Arc.  Otherwise appends 4 bytes to
/// the existing COMMUNITY attribute, or creates a new one if absent.
pub(super) fn with_llgr_stale_community(
    attr: &Arc<Vec<packet::Attribute>>,
) -> Arc<Vec<packet::Attribute>> {
    const LLGR_STALE: [u8; 4] = [0xff, 0xff, 0x00, 0x06];
    let existing = attr
        .iter()
        .find(|a| a.code() == packet::Attribute::COMMUNITY)
        .and_then(|a| a.binary());
    if let Some(bin) = existing {
        if bin.chunks(4).any(|c| c == LLGR_STALE) {
            return Arc::clone(attr);
        }
        // Append to the existing COMMUNITY attribute, replacing it in-place.
        let mut new_bin = bin.to_vec();
        new_bin.extend_from_slice(&LLGR_STALE);
        let new_community =
            packet::Attribute::new_with_bin(packet::Attribute::COMMUNITY, new_bin).unwrap();
        return Arc::new(
            attr.iter()
                .map(|a| {
                    if a.code() == packet::Attribute::COMMUNITY {
                        new_community.clone()
                    } else {
                        a.clone()
                    }
                })
                .collect(),
        );
    }
    // No COMMUNITY attribute: append a new one.
    let mut new_attrs: Vec<packet::Attribute> = attr.iter().cloned().collect();
    new_attrs.push(
        packet::Attribute::new_with_bin(packet::Attribute::COMMUNITY, LLGR_STALE.to_vec()).unwrap(),
    );
    Arc::new(new_attrs)
}

/// Return `true` when the incoming UPDATE contains the local AS (or confederation
/// identifier) in AS_PATH, indicating a routing loop (RFC 4271 §9.1.2).
/// Applies only to route announcements; `confederation_id` of 0 disables the
/// confederation check.
pub(super) fn is_as_loop(
    attr: &Arc<Vec<bgp::Attribute>>,
    local_asn: u32,
    confederation_id: u32,
) -> bool {
    let Some(as_path) = attr.iter().find(|a| a.code() == bgp::Attribute::AS_PATH) else {
        return false;
    };
    if as_path.as_path_count(local_asn).is_ok_and(|n| n > 0) {
        return true;
    }
    confederation_id != 0
        && confederation_id != local_asn
        && as_path.as_path_count(confederation_id).is_ok_and(|n| n > 0)
}

/// Inject LOCAL_PREF with the default value (100) when it is absent from `attr`.
///
/// RFC 4271 §5.1.5 requires LOCAL_PREF in all iBGP UPDATE messages.  Called
/// on the send path (export_attrs) so eBGP-learned routes gain LOCAL_PREF
/// before distribution to iBGP peers, and on the receive path as a defensive
/// fallback for peers that omit it.  Returns the original Arc unchanged when
/// LOCAL_PREF is already present (no allocation).
pub(super) fn inject_local_pref_if_absent(
    attr: Arc<Vec<packet::Attribute>>,
) -> Arc<Vec<packet::Attribute>> {
    if attr
        .iter()
        .any(|a| a.code() == packet::Attribute::LOCAL_PREF)
    {
        return attr;
    }
    let mut new_attr: Vec<packet::Attribute> = (*attr).clone();
    let pos = new_attr.partition_point(|a| a.code() < packet::Attribute::LOCAL_PREF);
    new_attr.insert(
        pos,
        packet::Attribute::new_with_value(
            packet::Attribute::LOCAL_PREF,
            packet::Attribute::DEFAULT_LOCAL_PREF,
        )
        .unwrap(),
    );
    Arc::new(new_attr)
}

/// Return `true` if `source` is an iBGP-learned path (not local, not eBGP).
pub(super) fn is_ibgp_learned(source: &table::Source) -> bool {
    !source.is_local() && source.remote_asn == source.local_asn
}

/// iBGP split-horizon check for a single path.
///
/// Returns `true` when the path should be suppressed (not sent to `dest_role`).
/// In plain iBGP mode (`cluster_id` is None) all iBGP-learned paths are
/// suppressed.  In RR mode only non-client -> non-client is suppressed.
pub(super) fn rs_isolation_suppress(source: &table::Source, dest_role: PeerRole) -> bool {
    // RS-client routes must not reach non-RS-client peers, and vice versa.
    source.is_rs_client() != matches!(dest_role, PeerRole::RsClient)
}

pub(super) fn ibgp_split_horizon_suppress(
    source: &table::Source,
    dest_role: PeerRole,
    cluster_id: Option<Ipv4Addr>,
) -> bool {
    if !matches!(dest_role, PeerRole::Ibgp | PeerRole::IbgpRrClient) {
        return false;
    }
    if !is_ibgp_learned(source) {
        return false;
    }
    match cluster_id {
        // Plain iBGP: suppress all iBGP -> iBGP.
        None => true,
        // RR mode: suppress only non-client -> non-client.
        Some(_) => !source.is_rr_client() && dest_role == PeerRole::Ibgp,
    }
}
