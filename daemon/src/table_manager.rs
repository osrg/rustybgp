// Copyright (C) 2019-2021 The RustyBGP Authors.
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
// implied. See the License for the specific language governing
// permissions and limitations under the License.

use arc_swap::{ArcSwap, ArcSwapOption};
use fnv::{FnvHashMap, FnvHashSet, FnvHasher};
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::Mutex;
use tokio::sync::mpsc;

use rustybgp_kernel as kernel;
use rustybgp_packet::{self as packet, Family, bgp};
use rustybgp_table as table;

use crate::event::ToPeerEvent;

/// Opaque subscription handle returned by [`TableManager::subscribe`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct SubscriptionId(u64);

/// A pre-import-policy Adj-RIB-In update from one peer.
/// `attrs` is `None` for withdrawals.
pub(crate) struct AdjRibInChange {
    pub(crate) source: Arc<table::Source>,
    pub(crate) family: Family,
    pub(crate) addpath: bool,
    pub(crate) nlris: Vec<packet::PathNlri>,
    pub(crate) attrs: Option<Arc<Vec<packet::Attribute>>>,
    pub(crate) nexthop: Option<bgp::Nexthop>,
    pub(crate) timestamp: std::time::SystemTime,
}

#[derive(Clone)]
pub(crate) struct PeerUpData {
    pub(crate) peer_addr: IpAddr,
    pub(crate) peer_asn: u32,
    pub(crate) peer_id: u32,
    pub(crate) uptime: u64,
    pub(crate) local_addr: IpAddr,
    pub(crate) local_port: u16,
    pub(crate) remote_port: u16,
    pub(crate) sent_open: bgp::Message,
    pub(crate) received_open: bgp::Message,
}

#[derive(Clone)]
pub(crate) struct PeerDownData {
    pub(crate) peer_addr: IpAddr,
    pub(crate) peer_asn: u32,
    pub(crate) peer_id: u32,
    pub(crate) uptime: u64,
    pub(crate) reason: rustybgp_packet::bmp::PeerDownReason,
}

/// An Adj-RIB-Out update for one neighbor (RFC 8671).
/// `attrs` is `None` for withdrawals; `Some` for route announcements.
#[derive(Clone)]
pub(crate) struct AdjRibOutChange {
    /// The neighbor this Adj-RIB-Out entry belongs to.
    pub(crate) peer_addr: IpAddr,
    pub(crate) peer_asn: u32,
    pub(crate) peer_id: u32,
    pub(crate) family: Family,
    pub(crate) addpath: bool,
    pub(crate) nlri: packet::PathNlri,
    pub(crate) attrs: Option<Arc<Vec<packet::Attribute>>>,
    pub(crate) nexthop: Option<bgp::Nexthop>,
    pub(crate) timestamp: std::time::SystemTime,
}

pub(crate) enum BgpEvent {
    AdjRibIn(AdjRibInChange),
    AdjRibInPost(AdjRibInChange),
    AdjRibOutPre(AdjRibOutChange),
    AdjRibOutPost(AdjRibOutChange),
    PeerUp(PeerUpData),
    PeerDown(PeerDownData),
    /// Sentinel sent by `subscribe(true)` after all snapshot events have been queued.
    EndOfSnapshot,
}

pub(crate) struct Subscription {
    pub(crate) rx: mpsc::UnboundedReceiver<BgpEvent>,
    pub(crate) id: SubscriptionId,
}

pub(crate) type TableHandle = Arc<TableManager>;

type SharedVrfs = Arc<ArcSwap<FnvHashMap<String, table::Vrf>>>;

pub(crate) struct TableManager {
    pub(crate) shards: Vec<Mutex<TableShard>>,
    pub(crate) rpki: std::sync::RwLock<table::RpkiTable>,
    pub(crate) kernel_handle: ArcSwapOption<kernel::KernelHandle>,
    pub(crate) import_policy: ArcSwapOption<table::PolicyAssignment>,
    pub(crate) export_policy: ArcSwapOption<table::PolicyAssignment>,
    /// Set of nexthop addresses currently considered unreachable by NHT.
    /// Written only from the event loop (serialized); read lock-free from any shard.
    nexthop_invalid: ArcSwap<FnvHashSet<IpAddr>>,
    next_sub_id: std::sync::atomic::AtomicU64,
    subscribers: ArcSwap<Vec<(SubscriptionId, mpsc::UnboundedSender<BgpEvent>)>>,
    vrfs: SharedVrfs,
    next_label: std::sync::atomic::AtomicU32,
}

impl TableManager {
    /// First available MPLS label (0-15 are reserved per RFC 3032).
    const LABEL_BASE: u32 = 16;

    pub(crate) fn new(num_shards: usize) -> Self {
        let vrfs: SharedVrfs = Arc::new(ArcSwap::new(Arc::new(FnvHashMap::default())));
        TableManager {
            shards: (0..num_shards)
                .map(|_| {
                    Mutex::new(TableShard {
                        rtable: table::Table::new(),
                        peer_event_tx: FnvHashMap::default(),
                        addpath: FnvHashMap::default(),
                        vrfs: Arc::clone(&vrfs),
                    })
                })
                .collect(),
            rpki: std::sync::RwLock::new(table::RpkiTable::new()),
            kernel_handle: ArcSwapOption::const_empty(),
            import_policy: ArcSwapOption::const_empty(),
            export_policy: ArcSwapOption::const_empty(),
            nexthop_invalid: ArcSwap::new(Arc::new(FnvHashSet::default())),
            next_sub_id: std::sync::atomic::AtomicU64::new(0),
            subscribers: ArcSwap::new(Arc::new(Vec::new())),
            vrfs,
            next_label: std::sync::atomic::AtomicU32::new(Self::LABEL_BASE),
        }
    }

    fn allocate_label(&self) -> packet::mpls::MplsLabel {
        packet::mpls::MplsLabel::new(
            self.next_label
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        )
    }

    pub(crate) fn add_vrf(
        &self,
        name: String,
        rd: packet::rd::RouteDistinguisher,
        import_rt: std::collections::HashSet<[u8; 8]>,
        export_rt: Vec<[u8; 8]>,
        id: u32,
    ) -> Result<packet::mpls::MplsLabel, table::TableError> {
        let current = self.vrfs.load_full();
        if current.contains_key(&name) {
            return Err(table::TableError::AlreadyExists(name));
        }
        let label = self.allocate_label();
        let mut new_map = (*current).clone();
        new_map.insert(
            name.clone(),
            table::Vrf {
                name: name.clone(),
                rd,
                import_rt,
                export_rt,
                label,
                id,
            },
        );
        self.vrfs.store(Arc::new(new_map));
        if id > 0
            && let Some(handle) = self.kernel_handle.load_full().as_deref()
        {
            handle.create_vrf(&name, id);
        }
        Ok(label)
    }

    pub(crate) fn delete_vrf(&self, name: &str) -> Result<table::Vrf, table::TableError> {
        let current = self.vrfs.load_full();
        let id = current.get(name).ok_or(table::TableError::NotFound)?.id;
        let mut new_map = (*current).clone();
        match new_map.remove(name) {
            Some(vrf) => {
                self.vrfs.store(Arc::new(new_map));
                if id > 0
                    && let Some(handle) = self.kernel_handle.load_full().as_deref()
                {
                    handle.delete_vrf(name);
                }
                Ok(vrf)
            }
            None => Err(table::TableError::NotFound),
        }
    }

    pub(crate) fn list_vrfs(&self, name: Option<&str>) -> Vec<table::Vrf> {
        let vrfs = self.vrfs.load();
        match name {
            Some(n) => vrfs.get(n).cloned().into_iter().collect(),
            None => vrfs.values().cloned().collect(),
        }
    }

    /// Collect paths from the global VPN table that can be imported into `vrf`.
    /// Returns destinations with the VPN wrapper stripped (plain V4/V6 NLRI).
    pub(crate) fn collect_vrf_paths(
        &self,
        vrf_name: &str,
        family: Family,
        prefixes: Vec<table::PrefixFilter>,
        enable_filtered: bool,
    ) -> Option<Vec<table::DestinationEntry>> {
        let vpn_family = match family {
            Family::IPV4 => Family::IPV4_VPN,
            Family::IPV6 => Family::IPV6_VPN,
            _ => return None,
        };
        let vrf = self.vrfs.load().get(vrf_name)?.clone();
        let mut out = Vec::new();
        for shard in &self.shards {
            let t = shard.lock().unwrap();
            for mut dest in t.rtable.destinations(
                table::TableQuery::Global,
                vpn_family,
                prefixes.clone(),
                enable_filtered,
            ) {
                if dest.paths.iter().any(|p| vrf.can_import(&p.attr)) {
                    // ToLocal() equivalent: strip VPN envelope from NLRI,
                    // remove EXTENDED_COMMUNITY (export RTs) from each path.
                    let Some(local_nlri) = table::vpn_to_local_nlri(&dest.net) else {
                        continue;
                    };
                    dest.net = local_nlri;
                    for path in &mut dest.paths {
                        let stripped: Vec<_> = path
                            .attr
                            .iter()
                            .filter(|a| a.code() != packet::Attribute::EXTENDED_COMMUNITY)
                            .cloned()
                            .collect();
                        path.attr = std::sync::Arc::new(stripped);
                    }
                    out.push(dest);
                }
            }
        }
        Some(out)
    }

    fn dealer<T: Hash>(&self, a: T) -> usize {
        let mut hasher = FnvHasher::default();
        a.hash(&mut hasher);
        hasher.finish() as usize % self.shards.len()
    }

    /// Insert a route into the appropriate shard and distribute changes to peers.
    /// Applies import policy and handles BMP/MRT notification internally.
    /// Returns `true` if the per-peer prefix limit (RFC 4486 §2) was exceeded.
    /// The caller must send a CEASE NOTIFICATION and close the session.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn insert_route(
        &self,
        source: Arc<table::Source>,
        family: Family,
        net: packet::PathNlri,
        nexthop: Option<bgp::Nexthop>,
        attr: Arc<Vec<packet::Attribute>>,
        prefix_limit: Option<(u32, Arc<std::sync::atomic::AtomicU64>)>,
        timestamp: std::time::SystemTime,
    ) -> bool {
        let import_policy = self.import_policy.load_full();
        let kernel_handle = self.kernel_handle.load_full();
        let nht_set = self.nexthop_invalid.load();
        let idx = self.dealer(&net.nlri);
        let mut t = self.shards[idx].lock().unwrap();
        // Load subscribers inside the shard lock (ArcSwap load is lock-free).
        // This guarantees that subscribe_with()'s rcu() is visible before any
        // notify call for routes inserted after the snapshot phase completes.
        let subs = self.subscribers.load();
        t.notify_adj_rib_in(
            &subs,
            source.clone(),
            family,
            std::slice::from_ref(&net),
            Some(&attr),
            nexthop,
            timestamp,
        );
        let old_nh = t
            .rtable
            .lookup_nexthop(source.remote_addr, family, &net.nlri, net.path_id);
        let mut nh = nexthop;
        let original_attr = Arc::clone(&attr);
        let (filtered, post_policy_attr) =
            self.apply_import(import_policy.as_deref(), &source, &net.nlri, &attr, &mut nh);
        if filtered {
            t.notify_adj_rib_in_post(
                &subs,
                source.clone(),
                family,
                std::slice::from_ref(&net),
                None,
                None,
                timestamp,
            );
        } else {
            t.notify_adj_rib_in_post(
                &subs,
                source.clone(),
                family,
                std::slice::from_ref(&net),
                Some(&post_policy_attr),
                nh,
                timestamp,
            );
        }
        let nexthop_invalid_flag = nh.is_some_and(|n| nht_set.contains(&n.addr()));
        let pl = prefix_limit.as_ref().map(|(max, counter)| (*max, counter));
        match t.rtable.insert(
            source.clone(),
            family,
            net.nlri,
            net.path_id,
            nh,
            post_policy_attr,
            Some(original_attr),
            filtered,
            nexthop_invalid_flag,
            pl,
            timestamp,
        ) {
            table::InsertResult::PrefixLimitExceeded => return true,
            table::InsertResult::Changed(update) => {
                nht_register(kernel_handle.as_deref(), &source, nh, old_nh);
                t.distribute_update(update, kernel_handle.as_deref());
            }
            table::InsertResult::NoChange => {
                nht_register(kernel_handle.as_deref(), &source, nh, old_nh);
            }
        }
        false
    }

    /// Remove a route from the appropriate shard and distribute changes to peers.
    pub(crate) fn remove_route(
        &self,
        source: Arc<table::Source>,
        family: Family,
        net: packet::PathNlri,
        prefix_counter: Option<Arc<std::sync::atomic::AtomicU64>>,
        timestamp: std::time::SystemTime,
    ) {
        let kernel_handle = self.kernel_handle.load_full();
        let idx = self.dealer(&net.nlri);
        let mut t = self.shards[idx].lock().unwrap();
        let subs = self.subscribers.load();
        t.notify_adj_rib_in(
            &subs,
            source.clone(),
            family,
            std::slice::from_ref(&net),
            None,
            None,
            timestamp,
        );
        t.notify_adj_rib_in_post(
            &subs,
            source.clone(),
            family,
            std::slice::from_ref(&net),
            None,
            None,
            timestamp,
        );
        let counter_ref = prefix_counter.as_ref();
        let (change, old_nh) =
            t.rtable
                .remove(source.clone(), family, net.nlri, net.path_id, counter_ref);
        if let Some(update) = change {
            t.distribute_update(update, kernel_handle.as_deref());
        }
        if let Some(nh) = old_nh
            && !source.is_kernel()
            && !source.is_local()
            && let Some(handle) = kernel_handle.as_deref()
        {
            handle.unregister_nexthop(nh.addr());
        }
    }

    /// Re-applies the current import policy to all non-stale paths from `peer`
    /// across every shard and distributes any routing changes to peers.
    pub(crate) fn soft_reset_in(&self, peer: IpAddr) {
        let rpki = self.rpki.read().unwrap();
        let import_policy = self.import_policy.load_full();
        let kernel_handle = self.kernel_handle.load_full();
        let nht_set = self.nexthop_invalid.load_full();
        let subs = self.subscribers.load();
        for shard in &self.shards {
            let mut t = shard.lock().unwrap();
            t.soft_reset_in(
                &subs,
                peer,
                import_policy.as_deref(),
                Some(&*rpki),
                kernel_handle.as_deref(),
                &nht_set,
            );
        }
    }

    /// Triggers a soft reset OUT for `peer`: re-advertises all current best
    /// paths to that peer.  Sends a [`ToPeerEvent::SoftResetOut`] on the
    /// peer's event channel; the peer session handles it by calling
    /// `do_route_refresh` for each negotiated family.
    ///
    /// If the peer's session is not Established (e.g., peer is in GR helper
    /// mode and the session is down), the peer session's `do_route_refresh`
    /// exits early, making this a safe no-op.
    pub(crate) fn soft_reset_out(&self, peer: IpAddr) {
        // All shards register the same sender for each peer; shard 0 suffices
        // for the lookup.
        let tx = self.shards[0]
            .lock()
            .unwrap()
            .peer_event_tx
            .get(&peer)
            .cloned();
        if let Some(tx) = tx {
            let _ = tx.send(ToPeerEvent::SoftResetOut);
        }
    }

    /// Notify `peer` to export all current best paths for the given families.
    /// Used by the RTC EOR timer to deliver VPN routes whose advertisement was
    /// suspended while waiting for the peer's RT interests (RFC 4684 s6).
    pub(crate) fn trigger_rtc_export(&self, peer: IpAddr, families: Vec<Family>) {
        let tx = self.shards[0]
            .lock()
            .unwrap()
            .peer_event_tx
            .get(&peer)
            .cloned();
        if let Some(tx) = tx {
            let _ = tx.send(ToPeerEvent::RouteRefreshFamilies(families));
        }
    }

    pub(crate) fn drop_families(&self, addr: IpAddr, families: &[Family]) {
        let kernel_handle = self.kernel_handle.load_full();
        for shard in &self.shards {
            let mut t = shard.lock().unwrap();
            for &family in families {
                t.disconnected(addr, family, kernel_handle.as_deref());
            }
        }
    }

    pub(crate) fn drop_stale_families(&self, addr: IpAddr, families: &[Family]) {
        let kernel_handle = self.kernel_handle.load_full();
        for shard in &self.shards {
            let mut t = shard.lock().unwrap();
            for &family in families {
                t.drop_stale(addr, family, kernel_handle.as_deref());
            }
        }
    }

    pub(crate) fn end_deferral_families(&self, families: &[Family]) {
        let kernel_handle = self.kernel_handle.load_full();
        for shard in &self.shards {
            let mut t = shard.lock().unwrap();
            for &family in families {
                t.end_deferral(family, kernel_handle.as_deref());
            }
        }
    }

    pub(crate) fn start_deferral_families(&self, families: &[Family]) {
        for shard in &self.shards {
            let mut t = shard.lock().unwrap();
            for &family in families {
                t.rtable.start_deferral(family);
            }
        }
    }

    pub(crate) fn rpki_insert(&self, roas: Vec<(packet::IpNet, Arc<table::Roa>)>) {
        let mut rpki = self.rpki.write().unwrap();
        for (net, roa) in roas {
            rpki.insert(net, roa);
        }
    }

    pub(crate) fn rpki_withdraw(&self, roas: Vec<(packet::IpNet, Arc<table::Roa>)>) {
        let mut rpki = self.rpki.write().unwrap();
        for (net, roa) in roas {
            rpki.remove(net, &roa);
        }
    }

    pub(crate) fn rpki_reset(
        &self,
        addr: Arc<IpAddr>,
        roas: Vec<(packet::IpNet, Arc<table::Roa>)>,
    ) {
        let mut rpki = self.rpki.write().unwrap();
        rpki.drop_source(addr);
        for (net, roa) in roas {
            rpki.insert(net, roa);
        }
    }

    pub(crate) fn rpki_drop_all(&self, addr: Arc<IpAddr>) {
        self.rpki.write().unwrap().drop_source(addr);
    }

    pub(crate) fn table_state(&self, family: Family) -> table::TableState {
        let mut state = table::TableState::default();
        for shard in &self.shards {
            state += shard.lock().unwrap().rtable.state(family);
        }
        state
    }

    pub(crate) fn collect_loc_rib_paths(&self, family: Family) -> Vec<table::NlriChange> {
        let mut out = Vec::new();
        for shard in &self.shards {
            out.extend(shard.lock().unwrap().rtable.collect_loc_rib_paths(&family));
        }
        out
    }

    /// Collect all adj-in RTC paths for `peer` across all shards (stale and fresh).
    /// Always includes stale paths so that RtcFilter::from_paths can distinguish
    /// GR-reconnect state (stale present) from normal Active state (no stale).
    pub(crate) fn collect_rtc_paths(&self, peer: std::net::IpAddr) -> Vec<table::SoftResetPath> {
        let mut out = Vec::new();
        for shard in &self.shards {
            out.extend(shard.lock().unwrap().rtable.collect_adj_in_paths(
                peer,
                Some(Family::RTC),
                true,
            ));
        }
        out
    }

    pub(crate) fn collect_roa(&self, family: Family) -> Vec<(packet::IpNet, table::Roa)> {
        self.rpki
            .read()
            .unwrap()
            .iter(family)
            .map(|(net, roa)| (net, roa.clone()))
            .collect()
    }

    pub(crate) fn rpki_state(&self, addr: &IpAddr) -> table::RpkiTableState {
        self.rpki.read().unwrap().state(addr)
    }

    pub(crate) fn apply_import(
        &self,
        policy: Option<&table::PolicyAssignment>,
        source: &Arc<table::Source>,
        net: &packet::Nlri,
        attrs: &Arc<Vec<packet::Attribute>>,
        nexthop: &mut Option<packet::bgp::Nexthop>,
    ) -> (bool, Arc<Vec<packet::Attribute>>) {
        let Some(policy) = policy else {
            return (false, Arc::clone(attrs));
        };
        let rpki = self.rpki.read().unwrap();
        table::apply_import(policy, Some(&rpki), source, net, attrs, nexthop)
    }

    pub(crate) fn collect_peer_stats(
        &self,
        addrs: &[IpAddr],
    ) -> FnvHashMap<IpAddr, FnvHashMap<Family, table::PrefixStats>> {
        let mut map: FnvHashMap<IpAddr, FnvHashMap<Family, table::PrefixStats>> =
            FnvHashMap::default();
        for shard in &self.shards {
            let t = shard.lock().unwrap();
            for addr in addrs {
                if let Some(iter) = t.rtable.peer_stats(addr) {
                    let entry = map.entry(*addr).or_default();
                    for (f, s) in iter {
                        let stats = entry.entry(f).or_default();
                        stats.received += s.received;
                        stats.accepted += s.accepted;
                    }
                }
            }
        }
        map
    }

    pub(crate) fn collect_paths(
        &self,
        query: table::TableQuery,
        family: Family,
        prefixes: Vec<table::PrefixFilter>,
        enable_filtered: bool,
    ) -> Vec<table::DestinationEntry> {
        // Phase 1: collect from each shard (validation: None); shard lock released after each.
        let mut out = Vec::new();
        for shard in &self.shards {
            let t = shard.lock().unwrap();
            out.extend(
                t.rtable
                    .destinations(query, family, prefixes.clone(), enable_filtered),
            );
        }
        // Phase 2: apply RPKI validation without holding any shard lock.
        let rpki = self.rpki.read().unwrap();
        for dest in &mut out {
            for path in &mut dest.paths {
                path.validation = rpki.validate(&path.source, &dest.net, &path.attr);
            }
        }
        out
    }

    /// Subscribe to BGP events.
    ///
    /// When `want_snapshot` is `true`, snapshot events for all current Adj-RIB-In
    /// routes are queued into the channel before this function returns, followed by
    /// a `BgpEvent::EndOfSnapshot` sentinel.  Live events (and any concurrent
    /// inserts that race with the snapshot) are delivered after the sentinel.
    ///
    /// When `want_snapshot` is `false`, only live events are delivered.
    pub(crate) fn subscribe(&self, want_snapshot: bool) -> Subscription {
        let id = SubscriptionId(
            self.next_sub_id
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        );
        let (tx, rx) = mpsc::unbounded_channel();
        // Register before snapshotting shards so that any insert_route() that takes
        // a shard lock after us will load the updated list and notify this subscriber.
        self.subscribers.rcu(|cur| {
            let mut v = (**cur).clone();
            v.push((id, tx.clone()));
            Arc::new(v)
        });
        if want_snapshot {
            // Snapshot each shard while holding the lock.  Any insert_route() on a
            // shard that has not yet been snapshotted either:
            //   (a) acquired the lock before us -> its route appears in the snapshot, or
            //   (b) acquires the lock after us  -> loads subscribers inside the lock and
            //       finds our tx (rcu already completed), so the live event is delivered.
            // Concurrent inserts in case (b) may arrive in the channel interleaved with
            // snapshot events; callers must drain until EndOfSnapshot and accumulate all
            // AdjRibIn events to obtain the net state at subscription time.
            for shard in &self.shards {
                let t = shard.lock().unwrap();
                for f in t.rtable.families().collect::<Vec<_>>() {
                    for reach in t.rtable.iter_reach(f) {
                        let addpath = t.has_addpath(&reach.source.remote_addr, &f);
                        let _ = tx.send(BgpEvent::AdjRibIn(AdjRibInChange {
                            source: reach.source,
                            family: f,
                            addpath,
                            nlris: vec![reach.net],
                            attrs: Some(reach.attr),
                            nexthop: reach.nexthop,
                            timestamp: reach.timestamp,
                        }));
                    }
                    for reach in t.rtable.iter_reach_post(f) {
                        let addpath = t.has_addpath(&reach.source.remote_addr, &f);
                        let _ = tx.send(BgpEvent::AdjRibInPost(AdjRibInChange {
                            source: reach.source,
                            family: f,
                            addpath,
                            nlris: vec![reach.net],
                            attrs: Some(reach.attr),
                            nexthop: reach.nexthop,
                            timestamp: reach.timestamp,
                        }));
                    }
                }
            }
            let _ = tx.send(BgpEvent::EndOfSnapshot);
        }
        Subscription { rx, id }
    }

    pub(crate) fn unsubscribe(&self, id: SubscriptionId) {
        self.subscribers
            .rcu(|cur| Arc::new(cur.iter().filter(|(i, _)| *i != id).cloned().collect()));
    }

    pub(crate) fn peer_up(&self, data: PeerUpData) {
        for (_, tx) in self.subscribers.load().iter() {
            let _ = tx.send(BgpEvent::PeerUp(data.clone()));
        }
    }

    pub(crate) fn peer_down(&self, data: PeerDownData) {
        for (_, tx) in self.subscribers.load().iter() {
            let _ = tx.send(BgpEvent::PeerDown(data.clone()));
        }
    }

    /// Collect the current set of BMP/MRT subscriber senders.
    ///
    /// Returns an empty Vec when no subscribers are registered, letting callers
    /// skip Adj-RIB-Out notification cheaply in the common (no-BMP) case.
    pub(crate) fn bmp_senders(&self) -> Vec<mpsc::UnboundedSender<BgpEvent>> {
        self.subscribers
            .load()
            .iter()
            .map(|(_, tx)| tx.clone())
            .collect()
    }

    /// Register a peer's event channel with every shard atomically.
    ///
    /// For each shard, while the lock is held, `on_shard` is called with the
    /// shard's routing table so the caller can populate its initial routes.
    /// The returned receiver delivers `ToPeerEvent` messages from all shards.
    pub(crate) fn register_peer<F>(
        &self,
        addr: IpAddr,
        addpath: FnvHashSet<Family>,
        mut on_shard: F,
    ) -> mpsc::UnboundedReceiver<ToPeerEvent>
    where
        F: FnMut(&table::Table),
    {
        let (tx, rx) = mpsc::unbounded_channel();
        for shard in &self.shards {
            let mut t = shard.lock().unwrap();
            on_shard(&t.rtable);
            t.peer_event_tx.insert(addr, tx.clone());
            if !addpath.is_empty() {
                t.addpath.insert(addr, addpath.clone());
            }
        }
        rx
    }

    pub(crate) fn unregister_peer(
        &self,
        addr: IpAddr,
        drop_families: &[Family],
        stale_families: &[Family],
    ) {
        let kernel_handle = self.kernel_handle.load_full();
        for shard in &self.shards {
            let mut t = shard.lock().unwrap();
            t.peer_event_tx.remove(&addr);
            t.addpath.remove(&addr);
            for &family in drop_families {
                t.disconnected(addr, family, kernel_handle.as_deref());
            }
            for &family in stale_families {
                t.mark_stale(addr, family, kernel_handle.as_deref());
            }
        }
    }

    /// Update the reachability state of a nexthop address received from NHT.
    ///
    /// Updates the `nexthop_invalid` ArcSwap set so that newly inserted paths
    /// see the current reachability, then walks all shards to flip
    /// `FLAG_NEXTHOP_INVALID` on affected paths and distribute routing changes.
    pub(crate) fn update_nexthop_validity(&self, addr: IpAddr, reachable: bool) {
        // Update the ArcSwap set.  Loads/swaps are serialized through the event loop.
        let current = self.nexthop_invalid.load_full();
        let mut new_set = (*current).clone();
        if reachable {
            new_set.remove(&addr);
        } else {
            new_set.insert(addr);
        }
        self.nexthop_invalid.store(Arc::new(new_set));

        let kernel_handle = self.kernel_handle.load_full();
        for shard in &self.shards {
            let mut t = shard.lock().unwrap();
            for change in t.rtable.update_nexthop_validity(addr, reachable) {
                t.distribute_update(change, kernel_handle.as_deref());
            }
        }
    }

    /// Inject a kernel-redistributed route into the BGP RIB.
    pub(crate) fn inject_kernel_route(&self, kr: kernel::KernelRoute) {
        let Some((family, net, nexthop, attr)) = kernel_route_to_path(&kr) else {
            return;
        };
        self.insert_route(
            table::Source::kernel(),
            family,
            net,
            Some(nexthop),
            attr,
            None,
            std::time::SystemTime::now(),
        );
    }

    /// Withdraw a kernel-redistributed route from the BGP RIB.
    pub(crate) fn withdraw_kernel_route(&self, dst: std::net::IpAddr, prefix_len: u8) {
        let nlri = ip_to_nlri(dst, prefix_len);
        let family = nlri_family(&nlri);
        self.remove_route(
            table::Source::kernel(),
            family,
            packet::PathNlri { nlri, path_id: 0 },
            None,
            std::time::SystemTime::now(),
        );
    }

    /// Inject or withdraw a Connected route triggered by an interface address event.
    ///
    /// The route destination is the network prefix (interface address masked by
    /// prefix_len); the BGP nexthop is the interface address itself per RFC 4271 §5.1.3.
    pub(crate) fn handle_address_event(&self, event: kernel::KernelAddressEvent) {
        let (ka, is_add) = match event {
            kernel::KernelAddressEvent::Add(a) => (a, true),
            kernel::KernelAddressEvent::Delete(a) => (a, false),
        };
        let network = apply_prefix_mask(ka.addr, ka.prefix_len);
        if is_add {
            let kr = kernel::KernelRoute {
                dst: network,
                prefix_len: ka.prefix_len,
                nexthop: Some(ka.addr),
                metric: 0,
                protocol: kernel::Protocol::Kernel,
            };
            self.inject_kernel_route(kr);
        } else {
            self.withdraw_kernel_route(network, ka.prefix_len);
        }
    }
}

/// Convert a `KernelRoute` to the components needed by `insert_route`.
///
/// Returns `None` when the route has no usable nexthop or the family cannot
/// be determined (e.g. MUP/VPN NLRIs).
fn kernel_route_to_path(
    kr: &kernel::KernelRoute,
) -> Option<(
    Family,
    packet::PathNlri,
    bgp::Nexthop,
    Arc<Vec<packet::Attribute>>,
)> {
    let nexthop_ip = kr.nexthop?;
    let nexthop = match nexthop_ip {
        std::net::IpAddr::V4(v4) => bgp::Nexthop::V4(v4),
        std::net::IpAddr::V6(v6) => bgp::Nexthop::V6(v6),
    };
    let (nlri, family) = match kr.dst {
        std::net::IpAddr::V4(addr) => {
            let nlri = packet::Nlri::V4(packet::bgp::Ipv4Net {
                addr,
                mask: kr.prefix_len,
            });
            (nlri, Family::IPV4)
        }
        std::net::IpAddr::V6(addr) => {
            let nlri = packet::Nlri::V6(packet::bgp::Ipv6Net {
                addr,
                mask: kr.prefix_len,
            });
            (nlri, Family::IPV6)
        }
    };
    let mut attrs = vec![
        packet::Attribute::new_with_value(packet::Attribute::ORIGIN, 0) // 0 = IGP
            .unwrap(),
        packet::Attribute::empty_as_path(),
    ];
    if kr.metric > 0
        && let Some(med) =
            packet::Attribute::new_with_value(packet::Attribute::MULTI_EXIT_DESC, kr.metric)
    {
        attrs.push(med);
    }
    Some((
        family,
        packet::PathNlri { nlri, path_id: 0 },
        nexthop,
        Arc::new(attrs),
    ))
}

fn ip_to_nlri(dst: std::net::IpAddr, prefix_len: u8) -> packet::Nlri {
    match dst {
        std::net::IpAddr::V4(addr) => packet::Nlri::V4(packet::bgp::Ipv4Net {
            addr,
            mask: prefix_len,
        }),
        std::net::IpAddr::V6(addr) => packet::Nlri::V6(packet::bgp::Ipv6Net {
            addr,
            mask: prefix_len,
        }),
    }
}

fn nlri_family(nlri: &packet::Nlri) -> Family {
    match nlri {
        packet::Nlri::V4(_) => Family::IPV4,
        packet::Nlri::V6(_) => Family::IPV6,
        _ => Family::IPV4,
    }
}

/// Apply a prefix mask to an IP address, returning the network address.
fn apply_prefix_mask(addr: std::net::IpAddr, prefix_len: u8) -> std::net::IpAddr {
    match addr {
        std::net::IpAddr::V4(v4) => {
            let bits = u32::from(v4);
            let mask = if prefix_len == 0 {
                0u32
            } else {
                u32::MAX << (32 - prefix_len)
            };
            std::net::IpAddr::V4(std::net::Ipv4Addr::from(bits & mask))
        }
        std::net::IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            let mask = if prefix_len == 0 {
                0u128
            } else {
                u128::MAX << (128 - prefix_len)
            };
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(bits & mask))
        }
    }
}

/// Register the new nexthop and unregister the old one for NHT tracking.
///
/// Called after every path insert (Changed or NoChange) for paths from
/// non-kernel, non-local sources.  When `new_nh == old_nh` the register and
/// unregister calls cancel out via the kernel service's reference counter.
fn nht_register(
    kernel_handle: Option<&kernel::KernelHandle>,
    source: &table::Source,
    new_nh: Option<bgp::Nexthop>,
    old_nh: Option<bgp::Nexthop>,
) {
    if source.is_kernel() || source.is_local() {
        return;
    }
    let Some(handle) = kernel_handle else {
        return;
    };
    if let Some(nh) = new_nh {
        handle.register_nexthop(nh.addr());
    }
    if let Some(nh) = old_nh {
        handle.unregister_nexthop(nh.addr());
    }
}

pub(crate) struct TableShard {
    pub(crate) rtable: table::Table,
    peer_event_tx: FnvHashMap<IpAddr, mpsc::UnboundedSender<ToPeerEvent>>,
    pub(crate) addpath: FnvHashMap<IpAddr, FnvHashSet<Family>>,
    vrfs: SharedVrfs,
}

impl TableShard {
    fn has_addpath(&self, addr: &IpAddr, family: &Family) -> bool {
        self.addpath.get(addr).is_some_and(|e| e.contains(family))
    }

    fn disconnected(
        &mut self,
        addr: IpAddr,
        family: Family,
        kernel_handle: Option<&kernel::KernelHandle>,
    ) {
        let (changes, nexthops) = self.rtable.drop(addr, family);
        for change in changes {
            self.distribute_update(change, kernel_handle);
        }
        if let Some(handle) = kernel_handle {
            for nh in nexthops {
                handle.unregister_nexthop(nh);
            }
        }
    }

    fn mark_stale(
        &mut self,
        addr: IpAddr,
        family: Family,
        kernel_handle: Option<&kernel::KernelHandle>,
    ) {
        for change in self.rtable.restale(addr, family) {
            self.distribute_update(change, kernel_handle);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn notify_adj_rib_in(
        &self,
        subs: &[(SubscriptionId, mpsc::UnboundedSender<BgpEvent>)],
        source: Arc<table::Source>,
        family: Family,
        nets: &[packet::PathNlri],
        attrs: Option<&Arc<Vec<packet::Attribute>>>,
        nexthop: Option<bgp::Nexthop>,
        timestamp: std::time::SystemTime,
    ) {
        let addpath = self.has_addpath(&source.remote_addr, &family);
        for (_, tx) in subs {
            let _ = tx.send(BgpEvent::AdjRibIn(AdjRibInChange {
                source: source.clone(),
                family,
                addpath,
                nlris: nets.to_owned(),
                attrs: attrs.cloned(),
                nexthop,
                timestamp,
            }));
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn notify_adj_rib_in_post(
        &self,
        subs: &[(SubscriptionId, mpsc::UnboundedSender<BgpEvent>)],
        source: Arc<table::Source>,
        family: Family,
        nets: &[packet::PathNlri],
        attrs: Option<&Arc<Vec<packet::Attribute>>>,
        nexthop: Option<bgp::Nexthop>,
        timestamp: std::time::SystemTime,
    ) {
        let addpath = self.has_addpath(&source.remote_addr, &family);
        for (_, tx) in subs {
            let _ = tx.send(BgpEvent::AdjRibInPost(AdjRibInChange {
                source: source.clone(),
                family,
                addpath,
                nlris: nets.to_owned(),
                attrs: attrs.cloned(),
                nexthop,
                timestamp,
            }));
        }
    }

    fn distribute_update(
        &self,
        update: table::NlriChange,
        kernel_handle: Option<&kernel::KernelHandle>,
    ) {
        // Kernel route update for rank-1 best (raw, without export policy).
        // kernel_handle is rarely set, so check it first.
        if let Some(handle) = kernel_handle
            && update.best_changed
        {
            let nexthops: Vec<_> = if update.new_best().is_none() {
                vec![]
            } else {
                update
                    .ecmp_paths()
                    .into_iter()
                    .filter_map(|p| p.nexthop)
                    .collect()
            };
            let metric = update
                .new_best()
                .and_then(|p| {
                    p.attr
                        .iter()
                        .find(|a| a.code() == packet::Attribute::MULTI_EXIT_DESC)
                })
                .and_then(|a| a.value())
                .unwrap_or(0);
            handle.apply(kernel::KernelRouteChange {
                net: update.net.clone(),
                nexthops: nexthops.clone(),
                metric,
                table_id: None,
            });

            // VRF FIB distribution: for VPN NLRIs, install/withdraw from each
            // VRF whose import-RT matches the best-path extended communities.
            // Withdrawals are attempted for all VRFs that have a table_id;
            // the kernel ignores routes not present in the table.
            if matches!(update.net, packet::Nlri::VpnV4(_) | packet::Nlri::VpnV6(_)) {
                let vrfs = self.vrfs.load();
                for vrf in vrfs.values() {
                    if vrf.id == 0 {
                        continue;
                    }
                    let Some(local_nlri) = table::vpn_to_local_nlri(&update.net) else {
                        continue;
                    };
                    let distribute = nexthops.is_empty()
                        || update.new_best().is_some_and(|p| vrf.can_import(&p.attr));
                    if distribute {
                        handle.apply(kernel::KernelRouteChange {
                            net: local_nlri,
                            nexthops: nexthops.clone(),
                            metric,
                            table_id: Some(vrf.id),
                        });
                    }
                }
            }
        }

        // Fan out raw NlriChange to all peer channels.
        // Each peer applies export policy per-peer in process_nlri_change.
        for tx in self.peer_event_tx.values() {
            let _ = tx.send(ToPeerEvent::NlriChange(update.clone()));
        }
    }

    /// Re-applies the current import policy to all non-stale paths from `peer`.
    ///
    /// Each path is re-inserted via [`table::Table::insert`] using its stored
    /// pre-policy attributes (`original_attr`), which replaces the existing RIB
    /// entry and triggers best-path recalculation and peer notification if the
    /// post-policy result changed.
    ///
    /// Stale paths (GR helper mode) are skipped; see
    /// [`table::Table::collect_adj_in_paths`] for the rationale.
    fn soft_reset_in(
        &mut self,
        subs: &[(SubscriptionId, mpsc::UnboundedSender<BgpEvent>)],
        peer: std::net::IpAddr,
        import_policy: Option<&table::PolicyAssignment>,
        rpki: Option<&table::RpkiTable>,
        kernel_handle: Option<&kernel::KernelHandle>,
        nexthop_invalid: &FnvHashSet<IpAddr>,
    ) {
        let paths = self.rtable.collect_adj_in_paths(peer, None, false);
        for (family, net, remote_path_id, mut nh, source, original_attr, timestamp) in paths {
            let old_nh =
                self.rtable
                    .lookup_nexthop(source.remote_addr, family, &net, remote_path_id);
            let (filtered, post_policy_attr) = if let Some(policy) = import_policy {
                table::apply_import(policy, rpki, &source, &net, &original_attr, &mut nh)
            } else {
                (false, Arc::clone(&original_attr))
            };
            let path_nlri = packet::PathNlri {
                nlri: net.clone(),
                path_id: remote_path_id,
            };
            if filtered {
                self.notify_adj_rib_in_post(
                    subs,
                    source.clone(),
                    family,
                    &[path_nlri],
                    None,
                    None,
                    timestamp,
                );
            } else {
                self.notify_adj_rib_in_post(
                    subs,
                    source.clone(),
                    family,
                    &[path_nlri],
                    Some(&post_policy_attr),
                    nh,
                    timestamp,
                );
            }
            let nexthop_invalid_flag = nh.is_some_and(|n| nexthop_invalid.contains(&n.addr()));
            // Propagate policy-induced nexthop change into NHT tracking.
            if !source.is_kernel()
                && !source.is_local()
                && old_nh.map(|o| o.addr()) != nh.map(|n| n.addr())
                && let Some(handle) = kernel_handle
            {
                if let Some(new_nh) = nh {
                    handle.register_nexthop(new_nh.addr());
                }
                if let Some(old) = old_nh {
                    handle.unregister_nexthop(old.addr());
                }
            }
            match self.rtable.insert(
                source.clone(),
                family,
                net,
                remote_path_id,
                nh,
                post_policy_attr,
                Some(original_attr),
                filtered,
                nexthop_invalid_flag,
                None,
                timestamp,
            ) {
                table::InsertResult::Changed(update) => {
                    self.distribute_update(update, kernel_handle);
                }
                table::InsertResult::NoChange | table::InsertResult::PrefixLimitExceeded => {}
            }
        }
    }

    fn drop_stale(
        &mut self,
        addr: IpAddr,
        family: Family,
        kernel_handle: Option<&kernel::KernelHandle>,
    ) {
        let (changes, nexthops) = self.rtable.drop_stale(addr, family, None);
        for change in changes {
            self.distribute_update(change, kernel_handle);
        }
        if let Some(handle) = kernel_handle {
            for nh in nexthops {
                handle.unregister_nexthop(nh);
            }
        }
    }

    fn end_deferral(&mut self, family: Family, kernel_handle: Option<&kernel::KernelHandle>) {
        for change in self.rtable.end_deferral(family) {
            self.distribute_update(change, kernel_handle);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn kr_v4(
        dst: &str,
        prefix_len: u8,
        nexthop: &str,
        metric: u32,
        protocol: kernel::Protocol,
    ) -> kernel::KernelRoute {
        kernel::KernelRoute {
            dst: dst.parse().unwrap(),
            prefix_len,
            nexthop: Some(nexthop.parse().unwrap()),
            metric,
            protocol,
        }
    }

    fn kr_v6(
        dst: &str,
        prefix_len: u8,
        nexthop: &str,
        metric: u32,
        protocol: kernel::Protocol,
    ) -> kernel::KernelRoute {
        kernel::KernelRoute {
            dst: dst.parse().unwrap(),
            prefix_len,
            nexthop: Some(nexthop.parse().unwrap()),
            metric,
            protocol,
        }
    }

    // --- kernel_route_to_path unit tests (no Netlink needed) ---

    #[test]
    fn kernel_route_to_path_v4_static() {
        let kr = kr_v4("10.0.0.0", 24, "192.168.1.1", 0, kernel::Protocol::Static);
        let (family, net, nexthop, attrs) = kernel_route_to_path(&kr).unwrap();
        assert_eq!(family, Family::IPV4);
        assert!(matches!(net.nlri, packet::Nlri::V4(_)));
        assert!(matches!(nexthop, packet::bgp::Nexthop::V4(a) if a == Ipv4Addr::new(192,168,1,1)));
        // Origin IGP (code=1, value=0) must be present.
        assert!(attrs.iter().any(|a| a.code() == packet::Attribute::ORIGIN));
        // AS_PATH must be present.
        assert!(attrs.iter().any(|a| a.code() == packet::Attribute::AS_PATH));
        // No MED when metric == 0.
        assert!(
            !attrs
                .iter()
                .any(|a| a.code() == packet::Attribute::MULTI_EXIT_DESC)
        );
    }

    #[test]
    fn kernel_route_to_path_v4_with_metric() {
        let kr = kr_v4("10.1.0.0", 24, "192.168.1.1", 100, kernel::Protocol::Ospf);
        let (_, _, _, attrs) = kernel_route_to_path(&kr).unwrap();
        assert!(
            attrs
                .iter()
                .any(|a| a.code() == packet::Attribute::MULTI_EXIT_DESC)
        );
    }

    #[test]
    fn kernel_route_to_path_v6() {
        let kr = kr_v6("2001:db8::", 32, "fe80::1", 0, kernel::Protocol::Static);
        let (family, net, nexthop, _) = kernel_route_to_path(&kr).unwrap();
        assert_eq!(family, Family::IPV6);
        assert!(matches!(net.nlri, packet::Nlri::V6(_)));
        assert!(matches!(nexthop, packet::bgp::Nexthop::V6(_)));
    }

    #[test]
    fn kernel_route_to_path_no_nexthop_returns_none() {
        let kr = kernel::KernelRoute {
            dst: "10.0.0.0".parse().unwrap(),
            prefix_len: 24,
            nexthop: None,
            metric: 0,
            protocol: kernel::Protocol::Static,
        };
        assert!(kernel_route_to_path(&kr).is_none());
    }

    // --- inject/withdraw kernel route tests (no Netlink needed) ---

    fn make_tables() -> Arc<TableManager> {
        Arc::new(TableManager::new(1))
    }

    #[tokio::test]
    async fn inject_kernel_route_adds_path() {
        let tables = make_tables();
        let kr = kr_v4("10.0.0.0", 24, "192.168.1.1", 0, kernel::Protocol::Static);
        tables.inject_kernel_route(kr);
        let paths = tables.collect_paths(
            rustybgp_table::TableQuery::Global,
            Family::IPV4,
            vec![],
            false,
        );
        assert_eq!(paths.len(), 1);
        assert!(paths[0].paths[0].source.is_kernel());
    }

    #[tokio::test]
    async fn withdraw_kernel_route_removes_path() {
        let tables = make_tables();
        let kr = kr_v4("10.0.0.0", 24, "192.168.1.1", 0, kernel::Protocol::Static);
        tables.inject_kernel_route(kr);
        tables.withdraw_kernel_route("10.0.0.0".parse().unwrap(), 24);
        let paths = tables.collect_paths(
            rustybgp_table::TableQuery::Global,
            Family::IPV4,
            vec![],
            false,
        );
        assert_eq!(paths.len(), 0);
    }

    // --- NHT (Nexthop Tracking) tests ---

    fn make_peer_source(remote: &str, local: &str, remote_asn: u32) -> Arc<table::Source> {
        Arc::new(table::Source::new(
            remote.parse().unwrap(),
            local.parse().unwrap(),
            remote_asn,
            65001,
            remote.parse().unwrap(),
            table::PeerRole::Ebgp,
        ))
    }

    fn insert_v4_route(
        tables: &TableManager,
        source: Arc<table::Source>,
        prefix: &str,
        nexthop: &str,
    ) {
        let nlri: packet::Nlri = prefix.parse().unwrap();
        let net = packet::PathNlri::new(nlri);
        let nh: std::net::Ipv4Addr = nexthop.parse().unwrap();
        tables.insert_route(
            source,
            Family::IPV4,
            net,
            Some(packet::bgp::Nexthop::V4(nh)),
            Arc::new(vec![]),
            None,
            std::time::SystemTime::UNIX_EPOCH,
        );
    }

    fn loc_rib_len(tables: &TableManager, shard: usize, family: Family) -> usize {
        // SAFETY: called in a synchronous context after all async inserts complete.
        // We use try_lock() to avoid blocking; the test controls concurrency.
        tables.shards[shard]
            .try_lock()
            .expect("shard locked unexpectedly")
            .rtable
            .collect_loc_rib_paths(&family)
            .len()
    }

    #[tokio::test]
    async fn nht_invalid_nexthop_excluded_from_best() {
        let tables = make_tables();
        let src = make_peer_source("10.0.0.2", "127.0.0.1", 65002);
        insert_v4_route(&tables, src, "192.168.1.0/24", "10.0.0.2");

        assert_eq!(loc_rib_len(&tables, 0, Family::IPV4), 1);

        tables.update_nexthop_validity("10.0.0.2".parse().unwrap(), false);

        // Nexthop is now invalid: path must be excluded from loc-RIB.
        assert_eq!(loc_rib_len(&tables, 0, Family::IPV4), 0);
    }

    #[tokio::test]
    async fn nht_valid_nexthop_restored() {
        let tables = make_tables();
        let src = make_peer_source("10.0.0.2", "127.0.0.1", 65002);
        insert_v4_route(&tables, src, "192.168.1.0/24", "10.0.0.2");

        tables.update_nexthop_validity("10.0.0.2".parse().unwrap(), false);
        assert_eq!(loc_rib_len(&tables, 0, Family::IPV4), 0);

        // Nexthop becomes reachable again: path must be restored to loc-RIB.
        tables.update_nexthop_validity("10.0.0.2".parse().unwrap(), true);
        assert_eq!(loc_rib_len(&tables, 0, Family::IPV4), 1);
    }

    #[tokio::test]
    async fn nht_new_path_with_already_invalid_nexthop() {
        let tables = make_tables();

        // Mark the nexthop unreachable BEFORE the path arrives.
        tables.update_nexthop_validity("10.0.0.2".parse().unwrap(), false);

        let src = make_peer_source("10.0.0.2", "127.0.0.1", 65002);
        insert_v4_route(&tables, src, "192.168.1.0/24", "10.0.0.2");

        // The path must not appear in loc-RIB: the ArcSwap set was checked
        // at insertion time and nexthop_invalid_flag was set.
        assert_eq!(loc_rib_len(&tables, 0, Family::IPV4), 0);
    }

    // --- apply_prefix_mask unit tests ---

    #[test]
    fn apply_prefix_mask_v4() {
        use std::net::IpAddr;
        let addr: IpAddr = "192.168.1.5".parse().unwrap();
        assert_eq!(
            apply_prefix_mask(addr, 24),
            "192.168.1.0".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            apply_prefix_mask(addr, 16),
            "192.168.0.0".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            apply_prefix_mask(addr, 0),
            "0.0.0.0".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            apply_prefix_mask(addr, 32),
            "192.168.1.5".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn apply_prefix_mask_v6() {
        use std::net::IpAddr;
        let addr: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(
            apply_prefix_mask(addr, 32),
            "2001:db8::".parse::<IpAddr>().unwrap()
        );
        assert_eq!(apply_prefix_mask(addr, 0), "::".parse::<IpAddr>().unwrap());
        assert_eq!(
            apply_prefix_mask(addr, 128),
            "2001:db8::1".parse::<IpAddr>().unwrap()
        );
    }
}
