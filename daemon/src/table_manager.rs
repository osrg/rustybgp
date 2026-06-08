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

use arc_swap::ArcSwapOption;
use fnv::{FnvHashMap, FnvHashSet, FnvHasher};
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};

use rustybgp_packet::{self as packet, Family, bgp};
use rustybgp_table as table;

use crate::event::{KernelRouteEvent, ToPeerEvent};

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

pub(crate) enum BgpEvent {
    AdjRibIn(AdjRibInChange),
    PeerUp(PeerUpData),
    PeerDown(PeerDownData),
}

pub(crate) struct Subscription {
    pub(crate) rx: mpsc::UnboundedReceiver<BgpEvent>,
    pub(crate) id: SubscriptionId,
}

pub(crate) type TableHandle = Arc<TableManager>;

pub(crate) struct TableManager {
    pub(crate) shards: Vec<Mutex<TableShard>>,
    rpki: std::sync::RwLock<table::RpkiTable>,
    pub(crate) kernel_tx: ArcSwapOption<mpsc::UnboundedSender<KernelRouteEvent>>,
    pub(crate) import_policy: ArcSwapOption<table::PolicyAssignment>,
    pub(crate) export_policy: ArcSwapOption<table::PolicyAssignment>,
    next_sub_id: std::sync::atomic::AtomicU64,
    subscribers: Mutex<FnvHashMap<SubscriptionId, mpsc::UnboundedSender<BgpEvent>>>,
}

impl TableManager {
    pub(crate) fn new(num_shards: usize) -> Self {
        TableManager {
            shards: (0..num_shards)
                .map(|_| {
                    Mutex::new(TableShard {
                        rtable: table::Table::new(),
                        peer_event_tx: FnvHashMap::default(),
                        subscribers: FnvHashMap::default(),
                        addpath: FnvHashMap::default(),
                    })
                })
                .collect(),
            rpki: std::sync::RwLock::new(table::RpkiTable::new()),
            kernel_tx: ArcSwapOption::const_empty(),
            import_policy: ArcSwapOption::const_empty(),
            export_policy: ArcSwapOption::const_empty(),
            next_sub_id: std::sync::atomic::AtomicU64::new(0),
            subscribers: Mutex::new(FnvHashMap::default()),
        }
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
    pub(crate) async fn insert_route(
        &self,
        source: Arc<table::Source>,
        family: Family,
        net: packet::PathNlri,
        nexthop: bgp::Nexthop,
        attr: Arc<Vec<packet::Attribute>>,
        prefix_limit: Option<(u32, Arc<std::sync::atomic::AtomicU64>)>,
    ) -> bool {
        let import_policy = self.import_policy.load_full();
        let export_policy = self.export_policy.load_full();
        let kernel_tx = self.kernel_tx.load_full();
        let idx = self.dealer(net.nlri);
        let mut t = self.shards[idx].lock().await;
        t.notify_adj_rib_in(source.clone(), family, &[net], Some(&attr), Some(nexthop));
        let mut nh = nexthop;
        let filtered = crate::policy::apply_import(
            import_policy.as_deref(),
            &source,
            &net.nlri,
            &attr,
            &mut nh,
        );
        let pl = prefix_limit.as_ref().map(|(max, counter)| (*max, counter));
        match t.rtable.insert(
            source,
            family,
            net.nlri,
            net.path_id,
            nh,
            attr,
            filtered,
            pl,
        ) {
            table::InsertResult::PrefixLimitExceeded => return true,
            table::InsertResult::Changed(update) => {
                t.distribute_update(update, kernel_tx.as_deref(), export_policy.as_deref());
            }
            table::InsertResult::NoChange => {}
        }
        false
    }

    /// Remove a route from the appropriate shard and distribute changes to peers.
    pub(crate) async fn remove_route(
        &self,
        source: Arc<table::Source>,
        family: Family,
        net: packet::PathNlri,
        prefix_counter: Option<Arc<std::sync::atomic::AtomicU64>>,
    ) {
        let export_policy = self.export_policy.load_full();
        let kernel_tx = self.kernel_tx.load_full();
        let idx = self.dealer(net.nlri);
        let mut t = self.shards[idx].lock().await;
        t.notify_adj_rib_in(source.clone(), family, &[net], None, None);
        let counter_ref = prefix_counter.as_ref();
        if let Some(update) = t
            .rtable
            .remove(source, family, net.nlri, net.path_id, counter_ref)
        {
            t.distribute_update(update, kernel_tx.as_deref(), export_policy.as_deref());
        }
    }

    pub(crate) async fn pass_update(
        &self,
        source: Arc<table::Source>,
        family: Family,
        nets: Vec<packet::PathNlri>,
        attrs: Option<Arc<Vec<packet::Attribute>>>,
        nexthop: Option<bgp::Nexthop>,
    ) {
        let Some(first) = nets.first() else { return };
        let idx = self.dealer(first.nlri);
        let import_policy = self.import_policy.load_full();
        let export_policy = self.export_policy.load_full();
        let kernel_tx = self.kernel_tx.load_full();
        self.shards[idx].lock().await.pass_update(
            source,
            family,
            nets,
            attrs,
            nexthop,
            import_policy.as_deref(),
            kernel_tx.as_deref(),
            export_policy.as_deref(),
        );
    }

    pub(crate) async fn drop_families(&self, addr: IpAddr, families: &[Family]) {
        let kernel_tx = self.kernel_tx.load_full();
        for shard in &self.shards {
            let mut t = shard.lock().await;
            for &family in families {
                t.disconnected(addr, family, kernel_tx.as_deref());
            }
        }
    }

    pub(crate) async fn drop_stale_families(&self, addr: IpAddr, families: &[Family]) {
        let kernel_tx = self.kernel_tx.load_full();
        for shard in &self.shards {
            let mut t = shard.lock().await;
            for &family in families {
                t.drop_stale(addr, family, kernel_tx.as_deref());
            }
        }
    }

    pub(crate) async fn end_deferral_families(&self, families: &[Family]) {
        let kernel_tx = self.kernel_tx.load_full();
        let export_policy = self.export_policy.load_full();
        for shard in &self.shards {
            let mut t = shard.lock().await;
            for &family in families {
                t.end_deferral(family, kernel_tx.as_deref(), export_policy.as_deref());
            }
        }
    }

    pub(crate) async fn start_deferral_families(&self, families: &[Family]) {
        for shard in &self.shards {
            let mut t = shard.lock().await;
            for &family in families {
                t.rtable.start_deferral(family);
            }
        }
    }

    pub(crate) async fn rpki_insert(&self, roas: Vec<(packet::IpNet, Arc<table::Roa>)>) {
        let mut rpki = self.rpki.write().unwrap();
        for (net, roa) in roas {
            rpki.insert(net, roa);
        }
    }

    pub(crate) async fn rpki_reset(
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

    pub(crate) async fn rpki_drop_all(&self, addr: Arc<IpAddr>) {
        self.rpki.write().unwrap().drop_source(addr);
    }

    pub(crate) async fn table_state(&self, family: Family) -> table::TableState {
        let mut state = table::TableState::default();
        for shard in &self.shards {
            state += shard.lock().await.rtable.state(family);
        }
        state
    }

    pub(crate) async fn collect_best_paths(
        &self,
        family: Family,
    ) -> Vec<(packet::Nlri, Vec<table::Path>)> {
        let mut out = Vec::new();
        for shard in &self.shards {
            out.extend(shard.lock().await.rtable.best_paths(&family));
        }
        out
    }

    pub(crate) async fn collect_roa(&self, family: Family) -> Vec<(packet::IpNet, table::Roa)> {
        self.rpki
            .read()
            .unwrap()
            .iter(family)
            .map(|(net, roa)| (net, roa.clone()))
            .collect()
    }

    pub(crate) async fn rpki_state(&self, addr: &IpAddr) -> table::RpkiTableState {
        self.rpki.read().unwrap().state(addr)
    }

    pub(crate) async fn collect_peer_stats(
        &self,
        addrs: &[IpAddr],
    ) -> FnvHashMap<IpAddr, FnvHashMap<Family, table::PrefixStats>> {
        let mut map: FnvHashMap<IpAddr, FnvHashMap<Family, table::PrefixStats>> =
            FnvHashMap::default();
        for shard in &self.shards {
            let t = shard.lock().await;
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

    pub(crate) async fn collect_paths(
        &self,
        query: table::TableQuery,
        family: Family,
        prefixes: Vec<packet::Nlri>,
    ) -> Vec<table::DestinationEntry> {
        let export_policy = if matches!(query, table::TableQuery::AdjOut(_)) {
            self.export_policy.load_full()
        } else {
            None
        };
        // Phase 1: collect from each shard (validation: None); shard lock released after each.
        let mut out = Vec::new();
        for shard in &self.shards {
            let t = shard.lock().await;
            out.extend(t.rtable.destinations(
                query,
                family,
                prefixes.clone(),
                export_policy.clone(),
            ));
        }
        // Phase 2: apply RPKI validation without holding any shard lock.
        let rpki = self.rpki.read().unwrap();
        for dest in &mut out {
            for path in &mut dest.paths {
                path.validation = rpki.validate(family, &path.source, &dest.net, &path.attr);
            }
        }
        out
    }

    /// Subscribe with snapshot: calls `on_change` for each current route (per shard, under lock),
    /// then registers for live AdjRibIn/PeerUp/PeerDown events.
    pub(crate) async fn subscribe_with<F>(&self, mut on_change: F) -> Subscription
    where
        F: FnMut(AdjRibInChange),
    {
        let id = SubscriptionId(
            self.next_sub_id
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        );
        let (tx, rx) = mpsc::unbounded_channel();
        // Register for peer events (PeerUp/PeerDown) first to avoid missing events.
        {
            let mut subs = self.subscribers.lock().await;
            subs.insert(id, tx.clone());
        }
        // Snapshot each shard atomically while registering for live AdjRibIn events.
        for shard in &self.shards {
            let mut t = shard.lock().await;
            for f in t.rtable.families().collect::<Vec<_>>() {
                for reach in t.rtable.iter_reach(f) {
                    let addpath = t.has_addpath(&reach.source.remote_addr, &f);
                    on_change(AdjRibInChange {
                        source: reach.source,
                        family: f,
                        addpath,
                        nlris: vec![reach.net],
                        attrs: Some(reach.attr),
                        nexthop: Some(reach.nexthop),
                    });
                }
            }
            t.subscribers.insert(id, tx.clone());
        }
        Subscription { rx, id }
    }

    /// Subscribe for live events only (no snapshot). Used by watch_event gRPC and MRT.
    pub(crate) async fn subscribe_live(&self) -> Subscription {
        let id = SubscriptionId(
            self.next_sub_id
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        );
        let (tx, rx) = mpsc::unbounded_channel();
        {
            let mut subs = self.subscribers.lock().await;
            subs.insert(id, tx.clone());
        }
        for shard in &self.shards {
            let mut shard = shard.lock().await;
            shard.subscribers.insert(id, tx.clone());
        }
        Subscription { rx, id }
    }

    pub(crate) async fn unsubscribe(&self, id: SubscriptionId) {
        {
            let mut subs = self.subscribers.lock().await;
            subs.remove(&id);
        }
        for shard in &self.shards {
            let mut shard = shard.lock().await;
            shard.subscribers.remove(&id);
        }
    }

    pub(crate) async fn peer_up(&self, data: PeerUpData) {
        let subs = self.subscribers.lock().await;
        for tx in subs.values() {
            let _ = tx.send(BgpEvent::PeerUp(data.clone()));
        }
    }

    pub(crate) async fn peer_down(&self, data: PeerDownData) {
        let subs = self.subscribers.lock().await;
        for tx in subs.values() {
            let _ = tx.send(BgpEvent::PeerDown(data.clone()));
        }
    }

    /// Register a peer's event channel with every shard atomically.
    ///
    /// For each shard, while the lock is held, `on_shard` is called with the
    /// shard's routing table so the caller can populate its initial routes.
    /// The returned receiver delivers `ToPeerEvent` messages from all shards.
    pub(crate) async fn register_peer<F>(
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
            let mut t = shard.lock().await;
            on_shard(&t.rtable);
            t.peer_event_tx.insert(addr, tx.clone());
            if !addpath.is_empty() {
                t.addpath.insert(addr, addpath.clone());
            }
        }
        rx
    }

    pub(crate) async fn unregister_peer(
        &self,
        addr: IpAddr,
        drop_families: &[Family],
        stale_families: &[Family],
    ) {
        let kernel_tx = self.kernel_tx.load_full();
        let export_policy = self.export_policy.load_full();
        for shard in &self.shards {
            let mut t = shard.lock().await;
            t.peer_event_tx.remove(&addr);
            t.addpath.remove(&addr);
            for &family in drop_families {
                t.disconnected(addr, family, kernel_tx.as_deref());
            }
            for &family in stale_families {
                t.mark_stale(addr, family, kernel_tx.as_deref(), export_policy.as_deref());
            }
        }
    }
}

pub(crate) struct TableShard {
    pub(crate) rtable: table::Table,
    pub(crate) peer_event_tx: FnvHashMap<IpAddr, mpsc::UnboundedSender<ToPeerEvent>>,
    pub(crate) subscribers: FnvHashMap<SubscriptionId, mpsc::UnboundedSender<BgpEvent>>,
    pub(crate) addpath: FnvHashMap<IpAddr, FnvHashSet<Family>>,
}

impl TableShard {
    pub(crate) fn has_addpath(&self, addr: &IpAddr, family: &Family) -> bool {
        self.addpath.get(addr).is_some_and(|e| e.contains(family))
    }

    pub(crate) fn disconnected(
        &mut self,
        addr: IpAddr,
        family: Family,
        kernel_tx: Option<&mpsc::UnboundedSender<KernelRouteEvent>>,
    ) {
        for change in self.rtable.drop(addr, family) {
            self.distribute_update(change, kernel_tx, None);
        }
    }

    pub(crate) fn mark_stale(
        &mut self,
        addr: IpAddr,
        family: Family,
        kernel_tx: Option<&mpsc::UnboundedSender<KernelRouteEvent>>,
        export_policy: Option<&table::PolicyAssignment>,
    ) {
        for change in self.rtable.restale(addr, family) {
            self.distribute_update(change, kernel_tx, export_policy);
        }
    }

    pub(crate) fn notify_adj_rib_in(
        &self,
        source: Arc<table::Source>,
        family: Family,
        nets: &[packet::PathNlri],
        attrs: Option<&Arc<Vec<packet::Attribute>>>,
        nexthop: Option<bgp::Nexthop>,
    ) {
        let addpath = self.has_addpath(&source.remote_addr, &family);
        for tx in self.subscribers.values() {
            let _ = tx.send(BgpEvent::AdjRibIn(AdjRibInChange {
                source: source.clone(),
                family,
                addpath,
                nlris: nets.to_owned(),
                attrs: attrs.cloned(),
                nexthop,
            }));
        }
    }

    pub(crate) fn distribute_update(
        &self,
        update: table::NlriChange,
        kernel_tx: Option<&mpsc::UnboundedSender<KernelRouteEvent>>,
        export_policy: Option<&table::PolicyAssignment>,
    ) {
        // Apply export policy to new_best.
        let filtered_new_best: Option<table::Path> = if let Some(best) = update.new_best() {
            let mut nexthop = best.nexthop;
            if export_policy.is_some_and(|policy| {
                table::Table::apply_policy(
                    policy,
                    &best.source,
                    &update.net,
                    &best.attr,
                    &mut nexthop,
                    best.source.local_addr,
                ) == table::Disposition::Reject
            }) {
                None
            } else {
                Some(table::Path {
                    nexthop,
                    ..best.clone()
                })
            }
        } else {
            None
        };

        // Apply export policy to current_paths (for Add-Path peers).
        let filtered_current_paths: Arc<Vec<table::Path>> = if export_policy.is_none() {
            Arc::clone(&update.current_paths)
        } else {
            Arc::new(
                update
                    .current_paths
                    .iter()
                    .filter_map(|p| {
                        let mut nexthop = p.nexthop;
                        if export_policy.is_some_and(|policy| {
                            table::Table::apply_policy(
                                policy,
                                &p.source,
                                &update.net,
                                &p.attr,
                                &mut nexthop,
                                p.source.local_addr,
                            ) == table::Disposition::Reject
                        }) {
                            None
                        } else {
                            Some(table::Path {
                                nexthop,
                                ..p.clone()
                            })
                        }
                    })
                    .collect(),
            )
        };

        let best_changed =
            update.best_changed || update.new_best().is_some() != filtered_new_best.is_some();
        let any_changed =
            update.any_changed || update.current_paths.len() != filtered_current_paths.len();

        let filtered_update = table::NlriChange {
            best_changed,
            any_changed,
            current_paths: filtered_current_paths,
            ..update
        };

        // Kernel route update for rank-1 best.
        if filtered_update.best_changed
            && let Some(tx) = kernel_tx
        {
            let (dst, prefix_len) = match filtered_update.net {
                packet::Nlri::V4(net) => (IpAddr::from(net.addr), net.mask),
                packet::Nlri::V6(net) => (IpAddr::from(net.addr), net.mask),
                packet::Nlri::Mup(_) => {
                    // Send to peers but skip kernel for MUP NLRIs.
                    for tx in self.peer_event_tx.values() {
                        let _ = tx.send(ToPeerEvent::NlriChange(filtered_update.clone()));
                    }
                    return;
                }
            };
            match &filtered_new_best {
                None => {
                    let _ = tx.send(KernelRouteEvent::Withdraw { dst, prefix_len });
                }
                Some(best) => {
                    let nexthop = best.nexthop.addr();
                    if matches!(
                        (dst, nexthop),
                        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
                    ) {
                        let _ = tx.send(KernelRouteEvent::Install {
                            dst,
                            prefix_len,
                            nexthop,
                        });
                    } else {
                        let _ = tx.send(KernelRouteEvent::Withdraw { dst, prefix_len });
                    }
                }
            }
        }

        // Fan out to all peer channels.
        for tx in self.peer_event_tx.values() {
            let _ = tx.send(ToPeerEvent::NlriChange(filtered_update.clone()));
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn pass_update(
        &mut self,
        source: Arc<table::Source>,
        family: Family,
        nets: Vec<packet::PathNlri>,
        attrs: Option<Arc<Vec<packet::Attribute>>>,
        nexthop: Option<bgp::Nexthop>,
        import_policy: Option<&table::PolicyAssignment>,
        kernel_tx: Option<&mpsc::UnboundedSender<KernelRouteEvent>>,
        export_policy: Option<&table::PolicyAssignment>,
    ) {
        self.notify_adj_rib_in(source.clone(), family, &nets, attrs.as_ref(), nexthop);

        match attrs {
            Some(attrs) => {
                // nexthop must be present for reach updates; a missing nexthop
                // is a protocol violation, so silently drop the update.
                let Some(nexthop) = nexthop else { return };
                for net in nets {
                    let mut nh = nexthop;
                    let filtered = crate::policy::apply_import(
                        import_policy,
                        &source,
                        &net.nlri,
                        &attrs,
                        &mut nh,
                    );
                    if let table::InsertResult::Changed(update) = self.rtable.insert(
                        source.clone(),
                        family,
                        net.nlri,
                        net.path_id,
                        nh,
                        attrs.clone(),
                        filtered,
                        None,
                    ) {
                        self.distribute_update(update, kernel_tx, export_policy);
                    }
                }
            }
            None => {
                for net in nets {
                    if let Some(update) =
                        self.rtable
                            .remove(source.clone(), family, net.nlri, net.path_id, None)
                    {
                        self.distribute_update(update, kernel_tx, export_policy);
                    }
                }
            }
        }
    }

    pub(crate) fn drop_stale(
        &mut self,
        addr: IpAddr,
        family: Family,
        kernel_tx: Option<&mpsc::UnboundedSender<KernelRouteEvent>>,
    ) {
        for change in self.rtable.drop_stale(addr, family, None) {
            self.distribute_update(change, kernel_tx, None);
        }
    }

    pub(crate) fn end_deferral(
        &mut self,
        family: Family,
        kernel_tx: Option<&mpsc::UnboundedSender<KernelRouteEvent>>,
        export_policy: Option<&table::PolicyAssignment>,
    ) {
        for change in self.rtable.end_deferral(family) {
            self.distribute_update(change, kernel_tx, export_policy);
        }
    }
}
