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
    pub(crate) kernel_tx: ArcSwapOption<mpsc::UnboundedSender<kernel::KernelRouteChange>>,
    pub(crate) import_policy: ArcSwapOption<table::PolicyAssignment>,
    pub(crate) export_policy: ArcSwapOption<table::PolicyAssignment>,
    next_sub_id: std::sync::atomic::AtomicU64,
    subscribers: Mutex<FnvHashMap<SubscriptionId, mpsc::UnboundedSender<BgpEvent>>>,
    vrfs: Mutex<FnvHashMap<String, table::Vrf>>,
    next_label: std::sync::atomic::AtomicU32,
}

impl TableManager {
    /// First available MPLS label (0-15 are reserved per RFC 3032).
    const LABEL_BASE: u32 = 16;

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
            vrfs: Mutex::new(FnvHashMap::default()),
            next_label: std::sync::atomic::AtomicU32::new(Self::LABEL_BASE),
        }
    }

    fn allocate_label(&self) -> packet::mpls::MplsLabel {
        packet::mpls::MplsLabel::new(
            self.next_label
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        )
    }

    pub(crate) async fn add_vrf(
        &self,
        name: String,
        rd: packet::rd::RouteDistinguisher,
        import_rt: std::collections::HashSet<[u8; 8]>,
        export_rt: Vec<[u8; 8]>,
    ) -> Result<packet::mpls::MplsLabel, table::TableError> {
        let mut vrfs = self.vrfs.lock().await;
        if vrfs.contains_key(&name) {
            return Err(table::TableError::AlreadyExists(name));
        }
        let label = self.allocate_label();
        vrfs.insert(
            name.clone(),
            table::Vrf {
                name,
                rd,
                import_rt,
                export_rt,
                label,
            },
        );
        Ok(label)
    }

    pub(crate) async fn delete_vrf(&self, name: &str) -> Result<(), table::TableError> {
        let mut vrfs = self.vrfs.lock().await;
        vrfs.remove(name).ok_or(table::TableError::NotFound)?;
        Ok(())
    }

    pub(crate) async fn list_vrfs(&self, name: Option<&str>) -> Vec<table::Vrf> {
        let vrfs = self.vrfs.lock().await;
        match name {
            Some(n) => vrfs.get(n).cloned().into_iter().collect(),
            None => vrfs.values().cloned().collect(),
        }
    }

    /// Collect paths from the global VPN table that can be imported into `vrf`.
    /// Returns destinations with the VPN wrapper stripped (plain V4/V6 NLRI).
    pub(crate) async fn collect_vrf_paths(
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
        let vrf = self.vrfs.lock().await.get(vrf_name)?.clone();
        let mut out = Vec::new();
        for shard in &self.shards {
            let t = shard.lock().await;
            for mut dest in t.rtable.destinations(
                table::TableQuery::Global,
                vpn_family,
                prefixes.clone(),
                None,
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
    pub(crate) async fn insert_route(
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
        let kernel_tx = self.kernel_tx.load_full();
        let idx = self.dealer(&net.nlri);
        let mut t = self.shards[idx].lock().await;
        t.notify_adj_rib_in(
            source.clone(),
            family,
            std::slice::from_ref(&net),
            Some(&attr),
            nexthop,
            timestamp,
        );
        let mut nh = nexthop;
        let original_attr = Arc::clone(&attr);
        let (filtered, post_policy_attr) = crate::policy::apply_import(
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
            post_policy_attr,
            Some(original_attr),
            filtered,
            pl,
            timestamp,
        ) {
            table::InsertResult::PrefixLimitExceeded => return true,
            table::InsertResult::Changed(update) => {
                t.distribute_update(update, kernel_tx.as_deref());
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
        timestamp: std::time::SystemTime,
    ) {
        let kernel_tx = self.kernel_tx.load_full();
        let idx = self.dealer(&net.nlri);
        let mut t = self.shards[idx].lock().await;
        t.notify_adj_rib_in(
            source.clone(),
            family,
            std::slice::from_ref(&net),
            None,
            None,
            timestamp,
        );
        let counter_ref = prefix_counter.as_ref();
        if let Some(update) = t
            .rtable
            .remove(source, family, net.nlri, net.path_id, counter_ref)
        {
            t.distribute_update(update, kernel_tx.as_deref());
        }
    }

    /// Re-applies the current import policy to all non-stale paths from `peer`
    /// across every shard and distributes any routing changes to peers.
    pub(crate) async fn soft_reset_in(&self, peer: IpAddr) {
        let import_policy = self.import_policy.load_full();
        let kernel_tx = self.kernel_tx.load_full();
        for shard in &self.shards {
            let mut t = shard.lock().await;
            t.soft_reset_in(peer, import_policy.as_deref(), kernel_tx.as_deref());
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
    pub(crate) async fn soft_reset_out(&self, peer: IpAddr) {
        // All shards register the same sender for each peer; shard 0 suffices
        // for the lookup.
        let tx = self.shards[0]
            .lock()
            .await
            .peer_event_tx
            .get(&peer)
            .cloned();
        if let Some(tx) = tx {
            let _ = tx.send(ToPeerEvent::SoftResetOut);
        }
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
        for shard in &self.shards {
            let mut t = shard.lock().await;
            for &family in families {
                t.end_deferral(family, kernel_tx.as_deref());
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

    pub(crate) async fn rpki_withdraw(&self, roas: Vec<(packet::IpNet, Arc<table::Roa>)>) {
        let mut rpki = self.rpki.write().unwrap();
        for (net, roa) in roas {
            rpki.remove(net, &roa);
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

    pub(crate) async fn collect_loc_rib_paths(&self, family: Family) -> Vec<table::NlriChange> {
        let mut out = Vec::new();
        for shard in &self.shards {
            out.extend(shard.lock().await.rtable.collect_loc_rib_paths(&family));
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
        prefixes: Vec<table::PrefixFilter>,
        enable_filtered: bool,
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
                enable_filtered,
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
                        nexthop: reach.nexthop,
                        timestamp: reach.timestamp,
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
        for shard in &self.shards {
            let mut t = shard.lock().await;
            t.peer_event_tx.remove(&addr);
            t.addpath.remove(&addr);
            for &family in drop_families {
                t.disconnected(addr, family, kernel_tx.as_deref());
            }
            for &family in stale_families {
                t.mark_stale(addr, family, kernel_tx.as_deref());
            }
        }
    }

    /// Inject a kernel-redistributed route into the BGP RIB.
    pub(crate) async fn inject_kernel_route(&self, kr: kernel::KernelRoute) {
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
        )
        .await;
    }

    /// Withdraw a kernel-redistributed route from the BGP RIB.
    pub(crate) async fn withdraw_kernel_route(&self, dst: std::net::IpAddr, prefix_len: u8) {
        let nlri = ip_to_nlri(dst, prefix_len);
        let family = nlri_family(&nlri);
        self.remove_route(
            table::Source::kernel(),
            family,
            packet::PathNlri { nlri, path_id: 0 },
            None,
            std::time::SystemTime::now(),
        )
        .await;
    }
}

/// Convert a `KernelRoute` to the components needed by `insert_route`.
///
/// Returns `None` when the route has no usable nexthop or the family cannot
/// be determined (e.g. MUP/VPN NLRIs).
pub(crate) fn kernel_route_to_path(
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

/// Consume a stream of `kernel::KernelRouteEvent`s and inject/withdraw routes into
/// the BGP RIB.
///
/// `redistribute` is the list of `kernel::Protocol` values to accept; events
/// from other protocols are silently dropped.  Pass an empty list to accept all
/// protocols.
///
/// Accepts any `Stream<Item = kernel::KernelRouteEvent>` so callers can substitute a
/// mock channel in tests.
pub(crate) async fn run_kernel_routes(
    tables: Arc<TableManager>,
    mut rx: impl futures::Stream<Item = kernel::KernelRouteEvent> + Unpin + Send,
    redistribute: Vec<kernel::Protocol>,
) {
    use futures::StreamExt;
    while let Some(event) = rx.next().await {
        match event {
            kernel::KernelRouteEvent::Add(kr) => {
                if !redistribute.is_empty() && !redistribute.contains(&kr.protocol) {
                    continue;
                }
                tables.inject_kernel_route(kr).await;
            }
            kernel::KernelRouteEvent::Delete(kr) => {
                if !redistribute.is_empty() && !redistribute.contains(&kr.protocol) {
                    continue;
                }
                tables.withdraw_kernel_route(kr.dst, kr.prefix_len).await;
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
        kernel_tx: Option<&mpsc::UnboundedSender<kernel::KernelRouteChange>>,
    ) {
        for change in self.rtable.drop(addr, family) {
            self.distribute_update(change, kernel_tx);
        }
    }

    pub(crate) fn mark_stale(
        &mut self,
        addr: IpAddr,
        family: Family,
        kernel_tx: Option<&mpsc::UnboundedSender<kernel::KernelRouteChange>>,
    ) {
        for change in self.rtable.restale(addr, family) {
            self.distribute_update(change, kernel_tx);
        }
    }

    pub(crate) fn notify_adj_rib_in(
        &self,
        source: Arc<table::Source>,
        family: Family,
        nets: &[packet::PathNlri],
        attrs: Option<&Arc<Vec<packet::Attribute>>>,
        nexthop: Option<bgp::Nexthop>,
        timestamp: std::time::SystemTime,
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
                timestamp,
            }));
        }
    }

    fn distribute_update(
        &self,
        update: table::NlriChange,
        kernel_tx: Option<&mpsc::UnboundedSender<kernel::KernelRouteChange>>,
    ) {
        // Kernel route update for rank-1 best (raw, without export policy).
        // kernel_tx is rarely set, so check it first.
        if let Some(tx) = kernel_tx
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
            let _ = tx.send(kernel::KernelRouteChange {
                net: update.net.clone(),
                nexthops,
            });
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
    pub(crate) fn soft_reset_in(
        &mut self,
        peer: std::net::IpAddr,
        import_policy: Option<&table::PolicyAssignment>,
        kernel_tx: Option<&mpsc::UnboundedSender<kernel::KernelRouteChange>>,
    ) {
        let paths = self.rtable.collect_adj_in_paths(peer);
        for (family, net, remote_path_id, mut nh, source, original_attr, timestamp) in paths {
            let (filtered, post_policy_attr) =
                crate::policy::apply_import(import_policy, &source, &net, &original_attr, &mut nh);
            if let table::InsertResult::Changed(update) = self.rtable.insert(
                source,
                family,
                net,
                remote_path_id,
                nh,
                post_policy_attr,
                Some(original_attr),
                filtered,
                None,
                timestamp,
            ) {
                self.distribute_update(update, kernel_tx);
            }
        }
    }

    pub(crate) fn drop_stale(
        &mut self,
        addr: IpAddr,
        family: Family,
        kernel_tx: Option<&mpsc::UnboundedSender<kernel::KernelRouteChange>>,
    ) {
        for change in self.rtable.drop_stale(addr, family, None) {
            self.distribute_update(change, kernel_tx);
        }
    }

    pub(crate) fn end_deferral(
        &mut self,
        family: Family,
        kernel_tx: Option<&mpsc::UnboundedSender<kernel::KernelRouteChange>>,
    ) {
        for change in self.rtable.end_deferral(family) {
            self.distribute_update(change, kernel_tx);
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

    // --- run_kernel_routes integration tests (mock stream, no Netlink) ---

    fn make_tables() -> Arc<TableManager> {
        Arc::new(TableManager::new(1))
    }

    #[tokio::test]
    async fn run_kernel_routes_injects_static_route() {
        use futures::stream;
        let tables = make_tables();
        let kr = kr_v4("10.0.0.0", 24, "192.168.1.1", 0, kernel::Protocol::Static);
        let events = stream::iter(vec![kernel::KernelRouteEvent::Add(kr)]);
        run_kernel_routes(tables.clone(), events, vec![]).await;
        let paths = tables
            .collect_paths(
                rustybgp_table::TableQuery::Global,
                Family::IPV4,
                vec![],
                false,
            )
            .await;
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].paths[0].source.is_kernel(), true);
    }

    #[tokio::test]
    async fn run_kernel_routes_withdraw_removes_route() {
        use futures::stream;
        let tables = make_tables();
        let kr = kr_v4("10.0.0.0", 24, "192.168.1.1", 0, kernel::Protocol::Static);
        let add = kernel::KernelRouteEvent::Add(kr.clone());
        let del = kernel::KernelRouteEvent::Delete(kr);
        let events = stream::iter(vec![add, del]);
        run_kernel_routes(tables.clone(), events, vec![]).await;
        let paths = tables
            .collect_paths(
                rustybgp_table::TableQuery::Global,
                Family::IPV4,
                vec![],
                false,
            )
            .await;
        assert_eq!(paths.len(), 0);
    }

    #[tokio::test]
    async fn run_kernel_routes_protocol_filter() {
        use futures::stream;
        let tables = make_tables();
        // Add a Kernel (connected) route and a Static route.
        let connected = kr_v4("10.1.0.0", 24, "192.168.1.1", 0, kernel::Protocol::Kernel);
        let statik = kr_v4("10.2.0.0", 24, "192.168.1.1", 0, kernel::Protocol::Static);
        let events = stream::iter(vec![
            kernel::KernelRouteEvent::Add(connected),
            kernel::KernelRouteEvent::Add(statik),
        ]);
        // Only accept Static; Kernel/connected must be filtered out.
        run_kernel_routes(tables.clone(), events, vec![kernel::Protocol::Static]).await;
        let paths = tables
            .collect_paths(
                rustybgp_table::TableQuery::Global,
                Family::IPV4,
                vec![],
                false,
            )
            .await;
        assert_eq!(paths.len(), 1);
        let dst = match &paths[0].net {
            packet::Nlri::V4(n) => n.addr,
            _ => panic!("expected V4"),
        };
        assert_eq!(dst, Ipv4Addr::new(10, 2, 0, 0));
    }
}
