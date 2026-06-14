// Copyright (C) 2024 The RustyBGP Authors.
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
// implied.  See the License for the specific language governing
// permissions and limitations under the License.

use fnv::{FnvHashMap, FnvHashSet};
use futures::{SinkExt, StreamExt};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;
use tokio::net::TcpStream;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tokio_util::codec::Framed;
use tokio_util::sync::CancellationToken;

use rustybgp_packet::{self as packet, Family, bgp, bmp};

use crate::event::{AdjRibInChange, BgpEvent, GlobalHandle, TableHandle};

/// Net-state snapshot: (family, nlri) -> single-nlri AdjRibInChange per peer.
type SnapshotMap = FnvHashMap<IpAddr, FnvHashMap<(Family, packet::PathNlri), AdjRibInChange>>;

/// Apply one `AdjRibInChange` to the snapshot net-state.
/// Reach events insert; withdrawal events remove.
fn apply_snapshot(snapshot: &mut SnapshotMap, change: AdjRibInChange) {
    if change.attrs.is_some() {
        let peer_map = snapshot.entry(change.source.remote_addr).or_default();
        for nlri in &change.nlris {
            peer_map.insert(
                (change.family, nlri.clone()),
                AdjRibInChange {
                    source: change.source.clone(),
                    family: change.family,
                    addpath: change.addpath,
                    nlris: vec![nlri.clone()],
                    attrs: change.attrs.clone(),
                    nexthop: change.nexthop,
                    timestamp: change.timestamp,
                },
            );
        }
    } else if let Some(peer_map) = snapshot.get_mut(&change.source.remote_addr) {
        for nlri in &change.nlris {
            peer_map.remove(&(change.family, nlri.clone()));
        }
    }
}

/// Drain all routes for `addr` from the snapshot and return the BMP messages
/// to send: one RouteMonitoring per route, then one EoR RouteMonitoring per
/// family that appeared.  `peer_header` is used for EoR messages (it carries
/// the session uptime).
fn flush_peer_snapshot(
    snapshot: &mut SnapshotMap,
    addr: IpAddr,
    peer_header: &bmp::PerPeerHeader,
) -> Vec<bmp::Message> {
    let mut messages = Vec::new();
    let mut families_seen: FnvHashSet<Family> = FnvHashSet::default();

    if let Some(peer_routes) = snapshot.remove(&addr) {
        for ((family, _), change) in &peer_routes {
            families_seen.insert(*family);
            let attrs = change.attrs.as_ref().unwrap();
            let update = bgp::Message::Update(bgp::Update::Routes {
                reach: Some(packet::bgp::ReachNlri {
                    family: *family,
                    entries: change.nlris.clone(),
                    nexthop: change.nexthop,
                }),
                attr: attrs.clone(),
                unreach: None,
            });
            messages.push(bmp::Message::RouteMonitoring {
                header: bmp::PerPeerHeader::new(
                    change.source.remote_asn,
                    Ipv4Addr::from(change.source.router_id),
                    0,
                    change.source.remote_addr,
                    change
                        .timestamp
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as u32,
                ),
                update,
                addpath: change.addpath,
            });
        }
    }

    for family in families_seen {
        messages.push(bmp::Message::RouteMonitoring {
            header: peer_header.clone(),
            update: bgp::Message::eor(family),
            addpath: false,
        });
    }

    messages
}

/// Convert a live `AdjRibInChange` to the BGP UPDATE used in RouteMonitoring.
fn adj_rib_in_to_bmp_update(change: &AdjRibInChange) -> bgp::Message {
    if let Some(ref attrs) = change.attrs {
        bgp::Message::Update(bgp::Update::Routes {
            reach: Some(packet::bgp::ReachNlri {
                family: change.family,
                entries: change.nlris.clone(),
                nexthop: change.nexthop,
            }),
            attr: attrs.clone(),
            unreach: None,
        })
    } else {
        bgp::Message::Update(bgp::Update::Routes {
            reach: None,
            attr: Arc::new(Vec::new()),
            unreach: Some(packet::bgp::UnreachNlri {
                family: change.family,
                entries: change.nlris.clone(),
            }),
        })
    }
}

/// Records that a PeerUp was sent for `addr`.
fn track_peer_up(sent: &mut FnvHashSet<IpAddr>, addr: IpAddr) {
    sent.insert(addr);
}

/// Returns true if a PeerDown should be forwarded (a PeerUp was sent for `addr`).
/// Removes `addr` from the tracking set so a second PeerDown is suppressed.
fn track_peer_down(sent: &mut FnvHashSet<IpAddr>, addr: IpAddr) -> bool {
    sent.remove(&addr)
}

/// Sends a PeerUp message and records the peer in `sent`.
/// Returns false if the connection is broken.
async fn send_peer_up(
    sent: &mut FnvHashSet<IpAddr>,
    lines: &mut Framed<TcpStream, bmp::BmpCodec>,
    addr: IpAddr,
    msg: &bmp::Message,
) -> bool {
    if lines.send(msg).await.is_err() {
        return false;
    }
    track_peer_up(sent, addr);
    true
}

/// Sends a PeerDown message only if a PeerUp was previously sent for `addr`.
/// Returns false if the connection is broken.
async fn send_peer_down(
    sent: &mut FnvHashSet<IpAddr>,
    lines: &mut Framed<TcpStream, bmp::BmpCodec>,
    addr: IpAddr,
    msg: &bmp::Message,
) -> bool {
    if !track_peer_down(sent, addr) {
        return true;
    }
    lines.send(msg).await.is_ok()
}

/// Convert a `SessionDownReason` to the BMP `PeerDownReason` encoding.
pub(crate) fn session_down_to_bmp(
    reason: Option<crate::fsm::SessionDownReason>,
) -> bmp::PeerDownReason {
    match reason {
        None => bmp::PeerDownReason::RemoteUnexpected,
        Some(crate::fsm::SessionDownReason::HoldTimerExpired) => bmp::PeerDownReason::LocalFsm(0),
        Some(crate::fsm::SessionDownReason::RemoteNotification(msg)) => {
            bmp::PeerDownReason::RemoteNotification(msg)
        }
        Some(crate::fsm::SessionDownReason::LocalNotification(msg)) => {
            bmp::PeerDownReason::LocalNotification(msg)
        }
        Some(crate::fsm::SessionDownReason::FsmError) => bmp::PeerDownReason::LocalFsm(0),
        Some(crate::fsm::SessionDownReason::AdminShutdown) => bmp::PeerDownReason::LocalFsm(0),
        Some(crate::fsm::SessionDownReason::IoError) => bmp::PeerDownReason::RemoteUnexpected,
    }
}

pub(crate) struct BmpClientState {
    pub(crate) uptime: AtomicU64,
    pub(crate) downtime: AtomicU64,
}

impl BmpClientState {
    fn new() -> Arc<Self> {
        Arc::new(BmpClientState {
            uptime: AtomicU64::new(0),
            downtime: AtomicU64::new(0),
        })
    }
}

pub(crate) struct BmpClient {
    pub(crate) cancel: CancellationToken,
    pub(crate) state: Arc<BmpClientState>,
}

impl BmpClient {
    pub(crate) fn new() -> Self {
        BmpClient {
            cancel: CancellationToken::new(),
            state: BmpClientState::new(),
        }
    }

    async fn serve(
        stream: TcpStream,
        cancel: CancellationToken,
        global: GlobalHandle,
        tables: TableHandle,
    ) {
        let mut lines = Framed::new(stream, bmp::BmpCodec::new());
        let sysname = hostname::get().unwrap_or_else(|_| std::ffi::OsString::from("unknown"));
        let _ = lines
            .send(&bmp::Message::Initiation(vec![
                (
                    bmp::Message::INFO_TYPE_SYSDESCR,
                    ascii::AsciiStr::from_ascii(
                        format!(
                            "RustyBGP v{}-{}",
                            env!("CARGO_PKG_VERSION"),
                            env!("GIT_HASH")
                        )
                        .as_str(),
                    )
                    .unwrap()
                    .as_bytes()
                    .to_vec(),
                ),
                (
                    bmp::Message::INFO_TYPE_SYSNAME,
                    ascii::AsciiStr::from_ascii(sysname.to_ascii_lowercase().to_str().unwrap())
                        .unwrap()
                        .as_bytes()
                        .to_vec(),
                ),
            ]))
            .await;

        let mut snapshot: SnapshotMap = FnvHashMap::default();
        let subscription = tables
            .subscribe_with(|change| apply_snapshot(&mut snapshot, change))
            .await;
        let rx = subscription.rx;

        // Send PeerUp for all established peers.
        let local_id = global.read().await.router_id;
        let mut sent_peer_up: FnvHashSet<IpAddr> = FnvHashSet::default();
        let mut established_peers: Vec<(IpAddr, bmp::PerPeerHeader)> = Vec::new();
        for peer in global.read().await.peers.values() {
            if let Some((addr, peer_header, msg)) = peer.bmp_peer_up(local_id) {
                if !send_peer_up(&mut sent_peer_up, &mut lines, addr, &msg).await {
                    tables.unsubscribe(subscription.id).await;
                    return;
                }
                established_peers.push((addr, peer_header));
            }
        }

        // Send RouteMonitoring + EoR for buffered snapshot routes (per established peer).
        for (addr, peer_header) in &established_peers {
            for msg in flush_peer_snapshot(&mut snapshot, *addr, peer_header) {
                if lines.send(&msg).await.is_err() {
                    tables.unsubscribe(subscription.id).await;
                    return;
                }
            }
        }

        // Live event loop.
        let mut rx = UnboundedReceiverStream::new(rx);
        loop {
            tokio::select! {
                msg = lines.next() => {
                    match msg {
                        Some(Ok(_)) => {}
                        _ => break,
                    }
                }
                event = rx.next() => {
                    match event {
                        Some(BgpEvent::AdjRibIn(change)) => {
                            let update = adj_rib_in_to_bmp_update(&change);
                            if lines
                                .send(&bmp::Message::RouteMonitoring {
                                    header: bmp::PerPeerHeader::new(
                                        change.source.remote_asn,
                                        Ipv4Addr::from(change.source.router_id),
                                        0,
                                        change.source.remote_addr,
                                        change.timestamp
                                            .duration_since(SystemTime::UNIX_EPOCH)
                                            .unwrap_or_default()
                                            .as_secs() as u32,
                                    ),
                                    update,
                                    addpath: change.addpath,
                                })
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        Some(BgpEvent::PeerUp(data)) => {
                            let remote_id = Ipv4Addr::from(data.peer_id);
                            let m = bmp::Message::PeerUp {
                                header: bmp::PerPeerHeader::new(
                                    data.peer_asn,
                                    remote_id,
                                    0,
                                    data.peer_addr,
                                    data.uptime as u32,
                                ),
                                local_addr: data.local_addr,
                                local_port: data.local_port,
                                remote_port: data.remote_port,
                                remote_open: data.received_open,
                                local_open: data.sent_open,
                            };
                            if !send_peer_up(&mut sent_peer_up, &mut lines, data.peer_addr, &m)
                                .await
                            {
                                break;
                            }
                        }
                        Some(BgpEvent::PeerDown(data)) => {
                            let m = bmp::Message::PeerDown {
                                header: bmp::PerPeerHeader::new(
                                    data.peer_asn,
                                    Ipv4Addr::from(data.peer_id),
                                    0,
                                    data.peer_addr,
                                    data.uptime as u32,
                                ),
                                reason: data.reason,
                            };
                            if !send_peer_down(&mut sent_peer_up, &mut lines, data.peer_addr, &m)
                                .await
                            {
                                break;
                            }
                        }
                        None => break,
                    }
                }
                _ = cancel.cancelled() => break,
            }
        }
        tables.unsubscribe(subscription.id).await;
    }

    pub(crate) fn try_connect(
        sockaddr: SocketAddr,
        cancel: CancellationToken,
        state: Arc<BmpClientState>,
        global: GlobalHandle,
        tables: TableHandle,
    ) {
        tokio::spawn(async move {
            loop {
                let stream = tokio::select! {
                    r = tokio::time::timeout(
                        tokio::time::Duration::from_secs(5),
                        TcpStream::connect(sockaddr),
                    ) => match r {
                        Ok(Ok(s)) => s,
                        _ => {
                            tokio::select! {
                                _ = tokio::time::sleep(tokio::time::Duration::from_secs(10)) => {}
                                _ = cancel.cancelled() => return,
                            }
                            continue;
                        }
                    },
                    _ = cancel.cancelled() => return,
                };

                state.uptime.store(
                    SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                    Ordering::Relaxed,
                );

                tokio::select! {
                    _ = BmpClient::serve(stream, cancel.clone(), global.clone(), tables.clone()) => {}
                    _ = cancel.cancelled() => return,
                }

                state.downtime.store(
                    SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                    Ordering::Relaxed,
                );

                tokio::select! {
                    _ = tokio::time::sleep(tokio::time::Duration::from_secs(10)) => {}
                    _ = cancel.cancelled() => return,
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustybgp_packet::{Family, bgp, bmp};
    use rustybgp_table as table;
    use std::net::IpAddr;
    use std::sync::Arc;

    fn make_source(addr: &str) -> Arc<table::Source> {
        Arc::new(table::Source::new(
            addr.parse().unwrap(),
            "192.0.2.1".parse().unwrap(),
            65000,
            65001,
            "192.0.2.1".parse().unwrap(),
            false,
            false,
        ))
    }

    fn make_nlri(prefix: &str) -> packet::PathNlri {
        let nlri: packet::Nlri = prefix.parse().unwrap();
        packet::PathNlri { path_id: 0, nlri }
    }

    fn reach_change(
        source: Arc<table::Source>,
        family: Family,
        nlris: Vec<packet::PathNlri>,
    ) -> AdjRibInChange {
        AdjRibInChange {
            source,
            family,
            addpath: false,
            nlris,
            attrs: Some(Arc::new(Vec::new())),
            nexthop: None,
            timestamp: SystemTime::UNIX_EPOCH,
        }
    }

    fn withdrawal_change(
        source: Arc<table::Source>,
        family: Family,
        nlris: Vec<packet::PathNlri>,
    ) -> AdjRibInChange {
        AdjRibInChange {
            source,
            family,
            addpath: false,
            nlris,
            attrs: None,
            nexthop: None,
            timestamp: SystemTime::UNIX_EPOCH,
        }
    }

    fn dummy_header(addr: &str) -> bmp::PerPeerHeader {
        bmp::PerPeerHeader::new(
            65000,
            "192.0.2.1".parse().unwrap(),
            0,
            addr.parse().unwrap(),
            0,
        )
    }

    // ---- apply_snapshot ----

    #[test]
    fn apply_snapshot_reach_inserts() {
        let source = make_source("10.0.0.1");
        let nlri = make_nlri("192.168.0.0/24");
        let mut snapshot = SnapshotMap::default();

        apply_snapshot(
            &mut snapshot,
            reach_change(source.clone(), Family::IPV4, vec![nlri.clone()]),
        );

        let peer_map = snapshot.get(&source.remote_addr).unwrap();
        assert_eq!(peer_map.len(), 1);
        assert!(peer_map.contains_key(&(Family::IPV4, nlri)));
    }

    #[test]
    fn apply_snapshot_withdrawal_removes() {
        let source = make_source("10.0.0.1");
        let nlri = make_nlri("192.168.0.0/24");
        let mut snapshot = SnapshotMap::default();

        apply_snapshot(
            &mut snapshot,
            reach_change(source.clone(), Family::IPV4, vec![nlri.clone()]),
        );
        apply_snapshot(
            &mut snapshot,
            withdrawal_change(source.clone(), Family::IPV4, vec![nlri]),
        );

        let peer_map = snapshot.get(&source.remote_addr).unwrap();
        assert!(peer_map.is_empty());
    }

    #[test]
    fn apply_snapshot_withdrawal_of_unknown_is_noop() {
        let source = make_source("10.0.0.1");
        let nlri = make_nlri("192.168.0.0/24");
        let mut snapshot = SnapshotMap::default();

        apply_snapshot(
            &mut snapshot,
            withdrawal_change(source.clone(), Family::IPV4, vec![nlri]),
        );

        assert!(snapshot.is_empty());
    }

    #[test]
    fn apply_snapshot_reach_then_withdrawal_net_state_empty() {
        let source = make_source("10.0.0.1");
        let n1 = make_nlri("10.0.0.0/8");
        let n2 = make_nlri("172.16.0.0/12");
        let mut snapshot = SnapshotMap::default();

        apply_snapshot(
            &mut snapshot,
            reach_change(source.clone(), Family::IPV4, vec![n1.clone(), n2.clone()]),
        );
        apply_snapshot(
            &mut snapshot,
            withdrawal_change(source.clone(), Family::IPV4, vec![n1, n2]),
        );

        let peer_map = snapshot.get(&source.remote_addr).unwrap();
        assert!(peer_map.is_empty());
    }

    // ---- flush_peer_snapshot ----

    #[test]
    fn flush_peer_snapshot_empty_peer_returns_no_messages() {
        let mut snapshot = SnapshotMap::default();
        let header = dummy_header("10.0.0.1");
        let msgs = flush_peer_snapshot(&mut snapshot, "10.0.0.1".parse().unwrap(), &header);
        assert!(msgs.is_empty());
    }

    #[test]
    fn flush_peer_snapshot_reach_produces_route_monitoring_and_eor() {
        let source = make_source("10.0.0.1");
        let nlri = make_nlri("192.168.0.0/24");
        let mut snapshot = SnapshotMap::default();
        apply_snapshot(
            &mut snapshot,
            reach_change(source.clone(), Family::IPV4, vec![nlri]),
        );

        let header = dummy_header("10.0.0.1");
        let msgs = flush_peer_snapshot(&mut snapshot, source.remote_addr, &header);

        // 1 RouteMonitoring + 1 EoR for IPV4
        assert_eq!(msgs.len(), 2);
        assert!(matches!(msgs[0], bmp::Message::RouteMonitoring { .. }));
        assert!(matches!(msgs[1], bmp::Message::RouteMonitoring { .. }));
        // snapshot is consumed
        assert!(snapshot.is_empty());
    }

    #[test]
    fn flush_peer_snapshot_eor_per_family() {
        let source = make_source("10.0.0.1");
        let v4_nlri = make_nlri("192.168.0.0/24");
        let v6_nlri = make_nlri("2001:db8::/32");
        let mut snapshot = SnapshotMap::default();
        apply_snapshot(
            &mut snapshot,
            reach_change(source.clone(), Family::IPV4, vec![v4_nlri]),
        );
        apply_snapshot(
            &mut snapshot,
            reach_change(source.clone(), Family::IPV6, vec![v6_nlri]),
        );

        let header = dummy_header("10.0.0.1");
        let msgs = flush_peer_snapshot(&mut snapshot, source.remote_addr, &header);

        // 2 RouteMonitoring + 2 EoR (one per family)
        assert_eq!(msgs.len(), 4);
    }

    // ---- track_peer_up / track_peer_down (Race 2 guard) ----

    #[test]
    fn peer_down_without_prior_peer_up_is_suppressed() {
        let mut sent: FnvHashSet<IpAddr> = FnvHashSet::default();
        let addr: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(!track_peer_down(&mut sent, addr));
        assert!(sent.is_empty());
    }

    #[test]
    fn peer_up_enables_peer_down() {
        let mut sent: FnvHashSet<IpAddr> = FnvHashSet::default();
        let addr: IpAddr = "10.0.0.1".parse().unwrap();
        track_peer_up(&mut sent, addr);
        assert!(track_peer_down(&mut sent, addr));
        assert!(sent.is_empty());
    }

    #[test]
    fn second_peer_down_after_first_is_suppressed() {
        let mut sent: FnvHashSet<IpAddr> = FnvHashSet::default();
        let addr: IpAddr = "10.0.0.1".parse().unwrap();
        track_peer_up(&mut sent, addr);
        assert!(track_peer_down(&mut sent, addr));
        assert!(!track_peer_down(&mut sent, addr));
    }

    #[test]
    fn peer_reconnect_restores_peer_down_forwarding() {
        let mut sent: FnvHashSet<IpAddr> = FnvHashSet::default();
        let addr: IpAddr = "10.0.0.1".parse().unwrap();
        track_peer_up(&mut sent, addr);
        assert!(track_peer_down(&mut sent, addr));
        track_peer_up(&mut sent, addr);
        assert!(track_peer_down(&mut sent, addr));
    }

    #[test]
    fn peer_down_tracking_is_per_peer() {
        let mut sent: FnvHashSet<IpAddr> = FnvHashSet::default();
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        track_peer_up(&mut sent, a);
        assert!(!track_peer_down(&mut sent, b));
        assert!(track_peer_down(&mut sent, a));
    }

    // ---- session_down_to_bmp ----

    #[test]
    fn session_down_to_bmp_none_is_remote_unexpected() {
        assert!(matches!(
            session_down_to_bmp(None),
            bmp::PeerDownReason::RemoteUnexpected
        ));
    }

    #[test]
    fn session_down_to_bmp_io_error_is_remote_unexpected() {
        assert!(matches!(
            session_down_to_bmp(Some(crate::fsm::SessionDownReason::IoError)),
            bmp::PeerDownReason::RemoteUnexpected
        ));
    }

    #[test]
    fn session_down_to_bmp_hold_timer_is_local_fsm() {
        assert!(matches!(
            session_down_to_bmp(Some(crate::fsm::SessionDownReason::HoldTimerExpired)),
            bmp::PeerDownReason::LocalFsm(0)
        ));
    }

    #[test]
    fn session_down_to_bmp_admin_shutdown_is_local_fsm() {
        assert!(matches!(
            session_down_to_bmp(Some(crate::fsm::SessionDownReason::AdminShutdown)),
            bmp::PeerDownReason::LocalFsm(0)
        ));
    }

    #[test]
    fn session_down_to_bmp_remote_notification_preserved() {
        let msg = bgp::Message::Notification(rustybgp_packet::error::Notification::Other {
            code: 6,
            subcode: 0,
            data: vec![],
        });
        assert!(matches!(
            session_down_to_bmp(Some(crate::fsm::SessionDownReason::RemoteNotification(msg))),
            bmp::PeerDownReason::RemoteNotification(_)
        ));
    }

    #[test]
    fn session_down_to_bmp_local_notification_preserved() {
        let msg = bgp::Message::Notification(rustybgp_packet::error::Notification::Other {
            code: 6,
            subcode: 0,
            data: vec![],
        });
        assert!(matches!(
            session_down_to_bmp(Some(crate::fsm::SessionDownReason::LocalNotification(msg))),
            bmp::PeerDownReason::LocalNotification(_)
        ));
    }
}
