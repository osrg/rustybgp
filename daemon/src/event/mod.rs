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

use arc_swap::ArcSwapOption;
use fnv::{FnvHashMap, FnvHashSet};
use futures::stream::FuturesUnordered;
use futures::{FutureExt, Stream, StreamExt};
use std::boxed::Box;
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::convert::{From, TryFrom};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::Deref;
use std::os::fd::AsFd;
use std::os::unix::io::{AsRawFd, RawFd};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU16, AtomicU32, AtomicU64, Ordering};
use std::time::SystemTime;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, mpsc};
use tokio::time::Duration;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tokio_util::sync::CancellationToken;

use crate::api::go_bgp_service_server::{GoBgpService, GoBgpServiceServer};

use rustybgp_packet::{self as packet, Family, HoldTime, bgp, bmp};

use crate::api;
use crate::auth;
use crate::bmp::BmpClient;
use crate::config;
use crate::convert;
use crate::error::Error;
use crate::rpki::{RpkiClient, RpkiState};
use rustybgp_kernel as kernel;
use rustybgp_table as table;

#[derive(Default)]
pub(super) struct MessageCounter {
    open: AtomicU64,
    update: AtomicU64,
    notification: AtomicU64,
    keepalive: AtomicU64,
    refresh: AtomicU64,
    discarded: AtomicU64,
    total: AtomicU64,
    withdraw_update: AtomicU64,
    withdraw_prefix: AtomicU64,
}

impl From<&MessageCounter> for api::Message {
    fn from(m: &MessageCounter) -> Self {
        api::Message {
            open: m.open.load(Ordering::Relaxed),
            update: m.update.load(Ordering::Relaxed),
            notification: m.notification.load(Ordering::Relaxed),
            keepalive: m.keepalive.load(Ordering::Relaxed),
            refresh: m.refresh.load(Ordering::Relaxed),
            discarded: m.discarded.load(Ordering::Relaxed),
            total: m.total.load(Ordering::Relaxed),
            withdraw_update: m.withdraw_update.load(Ordering::Relaxed),
            withdraw_prefix: m.withdraw_prefix.load(Ordering::Relaxed),
        }
    }
}

impl MessageCounter {
    // Count one received wire frame (called before validate_message splits it).
    fn sync_rx(&self, msg: &bgp::ParsedMessage) -> bool {
        let mut ret = false;
        match msg {
            bgp::ParsedMessage::Open(_) => {
                let _ = self.open.fetch_add(1, Ordering::Relaxed);
            }
            bgp::ParsedMessage::Update(bgp::ParsedUpdate::Routes {
                unreach,
                mp_unreach,
                ..
            }) => {
                self.update.fetch_add(1, Ordering::Relaxed);
                let unreach_count = unreach.as_ref().map_or(0, |s| s.entries.len())
                    + mp_unreach.as_ref().map_or(0, |s| s.entries.len());
                if unreach_count > 0 {
                    self.withdraw_update.fetch_add(1, Ordering::Relaxed);
                    self.withdraw_prefix
                        .fetch_add(unreach_count as u64, Ordering::Relaxed);
                }
            }
            bgp::ParsedMessage::Update(bgp::ParsedUpdate::EndOfRib(_)) => {
                self.update.fetch_add(1, Ordering::Relaxed);
            }
            bgp::ParsedMessage::Notification(_) => {
                ret = true;
                let _ = self.notification.fetch_add(1, Ordering::Relaxed);
            }
            bgp::ParsedMessage::Keepalive => {
                let _ = self.keepalive.fetch_add(1, Ordering::Relaxed);
            }
            bgp::ParsedMessage::RouteRefresh { .. } => {
                let _ = self.refresh.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.total.fetch_add(1, Ordering::Relaxed);
        ret
    }

    // Count wire_count encoded wire frames for a transmitted message.
    fn sync_tx(&self, msg: &bgp::Message, wire_count: usize) {
        match msg {
            bgp::Message::Update(bgp::Update::Unreach { entries, .. }) => {
                self.update.fetch_add(wire_count as u64, Ordering::Relaxed);
                self.withdraw_update
                    .fetch_add(wire_count as u64, Ordering::Relaxed);
                self.withdraw_prefix
                    .fetch_add(entries.len() as u64, Ordering::Relaxed);
            }
            bgp::Message::Update(_) => {
                self.update.fetch_add(wire_count as u64, Ordering::Relaxed);
            }
            bgp::Message::Open(_) => {
                let _ = self.open.fetch_add(1, Ordering::Relaxed);
            }
            bgp::Message::Notification(_) => {
                let _ = self.notification.fetch_add(1, Ordering::Relaxed);
            }
            bgp::Message::Keepalive => {
                let _ = self.keepalive.fetch_add(1, Ordering::Relaxed);
            }
            bgp::Message::RouteRefresh { .. } => {
                let _ = self.refresh.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.total.fetch_add(wire_count as u64, Ordering::Relaxed);
    }
}

mod grpc;
use grpc::GrpcService;

mod peer;
pub(super) use peer::{
    DynamicPeer, GrPeerConfig, PeerConfig, PeerGroup, PeerParams, RouteReflectorConfig,
};

use crate::fsm::State as SessionState;

/// Session-scoped counters and FSM state shared between `Peer` and the active
/// `PeerSession` via `Arc`.  All fields are atomics so they can be updated by
/// the session task without taking the global lock.  Reset at the start of each
/// new BGP session; the `Arc` itself lives as long as either side holds a clone.
pub(super) struct SessionAddrs {
    local: SocketAddr,
    remote_port: u16,
}

pub(super) struct PeerState {
    fsm: AtomicU8,
    peer_up_at: AtomicU64,
    peer_down_at: AtomicU64,
    remote_asn: AtomicU32,
    remote_id: AtomicU32,
    remote_holdtime: AtomicU16,
    remote_cap: ArcSwapOption<Vec<packet::Capability>>,
    session_addrs: ArcSwapOption<SessionAddrs>,
}

/// Per-peer FSM coordinator.  Created once when `local_router_id` is known
/// (inside `Global::add_peer`) and lives for the entire peer lifetime.
///
/// Bundles `PeerFsm` with the one-shot CEASE channels for both roles under a
/// single `std::sync::Mutex` so that collision detection and CEASE delivery to
/// the losing connection are atomic without touching the global `RwLock`.
pub(super) struct ConnArbiter {
    fsm: crate::fsm::PeerFsm,
    active_close_tx: Option<tokio::sync::oneshot::Sender<CloseReason>>,
    passive_close_tx: Option<tokio::sync::oneshot::Sender<CloseReason>>,
    active_join_handle: Option<tokio::task::JoinHandle<()>>,
    passive_join_handle: Option<tokio::task::JoinHandle<()>>,
}

/// Signal sent to a running connection to request shutdown.
#[derive(Clone)]
pub(super) enum CloseReason {
    /// Admin shutdown (disable_peer / shutdown_peer): the FSM handles CEASE generation.
    AdminShutdown,
    /// Direct CEASE delivery (collision resolution / delete_peer): send the given message.
    SendMessage(bgp::Message),
    /// Close the TCP connection without sending any BGP message (used for
    /// Graceful Restart: the remote peer detects the silent close and enters
    /// helper mode).
    Silent,
}

impl ConnArbiter {
    fn new(fsm: crate::fsm::PeerFsm) -> Self {
        ConnArbiter {
            fsm,
            active_close_tx: None,
            passive_close_tx: None,
            active_join_handle: None,
            passive_join_handle: None,
        }
    }

    /// Process an FSM input for the given role.
    ///
    /// Collision CEASE outputs (SendMessage to the other role) are delivered
    /// directly via the stored close_tx and are not returned to the caller.
    /// CloseConnection outputs for the other role are also dropped; the losing
    /// connection handles its own shutdown when it receives the CEASE.
    fn process(
        &mut self,
        role: crate::fsm::Role,
        input: crate::fsm::Input,
    ) -> Vec<crate::fsm::PeerFsmOutput> {
        let outputs = self.fsm.process(role, input);
        let mut result = Vec::new();
        for output in outputs {
            match output {
                crate::fsm::PeerFsmOutput::Connection(
                    out_role,
                    crate::fsm::Output::SendMessage(msg),
                ) if out_role != role => {
                    let tx = match out_role {
                        crate::fsm::Role::Active => self.active_close_tx.take(),
                        crate::fsm::Role::Passive => self.passive_close_tx.take(),
                    };
                    if let Some(tx) = tx {
                        let _ = tx.send(CloseReason::SendMessage(msg));
                    }
                }
                other => result.push(other),
            }
        }
        result
    }

    fn state(&self, role: crate::fsm::Role) -> crate::fsm::State {
        self.fsm.state(role)
    }

    fn connection(&self, role: crate::fsm::Role) -> Option<&crate::fsm::Connection> {
        self.fsm.connection(role)
    }
}

/// Return the effective send-max for `family` from the live session.
///
/// Connection::send_max is trimmed to negotiated families during OPEN, so
/// this naturally returns 1 for families where Add-Path TX was not negotiated.
///
/// `role = Some(r)` is the fast path used by `PeerSession` (which already
/// knows its own role).  `role = None` searches both Active and Passive slots
/// for a connection that has reached Established, so the caller does not need
/// to know the role.  Returns 1 if no Established connection exists.
fn conn_effective_max(arb: &ConnArbiter, role: Option<crate::fsm::Role>, family: Family) -> usize {
    use crate::fsm::{Role, State};
    let role = match role {
        Some(r) => r,
        None => match [Role::Active, Role::Passive]
            .into_iter()
            .find(|&r| arb.state(r) == State::Established)
        {
            Some(r) => r,
            None => return 1,
        },
    };
    arb.connection(role)
        .and_then(|c| c.send_max().get(&family))
        .copied()
        .unwrap_or(1)
}

/// Cross-session mutable state for a peer.
///
/// Holds everything that must survive individual BGP session boundaries:
/// the FSM arbiter, GR state machine, stale-route source, timers, and the
/// route export tracking map.  Lifetime: peer lifetime (from `add_peer` to
/// peer deletion).
///
/// Currently embedded in `Peer` via `Arc<Mutex<>>` so that `PeerSession::run`
/// can operate on `PeerContext` without holding the global write lock.
struct PeerContext {
    /// Shared arbiter for this peer: holds PeerFsm and collision close-channels.
    conn_arbiter: Arc<std::sync::Mutex<ConnArbiter>>,
    /// Cancels the active-connect retry loop spawned by `enable_active_connect`.
    /// Dropping the sender signals the task to exit; replaced on each reconnect.
    active_connect_cancel_tx: Option<tokio::sync::oneshot::Sender<()>>,
    /// JoinHandle for the active-connect retry task.  Stored alongside
    /// active_connect_cancel_tx so stop_bgp can await task completion.
    active_connect_join_handle: Option<tokio::task::JoinHandle<()>>,
    /// GR helper state machine; persists across sessions.
    gr_state: crate::gr::GrState,
    /// Command channel for the GR restart timer task.
    /// Send `()` to fire the timer immediately (RunNow); drop the sender to cancel silently.
    gr_restart_timer: Option<tokio::sync::oneshot::Sender<()>>,
}

impl PeerContext {
    /// Cancel the GR restart timer without running the expired handler.
    /// Used when a new session is established and GR recovery proceeds normally.
    fn cancel_gr_timer(&mut self) {
        self.gr_restart_timer.take(); // drop sender = cancel
    }

    /// Fire the GR restart timer immediately, triggering stale route purge.
    /// Used when an API call forces the peer down while in GR helper mode.
    fn fire_gr_timer(&mut self) {
        if let Some(tx) = self.gr_restart_timer.take() {
            let _ = tx.send(());
        }
    }

    /// Tear down the peer: fire GR timer, optionally stop the active-connect loop,
    /// and send a close reason to any live session tasks.
    fn force_down(&mut self, reason: CloseReason, cancel_active_connect: bool) {
        self.fire_gr_timer();
        if cancel_active_connect {
            self.active_connect_cancel_tx.take();
            self.active_connect_join_handle.take();
        }
        let mut arb = self.conn_arbiter.lock().unwrap();
        for tx in [arb.active_close_tx.take(), arb.passive_close_tx.take()]
            .into_iter()
            .flatten()
        {
            let _ = tx.send(reason.clone());
        }
    }
}

/// Administrative peer record stored in `Global::peers` under the global
/// `RwLock`.
///
/// Lifetime: from `add_peer` (config or gRPC) until the peer is deleted.
/// Not tied to any specific BGP session; a single `Peer` lives across
/// multiple connect/disconnect cycles.
///
/// Contains only the gRPC-visible snapshot (config, atomic state, message
/// counters) plus a handle to `PeerContext` for cross-session mutable state.
/// The split keeps the global lock section lean: gRPC reads never need to
/// acquire the per-peer `PeerContext` mutex.
pub(crate) struct Peer {
    config: PeerConfig,
    admin_down: bool,

    /// Shared with the active `PeerSession`; updated atomically during a session.
    state: Arc<PeerState>,

    counter_tx: Arc<MessageCounter>,
    counter_rx: Arc<MessageCounter>,

    /// Cross-session mutable state (FSM, GR, timers, export map).
    context: Arc<std::sync::Mutex<PeerContext>>,
}

/// Ephemeral snapshot of a `Peer` for a single gRPC list/get response.
///
/// Lifetime: one gRPC handler invocation.  Cheap to construct: config is
/// cloned once, state and counters are `Arc` references into the live peer.
pub(super) struct PeerView {
    config: PeerConfig,
    admin_down: bool,
    state: Arc<PeerState>,
    counter_tx: Arc<MessageCounter>,
    counter_rx: Arc<MessageCounter>,
    route_stats: FnvHashMap<Family, table::PrefixStats>,
    /// True if the remote peer is currently restarting (we are acting as helper).
    gr_peer_restarting: bool,
    /// True if this router is the restarting speaker for this peer.
    gr_local_restarting: bool,
}

impl PeerView {
    fn update_stats(&mut self, rti: FnvHashMap<Family, table::PrefixStats>) {
        for (f, v) in rti {
            let stats = self.route_stats.entry(f).or_default();
            stats.received += v.received;
            stats.accepted += v.accepted;
        }
    }
}

impl Peer {
    /// Returns `(remote_addr, PerPeerHeader, PeerUp message)` if this peer is
    /// currently Established, or `None` otherwise.  Used by BMP to build the
    /// initial PeerUp burst without exposing private `Peer` fields.
    pub(crate) fn bmp_peer_up(
        &self,
        local_router_id: Ipv4Addr,
    ) -> Option<(IpAddr, bmp::PerPeerHeader, bmp::Message)> {
        let addrs_guard = self.state.session_addrs.load();
        let addrs = (*addrs_guard).as_ref()?;
        let remote_asn = self.state.remote_asn.load(Ordering::Relaxed);
        let remote_id = Ipv4Addr::from(self.state.remote_id.load(Ordering::Relaxed));
        let peer_header = bmp::PerPeerHeader::new(
            remote_asn,
            remote_id,
            0,
            self.config.remote_addr,
            self.state.peer_up_at.load(Ordering::Relaxed) as u32,
        );
        let msg = bmp::Message::PeerUp {
            header: peer_header.clone(),
            local_addr: addrs.local.ip(),
            local_port: addrs.local.port(),
            remote_port: addrs.remote_port,
            remote_open: bgp::Message::Open(bgp::Open {
                as_number: remote_asn,
                holdtime: HoldTime::new(self.state.remote_holdtime.load(Ordering::Relaxed))
                    .unwrap_or(HoldTime::DISABLED),
                router_id: u32::from(remote_id),
                capability: self
                    .state
                    .remote_cap
                    .load()
                    .as_deref()
                    .cloned()
                    .unwrap_or_default(),
            }),
            local_open: bgp::Message::Open(bgp::Open {
                as_number: self.config.local_asn,
                holdtime: HoldTime::new(self.config.holdtime as u16).unwrap_or(HoldTime::DISABLED),
                router_id: u32::from(local_router_id),
                capability: self.config.local_cap.to_owned(),
            }),
        };
        Some((self.config.remote_addr, peer_header, msg))
    }

    fn view(&self, is_restarting: bool) -> PeerView {
        let ctx = self.context.lock().unwrap();
        PeerView {
            config: self.config.clone(),
            admin_down: self.admin_down,
            state: Arc::clone(&self.state),
            counter_tx: Arc::clone(&self.counter_tx),
            counter_rx: Arc::clone(&self.counter_rx),
            route_stats: FnvHashMap::default(),
            gr_peer_restarting: ctx.gr_state.is_peer_restarting(),
            gr_local_restarting: is_restarting,
        }
    }

    /// Clears session-negotiated state and connection handles so the peer is
    /// ready for the next connection attempt.  Config fields and
    /// `PeerContext::gr_state` are intentionally left untouched: config is
    /// operator-owned, and gr_state must survive across session boundaries
    /// while GR is active.
    fn clear_session_state(&mut self) {
        self.state.peer_down_at.store(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            Ordering::Relaxed,
        );
        self.state.remote_asn.store(0, Ordering::Relaxed);
        self.state.remote_cap.store(None);
        self.state.remote_id.store(0, Ordering::Relaxed);
        self.state.remote_holdtime.store(0, Ordering::Relaxed);

        self.state
            .fsm
            .store(SessionState::Idle as u8, Ordering::Relaxed);
        self.state.session_addrs.store(None);
        let mut ctx = self.context.lock().unwrap();
        ctx.active_connect_cancel_tx = None;
        ctx.active_connect_join_handle = None;
        {
            let mut arb = ctx.conn_arbiter.lock().unwrap();
            arb.active_close_tx = None;
            arb.passive_close_tx = None;
        }
    }

    fn peer_role(&self, global: &Global) -> PeerRole {
        let confederation = global.confederation.as_ref().map(|c| (c.id, &c.members));
        if self.config.route_server_client {
            PeerRole::RsClient
        } else if self.config.local_asn != 0
            && self.config.expected_remote_asn == self.config.local_asn
        {
            if self.config.route_reflector.route_reflector_client {
                PeerRole::IbgpRrClient
            } else {
                PeerRole::Ibgp
            }
        } else if confederation
            .as_ref()
            .is_some_and(|(_, members)| members.contains(&self.config.expected_remote_asn))
        {
            PeerRole::ConfedEbgp
        } else {
            PeerRole::Ebgp
        }
    }

    /// Build a `PeerExportContext` for adj-out display (no live session needed).
    ///
    /// Uses the router-id as `local_addr` fallback; `export_nexthop` is not
    /// called for display so the exact local address does not matter.
    fn adj_out_export_ctx(&self, global: &Global) -> PeerExportContext {
        PeerExportContext {
            role: self.peer_role(global),
            local_asn: self.config.local_asn,
            local_addr: IpAddr::V4(self.config.local_router_id),
            link_addr: None,
            confederation_id: global.confederation.as_ref().map_or(0, |c| c.id),
        }
    }

    /// Return the cluster-id used for RR reflection, if applicable.
    fn adj_out_cluster_id(&self, global: &Global) -> Option<Ipv4Addr> {
        match self.peer_role(global) {
            PeerRole::Ibgp | PeerRole::IbgpRrClient => Some(
                self.config
                    .route_reflector
                    .route_reflector_cluster_id
                    .unwrap_or(self.config.local_router_id),
            ),
            _ => None,
        }
    }

    /// Effective send-max for `family` for adj-out display.
    ///
    /// Returns None if no session is currently Established (adj-out should
    /// show empty in that case).  Returns Some(n) when Established: n > 1
    /// if Add-Path TX was negotiated, 1 otherwise.
    fn adj_out_effective_max(&self, family: Family) -> Option<usize> {
        let ctx = self.context.lock().unwrap();
        let arb = ctx.conn_arbiter.lock().unwrap();
        use crate::fsm::{Role, State};
        let role = [Role::Active, Role::Passive]
            .into_iter()
            .find(|&r| arb.state(r) == State::Established)?;
        Some(
            arb.connection(role)
                .and_then(|c| c.send_max().get(&family))
                .copied()
                .unwrap_or(1),
        )
    }
}

pub(super) async fn add_policy_assignment(
    req: api::PolicyAssignment,
    global: GlobalHandle,
    tables: TableHandle,
) -> Result<(), Error> {
    let (name, direction, default_action, policy_names) = convert::policy_assignment_from_api(req)?;
    let (dir, assignment) = global.write().await.ptable.add_assignment(
        &name,
        direction,
        default_action,
        policy_names,
    )?;
    if dir == table::PolicyDirection::Import {
        tables.import_policy.store(Some(Arc::clone(&assignment)));
    } else {
        tables.export_policy.store(Some(Arc::clone(&assignment)));
    }
    Ok(())
}

pub(crate) enum ToPeerEvent {
    NlriChange(table::NlriChange),
    /// Trigger a soft reset OUT: re-advertise all current best paths.
    SoftResetOut,
}

pub(super) fn enable_active_connect(peer: &mut Peer, ch: mpsc::UnboundedSender<TcpStream>) {
    if peer.admin_down || peer.config.passive || peer.config.delete_on_disconnected {
        return;
    }
    let peer_addr = peer.config.remote_addr;
    let sockaddr = std::net::SocketAddr::new(peer_addr, peer.config.remote_port);
    let retry_time = peer.config.connect_retry_time;
    let password = peer.config.password.as_ref().map(|x| x.to_string());
    let (cancel_tx, mut cancel_rx) = tokio::sync::oneshot::channel::<()>();
    let join_handle = tokio::spawn(async move {
        loop {
            let socket = match peer_addr {
                IpAddr::V4(_) => tokio::net::TcpSocket::new_v4().unwrap(),
                IpAddr::V6(_) => tokio::net::TcpSocket::new_v6().unwrap(),
            };
            if let Some(key) = password.as_ref() {
                auth::set_md5sig(socket.as_raw_fd(), &peer_addr, key);
            }
            tokio::select! {
                result = tokio::time::timeout(
                    tokio::time::Duration::from_secs(5),
                    socket.connect(sockaddr),
                ) => {
                    if let Ok(Ok(stream)) = result {
                        let _ = ch.send(stream);
                        return;
                    }
                }
                _ = &mut cancel_rx => return,
            }
            tokio::select! {
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(retry_time)) => {}
                _ = &mut cancel_rx => return,
            }
        }
    });
    let mut ctx = peer.context.lock().unwrap();
    ctx.active_connect_cancel_tx = Some(cancel_tx);
    ctx.active_connect_join_handle = Some(join_handle);
}

pub(super) fn create_listen_socket(
    addr: String,
    port: u16,
) -> std::io::Result<std::net::TcpListener> {
    let addr: std::net::SocketAddr = format!("{}:{}", addr, port).parse().unwrap();

    let sock = socket2::Socket::new(
        match addr {
            SocketAddr::V4(_) => socket2::Domain::IPV4,
            SocketAddr::V6(_) => socket2::Domain::IPV6,
        },
        socket2::Type::STREAM,
        None,
    )?;
    if addr.is_ipv6() {
        sock.set_only_v6(true)?;
    }

    sock.set_reuse_address(true)?;
    sock.set_reuse_port(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    sock.listen(4096)?;

    Ok(sock.into())
}

pub(crate) type GlobalHandle = Arc<tokio::sync::RwLock<Global>>;

/// Active BGP confederation configuration (RFC 5065).
///
/// Present only when confederation is enabled.  Set once at StartBgp time;
/// no dynamic changes are supported (same as GoBGP).
pub(super) struct ConfederationConfig {
    /// Externally visible AS number (Confederation Identifier).
    id: u32,
    /// Member-AS numbers.  O(1) lookup for ConfedEbgp peer classification.
    members: FnvHashSet<u32>,
}

pub(crate) struct Global {
    asn: u32,
    pub(crate) router_id: Ipv4Addr,
    listen_port: u16,
    listen_sockets: Vec<RawFd>,
    pub(crate) peers: FnvHashMap<IpAddr, Peer>,
    peer_group: FnvHashMap<String, PeerGroup>,

    confederation: Option<ConfederationConfig>,

    ptable: table::PolicyTable,

    rpki_clients: FnvHashMap<SocketAddr, RpkiClient>,
    bmp_clients: FnvHashMap<SocketAddr, BmpClient>,
    mrt_dumpers: FnvHashMap<String, CancellationToken>,
    watch_event_cancels: FnvHashMap<SubscriptionId, CancellationToken>,

    /// Selection Deferral state machine for the Restarting Speaker (RFC 4724 §4.1).
    /// Present only when the daemon started with --graceful-restart.
    selection_deferral: Option<crate::gr::RestartingDeferral>,
    /// Abort handle for the global Selection_Deferral_Timer (RFC 4724 §4.1).
    selection_deferral_timer: Option<tokio::task::AbortHandle>,

    /// Kernel integration service. Drop aborts the background task.
    kernel_service: Option<kernel::KernelService>,
    /// Sender end of the kernel event channel; cloned into KernelService::start.
    kernel_event_tx: mpsc::UnboundedSender<kernel::KernelEvent>,

    /// Sending on this channel causes the BGP listener loop to stop, enabling
    /// a subsequent start_bgp call to restart it.  None when BGP is not running.
    stop_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Global {
    const BGP_PORT: u16 = 179;

    fn new(kernel_event_tx: mpsc::UnboundedSender<kernel::KernelEvent>) -> Global {
        Global {
            asn: 0,
            router_id: Ipv4Addr::new(0, 0, 0, 0),
            listen_port: Global::BGP_PORT,
            listen_sockets: Vec::new(),

            peers: FnvHashMap::default(),
            peer_group: FnvHashMap::default(),

            confederation: None,

            ptable: table::PolicyTable::new(),

            rpki_clients: FnvHashMap::default(),
            bmp_clients: FnvHashMap::default(),
            mrt_dumpers: FnvHashMap::default(),
            watch_event_cancels: FnvHashMap::default(),

            selection_deferral: None,
            selection_deferral_timer: None,

            kernel_service: None,
            kernel_event_tx,

            stop_tx: None,
        }
    }

    fn add_bmp_client(
        &mut self,
        sockaddr: SocketAddr,
    ) -> Result<(CancellationToken, Arc<crate::bmp::BmpClientState>), ()> {
        use std::collections::hash_map::Entry;
        match self.bmp_clients.entry(sockaddr) {
            Entry::Occupied(_) => Err(()),
            Entry::Vacant(v) => {
                let client = BmpClient::new();
                let cancel = client.cancel.clone();
                let state = Arc::clone(&client.state);
                v.insert(client);
                Ok((cancel, state))
            }
        }
    }

    fn remove_bmp_client(&mut self, sockaddr: SocketAddr) -> bool {
        if let Some(client) = self.bmp_clients.remove(&sockaddr) {
            client.cancel.cancel();
            true
        } else {
            false
        }
    }

    fn iter_bmp_clients(&self) -> impl Iterator<Item = (&SocketAddr, &BmpClient)> {
        self.bmp_clients.iter()
    }

    fn add_rpki_client(
        &mut self,
        sockaddr: SocketAddr,
    ) -> Result<(CancellationToken, Arc<Notify>, Arc<RpkiState>), ()> {
        use std::collections::hash_map::Entry;
        match self.rpki_clients.entry(sockaddr) {
            Entry::Occupied(_) => Err(()),
            Entry::Vacant(v) => {
                let client = RpkiClient::new();
                let cancel = client.cancel.clone();
                let soft_reset = Arc::clone(&client.soft_reset);
                let state = Arc::clone(&client.state);
                v.insert(client);
                Ok((cancel, soft_reset, state))
            }
        }
    }

    fn remove_rpki_client(&mut self, sockaddr: SocketAddr) -> bool {
        if let Some(client) = self.rpki_clients.remove(&sockaddr) {
            client.cancel.cancel();
            true
        } else {
            false
        }
    }

    fn iter_rpki_clients(&self) -> impl Iterator<Item = (&SocketAddr, &RpkiClient)> {
        self.rpki_clients.iter()
    }

    fn add_peer(
        &mut self,
        mut params: PeerParams,
        tx: Option<mpsc::UnboundedSender<TcpStream>>,
    ) -> std::result::Result<(), Error> {
        if self.peers.contains_key(&params.remote_addr) {
            return Err(Error::AlreadyExists(
                "peer address already exists".to_string(),
            ));
        }
        // RFC 5065 §4: external peers see the confederation identifier as the
        // local AS number in OPEN messages, not the member-AS number.
        if let Some(conf) = &self.confederation
            && !conf.members.contains(&params.expected_remote_asn)
        {
            params.local_asn = conf.id;
        }
        let mut peer = params.build(u32::from(self.router_id), self.asn);
        if peer.admin_down {
            peer.state
                .fsm
                .store(SessionState::Connect as u8, Ordering::Relaxed);
        }
        if let Some(tx) = tx {
            enable_active_connect(&mut peer, tx);
        }
        self.peers.insert(peer.config.remote_addr, peer);
        Ok(())
    }
}

async fn accept_connection(
    global: &GlobalHandle,
    tables: &TableHandle,
    stream: TcpStream,
    role: crate::fsm::Role,
) -> Option<PeerSession> {
    let remote_sockaddr = stream.peer_addr().ok()?;
    let remote_addr = remote_sockaddr.ip();
    let mut g = global.write().await;
    let is_restarting = g.selection_deferral.is_some();
    let confederation = g.confederation.as_ref().map(|c| (c.id, c.members.clone()));
    let peer = match g.peers.get_mut(&remote_addr) {
        Some(peer) => {
            if peer.admin_down {
                log::warn!(
                    "admin down; ignore a new passive connection from {}",
                    remote_addr
                );
                return None;
            }
            let already_connected = {
                let arb = peer.context.lock().unwrap();
                let arb = arb.conn_arbiter.lock().unwrap();
                match role {
                    crate::fsm::Role::Active => arb.active_close_tx.is_some(),
                    crate::fsm::Role::Passive => arb.passive_close_tx.is_some(),
                }
            };
            if already_connected {
                log::warn!("already has {:?} connection {}", role, remote_addr);
                return None;
            }
            peer.state
                .fsm
                .store(SessionState::Active as u8, Ordering::Relaxed);
            peer
        }
        None => {
            let group = g.peer_group.values().find(|pg| {
                pg.dynamic_peers
                    .iter()
                    .any(|d| d.prefix.contains(&remote_addr))
            });
            let Some(group) = group else {
                log::warn!(
                    "can't find configuration a new passive connection {}",
                    remote_addr
                );
                return None;
            };
            let params = PeerParams {
                remote_addr,
                remote_port: Global::BGP_PORT,
                expected_remote_asn: group.as_number,
                local_asn: group.local_asn,
                passive: group.passive,
                rs_client: group.route_server_client,
                route_reflector: group.route_reflector.clone(),
                delete_on_disconnected: true,
                admin_down: false,
                state: SessionState::Active,
                holdtime: group.holdtime.unwrap_or(PeerParams::DEFAULT_HOLD_TIME),
                connect_retry_time: group
                    .connect_retry_time
                    .unwrap_or(PeerParams::DEFAULT_CONNECT_RETRY_TIME),
                multihop_ttl: group.multihop_ttl,
                ttl_security: group.ttl_security,
                password: group.auth_password.clone(),
                families: group.families.clone(),
                send_max: group.send_max.clone(),
                prefix_limits: FnvHashMap::default(),
                graceful_restart: group.graceful_restart.clone(),
            };
            let _ = g.add_peer(params, None);
            g.peers.get_mut(&remote_addr).unwrap()
        }
    };
    if let Some(ttl_min) = peer.config.ttl_security {
        // GTSM (RFC 5082): send with TTL=255, drop incoming below ttl_min.
        let _ = stream.set_ttl(255);
        auth::set_min_ttl(stream.as_raw_fd(), &remote_addr, ttl_min);
    } else if let Some(ttl) = peer.config.multihop_ttl {
        if peer.config.expected_remote_asn != peer.config.local_asn {
            let _ = stream.set_ttl(ttl.into());
        }
    } else {
        let _ = stream.set_ttl(1);
    }
    let context = Arc::clone(&peer.context);
    let (close_tx, close_rx) = tokio::sync::oneshot::channel::<CloseReason>();
    {
        let ctx = context.lock().unwrap();
        let mut arb = ctx.conn_arbiter.lock().unwrap();
        match role {
            crate::fsm::Role::Active => arb.active_close_tx = Some(close_tx),
            crate::fsm::Role::Passive => arb.passive_close_tx = Some(close_tx),
        }
    }
    let peer_role = if peer.config.route_server_client {
        PeerRole::RsClient
    } else if peer.config.local_asn != 0 && peer.config.expected_remote_asn == peer.config.local_asn
    {
        if peer.config.route_reflector.route_reflector_client {
            PeerRole::IbgpRrClient
        } else {
            PeerRole::Ibgp
        }
    } else if confederation
        .as_ref()
        .is_some_and(|(_, members)| members.contains(&peer.config.expected_remote_asn))
    {
        PeerRole::ConfedEbgp
    } else {
        PeerRole::Ebgp
    };
    let cluster_id = match peer_role {
        PeerRole::Ibgp | PeerRole::IbgpRrClient => Some(
            peer.config
                .route_reflector
                .route_reflector_cluster_id
                .unwrap_or(peer.config.local_router_id),
        ),
        _ => None,
    };
    let res = PeerResources {
        local_asn: peer.config.local_asn,
        local_cap: peer.config.local_cap.to_owned(),
        is_restarting,
        role: peer_role,
        prefix_limits: peer.config.prefix_limits.clone(),
        state: peer.state.clone(),
        counter_tx: peer.counter_tx.clone(),
        counter_rx: peer.counter_rx.clone(),
        tables: tables.clone(),
        context,
        local_router_id: peer.config.local_router_id,
        cluster_id,
        confederation_id: confederation.as_ref().map_or(0, |(id, _)| *id),
    };
    PeerSession::new(stream, remote_addr, role, Some(close_rx), res)
}

impl Global {
    async fn serve(
        bgp: Option<config::BgpConfig>,
        any_peer: bool,
        is_restarting: bool,
        active_tx: mpsc::UnboundedSender<TcpStream>,
        mut active_rx: mpsc::UnboundedReceiver<TcpStream>,
    ) {
        let (kernel_event_tx, mut kernel_event_rx) =
            mpsc::unbounded_channel::<kernel::KernelEvent>();
        let global: GlobalHandle = Arc::new(tokio::sync::RwLock::new(Global::new(kernel_event_tx)));
        let tables: TableHandle = Arc::new(TableManager::new(num_cpus::get()));
        let global_config = bgp
            .as_ref()
            .and_then(|x| x.global.as_ref())
            .and_then(|x| x.config.as_ref());
        let as_number = global_config
            .as_ref()
            .and_then(|x| x.r#as)
            .unwrap_or_default();
        let router_id =
            if let Some(router_id) = global_config.as_ref().and_then(|x| x.router_id.as_ref()) {
                *router_id
            } else {
                Ipv4Addr::new(0, 0, 0, 0)
            };
        let notify = Arc::new(tokio::sync::Notify::new());
        if as_number != 0 {
            let g = &mut global.write().await;
            if as_number != 0 {
                notify.clone().notify_one();
                g.asn = as_number;
                g.router_id = router_id;
            }
            if let Some((id, c)) = bgp
                .as_ref()
                .and_then(|x| x.global.as_ref())
                .and_then(|x| x.confederation.as_ref())
                .and_then(|x| x.config.as_ref())
                .filter(|c| c.enabled.unwrap_or(false))
                .and_then(|c| c.identifier.filter(|&id| id != 0).map(|id| (id, c)))
            {
                g.confederation = Some(ConfederationConfig {
                    id,
                    members: c
                        .member_as_list
                        .as_deref()
                        .unwrap_or(&[])
                        .iter()
                        .copied()
                        .collect(),
                });
            }
        }
        if let Some(mrt) = bgp.as_ref().and_then(|x| x.mrt_dump.as_ref()) {
            for m in mrt {
                if let Some(config) = m.config.as_ref()
                    && let Some(dump_type) = config.dump_type.as_ref()
                {
                    if dump_type != &config::generate::MrtType::Updates {
                        log::warn!("only update dump is supported");
                        continue;
                    }
                    if let Some(filename) = config.file_name.as_ref() {
                        let cancel = CancellationToken::new();
                        {
                            let mut g = global.write().await;
                            if g.mrt_dumpers.contains_key(filename) {
                                log::warn!("mrt dumper already enabled for {filename}, skipping");
                                continue;
                            }
                            g.mrt_dumpers.insert(filename.clone(), cancel.clone());
                        }
                        let interval = config.rotation_interval.as_ref().map_or(0, |x| *x);
                        let filename = filename.clone();
                        let mut d = crate::mrt::MrtDumper::new(&filename, interval);
                        match tokio::fs::File::create(std::path::Path::new(&d.pathname())).await {
                            Ok(file) => {
                                let tables2 = tables.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = d.serve(file, cancel, tables2).await {
                                        log::error!("mrt dumper failed: {:?}", e);
                                    }
                                });
                            }
                            Err(e) => {
                                global.write().await.mrt_dumpers.remove(&filename);
                                log::error!("failed to create mrt dump file: {:?}", e);
                            }
                        }
                    } else {
                        log::warn!("mrt dump filename needs to be specified");
                    }
                }
            }
        }
        if let Some(zebra_cfg) = bgp
            .as_ref()
            .and_then(|x| x.zebra.as_ref())
            .and_then(|x| x.config.as_ref())
            .filter(|x| x.enabled == Some(true))
        {
            let redistribute: Vec<kernel::Protocol> = zebra_cfg
                .redistribute_route_type_list
                .iter()
                .flatten()
                .filter_map(|s| kernel::route_type_to_protocol(s))
                .collect();
            let event_tx = global.read().await.kernel_event_tx.clone();
            match kernel::KernelService::start(redistribute, event_tx) {
                Ok((service, handle)) => {
                    global.write().await.kernel_service = Some(service);
                    tables.kernel_handle.store(Some(Arc::new(handle)));
                    log::info!("kernel route integration enabled");
                }
                Err(e) => {
                    log::error!("failed to enable kernel route integration: {:?}", e);
                }
            }
        }
        if let Some(groups) = bgp.as_ref().and_then(|x| x.peer_groups.as_ref()) {
            let mut server = global.write().await;
            for pg in groups {
                if let Some(name) = pg.config.as_ref().and_then(|x| x.peer_group_name.clone()) {
                    server.peer_group.insert(name, PeerGroup::from_yaml(pg));
                }
            }
        }
        if let Some(neighbors) = bgp.as_ref().and_then(|x| x.dynamic_neighbors.as_ref()) {
            let mut server = global.write().await;
            for n in neighbors {
                if let Some(prefix) = n.config.as_ref().and_then(|x| x.prefix.as_ref())
                    && let Ok(prefix) = packet::IpNet::from_str(prefix)
                    && let Some(name) = n.config.as_ref().and_then(|x| x.peer_group.as_ref())
                {
                    server
                        .peer_group
                        .entry(name.to_string())
                        .and_modify(|e| e.dynamic_peers.push(DynamicPeer { prefix }));
                }
            }
        }
        if let Some(bmp_servers) = bgp.as_ref().and_then(|x| x.bmp_servers.as_ref()) {
            let mut server = global.write().await;
            for s in bmp_servers {
                let config = s.config.as_ref().unwrap();
                let sockaddr =
                    SocketAddr::new(config.address.unwrap(), config.port.unwrap() as u16);
                match server.add_bmp_client(sockaddr) {
                    Err(()) => panic!("duplicated bmp server {}", sockaddr),
                    Ok((cancel, state)) => {
                        BmpClient::try_connect(
                            sockaddr,
                            cancel,
                            state,
                            global.clone(),
                            tables.clone(),
                        );
                    }
                }
            }
        }
        if let Some(bgp_conf) = bgp.as_ref()
            && (bgp_conf.defined_sets.is_some() || bgp_conf.policy_definitions.is_some())
        {
            let mut server = global.write().await;
            if let Err(e) = convert::load_policy_from_config(&mut server.ptable, bgp_conf) {
                panic!("{:?}", e);
            }
        }
        if let Some(g) = bgp.as_ref().and_then(|x| x.global.as_ref()) {
            let f = |direction: i32,
                     policy_list: Option<&Vec<String>>,
                     action: Option<&config::generate::DefaultPolicyType>|
             -> api::PolicyAssignment {
                api::PolicyAssignment {
                    name: "".to_string(),
                    direction,
                    policies: policy_list.map_or(Vec::new(), |x| {
                        x.iter()
                            .map(|x| api::Policy {
                                name: x.to_string(),
                                statements: Vec::new(),
                            })
                            .collect()
                    }),
                    default_action: action.map_or(1, convert::default_policy_type_to_i32),
                }
            };
            if let Some(Some(config)) = g.apply_policy.as_ref().map(|x| x.config.as_ref()) {
                if let Err(e) = add_policy_assignment(
                    f(
                        1,
                        config.import_policy_list.as_ref(),
                        config.default_import_policy.as_ref(),
                    ),
                    global.clone(),
                    tables.clone(),
                )
                .await
                {
                    panic!("{:?}", e);
                }
                if let Err(e) = add_policy_assignment(
                    f(
                        2,
                        config.export_policy_list.as_ref(),
                        config.default_export_policy.as_ref(),
                    ),
                    global.clone(),
                    tables.clone(),
                )
                .await
                {
                    panic!("{:?}", e);
                }
            }
        }
        if let Some(peers) = bgp.as_ref().and_then(|x| x.neighbors.as_ref()) {
            let mut server = global.write().await;
            for p in peers {
                match PeerParams::try_from(p) {
                    Ok(params) => {
                        if let Err(e) = server.add_peer(params, Some(active_tx.clone())) {
                            log::error!("failed to add peer from config: {}", e);
                        }
                    }
                    Err(e) => {
                        log::warn!("skipping invalid peer config: {}", e);
                    }
                }
            }
        }
        if let Some(rpki_servers) = bgp.as_ref().and_then(|x| x.rpki_servers.as_ref()) {
            for s in rpki_servers {
                let addr = s.config.as_ref().and_then(|c| c.address);
                let port = s
                    .config
                    .as_ref()
                    .and_then(|c| c.port)
                    .map(|p| p as u16)
                    .unwrap_or(323);
                if let Some(addr) = addr {
                    let sockaddr = SocketAddr::new(addr, port);
                    match global.write().await.add_rpki_client(sockaddr) {
                        Err(()) => {
                            log::warn!("rpki client {} already exists", sockaddr);
                        }
                        Ok((cancel, soft_reset, state)) => {
                            crate::rpki::RpkiClient::try_connect(
                                sockaddr,
                                cancel,
                                soft_reset,
                                state,
                                tables.clone(),
                            );
                        }
                    }
                }
            }
        }
        // Initialize Restarting Speaker deferral when started with --graceful-restart
        // and a config file (file-based startup only).
        if is_restarting && bgp.is_some() {
            let gr_peers: fnv::FnvHashMap<IpAddr, Vec<Family>> = {
                let server = global.read().await;
                server
                    .peers
                    .iter()
                    .filter_map(|(addr, peer)| {
                        peer.config
                            .graceful_restart
                            .as_ref()
                            .map(|gr| (*addr, gr.families.clone()))
                    })
                    .collect()
            };
            // Read Selection_Deferral_Timer from Global GR config (stale_routes_time).
            // None → default 360 s; 0 → disabled (wait indefinitely); >0 → use that value.
            let selection_deferral_time: Option<std::time::Duration> = bgp
                .as_ref()
                .and_then(|b| b.global.as_ref())
                .and_then(|g| g.graceful_restart.as_ref())
                .and_then(|gr| gr.config.as_ref())
                .and_then(|c| c.stale_routes_time)
                .map_or(Some(std::time::Duration::from_secs(360)), |secs| {
                    if secs == 0.0 {
                        None
                    } else {
                        Some(std::time::Duration::from_secs_f64(secs))
                    }
                });
            let (deferral, init_outputs) =
                crate::gr::RestartingDeferral::new(gr_peers, selection_deferral_time);
            if !deferral.is_completed() {
                for output in &init_outputs {
                    if let crate::gr::RestartingOutput::DeferFamilies(families) = output {
                        tables.start_deferral_families(families);
                    }
                }
                global.write().await.selection_deferral = Some(deferral);
            }
        }

        if any_peer {
            let mut server = global.write().await;
            server.peer_group.insert(
                "any".to_string(),
                PeerGroup {
                    as_number: 0,
                    dynamic_peers: vec![
                        DynamicPeer {
                            prefix: packet::IpNet::from_str("0.0.0.0/0").unwrap(),
                        },
                        DynamicPeer {
                            prefix: packet::IpNet::from_str("::/0").unwrap(),
                        },
                    ],
                    route_server_client: false,
                    holdtime: None,
                    local_asn: 0,
                    passive: false,
                    route_reflector: RouteReflectorConfig::default(),
                    multihop_ttl: None,
                    ttl_security: None,
                    auth_password: None,
                    connect_retry_time: None,
                    families: FnvHashMap::default(),
                    send_max: FnvHashMap::default(),
                    graceful_restart: None,
                },
            );
        }
        let addr = "0.0.0.0:50051".parse().unwrap();
        let notify2 = notify.clone();
        let active_tx2 = active_tx.clone();
        let global2 = global.clone();
        let tables2 = tables.clone();
        tokio::spawn(async move {
            if let Err(e) = tonic::transport::Server::builder()
                .add_service(GoBgpServiceServer::new(GrpcService::new(
                    notify2, active_tx2, global2, tables2,
                )))
                .serve(addr)
                .await
            {
                panic!("failed to listen on grpc {}", e);
            }
        });
        loop {
            notify.notified().await;
            let listen_port = global.read().await.listen_port;
            let listen_sockets: Vec<std::net::TcpListener> = vec![
                create_listen_socket("0.0.0.0".to_string(), listen_port),
                create_listen_socket("[::]".to_string(), listen_port),
            ]
            .into_iter()
            .filter_map(|x| x.ok())
            .collect();
            global
                .write()
                .await
                .listen_sockets
                .append(&mut listen_sockets.iter().map(|x| x.as_raw_fd()).collect());

            for (addr, peer) in &global.read().await.peers {
                if let Some(password) = &peer.config.password {
                    for l in &listen_sockets {
                        auth::set_md5sig(l.as_raw_fd(), addr, password);
                    }
                }
            }

            let mut incomings = listen_sockets
                .into_iter()
                .map(|x| {
                    tokio_stream::wrappers::TcpListenerStream::new(
                        TcpListener::from_std(x).unwrap(),
                    )
                })
                .collect::<Vec<tokio_stream::wrappers::TcpListenerStream>>();
            assert_ne!(incomings.len(), 0);

            let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();
            global.write().await.stop_tx = Some(stop_tx);

            loop {
                let mut bgp_listen_futures = FuturesUnordered::new();
                for incoming in &mut incomings {
                    bgp_listen_futures.push(incoming.next());
                }
                futures::select_biased! {
                    event = kernel_event_rx.recv().fuse() => {
                        match event {
                            Some(kernel::KernelEvent::Route(kernel::KernelRouteEvent::Add(kr))) => {
                                tables.inject_kernel_route(kr);
                            }
                            Some(kernel::KernelEvent::Route(kernel::KernelRouteEvent::Delete(kr))) => {
                                tables.withdraw_kernel_route(kr.dst, kr.prefix_len);
                            }
                            Some(kernel::KernelEvent::NexthopUpdate { addr, reachable }) => {
                                tables.update_nexthop_validity(addr, reachable);
                            }
                            Some(kernel::KernelEvent::Address(addr_event)) => {
                                tables.handle_address_event(addr_event);
                            }
                            None => {}
                        }
                    }
                    stream = bgp_listen_futures.next() => {
                        if let Some(Some(Ok(stream))) = stream
                            && let Some(h) = accept_connection(&global, &tables, stream, crate::fsm::Role::Passive).await
                        {
                            let arb = h.conn_arbiter.clone();
                            let join_handle = tokio::spawn(h.run(global.clone(), active_tx.clone()));
                            arb.lock().unwrap().passive_join_handle = Some(join_handle);
                        }
                    }
                    stream = active_rx.recv().fuse() => {
                        if let Some(stream) = stream
                            && let Some(h) = accept_connection(&global, &tables, stream, crate::fsm::Role::Active).await
                        {
                            let arb = h.conn_arbiter.clone();
                            let join_handle = tokio::spawn(h.run(global.clone(), active_tx.clone()));
                            arb.lock().unwrap().active_join_handle = Some(join_handle);
                        }
                    }
                    _ = (&mut stop_rx).fuse() => { break }
                }
            }
            // Close listeners by dropping incomings; clear stored FDs.
            drop(incomings);
            global.write().await.listen_sockets.clear();
        }
    }
}

use crate::table_manager::{PeerDownData, PeerUpData, SubscriptionId, TableManager};
// Re-export for mrt.rs and bmp.rs which import from crate::event.
pub(crate) use crate::table_manager::{AdjRibInChange, BgpEvent, TableHandle};

pub(crate) async fn main(bgp: Option<config::BgpConfig>, any_peer: bool, is_restarting: bool) {
    let (active_tx, active_rx) = mpsc::unbounded_channel();
    Global::serve(bgp, any_peer, is_restarting, active_tx, active_rx).await;
}

/// For an IPv6 socket, find the link-local address of the same interface.
/// Returns `None` for IPv4 sockets or if no link-local address is found.
/// For a directly-connected IPv6 peer, find the link-local address of the
/// local interface. Only looks up link-local when scope_id is non-zero
/// (indicating a directly-connected peer). Multihop peers have no
/// reachable link-local, so they get `None`.
fn find_link_local(local: &SocketAddr) -> Option<Ipv6Addr> {
    let scope_id = match local {
        SocketAddr::V6(v6) if v6.scope_id() != 0 => v6.scope_id(),
        _ => return None,
    };
    // If local address is itself link-local, use it directly.
    if let IpAddr::V6(v6) = local.ip()
        && v6.is_unicast_link_local()
    {
        return Some(v6);
    }
    // Look up the interface's link-local address.
    let name = nix::net::if_::if_indextoname(scope_id)
        .ok()
        .and_then(|c| c.into_string().ok())?;
    nix::ifaddrs::getifaddrs().ok()?.find_map(|ifa| {
        if ifa.interface_name != name {
            return None;
        }
        let addr = ifa.address?.as_sockaddr_in6()?.ip();
        if (addr.segments()[0] & 0xffc0) == 0xfe80 {
            Some(addr)
        } else {
            None
        }
    })
}

/// GR state negotiated during the last OPEN exchange.
/// Stored in DisconnectInfo so PeerSession::run can drive GrState on session drop.
#[derive(Clone)]
pub(super) struct NegotiatedGr {
    /// Intersection of local and remote GR families.
    families: Vec<Family>,
    /// Restart Time from the peer's OPEN GR capability.
    restart_time: std::time::Duration,
    /// Both sides advertised the N-bit (RFC 8538): GR applies to NOTIFICATION
    /// and Hold Timer expiry in addition to unplanned TCP disconnects.
    notification_enabled: bool,
}

struct DisconnectInfo {
    role: crate::fsm::Role,
    remote_addr: IpAddr,
    export_map: ExportMap,
    /// Set when GR was successfully negotiated for at least one family.
    negotiated_gr: Option<NegotiatedGr>,
}

/// Decide whether GR helper mode applies for a session disconnect.
///
/// RFC 4724: GR applies to unexpected TCP/IO drops.
/// RFC 8538: when the N-bit is negotiated, GR also applies to
/// NOTIFICATION (sent or received, unless Hard Reset) and Hold Timer expiry.
/// Only CEASE notifications are GR-eligible; OPEN/FSM/UPDATE errors are not.
fn gr_on_disconnect(
    shutdown: &Option<crate::fsm::SessionDownReason>,
    gr: NegotiatedGr,
) -> Option<NegotiatedGr> {
    let applies = match shutdown {
        None | Some(crate::fsm::SessionDownReason::IoError) => true,
        Some(crate::fsm::SessionDownReason::RemoteNotification(bgp::Message::Notification(
            err,
        ))) => gr.notification_enabled && !err.is_hard_reset(),
        Some(crate::fsm::SessionDownReason::LocalNotification(bgp::Message::Notification(err))) => {
            gr.notification_enabled
                && matches!(
                    err,
                    rustybgp_packet::Notification::CeaseMaxPrefixReached
                        | rustybgp_packet::Notification::CeaseAdminShutdown
                        | rustybgp_packet::Notification::CeasePeerDeconfigured
                        | rustybgp_packet::Notification::CeaseAdministrativeReset
                        | rustybgp_packet::Notification::CeaseConnectionRejected
                        | rustybgp_packet::Notification::CeaseOtherConfigurationChange
                        | rustybgp_packet::Notification::CeaseConnectionCollision
                        | rustybgp_packet::Notification::CeaseOutOfResources
                        | rustybgp_packet::Notification::CeaseHardReset
                        | rustybgp_packet::Notification::Other { code: 6, .. }
                )
                && !err.is_hard_reset()
        }
        Some(crate::fsm::SessionDownReason::HoldTimerExpired) => gr.notification_enabled,
        _ => false,
    };
    if applies { Some(gr) } else { None }
}

/// Apply outputs from [`crate::gr::RestartingDeferral::process`].
///
/// Handles FamilyDeferralComplete and EndDeferral immediately.
/// Returns `Some(duration)` when `StartDeferralTimer` was emitted so the
/// caller can spawn the timer; this avoids a circular Send dependency between
/// this function and `gr_selection_deferral_timer_expired`.
async fn process_restarting_outputs(
    outputs: Vec<crate::gr::RestartingOutput>,
    global: &GlobalHandle,
    tables: &TableHandle,
) -> Option<std::time::Duration> {
    let mut complete_families: Vec<Family> = vec![];
    let mut end_remaining: Option<Vec<Family>> = None;
    // None: no StartDeferralTimer output; Some(None): timer disabled; Some(Some(d)): start timer
    let mut start_timer: Option<Option<std::time::Duration>> = None;

    for output in outputs {
        match output {
            crate::gr::RestartingOutput::StartDeferralTimer(dur) => {
                start_timer = Some(dur);
            }
            crate::gr::RestartingOutput::FamilyDeferralComplete(family) => {
                complete_families.push(family);
            }
            crate::gr::RestartingOutput::EndDeferral(remaining) => {
                end_remaining = Some(remaining);
            }
            crate::gr::RestartingOutput::DeferFamilies(_) => {}
        }
    }

    if !complete_families.is_empty() {
        tables.end_deferral_families(&complete_families);
    }

    if let Some(remaining) = end_remaining {
        if !remaining.is_empty() {
            tables.end_deferral_families(&remaining);
        }
        let mut server = global.write().await;
        if let Some(h) = server.selection_deferral_timer.take() {
            h.abort();
        }
        server.selection_deferral = None;
        // R-bit is no longer stored in peer config; it is derived from
        // selection_deferral.is_some() at connection time (PeerFsm::on_connected).
        // Setting selection_deferral = None is sufficient.
        log::info!("graceful-restart: all peers sent EOR; cleared restarting state");
    }

    // Flatten: None (no output) and Some(None) (disabled) both mean "don't start timer".
    start_timer.flatten()
}

/// Convert plain IPv4/IPv6 NLRIs to VPNv4/VPNv6 for VRF export.
///
/// Attaches the VRF's RD, label, and export RTs (as EXTENDED_COMMUNITY) to
/// each path, then returns the translated family and updated NLRI/attrs.
type ExportedPath = (
    Family,
    Vec<packet::PathNlri>,
    Option<Arc<Vec<packet::Attribute>>>,
);

fn vrf_export_path(
    family: Family,
    nets: Vec<packet::PathNlri>,
    attrs: Option<Arc<Vec<packet::Attribute>>>,
    vrf: &table::Vrf,
) -> Result<ExportedPath, tonic::Status> {
    let vpn_family = match family {
        Family::IPV4 => Family::IPV4_VPN,
        Family::IPV6 => Family::IPV6_VPN,
        _ => {
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "VRF add_path only supports IPv4/IPv6 families",
            ));
        }
    };

    let vpn_nets: Vec<packet::PathNlri> = nets
        .into_iter()
        .map(|pn| {
            let vpn_nlri = match pn.nlri {
                packet::Nlri::V4(prefix) => packet::Nlri::VpnV4(packet::vpn::VpnV4Nlri {
                    labels: packet::mpls::MplsLabelStack::new(vec![vrf.label]),
                    rd: vrf.rd,
                    prefix,
                }),
                packet::Nlri::V6(prefix) => packet::Nlri::VpnV6(packet::vpn::VpnV6Nlri {
                    labels: packet::mpls::MplsLabelStack::new(vec![vrf.label]),
                    rd: vrf.rd,
                    prefix,
                }),
                other => {
                    return Err(tonic::Status::new(
                        tonic::Code::InvalidArgument,
                        format!("unsupported NLRI type for VRF export: {:?}", other),
                    ));
                }
            };
            Ok(packet::PathNlri {
                path_id: pn.path_id,
                nlri: vpn_nlri,
            })
        })
        .collect::<Result<_, _>>()?;

    let vpn_attrs = if vrf.export_rt.is_empty() {
        attrs
    } else {
        let rt_bytes: Vec<u8> = vrf
            .export_rt
            .iter()
            .flat_map(|rt| rt.iter().copied())
            .collect();
        let mut new_attrs: Vec<packet::Attribute> =
            attrs.as_deref().map_or_else(Vec::new, |v| v.to_vec());
        if let Some(ec) = new_attrs
            .iter_mut()
            .find(|a| a.code() == packet::bgp::Attribute::EXTENDED_COMMUNITY)
        {
            let mut data = ec.binary().cloned().unwrap_or_default();
            data.extend_from_slice(&rt_bytes);
            *ec = packet::Attribute::new_with_bin(packet::bgp::Attribute::EXTENDED_COMMUNITY, data)
                .unwrap();
        } else {
            if let Some(ec) = packet::Attribute::new_with_bin(
                packet::bgp::Attribute::EXTENDED_COMMUNITY,
                rt_bytes,
            ) {
                new_attrs.push(ec);
            }
        }
        Some(Arc::new(new_attrs))
    };

    Ok((vpn_family, vpn_nets, vpn_attrs))
}

async fn gr_selection_deferral_timer_expired(global: GlobalHandle, tables: TableHandle) {
    let outputs = {
        let mut server = global.write().await;
        if let Some(deferral) = &mut server.selection_deferral {
            deferral.process(crate::gr::RestartingInput::TimerExpired)
        } else {
            return;
        }
    };
    // TimerExpired never produces StartDeferralTimer, so we discard the return value.
    let _ = process_restarting_outputs(outputs, &global, &tables).await;
}

fn collect_delete_families(outputs: &[crate::gr::GrOutput]) -> Vec<Family> {
    outputs
        .iter()
        .filter_map(|o| {
            if let crate::gr::GrOutput::DeleteStaleRoutes(fs) = o {
                Some(fs.as_slice())
            } else {
                None
            }
        })
        .flatten()
        .copied()
        .collect()
}

async fn gr_restart_timer_expired(
    context: Arc<std::sync::Mutex<PeerContext>>,
    tables: TableHandle,
    addr: IpAddr,
) {
    let families = {
        let mut ctx = context.lock().unwrap();
        let outputs = ctx.gr_state.process(crate::gr::GrInput::TimerExpired);
        collect_delete_families(&outputs)
    };
    if !families.is_empty() {
        tables.drop_families(addr, &families);
    }
}

/// Side effects from `apply_outputs` that require mutating global peer state.
/// Returned by `apply_outputs` and processed by `process_effects` so that
/// `apply_outputs` itself has no async global dependency and is unit-testable.
enum GlobalEffect {
    /// Cancel the active-connect retry loop for this peer.
    StopActiveConnect,
    /// Peer reconnected while GR was active; drive GrState::SessionEstablished.
    GrSessionEstablished { negotiated_gr: Option<NegotiatedGr> },
    /// EOR received for a family while GR deferral timer is running.
    GrEorReceived { family: Family },
}

/// Returns the families whose routes must be dropped immediately on disconnect.
///
/// GR families are preserved (routes are kept stale until the restart timer
/// fires or EOR is received).  Every other session family is dropped right away,
/// even when GR is active for the peer.
fn families_to_drop_on_disconnect<'a>(
    session_families: impl Iterator<Item = &'a Family>,
    negotiated_gr: Option<&NegotiatedGr>,
) -> Vec<Family> {
    let gr_families: FnvHashSet<Family> = negotiated_gr
        .map(|g| g.families.iter().copied().collect())
        .unwrap_or_default();
    session_families
        .filter(|f| !gr_families.contains(f))
        .copied()
        .collect()
}

#[derive(Clone)]
struct ExportMap {
    // family -> nlri -> set of sent path_ids
    // Non-Add-Path: inner set is {0} when prefix is advertised
    // Add-Path: inner set contains each local_path_id that was sent
    advertised: FnvHashMap<Family, FnvHashMap<packet::Nlri, FnvHashSet<u32>>>,
}

impl Default for ExportMap {
    fn default() -> Self {
        Self::new()
    }
}

impl ExportMap {
    fn new() -> Self {
        ExportMap {
            advertised: FnvHashMap::default(),
        }
    }

    fn mark_sent(&mut self, family: Family, nlri: packet::Nlri, path_id: u32) {
        self.advertised
            .entry(family)
            .or_default()
            .entry(nlri)
            .or_default()
            .insert(path_id);
    }

    fn mark_withdrawn(&mut self, family: Family, nlri: &packet::Nlri, path_id: u32) {
        if let Some(m) = self.advertised.get_mut(&family)
            && let Some(s) = m.get_mut(nlri)
        {
            s.remove(&path_id);
            if s.is_empty() {
                m.remove(nlri);
            }
        }
    }

    fn was_sent(&self, family: Family, nlri: &packet::Nlri) -> bool {
        self.advertised
            .get(&family)
            .is_some_and(|m| m.contains_key(nlri))
    }

    fn contains_path(&self, family: Family, nlri: &packet::Nlri, path_id: u32) -> bool {
        self.advertised
            .get(&family)
            .and_then(|m| m.get(nlri))
            .is_some_and(|s| s.contains(&path_id))
    }

    fn sent_path_ids(&self, family: Family, nlri: &packet::Nlri) -> FnvHashSet<u32> {
        self.advertised
            .get(&family)
            .and_then(|m| m.get(nlri))
            .cloned()
            .unwrap_or_default()
    }

    fn clear_family(&mut self, family: Family) {
        self.advertised.remove(&family);
    }
}

use table::PeerRole;

/// Session-level peer export information.
///
/// Groups `PeerRole`, `local_asn`, `local_addr`, and `link_addr` so that
/// attribute transformation and route filtering decisions have a single source
/// of truth.  Built once in `PeerSession::new()` and stored as a field.
struct PeerExportContext {
    role: PeerRole,
    local_asn: u32,
    local_addr: IpAddr,
    link_addr: Option<Ipv6Addr>,
    /// Confederation Identifier (0 = not in a confederation).
    confederation_id: u32,
}

impl PeerExportContext {
    /// Build a `PeerCodec` for wire encoding.
    ///
    /// The codec handles only wire framing; all attribute transformation and
    /// loop detection is handled in the daemon.
    fn build_codec(&self) -> bgp::PeerCodec {
        bgp::PeerCodec::new()
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
    fn export_attrs(&self, attrs: &Arc<Vec<bgp::Attribute>>) -> Arc<Vec<bgp::Attribute>> {
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
                                | bgp::Attribute::MULTI_EXIT_DESC
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

    /// Apply per-peer nexthop transformation to an outgoing route nexthop.
    ///
    /// eBGP: replace with local_addr (with link-local for IPv6 when available).
    /// iBGP / iBGP-RR-client / RS client: pass through unchanged (next-hop
    /// unchanged).
    fn export_nexthop(&self, nexthop: Option<bgp::Nexthop>) -> Option<bgp::Nexthop> {
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
        match (self.role, nexthop) {
            // Flowspec carries no nexthop (RFC 8955 §4): preserve None.
            (_, None) => None,
            (PeerRole::RsClient | PeerRole::Ibgp | PeerRole::IbgpRrClient, Some(nh)) => Some(nh),
            (PeerRole::ConfedEbgp | PeerRole::Ebgp, Some(_)) => Some(local()),
        }
    }
}

/// Shared resources passed to `PeerSession::new()`.
///
/// Bundles the peer-level objects that come from `Peer` and `Global` so that
/// the session constructor does not need a long argument list.  Constructed as
/// a struct literal in `accept_connection` where all fields are already at hand.
struct PeerResources {
    local_asn: u32,
    local_cap: Vec<packet::Capability>,
    /// See `PeerSession::is_restarting`.
    is_restarting: bool,
    role: PeerRole,
    /// Per-family prefix limits from `PeerConfig`; used to initialise
    /// `PeerSession::prefix_counters` inside `new()`.
    prefix_limits: FnvHashMap<Family, u32>,
    state: Arc<PeerState>,
    counter_tx: Arc<MessageCounter>,
    counter_rx: Arc<MessageCounter>,
    tables: TableHandle,
    context: Arc<std::sync::Mutex<PeerContext>>,
    /// Local router-id used for RR ORIGINATOR_ID loop detection.
    local_router_id: Ipv4Addr,
    /// RFC 4456 cluster-id for RR attribute manipulation and loop detection.
    /// None for eBGP/RS-client sessions where RR logic does not apply.
    cluster_id: Option<Ipv4Addr>,
    /// Confederation Identifier for AS_PATH loop detection (0 = not configured).
    confederation_id: u32,
}

type CloseRxFuture = futures::future::OptionFuture<
    futures::future::Fuse<tokio::sync::oneshot::Receiver<CloseReason>>,
>;

enum Step {
    Continue,
    Terminate {
        reason: crate::fsm::SessionDownReason,
        notification: Option<bgp::Message>,
    },
}

/// I/O driver for one TCP connection (one BGP session).
///
/// Lifetime: a single BGP session — from `accept_connection` until the TCP
/// connection closes or a CEASE is received.  Runs as an independent tokio
/// task (`PeerSession::run`) and holds no reference back to the global `RwLock`
/// during normal operation; it accesses shared state only through
/// `Arc<PeerState>` (atomics), `Arc<MessageCounter>`, and
/// `Arc<Mutex<ConnArbiter>>`.
struct PeerSession {
    remote_addr: IpAddr,

    export_ctx: PeerExportContext,

    state: Arc<PeerState>,

    counter_tx: Arc<MessageCounter>,
    counter_rx: Arc<MessageCounter>,

    local_cap: Vec<packet::Capability>,
    /// True if the local router is the restarting speaker at session creation
    /// time (i.e., Global::selection_deferral was Some when the session was
    /// constructed).  Used to set the R-bit in the GR capability of the OPEN.
    is_restarting: bool,

    conn_arbiter: Arc<std::sync::Mutex<ConnArbiter>>,
    role: crate::fsm::Role,
    /// Receives a shutdown signal from an external source (collision winner or admin operation).
    close_rx: Option<tokio::sync::oneshot::Receiver<CloseReason>>,

    stream: Option<TcpStream>,
    source: FnvHashMap<Family, Arc<table::Source>>,
    peer_event_rx: Option<UnboundedReceiverStream<ToPeerEvent>>,
    tables: TableHandle,
    export_map: ExportMap,
    /// Per-family prefix counters: (max_prefixes, current_count).
    /// Created from PeerConfig::prefix_limits at session construction;
    /// counts unique prefixes currently accepted from this peer.
    prefix_counters: FnvHashMap<Family, (u32, Arc<std::sync::atomic::AtomicU64>)>,
    /// GR negotiation result from the most recent OPEN exchange.
    negotiated_gr: Option<NegotiatedGr>,
    /// Shared cross-session state for this peer; cloned from `Peer::context`
    /// so that `PeerSession::run` can operate on `PeerContext` without taking
    /// the global write lock.
    context: Arc<std::sync::Mutex<PeerContext>>,

    /// Local router-id for RR ORIGINATOR_ID loop detection (RFC 4456 §8).
    local_router_id: Ipv4Addr,
    /// RFC 4456 cluster-id; Some only for iBGP sessions on an RR.
    cluster_id: Option<Ipv4Addr>,

    // --- session I/O state ---
    ctrl_msgs: Vec<bgp::Message>,
    codec: bgp::PeerCodec,
    keepalive_futures: FuturesUnordered<tokio::time::Sleep>,
    holdtime_futures: FuturesUnordered<tokio::time::Sleep>,
    pending: FnvHashMap<Family, crate::peer_tx::PendingTx>,
    txbuf_size: usize,
}

impl PeerSession {
    fn new(
        stream: TcpStream,
        remote_addr: IpAddr,
        role: crate::fsm::Role,
        close_rx: Option<tokio::sync::oneshot::Receiver<CloseReason>>,
        res: PeerResources,
    ) -> Option<Self> {
        let local_sockaddr = stream.local_addr().ok()?;
        let local_addr = local_sockaddr.ip();
        let link_addr = find_link_local(&local_sockaddr);

        let mut txbuf_size = 1usize << 16;
        if let Ok(r) =
            nix::sys::socket::getsockopt(&stream.as_fd(), nix::sys::socket::sockopt::SndBuf)
        {
            txbuf_size = std::cmp::min(txbuf_size, r / 2);
        }

        let export_ctx = PeerExportContext {
            role: res.role,
            local_asn: res.local_asn,
            local_addr,
            link_addr,
            confederation_id: res.confederation_id,
        };
        let codec = export_ctx.build_codec();

        let prefix_counters = res
            .prefix_limits
            .iter()
            .map(|(family, max)| {
                (
                    *family,
                    (*max, Arc::new(std::sync::atomic::AtomicU64::new(0))),
                )
            })
            .collect();

        let conn_arbiter = Arc::clone(&res.context.lock().unwrap().conn_arbiter);

        Some(PeerSession {
            remote_addr,
            export_ctx,
            state: res.state,
            counter_tx: res.counter_tx,
            counter_rx: res.counter_rx,
            local_cap: res.local_cap,
            is_restarting: res.is_restarting,
            conn_arbiter,
            role,
            close_rx,
            stream: Some(stream),
            source: FnvHashMap::default(),
            peer_event_rx: None,
            tables: res.tables,
            export_map: ExportMap::new(),
            prefix_counters,
            negotiated_gr: None,
            context: res.context,
            local_router_id: res.local_router_id,
            cluster_id: res.cluster_id,
            ctrl_msgs: Vec::new(),
            codec,
            keepalive_futures: vec![tokio::time::sleep(Duration::new(u64::MAX, 0))]
                .into_iter()
                .collect(),
            holdtime_futures: vec![tokio::time::sleep(Duration::new(u64::MAX, 0))]
                .into_iter()
                .collect(),
            pending: FnvHashMap::default(),
            txbuf_size,
        })
    }

    /// Construct a minimal PeerSession for unit tests that do not need a real
    /// TCP connection.  `stream` is set to `None`; all I/O fields are inert.
    #[cfg(test)]
    fn new_for_test(
        remote_addr: IpAddr,
        context: Arc<std::sync::Mutex<PeerContext>>,
        tables: TableHandle,
    ) -> Self {
        use std::net::Ipv4Addr;

        let local_asn = 65001u32;
        let local_router_id = u32::from(Ipv4Addr::new(1, 0, 0, 1));
        let fsm = crate::fsm::PeerFsm::new(
            local_router_id,
            local_asn,
            vec![],
            90,
            0,
            FnvHashMap::default(),
        );
        let conn_arbiter = Arc::new(std::sync::Mutex::new(ConnArbiter::new(fsm)));
        context.lock().unwrap().conn_arbiter = Arc::clone(&conn_arbiter);

        let codec = bgp::PeerCodec::new();

        PeerSession {
            remote_addr,
            export_ctx: PeerExportContext {
                role: PeerRole::Ebgp,
                local_asn,
                local_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                link_addr: None,
                confederation_id: 0,
            },
            state: Arc::new(PeerState {
                fsm: AtomicU8::new(0),
                peer_up_at: AtomicU64::new(0),
                peer_down_at: AtomicU64::new(0),
                remote_asn: AtomicU32::new(0),
                remote_id: AtomicU32::new(0),
                remote_holdtime: AtomicU16::new(0),
                remote_cap: ArcSwapOption::empty(),
                session_addrs: ArcSwapOption::empty(),
            }),
            counter_tx: Default::default(),
            counter_rx: Default::default(),
            local_cap: vec![],
            is_restarting: false,
            conn_arbiter,
            role: crate::fsm::Role::Passive,
            close_rx: None,
            stream: None,
            source: FnvHashMap::default(),
            peer_event_rx: None,
            tables,
            export_map: ExportMap::new(),
            prefix_counters: FnvHashMap::default(),
            negotiated_gr: None,
            context,
            local_router_id: Ipv4Addr::new(1, 0, 0, 1),
            cluster_id: None,
            ctrl_msgs: Vec::new(),
            codec,
            keepalive_futures: vec![tokio::time::sleep(Duration::new(u64::MAX, 0))]
                .into_iter()
                .collect(),
            holdtime_futures: vec![tokio::time::sleep(Duration::new(u64::MAX, 0))]
                .into_iter()
                .collect(),
            pending: FnvHashMap::default(),
            txbuf_size: 1 << 16,
        }
    }

    /// Compute the intersection of local and remote GR families.
    /// Returns None if local_cap has no GR capability, the peer sent none,
    /// or if no families overlap.
    fn negotiate_gr(&self, remote_capabilities: &[packet::Capability]) -> Option<NegotiatedGr> {
        let (local_flags, local_families): (u8, Vec<Family>) =
            self.local_cap.iter().find_map(|c| match c {
                packet::Capability::GracefulRestart {
                    flags, families, ..
                } => Some((*flags, families.iter().map(|(f, _)| *f).collect())),
                _ => None,
            })?;

        let (peer_flags, peer_restart_time, peer_families) =
            remote_capabilities.iter().find_map(|c| match c {
                packet::Capability::GracefulRestart {
                    flags,
                    restart_time,
                    families,
                } => Some((*flags, *restart_time, families.as_slice())),
                _ => None,
            })?;

        let negotiated: Vec<Family> = local_families
            .into_iter()
            .filter(|f| peer_families.iter().any(|(pf, _)| pf == f))
            .collect();

        if negotiated.is_empty() {
            return None;
        }

        // N-bit (0x4): both sides must advertise it for RFC 8538 behavior.
        let notification_enabled = (local_flags & 0x4 != 0) && (peer_flags & 0x4 != 0);

        Some(NegotiatedGr {
            families: negotiated,
            restart_time: std::time::Duration::from_secs(peer_restart_time as u64),
            notification_enabled,
        })
    }

    async fn on_established(&mut self, local_sockaddr: SocketAddr, remote_sockaddr: SocketAddr) {
        let uptime = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.state.peer_up_at.store(uptime, Ordering::Relaxed);
        let remote_asn = self.state.remote_asn.load(Ordering::Relaxed);
        let router_id = Ipv4Addr::from(self.state.remote_id.load(Ordering::Relaxed));

        // Collect families up front so we don't borrow self.codec across .await.
        let families: Vec<Family> = self.codec.families_iter().collect();

        // Create one Source per negotiated family so GR can stale individual families.
        for family in &families {
            self.source.insert(
                *family,
                Arc::new(table::Source::new(
                    self.remote_addr,
                    self.export_ctx.local_addr,
                    remote_asn,
                    self.export_ctx.local_asn,
                    router_id,
                    self.export_ctx.role,
                )),
            );
        }

        let mut addpath = FnvHashSet::default();
        for family in &families {
            if let Some(s) = self.codec.family_state(*family) {
                if s.addpath_rx {
                    addpath.insert(*family);
                }
                self.pending
                    .insert(*family, crate::peer_tx::PendingTx::new(s.addpath_tx));
            }
        }

        let export_policy = self.tables.export_policy.load_full();
        let rpki = self.tables.rpki.read().unwrap();
        let peer_event_rx = self
            .tables
            .register_peer(self.remote_addr, addpath, |rtable| {
                for f in &families {
                    let effective_max =
                        conn_effective_max(&self.conn_arbiter.lock().unwrap(), Some(self.role), *f);
                    for change in rtable.collect_loc_rib_paths(f) {
                        let Some(pending) = self.pending.get_mut(&change.family) else {
                            continue;
                        };
                        process_nlri_change(
                            &change,
                            effective_max,
                            self.remote_addr,
                            &mut self.export_map,
                            pending,
                            &self.export_ctx,
                            export_policy.as_deref(),
                            self.cluster_id,
                            Some(&rpki),
                        );
                    }
                }
            });
        self.peer_event_rx = Some(UnboundedReceiverStream::new(peer_event_rx));
        let remote_holdtime = HoldTime::new(self.state.remote_holdtime.load(Ordering::Relaxed))
            .unwrap_or(HoldTime::DISABLED);
        self.tables.peer_up(PeerUpData {
            peer_addr: remote_sockaddr.ip(),
            peer_asn: remote_asn,
            peer_id: self.state.remote_id.load(Ordering::Relaxed),
            uptime,
            local_addr: self.export_ctx.local_addr,
            local_port: local_sockaddr.port(),
            remote_port: remote_sockaddr.port(),
            sent_open: bgp::Message::Open(bgp::Open {
                as_number: remote_asn,
                holdtime: remote_holdtime,
                router_id: self.state.remote_id.load(Ordering::Relaxed),
                capability: self.local_cap.to_owned(),
            }),
            received_open: bgp::Message::Open(bgp::Open {
                as_number: remote_asn,
                holdtime: remote_holdtime,
                router_id: self.state.remote_id.load(Ordering::Relaxed),
                // Safe to unwrap: called from on_established() where
                // remote_cap has just been set by apply_outputs().
                capability: self.state.remote_cap.load().as_deref().cloned().unwrap(),
            }),
        });
    }

    async fn do_route_refresh(&mut self, family: Family) {
        if !self.pending.contains_key(&family) {
            return;
        }
        let export_policy = self.tables.export_policy.load_full();
        let effective_max =
            conn_effective_max(&self.conn_arbiter.lock().unwrap(), Some(self.role), family);
        let changes = self.tables.collect_loc_rib_paths(family);
        let rpki = self.tables.rpki.read().unwrap();
        self.export_map.clear_family(family);
        for change in changes {
            let Some(pending) = self.pending.get_mut(&change.family) else {
                continue;
            };
            process_nlri_change(
                &change,
                effective_max,
                self.remote_addr,
                &mut self.export_map,
                pending,
                &self.export_ctx,
                export_policy.as_deref(),
                self.cluster_id,
                Some(&rpki),
            );
        }
        self.pending.get_mut(&family).unwrap().schedule_eor();
    }

    async fn apply_outputs(
        &mut self,
        outputs: Vec<crate::fsm::PeerFsmOutput>,
        local_sockaddr: SocketAddr,
        remote_sockaddr: SocketAddr,
    ) -> (Step, Vec<GlobalEffect>) {
        let mut effects = Vec::new();
        let mut down_reason = None;
        let mut notification: Option<bgp::Message> = None;
        for output in outputs {
            match output {
                crate::fsm::PeerFsmOutput::Connection(_, crate::fsm::Output::SendMessage(m)) => {
                    match &m {
                        bgp::Message::Notification(_) => {
                            notification = Some(m);
                        }
                        _ => self.ctrl_msgs.push(m),
                    }
                }
                crate::fsm::PeerFsmOutput::Connection(
                    _,
                    crate::fsm::Output::SetKeepaliveTimer(secs),
                ) => {
                    self.keepalive_futures = vec![tokio::time::sleep(Duration::from_secs(secs))]
                        .into_iter()
                        .collect();
                }
                crate::fsm::PeerFsmOutput::Connection(
                    _,
                    crate::fsm::Output::SetHoldTimer(secs),
                ) => {
                    self.holdtime_futures = vec![tokio::time::sleep(Duration::from_secs(secs))]
                        .into_iter()
                        .collect();
                }
                crate::fsm::PeerFsmOutput::Connection(
                    _,
                    crate::fsm::Output::SessionNegotiated(codec),
                ) => {
                    self.codec = codec;
                }
                crate::fsm::PeerFsmOutput::Connection(
                    _,
                    crate::fsm::Output::SessionEstablished {
                        remote_asn,
                        remote_id,
                        remote_holdtime,
                        remote_capabilities,
                    },
                ) => {
                    self.state.remote_asn.store(remote_asn, Ordering::Relaxed);
                    self.state.remote_id.store(remote_id, Ordering::Relaxed);
                    self.state
                        .remote_holdtime
                        .store(remote_holdtime, Ordering::Relaxed);

                    // Compute GR negotiation result before remote_capabilities
                    // is consumed by Arc::new below.
                    self.negotiated_gr = self.negotiate_gr(&remote_capabilities);
                    effects.push(GlobalEffect::GrSessionEstablished {
                        negotiated_gr: self.negotiated_gr.clone(),
                    });

                    self.state
                        .remote_cap
                        .store(Some(Arc::new(remote_capabilities)));
                    self.state.session_addrs.store(Some(Arc::new(SessionAddrs {
                        local: local_sockaddr,
                        remote_port: remote_sockaddr.port(),
                    })));
                    self.on_established(local_sockaddr, remote_sockaddr).await;
                }
                crate::fsm::PeerFsmOutput::Connection(
                    _,
                    crate::fsm::Output::SessionDown(reason),
                ) => {
                    self.state.session_addrs.store(None);
                    down_reason = Some(reason);
                }
                crate::fsm::PeerFsmOutput::Connection(_, crate::fsm::Output::StateChanged(s)) => {
                    self.state.fsm.store(u8::from(s), Ordering::Relaxed);
                }
                crate::fsm::PeerFsmOutput::Connection(
                    _,
                    crate::fsm::Output::RouteRefresh(family),
                ) => {
                    self.do_route_refresh(family).await;
                }
                crate::fsm::PeerFsmOutput::CloseConnection => {
                    down_reason = Some(crate::fsm::SessionDownReason::FsmError);
                }
                crate::fsm::PeerFsmOutput::StopActiveConnect => {
                    effects.push(GlobalEffect::StopActiveConnect);
                }
            }
        }
        if let Some(reason) = down_reason {
            (
                Step::Terminate {
                    reason,
                    notification,
                },
                effects,
            )
        } else {
            (Step::Continue, effects)
        }
    }

    async fn process_effects(&mut self, effects: Vec<GlobalEffect>, global: &GlobalHandle) {
        for effect in effects {
            match effect {
                GlobalEffect::StopActiveConnect => {
                    let mut ctx = self.context.lock().unwrap();
                    ctx.active_connect_cancel_tx.take();
                    ctx.active_connect_join_handle.take();
                }
                GlobalEffect::GrSessionEstablished { negotiated_gr } => {
                    let gr_families = negotiated_gr
                        .as_ref()
                        .map(|g| g.families.clone())
                        .unwrap_or_default();

                    // Cancel any previous restart timer (no ctx lock held across await).
                    {
                        let mut ctx = self.context.lock().unwrap();
                        ctx.cancel_gr_timer();
                    }

                    // Check global state to decide role: Restarting Speaker or Helper.
                    let (is_restarting, rd_outputs) = {
                        let mut server = global.write().await;
                        if let Some(rd) = &mut server.selection_deferral {
                            let out = rd.process(crate::gr::RestartingInput::PeerEstablished(
                                self.remote_addr,
                                gr_families.clone(),
                            ));
                            (true, out)
                        } else {
                            (false, vec![])
                        }
                    };

                    if is_restarting {
                        // Restarting Speaker: delegate EOR tracking to RestartingDeferral.
                        if let Some(dur) =
                            process_restarting_outputs(rd_outputs, global, &self.tables).await
                        {
                            let global_c = global.clone();
                            let tables_c = self.tables.clone();
                            let handle = tokio::spawn(async move {
                                tokio::time::sleep(dur).await;
                                gr_selection_deferral_timer_expired(global_c, tables_c).await;
                            })
                            .abort_handle();
                            global.write().await.selection_deferral_timer = Some(handle);
                        }
                    } else {
                        // Helper side: advance GrState (no deferral timer — restart timer
                        // started at session drop covers the full stale-route window).
                        let delete_families = {
                            let mut ctx = self.context.lock().unwrap();
                            let outputs = ctx
                                .gr_state
                                .process(crate::gr::GrInput::SessionEstablished { gr_families });
                            collect_delete_families(&outputs)
                        };
                        if !delete_families.is_empty() {
                            self.tables
                                .drop_stale_families(self.remote_addr, &delete_families);
                        }
                    }
                }
                GlobalEffect::GrEorReceived { family } => {
                    // Restarting Speaker path: feed into RestartingDeferral if active.
                    let rd_outputs = {
                        let mut server = global.write().await;
                        if let Some(rd) = &mut server.selection_deferral {
                            rd.process(crate::gr::RestartingInput::EorReceived(
                                self.remote_addr,
                                family,
                            ))
                        } else {
                            vec![]
                        }
                    };
                    // EorReceived never produces StartDeferralTimer.
                    let _ = process_restarting_outputs(rd_outputs, global, &self.tables).await;

                    // Helper side: GrState EOR handling (no-op when GrState is Idle).
                    let delete_families = {
                        let mut ctx = self.context.lock().unwrap();
                        let outputs = ctx
                            .gr_state
                            .process(crate::gr::GrInput::EorReceived(family));
                        collect_delete_families(&outputs)
                    };
                    if !delete_families.is_empty() {
                        self.tables
                            .drop_stale_families(self.remote_addr, &delete_families);
                    }
                }
            }
        }
    }

    // Returns false if a write error occurred; the caller must route
    // Input::Disconnected through the FSM in that case.
    async fn flush_tx(&mut self, stream: &mut TcpStream) -> bool {
        // 1. Flush control (open and keepalive) messages.
        let mut txbuf = bytes::BytesMut::with_capacity(self.txbuf_size);
        for _ in 0..self.ctrl_msgs.len() {
            let msg = self.ctrl_msgs.remove(0);
            let wire_count = self.codec.encode_to(&msg, &mut txbuf).unwrap_or(1);
            (*self.counter_tx).sync_tx(&msg, wire_count);

            if txbuf.len() > self.txbuf_size {
                let buf = txbuf.freeze();
                txbuf = bytes::BytesMut::with_capacity(self.txbuf_size);
                if stream.write_all(&buf).await.is_err() {
                    return false;
                }
            }
        }
        if !txbuf.is_empty() && stream.write_all(&txbuf.freeze()).await.is_err() {
            return false;
        }

        // 2. Drain pending updates (withdrawals, reach, EOR) via peer_tx.
        txbuf = bytes::BytesMut::with_capacity(self.txbuf_size);
        let any_update_pending = self.pending.values().any(|p| !p.is_empty());
        for (family, p) in self.pending.iter_mut() {
            for msg in p.drain_messages(*family) {
                let wire_count = self.codec.encode_to(&msg, &mut txbuf).unwrap_or(1);
                self.counter_tx.sync_tx(&msg, wire_count);

                if txbuf.len() > self.txbuf_size {
                    let buf = txbuf.freeze();
                    txbuf = bytes::BytesMut::with_capacity(self.txbuf_size);
                    if stream.write_all(&buf).await.is_err() {
                        return false;
                    }
                }
            }
        }
        if !txbuf.is_empty() && stream.write_all(&txbuf.freeze()).await.is_err() {
            return false;
        }
        if any_update_pending {
            let outputs = self
                .conn_arbiter
                .lock()
                .unwrap()
                .process(self.role, crate::fsm::Input::UpdateSent);
            for output in outputs {
                if let crate::fsm::PeerFsmOutput::Connection(
                    _,
                    crate::fsm::Output::SetKeepaliveTimer(secs),
                ) = output
                {
                    self.keepalive_futures = vec![tokio::time::sleep(Duration::from_secs(secs))]
                        .into_iter()
                        .collect();
                }
            }
        }
        true
    }

    /// Returns `true` if the per-peer prefix limit was exceeded (RFC 4486 §2).
    /// The caller must send a CEASE NOTIFICATION and close the session.
    async fn rx_update(
        &mut self,
        reach: Option<bgp::ReachNlri>,
        unreach: Option<packet::UnreachNlri>,
        attr: Arc<Vec<packet::Attribute>>,
        timestamp: std::time::SystemTime,
    ) -> bool {
        // RFC 4456 §8 loop detection: discard UPDATE if ORIGINATOR_ID equals
        // local router-id, or if CLUSTER_LIST already contains local cluster-id.
        if reach.is_some() {
            let local_rid = u32::from(self.local_router_id);
            let originator_loop = attr
                .iter()
                .find(|a| a.code() == packet::Attribute::ORIGINATOR_ID)
                .is_some_and(|a| a.value().unwrap_or(0) == local_rid);
            let cluster_loop = self.cluster_id.is_some_and(|cid| {
                let cid_bytes = u32::from(cid).to_be_bytes();
                attr.iter()
                    .find(|a| a.code() == packet::Attribute::CLUSTER_LIST)
                    .is_some_and(|a| {
                        a.binary()
                            .is_some_and(|b| b.chunks(4).any(|c| c == cid_bytes))
                    })
            });
            if originator_loop || cluster_loop {
                return false;
            }
        }
        // Inject default LOCAL_PREF for iBGP announcements that omit it.
        let attr = if reach.is_some()
            && matches!(
                self.export_ctx.role,
                PeerRole::Ibgp | PeerRole::IbgpRrClient
            ) {
            inject_local_pref_if_absent(attr)
        } else {
            attr
        };
        if let Some(s) = reach {
            let family = s.family;
            let nexthop = s.nexthop;
            let source = self.source[&family].clone();
            let prefix_limit = self
                .prefix_counters
                .get(&family)
                .map(|(max, counter)| (*max, Arc::clone(counter)));
            for net in s.entries {
                if self.tables.insert_route(
                    source.clone(),
                    family,
                    net,
                    nexthop,
                    attr.clone(),
                    prefix_limit.clone(),
                    timestamp,
                ) {
                    return true;
                }
            }
        }
        if let Some(s) = unreach {
            let family = s.family;
            let source = self.source[&family].clone();
            let prefix_counter = self
                .prefix_counters
                .get(&family)
                .map(|(_, counter)| Arc::clone(counter));
            for net in s.entries {
                self.tables.remove_route(
                    source.clone(),
                    family,
                    net,
                    prefix_counter.clone(),
                    timestamp,
                );
            }
        }
        false
    }

    fn handle_prefix_update(&mut self, update: table::NlriChange) {
        if self.conn_arbiter.lock().unwrap().state(self.role) != SessionState::Established {
            return;
        }
        if !self.codec.has_family(update.family) {
            return;
        }
        let effective_max = conn_effective_max(
            &self.conn_arbiter.lock().unwrap(),
            Some(self.role),
            update.family,
        );
        let Some(pending) = self.pending.get_mut(&update.family) else {
            return;
        };
        let export_policy = self.tables.export_policy.load_full();
        let rpki = self.tables.rpki.read().unwrap();
        process_nlri_change(
            &update,
            effective_max,
            self.remote_addr,
            &mut self.export_map,
            pending,
            &self.export_ctx,
            export_policy.as_deref(),
            self.cluster_id,
            Some(&rpki),
        );
    }

    async fn rx_msg(
        &mut self,
        global: &GlobalHandle,
        local_sockaddr: SocketAddr,
        remote_sockaddr: SocketAddr,
        msg: bgp::Message,
    ) -> Step {
        // Extract UPDATE fields before consuming msg into the FSM.
        let route_fields = match &msg {
            bgp::Message::Update(bgp::Update::Reach {
                family,
                entries,
                nexthop,
                attr,
            }) => Some((
                Some(packet::bgp::ReachNlri {
                    family: *family,
                    entries: entries.clone(),
                    nexthop: *nexthop,
                }),
                None,
                attr.clone(),
            )),
            bgp::Message::Update(bgp::Update::Unreach { family, entries }) => Some((
                None,
                Some(packet::UnreachNlri {
                    family: *family,
                    entries: entries.clone(),
                }),
                Arc::new(Vec::new()),
            )),
            _ => None,
        };
        let eor_family = if let bgp::Message::Update(bgp::Update::EndOfRib(f)) = &msg {
            Some(*f)
        } else {
            None
        };

        let outputs = self
            .conn_arbiter
            .lock()
            .unwrap()
            .process(self.role, crate::fsm::Input::MessageReceived(msg));
        let (step, effects) = self
            .apply_outputs(outputs, local_sockaddr, remote_sockaddr)
            .await;
        self.process_effects(effects, global).await;

        if matches!(step, Step::Terminate { .. }) {
            return step;
        }

        // For UPDATE Routes: if FSM didn't reject (no SessionDown), process routes.
        if let Some((reach, unreach, attr)) = route_fields {
            let rx_timestamp = std::time::SystemTime::now();
            if self.rx_update(reach, unreach, attr, rx_timestamp).await {
                let cease = bgp::Message::Notification(
                    rustybgp_packet::Notification::CeaseMaxPrefixReached,
                );
                return Step::Terminate {
                    reason: crate::fsm::SessionDownReason::LocalNotification(cease.clone()),
                    notification: Some(cease),
                };
            }
        }

        // For UPDATE EndOfRib: signal GR if negotiated.
        if let Some(family) = eor_family
            && self.negotiated_gr.is_some()
        {
            self.process_effects(vec![GlobalEffect::GrEorReceived { family }], global)
                .await;
        }
        Step::Continue
    }

    const RXBUF_SIZE: usize = 1 << 17;

    async fn run_select(
        &mut self,
        global: &GlobalHandle,
        stream: &mut TcpStream,
        rxbuf: &mut bytes::BytesMut,
        remote_sockaddr: SocketAddr,
        local_sockaddr: SocketAddr,
        mut close_rx: &mut CloseRxFuture,
    ) -> Step {
        let mut peer_event_next: futures::future::OptionFuture<_> = self
            .peer_event_rx
            .as_mut()
            .map(|rx| rx.next().fuse())
            .into();

        let interest = if self.ctrl_msgs.is_empty() {
            let mut interest = tokio::io::Interest::READABLE;
            for p in self.pending.values_mut() {
                if !p.is_empty() {
                    interest |= tokio::io::Interest::WRITABLE;
                    break;
                }
            }
            interest
        } else {
            tokio::io::Interest::READABLE | tokio::io::Interest::WRITABLE
        };

        futures::select_biased! {
            cease = close_rx => {
                match cease {
                    Some(Ok(CloseReason::AdminShutdown)) => {
                        let outputs = self.conn_arbiter.lock().unwrap().process(self.role, crate::fsm::Input::AdminShutdown);
                        let (step, effects) = self.apply_outputs(outputs, local_sockaddr, remote_sockaddr).await;
                        self.process_effects(effects, global).await;
                        if matches!(step, Step::Terminate { .. }) {
                            return step;
                        }
                    }
                    Some(Ok(CloseReason::SendMessage(msg))) => {
                        // Bypass FSM: NOTIFICATION content is pre-determined by
                        // the caller (collision subcode 7, peer delete subcode 3);
                        // Input::AdminShutdown would overwrite it with subcode 2.
                        return Step::Terminate { reason: crate::fsm::SessionDownReason::AdminShutdown, notification: Some(msg) };
                    }
                    Some(Ok(CloseReason::Silent)) => {
                        // Close TCP without sending a NOTIFICATION so the remote
                        // peer treats this as a GR restart event.
                        return Step::Terminate { reason: crate::fsm::SessionDownReason::AdminShutdown, notification: None };
                    }
                    _ => {}
                }
            }
            _ = self.holdtime_futures.next() => {
                log::warn!("{}: holdtime expired", self.remote_addr);
                let outputs = self.conn_arbiter.lock().unwrap().process(self.role, crate::fsm::Input::HoldTimerExpired);
                let (step, effects) = self.apply_outputs(outputs, local_sockaddr, remote_sockaddr).await;
                self.process_effects(effects, global).await;
                if matches!(step, Step::Terminate { .. }) {
                    return step;
                }
            }
            _ = self.keepalive_futures.next() => {
                let outputs = self.conn_arbiter.lock().unwrap().process(self.role, crate::fsm::Input::KeepaliveTimerExpired);
                let (step, effects) = self.apply_outputs(outputs, local_sockaddr, remote_sockaddr).await;
                self.process_effects(effects, global).await;
                if matches!(step, Step::Terminate { .. }) {
                    return step;
                }
            }
            msg = peer_event_next => {
                match msg {
                    Some(Some(ToPeerEvent::NlriChange(update))) => {
                        self.handle_prefix_update(update);
                    }
                    Some(Some(ToPeerEvent::SoftResetOut)) => {
                        // Re-advertise all current best paths to this peer.
                        // do_route_refresh() checks SessionState::Established
                        // internally, so if the session is down (e.g. GR
                        // helper mode) this is a safe no-op.
                        for family in self.pending.keys().cloned().collect::<Vec<_>>() {
                            self.do_route_refresh(family).await;
                        }
                    }
                    Some(None) => {
                        self.peer_event_rx = None;
                    }
                    _ => {}
                }
            }
            ready = stream.ready(interest).fuse() => {
                let ready = match ready {
                    Ok(ready) => ready,
                    Err(_) => return Step::Continue,
                };

                if ready.is_readable() {
                    rxbuf.reserve(PeerSession::RXBUF_SIZE);
                    match stream.try_read_buf(rxbuf) {
                        Ok(0) => {
                            let outputs = self.conn_arbiter.lock().unwrap().process(
                                self.role,
                                crate::fsm::Input::Disconnected,
                            );
                            let (step, effects) = self.apply_outputs(outputs, local_sockaddr, remote_sockaddr).await;
                            self.process_effects(effects, global).await;
                            if matches!(step, Step::Terminate { .. }) {
                                return step;
                            }
                        }
                        Ok(_) => loop {
                                match self.codec.try_parse(rxbuf) {
                                Ok(msg) => match msg {
                                    Some(parsed) => {
                                        // Count one wire frame before validate_message moves `parsed`.
                                        (*self.counter_rx).sync_rx(&parsed);
                                        let is_ebgp = matches!(self.export_ctx.role, PeerRole::Ebgp);
                                        match bgp::validate_message(parsed, is_ebgp) {
                                            Err(notif) => {
                                                return Step::Terminate {
                                                    reason: crate::fsm::SessionDownReason::LocalNotification(bgp::Message::Notification(notif.clone())),
                                                    notification: Some(bgp::Message::Notification(notif)),
                                                };
                                            }
                                            Ok(iter) => {
                                                for msg in iter {
                                                    if let bgp::Message::Update(bgp::Update::Reach { attr, .. }) = &msg
                                                        && is_as_loop(
                                                            attr,
                                                            self.export_ctx.local_asn,
                                                            self.export_ctx.confederation_id,
                                                        )
                                                    {
                                                        continue;
                                                    }
                                                    let step = self.rx_msg(global, local_sockaddr, remote_sockaddr, msg).await;
                                                    if matches!(step, Step::Terminate { .. }) {
                                                        return step;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    None => {
                                        // partial read
                                        break;
                                    },
                                }
                                Err(e) => {
                                    // Bypass FSM: Notification already encodes the
                                    // correct NOTIFICATION; the FSM has no
                                    // decision to make here.
                                    return Step::Terminate {
                                        reason: crate::fsm::SessionDownReason::LocalNotification(bgp::Message::Notification(e.clone())),
                                        notification: Some(bgp::Message::Notification(e)),
                                    };
                                },
                            }
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {},
                        Err(_e) => {
                            let outputs = self.conn_arbiter.lock().unwrap().process(
                                self.role,
                                crate::fsm::Input::Disconnected,
                            );
                            let (step, effects) = self.apply_outputs(outputs, local_sockaddr, remote_sockaddr).await;
                            self.process_effects(effects, global).await;
                            if matches!(step, Step::Terminate { .. }) {
                                return step;
                            }
                        }
                    }
                }

                if ready.is_writable()
                    && !self.flush_tx(stream).await
                {
                    let outputs = self.conn_arbiter.lock().unwrap().process(
                        self.role,
                        crate::fsm::Input::Disconnected,
                    );
                    let (step, effects) = self.apply_outputs(outputs, local_sockaddr, remote_sockaddr).await;
                    self.process_effects(effects, global).await;
                    if matches!(step, Step::Terminate { .. }) {
                        return step;
                    }
                }

            }
        }

        Step::Continue
    }

    async fn session_loop(&mut self, global: &GlobalHandle) -> DisconnectInfo {
        let mut disconnect = DisconnectInfo {
            role: self.role,
            remote_addr: self.remote_addr,
            export_map: ExportMap::new(),
            negotiated_gr: None,
        };
        let mut stream = self.stream.take().unwrap();
        let Ok(remote_sockaddr) = stream.peer_addr() else {
            return disconnect;
        };
        let Ok(local_sockaddr) = stream.local_addr() else {
            return disconnect;
        };

        // Kick off the OPEN exchange via the FSM.
        let outputs = self
            .conn_arbiter
            .lock()
            .unwrap()
            .process(self.role, crate::fsm::Input::Connected(self.is_restarting));
        let (_, effects) = self
            .apply_outputs(outputs, local_sockaddr, remote_sockaddr)
            .await;
        self.process_effects(effects, global).await;

        let mut rxbuf = bytes::BytesMut::with_capacity(PeerSession::RXBUF_SIZE);
        let mut close_rx: futures::future::OptionFuture<_> =
            self.close_rx.take().map(|rx| rx.fuse()).into();

        let reason = loop {
            match self
                .run_select(
                    global,
                    &mut stream,
                    &mut rxbuf,
                    remote_sockaddr,
                    local_sockaddr,
                    &mut close_rx,
                )
                .await
            {
                Step::Continue => {}
                Step::Terminate {
                    reason,
                    notification,
                } => {
                    if let Some(msg) = notification {
                        let mut txbuf = bytes::BytesMut::with_capacity(self.txbuf_size);
                        if self.codec.encode_to(&msg, &mut txbuf).is_ok()
                            && stream.write_all(&txbuf.freeze()).await.is_ok()
                        {
                            self.counter_tx.sync_tx(&msg, 1);
                        }
                    }
                    break reason;
                }
            }
        };

        let shutdown_reason = Some(reason);

        if !self.source.is_empty() {
            let drop_families =
                families_to_drop_on_disconnect(self.source.keys(), self.negotiated_gr.as_ref());
            let stale_families: Vec<Family> = self
                .negotiated_gr
                .as_ref()
                .map(|g| g.families.clone())
                .unwrap_or_default();
            // All per-family Sources share the same peer-level fields; use any for BMP.
            let any_source = self.source.values().next().unwrap().clone();
            let bmp_reason = crate::bmp::session_down_to_bmp(shutdown_reason.clone());
            self.peer_event_rx = None;
            self.tables
                .unregister_peer(self.remote_addr, &drop_families, &stale_families);
            self.tables.peer_down(PeerDownData {
                peer_addr: any_source.remote_addr,
                peer_asn: any_source.remote_asn,
                peer_id: any_source.router_id,
                uptime: self.state.peer_up_at.load(Ordering::Relaxed),
                reason: bmp_reason,
            });
        }
        disconnect.export_map = std::mem::take(&mut self.export_map);

        disconnect.negotiated_gr = self
            .negotiated_gr
            .take()
            .and_then(|gr| gr_on_disconnect(&shutdown_reason, gr));
        disconnect
    }

    async fn run(mut self, global: GlobalHandle, active_conn_tx: mpsc::UnboundedSender<TcpStream>) {
        let tables = self.tables.clone();
        let mut info = self.session_loop(&global).await;
        let remote_addr = info.remote_addr;

        // Suppress GR helper mode when the peer is admin-down: holding stale
        // routes for a peer that is intentionally disabled serves no purpose.
        if global
            .read()
            .await
            .peers
            .get(&remote_addr)
            .is_some_and(|p| p.admin_down)
        {
            info.negotiated_gr = None;
        }

        // Operate on PeerContext directly via self.context — no global lock needed
        // for the ctx-only operations.
        let no_sessions = apply_disconnect(&self.context, self.remote_addr, &tables, info).await;

        // Notify RestartingDeferral that this peer has disconnected, if active.
        let rd_outputs = {
            let mut server = global.write().await;
            if let Some(rd) = &mut server.selection_deferral {
                rd.process(crate::gr::RestartingInput::PeerWithdrawn(self.remote_addr))
            } else {
                vec![]
            }
        };
        // PeerWithdrawn never produces StartDeferralTimer.
        let _ = process_restarting_outputs(rd_outputs, &global, &tables).await;

        // Peer-level operations still require the global write lock.
        let mut server = global.write().await;
        if let Some(peer) = server.peers.get_mut(&remote_addr)
            && no_sessions
        {
            if peer.config.delete_on_disconnected {
                server.peers.remove(&remote_addr);
            } else {
                peer.clear_session_state();
                enable_active_connect(peer, active_conn_tx);
            }
        }
    }
}

/// Cleans up after a BGP session ends: updates the FSM slot, handles the GR
/// state machine, discards the session's export_map, and returns whether this
/// was the last active session for the peer.
///
/// Extracted from `PeerSession::run()` so that both GR and non-GR paths can
/// be tested without a live TCP connection.
async fn apply_disconnect(
    context: &Arc<std::sync::Mutex<PeerContext>>,
    remote_addr: IpAddr,
    tables: &TableHandle,
    info: DisconnectInfo,
) -> bool {
    let mut ctx = context.lock().unwrap();

    {
        let mut arb = ctx.conn_arbiter.lock().unwrap();
        match info.role {
            crate::fsm::Role::Active => {
                arb.active_close_tx = None;
                arb.active_join_handle = None;
            }
            crate::fsm::Role::Passive => {
                arb.passive_close_tx = None;
                arb.passive_join_handle = None;
            }
        }
        // Ensure the FSM slot is cleared regardless of how the session
        // ended.  Most paths (I/O errors, hold-timer, admin-shutdown) route
        // through the FSM and clear the slot via close_connection(); this
        // call is a fallback for paths that set self.shutdown directly
        // (LocalNotification, FsmError from parse, SendMessage cease).
        // If the slot is already None process() is a no-op.
        let _ = arb.process(info.role, crate::fsm::Input::Disconnected);
    }

    if let Some(gr) = &info.negotiated_gr {
        // GR active (we are the helper; the peer is the restarting speaker):
        // advance the GR state machine to arm the restart timer, then wait
        // for the peer to reconnect and re-send its routes.
        //
        // The peer crashed and its RIB is now empty.  When it reconnects it
        // must learn all routes from us again, so the next session must send
        // a full update -- exactly the same as a brand-new session.  Keeping
        // the old export_map would cause the new session to treat those routes
        // as "already sent" and skip re-advertising them to the peer, leaving
        // the peer with an incomplete RIB after recovery.  Drop it so that
        // the next session starts with a clean slate.
        //
        // The stale-route side (routes received FROM the peer) is handled
        // separately: MarkStale table events were already sent in
        // session_loop() under the same shard locks as peer_event_tx.remove(),
        // so no second pass over the table is needed here.
        ctx.cancel_gr_timer();

        let outputs = ctx.gr_state.process(crate::gr::GrInput::SessionDropped {
            families: gr.families.clone(),
            restart_time: gr.restart_time,
        });
        for output in &outputs {
            if let crate::gr::GrOutput::StartTimer(duration) = output {
                let dur = *duration;
                let context_c = Arc::clone(context);
                let tables_c = tables.clone();
                let (timer_tx, timer_rx) = tokio::sync::oneshot::channel::<()>();
                tokio::spawn(async move {
                    let run = match tokio::time::timeout(dur, timer_rx).await {
                        Err(_) | Ok(Ok(())) => true,
                        Ok(Err(_)) => false,
                    };
                    if run {
                        gr_restart_timer_expired(context_c, tables_c, remote_addr).await;
                    }
                });
                ctx.gr_restart_timer = Some(timer_tx);
            }
        }
        drop(info.export_map);
    } else {
        // Normal disconnect (no GR): the peer's routes were already removed
        // from the RIB in session_loop().  The next session must also send a
        // full update, so the export_map is discarded here and the next
        // session starts with an empty one.  Clean up any leftover GR state
        // from a previous cycle that never recovered.
        ctx.cancel_gr_timer();
        drop(info.export_map);
    }

    // Only reset and reconnect when no PeerSession remains for this peer.
    let arb = ctx.conn_arbiter.lock().unwrap();
    arb.active_close_tx.is_none() && arb.passive_close_tx.is_none()
}

/// Build reflected attribute set for an RR (RFC 4456 §8).
///
/// Sets ORIGINATOR_ID to `source_router_id` if absent, and prepends
/// `cluster_id` to CLUSTER_LIST (creating the attribute if absent).
fn rr_reflect_attrs(
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

/// Return `true` when the incoming UPDATE contains the local AS (or confederation
/// identifier) in AS_PATH, indicating a routing loop (RFC 4271 §9.1.2).
/// Applies only to route announcements; `confederation_id` of 0 disables the
/// confederation check.
fn is_as_loop(attr: &Arc<Vec<bgp::Attribute>>, local_asn: u32, confederation_id: u32) -> bool {
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
fn inject_local_pref_if_absent(attr: Arc<Vec<packet::Attribute>>) -> Arc<Vec<packet::Attribute>> {
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
fn is_ibgp_learned(source: &table::Source) -> bool {
    !source.is_local() && source.remote_asn == source.local_asn
}

/// iBGP split-horizon check for a single path.
///
/// Returns `true` when the path should be suppressed (not sent to `dest_role`).
/// In plain iBGP mode (`cluster_id` is None) all iBGP-learned paths are
/// suppressed.  In RR mode only non-client -> non-client is suppressed.
fn rs_isolation_suppress(source: &table::Source, dest_role: PeerRole) -> bool {
    // RS-client routes must not reach non-RS-client peers, and vice versa.
    source.is_rs_client() != matches!(dest_role, PeerRole::RsClient)
}

fn ibgp_split_horizon_suppress(
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

/// Abstraction over the output of `process_nlri_change()`.
///
/// `PendingTx` implements this for the normal send path.  `AdjOutSink`
/// implements it to collect a snapshot for adj-out display without sending.
pub(crate) trait NlriSink {
    fn reach(
        &mut self,
        nlri: packet::Nlri,
        path_id: u32,
        nexthop: Option<bgp::Nexthop>,
        attr: Arc<Vec<packet::Attribute>>,
        source: &Arc<table::Source>,
    );
    fn unreach(&mut self, nlri: packet::Nlri, path_id: u32);
}

impl NlriSink for crate::peer_tx::PendingTx {
    fn reach(
        &mut self,
        nlri: packet::Nlri,
        path_id: u32,
        nexthop: Option<bgp::Nexthop>,
        attr: Arc<Vec<packet::Attribute>>,
        _source: &Arc<table::Source>,
    ) {
        crate::peer_tx::PendingTx::reach(self, nlri, path_id, nexthop, attr);
    }
    fn unreach(&mut self, nlri: packet::Nlri, path_id: u32) {
        crate::peer_tx::PendingTx::unreach(self, nlri, path_id);
    }
}

/// `NlriSink` that collects adj-out paths for display.
///
/// Uses a fresh `ExportMap` (empty = nothing previously sent), so
/// `process_nlri_change()` treats every visible path as new and calls
/// `reach()` for each one; `unreach()` is never called.
#[derive(Default)]
struct AdjOutSink {
    destinations: Vec<table::DestinationEntry>,
    /// net -> index into `destinations` for O(1) lookup on duplicate nets.
    index: FnvHashMap<packet::Nlri, usize>,
}

impl NlriSink for AdjOutSink {
    fn reach(
        &mut self,
        nlri: packet::Nlri,
        _path_id: u32,
        _nexthop: Option<bgp::Nexthop>,
        attr: Arc<Vec<packet::Attribute>>,
        source: &Arc<table::Source>,
    ) {
        let entry = table::PathEntry {
            source: Arc::clone(source),
            remote_path_id: 0,
            timestamp: std::time::SystemTime::UNIX_EPOCH,
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

    fn unreach(&mut self, _nlri: packet::Nlri, _path_id: u32) {
        // Snapshot mode: ExportMap is always empty so this is never called.
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
fn process_nlri_change<S: NlriSink>(
    update: &table::NlriChange,
    effective_max: usize,
    remote_addr: IpAddr,
    export_map: &mut ExportMap,
    sink: &mut S,
    export_ctx: &PeerExportContext,
    export_policy: Option<&table::PolicyAssignment>,
    cluster_id: Option<Ipv4Addr>,
    rpki: Option<&table::RpkiTable>,
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
        // Apply export policy to the visible best; a rejected best is treated
        // as if no best exists (withdraw if previously advertised).
        let policy_result = visible_best.and_then(|best| {
            let mut nexthop = best.nexthop;
            let mut attr = Arc::clone(&best.attr);
            if export_policy.is_some_and(|policy| {
                table::apply_export(
                    policy,
                    rpki,
                    &best.source,
                    &update.net,
                    &mut attr,
                    &mut nexthop,
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
                if export_map.was_sent(update.family, &update.net) {
                    export_map.mark_withdrawn(update.family, &update.net, 0);
                    sink.unreach(update.net.clone(), 0);
                }
            }
            Some((best, attr, nexthop)) => {
                export_map.mark_sent(update.family, update.net.clone(), 0);
                let attr = export_ctx.export_attrs(&attr);
                let nexthop = export_ctx.export_nexthop(nexthop);
                sink.reach(update.net.clone(), 0, nexthop, attr, &best.source);
            }
        }
    } else {
        // Add-Path: compare current_paths[..effective_max] vs export_map.
        if !update.any_changed {
            return;
        }
        // Build the effective top-N after echo prevention, split horizon, and
        // export policy.  Store post-policy (attr, nexthop) so that
        // export_attrs/export_nexthop can be applied in one step below.
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
                let mut nexthop = path.nexthop;
                let mut attr = Arc::clone(&path.attr);
                if export_policy.is_some_and(|policy| {
                    table::apply_export(
                        policy,
                        rpki,
                        &path.source,
                        &update.net,
                        &mut attr,
                        &mut nexthop,
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
                Some((path.local_path_id, attr, nexthop, Arc::clone(&path.source)))
            })
            .collect();

        // Withdraw paths that were sent but are no longer in top-N
        // (including paths pushed out by send_max boundary or policy).
        let sent_ids = export_map.sent_path_ids(update.family, &update.net);
        let current_ids: FnvHashSet<u32> =
            current_top_n.iter().map(|(pid, _, _, _)| *pid).collect();
        for &pid in sent_ids.difference(&current_ids) {
            export_map.mark_withdrawn(update.family, &update.net, pid);
            sink.unreach(update.net.clone(), pid);
        }

        // Advertise paths that are new or whose attributes were replaced.
        for (pid, attr, nexthop, source) in &current_top_n {
            let already_sent = export_map.contains_path(update.family, &update.net, *pid);
            let was_replaced = update.replaced_path_id == Some(*pid);
            if !already_sent || was_replaced {
                export_map.mark_sent(update.family, update.net.clone(), *pid);
                let attr = export_ctx.export_attrs(attr);
                let nexthop = export_ctx.export_nexthop(*nexthop);
                sink.reach(update.net.clone(), *pid, nexthop, attr, source);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn make_global() -> GlobalHandle {
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut g = Global::new(tx);
        g.asn = 65001;
        g.router_id = Ipv4Addr::new(1, 0, 0, 1);
        Arc::new(tokio::sync::RwLock::new(g))
    }

    fn make_tables() -> TableHandle {
        Arc::new(TableManager::new(1))
    }

    fn default_peer_params(remote_addr: IpAddr) -> PeerParams {
        PeerParams {
            remote_addr,
            remote_port: Global::BGP_PORT,
            expected_remote_asn: 0,
            local_asn: 0,
            passive: false,
            rs_client: false,
            route_reflector: RouteReflectorConfig::default(),
            delete_on_disconnected: false,
            admin_down: false,
            state: SessionState::Idle,
            holdtime: PeerParams::DEFAULT_HOLD_TIME,
            connect_retry_time: PeerParams::DEFAULT_CONNECT_RETRY_TIME,
            multihop_ttl: None,
            ttl_security: None,
            password: None,
            families: FnvHashMap::default(),
            send_max: FnvHashMap::default(),
            prefix_limits: FnvHashMap::default(),
            graceful_restart: None,
        }
    }

    /// Returns (client_stream, server_stream) connected over loopback.
    /// Pass `server_stream` to `accept_connection`; `remote_addr` is
    /// `client_stream.local_addr().ip()`.
    async fn loopback_pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, server) =
            tokio::join!(tokio::net::TcpStream::connect(addr), listener.accept(),);
        (client.unwrap(), server.unwrap().0)
    }

    #[tokio::test]
    async fn accept_known_peer_passive() {
        let global = make_global();
        let tables = make_tables();
        let (client, server) = loopback_pair().await;
        let remote_addr = client.local_addr().unwrap().ip();

        {
            let mut g = global.write().await;
            g.add_peer(default_peer_params(remote_addr), None).unwrap();
        }

        let h = accept_connection(&global, &tables, server, crate::fsm::Role::Passive).await;
        assert!(h.is_some());

        let g = global.read().await;
        let peer = g.peers.get(&remote_addr).unwrap();
        assert_eq!(
            peer.state.fsm.load(Ordering::Relaxed),
            SessionState::Active as u8
        );
        assert!(
            peer.context
                .lock()
                .unwrap()
                .conn_arbiter
                .lock()
                .unwrap()
                .passive_close_tx
                .is_some()
        );
    }

    #[tokio::test]
    async fn accept_known_peer_active() {
        let global = make_global();
        let tables = make_tables();
        let (client, server) = loopback_pair().await;
        let remote_addr = client.local_addr().unwrap().ip();

        {
            let mut g = global.write().await;
            g.add_peer(default_peer_params(remote_addr), None).unwrap();
        }

        let h = accept_connection(&global, &tables, server, crate::fsm::Role::Active).await;
        assert!(h.is_some());

        let g = global.read().await;
        let peer = g.peers.get(&remote_addr).unwrap();
        assert!(
            peer.context
                .lock()
                .unwrap()
                .conn_arbiter
                .lock()
                .unwrap()
                .active_close_tx
                .is_some()
        );
    }

    #[tokio::test]
    async fn accept_admin_down_peer_rejected() {
        let global = make_global();
        let tables = make_tables();
        let (client, server) = loopback_pair().await;
        let remote_addr = client.local_addr().unwrap().ip();

        {
            let mut g = global.write().await;
            g.add_peer(
                PeerParams {
                    admin_down: true,
                    ..default_peer_params(remote_addr)
                },
                None,
            )
            .unwrap();
        }

        let h = accept_connection(&global, &tables, server, crate::fsm::Role::Passive).await;
        assert!(h.is_none());
    }

    #[tokio::test]
    async fn accept_already_connected_peer_rejected() {
        let global = make_global();
        let tables = make_tables();
        let (client, server) = loopback_pair().await;
        let remote_addr = client.local_addr().unwrap().ip();

        {
            let mut g = global.write().await;
            g.add_peer(default_peer_params(remote_addr), None).unwrap();
            let (tx, _rx) = tokio::sync::oneshot::channel::<CloseReason>();
            g.peers
                .get_mut(&remote_addr)
                .unwrap()
                .context
                .lock()
                .unwrap()
                .conn_arbiter
                .lock()
                .unwrap()
                .passive_close_tx = Some(tx);
        }

        let h = accept_connection(&global, &tables, server, crate::fsm::Role::Passive).await;
        assert!(h.is_none());
    }

    #[tokio::test]
    async fn accept_unknown_peer_no_dynamic_config_rejected() {
        let global = make_global();
        let tables = make_tables();
        let (_client, server) = loopback_pair().await;

        let h = accept_connection(&global, &tables, server, crate::fsm::Role::Passive).await;
        assert!(h.is_none());
    }

    // --- Confederation tests ---

    #[test]
    fn confederation_api_parses_id_and_members() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut g = Global::new(tx);
        g.asn = 65001;
        let conf = api::Confederation {
            enabled: true,
            identifier: 65000,
            member_as_list: vec![65001, 65002, 65003],
        };
        if let Some(c) = Some(conf).filter(|c| c.enabled && c.identifier != 0) {
            g.confederation = Some(ConfederationConfig {
                id: c.identifier,
                members: c.member_as_list.into_iter().collect(),
            });
        }
        let conf = g.confederation.as_ref().unwrap();
        assert_eq!(conf.id, 65000);
        assert!(conf.members.contains(&65001));
        assert!(conf.members.contains(&65002));
        assert!(conf.members.contains(&65003));
    }

    #[test]
    fn confederation_api_disabled_flag_ignored() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut g = Global::new(tx);
        g.asn = 65001;
        let conf = api::Confederation {
            enabled: false,
            identifier: 65000,
            member_as_list: vec![65002],
        };
        if let Some(c) = Some(conf).filter(|c| c.enabled && c.identifier != 0) {
            g.confederation = Some(ConfederationConfig {
                id: c.identifier,
                members: c.member_as_list.into_iter().collect(),
            });
        }
        assert!(g.confederation.is_none());
    }

    #[test]
    fn confederation_yaml_parses_id_and_members() {
        let conf_config = config::generate::ConfederationConfig {
            enabled: Some(true),
            identifier: Some(65000),
            member_as_list: Some(vec![65001, 65002]),
        };
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut g = Global::new(tx);
        g.asn = 65001;
        if let Some((id, c)) = conf_config
            .enabled
            .filter(|&e| e)
            .and(conf_config.identifier.filter(|&id| id != 0))
            .map(|id| (id, &conf_config))
        {
            g.confederation = Some(ConfederationConfig {
                id,
                members: c
                    .member_as_list
                    .as_deref()
                    .unwrap_or(&[])
                    .iter()
                    .copied()
                    .collect(),
            });
        }
        let conf = g.confederation.as_ref().unwrap();
        assert_eq!(conf.id, 65000);
        assert!(conf.members.contains(&65001));
        assert!(conf.members.contains(&65002));
    }

    #[tokio::test]
    async fn accept_confed_ebgp_peer_gets_confed_role() {
        let global = make_global();
        let tables = make_tables();
        let (client, server) = loopback_pair().await;
        let remote_addr = client.local_addr().unwrap().ip();

        {
            let mut g = global.write().await;
            g.confederation = Some(ConfederationConfig {
                id: 65000,
                members: [65002].into_iter().collect(),
            });
            g.add_peer(
                PeerParams {
                    expected_remote_asn: 65002,
                    local_asn: 65001,
                    ..default_peer_params(remote_addr)
                },
                None,
            )
            .unwrap();
        }

        let session = accept_connection(&global, &tables, server, crate::fsm::Role::Passive).await;
        assert!(session.is_some());
        assert_eq!(
            session.unwrap().export_ctx.role,
            PeerRole::ConfedEbgp,
            "peer in confederation member AS must get ConfedEbgp role"
        );
    }

    #[tokio::test]
    async fn accept_non_member_peer_gets_ebgp_role() {
        let global = make_global();
        let tables = make_tables();
        let (client, server) = loopback_pair().await;
        let remote_addr = client.local_addr().unwrap().ip();

        {
            let mut g = global.write().await;
            g.confederation = Some(ConfederationConfig {
                id: 65000,
                members: [65002].into_iter().collect(),
            });
            g.add_peer(
                PeerParams {
                    expected_remote_asn: 65099,
                    local_asn: 65001,
                    ..default_peer_params(remote_addr)
                },
                None,
            )
            .unwrap();
        }

        let session = accept_connection(&global, &tables, server, crate::fsm::Role::Passive).await;
        assert!(session.is_some());
        assert_eq!(
            session.unwrap().export_ctx.role,
            PeerRole::Ebgp,
            "peer outside confederation must remain Ebgp"
        );
    }

    #[test]
    fn external_peer_gets_confederation_id_as_local_asn() {
        // RFC 5065 §4: OPEN my_as for non-member peers must be confederation id.
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut g = Global::new(tx);
        g.asn = 65001;
        g.router_id = Ipv4Addr::new(1, 0, 0, 1);
        g.confederation = Some(ConfederationConfig {
            id: 65000,
            members: [65001, 65002].into_iter().collect(),
        });
        let addr: IpAddr = "127.0.0.1".parse().unwrap();
        g.add_peer(
            PeerParams {
                expected_remote_asn: 65100,
                ..default_peer_params(addr)
            },
            None,
        )
        .unwrap();
        let peer = g.peers.get(&addr).unwrap();
        assert_eq!(
            peer.config.local_asn, 65000,
            "external peer must advertise confederation id in OPEN"
        );
    }

    #[tokio::test]
    async fn accept_dynamic_peer_added() {
        let global = make_global();
        let tables = make_tables();
        let (client, server) = loopback_pair().await;
        let remote_addr = client.local_addr().unwrap().ip();

        {
            let mut g = global.write().await;
            g.peer_group.insert(
                "test-group".to_string(),
                PeerGroup {
                    as_number: 65002,
                    dynamic_peers: vec![DynamicPeer {
                        prefix: packet::IpNet::new(remote_addr, 32),
                    }],
                    route_server_client: false,
                    holdtime: None,
                    local_asn: 0,
                    passive: false,
                    route_reflector: RouteReflectorConfig::default(),
                    multihop_ttl: None,
                    ttl_security: None,
                    auth_password: None,
                    connect_retry_time: None,
                    families: FnvHashMap::default(),
                    send_max: FnvHashMap::default(),
                    graceful_restart: None,
                },
            );
        }

        let h = accept_connection(&global, &tables, server, crate::fsm::Role::Passive).await;
        assert!(h.is_some());

        let g = global.read().await;
        assert!(g.peers.contains_key(&remote_addr));
        let peer = g.peers.get(&remote_addr).unwrap();
        assert!(peer.config.delete_on_disconnected);
    }

    #[tokio::test]
    async fn dynamic_peer_inherits_all_group_fields() {
        let global = make_global();
        let tables = make_tables();
        let (client, server) = loopback_pair().await;
        let remote_addr = client.local_addr().unwrap().ip();
        let cluster_id: Ipv4Addr = "1.2.3.4".parse().unwrap();

        {
            let mut g = global.write().await;
            g.peer_group.insert(
                "full-group".to_string(),
                PeerGroup {
                    as_number: 65002,
                    dynamic_peers: vec![DynamicPeer {
                        prefix: packet::IpNet::new(remote_addr, 32),
                    }],
                    route_server_client: false,
                    holdtime: Some(90),
                    local_asn: 65001,
                    passive: true,
                    route_reflector: RouteReflectorConfig {
                        route_reflector_client: true,
                        route_reflector_cluster_id: Some(cluster_id),
                    },
                    multihop_ttl: Some(5),
                    ttl_security: None,
                    auth_password: Some("secret".to_string()),
                    connect_retry_time: Some(30),
                    families: FnvHashMap::default(),
                    send_max: FnvHashMap::default(),
                    graceful_restart: None,
                },
            );
        }

        let h = accept_connection(&global, &tables, server, crate::fsm::Role::Passive).await;
        assert!(h.is_some());

        let g = global.read().await;
        let peer = g.peers.get(&remote_addr).unwrap();
        assert_eq!(peer.config.expected_remote_asn, 65002);
        assert_eq!(peer.config.local_asn, 65001);
        assert!(peer.config.passive);
        assert!(peer.config.route_reflector.route_reflector_client);
        assert_eq!(
            peer.config.route_reflector.route_reflector_cluster_id,
            Some(cluster_id)
        );
        assert_eq!(peer.config.multihop_ttl, Some(5));
        assert_eq!(peer.config.password, Some("secret".to_string()));
        assert_eq!(peer.config.holdtime, 90);
        assert_eq!(peer.config.connect_retry_time, 30);
        assert!(peer.config.delete_on_disconnected);
    }

    // --- PeerGroup gRPC round-trip tests ---

    fn make_full_api_peer_group(name: &str) -> api::PeerGroup {
        api::PeerGroup {
            conf: Some(api::PeerGroupConf {
                peer_group_name: name.to_string(),
                peer_asn: 65002,
                local_asn: 65001,
                auth_password: "secret".to_string(),
                ..Default::default()
            }),
            timers: Some(api::Timers {
                config: Some(api::TimersConfig {
                    hold_time: 90,
                    connect_retry: 30,
                    ..Default::default()
                }),
                ..Default::default()
            }),
            route_server: Some(api::RouteServer {
                route_server_client: false,
                ..Default::default()
            }),
            transport: Some(api::Transport {
                passive_mode: true,
                ..Default::default()
            }),
            route_reflector: Some(api::RouteReflector {
                route_reflector_client: true,
                route_reflector_cluster_id: "1.2.3.4".to_string(),
            }),
            ebgp_multihop: Some(api::EbgpMultihop {
                enabled: true,
                multihop_ttl: 5,
            }),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn peer_group_grpc_roundtrip_all_fields() {
        let svc = make_grpc_service();
        let pg = make_full_api_peer_group("grp");
        svc.add_peer_group(tonic::Request::new(api::AddPeerGroupRequest {
            peer_group: Some(pg),
        }))
        .await
        .unwrap();

        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        svc.list_peer_group(tonic::Request::new(api::ListPeerGroupRequest {
            peer_group_name: "grp".to_string(),
        }))
        .await
        .unwrap()
        .into_inner()
        .for_each(|r| {
            let tx = tx.clone();
            async move {
                let _ = tx.send(r.unwrap().peer_group.unwrap()).await;
            }
        })
        .await;

        let got = rx.recv().await.unwrap();
        let conf = got.conf.as_ref().unwrap();
        assert_eq!(conf.peer_asn, 65002);
        assert_eq!(conf.local_asn, 65001);
        assert_eq!(conf.auth_password, "secret");
        let tc = got.timers.as_ref().unwrap().config.as_ref().unwrap();
        assert_eq!(tc.hold_time, 90);
        assert_eq!(tc.connect_retry, 30);
        assert!(got.transport.as_ref().unwrap().passive_mode);
        let rr = got.route_reflector.as_ref().unwrap();
        assert!(rr.route_reflector_client);
        assert_eq!(rr.route_reflector_cluster_id, "1.2.3.4");
        let mh = got.ebgp_multihop.as_ref().unwrap();
        assert!(mh.enabled);
        assert_eq!(mh.multihop_ttl, 5);
    }

    #[tokio::test]
    async fn peer_group_grpc_update_all_fields() {
        let svc = make_grpc_service();

        // Add with initial values.
        svc.add_peer_group(tonic::Request::new(api::AddPeerGroupRequest {
            peer_group: Some(make_full_api_peer_group("grp")),
        }))
        .await
        .unwrap();

        // Update with new values.
        let updated = api::PeerGroup {
            conf: Some(api::PeerGroupConf {
                peer_group_name: "grp".to_string(),
                peer_asn: 65003,
                local_asn: 65004,
                auth_password: "new-secret".to_string(),
                ..Default::default()
            }),
            timers: Some(api::Timers {
                config: Some(api::TimersConfig {
                    hold_time: 120,
                    connect_retry: 60,
                    ..Default::default()
                }),
                ..Default::default()
            }),
            transport: Some(api::Transport {
                passive_mode: false,
                ..Default::default()
            }),
            ebgp_multihop: Some(api::EbgpMultihop {
                enabled: true,
                multihop_ttl: 10,
            }),
            ..Default::default()
        };
        svc.update_peer_group(tonic::Request::new(api::UpdatePeerGroupRequest {
            peer_group: Some(updated),
            ..Default::default()
        }))
        .await
        .unwrap();

        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        svc.list_peer_group(tonic::Request::new(api::ListPeerGroupRequest {
            peer_group_name: "grp".to_string(),
        }))
        .await
        .unwrap()
        .into_inner()
        .for_each(|r| {
            let tx = tx.clone();
            async move {
                let _ = tx.send(r.unwrap().peer_group.unwrap()).await;
            }
        })
        .await;

        let got = rx.recv().await.unwrap();
        let conf = got.conf.as_ref().unwrap();
        assert_eq!(conf.peer_asn, 65003);
        assert_eq!(conf.local_asn, 65004);
        assert_eq!(conf.auth_password, "new-secret");
        let tc = got.timers.as_ref().unwrap().config.as_ref().unwrap();
        assert_eq!(tc.hold_time, 120);
        assert_eq!(tc.connect_retry, 60);
        assert!(
            !got.transport
                .as_ref()
                .map(|t| t.passive_mode)
                .unwrap_or(false)
        );
        let mh = got.ebgp_multihop.as_ref().unwrap();
        assert_eq!(mh.multihop_ttl, 10);
    }

    // --- PeerGroup YAML parsing tests ---

    fn make_yaml_peer_group() -> config::PeerGroup {
        config::PeerGroup {
            config: Some(config::PeerGroupConfig {
                peer_group_name: Some("yaml-grp".to_string()),
                peer_as: Some(65002),
                local_as: Some(65001),
                auth_password: Some("yaml-secret".to_string()),
                ..Default::default()
            }),
            timers: Some(config::Timers {
                config: Some(config::TimersConfig {
                    hold_time: Some(90.0),
                    connect_retry: Some(30.0),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            transport: Some(config::Transport {
                config: Some(config::TransportConfig {
                    passive_mode: Some(true),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            route_reflector: Some(config::RouteReflector {
                config: Some(config::RouteReflectorConfig {
                    route_reflector_client: Some(true),
                    route_reflector_cluster_id: Some("1.2.3.4".to_string()),
                }),
                ..Default::default()
            }),
            ebgp_multihop: Some(config::EbgpMultihop {
                config: Some(config::EbgpMultihopConfig {
                    enabled: Some(true),
                    multihop_ttl: Some(5),
                }),
                ..Default::default()
            }),
            route_server: Some(config::RouteServer {
                config: Some(config::RouteServerConfig {
                    route_server_client: Some(false),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn peer_group_yaml_parses_all_fields() {
        let pg = PeerGroup::from_yaml(&make_yaml_peer_group());
        assert_eq!(pg.as_number, 65002);
        assert_eq!(pg.local_asn, 65001);
        assert_eq!(pg.auth_password, Some("yaml-secret".to_string()));
        assert_eq!(pg.holdtime, Some(90));
        assert_eq!(pg.connect_retry_time, Some(30));
        assert!(pg.passive);
        assert!(pg.route_reflector.route_reflector_client);
        assert_eq!(
            pg.route_reflector.route_reflector_cluster_id,
            Some("1.2.3.4".parse().unwrap())
        );
        assert_eq!(pg.multihop_ttl, Some(5));
    }

    #[test]
    fn peer_group_yaml_empty_password_becomes_none() {
        let yaml_pg = config::PeerGroup {
            config: Some(config::PeerGroupConfig {
                peer_group_name: Some("g".to_string()),
                auth_password: Some(String::new()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let pg = PeerGroup::from_yaml(&yaml_pg);
        assert!(pg.auth_password.is_none());
    }

    #[test]
    fn peer_group_yaml_multihop_disabled_yields_none() {
        let yaml_pg = config::PeerGroup {
            config: Some(config::PeerGroupConfig {
                peer_group_name: Some("g".to_string()),
                ..Default::default()
            }),
            ebgp_multihop: Some(config::EbgpMultihop {
                config: Some(config::EbgpMultihopConfig {
                    enabled: Some(false),
                    multihop_ttl: Some(5),
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let pg = PeerGroup::from_yaml(&yaml_pg);
        assert!(pg.multihop_ttl.is_none());
    }

    // --- PeerGroup families tests ---

    fn make_api_peer_group_with_families(name: &str) -> api::PeerGroup {
        api::PeerGroup {
            conf: Some(api::PeerGroupConf {
                peer_group_name: name.to_string(),
                peer_asn: 65002,
                ..Default::default()
            }),
            afi_safis: vec![
                api::AfiSafi {
                    config: Some(api::AfiSafiConfig {
                        family: Some(api::Family {
                            afi: api::family::Afi::Ip as i32,
                            safi: api::family::Safi::Unicast as i32,
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                api::AfiSafi {
                    config: Some(api::AfiSafiConfig {
                        family: Some(api::Family {
                            afi: api::family::Afi::Ip6 as i32,
                            safi: api::family::Safi::Unicast as i32,
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            ],
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn peer_group_grpc_families_roundtrip() {
        let svc = make_grpc_service();
        svc.add_peer_group(tonic::Request::new(api::AddPeerGroupRequest {
            peer_group: Some(make_api_peer_group_with_families("grp")),
        }))
        .await
        .unwrap();

        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        svc.list_peer_group(tonic::Request::new(api::ListPeerGroupRequest {
            peer_group_name: "grp".to_string(),
        }))
        .await
        .unwrap()
        .into_inner()
        .for_each(|r| {
            let tx = tx.clone();
            async move {
                let _ = tx.send(r.unwrap().peer_group.unwrap()).await;
            }
        })
        .await;

        let got = rx.recv().await.unwrap();
        assert_eq!(got.afi_safis.len(), 2);
        let afis: Vec<i32> = got
            .afi_safis
            .iter()
            .map(|a| a.config.as_ref().unwrap().family.as_ref().unwrap().afi)
            .collect();
        assert!(afis.contains(&(api::family::Afi::Ip as i32)));
        assert!(afis.contains(&(api::family::Afi::Ip6 as i32)));
    }

    #[test]
    fn peer_group_yaml_families_parsed() {
        let yaml_pg = config::PeerGroup {
            config: Some(config::PeerGroupConfig {
                peer_group_name: Some("g".to_string()),
                ..Default::default()
            }),
            afi_safis: Some(vec![
                config::AfiSafi {
                    config: Some(config::AfiSafiConfig {
                        afi_safi_name: Some(config::AfiSafiType::Ipv4Unicast),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                config::AfiSafi {
                    config: Some(config::AfiSafiConfig {
                        afi_safi_name: Some(config::AfiSafiType::Ipv6Unicast),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            ]),
            ..Default::default()
        };
        let pg = PeerGroup::from_yaml(&yaml_pg);
        assert_eq!(pg.families.len(), 2);
        assert!(pg.families.contains_key(&Family::IPV4));
        assert!(pg.families.contains_key(&Family::IPV6));
        assert!(pg.send_max.is_empty());
    }

    #[test]
    fn peer_group_yaml_addpath_send_max_parsed() {
        let yaml_pg = config::PeerGroup {
            config: Some(config::PeerGroupConfig {
                peer_group_name: Some("g".to_string()),
                ..Default::default()
            }),
            afi_safis: Some(vec![config::AfiSafi {
                config: Some(config::AfiSafiConfig {
                    afi_safi_name: Some(config::AfiSafiType::Ipv4Unicast),
                    ..Default::default()
                }),
                add_paths: Some(config::AddPaths {
                    config: Some(config::AddPathsConfig {
                        receive: Some(true),
                        send_max: Some(4),
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }]),
            ..Default::default()
        };
        let pg = PeerGroup::from_yaml(&yaml_pg);
        assert_eq!(pg.families.len(), 1);
        // mode: bit0=RX(1), bit1=TX(1) -> 3
        assert_eq!(*pg.families.get(&Family::IPV4).unwrap(), 3u8);
        assert_eq!(*pg.send_max.get(&Family::IPV4).unwrap(), 4);
    }

    // --- PeerGroup graceful_restart tests ---

    #[test]
    fn peer_group_yaml_gr_parsed() {
        let yaml_pg = config::PeerGroup {
            config: Some(config::PeerGroupConfig {
                peer_group_name: Some("g".to_string()),
                ..Default::default()
            }),
            afi_safis: Some(vec![config::AfiSafi {
                config: Some(config::AfiSafiConfig {
                    afi_safi_name: Some(config::AfiSafiType::Ipv4Unicast),
                    ..Default::default()
                }),
                mp_graceful_restart: Some(config::MpGracefulRestart {
                    config: Some(config::MpGracefulRestartConfig {
                        enabled: Some(true),
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }]),
            graceful_restart: Some(config::GracefulRestart {
                config: Some(config::GracefulRestartConfig {
                    enabled: Some(true),
                    restart_time: Some(90),
                    notification_enabled: Some(true),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let pg = PeerGroup::from_yaml(&yaml_pg);
        let gr = pg.graceful_restart.as_ref().expect("GR should be Some");
        assert_eq!(gr.restart_time, 90);
        assert!(gr.notification_enabled);
        assert_eq!(gr.families, vec![Family::IPV4]);
    }

    #[test]
    fn peer_group_yaml_gr_disabled_yields_none() {
        let yaml_pg = config::PeerGroup {
            config: Some(config::PeerGroupConfig {
                peer_group_name: Some("g".to_string()),
                ..Default::default()
            }),
            graceful_restart: Some(config::GracefulRestart {
                config: Some(config::GracefulRestartConfig {
                    enabled: Some(false),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let pg = PeerGroup::from_yaml(&yaml_pg);
        assert!(pg.graceful_restart.is_none());
    }

    #[test]
    fn peer_group_yaml_gr_no_families_yields_none() {
        // GR enabled but no afi-safi has mp-graceful-restart -> None
        let yaml_pg = config::PeerGroup {
            config: Some(config::PeerGroupConfig {
                peer_group_name: Some("g".to_string()),
                ..Default::default()
            }),
            afi_safis: Some(vec![config::AfiSafi {
                config: Some(config::AfiSafiConfig {
                    afi_safi_name: Some(config::AfiSafiType::Ipv4Unicast),
                    ..Default::default()
                }),
                ..Default::default()
            }]),
            graceful_restart: Some(config::GracefulRestart {
                config: Some(config::GracefulRestartConfig {
                    enabled: Some(true),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let pg = PeerGroup::from_yaml(&yaml_pg);
        assert!(pg.graceful_restart.is_none());
    }

    #[tokio::test]
    async fn peer_group_grpc_gr_roundtrip() {
        let svc = make_grpc_service();
        svc.add_peer_group(tonic::Request::new(api::AddPeerGroupRequest {
            peer_group: Some(api::PeerGroup {
                conf: Some(api::PeerGroupConf {
                    peer_group_name: "gr-grp".to_string(),
                    ..Default::default()
                }),
                graceful_restart: Some(api::GracefulRestart {
                    enabled: true,
                    restart_time: 150,
                    notification_enabled: true,
                    ..Default::default()
                }),
                afi_safis: vec![api::AfiSafi {
                    config: Some(api::AfiSafiConfig {
                        family: Some(api::Family {
                            afi: api::family::Afi::Ip as i32,
                            safi: api::family::Safi::Unicast as i32,
                        }),
                        ..Default::default()
                    }),
                    mp_graceful_restart: Some(api::MpGracefulRestart {
                        config: Some(api::MpGracefulRestartConfig { enabled: true }),
                        ..Default::default()
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            }),
        }))
        .await
        .unwrap();

        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        svc.list_peer_group(tonic::Request::new(api::ListPeerGroupRequest {
            peer_group_name: "gr-grp".to_string(),
        }))
        .await
        .unwrap()
        .into_inner()
        .for_each(|r| {
            let tx = tx.clone();
            async move {
                let _ = tx.send(r.unwrap().peer_group.unwrap()).await;
            }
        })
        .await;

        let got = rx.recv().await.unwrap();
        let gr = got.graceful_restart.as_ref().expect("GR should be Some");
        assert!(gr.enabled);
        assert_eq!(gr.restart_time, 150);
        assert!(gr.notification_enabled);
        // mp_graceful_restart should be reflected in afi_safis
        assert_eq!(got.afi_safis.len(), 1);
        assert!(
            got.afi_safis[0]
                .mp_graceful_restart
                .as_ref()
                .and_then(|m| m.config.as_ref())
                .is_some_and(|c| c.enabled)
        );
    }

    #[tokio::test]
    async fn dynamic_peer_inherits_gr_from_group() {
        let global = make_global();
        let tables = make_tables();
        let (client, server) = loopback_pair().await;
        let remote_addr = client.local_addr().unwrap().ip();

        let mut families = FnvHashMap::default();
        families.insert(Family::IPV4, 0u8);

        {
            let mut g = global.write().await;
            g.peer_group.insert(
                "gr-group".to_string(),
                PeerGroup {
                    as_number: 65002,
                    dynamic_peers: vec![DynamicPeer {
                        prefix: packet::IpNet::new(remote_addr, 32),
                    }],
                    route_server_client: false,
                    holdtime: None,
                    local_asn: 0,
                    passive: false,
                    route_reflector: RouteReflectorConfig::default(),
                    multihop_ttl: None,
                    ttl_security: None,
                    auth_password: None,
                    connect_retry_time: None,
                    families,
                    send_max: FnvHashMap::default(),
                    graceful_restart: Some(GrPeerConfig {
                        restart_time: 120,
                        notification_enabled: false,
                        families: vec![Family::IPV4],
                    }),
                },
            );
        }

        let h = accept_connection(&global, &tables, server, crate::fsm::Role::Passive).await;
        assert!(h.is_some());

        let g = global.read().await;
        let peer = g.peers.get(&remote_addr).unwrap();
        let gr = peer
            .config
            .graceful_restart
            .as_ref()
            .expect("GR should be inherited");
        assert_eq!(gr.restart_time, 120);
        assert_eq!(gr.families, vec![Family::IPV4]);
        // GR capability should appear in local_cap
        let has_gr_cap = peer
            .config
            .local_cap
            .iter()
            .any(|c| matches!(c, packet::Capability::GracefulRestart { .. }));
        assert!(has_gr_cap);
    }

    // --- PeerGroup ttl_security tests ---

    #[tokio::test]
    async fn peer_group_grpc_ttl_security_roundtrip() {
        let svc = make_grpc_service();
        svc.add_peer_group(tonic::Request::new(api::AddPeerGroupRequest {
            peer_group: Some(api::PeerGroup {
                conf: Some(api::PeerGroupConf {
                    peer_group_name: "ts-grp".to_string(),
                    ..Default::default()
                }),
                ttl_security: Some(api::TtlSecurity {
                    enabled: true,
                    ttl_min: 200,
                }),
                ..Default::default()
            }),
        }))
        .await
        .unwrap();

        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        svc.list_peer_group(tonic::Request::new(api::ListPeerGroupRequest {
            peer_group_name: "ts-grp".to_string(),
        }))
        .await
        .unwrap()
        .into_inner()
        .for_each(|r| {
            let tx = tx.clone();
            async move {
                let _ = tx.send(r.unwrap().peer_group.unwrap()).await;
            }
        })
        .await;

        let got = rx.recv().await.unwrap();
        let ts = got
            .ttl_security
            .as_ref()
            .expect("ttl_security should be Some");
        assert!(ts.enabled);
        assert_eq!(ts.ttl_min, 200);
    }

    #[tokio::test]
    async fn peer_group_grpc_ttl_security_default_min() {
        // ttl_min == 0 with enabled=true should default to 255.
        let svc = make_grpc_service();
        svc.add_peer_group(tonic::Request::new(api::AddPeerGroupRequest {
            peer_group: Some(api::PeerGroup {
                conf: Some(api::PeerGroupConf {
                    peer_group_name: "ts-default".to_string(),
                    ..Default::default()
                }),
                ttl_security: Some(api::TtlSecurity {
                    enabled: true,
                    ttl_min: 0,
                }),
                ..Default::default()
            }),
        }))
        .await
        .unwrap();

        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        svc.list_peer_group(tonic::Request::new(api::ListPeerGroupRequest {
            peer_group_name: "ts-default".to_string(),
        }))
        .await
        .unwrap()
        .into_inner()
        .for_each(|r| {
            let tx = tx.clone();
            async move {
                let _ = tx.send(r.unwrap().peer_group.unwrap()).await;
            }
        })
        .await;

        let got = rx.recv().await.unwrap();
        let ts = got
            .ttl_security
            .as_ref()
            .expect("ttl_security should be Some");
        assert!(ts.enabled);
        assert_eq!(ts.ttl_min, 255);
    }

    #[test]
    fn peer_group_yaml_ttl_security_parsed() {
        let yaml_pg = config::PeerGroup {
            config: Some(config::PeerGroupConfig {
                peer_group_name: Some("g".to_string()),
                ..Default::default()
            }),
            ttl_security: Some(config::TtlSecurity {
                config: Some(config::TtlSecurityConfig {
                    enabled: Some(true),
                    ttl_min: Some(200),
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let pg = PeerGroup::from_yaml(&yaml_pg);
        assert_eq!(pg.ttl_security, Some(200u8));
    }

    #[test]
    fn peer_group_yaml_ttl_security_default_min() {
        let yaml_pg = config::PeerGroup {
            config: Some(config::PeerGroupConfig {
                peer_group_name: Some("g".to_string()),
                ..Default::default()
            }),
            ttl_security: Some(config::TtlSecurity {
                config: Some(config::TtlSecurityConfig {
                    enabled: Some(true),
                    ttl_min: None,
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let pg = PeerGroup::from_yaml(&yaml_pg);
        assert_eq!(pg.ttl_security, Some(255u8));
    }

    #[tokio::test]
    async fn dynamic_peer_inherits_ttl_security_from_group() {
        let global = make_global();
        let tables = make_tables();
        let (client, server) = loopback_pair().await;
        let remote_addr = client.local_addr().unwrap().ip();

        {
            let mut g = global.write().await;
            g.peer_group.insert(
                "ts-group".to_string(),
                PeerGroup {
                    as_number: 65002,
                    dynamic_peers: vec![DynamicPeer {
                        prefix: packet::IpNet::new(remote_addr, 32),
                    }],
                    route_server_client: false,
                    holdtime: None,
                    local_asn: 0,
                    passive: false,
                    route_reflector: RouteReflectorConfig::default(),
                    multihop_ttl: None,
                    ttl_security: Some(200),
                    auth_password: None,
                    connect_retry_time: None,
                    families: FnvHashMap::default(),
                    send_max: FnvHashMap::default(),
                    graceful_restart: None,
                },
            );
        }

        let h = accept_connection(&global, &tables, server, crate::fsm::Role::Passive).await;
        assert!(h.is_some());

        let g = global.read().await;
        let peer = g.peers.get(&remote_addr).unwrap();
        assert_eq!(peer.config.ttl_security, Some(200u8));
    }

    #[tokio::test]
    async fn dynamic_peer_inherits_families_from_group() {
        let global = make_global();
        let tables = make_tables();
        let (client, server) = loopback_pair().await;
        let remote_addr = client.local_addr().unwrap().ip();

        let mut families = FnvHashMap::default();
        families.insert(Family::IPV4, 0u8);
        families.insert(Family::IPV6, 0u8);

        {
            let mut g = global.write().await;
            g.peer_group.insert(
                "fam-group".to_string(),
                PeerGroup {
                    as_number: 65002,
                    dynamic_peers: vec![DynamicPeer {
                        prefix: packet::IpNet::new(remote_addr, 32),
                    }],
                    route_server_client: false,
                    holdtime: None,
                    local_asn: 0,
                    passive: false,
                    route_reflector: RouteReflectorConfig::default(),
                    multihop_ttl: None,
                    ttl_security: None,
                    auth_password: None,
                    connect_retry_time: None,
                    families,
                    send_max: FnvHashMap::default(),
                    graceful_restart: None,
                },
            );
        }

        let h = accept_connection(&global, &tables, server, crate::fsm::Role::Passive).await;
        assert!(h.is_some());

        let g = global.read().await;
        let peer = g.peers.get(&remote_addr).unwrap();
        // Inherited families should appear in local_cap as MultiProtocol capabilities.
        let mp_families: Vec<Family> = peer
            .config
            .local_cap
            .iter()
            .filter_map(|c| {
                if let packet::Capability::MultiProtocol(f) = c {
                    Some(*f)
                } else {
                    None
                }
            })
            .collect();
        assert!(mp_families.contains(&Family::IPV4));
        assert!(mp_families.contains(&Family::IPV6));
    }

    fn cease_notification() -> bgp::Message {
        bgp::Message::Notification(packet::Notification::CeaseConnectionCollision)
    }

    /// Helper: add a peer and return a passive PeerSession via accept_connection.
    async fn passive_connection(
        global: &GlobalHandle,
        tables: &TableHandle,
        remote_addr: IpAddr,
        server: TcpStream,
    ) -> PeerSession {
        {
            let mut g = global.write().await;
            g.add_peer(default_peer_params(remote_addr), None).unwrap();
        }
        accept_connection(global, tables, server, crate::fsm::Role::Passive)
            .await
            .unwrap()
    }

    /// Returns a PeerSession with the Passive FSM driven to Established and source set.
    async fn established_connection(
        global: &GlobalHandle,
        tables: &TableHandle,
        remote_addr: IpAddr,
        server: TcpStream,
    ) -> PeerSession {
        let mut conn = passive_connection(global, tables, remote_addr, server).await;
        {
            let open = bgp::Message::Open(bgp::Open {
                as_number: 65002,
                holdtime: HoldTime::new(90).unwrap(),
                router_id: u32::from(Ipv4Addr::new(10, 0, 0, 1)),
                capability: vec![bgp::Capability::FourOctetAsNumber(65002)],
            });
            let mut arb = conn.conn_arbiter.lock().unwrap();
            arb.process(
                crate::fsm::Role::Passive,
                crate::fsm::Input::Connected(false),
            );
            arb.process(
                crate::fsm::Role::Passive,
                crate::fsm::Input::MessageReceived(open),
            );
            arb.process(
                crate::fsm::Role::Passive,
                crate::fsm::Input::MessageReceived(bgp::Message::Keepalive),
            );
        }
        conn.source.insert(
            Family::IPV4,
            Arc::new(table::Source::new(
                remote_addr,
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                65002,
                65001,
                Ipv4Addr::new(10, 0, 0, 1),
                PeerRole::Ebgp,
            )),
        );
        conn
    }

    /// Prepare a PeerSession for tests: open the IPv4 channel
    /// and insert an IPv4 pending bucket, matching what on_established would do.
    fn setup_ipv4_session(conn: &mut PeerSession) {
        conn.codec
            .set_family(Family::IPV4, bgp::FamilyState::default());
        conn.pending
            .insert(Family::IPV4, crate::peer_tx::PendingTx::new(false));
    }

    fn other_source() -> Arc<table::Source> {
        Arc::new(table::Source::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            65002,
            65001,
            Ipv4Addr::new(10, 0, 0, 2),
            PeerRole::Ebgp,
        ))
    }

    // ---- handle_prefix_update tests ----

    fn make_prefix_update_reach(
        nlri: &packet::Nlri,
        source: Arc<table::Source>,
    ) -> table::NlriChange {
        let best = table::Path {
            local_path_id: 1,
            source,
            nexthop: Some(bgp::Nexthop::V4(Ipv4Addr::new(1, 1, 1, 1))),
            attr: Arc::new(vec![
                packet::Attribute::new_with_value(packet::Attribute::ORIGIN, 0).unwrap(),
            ]),
        };
        table::NlriChange {
            family: Family::IPV4,
            net: nlri.clone(),
            best_changed: true,
            any_changed: true,
            replaced_path_id: None,
            current_paths: Arc::new(vec![best]),
        }
    }

    fn make_prefix_update_withdraw(nlri: &packet::Nlri) -> table::NlriChange {
        table::NlriChange {
            family: Family::IPV4,
            net: nlri.clone(),
            best_changed: true,
            any_changed: true,
            replaced_path_id: None,
            current_paths: Arc::new(vec![]),
        }
    }

    fn make_prefix_update_no_change(
        nlri: &packet::Nlri,
        source: Arc<table::Source>,
    ) -> table::NlriChange {
        let best = table::Path {
            local_path_id: 1,
            source,
            nexthop: Some(bgp::Nexthop::V4(Ipv4Addr::new(1, 1, 1, 1))),
            attr: Arc::new(vec![]),
        };
        table::NlriChange {
            family: Family::IPV4,
            net: nlri.clone(),
            best_changed: false,
            any_changed: false,
            replaced_path_id: None,
            current_paths: Arc::new(vec![best]),
        }
    }

    #[tokio::test]
    async fn handle_prefix_update_reach_tracked_in_export_map() {
        let global = make_global();
        let tables = make_tables();
        let (client, server) = loopback_pair().await;
        let remote_addr = client.local_addr().unwrap().ip();

        let mut conn = established_connection(&global, &tables, remote_addr, server).await;
        setup_ipv4_session(&mut conn);
        let nlri: packet::Nlri = "10.0.0.0/24".parse().unwrap();
        let update = make_prefix_update_reach(&nlri, other_source());

        conn.handle_prefix_update(update);

        // path_id=0 stored in export_map for non-Add-Path
        assert!(conn.export_map.was_sent(Family::IPV4, &nlri));
        assert!(conn.export_map.contains_path(Family::IPV4, &nlri, 0));
        assert!(!conn.pending[&Family::IPV4].is_empty());
    }

    #[tokio::test]
    async fn handle_prefix_update_noop_when_best_unchanged() {
        let global = make_global();
        let tables = make_tables();
        let (client, server) = loopback_pair().await;
        let remote_addr = client.local_addr().unwrap().ip();

        let mut conn = established_connection(&global, &tables, remote_addr, server).await;
        setup_ipv4_session(&mut conn);
        let nlri: packet::Nlri = "10.0.0.0/24".parse().unwrap();
        let update = make_prefix_update_no_change(&nlri, other_source());

        conn.handle_prefix_update(update);

        assert!(!conn.export_map.was_sent(Family::IPV4, &nlri));
        assert!(conn.pending[&Family::IPV4].is_empty());
    }

    #[tokio::test]
    async fn handle_prefix_update_withdraw_when_best_gone() {
        let global = make_global();
        let tables = make_tables();
        let (client, server) = loopback_pair().await;
        let remote_addr = client.local_addr().unwrap().ip();

        let mut conn = established_connection(&global, &tables, remote_addr, server).await;
        setup_ipv4_session(&mut conn);
        let nlri: packet::Nlri = "10.0.0.0/24".parse().unwrap();

        // Pre-mark as sent so the withdraw fires.
        conn.export_map.mark_sent(Family::IPV4, nlri.clone(), 0);

        let update = make_prefix_update_withdraw(&nlri);
        conn.handle_prefix_update(update);

        assert!(!conn.export_map.was_sent(Family::IPV4, &nlri));
        assert!(!conn.pending[&Family::IPV4].is_empty());
    }

    #[tokio::test]
    async fn handle_prefix_update_spurious_withdraw_suppressed() {
        let global = make_global();
        let tables = make_tables();
        let (client, server) = loopback_pair().await;
        let remote_addr = client.local_addr().unwrap().ip();

        let mut conn = established_connection(&global, &tables, remote_addr, server).await;
        setup_ipv4_session(&mut conn);
        let nlri: packet::Nlri = "10.0.0.0/24".parse().unwrap();

        // Never advertised → spurious withdraw should be suppressed.
        let update = make_prefix_update_withdraw(&nlri);
        conn.handle_prefix_update(update);

        assert!(!conn.export_map.was_sent(Family::IPV4, &nlri));
        assert!(conn.pending[&Family::IPV4].is_empty());
    }

    /// `apply_outputs` returns `SendMessage(Notification(_))` outputs as `Step::Terminate`
    /// with the notification field set. Cross-role CEASE delivery is handled atomically by
    /// `ConnArbiter::process` before outputs reach `apply_outputs`, so non-Notification
    /// `SendMessage` outputs are queued into `ctrl_msgs`.
    #[tokio::test]
    async fn apply_outputs_send_message_goes_to_ctrl() {
        let global = make_global();
        let tables = make_tables();
        let (client, server) = loopback_pair().await;
        let remote_addr = client.local_addr().unwrap().ip();

        let mut conn = passive_connection(&global, &tables, remote_addr, server).await;
        let cease = cease_notification();

        let outputs = vec![
            crate::fsm::PeerFsmOutput::Connection(
                crate::fsm::Role::Passive,
                crate::fsm::Output::SendMessage(cease.clone()),
            ),
            crate::fsm::PeerFsmOutput::Connection(
                crate::fsm::Role::Passive,
                crate::fsm::Output::SessionDown(crate::fsm::SessionDownReason::LocalNotification(
                    cease.clone(),
                )),
            ),
        ];
        let dummy: SocketAddr = "127.0.0.1:179".parse().unwrap();
        let (step, effects) = conn.apply_outputs(outputs, dummy, dummy).await;

        assert!(effects.is_empty());
        let Step::Terminate { notification, .. } = step else {
            panic!("expected Terminate");
        };
        assert!(matches!(
            notification,
            Some(bgp::Message::Notification(
                packet::Notification::CeaseConnectionCollision
            ))
        ));
        let _ = tables;
    }

    /// End-to-end collision test: the loser is determined by real router-ID comparison
    /// inside `PeerFsm::check_collision`, not by hand-crafted outputs.
    /// ConnArbiter::process delivers the CEASE directly to the losing connection's
    /// close channel; no GlobalEffect/process_effects call is needed.
    ///
    /// make_global() sets local router_id = 1.0.0.1.
    /// Remote router_id = 10.0.0.1 (higher) → passive wins → active is the loser.
    #[tokio::test]
    async fn collision_loser_determined_by_router_id() {
        let global = make_global(); // local router_id = 1.0.0.1
        let tables = make_tables();
        let (client, server) = loopback_pair().await;
        let remote_addr = client.local_addr().unwrap().ip();

        passive_connection(&global, &tables, remote_addr, server).await;

        // Pre-install active_close_tx inside the arbiter.
        let (active_close_tx, mut active_close_rx) = tokio::sync::oneshot::channel::<CloseReason>();
        let conn_arbiter = {
            let g = global.read().await;
            Arc::clone(&g.peers[&remote_addr].context.lock().unwrap().conn_arbiter)
        };
        conn_arbiter.lock().unwrap().active_close_tx = Some(active_close_tx);

        // remote router_id 10.0.0.1 > local 1.0.0.1 → passive wins → active is loser
        let open_msg = bgp::Message::Open(bgp::Open {
            as_number: 65001,
            holdtime: HoldTime::new(90).unwrap(),
            router_id: u32::from(Ipv4Addr::new(10, 0, 0, 1)),
            capability: vec![bgp::Capability::FourOctetAsNumber(65001)],
        });

        {
            let mut arb = conn_arbiter.lock().unwrap();
            // Active → OpenConfirm
            arb.process(
                crate::fsm::Role::Active,
                crate::fsm::Input::Connected(false),
            );
            arb.process(
                crate::fsm::Role::Active,
                crate::fsm::Input::MessageReceived(open_msg.clone()),
            );
            // Passive → OpenConfirm → collision detected → CEASE sent directly to active_close_tx
            arb.process(
                crate::fsm::Role::Passive,
                crate::fsm::Input::Connected(false),
            );
            arb.process(
                crate::fsm::Role::Passive,
                crate::fsm::Input::MessageReceived(open_msg),
            );
        }

        let received = active_close_rx
            .try_recv()
            .expect("CEASE not delivered to active (loser)");
        assert!(matches!(
            received,
            CloseReason::SendMessage(bgp::Message::Notification(_))
        ));
        let _ = tables; // suppress unused warning
    }

    #[test]
    fn export_map_mark_and_check() {
        let nlri: packet::Nlri = "10.0.0.0/24".parse().unwrap();
        let mut m = ExportMap::new();
        assert!(!m.was_sent(Family::IPV4, &nlri));
        m.mark_sent(Family::IPV4, nlri.clone(), 0);
        assert!(m.was_sent(Family::IPV4, &nlri));
    }

    #[test]
    fn export_map_never_sent_returns_false() {
        let nlri: packet::Nlri = "192.168.1.0/24".parse().unwrap();
        let m = ExportMap::new();
        assert!(!m.was_sent(Family::IPV4, &nlri));
    }

    #[test]
    fn export_map_mark_withdrawn_clears() {
        let nlri: packet::Nlri = "10.1.0.0/16".parse().unwrap();
        let mut m = ExportMap::new();
        m.mark_sent(Family::IPV4, nlri.clone(), 0);
        assert!(m.was_sent(Family::IPV4, &nlri));
        m.mark_withdrawn(Family::IPV4, &nlri, 0);
        assert!(!m.was_sent(Family::IPV4, &nlri));
    }

    #[test]
    fn export_map_multiple_families_independent() {
        let v4: packet::Nlri = "10.0.0.0/8".parse().unwrap();
        let v6: packet::Nlri = "2001:db8::/32".parse().unwrap();
        let mut m = ExportMap::new();
        m.mark_sent(Family::IPV4, v4.clone(), 0);
        assert!(m.was_sent(Family::IPV4, &v4));
        assert!(!m.was_sent(Family::IPV6, &v4));
        m.mark_sent(Family::IPV6, v6.clone(), 0);
        assert!(m.was_sent(Family::IPV6, &v6));
        assert!(!m.was_sent(Family::IPV4, &v6));
    }

    fn make_context() -> Arc<std::sync::Mutex<PeerContext>> {
        use std::net::Ipv4Addr;
        let fsm = crate::fsm::PeerFsm::new(
            u32::from(Ipv4Addr::new(1, 0, 0, 1)),
            65001,
            vec![],
            90,
            0,
            FnvHashMap::default(),
        );
        let conn_arbiter = Arc::new(std::sync::Mutex::new(ConnArbiter::new(fsm)));
        Arc::new(std::sync::Mutex::new(PeerContext {
            conn_arbiter,
            active_connect_cancel_tx: None,
            active_connect_join_handle: None,
            gr_state: crate::gr::GrState::new(),
            gr_restart_timer: None,
        }))
    }

    // ---- process_effects: StopActiveConnect ----

    #[tokio::test]
    async fn process_effects_stop_active_connect_clears_cancel_tx() {
        let global = make_global();
        let tables = make_tables();
        let remote_addr: IpAddr = "10.0.0.1".parse().unwrap();
        let context = make_context();

        let (tx, _rx) = tokio::sync::oneshot::channel::<()>();
        context.lock().unwrap().active_connect_cancel_tx = Some(tx);

        let mut session = PeerSession::new_for_test(remote_addr, context.clone(), tables);
        session
            .process_effects(vec![GlobalEffect::StopActiveConnect], &global)
            .await;

        assert!(context.lock().unwrap().active_connect_cancel_tx.is_none());
    }

    // ---- process_effects: GrSessionEstablished (helper side) ----

    #[tokio::test]
    async fn process_effects_gr_session_established_helper_enters_waiting_eor() {
        let global = make_global();
        let tables = make_tables();
        let remote_addr: IpAddr = "10.0.0.1".parse().unwrap();
        let context = make_context();

        // Drive GrState to Restarting (session drop with GR) so that the
        // subsequent SessionEstablished can transition it to WaitingEor.
        // SessionEstablished is a no-op from Idle.
        {
            let mut ctx = context.lock().unwrap();
            ctx.gr_state.process(crate::gr::GrInput::SessionDropped {
                families: vec![Family::IPV4],
                restart_time: Duration::from_secs(90),
            });
        }

        let negotiated_gr = Some(NegotiatedGr {
            families: vec![Family::IPV4],
            restart_time: Duration::from_secs(90),
            notification_enabled: false,
        });

        let mut session = PeerSession::new_for_test(remote_addr, context.clone(), tables);
        session
            .process_effects(
                vec![GlobalEffect::GrSessionEstablished { negotiated_gr }],
                &global,
            )
            .await;

        let ctx = context.lock().unwrap();
        // GrState should now be in PeerReconnected (helper side, waiting for EOR).
        assert!(ctx.gr_state.is_peer_restarting());
    }

    // ---- process_effects: GrEorReceived (helper side) ----

    #[tokio::test]
    async fn process_effects_gr_eor_received_helper_clears_restarting() {
        let global = make_global();
        let tables = make_tables();
        let remote_addr: IpAddr = "10.0.0.1".parse().unwrap();
        let context = make_context();

        // Drive GrState through SessionDropped → SessionEstablished to reach PeerReconnected.
        {
            let mut ctx = context.lock().unwrap();
            ctx.gr_state.process(crate::gr::GrInput::SessionDropped {
                families: vec![Family::IPV4],
                restart_time: Duration::from_secs(90),
            });
            ctx.gr_state
                .process(crate::gr::GrInput::SessionEstablished {
                    gr_families: vec![Family::IPV4],
                });
        }

        let mut session = PeerSession::new_for_test(remote_addr, context.clone(), tables);
        session
            .process_effects(
                vec![GlobalEffect::GrEorReceived {
                    family: Family::IPV4,
                }],
                &global,
            )
            .await;

        let ctx = context.lock().unwrap();
        // GrState is now Idle (EOR for only family received).
        assert!(!ctx.gr_state.is_peer_restarting());
    }

    // ---- families_to_drop_on_disconnect ----

    #[test]
    fn drop_on_disconnect_no_gr_drops_all_families() {
        let families = [Family::IPV4, Family::IPV6];
        let result = families_to_drop_on_disconnect(families.iter(), None);
        assert_eq!(result.len(), 2);
        assert!(result.contains(&Family::IPV4));
        assert!(result.contains(&Family::IPV6));
    }

    #[test]
    fn drop_on_disconnect_gr_for_all_drops_nothing() {
        let families = [Family::IPV4, Family::IPV6];
        let negotiated_gr = NegotiatedGr {
            families: vec![Family::IPV4, Family::IPV6],
            restart_time: Duration::from_secs(90),
            notification_enabled: false,
        };
        let result = families_to_drop_on_disconnect(families.iter(), Some(&negotiated_gr));
        assert!(result.is_empty());
    }

    #[test]
    fn drop_on_disconnect_gr_for_ipv4_only_drops_ipv6() {
        let families = [Family::IPV4, Family::IPV6];
        let negotiated_gr = NegotiatedGr {
            families: vec![Family::IPV4],
            restart_time: Duration::from_secs(90),
            notification_enabled: false,
        };
        let result = families_to_drop_on_disconnect(families.iter(), Some(&negotiated_gr));
        assert_eq!(result, vec![Family::IPV6]);
    }

    // ---- disconnect drops non-GR family routes in the routing table ----

    #[tokio::test]
    async fn disconnect_with_gr_drops_non_gr_family_routes() {
        use std::net::Ipv4Addr;
        let tables = make_tables();
        let remote_addr: IpAddr = "10.0.0.2".parse().unwrap();
        let local_addr: IpAddr = "127.0.0.1".parse().unwrap();

        let source = Arc::new(table::Source::new(
            remote_addr,
            local_addr,
            65002,
            65001,
            Ipv4Addr::new(10, 0, 0, 2),
            PeerRole::Ebgp,
        ));
        let ipv4_net: packet::Nlri = "10.1.0.0/24".parse().unwrap();
        let ipv6_net: packet::Nlri = "2001:db8::/32".parse().unwrap();
        let attrs = Arc::new(Vec::new());
        let nh4 = packet::bgp::Nexthop::V4(Ipv4Addr::new(10, 0, 0, 2));
        let nh6 =
            packet::bgp::Nexthop::V6(std::net::Ipv6Addr::new(0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1));

        // Insert one IPv4 route and one IPv6 route for the peer.
        {
            let mut t = tables.shards[0].lock().unwrap();
            let _ = t.rtable.insert(
                source.clone(),
                Family::IPV4,
                ipv4_net,
                0,
                Some(nh4),
                attrs.clone(),
                None,
                false,
                false,
                None,
                std::time::SystemTime::UNIX_EPOCH,
            );
            let _ = t.rtable.insert(
                source.clone(),
                Family::IPV6,
                ipv6_net,
                0,
                Some(nh6),
                attrs.clone(),
                None,
                false,
                false,
                None,
                std::time::SystemTime::UNIX_EPOCH,
            );
        }

        // GR active for IPv4 only: IPv6 must be dropped immediately, IPv4 preserved.
        let negotiated_gr = NegotiatedGr {
            families: vec![Family::IPV4],
            restart_time: Duration::from_secs(90),
            notification_enabled: false,
        };
        let session_families = [Family::IPV4, Family::IPV6];
        let drop_families =
            families_to_drop_on_disconnect(session_families.iter(), Some(&negotiated_gr));
        tables.drop_families(remote_addr, &drop_families);

        let t = tables.shards[0].lock().unwrap();
        // IPv4 route (GR family) must still be in the table.
        assert_eq!(t.rtable.collect_loc_rib_paths(&Family::IPV4).len(), 1);
        // IPv6 route (non-GR family) must have been removed.
        assert!(t.rtable.collect_loc_rib_paths(&Family::IPV6).is_empty());
    }

    #[tokio::test]
    async fn disconnect_without_gr_drops_all_routes() {
        use std::net::Ipv4Addr;
        let tables = make_tables();
        let remote_addr: IpAddr = "10.0.0.3".parse().unwrap();
        let local_addr: IpAddr = "127.0.0.1".parse().unwrap();

        let source = Arc::new(table::Source::new(
            remote_addr,
            local_addr,
            65003,
            65001,
            Ipv4Addr::new(10, 0, 0, 3),
            PeerRole::Ebgp,
        ));
        let ipv4_net: packet::Nlri = "10.2.0.0/24".parse().unwrap();
        let attrs = Arc::new(Vec::new());
        let nh4 = packet::bgp::Nexthop::V4(Ipv4Addr::new(10, 0, 0, 3));

        {
            let mut t = tables.shards[0].lock().unwrap();
            t.rtable.insert(
                source,
                Family::IPV4,
                ipv4_net,
                0,
                Some(nh4),
                attrs,
                None,
                false,
                false,
                None,
                std::time::SystemTime::UNIX_EPOCH,
            );
        }
        assert_eq!(
            tables.shards[0]
                .lock()
                .unwrap()
                .rtable
                .collect_loc_rib_paths(&Family::IPV4)
                .len(),
            1
        );

        // No GR: all families dropped.
        let session_families = [Family::IPV4];
        let drop_families = families_to_drop_on_disconnect(session_families.iter(), None);
        tables.drop_families(remote_addr, &drop_families);

        assert!(
            tables.shards[0]
                .lock()
                .unwrap()
                .rtable
                .collect_loc_rib_paths(&Family::IPV4)
                .is_empty()
        );
    }

    // After a session ends via EOF the FSM Connection slot must be cleared
    // so that the next connection is not rejected.
    #[tokio::test]
    async fn fsm_slot_cleared_after_eof() {
        let global = make_global();
        let tables = make_tables();
        let (client, server) = loopback_pair().await;
        let remote_addr = client.local_addr().unwrap().ip();

        {
            let mut g = global.write().await;
            g.add_peer(default_peer_params(remote_addr), None).unwrap();
        }

        let session = accept_connection(&global, &tables, server, crate::fsm::Role::Passive)
            .await
            .unwrap();

        // Spawn the session task.  The session sends BGP OPEN and waits for I/O.
        let (active_tx, _active_rx) = mpsc::unbounded_channel::<TcpStream>();
        let global_clone = Arc::clone(&global);
        let h = tokio::spawn(async move { session.run(global_clone, active_tx).await });

        // Drop the client-side socket → the server sees EOF → Input::Disconnected
        // is routed through the FSM, which clears the Connection slot.
        drop(client);
        h.await.unwrap();

        // After run() completes the passive FSM slot must be None.
        let g = global.read().await;
        let ctx = g.peers[&remote_addr].context.lock().unwrap();
        let arb = ctx.conn_arbiter.lock().unwrap();
        assert!(arb.fsm.connection(crate::fsm::Role::Passive).is_none());
    }

    // ---- Selection Deferral (Restarting Speaker, RFC 4724 section 4.1) ----

    fn make_selection_deferral(peers: &[(IpAddr, Vec<Family>)]) -> crate::gr::RestartingDeferral {
        let map: fnv::FnvHashMap<IpAddr, Vec<Family>> = peers.iter().cloned().collect();
        let (deferral, _) = crate::gr::RestartingDeferral::new(map, Some(Duration::from_secs(360)));
        deferral
    }

    #[tokio::test]
    async fn selection_deferral_peer_established_starts_timer() {
        let global = make_global();
        let tables = make_tables();
        let remote_addr: IpAddr = "10.0.0.1".parse().unwrap();
        let context = make_context();

        // Install a selection_deferral with this peer as the sole GR peer.
        global.write().await.selection_deferral = Some(make_selection_deferral(&[(
            remote_addr,
            vec![Family::IPV4],
        )]));

        let negotiated_gr = Some(NegotiatedGr {
            families: vec![Family::IPV4],
            restart_time: Duration::from_secs(90),
            notification_enabled: false,
        });
        let mut session = PeerSession::new_for_test(remote_addr, context, tables);
        session
            .process_effects(
                vec![GlobalEffect::GrSessionEstablished { negotiated_gr }],
                &global,
            )
            .await;

        let g = global.read().await;
        // Timer must have been started.
        assert!(g.selection_deferral_timer.is_some());
        // selection_deferral is still Some (waiting for EOR).
        assert!(g.selection_deferral.is_some());
    }

    #[tokio::test]
    async fn selection_deferral_eor_received_completes_deferral() {
        let global = make_global();
        let tables = make_tables();
        let remote_addr: IpAddr = "10.0.0.1".parse().unwrap();
        let context = make_context();

        // Install selection_deferral: one peer, one family.
        global.write().await.selection_deferral = Some(make_selection_deferral(&[(
            remote_addr,
            vec![Family::IPV4],
        )]));

        let negotiated_gr = Some(NegotiatedGr {
            families: vec![Family::IPV4],
            restart_time: Duration::from_secs(90),
            notification_enabled: false,
        });
        let mut session = PeerSession::new_for_test(remote_addr, context, tables);

        // Establish → starts timer and moves to Deferring.
        session
            .process_effects(
                vec![GlobalEffect::GrSessionEstablished { negotiated_gr }],
                &global,
            )
            .await;

        // EOR received → deferral completes.
        session
            .process_effects(
                vec![GlobalEffect::GrEorReceived {
                    family: Family::IPV4,
                }],
                &global,
            )
            .await;

        let g = global.read().await;
        // Deferral must be cleared after all EOR received.
        assert!(g.selection_deferral.is_none());
        assert!(g.selection_deferral_timer.is_none());
    }

    #[tokio::test]
    async fn selection_deferral_timer_expired_clears_deferral() {
        let global = make_global();
        let tables = make_tables();
        let remote_addr: IpAddr = "10.0.0.1".parse().unwrap();

        // Install selection_deferral in Deferring state by processing PeerEstablished.
        {
            let mut g = global.write().await;
            let mut deferral = make_selection_deferral(&[(remote_addr, vec![Family::IPV4])]);
            // Advance to Deferring by feeding PeerEstablished.
            deferral.process(crate::gr::RestartingInput::PeerEstablished(
                remote_addr,
                vec![Family::IPV4],
            ));
            g.selection_deferral = Some(deferral);
        }

        // Fire the timer directly.
        gr_selection_deferral_timer_expired(global.clone(), tables).await;

        let g = global.read().await;
        // Deferral must be cleared after timer expiry.
        assert!(g.selection_deferral.is_none());
    }

    #[tokio::test]
    async fn selection_deferral_unknown_peer_established_is_noop() {
        let global = make_global();
        let tables = make_tables();
        let remote_addr: IpAddr = "10.0.0.1".parse().unwrap();
        let unknown_addr: IpAddr = "10.0.0.99".parse().unwrap();
        let context = make_context();

        // Install selection_deferral with remote_addr, but session is from unknown_addr.
        global.write().await.selection_deferral = Some(make_selection_deferral(&[(
            remote_addr,
            vec![Family::IPV4],
        )]));

        let negotiated_gr = Some(NegotiatedGr {
            families: vec![Family::IPV4],
            restart_time: Duration::from_secs(90),
            notification_enabled: false,
        });
        let mut session = PeerSession::new_for_test(unknown_addr, context, tables);
        session
            .process_effects(
                vec![GlobalEffect::GrSessionEstablished { negotiated_gr }],
                &global,
            )
            .await;

        let g = global.read().await;
        // Unknown peer: timer must NOT be started, deferral still in AwaitingStart.
        assert!(g.selection_deferral_timer.is_none());
        assert!(g.selection_deferral.is_some());
    }

    // ---- RFC 8538 N-bit: negotiate_gr N-bit extraction ----

    async fn make_gr_cap(local_flags: u8, peer_flags: u8) -> Option<NegotiatedGr> {
        let tables = make_tables();
        let context = make_context();
        let mut session = PeerSession::new_for_test("10.0.0.1".parse().unwrap(), context, tables);
        session.local_cap = vec![packet::Capability::GracefulRestart {
            flags: local_flags,
            restart_time: 120,
            families: vec![(Family::IPV4, 0)],
        }];
        let remote_caps = vec![packet::Capability::GracefulRestart {
            flags: peer_flags,
            restart_time: 90,
            families: vec![(Family::IPV4, 0)],
        }];
        session.negotiate_gr(&remote_caps)
    }

    #[tokio::test]
    async fn negotiate_gr_both_n_bit_sets_notification_enabled() {
        let gr = make_gr_cap(0x4, 0x4).await.unwrap();
        assert!(gr.notification_enabled);
    }

    #[tokio::test]
    async fn negotiate_gr_only_local_n_bit_not_enabled() {
        let gr = make_gr_cap(0x4, 0x0).await.unwrap();
        assert!(!gr.notification_enabled);
    }

    #[tokio::test]
    async fn negotiate_gr_only_peer_n_bit_not_enabled() {
        let gr = make_gr_cap(0x0, 0x4).await.unwrap();
        assert!(!gr.notification_enabled);
    }

    #[tokio::test]
    async fn negotiate_gr_neither_n_bit_not_enabled() {
        let gr = make_gr_cap(0x0, 0x0).await.unwrap();
        assert!(!gr.notification_enabled);
    }

    // ---- RFC 8538 N-bit: gr_on_disconnect logic ----

    fn make_negotiated_gr(notification_enabled: bool) -> NegotiatedGr {
        NegotiatedGr {
            families: vec![Family::IPV4],
            restart_time: Duration::from_secs(90),
            notification_enabled,
        }
    }

    fn cease(subcode: u8) -> crate::fsm::SessionDownReason {
        crate::fsm::SessionDownReason::RemoteNotification(bgp::Message::Notification(
            rustybgp_packet::Notification::Other {
                code: 6,
                subcode,
                data: vec![],
            },
        ))
    }

    fn local_cease(subcode: u8) -> crate::fsm::SessionDownReason {
        crate::fsm::SessionDownReason::LocalNotification(bgp::Message::Notification(
            rustybgp_packet::Notification::Other {
                code: 6,
                subcode,
                data: vec![],
            },
        ))
    }

    #[test]
    fn gr_on_disconnect_tcp_drop_always_applies() {
        assert!(gr_on_disconnect(&None, make_negotiated_gr(false)).is_some());
        assert!(gr_on_disconnect(&None, make_negotiated_gr(true)).is_some());
    }

    #[test]
    fn gr_on_disconnect_io_error_always_applies() {
        let r = Some(crate::fsm::SessionDownReason::IoError);
        assert!(gr_on_disconnect(&r, make_negotiated_gr(false)).is_some());
        assert!(gr_on_disconnect(&r, make_negotiated_gr(true)).is_some());
    }

    #[test]
    fn gr_on_disconnect_remote_notification_requires_n_bit() {
        assert!(gr_on_disconnect(&Some(cease(0)), make_negotiated_gr(false)).is_none());
        assert!(gr_on_disconnect(&Some(cease(0)), make_negotiated_gr(true)).is_some());
    }

    #[test]
    fn gr_on_disconnect_hard_reset_never_applies() {
        let hard_reset = crate::fsm::SessionDownReason::RemoteNotification(
            bgp::Message::Notification(rustybgp_packet::Notification::CeaseHardReset),
        );
        assert!(gr_on_disconnect(&Some(hard_reset.clone()), make_negotiated_gr(false)).is_none());
        assert!(gr_on_disconnect(&Some(hard_reset), make_negotiated_gr(true)).is_none());
    }

    #[test]
    fn gr_on_disconnect_local_notification_requires_n_bit() {
        assert!(gr_on_disconnect(&Some(local_cease(0)), make_negotiated_gr(false)).is_none());
        assert!(gr_on_disconnect(&Some(local_cease(0)), make_negotiated_gr(true)).is_some());
    }

    #[test]
    fn gr_on_disconnect_local_hard_reset_never_applies() {
        let hard_reset = crate::fsm::SessionDownReason::LocalNotification(
            bgp::Message::Notification(rustybgp_packet::Notification::CeaseHardReset),
        );
        assert!(gr_on_disconnect(&Some(hard_reset), make_negotiated_gr(true)).is_none());
    }

    #[test]
    fn gr_on_disconnect_hold_timer_requires_n_bit() {
        let r = Some(crate::fsm::SessionDownReason::HoldTimerExpired);
        assert!(gr_on_disconnect(&r, make_negotiated_gr(false)).is_none());
        assert!(gr_on_disconnect(&r, make_negotiated_gr(true)).is_some());
    }

    #[test]
    fn gr_on_disconnect_admin_shutdown_never_applies() {
        let r = Some(crate::fsm::SessionDownReason::AdminShutdown);
        assert!(gr_on_disconnect(&r, make_negotiated_gr(false)).is_none());
        assert!(gr_on_disconnect(&r, make_negotiated_gr(true)).is_none());
    }

    #[test]
    fn gr_on_disconnect_fsm_error_never_applies() {
        let r = Some(crate::fsm::SessionDownReason::FsmError);
        assert!(gr_on_disconnect(&r, make_negotiated_gr(false)).is_none());
        assert!(gr_on_disconnect(&r, make_negotiated_gr(true)).is_none());
    }

    /// Tests for process_nlri_change() — the pure routing-update function.
    /// drain_messages() is used to inspect the actual BGP UPDATE/WITHDRAW content.
    mod process_nlri_change {
        use super::*;

        fn nlri(s: &str) -> packet::Nlri {
            s.parse().unwrap()
        }

        fn source(addr: &str) -> Arc<table::Source> {
            let ip: IpAddr = addr.parse().unwrap();
            Arc::new(table::Source::new(
                ip,
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                65002,
                65001,
                Ipv4Addr::new(10, 0, 0, 1),
                PeerRole::Ebgp,
            ))
        }

        fn path(local_path_id: u32, source: Arc<table::Source>) -> table::Path {
            table::Path {
                local_path_id,
                source,
                nexthop: Some(bgp::Nexthop::V4(Ipv4Addr::new(1, 1, 1, 1))),
                attr: Arc::new(vec![
                    packet::Attribute::new_with_value(packet::Attribute::ORIGIN, 0).unwrap(),
                ]),
            }
        }

        fn ebgp_ctx() -> PeerExportContext {
            PeerExportContext {
                role: PeerRole::Ebgp,
                local_asn: 65001,
                local_addr: "127.0.0.1".parse().unwrap(),
                link_addr: None,
                confederation_id: 0,
            }
        }

        fn change(
            nlri: &packet::Nlri,
            best_changed: bool,
            any_changed: bool,
            replaced_path_id: Option<u32>,
            paths: Vec<table::Path>,
        ) -> table::NlriChange {
            table::NlriChange {
                family: Family::IPV4,
                net: nlri.clone(),
                best_changed,
                any_changed,
                replaced_path_id,
                current_paths: Arc::new(paths),
            }
        }

        /// Extract (nlri, path_id) pairs from reach entries in UPDATE messages.
        fn reach_entries(msgs: &[bgp::Message]) -> Vec<(packet::Nlri, u32)> {
            let mut out = Vec::new();
            for msg in msgs {
                if let bgp::Message::Update(bgp::Update::Reach { entries, .. }) = msg {
                    for e in entries {
                        out.push((e.nlri.clone(), e.path_id));
                    }
                }
            }
            out
        }

        /// Extract (nlri, path_id) pairs from unreach entries in UPDATE messages.
        fn unreach_entries(msgs: &[bgp::Message]) -> Vec<(packet::Nlri, u32)> {
            let mut out = Vec::new();
            for msg in msgs {
                if let bgp::Message::Update(bgp::Update::Unreach { entries, .. }) = msg {
                    for e in entries {
                        out.push((e.nlri.clone(), e.path_id));
                    }
                }
            }
            out
        }

        const SELF: &str = "10.0.0.1";
        const PEER: &str = "10.0.0.2";

        // ---- Non-Add-Path (effective_max=1) ----

        #[test]
        fn noop_when_best_unchanged() {
            let mut em = ExportMap::new();
            let mut pending = crate::peer_tx::PendingTx::new(false);
            let net = nlri("10.0.0.0/24");
            let update = change(&net, false, false, None, vec![]);

            process_nlri_change(
                &update,
                1,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ebgp_ctx(),
                None,
                None,
                None,
            );

            assert!(pending.is_empty());
            assert!(!em.was_sent(Family::IPV4, &net));
        }

        #[test]
        fn new_best_sends_update() {
            let mut em = ExportMap::new();
            let mut pending = crate::peer_tx::PendingTx::new(false);
            let net = nlri("10.0.0.0/24");
            let path = path(1, source(PEER));
            let update = change(&net, true, true, None, vec![path]);

            process_nlri_change(
                &update,
                1,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ebgp_ctx(),
                None,
                None,
                None,
            );

            assert!(em.was_sent(Family::IPV4, &net));
            assert!(em.contains_path(Family::IPV4, &net, 0)); // non-addpath uses path_id=0
            let msgs = pending.drain_messages(Family::IPV4);
            let reach = reach_entries(&msgs);
            assert_eq!(reach.len(), 1);
            assert_eq!(reach[0].0, net);
            assert_eq!(reach[0].1, 0); // path_id=0 on wire for non-addpath
        }

        #[test]
        fn withdraw_when_best_gone_and_was_sent() {
            let mut em = ExportMap::new();
            em.mark_sent(Family::IPV4, nlri("10.0.0.0/24"), 0);
            let mut pending = crate::peer_tx::PendingTx::new(false);
            let net = nlri("10.0.0.0/24");
            let update = change(&net, true, true, None, vec![]);

            process_nlri_change(
                &update,
                1,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ebgp_ctx(),
                None,
                None,
                None,
            );

            assert!(!em.was_sent(Family::IPV4, &net));
            let msgs = pending.drain_messages(Family::IPV4);
            let unreach = unreach_entries(&msgs);
            assert_eq!(unreach.len(), 1);
            assert_eq!(unreach[0].0, net);
        }

        #[test]
        fn spurious_withdraw_suppressed() {
            let mut em = ExportMap::new();
            let mut pending = crate::peer_tx::PendingTx::new(false);
            let net = nlri("10.0.0.0/24");
            let update = change(&net, true, true, None, vec![]);

            process_nlri_change(
                &update,
                1,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ebgp_ctx(),
                None,
                None,
                None,
            );

            assert!(pending.is_empty());
            assert!(!em.was_sent(Family::IPV4, &net));
        }

        #[test]
        fn nonaddpath_echo_prevention() {
            let mut em = ExportMap::new();
            let mut pending = crate::peer_tx::PendingTx::new(false);
            let net = nlri("10.0.0.0/24");
            // Path from self — must not be echoed back
            let path = path(1, source(SELF));
            let update = change(&net, true, true, None, vec![path]);

            process_nlri_change(
                &update,
                1,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ebgp_ctx(),
                None,
                None,
                None,
            );

            assert!(pending.is_empty());
            assert!(!em.was_sent(Family::IPV4, &net));
        }

        #[test]
        fn advertise_then_withdraw_sequence() {
            let mut em = ExportMap::new();
            let mut pending = crate::peer_tx::PendingTx::new(false);
            let net = nlri("10.0.0.0/24");
            let remote = SELF.parse().unwrap();

            // 1. Advertise
            let path = path(1, source(PEER));
            process_nlri_change(
                &change(&net, true, true, None, vec![path]),
                1,
                remote,
                &mut em,
                &mut pending,
                &ebgp_ctx(),
                None,
                None,
                None,
            );
            assert!(em.was_sent(Family::IPV4, &net));
            pending.drain_messages(Family::IPV4); // flush

            // 2. Withdraw
            process_nlri_change(
                &change(&net, true, true, None, vec![]),
                1,
                remote,
                &mut em,
                &mut pending,
                &ebgp_ctx(),
                None,
                None,
                None,
            );
            assert!(!em.was_sent(Family::IPV4, &net));
            let msgs = pending.drain_messages(Family::IPV4);
            assert_eq!(unreach_entries(&msgs).len(), 1);
        }

        // ---- Add-Path (effective_max=2) ----

        #[test]
        fn noop_when_any_unchanged() {
            let mut em = ExportMap::new();
            let mut pending = crate::peer_tx::PendingTx::new(true);
            let net = nlri("10.0.0.0/24");
            let path = path(1, source(PEER));
            let update = change(&net, false, false, None, vec![path]);

            process_nlri_change(
                &update,
                2,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ebgp_ctx(),
                None,
                None,
                None,
            );

            assert!(pending.is_empty());
        }

        #[test]
        fn new_paths_send_updates() {
            let mut em = ExportMap::new();
            let mut pending = crate::peer_tx::PendingTx::new(true);
            let net = nlri("10.0.0.0/24");
            let src = source(PEER);
            let paths = vec![path(1, src.clone()), path(2, src.clone())];
            let update = change(&net, true, true, None, paths);

            process_nlri_change(
                &update,
                2,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ebgp_ctx(),
                None,
                None,
                None,
            );

            assert!(em.contains_path(Family::IPV4, &net, 1));
            assert!(em.contains_path(Family::IPV4, &net, 2));
            let msgs = pending.drain_messages(Family::IPV4);
            let reach = reach_entries(&msgs);
            let pids: std::collections::HashSet<u32> = reach.iter().map(|e| e.1).collect();
            assert!(pids.contains(&1));
            assert!(pids.contains(&2));
            assert!(reach.iter().all(|e| e.0 == net));
        }

        #[test]
        fn path_removed_sends_withdraw() {
            let mut em = ExportMap::new();
            let net = nlri("10.0.0.0/24");
            em.mark_sent(Family::IPV4, net.clone(), 1);
            em.mark_sent(Family::IPV4, net.clone(), 2);
            let mut pending = crate::peer_tx::PendingTx::new(true);
            let src = source(PEER);
            // path_id=2 is removed; only path_id=1 remains
            let update = change(&net, true, true, None, vec![path(1, src)]);

            process_nlri_change(
                &update,
                2,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ebgp_ctx(),
                None,
                None,
                None,
            );

            assert!(em.contains_path(Family::IPV4, &net, 1));
            assert!(!em.contains_path(Family::IPV4, &net, 2));
            let msgs = pending.drain_messages(Family::IPV4);
            let unreach = unreach_entries(&msgs);
            assert_eq!(unreach.len(), 1);
            assert_eq!(unreach[0].1, 2);
        }

        #[test]
        fn replaced_path_readvertised() {
            let mut em = ExportMap::new();
            let net = nlri("10.0.0.0/24");
            em.mark_sent(Family::IPV4, net.clone(), 1);
            em.mark_sent(Family::IPV4, net.clone(), 2);
            let mut pending = crate::peer_tx::PendingTx::new(true);
            let src = source(PEER);
            // path_id=1 was replaced (new attributes); path_id=2 unchanged
            let paths = vec![path(1, src.clone()), path(2, src)];
            let update = change(&net, false, true, Some(1), paths);

            process_nlri_change(
                &update,
                2,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ebgp_ctx(),
                None,
                None,
                None,
            );

            let msgs = pending.drain_messages(Family::IPV4);
            let reach = reach_entries(&msgs);
            // Only path_id=1 re-advertised; path_id=2 unchanged
            assert_eq!(reach.len(), 1);
            assert_eq!(reach[0].1, 1);
            assert!(unreach_entries(&msgs).is_empty());
        }

        #[test]
        fn new_path_pushes_existing_out_of_send_max() {
            // Before: export_map = {pid=1(rank1), pid=2(rank2)}, send_max=2
            // New path pid=3 arrives at rank1 → current_paths = [pid=3, pid=1, pid=2]
            // top-2 = [pid=3, pid=1]; pid=2 pushed out → WITHDRAW pid=2, UPDATE pid=3
            let mut em = ExportMap::new();
            let net = nlri("10.0.0.0/24");
            em.mark_sent(Family::IPV4, net.clone(), 1);
            em.mark_sent(Family::IPV4, net.clone(), 2);
            let mut pending = crate::peer_tx::PendingTx::new(true);
            let src = source(PEER);
            let paths = vec![path(3, src.clone()), path(1, src.clone()), path(2, src)];
            let update = change(&net, true, true, None, paths);

            process_nlri_change(
                &update,
                2,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ebgp_ctx(),
                None,
                None,
                None,
            );

            assert!(em.contains_path(Family::IPV4, &net, 3));
            assert!(em.contains_path(Family::IPV4, &net, 1));
            assert!(!em.contains_path(Family::IPV4, &net, 2)); // pushed out
            let msgs = pending.drain_messages(Family::IPV4);
            let reach_pids: Vec<u32> = reach_entries(&msgs).into_iter().map(|e| e.1).collect();
            let unreach_pids: Vec<u32> = unreach_entries(&msgs).into_iter().map(|e| e.1).collect();
            assert!(reach_pids.contains(&3));
            assert!(!reach_pids.contains(&1)); // already sent, no re-advertise
            assert_eq!(unreach_pids, vec![2]);
        }

        #[test]
        fn path_deleted_pulls_outside_path_into_send_max() {
            // Before: export_map = {pid=1(rank1), pid=2(rank2)}, send_max=2
            // paths = [pid=1(rank1), pid=2(rank2), pid=3(rank3)] — pid=3 outside window
            // Delete pid=1 → current_paths = [pid=2(rank1), pid=3(rank2)]
            // top-2 = [pid=2, pid=3]: WITHDRAW pid=1, UPDATE pid=3 (enters window)
            let mut em = ExportMap::new();
            let net = nlri("10.0.0.0/24");
            em.mark_sent(Family::IPV4, net.clone(), 1);
            em.mark_sent(Family::IPV4, net.clone(), 2);
            let mut pending = crate::peer_tx::PendingTx::new(true);
            let src = source(PEER);
            // pid=1 was removed; remaining: pid=2, pid=3
            let paths = vec![path(2, src.clone()), path(3, src)];
            let update = change(&net, true, true, None, paths);

            process_nlri_change(
                &update,
                2,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ebgp_ctx(),
                None,
                None,
                None,
            );

            assert!(!em.contains_path(Family::IPV4, &net, 1)); // withdrawn
            assert!(em.contains_path(Family::IPV4, &net, 2)); // kept
            assert!(em.contains_path(Family::IPV4, &net, 3)); // entered window
            let msgs = pending.drain_messages(Family::IPV4);
            let reach_pids: Vec<u32> = reach_entries(&msgs).into_iter().map(|e| e.1).collect();
            let unreach_pids: Vec<u32> = unreach_entries(&msgs).into_iter().map(|e| e.1).collect();
            assert!(reach_pids.contains(&3));
            assert!(!reach_pids.contains(&2)); // already sent
            assert_eq!(unreach_pids, vec![1]);
        }

        #[test]
        fn all_paths_removed_withdraws_all() {
            let mut em = ExportMap::new();
            let net = nlri("10.0.0.0/24");
            em.mark_sent(Family::IPV4, net.clone(), 1);
            em.mark_sent(Family::IPV4, net.clone(), 2);
            let mut pending = crate::peer_tx::PendingTx::new(true);
            let update = change(&net, true, true, None, vec![]);

            process_nlri_change(
                &update,
                2,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ebgp_ctx(),
                None,
                None,
                None,
            );

            assert!(!em.was_sent(Family::IPV4, &net));
            let msgs = pending.drain_messages(Family::IPV4);
            let unreach_pids: std::collections::HashSet<u32> =
                unreach_entries(&msgs).into_iter().map(|e| e.1).collect();
            assert!(unreach_pids.contains(&1));
            assert!(unreach_pids.contains(&2));
        }

        #[test]
        fn addpath_echo_prevention() {
            let mut em = ExportMap::new();
            let mut pending = crate::peer_tx::PendingTx::new(true);
            let net = nlri("10.0.0.0/24");
            // Both paths from self — neither should be sent
            let self_src = source(SELF);
            let paths = vec![path(1, self_src.clone()), path(2, self_src)];
            let update = change(&net, true, true, None, paths);

            process_nlri_change(
                &update,
                2,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ebgp_ctx(),
                None,
                None,
                None,
            );

            assert!(pending.is_empty());
            assert!(!em.was_sent(Family::IPV4, &net));
        }

        #[test]
        fn mixed_self_and_peer_paths() {
            // Only peer paths should be sent; self paths filtered out
            let mut em = ExportMap::new();
            let mut pending = crate::peer_tx::PendingTx::new(true);
            let net = nlri("10.0.0.0/24");
            let self_src = source(SELF);
            let peer_src = source(PEER);
            let paths = vec![
                path(1, peer_src.clone()),
                path(2, self_src), // filtered
                path(3, peer_src),
            ];
            let update = change(&net, true, true, None, paths);

            // send_max=3 but only 2 peer paths after echo filter
            process_nlri_change(
                &update,
                3,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ebgp_ctx(),
                None,
                None,
                None,
            );

            assert!(em.contains_path(Family::IPV4, &net, 1));
            assert!(!em.contains_path(Family::IPV4, &net, 2)); // self path not sent
            assert!(em.contains_path(Family::IPV4, &net, 3));
            let msgs = pending.drain_messages(Family::IPV4);
            let reach_pids: Vec<u32> = reach_entries(&msgs).into_iter().map(|e| e.1).collect();
            assert_eq!(reach_pids.len(), 2);
            assert!(reach_pids.contains(&1));
            assert!(reach_pids.contains(&3));
        }
        // ---- iBGP split horizon ----

        fn ibgp_source(addr: &str) -> Arc<table::Source> {
            let ip: IpAddr = addr.parse().unwrap();
            Arc::new(table::Source::new(
                ip,
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                65001,
                65001,
                Ipv4Addr::new(10, 0, 0, 1),
                PeerRole::Ibgp,
            ))
        }

        fn ibgp_ctx() -> PeerExportContext {
            PeerExportContext {
                role: PeerRole::Ibgp,
                local_asn: 65001,
                local_addr: "127.0.0.1".parse().unwrap(),
                link_addr: None,
                confederation_id: 0,
            }
        }

        #[test]
        fn ibgp_split_horizon_suppresses_ibgp_learned_route() {
            let mut em = ExportMap::new();
            let mut pending = crate::peer_tx::PendingTx::new(false);
            let net = nlri("10.0.0.0/24");
            // Route learned from an iBGP peer (remote_asn == local_asn)
            let path = path(1, ibgp_source(PEER));
            let update = change(&net, true, true, None, vec![path]);

            process_nlri_change(
                &update,
                1,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ibgp_ctx(),
                None,
                None,
                None,
            );

            // Split horizon: iBGP-learned route must not be forwarded to iBGP peer
            assert!(pending.is_empty());
            assert!(!em.was_sent(Family::IPV4, &net));
        }

        #[test]
        fn ibgp_split_horizon_withdraws_when_best_becomes_ibgp() {
            let mut em = ExportMap::new();
            let net = nlri("10.0.0.0/24");
            // Previously sent an eBGP-learned best
            em.mark_sent(Family::IPV4, net.clone(), 0);
            let mut pending = crate::peer_tx::PendingTx::new(false);
            // New best is iBGP-learned
            let path = path(1, ibgp_source(PEER));
            let update = change(&net, true, true, None, vec![path]);

            process_nlri_change(
                &update,
                1,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ibgp_ctx(),
                None,
                None,
                None,
            );

            // Must send a withdrawal for the previously-sent route
            assert!(!em.was_sent(Family::IPV4, &net));
            let msgs = pending.drain_messages(Family::IPV4);
            assert_eq!(unreach_entries(&msgs).len(), 1);
        }

        #[test]
        fn ibgp_forwards_ebgp_learned_route() {
            let mut em = ExportMap::new();
            let mut pending = crate::peer_tx::PendingTx::new(false);
            let net = nlri("10.0.0.0/24");
            // Route learned from an eBGP peer (remote_asn != local_asn)
            let path = path(1, source(PEER)); // source() uses remote_asn=65002
            let update = change(&net, true, true, None, vec![path]);

            process_nlri_change(
                &update,
                1,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ibgp_ctx(),
                None,
                None,
                None,
            );

            // eBGP-learned route CAN be forwarded to iBGP peer
            assert!(em.was_sent(Family::IPV4, &net));
            let msgs = pending.drain_messages(Family::IPV4);
            assert_eq!(reach_entries(&msgs).len(), 1);
        }

        #[test]
        fn ibgp_split_horizon_addpath_filters_ibgp_paths() {
            let mut em = ExportMap::new();
            let mut pending = crate::peer_tx::PendingTx::new(true);
            let net = nlri("10.0.0.0/24");
            let paths = vec![
                path(1, ibgp_source(PEER)), // iBGP-learned — must be filtered
                path(2, source(PEER)),      // eBGP-learned — may be forwarded
            ];
            let update = change(&net, true, true, None, paths);

            process_nlri_change(
                &update,
                2,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ibgp_ctx(),
                None,
                None,
                None,
            );

            // Only the eBGP-learned path (pid=2) should be advertised
            assert!(!em.contains_path(Family::IPV4, &net, 1));
            assert!(em.contains_path(Family::IPV4, &net, 2));
            let msgs = pending.drain_messages(Family::IPV4);
            let reach = reach_entries(&msgs);
            assert_eq!(reach.len(), 1);
            assert_eq!(reach[0].1, 2);
        }

        // ---- export_attrs / export_nexthop per-role correctness ----

        fn attr_with_local_pref() -> Arc<Vec<packet::Attribute>> {
            Arc::new(vec![
                packet::Attribute::new_with_value(packet::Attribute::ORIGIN, 0).unwrap(),
                packet::Attribute::new_with_value(packet::Attribute::LOCAL_PREF, 200).unwrap(),
            ])
        }

        fn attr_with_aspath() -> Arc<Vec<packet::Attribute>> {
            Arc::new(vec![
                packet::Attribute::new_with_value(packet::Attribute::ORIGIN, 0).unwrap(),
                packet::Attribute::empty_as_path(),
            ])
        }

        fn attr_with_med() -> Arc<Vec<packet::Attribute>> {
            Arc::new(vec![
                packet::Attribute::new_with_value(packet::Attribute::ORIGIN, 0).unwrap(),
                packet::Attribute::new_with_value(packet::Attribute::MULTI_EXIT_DESC, 50).unwrap(),
            ])
        }

        #[test]
        fn ebgp_export_strips_local_pref() {
            let ctx = ebgp_ctx();
            let exported = ctx.export_attrs(&attr_with_local_pref());
            assert!(
                exported
                    .iter()
                    .all(|a| a.code() != packet::Attribute::LOCAL_PREF),
                "LOCAL_PREF must be stripped for eBGP"
            );
        }

        #[test]
        fn ibgp_export_keeps_local_pref() {
            let ctx = ibgp_ctx();
            let exported = ctx.export_attrs(&attr_with_local_pref());
            assert!(
                exported
                    .iter()
                    .any(|a| a.code() == packet::Attribute::LOCAL_PREF),
                "LOCAL_PREF must be preserved for iBGP"
            );
        }

        #[test]
        fn ebgp_export_prepends_aspath() {
            let ctx = ebgp_ctx();
            let exported = ctx.export_attrs(&attr_with_aspath());
            let aspath = exported
                .iter()
                .find(|a| a.code() == packet::Attribute::AS_PATH)
                .expect("AS_PATH must be present");
            // After prepend, AS_PATH origin should be local_asn (65001)
            assert_eq!(aspath.as_path_origin(), Some(65001));
        }

        #[test]
        fn ibgp_export_does_not_prepend_aspath() {
            let ctx = ibgp_ctx();
            let original = attr_with_aspath();
            let exported = ctx.export_attrs(&original);
            let aspath = exported
                .iter()
                .find(|a| a.code() == packet::Attribute::AS_PATH)
                .expect("AS_PATH must be present after iBGP export");
            assert_eq!(
                aspath.as_path_origin(),
                None,
                "iBGP export must not prepend local ASN to AS_PATH"
            );
        }

        #[test]
        fn ibgp_export_injects_local_pref_when_absent() {
            let ctx = ibgp_ctx();
            let exported = ctx.export_attrs(&attr_with_aspath());
            assert!(
                exported
                    .iter()
                    .any(|a| a.code() == packet::Attribute::LOCAL_PREF
                        && a.value() == Some(packet::Attribute::DEFAULT_LOCAL_PREF)),
                "iBGP export must inject LOCAL_PREF=100 when absent"
            );
        }

        #[test]
        fn ebgp_export_strips_med() {
            let ctx = ebgp_ctx();
            let exported = ctx.export_attrs(&attr_with_med());
            assert!(
                exported
                    .iter()
                    .all(|a| a.code() != packet::Attribute::MULTI_EXIT_DESC),
                "MED must be stripped for eBGP (non-transitive, MUST NOT leak to other ASes)"
            );
        }

        #[test]
        fn ibgp_export_keeps_med() {
            let ctx = ibgp_ctx();
            let exported = ctx.export_attrs(&attr_with_med());
            assert!(
                exported.iter().any(
                    |a| a.code() == packet::Attribute::MULTI_EXIT_DESC && a.value() == Some(50)
                ),
                "MED must be passed through for iBGP"
            );
        }

        fn attr_with_originator_id() -> Arc<Vec<packet::Attribute>> {
            Arc::new(vec![
                packet::Attribute::new_with_value(packet::Attribute::ORIGIN, 0).unwrap(),
                packet::Attribute::new_with_value(packet::Attribute::ORIGINATOR_ID, 0x0a000001)
                    .unwrap(),
            ])
        }

        fn attr_with_cluster_list() -> Arc<Vec<packet::Attribute>> {
            Arc::new(vec![
                packet::Attribute::new_with_value(packet::Attribute::ORIGIN, 0).unwrap(),
                packet::Attribute::new_with_bin(
                    packet::Attribute::CLUSTER_LIST,
                    vec![0x00, 0x00, 0xff, 0x01],
                )
                .unwrap(),
            ])
        }

        #[test]
        fn ebgp_export_strips_originator_id() {
            let ctx = ebgp_ctx();
            let exported = ctx.export_attrs(&attr_with_originator_id());
            assert!(
                exported
                    .iter()
                    .all(|a| a.code() != packet::Attribute::ORIGINATOR_ID),
                "ORIGINATOR_ID must be stripped for eBGP"
            );
        }

        #[test]
        fn ebgp_export_strips_cluster_list() {
            let ctx = ebgp_ctx();
            let exported = ctx.export_attrs(&attr_with_cluster_list());
            assert!(
                exported
                    .iter()
                    .all(|a| a.code() != packet::Attribute::CLUSTER_LIST),
                "CLUSTER_LIST must be stripped for eBGP"
            );
        }

        #[test]
        fn ibgp_export_keeps_originator_id() {
            let ctx = ibgp_ctx();
            let exported = ctx.export_attrs(&attr_with_originator_id());
            assert!(
                exported
                    .iter()
                    .any(|a| a.code() == packet::Attribute::ORIGINATOR_ID),
                "ORIGINATOR_ID must be preserved for iBGP"
            );
        }

        #[test]
        fn ibgp_export_keeps_cluster_list() {
            let ctx = ibgp_ctx();
            let exported = ctx.export_attrs(&attr_with_cluster_list());
            assert!(
                exported
                    .iter()
                    .any(|a| a.code() == packet::Attribute::CLUSTER_LIST),
                "CLUSTER_LIST must be preserved for iBGP"
            );
        }

        #[test]
        fn rs_client_export_passes_attrs_unchanged() {
            let ctx = rs_client_ctx();
            // RS client must pass attrs as-is: no stripping, no LOCAL_PREF injection.
            let attrs = attr_with_originator_id();
            let exported = ctx.export_attrs(&attrs);
            assert_eq!(
                exported.len(),
                attrs.len(),
                "RS client must not add or remove any attributes"
            );
            assert!(
                exported
                    .iter()
                    .any(|a| a.code() == packet::Attribute::ORIGINATOR_ID),
                "RS client must preserve ORIGINATOR_ID"
            );
            assert!(
                exported
                    .iter()
                    .all(|a| a.code() != packet::Attribute::LOCAL_PREF),
                "RS client must not inject LOCAL_PREF"
            );
        }

        fn attr_with_opaque_transitive() -> Arc<Vec<packet::Attribute>> {
            Arc::new(vec![
                packet::Attribute::new_with_value(packet::Attribute::ORIGIN, 0).unwrap(),
                // Unknown optional transitive (code=200, flags=optional|transitive)
                packet::Attribute::new_opaque(
                    200,
                    packet::Attribute::FLAG_PARTIAL
                        | 0x40 /* transitive */
                        | 0x80, /* optional */
                    vec![0x01, 0x02, 0x03],
                ),
            ])
        }

        fn attr_with_opaque_non_transitive() -> Arc<Vec<packet::Attribute>> {
            Arc::new(vec![
                packet::Attribute::new_with_value(packet::Attribute::ORIGIN, 0).unwrap(),
                // Unknown optional non-transitive (code=201, flags=optional only)
                packet::Attribute::new_opaque(
                    201,
                    0x80, /* optional */
                    vec![0x04, 0x05, 0x06],
                ),
            ])
        }

        #[test]
        fn opaque_transitive_attr_forwarded_with_partial_bit() {
            // RFC 4271 §5.1.4: unknown optional transitive attrs are forwarded
            // with PARTIAL bit set, for every peer role.
            for ctx in [ebgp_ctx(), ibgp_ctx(), rs_client_ctx()] {
                let exported = ctx.export_attrs(&attr_with_opaque_transitive());
                let opaque = exported.iter().find(|a| a.code() == 200);
                assert!(
                    opaque.is_some(),
                    "unknown optional transitive attr must be forwarded (role: {:?})",
                    ctx.role
                );
                assert!(
                    opaque.unwrap().flags() & packet::Attribute::FLAG_PARTIAL != 0,
                    "PARTIAL bit must be set on forwarded unknown transitive attr (role: {:?})",
                    ctx.role
                );
            }
        }

        #[test]
        fn opaque_non_transitive_attr_discarded() {
            // RFC 4271 §5.1.4: unknown optional non-transitive attrs are discarded.
            for ctx in [ebgp_ctx(), ibgp_ctx(), rs_client_ctx()] {
                let exported = ctx.export_attrs(&attr_with_opaque_non_transitive());
                assert!(
                    exported.iter().all(|a| a.code() != 201),
                    "unknown optional non-transitive attr must be discarded (role: {:?})",
                    ctx.role
                );
            }
        }

        fn aigp_attr() -> Arc<Vec<bgp::Attribute>> {
            // AIGP TLV: type=1, len=11, value=8-byte metric (all zeros)
            let aigp_tlv: Vec<u8> = vec![1, 0, 11, 0, 0, 0, 0, 0, 0, 0, 0];
            Arc::new(vec![
                bgp::Attribute::new_with_bin(bgp::Attribute::AIGP, aigp_tlv).unwrap(),
            ])
        }

        #[test]
        fn ebgp_export_strips_aigp() {
            // AIGP is optional non-transitive (RFC 7311 §2.1); must not cross AS boundaries.
            let exported = ebgp_ctx().export_attrs(&aigp_attr());
            assert!(
                exported.iter().all(|a| a.code() != bgp::Attribute::AIGP),
                "eBGP export must strip AIGP"
            );
        }

        #[test]
        fn ibgp_export_keeps_aigp() {
            // AIGP is iBGP-safe: non-transitive attrs are forwarded within the AS.
            let exported = ibgp_ctx().export_attrs(&aigp_attr());
            assert!(
                exported.iter().any(|a| a.code() == bgp::Attribute::AIGP),
                "iBGP export must keep AIGP"
            );
        }

        #[test]
        fn ebgp_export_rewrites_nexthop() {
            let ctx = ebgp_ctx(); // local_addr = 127.0.0.1
            let original = bgp::Nexthop::V4(Ipv4Addr::new(10, 0, 0, 1));
            let exported = ctx.export_nexthop(Some(original));
            assert_eq!(
                exported,
                Some(bgp::Nexthop::V4(Ipv4Addr::new(127, 0, 0, 1))),
                "eBGP nexthop must be rewritten to local_addr"
            );
        }

        #[test]
        fn ibgp_export_keeps_nexthop() {
            let ctx = ibgp_ctx();
            let original = bgp::Nexthop::V4(Ipv4Addr::new(10, 0, 0, 1));
            let exported = ctx.export_nexthop(Some(original));
            assert_eq!(exported, Some(original), "iBGP nexthop must be unchanged");
        }

        // ---- Confederation: export_attrs / export_nexthop ----

        fn confed_ebgp_ctx() -> PeerExportContext {
            PeerExportContext {
                role: PeerRole::ConfedEbgp,
                local_asn: 65001,
                local_addr: "127.0.0.1".parse().unwrap(),
                link_addr: None,
                confederation_id: 65000,
            }
        }

        fn ebgp_confed_ctx() -> PeerExportContext {
            PeerExportContext {
                role: PeerRole::Ebgp,
                local_asn: 65001,
                local_addr: "127.0.0.1".parse().unwrap(),
                link_addr: None,
                confederation_id: 65000,
            }
        }

        fn attr_with_confed_seq() -> Arc<Vec<packet::Attribute>> {
            // AS_PATH: AS_CONFED_SEQ [65002] followed by AS_SEQ [65100]
            let mut data: Vec<u8> = vec![packet::Attribute::AS_PATH_TYPE_CONFED_SEQ, 1];
            data.extend_from_slice(&65002u32.to_be_bytes());
            data.extend_from_slice(&[packet::Attribute::AS_PATH_TYPE_SEQ, 1]);
            data.extend_from_slice(&65100u32.to_be_bytes());
            Arc::new(vec![
                packet::Attribute::new_with_value(packet::Attribute::ORIGIN, 0).unwrap(),
                packet::Attribute::new_with_value(packet::Attribute::LOCAL_PREF, 100).unwrap(),
                packet::Attribute::new_with_bin(packet::Attribute::AS_PATH, data).unwrap(),
            ])
        }

        #[test]
        fn confed_ebgp_export_attrs_prepends_confed_seq() {
            let ctx = confed_ebgp_ctx();
            let exported = ctx.export_attrs(&attr_with_aspath());
            let aspath = exported
                .iter()
                .find(|a| a.code() == packet::Attribute::AS_PATH)
                .expect("AS_PATH must be present");
            let buf = aspath.binary().unwrap();
            assert_eq!(
                buf[0],
                packet::Attribute::AS_PATH_TYPE_CONFED_SEQ,
                "first segment must be AS_CONFED_SEQ"
            );
            assert_eq!(buf[1], 1, "segment must have one entry");
            let asn = u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]);
            assert_eq!(asn, 65001, "prepended ASN must be local_asn");
        }

        #[test]
        fn confed_ebgp_export_attrs_retains_local_pref() {
            let ctx = confed_ebgp_ctx();
            let attrs = Arc::new(vec![
                packet::Attribute::new_with_value(packet::Attribute::ORIGIN, 0).unwrap(),
                packet::Attribute::new_with_value(packet::Attribute::LOCAL_PREF, 200).unwrap(),
            ]);
            let exported = ctx.export_attrs(&attrs);
            assert!(
                exported
                    .iter()
                    .any(|a| a.code() == packet::Attribute::LOCAL_PREF),
                "ConfedEbgp must retain LOCAL_PREF"
            );
        }

        #[test]
        fn ebgp_with_confederation_strips_confed_and_prepends_id() {
            let ctx = ebgp_confed_ctx();
            let exported = ctx.export_attrs(&attr_with_confed_seq());
            let aspath = exported
                .iter()
                .find(|a| a.code() == packet::Attribute::AS_PATH)
                .expect("AS_PATH must be present");
            let buf = aspath.binary().unwrap();
            // First segment must be AS_SEQUENCE with confederation_id (65000)
            assert_eq!(
                buf[0],
                packet::Attribute::AS_PATH_TYPE_SEQ,
                "first segment must be AS_SEQUENCE"
            );
            let prepended = u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]);
            assert_eq!(prepended, 65000, "prepended ASN must be confederation_id");
            // No CONFED segments must remain
            assert!(
                !buf.iter().any(|&b| {
                    b == packet::Attribute::AS_PATH_TYPE_CONFED_SEQ
                        || b == packet::Attribute::AS_PATH_TYPE_CONFED_SET
                }),
                "CONFED segments must be stripped"
            );
            // LOCAL_PREF must be gone
            assert!(
                exported
                    .iter()
                    .all(|a| a.code() != packet::Attribute::LOCAL_PREF),
                "LOCAL_PREF must be stripped for Ebgp"
            );
        }

        #[test]
        fn confed_ebgp_export_nexthop_rewrites_to_local() {
            let ctx = confed_ebgp_ctx(); // local_addr = 127.0.0.1
            let original = bgp::Nexthop::V4(Ipv4Addr::new(10, 0, 0, 1));
            let exported = ctx.export_nexthop(Some(original));
            assert_eq!(
                exported,
                Some(bgp::Nexthop::V4(Ipv4Addr::new(127, 0, 0, 1))),
                "ConfedEbgp nexthop must be rewritten to local_addr"
            );
        }

        // ---- Route Reflector: split horizon relaxation ----

        fn rr_client_source(addr: &str) -> Arc<table::Source> {
            let ip: IpAddr = addr.parse().unwrap();
            Arc::new(table::Source::new(
                ip,
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                65001,
                65001,
                Ipv4Addr::new(10, 0, 0, 1),
                PeerRole::IbgpRrClient,
            ))
        }

        fn ibgp_rr_client_ctx() -> PeerExportContext {
            PeerExportContext {
                role: PeerRole::IbgpRrClient,
                local_asn: 65001,
                local_addr: "127.0.0.1".parse().unwrap(),
                link_addr: None,
                confederation_id: 0,
            }
        }

        const CLUSTER_ID: Ipv4Addr = Ipv4Addr::new(1, 0, 0, 1);

        // non-client source -> non-client dest: still suppressed in RR mode
        #[test]
        fn rr_non_client_to_non_client_suppressed() {
            let mut em = ExportMap::new();
            let mut pending = crate::peer_tx::PendingTx::new(false);
            let net = nlri("10.0.0.0/24");
            let p = path(1, ibgp_source(PEER));
            let update = change(&net, true, true, None, vec![p]);

            process_nlri_change(
                &update,
                1,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ibgp_ctx(),
                None,
                Some(CLUSTER_ID),
                None,
            );

            assert!(pending.is_empty());
            assert!(!em.was_sent(Family::IPV4, &net));
        }

        // rr-client source -> non-client dest: forwarded in RR mode
        #[test]
        fn rr_client_source_forwarded_to_non_client() {
            let mut em = ExportMap::new();
            let mut pending = crate::peer_tx::PendingTx::new(false);
            let net = nlri("10.0.0.0/24");
            let p = path(1, rr_client_source(PEER));
            let update = change(&net, true, true, None, vec![p]);

            process_nlri_change(
                &update,
                1,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ibgp_ctx(),
                None,
                Some(CLUSTER_ID),
                None,
            );

            assert!(em.was_sent(Family::IPV4, &net));
            assert_eq!(
                reach_entries(&pending.drain_messages(Family::IPV4)).len(),
                1
            );
        }

        // non-client source -> rr-client dest: forwarded in RR mode
        #[test]
        fn rr_non_client_forwarded_to_rr_client() {
            let mut em = ExportMap::new();
            let mut pending = crate::peer_tx::PendingTx::new(false);
            let net = nlri("10.0.0.0/24");
            let p = path(1, ibgp_source(PEER));
            let update = change(&net, true, true, None, vec![p]);

            process_nlri_change(
                &update,
                1,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ibgp_rr_client_ctx(),
                None,
                Some(CLUSTER_ID),
                None,
            );

            assert!(em.was_sent(Family::IPV4, &net));
            assert_eq!(
                reach_entries(&pending.drain_messages(Family::IPV4)).len(),
                1
            );
        }

        // ---- Route Reflector: rr_reflect_attrs via process_nlri_change ----

        fn path_with_attrs(
            pid: u32,
            src: Arc<table::Source>,
            attrs: Arc<Vec<packet::Attribute>>,
        ) -> table::Path {
            table::Path {
                local_path_id: pid,
                source: src,
                nexthop: Some(bgp::Nexthop::V4(Ipv4Addr::new(1, 1, 1, 1))),
                attr: attrs,
            }
        }

        fn drain_first_reach_attrs(
            pending: &mut crate::peer_tx::PendingTx,
        ) -> Arc<Vec<packet::Attribute>> {
            let msgs = pending.drain_messages(Family::IPV4);
            for msg in msgs {
                if let bgp::Message::Update(bgp::Update::Reach { entries, attr, .. }) = msg
                    && !entries.is_empty()
                {
                    return attr;
                }
            }
            panic!("no reach message found");
        }

        // ORIGINATOR_ID is set to source router_id when absent
        #[test]
        fn rr_reflect_sets_originator_id() {
            let mut em = ExportMap::new();
            let mut pending = crate::peer_tx::PendingTx::new(false);
            let net = nlri("10.0.0.0/24");
            // ibgp_source router_id = 10.0.0.1
            let p = path(1, ibgp_source(PEER));
            let update = change(&net, true, true, None, vec![p]);

            process_nlri_change(
                &update,
                1,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ibgp_rr_client_ctx(),
                None,
                Some(CLUSTER_ID),
                None,
            );

            let attrs = drain_first_reach_attrs(&mut pending);
            let orig = attrs
                .iter()
                .find(|a| a.code() == packet::Attribute::ORIGINATOR_ID)
                .expect("ORIGINATOR_ID must be present after reflection");
            assert_eq!(
                orig.value().unwrap(),
                u32::from(Ipv4Addr::new(10, 0, 0, 1)),
                "ORIGINATOR_ID must equal source router_id"
            );
        }

        // Existing ORIGINATOR_ID is preserved (not overwritten)
        #[test]
        fn rr_reflect_preserves_existing_originator_id() {
            let mut em = ExportMap::new();
            let mut pending = crate::peer_tx::PendingTx::new(false);
            let net = nlri("10.0.0.0/24");
            let orig_id = u32::from(Ipv4Addr::new(9, 9, 9, 9));
            let attrs = Arc::new(vec![
                packet::Attribute::new_with_value(packet::Attribute::ORIGIN, 0).unwrap(),
                packet::Attribute::new_with_value(packet::Attribute::ORIGINATOR_ID, orig_id)
                    .unwrap(),
            ]);
            let src = ibgp_source(PEER);
            let p = path_with_attrs(1, src, attrs);
            let update = change(&net, true, true, None, vec![p]);

            process_nlri_change(
                &update,
                1,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ibgp_rr_client_ctx(),
                None,
                Some(CLUSTER_ID),
                None,
            );

            let attrs = drain_first_reach_attrs(&mut pending);
            let origs: Vec<_> = attrs
                .iter()
                .filter(|a| a.code() == packet::Attribute::ORIGINATOR_ID)
                .collect();
            assert_eq!(origs.len(), 1, "must have exactly one ORIGINATOR_ID");
            assert_eq!(
                origs[0].value().unwrap(),
                orig_id,
                "existing ORIGINATOR_ID must not be overwritten"
            );
        }

        // Local cluster_id is prepended to CLUSTER_LIST
        #[test]
        fn rr_reflect_prepends_cluster_id_to_cluster_list() {
            let mut em = ExportMap::new();
            let mut pending = crate::peer_tx::PendingTx::new(false);
            let net = nlri("10.0.0.0/24");
            let existing_cid = Ipv4Addr::new(2, 0, 0, 2);
            let cluster_bytes: Vec<u8> = u32::from(existing_cid).to_be_bytes().to_vec();
            let attrs = Arc::new(vec![
                packet::Attribute::new_with_value(packet::Attribute::ORIGIN, 0).unwrap(),
                packet::Attribute::new_with_bin(packet::Attribute::CLUSTER_LIST, cluster_bytes)
                    .unwrap(),
            ]);
            let p = path_with_attrs(1, ibgp_source(PEER), attrs);
            let update = change(&net, true, true, None, vec![p]);

            process_nlri_change(
                &update,
                1,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ibgp_rr_client_ctx(),
                None,
                Some(CLUSTER_ID),
                None,
            );

            let attrs = drain_first_reach_attrs(&mut pending);
            let cl = attrs
                .iter()
                .find(|a| a.code() == packet::Attribute::CLUSTER_LIST)
                .expect("CLUSTER_LIST must be present");
            let bytes = cl.binary().expect("CLUSTER_LIST must have binary value");
            assert_eq!(bytes.len(), 8, "must contain two 4-byte cluster IDs");
            let first = Ipv4Addr::from(u32::from_be_bytes(bytes[0..4].try_into().unwrap()));
            let second = Ipv4Addr::from(u32::from_be_bytes(bytes[4..8].try_into().unwrap()));
            assert_eq!(first, CLUSTER_ID, "local cluster_id must be prepended");
            assert_eq!(second, existing_cid, "original cluster_id must follow");
        }

        // CLUSTER_LIST is created from scratch (not present in original attrs)
        #[test]
        fn rr_reflect_creates_cluster_list_when_absent() {
            let mut em = ExportMap::new();
            let mut pending = crate::peer_tx::PendingTx::new(false);
            let net = nlri("10.0.0.0/24");
            // path() uses plain attrs (ORIGIN only, no CLUSTER_LIST)
            let p = path(1, ibgp_source(PEER));
            let update = change(&net, true, true, None, vec![p]);

            process_nlri_change(
                &update,
                1,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ibgp_rr_client_ctx(),
                None,
                Some(CLUSTER_ID),
                None,
            );

            let attrs = drain_first_reach_attrs(&mut pending);
            let cl = attrs
                .iter()
                .find(|a| a.code() == packet::Attribute::CLUSTER_LIST)
                .expect("CLUSTER_LIST must be created when absent");
            let bytes = cl.binary().expect("CLUSTER_LIST must have binary value");
            assert_eq!(bytes.len(), 4, "must contain exactly one cluster ID");
            let cid = Ipv4Addr::from(u32::from_be_bytes(bytes[0..4].try_into().unwrap()));
            assert_eq!(cid, CLUSTER_ID, "sole entry must be local cluster_id");
        }

        // eBGP-learned route forwarded to RR client: no RR attributes added
        #[test]
        fn rr_no_reflection_for_ebgp_route() {
            let mut em = ExportMap::new();
            let mut pending = crate::peer_tx::PendingTx::new(false);
            let net = nlri("10.0.0.0/24");
            // source() has remote_asn=65002, local_asn=65001 → eBGP learned
            let p = path(1, source(PEER));
            let update = change(&net, true, true, None, vec![p]);

            process_nlri_change(
                &update,
                1,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ibgp_rr_client_ctx(),
                None,
                Some(CLUSTER_ID),
                None,
            );

            let attrs = drain_first_reach_attrs(&mut pending);
            assert!(
                attrs
                    .iter()
                    .all(|a| a.code() != packet::Attribute::ORIGINATOR_ID),
                "eBGP-learned route must not get ORIGINATOR_ID"
            );
            assert!(
                attrs
                    .iter()
                    .all(|a| a.code() != packet::Attribute::CLUSTER_LIST),
                "eBGP-learned route must not get CLUSTER_LIST"
            );
        }

        // RR client source -> RR client dest: forwarded (client-to-client)
        #[test]
        fn rr_client_to_client_forwarded() {
            let mut em = ExportMap::new();
            let mut pending = crate::peer_tx::PendingTx::new(false);
            let net = nlri("10.0.0.0/24");
            let p = path(1, rr_client_source(PEER));
            let update = change(&net, true, true, None, vec![p]);

            process_nlri_change(
                &update,
                1,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ibgp_rr_client_ctx(),
                None,
                Some(CLUSTER_ID),
                None,
            );

            assert!(em.was_sent(Family::IPV4, &net));
            assert_eq!(
                reach_entries(&pending.drain_messages(Family::IPV4)).len(),
                1
            );
        }

        // ---- RS isolation ----

        fn rs_client_source(addr: &str) -> Arc<table::Source> {
            let ip: IpAddr = addr.parse().unwrap();
            Arc::new(table::Source::new(
                ip,
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                65002,
                65001,
                Ipv4Addr::new(10, 0, 0, 1),
                PeerRole::RsClient,
            ))
        }

        fn rs_client_ctx() -> PeerExportContext {
            PeerExportContext {
                role: PeerRole::RsClient,
                local_asn: 65001,
                local_addr: "127.0.0.1".parse().unwrap(),
                link_addr: None,
                confederation_id: 0,
            }
        }

        // RS-client source must not reach a non-RS-client (eBGP) peer.
        #[test]
        fn rs_isolation_suppresses_rs_client_route_to_ebgp_peer() {
            let mut em = ExportMap::new();
            let mut pending = crate::peer_tx::PendingTx::new(false);
            let net = nlri("10.0.0.0/24");
            let p = path(1, rs_client_source(PEER));
            let update = change(&net, true, true, None, vec![p]);

            process_nlri_change(
                &update,
                1,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ebgp_ctx(),
                None,
                None,
                None,
            );

            assert!(!em.was_sent(Family::IPV4, &net));
            assert_eq!(
                reach_entries(&pending.drain_messages(Family::IPV4)).len(),
                0
            );
        }

        // Non-RS-client (eBGP) source must not reach an RS-client peer.
        #[test]
        fn rs_isolation_suppresses_ebgp_route_to_rs_client_peer() {
            let mut em = ExportMap::new();
            let mut pending = crate::peer_tx::PendingTx::new(false);
            let net = nlri("10.0.0.0/24");
            let p = path(1, source(PEER));
            let update = change(&net, true, true, None, vec![p]);

            process_nlri_change(
                &update,
                1,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &rs_client_ctx(),
                None,
                None,
                None,
            );

            assert!(!em.was_sent(Family::IPV4, &net));
            assert_eq!(
                reach_entries(&pending.drain_messages(Family::IPV4)).len(),
                0
            );
        }

        // RS-client source must be forwarded to another RS-client peer.
        #[test]
        fn rs_isolation_forwards_rs_client_route_to_rs_client_peer() {
            let mut em = ExportMap::new();
            let mut pending = crate::peer_tx::PendingTx::new(false);
            let net = nlri("10.0.0.0/24");
            let p = path(1, rs_client_source(PEER));
            let update = change(&net, true, true, None, vec![p]);

            process_nlri_change(
                &update,
                1,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &rs_client_ctx(),
                None,
                None,
                None,
            );

            assert!(em.was_sent(Family::IPV4, &net));
            assert_eq!(
                reach_entries(&pending.drain_messages(Family::IPV4)).len(),
                1
            );
        }
    } // mod process_nlri_change

    fn make_grpc_service() -> GrpcService {
        let (active_conn_tx, _) = mpsc::unbounded_channel();
        GrpcService::new(
            Arc::new(tokio::sync::Notify::new()),
            active_conn_tx,
            make_global(),
            make_tables(),
        )
    }

    fn ipv4_path(prefix: &str, prefix_len: u32, nexthop: &str) -> api::Path {
        api::Path {
            nlri: Some(api::Nlri {
                nlri: Some(api::nlri::Nlri::Prefix(api::IpAddressPrefix {
                    prefix_len,
                    prefix: prefix.to_string(),
                })),
            }),
            pattrs: vec![
                api::Attribute {
                    attr: Some(api::attribute::Attr::Origin(api::OriginAttribute {
                        origin: 0,
                    })),
                },
                api::Attribute {
                    attr: Some(api::attribute::Attr::NextHop(api::NextHopAttribute {
                        next_hop: nexthop.to_string(),
                    })),
                },
            ],
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn add_path_inserts_route() {
        let svc = make_grpc_service();
        let req = tonic::Request::new(api::AddPathRequest {
            path: Some(ipv4_path("10.1.0.0", 24, "10.0.0.1")),
            ..Default::default()
        });
        svc.add_path(req).await.unwrap();
        let t = svc.tables.shards[0].lock().unwrap();
        assert_eq!(t.rtable.collect_loc_rib_paths(&Family::IPV4).len(), 1);
    }

    #[tokio::test]
    async fn delete_path_removes_route() {
        let svc = make_grpc_service();

        let add_req = tonic::Request::new(api::AddPathRequest {
            path: Some(ipv4_path("10.2.0.0", 24, "10.0.0.1")),
            ..Default::default()
        });
        let uuid = svc.add_path(add_req).await.unwrap().into_inner().uuid;
        {
            let t = svc.tables.shards[0].lock().unwrap();
            assert_eq!(t.rtable.collect_loc_rib_paths(&Family::IPV4).len(), 1);
        }

        let del_req = tonic::Request::new(api::DeletePathRequest {
            uuid,
            ..Default::default()
        });
        svc.delete_path(del_req).await.unwrap();
        let t = svc.tables.shards[0].lock().unwrap();
        assert!(t.rtable.collect_loc_rib_paths(&Family::IPV4).is_empty());
    }

    #[tokio::test]
    async fn add_path_returns_valid_uuid() {
        let svc = make_grpc_service();
        let req = tonic::Request::new(api::AddPathRequest {
            path: Some(ipv4_path("10.3.0.0", 24, "10.0.0.1")),
            ..Default::default()
        });
        let uuid = svc.add_path(req).await.unwrap().into_inner().uuid;
        assert_eq!(uuid.len(), 16);
        assert!(uuid::Uuid::from_slice(&uuid).is_ok());
    }

    #[tokio::test]
    async fn add_path_returns_unique_uuids() {
        let svc = make_grpc_service();
        let req1 = tonic::Request::new(api::AddPathRequest {
            path: Some(ipv4_path("10.4.0.0", 24, "10.0.0.1")),
            ..Default::default()
        });
        let req2 = tonic::Request::new(api::AddPathRequest {
            path: Some(ipv4_path("10.5.0.0", 24, "10.0.0.1")),
            ..Default::default()
        });
        let uuid1 = svc.add_path(req1).await.unwrap().into_inner().uuid;
        let uuid2 = svc.add_path(req2).await.unwrap().into_inner().uuid;
        assert_ne!(uuid1, uuid2);
    }

    #[tokio::test]
    async fn delete_path_without_uuid_is_rejected() {
        let svc = make_grpc_service();
        let req = tonic::Request::new(api::DeletePathRequest {
            uuid: vec![],
            ..Default::default()
        });
        let err = svc.delete_path(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn delete_path_with_unknown_uuid_returns_not_found() {
        let svc = make_grpc_service();
        let unknown_uuid = uuid::Uuid::new_v4().as_bytes().to_vec();
        let req = tonic::Request::new(api::DeletePathRequest {
            uuid: unknown_uuid,
            ..Default::default()
        });
        let err = svc.delete_path(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    fn ipv4_path_with_id(prefix: &str, prefix_len: u32, nexthop: &str, path_id: u32) -> api::Path {
        api::Path {
            identifier: path_id,
            ..ipv4_path(prefix, prefix_len, nexthop)
        }
    }

    #[tokio::test]
    async fn add_path_with_path_id_inserts_route() {
        let svc = make_grpc_service();
        let req = tonic::Request::new(api::AddPathRequest {
            path: Some(ipv4_path_with_id("10.6.0.0", 24, "10.0.0.1", 1)),
            ..Default::default()
        });
        svc.add_path(req).await.unwrap();
        let t = svc.tables.shards[0].lock().unwrap();
        assert_eq!(t.rtable.collect_loc_rib_paths(&Family::IPV4).len(), 1);
    }

    #[tokio::test]
    async fn add_path_with_different_path_ids_coexist() {
        let svc = make_grpc_service();
        let prefix = "10.7.0.0";

        let req1 = tonic::Request::new(api::AddPathRequest {
            path: Some(ipv4_path_with_id(prefix, 24, "10.0.0.1", 1)),
            ..Default::default()
        });
        let req2 = tonic::Request::new(api::AddPathRequest {
            path: Some(ipv4_path_with_id(prefix, 24, "10.0.0.2", 2)),
            ..Default::default()
        });
        let uuid1 = svc.add_path(req1).await.unwrap().into_inner().uuid;
        let uuid2 = svc.add_path(req2).await.unwrap().into_inner().uuid;

        {
            let t = svc.tables.shards[0].lock().unwrap();
            let entries = t.rtable.collect_loc_rib_paths(&Family::IPV4);
            assert_eq!(entries.len(), 1);
            assert_eq!(
                entries[0].current_paths.len(),
                2,
                "both path_id=1 and path_id=2 should coexist"
            );
        }

        svc.delete_path(tonic::Request::new(api::DeletePathRequest {
            uuid: uuid1,
            ..Default::default()
        }))
        .await
        .unwrap();
        {
            let t = svc.tables.shards[0].lock().unwrap();
            let entries = t.rtable.collect_loc_rib_paths(&Family::IPV4);
            assert_eq!(
                entries[0].current_paths.len(),
                1,
                "one path should remain after first delete"
            );
        }

        svc.delete_path(tonic::Request::new(api::DeletePathRequest {
            uuid: uuid2,
            ..Default::default()
        }))
        .await
        .unwrap();
        let t = svc.tables.shards[0].lock().unwrap();
        assert!(t.rtable.collect_loc_rib_paths(&Family::IPV4).is_empty());
    }

    // ---- apply_disconnect: export_map lifetime ----

    fn make_disconnect_info(negotiated_gr: Option<NegotiatedGr>) -> DisconnectInfo {
        let nlri: packet::Nlri = "10.0.0.0/24".parse().unwrap();
        let mut em = ExportMap::new();
        em.mark_sent(Family::IPV4, nlri, 0);
        DisconnectInfo {
            role: crate::fsm::Role::Active,
            remote_addr: "10.0.0.1".parse().unwrap(),
            export_map: em,
            negotiated_gr,
        }
    }

    #[tokio::test]
    async fn gr_disconnect_runs_without_panic() {
        let tables = make_tables();
        let context = make_context();
        let remote_addr: IpAddr = "10.0.0.1".parse().unwrap();
        let info = make_disconnect_info(Some(NegotiatedGr {
            families: vec![Family::IPV4],
            restart_time: std::time::Duration::from_secs(90),
            notification_enabled: false,
        }));
        apply_disconnect(&context, remote_addr, &tables, info).await;
    }

    #[tokio::test]
    async fn non_gr_disconnect_runs_without_panic() {
        let tables = make_tables();
        let context = make_context();
        let remote_addr: IpAddr = "10.0.0.1".parse().unwrap();
        let info = make_disconnect_info(None);
        apply_disconnect(&context, remote_addr, &tables, info).await;
    }

    // --- build_local_cap tests ---

    fn cap_code(c: &packet::Capability) -> u8 {
        c.into()
    }

    fn has_cap(caps: &[packet::Capability], code: u8) -> bool {
        caps.iter().any(|c| cap_code(c) == code)
    }

    const CAP_FOUR_OCTET_ASN: u8 = 65;
    const CAP_ADDPATH: u8 = 69;
    const CAP_EXTENDED_NEXTHOP: u8 = 5;
    const CAP_GRACEFUL_RESTART: u8 = 64;

    #[test]
    fn build_local_cap_ipv4_peer_no_families_defaults_to_ipv4() {
        let remote_addr: IpAddr = "10.0.0.1".parse().unwrap();
        let caps = PeerParams::build_local_cap(remote_addr, 65001, &FnvHashMap::default(), None);
        assert!(caps.iter().any(|c| matches!(
            c,
            packet::Capability::MultiProtocol(f) if *f == Family::IPV4
        )));
        assert!(has_cap(&caps, CAP_FOUR_OCTET_ASN));
        assert!(!has_cap(&caps, CAP_ADDPATH));
        assert!(!has_cap(&caps, CAP_EXTENDED_NEXTHOP));
    }

    #[test]
    fn build_local_cap_ipv6_peer_no_families_defaults_to_ipv6() {
        let remote_addr: IpAddr = "2001:db8::1".parse().unwrap();
        let caps = PeerParams::build_local_cap(remote_addr, 65001, &FnvHashMap::default(), None);
        assert!(caps.iter().any(|c| matches!(
            c,
            packet::Capability::MultiProtocol(f) if *f == Family::IPV6
        )));
        assert!(!has_cap(&caps, CAP_EXTENDED_NEXTHOP));
    }

    #[test]
    fn build_local_cap_ipv6_peer_with_ipv4_family_includes_extended_nexthop() {
        let remote_addr: IpAddr = "2001:db8::1".parse().unwrap();
        let mut families = FnvHashMap::default();
        families.insert(Family::IPV4, 0u8);
        let caps = PeerParams::build_local_cap(remote_addr, 65001, &families, None);
        assert!(has_cap(&caps, CAP_EXTENDED_NEXTHOP));
        assert!(caps.iter().any(|c| matches!(
            c,
            packet::Capability::ExtendedNexthop(fams)
                if fams.iter().any(|(f, nh)| *f == Family::IPV4 && *nh == Family::AFI_IP6)
        )));
    }

    #[test]
    fn build_local_cap_ipv6_peer_ipv6_only_family_no_extended_nexthop() {
        let remote_addr: IpAddr = "2001:db8::1".parse().unwrap();
        let mut families = FnvHashMap::default();
        families.insert(Family::IPV6, 0u8);
        let caps = PeerParams::build_local_cap(remote_addr, 65001, &families, None);
        assert!(!has_cap(&caps, CAP_EXTENDED_NEXTHOP));
    }

    #[test]
    fn build_local_cap_ipv4_peer_with_ipv4_family_no_extended_nexthop() {
        let remote_addr: IpAddr = "10.0.0.1".parse().unwrap();
        let mut families = FnvHashMap::default();
        families.insert(Family::IPV4, 0u8);
        let caps = PeerParams::build_local_cap(remote_addr, 65001, &families, None);
        assert!(!has_cap(&caps, CAP_EXTENDED_NEXTHOP));
    }

    #[test]
    fn build_local_cap_ipv6_peer_srpolicy_excluded_from_extended_nexthop() {
        // IPV4_SRPOLICY must not appear in ExtendedNexthop: its nexthop is
        // always the originator IPv4 address, not an IPv6-mapped address.
        let remote_addr: IpAddr = "2001:db8::1".parse().unwrap();
        let mut families = FnvHashMap::default();
        families.insert(Family::IPV4, 0u8);
        families.insert(Family::IPV4_SRPOLICY, 0u8);
        let caps = PeerParams::build_local_cap(remote_addr, 65001, &families, None);
        // ExtendedNexthop is still advertised for IPV4, but not for IPV4_SRPOLICY.
        assert!(has_cap(&caps, CAP_EXTENDED_NEXTHOP));
        assert!(!caps.iter().any(|c| matches!(
            c,
            packet::Capability::ExtendedNexthop(fams)
                if fams.iter().any(|(f, _)| *f == Family::IPV4_SRPOLICY)
        )));
    }

    #[test]
    fn build_local_cap_addpath_only_for_nonzero_modes() {
        let remote_addr: IpAddr = "10.0.0.1".parse().unwrap();
        let mut families = FnvHashMap::default();
        families.insert(Family::IPV4, 3u8); // mode > 0: include in AddPath
        families.insert(Family::IPV6, 0u8); // mode == 0: exclude from AddPath
        let caps = PeerParams::build_local_cap(remote_addr, 65001, &families, None);
        assert!(has_cap(&caps, CAP_ADDPATH));
        let addpath_families: Vec<Family> = caps
            .iter()
            .find_map(|c| {
                if let packet::Capability::AddPath(fams) = c {
                    Some(fams.iter().map(|(f, _)| *f).collect())
                } else {
                    None
                }
            })
            .unwrap_or_default();
        assert!(addpath_families.contains(&Family::IPV4));
        assert!(!addpath_families.contains(&Family::IPV6));
    }

    #[test]
    fn build_local_cap_no_addpath_when_all_modes_zero() {
        let remote_addr: IpAddr = "10.0.0.1".parse().unwrap();
        let mut families = FnvHashMap::default();
        families.insert(Family::IPV4, 0u8);
        families.insert(Family::IPV6, 0u8);
        let caps = PeerParams::build_local_cap(remote_addr, 65001, &families, None);
        assert!(!has_cap(&caps, CAP_ADDPATH));
    }

    #[test]
    fn build_local_cap_gr_notification_enabled_sets_n_bit() {
        let remote_addr: IpAddr = "10.0.0.1".parse().unwrap();
        let gr = GrPeerConfig {
            restart_time: 120,
            notification_enabled: true,
            families: vec![Family::IPV4],
        };
        let caps =
            PeerParams::build_local_cap(remote_addr, 65001, &FnvHashMap::default(), Some(&gr));
        let gr_cap = caps.iter().find_map(|c| {
            if let packet::Capability::GracefulRestart { flags, .. } = c {
                Some(*flags)
            } else {
                None
            }
        });
        assert!(has_cap(&caps, CAP_GRACEFUL_RESTART));
        assert_eq!(gr_cap.unwrap() & 0x4, 0x4, "N-bit must be set");
    }

    #[test]
    fn build_local_cap_gr_notification_disabled_clears_n_bit() {
        let remote_addr: IpAddr = "10.0.0.1".parse().unwrap();
        let gr = GrPeerConfig {
            restart_time: 120,
            notification_enabled: false,
            families: vec![Family::IPV4],
        };
        let caps =
            PeerParams::build_local_cap(remote_addr, 65001, &FnvHashMap::default(), Some(&gr));
        let gr_cap = caps.iter().find_map(|c| {
            if let packet::Capability::GracefulRestart { flags, .. } = c {
                Some(*flags)
            } else {
                None
            }
        });
        assert_eq!(gr_cap.unwrap() & 0x4, 0, "N-bit must not be set");
    }

    fn make_peer_params(toml: &str) -> PeerParams {
        let neighbor: rustybgp_config::generate::Neighbor =
            toml::from_str(toml).expect("invalid TOML");
        PeerParams::try_from(&neighbor).expect("PeerParams::try_from failed")
    }

    #[test]
    fn peer_config_basic() {
        let p = make_peer_params(
            r#"
[config]
neighbor-address = "10.0.0.1"
peer-as = 65002
"#,
        );
        assert_eq!(p.remote_addr, "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(p.expected_remote_asn, 65002);
    }

    #[test]
    fn peer_config_local_as() {
        let p = make_peer_params(
            r#"
[config]
neighbor-address = "10.0.0.1"
peer-as = 65002
local-as = 65001
"#,
        );
        assert_eq!(p.local_asn, 65001);
    }

    #[test]
    fn peer_config_admin_down() {
        let p = make_peer_params(
            r#"
[config]
neighbor-address = "10.0.0.1"
peer-as = 65002
admin-down = true
"#,
        );
        assert!(p.admin_down);
    }

    #[test]
    fn peer_config_auth_password() {
        let p = make_peer_params(
            r#"
[config]
neighbor-address = "10.0.0.1"
peer-as = 65002
auth-password = "secret"
"#,
        );
        assert_eq!(p.password.as_deref(), Some("secret"));
    }

    #[test]
    fn peer_config_hold_time() {
        let p = make_peer_params(
            r#"
[config]
neighbor-address = "10.0.0.1"
peer-as = 65002

[timers.config]
hold-time = 90.0
"#,
        );
        assert_eq!(p.holdtime, 90);
    }

    #[test]
    fn peer_config_connect_retry() {
        let p = make_peer_params(
            r#"
[config]
neighbor-address = "10.0.0.1"
peer-as = 65002

[timers.config]
connect-retry = 10.0
"#,
        );
        assert_eq!(p.connect_retry_time, 10);
    }

    #[test]
    fn peer_config_passive_mode() {
        let p = make_peer_params(
            r#"
[config]
neighbor-address = "10.0.0.1"
peer-as = 65002

[transport.config]
passive-mode = true
"#,
        );
        assert!(p.passive);
    }

    #[test]
    fn peer_config_remote_port() {
        let p = make_peer_params(
            r#"
[config]
neighbor-address = "10.0.0.1"
peer-as = 65002

[transport.config]
remote-port = 1179
"#,
        );
        assert_eq!(p.remote_port, 1179);
    }

    #[test]
    fn peer_config_multihop_ttl() {
        let p = make_peer_params(
            r#"
[config]
neighbor-address = "10.0.0.1"
peer-as = 65002

[ebgp-multihop.config]
enabled = true
multihop-ttl = 3
"#,
        );
        assert_eq!(p.multihop_ttl, Some(3));
    }

    #[test]
    fn peer_config_multihop_disabled() {
        let p = make_peer_params(
            r#"
[config]
neighbor-address = "10.0.0.1"
peer-as = 65002

[ebgp-multihop.config]
enabled = false
multihop-ttl = 3
"#,
        );
        assert_eq!(p.multihop_ttl, None);
    }

    #[test]
    fn peer_config_route_server_client() {
        let p = make_peer_params(
            r#"
[config]
neighbor-address = "10.0.0.1"
peer-as = 65002

[route-server.config]
route-server-client = true
"#,
        );
        assert!(p.rs_client);
    }

    #[test]
    fn peer_config_afi_safis_ipv4_ipv6() {
        let p = make_peer_params(
            r#"
[config]
neighbor-address = "10.0.0.1"
peer-as = 65002

[[afi-safis]]
[afi-safis.config]
afi-safi-name = "ipv4-unicast"

[[afi-safis]]
[afi-safis.config]
afi-safi-name = "ipv6-unicast"
"#,
        );
        assert!(p.families.contains_key(&packet::Family::IPV4));
        assert!(p.families.contains_key(&packet::Family::IPV6));
        assert_eq!(p.families.len(), 2);
    }

    #[test]
    fn peer_config_addpath_receive_only() {
        let p = make_peer_params(
            r#"
[config]
neighbor-address = "10.0.0.1"
peer-as = 65002

[[afi-safis]]
[afi-safis.config]
afi-safi-name = "ipv4-unicast"
[afi-safis.add-paths.config]
receive = true
"#,
        );
        // mode bit 0 = receive
        assert_eq!(p.families.get(&packet::Family::IPV4).copied(), Some(1));
    }

    #[test]
    fn peer_config_addpath_send_only() {
        let p = make_peer_params(
            r#"
[config]
neighbor-address = "10.0.0.1"
peer-as = 65002

[[afi-safis]]
[afi-safis.config]
afi-safi-name = "ipv4-unicast"
[afi-safis.add-paths.config]
send-max = 2
"#,
        );
        // mode bit 1 = send
        assert_eq!(p.families.get(&packet::Family::IPV4).copied(), Some(2));
        assert_eq!(p.send_max.get(&packet::Family::IPV4).copied(), Some(2));
    }

    #[test]
    fn peer_config_addpath_both() {
        let p = make_peer_params(
            r#"
[config]
neighbor-address = "10.0.0.1"
peer-as = 65002

[[afi-safis]]
[afi-safis.config]
afi-safi-name = "ipv4-unicast"
[afi-safis.add-paths.config]
receive = true
send-max = 3
"#,
        );
        // mode bits 0+1 = 3
        assert_eq!(p.families.get(&packet::Family::IPV4).copied(), Some(3));
        assert_eq!(p.send_max.get(&packet::Family::IPV4).copied(), Some(3));
    }

    #[test]
    fn peer_config_prefix_limit_ipv4() {
        let p = make_peer_params(
            r#"
[config]
neighbor-address = "10.0.0.1"
peer-as = 65002

[[afi-safis]]
[afi-safis.config]
afi-safi-name = "ipv4-unicast"
[afi-safis.ipv4-unicast.prefix-limit.config]
max-prefixes = 1000
"#,
        );
        assert_eq!(
            p.prefix_limits.get(&packet::Family::IPV4).copied(),
            Some(1000)
        );
    }

    #[test]
    fn peer_config_prefix_limit_ipv6() {
        let p = make_peer_params(
            r#"
[config]
neighbor-address = "::1"
peer-as = 65002

[[afi-safis]]
[afi-safis.config]
afi-safi-name = "ipv6-unicast"
[afi-safis.ipv6-unicast.prefix-limit.config]
max-prefixes = 500
"#,
        );
        assert_eq!(
            p.prefix_limits.get(&packet::Family::IPV6).copied(),
            Some(500)
        );
    }

    #[test]
    fn peer_config_graceful_restart() {
        let p = make_peer_params(
            r#"
[config]
neighbor-address = "10.0.0.1"
peer-as = 65002

[graceful-restart.config]
enabled = true
restart-time = 30

[[afi-safis]]
[afi-safis.config]
afi-safi-name = "ipv4-unicast"
[afi-safis.mp-graceful-restart.config]
enabled = true
"#,
        );
        let gr = p
            .graceful_restart
            .as_ref()
            .expect("graceful_restart is None");
        assert_eq!(gr.restart_time, 30);
        assert!(gr.families.contains(&packet::Family::IPV4));
    }

    #[test]
    fn peer_config_graceful_restart_notification_enabled() {
        let p = make_peer_params(
            r#"
[config]
neighbor-address = "10.0.0.1"
peer-as = 65002

[graceful-restart.config]
enabled = true
notification-enabled = true

[[afi-safis]]
[afi-safis.config]
afi-safi-name = "ipv4-unicast"
[afi-safis.mp-graceful-restart.config]
enabled = true
"#,
        );
        let gr = p
            .graceful_restart
            .as_ref()
            .expect("graceful_restart is None");
        assert!(gr.notification_enabled);
    }

    #[test]
    fn peer_config_graceful_restart_no_families_yields_none() {
        // GR enabled but no afi-safi has mp-graceful-restart enabled -> no GR config
        let p = make_peer_params(
            r#"
[config]
neighbor-address = "10.0.0.1"
peer-as = 65002

[graceful-restart.config]
enabled = true

[[afi-safis]]
[afi-safis.config]
afi-safi-name = "ipv4-unicast"
"#,
        );
        assert!(p.graceful_restart.is_none());
    }

    #[test]
    fn peer_config_defaults() {
        let p = make_peer_params(
            r#"
[config]
neighbor-address = "10.0.0.1"
peer-as = 65002
"#,
        );
        assert_eq!(p.holdtime, PeerParams::DEFAULT_HOLD_TIME);
        assert_eq!(p.connect_retry_time, PeerParams::DEFAULT_CONNECT_RETRY_TIME);
        assert_eq!(p.remote_port, Global::BGP_PORT);
        assert!(!p.passive);
        assert!(!p.rs_client);
        assert!(!p.admin_down);
        assert_eq!(p.local_asn, 0);
        assert!(p.multihop_ttl.is_none());
        assert!(p.password.is_none());
        assert!(p.graceful_restart.is_none());
    }

    #[test]
    fn peer_config_missing_neighbor_address() {
        let neighbor: rustybgp_config::generate::Neighbor = toml::from_str(
            r#"
[config]
peer-as = 65002
"#,
        )
        .expect("invalid TOML");
        assert!(PeerParams::try_from(&neighbor).is_err());
    }

    #[test]
    fn peer_config_missing_peer_as() {
        let neighbor: rustybgp_config::generate::Neighbor = toml::from_str(
            r#"
[config]
neighbor-address = "10.0.0.1"
"#,
        )
        .expect("invalid TOML");
        assert!(PeerParams::try_from(&neighbor).is_err());
    }

    // ---- rpki server config ----

    fn rpki_sockaddr_from_config(s: &rustybgp_config::generate::RpkiServer) -> Option<SocketAddr> {
        let addr = s.config.as_ref().and_then(|c| c.address);
        let port = s
            .config
            .as_ref()
            .and_then(|c| c.port)
            .map(|p| p as u16)
            .unwrap_or(323);
        addr.map(|a| SocketAddr::new(a, port))
    }

    #[test]
    fn rpki_server_config_address_and_explicit_port() {
        let s: rustybgp_config::generate::RpkiServer = toml::from_str(
            r#"
[config]
address = "192.0.2.1"
port = 3323
"#,
        )
        .expect("invalid TOML");
        assert_eq!(
            rpki_sockaddr_from_config(&s),
            Some("192.0.2.1:3323".parse().unwrap())
        );
    }

    #[test]
    fn rpki_server_config_default_port_is_323() {
        let s: rustybgp_config::generate::RpkiServer = toml::from_str(
            r#"
[config]
address = "192.0.2.1"
"#,
        )
        .expect("invalid TOML");
        assert_eq!(
            rpki_sockaddr_from_config(&s),
            Some("192.0.2.1:323".parse().unwrap())
        );
    }

    #[test]
    fn rpki_server_config_missing_address_yields_none() {
        let s: rustybgp_config::generate::RpkiServer = toml::from_str(
            r#"
[config]
port = 3323
"#,
        )
        .expect("invalid TOML");
        assert!(rpki_sockaddr_from_config(&s).is_none());
    }

    // ---- rx_update: RFC 4456 loop detection ----
    //
    // new_for_test sets local_router_id = 1.0.0.1.  Loop detection fires before
    // source lookup, so no source setup is required; the absence of an inserted
    // route is verified via table_state().

    fn reach_set(prefix: &str) -> Option<bgp::ReachNlri> {
        Some(bgp::ReachNlri {
            family: Family::IPV4,
            entries: vec![packet::PathNlri::new(prefix.parse().unwrap())],
            nexthop: None,
        })
    }

    #[tokio::test]
    async fn rx_update_originator_id_loop_drops_route() {
        let tables = make_tables();
        let context = make_context();
        let remote_addr: IpAddr = "10.0.0.2".parse().unwrap();
        let mut session = PeerSession::new_for_test(remote_addr, context, tables.clone());
        // local_router_id is 1.0.0.1 in new_for_test
        let attrs = Arc::new(vec![
            packet::Attribute::new_with_value(
                packet::Attribute::ORIGINATOR_ID,
                u32::from(Ipv4Addr::new(1, 0, 0, 1)),
            )
            .unwrap(),
        ]);

        let exceeded = session
            .rx_update(
                reach_set("10.0.0.0/24"),
                None,
                attrs,
                std::time::SystemTime::now(),
            )
            .await;

        assert!(!exceeded, "loop detection must not trigger CEASE");
        let state = tables.table_state(Family::IPV4);
        assert_eq!(state.num_destination, 0, "route must not be inserted");
    }

    #[tokio::test]
    async fn rx_update_cluster_list_loop_drops_route() {
        let tables = make_tables();
        let context = make_context();
        let remote_addr: IpAddr = "10.0.0.2".parse().unwrap();
        let mut session = PeerSession::new_for_test(remote_addr, context, tables.clone());
        let local_cid = Ipv4Addr::new(1, 2, 3, 4);
        session.cluster_id = Some(local_cid);
        let cid_bytes = u32::from(local_cid).to_be_bytes().to_vec();
        let attrs = Arc::new(vec![
            packet::Attribute::new_with_bin(packet::Attribute::CLUSTER_LIST, cid_bytes).unwrap(),
        ]);

        let exceeded = session
            .rx_update(
                reach_set("10.0.0.0/24"),
                None,
                attrs,
                std::time::SystemTime::now(),
            )
            .await;

        assert!(!exceeded, "loop detection must not trigger CEASE");
        let state = tables.table_state(Family::IPV4);
        assert_eq!(state.num_destination, 0, "route must not be inserted");
    }

    // local cluster_id appears in the middle of a multi-entry CLUSTER_LIST
    #[tokio::test]
    async fn rx_update_cluster_list_loop_detects_middle_entry() {
        let tables = make_tables();
        let context = make_context();
        let remote_addr: IpAddr = "10.0.0.2".parse().unwrap();
        let mut session = PeerSession::new_for_test(remote_addr, context, tables.clone());
        let local_cid = Ipv4Addr::new(1, 2, 3, 4);
        session.cluster_id = Some(local_cid);
        // CLUSTER_LIST: [2.0.0.2, 1.2.3.4 (local), 3.0.0.3]
        let mut cid_bytes = Vec::new();
        cid_bytes.extend_from_slice(&u32::from(Ipv4Addr::new(2, 0, 0, 2)).to_be_bytes());
        cid_bytes.extend_from_slice(&u32::from(local_cid).to_be_bytes());
        cid_bytes.extend_from_slice(&u32::from(Ipv4Addr::new(3, 0, 0, 3)).to_be_bytes());
        let attrs = Arc::new(vec![
            packet::Attribute::new_with_bin(packet::Attribute::CLUSTER_LIST, cid_bytes).unwrap(),
        ]);

        let exceeded = session
            .rx_update(
                reach_set("10.0.0.0/24"),
                None,
                attrs,
                std::time::SystemTime::now(),
            )
            .await;

        assert!(!exceeded, "loop detection must not trigger CEASE");
        let state = tables.table_state(Family::IPV4);
        assert_eq!(state.num_destination, 0, "route must not be inserted");
    }

    // --- VRF gRPC end-to-end ---

    fn two_octet_rt(asn: u32, local_admin: u32) -> api::RouteTarget {
        api::RouteTarget {
            rt: Some(api::route_target::Rt::TwoOctetAsSpecific(
                api::TwoOctetAsSpecificExtended {
                    is_transitive: true,
                    sub_type: 2,
                    asn,
                    local_admin,
                },
            )),
        }
    }

    fn make_vrf_req(
        name: &str,
        rd_asn: u32,
        rd_admin: u32,
        rt_asn: u32,
        rt_local: u32,
    ) -> api::AddVrfRequest {
        api::AddVrfRequest {
            vrf: Some(api::Vrf {
                name: name.to_string(),
                rd: Some(api::RouteDistinguisher {
                    rd: Some(api::route_distinguisher::Rd::TwoOctetAsn(
                        api::RouteDistinguisherTwoOctetAsn {
                            admin: rd_asn,
                            assigned: rd_admin,
                        },
                    )),
                }),
                import_rt: vec![two_octet_rt(rt_asn, rt_local)],
                export_rt: vec![two_octet_rt(rt_asn, rt_local)],
                ..Default::default()
            }),
        }
    }

    async fn collect_list_vrf(svc: &GrpcService, name: &str) -> Vec<api::Vrf> {
        let req = tonic::Request::new(api::ListVrfRequest {
            name: name.to_string(),
        });
        let stream = svc.list_vrf(req).await.unwrap().into_inner();
        stream
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .filter_map(|r| r.ok()?.vrf)
            .collect()
    }

    async fn collect_list_path_vrf(
        svc: &GrpcService,
        vrf_name: &str,
        afi: i32,
        safi: i32,
    ) -> Vec<api::Destination> {
        let req = tonic::Request::new(api::ListPathRequest {
            table_type: api::TableType::Vrf as i32,
            name: vrf_name.to_string(),
            family: Some(api::Family { afi, safi }),
            ..Default::default()
        });
        let stream = svc.list_path(req).await.unwrap().into_inner();
        stream
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .filter_map(|r| r.ok()?.destination)
            .collect()
    }

    #[tokio::test]
    async fn add_vrf_and_list_vrf() {
        let svc = make_grpc_service();
        svc.add_vrf(tonic::Request::new(make_vrf_req(
            "vrf1", 65000, 1, 65000, 1,
        )))
        .await
        .unwrap();
        let vrfs = collect_list_vrf(&svc, "vrf1").await;
        assert_eq!(vrfs.len(), 1);
        assert_eq!(vrfs[0].name, "vrf1");
    }

    #[tokio::test]
    async fn add_vrf_duplicate_returns_error() {
        let svc = make_grpc_service();
        svc.add_vrf(tonic::Request::new(make_vrf_req(
            "vrf1", 65000, 1, 65000, 1,
        )))
        .await
        .unwrap();
        let err = svc
            .add_vrf(tonic::Request::new(make_vrf_req(
                "vrf1", 65000, 2, 65000, 2,
            )))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::AlreadyExists);
    }

    #[tokio::test]
    async fn delete_vrf_removes_it() {
        let svc = make_grpc_service();
        svc.add_vrf(tonic::Request::new(make_vrf_req(
            "vrf1", 65000, 1, 65000, 1,
        )))
        .await
        .unwrap();
        svc.delete_vrf(tonic::Request::new(api::DeleteVrfRequest {
            name: "vrf1".to_string(),
        }))
        .await
        .unwrap();
        let vrfs = collect_list_vrf(&svc, "vrf1").await;
        assert!(vrfs.is_empty());
    }

    #[tokio::test]
    async fn delete_vrf_not_found_returns_error() {
        let svc = make_grpc_service();
        let err = svc
            .delete_vrf(tonic::Request::new(api::DeleteVrfRequest {
                name: "noexist".to_string(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn consecutive_vrfs_get_different_labels() {
        let svc = make_grpc_service();
        // Both VRFs use the same RT so both import the other's routes; they differ only by RD.
        // Injecting the same prefix into each VRF produces two distinct VPN NLRI (different labels),
        // which means the global IPV4_VPN table has two destinations.
        svc.add_vrf(tonic::Request::new(make_vrf_req(
            "vrf1", 65000, 1, 65000, 100,
        )))
        .await
        .unwrap();
        svc.add_vrf(tonic::Request::new(make_vrf_req(
            "vrf2", 65000, 2, 65000, 100,
        )))
        .await
        .unwrap();

        for vrf in ["vrf1", "vrf2"] {
            let req = tonic::Request::new(api::AddPathRequest {
                table_type: api::TableType::Vrf as i32,
                vrf_id: vrf.to_string(),
                path: Some(ipv4_path("10.1.0.0", 24, "10.0.0.1")),
            });
            svc.add_path(req).await.unwrap();
        }

        let req = tonic::Request::new(api::ListPathRequest {
            table_type: api::TableType::Global as i32,
            family: Some(api::Family { afi: 1, safi: 128 }),
            ..Default::default()
        });
        let stream = svc.list_path(req).await.unwrap().into_inner();
        let dests: Vec<_> = stream
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .filter_map(|r| r.ok()?.destination)
            .collect();
        // Each VRF gets a unique label so they produce distinct VPN NLRI (two separate destinations)
        assert_eq!(
            dests.len(),
            2,
            "each VRF label yields a distinct VPN destination"
        );
    }

    #[tokio::test]
    async fn add_path_vrf_appears_in_global_vpn_table() {
        let svc = make_grpc_service();
        // Create VRF with RT 65000:100
        svc.add_vrf(tonic::Request::new(make_vrf_req(
            "vrf1", 65000, 100, 65000, 100,
        )))
        .await
        .unwrap();

        // Inject a plain IPv4 route via the VRF table type
        let req = tonic::Request::new(api::AddPathRequest {
            table_type: api::TableType::Vrf as i32,
            vrf_id: "vrf1".to_string(),
            path: Some(ipv4_path("10.1.0.0", 24, "10.0.0.1")),
        });
        svc.add_path(req).await.unwrap();

        // The route must appear in the global IPV4_VPN table (AFI=1, SAFI=128)
        let req = tonic::Request::new(api::ListPathRequest {
            table_type: api::TableType::Global as i32,
            family: Some(api::Family { afi: 1, safi: 128 }),
            ..Default::default()
        });
        let stream = svc.list_path(req).await.unwrap().into_inner();
        let dests: Vec<_> = stream
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .filter_map(|r| r.ok()?.destination)
            .collect();
        assert_eq!(dests.len(), 1, "VPN route must be in global VPN table");
    }

    #[tokio::test]
    async fn list_path_vrf_shows_plain_prefix() {
        let svc = make_grpc_service();
        svc.add_vrf(tonic::Request::new(make_vrf_req(
            "vrf1", 65000, 100, 65000, 100,
        )))
        .await
        .unwrap();

        let req = tonic::Request::new(api::AddPathRequest {
            table_type: api::TableType::Vrf as i32,
            vrf_id: "vrf1".to_string(),
            path: Some(ipv4_path("192.0.2.0", 24, "10.0.0.1")),
        });
        svc.add_path(req).await.unwrap();

        // list_path with TABLE_TYPE_VRF applies ToLocal(): the destination prefix
        // and the path NLRI are plain unicast (IPv4/IPv6), matching GoBGP behavior.
        let dests = collect_list_path_vrf(&svc, "vrf1", 1, 1).await;
        assert_eq!(dests.len(), 1);
        // destination.prefix is a plain CIDR string ("192.0.2.0/24"), not VPN format.
        assert_eq!(
            dests[0].prefix, "192.0.2.0/24",
            "expected plain CIDR, got: {}",
            dests[0].prefix
        );
        // path.nlri must be IpAddressPrefix (plain), not LabeledVpnIpPrefix.
        let path_nlri = dests[0].paths[0].nlri.as_ref().unwrap();
        assert!(
            matches!(path_nlri.nlri, Some(api::nlri::Nlri::Prefix(_))),
            "expected plain IpAddressPrefix NLRI"
        );
    }

    #[tokio::test]
    async fn list_path_vrf_to_local_family_and_no_ext_community() {
        // ToLocal() must:
        //   1. return paths with unicast family (afi=1/safi=1 for IPv4), not VPN family
        //   2. remove EXTENDED_COMMUNITY attribute (export RTs) from each path
        let svc = make_grpc_service();
        svc.add_vrf(tonic::Request::new(make_vrf_req(
            "vrf1", 65000, 100, 65000, 100,
        )))
        .await
        .unwrap();

        let req = tonic::Request::new(api::AddPathRequest {
            table_type: api::TableType::Vrf as i32,
            vrf_id: "vrf1".to_string(),
            path: Some(ipv4_path("10.0.1.0", 24, "10.0.0.1")),
        });
        svc.add_path(req).await.unwrap();

        let dests = collect_list_path_vrf(&svc, "vrf1", 1, 1).await;
        assert_eq!(dests.len(), 1);

        let path = &dests[0].paths[0];

        // family must be IPv4 unicast (afi=1, safi=1), not IPv4 VPN (afi=1, safi=128)
        let fam = path.family.as_ref().expect("family must be set");
        assert_eq!(fam.afi, 1, "expected AFI_IP (1), got {}", fam.afi);
        assert_eq!(fam.safi, 1, "expected SAFI_UNICAST (1), got {}", fam.safi);

        // EXTENDED_COMMUNITY must not appear in the path attributes
        let has_ext_comm = path
            .pattrs
            .iter()
            .any(|a| matches!(a.attr, Some(api::attribute::Attr::ExtendedCommunities(_))));
        assert!(
            !has_ext_comm,
            "EXTENDED_COMMUNITY must be stripped from VRF list_path response"
        );
    }

    #[tokio::test]
    async fn list_path_vrf_ipv6_to_local() {
        // Verify ToLocal() works correctly for IPv6 VRF paths:
        //   destination.prefix must be plain IPv6 CIDR parseable by net.ParseCIDR,
        //   path NLRI must be IpAddressPrefix (not LabeledVpnIpPrefix),
        //   path family must be IPv6 unicast (afi=2, safi=1).
        let svc = make_grpc_service();
        svc.add_vrf(tonic::Request::new(make_vrf_req(
            "vrf1", 65000, 100, 65000, 100,
        )))
        .await
        .unwrap();

        let ipv6_path = api::Path {
            family: Some(api::Family { afi: 2, safi: 1 }),
            nlri: Some(api::Nlri {
                nlri: Some(api::nlri::Nlri::Prefix(api::IpAddressPrefix {
                    prefix: "2001:db8::".to_string(),
                    prefix_len: 32,
                })),
            }),
            pattrs: vec![
                api::Attribute {
                    attr: Some(api::attribute::Attr::Origin(api::OriginAttribute {
                        origin: 0,
                    })),
                },
                api::Attribute {
                    attr: Some(api::attribute::Attr::MpReach(api::MpReachNlriAttribute {
                        family: Some(api::Family { afi: 2, safi: 1 }),
                        next_hops: vec!["::1".to_string()],
                        nlris: vec![],
                    })),
                },
            ],
            ..Default::default()
        };

        let req = tonic::Request::new(api::AddPathRequest {
            table_type: api::TableType::Vrf as i32,
            vrf_id: "vrf1".to_string(),
            path: Some(ipv6_path),
        });
        svc.add_path(req).await.unwrap();

        // AFI=2 (IPv6), SAFI=1 (unicast) — VRF view
        let dests = collect_list_path_vrf(&svc, "vrf1", 2, 1).await;
        assert_eq!(dests.len(), 1, "IPv6 VRF path must appear");

        // destination.prefix must be a plain IPv6 CIDR
        assert_eq!(
            dests[0].prefix, "2001:db8::/32",
            "expected plain IPv6 CIDR, got: {}",
            dests[0].prefix
        );

        let path = &dests[0].paths[0];

        // path NLRI must be plain IpAddressPrefix
        let nlri = path.nlri.as_ref().unwrap();
        assert!(
            matches!(nlri.nlri, Some(api::nlri::Nlri::Prefix(_))),
            "expected IpAddressPrefix NLRI for IPv6 VRF path"
        );

        // family must be IPv6 unicast (afi=2, safi=1)
        let fam = path.family.as_ref().unwrap();
        assert_eq!(fam.afi, 2, "expected AFI_IP6 (2), got {}", fam.afi);
        assert_eq!(fam.safi, 1, "expected SAFI_UNICAST (1), got {}", fam.safi);

        // EXTENDED_COMMUNITY must be absent
        assert!(
            !path
                .pattrs
                .iter()
                .any(|a| matches!(a.attr, Some(api::attribute::Attr::ExtendedCommunities(_)))),
            "EXTENDED_COMMUNITY must be stripped"
        );
    }

    #[tokio::test]
    async fn list_path_vrf_rt_isolation() {
        let svc = make_grpc_service();
        // vrf1 uses RT 65000:1; vrf2 uses RT 65000:2 — routes must not leak
        svc.add_vrf(tonic::Request::new(make_vrf_req(
            "vrf1", 65000, 1, 65000, 1,
        )))
        .await
        .unwrap();
        svc.add_vrf(tonic::Request::new(make_vrf_req(
            "vrf2", 65000, 2, 65000, 2,
        )))
        .await
        .unwrap();

        let req = tonic::Request::new(api::AddPathRequest {
            table_type: api::TableType::Vrf as i32,
            vrf_id: "vrf1".to_string(),
            path: Some(ipv4_path("10.1.0.0", 24, "10.0.0.1")),
        });
        svc.add_path(req).await.unwrap();

        let dests_vrf1 = collect_list_path_vrf(&svc, "vrf1", 1, 1).await;
        let dests_vrf2 = collect_list_path_vrf(&svc, "vrf2", 1, 1).await;

        assert_eq!(dests_vrf1.len(), 1, "vrf1 must see its own route");
        assert_eq!(dests_vrf2.len(), 0, "vrf2 must not see vrf1's route");
    }

    #[tokio::test]
    async fn adj_out_non_established_returns_empty() {
        let svc = make_grpc_service();
        let peer_addr: IpAddr = "10.0.0.2".parse().unwrap();

        svc.add_peer(tonic::Request::new(api::AddPeerRequest {
            peer: Some(api::Peer {
                conf: Some(api::PeerConf {
                    neighbor_address: peer_addr.to_string(),
                    peer_asn: 65002,
                    ..Default::default()
                }),
                ..Default::default()
            }),
        }))
        .await
        .unwrap();

        svc.add_path(tonic::Request::new(api::AddPathRequest {
            path: Some(ipv4_path("10.1.0.0", 24, "10.0.0.1")),
            ..Default::default()
        }))
        .await
        .unwrap();

        // Peer is Idle (never connected): adj-out must be empty.
        let req = tonic::Request::new(api::ListPathRequest {
            table_type: api::TableType::AdjOut as i32,
            name: peer_addr.to_string(),
            family: Some(api::Family { afi: 1, safi: 1 }),
            ..Default::default()
        });
        let dests: Vec<_> = svc
            .list_path(req)
            .await
            .unwrap()
            .into_inner()
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .filter_map(|r| r.ok()?.destination)
            .collect();
        assert!(
            dests.is_empty(),
            "adj-out must be empty for a non-Established peer"
        );
    }

    #[tokio::test]
    async fn adj_out_established_returns_paths() {
        let svc = make_grpc_service();
        let peer_addr: IpAddr = "10.0.0.2".parse().unwrap();

        svc.add_peer(tonic::Request::new(api::AddPeerRequest {
            peer: Some(api::Peer {
                conf: Some(api::PeerConf {
                    neighbor_address: peer_addr.to_string(),
                    peer_asn: 65002,
                    ..Default::default()
                }),
                ..Default::default()
            }),
        }))
        .await
        .unwrap();

        svc.add_path(tonic::Request::new(api::AddPathRequest {
            path: Some(ipv4_path("10.1.0.0", 24, "10.0.0.1")),
            ..Default::default()
        }))
        .await
        .unwrap();

        // Drive the peer FSM to Established without a real TCP connection.
        {
            let global = svc.global.read().await;
            let peer = global.peers.get(&peer_addr).unwrap();
            let ctx = peer.context.lock().unwrap();
            let mut arb = ctx.conn_arbiter.lock().unwrap();
            let open = bgp::Message::Open(bgp::Open {
                as_number: 65002,
                holdtime: HoldTime::new(90).unwrap(),
                router_id: u32::from(Ipv4Addr::new(10, 0, 0, 1)),
                capability: vec![bgp::Capability::FourOctetAsNumber(65002)],
            });
            arb.process(
                crate::fsm::Role::Active,
                crate::fsm::Input::Connected(false),
            );
            arb.process(
                crate::fsm::Role::Active,
                crate::fsm::Input::MessageReceived(open),
            );
            arb.process(
                crate::fsm::Role::Active,
                crate::fsm::Input::MessageReceived(bgp::Message::Keepalive),
            );
        }

        let req = tonic::Request::new(api::ListPathRequest {
            table_type: api::TableType::AdjOut as i32,
            name: peer_addr.to_string(),
            family: Some(api::Family { afi: 1, safi: 1 }),
            ..Default::default()
        });
        let dests: Vec<_> = svc
            .list_path(req)
            .await
            .unwrap()
            .into_inner()
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .filter_map(|r| r.ok()?.destination)
            .collect();
        assert_eq!(
            dests.len(),
            1,
            "adj-out must show the injected route for an Established peer"
        );
    }
}

#[cfg(test)]
mod as_loop_tests {
    use super::*;

    fn as_path_attr(asns: &[u32]) -> bgp::Attribute {
        let mut data = Vec::new();
        data.push(bgp::Attribute::AS_PATH_TYPE_SEQ);
        data.push(asns.len() as u8);
        for asn in asns {
            data.extend_from_slice(&asn.to_be_bytes());
        }
        bgp::Attribute::new_with_bin(bgp::Attribute::AS_PATH, data).unwrap()
    }

    fn make_attr(asns: &[u32]) -> Arc<Vec<bgp::Attribute>> {
        Arc::new(vec![as_path_attr(asns)])
    }

    #[test]
    fn loop_detected_when_local_asn_in_path() {
        assert!(is_as_loop(&make_attr(&[65001, 65002]), 65001, 0));
    }

    #[test]
    fn no_loop_when_not_in_path() {
        assert!(!is_as_loop(&make_attr(&[65002, 65003]), 65001, 0));
    }

    #[test]
    fn confederation_loop_detected() {
        assert!(is_as_loop(&make_attr(&[65000, 65001]), 65001, 65000));
    }

    #[test]
    fn confederation_id_equal_to_local_asn_not_double_checked() {
        // When confederation_id == local_asn, the confederation check is skipped
        // (it would be redundant with the local_asn check).
        assert!(!is_as_loop(&make_attr(&[65002]), 65001, 65001));
    }

    #[test]
    fn no_as_path_attr_is_not_a_loop() {
        let attr = Arc::new(vec![
            bgp::Attribute::new_with_value(bgp::Attribute::ORIGIN, 0).unwrap(),
        ]);
        assert!(!is_as_loop(&attr, 65001, 0));
    }
}

#[cfg(test)]
mod local_pref_tests {
    use super::*;

    fn attr_with_codes(codes: &[u8]) -> Arc<Vec<packet::Attribute>> {
        Arc::new(
            codes
                .iter()
                .map(|&code| packet::Attribute::new_with_value(code, 0).unwrap())
                .collect(),
        )
    }

    #[test]
    fn injects_default_when_absent() {
        let attr = attr_with_codes(&[packet::Attribute::ORIGIN]);
        let result = inject_local_pref_if_absent(attr);
        let lp = result
            .iter()
            .find(|a| a.code() == packet::Attribute::LOCAL_PREF);
        assert!(lp.is_some());
        assert_eq!(
            lp.unwrap().value().unwrap(),
            packet::Attribute::DEFAULT_LOCAL_PREF
        );
    }

    #[test]
    fn preserves_existing_local_pref() {
        let attr = Arc::new(vec![
            packet::Attribute::new_with_value(packet::Attribute::ORIGIN, 0).unwrap(),
            packet::Attribute::new_with_value(packet::Attribute::LOCAL_PREF, 200).unwrap(),
        ]);
        let result = inject_local_pref_if_absent(Arc::clone(&attr));
        assert!(Arc::ptr_eq(&result, &attr), "must return the same Arc");
        let lp = result
            .iter()
            .find(|a| a.code() == packet::Attribute::LOCAL_PREF);
        assert_eq!(lp.unwrap().value().unwrap(), 200);
    }

    #[test]
    fn insertion_preserves_attribute_order() {
        // ORIGIN(1), AS_PATH(2) — LOCAL_PREF(5) must be inserted in code order.
        let attr = attr_with_codes(&[packet::Attribute::ORIGIN, packet::Attribute::AS_PATH]);
        let result = inject_local_pref_if_absent(attr);
        let codes: Vec<u8> = result.iter().map(|a| a.code()).collect();
        assert!(
            codes.windows(2).all(|w| w[0] <= w[1]),
            "attributes out of order: {codes:?}"
        );
        assert!(codes.contains(&packet::Attribute::LOCAL_PREF));
    }

    #[test]
    fn no_allocation_when_already_present() {
        // Arc::ptr_eq confirms inject_local_pref_if_absent returns the original Arc.
        let attr = Arc::new(vec![
            packet::Attribute::new_with_value(packet::Attribute::LOCAL_PREF, 100).unwrap(),
        ]);
        let result = inject_local_pref_if_absent(Arc::clone(&attr));
        assert!(Arc::ptr_eq(&result, &attr));
    }
}
