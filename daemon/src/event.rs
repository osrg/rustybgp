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

use rustybgp_packet::{self as packet, BgpFramer, Family, HoldTime, bgp, bmp};

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
struct MessageCounter {
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
    fn sync(&self, msg: &bgp::Message) -> bool {
        let mut ret = false;
        match msg {
            bgp::Message::Open(bgp::Open { .. }) => {
                let _ = self.open.fetch_add(1, Ordering::Relaxed);
            }
            bgp::Message::Update(bgp::Update {
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
            bgp::Message::Notification(_) => {
                ret = true;
                let _ = self.notification.fetch_add(1, Ordering::Relaxed);
            }
            bgp::Message::Keepalive => {
                let _ = self.keepalive.fetch_add(1, Ordering::Relaxed);
            }
            bgp::Message::RouteRefresh { .. } => {
                let _ = self.refresh.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.total.fetch_add(1, Ordering::Relaxed);
        ret
    }
}

use crate::fsm::State as SessionState;

fn session_state_to_api(v: SessionState) -> api::peer_state::SessionState {
    match v {
        SessionState::Idle => api::peer_state::SessionState::Idle,
        SessionState::Connect => api::peer_state::SessionState::Connect,
        SessionState::Active => api::peer_state::SessionState::Active,
        SessionState::OpenSent => api::peer_state::SessionState::Opensent,
        SessionState::OpenConfirm => api::peer_state::SessionState::Openconfirm,
        SessionState::Established => api::peer_state::SessionState::Established,
    }
}

/// Session-scoped counters and FSM state shared between `Peer` and the active
/// `PeerSession` via `Arc`.  All fields are atomics so they can be updated by
/// the session task without taking the global lock.  Reset at the start of each
/// new BGP session; the `Arc` itself lives as long as either side holds a clone.
struct SessionAddrs {
    local: SocketAddr,
    remote_port: u16,
}

struct PeerState {
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
struct ConnArbiter {
    fsm: crate::fsm::PeerFsm,
    active_close_tx: Option<tokio::sync::oneshot::Sender<CloseReason>>,
    passive_close_tx: Option<tokio::sync::oneshot::Sender<CloseReason>>,
    active_join_handle: Option<tokio::task::JoinHandle<()>>,
    passive_join_handle: Option<tokio::task::JoinHandle<()>>,
}

/// Signal sent to a running connection to request shutdown.
#[derive(Clone)]
enum CloseReason {
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

/// Static GR configuration for a single peer, set at peer creation.
/// `None` in `PeerConfig::graceful_restart` means GR is disabled for this peer.
/// Cloned into capability negotiation at each session open.
#[derive(Clone)]
struct GrPeerConfig {
    /// Restart Time advertised in our OPEN (12-bit, max 4095 s).
    restart_time: u16,
    /// Whether to set the N-bit (RFC 8538): GR applies to NOTIFICATION and Hold Timer expiry.
    notification_enabled: bool,
    /// Families included in the GR capability (non-empty by construction).
    families: Vec<Family>,
}

/// RFC 4456 Route Reflector configuration for a single peer.
#[derive(Clone, Default)]
struct RouteReflectorConfig {
    route_reflector_client: bool,
    /// Per-peer cluster ID; None means fall back to the local router-id.
    route_reflector_cluster_id: Option<Ipv4Addr>,
}

/// Static per-peer configuration.  Set at peer creation (via `PeerParams::build`)
/// and immutable for the lifetime of the peer.  Cloned into `PeerSession` at
/// session start so the session task can access it without the global lock.
#[derive(Clone)]
struct PeerConfig {
    remote_addr: IpAddr,
    remote_port: u16,
    /// Expected AS number from configuration; 0 means "accept any".
    /// The actual negotiated ASN lives in PeerState.remote_asn (session-scoped).
    expected_remote_asn: u32,
    local_asn: u32,
    passive: bool,
    delete_on_disconnected: bool,
    holdtime: u64,
    connect_retry_time: u64,
    local_cap: Vec<packet::Capability>,
    route_server_client: bool,
    route_reflector: RouteReflectorConfig,
    /// Snapshot of the global router-id taken at peer creation.
    /// Immutable for the lifetime of the peer; used for RR ORIGINATOR_ID loop
    /// detection without holding the global lock.
    local_router_id: Ipv4Addr,
    multihop_ttl: Option<u8>,
    /// GTSM minimum TTL (RFC 5082); None = GTSM disabled.
    /// When set, outgoing TTL is 255 and incoming packets below this value are dropped.
    /// Takes priority over multihop_ttl when both are configured.
    ttl_security: Option<u8>,
    password: Option<String>,
    /// Per-family prefix limits from config.
    /// Used to initialize PeerSession::prefix_counters in accept_connection().
    prefix_limits: FnvHashMap<Family, u32>,
    /// GR helper config; None = GR disabled.
    graceful_restart: Option<GrPeerConfig>,
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
struct PeerView {
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
}

/// Plain-struct replacement for the old PeerBuilder.
///
/// Both TryFrom<&api::Peer> and TryFrom<&config::Neighbor> construct this as
/// an exhaustive struct literal so that adding a new field causes a compile
/// error at every construction site.
struct PeerParams {
    remote_addr: IpAddr,
    remote_port: u16,
    expected_remote_asn: u32,
    local_asn: u32,
    passive: bool,
    rs_client: bool,
    route_reflector: RouteReflectorConfig,
    delete_on_disconnected: bool,
    admin_down: bool,
    state: SessionState,
    holdtime: u64,
    connect_retry_time: u64,
    multihop_ttl: Option<u8>,
    ttl_security: Option<u8>,
    password: Option<String>,
    /// Per-family add-path mode (RFC 7911 2-bit flags); mode 0 means plain MP.
    families: FnvHashMap<Family, u8>,
    send_max: FnvHashMap<Family, usize>,
    prefix_limits: FnvHashMap<Family, u32>,
    graceful_restart: Option<GrPeerConfig>,
}

impl PeerParams {
    const DEFAULT_HOLD_TIME: u64 = 180;
    const DEFAULT_CONNECT_RETRY_TIME: u64 = 3;

    /// Derive the local capability list from peer configuration.
    ///
    /// Separated from `build()` so the capability logic can be tested
    /// independently of struct construction.
    fn build_local_cap(
        remote_addr: IpAddr,
        local_asn: u32,
        families: &FnvHashMap<Family, u8>,
        graceful_restart: Option<&GrPeerConfig>,
    ) -> Vec<packet::Capability> {
        let mut local_cap: Vec<packet::Capability> = Vec::new();
        if families.is_empty() {
            local_cap.push(match remote_addr {
                IpAddr::V4(_) => packet::Capability::MultiProtocol(Family::IPV4),
                IpAddr::V6(_) => packet::Capability::MultiProtocol(Family::IPV6),
            });
        } else {
            let mut addpath = Vec::new();
            for (f, mode) in families {
                if *mode > 0 {
                    addpath.push((*f, *mode));
                }
                local_cap.push(packet::Capability::MultiProtocol(*f));
            }
            if !addpath.is_empty() {
                local_cap.push(packet::Capability::AddPath(addpath));
            }
            // RFC 8950: advertise ExtendedNexthop when peering over IPv6
            // with IPv4 address family configured
            if matches!(remote_addr, IpAddr::V6(_)) {
                let enh_families: Vec<(Family, u16)> = families
                    .keys()
                    .filter(|f| f.afi() == Family::AFI_IP)
                    .map(|f| (*f, Family::AFI_IP6))
                    .collect();
                if !enh_families.is_empty() {
                    local_cap.push(packet::Capability::ExtendedNexthop(enh_families));
                }
            }
        }
        if let Some(gr) = graceful_restart {
            // N-bit (0x4): supports GR for NOTIFICATION and Hold Timer (RFC 8538).
            // R-bit (0x8) is NOT set here; it is applied at connection time in
            // PeerFsm::on_connected() based on the current global restarting state.
            let flags = if gr.notification_enabled { 0x4 } else { 0 };
            local_cap.push(packet::Capability::GracefulRestart {
                flags,
                restart_time: gr.restart_time,
                families: gr.families.iter().map(|f| (*f, 0)).collect(),
            });
        }

        // Always advertise 4-byte ASN support.
        let four_octet = packet::Capability::FourOctetAsNumber(local_asn);
        let four_octet_code: u8 = (&four_octet).into();
        if !local_cap
            .iter()
            .any(|c| Into::<u8>::into(c) == four_octet_code)
        {
            local_cap.push(four_octet);
        }
        local_cap
    }

    /// Build a `Peer` from these params.
    ///
    /// `local_router_id` is needed to construct `PeerFsm` for collision
    /// detection; it is only known once `Global::router_id` is set, so callers
    /// always go through `Global::add_peer` rather than calling this directly.
    fn build(mut self, local_router_id: u32, global_asn: u32) -> Peer {
        if self.local_asn == 0 {
            self.local_asn = global_asn;
        }

        let local_cap = Self::build_local_cap(
            self.remote_addr,
            self.local_asn,
            &self.families,
            self.graceful_restart.as_ref(),
        );

        let conn_arbiter = Arc::new(std::sync::Mutex::new(ConnArbiter::new(
            crate::fsm::PeerFsm::new(
                local_router_id,
                self.local_asn,
                local_cap.clone(),
                self.holdtime,
                self.expected_remote_asn,
                self.send_max.clone(),
            ),
        )));

        Peer {
            config: PeerConfig {
                remote_addr: self.remote_addr,
                remote_port: if self.remote_port != 0 {
                    self.remote_port
                } else {
                    Global::BGP_PORT
                },
                expected_remote_asn: self.expected_remote_asn,
                local_asn: self.local_asn,
                passive: self.passive,
                delete_on_disconnected: self.delete_on_disconnected,
                holdtime: self.holdtime,
                connect_retry_time: self.connect_retry_time,
                local_cap,
                route_server_client: self.rs_client,
                route_reflector: self.route_reflector.clone(),
                local_router_id: Ipv4Addr::from(local_router_id),
                multihop_ttl: self.multihop_ttl,
                ttl_security: self.ttl_security,
                password: self.password,
                prefix_limits: self.prefix_limits,
                graceful_restart: self.graceful_restart,
            },
            admin_down: self.admin_down,
            state: Arc::new(PeerState {
                fsm: AtomicU8::new(self.state as u8),
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
            context: Arc::new(std::sync::Mutex::new(PeerContext {
                conn_arbiter,
                active_connect_cancel_tx: None,
                active_connect_join_handle: None,
                gr_state: crate::gr::GrState::new(),
                gr_restart_timer: None,
            })),
        }
    }
}

impl From<&PeerView> for api::Peer {
    fn from(p: &PeerView) -> Self {
        let session_state = SessionState::try_from(p.state.fsm.load(Ordering::Relaxed))
            .unwrap_or(SessionState::Idle);
        let remote_cap = p
            .state
            .remote_cap
            .load()
            .as_ref()
            .map(|caps| caps.iter().map(convert::capability_to_api).collect())
            .unwrap_or_default();
        let mut ps = api::PeerState {
            neighbor_address: p.config.remote_addr.to_string(),
            peer_asn: {
                let negotiated = p.state.remote_asn.load(Ordering::Relaxed);
                if negotiated != 0 {
                    negotiated
                } else {
                    p.config.expected_remote_asn
                }
            },
            local_asn: p.config.local_asn,
            router_id: Ipv4Addr::from(p.state.remote_id.load(Ordering::Relaxed)).to_string(),
            messages: Some(api::Messages {
                received: Some((&*p.counter_rx).into()),
                sent: Some((&*p.counter_tx).into()),
            }),
            queues: Some(Default::default()),
            remote_cap,
            local_cap: p
                .config
                .local_cap
                .iter()
                .map(convert::capability_to_api)
                .collect(),
            ..Default::default()
        };
        ps.session_state = session_state_to_api(session_state) as i32;
        ps.admin_state = if p.admin_down {
            api::peer_state::AdminState::Down as i32
        } else {
            api::peer_state::AdminState::Up as i32
        };
        let mut tm = api::Timers {
            config: Some(api::TimersConfig {
                hold_time: p.config.holdtime,
                keepalive_interval: p.config.holdtime / 3,
                ..Default::default()
            }),
            state: Some(Default::default()),
        };
        let uptime = p.state.peer_up_at.load(Ordering::Relaxed);
        if uptime != 0 {
            let negotiated_holdtime = std::cmp::min(
                p.config.holdtime,
                p.state.remote_holdtime.load(Ordering::Relaxed) as u64,
            );
            let mut ts = api::TimersState {
                uptime: Some(prost_types::Timestamp {
                    seconds: uptime as i64,
                    nanos: 0,
                }),
                negotiated_hold_time: negotiated_holdtime,
                keepalive_interval: negotiated_holdtime / 3,
                ..Default::default()
            };
            let downtime = p.state.peer_down_at.load(Ordering::Relaxed);
            if downtime != 0 {
                ts.downtime = Some(prost_types::Timestamp {
                    seconds: downtime as i64,
                    nanos: 0,
                });
            }
            tm.state = Some(ts);
        }
        let afisafis = p
            .route_stats
            .iter()
            .map(|(f, stats)| api::AfiSafi {
                state: Some(api::AfiSafiState {
                    family: Some(convert::family_to_api(*f)),
                    enabled: true,
                    received: stats.received,
                    accepted: stats.accepted,
                    ..Default::default()
                }),
                ..Default::default()
            })
            .collect();
        let graceful_restart = p
            .config
            .graceful_restart
            .as_ref()
            .map(|gr| api::GracefulRestart {
                enabled: true,
                restart_time: gr.restart_time as u32,
                peer_restarting: p.gr_peer_restarting,
                local_restarting: p.gr_local_restarting,
                ..Default::default()
            });
        api::Peer {
            state: Some(ps),
            conf: Some(Default::default()),
            timers: Some(tm),
            transport: Some(api::Transport {
                local_address: p
                    .state
                    .session_addrs
                    .load()
                    .as_ref()
                    .map(|a| a.local.ip().to_string())
                    .unwrap_or_default(),
                ..Default::default()
            }),
            route_reflector: Some(api::RouteReflector {
                route_reflector_client: p.config.route_reflector.route_reflector_client,
                route_reflector_cluster_id: p
                    .config
                    .route_reflector
                    .route_reflector_cluster_id
                    .map(|a| a.to_string())
                    .unwrap_or_default(),
            }),
            route_server: Some(api::RouteServer {
                route_server_client: p.config.route_server_client,
                secondary_route: false,
            }),
            afi_safis: afisafis,
            graceful_restart,
            ttl_security: p.config.ttl_security.map(|ttl_min| api::TtlSecurity {
                enabled: true,
                ttl_min: ttl_min as u32,
            }),
            ..Default::default()
        }
    }
}

impl TryFrom<&api::Peer> for PeerParams {
    type Error = Error;

    fn try_from(p: &api::Peer) -> Result<Self, Self::Error> {
        let conf = p.conf.as_ref().ok_or(Error::EmptyArgument)?;
        let remote_addr = IpAddr::from_str(&conf.neighbor_address).map_err(|_| {
            Error::InvalidArgument(format!("invalid peer address: {}", conf.neighbor_address))
        })?;

        let families: FnvHashMap<Family, u8> = p
            .afi_safis
            .iter()
            .filter(|x| x.config.as_ref().is_some_and(|x| x.family.is_some()))
            .map(|x| {
                let f =
                    convert::family_from_api(x.config.as_ref().unwrap().family.as_ref().unwrap());
                (f, 0u8)
            })
            .collect();

        let graceful_restart = { parse_gr_api(p.graceful_restart.as_ref(), &p.afi_safis) };

        let holdtime = {
            let t = p
                .timers
                .as_ref()
                .map(|x| &x.config)
                .map_or(0, |x| x.as_ref().map_or(0, |x| x.hold_time));
            if t != 0 {
                t
            } else {
                PeerParams::DEFAULT_HOLD_TIME
            }
        };
        let connect_retry_time = {
            let t = p
                .timers
                .as_ref()
                .map(|x| &x.config)
                .map_or(0, |x| x.as_ref().map_or(0, |x| x.connect_retry));
            if t != 0 {
                t
            } else {
                PeerParams::DEFAULT_CONNECT_RETRY_TIME
            }
        };

        Ok(PeerParams {
            remote_addr,
            remote_port: p.transport.as_ref().map_or(Global::BGP_PORT, |x| {
                if x.remote_port != 0 {
                    x.remote_port as u16
                } else {
                    Global::BGP_PORT
                }
            }),
            expected_remote_asn: conf.peer_asn,
            local_asn: conf.local_asn,
            passive: p.transport.as_ref().is_some_and(|x| x.passive_mode),
            rs_client: p
                .route_server
                .as_ref()
                .is_some_and(|x| x.route_server_client),
            route_reflector: {
                let rr = p.route_reflector.as_ref();
                RouteReflectorConfig {
                    route_reflector_client: rr.is_some_and(|x| x.route_reflector_client),
                    route_reflector_cluster_id: rr
                        .map(|x| x.route_reflector_cluster_id.as_str())
                        .filter(|s| !s.is_empty())
                        .and_then(|s| Ipv4Addr::from_str(s).ok()),
                }
            },
            delete_on_disconnected: false,
            admin_down: conf.admin_down,
            state: SessionState::Idle,
            holdtime,
            connect_retry_time,
            multihop_ttl: p.ebgp_multihop.as_ref().and_then(|x| {
                if x.enabled && x.multihop_ttl != 0 {
                    Some(x.multihop_ttl as u8)
                } else {
                    None
                }
            }),
            ttl_security: p.ttl_security.as_ref().and_then(|ts| {
                if ts.enabled {
                    let min = if ts.ttl_min == 0 {
                        255
                    } else {
                        ts.ttl_min as u8
                    };
                    Some(min)
                } else {
                    None
                }
            }),
            password: if conf.auth_password.is_empty() {
                None
            } else {
                Some(conf.auth_password.clone())
            },
            families,
            send_max: FnvHashMap::default(),
            prefix_limits: FnvHashMap::default(),
            graceful_restart,
        })
    }
}

/// Parse an afi-safis slice from YAML config into (families, send_max) maps.
///
/// Returns a map of Family -> add-path mode (RFC 7911 2-bit: bit0=RX, bit1=TX)
/// and a separate send_max map for families where add-path TX is configured.
fn parse_afi_safis_yaml(
    afi_safis: &[config::AfiSafi],
) -> (FnvHashMap<Family, u8>, FnvHashMap<Family, usize>) {
    let mut base_families: Vec<Family> = Vec::new();
    let addpath_entries: Vec<(packet::Family, u8, usize)> = afi_safis
        .iter()
        .filter(|x| {
            let name = x.config.as_ref().and_then(|c| c.afi_safi_name.as_ref());
            let Some(f) = name else { return false };
            if let Ok(family) = convert::family_from_config(f) {
                base_families.push(family);
            }
            true
        })
        .filter_map(|x| {
            let ap_config = x.add_paths.as_ref()?.config.as_ref()?;
            let rx = ap_config.receive.unwrap_or(false);
            let send_max = ap_config.send_max.unwrap_or(0) as usize;
            let tx = send_max > 0;
            let mode = u8::from(rx) | (u8::from(tx) << 1);
            if mode == 0 {
                return None;
            }
            let family =
                convert::family_from_config(x.config.as_ref()?.afi_safi_name.as_ref()?).ok()?;
            Some((family, mode, send_max))
        })
        .collect();

    let mut families: FnvHashMap<Family, u8> =
        base_families.into_iter().map(|f| (f, 0u8)).collect();
    let mut send_max: FnvHashMap<Family, usize> = FnvHashMap::default();
    for (f, mode, sm) in addpath_entries {
        families.insert(f, mode & 0x3);
        if sm > 0 {
            send_max.insert(f, sm);
        }
    }
    (families, send_max)
}

/// Build GrPeerConfig from gRPC GracefulRestart message + per-family mp_graceful_restart flags.
fn parse_gr_api(
    gr: Option<&api::GracefulRestart>,
    afi_safis: &[api::AfiSafi],
) -> Option<GrPeerConfig> {
    const DEFAULT_RESTART_TIME: u16 = 120;
    if !gr.is_some_and(|g| g.enabled) {
        return None;
    }
    let gr_families: Vec<Family> = afi_safis
        .iter()
        .filter(|a| {
            a.mp_graceful_restart
                .as_ref()
                .is_some_and(|m| m.config.as_ref().is_some_and(|c| c.enabled))
        })
        .filter_map(|a| {
            let f = a.config.as_ref()?.family.as_ref()?;
            Some(convert::family_from_api(f))
        })
        .collect();
    if gr_families.is_empty() {
        return None;
    }
    Some(GrPeerConfig {
        restart_time: gr
            .and_then(|g| u16::try_from(g.restart_time).ok())
            .unwrap_or(DEFAULT_RESTART_TIME),
        notification_enabled: gr.is_some_and(|g| g.notification_enabled),
        families: gr_families,
    })
}

/// Build GrPeerConfig from YAML GracefulRestartConfig + per-family mp-graceful-restart flags.
fn parse_gr_yaml(
    afi_safis: &[config::AfiSafi],
    gr_config: Option<&config::GracefulRestartConfig>,
) -> Option<GrPeerConfig> {
    const DEFAULT_RESTART_TIME: u16 = 120;
    if !gr_config.and_then(|c| c.enabled).unwrap_or(false) {
        return None;
    }
    let gr_families: Vec<Family> = afi_safis
        .iter()
        .filter(|a| {
            a.mp_graceful_restart
                .as_ref()
                .and_then(|gr| gr.config.as_ref())
                .and_then(|c| c.enabled)
                .unwrap_or(false)
        })
        .filter_map(|a| {
            convert::family_from_config(a.config.as_ref()?.afi_safi_name.as_ref()?).ok()
        })
        .collect();
    if gr_families.is_empty() {
        return None;
    }
    Some(GrPeerConfig {
        restart_time: gr_config
            .and_then(|c| c.restart_time)
            .unwrap_or(DEFAULT_RESTART_TIME),
        notification_enabled: gr_config
            .and_then(|c| c.notification_enabled)
            .unwrap_or(false),
        families: gr_families,
    })
}

impl TryFrom<&config::Neighbor> for PeerParams {
    type Error = String;

    fn try_from(n: &config::Neighbor) -> Result<PeerParams, Self::Error> {
        let c = n.config.as_ref().ok_or("missing neighbor config")?;
        let afi_safis = n.afi_safis.as_deref().unwrap_or_default();

        let remote_addr = c
            .neighbor_address
            .as_ref()
            .ok_or("missing neighbor address")?;
        let peer_as = c.peer_as.ok_or("missing peer-as")?;

        let transport_config = n.transport.as_ref().and_then(|t| t.config.as_ref());
        let timer_config = n.timers.as_ref().and_then(|t| t.config.as_ref());

        let (families, send_max) = parse_afi_safis_yaml(afi_safis);
        let graceful_restart = parse_gr_yaml(
            afi_safis,
            n.graceful_restart
                .as_ref()
                .and_then(|gr| gr.config.as_ref()),
        );

        // Extract per-family prefix limits.
        let mut prefix_limits: FnvHashMap<Family, u32> = FnvHashMap::default();
        for afi_safi in afi_safis {
            let prefix_max = |pl: &Option<config::generate::PrefixLimit>| -> Option<u32> {
                pl.as_ref()?.config.as_ref()?.max_prefixes
            };
            if let Some(v4) = &afi_safi.ipv4_unicast
                && let Some(max) = prefix_max(&v4.prefix_limit)
            {
                prefix_limits.insert(packet::Family::IPV4, max);
            }
            if let Some(v6) = &afi_safi.ipv6_unicast
                && let Some(max) = prefix_max(&v6.prefix_limit)
            {
                prefix_limits.insert(packet::Family::IPV6, max);
            }
        }

        let holdtime = timer_config
            .and_then(|c| c.hold_time)
            .map(|v| v as u64)
            .filter(|&v| v != 0)
            .unwrap_or(PeerParams::DEFAULT_HOLD_TIME);
        let connect_retry_time = timer_config
            .and_then(|c| c.connect_retry)
            .map(|v| v as u64)
            .filter(|&v| v != 0)
            .unwrap_or(PeerParams::DEFAULT_CONNECT_RETRY_TIME);

        Ok(PeerParams {
            remote_addr: *remote_addr,
            remote_port: transport_config
                .and_then(|t| t.remote_port)
                .unwrap_or(Global::BGP_PORT),
            expected_remote_asn: peer_as,
            local_asn: c.local_as.unwrap_or(0),
            passive: transport_config
                .and_then(|t| t.passive_mode)
                .unwrap_or(false),
            rs_client: n
                .route_server
                .as_ref()
                .and_then(|r| r.config.as_ref())
                .and_then(|r| r.route_server_client)
                .unwrap_or(false),
            route_reflector: {
                let rr_cfg = n.route_reflector.as_ref().and_then(|r| r.config.as_ref());
                RouteReflectorConfig {
                    route_reflector_client: rr_cfg
                        .and_then(|r| r.route_reflector_client)
                        .unwrap_or(false),
                    route_reflector_cluster_id: rr_cfg
                        .and_then(|r| r.route_reflector_cluster_id.as_deref())
                        .filter(|s| !s.is_empty())
                        .and_then(|s| Ipv4Addr::from_str(s).ok()),
                }
            },
            delete_on_disconnected: false,
            admin_down: c.admin_down.unwrap_or(false),
            state: SessionState::Idle,
            holdtime,
            connect_retry_time,
            multihop_ttl: n
                .ebgp_multihop
                .as_ref()
                .and_then(|m| m.config.as_ref())
                .and_then(|c| c.enabled.filter(|&en| en).and(c.multihop_ttl)),
            ttl_security: n
                .ttl_security
                .as_ref()
                .and_then(|ts| ts.config.as_ref())
                .and_then(|c| {
                    if c.enabled.unwrap_or(false) {
                        Some(
                            c.ttl_min
                                .map(|v| if v == 0 { 255 } else { v })
                                .unwrap_or(255),
                        )
                    } else {
                        None
                    }
                }),
            password: c.auth_password.clone(),
            families,
            send_max,
            prefix_limits,
            graceful_restart,
        })
    }
}

struct DynamicPeer {
    prefix: packet::IpNet,
}

struct PeerGroup {
    as_number: u32,
    dynamic_peers: Vec<DynamicPeer>,
    route_server_client: bool,
    holdtime: Option<u64>,
    local_asn: u32,
    passive: bool,
    route_reflector: RouteReflectorConfig,
    multihop_ttl: Option<u8>,
    ttl_security: Option<u8>,
    auth_password: Option<String>,
    connect_retry_time: Option<u64>,
    families: FnvHashMap<Family, u8>,
    send_max: FnvHashMap<Family, usize>,
    graceful_restart: Option<GrPeerConfig>,
}

fn peer_group_to_api(name: &str, pg: &PeerGroup) -> api::PeerGroup {
    api::PeerGroup {
        conf: Some(api::PeerGroupConf {
            peer_group_name: name.to_string(),
            peer_asn: pg.as_number,
            local_asn: pg.local_asn,
            auth_password: pg.auth_password.clone().unwrap_or_default(),
            ..Default::default()
        }),
        timers: {
            let has_holdtime = pg.holdtime.is_some();
            let has_connect_retry = pg.connect_retry_time.is_some();
            if has_holdtime || has_connect_retry {
                Some(api::Timers {
                    config: Some(api::TimersConfig {
                        hold_time: pg.holdtime.unwrap_or(0),
                        keepalive_interval: pg.holdtime.map(|h| h / 3).unwrap_or(0),
                        connect_retry: pg.connect_retry_time.unwrap_or(0),
                        ..Default::default()
                    }),
                    ..Default::default()
                })
            } else {
                None
            }
        },
        route_server: if pg.route_server_client {
            Some(api::RouteServer {
                route_server_client: true,
                ..Default::default()
            })
        } else {
            None
        },
        transport: if pg.passive {
            Some(api::Transport {
                passive_mode: true,
                ..Default::default()
            })
        } else {
            None
        },
        route_reflector: if pg.route_reflector.route_reflector_client
            || pg.route_reflector.route_reflector_cluster_id.is_some()
        {
            Some(api::RouteReflector {
                route_reflector_client: pg.route_reflector.route_reflector_client,
                route_reflector_cluster_id: pg
                    .route_reflector
                    .route_reflector_cluster_id
                    .map(|a| a.to_string())
                    .unwrap_or_default(),
            })
        } else {
            None
        },
        ebgp_multihop: pg.multihop_ttl.map(|ttl| api::EbgpMultihop {
            enabled: true,
            multihop_ttl: ttl as u32,
        }),
        afi_safis: pg
            .families
            .iter()
            .map(|(family, mode)| {
                let gr_enabled = pg
                    .graceful_restart
                    .as_ref()
                    .is_some_and(|gr| gr.families.contains(family));
                api::AfiSafi {
                    config: Some(api::AfiSafiConfig {
                        family: Some(convert::family_to_api(*family)),
                        ..Default::default()
                    }),
                    add_paths: if *mode != 0 {
                        Some(api::AddPaths {
                            config: Some(api::AddPathsConfig {
                                receive: (*mode & 1) != 0,
                                send_max: pg.send_max.get(family).copied().unwrap_or(0) as u32,
                            }),
                            ..Default::default()
                        })
                    } else {
                        None
                    },
                    mp_graceful_restart: if gr_enabled {
                        Some(api::MpGracefulRestart {
                            config: Some(api::MpGracefulRestartConfig { enabled: true }),
                            ..Default::default()
                        })
                    } else {
                        None
                    },
                    ..Default::default()
                }
            })
            .collect(),
        graceful_restart: pg.graceful_restart.as_ref().map(|gr| api::GracefulRestart {
            enabled: true,
            restart_time: gr.restart_time as u32,
            notification_enabled: gr.notification_enabled,
            ..Default::default()
        }),
        ttl_security: pg.ttl_security.map(|ttl_min| api::TtlSecurity {
            enabled: true,
            ttl_min: ttl_min as u32,
        }),
        ..Default::default()
    }
}

impl From<api::PeerGroup> for PeerGroup {
    fn from(p: api::PeerGroup) -> PeerGroup {
        let conf = p.conf.as_ref();
        PeerGroup {
            as_number: conf.map_or(0, |c| c.peer_asn),
            dynamic_peers: Vec::new(),
            route_server_client: p.route_server.is_some_and(|c| c.route_server_client),
            holdtime: p
                .timers
                .as_ref()
                .and_then(|t| t.config.as_ref())
                .map(|c| c.hold_time)
                .filter(|&h| h != 0),
            local_asn: conf.map_or(0, |c| c.local_asn),
            passive: p.transport.is_some_and(|t| t.passive_mode),
            route_reflector: {
                let rr = p.route_reflector.as_ref();
                RouteReflectorConfig {
                    route_reflector_client: rr.is_some_and(|x| x.route_reflector_client),
                    route_reflector_cluster_id: rr
                        .map(|x| x.route_reflector_cluster_id.as_str())
                        .filter(|s| !s.is_empty())
                        .and_then(|s| Ipv4Addr::from_str(s).ok()),
                }
            },
            multihop_ttl: p.ebgp_multihop.and_then(|x| {
                if x.enabled && x.multihop_ttl != 0 {
                    Some(x.multihop_ttl as u8)
                } else {
                    None
                }
            }),
            ttl_security: p.ttl_security.as_ref().and_then(|ts| {
                if ts.enabled {
                    let min = if ts.ttl_min == 0 {
                        255
                    } else {
                        ts.ttl_min as u8
                    };
                    Some(min)
                } else {
                    None
                }
            }),
            auth_password: conf
                .map(|c| c.auth_password.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string()),
            connect_retry_time: p
                .timers
                .and_then(|t| t.config)
                .map(|c| c.connect_retry)
                .filter(|&t| t != 0),
            families: p
                .afi_safis
                .iter()
                .filter(|x| x.config.as_ref().is_some_and(|c| c.family.is_some()))
                .map(|x| {
                    let f = convert::family_from_api(
                        x.config.as_ref().unwrap().family.as_ref().unwrap(),
                    );
                    (f, 0u8)
                })
                .collect(),
            send_max: FnvHashMap::default(),
            graceful_restart: parse_gr_api(p.graceful_restart.as_ref(), &p.afi_safis),
        }
    }
}

impl PeerGroup {
    fn from_yaml(pg: &config::PeerGroup) -> Self {
        let timer_config = pg.timers.as_ref().and_then(|t| t.config.as_ref());
        let (families, send_max) =
            parse_afi_safis_yaml(pg.afi_safis.as_deref().unwrap_or_default());
        PeerGroup {
            as_number: pg.config.as_ref().and_then(|c| c.peer_as).unwrap_or(0),
            dynamic_peers: Vec::new(),
            route_server_client: pg
                .route_server
                .as_ref()
                .and_then(|rs| rs.config.as_ref())
                .and_then(|c| c.route_server_client)
                .unwrap_or(false),
            holdtime: timer_config
                .and_then(|c| c.hold_time)
                .map(|h| h as u64)
                .filter(|&h| h != 0),
            local_asn: pg.config.as_ref().and_then(|c| c.local_as).unwrap_or(0),
            passive: pg
                .transport
                .as_ref()
                .and_then(|t| t.config.as_ref())
                .and_then(|c| c.passive_mode)
                .unwrap_or(false),
            route_reflector: {
                let rr = pg.route_reflector.as_ref().and_then(|r| r.config.as_ref());
                RouteReflectorConfig {
                    route_reflector_client: rr
                        .and_then(|c| c.route_reflector_client)
                        .unwrap_or(false),
                    route_reflector_cluster_id: rr
                        .and_then(|c| c.route_reflector_cluster_id.as_deref())
                        .filter(|s| !s.is_empty())
                        .and_then(|s| Ipv4Addr::from_str(s).ok()),
                }
            },
            multihop_ttl: pg
                .ebgp_multihop
                .as_ref()
                .and_then(|m| m.config.as_ref())
                .and_then(|c| {
                    if c.enabled.unwrap_or(false) {
                        c.multihop_ttl
                    } else {
                        None
                    }
                }),
            ttl_security: pg
                .ttl_security
                .as_ref()
                .and_then(|ts| ts.config.as_ref())
                .and_then(|c| {
                    if c.enabled.unwrap_or(false) {
                        Some(
                            c.ttl_min
                                .map(|v| if v == 0 { 255 } else { v })
                                .unwrap_or(255),
                        )
                    } else {
                        None
                    }
                }),
            auth_password: pg
                .config
                .as_ref()
                .and_then(|c| c.auth_password.as_deref())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string()),
            connect_retry_time: timer_config
                .and_then(|c| c.connect_retry)
                .map(|t| t as u64)
                .filter(|&t| t != 0),
            families,
            send_max,
            graceful_restart: parse_gr_yaml(
                pg.afi_safis.as_deref().unwrap_or_default(),
                pg.graceful_restart
                    .as_ref()
                    .and_then(|gr| gr.config.as_ref()),
            ),
        }
    }
}

struct GrpcService {
    init: Arc<tokio::sync::Notify>,
    policy_assignment_sem: tokio::sync::Semaphore,
    active_conn_tx: mpsc::UnboundedSender<TcpStream>,
    global: GlobalHandle,
    tables: TableHandle,
    path_uuid_map: tokio::sync::Mutex<FnvHashMap<uuid::Uuid, (Family, Vec<packet::PathNlri>)>>,
}

impl GrpcService {
    fn new(
        init: Arc<tokio::sync::Notify>,
        active_conn_tx: mpsc::UnboundedSender<TcpStream>,
        global: GlobalHandle,
        tables: TableHandle,
    ) -> Self {
        GrpcService {
            init,
            policy_assignment_sem: tokio::sync::Semaphore::new(1),
            active_conn_tx,
            global,
            tables,
            path_uuid_map: tokio::sync::Mutex::new(FnvHashMap::default()),
        }
    }

    async fn is_available(&self, need_active: bool) -> Result<(), Error> {
        let global = &self.global.read().await;
        if need_active && global.asn == 0 {
            return Err(Error::NotStarted);
        }
        Ok(())
    }

    #[allow(clippy::type_complexity)]
    fn local_path(
        &self,
        path: api::Path,
    ) -> Result<
        (
            Family,
            Vec<packet::PathNlri>,
            Option<Arc<Vec<packet::Attribute>>>,
            Option<bgp::Nexthop>,
        ),
        tonic::Status,
    > {
        let family = match path.family {
            Some(family) => convert::family_from_api(&family),
            None => Family::IPV4,
        };
        let net = convert::net_from_api(path.nlri.ok_or(Error::EmptyArgument)?)
            .map_err(|_| tonic::Status::new(tonic::Code::InvalidArgument, "prefix is invalid"))?;
        let mut attr = Vec::new();
        let mut nexthop = None;
        for a in path.pattrs {
            let a = convert::attr_from_api(a).map_err(|_| {
                tonic::Status::new(tonic::Code::InvalidArgument, "invalid attribute")
            })?;
            if a.code() == bgp::Attribute::MP_REACH {
                // MP_REACH binary: [AFI:2][SAFI:1][NH_LEN:1][nexthop:NH_LEN][reserved:1][NLRI...]
                // Extract just the nexthop.
                nexthop = a.binary().and_then(|b| {
                    let len = *b.get(3)? as usize;
                    if b.len() < 5 + len {
                        return None;
                    }
                    bgp::Nexthop::from_bytes(&b[4..4 + len])
                });
                if nexthop.is_none() {
                    return Err(tonic::Status::new(
                        tonic::Code::InvalidArgument,
                        "malformed MP_REACH nexthop",
                    ));
                }
            } else if a.code() == bgp::Attribute::NEXTHOP {
                nexthop = a.binary().and_then(|b| bgp::Nexthop::from_bytes(b));
            } else if a.code() == bgp::Attribute::ORIGINATOR_ID
                || a.code() == bgp::Attribute::CLUSTER_LIST
            {
                // Strip RR attributes from locally injected routes; they are
                // added by the RR on reflection and must not be set by operators.
            } else {
                attr.push(a);
            }
        }
        let attrs = if attr.is_empty() {
            None
        } else {
            Some(Arc::new(attr))
        };
        Ok((
            family,
            vec![packet::PathNlri {
                path_id: path.identifier,
                nlri: net,
            }],
            attrs,
            nexthop,
        ))
    }
}

#[tonic::async_trait]
impl GoBgpService for GrpcService {
    async fn start_bgp(
        &self,
        request: tonic::Request<api::StartBgpRequest>,
    ) -> Result<tonic::Response<api::StartBgpResponse>, tonic::Status> {
        let g = request.into_inner().global.ok_or(Error::EmptyArgument)?;
        if g.asn == 0 {
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "invalid as number",
            ));
        }
        if Ipv4Addr::from_str(&g.router_id).is_err() {
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "invalid router id",
            ));
        }

        let global = &mut self.global.write().await;
        if global.asn != 0 {
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "already started",
            ));
        }
        global.asn = g.asn;
        global.listen_port = if g.listen_port > 0 {
            g.listen_port as u16
        } else {
            Global::BGP_PORT
        };
        global.router_id = Ipv4Addr::from_str(&g.router_id).map_err(|_| {
            tonic::Status::new(
                tonic::Code::InvalidArgument,
                format!("invalid router-id: {}", g.router_id),
            )
        })?;
        if let Some(c) = g.confederation.filter(|c| c.enabled && c.identifier != 0) {
            global.confederation = Some(ConfederationConfig {
                id: c.identifier,
                members: c.member_as_list.into_iter().collect(),
            });
        }
        self.init.notify_one();

        Ok(tonic::Response::new(api::StartBgpResponse {}))
    }
    async fn stop_bgp(
        &self,
        request: tonic::Request<api::StopBgpRequest>,
    ) -> Result<tonic::Response<api::StopBgpResponse>, tonic::Status> {
        let allow_gr = request.into_inner().allow_graceful_restart;
        let cease = bgp::Message::Notification(rustybgp_packet::BgpError::Other {
            code: 6,
            subcode: 3,
            data: vec![],
        });

        let mut global = self.global.write().await;
        if global.asn == 0 {
            return Err(tonic::Status::new(
                tonic::Code::FailedPrecondition,
                "BGP is not running",
            ));
        }

        // Collect all peer task handles and send close signals while holding
        // the lock.  The handles are awaited after the lock is released.
        let mut join_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();
        for peer in global.peers.values_mut() {
            let has_gr = peer.config.graceful_restart.is_some();
            let reason = if !allow_gr || !has_gr {
                CloseReason::SendMessage(cease.clone())
            } else {
                CloseReason::Silent
            };

            let mut ctx = peer.context.lock().unwrap();
            ctx.active_connect_cancel_tx.take();
            if let Some(h) = ctx.active_connect_join_handle.take() {
                join_handles.push(h);
            }
            ctx.cancel_gr_timer();
            let mut arb = ctx.conn_arbiter.lock().unwrap();
            for (close_tx, join_handle) in [
                (arb.active_close_tx.take(), arb.active_join_handle.take()),
                (arb.passive_close_tx.take(), arb.passive_join_handle.take()),
            ] {
                if let Some(tx) = close_tx {
                    let _ = tx.send(reason.clone());
                }
                if let Some(h) = join_handle {
                    join_handles.push(h);
                }
            }
        }
        global.peers.clear();
        for client in global.bmp_clients.values() {
            client.cancel.cancel();
        }
        global.bmp_clients.clear();
        for client in global.rpki_clients.values() {
            client.cancel.cancel();
        }
        global.rpki_clients.clear();
        for cancel in global.mrt_dumpers.values() {
            cancel.cancel();
        }
        global.mrt_dumpers.clear();
        for cancel in global.watch_event_cancels.values() {
            cancel.cancel();
        }
        global.watch_event_cancels.clear();
        global.asn = 0;
        global.router_id = Ipv4Addr::new(0, 0, 0, 0);
        global.listen_port = Global::BGP_PORT;
        if let Some(tx) = global.stop_tx.take() {
            let _ = tx.send(());
        }
        drop(global);

        for h in join_handles {
            let _ = h.await;
        }
        Ok(tonic::Response::new(api::StopBgpResponse {}))
    }
    async fn get_bgp(
        &self,
        _request: tonic::Request<api::GetBgpRequest>,
    ) -> Result<tonic::Response<api::GetBgpResponse>, tonic::Status> {
        let global = (self.global.read().await.deref()).into();

        Ok(tonic::Response::new(api::GetBgpResponse {
            global: Some(global),
        }))
    }
    async fn add_peer(
        &self,
        request: tonic::Request<api::AddPeerRequest>,
    ) -> Result<tonic::Response<api::AddPeerResponse>, tonic::Status> {
        let api_peer = request.into_inner().peer.ok_or(Error::EmptyArgument)?;
        let params = PeerParams::try_from(&api_peer)?;
        let mut global = self.global.write().await;
        if let Some(password) = params.password.as_ref() {
            for fd in &global.listen_sockets {
                auth::set_md5sig(*fd, &params.remote_addr, password);
            }
        }
        global.add_peer(params, Some(self.active_conn_tx.clone()))?;
        Ok(tonic::Response::new(api::AddPeerResponse {}))
    }
    async fn delete_peer(
        &self,
        request: tonic::Request<api::DeletePeerRequest>,
    ) -> Result<tonic::Response<api::DeletePeerResponse>, tonic::Status> {
        if let Ok(peer_addr) = IpAddr::from_str(&request.into_inner().address) {
            let mut global = self.global.write().await;
            if let Some(p) = global.peers.remove(&peer_addr) {
                {
                    let mut ctx = p.context.lock().unwrap();
                    ctx.force_down(
                        CloseReason::SendMessage(bgp::Message::Notification(
                            rustybgp_packet::BgpError::Other {
                                code: 6,
                                subcode: 3,
                                data: vec![],
                            },
                        )),
                        true,
                    );
                }
                if p.config.password.is_some() {
                    for fd in &global.listen_sockets {
                        auth::set_md5sig(*fd, &peer_addr, "");
                    }
                }
                return Ok(tonic::Response::new(api::DeletePeerResponse {}));
            } else {
                return Err(tonic::Status::new(
                    tonic::Code::AlreadyExists,
                    "peer address doesn't exists",
                ));
            }
        }
        Err(tonic::Status::new(
            tonic::Code::InvalidArgument,
            "invalid peer address",
        ))
    }
    type ListPeerStream = Pin<
        Box<
            dyn Stream<Item = Result<api::ListPeerResponse, tonic::Status>> + Send + Sync + 'static,
        >,
    >;
    async fn list_peer(
        &self,
        request: tonic::Request<api::ListPeerRequest>,
    ) -> Result<tonic::Response<Self::ListPeerStream>, tonic::Status> {
        self.is_available(false).await?;
        let peer_addr = IpAddr::from_str(&request.into_inner().address);
        let mut peers: FnvHashMap<IpAddr, PeerView> = {
            let g = self.global.read().await;
            let is_restarting = g.selection_deferral.is_some();
            g.peers
                .iter()
                .map(|(a, p)| (*a, p.view(is_restarting)))
                .collect()
        };

        let addrs: Vec<IpAddr> = peers.keys().copied().collect();
        let all_stats = self.tables.collect_peer_stats(&addrs).await;
        for (addr, peer) in &mut peers {
            if let Some(stats) = all_stats.get(addr) {
                peer.update_stats(stats.clone());
            }
        }

        let (tx, rx) = mpsc::channel(1024);
        tokio::spawn(async move {
            for (addr, peer) in &peers {
                if let Ok(peer_addr) = peer_addr
                    && &peer_addr != addr
                {
                    continue;
                }
                let _ = tx
                    .send(Ok(api::ListPeerResponse {
                        peer: Some(peer.into()),
                    }))
                    .await;
            }
        });

        Ok(tonic::Response::new(Box::pin(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        )))
    }
    async fn update_peer(
        &self,
        request: tonic::Request<api::UpdatePeerRequest>,
    ) -> Result<tonic::Response<api::UpdatePeerResponse>, tonic::Status> {
        let req = request.into_inner();
        let api_peer = req.peer.ok_or(Error::EmptyArgument)?;
        let new_params = PeerParams::try_from(&api_peer)?;

        let mut global = self.global.write().await;

        let peer = global
            .peers
            .get(&new_params.remote_addr)
            .ok_or_else(|| tonic::Status::not_found("peer not found"))?;

        if new_params.rs_client != peer.config.route_server_client {
            return Err(tonic::Status::invalid_argument(
                "route_server_client cannot be changed via update_peer",
            ));
        }
        if new_params.route_reflector.route_reflector_client
            != peer.config.route_reflector.route_reflector_client
        {
            return Err(tonic::Status::invalid_argument(
                "route_reflector_client cannot be changed via update_peer",
            ));
        }

        let global_asn = global.asn;
        let router_id = u32::from(global.router_id);
        let listen_sockets = global.listen_sockets.clone();
        let peer_addr = new_params.remote_addr;

        let new_local_asn = if new_params.local_asn == 0 {
            global_asn
        } else {
            new_params.local_asn
        };
        let new_local_cap = PeerParams::build_local_cap(
            peer_addr,
            new_local_asn,
            &new_params.families,
            new_params.graceful_restart.as_ref(),
        );
        let effective_remote_port = if new_params.remote_port != 0 {
            new_params.remote_port
        } else {
            Global::BGP_PORT
        };

        let old_password;
        {
            let peer = global.peers.get_mut(&peer_addr).unwrap();

            let needs_teardown = effective_remote_port != peer.config.remote_port
                || new_params.expected_remote_asn != peer.config.expected_remote_asn
                || new_local_asn != peer.config.local_asn
                || new_params.passive != peer.config.passive
                || new_params.holdtime != peer.config.holdtime
                || new_local_cap != peer.config.local_cap
                || new_params.multihop_ttl != peer.config.multihop_ttl
                || new_params.password != peer.config.password;

            old_password = peer.config.password.clone();

            peer.config = PeerConfig {
                remote_addr: peer_addr,
                remote_port: effective_remote_port,
                expected_remote_asn: new_params.expected_remote_asn,
                local_asn: new_local_asn,
                passive: new_params.passive,
                delete_on_disconnected: new_params.delete_on_disconnected,
                holdtime: new_params.holdtime,
                connect_retry_time: new_params.connect_retry_time,
                local_cap: new_local_cap.clone(),
                route_server_client: new_params.rs_client,
                route_reflector: new_params.route_reflector.clone(),
                local_router_id: Ipv4Addr::from(router_id),
                multihop_ttl: new_params.multihop_ttl,
                ttl_security: new_params.ttl_security,
                password: new_params.password.clone(),
                prefix_limits: new_params.prefix_limits,
                graceful_restart: new_params.graceful_restart.clone(),
            };

            if needs_teardown {
                // Build a fresh ConnArbiter carrying the updated PeerFsm so the
                // next session uses the new capabilities, ASN, and hold time.
                // The session task (if any) holds the old Arc and will exit after
                // receiving CEASE; apply_disconnect then calls
                // clear_session_state + enable_active_connect on the new arbiter.
                let new_conn_arbiter = Arc::new(std::sync::Mutex::new(ConnArbiter::new(
                    crate::fsm::PeerFsm::new(
                        router_id,
                        new_local_asn,
                        new_local_cap,
                        new_params.holdtime,
                        new_params.expected_remote_asn,
                        new_params.send_max,
                    ),
                )));
                let mut ctx = peer.context.lock().unwrap();
                ctx.force_down(
                    CloseReason::SendMessage(bgp::Message::Notification(
                        rustybgp_packet::BgpError::Other {
                            code: 6,
                            subcode: 3,
                            data: vec![],
                        },
                    )),
                    true,
                );
                ctx.conn_arbiter = new_conn_arbiter;
            }
        }

        // Update TCP MD5 socket option after releasing the peer borrow.
        if old_password != new_params.password {
            if old_password.is_some() {
                for fd in &listen_sockets {
                    auth::set_md5sig(*fd, &peer_addr, "");
                }
            }
            if let Some(pw) = &new_params.password {
                for fd in &listen_sockets {
                    auth::set_md5sig(*fd, &peer_addr, pw);
                }
            }
        }

        Ok(tonic::Response::new(api::UpdatePeerResponse {
            needs_soft_reset_in: false,
        }))
    }
    async fn reset_peer(
        &self,
        request: tonic::Request<api::ResetPeerRequest>,
    ) -> Result<tonic::Response<api::ResetPeerResponse>, tonic::Status> {
        let req = request.into_inner();
        let peer_addr = IpAddr::from_str(&req.address)
            .map_err(|_| tonic::Status::invalid_argument("invalid peer address"))?;

        if !req.soft {
            // Hard reset: send CEASE NOTIFICATION to drop the session.
            // Unlike delete_peer the peer remains in the configuration
            // and will attempt to reconnect.
            //
            // If GR helper mode is active, fire the GR timer immediately to
            // purge stale routes, matching the behaviour of a restart-timer expiry.
            // The active-connect retry loop is kept running so the peer can reconnect.
            let global = self.global.read().await;
            let peer = global
                .peers
                .get(&peer_addr)
                .ok_or_else(|| tonic::Status::not_found("peer not found"))?;
            let mut ctx = peer.context.lock().unwrap();
            ctx.force_down(
                CloseReason::SendMessage(bgp::Message::Notification(
                    rustybgp_packet::BgpError::Other {
                        code: 6,
                        subcode: 3,
                        data: vec![],
                    },
                )),
                false,
            );
            return Ok(tonic::Response::new(api::ResetPeerResponse {}));
        }

        // Soft reset: re-apply policy / re-advertise without dropping the session.
        //
        // Soft reset IN re-applies the current import policy to all non-stale
        // RIB entries from this peer.  Stale entries (held during GR helper
        // mode) are intentionally skipped: they are transient, awaiting either
        // the peer's reconnection or restart-timer expiry.  Re-applying policy
        // to them would cause spurious churn for no practical benefit.  There
        // is no RFC guidance on this interaction; skipping stale entries is a
        // pragmatic implementation choice.
        //
        // Soft reset OUT re-advertises the current best paths to this peer via
        // do_route_refresh().  If the session is not Established (e.g., the
        // peer is in GR helper mode and the session is currently down),
        // do_route_refresh() exits early, making this a safe no-op.
        let direction = api::reset_peer_request::Direction::try_from(req.direction)
            .unwrap_or(api::reset_peer_request::Direction::Unspecified);
        let (do_in, do_out) = match direction {
            api::reset_peer_request::Direction::Both => (true, true),
            api::reset_peer_request::Direction::In => (true, false),
            api::reset_peer_request::Direction::Out => (false, true),
            api::reset_peer_request::Direction::Unspecified => {
                return Err(tonic::Status::invalid_argument(
                    "direction must be specified",
                ));
            }
        };

        // Verify the peer exists before touching the table.
        {
            let global = self.global.read().await;
            if !global.peers.contains_key(&peer_addr) {
                return Err(tonic::Status::not_found("peer not found"));
            }
        }

        if do_in {
            self.tables.soft_reset_in(peer_addr).await;
        }
        if do_out {
            self.tables.soft_reset_out(peer_addr).await;
        }
        Ok(tonic::Response::new(api::ResetPeerResponse {}))
    }
    async fn shutdown_peer(
        &self,
        request: tonic::Request<api::ShutdownPeerRequest>,
    ) -> Result<tonic::Response<api::ShutdownPeerResponse>, tonic::Status> {
        if let Ok(peer_addr) = IpAddr::from_str(&request.into_inner().address) {
            for (addr, p) in &mut self.global.write().await.peers {
                if addr == &peer_addr {
                    p.context
                        .lock()
                        .unwrap()
                        .force_down(CloseReason::AdminShutdown, false);
                    return Ok(tonic::Response::new(api::ShutdownPeerResponse {}));
                }
            }
            return Err(tonic::Status::new(
                tonic::Code::NotFound,
                "peer address not found",
            ));
        }
        Err(tonic::Status::new(
            tonic::Code::InvalidArgument,
            "invalid peer address",
        ))
    }
    async fn enable_peer(
        &self,
        request: tonic::Request<api::EnablePeerRequest>,
    ) -> Result<tonic::Response<api::EnablePeerResponse>, tonic::Status> {
        if let Ok(peer_addr) = IpAddr::from_str(&request.into_inner().address) {
            for (addr, p) in &mut self.global.write().await.peers {
                if addr == &peer_addr {
                    if p.admin_down {
                        p.admin_down = false;
                        enable_active_connect(p, self.active_conn_tx.clone());
                    }
                    return Ok(tonic::Response::new(api::EnablePeerResponse {}));
                }
            }
            return Err(tonic::Status::new(
                tonic::Code::AlreadyExists,
                "peer address doesn't exists",
            ));
        }
        Err(tonic::Status::new(
            tonic::Code::InvalidArgument,
            "invalid peer address",
        ))
    }
    async fn disable_peer(
        &self,
        request: tonic::Request<api::DisablePeerRequest>,
    ) -> Result<tonic::Response<api::DisablePeerResponse>, tonic::Status> {
        if let Ok(peer_addr) = IpAddr::from_str(&request.into_inner().address) {
            for (addr, p) in &mut self.global.write().await.peers {
                if addr == &peer_addr {
                    if !p.admin_down {
                        p.admin_down = true;
                        p.context
                            .lock()
                            .unwrap()
                            .force_down(CloseReason::AdminShutdown, true);
                    }
                    return Ok(tonic::Response::new(api::DisablePeerResponse {}));
                }
            }
            return Err(tonic::Status::new(
                tonic::Code::AlreadyExists,
                "peer address doesn't exists",
            ));
        }
        Err(tonic::Status::new(
            tonic::Code::InvalidArgument,
            "invalid peer address",
        ))
    }
    type WatchEventStream = Pin<
        Box<
            dyn Stream<Item = Result<api::WatchEventResponse, tonic::Status>>
                + Send
                + Sync
                + 'static,
        >,
    >;
    async fn watch_event(
        &self,
        _request: tonic::Request<api::WatchEventRequest>,
    ) -> Result<tonic::Response<Self::WatchEventStream>, tonic::Status> {
        let tables2 = self.tables.clone();
        let global2 = self.global.clone();
        let subscription = self.tables.subscribe_live().await;
        let sub_id = subscription.id;
        let (tx, rx) = mpsc::channel(1024);
        let cancel = CancellationToken::new();
        self.global
            .write()
            .await
            .watch_event_cancels
            .insert(sub_id, cancel.clone());
        tokio::spawn(async move {
            let mut rx = UnboundedReceiverStream::new(subscription.rx);
            loop {
                let event = tokio::select! {
                    e = rx.next() => match e { Some(e) => e, None => break },
                    _ = cancel.cancelled() => break,
                };
                let r = match event {
                    BgpEvent::PeerUp(data) => api::WatchEventResponse {
                        event: Some(api::watch_event_response::Event::Peer(
                            api::watch_event_response::PeerEvent {
                                r#type: api::watch_event_response::peer_event::Type::State.into(),
                                peer: Some(api::Peer {
                                    conf: Some(api::PeerConf {
                                        peer_asn: data.peer_asn,
                                        neighbor_address: data.peer_addr.to_string(),
                                        ..Default::default()
                                    }),
                                    state: Some(api::PeerState {
                                        session_state: 6,
                                        ..Default::default()
                                    }),
                                    ..Default::default()
                                }),
                            },
                        )),
                    },
                    BgpEvent::PeerDown(data) => api::WatchEventResponse {
                        event: Some(api::watch_event_response::Event::Peer(
                            api::watch_event_response::PeerEvent {
                                r#type: api::watch_event_response::peer_event::Type::State.into(),
                                peer: Some(api::Peer {
                                    conf: Some(api::PeerConf {
                                        peer_asn: data.peer_asn,
                                        neighbor_address: data.peer_addr.to_string(),
                                        ..Default::default()
                                    }),
                                    state: Some(api::PeerState {
                                        session_state: 1,
                                        ..Default::default()
                                    }),
                                    ..Default::default()
                                }),
                            },
                        )),
                    },
                    BgpEvent::AdjRibIn(change) => {
                        let mut paths = Vec::new();
                        for net in &change.nlris {
                            let path = if let Some(ref attrs) = change.attrs {
                                api::Path {
                                    nlri: Some(convert::nlri_to_api(&net.nlri)),
                                    family: Some(convert::family_to_api(change.family)),
                                    identifier: net.path_id,
                                    pattrs: attrs.iter().map(convert::attr_to_api).collect(),
                                    ..Default::default()
                                }
                            } else {
                                api::Path {
                                    nlri: Some(convert::nlri_to_api(&net.nlri)),
                                    family: Some(convert::family_to_api(change.family)),
                                    identifier: net.path_id,
                                    ..Default::default()
                                }
                            };
                            paths.push(path);
                        }
                        api::WatchEventResponse {
                            event: Some(api::watch_event_response::Event::Table(
                                api::watch_event_response::TableEvent { paths },
                            )),
                        }
                    }
                };
                if tx.send(Ok(r)).await.is_err() {
                    break;
                }
            }
            tables2.unsubscribe(sub_id).await;
            global2.write().await.watch_event_cancels.remove(&sub_id);
        });
        Ok(tonic::Response::new(Box::pin(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        )))
    }
    async fn add_peer_group(
        &self,
        request: tonic::Request<api::AddPeerGroupRequest>,
    ) -> Result<tonic::Response<api::AddPeerGroupResponse>, tonic::Status> {
        let pg = request
            .into_inner()
            .peer_group
            .ok_or(Error::EmptyArgument)?;
        let conf = pg.conf.as_ref().ok_or(Error::EmptyArgument)?;

        match self
            .global
            .write()
            .await
            .peer_group
            .entry(conf.peer_group_name.clone())
        {
            Occupied(_) => {
                return Err(tonic::Status::new(
                    tonic::Code::AlreadyExists,
                    "peer group name already exists",
                ));
            }
            Vacant(v) => {
                v.insert(PeerGroup::from(pg));
                return Ok(tonic::Response::new(api::AddPeerGroupResponse {}));
            }
        }
    }
    async fn delete_peer_group(
        &self,
        request: tonic::Request<api::DeletePeerGroupRequest>,
    ) -> Result<tonic::Response<api::DeletePeerGroupResponse>, tonic::Status> {
        let name = request.into_inner().name;
        let mut global = self.global.write().await;
        match global.peer_group.get(&name) {
            None => Err(tonic::Status::new(
                tonic::Code::NotFound,
                "peer group not found",
            )),
            Some(pg) if !pg.dynamic_peers.is_empty() => Err(tonic::Status::new(
                tonic::Code::FailedPrecondition,
                "peer group has dynamic neighbors; delete them first",
            )),
            Some(_) => {
                global.peer_group.remove(&name);
                Ok(tonic::Response::new(api::DeletePeerGroupResponse {}))
            }
        }
    }
    async fn update_peer_group(
        &self,
        request: tonic::Request<api::UpdatePeerGroupRequest>,
    ) -> Result<tonic::Response<api::UpdatePeerGroupResponse>, tonic::Status> {
        let pg = request
            .into_inner()
            .peer_group
            .ok_or(Error::EmptyArgument)?;
        let name = pg
            .conf
            .as_ref()
            .ok_or(Error::EmptyArgument)?
            .peer_group_name
            .clone();
        let updated = PeerGroup::from(pg);
        let mut global = self.global.write().await;
        match global.peer_group.get_mut(&name) {
            None => Err(tonic::Status::new(
                tonic::Code::NotFound,
                "peer group not found",
            )),
            Some(entry) => {
                entry.as_number = updated.as_number;
                entry.route_server_client = updated.route_server_client;
                entry.holdtime = updated.holdtime;
                entry.local_asn = updated.local_asn;
                entry.passive = updated.passive;
                entry.route_reflector = updated.route_reflector;
                entry.multihop_ttl = updated.multihop_ttl;
                entry.auth_password = updated.auth_password;
                entry.connect_retry_time = updated.connect_retry_time;
                Ok(tonic::Response::new(api::UpdatePeerGroupResponse {
                    needs_soft_reset_in: false,
                }))
            }
        }
    }
    type ListPeerGroupStream = Pin<
        Box<
            dyn Stream<Item = Result<api::ListPeerGroupResponse, tonic::Status>>
                + Send
                + Sync
                + 'static,
        >,
    >;
    async fn list_peer_group(
        &self,
        request: tonic::Request<api::ListPeerGroupRequest>,
    ) -> Result<tonic::Response<Self::ListPeerGroupStream>, tonic::Status> {
        let name_filter = request.into_inner().peer_group_name;
        let global = self.global.read().await;
        let v: Vec<api::PeerGroup> = global
            .peer_group
            .iter()
            .filter(|(name, _)| name_filter.is_empty() || name_filter == **name)
            .map(|(name, pg)| peer_group_to_api(name, pg))
            .collect();
        drop(global);
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            for pg in v {
                let _ = tx.send(Ok(api::ListPeerGroupResponse {
                    peer_group: Some(pg),
                }));
            }
        });
        Ok(tonic::Response::new(Box::pin(
            tokio_stream::wrappers::UnboundedReceiverStream::new(rx),
        )))
    }
    async fn add_dynamic_neighbor(
        &self,
        request: tonic::Request<api::AddDynamicNeighborRequest>,
    ) -> Result<tonic::Response<api::AddDynamicNeighborResponse>, tonic::Status> {
        let dynamic = request
            .into_inner()
            .dynamic_neighbor
            .ok_or(Error::EmptyArgument)?;

        let prefix = packet::IpNet::from_str(&dynamic.prefix)
            .map_err(|_| tonic::Status::new(tonic::Code::InvalidArgument, "prefix is invalid"))?;

        let global = &mut self.global.write().await;
        let pg = global
            .peer_group
            .get_mut(&dynamic.peer_group)
            .ok_or_else(|| tonic::Status::new(tonic::Code::NotFound, "peer group isn't found"))?;

        for p in &pg.dynamic_peers {
            if p.prefix == prefix {
                return Err(tonic::Status::new(
                    tonic::Code::AlreadyExists,
                    "prefix already exists",
                ));
            }
        }
        pg.dynamic_peers.push(DynamicPeer { prefix });
        Ok(tonic::Response::new(api::AddDynamicNeighborResponse {}))
    }
    async fn delete_dynamic_neighbor(
        &self,
        request: tonic::Request<api::DeleteDynamicNeighborRequest>,
    ) -> Result<tonic::Response<api::DeleteDynamicNeighborResponse>, tonic::Status> {
        let req = request.into_inner();
        let prefix = packet::IpNet::from_str(&req.prefix)
            .map_err(|_| tonic::Status::new(tonic::Code::InvalidArgument, "prefix is invalid"))?;
        let mut global = self.global.write().await;
        let pg = global
            .peer_group
            .get_mut(&req.peer_group)
            .ok_or_else(|| tonic::Status::new(tonic::Code::NotFound, "peer group not found"))?;
        let before = pg.dynamic_peers.len();
        pg.dynamic_peers.retain(|dp| dp.prefix != prefix);
        if pg.dynamic_peers.len() == before {
            return Err(tonic::Status::new(
                tonic::Code::NotFound,
                "prefix not found in peer group",
            ));
        }
        Ok(tonic::Response::new(api::DeleteDynamicNeighborResponse {}))
    }
    type ListDynamicNeighborStream = Pin<
        Box<
            dyn Stream<Item = Result<api::ListDynamicNeighborResponse, tonic::Status>>
                + Send
                + Sync
                + 'static,
        >,
    >;
    async fn list_dynamic_neighbor(
        &self,
        request: tonic::Request<api::ListDynamicNeighborRequest>,
    ) -> Result<tonic::Response<Self::ListDynamicNeighborStream>, tonic::Status> {
        let group_filter = request.into_inner().peer_group;
        let global = self.global.read().await;
        let v: Vec<api::DynamicNeighbor> = global
            .peer_group
            .iter()
            .filter(|(name, _)| group_filter.is_empty() || group_filter == **name)
            .flat_map(|(name, pg)| {
                pg.dynamic_peers.iter().map(move |dp| api::DynamicNeighbor {
                    prefix: dp.prefix.to_string(),
                    peer_group: name.clone(),
                })
            })
            .collect();
        drop(global);
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            for dn in v {
                let _ = tx.send(Ok(api::ListDynamicNeighborResponse {
                    dynamic_neighbor: Some(dn),
                }));
            }
        });
        Ok(tonic::Response::new(Box::pin(
            tokio_stream::wrappers::UnboundedReceiverStream::new(rx),
        )))
    }
    async fn add_path(
        &self,
        request: tonic::Request<api::AddPathRequest>,
    ) -> Result<tonic::Response<api::AddPathResponse>, tonic::Status> {
        let (family, nets, attrs, nexthop) =
            self.local_path(request.into_inner().path.ok_or(Error::EmptyArgument)?)?;
        let map_nets = nets.clone();
        let timestamp = std::time::SystemTime::now();
        let source = table::Source::local();
        if let Some(attrs) = attrs {
            for net in nets.clone() {
                self.tables
                    .insert_route(
                        source.clone(),
                        family,
                        net,
                        nexthop,
                        attrs.clone(),
                        None,
                        timestamp,
                    )
                    .await;
            }
        }
        let id = uuid::Uuid::new_v4();
        self.path_uuid_map
            .lock()
            .await
            .insert(id, (family, map_nets));
        Ok(tonic::Response::new(api::AddPathResponse {
            uuid: id.as_bytes().to_vec(),
        }))
    }
    async fn delete_path(
        &self,
        request: tonic::Request<api::DeletePathRequest>,
    ) -> Result<tonic::Response<api::DeletePathResponse>, tonic::Status> {
        let inner = request.into_inner();
        if inner.uuid.is_empty() {
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "uuid is required",
            ));
        }
        let id = uuid::Uuid::from_slice(&inner.uuid)
            .map_err(|_| tonic::Status::new(tonic::Code::InvalidArgument, "invalid uuid"))?;
        let (family, nets) = self
            .path_uuid_map
            .lock()
            .await
            .remove(&id)
            .ok_or_else(|| tonic::Status::new(tonic::Code::NotFound, "uuid not found"))?;
        let timestamp = std::time::SystemTime::now();
        let source = table::Source::local();
        for net in nets {
            self.tables
                .remove_route(source.clone(), family, net, None, timestamp)
                .await;
        }
        Ok(tonic::Response::new(api::DeletePathResponse {}))
    }
    type ListPathStream = Pin<
        Box<
            dyn Stream<Item = Result<api::ListPathResponse, tonic::Status>> + Send + Sync + 'static,
        >,
    >;
    async fn list_path(
        &self,
        request: tonic::Request<api::ListPathRequest>,
    ) -> Result<tonic::Response<Self::ListPathStream>, tonic::Status> {
        self.is_available(false).await?;
        let request = request.into_inner();
        let family = match request.family {
            Some(family) => convert::family_from_api(&family),
            None => Family::IPV4,
        };
        let query = if let Ok(t) = api::TableType::try_from(request.table_type) {
            match t {
                api::TableType::Unspecified => {
                    return Err(tonic::Status::new(
                        tonic::Code::InvalidArgument,
                        "table type unspecified",
                    ));
                }
                api::TableType::Global => table::TableQuery::Global,
                api::TableType::Local | api::TableType::Vrf => {
                    return Err(tonic::Status::unimplemented("Not yet implemented"));
                }
                api::TableType::AdjIn => IpAddr::from_str(&request.name)
                    .map(table::TableQuery::AdjIn)
                    .map_err(|_| {
                        tonic::Status::new(tonic::Code::InvalidArgument, "invalid neighbor name")
                    })?,
                api::TableType::AdjOut => IpAddr::from_str(&request.name)
                    .map(table::TableQuery::AdjOut)
                    .map_err(|_| {
                        tonic::Status::new(tonic::Code::InvalidArgument, "invalid neighbor name")
                    })?,
            }
        } else {
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "invalid table type",
            ));
        };

        let prefixes: Vec<table::PrefixFilter> = request
            .prefixes
            .iter()
            .filter_map(|x| {
                let prefix = packet::Nlri::from_str(&x.prefix).ok()?;
                let lookup_type = match api::table_lookup_prefix::Type::try_from(x.r#type).ok()? {
                    api::table_lookup_prefix::Type::Unspecified
                    | api::table_lookup_prefix::Type::Exact => table::LookupType::Exact,
                    api::table_lookup_prefix::Type::Longer => table::LookupType::Longer,
                    api::table_lookup_prefix::Type::Shorter => table::LookupType::Shorter,
                };
                Some(table::PrefixFilter {
                    prefix,
                    lookup_type,
                })
            })
            .collect();

        let batch_size = request.batch_size;
        let enable_filtered = request.enable_filtered;
        let binary = convert::PathBinaryFlags {
            nlri_binary: request.enable_nlri_binary || request.enable_only_binary,
            attr_binary: request.enable_attribute_binary || request.enable_only_binary,
            only_binary: request.enable_only_binary,
        };
        let mut path_count = 0u64;
        let v: Vec<_> = self
            .tables
            .collect_paths(query, family, prefixes, enable_filtered)
            .await
            .into_iter()
            .take_while(|d| {
                if batch_size == 0 {
                    return true;
                }
                path_count += d.paths.len() as u64;
                path_count <= batch_size
            })
            .map(|d| api::ListPathResponse {
                destination: Some(convert::destination_to_api(d, family, &binary)),
            })
            .collect();
        let (tx, rx) = mpsc::channel(1024);
        tokio::spawn(async move {
            for r in v {
                if tx.send(Ok(r)).await.is_err() {
                    break;
                }
            }
        });

        Ok(tonic::Response::new(Box::pin(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        )))
    }
    async fn add_path_stream(
        &self,
        request: tonic::Request<tonic::Streaming<api::AddPathStreamRequest>>,
    ) -> Result<tonic::Response<api::AddPathStreamResponse>, tonic::Status> {
        let mut stream = request.into_inner();
        let source = table::Source::local();
        while let Some(Ok(request)) = stream.next().await {
            for path in request.paths {
                if let Ok((family, nets, attrs, nexthop)) = self.local_path(path)
                    && let Some(attrs) = attrs
                {
                    let timestamp = std::time::SystemTime::now();
                    for net in nets {
                        self.tables
                            .insert_route(
                                source.clone(),
                                family,
                                net,
                                nexthop,
                                attrs.clone(),
                                None,
                                timestamp,
                            )
                            .await;
                    }
                }
            }
        }
        Ok(tonic::Response::new(api::AddPathStreamResponse {}))
    }
    async fn get_table(
        &self,
        request: tonic::Request<api::GetTableRequest>,
    ) -> Result<tonic::Response<api::GetTableResponse>, tonic::Status> {
        self.is_available(true).await?;
        let family = match request.into_inner().family {
            Some(family) => convert::family_from_api(&family),
            None => Family::IPV4,
        };
        let info = self.tables.table_state(family).await;
        Ok(tonic::Response::new(convert::routing_table_state_to_api(
            info,
        )))
    }
    async fn add_vrf(
        &self,
        _request: tonic::Request<api::AddVrfRequest>,
    ) -> Result<tonic::Response<api::AddVrfResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }
    async fn delete_vrf(
        &self,
        _request: tonic::Request<api::DeleteVrfRequest>,
    ) -> Result<tonic::Response<api::DeleteVrfResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }
    type ListVrfStream = Pin<
        Box<dyn Stream<Item = Result<api::ListVrfResponse, tonic::Status>> + Send + Sync + 'static>,
    >;
    async fn list_vrf(
        &self,
        _request: tonic::Request<api::ListVrfRequest>,
    ) -> Result<tonic::Response<Self::ListVrfStream>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }
    async fn add_policy(
        &self,
        request: tonic::Request<api::AddPolicyRequest>,
    ) -> Result<tonic::Response<api::AddPolicyResponse>, tonic::Status> {
        let policy = request.into_inner().policy.ok_or(Error::EmptyArgument)?;
        self.global
            .write()
            .await
            .ptable
            .add_policy(
                &policy.name,
                policy.statements.into_iter().map(|s| s.name).collect(),
            )
            .map_err(Error::from)
            .map(|_| Ok(tonic::Response::new(api::AddPolicyResponse {})))?
    }
    async fn delete_policy(
        &self,
        request: tonic::Request<api::DeletePolicyRequest>,
    ) -> Result<tonic::Response<api::DeletePolicyResponse>, tonic::Status> {
        let req = request.into_inner();
        let name = req.policy.map(|p| p.name).unwrap_or_default();
        let (import, export) = self
            .global
            .write()
            .await
            .ptable
            .delete_policy(&name, req.preserve_statements, req.all)
            .map_err(Error::from)?;
        self.tables.import_policy.store(import);
        self.tables.export_policy.store(export);
        Ok(tonic::Response::new(api::DeletePolicyResponse {}))
    }
    type ListPolicyStream = Pin<
        Box<
            dyn Stream<Item = Result<api::ListPolicyResponse, tonic::Status>>
                + Send
                + Sync
                + 'static,
        >,
    >;
    async fn list_policy(
        &self,
        request: tonic::Request<api::ListPolicyRequest>,
    ) -> Result<tonic::Response<Self::ListPolicyStream>, tonic::Status> {
        let request = request.into_inner();
        let v: Vec<api::ListPolicyResponse> = self
            .global
            .read()
            .await
            .ptable
            .iter_policies(request.name)
            .map(|p| api::ListPolicyResponse {
                policy: Some(convert::policy_to_api(p)),
            })
            .collect();

        let (tx, rx) = mpsc::channel(1024);
        tokio::spawn(async move {
            for r in v {
                if tx.send(Ok(r)).await.is_err() {
                    break;
                }
            }
        });
        Ok(tonic::Response::new(Box::pin(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        )))
    }
    async fn set_policies(
        &self,
        request: tonic::Request<api::SetPoliciesRequest>,
    ) -> Result<tonic::Response<api::SetPoliciesResponse>, tonic::Status> {
        let req = request.into_inner();
        let mut new_ptable = table::PolicyTable::new();

        for ds in req.defined_sets {
            let set = convert::defined_set_from_api(ds).map_err(Error::from)?;
            new_ptable.add_defined_set(set).map_err(Error::from)?;
        }

        for policy in &req.policies {
            for stmt in &policy.statements {
                let conditions =
                    convert::conditions_from_api(stmt.conditions.clone()).map_err(Error::from)?;
                let (disposition, actions) =
                    convert::disposition_from_api(stmt.actions.clone()).map_err(Error::from)?;
                // Ignore AlreadyExists: the same statement may appear in multiple policies.
                let _ = new_ptable.add_statement(&stmt.name, conditions, disposition, actions);
            }
            let stmt_names = policy.statements.iter().map(|s| s.name.clone()).collect();
            new_ptable
                .add_policy(&policy.name, stmt_names)
                .map_err(Error::from)?;
        }

        let mut new_import = None;
        let mut new_export = None;
        for assign in req.assignments {
            let (name, direction, default_action, policy_names) =
                convert::policy_assignment_from_api(assign).map_err(Error::from)?;
            let (dir, assignment) = new_ptable
                .add_assignment(&name, direction, default_action, policy_names)
                .map_err(Error::from)?;
            if dir == table::PolicyDirection::Import {
                new_import = Some(assignment);
            } else {
                new_export = Some(assignment);
            }
        }

        self.global.write().await.ptable = new_ptable;
        self.tables.import_policy.store(new_import);
        self.tables.export_policy.store(new_export);
        Ok(tonic::Response::new(api::SetPoliciesResponse {}))
    }
    async fn add_defined_set(
        &self,
        request: tonic::Request<api::AddDefinedSetRequest>,
    ) -> Result<tonic::Response<api::AddDefinedSetResponse>, tonic::Status> {
        let set = request
            .into_inner()
            .defined_set
            .ok_or(Error::EmptyArgument)?;
        let set = convert::defined_set_from_api(set).map_err(Error::from)?;
        self.global
            .write()
            .await
            .ptable
            .add_defined_set(set)
            .map_err(Error::from)
            .map(|_| Ok(tonic::Response::new(api::AddDefinedSetResponse {})))?
    }
    async fn delete_defined_set(
        &self,
        request: tonic::Request<api::DeleteDefinedSetRequest>,
    ) -> Result<tonic::Response<api::DeleteDefinedSetResponse>, tonic::Status> {
        let req = request.into_inner();
        let set = req.defined_set.ok_or(Error::EmptyArgument)?;
        let kind = convert::defined_set_kind_from_api(set.defined_type).map_err(Error::from)?;
        self.global
            .write()
            .await
            .ptable
            .delete_defined_set(&set.name, kind, req.all)
            .map_err(Error::from)?;
        Ok(tonic::Response::new(api::DeleteDefinedSetResponse {}))
    }
    type ListDefinedSetStream = Pin<
        Box<
            dyn Stream<Item = Result<api::ListDefinedSetResponse, tonic::Status>>
                + Send
                + Sync
                + 'static,
        >,
    >;
    async fn list_defined_set(
        &self,
        request: tonic::Request<api::ListDefinedSetRequest>,
    ) -> Result<tonic::Response<Self::ListDefinedSetStream>, tonic::Status> {
        let req = request.into_inner();
        let v: Vec<api::ListDefinedSetResponse> = self
            .global
            .read()
            .await
            .ptable
            .iter_defined_sets()
            .map(convert::defined_set_to_api)
            .filter(|x| x.defined_type == req.defined_type)
            .map(|x| api::ListDefinedSetResponse {
                defined_set: Some(x),
            })
            .collect();
        let (tx, rx) = mpsc::channel(1024);
        tokio::spawn(async move {
            for r in v {
                if tx.send(Ok(r)).await.is_err() {
                    break;
                }
            }
        });
        Ok(tonic::Response::new(Box::pin(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        )))
    }
    async fn add_statement(
        &self,
        request: tonic::Request<api::AddStatementRequest>,
    ) -> Result<tonic::Response<api::AddStatementResponse>, tonic::Status> {
        let statement = request.into_inner().statement.ok_or(Error::EmptyArgument)?;
        let conditions = convert::conditions_from_api(statement.conditions).map_err(Error::from)?;
        let (disposition, actions) =
            convert::disposition_from_api(statement.actions).map_err(Error::from)?;
        self.global
            .write()
            .await
            .ptable
            .add_statement(&statement.name, conditions, disposition, actions)
            .map_err(Error::from)
            .map(|_| Ok(tonic::Response::new(api::AddStatementResponse {})))?
    }
    async fn delete_statement(
        &self,
        request: tonic::Request<api::DeleteStatementRequest>,
    ) -> Result<tonic::Response<api::DeleteStatementResponse>, tonic::Status> {
        let req = request.into_inner();
        let name = req.statement.map(|s| s.name).unwrap_or_default();
        self.global
            .write()
            .await
            .ptable
            .delete_statement(&name, req.all)
            .map_err(Error::from)?;
        Ok(tonic::Response::new(api::DeleteStatementResponse {}))
    }
    type ListStatementStream = Pin<
        Box<
            dyn Stream<Item = Result<api::ListStatementResponse, tonic::Status>>
                + Send
                + Sync
                + 'static,
        >,
    >;
    async fn list_statement(
        &self,
        request: tonic::Request<api::ListStatementRequest>,
    ) -> Result<tonic::Response<Self::ListStatementStream>, tonic::Status> {
        let request = request.into_inner();
        let v: Vec<api::ListStatementResponse> = self
            .global
            .read()
            .await
            .ptable
            .iter_statements(request.name)
            .map(|s| api::ListStatementResponse {
                statement: Some(convert::statement_to_api(s)),
            })
            .collect();
        let (tx, rx) = mpsc::channel(1024);
        tokio::spawn(async move {
            for r in v {
                if tx.send(Ok(r)).await.is_err() {
                    break;
                }
            }
        });
        Ok(tonic::Response::new(Box::pin(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        )))
    }
    async fn add_policy_assignment(
        &self,
        request: tonic::Request<api::AddPolicyAssignmentRequest>,
    ) -> Result<tonic::Response<api::AddPolicyAssignmentResponse>, tonic::Status> {
        let _ = self.policy_assignment_sem.acquire().await;
        let request = request
            .into_inner()
            .assignment
            .ok_or(Error::EmptyArgument)?;
        add_policy_assignment(request, self.global.clone(), self.tables.clone()).await?;
        Ok(tonic::Response::new(api::AddPolicyAssignmentResponse {}))
    }
    async fn delete_policy_assignment(
        &self,
        request: tonic::Request<api::DeletePolicyAssignmentRequest>,
    ) -> Result<tonic::Response<api::DeletePolicyAssignmentResponse>, tonic::Status> {
        let _ = self.policy_assignment_sem.acquire().await;
        let req = request.into_inner();
        let assignment = req.assignment.ok_or(Error::EmptyArgument)?;
        let (_, direction, _, policy_names) =
            convert::policy_assignment_from_api(assignment).map_err(Error::from)?;
        let updated = self
            .global
            .write()
            .await
            .ptable
            .delete_policy_assignment(direction, &policy_names, req.all)
            .map_err(Error::from)?;
        if direction == table::PolicyDirection::Import {
            self.tables.import_policy.store(updated);
        } else {
            self.tables.export_policy.store(updated);
        }
        Ok(tonic::Response::new(api::DeletePolicyAssignmentResponse {}))
    }
    type ListPolicyAssignmentStream = Pin<
        Box<
            dyn Stream<Item = Result<api::ListPolicyAssignmentResponse, tonic::Status>>
                + Send
                + Sync
                + 'static,
        >,
    >;
    async fn list_policy_assignment(
        &self,
        request: tonic::Request<api::ListPolicyAssignmentRequest>,
    ) -> Result<tonic::Response<Self::ListPolicyAssignmentStream>, tonic::Status> {
        let request = request.into_inner();
        let v: Vec<api::ListPolicyAssignmentResponse> = self
            .global
            .read()
            .await
            .ptable
            .iter_assignments(request.direction)
            .map(|(dir, pa)| api::ListPolicyAssignmentResponse {
                assignment: Some(convert::policy_assignment_to_api(pa, dir)),
            })
            .collect();

        let (tx, rx) = mpsc::channel(1024);
        tokio::spawn(async move {
            for r in v {
                if tx.send(Ok(r)).await.is_err() {
                    break;
                }
            }
        });
        Ok(tonic::Response::new(Box::pin(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        )))
    }
    async fn set_policy_assignment(
        &self,
        request: tonic::Request<api::SetPolicyAssignmentRequest>,
    ) -> Result<tonic::Response<api::SetPolicyAssignmentResponse>, tonic::Status> {
        let _ = self.policy_assignment_sem.acquire().await;
        let assignment = request
            .into_inner()
            .assignment
            .ok_or(Error::EmptyArgument)?;
        let (name, direction, default_action, policy_names) =
            convert::policy_assignment_from_api(assignment).map_err(Error::from)?;
        let updated = self
            .global
            .write()
            .await
            .ptable
            .set_policy_assignment(&name, direction, default_action, policy_names)
            .map_err(Error::from)?;
        if direction == table::PolicyDirection::Import {
            self.tables.import_policy.store(Some(updated));
        } else {
            self.tables.export_policy.store(Some(updated));
        }
        Ok(tonic::Response::new(api::SetPolicyAssignmentResponse {}))
    }
    async fn add_rpki(
        &self,
        request: tonic::Request<api::AddRpkiRequest>,
    ) -> Result<tonic::Response<api::AddRpkiResponse>, tonic::Status> {
        let request = request.into_inner();
        let addr = IpAddr::from_str(&request.address)
            .map_err(|_| tonic::Status::new(tonic::Code::InvalidArgument, "invalid address"))?;

        let sockaddr = SocketAddr::new(addr, request.port as u16);
        match self.global.write().await.add_rpki_client(sockaddr) {
            Err(()) => {
                return Err(tonic::Status::new(
                    tonic::Code::AlreadyExists,
                    format!("rpki client {} already exists", sockaddr),
                ));
            }
            Ok((cancel, soft_reset, state)) => {
                RpkiClient::try_connect(sockaddr, cancel, soft_reset, state, self.tables.clone());
            }
        }
        Ok(tonic::Response::new(api::AddRpkiResponse {}))
    }
    async fn delete_rpki(
        &self,
        request: tonic::Request<api::DeleteRpkiRequest>,
    ) -> Result<tonic::Response<api::DeleteRpkiResponse>, tonic::Status> {
        let request = request.into_inner();
        let addr = IpAddr::from_str(&request.address)
            .map_err(|_| tonic::Status::new(tonic::Code::InvalidArgument, "invalid address"))?;
        let sockaddr = SocketAddr::new(addr, request.port as u16);
        if self.global.write().await.remove_rpki_client(sockaddr) {
            Ok(tonic::Response::new(api::DeleteRpkiResponse {}))
        } else {
            Err(tonic::Status::new(
                tonic::Code::NotFound,
                format!("rpki client {} not found", sockaddr),
            ))
        }
    }
    type ListRpkiStream = Pin<
        Box<
            dyn Stream<Item = Result<api::ListRpkiResponse, tonic::Status>> + Send + Sync + 'static,
        >,
    >;
    async fn list_rpki(
        &self,
        _request: tonic::Request<api::ListRpkiRequest>,
    ) -> Result<tonic::Response<Self::ListRpkiStream>, tonic::Status> {
        let mut v = FnvHashMap::default();

        for (sockaddr, client) in self.global.read().await.iter_rpki_clients() {
            let r = api::Rpki {
                conf: Some(api::RpkiConf {
                    address: sockaddr.ip().to_string(),
                    remote_port: sockaddr.port() as u32,
                }),
                state: Some((&*client.state).into()),
            };
            v.insert(sockaddr.ip(), r);
        }

        for (addr, r) in v.iter_mut() {
            let s = self.tables.rpki_state(addr).await;
            r.state.as_mut().unwrap().record_ipv4 = s.num_records_v4;
            r.state.as_mut().unwrap().record_ipv6 = s.num_records_v6;
            r.state.as_mut().unwrap().prefix_ipv4 = s.num_prefixes_v4;
            r.state.as_mut().unwrap().prefix_ipv6 = s.num_prefixes_v6;
        }

        let (tx, rx) = mpsc::channel(1024);
        tokio::spawn(async move {
            for (_, r) in v {
                let _ = tx.send(Ok(api::ListRpkiResponse { server: Some(r) })).await;
            }
        });
        Ok(tonic::Response::new(Box::pin(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        )))
    }
    async fn enable_rpki(
        &self,
        request: tonic::Request<api::EnableRpkiRequest>,
    ) -> Result<tonic::Response<api::EnableRpkiResponse>, tonic::Status> {
        let request = request.into_inner();
        let addr = IpAddr::from_str(&request.address)
            .map_err(|_| tonic::Status::new(tonic::Code::InvalidArgument, "invalid address"))?;
        let sockaddr = SocketAddr::new(addr, request.port as u16);
        let (cancel, soft_reset, state) = {
            let mut global = self.global.write().await;
            match global.rpki_clients.get_mut(&sockaddr) {
                None => {
                    return Err(tonic::Status::new(
                        tonic::Code::NotFound,
                        format!("rpki client {} not found", sockaddr),
                    ));
                }
                Some(client) if !client.disabled => {
                    return Err(tonic::Status::new(
                        tonic::Code::FailedPrecondition,
                        format!("rpki client {} is not disabled", sockaddr),
                    ));
                }
                Some(client) => {
                    client.disabled = false;
                    (
                        client.cancel.clone(),
                        Arc::clone(&client.soft_reset),
                        Arc::clone(&client.state),
                    )
                }
            }
        };
        RpkiClient::try_connect(sockaddr, cancel, soft_reset, state, self.tables.clone());
        Ok(tonic::Response::new(api::EnableRpkiResponse {}))
    }
    async fn disable_rpki(
        &self,
        request: tonic::Request<api::DisableRpkiRequest>,
    ) -> Result<tonic::Response<api::DisableRpkiResponse>, tonic::Status> {
        let request = request.into_inner();
        let addr = IpAddr::from_str(&request.address)
            .map_err(|_| tonic::Status::new(tonic::Code::InvalidArgument, "invalid address"))?;
        let sockaddr = SocketAddr::new(addr, request.port as u16);
        let mut global = self.global.write().await;
        match global.rpki_clients.get_mut(&sockaddr) {
            None => Err(tonic::Status::new(
                tonic::Code::NotFound,
                format!("rpki client {} not found", sockaddr),
            )),
            Some(client) if client.disabled => Err(tonic::Status::new(
                tonic::Code::FailedPrecondition,
                format!("rpki client {} is already disabled", sockaddr),
            )),
            Some(client) => {
                client.cancel.cancel();
                client.cancel = CancellationToken::new();
                client.disabled = true;
                Ok(tonic::Response::new(api::DisableRpkiResponse {}))
            }
        }
    }
    async fn reset_rpki(
        &self,
        request: tonic::Request<api::ResetRpkiRequest>,
    ) -> Result<tonic::Response<api::ResetRpkiResponse>, tonic::Status> {
        let request = request.into_inner();
        let addr = IpAddr::from_str(&request.address)
            .map_err(|_| tonic::Status::new(tonic::Code::InvalidArgument, "invalid address"))?;
        let sockaddr = SocketAddr::new(addr, request.port as u16);
        if request.soft {
            let global = self.global.read().await;
            return match global.rpki_clients.get(&sockaddr) {
                None => Err(tonic::Status::new(
                    tonic::Code::NotFound,
                    format!("rpki client {} not found", sockaddr),
                )),
                Some(client) if client.disabled => Err(tonic::Status::new(
                    tonic::Code::FailedPrecondition,
                    format!("rpki client {} is disabled", sockaddr),
                )),
                Some(client) => {
                    client.soft_reset.notify_one();
                    Ok(tonic::Response::new(api::ResetRpkiResponse {}))
                }
            };
        }
        let (disabled, cancel, soft_reset, state) = {
            let mut global = self.global.write().await;
            match global.rpki_clients.get_mut(&sockaddr) {
                None => {
                    return Err(tonic::Status::new(
                        tonic::Code::NotFound,
                        format!("rpki client {} not found", sockaddr),
                    ));
                }
                Some(client) => {
                    let disabled = client.disabled;
                    client.cancel.cancel();
                    client.cancel = CancellationToken::new();
                    (
                        disabled,
                        client.cancel.clone(),
                        Arc::clone(&client.soft_reset),
                        Arc::clone(&client.state),
                    )
                }
            }
        };
        self.tables.rpki_drop_all(Arc::new(addr)).await;
        if !disabled {
            RpkiClient::try_connect(sockaddr, cancel, soft_reset, state, self.tables.clone());
        }
        Ok(tonic::Response::new(api::ResetRpkiResponse {}))
    }
    type ListRpkiTableStream = Pin<
        Box<
            dyn Stream<Item = Result<api::ListRpkiTableResponse, tonic::Status>>
                + Send
                + Sync
                + 'static,
        >,
    >;
    async fn list_rpki_table(
        &self,
        request: tonic::Request<api::ListRpkiTableRequest>,
    ) -> Result<tonic::Response<Self::ListRpkiTableStream>, tonic::Status> {
        let family = match request.into_inner().family {
            Some(family) => convert::family_from_api(&family),
            None => Family::IPV4,
        };

        let v: Vec<api::ListRpkiTableResponse> = self
            .tables
            .collect_roa(family)
            .await
            .into_iter()
            .map(|(net, roa)| api::ListRpkiTableResponse {
                roa: Some(convert::roa_to_api(&net, &roa)),
            })
            .collect();
        let (tx, rx) = mpsc::channel(1024);
        tokio::spawn(async move {
            for r in v {
                if tx.send(Ok(r)).await.is_err() {
                    break;
                }
            }
        });
        Ok(tonic::Response::new(Box::pin(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        )))
    }
    async fn enable_zebra(
        &self,
        _request: tonic::Request<api::EnableZebraRequest>,
    ) -> Result<tonic::Response<api::EnableZebraResponse>, tonic::Status> {
        if self.tables.kernel_tx.load().is_some() {
            return Ok(tonic::Response::new(api::EnableZebraResponse {}));
        }
        match kernel::Handle::new() {
            Ok((handle, connection)) => {
                tokio::spawn(connection);
                let (tx, mut rx) = mpsc::unbounded_channel();
                tokio::spawn(async move {
                    while let Some(change) = rx.recv().await {
                        if let Err(e) = handle.apply(&change).await {
                            log::error!("kernel route update failed: {}", e);
                        }
                    }
                });
                self.tables.kernel_tx.store(Some(Arc::new(tx)));
                log::info!("kernel route integration enabled");
                Ok(tonic::Response::new(api::EnableZebraResponse {}))
            }
            Err(e) => Err(tonic::Status::internal(format!(
                "failed to enable kernel route integration: {:?}",
                e
            ))),
        }
    }
    async fn enable_mrt(
        &self,
        request: tonic::Request<api::EnableMrtRequest>,
    ) -> Result<tonic::Response<api::EnableMrtResponse>, tonic::Status> {
        let request = request.into_inner();
        if request.dump_type != config::generate::MrtType::Updates as i32 {
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "only update dump is supported",
            ));
        }
        let interval = request.rotation_interval;
        let filename = request.filename;
        let mut d = crate::mrt::MrtDumper::new(&filename, interval);
        let cancel = CancellationToken::new();
        {
            let mut g = self.global.write().await;
            if g.mrt_dumpers.contains_key(&filename) {
                return Err(tonic::Status::new(
                    tonic::Code::AlreadyExists,
                    "mrt dumper already enabled for this file",
                ));
            }
            g.mrt_dumpers.insert(filename.clone(), cancel.clone());
        }
        let file = match tokio::fs::File::create(std::path::Path::new(&d.pathname())).await {
            Ok(file) => file,
            Err(e) => {
                self.global.write().await.mrt_dumpers.remove(&filename);
                return Err(tonic::Status::new(
                    tonic::Code::Internal,
                    format!("failed to create mrt dump file: {e}"),
                ));
            }
        };
        let tables = self.tables.clone();
        tokio::spawn(async move {
            if let Err(e) = d.serve(file, cancel, tables).await {
                log::error!("mrt dumper failed: {:?}", e);
            }
        });
        Ok(tonic::Response::new(api::EnableMrtResponse {}))
    }
    async fn disable_mrt(
        &self,
        request: tonic::Request<api::DisableMrtRequest>,
    ) -> Result<tonic::Response<api::DisableMrtResponse>, tonic::Status> {
        let filename = request.into_inner().filename;
        if let Some(cancel) = self.global.write().await.mrt_dumpers.remove(&filename) {
            cancel.cancel();
            Ok(tonic::Response::new(api::DisableMrtResponse {}))
        } else {
            Err(tonic::Status::new(
                tonic::Code::NotFound,
                format!("mrt dumper not found for file: {filename}"),
            ))
        }
    }
    async fn add_bmp(
        &self,
        request: tonic::Request<api::AddBmpRequest>,
    ) -> Result<tonic::Response<api::AddBmpResponse>, tonic::Status> {
        let request = request.into_inner();
        let addr = IpAddr::from_str(&request.address)
            .map_err(|_| tonic::Status::new(tonic::Code::InvalidArgument, "invalid address"))?;

        if request.policy != api::add_bmp_request::MonitoringPolicy::Pre as i32 {
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "unsupported policy (only pre-policy supporeted",
            ));
        }

        let sockaddr = SocketAddr::new(addr, request.port as u16);
        match self.global.write().await.add_bmp_client(sockaddr) {
            Err(()) => {
                return Err(tonic::Status::new(
                    tonic::Code::AlreadyExists,
                    format!("bmp client {} already exists", sockaddr),
                ));
            }
            Ok((cancel, state)) => {
                BmpClient::try_connect(
                    sockaddr,
                    cancel,
                    state,
                    self.global.clone(),
                    self.tables.clone(),
                );
            }
        }
        Ok(tonic::Response::new(api::AddBmpResponse {}))
    }
    async fn delete_bmp(
        &self,
        request: tonic::Request<api::DeleteBmpRequest>,
    ) -> Result<tonic::Response<api::DeleteBmpResponse>, tonic::Status> {
        let request = request.into_inner();
        let addr = IpAddr::from_str(&request.address)
            .map_err(|_| tonic::Status::new(tonic::Code::InvalidArgument, "invalid address"))?;
        let sockaddr = SocketAddr::new(addr, request.port as u16);
        if self.global.write().await.remove_bmp_client(sockaddr) {
            Ok(tonic::Response::new(api::DeleteBmpResponse {}))
        } else {
            Err(tonic::Status::new(
                tonic::Code::NotFound,
                format!("bmp client {} not found", sockaddr),
            ))
        }
    }
    type ListBmpStream = Pin<
        Box<dyn Stream<Item = Result<api::ListBmpResponse, tonic::Status>> + Send + Sync + 'static>,
    >;
    async fn list_bmp(
        &self,
        _request: tonic::Request<api::ListBmpRequest>,
    ) -> Result<tonic::Response<Self::ListBmpStream>, tonic::Status> {
        let v = self
            .global
            .read()
            .await
            .iter_bmp_clients()
            .map(|(k, v)| api::ListBmpResponse {
                station: Some(api::list_bmp_response::BmpStation {
                    conf: Some(api::list_bmp_response::bmp_station::Conf {
                        address: k.ip().to_string(),
                        port: k.port() as u32,
                    }),
                    state: Some(api::list_bmp_response::bmp_station::State {
                        uptime: Some(prost_types::Timestamp {
                            seconds: v.state.uptime.load(std::sync::atomic::Ordering::Relaxed)
                                as i64,
                            nanos: 0,
                        }),
                        downtime: Some(prost_types::Timestamp {
                            seconds: v.state.downtime.load(std::sync::atomic::Ordering::Relaxed)
                                as i64,
                            nanos: 0,
                        }),
                    }),
                }),
            })
            .collect::<Vec<api::ListBmpResponse>>();
        let (tx, rx) = mpsc::channel(1024);
        tokio::spawn(async move {
            for r in v {
                let _ = tx.send(Ok(r)).await;
            }
        });
        Ok(tonic::Response::new(Box::pin(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        )))
    }
    async fn set_log_level(
        &self,
        _request: tonic::Request<api::SetLogLevelRequest>,
    ) -> Result<tonic::Response<api::SetLogLevelResponse>, tonic::Status> {
        let level = match api::set_log_level_request::Level::try_from(_request.into_inner().level)
            .unwrap_or(api::set_log_level_request::Level::Unspecified)
        {
            api::set_log_level_request::Level::Unspecified => {
                return Err(tonic::Status::new(
                    tonic::Code::InvalidArgument,
                    "log level unspecified",
                ));
            }
            api::set_log_level_request::Level::Panic
            | api::set_log_level_request::Level::Fatal
            | api::set_log_level_request::Level::Error => log::LevelFilter::Error,
            api::set_log_level_request::Level::Warn => log::LevelFilter::Warn,
            api::set_log_level_request::Level::Info => log::LevelFilter::Info,
            api::set_log_level_request::Level::Debug => log::LevelFilter::Debug,
            api::set_log_level_request::Level::Trace => log::LevelFilter::Trace,
        };
        log::set_max_level(level);
        Ok(tonic::Response::new(api::SetLogLevelResponse {}))
    }
}

async fn add_policy_assignment(
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

fn enable_active_connect(peer: &mut Peer, ch: mpsc::UnboundedSender<TcpStream>) {
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

impl From<&crate::rpki::RpkiState> for api::RpkiState {
    fn from(s: &crate::rpki::RpkiState) -> Self {
        let uptime = s.uptime.load(Ordering::Relaxed);
        let downtime = s.downtime.load(Ordering::Relaxed);
        api::RpkiState {
            uptime: Some(prost_types::Timestamp {
                seconds: uptime as i64,
                nanos: 0,
            }),
            downtime: Some(prost_types::Timestamp {
                seconds: downtime as i64,
                nanos: 0,
            }),
            up: s.up.load(Ordering::Relaxed),
            record_ipv4: 0,
            record_ipv6: 0,
            prefix_ipv4: 0,
            prefix_ipv6: 0,
            serial: s.serial.load(Ordering::Relaxed),
            received_ipv4: s.received_ipv4.load(Ordering::Relaxed),
            received_ipv6: s.received_ipv6.load(Ordering::Relaxed),
            serial_notify: s.serial_notify.load(Ordering::Relaxed),
            cache_reset: s.cache_reset.load(Ordering::Relaxed),
            cache_response: s.cache_response.load(Ordering::Relaxed),
            end_of_data: s.end_of_data.load(Ordering::Relaxed),
            error: s.error.load(Ordering::Relaxed),
            serial_query: s.serial_query.load(Ordering::Relaxed),
            reset_query: s.reset_query.load(Ordering::Relaxed),
        }
    }
}

fn create_listen_socket(addr: String, port: u16) -> std::io::Result<std::net::TcpListener> {
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
struct ConfederationConfig {
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

    /// Sending on this channel causes the BGP listener loop to stop, enabling
    /// a subsequent start_bgp call to restart it.  None when BGP is not running.
    stop_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl From<&Global> for api::Global {
    fn from(g: &Global) -> Self {
        api::Global {
            asn: g.asn,
            router_id: g.router_id.to_string(),
            listen_port: g.listen_port as i32,
            listen_addresses: Vec::new(),
            families: Vec::new(),
            use_multiple_paths: false,
            route_selection_options: None,
            default_route_distance: None,
            confederation: g.confederation.as_ref().map(|c| api::Confederation {
                enabled: true,
                identifier: c.id,
                member_as_list: c.members.iter().copied().collect(),
            }),
            graceful_restart: None,
            bind_to_device: "".to_string(),
        }
    }
}

impl Global {
    const BGP_PORT: u16 = 179;

    fn new() -> Global {
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
        params: PeerParams,
        tx: Option<mpsc::UnboundedSender<TcpStream>>,
    ) -> std::result::Result<(), Error> {
        if self.peers.contains_key(&params.remote_addr) {
            return Err(Error::AlreadyExists(
                "peer address already exists".to_string(),
            ));
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
        let global: GlobalHandle = Arc::new(tokio::sync::RwLock::new(Global::new()));
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
        if bgp
            .as_ref()
            .and_then(|x| x.zebra.as_ref())
            .and_then(|x| x.config.as_ref())
            .is_some_and(|x| x.enabled == Some(true))
        {
            match kernel::Handle::new() {
                Ok((handle, connection)) => {
                    tokio::spawn(connection);
                    let (tx, mut rx) = mpsc::unbounded_channel();
                    tokio::spawn(async move {
                        while let Some(change) = rx.recv().await {
                            if let Err(e) = handle.apply(&change).await {
                                log::error!("kernel route update failed: {}", e);
                            }
                        }
                    });
                    tables.kernel_tx.store(Some(Arc::new(tx)));
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
                        tables.start_deferral_families(families).await;
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
struct NegotiatedGr {
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
/// AdminShutdown and FsmError never trigger GR.
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
            gr.notification_enabled && !err.is_hard_reset()
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
        tables.end_deferral_families(&complete_families).await;
    }

    if let Some(remaining) = end_remaining {
        if !remaining.is_empty() {
            tables.end_deferral_families(&remaining).await;
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
        tables.drop_families(addr, &families).await;
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

/// Per-session peer role, used to control attribute export and route filtering.
///
/// Determined once from peer configuration at session creation time and stored
/// in `PeerExportContext`.  Extended to `IbgpRrClient` when Route Reflector
/// support is added.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerRole {
    Ibgp,
    IbgpRrClient,
    Ebgp,
    /// Session between two different Member-ASes within the same confederation.
    /// Keeps LOCAL_PREF (unlike regular eBGP) and uses CONFED_SEQUENCE for AS_PATH.
    ConfedEbgp,
    RsClient,
}

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
    /// The codec carries only session-level parameters needed for decoding
    /// (local_asn for iBGP loop detection) and message framing.  All attribute
    /// transformation is handled by `export_attrs`/`export_nexthop` before
    /// routes enter `PendingTx`.
    fn build_codec(&self) -> bgp::PeerCodec {
        bgp::PeerCodecBuilder::new()
            .local_asn(self.local_asn)
            .confederation_id(self.confederation_id)
            .build()
    }

    /// Apply per-peer attribute transformation to outgoing route attributes.
    ///
    /// eBGP: prepend `local_asn` to AS_PATH (adding a synthetic segment for
    /// locally-originated routes), and strip LOCAL_PREF (not sent to eBGP
    /// peers per RFC 4271).
    /// iBGP / iBGP-RR-client: pass through unchanged — no AS_PATH prepend,
    /// LOCAL_PREF retained.
    /// RS client: pass through unchanged.
    fn export_attrs(&self, attrs: &Arc<Vec<bgp::Attribute>>) -> Arc<Vec<bgp::Attribute>> {
        match self.role {
            PeerRole::RsClient | PeerRole::Ibgp | PeerRole::IbgpRrClient => attrs.clone(),
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
                    .filter(|a| a.code() != bgp::Attribute::LOCAL_PREF)
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
        }
    }

    /// Apply per-peer nexthop transformation to an outgoing route nexthop.
    ///
    /// eBGP: replace with local_addr (with link-local for IPv6 when available).
    /// iBGP / iBGP-RR-client / RS client: pass through unchanged (next-hop
    /// unchanged).
    fn export_nexthop(&self, nexthop: Option<bgp::Nexthop>) -> bgp::Nexthop {
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
            (_, None) => local(),
            (PeerRole::RsClient | PeerRole::Ibgp | PeerRole::IbgpRrClient, Some(nh)) => nh,
            (PeerRole::ConfedEbgp | PeerRole::Ebgp, Some(_)) => local(),
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
    shutdown: Option<crate::fsm::SessionDownReason>,
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
    urgent: Vec<bgp::Message>,
    framer: BgpFramer,
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
        let framer = BgpFramer::new(export_ctx.build_codec());

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
            shutdown: None,
            tables: res.tables,
            export_map: ExportMap::new(),
            prefix_counters,
            negotiated_gr: None,
            context: res.context,
            local_router_id: res.local_router_id,
            cluster_id: res.cluster_id,
            urgent: Vec::new(),
            framer,
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

        let framer = BgpFramer::new(bgp::PeerCodecBuilder::new().build());

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
            shutdown: None,
            tables,
            export_map: ExportMap::new(),
            prefix_counters: FnvHashMap::default(),
            negotiated_gr: None,
            context,
            local_router_id: Ipv4Addr::new(1, 0, 0, 1),
            cluster_id: None,
            urgent: vec![],
            framer,
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

        // Collect channel info up front so we don't borrow self.framer across .await.
        let channel_info: Vec<(Family, bool, bool)> = self
            .framer
            .inner()
            .channel
            .iter()
            .map(|(f, c)| (*f, c.addpath_rx(), c.addpath_tx()))
            .collect();

        // Create one Source per negotiated family so GR can stale individual families.
        for (family, _, _) in &channel_info {
            self.source.insert(
                *family,
                Arc::new(table::Source::new(
                    self.remote_addr,
                    self.export_ctx.local_addr,
                    remote_asn,
                    self.export_ctx.local_asn,
                    router_id,
                    self.export_ctx.role == PeerRole::RsClient,
                    self.export_ctx.role == PeerRole::IbgpRrClient,
                )),
            );
        }

        let mut addpath = FnvHashSet::default();
        for (family, addpath_rx, addpath_tx) in &channel_info {
            if *addpath_rx {
                addpath.insert(*family);
            }
            self.pending
                .insert(*family, crate::peer_tx::PendingTx::new(*addpath_tx));
        }

        let export_policy = self.tables.export_policy.load_full();
        let peer_event_rx = self
            .tables
            .register_peer(self.remote_addr, addpath, |rtable| {
                for (f, _, _) in &channel_info {
                    let effective_max = self
                        .conn_arbiter
                        .lock()
                        .unwrap()
                        .connection(self.role)
                        .and_then(|s| s.send_max().get(f))
                        .copied()
                        .unwrap_or(1);
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
                        );
                    }
                }
            })
            .await;
        self.peer_event_rx = Some(UnboundedReceiverStream::new(peer_event_rx));
        let remote_holdtime = HoldTime::new(self.state.remote_holdtime.load(Ordering::Relaxed))
            .unwrap_or(HoldTime::DISABLED);
        self.tables
            .peer_up(PeerUpData {
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
            })
            .await;
    }

    async fn do_route_refresh(&mut self, family: Family) {
        if !self.pending.contains_key(&family) {
            return;
        }
        let export_policy = self.tables.export_policy.load_full();
        let effective_max = self
            .conn_arbiter
            .lock()
            .unwrap()
            .connection(self.role)
            .and_then(|s| s.send_max().get(&family))
            .copied()
            .unwrap_or(1);
        let changes = self.tables.collect_loc_rib_paths(family).await;
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
            );
        }
        self.pending.get_mut(&family).unwrap().schedule_eor();
    }

    async fn apply_outputs(
        &mut self,
        outputs: Vec<crate::fsm::PeerFsmOutput>,
        local_sockaddr: SocketAddr,
        remote_sockaddr: SocketAddr,
    ) -> Vec<GlobalEffect> {
        let mut effects = Vec::new();
        for output in outputs {
            match output {
                crate::fsm::PeerFsmOutput::Connection(_, crate::fsm::Output::SendMessage(m)) => {
                    self.urgent.push(m);
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
                    crate::fsm::Output::ChannelsNegotiated(channels),
                ) => {
                    // Log Add-Path warnings for locally configured but not negotiated families
                    let local_addpath: Vec<(Family, u8)> = self
                        .local_cap
                        .iter()
                        .filter_map(|c| {
                            if let packet::Capability::AddPath(v) = c {
                                Some(v.clone())
                            } else {
                                None
                            }
                        })
                        .flatten()
                        .collect();
                    for (family, mode) in &local_addpath {
                        match channels.get(family) {
                            Some(ch) => {
                                if mode & 0x1 > 0 && !ch.addpath_rx() {
                                    log::warn!(
                                        "add-path receive configured for {:?} but not negotiated with peer {}",
                                        family,
                                        self.remote_addr
                                    );
                                }
                                if mode & 0x2 > 0 && !ch.addpath_tx() {
                                    log::warn!(
                                        "add-path send configured for {:?} but not negotiated with peer {}",
                                        family,
                                        self.remote_addr
                                    );
                                }
                            }
                            None => {
                                log::warn!(
                                    "add-path configured for {:?} but family not negotiated with peer {}",
                                    family,
                                    self.remote_addr
                                );
                            }
                        }
                    }
                    self.framer.inner_mut().channel = channels;
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
                    self.shutdown = Some(reason);
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
                    self.shutdown = Some(crate::fsm::SessionDownReason::FsmError);
                }
                crate::fsm::PeerFsmOutput::StopActiveConnect => {
                    effects.push(GlobalEffect::StopActiveConnect);
                }
            }
        }
        effects
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
                                .drop_stale_families(self.remote_addr, &delete_families)
                                .await;
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
                            .drop_stale_families(self.remote_addr, &delete_families)
                            .await;
                    }
                }
            }
        }
    }

    // Returns false if a write error occurred; the caller must route
    // Input::Disconnected through the FSM in that case.
    async fn flush_tx(&mut self, stream: &mut TcpStream) -> bool {
        // 1. Flush urgent (open, keepalive, notification) messages.
        let mut txbuf = bytes::BytesMut::with_capacity(self.txbuf_size);
        for _ in 0..self.urgent.len() {
            let msg = self.urgent.remove(0);
            let _ = self.framer.encode_to(&msg, &mut txbuf);
            (*self.counter_tx).sync(&msg);

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
            // IPv4-unicast can carry reachability either in the UPDATE's
            // traditional NLRI section or via MP_REACH_NLRI (when RFC 8950
            // Extended Nexthop is negotiated). Every other family must use
            // MP_REACH_NLRI.
            let use_mp = *family != packet::Family::IPV4
                || self
                    .framer
                    .inner()
                    .channel
                    .get(family)
                    .is_some_and(|c| c.extended_nexthop());
            for msg in p.drain_messages(*family, use_mp) {
                let _ = self.framer.encode_to(&msg, &mut txbuf);
                self.counter_tx.sync(&msg);

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
        reach: Option<packet::NlriSet>,
        unreach: Option<packet::NlriSet>,
        attr: Arc<Vec<packet::Attribute>>,
        nexthop: Option<bgp::Nexthop>,
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
        if let Some(s) = reach {
            let family = s.family;
            let source = self.source[&family].clone();
            let prefix_limit = self
                .prefix_counters
                .get(&family)
                .map(|(max, counter)| (*max, Arc::clone(counter)));
            for net in s.entries {
                if self
                    .tables
                    .insert_route(
                        source.clone(),
                        family,
                        net,
                        nexthop,
                        attr.clone(),
                        prefix_limit.clone(),
                        timestamp,
                    )
                    .await
                {
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
                self.tables
                    .remove_route(
                        source.clone(),
                        family,
                        net,
                        prefix_counter.clone(),
                        timestamp,
                    )
                    .await;
            }
        }
        false
    }

    fn handle_prefix_update(&mut self, update: table::NlriChange) {
        if self.conn_arbiter.lock().unwrap().state(self.role) != SessionState::Established {
            return;
        }
        if !self.framer.inner().channel.contains_key(&update.family) {
            return;
        }
        let effective_max = self
            .conn_arbiter
            .lock()
            .unwrap()
            .connection(self.role)
            .and_then(|s| s.send_max().get(&update.family))
            .copied()
            .unwrap_or(1);
        let Some(pending) = self.pending.get_mut(&update.family) else {
            return;
        };
        let export_policy = self.tables.export_policy.load_full();
        process_nlri_change(
            &update,
            effective_max,
            self.remote_addr,
            &mut self.export_map,
            pending,
            &self.export_ctx,
            export_policy.as_deref(),
            self.cluster_id,
        );
    }

    async fn rx_msg(
        &mut self,
        global: &GlobalHandle,
        local_sockaddr: SocketAddr,
        remote_sockaddr: SocketAddr,
        msg: bgp::Message,
    ) -> std::result::Result<(), Error> {
        // Extract UPDATE fields before passing to FSM (FSM doesn't process routes).
        let update_fields = if let bgp::Message::Update(ref u) = msg {
            Some((
                u.reach.clone(),
                u.mp_reach.clone(),
                u.attr.clone(),
                u.unreach.clone(),
                u.mp_unreach.clone(),
                u.nexthop,
            ))
        } else {
            None
        };

        let outputs = self
            .conn_arbiter
            .lock()
            .unwrap()
            .process(self.role, crate::fsm::Input::MessageReceived(msg));
        let has_session_down = outputs.iter().any(|o| {
            matches!(
                o,
                crate::fsm::PeerFsmOutput::Connection(_, crate::fsm::Output::SessionDown(_))
            )
        });
        let effects = self
            .apply_outputs(outputs, local_sockaddr, remote_sockaddr)
            .await;
        self.process_effects(effects, global).await;

        // For UPDATE messages: if FSM didn't reject (no SessionDown), process routes.
        if let Some((reach, mp_reach, attr, unreach, mp_unreach, nexthop)) = update_fields {
            if has_session_down {
                return Err(Error::Packet(
                    rustybgp_packet::BgpError::FsmUnexpectedState {
                        state: u8::from(self.conn_arbiter.lock().unwrap().state(self.role)),
                    }
                    .into(),
                ));
            }
            let rx_timestamp = std::time::SystemTime::now();
            let prefix_limit_exceeded = self
                .rx_update(reach.clone(), unreach, attr.clone(), nexthop, rx_timestamp)
                .await
                || self
                    .rx_update(mp_reach, mp_unreach.clone(), attr, nexthop, rx_timestamp)
                    .await;
            if prefix_limit_exceeded {
                let cease = bgp::Message::Notification(rustybgp_packet::BgpError::Other {
                    code: 6,
                    subcode: 1,
                    data: vec![],
                });
                self.urgent.insert(0, cease.clone());
                self.shutdown = Some(crate::fsm::SessionDownReason::LocalNotification(cease));
                return Ok(());
            }

            // Detect End-of-RIB: empty NlriSet with no attributes.
            // IPv4 EOR: reach has empty entries; other families: mp_unreach has empty entries.
            if self.negotiated_gr.is_some() {
                let mut eor_effects = Vec::new();
                if let Some(r) = &reach
                    && r.entries.is_empty()
                {
                    eor_effects.push(GlobalEffect::GrEorReceived { family: r.family });
                }
                if let Some(u) = &mp_unreach
                    && u.entries.is_empty()
                {
                    eor_effects.push(GlobalEffect::GrEorReceived { family: u.family });
                }
                if !eor_effects.is_empty() {
                    self.process_effects(eor_effects, global).await;
                }
            }
        }
        Ok(())
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
        let rxbuf_size = 1 << 16;

        // Kick off the OPEN exchange via the FSM.
        let outputs = self
            .conn_arbiter
            .lock()
            .unwrap()
            .process(self.role, crate::fsm::Input::Connected(self.is_restarting));
        let effects = self
            .apply_outputs(outputs, local_sockaddr, remote_sockaddr)
            .await;
        self.process_effects(effects, global).await;

        let mut close_rx: futures::future::OptionFuture<_> =
            self.close_rx.take().map(|rx| rx.fuse()).into();
        let mut rxbuf = bytes::BytesMut::with_capacity(rxbuf_size);
        while self.shutdown.is_none() {
            let mut peer_event_next: futures::future::OptionFuture<_> = self
                .peer_event_rx
                .as_mut()
                .map(|rx| rx.next().fuse())
                .into();

            let interest = if self.urgent.is_empty() {
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
                cease = &mut close_rx => {
                    match cease {
                        Some(Ok(CloseReason::AdminShutdown)) => {
                            let outputs = self.conn_arbiter.lock().unwrap().process(self.role, crate::fsm::Input::AdminShutdown);
                            let effects = self.apply_outputs(outputs, local_sockaddr, remote_sockaddr).await;
                            self.process_effects(effects, global).await;
                        }
                        Some(Ok(CloseReason::SendMessage(msg))) => {
                            // Bypass FSM: NOTIFICATION content is pre-determined by
                            // the caller (collision subcode 7, peer delete subcode 3);
                            // Input::AdminShutdown would overwrite it with subcode 2.
                            self.urgent.insert(0, msg);
                            self.shutdown = Some(crate::fsm::SessionDownReason::AdminShutdown);
                        }
                        Some(Ok(CloseReason::Silent)) => {
                            // Close TCP without sending a NOTIFICATION so the remote
                            // peer treats this as a GR restart event.
                            self.shutdown = Some(crate::fsm::SessionDownReason::AdminShutdown);
                        }
                        _ => {}
                    }
                }
                _ = self.holdtime_futures.next() => {
                    log::warn!("{}: holdtime expired", self.remote_addr);
                    let outputs = self.conn_arbiter.lock().unwrap().process(self.role, crate::fsm::Input::HoldTimerExpired);
                    let effects = self.apply_outputs(outputs, local_sockaddr, remote_sockaddr).await;
                    self.process_effects(effects, global).await;
                }
                _ = self.keepalive_futures.next() => {
                    let outputs = self.conn_arbiter.lock().unwrap().process(self.role, crate::fsm::Input::KeepaliveTimerExpired);
                    let effects = self.apply_outputs(outputs, local_sockaddr, remote_sockaddr).await;
                    self.process_effects(effects, global).await;
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
                        Err(_) => continue,
                    };

                    if ready.is_readable() {
                        rxbuf.reserve(rxbuf_size);
                        match stream.try_read_buf(&mut rxbuf) {
                            Ok(0) => {
                                let outputs = self.conn_arbiter.lock().unwrap().process(
                                    self.role,
                                    crate::fsm::Input::Disconnected,
                                );
                                let effects = self.apply_outputs(outputs, local_sockaddr, remote_sockaddr).await;
                                self.process_effects(effects, global).await;
                            }
                            Ok(_) => loop {
                                    match self.framer.try_parse(&mut rxbuf) {
                                    Ok(msg) => match msg {
                                        Some(msg) => {
                                            (*self.counter_rx).sync(&msg);
                                            let _ = self.rx_msg(global, local_sockaddr, remote_sockaddr, msg).await;
                                        }
                                        None => {
                                            // partial read
                                            break;
                                        },
                                    }
                                    Err(e) => {
                                        // Bypass FSM: BgpError already encodes the
                                        // correct NOTIFICATION; the FSM has no
                                        // decision to make here.
                                        if let rustybgp_packet::Error::Bgp(ref bgp_err) = e {
                                            self.urgent.insert(0, bgp::Message::Notification(bgp_err.clone()));
                                            self.shutdown = Some(crate::fsm::SessionDownReason::LocalNotification(bgp::Message::Notification(bgp_err.clone())));
                                        } else {
                                            self.shutdown = Some(crate::fsm::SessionDownReason::FsmError);
                                        }
                                        break;
                                    },
                                }
                            }
                            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {},
                            Err(_e) => {
                                let outputs = self.conn_arbiter.lock().unwrap().process(
                                    self.role,
                                    crate::fsm::Input::Disconnected,
                                );
                                let effects = self.apply_outputs(outputs, local_sockaddr, remote_sockaddr).await;
                                self.process_effects(effects, global).await;
                            }
                        }
                    }

                    if ready.is_writable()
                        && !self.flush_tx(&mut stream).await
                    {
                        let outputs = self.conn_arbiter.lock().unwrap().process(
                            self.role,
                            crate::fsm::Input::Disconnected,
                        );
                        let effects = self.apply_outputs(outputs, local_sockaddr, remote_sockaddr).await;
                        self.process_effects(effects, global).await;
                    }
                }
            }

            // Hold timer setup is now handled by apply_outputs (SetHoldTimer).
        }
        // Capture shutdown reason before the shard loop consumes it.
        // Used below to decide whether N-bit GR applies to this disconnect.
        let shutdown_reason = self.shutdown.clone();

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
            let bmp_reason = crate::bmp::session_down_to_bmp(self.shutdown.take());
            self.peer_event_rx = None;
            self.tables
                .unregister_peer(self.remote_addr, &drop_families, &stale_families)
                .await;
            self.tables
                .peer_down(PeerDownData {
                    peer_addr: any_source.remote_addr,
                    peer_asn: any_source.remote_asn,
                    peer_id: any_source.router_id,
                    uptime: self.state.peer_up_at.load(Ordering::Relaxed),
                    reason: bmp_reason,
                })
                .await;
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
#[allow(clippy::too_many_arguments)]
fn process_nlri_change(
    update: &table::NlriChange,
    effective_max: usize,
    remote_addr: IpAddr,
    export_map: &mut ExportMap,
    pending: &mut crate::peer_tx::PendingTx,
    export_ctx: &PeerExportContext,
    export_policy: Option<&table::PolicyAssignment>,
    cluster_id: Option<Ipv4Addr>,
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
                table::Table::apply_policy(
                    policy,
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
            Some((attr, nexthop))
        });
        match policy_result {
            None => {
                if export_map.was_sent(update.family, &update.net) {
                    export_map.mark_withdrawn(update.family, &update.net, 0);
                    pending.unreach(update.net, 0);
                }
            }
            Some((attr, nexthop)) => {
                export_map.mark_sent(update.family, update.net, 0);
                let attr = export_ctx.export_attrs(&attr);
                let nexthop = export_ctx.export_nexthop(nexthop);
                pending.reach(update.net, 0, nexthop, attr);
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
        let current_top_n: Vec<(u32, Arc<Vec<packet::Attribute>>, Option<bgp::Nexthop>)> = update
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
                    table::Table::apply_policy(
                        policy,
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
                Some((path.local_path_id, attr, nexthop))
            })
            .collect();

        // Withdraw paths that were sent but are no longer in top-N
        // (including paths pushed out by send_max boundary or policy).
        let sent_ids = export_map.sent_path_ids(update.family, &update.net);
        let current_ids: FnvHashSet<u32> = current_top_n.iter().map(|(pid, _, _)| *pid).collect();
        for &pid in sent_ids.difference(&current_ids) {
            export_map.mark_withdrawn(update.family, &update.net, pid);
            pending.unreach(update.net, pid);
        }

        // Advertise paths that are new or whose attributes were replaced.
        for (pid, attr, nexthop) in &current_top_n {
            let already_sent = export_map.contains_path(update.family, &update.net, *pid);
            let was_replaced = update.replaced_path_id == Some(*pid);
            if !already_sent || was_replaced {
                export_map.mark_sent(update.family, update.net, *pid);
                let attr = export_ctx.export_attrs(attr);
                let nexthop = export_ctx.export_nexthop(*nexthop);
                pending.reach(update.net, *pid, nexthop, attr);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn make_global() -> GlobalHandle {
        let mut g = Global::new();
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
        let mut g = Global::new();
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
        let mut g = Global::new();
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
        let mut g = Global::new();
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
                        ..Default::default()
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
        bgp::Message::Notification(packet::BgpError::Other {
            code: 6,    // Cease
            subcode: 7, // Connection Collision Resolution
            data: vec![],
        })
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
                capability: vec![],
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
                false,
                false,
            )),
        );
        conn
    }

    /// Prepare a PeerSession for tests: open the IPv4 channel
    /// and insert an IPv4 pending bucket, matching what on_established would do.
    fn setup_ipv4_session(conn: &mut PeerSession) {
        conn.framer
            .inner_mut()
            .channel
            .insert(Family::IPV4, bgp::Channel::new(Family::IPV4, false, false));
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
            false,
            false,
        ))
    }

    // ---- handle_prefix_update tests ----

    fn make_prefix_update_reach(
        nlri: packet::Nlri,
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
            net: nlri,
            best_changed: true,
            any_changed: true,
            replaced_path_id: None,
            current_paths: Arc::new(vec![best]),
        }
    }

    fn make_prefix_update_withdraw(nlri: packet::Nlri) -> table::NlriChange {
        table::NlriChange {
            family: Family::IPV4,
            net: nlri,
            best_changed: true,
            any_changed: true,
            replaced_path_id: None,
            current_paths: Arc::new(vec![]),
        }
    }

    fn make_prefix_update_no_change(
        nlri: packet::Nlri,
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
            net: nlri,
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
        let update = make_prefix_update_reach(nlri, other_source());

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
        let update = make_prefix_update_no_change(nlri, other_source());

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
        conn.export_map.mark_sent(Family::IPV4, nlri, 0);

        let update = make_prefix_update_withdraw(nlri);
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
        let update = make_prefix_update_withdraw(nlri);
        conn.handle_prefix_update(update);

        assert!(!conn.export_map.was_sent(Family::IPV4, &nlri));
        assert!(conn.pending[&Family::IPV4].is_empty());
    }

    /// `apply_outputs` places any `SendMessage` output into `rs.urgent`.
    /// Cross-role CEASE delivery is now handled atomically by `ConnArbiter::process`
    /// before outputs reach `apply_outputs`, so `apply_outputs` just queues them.
    #[tokio::test]
    async fn apply_outputs_send_message_goes_to_urgent() {
        let global = make_global();
        let tables = make_tables();
        let (client, server) = loopback_pair().await;
        let remote_addr = client.local_addr().unwrap().ip();

        let mut conn = passive_connection(&global, &tables, remote_addr, server).await;

        let outputs = vec![crate::fsm::PeerFsmOutput::Connection(
            crate::fsm::Role::Passive,
            crate::fsm::Output::SendMessage(cease_notification()),
        )];
        let dummy: SocketAddr = "127.0.0.1:179".parse().unwrap();
        let effects = conn.apply_outputs(outputs, dummy, dummy).await;

        // No GlobalEffect::SendCease — CEASE goes into conn.urgent directly.
        assert!(effects.is_empty());
        assert_eq!(conn.urgent.len(), 1);
        assert!(matches!(conn.urgent[0], bgp::Message::Notification(_)));
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
            capability: vec![],
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
        m.mark_sent(Family::IPV4, nlri, 0);
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
        m.mark_sent(Family::IPV4, nlri, 0);
        assert!(m.was_sent(Family::IPV4, &nlri));
        m.mark_withdrawn(Family::IPV4, &nlri, 0);
        assert!(!m.was_sent(Family::IPV4, &nlri));
    }

    #[test]
    fn export_map_multiple_families_independent() {
        let v4: packet::Nlri = "10.0.0.0/8".parse().unwrap();
        let v6: packet::Nlri = "2001:db8::/32".parse().unwrap();
        let mut m = ExportMap::new();
        m.mark_sent(Family::IPV4, v4, 0);
        assert!(m.was_sent(Family::IPV4, &v4));
        assert!(!m.was_sent(Family::IPV6, &v4));
        m.mark_sent(Family::IPV6, v6, 0);
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
        let families = vec![Family::IPV4, Family::IPV6];
        let result = families_to_drop_on_disconnect(families.iter(), None);
        assert_eq!(result.len(), 2);
        assert!(result.contains(&Family::IPV4));
        assert!(result.contains(&Family::IPV6));
    }

    #[test]
    fn drop_on_disconnect_gr_for_all_drops_nothing() {
        let families = vec![Family::IPV4, Family::IPV6];
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
        let families = vec![Family::IPV4, Family::IPV6];
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
            false,
            false,
        ));
        let ipv4_net: packet::Nlri = "10.1.0.0/24".parse().unwrap();
        let ipv6_net: packet::Nlri = "2001:db8::/32".parse().unwrap();
        let attrs = Arc::new(Vec::new());
        let nh4 = packet::bgp::Nexthop::V4(Ipv4Addr::new(10, 0, 0, 2));
        let nh6 =
            packet::bgp::Nexthop::V6(std::net::Ipv6Addr::new(0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1));

        // Insert one IPv4 route and one IPv6 route for the peer.
        {
            let mut t = tables.shards[0].lock().await;
            let _ = t.rtable.insert(
                source.clone(),
                Family::IPV4,
                ipv4_net,
                0,
                Some(nh4),
                attrs.clone(),
                None,
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
        let session_families = vec![Family::IPV4, Family::IPV6];
        let drop_families =
            families_to_drop_on_disconnect(session_families.iter(), Some(&negotiated_gr));
        tables.drop_families(remote_addr, &drop_families).await;

        let t = tables.shards[0].lock().await;
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
            false,
            false,
        ));
        let ipv4_net: packet::Nlri = "10.2.0.0/24".parse().unwrap();
        let attrs = Arc::new(Vec::new());
        let nh4 = packet::bgp::Nexthop::V4(Ipv4Addr::new(10, 0, 0, 3));

        {
            let mut t = tables.shards[0].lock().await;
            t.rtable.insert(
                source,
                Family::IPV4,
                ipv4_net,
                0,
                Some(nh4),
                attrs,
                None,
                false,
                None,
                std::time::SystemTime::UNIX_EPOCH,
            );
        }
        assert_eq!(
            tables.shards[0]
                .lock()
                .await
                .rtable
                .collect_loc_rib_paths(&Family::IPV4)
                .len(),
            1
        );

        // No GR: all families dropped.
        let session_families = vec![Family::IPV4];
        let drop_families = families_to_drop_on_disconnect(session_families.iter(), None);
        tables.drop_families(remote_addr, &drop_families).await;

        assert!(
            tables.shards[0]
                .lock()
                .await
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
            rustybgp_packet::error::BgpError::Other {
                code: 6,
                subcode,
                data: vec![],
            },
        ))
    }

    fn local_cease(subcode: u8) -> crate::fsm::SessionDownReason {
        crate::fsm::SessionDownReason::LocalNotification(bgp::Message::Notification(
            rustybgp_packet::error::BgpError::Other {
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
        assert!(gr_on_disconnect(&Some(cease(9)), make_negotiated_gr(false)).is_none());
        assert!(gr_on_disconnect(&Some(cease(9)), make_negotiated_gr(true)).is_none());
    }

    #[test]
    fn gr_on_disconnect_local_notification_requires_n_bit() {
        assert!(gr_on_disconnect(&Some(local_cease(0)), make_negotiated_gr(false)).is_none());
        assert!(gr_on_disconnect(&Some(local_cease(0)), make_negotiated_gr(true)).is_some());
    }

    #[test]
    fn gr_on_disconnect_local_hard_reset_never_applies() {
        assert!(gr_on_disconnect(&Some(local_cease(9)), make_negotiated_gr(true)).is_none());
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
                false,
                false,
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
            nlri: packet::Nlri,
            best_changed: bool,
            any_changed: bool,
            replaced_path_id: Option<u32>,
            paths: Vec<table::Path>,
        ) -> table::NlriChange {
            table::NlriChange {
                family: Family::IPV4,
                net: nlri,
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
                if let bgp::Message::Update(u) = msg {
                    for e in u
                        .reach
                        .iter()
                        .chain(u.mp_reach.iter())
                        .flat_map(|s| &s.entries)
                    {
                        out.push((e.nlri, e.path_id));
                    }
                }
            }
            out
        }

        /// Extract (nlri, path_id) pairs from unreach entries in UPDATE messages.
        fn unreach_entries(msgs: &[bgp::Message]) -> Vec<(packet::Nlri, u32)> {
            let mut out = Vec::new();
            for msg in msgs {
                if let bgp::Message::Update(u) = msg {
                    for e in u
                        .unreach
                        .iter()
                        .chain(u.mp_unreach.iter())
                        .flat_map(|s| &s.entries)
                    {
                        out.push((e.nlri, e.path_id));
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
            let update = change(net, false, false, None, vec![]);

            process_nlri_change(
                &update,
                1,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ebgp_ctx(),
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
            let update = change(net, true, true, None, vec![path]);

            process_nlri_change(
                &update,
                1,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ebgp_ctx(),
                None,
                None,
            );

            assert!(em.was_sent(Family::IPV4, &net));
            assert!(em.contains_path(Family::IPV4, &net, 0)); // non-addpath uses path_id=0
            let msgs = pending.drain_messages(Family::IPV4, false);
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
            let update = change(net, true, true, None, vec![]);

            process_nlri_change(
                &update,
                1,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ebgp_ctx(),
                None,
                None,
            );

            assert!(!em.was_sent(Family::IPV4, &net));
            let msgs = pending.drain_messages(Family::IPV4, false);
            let unreach = unreach_entries(&msgs);
            assert_eq!(unreach.len(), 1);
            assert_eq!(unreach[0].0, net);
        }

        #[test]
        fn spurious_withdraw_suppressed() {
            let mut em = ExportMap::new();
            let mut pending = crate::peer_tx::PendingTx::new(false);
            let net = nlri("10.0.0.0/24");
            let update = change(net, true, true, None, vec![]);

            process_nlri_change(
                &update,
                1,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ebgp_ctx(),
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
            let update = change(net, true, true, None, vec![path]);

            process_nlri_change(
                &update,
                1,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ebgp_ctx(),
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
                &change(net, true, true, None, vec![path]),
                1,
                remote,
                &mut em,
                &mut pending,
                &ebgp_ctx(),
                None,
                None,
            );
            assert!(em.was_sent(Family::IPV4, &net));
            pending.drain_messages(Family::IPV4, false); // flush

            // 2. Withdraw
            process_nlri_change(
                &change(net, true, true, None, vec![]),
                1,
                remote,
                &mut em,
                &mut pending,
                &ebgp_ctx(),
                None,
                None,
            );
            assert!(!em.was_sent(Family::IPV4, &net));
            let msgs = pending.drain_messages(Family::IPV4, false);
            assert_eq!(unreach_entries(&msgs).len(), 1);
        }

        // ---- Add-Path (effective_max=2) ----

        #[test]
        fn noop_when_any_unchanged() {
            let mut em = ExportMap::new();
            let mut pending = crate::peer_tx::PendingTx::new(true);
            let net = nlri("10.0.0.0/24");
            let path = path(1, source(PEER));
            let update = change(net, false, false, None, vec![path]);

            process_nlri_change(
                &update,
                2,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ebgp_ctx(),
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
            let update = change(net, true, true, None, paths);

            process_nlri_change(
                &update,
                2,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ebgp_ctx(),
                None,
                None,
            );

            assert!(em.contains_path(Family::IPV4, &net, 1));
            assert!(em.contains_path(Family::IPV4, &net, 2));
            let msgs = pending.drain_messages(Family::IPV4, false);
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
            em.mark_sent(Family::IPV4, net, 1);
            em.mark_sent(Family::IPV4, net, 2);
            let mut pending = crate::peer_tx::PendingTx::new(true);
            let src = source(PEER);
            // path_id=2 is removed; only path_id=1 remains
            let update = change(net, true, true, None, vec![path(1, src)]);

            process_nlri_change(
                &update,
                2,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ebgp_ctx(),
                None,
                None,
            );

            assert!(em.contains_path(Family::IPV4, &net, 1));
            assert!(!em.contains_path(Family::IPV4, &net, 2));
            let msgs = pending.drain_messages(Family::IPV4, false);
            let unreach = unreach_entries(&msgs);
            assert_eq!(unreach.len(), 1);
            assert_eq!(unreach[0].1, 2);
        }

        #[test]
        fn replaced_path_readvertised() {
            let mut em = ExportMap::new();
            let net = nlri("10.0.0.0/24");
            em.mark_sent(Family::IPV4, net, 1);
            em.mark_sent(Family::IPV4, net, 2);
            let mut pending = crate::peer_tx::PendingTx::new(true);
            let src = source(PEER);
            // path_id=1 was replaced (new attributes); path_id=2 unchanged
            let paths = vec![path(1, src.clone()), path(2, src)];
            let update = change(net, false, true, Some(1), paths);

            process_nlri_change(
                &update,
                2,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ebgp_ctx(),
                None,
                None,
            );

            let msgs = pending.drain_messages(Family::IPV4, false);
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
            em.mark_sent(Family::IPV4, net, 1);
            em.mark_sent(Family::IPV4, net, 2);
            let mut pending = crate::peer_tx::PendingTx::new(true);
            let src = source(PEER);
            let paths = vec![path(3, src.clone()), path(1, src.clone()), path(2, src)];
            let update = change(net, true, true, None, paths);

            process_nlri_change(
                &update,
                2,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ebgp_ctx(),
                None,
                None,
            );

            assert!(em.contains_path(Family::IPV4, &net, 3));
            assert!(em.contains_path(Family::IPV4, &net, 1));
            assert!(!em.contains_path(Family::IPV4, &net, 2)); // pushed out
            let msgs = pending.drain_messages(Family::IPV4, false);
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
            em.mark_sent(Family::IPV4, net, 1);
            em.mark_sent(Family::IPV4, net, 2);
            let mut pending = crate::peer_tx::PendingTx::new(true);
            let src = source(PEER);
            // pid=1 was removed; remaining: pid=2, pid=3
            let paths = vec![path(2, src.clone()), path(3, src)];
            let update = change(net, true, true, None, paths);

            process_nlri_change(
                &update,
                2,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ebgp_ctx(),
                None,
                None,
            );

            assert!(!em.contains_path(Family::IPV4, &net, 1)); // withdrawn
            assert!(em.contains_path(Family::IPV4, &net, 2)); // kept
            assert!(em.contains_path(Family::IPV4, &net, 3)); // entered window
            let msgs = pending.drain_messages(Family::IPV4, false);
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
            em.mark_sent(Family::IPV4, net, 1);
            em.mark_sent(Family::IPV4, net, 2);
            let mut pending = crate::peer_tx::PendingTx::new(true);
            let update = change(net, true, true, None, vec![]);

            process_nlri_change(
                &update,
                2,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ebgp_ctx(),
                None,
                None,
            );

            assert!(!em.was_sent(Family::IPV4, &net));
            let msgs = pending.drain_messages(Family::IPV4, false);
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
            let update = change(net, true, true, None, paths);

            process_nlri_change(
                &update,
                2,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ebgp_ctx(),
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
            let update = change(net, true, true, None, paths);

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
            );

            assert!(em.contains_path(Family::IPV4, &net, 1));
            assert!(!em.contains_path(Family::IPV4, &net, 2)); // self path not sent
            assert!(em.contains_path(Family::IPV4, &net, 3));
            let msgs = pending.drain_messages(Family::IPV4, false);
            let reach_pids: Vec<u32> = reach_entries(&msgs).into_iter().map(|e| e.1).collect();
            assert_eq!(reach_pids.len(), 2);
            assert!(reach_pids.contains(&1));
            assert!(reach_pids.contains(&3));
        }
        // ---- iBGP split horizon ----

        fn ibgp_source(addr: &str) -> Arc<table::Source> {
            let ip: IpAddr = addr.parse().unwrap();
            // remote_asn == local_asn → iBGP source
            Arc::new(table::Source::new(
                ip,
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                65001,
                65001,
                Ipv4Addr::new(10, 0, 0, 1),
                false,
                false,
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
            let update = change(net, true, true, None, vec![path]);

            process_nlri_change(
                &update,
                1,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ibgp_ctx(),
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
            em.mark_sent(Family::IPV4, net, 0);
            let mut pending = crate::peer_tx::PendingTx::new(false);
            // New best is iBGP-learned
            let path = path(1, ibgp_source(PEER));
            let update = change(net, true, true, None, vec![path]);

            process_nlri_change(
                &update,
                1,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ibgp_ctx(),
                None,
                None,
            );

            // Must send a withdrawal for the previously-sent route
            assert!(!em.was_sent(Family::IPV4, &net));
            let msgs = pending.drain_messages(Family::IPV4, false);
            assert_eq!(unreach_entries(&msgs).len(), 1);
        }

        #[test]
        fn ibgp_forwards_ebgp_learned_route() {
            let mut em = ExportMap::new();
            let mut pending = crate::peer_tx::PendingTx::new(false);
            let net = nlri("10.0.0.0/24");
            // Route learned from an eBGP peer (remote_asn != local_asn)
            let path = path(1, source(PEER)); // source() uses remote_asn=65002
            let update = change(net, true, true, None, vec![path]);

            process_nlri_change(
                &update,
                1,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ibgp_ctx(),
                None,
                None,
            );

            // eBGP-learned route CAN be forwarded to iBGP peer
            assert!(em.was_sent(Family::IPV4, &net));
            let msgs = pending.drain_messages(Family::IPV4, false);
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
            let update = change(net, true, true, None, paths);

            process_nlri_change(
                &update,
                2,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ibgp_ctx(),
                None,
                None,
            );

            // Only the eBGP-learned path (pid=2) should be advertised
            assert!(!em.contains_path(Family::IPV4, &net, 1));
            assert!(em.contains_path(Family::IPV4, &net, 2));
            let msgs = pending.drain_messages(Family::IPV4, false);
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
            // iBGP should return the same Arc (no cloning/modification)
            assert!(
                Arc::ptr_eq(&exported, &original),
                "iBGP export_attrs should return attrs unchanged"
            );
        }

        #[test]
        fn ebgp_export_rewrites_nexthop() {
            let ctx = ebgp_ctx(); // local_addr = 127.0.0.1
            let original = bgp::Nexthop::V4(Ipv4Addr::new(10, 0, 0, 1));
            let exported = ctx.export_nexthop(Some(original));
            assert_eq!(
                exported,
                bgp::Nexthop::V4(Ipv4Addr::new(127, 0, 0, 1)),
                "eBGP nexthop must be rewritten to local_addr"
            );
        }

        #[test]
        fn ibgp_export_keeps_nexthop() {
            let ctx = ibgp_ctx();
            let original = bgp::Nexthop::V4(Ipv4Addr::new(10, 0, 0, 1));
            let exported = ctx.export_nexthop(Some(original));
            assert_eq!(exported, original, "iBGP nexthop must be unchanged");
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
                !buf.windows(1)
                    .enumerate()
                    .step_by(1)
                    .any(|(i, _)| i % 1 == 0
                        && (buf[i] == packet::Attribute::AS_PATH_TYPE_CONFED_SEQ
                            || buf[i] == packet::Attribute::AS_PATH_TYPE_CONFED_SET)),
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
                bgp::Nexthop::V4(Ipv4Addr::new(127, 0, 0, 1)),
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
                false,
                true, // rr_client = true
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
            let update = change(net, true, true, None, vec![p]);

            process_nlri_change(
                &update,
                1,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ibgp_ctx(),
                None,
                Some(CLUSTER_ID),
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
            let update = change(net, true, true, None, vec![p]);

            process_nlri_change(
                &update,
                1,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ibgp_ctx(),
                None,
                Some(CLUSTER_ID),
            );

            assert!(em.was_sent(Family::IPV4, &net));
            assert_eq!(
                reach_entries(&pending.drain_messages(Family::IPV4, false)).len(),
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
            let update = change(net, true, true, None, vec![p]);

            process_nlri_change(
                &update,
                1,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ibgp_rr_client_ctx(),
                None,
                Some(CLUSTER_ID),
            );

            assert!(em.was_sent(Family::IPV4, &net));
            assert_eq!(
                reach_entries(&pending.drain_messages(Family::IPV4, false)).len(),
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
            let msgs = pending.drain_messages(Family::IPV4, false);
            for msg in msgs {
                if let bgp::Message::Update(u) = msg {
                    if u.reach.as_ref().is_some_and(|r| !r.entries.is_empty()) {
                        return u.attr;
                    }
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
            let update = change(net, true, true, None, vec![p]);

            process_nlri_change(
                &update,
                1,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ibgp_rr_client_ctx(),
                None,
                Some(CLUSTER_ID),
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
            let update = change(net, true, true, None, vec![p]);

            process_nlri_change(
                &update,
                1,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ibgp_rr_client_ctx(),
                None,
                Some(CLUSTER_ID),
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
            let update = change(net, true, true, None, vec![p]);

            process_nlri_change(
                &update,
                1,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ibgp_rr_client_ctx(),
                None,
                Some(CLUSTER_ID),
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
            let update = change(net, true, true, None, vec![p]);

            process_nlri_change(
                &update,
                1,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ibgp_rr_client_ctx(),
                None,
                Some(CLUSTER_ID),
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
            let update = change(net, true, true, None, vec![p]);

            process_nlri_change(
                &update,
                1,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ibgp_rr_client_ctx(),
                None,
                Some(CLUSTER_ID),
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
            let update = change(net, true, true, None, vec![p]);

            process_nlri_change(
                &update,
                1,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ibgp_rr_client_ctx(),
                None,
                Some(CLUSTER_ID),
            );

            assert!(em.was_sent(Family::IPV4, &net));
            assert_eq!(
                reach_entries(&pending.drain_messages(Family::IPV4, false)).len(),
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
                true,
                false,
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
            let update = change(net, true, true, None, vec![p]);

            process_nlri_change(
                &update,
                1,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &ebgp_ctx(),
                None,
                None,
            );

            assert!(!em.was_sent(Family::IPV4, &net));
            assert_eq!(
                reach_entries(&pending.drain_messages(Family::IPV4, false)).len(),
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
            let update = change(net, true, true, None, vec![p]);

            process_nlri_change(
                &update,
                1,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &rs_client_ctx(),
                None,
                None,
            );

            assert!(!em.was_sent(Family::IPV4, &net));
            assert_eq!(
                reach_entries(&pending.drain_messages(Family::IPV4, false)).len(),
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
            let update = change(net, true, true, None, vec![p]);

            process_nlri_change(
                &update,
                1,
                SELF.parse().unwrap(),
                &mut em,
                &mut pending,
                &rs_client_ctx(),
                None,
                None,
            );

            assert!(em.was_sent(Family::IPV4, &net));
            assert_eq!(
                reach_entries(&pending.drain_messages(Family::IPV4, false)).len(),
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
        let t = svc.tables.shards[0].lock().await;
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
            let t = svc.tables.shards[0].lock().await;
            assert_eq!(t.rtable.collect_loc_rib_paths(&Family::IPV4).len(), 1);
        }

        let del_req = tonic::Request::new(api::DeletePathRequest {
            uuid,
            ..Default::default()
        });
        svc.delete_path(del_req).await.unwrap();
        let t = svc.tables.shards[0].lock().await;
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
        let t = svc.tables.shards[0].lock().await;
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
            let t = svc.tables.shards[0].lock().await;
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
            let t = svc.tables.shards[0].lock().await;
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
        let t = svc.tables.shards[0].lock().await;
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

    // ---- rx_update: RFC 4456 loop detection ----
    //
    // new_for_test sets local_router_id = 1.0.0.1.  Loop detection fires before
    // source lookup, so no source setup is required; the absence of an inserted
    // route is verified via table_state().

    fn reach_set(prefix: &str) -> Option<packet::NlriSet> {
        Some(packet::NlriSet {
            family: Family::IPV4,
            entries: vec![packet::PathNlri::new(prefix.parse().unwrap())],
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
                None,
                std::time::SystemTime::now(),
            )
            .await;

        assert!(!exceeded, "loop detection must not trigger CEASE");
        let state = tables.table_state(Family::IPV4).await;
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
                None,
                std::time::SystemTime::now(),
            )
            .await;

        assert!(!exceeded, "loop detection must not trigger CEASE");
        let state = tables.table_state(Family::IPV4).await;
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
                None,
                std::time::SystemTime::now(),
            )
            .await;

        assert!(!exceeded, "loop detection must not trigger CEASE");
        let state = tables.table_state(Family::IPV4).await;
        assert_eq!(state.num_destination, 0, "route must not be inserted");
    }
}
