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
use fnv::{FnvHashMap, FnvHashSet, FnvHasher};
use futures::stream::FuturesUnordered;
use futures::{FutureExt, SinkExt, Stream, StreamExt};
use std::boxed::Box;
use std::collections::HashSet;
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::convert::{From, TryFrom};
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::Deref;
use std::os::fd::AsFd;
use std::os::unix::io::{AsRawFd, RawFd};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{
    AtomicBool, AtomicI64, AtomicU8, AtomicU16, AtomicU32, AtomicU64, Ordering,
};
use std::time::SystemTime;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, mpsc};
use tokio::time::{Duration, Instant};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tokio_util::codec::{Encoder, Framed};

use crate::api::go_bgp_service_server::{GoBgpService, GoBgpServiceServer};

use rustybgp_packet::{self as packet, BgpFramer, Family, HoldTime, bgp, bmp, mrt, rpki};

use crate::api;
use crate::auth;
use crate::config;
use crate::convert;
use crate::error::Error;
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

struct PeerState {
    fsm: AtomicU8,
    uptime: AtomicU64,
    downtime: AtomicU64,
    remote_asn: AtomicU32,
    remote_id: AtomicU32,
    remote_holdtime: AtomicU16,
    remote_cap: ArcSwapOption<Vec<packet::Capability>>,
}

/// Wraps a oneshot Sender so that `Peer` can derive `Clone`.
/// Cloning produces `None` — the clone is for read-only listing, not signalling.
#[derive(Default)]
struct CloseTx(Option<tokio::sync::oneshot::Sender<bgp::Message>>);

/// Cancellation handle for the active-connect retry task.
/// Cloning produces `None`; dropping the inner `Sender` signals the task to exit.
#[derive(Default)]
struct ActiveConnectCancel(Option<tokio::sync::oneshot::Sender<()>>);

/// GR helper configuration for a single peer.
/// `None` in `PeerConfig::graceful_restart` means GR is disabled.
#[derive(Clone)]
#[allow(dead_code)]
struct GrPeerConfig {
    /// Restart Time advertised in our OPEN (12-bit, max 4095 s).
    restart_time: u16,
    /// Local Selection Deferral Timer: how long to wait for EOR after
    /// the peer reconnects before deleting remaining stale routes.
    deferral_time: std::time::Duration,
    /// Families included in the GR capability (non-empty by construction).
    families: Vec<Family>,
}

#[derive(Clone)]
struct PeerConfig {
    remote_addr: IpAddr,
    remote_port: u16,
    /// Expected AS number from configuration; 0 means "accept any".
    /// The actual negotiated ASN lives in PeerState.remote_asn (session-scoped).
    remote_asn: u32,
    local_asn: u32,
    passive: bool,
    delete_on_disconnected: bool,
    holdtime: u64,
    connect_retry_time: u64,
    local_cap: Vec<packet::Capability>,
    route_server_client: bool,
    multihop_ttl: Option<u8>,
    password: Option<String>,
    /// Per-family send_max for Add-Path TX (RFC 7911).
    send_max: FnvHashMap<Family, usize>,
    /// Per-family prefix limits from config.
    prefix_limits: FnvHashMap<Family, u32>,
    /// GR helper config; None = GR disabled.
    #[allow(dead_code)]
    graceful_restart: Option<GrPeerConfig>,
}

struct Peer {
    config: PeerConfig,
    admin_down: bool,

    remote_sockaddr: SocketAddr,
    local_sockaddr: SocketAddr,

    state: Arc<PeerState>,

    counter_tx: Arc<MessageCounter>,
    counter_rx: Arc<MessageCounter>,

    /// Shared FSM for this peer; active and passive Connections for the same peer
    /// share one instance so collision detection sees both sessions.
    ///
    /// `Option` because `PeerFsm::new` requires `local_router_id`, which is
    /// only known in `Global` but not at `Peer` construction time
    /// (`PeerBuilder::build`). It is always `Some` after `Global::add_peer`.
    peer_fsm: Option<Arc<std::sync::Mutex<crate::fsm::PeerFsm>>>,
    /// Cancels the active-connect retry loop spawned by `enable_active_connect`.
    /// Dropping the inner sender signals the task to exit.
    active_connect_cancel_tx: ActiveConnectCancel,
    /// One-shot channels used by the collision winner to deliver a CEASE
    /// Notification to the losing Connection. Each is consumed at most once.
    active_close_tx: CloseTx,
    passive_close_tx: CloseTx,
    export_map: ExportMap,
}

/// Read-only view of a peer for gRPC list responses.
/// Holds clones of the config and cheap Arc references to live session state.
struct PeerView {
    config: PeerConfig,
    admin_down: bool,
    local_sockaddr: SocketAddr,
    state: Arc<PeerState>,
    counter_tx: Arc<MessageCounter>,
    counter_rx: Arc<MessageCounter>,
    route_stats: FnvHashMap<Family, (u64, u64)>,
}

impl PeerView {
    fn update_stats(&mut self, rti: FnvHashMap<Family, (u64, u64)>) {
        for (f, v) in rti {
            let stats = self.route_stats.entry(f).or_insert((0, 0));
            stats.0 += v.0;
            stats.1 += v.1;
        }
    }
}

impl Peer {
    fn view(&self) -> PeerView {
        PeerView {
            config: self.config.clone(),
            admin_down: self.admin_down,
            local_sockaddr: self.local_sockaddr,
            state: Arc::clone(&self.state),
            counter_tx: Arc::clone(&self.counter_tx),
            counter_rx: Arc::clone(&self.counter_rx),
            route_stats: FnvHashMap::default(),
        }
    }

    fn reset(&mut self) {
        self.state.downtime.store(
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
        self.active_connect_cancel_tx = ActiveConnectCancel::default();
        self.active_close_tx = CloseTx::default();
        self.passive_close_tx = CloseTx::default();
    }
}

struct PeerBuilder {
    remote_addr: IpAddr,
    remote_port: u16,
    remote_asn: u32,
    remote_sockaddr: SocketAddr,
    local_sockaddr: SocketAddr,
    local_asn: u32,
    local_cap: Vec<packet::Capability>,
    passive: bool,
    rs_client: bool,
    delete_on_disconnected: bool,
    admin_down: bool,
    state: SessionState,
    holdtime: u64,
    connect_retry_time: u64,
    multihop_ttl: Option<u8>,
    password: Option<String>,
    families: FnvHashMap<Family, u8>,
    send_max: FnvHashMap<Family, usize>,
    prefix_limits: FnvHashMap<Family, u32>,
    graceful_restart: Option<GrPeerConfig>,
}

impl PeerBuilder {
    const DEFAULT_HOLD_TIME: u64 = 180;
    const DEFAULT_CONNECT_RETRY_TIME: u64 = 3;

    fn new(remote_addr: IpAddr) -> Self {
        PeerBuilder {
            remote_addr,
            remote_asn: 0,
            remote_port: Global::BGP_PORT,
            remote_sockaddr: SocketAddr::new(IpAddr::V4(Ipv4Addr::from(0)), 0),
            local_sockaddr: SocketAddr::new(IpAddr::V4(Ipv4Addr::from(0)), 0),
            local_asn: 0,
            local_cap: Vec::new(),
            passive: false,
            rs_client: false,
            delete_on_disconnected: false,
            admin_down: false,
            state: SessionState::Idle,
            holdtime: Self::DEFAULT_HOLD_TIME,
            connect_retry_time: Self::DEFAULT_CONNECT_RETRY_TIME,
            multihop_ttl: None,
            password: None,
            families: Default::default(),
            send_max: Default::default(),
            prefix_limits: Default::default(),
            graceful_restart: None,
        }
    }

    fn families(&mut self, families: Vec<Family>) -> &mut Self {
        for f in families {
            self.families.insert(f, 0);
        }
        self
    }

    fn remote_port(&mut self, remote_port: u16) -> &mut Self {
        self.remote_port = remote_port;
        self
    }

    fn remote_asn(&mut self, remote_asn: u32) -> &mut Self {
        self.remote_asn = remote_asn;
        self
    }

    fn remote_sockaddr(&mut self, sockaddr: SocketAddr) -> &mut Self {
        self.remote_sockaddr = sockaddr;
        self
    }

    fn local_sockaddr(&mut self, sockaddr: SocketAddr) -> &mut Self {
        self.local_sockaddr = sockaddr;
        self
    }

    fn local_asn(&mut self, local_asn: u32) -> &mut Self {
        self.local_asn = local_asn;
        self
    }

    fn passive(&mut self, passive: bool) -> &mut Self {
        self.passive = passive;
        self
    }

    fn rs_client(&mut self, rs: bool) -> &mut Self {
        self.rs_client = rs;
        self
    }

    fn delete_on_disconnected(&mut self, delete: bool) -> &mut Self {
        self.delete_on_disconnected = delete;
        self
    }

    fn state(&mut self, state: SessionState) -> &mut Self {
        self.state = state;
        self
    }

    fn holdtime(&mut self, t: u64) -> &mut Self {
        if t != 0 {
            self.holdtime = t;
        }
        self
    }

    fn connect_retry_time(&mut self, t: u64) -> &mut Self {
        if t != 0 {
            self.connect_retry_time = t;
        }
        self
    }

    fn admin_down(&mut self, b: bool) -> &mut Self {
        self.admin_down = b;
        self
    }

    fn password(&mut self, password: &str) -> &mut Self {
        self.password = Some(password.to_string());
        self
    }

    fn multihop_ttl(&mut self, ttl: u8) -> &mut Self {
        if ttl == 0 {
            self.multihop_ttl = None;
        } else {
            self.multihop_ttl = Some(ttl);
        }
        self
    }

    fn graceful_restart(&mut self, gr: Option<GrPeerConfig>) -> &mut Self {
        self.graceful_restart = gr;
        self
    }

    fn addpath(&mut self, families: Vec<(packet::Family, u8, usize)>) -> &mut Self {
        for (f, mode, sm) in families {
            // RFC 7911 mode is 2 bits: bit 0 = receive, bit 1 = send
            self.families.insert(f, mode & 0x3);
            if sm > 0 {
                self.send_max.insert(f, sm);
            }
        }
        self
    }

    fn build(&mut self) -> Peer {
        if self.families.is_empty() {
            self.local_cap.push(match self.remote_addr {
                IpAddr::V4(_) => packet::Capability::MultiProtocol(Family::IPV4),
                IpAddr::V6(_) => packet::Capability::MultiProtocol(Family::IPV6),
            });
        } else {
            let mut addpath = Vec::new();
            for (f, mode) in &self.families {
                if *mode > 0 {
                    addpath.push((*f, *mode));
                }
                self.local_cap.push(packet::Capability::MultiProtocol(*f));
            }
            if !addpath.is_empty() {
                self.local_cap.push(packet::Capability::AddPath(addpath));
            }
            // RFC 8950: advertise ExtendedNexthop when peering over IPv6
            // with IPv4 address family configured
            if matches!(self.remote_addr, IpAddr::V6(_)) {
                let enh_families: Vec<(Family, u16)> = self
                    .families
                    .keys()
                    .filter(|f| f.afi() == Family::AFI_IP)
                    .map(|f| (*f, Family::AFI_IP6))
                    .collect();
                if !enh_families.is_empty() {
                    self.local_cap
                        .push(packet::Capability::ExtendedNexthop(enh_families));
                }
            }
        }
        if let Some(gr) = &self.graceful_restart {
            self.local_cap.push(packet::Capability::GracefulRestart {
                flags: 0,
                restart_time: gr.restart_time,
                families: gr.families.iter().map(|f| (*f, 0)).collect(),
            });
        }
        Peer {
            config: PeerConfig {
                remote_addr: self.remote_addr,
                remote_port: if self.remote_port != 0 {
                    self.remote_port
                } else {
                    Global::BGP_PORT
                },
                remote_asn: self.remote_asn,
                local_asn: self.local_asn,
                passive: self.passive,
                delete_on_disconnected: self.delete_on_disconnected,
                holdtime: self.holdtime,
                connect_retry_time: self.connect_retry_time,
                local_cap: self.local_cap.split_off(0),
                route_server_client: self.rs_client,
                multihop_ttl: self.multihop_ttl.take(),
                password: self.password.take(),
                send_max: std::mem::take(&mut self.send_max),
                prefix_limits: std::mem::take(&mut self.prefix_limits),
                graceful_restart: self.graceful_restart.take(),
            },
            admin_down: self.admin_down,
            local_sockaddr: self.local_sockaddr,
            remote_sockaddr: self.remote_sockaddr,
            state: Arc::new(PeerState {
                fsm: AtomicU8::new(self.state as u8),
                uptime: AtomicU64::new(0),
                downtime: AtomicU64::new(0),
                remote_asn: AtomicU32::new(0),
                remote_id: AtomicU32::new(0),
                remote_holdtime: AtomicU16::new(0),
                remote_cap: ArcSwapOption::empty(),
            }),
            counter_tx: Default::default(),
            counter_rx: Default::default(),
            peer_fsm: None,
            active_connect_cancel_tx: ActiveConnectCancel::default(),
            active_close_tx: CloseTx::default(),
            passive_close_tx: CloseTx::default(),
            export_map: ExportMap::new(),
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
            peer_asn: p.config.remote_asn,
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
        let uptime = p.state.uptime.load(Ordering::Relaxed);
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
            let downtime = p.state.downtime.load(Ordering::Relaxed);
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
                    received: stats.0,
                    accepted: stats.1,
                    ..Default::default()
                }),
                ..Default::default()
            })
            .collect();
        api::Peer {
            state: Some(ps),
            conf: Some(Default::default()),
            timers: Some(tm),
            transport: Some(api::Transport {
                local_address: p.local_sockaddr.ip().to_string(),
                ..Default::default()
            }),
            route_reflector: Some(Default::default()),
            route_server: Some(api::RouteServer {
                route_server_client: p.config.route_server_client,
                secondary_route: false,
            }),
            afi_safis: afisafis,
            ..Default::default()
        }
    }
}

impl TryFrom<&api::Peer> for Peer {
    type Error = Error;

    fn try_from(p: &api::Peer) -> Result<Self, Self::Error> {
        let conf = p.conf.as_ref().ok_or(Error::EmptyArgument)?;
        let peer_addr = IpAddr::from_str(&conf.neighbor_address).map_err(|_| {
            Error::InvalidArgument(format!("invalid peer address: {}", conf.neighbor_address))
        })?;
        let mut builder = PeerBuilder::new(peer_addr);
        if !conf.auth_password.is_empty() {
            builder.password(&conf.auth_password);
        }
        Ok(builder
            .local_asn(conf.local_asn)
            .remote_asn(conf.peer_asn)
            .remote_port(p.transport.as_ref().map_or(0, |x| x.remote_port as u16))
            .families(
                p.afi_safis
                    .iter()
                    .filter(|x| x.config.as_ref().is_some_and(|x| x.family.is_some()))
                    .map(|x| {
                        convert::family_from_api(
                            x.config.as_ref().unwrap().family.as_ref().unwrap(),
                        )
                    })
                    .collect(),
            )
            .passive(p.transport.as_ref().is_some_and(|x| x.passive_mode))
            .rs_client(
                p.route_server
                    .as_ref()
                    .is_some_and(|x| x.route_server_client),
            )
            .holdtime(
                p.timers
                    .as_ref()
                    .map(|x| &x.config)
                    .map_or(0, |x| x.as_ref().map_or(0, |x| x.hold_time)),
            )
            .connect_retry_time(
                p.timers
                    .as_ref()
                    .map(|x| &x.config)
                    .map_or(0, |x| x.as_ref().map_or(0, |x| x.connect_retry)),
            )
            .admin_down(conf.admin_down)
            .multihop_ttl(
                p.ebgp_multihop
                    .as_ref()
                    .map_or(0, |x| if x.enabled { x.multihop_ttl as u8 } else { 0 }),
            )
            .graceful_restart({
                const DEFAULT_RESTART_TIME: u16 = 120;
                const DEFAULT_DEFERRAL_SECS: u64 = 360;

                let gr = p.graceful_restart.as_ref();
                if gr.is_some_and(|g| g.enabled) {
                    let gr_families: Vec<Family> = p
                        .afi_safis
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

                    if !gr_families.is_empty() {
                        let restart_time = gr
                            .and_then(|g| u16::try_from(g.restart_time).ok())
                            .unwrap_or(DEFAULT_RESTART_TIME);
                        let deferral_secs = gr
                            .map(|g| {
                                if g.deferral_time > 0 {
                                    g.deferral_time as u64
                                } else {
                                    g.stale_routes_time as u64
                                }
                            })
                            .filter(|&v| v > 0)
                            .unwrap_or(DEFAULT_DEFERRAL_SECS);
                        Some(GrPeerConfig {
                            restart_time,
                            deferral_time: std::time::Duration::from_secs(deferral_secs),
                            families: gr_families,
                        })
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .build())
    }
}

impl TryFrom<&config::Neighbor> for Peer {
    type Error = String;

    fn try_from(n: &config::Neighbor) -> Result<Peer, Self::Error> {
        let c = n.config.as_ref().ok_or("missing neighbor config")?;
        let afi_safis = n.afi_safis.as_deref().unwrap_or_default();

        // Collect address families and add-path configuration.
        let mut families = Vec::new();
        let addpath_families: Vec<(packet::Family, u8, usize)> = afi_safis
            .iter()
            .filter(|x| {
                let name = x.config.as_ref().and_then(|c| c.afi_safi_name.as_ref());
                let Some(f) = name else { return false };
                if let Ok(family) = convert::family_from_config(f) {
                    families.push(family);
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

        let addr = c
            .neighbor_address
            .as_ref()
            .ok_or("missing neighbor address")?;
        let peer_as = c.peer_as.ok_or("missing peer-as")?;

        let transport_config = n.transport.as_ref().and_then(|t| t.config.as_ref());
        let timer_config = n.timers.as_ref().and_then(|t| t.config.as_ref());

        let mut builder = PeerBuilder::new(*addr);
        builder
            .local_asn(c.local_as.unwrap_or(0))
            .remote_asn(peer_as)
            .remote_port(
                transport_config
                    .and_then(|t| t.remote_port)
                    .unwrap_or(Global::BGP_PORT),
            )
            .passive(
                transport_config
                    .and_then(|t| t.passive_mode)
                    .unwrap_or(false),
            )
            .rs_client(
                n.route_server
                    .as_ref()
                    .and_then(|r| r.config.as_ref())
                    .and_then(|r| r.route_server_client)
                    .unwrap_or(false),
            )
            .holdtime(
                timer_config
                    .and_then(|c| c.hold_time)
                    .map(|v| v as u64)
                    .unwrap_or(0),
            )
            .connect_retry_time(
                timer_config
                    .and_then(|c| c.connect_retry)
                    .map(|v| v as u64)
                    .unwrap_or(0),
            )
            .admin_down(c.admin_down.unwrap_or(false))
            .multihop_ttl(
                n.ebgp_multihop
                    .as_ref()
                    .and_then(|m| m.config.as_ref())
                    .and_then(|c| c.enabled.and(c.multihop_ttl))
                    .unwrap_or(0),
            );
        if let Some(password) = c.auth_password.as_ref() {
            builder.password(password);
        }

        builder.families(families);
        builder.addpath(addpath_families);

        // Build GR helper config from graceful-restart + per-family mp-graceful-restart.
        {
            const DEFAULT_RESTART_TIME: u16 = 120;
            const DEFAULT_DEFERRAL_SECS: u64 = 360;

            let gr_config = n
                .graceful_restart
                .as_ref()
                .and_then(|gr| gr.config.as_ref());
            let gr_enabled = gr_config.and_then(|c| c.enabled).unwrap_or(false);

            if gr_enabled {
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

                if !gr_families.is_empty() {
                    let restart_time = gr_config
                        .and_then(|c| c.restart_time)
                        .unwrap_or(DEFAULT_RESTART_TIME);
                    let deferral_secs = gr_config
                        .and_then(|c| c.deferral_time.map(|v| v as u64))
                        .or_else(|| {
                            gr_config
                                .and_then(|c| c.stale_routes_time)
                                .map(|v| v as u64)
                        })
                        .unwrap_or(DEFAULT_DEFERRAL_SECS);
                    builder.graceful_restart(Some(GrPeerConfig {
                        restart_time,
                        deferral_time: std::time::Duration::from_secs(deferral_secs),
                        families: gr_families,
                    }));
                }
            }
        }

        // Extract per-family prefix limits.
        for afi_safi in afi_safis {
            let prefix_max = |pl: &Option<config::generate::PrefixLimit>| -> Option<u32> {
                pl.as_ref()?.config.as_ref()?.max_prefixes
            };
            if let Some(v4) = &afi_safi.ipv4_unicast
                && let Some(max) = prefix_max(&v4.prefix_limit)
            {
                builder.prefix_limits.insert(packet::Family::IPV4, max);
            }
            if let Some(v6) = &afi_safi.ipv6_unicast
                && let Some(max) = prefix_max(&v6.prefix_limit)
            {
                builder.prefix_limits.insert(packet::Family::IPV6, max);
            }
        }

        Ok(builder.build())
    }
}

struct DynamicPeer {
    prefix: packet::IpNet,
}

struct PeerGroup {
    as_number: u32,
    dynamic_peers: Vec<DynamicPeer>,
    // passive: bool,
    route_server_client: bool,
    holdtime: Option<u64>,
}

impl From<api::PeerGroup> for PeerGroup {
    fn from(p: api::PeerGroup) -> PeerGroup {
        PeerGroup {
            as_number: p.conf.map_or(0, |c| c.peer_asn),
            dynamic_peers: Vec::new(),
            // passive: p.transport.map_or(false, |c| c.passive_mode),
            route_server_client: p.route_server.is_some_and(|c| c.route_server_client),
            holdtime: None,
        }
    }
}

struct GrpcService {
    init: Arc<tokio::sync::Notify>,
    policy_assignment_sem: tokio::sync::Semaphore,
    local_source: Arc<table::Source>,
    active_conn_tx: mpsc::UnboundedSender<TcpStream>,
    global: GlobalHandle,
    tables: TableHandle,
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
            local_source: Arc::new(table::Source::new(
                IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                0,
                0,
                Ipv4Addr::new(0, 0, 0, 0),
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                false,
            )),
            active_conn_tx,
            global,
            tables,
        }
    }

    async fn is_available(&self, need_active: bool) -> Result<(), Error> {
        let global = &self.global.read().await;
        if need_active && global.asn == 0 {
            return Err(Error::NotStarted);
        }
        Ok(())
    }

    fn local_path(&self, path: api::Path) -> Result<(usize, TableEvent), tonic::Status> {
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
            } else {
                attr.push(a);
            }
        }
        Ok((
            self.tables.dealer(net),
            TableEvent::PassUpdate(
                self.local_source.clone(),
                family,
                vec![packet::PathNlri {
                    path_id: path.identifier,
                    nlri: net,
                }],
                {
                    if attr.is_empty() {
                        None
                    } else {
                        Some(Arc::new(attr))
                    }
                },
                nexthop,
            ),
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
        global.router_id = Ipv4Addr::from_str(&g.router_id).unwrap();
        self.init.notify_one();

        Ok(tonic::Response::new(api::StartBgpResponse {}))
    }
    async fn stop_bgp(
        &self,
        _request: tonic::Request<api::StopBgpRequest>,
    ) -> Result<tonic::Response<api::StopBgpResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
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
        let peer = Peer::try_from(&request.into_inner().peer.ok_or(Error::EmptyArgument)?)?;
        let mut global = self.global.write().await;
        if let Some(password) = peer.config.password.as_ref() {
            for fd in &global.listen_sockets {
                auth::set_md5sig(*fd, &peer.config.remote_addr, password);
            }
        }
        global.add_peer(peer, Some(self.active_conn_tx.clone()))?;
        Ok(tonic::Response::new(api::AddPeerResponse {}))
    }
    async fn delete_peer(
        &self,
        request: tonic::Request<api::DeletePeerRequest>,
    ) -> Result<tonic::Response<api::DeletePeerResponse>, tonic::Status> {
        if let Ok(peer_addr) = IpAddr::from_str(&request.into_inner().address) {
            let mut global = self.global.write().await;
            if let Some(mut p) = global.peers.remove(&peer_addr) {
                let cease = bgp::Message::Notification(rustybgp_packet::BgpError::Other {
                    code: 6,
                    subcode: 3,
                    data: vec![],
                });
                for tx in [p.active_close_tx.0.take(), p.passive_close_tx.0.take()]
                    .into_iter()
                    .flatten()
                {
                    let _ = tx.send(cease.clone());
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
        let mut peers: FnvHashMap<IpAddr, PeerView> = self
            .global
            .read()
            .await
            .peers
            .iter()
            .map(|(a, p)| (*a, p.view()))
            .collect();

        for i in 0..self.tables.shards.len() {
            let t = self.tables.shards[i].lock().await;
            for (peer_addr, peer) in &mut peers {
                if let Some(m) = t.rtable.peer_stats(peer_addr) {
                    peer.update_stats(m.collect());
                }
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
        _request: tonic::Request<api::UpdatePeerRequest>,
    ) -> Result<tonic::Response<api::UpdatePeerResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }
    async fn reset_peer(
        &self,
        _request: tonic::Request<api::ResetPeerRequest>,
    ) -> Result<tonic::Response<api::ResetPeerResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }
    async fn shutdown_peer(
        &self,
        _request: tonic::Request<api::ShutdownPeerRequest>,
    ) -> Result<tonic::Response<api::ShutdownPeerResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
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
                        return Ok(tonic::Response::new(api::EnablePeerResponse {}));
                    } else {
                        return Err(tonic::Status::new(
                            tonic::Code::InvalidArgument,
                            "peer is already admin-up",
                        ));
                    }
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
                    if p.admin_down {
                        return Err(tonic::Status::new(
                            tonic::Code::InvalidArgument,
                            "peer is already admin-down",
                        ));
                    } else {
                        p.admin_down = true;
                        p.active_connect_cancel_tx.0.take();
                        let cease = bgp::Message::Notification(rustybgp_packet::BgpError::Other {
                            code: 6,
                            subcode: 2,
                            data: vec![],
                        });
                        for tx in [p.active_close_tx.0.take(), p.passive_close_tx.0.take()]
                            .into_iter()
                            .flatten()
                        {
                            let _ = tx.send(cease.clone());
                        }
                        return Ok(tonic::Response::new(api::DisablePeerResponse {}));
                    }
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
        request: tonic::Request<api::WatchEventRequest>,
    ) -> Result<tonic::Response<Self::WatchEventStream>, tonic::Status> {
        let (bmp_tx, bmp_rx) = mpsc::unbounded_channel();

        if let Some(sockaddr) = request.remote_addr() {
            for i in 0..self.tables.shards.len() {
                let mut t = self.tables.shards[i].lock().await;
                t.bmp_event_tx.insert(sockaddr, bmp_tx.clone());
            }

            let tables = self.tables.clone();
            let (tx, rx) = mpsc::channel(1024);
            tokio::spawn(async move {
                let mut bmp_rx = UnboundedReceiverStream::new(bmp_rx);
                while let Some(msg) = bmp_rx.next().await {
                    match &msg {
                        bmp::Message::PeerUp { header, .. }
                        | bmp::Message::PeerDown { header, .. } => {
                            let state = match &msg {
                                bmp::Message::PeerUp { .. } => 6,
                                _ => 1,
                            };

                            let r = api::WatchEventResponse {
                                event: Some(api::watch_event_response::Event::Peer(
                                    api::watch_event_response::PeerEvent {
                                        r#type: api::watch_event_response::peer_event::Type::State
                                            .into(),
                                        peer: Some(api::Peer {
                                            conf: Some(api::PeerConf {
                                                peer_asn: header.asn,
                                                neighbor_address: header.remote_addr.to_string(),
                                                ..Default::default()
                                            }),
                                            state: Some(api::PeerState {
                                                session_state: state,
                                                ..Default::default()
                                            }),
                                            ..Default::default()
                                        }),
                                    },
                                )),
                            };
                            if tx.send(Ok(r)).await.is_err() {
                                break;
                            }
                        }
                        bmp::Message::RouteMonitoring {
                            header: _, update, ..
                        } => {
                            let mut paths = Vec::new();
                            if let bgp::Message::Update(bgp::Update {
                                reach,
                                unreach,
                                attr,
                                ..
                            }) = update
                            {
                                if let Some(s) = reach {
                                    for net in &s.entries {
                                        paths.push(api::Path {
                                            nlri: Some(convert::nlri_to_api(&net.nlri)),
                                            family: Some(convert::family_to_api(s.family)),
                                            identifier: net.path_id,
                                            pattrs: attr.iter().map(convert::attr_to_api).collect(),
                                            ..Default::default()
                                        });
                                    }
                                }
                                if let Some(s) = unreach {
                                    for net in &s.entries {
                                        paths.push(api::Path {
                                            nlri: Some(convert::nlri_to_api(&net.nlri)),
                                            family: Some(convert::family_to_api(s.family)),
                                            identifier: net.path_id,
                                            ..Default::default()
                                        });
                                    }
                                }
                            }

                            let r = api::WatchEventResponse {
                                event: Some(api::watch_event_response::Event::Table(
                                    api::watch_event_response::TableEvent { paths },
                                )),
                            };
                            if tx.send(Ok(r)).await.is_err() {
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                for i in 0..tables.shards.len() {
                    let mut t = tables.shards[i].lock().await;
                    t.bmp_event_tx.remove(&sockaddr);
                }
            });
            Ok(tonic::Response::new(Box::pin(
                tokio_stream::wrappers::ReceiverStream::new(rx),
            )))
        } else {
            Err(tonic::Status::unimplemented("Not yet implemented"))
        }
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
        _request: tonic::Request<api::DeletePeerGroupRequest>,
    ) -> Result<tonic::Response<api::DeletePeerGroupResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }
    async fn update_peer_group(
        &self,
        _request: tonic::Request<api::UpdatePeerGroupRequest>,
    ) -> Result<tonic::Response<api::UpdatePeerGroupResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
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
        _request: tonic::Request<api::ListPeerGroupRequest>,
    ) -> Result<tonic::Response<Self::ListPeerGroupStream>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
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
        _request: tonic::Request<api::DeleteDynamicNeighborRequest>,
    ) -> Result<tonic::Response<api::DeleteDynamicNeighborResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
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
        _request: tonic::Request<api::ListDynamicNeighborRequest>,
    ) -> Result<tonic::Response<Self::ListDynamicNeighborStream>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }
    async fn add_path(
        &self,
        request: tonic::Request<api::AddPathRequest>,
    ) -> Result<tonic::Response<api::AddPathResponse>, tonic::Status> {
        let u = self.local_path(request.into_inner().path.ok_or(Error::EmptyArgument)?)?;
        self.tables.event(u.0, u.1).await;

        // FIXME: support uuid
        Ok(tonic::Response::new(api::AddPathResponse {
            uuid: Vec::new(),
        }))
    }
    async fn delete_path(
        &self,
        request: tonic::Request<api::DeletePathRequest>,
    ) -> Result<tonic::Response<api::DeletePathResponse>, tonic::Status> {
        let u = self.local_path(request.into_inner().path.ok_or(Error::EmptyArgument)?)?;
        self.tables.event(u.0, u.1).await;
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
        let (table_type, peer_addr) = if let Ok(t) = api::TableType::try_from(request.table_type) {
            let s = match t {
                api::TableType::Unspecified => {
                    return Err(tonic::Status::new(
                        tonic::Code::InvalidArgument,
                        "table type unspecified",
                    ));
                }
                api::TableType::Global => None,
                api::TableType::Local | api::TableType::Vrf => {
                    return Err(tonic::Status::unimplemented("Not yet implemented"));
                }
                api::TableType::AdjIn | api::TableType::AdjOut => {
                    if let Ok(addr) = IpAddr::from_str(&request.name) {
                        Some(addr)
                    } else {
                        return Err(tonic::Status::new(
                            tonic::Code::InvalidArgument,
                            "invalid neighbor name",
                        ));
                    }
                }
            };
            (convert::table_type_from_api(t), s)
        } else {
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "invalid table type",
            ));
        };

        let prefixes: Vec<packet::Nlri> = request
            .prefixes
            .iter()
            .map(|x| packet::Nlri::from_str(&x.prefix))
            .filter_map(|x| x.ok())
            .collect();

        let mut v = Vec::new();
        let pa = if table_type == table::TableType::AdjOut {
            self.tables.export_policy.load_full()
        } else {
            None
        };
        for i in 0..self.tables.shards.len() {
            let t = self.tables.shards[i].lock().await;
            for d in t.rtable.iter_destinations(
                table_type,
                family,
                peer_addr,
                prefixes.clone(),
                pa.clone(),
            ) {
                v.push(api::ListPathResponse {
                    destination: Some(convert::destination_to_api(d, family)),
                });
            }
        }
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
        while let Some(Ok(request)) = stream.next().await {
            for path in request.paths {
                if let Ok(u) = self.local_path(path) {
                    self.tables.event(u.0, u.1).await;
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
        let mut info = table::RoutingTableState::default();
        for i in 0..self.tables.shards.len() {
            let t = self.tables.shards[i].lock().await;
            info += t.rtable.state(family);
        }
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
        _request: tonic::Request<api::DeletePolicyRequest>,
    ) -> Result<tonic::Response<api::DeletePolicyResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
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
        _request: tonic::Request<api::SetPoliciesRequest>,
    ) -> Result<tonic::Response<api::SetPoliciesResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
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
        _request: tonic::Request<api::DeleteDefinedSetRequest>,
    ) -> Result<tonic::Response<api::DeleteDefinedSetResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
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
        _request: tonic::Request<api::DeleteStatementRequest>,
    ) -> Result<tonic::Response<api::DeleteStatementResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
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
        _request: tonic::Request<api::DeletePolicyAssignmentRequest>,
    ) -> Result<tonic::Response<api::DeletePolicyAssignmentResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
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
        _request: tonic::Request<api::SetPolicyAssignmentRequest>,
    ) -> Result<tonic::Response<api::SetPolicyAssignmentResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }
    async fn add_rpki(
        &self,
        request: tonic::Request<api::AddRpkiRequest>,
    ) -> Result<tonic::Response<api::AddRpkiResponse>, tonic::Status> {
        let request = request.into_inner();
        let addr = IpAddr::from_str(&request.address)
            .map_err(|_| tonic::Status::new(tonic::Code::InvalidArgument, "invalid address"))?;

        let sockaddr = SocketAddr::new(addr, request.port as u16);
        match self.global.write().await.rpki_clients.entry(sockaddr) {
            Occupied(_) => {
                return Err(tonic::Status::new(
                    tonic::Code::AlreadyExists,
                    format!("rpki client {} already exists", sockaddr),
                ));
            }
            Vacant(v) => {
                let client = RpkiClient::new();
                let t = client.configured_time;
                v.insert(client);
                RpkiClient::try_connect(sockaddr, t, self.global.clone(), self.tables.clone());
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

        let tx = if let Some(mut client) = self.global.write().await.rpki_clients.remove(&sockaddr)
        {
            client.mgmt_tx.take()
        } else {
            None
        };
        if let Some(tx) = tx {
            let _ = tx.send(RpkiMgmtMsg::Deconfigured);
        }
        Ok(tonic::Response::new(api::DeleteRpkiResponse {}))
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

        for (sockaddr, client) in &self.global.read().await.rpki_clients {
            let r = api::Rpki {
                conf: Some(api::RpkiConf {
                    address: sockaddr.ip().to_string(),
                    remote_port: sockaddr.port() as u32,
                }),
                state: Some((&*client.state).into()),
            };
            v.insert(sockaddr.ip(), r);
        }

        {
            let t = self.tables.shards[0].lock().await;
            for (addr, r) in v.iter_mut() {
                let s = t.rtable.rpki_state(addr);
                r.state.as_mut().unwrap().record_ipv4 = s.num_records_v4;
                r.state.as_mut().unwrap().record_ipv6 = s.num_records_v6;
                r.state.as_mut().unwrap().prefix_ipv4 = s.num_prefixes_v4;
                r.state.as_mut().unwrap().prefix_ipv6 = s.num_prefixes_v6;
            }
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
        _request: tonic::Request<api::EnableRpkiRequest>,
    ) -> Result<tonic::Response<api::EnableRpkiResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }
    async fn disable_rpki(
        &self,
        _request: tonic::Request<api::DisableRpkiRequest>,
    ) -> Result<tonic::Response<api::DisableRpkiResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }
    async fn reset_rpki(
        &self,
        _request: tonic::Request<api::ResetRpkiRequest>,
    ) -> Result<tonic::Response<api::ResetRpkiResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
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

        let v: Vec<api::ListRpkiTableResponse> = self.tables.shards[0]
            .lock()
            .await
            .rtable
            .iter_roa(family)
            .map(|(net, roa)| api::ListRpkiTableResponse {
                roa: Some(convert::roa_to_api(&net, roa)),
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
        Err(tonic::Status::unimplemented("Not yet implemented"))
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
        let mut d = MrtDumper::new(&filename, interval);
        {
            let mut g = self.global.write().await;
            if !g.mrt_filenames.insert(filename.clone()) {
                return Err(tonic::Status::new(
                    tonic::Code::AlreadyExists,
                    "mrt dumper already enabled for this file",
                ));
            }
        }
        let file = match tokio::fs::File::create(std::path::Path::new(&d.pathname())).await {
            Ok(file) => file,
            Err(e) => {
                self.global.write().await.mrt_filenames.remove(&filename);
                return Err(tonic::Status::new(
                    tonic::Code::Internal,
                    format!("failed to create mrt dump file: {e}"),
                ));
            }
        };
        let global = self.global.clone();
        let tables = self.tables.clone();
        tokio::spawn(async move {
            if let Err(e) = d.serve(file, global, tables).await {
                println!("mrt dumper failed: {:?}", e);
            }
        });
        Ok(tonic::Response::new(api::EnableMrtResponse {}))
    }
    async fn disable_mrt(
        &self,
        _request: tonic::Request<api::DisableMrtRequest>,
    ) -> Result<tonic::Response<api::DisableMrtResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
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
        match self.global.write().await.bmp_clients.entry(sockaddr) {
            Occupied(_) => {
                return Err(tonic::Status::new(
                    tonic::Code::AlreadyExists,
                    format!("bmp client {} already exists", sockaddr),
                ));
            }
            Vacant(v) => {
                let client = BmpClient::new();
                let t = client.configured_time;
                v.insert(client);
                BmpClient::try_connect(sockaddr, t, self.global.clone(), self.tables.clone());
            }
        }
        Ok(tonic::Response::new(api::AddBmpResponse {}))
    }
    async fn delete_bmp(
        &self,
        _request: tonic::Request<api::DeleteBmpRequest>,
    ) -> Result<tonic::Response<api::DeleteBmpResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
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
            .bmp_clients
            .iter()
            .map(|(k, v)| api::ListBmpResponse {
                station: Some(api::list_bmp_response::BmpStation {
                    conf: Some(api::list_bmp_response::bmp_station::Conf {
                        address: k.ip().to_string(),
                        port: k.port() as u32,
                    }),
                    state: Some(api::list_bmp_response::bmp_station::State {
                        uptime: Some(prost_types::Timestamp {
                            seconds: v.uptime as i64,
                            nanos: 0,
                        }),
                        downtime: Some(prost_types::Timestamp {
                            seconds: v.downtime as i64,
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
        Err(tonic::Status::unimplemented("Not yet implemented"))
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

enum ToPeerEvent {
    Advertise(table::Change),
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
    peer.active_connect_cancel_tx = ActiveConnectCancel(Some(cancel_tx));
    tokio::spawn(async move {
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
}

struct MrtDumper {
    filename: String,
    interval: u64,
}

impl MrtDumper {
    fn new(filename: &str, interval: u64) -> Self {
        MrtDumper {
            filename: filename.to_string(),
            interval,
        }
    }

    fn pathname(&self) -> String {
        if self.interval != 0 {
            chrono::Local::now().format(&self.filename).to_string()
        } else {
            self.filename.clone()
        }
    }

    async fn serve(
        &mut self,
        mut file: tokio::fs::File,
        global: GlobalHandle,
        tables: TableHandle,
    ) -> Result<(), Error> {
        let (tx, rx) = mpsc::unbounded_channel();
        for i in 0..tables.shards.len() {
            let mut t = tables.shards[i].lock().await;
            t.mrt_event_tx.insert(self.filename.clone(), tx.clone());
        }

        let result = self.run_loop(&mut file, rx).await;

        for i in 0..tables.shards.len() {
            let mut t = tables.shards[i].lock().await;
            t.mrt_event_tx.remove(&self.filename);
        }
        global.write().await.mrt_filenames.remove(&self.filename);
        result
    }

    async fn run_loop(
        &self,
        file: &mut tokio::fs::File,
        rx: mpsc::UnboundedReceiver<mrt::Message>,
    ) -> Result<(), Error> {
        let mut codec = mrt::MrtCodec::new();
        let mut rx = UnboundedReceiverStream::new(rx);
        let interval = if self.interval == 0 {
            60 * 24 * 60 * 365 * 100
        } else {
            self.interval
        };
        let start = Instant::now() + Duration::from_secs(interval);
        let mut timer = tokio::time::interval_at(start, Duration::from_secs(interval));
        loop {
            tokio::select! {
                msg = rx.next() => {
                    match msg {
                        Some(msg) => {
                            let mut buf = bytes::BytesMut::with_capacity(8192);
                            codec.encode(&msg, &mut buf)?;
                            file.write_all(&buf).await?;
                        }
                        None => return Ok(()),
                    }
                }
                _ = timer.tick().fuse() => {
                    if self.interval != 0 {
                        *file = tokio::fs::File::create(std::path::Path::new(&self.pathname()))
                            .await?;
                    }
                }
            }
        }
    }
}

#[derive(Default)]
struct BmpClient {
    configured_time: u64,
    uptime: u64,
    downtime: u64,
}

impl BmpClient {
    fn new() -> Self {
        BmpClient {
            configured_time: SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            ..Default::default()
        }
    }

    async fn serve(
        stream: TcpStream,
        sockaddr: SocketAddr,
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

        let (tx, rx) = mpsc::unbounded_channel();
        let mut adjin = FnvHashMap::default();
        for i in 0..tables.shards.len() {
            let mut t = tables.shards[i].lock().await;
            t.bmp_event_tx.insert(sockaddr, tx.clone());
            for f in &[Family::IPV4, Family::IPV6] {
                for c in t.rtable.iter_reach(*f) {
                    let e = adjin.entry(c.source.remote_addr).or_insert_with(Vec::new);
                    let addpath = if let Some(e) = t.addpath.get(&c.source.remote_addr) {
                        e.contains(f)
                    } else {
                        false
                    };
                    e.push((c, addpath));
                }
            }
        }
        let local_id = global.read().await.router_id;
        let mut established_peers = Vec::new();
        for peer in global.read().await.peers.values() {
            if peer.state.fsm.load(Ordering::Relaxed) == SessionState::Established as u8 {
                established_peers.push(peer.config.remote_addr);
                let remote_asn = peer.state.remote_asn.load(Ordering::Relaxed);
                let remote_id = Ipv4Addr::from(peer.state.remote_id.load(Ordering::Relaxed));
                let m = bmp::Message::PeerUp {
                    header: bmp::PerPeerHeader::new(
                        remote_asn,
                        remote_id,
                        0,
                        peer.config.remote_addr,
                        peer.state.uptime.load(Ordering::Relaxed) as u32,
                    ),
                    local_addr: peer.local_sockaddr.ip(),
                    local_port: peer.local_sockaddr.port(),
                    remote_port: peer.remote_sockaddr.port(),
                    remote_open: bgp::Message::Open(bgp::Open {
                        as_number: peer.state.remote_asn.load(Ordering::Relaxed),
                        holdtime: HoldTime::new(peer.state.remote_holdtime.load(Ordering::Relaxed))
                            .unwrap_or(HoldTime::DISABLED),
                        router_id: u32::from(remote_id),
                        capability: peer
                            .state
                            .remote_cap
                            .load()
                            .as_deref()
                            .cloned()
                            .unwrap_or_default(),
                    }),
                    local_open: bgp::Message::Open(bgp::Open {
                        as_number: peer.config.local_asn,
                        holdtime: HoldTime::new(peer.config.holdtime as u16)
                            .unwrap_or(HoldTime::DISABLED),
                        router_id: u32::from(local_id),
                        capability: peer.config.local_cap.to_owned(),
                    }),
                };
                if lines.send(&m).await.is_err() {
                    return;
                }
            }
        }
        for addr in established_peers {
            let mut header = None;
            if let Some(v) = adjin.remove(&addr) {
                for (m, addpath) in v {
                    if header.is_none() {
                        header = Some(bmp::PerPeerHeader::new(
                            m.source.remote_asn,
                            Ipv4Addr::from(m.source.router_id),
                            0,
                            m.source.remote_addr,
                            m.source.uptime as u32,
                        ));
                    }
                    if lines
                        .send(&bmp::Message::RouteMonitoring {
                            header: bmp::PerPeerHeader::new(
                                m.source.remote_asn,
                                Ipv4Addr::from(m.source.router_id),
                                0,
                                m.source.remote_addr,
                                m.source.uptime as u32,
                            ),
                            update: m.into(),
                            addpath,
                        })
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
                if lines
                    .send(&bmp::Message::RouteMonitoring {
                        header: header.unwrap(),
                        update: bgp::Message::eor(Family::IPV4),
                        addpath: false,
                    })
                    .await
                    .is_err()
                {
                    return;
                }
            }
        }
        let mut rx = UnboundedReceiverStream::new(rx);
        loop {
            tokio::select! {
                msg = lines.next() => {
                    let _msg = match msg {
                        Some(msg) => match msg {
                            Ok(msg) => msg,
                            Err(_) => break,
                        },
                        None => break,
                    };
                }
                msg = rx.next() => {
                    if let Some(msg) = msg {
                        if lines.send(&msg).await.is_err() {
                            break;
                        }
                    } else {
                        break;
                    }
                }
            }
        }
        for i in 0..tables.shards.len() {
            let mut t = tables.shards[i].lock().await;
            let _ = t.bmp_event_tx.remove(&sockaddr);
        }
    }

    fn try_connect(
        sockaddr: SocketAddr,
        configured_time: u64,
        global: GlobalHandle,
        tables: TableHandle,
    ) {
        tokio::spawn(async move {
            loop {
                if let Ok(Ok(stream)) = tokio::time::timeout(
                    tokio::time::Duration::from_secs(5),
                    TcpStream::connect(sockaddr),
                )
                .await
                {
                    if let Some(client) = global.write().await.bmp_clients.get_mut(&sockaddr) {
                        client.uptime = SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs();
                    } else {
                        break;
                    }
                    BmpClient::serve(stream, sockaddr, global.clone(), tables.clone()).await;
                    if let Some(client) = global.write().await.bmp_clients.get_mut(&sockaddr) {
                        client.downtime = SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs();
                    } else {
                        break;
                    }
                }
                tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                if let Some(client) = global.write().await.bmp_clients.get_mut(&sockaddr) {
                    if client.configured_time != configured_time {
                        break;
                    }
                } else {
                    // de-configured
                    break;
                }
            }
        });
    }
}

#[derive(Default)]
struct RpkiState {
    uptime: AtomicU64,
    downtime: AtomicU64,
    up: AtomicBool,
    serial: AtomicU32,
    received_ipv4: AtomicI64,
    received_ipv6: AtomicI64,
    serial_notify: AtomicI64,
    cache_reset: AtomicI64,
    cache_response: AtomicI64,
    end_of_data: AtomicI64,
    error: AtomicI64,
    serial_query: AtomicI64,
    reset_query: AtomicI64,
}

impl RpkiState {
    fn update(&self, msg: &rpki::Message) {
        match msg {
            rpki::Message::SerialNotify { .. } => {
                self.serial_notify.fetch_add(1, Ordering::Relaxed);
            }
            rpki::Message::SerialQuery { .. } => {
                let _ = self.serial_query.fetch_add(1, Ordering::Relaxed);
            }
            rpki::Message::ResetQuery => {
                let _ = self.reset_query.fetch_add(1, Ordering::Relaxed);
            }
            rpki::Message::CacheResponse => {
                let _ = self.cache_response.fetch_add(1, Ordering::Relaxed);
            }
            rpki::Message::IpPrefix(prefix) => match prefix.net {
                packet::IpNet::V4(_) => {
                    let _ = self.received_ipv4.fetch_add(1, Ordering::Relaxed);
                }
                packet::IpNet::V6(_) => {
                    let _ = self.received_ipv6.fetch_add(1, Ordering::Relaxed);
                }
            },
            rpki::Message::EndOfData { .. } => {
                let _ = self.end_of_data.fetch_add(1, Ordering::Relaxed);
            }
            rpki::Message::CacheReset => {
                let _ = self.cache_reset.fetch_add(1, Ordering::Relaxed);
            }
            rpki::Message::ErrorReport => {
                let _ = self.error.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

impl From<&RpkiState> for api::RpkiState {
    fn from(s: &RpkiState) -> Self {
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

enum RpkiMgmtMsg {
    Deconfigured,
}

struct RpkiClient {
    configured_time: u64,
    state: Arc<RpkiState>,
    mgmt_tx: Option<mpsc::UnboundedSender<RpkiMgmtMsg>>,
}

impl RpkiClient {
    fn new() -> Self {
        RpkiClient {
            configured_time: SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            state: Arc::new(RpkiState::default()),
            mgmt_tx: None,
        }
    }

    async fn serve(
        stream: TcpStream,
        rx: mpsc::UnboundedReceiver<RpkiMgmtMsg>,
        state: Arc<RpkiState>,
        tables: TableHandle,
    ) -> Result<(), Error> {
        let remote_addr = stream.peer_addr()?.ip();
        let remote_addr = Arc::new(remote_addr);
        let mut lines = Framed::new(stream, rpki::RtrCodec::new());
        let _ = lines.send(&rpki::Message::ResetQuery).await;
        state.uptime.store(
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            Ordering::Relaxed,
        );
        state.up.store(true, Ordering::Relaxed);
        let mut rx = UnboundedReceiverStream::new(rx);
        let mut v = Vec::new();
        let mut end_of_data = false;
        loop {
            tokio::select! {
                msg = rx.next() => {
                    if let Some(RpkiMgmtMsg::Deconfigured) = msg {
                            break;
                    }
                }
                msg = lines.next() => {
                    let msg = match msg {
                        Some(msg) => match msg {
                            Ok(msg) => msg,
                            Err(_) => break,
                        },
                        None => break,
                    };
                    state.update(&msg);
                    match msg {
                        rpki::Message::IpPrefix(prefix)
                            if prefix.flags & 1 > 0 =>
                        {
                            let roa = Arc::new(table::Roa::new(prefix.max_length, prefix.as_number, remote_addr.clone()));
                            if end_of_data {
                                for i in 0..tables.shards.len() {
                                    tables.event(i, TableEvent::InsertRoa(vec![(prefix.net.clone(), roa.clone())])).await;
                                }
                            } else {
                                v.push((
                                    prefix.net,
                                    roa,
                                ));
                            }
                        }
                        rpki::Message::EndOfData { serial_number } => {
                            end_of_data = true;
                            state.serial.store(serial_number, Ordering::Relaxed);
                            for i in 0..tables.shards.len() {
                                tables.event(i, TableEvent::Drop(remote_addr.clone())).await;
                                tables.event(i, TableEvent::InsertRoa(v.to_owned())).await;
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        state.downtime.store(
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            Ordering::Relaxed,
        );
        for i in 0..tables.shards.len() {
            tables.event(i, TableEvent::Drop(remote_addr.clone())).await;
        }
        Ok(())
    }

    fn try_connect(
        sockaddr: SocketAddr,
        configured_time: u64,
        global: GlobalHandle,
        tables: TableHandle,
    ) {
        tokio::spawn(async move {
            loop {
                if let Ok(Ok(stream)) = tokio::time::timeout(
                    tokio::time::Duration::from_secs(5),
                    TcpStream::connect(sockaddr),
                )
                .await
                {
                    let (tx, rx) = mpsc::unbounded_channel();
                    let state = if let Some(client) =
                        global.write().await.rpki_clients.get_mut(&sockaddr)
                    {
                        client.mgmt_tx = Some(tx);
                        client.state.clone()
                    } else {
                        break;
                    };
                    let _ = RpkiClient::serve(stream, rx, state, tables.clone()).await;
                } else {
                    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                }
                if let Some(client) = global.write().await.rpki_clients.get_mut(&sockaddr) {
                    if client.configured_time != configured_time {
                        break;
                    }
                    if client.mgmt_tx.is_some() {
                        client.mgmt_tx = None;
                    }
                } else {
                    break;
                }
            }
        });
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

type GlobalHandle = Arc<tokio::sync::RwLock<Global>>;

struct Global {
    asn: u32,
    router_id: Ipv4Addr,
    listen_port: u16,
    listen_sockets: Vec<RawFd>,
    peers: FnvHashMap<IpAddr, Peer>,
    peer_group: FnvHashMap<String, PeerGroup>,

    ptable: table::PolicyTable,

    rpki_clients: FnvHashMap<SocketAddr, RpkiClient>,
    bmp_clients: FnvHashMap<SocketAddr, BmpClient>,
    mrt_filenames: FnvHashSet<String>,
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
            confederation: None,
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

            ptable: table::PolicyTable::new(),

            rpki_clients: FnvHashMap::default(),
            bmp_clients: FnvHashMap::default(),
            mrt_filenames: FnvHashSet::default(),
        }
    }

    fn add_peer(
        &mut self,
        mut peer: Peer,
        tx: Option<mpsc::UnboundedSender<TcpStream>>,
    ) -> std::result::Result<(), Error> {
        if self.peers.contains_key(&peer.config.remote_addr) {
            return Err(Error::AlreadyExists(
                "peer address already exists".to_string(),
            ));
        }
        if peer.config.local_asn == 0 {
            peer.config.local_asn = self.asn;
        }
        let mut caps = HashSet::new();
        for c in &peer.config.local_cap {
            caps.insert(Into::<u8>::into(c));
        }
        let c = packet::Capability::FourOctetAsNumber(peer.config.local_asn);
        if !caps.contains(&Into::<u8>::into(&c)) {
            peer.config.local_cap.push(c);
        }
        peer.peer_fsm = Some(Arc::new(std::sync::Mutex::new(crate::fsm::PeerFsm::new(
            u32::from(self.router_id),
            peer.config.local_asn,
            peer.config.local_cap.clone(),
            peer.config.holdtime,
            peer.config.remote_asn,
            peer.config.send_max.clone(),
        ))));
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
) -> Option<Connection> {
    let local_sockaddr = stream.local_addr().ok()?;
    let remote_sockaddr = stream.peer_addr().ok()?;
    let remote_addr = remote_sockaddr.ip();
    let mut g = global.write().await;
    let peer = match g.peers.get_mut(&remote_addr) {
        Some(peer) => {
            if peer.admin_down {
                println!(
                    "admin down; ignore a new passive connection from {}",
                    remote_addr
                );
                return None;
            }
            let already_connected = match role {
                crate::fsm::Role::Active => peer.active_close_tx.0.is_some(),
                crate::fsm::Role::Passive => peer.passive_close_tx.0.is_some(),
            };
            if already_connected {
                println!("already has {:?} connection {}", role, remote_addr);
                return None;
            }
            peer.remote_sockaddr = remote_sockaddr;
            peer.local_sockaddr = local_sockaddr;
            peer.state
                .fsm
                .store(SessionState::Active as u8, Ordering::Relaxed);
            peer
        }
        None => {
            let mut is_dynamic = false;
            let mut rs_client = false;
            let mut remote_asn = 0;
            let mut holdtime = None;
            for p in &g.peer_group {
                for d in &p.1.dynamic_peers {
                    if d.prefix.contains(&remote_addr) {
                        remote_asn = p.1.as_number;
                        is_dynamic = true;
                        rs_client = p.1.route_server_client;
                        holdtime = p.1.holdtime;
                        break;
                    }
                }
            }
            if !is_dynamic {
                println!(
                    "can't find configuration a new passive connection {}",
                    remote_addr
                );
                return None;
            }
            let mut builder = PeerBuilder::new(remote_addr);
            builder
                .state(SessionState::Active)
                .remote_asn(remote_asn)
                .delete_on_disconnected(true)
                .rs_client(rs_client)
                .remote_sockaddr(remote_sockaddr)
                .local_sockaddr(local_sockaddr);
            if let Some(holdtime) = holdtime {
                builder.holdtime(holdtime);
            }
            let _ = g.add_peer(builder.build(), None);
            g.peers.get_mut(&remote_addr).unwrap()
        }
    };
    if let Some(ttl) = peer.config.multihop_ttl {
        if peer.config.remote_asn != peer.config.local_asn {
            let _ = stream.set_ttl(ttl.into());
        }
    } else {
        let _ = stream.set_ttl(1);
    }
    let peer_fsm = Arc::clone(peer.peer_fsm.as_ref().expect("peer_fsm set in add_peer"));
    let (close_tx, close_rx) = tokio::sync::oneshot::channel::<bgp::Message>();
    match role {
        crate::fsm::Role::Active => peer.active_close_tx = CloseTx(Some(close_tx)),
        crate::fsm::Role::Passive => peer.passive_close_tx = CloseTx(Some(close_tx)),
    }
    Connection::new(
        stream,
        remote_addr,
        peer.config.local_asn,
        peer.config.local_cap.to_owned(),
        peer.config.route_server_client,
        role,
        peer_fsm,
        Some(close_rx),
        peer.state.clone(),
        peer.counter_tx.clone(),
        peer.counter_rx.clone(),
        peer.config.prefix_limits.clone(),
        tables.clone(),
        peer.export_map.clone(),
    )
}

impl Global {
    async fn serve(
        bgp: Option<config::BgpConfig>,
        any_peer: bool,
        active_tx: mpsc::UnboundedSender<TcpStream>,
        mut active_rx: mpsc::UnboundedReceiver<TcpStream>,
    ) {
        let global: GlobalHandle = Arc::new(tokio::sync::RwLock::new(Global::new()));
        let tables: TableHandle = Arc::new(Tables::new(num_cpus::get()));
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
            notify.clone().notify_one();
            let g = &mut global.write().await;
            g.asn = as_number;
            g.router_id = router_id;
        }
        if let Some(mrt) = bgp.as_ref().and_then(|x| x.mrt_dump.as_ref()) {
            for m in mrt {
                if let Some(config) = m.config.as_ref()
                    && let Some(dump_type) = config.dump_type.as_ref()
                {
                    if dump_type != &config::generate::MrtType::Updates {
                        println!("only update dump is supported");
                        continue;
                    }
                    if let Some(filename) = config.file_name.as_ref() {
                        {
                            let mut g = global.write().await;
                            if !g.mrt_filenames.insert(filename.clone()) {
                                println!("mrt dumper already enabled for {filename}, skipping");
                                continue;
                            }
                        }
                        let interval = config.rotation_interval.as_ref().map_or(0, |x| *x);
                        let filename = filename.clone();
                        let mut d = MrtDumper::new(&filename, interval);
                        match tokio::fs::File::create(std::path::Path::new(&d.pathname())).await {
                            Ok(file) => {
                                let global2 = global.clone();
                                let tables2 = tables.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = d.serve(file, global2, tables2).await {
                                        println!("mrt dumper failed: {:?}", e);
                                    }
                                });
                            }
                            Err(e) => {
                                global.write().await.mrt_filenames.remove(&filename);
                                println!("failed to create mrt dump file: {:?}", e);
                            }
                        }
                    } else {
                        println!("mrt dump filename needs to be specified");
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
                        while let Some(event) = rx.recv().await {
                            match event {
                                KernelRouteEvent::Install {
                                    dst,
                                    prefix_len,
                                    nexthop,
                                } => {
                                    if let Err(e) =
                                        handle.install(dst, prefix_len, nexthop, 0).await
                                    {
                                        eprintln!("kernel route install failed: {}", e);
                                    }
                                }
                                KernelRouteEvent::Withdraw { dst, prefix_len } => {
                                    if let Err(e) = handle.withdraw(dst, prefix_len).await {
                                        eprintln!("kernel route withdraw failed: {}", e);
                                    }
                                }
                            }
                        }
                    });
                    tables.kernel_tx.store(Some(Arc::new(tx)));
                    println!("kernel route integration enabled");
                }
                Err(e) => {
                    eprintln!("failed to enable kernel route integration: {:?}", e);
                }
            }
        }
        if let Some(groups) = bgp.as_ref().and_then(|x| x.peer_groups.as_ref()) {
            let mut server = global.write().await;
            for pg in groups {
                if let Some(name) = pg.config.as_ref().and_then(|x| x.peer_group_name.clone()) {
                    server.peer_group.insert(
                        name,
                        PeerGroup {
                            as_number: pg.config.as_ref().map_or(0, |x| x.peer_as.map_or(0, |x| x)),
                            dynamic_peers: Vec::new(),
                            route_server_client: pg.route_server.as_ref().is_some_and(|x| {
                                x.config
                                    .as_ref()
                                    .is_some_and(|x| x.route_server_client.unwrap_or(false))
                            }),
                            holdtime: pg.timers.as_ref().and_then(|x| {
                                x.config
                                    .as_ref()
                                    .and_then(|x| x.hold_time.as_ref().map(|x| *x as u64))
                            }),
                            // passive: pg.transport.as_ref().map_or(false, |x| {
                            //     x.config
                            //         .as_ref()
                            //         .map_or(false, |x| x.passive_mode.map_or(false, |x| x))
                            // }),
                        },
                    );
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
                match server.bmp_clients.entry(sockaddr) {
                    Occupied(_) => {
                        panic!("duplicated bmp server {}", sockaddr);
                    }
                    Vacant(v) => {
                        let client = BmpClient::new();
                        let t = client.configured_time;
                        v.insert(client);
                        BmpClient::try_connect(sockaddr, t, global.clone(), tables.clone());
                    }
                }
            }
        }
        if let Some(defined_sets) = bgp.as_ref().and_then(|x| x.defined_sets.as_ref()) {
            match convert::defined_sets_to_api(defined_sets) {
                Ok(sets) => {
                    let mut server = global.write().await;
                    for set in sets {
                        let set = convert::defined_set_from_api(set).unwrap();
                        if let Err(e) = server.ptable.add_defined_set(set) {
                            panic!("{:?}", e);
                        }
                    }
                }
                Err(e) => panic!("{:?}", e),
            }
        }
        if let Some(policies) = bgp.as_ref().and_then(|x| x.policy_definitions.as_ref()) {
            let mut h = HashSet::new();
            let mut server = global.write().await;
            for policy in policies {
                if let Some(name) = &policy.name {
                    let mut s_names = Vec::new();
                    if let Some(statements) = &policy.statements {
                        for s in statements {
                            if let Some(n) = s.name.as_ref()
                                && h.contains(n)
                            {
                                s_names.push(n.clone());
                                continue;
                            }
                            match convert::statement_from_config(s) {
                                Ok(s) => {
                                    let conditions =
                                        convert::conditions_from_api(s.conditions).unwrap();
                                    let (disposition, actions) =
                                        convert::disposition_from_api(s.actions).unwrap();
                                    server
                                        .ptable
                                        .add_statement(&s.name, conditions, disposition, actions)
                                        .unwrap();
                                    s_names.push(s.name.clone());
                                    h.insert(s.name);
                                }
                                Err(e) => panic!("{:?}", e),
                            }
                        }
                    }
                    if let Err(e) = server.ptable.add_policy(name, s_names) {
                        panic!("{:?}", e);
                    }
                }
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
                match Peer::try_from(p) {
                    Ok(peer) => {
                        if let Err(e) = server.add_peer(peer, Some(active_tx.clone())) {
                            eprintln!("failed to add peer from config: {}", e);
                        }
                    }
                    Err(e) => {
                        eprintln!("skipping invalid peer config: {}", e);
                    }
                }
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
                    // passive: true,
                    route_server_client: false,
                    holdtime: None,
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
                tokio_stream::wrappers::TcpListenerStream::new(TcpListener::from_std(x).unwrap())
            })
            .collect::<Vec<tokio_stream::wrappers::TcpListenerStream>>();
        assert_ne!(incomings.len(), 0);
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
                        tokio::spawn(peer_loop(h, global.clone(), active_tx.clone()));
                    }
                }
                stream = active_rx.recv().fuse() => {
                    if let Some(stream) = stream
                        && let Some(h) = accept_connection(&global, &tables, stream, crate::fsm::Role::Active).await
                    {
                        tokio::spawn(peer_loop(h, global.clone(), active_tx.clone()));
                    }
                }
            }
        }
    }
}

enum KernelRouteEvent {
    Install {
        dst: IpAddr,
        prefix_len: u8,
        nexthop: IpAddr,
    },
    Withdraw {
        dst: IpAddr,
        prefix_len: u8,
    },
}

enum TableEvent {
    // BGP events
    PassUpdate(
        Arc<table::Source>,
        Family,
        Vec<packet::PathNlri>,
        Option<Arc<Vec<packet::Attribute>>>,
        Option<bgp::Nexthop>,
    ),
    Disconnected(Arc<table::Source>),
    // RPKI events
    InsertRoa(Vec<(packet::IpNet, Arc<table::Roa>)>),
    Drop(Arc<IpAddr>),
}

type TableHandle = Arc<Tables>;

struct Tables {
    shards: Vec<Mutex<Table>>,
    kernel_tx: ArcSwapOption<mpsc::UnboundedSender<KernelRouteEvent>>,
    import_policy: ArcSwapOption<table::PolicyAssignment>,
    export_policy: ArcSwapOption<table::PolicyAssignment>,
}

impl Tables {
    fn new(num_shards: usize) -> Self {
        Tables {
            shards: (0..num_shards)
                .map(|_| {
                    Mutex::new(Table {
                        rtable: table::RoutingTable::new(),
                        peer_event_tx: FnvHashMap::default(),
                        bmp_event_tx: FnvHashMap::default(),
                        mrt_event_tx: FnvHashMap::default(),
                        addpath: FnvHashMap::default(),
                    })
                })
                .collect(),
            kernel_tx: ArcSwapOption::const_empty(),
            import_policy: ArcSwapOption::const_empty(),
            export_policy: ArcSwapOption::const_empty(),
        }
    }

    fn dealer<T: Hash>(&self, a: T) -> usize {
        let mut hasher = FnvHasher::default();
        a.hash(&mut hasher);
        hasher.finish() as usize % self.shards.len()
    }

    async fn event(&self, idx: usize, msg: TableEvent) {
        let import_policy = self.import_policy.load_full();
        let export_policy = self.export_policy.load_full();
        let kernel_tx = self.kernel_tx.load_full();
        self.shards[idx].lock().await.event(
            msg,
            kernel_tx.as_deref(),
            import_policy.as_deref(),
            export_policy.as_deref(),
        );
    }
}

struct Table {
    rtable: table::RoutingTable,
    peer_event_tx: FnvHashMap<IpAddr, mpsc::UnboundedSender<ToPeerEvent>>,
    bmp_event_tx: FnvHashMap<SocketAddr, mpsc::UnboundedSender<bmp::Message>>,
    mrt_event_tx: FnvHashMap<String, mpsc::UnboundedSender<mrt::Message>>,
    addpath: FnvHashMap<IpAddr, FnvHashSet<Family>>,
}

impl Table {
    fn has_addpath(&self, addr: &IpAddr, family: &Family) -> bool {
        self.addpath.get(addr).is_some_and(|e| e.contains(family))
    }

    fn send_bmp_update(
        &self,
        source: &table::Source,
        family: Family,
        nets: &[packet::PathNlri],
        attrs: Option<&Arc<Vec<packet::Attribute>>>,
        nexthop: Option<bgp::Nexthop>,
    ) {
        let addpath = self.has_addpath(&source.remote_addr, &family);
        let header = bmp::PerPeerHeader::new(
            source.remote_asn,
            Ipv4Addr::from(source.router_id),
            0,
            source.remote_addr,
            source.uptime as u32,
        );
        let update = if let Some(attrs) = attrs {
            bgp::Message::Update(bgp::Update {
                reach: Some(packet::bgp::NlriSet {
                    family,
                    entries: nets.to_owned(),
                }),
                mp_reach: None,
                attr: attrs.clone(),
                unreach: None,
                mp_unreach: None,
                nexthop,
            })
        } else {
            bgp::Message::Update(bgp::Update {
                reach: None,
                mp_reach: None,
                attr: Arc::new(Vec::new()),
                unreach: None,
                mp_unreach: Some(packet::bgp::NlriSet {
                    family,
                    entries: nets.to_owned(),
                }),
                nexthop: None,
            })
        };
        for bmp_tx in self.bmp_event_tx.values() {
            let _ = bmp_tx.send(bmp::Message::RouteMonitoring {
                header: header.clone(),
                update: update.clone(),
                addpath,
            });
        }
    }

    fn send_mrt_update(
        &self,
        source: &table::Source,
        family: Family,
        nets: &[packet::PathNlri],
        attrs: Option<&Arc<Vec<packet::Attribute>>>,
        nexthop: Option<bgp::Nexthop>,
    ) {
        if self.mrt_event_tx.is_empty() {
            return;
        }
        let addpath = self.has_addpath(&source.remote_addr, &family);
        let header = mrt::MpHeader::new(
            source.remote_asn,
            source.local_asn,
            0,
            source.remote_addr,
            source.local_addr,
            true,
        );
        let body = if let Some(attrs) = attrs {
            bgp::Message::Update(bgp::Update {
                reach: Some(packet::bgp::NlriSet {
                    family,
                    entries: nets.to_owned(),
                }),
                mp_reach: None,
                attr: attrs.clone(),
                unreach: None,
                mp_unreach: None,
                nexthop,
            })
        } else {
            bgp::Message::Update(bgp::Update {
                reach: None,
                mp_reach: None,
                attr: Arc::new(Vec::new()),
                unreach: None,
                mp_unreach: Some(packet::bgp::NlriSet {
                    family,
                    entries: nets.to_owned(),
                }),
                nexthop: None,
            })
        };
        for mrt_tx in self.mrt_event_tx.values() {
            let _ = mrt_tx.send(mrt::Message::Mp {
                header: header.clone(),
                body: body.clone(),
                addpath,
            });
        }
    }

    fn distribute_changes(
        &self,
        changes: Vec<table::Change>,
        kernel_tx: Option<&mpsc::UnboundedSender<KernelRouteEvent>>,
        export_policy: Option<&table::PolicyAssignment>,
    ) {
        for c in &changes {
            if c.rank == 1
                && let Some(tx) = kernel_tx
            {
                let (dst, prefix_len) = match c.net {
                    packet::Nlri::V4(net) => (IpAddr::from(net.addr), net.mask),
                    packet::Nlri::V6(net) => (IpAddr::from(net.addr), net.mask),
                    // MUP NLRI do not map to kernel routes; skip them here.
                    packet::Nlri::Mup(_) => continue,
                };
                if c.attr.is_empty() {
                    let _ = tx.send(KernelRouteEvent::Withdraw { dst, prefix_len });
                } else {
                    let nexthop = c.nexthop.addr();
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
                        // Family mismatch (e.g., RFC 8950); withdraw to avoid stale kernel route.
                        let _ = tx.send(KernelRouteEvent::Withdraw { dst, prefix_len });
                    }
                }
            }
        }
        for c in crate::policy::filter_export(changes, export_policy, &self.rtable) {
            for tx in self.peer_event_tx.values() {
                let _ = tx.send(ToPeerEvent::Advertise(c.clone()));
            }
        }
    }

    fn event(
        &mut self,
        msg: TableEvent,
        kernel_tx: Option<&mpsc::UnboundedSender<KernelRouteEvent>>,
        import_policy: Option<&table::PolicyAssignment>,
        export_policy: Option<&table::PolicyAssignment>,
    ) {
        match msg {
            TableEvent::PassUpdate(source, family, nets, attrs, nexthop) => {
                self.send_bmp_update(&source, family, &nets, attrs.as_ref(), nexthop);
                self.send_mrt_update(&source, family, &nets, attrs.as_ref(), nexthop);

                match attrs {
                    Some(attrs) => {
                        for net in nets {
                            let mut nh = nexthop.unwrap();
                            let filtered = crate::policy::apply_import(
                                import_policy,
                                &self.rtable,
                                &source,
                                &net.nlri,
                                &attrs,
                                &mut nh,
                            );
                            let changes = self.rtable.insert(
                                source.clone(),
                                family,
                                net.nlri,
                                net.path_id,
                                nh,
                                attrs.clone(),
                                filtered,
                            );
                            self.distribute_changes(changes, kernel_tx, export_policy);
                        }
                    }
                    None => {
                        for net in nets {
                            let changes =
                                self.rtable
                                    .remove(source.clone(), family, net.nlri, net.path_id);
                            self.distribute_changes(changes, kernel_tx, export_policy);
                        }
                    }
                }
            }
            TableEvent::Disconnected(source) => {
                let changes = self.rtable.drop(source.clone());
                self.distribute_changes(changes, kernel_tx, None);
            }
            TableEvent::InsertRoa(v) => {
                for (net, roa) in v {
                    self.rtable.roa_insert(net, roa);
                }
            }
            TableEvent::Drop(addr) => {
                self.rtable.rpki_drop(addr);
            }
        }
    }
}

pub(crate) async fn main(bgp: Option<config::BgpConfig>, any_peer: bool) {
    let (active_tx, active_rx) = mpsc::unbounded_channel();
    Global::serve(bgp, any_peer, active_tx, active_rx).await;
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
/// Stored in DisconnectInfo so peer_loop can drive GrState on session drop.
#[allow(dead_code)]
struct NegotiatedGr {
    /// Intersection of local and remote GR families.
    families: Vec<Family>,
    /// Restart Time from the peer's OPEN GR capability.
    restart_time: std::time::Duration,
}

struct DisconnectInfo {
    role: crate::fsm::Role,
    remote_addr: IpAddr,
    export_map: ExportMap,
    /// Set when GR was successfully negotiated for at least one family.
    #[allow(dead_code)]
    negotiated_gr: Option<NegotiatedGr>,
}

async fn peer_loop(
    mut h: Connection,
    global: GlobalHandle,
    active_conn_tx: mpsc::UnboundedSender<TcpStream>,
) {
    let info = h.run(&global).await;
    let mut server = global.write().await;
    if let Some(peer) = server.peers.get_mut(&info.remote_addr) {
        // GR not yet implemented: always discard the export_map on disconnect.
        // When GR is enabled, preserve it here for the next session.
        drop(info.export_map);
        match info.role {
            crate::fsm::Role::Active => peer.active_close_tx = CloseTx::default(),
            crate::fsm::Role::Passive => peer.passive_close_tx = CloseTx::default(),
        }
        // Only reset and reconnect when no Connection remains for this peer.
        if peer.active_close_tx.0.is_none() && peer.passive_close_tx.0.is_none() {
            if peer.config.delete_on_disconnected {
                server.peers.remove(&info.remote_addr);
            } else {
                peer.reset();
                enable_active_connect(peer, active_conn_tx);
            }
        }
    }
}

/// Side effects from `apply_outputs` that require mutating global peer state.
/// Returned by `apply_outputs` and processed by `process_effects` so that
/// `apply_outputs` itself has no async global dependency and is unit-testable.
enum GlobalEffect {
    /// Send a CEASE Notification to the connection with the given role
    /// (collision loser dispatch via that connection's close_tx).
    SendCease {
        role: crate::fsm::Role,
        msg: bgp::Message,
    },
    /// Cancel the active-connect retry loop for this peer.
    StopActiveConnect,
}

struct RunState {
    urgent: Vec<bgp::Message>,
    framer: BgpFramer,
    keepalive_futures: FuturesUnordered<tokio::time::Sleep>,
    holdtime_futures: FuturesUnordered<tokio::time::Sleep>,
    pending: FnvHashMap<Family, crate::peer_tx::PendingTx>,
    txbuf_size: usize,
}

#[derive(Clone)]
struct ExportMap {
    advertised: FnvHashMap<Family, FnvHashSet<packet::Nlri>>,
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

    fn mark_sent(&mut self, family: Family, nlri: packet::Nlri) {
        self.advertised.entry(family).or_default().insert(nlri);
    }

    fn mark_withdrawn(&mut self, family: Family, nlri: &packet::Nlri) {
        if let Some(s) = self.advertised.get_mut(&family) {
            s.remove(nlri);
        }
    }

    fn was_sent(&self, family: Family, nlri: &packet::Nlri) -> bool {
        self.advertised
            .get(&family)
            .is_some_and(|s| s.contains(nlri))
    }
}

struct Connection {
    remote_addr: IpAddr,
    local_addr: IpAddr,
    /// IPv6 link-local address of the local interface (for 32-byte MP_REACH nexthop).
    link_addr: Option<Ipv6Addr>,

    local_asn: u32,

    state: Arc<PeerState>,

    counter_tx: Arc<MessageCounter>,
    counter_rx: Arc<MessageCounter>,

    local_cap: Vec<packet::Capability>,

    rs_client: bool,

    peer_fsm: Arc<std::sync::Mutex<crate::fsm::PeerFsm>>,
    role: crate::fsm::Role,
    /// Receives a CEASE Notification from an external signal (collision winner
    /// or admin operation); on receipt this Connection sends the message and closes.
    close_rx: Option<tokio::sync::oneshot::Receiver<bgp::Message>>,

    stream: Option<TcpStream>,
    source: Option<Arc<table::Source>>,
    peer_event_tx: Vec<mpsc::UnboundedSender<ToPeerEvent>>,
    shutdown: Option<bmp::PeerDownReason>,
    /// Per-family prefix limits from config.
    prefix_limits: FnvHashMap<Family, u32>,
    tables: TableHandle,
    export_map: ExportMap,
    /// GR negotiation result from the most recent OPEN exchange.
    negotiated_gr: Option<NegotiatedGr>,
}

impl Connection {
    #[allow(clippy::too_many_arguments)]
    fn new(
        stream: TcpStream,
        remote_addr: IpAddr,
        local_asn: u32,
        local_cap: Vec<packet::Capability>,
        rs_client: bool,
        role: crate::fsm::Role,
        peer_fsm: Arc<std::sync::Mutex<crate::fsm::PeerFsm>>,
        close_rx: Option<tokio::sync::oneshot::Receiver<bgp::Message>>,
        state: Arc<PeerState>,
        counter_tx: Arc<MessageCounter>,
        counter_rx: Arc<MessageCounter>,
        prefix_limits: FnvHashMap<Family, u32>,
        tables: TableHandle,
        export_map: ExportMap,
    ) -> Option<Self> {
        let local_sockaddr = stream.local_addr().ok()?;
        let local_addr = local_sockaddr.ip();
        let link_addr = find_link_local(&local_sockaddr);
        Some(Connection {
            remote_addr,
            local_addr,
            link_addr,
            local_asn,
            state,
            counter_tx,
            counter_rx,
            local_cap,
            rs_client,
            peer_fsm,
            role,
            close_rx,
            stream: Some(stream),
            source: None,
            peer_event_tx: Vec::new(),
            shutdown: None,
            prefix_limits,
            tables,
            export_map,
            negotiated_gr: None,
        })
    }

    /// Compute the intersection of local and remote GR families.
    /// Returns None if local_cap has no GR capability, the peer sent none,
    /// or if no families overlap.
    fn negotiate_gr(&self, remote_capabilities: &[packet::Capability]) -> Option<NegotiatedGr> {
        let local_families: Vec<Family> = self.local_cap.iter().find_map(|c| match c {
            packet::Capability::GracefulRestart { families, .. } => {
                Some(families.iter().map(|(f, _)| *f).collect())
            }
            _ => None,
        })?;

        let (peer_restart_time, peer_families) =
            remote_capabilities.iter().find_map(|c| match c {
                packet::Capability::GracefulRestart {
                    restart_time,
                    families,
                    ..
                } => Some((*restart_time, families.as_slice())),
                _ => None,
            })?;

        let negotiated: Vec<Family> = local_families
            .into_iter()
            .filter(|f| peer_families.iter().any(|(pf, _)| pf == f))
            .collect();

        if negotiated.is_empty() {
            return None;
        }
        Some(NegotiatedGr {
            families: negotiated,
            restart_time: std::time::Duration::from_secs(peer_restart_time as u64),
        })
    }

    async fn on_established(
        &mut self,
        codec: &bgp::PeerCodec,
        local_sockaddr: SocketAddr,
        remote_sockaddr: SocketAddr,
        pending: &mut FnvHashMap<Family, crate::peer_tx::PendingTx>,
    ) {
        let uptime = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.state.uptime.store(uptime, Ordering::Relaxed);
        let remote_asn = self.state.remote_asn.load(Ordering::Relaxed);
        self.source = Some(Arc::new(table::Source::new(
            self.remote_addr,
            self.local_addr,
            remote_asn,
            self.local_asn,
            Ipv4Addr::from(self.state.remote_id.load(Ordering::Relaxed)),
            uptime,
            self.rs_client,
        )));

        let mut addpath = FnvHashSet::default();
        for (family, c) in &codec.channel {
            if c.addpath_rx() {
                addpath.insert(*family);
            }
            pending.insert(*family, crate::peer_tx::PendingTx::new(c.addpath_tx()));
        }

        let export_policy = self.tables.export_policy.load_full();
        for i in 0..self.tables.shards.len() {
            let mut t = self.tables.shards[i].lock().await;

            // Populate initial routes for each negotiated family.
            for f in codec.channel.keys() {
                let effective_max = self
                    .peer_fsm
                    .lock()
                    .unwrap()
                    .session(self.role)
                    .and_then(|s| s.send_max().get(f))
                    .copied()
                    .unwrap_or(1);
                Self::populate_from_shard(
                    &t,
                    *f,
                    effective_max,
                    &export_policy,
                    pending,
                    &mut self.export_map,
                );
            }

            // Register per-peer prefix limits.
            for (f, max) in &self.prefix_limits {
                t.rtable.set_prefix_limit(self.remote_addr, *f, *max);
            }

            t.peer_event_tx
                .insert(self.remote_addr, self.peer_event_tx.remove(0));
            if !addpath.is_empty() {
                t.addpath.insert(self.remote_addr, addpath.clone());
            }

            // Send BMP PeerUp from the first table partition only.
            if i == 0 {
                self.send_bmp_peer_up(&t, remote_asn, uptime, local_sockaddr, remote_sockaddr)
                    .await;
            }
        }
    }

    async fn send_bmp_peer_up(
        &self,
        t: &Table,
        remote_asn: u32,
        uptime: u64,
        local_sockaddr: SocketAddr,
        remote_sockaddr: SocketAddr,
    ) {
        let remote_id = self.state.remote_id.load(Ordering::Relaxed);
        let remote_holdtime = HoldTime::new(self.state.remote_holdtime.load(Ordering::Relaxed))
            .unwrap_or(HoldTime::DISABLED);
        for bmp_tx in t.bmp_event_tx.values() {
            let bmp_msg = bmp::Message::PeerUp {
                header: bmp::PerPeerHeader::new(
                    remote_asn,
                    Ipv4Addr::from(remote_id),
                    0,
                    remote_sockaddr.ip(),
                    uptime as u32,
                ),
                local_addr: self.local_addr,
                local_port: local_sockaddr.port(),
                remote_port: remote_sockaddr.port(),
                remote_open: bgp::Message::Open(bgp::Open {
                    as_number: remote_asn,
                    holdtime: remote_holdtime,
                    router_id: remote_id,
                    // Safe to unwrap: called from on_established() where
                    // remote_cap has just been set by apply_outputs().
                    capability: self.state.remote_cap.load().as_deref().cloned().unwrap(),
                }),
                local_open: bgp::Message::Open(bgp::Open {
                    as_number: remote_asn,
                    holdtime: remote_holdtime,
                    router_id: remote_id,
                    capability: self.local_cap.to_owned(),
                }),
            };
            let _ = bmp_tx.send(bmp_msg);
        }
    }

    fn populate_from_shard(
        t: &Table,
        family: Family,
        effective_max: usize,
        export_policy: &Option<Arc<table::PolicyAssignment>>,
        pending: &mut FnvHashMap<Family, crate::peer_tx::PendingTx>,
        export_map: &mut ExportMap,
    ) {
        for mut c in t.rtable.best(&family).into_iter() {
            if c.rank > effective_max {
                continue;
            }
            if export_policy.as_ref().is_some_and(|a| {
                t.rtable.apply_policy(
                    a,
                    &c.source,
                    &c.net,
                    &c.attr,
                    &mut c.nexthop,
                    c.source.local_addr,
                ) == table::Disposition::Reject
            }) {
                continue;
            }
            let (fam, net) = (c.family, c.net);
            pending.get_mut(&family).unwrap().insert_change(c);
            export_map.mark_sent(fam, net);
        }
    }

    async fn do_route_refresh(&mut self, family: Family, rs: &mut RunState) {
        if !rs.pending.contains_key(&family) {
            return;
        }
        let export_policy = self.tables.export_policy.load_full();
        let effective_max = self
            .peer_fsm
            .lock()
            .unwrap()
            .session(self.role)
            .and_then(|s| s.send_max().get(&family))
            .copied()
            .unwrap_or(1);
        for i in 0..self.tables.shards.len() {
            let t = self.tables.shards[i].lock().await;
            Self::populate_from_shard(
                &t,
                family,
                effective_max,
                &export_policy,
                &mut rs.pending,
                &mut self.export_map,
            );
        }
        rs.pending.get_mut(&family).unwrap().schedule_eor();
    }

    async fn apply_outputs(
        &mut self,
        outputs: Vec<crate::fsm::PeerFsmOutput>,
        rs: &mut RunState,
        local_sockaddr: SocketAddr,
        remote_sockaddr: SocketAddr,
    ) -> Vec<GlobalEffect> {
        let mut effects = Vec::new();
        for output in outputs {
            match output {
                crate::fsm::PeerFsmOutput::Session(role, crate::fsm::Output::SendMessage(m)) => {
                    if role == self.role {
                        rs.urgent.push(m);
                    } else {
                        effects.push(GlobalEffect::SendCease { role, msg: m });
                    }
                }
                crate::fsm::PeerFsmOutput::Session(
                    _,
                    crate::fsm::Output::SetKeepaliveTimer(secs),
                ) => {
                    rs.keepalive_futures = vec![tokio::time::sleep(Duration::from_secs(secs))]
                        .into_iter()
                        .collect();
                }
                crate::fsm::PeerFsmOutput::Session(_, crate::fsm::Output::SetHoldTimer(secs)) => {
                    rs.holdtime_futures = vec![tokio::time::sleep(Duration::from_secs(secs))]
                        .into_iter()
                        .collect();
                }
                crate::fsm::PeerFsmOutput::Session(
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
                                    eprintln!(
                                        "add-path receive configured for {:?} but not negotiated with peer {}",
                                        family, self.remote_addr
                                    );
                                }
                                if mode & 0x2 > 0 && !ch.addpath_tx() {
                                    eprintln!(
                                        "add-path send configured for {:?} but not negotiated with peer {}",
                                        family, self.remote_addr
                                    );
                                }
                            }
                            None => {
                                eprintln!(
                                    "add-path configured for {:?} but family not negotiated with peer {}",
                                    family, self.remote_addr
                                );
                            }
                        }
                    }
                    rs.framer.inner_mut().channel = channels;
                }
                crate::fsm::PeerFsmOutput::Session(
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

                    self.state
                        .remote_cap
                        .store(Some(Arc::new(remote_capabilities)));
                    self.on_established(
                        rs.framer.inner(),
                        local_sockaddr,
                        remote_sockaddr,
                        &mut rs.pending,
                    )
                    .await;
                }
                crate::fsm::PeerFsmOutput::Session(_, crate::fsm::Output::SessionDown(reason)) => {
                    self.shutdown = Some(match reason {
                        crate::fsm::SessionDownReason::HoldTimerExpired => {
                            bmp::PeerDownReason::LocalFsm(0)
                        }
                        crate::fsm::SessionDownReason::RemoteNotification(msg) => {
                            bmp::PeerDownReason::RemoteNotification(msg)
                        }
                        crate::fsm::SessionDownReason::FsmError(_) => {
                            bmp::PeerDownReason::LocalFsm(0)
                        }
                        crate::fsm::SessionDownReason::AdminShutdown => {
                            bmp::PeerDownReason::LocalFsm(0)
                        }
                        crate::fsm::SessionDownReason::IoError => {
                            bmp::PeerDownReason::RemoteUnexpected
                        }
                    });
                }
                crate::fsm::PeerFsmOutput::Session(_, crate::fsm::Output::StateChanged(s)) => {
                    self.state.fsm.store(u8::from(s), Ordering::Relaxed);
                }
                crate::fsm::PeerFsmOutput::Session(_, crate::fsm::Output::RouteRefresh(family)) => {
                    self.do_route_refresh(family, rs).await;
                }
                crate::fsm::PeerFsmOutput::CloseConnection(_) => {
                    self.shutdown = Some(bmp::PeerDownReason::LocalFsm(0));
                }
                crate::fsm::PeerFsmOutput::StopActiveConnect => {
                    effects.push(GlobalEffect::StopActiveConnect);
                }
            }
        }
        effects
    }

    async fn process_effects(
        effects: Vec<GlobalEffect>,
        global: &GlobalHandle,
        remote_addr: IpAddr,
    ) {
        for effect in effects {
            match effect {
                GlobalEffect::SendCease { role, msg } => {
                    let mut g = global.write().await;
                    if let Some(peer) = g.peers.get_mut(&remote_addr) {
                        let tx = match role {
                            crate::fsm::Role::Active => peer.active_close_tx.0.take(),
                            crate::fsm::Role::Passive => peer.passive_close_tx.0.take(),
                        };
                        if let Some(tx) = tx {
                            let _ = tx.send(msg);
                        }
                    }
                }
                GlobalEffect::StopActiveConnect => {
                    let mut g = global.write().await;
                    if let Some(peer) = g.peers.get_mut(&remote_addr) {
                        peer.active_connect_cancel_tx.0.take();
                    }
                }
            }
        }
    }

    async fn flush_tx(&mut self, stream: &mut TcpStream, rs: &mut RunState) {
        // 1. Flush urgent (open, keepalive, notification) messages.
        let mut txbuf = bytes::BytesMut::with_capacity(rs.txbuf_size);
        for _ in 0..rs.urgent.len() {
            let msg = rs.urgent.remove(0);
            let _ = rs.framer.encode_to(&msg, &mut txbuf);
            (*self.counter_tx).sync(&msg);

            if txbuf.len() > rs.txbuf_size {
                let buf = txbuf.freeze();
                txbuf = bytes::BytesMut::with_capacity(rs.txbuf_size);
                if stream.write_all(&buf).await.is_err() {
                    self.shutdown = Some(bmp::PeerDownReason::RemoteUnexpected);
                    return;
                }
            }
        }
        if !txbuf.is_empty() && stream.write_all(&txbuf.freeze()).await.is_err() {
            self.shutdown = Some(bmp::PeerDownReason::RemoteUnexpected);
            return;
        }

        // 2. Drain pending updates (withdrawals, reach, EOR) via peer_tx.
        txbuf = bytes::BytesMut::with_capacity(rs.txbuf_size);
        let any_update_pending = rs.pending.values().any(|p| !p.is_empty());
        for (family, p) in rs.pending.iter_mut() {
            // IPv4-unicast can carry reachability either in the UPDATE's
            // traditional NLRI section or via MP_REACH_NLRI (when RFC 8950
            // Extended Nexthop is negotiated). Every other family must use
            // MP_REACH_NLRI.
            let use_mp = *family != packet::Family::IPV4
                || rs
                    .framer
                    .inner()
                    .channel
                    .get(family)
                    .is_some_and(|c| c.extended_nexthop());
            for msg in p.drain_messages(*family, use_mp) {
                let _ = rs.framer.encode_to(&msg, &mut txbuf);
                self.counter_tx.sync(&msg);

                if txbuf.len() > rs.txbuf_size {
                    let buf = txbuf.freeze();
                    txbuf = bytes::BytesMut::with_capacity(rs.txbuf_size);
                    if stream.write_all(&buf).await.is_err() {
                        self.shutdown = Some(bmp::PeerDownReason::RemoteUnexpected);
                        return;
                    }
                }
            }
        }
        if !txbuf.is_empty() && stream.write_all(&txbuf.freeze()).await.is_err() {
            self.shutdown = Some(bmp::PeerDownReason::RemoteUnexpected);
        }
        if any_update_pending {
            let outputs = self
                .peer_fsm
                .lock()
                .unwrap()
                .process(self.role, crate::fsm::Input::UpdateSent);
            for output in outputs {
                if let crate::fsm::PeerFsmOutput::Session(
                    _,
                    crate::fsm::Output::SetKeepaliveTimer(secs),
                ) = output
                {
                    rs.keepalive_futures = vec![tokio::time::sleep(Duration::from_secs(secs))]
                        .into_iter()
                        .collect();
                }
            }
        }
    }

    async fn rx_update(
        &mut self,
        reach: Option<packet::NlriSet>,
        unreach: Option<packet::NlriSet>,
        attr: Arc<Vec<packet::Attribute>>,
        nexthop: Option<bgp::Nexthop>,
    ) {
        if let Some(s) = reach {
            let family = s.family;
            for net in s.entries {
                let idx = self.tables.dealer(net.nlri);
                self.tables
                    .event(
                        idx,
                        TableEvent::PassUpdate(
                            self.source.as_ref().unwrap().clone(),
                            family,
                            vec![net],
                            Some(attr.clone()),
                            nexthop,
                        ),
                    )
                    .await;
            }
        }
        if let Some(s) = unreach {
            let family = s.family;
            for net in s.entries {
                let idx = self.tables.dealer(net.nlri);
                self.tables
                    .event(
                        idx,
                        TableEvent::PassUpdate(
                            self.source.as_ref().unwrap().clone(),
                            family,
                            vec![net],
                            None,
                            None,
                        ),
                    )
                    .await;
            }
        }
    }

    fn handle_advertise(&mut self, rs: &mut RunState, ri: table::Change) {
        if self.peer_fsm.lock().unwrap().state(self.role) != SessionState::Established {
            return;
        }
        if Arc::ptr_eq(&ri.source, self.source.as_ref().unwrap()) {
            return;
        }
        if !rs.framer.inner().channel.contains_key(&ri.family) {
            return;
        }
        let effective_max = self
            .peer_fsm
            .lock()
            .unwrap()
            .session(self.role)
            .and_then(|s| s.send_max().get(&ri.family))
            .copied()
            .unwrap_or(1);
        if ri.rank > effective_max {
            if self
                .peer_fsm
                .lock()
                .unwrap()
                .session(self.role)
                .is_some_and(|s| s.send_max().contains_key(&ri.family))
                && ri.old_rank > 0
                && ri.old_rank <= effective_max
                && self.export_map.was_sent(ri.family, &ri.net)
            {
                let family = ri.family;
                let net = ri.net;
                self.export_map.mark_withdrawn(family, &net);
                rs.pending
                    .get_mut(&family)
                    .unwrap()
                    .insert_change(table::Change {
                        attr: Arc::new(Vec::new()),
                        ..ri
                    });
            }
            return;
        }
        if ri.attr.is_empty() {
            if self.export_map.was_sent(ri.family, &ri.net) {
                self.export_map.mark_withdrawn(ri.family, &ri.net);
                rs.pending.get_mut(&ri.family).unwrap().insert_change(ri);
            }
        } else {
            self.export_map.mark_sent(ri.family, ri.net);
            rs.pending.get_mut(&ri.family).unwrap().insert_change(ri);
        }
    }

    async fn rx_msg(
        &mut self,
        rs: &mut RunState,
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
            .peer_fsm
            .lock()
            .unwrap()
            .process(self.role, crate::fsm::Input::MessageReceived(msg));
        let has_session_down = outputs.iter().any(|o| {
            matches!(
                o,
                crate::fsm::PeerFsmOutput::Session(_, crate::fsm::Output::SessionDown(_))
            )
        });
        let effects = self
            .apply_outputs(outputs, rs, local_sockaddr, remote_sockaddr)
            .await;
        Self::process_effects(effects, global, self.remote_addr).await;

        // For UPDATE messages: if FSM didn't reject (no SessionDown), process routes.
        if let Some((reach, mp_reach, attr, unreach, mp_unreach, nexthop)) = update_fields {
            if has_session_down {
                return Err(Error::Packet(
                    rustybgp_packet::BgpError::FsmUnexpectedState {
                        state: u8::from(self.peer_fsm.lock().unwrap().state(self.role)),
                    }
                    .into(),
                ));
            }
            self.rx_update(reach, unreach, attr.clone(), nexthop).await;
            self.rx_update(mp_reach, mp_unreach, attr, nexthop).await;
        }
        Ok(())
    }

    async fn run(&mut self, global: &GlobalHandle) -> DisconnectInfo {
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
        let mut txbuf_size = 1 << 16;
        if let Ok(r) =
            nix::sys::socket::getsockopt(&stream.as_fd(), nix::sys::socket::sockopt::SndBuf)
        {
            txbuf_size = std::cmp::min(txbuf_size, r / 2);
        }

        let mut builder = bgp::PeerCodecBuilder::new();
        builder
            .local_asn(self.local_asn)
            .local_addr(self.local_addr);
        if let Some(ll) = self.link_addr {
            builder.link_addr(ll);
        }
        if self.rs_client {
            builder.keep_aspath(true).keep_nexthop(true);
        }
        let framer = BgpFramer::new(builder.build());

        let mut peer_event_rx = Vec::new();
        for _ in 0..self.tables.shards.len() {
            let (tx, rx) = mpsc::unbounded_channel();
            self.peer_event_tx.push(tx);
            peer_event_rx.push(UnboundedReceiverStream::new(rx));
        }

        let mut rs = RunState {
            urgent: Vec::new(),
            framer,
            holdtime_futures: vec![tokio::time::sleep(Duration::new(u64::MAX, 0))]
                .into_iter()
                .collect(),
            keepalive_futures: vec![tokio::time::sleep(Duration::new(u64::MAX, 0))]
                .into_iter()
                .collect(),
            pending: FnvHashMap::default(),
            txbuf_size,
        };

        // Kick off the OPEN exchange via the FSM.
        let outputs = self
            .peer_fsm
            .lock()
            .unwrap()
            .process(self.role, crate::fsm::Input::Connected);
        let effects = self
            .apply_outputs(outputs, &mut rs, local_sockaddr, remote_sockaddr)
            .await;
        Self::process_effects(effects, global, self.remote_addr).await;

        let mut close_rx: futures::future::OptionFuture<_> =
            self.close_rx.take().map(|rx| rx.fuse()).into();
        let mut rxbuf = bytes::BytesMut::with_capacity(rxbuf_size);
        while self.shutdown.is_none() {
            let mut peer_event_futures: FuturesUnordered<_> =
                peer_event_rx.iter_mut().map(|rx| rx.next()).collect();

            let interest = if rs.urgent.is_empty() {
                let mut interest = tokio::io::Interest::READABLE;
                for p in rs.pending.values_mut() {
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
                    if let Some(Ok(msg)) = cease {
                        rs.urgent.insert(0, msg);
                        self.shutdown = Some(bmp::PeerDownReason::LocalFsm(0));
                    }
                }
                _ = rs.holdtime_futures.next() => {
                    println!("{}: holdtime expired", self.remote_addr);
                    let outputs = self.peer_fsm.lock().unwrap().process(self.role, crate::fsm::Input::HoldTimerExpired);
                    let effects = self.apply_outputs(outputs, &mut rs, local_sockaddr, remote_sockaddr).await;
                    Self::process_effects(effects, global, self.remote_addr).await;
                }
                _ = rs.keepalive_futures.next() => {
                    let outputs = self.peer_fsm.lock().unwrap().process(self.role, crate::fsm::Input::KeepaliveTimerExpired);
                    let effects = self.apply_outputs(outputs, &mut rs, local_sockaddr, remote_sockaddr).await;
                    Self::process_effects(effects, global, self.remote_addr).await;
                }
                msg = peer_event_futures.next().fuse() => {
                    if let Some(Some(msg)) = msg {
                        match msg {
                            ToPeerEvent::Advertise(ri) => {
                                self.handle_advertise(&mut rs, ri);
                            }
                        }
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
                                self.shutdown = Some(bmp::PeerDownReason::RemoteUnexpected);
                            }
                            Ok(_) => loop {
                                    match rs.framer.try_parse(&mut rxbuf) {
                                    Ok(msg) => match msg {
                                        Some(msg) => {
                                            (*self.counter_rx).sync(&msg);
                                            let _ = self.rx_msg(&mut rs, global, local_sockaddr, remote_sockaddr, msg).await;
                                        }
                                        None => {
                                            // partial read
                                            break;
                                        },
                                    }
                                    Err(e) => {
                                        if let rustybgp_packet::Error::Bgp(ref bgp_err) = e {
                                            rs.urgent.insert(0, bgp::Message::Notification(bgp_err.clone()));
                                            self.shutdown = Some(bmp::PeerDownReason::LocalNotification(bgp::Message::Notification(bgp_err.clone())));
                                        } else {
                                            self.shutdown = Some(bmp::PeerDownReason::LocalFsm(0));
                                        }
                                        break;
                                    },
                                }
                            }
                            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {},
                            Err(_e) => {
                                self.shutdown = Some(bmp::PeerDownReason::RemoteUnexpected);
                            }
                        }
                    }

                    if ready.is_writable() {
                        self.flush_tx(&mut stream, &mut rs).await;
                    }
                }
            }

            // Hold timer setup is now handled by apply_outputs (SetHoldTimer).
        }
        if let Some(source) = self.source.take() {
            let import_policy = self.tables.import_policy.load_full();
            let export_policy = self.tables.export_policy.load_full();
            let kernel_tx = self.tables.kernel_tx.load_full();
            for i in 0..self.tables.shards.len() {
                let mut t = self.tables.shards[i].lock().await;
                t.peer_event_tx.remove(&self.remote_addr);
                t.addpath.remove(&self.remote_addr);
                t.event(
                    TableEvent::Disconnected(source.clone()),
                    kernel_tx.as_deref(),
                    import_policy.as_deref(),
                    export_policy.as_deref(),
                );
                let reason = self
                    .shutdown
                    .take()
                    .unwrap_or(bmp::PeerDownReason::RemoteUnexpected);
                if i == 0 {
                    for bmp_tx in t.bmp_event_tx.values() {
                        let m = bmp::Message::PeerDown {
                            header: bmp::PerPeerHeader::new(
                                source.remote_asn,
                                Ipv4Addr::from(source.router_id),
                                0,
                                source.remote_addr,
                                source.uptime as u32,
                            ),
                            reason: reason.clone(),
                        };
                        let _ = bmp_tx.send(m);
                    }
                }
            }
        }
        disconnect.export_map = std::mem::take(&mut self.export_map);
        disconnect.negotiated_gr = self.negotiated_gr.take();
        disconnect
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
        Arc::new(Tables::new(1))
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
            g.add_peer(PeerBuilder::new(remote_addr).build(), None)
                .unwrap();
        }

        let h = accept_connection(&global, &tables, server, crate::fsm::Role::Passive).await;
        assert!(h.is_some());

        let g = global.read().await;
        let peer = g.peers.get(&remote_addr).unwrap();
        assert_eq!(
            peer.state.fsm.load(Ordering::Relaxed),
            SessionState::Active as u8
        );
        assert!(peer.passive_close_tx.0.is_some());
    }

    #[tokio::test]
    async fn accept_known_peer_active() {
        let global = make_global();
        let tables = make_tables();
        let (client, server) = loopback_pair().await;
        let remote_addr = client.local_addr().unwrap().ip();

        {
            let mut g = global.write().await;
            g.add_peer(PeerBuilder::new(remote_addr).build(), None)
                .unwrap();
        }

        let h = accept_connection(&global, &tables, server, crate::fsm::Role::Active).await;
        assert!(h.is_some());

        let g = global.read().await;
        let peer = g.peers.get(&remote_addr).unwrap();
        assert!(peer.active_close_tx.0.is_some());
    }

    #[tokio::test]
    async fn accept_admin_down_peer_rejected() {
        let global = make_global();
        let tables = make_tables();
        let (client, server) = loopback_pair().await;
        let remote_addr = client.local_addr().unwrap().ip();

        {
            let mut g = global.write().await;
            g.add_peer(PeerBuilder::new(remote_addr).admin_down(true).build(), None)
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
            g.add_peer(PeerBuilder::new(remote_addr).build(), None)
                .unwrap();
            let (tx, _rx) = tokio::sync::oneshot::channel::<bgp::Message>();
            g.peers.get_mut(&remote_addr).unwrap().passive_close_tx = CloseTx(Some(tx));
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

    fn make_framer() -> BgpFramer {
        BgpFramer::new(
            bgp::PeerCodecBuilder::new()
                .local_asn(65001)
                .local_addr(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
                .build(),
        )
    }

    fn make_timers() -> FuturesUnordered<tokio::time::Sleep> {
        vec![tokio::time::sleep(Duration::new(u64::MAX, 0))]
            .into_iter()
            .collect()
    }

    fn cease_notification() -> bgp::Message {
        bgp::Message::Notification(packet::BgpError::Other {
            code: 6,    // Cease
            subcode: 7, // Connection Collision Resolution
            data: vec![],
        })
    }

    /// Helper: add a peer and return a passive Connection via accept_connection.
    async fn passive_connection(
        global: &GlobalHandle,
        tables: &TableHandle,
        remote_addr: IpAddr,
        server: TcpStream,
    ) -> Connection {
        {
            let mut g = global.write().await;
            g.add_peer(PeerBuilder::new(remote_addr).build(), None)
                .unwrap();
        }
        accept_connection(global, tables, server, crate::fsm::Role::Passive)
            .await
            .unwrap()
    }

    /// Returns a Connection with the Passive FSM driven to Established and source set.
    async fn established_connection(
        global: &GlobalHandle,
        tables: &TableHandle,
        remote_addr: IpAddr,
        server: TcpStream,
    ) -> Connection {
        let mut conn = passive_connection(global, tables, remote_addr, server).await;
        {
            let peer_fsm = Arc::clone(&conn.peer_fsm);
            let open = bgp::Message::Open(bgp::Open {
                as_number: 65002,
                holdtime: HoldTime::new(90).unwrap(),
                router_id: u32::from(Ipv4Addr::new(10, 0, 0, 1)),
                capability: vec![],
            });
            let mut fsm = peer_fsm.lock().unwrap();
            fsm.process(crate::fsm::Role::Passive, crate::fsm::Input::Connected);
            fsm.process(
                crate::fsm::Role::Passive,
                crate::fsm::Input::MessageReceived(open),
            );
            fsm.process(
                crate::fsm::Role::Passive,
                crate::fsm::Input::MessageReceived(bgp::Message::Keepalive),
            );
        }
        conn.source = Some(Arc::new(table::Source::new(
            remote_addr,
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            65002,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            0,
            false,
        )));
        conn
    }

    fn make_rs_ipv4() -> RunState {
        let mut pending = FnvHashMap::default();
        pending.insert(Family::IPV4, crate::peer_tx::PendingTx::new(false));
        RunState {
            urgent: Vec::new(),
            framer: BgpFramer::new(
                bgp::PeerCodecBuilder::new()
                    .local_asn(65001)
                    .local_addr(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
                    .families(vec![Family::IPV4])
                    .build(),
            ),
            keepalive_futures: make_timers(),
            holdtime_futures: make_timers(),
            pending,
            txbuf_size: 1 << 16,
        }
    }

    fn make_reach_change(nlri: packet::Nlri, source: Arc<table::Source>) -> table::Change {
        table::Change {
            source,
            family: Family::IPV4,
            net: nlri,
            nexthop: bgp::Nexthop::V4(Ipv4Addr::new(1, 1, 1, 1)),
            attr: Arc::new(vec![
                packet::Attribute::new_with_value(packet::Attribute::ORIGIN, 0).unwrap(),
            ]),
            path_id: 0,
            rank: 1,
            old_rank: 0,
        }
    }

    fn make_withdraw_change(nlri: packet::Nlri, source: Arc<table::Source>) -> table::Change {
        table::Change {
            source,
            family: Family::IPV4,
            net: nlri,
            nexthop: bgp::Nexthop::V4(Ipv4Addr::new(1, 1, 1, 1)),
            attr: Arc::new(vec![]),
            path_id: 0,
            rank: 1,
            old_rank: 0,
        }
    }

    fn other_source() -> Arc<table::Source> {
        Arc::new(table::Source::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            65002,
            65001,
            Ipv4Addr::new(10, 0, 0, 2),
            0,
            false,
        ))
    }

    #[tokio::test]
    async fn handle_advertise_reach_tracked_in_export_map() {
        let global = make_global();
        let tables = make_tables();
        let (client, server) = loopback_pair().await;
        let remote_addr = client.local_addr().unwrap().ip();

        let mut conn = established_connection(&global, &tables, remote_addr, server).await;
        let mut rs = make_rs_ipv4();
        let nlri: packet::Nlri = "10.0.0.0/24".parse().unwrap();
        let ri = make_reach_change(nlri, other_source());

        conn.handle_advertise(&mut rs, ri);

        assert!(conn.export_map.was_sent(Family::IPV4, &nlri));
        assert!(!rs.pending[&Family::IPV4].is_empty());
    }

    #[tokio::test]
    async fn handle_advertise_spurious_withdraw_suppressed() {
        let global = make_global();
        let tables = make_tables();
        let (client, server) = loopback_pair().await;
        let remote_addr = client.local_addr().unwrap().ip();

        let mut conn = established_connection(&global, &tables, remote_addr, server).await;
        let mut rs = make_rs_ipv4();
        let nlri: packet::Nlri = "10.0.0.0/24".parse().unwrap();
        let ri = make_withdraw_change(nlri, other_source());

        conn.handle_advertise(&mut rs, ri);

        assert!(!conn.export_map.was_sent(Family::IPV4, &nlri));
        assert!(rs.pending[&Family::IPV4].is_empty());
    }

    #[tokio::test]
    async fn handle_advertise_known_withdraw_forwarded_and_export_map_cleared() {
        let global = make_global();
        let tables = make_tables();
        let (client, server) = loopback_pair().await;
        let remote_addr = client.local_addr().unwrap().ip();

        let mut conn = established_connection(&global, &tables, remote_addr, server).await;
        let mut rs = make_rs_ipv4();
        let nlri: packet::Nlri = "10.0.0.0/24".parse().unwrap();

        conn.export_map.mark_sent(Family::IPV4, nlri);
        let ri = make_withdraw_change(nlri, other_source());
        conn.handle_advertise(&mut rs, ri);

        assert!(!conn.export_map.was_sent(Family::IPV4, &nlri));
        assert!(!rs.pending[&Family::IPV4].is_empty());
    }

    #[tokio::test]
    async fn handle_advertise_noop_when_not_established() {
        let global = make_global();
        let tables = make_tables();
        let (client, server) = loopback_pair().await;
        let remote_addr = client.local_addr().unwrap().ip();

        // passive_connection gives Active state, not Established
        let mut conn = passive_connection(&global, &tables, remote_addr, server).await;
        let mut rs = make_rs_ipv4();
        let nlri: packet::Nlri = "10.0.0.0/24".parse().unwrap();
        let ri = make_reach_change(nlri, other_source());

        conn.handle_advertise(&mut rs, ri);

        assert!(!conn.export_map.was_sent(Family::IPV4, &nlri));
        assert!(rs.pending[&Family::IPV4].is_empty());
    }

    /// `apply_outputs` must return `GlobalEffect::SendCease` for a `SendMessage`
    /// output targeting the other role, without touching global state.
    #[tokio::test]
    async fn apply_outputs_returns_send_cease_for_other_role() {
        let global = make_global();
        let tables = make_tables();
        let (client, server) = loopback_pair().await;
        let remote_addr = client.local_addr().unwrap().ip();

        let mut conn = passive_connection(&global, &tables, remote_addr, server).await;

        let outputs = vec![crate::fsm::PeerFsmOutput::Session(
            crate::fsm::Role::Active,
            crate::fsm::Output::SendMessage(cease_notification()),
        )];
        let dummy: SocketAddr = "127.0.0.1:179".parse().unwrap();
        let mut rs = RunState {
            urgent: Vec::new(),
            framer: make_framer(),
            keepalive_futures: make_timers(),
            holdtime_futures: make_timers(),
            pending: FnvHashMap::default(),
            txbuf_size: 1 << 16,
        };
        let effects = conn.apply_outputs(outputs, &mut rs, dummy, dummy).await;

        assert_eq!(effects.len(), 1);
        assert!(matches!(
            effects[0],
            GlobalEffect::SendCease {
                role: crate::fsm::Role::Active,
                ..
            }
        ));
    }

    /// `apply_outputs` + `process_effects` must deliver the CEASE message to the
    /// losing connection's oneshot channel.
    #[tokio::test]
    async fn collision_cease_dispatched_to_loser() {
        // NOTE: outputs are hand-crafted; router-ID comparison is NOT exercised here.
        // See collision_loser_determined_by_router_id for end-to-end coverage.
        let global = make_global();
        let tables = make_tables();
        let (client, server) = loopback_pair().await;
        let remote_addr = client.local_addr().unwrap().ip();

        let mut conn = passive_connection(&global, &tables, remote_addr, server).await;

        // Simulate the losing active connection by pre-installing its close_tx.
        let (active_close_tx, mut active_close_rx) =
            tokio::sync::oneshot::channel::<bgp::Message>();
        {
            let mut g = global.write().await;
            g.peers.get_mut(&remote_addr).unwrap().active_close_tx = CloseTx(Some(active_close_tx));
        }

        let outputs = vec![crate::fsm::PeerFsmOutput::Session(
            crate::fsm::Role::Active,
            crate::fsm::Output::SendMessage(cease_notification()),
        )];
        let dummy: SocketAddr = "127.0.0.1:179".parse().unwrap();
        let mut rs = RunState {
            urgent: Vec::new(),
            framer: make_framer(),
            keepalive_futures: make_timers(),
            holdtime_futures: make_timers(),
            pending: FnvHashMap::default(),
            txbuf_size: 1 << 16,
        };
        let effects = conn.apply_outputs(outputs, &mut rs, dummy, dummy).await;
        Connection::process_effects(effects, &global, remote_addr).await;

        let received = active_close_rx
            .try_recv()
            .expect("CEASE not delivered to loser");
        assert!(matches!(received, bgp::Message::Notification(_)));
    }

    /// End-to-end collision test: the loser is determined by real router-ID comparison
    /// inside `PeerFsm::check_collision`, not by hand-crafted outputs.
    ///
    /// make_global() sets local router_id = 1.0.0.1.
    /// Remote router_id = 10.0.0.1 (higher) → passive wins → active is the loser.
    #[tokio::test]
    async fn collision_loser_determined_by_router_id() {
        let global = make_global(); // local router_id = 1.0.0.1
        let tables = make_tables();
        let (client, server) = loopback_pair().await;
        let remote_addr = client.local_addr().unwrap().ip();

        let mut conn = passive_connection(&global, &tables, remote_addr, server).await;

        // Pre-install active_close_tx so process_effects can deliver to it.
        let (active_close_tx, mut active_close_rx) =
            tokio::sync::oneshot::channel::<bgp::Message>();
        {
            let mut g = global.write().await;
            g.peers.get_mut(&remote_addr).unwrap().active_close_tx = CloseTx(Some(active_close_tx));
        }

        // remote router_id 10.0.0.1 > local 1.0.0.1 → passive wins → active is loser
        let open_msg = bgp::Message::Open(bgp::Open {
            as_number: 65001,
            holdtime: HoldTime::new(90).unwrap(),
            router_id: u32::from(Ipv4Addr::new(10, 0, 0, 1)),
            capability: vec![],
        });

        let peer_fsm = {
            let g = global.read().await;
            Arc::clone(g.peers[&remote_addr].peer_fsm.as_ref().unwrap())
        };

        // Active → OpenConfirm
        peer_fsm
            .lock()
            .unwrap()
            .process(crate::fsm::Role::Active, crate::fsm::Input::Connected);
        peer_fsm.lock().unwrap().process(
            crate::fsm::Role::Active,
            crate::fsm::Input::MessageReceived(open_msg.clone()),
        );

        // Passive → OpenConfirm → collision detected → outputs include SendMessage to Active
        peer_fsm
            .lock()
            .unwrap()
            .process(crate::fsm::Role::Passive, crate::fsm::Input::Connected);
        let outputs = peer_fsm.lock().unwrap().process(
            crate::fsm::Role::Passive,
            crate::fsm::Input::MessageReceived(open_msg),
        );

        let dummy: SocketAddr = "127.0.0.1:179".parse().unwrap();
        let mut rs = RunState {
            urgent: Vec::new(),
            framer: make_framer(),
            keepalive_futures: make_timers(),
            holdtime_futures: make_timers(),
            pending: FnvHashMap::default(),
            txbuf_size: 1 << 16,
        };
        let effects = conn.apply_outputs(outputs, &mut rs, dummy, dummy).await;
        Connection::process_effects(effects, &global, remote_addr).await;

        let received = active_close_rx
            .try_recv()
            .expect("CEASE not delivered to active (loser)");
        assert!(matches!(received, bgp::Message::Notification(_)));
    }

    #[test]
    fn export_map_mark_and_check() {
        let nlri: packet::Nlri = "10.0.0.0/24".parse().unwrap();
        let mut m = ExportMap::new();
        assert!(!m.was_sent(Family::IPV4, &nlri));
        m.mark_sent(Family::IPV4, nlri);
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
        m.mark_sent(Family::IPV4, nlri);
        assert!(m.was_sent(Family::IPV4, &nlri));
        m.mark_withdrawn(Family::IPV4, &nlri);
        assert!(!m.was_sent(Family::IPV4, &nlri));
    }

    #[test]
    fn export_map_multiple_families_independent() {
        let v4: packet::Nlri = "10.0.0.0/8".parse().unwrap();
        let v6: packet::Nlri = "2001:db8::/32".parse().unwrap();
        let mut m = ExportMap::new();
        m.mark_sent(Family::IPV4, v4);
        assert!(m.was_sent(Family::IPV4, &v4));
        assert!(!m.was_sent(Family::IPV6, &v4));
        m.mark_sent(Family::IPV6, v6);
        assert!(m.was_sent(Family::IPV6, &v6));
        assert!(!m.was_sent(Family::IPV4, &v6));
    }
}
