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

#![allow(clippy::too_many_arguments)]

use arc_swap::ArcSwapOption;
use fnv::{FnvHashMap, FnvHashSet, FnvHasher};
use futures::stream::FuturesUnordered;
use futures::{FutureExt, SinkExt, Stream, StreamExt};
use tracing::Instrument;
use once_cell::sync::Lazy;
use std::boxed::Box;
use std::collections::HashSet;
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::convert::{From, TryFrom};
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
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
use tokio::sync::{Mutex, RwLock, mpsc};
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
        self.total.fetch_add(1, Ordering::SeqCst);
        ret
    }
}

#[derive(PartialEq, Clone, Copy)]
enum SessionState {
    Idle,
    Connect,
    Active,
    OpenSent,
    OpenConfirm,
    Established,
}

fn session_state_to_api(v: u8) -> api::peer_state::SessionState {
    match v {
        0 => api::peer_state::SessionState::Idle,
        1 => api::peer_state::SessionState::Connect,
        2 => api::peer_state::SessionState::Active,
        3 => api::peer_state::SessionState::Opensent,
        4 => api::peer_state::SessionState::Openconfirm,
        5 => api::peer_state::SessionState::Established,
        _ => panic!("unexpected session state {}", v),
    }
}

impl From<SessionState> for u8 {
    fn from(s: SessionState) -> Self {
        match s {
            SessionState::Idle => 0,
            SessionState::Connect => 1,
            SessionState::Active => 2,
            SessionState::OpenSent => 3,
            SessionState::OpenConfirm => 4,
            SessionState::Established => 5,
        }
    }
}

struct PeerState {
    fsm: AtomicU8,
    uptime: AtomicU64,
    downtime: AtomicU64,
    remote_asn: AtomicU32,
    remote_id: AtomicU32,
    remote_holdtime: AtomicU16,
    remote_cap: RwLock<Vec<packet::Capability>>,
}

#[derive(Clone)]
struct Peer {
    /// if a peer was removed and created again quickly,
    /// we could run multiple tasks for active connection
    configured_time: u64,

    remote_addr: IpAddr,
    remote_port: u16,
    local_asn: u32,
    passive: bool,
    admin_down: bool,
    delete_on_disconnected: bool,

    remote_sockaddr: SocketAddr,
    local_sockaddr: SocketAddr,

    holdtime: u64,
    connect_retry_time: u64,

    state: Arc<PeerState>,

    counter_tx: Arc<MessageCounter>,
    counter_rx: Arc<MessageCounter>,

    // received and accepted
    route_stats: FnvHashMap<Family, (u64, u64)>,

    local_cap: Vec<packet::Capability>,

    route_server_client: bool,
    multihop_ttl: Option<u8>,
    password: Option<String>,

    mgmt_tx: Option<mpsc::UnboundedSender<PeerMgmtMsg>>,
    /// Per-family send_max for Add-Path TX (RFC 7911).
    send_max: FnvHashMap<Family, usize>,
    /// Per-family prefix limits from config.
    prefix_limits: FnvHashMap<Family, u32>,
}

impl Peer {
    fn update_stats(&mut self, rti: FnvHashMap<Family, (u64, u64)>) {
        for (f, v) in rti {
            let stats = self.route_stats.entry(f).or_insert((0, 0));
            stats.0 += v.0;
            stats.1 += v.1;
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
        loop {
            if let Ok(mut a) = self.state.remote_cap.try_write() {
                a.clear();
                break;
            }
        }
        self.state.remote_id.store(0, Ordering::Relaxed);
        self.state.remote_holdtime.store(0, Ordering::Relaxed);

        self.state
            .fsm
            .store(SessionState::Idle as u8, Ordering::Relaxed);
        self.route_stats = FnvHashMap::default();
        self.mgmt_tx = None;
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
    ctrl_channel: Option<mpsc::UnboundedSender<PeerMgmtMsg>>,
    multihop_ttl: Option<u8>,
    password: Option<String>,
    families: FnvHashMap<Family, u8>,
    send_max: FnvHashMap<Family, usize>,
    prefix_limits: FnvHashMap<Family, u32>,
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
            ctrl_channel: None,
            multihop_ttl: None,
            password: None,
            families: Default::default(),
            send_max: Default::default(),
            prefix_limits: Default::default(),
        }
    }

    fn ctrl_channel(&mut self, tx: mpsc::UnboundedSender<PeerMgmtMsg>) -> &mut Self {
        self.ctrl_channel = Some(tx);
        self
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
        Peer {
            remote_addr: self.remote_addr,
            configured_time: SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            remote_port: if self.remote_port != 0 {
                self.remote_port
            } else {
                Global::BGP_PORT
            },
            local_sockaddr: self.local_sockaddr,
            remote_sockaddr: self.remote_sockaddr,
            local_asn: self.local_asn,
            passive: self.passive,
            delete_on_disconnected: self.delete_on_disconnected,
            admin_down: self.admin_down,
            holdtime: self.holdtime,
            connect_retry_time: self.connect_retry_time,
            state: Arc::new(PeerState {
                fsm: AtomicU8::new(self.state as u8),
                uptime: AtomicU64::new(0),
                downtime: AtomicU64::new(0),
                remote_asn: AtomicU32::new(self.remote_asn),
                remote_id: AtomicU32::new(0),
                remote_holdtime: AtomicU16::new(0),
                remote_cap: RwLock::new(Vec::new()),
            }),
            route_stats: FnvHashMap::default(),
            local_cap: self.local_cap.split_off(0),
            route_server_client: self.rs_client,
            mgmt_tx: self.ctrl_channel.take(),
            counter_tx: Default::default(),
            counter_rx: Default::default(),
            multihop_ttl: self.multihop_ttl.take(),
            password: self.password.take(),
            send_max: std::mem::take(&mut self.send_max),
            prefix_limits: std::mem::take(&mut self.prefix_limits),
        }
    }
}

impl From<&Peer> for api::Peer {
    fn from(p: &Peer) -> Self {
        let session_state = p.state.fsm.load(Ordering::Acquire);
        let remote_cap = {
            let mut v = Vec::new();
            loop {
                if let Ok(a) = p.state.remote_cap.try_read() {
                    v.append(&mut a.iter().map(convert::capability_to_api).collect());
                    break;
                }
            }
            v
        };
        let mut ps = api::PeerState {
            neighbor_address: p.remote_addr.to_string(),
            peer_asn: p.state.remote_asn.load(Ordering::Relaxed),
            local_asn: p.local_asn,
            router_id: Ipv4Addr::from(p.state.remote_id.load(Ordering::Relaxed)).to_string(),
            messages: Some(api::Messages {
                received: Some((&*p.counter_rx).into()),
                sent: Some((&*p.counter_tx).into()),
            }),
            queues: Some(Default::default()),
            remote_cap,
            local_cap: p.local_cap.iter().map(convert::capability_to_api).collect(),
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
                hold_time: p.holdtime,
                keepalive_interval: p.holdtime / 3,
                ..Default::default()
            }),
            state: Some(Default::default()),
        };
        let uptime = p.state.uptime.load(Ordering::Relaxed);
        if uptime != 0 {
            let negotiated_holdtime = std::cmp::min(
                p.holdtime,
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
                route_server_client: p.route_server_client,
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
                if (f == &config::generate::AfiSafiType::Ipv4Unicast
                    || f == &config::generate::AfiSafiType::Ipv6Unicast)
                    && let Ok(family) = convert::family_from_config(f)
                {
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

        let addr_str = c
            .neighbor_address
            .as_ref()
            .ok_or("missing neighbor address")?;
        let addr = addr_str
            .parse()
            .map_err(|e| format!("invalid neighbor address: {}", e))?;
        let peer_as = c.peer_as.ok_or("missing peer-as")?;

        let transport_config = n.transport.as_ref().and_then(|t| t.config.as_ref());
        let timer_config = n.timers.as_ref().and_then(|t| t.config.as_ref());

        let mut builder = PeerBuilder::new(addr);
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
}

impl GrpcService {
    fn new(
        init: Arc<tokio::sync::Notify>,
        active_conn_tx: mpsc::UnboundedSender<TcpStream>,
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
        }
    }

    async fn is_available(&self, need_active: bool) -> Result<(), Error> {
        let global = &GLOBAL.read().await;
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
        for a in path.pattrs {
            let a = convert::attr_from_api(a).map_err(|_| {
                tonic::Status::new(tonic::Code::InvalidArgument, "invalid attribute")
            })?;
            if a.code() == bgp::Attribute::MP_REACH {
                attr.push(
                    bgp::Attribute::new_with_bin(
                        bgp::Attribute::NEXTHOP,
                        a.binary().unwrap().to_owned(),
                    )
                    .unwrap(),
                );
            } else {
                attr.push(a);
            }
        }
        Ok((
            Table::dealer(net),
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

        let global = &mut GLOBAL.write().await;
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
        let global = (GLOBAL.read().await.deref()).into();

        Ok(tonic::Response::new(api::GetBgpResponse {
            global: Some(global),
        }))
    }
    async fn add_peer(
        &self,
        request: tonic::Request<api::AddPeerRequest>,
    ) -> Result<tonic::Response<api::AddPeerResponse>, tonic::Status> {
        let peer = Peer::try_from(&request.into_inner().peer.ok_or(Error::EmptyArgument)?)?;
        tracing::info!(peer = %peer.remote_addr, "gRPC: adding peer");
        let mut global = GLOBAL.write().await;
        if let Some(password) = peer.password.as_ref() {
            for fd in &global.listen_sockets {
                auth::set_md5sig(*fd, &peer.remote_addr, password);
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
            tracing::info!(peer = %peer_addr, "gRPC: deleting peer");
            let mut global = GLOBAL.write().await;
            if let Some(p) = global.peers.remove(&peer_addr) {
                if let Some(mgmt_tx) = &p.mgmt_tx {
                    if mgmt_tx.send(PeerMgmtMsg::Notification(bgp::Message::Notification(
                        rustybgp_packet::BgpError::Other {
                            code: 6,
                            subcode: 3,
                            data: vec![],
                        },
                    ))).is_err() {
                        tracing::warn!(peer = %peer_addr, "failed to send cease notification to peer handler");
                    }
                }
                if p.password.is_some() {
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
        let mut peers: FnvHashMap<IpAddr, Peer> = GLOBAL
            .read()
            .await
            .peers
            .iter()
            .map(|(a, p)| (*a, p.clone()))
            .collect();

        for i in 0..*NUM_TABLES {
            let t = TABLE[i].lock().await;
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
            for (addr, p) in &mut GLOBAL.write().await.peers {
                if addr == &peer_addr {
                    if p.admin_down {
                        tracing::info!(peer = %peer_addr, "gRPC: enabling peer");
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
            for (addr, p) in &mut GLOBAL.write().await.peers {
                if addr == &peer_addr {
                    if p.admin_down {
                        return Err(tonic::Status::new(
                            tonic::Code::InvalidArgument,
                            "peer is already admin-down",
                        ));
                    } else {
                        tracing::info!(peer = %peer_addr, "gRPC: disabling peer");
                        p.admin_down = true;
                        if let Some(mgmt_tx) = &p.mgmt_tx {
                            if mgmt_tx.send(PeerMgmtMsg::Notification(
                                bgp::Message::Notification(rustybgp_packet::BgpError::Other {
                                    code: 6,
                                    subcode: 2,
                                    data: vec![],
                                }),
                            )).is_err() {
                                tracing::warn!(peer = %peer_addr, "failed to send admin-down notification to peer handler");
                            }
                            return Ok(tonic::Response::new(api::DisablePeerResponse {}));
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
            for i in 0..*NUM_TABLES {
                let mut t = TABLE[i].lock().await;
                t.bmp_event_tx.insert(sockaddr, bmp_tx.clone());
            }

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
                for i in 0..*NUM_TABLES {
                    let mut t = TABLE[i].lock().await;
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

        match GLOBAL
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

        let global = &mut GLOBAL.write().await;
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
        let chan = TABLE[u.0].lock().await.table_event_tx[0].clone();
        let _ = chan.send(u.1);
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
        let chan = TABLE[u.0].lock().await.table_event_tx[0].clone();
        let _ = chan.send(u.1);
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
            GLOBAL_EXPORT_POLICY.load_full()
        } else {
            None
        };
        for i in 0..*NUM_TABLES {
            let t = TABLE[i].lock().await;
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
                    let chan = TABLE[u.0].lock().await.table_event_tx[0].clone();
                    let _ = chan.send(u.1);
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
        for i in 0..*NUM_TABLES {
            let t = TABLE[i].lock().await;
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
        GLOBAL
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
        let v: Vec<api::ListPolicyResponse> = GLOBAL
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
        GLOBAL
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
        let v: Vec<api::ListDefinedSetResponse> = GLOBAL
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
        let disposition = convert::disposition_from_api(statement.actions).map_err(Error::from)?;
        GLOBAL
            .write()
            .await
            .ptable
            .add_statement(&statement.name, conditions, disposition)
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
        let v: Vec<api::ListStatementResponse> = GLOBAL
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
        add_policy_assignment(request).await?;
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
        let v: Vec<api::ListPolicyAssignmentResponse> = GLOBAL
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
        match GLOBAL.write().await.rpki_clients.entry(sockaddr) {
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
                RpkiClient::try_connect(sockaddr, t);
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

        let tx = if let Some(mut client) = GLOBAL.write().await.rpki_clients.remove(&sockaddr) {
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

        for (sockaddr, client) in &GLOBAL.read().await.rpki_clients {
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
            let t = TABLE[0].lock().await;
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

        let v: Vec<api::ListRpkiTableResponse> = TABLE[0]
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
        tokio::spawn(async move {
            let mut d = MrtDumper::new(&request.filename, interval);
            d.serve().await;
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
        match GLOBAL.write().await.bmp_clients.entry(sockaddr) {
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
                BmpClient::try_connect(sockaddr, t);
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
        let v = GLOBAL
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
        request: tonic::Request<api::SetLogLevelRequest>,
    ) -> Result<tonic::Response<api::SetLogLevelResponse>, tonic::Status> {
        use tracing_subscriber::EnvFilter;

        let req = request.into_inner();
        let level_enum = api::set_log_level_request::Level::try_from(req.level)
            .unwrap_or(api::set_log_level_request::Level::Unspecified);
        let filter_str = match level_enum {
            api::set_log_level_request::Level::Panic
            | api::set_log_level_request::Level::Fatal
            | api::set_log_level_request::Level::Error => "error",
            api::set_log_level_request::Level::Warn => "warn",
            api::set_log_level_request::Level::Info => "info",
            api::set_log_level_request::Level::Debug => "debug",
            api::set_log_level_request::Level::Trace => "trace",
            api::set_log_level_request::Level::Unspecified => {
                return Err(tonic::Status::invalid_argument("log level not specified"));
            }
        };
        let new_filter = EnvFilter::new(filter_str);
        let handle = crate::LOG_RELOAD_HANDLE
            .get()
            .ok_or_else(|| tonic::Status::internal("log reload handle not initialized"))?;
        handle
            .reload(new_filter)
            .map_err(|e| tonic::Status::internal(format!("failed to reload log filter: {}", e)))?;
        tracing::info!(level = filter_str, "log level changed via gRPC");
        Ok(tonic::Response::new(api::SetLogLevelResponse {}))
    }
}

async fn add_policy_assignment(req: api::PolicyAssignment) -> Result<(), Error> {
    let (name, direction, default_action, policy_names) = convert::policy_assignment_from_api(req)?;
    let (dir, assignment) = GLOBAL.write().await.ptable.add_assignment(
        &name,
        direction,
        default_action,
        policy_names,
    )?;
    if dir == table::PolicyDirection::Import {
        GLOBAL_IMPORT_POLICY.store(Some(Arc::clone(&assignment)));
    } else {
        GLOBAL_EXPORT_POLICY.store(Some(Arc::clone(&assignment)));
    }
    Ok(())
}

enum ToPeerEvent {
    Advertise(table::Change),
}

enum PeerMgmtMsg {
    Notification(bgp::Message),
}

fn enable_active_connect(peer: &Peer, ch: mpsc::UnboundedSender<TcpStream>) {
    if peer.admin_down || peer.passive || peer.delete_on_disconnected {
        return;
    }
    let peer_addr = peer.remote_addr;
    let remote_port = peer.remote_port;
    let configured_time = peer.configured_time;
    let sockaddr = std::net::SocketAddr::new(peer_addr, remote_port);
    let retry_time = peer.connect_retry_time;
    let password = peer.password.as_ref().map(|x| x.to_string());
    tracing::debug!(peer = %peer_addr, port = remote_port, "initiating active connection attempts");
    tokio::spawn(async move {
        loop {
            let socket = match peer_addr {
                IpAddr::V4(_) => tokio::net::TcpSocket::new_v4().unwrap(),
                IpAddr::V6(_) => tokio::net::TcpSocket::new_v6().unwrap(),
            };
            if let Some(key) = password.as_ref() {
                auth::set_md5sig(socket.as_raw_fd(), &peer_addr, key);
            }
            if let Ok(Ok(stream)) = tokio::time::timeout(
                tokio::time::Duration::from_secs(5),
                socket.connect(sockaddr),
            )
            .await
            {
                tracing::debug!(peer = %peer_addr, "active TCP connection established");
                let _ = ch.send(stream);
                return;
            }
            tracing::debug!(peer = %peer_addr, retry_secs = retry_time, "active connect failed, retrying");
            tokio::time::sleep(tokio::time::Duration::from_secs(retry_time)).await;
            {
                let server = GLOBAL.write().await;
                if let Some(peer) = server.peers.get(&peer_addr) {
                    if peer.configured_time != configured_time || peer.mgmt_tx.is_some() {
                        return;
                    }
                } else {
                    return;
                }
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

    async fn serve(&mut self) {
        let mut file = tokio::fs::File::create(std::path::Path::new(&self.pathname()))
            .await
            .unwrap();

        let (tx, rx) = mpsc::unbounded_channel();
        for i in 0..*NUM_TABLES {
            let mut t = TABLE[i].lock().await;
            t.mrt_event_tx = Some(tx.clone());
        }

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
                    if let Some(msg) = msg {
                        let mut buf = bytes::BytesMut::with_capacity(8192);
                        if let Err(e) = codec.encode(&msg, &mut buf) {
                            tracing::error!(error = %e, "MRT message encode failed");
                            continue;
                        }
                        if let Err(e) = file.write_all(&buf).await {
                            tracing::error!(error = %e, "MRT file write failed");
                        }
                    }
                }
                _ = timer.tick().fuse() => {
                    if self.interval != 0 {
                        file = tokio::fs::File::create(std::path::Path::new(&self.pathname()))
                        .await
                        .unwrap();
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

    async fn serve(stream: TcpStream, sockaddr: SocketAddr) {
        tracing::info!(%sockaddr, "BMP client connected");
        let mut lines = Framed::new(stream, bmp::BmpCodec::new());
        let sysname = hostname::get().unwrap_or_else(|_| std::ffi::OsString::from("unknown"));
        if let Err(e) = lines
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
            .await
        {
            tracing::warn!(%sockaddr, error = %e, "failed to send BMP initiation message");
        }

        let (tx, rx) = mpsc::unbounded_channel();
        let mut adjin = FnvHashMap::default();
        for i in 0..*NUM_TABLES {
            let mut t = TABLE[i].lock().await;
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
        let local_id = GLOBAL.read().await.router_id;
        let mut established_peers = Vec::new();
        for peer in GLOBAL.read().await.peers.values() {
            if peer.state.fsm.load(Ordering::Acquire) == SessionState::Established as u8 {
                established_peers.push(peer.remote_addr);
                let remote_asn = peer.state.remote_asn.load(Ordering::Relaxed);
                let remote_id = Ipv4Addr::from(peer.state.remote_id.load(Ordering::Relaxed));
                let m = bmp::Message::PeerUp {
                    header: bmp::PerPeerHeader::new(
                        remote_asn,
                        remote_id,
                        0,
                        peer.remote_addr,
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
                        capability: peer.state.remote_cap.read().await.to_owned(),
                    }),
                    local_open: bgp::Message::Open(bgp::Open {
                        as_number: peer.local_asn,
                        holdtime: HoldTime::new(peer.holdtime as u16).unwrap_or(HoldTime::DISABLED),
                        router_id: u32::from(local_id),
                        capability: peer.local_cap.to_owned(),
                    }),
                };
                if lines.send(&m).await.is_err() {
                    tracing::warn!(%sockaddr, "BMP PeerUp send failed, disconnecting");
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
                            Err(e) => {
                                tracing::warn!(%sockaddr, error = %e, "BMP framing error");
                                break;
                            }
                        },
                        None => break,
                    };
                }
                msg = rx.next() => {
                    if let Some(msg) = msg {
                        if lines.send(&msg).await.is_err() {
                            tracing::warn!(%sockaddr, "BMP event send failed, disconnecting");
                            break;
                        }
                    } else {
                        break;
                    }
                }
            }
        }
        tracing::info!(%sockaddr, "BMP client disconnected");
        for i in 0..*NUM_TABLES {
            let mut t = TABLE[i].lock().await;
            let _ = t.bmp_event_tx.remove(&sockaddr);
        }
    }

    fn try_connect(sockaddr: SocketAddr, configured_time: u64) {
        tokio::spawn(async move {
            loop {
                tracing::debug!(%sockaddr, "BMP connecting");
                if let Ok(Ok(stream)) = tokio::time::timeout(
                    tokio::time::Duration::from_secs(5),
                    TcpStream::connect(sockaddr),
                )
                .await
                {
                    if let Some(client) = GLOBAL.write().await.bmp_clients.get_mut(&sockaddr) {
                        client.uptime = SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs();
                    } else {
                        break;
                    }
                    BmpClient::serve(stream, sockaddr).await;
                    if let Some(client) = GLOBAL.write().await.bmp_clients.get_mut(&sockaddr) {
                        client.downtime = SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs();
                    } else {
                        break;
                    }
                } else {
                    tracing::debug!(%sockaddr, "BMP connection attempt failed, retrying in 10s");
                }
                tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                if let Some(client) = GLOBAL.write().await.bmp_clients.get_mut(&sockaddr) {
                    if client.configured_time != configured_time {
                        tracing::debug!(%sockaddr, "BMP client reconfigured, stopping retry");
                        break;
                    }
                } else {
                    tracing::debug!(%sockaddr, "BMP client deconfigured, stopping retry");
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
        txv: Vec<mpsc::UnboundedSender<TableEvent>>,
        state: Arc<RpkiState>,
    ) -> Result<(), Error> {
        let remote_addr = stream.peer_addr()?.ip();
        tracing::info!(rpki_server = %remote_addr, "RPKI client connected");
        let remote_addr = Arc::new(remote_addr);
        let mut lines = Framed::new(stream, rpki::RtrCodec::new());
        if let Err(e) = lines.send(&rpki::Message::ResetQuery).await {
            tracing::warn!(rpki_server = %remote_addr, error = %e, "failed to send RPKI ResetQuery");
        }
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
                            Err(e) => {
                                tracing::warn!(rpki_server = %remote_addr, error = %e, "RPKI framing error");
                                break;
                            }
                        },
                        None => break,
                    };
                    tracing::trace!(rpki_server = %remote_addr, "received RPKI message");
                    state.update(&msg);
                    match msg {
                        rpki::Message::IpPrefix(prefix) => {
                            if prefix.flags & 1 > 0 {
                                let roa = Arc::new(table::Roa::new(prefix.max_length, prefix.as_number, remote_addr.clone()));
                                if end_of_data {
                                    for tx in &txv {
                                        let _ = tx.send(TableEvent::InsertRoa(vec![(prefix.net.clone(), roa.clone())]));
                                    }
                                } else {
                                    v.push((
                                        prefix.net,
                                        roa,
                                    ));
                                }
                            }
                        }
                        rpki::Message::EndOfData { serial_number } => {
                            tracing::info!(rpki_server = %remote_addr, serial = serial_number, roas = v.len(), "RPKI EndOfData received");
                            end_of_data = true;
                            state.serial.store(serial_number, Ordering::Relaxed);
                            for tx in &txv {
                                let _ = tx.send(TableEvent::Drop(remote_addr.clone()));
                                let _ = tx.send(TableEvent::InsertRoa(v.to_owned()));
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        tracing::info!(rpki_server = %remote_addr, "RPKI client disconnected");
        state.downtime.store(
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            Ordering::Relaxed,
        );
        for tx in &txv {
            let _ = tx.send(TableEvent::Drop(remote_addr.clone()));
        }
        Ok(())
    }

    fn try_connect(sockaddr: SocketAddr, configured_time: u64) {
        tokio::spawn(async move {
            let mut table_tx = Vec::with_capacity(*NUM_TABLES);
            let d = Table::dealer(sockaddr);
            for i in 0..*NUM_TABLES {
                let t = TABLE[i].lock().await;
                table_tx.push(t.table_event_tx[d].clone());
            }
            loop {
                tracing::debug!(%sockaddr, "RPKI connecting");
                if let Ok(Ok(stream)) = tokio::time::timeout(
                    tokio::time::Duration::from_secs(5),
                    TcpStream::connect(sockaddr),
                )
                .await
                {
                    let (tx, rx) = mpsc::unbounded_channel();
                    let state = if let Some(client) =
                        GLOBAL.write().await.rpki_clients.get_mut(&sockaddr)
                    {
                        client.mgmt_tx = Some(tx);
                        client.state.clone()
                    } else {
                        break;
                    };
                    if let Err(e) = RpkiClient::serve(stream, rx, table_tx.to_vec(), state).await {
                        tracing::warn!(%sockaddr, error = %e, "RPKI session ended with error");
                    }
                } else {
                    tracing::debug!(%sockaddr, "RPKI connection attempt failed, retrying in 10s");
                    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                }
                if let Some(client) = GLOBAL.write().await.rpki_clients.get_mut(&sockaddr) {
                    if client.configured_time != configured_time {
                        tracing::debug!(%sockaddr, "RPKI client reconfigured, stopping retry");
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

static NUM_TABLES: Lazy<usize> = Lazy::new(|| num_cpus::get() / 2);
static GLOBAL: Lazy<RwLock<Global>> = Lazy::new(|| RwLock::new(Global::new()));
static GLOBAL_IMPORT_POLICY: ArcSwapOption<table::PolicyAssignment> = ArcSwapOption::const_empty();
static GLOBAL_EXPORT_POLICY: ArcSwapOption<table::PolicyAssignment> = ArcSwapOption::const_empty();
static TABLE: Lazy<Vec<Mutex<Table>>> = Lazy::new(|| {
    let mut table = Vec::with_capacity(*NUM_TABLES);
    for _ in 0..*NUM_TABLES {
        table.push(Mutex::new(Table {
            rtable: table::RoutingTable::new(),
            peer_event_tx: FnvHashMap::default(),
            table_event_tx: Vec::new(),
            bmp_event_tx: FnvHashMap::default(),
            mrt_event_tx: None,
            addpath: FnvHashMap::default(),
        }));
    }
    table
});

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
        }
    }

    #[tracing::instrument(skip(self, peer, tx), fields(peer = %peer.remote_addr))]
    fn add_peer(
        &mut self,
        mut peer: Peer,
        tx: Option<mpsc::UnboundedSender<TcpStream>>,
    ) -> std::result::Result<(), Error> {
        if self.peers.contains_key(&peer.remote_addr) {
            return Err(Error::AlreadyExists(
                "peer address already exists".to_string(),
            ));
        }
        if peer.local_asn == 0 {
            peer.local_asn = self.asn;
        }
        let mut caps = HashSet::new();
        for c in &peer.local_cap {
            caps.insert(Into::<u8>::into(c));
        }
        let c = packet::Capability::FourOctetAsNumber(peer.local_asn);
        if !caps.contains(&Into::<u8>::into(&c)) {
            peer.local_cap.push(c);
        }
        if peer.admin_down {
            peer.state
                .fsm
                .store(SessionState::Connect as u8, Ordering::Relaxed);
        }
        if let Some(tx) = tx {
            enable_active_connect(&peer, tx);
        }
        tracing::info!(peer = %peer.remote_addr, asn = peer.local_asn, "peer added");
        self.peers.insert(peer.remote_addr, peer);
        Ok(())
    }

    #[tracing::instrument(skip(stream), level = "debug")]
    async fn accept_connection(
        stream: TcpStream,
    ) -> Option<(Handler, mpsc::UnboundedReceiver<PeerMgmtMsg>)> {
        let local_sockaddr = stream.local_addr().ok()?;
        let remote_sockaddr = stream.peer_addr().ok()?;
        let remote_addr = remote_sockaddr.ip();
        tracing::debug!(peer = %remote_addr, local = %local_sockaddr, "accepting incoming TCP connection");
        let mut global = GLOBAL.write().await;
        let router_id = global.router_id;
        let (peer, mgmt_rx) = match global.peers.get_mut(&remote_addr) {
            Some(peer) => {
                if peer.admin_down {
                    tracing::warn!(peer = %remote_addr, "admin down; ignoring passive connection");
                    return None;
                }
                if peer.mgmt_tx.is_some() {
                    tracing::warn!(peer = %remote_addr, "already has active connection");
                    return None;
                }
                peer.remote_sockaddr = remote_sockaddr;
                peer.local_sockaddr = local_sockaddr;
                peer.state
                    .fsm
                    .store(SessionState::Active as u8, Ordering::Relaxed);
                let (tx, rx) = mpsc::unbounded_channel();
                peer.mgmt_tx = Some(tx);
                (peer, rx)
            }
            None => {
                let mut is_dynamic = false;
                let mut rs_client = false;
                let mut remote_asn = 0;
                let mut holdtime = None;
                for p in &global.peer_group {
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
                    tracing::warn!(peer = %remote_addr, "no configuration found for passive connection");
                    return None;
                }
                let (tx, rx) = mpsc::unbounded_channel();
                let mut builder = PeerBuilder::new(remote_addr);
                builder
                    .state(SessionState::Active)
                    .remote_asn(remote_asn)
                    .delete_on_disconnected(true)
                    .rs_client(rs_client)
                    .remote_sockaddr(remote_sockaddr)
                    .local_sockaddr(local_sockaddr)
                    .ctrl_channel(tx);
                if let Some(holdtime) = holdtime {
                    builder.holdtime(holdtime);
                }
                tracing::debug!(peer = %remote_addr, remote_asn = remote_asn, "creating dynamic peer");
                let _ = global.add_peer(builder.build(), None);
                let peer = global.peers.get_mut(&remote_addr).unwrap();
                (peer, rx)
            }
        };
        if let Some(ttl) = peer.multihop_ttl {
            if peer.state.remote_asn.load(Ordering::Relaxed) != peer.local_asn {
                if let Err(e) = stream.set_ttl(ttl.into()) {
                    tracing::warn!(peer = %remote_addr, ttl = ttl, error = %e, "failed to set multihop TTL");
                }
            }
        } else if let Err(e) = stream.set_ttl(1) {
            tracing::warn!(peer = %remote_addr, error = %e, "failed to set TTL to 1");
        }
        Handler::new(
            stream,
            remote_addr,
            peer.local_asn,
            router_id,
            peer.local_cap.to_owned(),
            peer.holdtime,
            peer.route_server_client,
            peer.state.clone(),
            peer.counter_tx.clone(),
            peer.counter_rx.clone(),
            peer.send_max.clone(),
            peer.prefix_limits.clone(),
        )
        .map(|h| (h, mgmt_rx))
    }

    async fn serve(
        bgp: Option<config::BgpConfig>,
        any_peer: bool,
        conn_tx: Vec<mpsc::UnboundedSender<(Handler, mpsc::UnboundedReceiver<PeerMgmtMsg>)>>,
        active_tx: mpsc::UnboundedSender<TcpStream>,
        mut active_rx: mpsc::UnboundedReceiver<TcpStream>,
    ) {
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
                router_id.parse().unwrap()
            } else {
                Ipv4Addr::new(0, 0, 0, 0)
            };
        let notify = Arc::new(tokio::sync::Notify::new());
        if as_number != 0 {
            notify.clone().notify_one();
            let global = &mut GLOBAL.write().await;
            global.asn = as_number;
            global.router_id = router_id;
        }
        if let Some(mrt) = bgp.as_ref().and_then(|x| x.mrt_dump.as_ref()) {
            for m in mrt {
                if let Some(config) = m.config.as_ref()
                    && let Some(dump_type) = config.dump_type.as_ref()
                {
                    if dump_type != &config::generate::MrtType::Updates {
                        tracing::warn!("only MRT update dump is supported");
                        continue;
                    }
                    if let Some(filename) = config.file_name.as_ref() {
                        let interval = config.rotation_interval.as_ref().map_or(0, |x| *x);
                        let filename = filename.clone();
                        tokio::spawn(async move {
                            let mut d = MrtDumper::new(&filename, interval);
                            d.serve().await;
                        });
                    } else {
                        tracing::warn!("MRT dump filename must be specified");
                    }
                }
            }
        }
        if let Some(groups) = bgp.as_ref().and_then(|x| x.peer_groups.as_ref()) {
            let mut server = GLOBAL.write().await;
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
            let mut server = GLOBAL.write().await;
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
            let mut server = GLOBAL.write().await;
            for s in bmp_servers {
                let config = s.config.as_ref().unwrap();
                let sockaddr = SocketAddr::new(
                    config.address.as_ref().unwrap().parse().unwrap(),
                    config.port.unwrap() as u16,
                );
                match server.bmp_clients.entry(sockaddr) {
                    Occupied(_) => {
                        tracing::error!(%sockaddr, "duplicate BMP server in config");
                        panic!("duplicated bmp server {}", sockaddr);
                    }
                    Vacant(v) => {
                        let client = BmpClient::new();
                        let t = client.configured_time;
                        v.insert(client);
                        BmpClient::try_connect(sockaddr, t);
                    }
                }
            }
        }
        if let Some(defined_sets) = bgp.as_ref().and_then(|x| x.defined_sets.as_ref()) {
            match convert::defined_sets_to_api(defined_sets) {
                Ok(sets) => {
                    let mut server = GLOBAL.write().await;
                    for set in sets {
                        let set = convert::defined_set_from_api(set).unwrap();
                        if let Err(e) = server.ptable.add_defined_set(set) {
                            tracing::error!(error = ?e, "failed to add defined set from config");
                            panic!("{:?}", e);
                        }
                    }
                }
                Err(e) => {
                    tracing::error!(error = ?e, "failed to convert defined sets from config");
                    panic!("{:?}", e);
                }
            }
        }
        if let Some(policies) = bgp.as_ref().and_then(|x| x.policy_definitions.as_ref()) {
            let mut h = HashSet::new();
            let mut server = GLOBAL.write().await;
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
                                    let disposition =
                                        convert::disposition_from_api(s.actions).unwrap();
                                    if let Err(e) = server
                                        .ptable
                                        .add_statement(&s.name, conditions, disposition)
                                    {
                                        tracing::error!(statement = %s.name, error = ?e, "failed to add policy statement");
                                        panic!("{:?}", e);
                                    }
                                    s_names.push(s.name.clone());
                                    h.insert(s.name);
                                }
                                Err(e) => {
                                    tracing::error!(error = ?e, "failed to convert policy statement from config");
                                    panic!("{:?}", e);
                                }
                            }
                        }
                    }
                    if let Err(e) = server.ptable.add_policy(name, s_names) {
                        tracing::error!(policy = %name, error = ?e, "failed to add policy");
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
                if let Err(e) = add_policy_assignment(f(
                    1,
                    config.import_policy_list.as_ref(),
                    config.default_import_policy.as_ref(),
                ))
                .await
                {
                    tracing::error!(error = ?e, "failed to load import policy assignment from config");
                    panic!("{:?}", e);
                }
                if let Err(e) = add_policy_assignment(f(
                    2,
                    config.export_policy_list.as_ref(),
                    config.default_export_policy.as_ref(),
                ))
                .await
                {
                    tracing::error!(error = ?e, "failed to load export policy assignment from config");
                    panic!("{:?}", e);
                }
            }
        }
        if let Some(peers) = bgp.as_ref().and_then(|x| x.neighbors.as_ref()) {
            let mut server = GLOBAL.write().await;
            for p in peers {
                match Peer::try_from(p) {
                    Ok(peer) => {
                        if let Err(e) = server.add_peer(peer, Some(active_tx.clone())) {
                            tracing::error!(error = %e, "failed to add peer from config");
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "skipping invalid peer config");
                    }
                }
            }
        }
        if any_peer {
            let mut server = GLOBAL.write().await;
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
        tracing::info!(%addr, "starting gRPC server");
        let notify2 = notify.clone();
        tokio::spawn(async move {
            if let Err(e) = tonic::transport::Server::builder()
                .add_service(GoBgpServiceServer::new(GrpcService::new(
                    notify2, active_tx,
                )))
                .serve(addr)
                .await
            {
                tracing::error!(%addr, error = %e, "gRPC server failed");
                panic!("failed to listen on grpc {}", e);
            }
        });
        notify.notified().await;
        let listen_port = GLOBAL.read().await.listen_port;
        tracing::info!(port = listen_port, "listening for BGP connections");
        let listen_sockets: Vec<std::net::TcpListener> = vec![
            create_listen_socket("0.0.0.0".to_string(), listen_port),
            create_listen_socket("[::]".to_string(), listen_port),
        ]
        .into_iter()
        .filter_map(|x| x.ok())
        .collect();
        GLOBAL
            .write()
            .await
            .listen_sockets
            .append(&mut listen_sockets.iter().map(|x| x.as_raw_fd()).collect());

        for (addr, peer) in &GLOBAL.read().await.peers {
            if let Some(password) = &peer.password {
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
        let mut next_peer_taker = 0;
        let nr_takers = conn_tx.len();
        let mut stats_timer = tokio::time::interval(Duration::from_secs(60));
        stats_timer.tick().await; // consume the immediate first tick
        loop {
            let mut bgp_listen_futures = FuturesUnordered::new();
            for incoming in &mut incomings {
                bgp_listen_futures.push(incoming.next());
            }
            futures::select_biased! {
                stream = bgp_listen_futures.next() => {
                    if let Some(Some(Ok(stream))) = stream
                        && let Some(r) = Global::accept_connection(stream).await {
                            if conn_tx[next_peer_taker].send(r).is_err() {
                                tracing::warn!("failed to hand off passive connection to handler thread");
                            }
                            next_peer_taker = (next_peer_taker + 1) % nr_takers;
                        }
                }
                stream = active_rx.recv().fuse() => {
                    if let Some(stream) = stream
                        && let Some(r) = Global::accept_connection(stream).await {
                            if conn_tx[next_peer_taker].send(r).is_err() {
                                tracing::warn!("failed to hand off active connection to handler thread");
                            }
                            next_peer_taker = (next_peer_taker + 1) % nr_takers;
                        }
                }
                _ = stats_timer.tick().fuse() => {
                    let global = GLOBAL.read().await;
                    let total = global.peers.len();
                    let established = global.peers.values()
                        .filter(|p| p.state.fsm.load(Ordering::Relaxed) == SessionState::Established as u8)
                        .count();
                    let mut routes_v4 = 0u64;
                    let mut routes_v6 = 0u64;
                    drop(global);
                    for i in 0..*NUM_TABLES {
                        let t = TABLE[i].lock().await;
                        routes_v4 += t.rtable.state(Family::IPV4).num_destination as u64;
                        routes_v6 += t.rtable.state(Family::IPV6).num_destination as u64;
                    }
                    tracing::info!(
                        peers_total = total,
                        peers_established = established,
                        routes_v4 = routes_v4,
                        routes_v6 = routes_v6,
                        "periodic stats"
                    );
                }
            }
        }
    }
}

enum TableEvent {
    // BGP events
    PassUpdate(
        Arc<table::Source>,
        Family,
        Vec<packet::PathNlri>,
        Option<Arc<Vec<packet::Attribute>>>,
    ),
    Disconnected(Arc<table::Source>),
    // RPKI events
    InsertRoa(Vec<(packet::IpNet, Arc<table::Roa>)>),
    Drop(Arc<IpAddr>),
}

struct Table {
    rtable: table::RoutingTable,
    peer_event_tx: FnvHashMap<IpAddr, mpsc::UnboundedSender<ToPeerEvent>>,
    table_event_tx: Vec<mpsc::UnboundedSender<TableEvent>>,
    bmp_event_tx: FnvHashMap<SocketAddr, mpsc::UnboundedSender<bmp::Message>>,
    mrt_event_tx: Option<mpsc::UnboundedSender<mrt::Message>>,
    addpath: FnvHashMap<IpAddr, FnvHashSet<Family>>,
}

impl Table {
    fn dealer<T: Hash>(a: T) -> usize {
        let mut hasher = FnvHasher::default();
        a.hash(&mut hasher);
        hasher.finish() as usize % *NUM_TABLES
    }

    fn has_addpath(&self, addr: &IpAddr, family: &Family) -> bool {
        self.addpath.get(addr).is_some_and(|e| e.contains(family))
    }

    fn send_bmp_update(
        &self,
        source: &table::Source,
        family: Family,
        nets: &[packet::PathNlri],
        attrs: Option<&Arc<Vec<packet::Attribute>>>,
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
            })
        };
        for bmp_tx in self.bmp_event_tx.values() {
            if bmp_tx.send(bmp::Message::RouteMonitoring {
                header: header.clone(),
                update: update.clone(),
                addpath,
            }).is_err() {
                tracing::debug!("BMP route monitoring channel closed");
            }
        }
    }

    fn send_mrt_update(
        &self,
        source: &table::Source,
        family: Family,
        nets: &[packet::PathNlri],
        attrs: Option<&Arc<Vec<packet::Attribute>>>,
    ) {
        let Some(mrt_tx) = self.mrt_event_tx.as_ref() else {
            return;
        };
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
            })
        };
        if mrt_tx.send(mrt::Message::Mp {
            header,
            body,
            addpath,
        }).is_err() {
            tracing::debug!("MRT event channel closed");
        }
    }

    async fn serve(idx: usize, mut v: Vec<UnboundedReceiverStream<TableEvent>>) {
        loop {
            let mut futures: FuturesUnordered<_> = v.iter_mut().map(|rx| rx.next()).collect();
            if let Some(Some(msg)) = futures.next().await {
                match msg {
                    TableEvent::PassUpdate(source, family, nets, attrs) => {
                        let mut t = TABLE[idx].lock().await;
                        t.send_bmp_update(&source, family, &nets, attrs.as_ref());
                        t.send_mrt_update(&source, family, &nets, attrs.as_ref());

                        match attrs {
                            Some(attrs) => {
                                let import_policy = GLOBAL_IMPORT_POLICY.load();
                                let export_policy = GLOBAL_EXPORT_POLICY.load();
                                for net in nets {
                                    let filtered = import_policy.as_ref().is_some_and(|a| {
                                        t.rtable.apply_policy(a, &source, &net.nlri, &attrs)
                                            == table::Disposition::Reject
                                    });
                                    if filtered {
                                        tracing::trace!(peer = %source.remote_addr, nlri = ?net.nlri, "import policy rejected route");
                                    }
                                    let changes = t.rtable.insert(
                                        source.clone(),
                                        family,
                                        net.nlri,
                                        net.path_id,
                                        attrs.clone(),
                                        filtered,
                                    );
                                    for ri in changes {
                                        if !ri.attr.is_empty()
                                            && export_policy.as_ref().is_some_and(|a| {
                                                t.rtable
                                                    .apply_policy(a, &ri.source, &ri.net, &ri.attr)
                                                    == table::Disposition::Reject
                                            })
                                        {
                                            tracing::trace!(nlri = ?ri.net, "export policy rejected route advertisement");
                                            continue;
                                        }
                                        for c in t.peer_event_tx.values() {
                                            if c.send(ToPeerEvent::Advertise(ri.clone())).is_err() {
                                                tracing::debug!("peer event channel closed during reach advertisement");
                                            }
                                        }
                                    }
                                }
                            }
                            None => {
                                let export_policy = GLOBAL_EXPORT_POLICY.load();
                                for net in nets {
                                    let changes = t.rtable.remove(
                                        source.clone(),
                                        family,
                                        net.nlri,
                                        net.path_id,
                                    );
                                    for ri in changes {
                                        // don't apply export policy for withdrawn routes.
                                        if !ri.attr.is_empty()
                                            && export_policy.as_ref().is_some_and(|a| {
                                                t.rtable
                                                    .apply_policy(a, &ri.source, &ri.net, &ri.attr)
                                                    == table::Disposition::Reject
                                            })
                                        {
                                            tracing::trace!(nlri = ?ri.net, "export policy rejected withdrawal propagation");
                                            continue;
                                        }
                                        for c in t.peer_event_tx.values() {
                                            if c.send(ToPeerEvent::Advertise(ri.clone())).is_err() {
                                                tracing::debug!("peer event channel closed during withdrawal");
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    TableEvent::Disconnected(source) => {
                        let mut t = TABLE[idx].lock().await;
                        let changes = t.rtable.drop(source.clone());
                        for change in changes {
                            for c in t.peer_event_tx.values() {
                                if c.send(ToPeerEvent::Advertise(change.clone())).is_err() {
                                    tracing::debug!("peer event channel closed during disconnect cleanup");
                                }
                            }
                        }
                    }
                    TableEvent::InsertRoa(v) => {
                        let mut t = TABLE[idx].lock().await;
                        for (net, roa) in v {
                            t.rtable.roa_insert(net, roa);
                        }
                    }
                    TableEvent::Drop(addr) => {
                        TABLE[idx].lock().await.rtable.rpki_drop(addr);
                    }
                }
            }
        }
    }
}

pub(crate) fn main(bgp: Option<config::BgpConfig>, any_peer: bool) {
    let mut handlers = Vec::new();
    for i in 0..*NUM_TABLES {
        let h = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let mut v = Vec::new();
                    for _ in 0..*NUM_TABLES {
                        let mut t = TABLE[i].lock().await;
                        let (tx, rx) = mpsc::unbounded_channel();
                        t.table_event_tx.push(tx);
                        v.push(UnboundedReceiverStream::new(rx));
                    }
                    Table::serve(i, v).await;
                })
        });
        handlers.push(h);
    }

    let (active_tx, active_rx) = mpsc::unbounded_channel();
    let mut conn_tx = Vec::new();
    for _ in 0..*NUM_TABLES - 1 {
        let (tx, mut rx) =
            mpsc::unbounded_channel::<(Handler, mpsc::UnboundedReceiver<PeerMgmtMsg>)>();
        conn_tx.push(tx);
        let active_conn_tx = active_tx.clone();
        let h = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    loop {
                        if let Some((mut h, mgmt_rx)) = rx.recv().await {
                            let active_conn_tx = active_conn_tx.clone();

                            let peer_addr = h.remote_addr;
                            let span = tracing::info_span!("peer", addr = %peer_addr);
                            tokio::spawn(async move {
                                if let Err(e) = h.run(mgmt_rx).await {
                                    tracing::warn!(error = %e, "BGP session ended with error");
                                }
                                let mut server = GLOBAL.write().await;
                                if let Some(peer) = server.peers.get_mut(&peer_addr) {
                                    if peer.delete_on_disconnected {
                                        server.peers.remove(&peer_addr);
                                    } else {
                                        peer.reset();
                                        enable_active_connect(peer, active_conn_tx.clone());
                                    }
                                }
                            }.instrument(span));
                        }
                    }
                })
        });
        handlers.push(h);
    }

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(Global::serve(bgp, any_peer, conn_tx, active_tx, active_rx));
}

struct Handler {
    remote_addr: IpAddr,
    local_addr: IpAddr,

    local_asn: u32,

    local_router_id: Ipv4Addr,

    state: Arc<PeerState>,

    counter_tx: Arc<MessageCounter>,
    counter_rx: Arc<MessageCounter>,

    local_cap: Vec<packet::Capability>,

    local_holdtime: u64,
    negotiated_holdtime: u64,
    rs_client: bool,

    stream: Option<TcpStream>,
    keepalive_timer: tokio::time::Interval,
    source: Option<Arc<table::Source>>,
    table_tx: Vec<mpsc::UnboundedSender<TableEvent>>,
    peer_event_tx: Vec<mpsc::UnboundedSender<ToPeerEvent>>,
    holdtimer_renewed: Instant,
    shutdown: Option<bmp::PeerDownReason>,
    /// Per-family send_max for Add-Path TX (RFC 7911).
    send_max: FnvHashMap<Family, usize>,
    /// Per-family prefix limits from config.
    prefix_limits: FnvHashMap<Family, u32>,
}

impl Handler {
    fn new(
        stream: TcpStream,
        remote_addr: IpAddr,
        local_asn: u32,
        local_router_id: Ipv4Addr,
        local_cap: Vec<packet::Capability>,
        local_holdtime: u64,
        rs_client: bool,
        state: Arc<PeerState>,
        counter_tx: Arc<MessageCounter>,
        counter_rx: Arc<MessageCounter>,
        send_max: FnvHashMap<Family, usize>,
        prefix_limits: FnvHashMap<Family, u32>,
    ) -> Option<Self> {
        let local_sockaddr = stream.local_addr().ok()?;
        Some(Handler {
            remote_addr,
            local_addr: local_sockaddr.ip(),
            local_router_id,
            local_asn,
            state,
            counter_tx,
            counter_rx,
            local_cap,
            local_holdtime,
            negotiated_holdtime: 0,
            rs_client,
            keepalive_timer: tokio::time::interval_at(
                tokio::time::Instant::now() + Duration::new(u32::MAX.into(), 0),
                Duration::from_secs(3600),
            ),
            stream: Some(stream),
            source: None,
            table_tx: Vec::with_capacity(*NUM_TABLES),
            peer_event_tx: Vec::new(),
            holdtimer_renewed: Instant::now(),
            shutdown: None,
            send_max,
            prefix_limits,
        })
    }

    #[tracing::instrument(skip(self, codec, pending), level = "debug")]
    async fn on_established(
        &mut self,
        codec: &bgp::PeerCodec,
        local_sockaddr: SocketAddr,
        remote_sockaddr: SocketAddr,
        pending: &mut FnvHashMap<Family, PendingTx>,
    ) {
        let uptime = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.state.uptime.store(uptime, Ordering::Relaxed);
        let remote_asn = self.state.remote_asn.load(Ordering::Relaxed);
        tracing::info!(
            remote_asn = remote_asn,
            holdtime = self.negotiated_holdtime,
            "BGP session established"
        );
        self.state
            .fsm
            .store(SessionState::Established as u8, Ordering::Release);
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
            pending.insert(
                *family,
                PendingTx {
                    sync: true,
                    addpath_tx: c.addpath_tx(),
                    ..Default::default()
                },
            );
        }

        let d = Table::dealer(self.remote_addr);
        for i in 0..*NUM_TABLES {
            let mut t = TABLE[i].lock().await;

            // Populate initial routes for each negotiated family.
            let export_policy = GLOBAL_EXPORT_POLICY.load();
            for f in codec.channel.keys() {
                let effective_max = self.send_max.get(f).copied().unwrap_or(1);
                for c in t.rtable.best(f).into_iter() {
                    if c.rank > effective_max {
                        continue;
                    }
                    if export_policy.as_ref().is_some_and(|a| {
                        t.rtable.apply_policy(a, &c.source, &c.net, &c.attr)
                            == table::Disposition::Reject
                    }) {
                        tracing::trace!(nlri = ?c.net, "export policy rejected initial route");
                        continue;
                    }
                    pending.get_mut(f).unwrap().insert_change(c);
                }
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

            let tx = t.table_event_tx[d].clone();
            self.table_tx.push(tx);

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
                    capability: self.state.remote_cap.read().await.to_owned(),
                }),
                local_open: bgp::Message::Open(bgp::Open {
                    as_number: remote_asn,
                    holdtime: remote_holdtime,
                    router_id: remote_id,
                    capability: self.local_cap.to_owned(),
                }),
            };
            if bmp_tx.send(bmp_msg).is_err() {
                tracing::debug!("BMP PeerUp channel closed");
            }
        }
    }

    async fn flush_tx(
        &mut self,
        stream: &mut TcpStream,
        framer: &mut BgpFramer,
        txbuf_size: usize,
        urgent: &mut Vec<bgp::Message>,
        pending: &mut FnvHashMap<Family, PendingTx>,
    ) {
        // 1. Flush urgent (open, keepalive, notification) messages.
        let mut txbuf = bytes::BytesMut::with_capacity(txbuf_size);
        for _ in 0..urgent.len() {
            let msg = urgent.remove(0);
            if let Err(e) = framer.encode_to(&msg, &mut txbuf) {
                tracing::error!(error = %e, "failed to encode urgent BGP message");
            }
            (*self.counter_tx).sync(&msg);

            if txbuf.len() > txbuf_size {
                let buf = txbuf.freeze();
                txbuf = bytes::BytesMut::with_capacity(txbuf_size);
                if let Err(e) = stream.write_all(&buf).await {
                    tracing::error!(error = %e, "TCP write failed for urgent message");
                    self.shutdown = Some(bmp::PeerDownReason::RemoteUnexpected);
                    return;
                }
            }
        }
        if !txbuf.is_empty() {
            if let Err(e) = stream.write_all(&txbuf.freeze()).await {
                tracing::error!(error = %e, "TCP write failed flushing urgent messages");
                self.shutdown = Some(bmp::PeerDownReason::RemoteUnexpected);
                return;
            }
        }

        // 2. Flush pending withdrawals.
        for (family, p) in pending.iter_mut() {
            let addpath_tx = framer
                .inner()
                .channel
                .get(family)
                .is_some_and(|c| c.addpath_tx());
            let unreach: Vec<packet::PathNlri> = p
                .unreach
                .drain()
                .map(|(nlri, pid)| packet::PathNlri {
                    path_id: if addpath_tx { pid } else { 0 },
                    nlri,
                })
                .collect();
            if !unreach.is_empty() {
                txbuf = bytes::BytesMut::with_capacity(txbuf_size);
                let msg = bgp::Message::Update(bgp::Update {
                    reach: None,
                    mp_reach: None,
                    attr: Arc::new(Vec::new()),
                    unreach: None,
                    mp_unreach: Some(packet::NlriSet {
                        family: *family,
                        entries: unreach,
                    }),
                });
                if let Err(e) = framer.encode_to(&msg, &mut txbuf) {
                    tracing::error!(error = %e, "failed to encode withdrawal UPDATE");
                }
                self.counter_tx.sync(&msg);
                if !txbuf.is_empty() {
                    if let Err(e) = stream.write_all(&txbuf.freeze()).await {
                        tracing::error!(error = %e, "TCP write failed for withdrawal");
                        self.shutdown = Some(bmp::PeerDownReason::RemoteUnexpected);
                        return;
                    }
                }
            }
        }

        // 3. Flush pending reach updates (batched by attribute).
        txbuf = bytes::BytesMut::with_capacity(txbuf_size);
        let max_tx_count = 2048;
        let mut updates_sent = 0usize;
        let mut sent: FnvHashMap<Family, Vec<Arc<Vec<packet::Attribute>>>> = FnvHashMap::default();
        'flush: for (family, p) in pending.iter_mut() {
            let addpath_tx = framer
                .inner()
                .channel
                .get(family)
                .is_some_and(|c| c.addpath_tx());
            let use_mp = framer
                .inner()
                .channel
                .get(family)
                .is_some_and(|c| c.extended_nexthop());
            for (attr, reach) in p.bucket.iter() {
                let nlri_set = packet::NlriSet {
                    family: *family,
                    entries: reach
                        .iter()
                        .copied()
                        .map(|(nlri, pid)| packet::PathNlri {
                            path_id: if addpath_tx { pid } else { 0 },
                            nlri,
                        })
                        .collect(),
                };
                // RFC 8950: use MP_REACH_NLRI for IPv4 when extended nexthop is negotiated
                let (reach, mp_reach) = if use_mp {
                    (None, Some(nlri_set))
                } else {
                    (Some(nlri_set), None)
                };
                let msg = bgp::Message::Update(bgp::Update {
                    reach,
                    mp_reach,
                    attr: attr.clone(),
                    unreach: None,
                    mp_unreach: None,
                });
                if let Err(e) = framer.encode_to(&msg, &mut txbuf) {
                    tracing::error!(error = %e, "failed to encode reach UPDATE");
                }
                self.counter_tx.sync(&msg);
                sent.entry(*family).or_default().push(attr.clone());

                updates_sent += 1;

                if txbuf.len() > txbuf_size {
                    let buf = txbuf.freeze();
                    txbuf = bytes::BytesMut::with_capacity(txbuf_size);
                    if let Err(e) = stream.write_all(&buf).await {
                        tracing::error!(error = %e, "TCP write failed for reach update");
                        self.shutdown = Some(bmp::PeerDownReason::RemoteUnexpected);
                        return;
                    }
                }

                if updates_sent >= max_tx_count {
                    break 'flush;
                }
            }
        }
        if !txbuf.is_empty() {
            if let Err(e) = stream.write_all(&txbuf.freeze()).await {
                tracing::error!(error = %e, "TCP write failed flushing reach updates");
                self.shutdown = Some(bmp::PeerDownReason::RemoteUnexpected);
                return;
            }
        }

        // 4. Remove sent entries from pending maps.
        for (family, mut s) in sent {
            for attr in s.drain(..) {
                let p = pending.get_mut(&family).unwrap();
                let mut bucket = p.bucket.remove(&attr).unwrap();
                for net in bucket.drain() {
                    let _ = p.reach.remove(&net).unwrap();
                }
            }
        }

        // 5. Send EOR markers for families that have completed initial sync.
        if self.state.fsm.load(Ordering::Relaxed) == SessionState::Established as u8 {
            for (family, p) in pending.iter_mut() {
                if p.sync && p.is_empty() {
                    p.sync = false;
                    let mut b = bytes::BytesMut::with_capacity(txbuf_size);
                    let eor = bgp::Message::eor(*family);
                    if let Err(e) = framer.encode_to(&eor, &mut b) {
                        tracing::error!(family = ?family, error = %e, "failed to encode EOR");
                    }
                    tracing::debug!(family = ?family, "sending EOR");
                    if let Err(e) = stream.write_all(&b.freeze()).await {
                        tracing::error!(error = %e, "TCP write failed for EOR");
                        self.shutdown = Some(bmp::PeerDownReason::RemoteUnexpected);
                        return;
                    }
                }
            }
        }
    }

    async fn rx_update(
        &mut self,
        reach: Option<packet::NlriSet>,
        unreach: Option<packet::NlriSet>,
        attr: Arc<Vec<packet::Attribute>>,
    ) {
        if let Some(s) = reach {
            let family = s.family;
            for net in s.entries {
                let idx = Table::dealer(net.nlri);
                if self.table_tx[idx].send(TableEvent::PassUpdate(
                    self.source.as_ref().unwrap().clone(),
                    family,
                    vec![net],
                    Some(attr.clone()),
                )).is_err() {
                    tracing::warn!("table channel closed, cannot forward reach update");
                }
            }
        }
        if let Some(s) = unreach {
            let family = s.family;
            for net in s.entries {
                let idx = Table::dealer(net.nlri);
                if self.table_tx[idx].send(TableEvent::PassUpdate(
                    self.source.as_ref().unwrap().clone(),
                    family,
                    vec![net],
                    None,
                )).is_err() {
                    tracing::warn!("table channel closed, cannot forward withdrawal");
                }
            }
        }
    }

    async fn rx_msg(
        &mut self,
        codec: &mut packet::bgp::PeerCodec,
        local_sockaddr: SocketAddr,
        remote_sockaddr: SocketAddr,
        msg: bgp::Message,
        urgent: &mut Vec<bgp::Message>,
        pending: &mut FnvHashMap<Family, PendingTx>,
    ) -> std::result::Result<(), Error> {
        match msg {
            bgp::Message::Open(bgp::Open {
                as_number,
                holdtime,
                router_id,
                mut capability,
            }) => {
                tracing::debug!(
                    remote_asn = as_number,
                    remote_router_id = %Ipv4Addr::from(router_id),
                    holdtime = holdtime.seconds(),
                    "received BGP OPEN"
                );
                urgent.push(bgp::Message::Keepalive);
                self.state
                    .remote_holdtime
                    .store(holdtime.seconds(), Ordering::Relaxed);
                self.state.remote_id.store(router_id, Ordering::Relaxed);
                let remote_asn = self.state.remote_asn.load(Ordering::Relaxed);
                if remote_asn != 0 && remote_asn != as_number {
                    urgent.insert(
                        0,
                        bgp::Message::Notification(rustybgp_packet::BgpError::Other {
                            code: 2,
                            subcode: 2,
                            data: vec![],
                        }),
                    );
                    return Ok(());
                }
                self.state.remote_asn.store(as_number, Ordering::Relaxed);
                // Collect locally-configured Add-Path families before negotiation
                let local_addpath: Vec<(packet::Family, u8)> = self
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

                for (f, c) in bgp::create_channel(&self.local_cap, &capability) {
                    codec.channel.insert(f, c);
                }

                // Drop send_max for families where Add-Path TX was not negotiated
                self.send_max
                    .retain(|f, _| codec.channel.get(f).is_some_and(|c| c.addpath_tx()));

                // Warn when locally-configured Add-Path was not negotiated
                for (family, mode) in &local_addpath {
                    match codec.channel.get(family) {
                        Some(ch) => {
                            if mode & 0x1 > 0 && !ch.addpath_rx() {
                                tracing::warn!(
                                    family = ?family,
                                    "add-path receive configured but not negotiated"
                                );
                            }
                            if mode & 0x2 > 0 && !ch.addpath_tx() {
                                tracing::warn!(
                                    family = ?family,
                                    "add-path send configured but not negotiated"
                                );
                            }
                        }
                        None => {
                            tracing::warn!(
                                family = ?family,
                                "add-path configured but address family not negotiated"
                            );
                        }
                    }
                }

                self.state.remote_cap.write().await.append(&mut capability);
                self.negotiated_holdtime =
                    std::cmp::min(self.local_holdtime, holdtime.seconds() as u64);
                if self.negotiated_holdtime != 0 {
                    self.keepalive_timer =
                        tokio::time::interval(Duration::from_secs(self.negotiated_holdtime / 3));
                }
                self.state
                    .fsm
                    .store(SessionState::OpenConfirm as u8, Ordering::Release);
                Ok(())
            }
            bgp::Message::Update(bgp::Update {
                reach,
                mp_reach,
                attr,
                unreach,
                mp_unreach,
            }) => {
                let session_state = self.state.fsm.load(Ordering::Relaxed);
                if session_state != SessionState::Established as u8 {
                    return Err(Error::Packet(
                        rustybgp_packet::BgpError::FsmUnexpectedState {
                            state: session_state,
                        }
                        .into(),
                    ));
                }
                tracing::trace!("received UPDATE");
                self.holdtimer_renewed = Instant::now();
                self.rx_update(reach, unreach, attr.clone()).await;
                self.rx_update(mp_reach, mp_unreach, attr).await;
                Ok(())
            }
            bgp::Message::Notification(err) => {
                tracing::warn!(
                    code = err.notification_code(),
                    subcode = err.notification_subcode(),
                    "received BGP NOTIFICATION"
                );
                self.shutdown = Some(bmp::PeerDownReason::RemoteNotification(
                    bgp::Message::Notification(err),
                ));
                Ok(())
            }
            bgp::Message::Keepalive => {
                tracing::trace!("received KEEPALIVE");
                self.holdtimer_renewed = Instant::now();
                if self.state.fsm.load(Ordering::Relaxed) == SessionState::OpenConfirm as u8 {
                    self.on_established(codec, local_sockaddr, remote_sockaddr, pending)
                        .await;
                }
                Ok(())
            }
            bgp::Message::RouteRefresh { family: _ } => Ok(()),
        }
    }

    async fn run(
        &mut self,
        mut mgmt_rx: mpsc::UnboundedReceiver<PeerMgmtMsg>,
    ) -> Result<(), Error> {
        tracing::debug!("BGP session handler starting");
        let mut stream = self.stream.take().unwrap();
        let remote_sockaddr = stream.peer_addr()?;
        let local_sockaddr = stream.local_addr()?;
        let rxbuf_size = 1 << 16;
        let mut txbuf_size = 1 << 16;
        if let Ok(r) =
            nix::sys::socket::getsockopt(&stream.as_fd(), nix::sys::socket::sockopt::SndBuf)
        {
            txbuf_size = std::cmp::min(txbuf_size, r / 2);
        }

        let mut framer = BgpFramer::new(if self.rs_client {
            bgp::PeerCodecBuilder::new()
                .local_asn(self.local_asn)
                .local_addr(self.local_addr)
                .keep_aspath(true)
                .keep_nexthop(true)
                .build()
        } else {
            bgp::PeerCodecBuilder::new()
                .local_asn(self.local_asn)
                .local_addr(self.local_addr)
                .build()
        });

        let mut peer_event_rx = Vec::new();
        for _ in 0..*NUM_TABLES {
            let (tx, rx) = mpsc::unbounded_channel();
            self.peer_event_tx.push(tx);
            peer_event_rx.push(UnboundedReceiverStream::new(rx));
        }

        let mut pending_update: FnvHashMap<Family, PendingTx> = FnvHashMap::default();
        let mut urgent = vec![bgp::Message::Open(bgp::Open {
            as_number: self.local_asn,
            holdtime: HoldTime::new(self.local_holdtime as u16).unwrap_or(HoldTime::DISABLED),
            router_id: u32::from(self.local_router_id),
            capability: self.local_cap.to_owned(),
        })];

        self.state
            .fsm
            .store(SessionState::OpenSent as u8, Ordering::Relaxed);
        let mut holdtime_futures: FuturesUnordered<_> =
            vec![tokio::time::sleep(Duration::new(u64::MAX, 0))]
                .into_iter()
                .collect();

        let mut rxbuf = bytes::BytesMut::with_capacity(rxbuf_size);
        while self.shutdown.is_none() {
            let mut peer_event_futures: FuturesUnordered<_> =
                peer_event_rx.iter_mut().map(|rx| rx.next()).collect();

            let interest = if urgent.is_empty() {
                let mut interest = tokio::io::Interest::READABLE;
                for p in pending_update.values_mut() {
                    if !p.is_empty() {
                        interest |= tokio::io::Interest::WRITABLE;
                        break;
                    }
                }
                interest
            } else {
                tokio::io::Interest::READABLE | tokio::io::Interest::WRITABLE
            };

            let oldstate = self.state.fsm.load(Ordering::Relaxed);
            futures::select_biased! {
                _ = self.keepalive_timer.tick().fuse() => {
                    if self.state.fsm.load(Ordering::Relaxed) == SessionState::Established as u8 {
                        urgent.insert(0, bgp::Message::Keepalive);
                    }
                }
                msg = mgmt_rx.recv().fuse() => {
                    if let Some(PeerMgmtMsg::Notification(msg)) = msg {
                        urgent.insert(0, msg);
                    }
                }
                _ = holdtime_futures.next() => {
                    let elapsed = self.holdtimer_renewed.elapsed().as_secs();
                    if elapsed > self.negotiated_holdtime + 20 {
                        tracing::warn!(elapsed_secs = self.holdtimer_renewed.elapsed().as_secs(), "hold timer expired");
                        break;
                    }
                    holdtime_futures.push(tokio::time::sleep(Duration::from_secs(self.negotiated_holdtime - elapsed + 10)));
                }
                msg = peer_event_futures.next().fuse() => {
                    if let Some(Some(msg)) = msg {
                        match msg {
                            ToPeerEvent::Advertise(ri) => {
                                if self.state.fsm.load(Ordering::Relaxed) != SessionState::Established as u8 {
                                    continue;
                                }
                                if Arc::ptr_eq(&ri.source, self.source.as_ref().unwrap()) {
                                    continue;
                                }
                                if !framer.inner().channel.contains_key(&ri.family) {
                                    continue;
                                }
                                // Filter changes that exceed this peer's effective send_max.
                                // Note: ranks are 1-based for all changes (including withdrawals); there is no special rank=0.
                                let effective_max = self.send_max.get(&ri.family).copied().unwrap_or(1);
                                if ri.rank > effective_max {
                                    // Only withdraw if the path was previously within
                                    // this peer's window (old_rank <= effective_max).
                                    if self.send_max.contains_key(&ri.family)
                                        && ri.old_rank > 0
                                        && ri.old_rank <= effective_max
                                    {
                                        pending_update.get_mut(&ri.family).unwrap().insert_change(
                                            table::Change {
                                                attr: Arc::new(Vec::new()),
                                                ..ri
                                            },
                                        );
                                    }
                                    continue;
                                }
                                pending_update.get_mut(&ri.family).unwrap().insert_change(ri);
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
                                    match framer.try_parse(&mut rxbuf) {
                                    Ok(msg) => match msg {
                                        Some(msg) => {
                                            (*self.counter_rx).sync(&msg);
                                            let _ = self.rx_msg(framer.inner_mut(), local_sockaddr, remote_sockaddr, msg, &mut urgent, &mut pending_update).await;
                                        }
                                        None => {
                                            // partial read
                                            break;
                                        },
                                    }
                                    Err(e) => {
                                        if let rustybgp_packet::Error::Bgp(ref bgp_err) = e {
                                            urgent.insert(0, bgp::Message::Notification(bgp_err.clone()));
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
                        self.flush_tx(&mut stream, &mut framer, txbuf_size, &mut urgent, &mut pending_update).await;
                    }
                }
            }

            if oldstate == SessionState::OpenSent as u8
                && self.state.fsm.load(Ordering::Relaxed) == SessionState::OpenConfirm as u8
                && self.negotiated_holdtime != 0
            {
                holdtime_futures = vec![tokio::time::sleep(Duration::from_secs(
                    self.negotiated_holdtime,
                ))]
                .into_iter()
                .collect();
            }
        }
        if let Some(source) = self.source.take() {
            tracing::info!("BGP session disconnected");
            for i in 0..*NUM_TABLES {
                let mut t = TABLE[i].lock().await;
                t.peer_event_tx.remove(&self.remote_addr);
                t.addpath.remove(&self.remote_addr);
                let _ = self.table_tx[i].send(TableEvent::Disconnected(source.clone()));
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
        Ok(())
    }
}

/// Key for PendingTx maps: (NLRI, path_id). path_id distinguishes
/// multiple paths for the same prefix under RFC 7911 Add-Path.
type PendingKey = (packet::Nlri, u32);

#[derive(Default)]
struct PendingTx {
    reach: FnvHashMap<PendingKey, Arc<Vec<packet::Attribute>>>,
    unreach: FnvHashSet<PendingKey>,
    bucket: FnvHashMap<Arc<Vec<packet::Attribute>>, FnvHashSet<PendingKey>>,
    sync: bool,
    addpath_tx: bool,
}

impl PendingTx {
    fn is_empty(&self) -> bool {
        self.reach.is_empty() && self.unreach.is_empty()
    }

    fn insert_change(&mut self, change: table::Change) {
        let pid = if self.addpath_tx { change.path_id } else { 0 };
        let key: PendingKey = (change.net, pid);
        if change.attr.is_empty() {
            if let Some(attr) = self.reach.remove(&key) {
                let set = self.bucket.get_mut(&attr).unwrap();
                let b = set.remove(&key);
                assert!(b);
                if set.is_empty() {
                    self.bucket.remove(&attr);
                }
            }
            self.unreach.insert(key);
        } else {
            self.unreach.remove(&key);

            if let Some(old_attr) = self.reach.insert(key, change.attr.clone()) {
                // b-1) same attr → no-op
                if old_attr == change.attr {
                    return;
                }

                // b-2) different attr → move between buckets
                let old_bucket = self.bucket.get_mut(&old_attr).unwrap();
                let b = old_bucket.remove(&key);
                assert!(b);
                if old_bucket.is_empty() {
                    self.bucket.remove(&old_attr);
                }

                let bucket = self.bucket.entry(change.attr).or_default();
                bucket.insert(key);
            } else {
                // a) new key
                let bucket = self.bucket.entry(change.attr).or_default();
                bucket.insert(key);
            }
        }
    }
}

#[test]
fn bucket() {
    let src = Arc::new(table::Source::new(
        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
        1,
        2,
        Ipv4Addr::new(127, 0, 0, 1),
        0,
        false,
    ));
    let family = Family::IPV4;

    let net1 = packet::Nlri::from_str("10.0.0.0/24").unwrap();
    let net2 = packet::Nlri::from_str("20.0.0.0/24").unwrap();

    let attr1 = vec![packet::Attribute::new_with_value(packet::Attribute::ORIGIN, 0).unwrap()];

    let mut pending = PendingTx {
        addpath_tx: true,
        ..Default::default()
    };

    pending.insert_change(table::Change {
        source: src.clone(),
        family,
        net: net1,
        attr: Arc::new(attr1.clone()),
        path_id: 1,
        rank: 1,
        old_rank: 0,
    });

    pending.insert_change(table::Change {
        source: src.clone(),
        family: Family::IPV4,
        net: net2,
        attr: Arc::new(vec![
            packet::Attribute::new_with_value(packet::Attribute::ORIGIN, 0).unwrap(),
        ]),
        path_id: 1,
        rank: 1,
        old_rank: 0,
    });

    // a-1) and a-2) properly marged?
    assert_eq!(1, pending.bucket.len());
    assert_eq!(
        2,
        pending.bucket.get(&Arc::new(attr1.clone())).unwrap().len()
    );

    // b-1)
    pending.insert_change(table::Change {
        source: src.clone(),
        family,
        net: net2,
        attr: Arc::new(vec![
            packet::Attribute::new_with_value(packet::Attribute::ORIGIN, 0).unwrap(),
        ]),
        path_id: 1,
        rank: 1,
        old_rank: 0,
    });
    assert_eq!(1, pending.bucket.len());
    assert_eq!(
        2,
        pending.bucket.get(&Arc::new(attr1.clone())).unwrap().len()
    );

    // b-2-2)
    let attr2 = vec![packet::Attribute::new_with_value(packet::Attribute::ORIGIN, 1).unwrap()];
    pending.insert_change(table::Change {
        source: src.clone(),
        family,
        net: net2,
        attr: Arc::new(vec![
            packet::Attribute::new_with_value(packet::Attribute::ORIGIN, 1).unwrap(),
        ]),
        path_id: 1,
        rank: 1,
        old_rank: 0,
    });
    assert_eq!(2, pending.bucket.len());
    assert_eq!(&Arc::new(attr2), pending.reach.get(&(net2, 1)).unwrap());
    assert_eq!(
        1,
        pending.bucket.get(&Arc::new(attr1.clone())).unwrap().len()
    );
}
