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
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use fnv::{FnvHashMap, FnvHashSet, FnvHasher};
use futures::stream::FuturesUnordered;
use futures::{FutureExt, SinkExt, Stream, StreamExt};
use once_cell::sync::Lazy;
use std::boxed::Box;
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::collections::HashSet;
use std::convert::{From, TryFrom};
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::Deref;
use std::os::unix::io::AsRawFd;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tokio_util::codec::{Decoder, Encoder, Framed};

use api::gobgp_api_server::{GobgpApi, GobgpApiServer};

use crate::api;
use crate::config;
use crate::error::Error;
use crate::net;
use crate::packet::{self, bgp, bmp, rpki};
use crate::proto::ToApi;
use crate::table;

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
            bgp::Message::Open { .. } => {
                let _ = self.open.fetch_add(1, Ordering::Relaxed);
            }
            bgp::Message::Update {
                reach: _,
                unreach,
                attr: _,
                mp_reach: _,
                mp_attr: _,
                mp_unreach,
            } => {
                self.update.fetch_add(1, Ordering::Relaxed);

                if !unreach.is_empty() {
                    self.withdraw_update.fetch_add(1, Ordering::Relaxed);
                    self.withdraw_prefix.fetch_add(1, Ordering::Relaxed);
                }
                if let Some((_, v)) = mp_unreach {
                    self.withdraw_update.fetch_add(1, Ordering::Relaxed);
                    self.withdraw_prefix
                        .fetch_add(v.len() as u64, Ordering::Relaxed);
                }
            }
            bgp::Message::Notification { .. } => {
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

impl From<u8> for api::peer_state::SessionState {
    fn from(v: u8) -> Self {
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
    local_addr: IpAddr,
    local_port: u16,
    remote_port: u16,
    local_as: u32,
    passive: bool,
    admin_down: bool,
    delete_on_disconnected: bool,

    holdtime: u64,
    connect_retry_time: u64,

    state: Arc<PeerState>,

    counter_tx: Arc<MessageCounter>,
    counter_rx: Arc<MessageCounter>,

    // received and accepted
    route_stats: FnvHashMap<packet::Family, (u64, u64)>,

    local_cap: Vec<packet::Capability>,

    route_server_client: bool,

    mgmt_tx: Option<mpsc::UnboundedSender<PeerMgmtMsg>>,
}

impl Peer {
    fn update_stats(&mut self, rti: FnvHashMap<packet::Family, (u64, u64)>) {
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
        self.local_port = 0;
        self.remote_port = 0;
    }
}

struct PeerBuilder {
    remote_addr: IpAddr,
    remote_asn: u32,
    remote_port: u16,
    local_addr: IpAddr,
    local_asn: u32,
    local_port: u16,
    local_cap: Vec<packet::Capability>,
    passive: bool,
    rs_client: bool,
    delete_on_disconnected: bool,
    admin_down: bool,
    state: SessionState,
    holdtime: u64,
    connect_retry_time: u64,
    ctrl_channel: Option<mpsc::UnboundedSender<PeerMgmtMsg>>,
}

impl PeerBuilder {
    const DEFAULT_HOLD_TIME: u64 = 180;
    const DEFAULT_CONNECT_RETRY_TIME: u64 = 3;

    fn new(remote_addr: IpAddr) -> Self {
        PeerBuilder {
            remote_addr,
            remote_asn: 0,
            remote_port: Global::BGP_PORT,
            local_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            local_asn: 0,
            local_port: 0,
            local_cap: Vec::new(),
            passive: false,
            rs_client: false,
            delete_on_disconnected: false,
            admin_down: false,
            state: SessionState::Idle,
            holdtime: Self::DEFAULT_HOLD_TIME,
            connect_retry_time: Self::DEFAULT_CONNECT_RETRY_TIME,
            ctrl_channel: None,
        }
    }

    fn ctrl_channel(&mut self, tx: mpsc::UnboundedSender<PeerMgmtMsg>) -> &mut Self {
        self.ctrl_channel = Some(tx);
        self
    }

    fn families(&mut self, families: Vec<packet::Family>) -> &mut Self {
        let mut v: Vec<packet::Capability> = families
            .iter()
            .map(|family| packet::Capability::MultiProtocol(*family))
            .collect();
        self.local_cap.append(&mut v);
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

    fn local_addr(&mut self, addr: IpAddr) -> &mut Self {
        self.local_addr = addr;
        self
    }

    fn local_port(&mut self, port: u16) -> &mut Self {
        self.local_port = port;
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

    fn build(&mut self) -> Peer {
        Peer {
            remote_addr: self.remote_addr,
            local_addr: self.local_addr,
            configured_time: SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            remote_port: self.remote_port,
            local_port: 0,
            local_as: self.local_asn,
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
                    v.append(&mut a.iter().map(|c| c.into()).collect());
                    break;
                }
            }
            v
        };
        let mut ps = api::PeerState {
            neighbor_address: p.remote_addr.to_string(),
            peer_as: p.state.remote_asn.load(Ordering::Relaxed),
            router_id: Ipv4Addr::from(p.state.remote_id.load(Ordering::Relaxed)).to_string(),
            messages: Some(api::Messages {
                received: Some((&*p.counter_rx).into()),
                sent: Some((&*p.counter_tx).into()),
            }),
            queues: Some(Default::default()),
            remote_cap,
            local_cap: p.local_cap.iter().map(|c| c.into()).collect(),
            ..Default::default()
        };
        ps.session_state = api::peer_state::SessionState::from(session_state) as i32;
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
                    family: Some((*f).into()),
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
        Ok(PeerBuilder::new(peer_addr)
            .local_asn(conf.local_as)
            .remote_asn(conf.peer_as)
            .remote_port(p.transport.as_ref().map_or(0, |x| x.remote_port as u16))
            .families(
                p.afi_safis
                    .iter()
                    .filter(|x| x.config.as_ref().map_or(false, |x| x.family.is_some()))
                    .map(|x| {
                        packet::Family::from(x.config.as_ref().unwrap().family.as_ref().unwrap())
                    })
                    .collect(),
            )
            .passive(p.transport.as_ref().map_or(false, |x| x.passive_mode))
            .rs_client(
                p.route_server
                    .as_ref()
                    .map_or(false, |x| x.route_server_client),
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
            .build())
    }
}

// assumes that config::Neighbor is valified so use From instead of TryFrom
impl From<&config::Neighbor> for Peer {
    fn from(n: &config::Neighbor) -> Peer {
        let c = n.config.as_ref().unwrap();
        PeerBuilder::new(c.neighbor_address.as_ref().unwrap().parse().unwrap())
            .local_asn(c.local_as.map_or(0, |x| x))
            .remote_asn(c.peer_as.unwrap())
            .remote_port(n.transport.as_ref().map_or(0, |t| {
                t.config
                    .as_ref()
                    .map_or(0, |t| t.remote_port.map_or(0, |n| n))
            }))
            .passive(n.transport.as_ref().map_or(false, |t| {
                t.config
                    .as_ref()
                    .map_or(false, |t| t.passive_mode.map_or(false, |t| t))
            }))
            .rs_client(n.route_server.as_ref().map_or(false, |r| {
                r.config
                    .as_ref()
                    .map_or(false, |r| r.route_server_client.map_or(false, |r| r))
            }))
            .holdtime(n.timers.as_ref().map_or(0, |c| {
                c.config
                    .as_ref()
                    .map_or(0, |c| c.hold_time.map_or(0, |c| c as u64))
            }))
            .connect_retry_time(n.timers.as_ref().map_or(0, |c| {
                c.config
                    .as_ref()
                    .map_or(0, |c| c.connect_retry.map_or(0, |c| c as u64))
            }))
            .admin_down(c.admin_down.map_or(false, |c| c))
            .build()
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
            as_number: p.conf.map_or(0, |c| c.peer_as),
            dynamic_peers: Vec::new(),
            // passive: p.transport.map_or(false, |c| c.passive_mode),
            route_server_client: p.route_server.map_or(false, |c| c.route_server_client),
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
                Ipv4Addr::new(0, 0, 0, 0),
                table::PeerType::Ibgp,
                IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                0,
                0,
                false,
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            )),
            active_conn_tx,
        }
    }

    async fn is_available(&self, need_active: bool) -> Result<(), Error> {
        let global = &GLOBAL.read().await;
        if need_active && global.as_number == 0 {
            return Err(Error::NotStarted);
        }
        Ok(())
    }

    fn local_path(&self, path: api::Path) -> Result<(usize, TableEvent), tonic::Status> {
        let family = match path.family {
            Some(family) => packet::Family::from(&family),
            None => packet::Family::IPV4,
        };
        let net = packet::Net::try_from(path.nlri.ok_or(Error::EmptyArgument)?)
            .map_err(|_| tonic::Status::new(tonic::Code::InvalidArgument, "prefix is invalid"))?;
        let mut attr = Vec::new();
        for a in path.pattrs {
            attr.push(packet::Attribute::try_from(a).map_err(|_| {
                tonic::Status::new(tonic::Code::InvalidArgument, "invalid attribute")
            })?);
        }
        Ok((
            Table::dealer(&net),
            TableEvent::PassUpdate(self.local_source.clone(), family, vec![net], {
                if attr.is_empty() {
                    None
                } else {
                    Some(Arc::new(attr))
                }
            }),
        ))
    }
}

#[tonic::async_trait]
impl GobgpApi for GrpcService {
    async fn start_bgp(
        &self,
        request: tonic::Request<api::StartBgpRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        let g = request.into_inner().global.ok_or(Error::EmptyArgument)?;
        if g.r#as == 0 {
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
        if global.as_number != 0 {
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "already started",
            ));
        }
        global.as_number = g.r#as;
        global.listen_port = if g.listen_port > 0 {
            g.listen_port as u16
        } else {
            Global::BGP_PORT
        };
        global.router_id = Ipv4Addr::from_str(&g.router_id).unwrap();
        self.init.notify_one();

        Ok(tonic::Response::new(()))
    }
    async fn stop_bgp(
        &self,
        _request: tonic::Request<api::StopBgpRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
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
    ) -> Result<tonic::Response<()>, tonic::Status> {
        let peer = Peer::try_from(&request.into_inner().peer.ok_or(Error::EmptyArgument)?)?;
        GLOBAL
            .write()
            .await
            .add_peer(peer, Some(self.active_conn_tx.clone()))?;
        Ok(tonic::Response::new(()))
    }
    async fn delete_peer(
        &self,
        request: tonic::Request<api::DeletePeerRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        if let Ok(peer_addr) = IpAddr::from_str(&request.into_inner().address) {
            for (addr, p) in &GLOBAL.write().await.peers {
                if addr == &peer_addr {
                    match &p.mgmt_tx {
                        Some(mgmt_tx) => {
                            let _ = mgmt_tx.send(PeerMgmtMsg::Notification(
                                bgp::Message::Notification {
                                    code: 6,
                                    subcode: 3,
                                    data: Vec::new(),
                                },
                            ));
                            return Ok(tonic::Response::new(()));
                        }
                        None => {
                            return Err(tonic::Status::new(
                                tonic::Code::NotFound,
                                "peer isn't not active",
                            ));
                        }
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
                if let Ok(peer_addr) = peer_addr {
                    if &peer_addr != addr {
                        continue;
                    }
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
    ) -> Result<tonic::Response<()>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }
    async fn shutdown_peer(
        &self,
        _request: tonic::Request<api::ShutdownPeerRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }
    async fn enable_peer(
        &self,
        request: tonic::Request<api::EnablePeerRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        if let Ok(peer_addr) = IpAddr::from_str(&request.into_inner().address) {
            for (addr, mut p) in &mut GLOBAL.write().await.peers {
                if addr == &peer_addr {
                    if p.admin_down {
                        p.admin_down = false;
                        enable_active_connect(p, self.active_conn_tx.clone());
                        return Ok(tonic::Response::new(()));
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
    ) -> Result<tonic::Response<()>, tonic::Status> {
        if let Ok(peer_addr) = IpAddr::from_str(&request.into_inner().address) {
            for (addr, mut p) in &mut GLOBAL.write().await.peers {
                if addr == &peer_addr {
                    if p.admin_down {
                        return Err(tonic::Status::new(
                            tonic::Code::InvalidArgument,
                            "peer is already admin-down",
                        ));
                    } else {
                        p.admin_down = true;
                        match &p.mgmt_tx {
                            Some(mgmt_tx) => {
                                let _ = mgmt_tx.send(PeerMgmtMsg::Notification(
                                    bgp::Message::Notification {
                                        code: 6,
                                        subcode: 2,
                                        data: Vec::new(),
                                    },
                                ));
                                return Ok(tonic::Response::new(()));
                            }
                            None => {}
                        }
                        return Ok(tonic::Response::new(()));
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
    type MonitorPeerStream = Pin<
        Box<
            dyn Stream<Item = Result<api::MonitorPeerResponse, tonic::Status>>
                + Send
                + Sync
                + 'static,
        >,
    >;
    async fn monitor_peer(
        &self,
        _request: tonic::Request<api::MonitorPeerRequest>,
    ) -> Result<tonic::Response<Self::MonitorPeerStream>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }
    async fn add_peer_group(
        &self,
        request: tonic::Request<api::AddPeerGroupRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
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
                return Ok(tonic::Response::new(()));
            }
        }
    }
    async fn delete_peer_group(
        &self,
        _request: tonic::Request<api::DeletePeerGroupRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
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
    ) -> Result<tonic::Response<()>, tonic::Status> {
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
        Ok(tonic::Response::new(()))
    }
    async fn delete_dynamic_neighbor(
        &self,
        _request: tonic::Request<api::DeleteDynamicNeighborRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
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
    ) -> Result<tonic::Response<()>, tonic::Status> {
        let u = self.local_path(request.into_inner().path.ok_or(Error::EmptyArgument)?)?;
        let chan = TABLE[u.0].lock().await.table_event_tx[0].clone();
        let _ = chan.send(u.1);
        Ok(tonic::Response::new(()))
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
            Some(family) => packet::Family::from(&family),
            None => packet::Family::IPV4,
        };
        let (table_type, peer_addr) = if let Some(t) = api::TableType::from_i32(request.table_type)
        {
            let s = match t {
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
            (t, s)
        } else {
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "invalid table type",
            ));
        };

        let prefixes: Vec<packet::Net> = request
            .prefixes
            .iter()
            .map(|x| packet::Net::from_str(&x.prefix))
            .filter(|x| x.is_ok())
            .map(|x| x.unwrap())
            .collect();

        let mut v = Vec::new();
        for i in 0..*NUM_TABLES {
            let t = TABLE[i].lock().await;
            v.append(
                &mut t
                    .rtable
                    .iter_api(table_type, family, peer_addr, prefixes.clone())
                    .map(|x| api::ListPathResponse {
                        destination: Some(x),
                    })
                    .collect(),
            );
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
    ) -> Result<tonic::Response<()>, tonic::Status> {
        let mut stream = request.into_inner();
        while let Some(Ok(request)) = stream.next().await {
            for path in request.paths {
                let u = self.local_path(path)?;
                let chan = TABLE[u.0].lock().await.table_event_tx[0].clone();
                let _ = chan.send(u.1);
            }
        }
        Ok(tonic::Response::new(()))
    }
    async fn get_table(
        &self,
        request: tonic::Request<api::GetTableRequest>,
    ) -> Result<tonic::Response<api::GetTableResponse>, tonic::Status> {
        self.is_available(true).await?;
        let family = match request.into_inner().family {
            Some(family) => packet::Family::from(&family),
            None => packet::Family::IPV4,
        };
        let mut info = table::RoutingTableState::default();
        for i in 0..*NUM_TABLES {
            let t = TABLE[i].lock().await;
            info += t.rtable.state(family);
        }
        Ok(tonic::Response::new(api::GetTableResponse::from(info)))
    }
    type MonitorTableStream = Pin<
        Box<
            dyn Stream<Item = Result<api::MonitorTableResponse, tonic::Status>>
                + Send
                + Sync
                + 'static,
        >,
    >;
    async fn monitor_table(
        &self,
        _request: tonic::Request<api::MonitorTableRequest>,
    ) -> Result<tonic::Response<Self::MonitorTableStream>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }
    async fn add_vrf(
        &self,
        _request: tonic::Request<api::AddVrfRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }
    async fn delete_vrf(
        &self,
        _request: tonic::Request<api::DeleteVrfRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
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
    ) -> Result<tonic::Response<()>, tonic::Status> {
        let policy = request.into_inner().policy.ok_or(Error::EmptyArgument)?;
        GLOBAL
            .write()
            .await
            .ptable
            .add_policy(&policy.name, policy.statements)
            .map(|_| Ok(tonic::Response::new(())))?
    }
    async fn delete_policy(
        &self,
        _request: tonic::Request<api::DeletePolicyRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
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
            .iter_policy_api(request.name)
            .map(|p| api::ListPolicyResponse { policy: Some(p) })
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
    ) -> Result<tonic::Response<()>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }
    async fn add_defined_set(
        &self,
        request: tonic::Request<api::AddDefinedSetRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        let set = request
            .into_inner()
            .defined_set
            .ok_or(Error::EmptyArgument)?;
        GLOBAL
            .write()
            .await
            .ptable
            .add_defined_set(set)
            .map(|_| Ok(tonic::Response::new(())))?
    }
    async fn delete_defined_set(
        &self,
        _request: tonic::Request<api::DeleteDefinedSetRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
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
            .iter_defined_set_api()
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
    ) -> Result<tonic::Response<()>, tonic::Status> {
        let statement = request.into_inner().statement.ok_or(Error::EmptyArgument)?;
        GLOBAL
            .write()
            .await
            .ptable
            .add_statement(&statement.name, statement.conditions, statement.actions)
            .map(|_| Ok(tonic::Response::new(())))?
    }
    async fn delete_statement(
        &self,
        _request: tonic::Request<api::DeleteStatementRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
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
            .iter_statement_api(request.name)
            .map(|s| api::ListStatementResponse { statement: Some(s) })
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
    ) -> Result<tonic::Response<()>, tonic::Status> {
        let _ = self.policy_assignment_sem.acquire().await;
        let request = request
            .into_inner()
            .assignment
            .ok_or(Error::EmptyArgument)?;
        add_policy_assignment(request).await?;
        Ok(tonic::Response::new(()))
    }
    async fn delete_policy_assignment(
        &self,
        _request: tonic::Request<api::DeletePolicyAssignmentRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
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
            .iter_assignment_api(request.direction)
            .map(|x| api::ListPolicyAssignmentResponse {
                assignment: Some(x),
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
    ) -> Result<tonic::Response<()>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }
    async fn add_rpki(
        &self,
        request: tonic::Request<api::AddRpkiRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
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
        Ok(tonic::Response::new(()))
    }
    async fn delete_rpki(
        &self,
        request: tonic::Request<api::DeleteRpkiRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
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
        Ok(tonic::Response::new(()))
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
        let mut mgmt = FnvHashMap::default();
        for (sockaddr, client) in &GLOBAL.read().await.rpki_clients {
            if let Some(tx) = &client.mgmt_tx {
                mgmt.insert(sockaddr.ip(), tx.clone());
            }
            let mut r = api::Rpki {
                conf: Some(api::RpkiConf {
                    address: sockaddr.ip().to_string(),
                    remote_port: sockaddr.port() as u32,
                }),
                state: Some(Default::default()),
            };
            if let Some(downtime) = client.downtime {
                let mut s = r.state.take().unwrap();
                s.downtime = Some(downtime.to_api());
                r.state = Some(s);
            }
            v.insert(sockaddr.ip(), r);
        }

        for (addr, mgmt_tx) in mgmt {
            let (tx, mut rx) = mpsc::channel(1);
            let _ = mgmt_tx.send(RpkiMgmtMsg::State(tx));
            if let Some(state) = rx.recv().await {
                if let Some(r) = v.get_mut(&addr) {
                    r.state = Some(state);
                }
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
    ) -> Result<tonic::Response<()>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }
    async fn disable_rpki(
        &self,
        _request: tonic::Request<api::DisableRpkiRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }
    async fn reset_rpki(
        &self,
        _request: tonic::Request<api::ResetRpkiRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
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
            Some(family) => packet::Family::from(&family),
            None => packet::Family::IPV4,
        };

        let v: Vec<api::ListRpkiTableResponse> = TABLE[0]
            .lock()
            .await
            .rtable
            .iter_roa_api(family)
            .map(|roa| api::ListRpkiTableResponse { roa: Some(roa) })
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
    ) -> Result<tonic::Response<()>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }
    async fn enable_mrt(
        &self,
        _request: tonic::Request<api::EnableMrtRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }
    async fn disable_mrt(
        &self,
        _request: tonic::Request<api::DisableMrtRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }
    async fn add_bmp(
        &self,
        request: tonic::Request<api::AddBmpRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
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
        Ok(tonic::Response::new(()))
    }
    async fn delete_bmp(
        &self,
        _request: tonic::Request<api::DeleteBmpRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }
    async fn set_log_level(
        &self,
        _request: tonic::Request<api::SetLogLevelRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }
}

async fn add_policy_assignment(req: api::PolicyAssignment) -> Result<(), Error> {
    let (dir, assingment) = GLOBAL.write().await.ptable.add_assignment(req)?;
    for i in 0..*NUM_TABLES {
        let mut t = TABLE[i].lock().await;
        if dir == api::PolicyDirection::Import {
            t.global_import_policy = Some(assingment.clone());
        } else {
            t.global_export_policy = Some(assingment.clone());
        }
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
    tokio::spawn(async move {
        loop {
            if let Ok(Ok(stream)) = tokio::time::timeout(
                tokio::time::Duration::from_secs(5),
                TcpStream::connect(sockaddr),
            )
            .await
            {
                let _ = ch.send(stream);
                return;
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(retry_time)).await;
            {
                let server = GLOBAL.write().await;
                if let Some(peer) = server.peers.get(&peer_addr) {
                    if peer.configured_time != configured_time {
                        return;
                    }
                } else {
                    return;
                }
            }
        }
    });
}

struct BmpClient {
    configured_time: u64,
}

impl BmpClient {
    fn new() -> Self {
        BmpClient {
            configured_time: SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    async fn serve(stream: TcpStream, sockaddr: SocketAddr) {
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
        for i in 0..*NUM_TABLES {
            let mut t = TABLE[i].lock().await;
            t.bmp_event_tx.insert(sockaddr.ip(), tx.clone());
            for c in t.rtable.iter_change(packet::Family::IPV4) {
                let e = adjin.entry(c.source.peer_addr).or_insert_with(Vec::new);
                e.push(c);
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
                    local_addr: peer.local_addr,
                    local_port: peer.local_port,
                    remote_port: peer.remote_port,
                    remote_open: bgp::Message::Open {
                        version: 4,
                        as_number: peer.state.remote_asn.load(Ordering::Relaxed),
                        holdtime: peer.state.remote_holdtime.load(Ordering::Relaxed),
                        router_id: remote_id,
                        capability: peer.state.remote_cap.read().await.to_owned(),
                    },
                    local_open: bgp::Message::Open {
                        version: 4,
                        as_number: peer.local_as,
                        holdtime: peer.holdtime as u16,
                        router_id: local_id,
                        capability: peer.local_cap.to_owned(),
                    },
                };
                if lines.send(&m).await.is_err() {
                    return;
                }
            }
        }
        for addr in established_peers {
            let mut header = None;
            if let Some(v) = adjin.remove(&addr) {
                for m in v {
                    if header.is_none() {
                        header = Some(bmp::PerPeerHeader::new(
                            m.source.remote_asn,
                            Ipv4Addr::from(m.source.router_id),
                            0,
                            m.source.peer_addr,
                            m.source.uptime as u32,
                        ));
                    }
                    if lines
                        .send(&bmp::Message::RouteMonitoring {
                            header: bmp::PerPeerHeader::new(
                                m.source.remote_asn,
                                Ipv4Addr::from(m.source.router_id),
                                0,
                                m.source.peer_addr,
                                m.source.uptime as u32,
                            ),
                            update: m.into(),
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
                        update: bgp::Message::eor(packet::Family::IPV4),
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
    }

    fn try_connect(sockaddr: SocketAddr, configured_time: u64) {
        tokio::spawn(async move {
            loop {
                if let Ok(Ok(stream)) = tokio::time::timeout(
                    tokio::time::Duration::from_secs(5),
                    TcpStream::connect(sockaddr),
                )
                .await
                {
                    let _ = BmpClient::serve(stream, sockaddr).await;
                } else {
                    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                }
                if let Some(client) = GLOBAL.write().await.bmp_clients.get_mut(&sockaddr) {
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

enum RpkiMgmtMsg {
    State(mpsc::Sender<api::RpkiState>),
    Deconfigured,
}

struct RpkiClient {
    configured_time: u64,
    downtime: Option<SystemTime>,
    mgmt_tx: Option<mpsc::UnboundedSender<RpkiMgmtMsg>>,
}

impl RpkiClient {
    fn new() -> Self {
        RpkiClient {
            configured_time: SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            downtime: None,
            mgmt_tx: None,
        }
    }

    async fn serve(
        stream: TcpStream,
        rx: mpsc::UnboundedReceiver<RpkiMgmtMsg>,
        txv: Vec<mpsc::UnboundedSender<TableEvent>>,
    ) -> Result<(), Error> {
        let remote_addr = stream.peer_addr()?.ip();
        let remote_addr = Arc::new(remote_addr);
        let mut lines = Framed::new(stream, rpki::RtrCodec::new());
        let _ = lines.send(&rpki::Message::ResetQuery).await;
        let mut rx_counter: FnvHashMap<u8, i64> = FnvHashMap::default();
        let uptime = SystemTime::now();
        let mut rx = UnboundedReceiverStream::new(rx);
        let mut v = Vec::new();
        let mut serial = 0;
        let mut end_of_data = false;
        loop {
            tokio::select! {
                msg = rx.next() => {
                    match msg {
                        Some(RpkiMgmtMsg::State(tx)) => {
                            let s = TABLE[0].lock().await.rtable.rpki_state(remote_addr.clone());
                            let _ = tx.send(
                                api::RpkiState {
                                    uptime: Some(uptime.to_api()),
                                    downtime: None,
                                    up: true,
                                    record_ipv4: s.num_records_v4,
                                    record_ipv6: s.num_records_v6,
                                    prefix_ipv4: s.num_prefixes_v4,
                                    prefix_ipv6: s.num_prefixes_v6,
                                    serial,
                                    serial_notify: *rx_counter.get(&rpki::Message::SERIAL_NOTIFY).unwrap_or(&0),
                                    serial_query: *rx_counter.get(&rpki::Message::SERIAL_NOTIFY).unwrap_or(&0),
                                    reset_query: *rx_counter.get(&rpki::Message::RESET_QUERY).unwrap_or(&0),
                                    cache_response: *rx_counter.get(&rpki::Message::CACHE_RESPONSE).unwrap_or(&0),
                                    received_ipv4: *rx_counter.get(&rpki::Message::IPV4_PREFIX).unwrap_or(&0),
                                    received_ipv6: *rx_counter.get(&rpki::Message::IPV6_PREFIX).unwrap_or(&0),
                                    end_of_data: *rx_counter.get(&rpki::Message::END_OF_DATA).unwrap_or(&0),
                                    cache_reset: *rx_counter.get(&rpki::Message::CACHE_RESET).unwrap_or(&0),
                                    error: *rx_counter.get(&rpki::Message::ERROR_REPORT).unwrap_or(&0),
                                }
                            ).await;
                        }
                        Some(RpkiMgmtMsg::Deconfigured) => {
                            break;
                        }
                        None => {}
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
                    *rx_counter.entry(msg.code()).or_insert(0) += 1;
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
                            end_of_data = true;
                            serial = serial_number;
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
        for tx in &txv {
            let _ = tx.send(TableEvent::Drop(remote_addr.clone()));
        }
        Ok(())
    }

    fn try_connect(sockaddr: SocketAddr, configured_time: u64) {
        tokio::spawn(async move {
            let mut table_tx = Vec::with_capacity(*NUM_TABLES);
            let d = Table::dealer(&sockaddr);
            for i in 0..*NUM_TABLES {
                let t = TABLE[i].lock().await;
                table_tx.push(t.table_event_tx[d].clone());
            }
            loop {
                if let Ok(Ok(stream)) = tokio::time::timeout(
                    tokio::time::Duration::from_secs(5),
                    TcpStream::connect(sockaddr),
                )
                .await
                {
                    let (tx, rx) = mpsc::unbounded_channel();
                    if let Some(mut client) = GLOBAL.write().await.rpki_clients.get_mut(&sockaddr) {
                        client.mgmt_tx = Some(tx);
                    } else {
                        break;
                    }
                    let _ = RpkiClient::serve(stream, rx, table_tx.to_vec()).await;
                } else {
                    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                }
                if let Some(mut client) = GLOBAL.write().await.rpki_clients.get_mut(&sockaddr) {
                    if client.configured_time != configured_time {
                        break;
                    }
                    if client.mgmt_tx.is_some() {
                        client.downtime = Some(SystemTime::now());
                        client.mgmt_tx = None;
                    }
                } else {
                    break;
                }
            }
        });
    }
}

static NUM_TABLES: Lazy<usize> = Lazy::new(|| num_cpus::get() / 2);
static GLOBAL: Lazy<RwLock<Global>> = Lazy::new(|| RwLock::new(Global::new()));
static TABLE: Lazy<Vec<Mutex<Table>>> = Lazy::new(|| {
    let mut table = Vec::with_capacity(*NUM_TABLES);
    for _ in 0..*NUM_TABLES {
        table.push(Mutex::new(Table {
            rtable: table::RoutingTable::new(),
            peer_event_tx: FnvHashMap::default(),
            table_event_tx: Vec::new(),
            bmp_event_tx: FnvHashMap::default(),
            global_import_policy: None,
            global_export_policy: None,
        }));
    }
    table
});

struct Global {
    as_number: u32,
    router_id: Ipv4Addr,
    listen_port: u16,

    peers: FnvHashMap<IpAddr, Peer>,
    peer_group: FnvHashMap<String, PeerGroup>,

    ptable: table::PolicyTable,

    rpki_clients: FnvHashMap<SocketAddr, RpkiClient>,
    bmp_clients: FnvHashMap<SocketAddr, BmpClient>,
}

impl From<&Global> for api::Global {
    fn from(g: &Global) -> Self {
        api::Global {
            r#as: g.as_number,
            router_id: g.router_id.to_string(),
            listen_port: g.listen_port as i32,
            listen_addresses: Vec::new(),
            families: Vec::new(),
            use_multiple_paths: false,
            route_selection_options: None,
            default_route_distance: None,
            confederation: None,
            graceful_restart: None,
            apply_policy: None,
            bind_to_device: "".to_string(),
        }
    }
}

impl Global {
    const BGP_PORT: u16 = 179;

    fn new() -> Global {
        Global {
            as_number: 0,
            router_id: Ipv4Addr::new(0, 0, 0, 0),
            listen_port: Global::BGP_PORT,

            peers: FnvHashMap::default(),
            peer_group: FnvHashMap::default(),

            ptable: table::PolicyTable::new(),

            rpki_clients: FnvHashMap::default(),
            bmp_clients: FnvHashMap::default(),
        }
    }

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
        if peer.local_as == 0 {
            peer.local_as = self.as_number;
        }
        let mut caps = HashSet::new();
        for c in &peer.local_cap {
            caps.insert(Into::<u8>::into(c));
        }
        let c = packet::Capability::FourOctetAsNumber(peer.local_as);
        if !caps.contains(&Into::<u8>::into(&c)) {
            peer.local_cap.push(c);
        }
        let c = match peer.remote_addr {
            IpAddr::V4(_) => packet::Capability::MultiProtocol(packet::Family::IPV4),
            IpAddr::V6(_) => packet::Capability::MultiProtocol(packet::Family::IPV6),
        };
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
        self.peers.insert(peer.remote_addr, peer);
        Ok(())
    }

    async fn accept_connection(
        stream: TcpStream,
    ) -> Option<(Handler, mpsc::UnboundedReceiver<PeerMgmtMsg>)> {
        let local_sockaddr = stream.local_addr().ok()?;
        let remote_sockaddr = stream.peer_addr().ok()?;
        let remote_addr = remote_sockaddr.ip();
        let remote_port = remote_sockaddr.port();
        let mut global = GLOBAL.write().await;
        let router_id = global.router_id;
        let (peer, mgmt_rx) = match global.peers.get_mut(&remote_addr) {
            Some(peer) => {
                if peer.admin_down {
                    println!(
                        "admin down; ignore a new passive connection from {}",
                        remote_addr
                    );
                    return None;
                }
                if peer.mgmt_tx.is_some() {
                    println!("already has connection {}", remote_addr);
                    return None;
                }
                peer.remote_port = remote_port;
                peer.local_port = local_sockaddr.port();
                peer.local_addr = local_sockaddr.ip();
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
                    println!(
                        "can't find configuration a new passive connection {}",
                        remote_addr
                    );
                    return None;
                }
                let (tx, rx) = mpsc::unbounded_channel();
                let mut builder = PeerBuilder::new(remote_addr);
                builder
                    .state(SessionState::Active)
                    .remote_asn(remote_asn)
                    .delete_on_disconnected(true)
                    .rs_client(rs_client)
                    .remote_port(remote_port)
                    .local_port(local_sockaddr.port())
                    .local_addr(local_sockaddr.ip())
                    .ctrl_channel(tx);
                if let Some(holdtime) = holdtime {
                    builder.holdtime(holdtime);
                }
                let _ = global.add_peer(builder.build(), None);
                let peer = global.peers.get_mut(&remote_addr).unwrap();
                (peer, rx)
            }
        };
        Handler::new(
            stream,
            remote_addr,
            peer.local_as,
            router_id,
            peer.local_cap.to_owned(),
            peer.holdtime,
            peer.route_server_client,
            peer.state.clone(),
            peer.counter_tx.clone(),
            peer.counter_rx.clone(),
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
        let as_number = if let Some(asn) = global_config.as_ref().and_then(|x| x.r#as) {
            asn
        } else {
            0
        };
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
            global.as_number = as_number;
            global.router_id = router_id;
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
                            route_server_client: pg.route_server.as_ref().map_or(false, |x| {
                                x.config
                                    .as_ref()
                                    .map_or(false, |x| x.route_server_client.map_or(false, |x| x))
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
                if let Some(prefix) = n.config.as_ref().and_then(|x| x.prefix.as_ref()) {
                    if let Ok(prefix) = packet::IpNet::from_str(prefix) {
                        if let Some(name) = n.config.as_ref().and_then(|x| x.peer_group.as_ref()) {
                            server
                                .peer_group
                                .entry(name.to_string())
                                .and_modify(|e| e.dynamic_peers.push(DynamicPeer { prefix }));
                        }
                    }
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
            match Vec::<api::DefinedSet>::try_from(defined_sets) {
                Ok(sets) => {
                    let mut server = GLOBAL.write().await;
                    for set in sets {
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
            let mut server = GLOBAL.write().await;
            for policy in policies {
                if let Some(name) = &policy.name {
                    let mut s_names = Vec::new();
                    if let Some(statements) = &policy.statements {
                        for s in statements {
                            if let Some(n) = s.name.as_ref() {
                                if h.contains(n) {
                                    s_names.push(n.clone());
                                    continue;
                                }
                            }
                            match api::Statement::try_from(s) {
                                Ok(s) => {
                                    server
                                        .ptable
                                        .add_statement(&s.name, s.conditions, s.actions)
                                        .unwrap();
                                    s_names.push(s.name.clone());
                                    h.insert(s.name);
                                }
                                Err(e) => panic!("{:?}", e),
                            }
                        }
                    }
                    if let Err(e) = server.ptable.add_policy(
                        name,
                        s_names
                            .into_iter()
                            .map(|x| api::Statement {
                                name: x,
                                ..Default::default()
                            })
                            .collect(),
                    ) {
                        panic!("{:?}", e);
                    }
                }
            }
        }
        if let Some(g) = bgp.as_ref().and_then(|x| x.global.as_ref()) {
            let f = |direction: i32,
                     policy_list: Option<&Vec<String>>,
                     action: Option<&config::gen::DefaultPolicyType>|
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
                    default_action: action.map_or(1, |x| x.into()),
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
                    panic!("{:?}", e);
                }
                if let Err(e) = add_policy_assignment(f(
                    2,
                    config.export_policy_list.as_ref(),
                    config.default_export_policy.as_ref(),
                ))
                .await
                {
                    panic!("{:?}", e);
                }
            }
        }
        if let Some(peers) = bgp.as_ref().and_then(|x| x.neighbors.as_ref()) {
            let mut server = GLOBAL.write().await;
            for p in peers {
                server
                    .add_peer(Peer::from(p), Some(active_tx.clone()))
                    .unwrap();
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
        let notify2 = notify.clone();
        tokio::spawn(async move {
            if let Err(e) = tonic::transport::Server::builder()
                .add_service(GobgpApiServer::new(GrpcService::new(notify2, active_tx)))
                .serve(addr)
                .await
            {
                panic!("failed to listen on grpc {}", e);
            }
        });
        notify.notified().await;
        let listen_port = GLOBAL.read().await.listen_port;
        let mut incomings = vec![
            net::create_listen_socket("0.0.0.0".to_string(), listen_port),
            net::create_listen_socket("[::]".to_string(), listen_port),
        ]
        .into_iter()
        .filter(|x| x.is_ok())
        .map(|x| {
            tokio_stream::wrappers::TcpListenerStream::new(
                TcpListener::from_std(x.unwrap()).unwrap(),
            )
        })
        .collect::<Vec<tokio_stream::wrappers::TcpListenerStream>>();
        assert_ne!(incomings.len(), 0);
        let mut next_peer_taker = 0;
        let nr_takers = conn_tx.len();
        loop {
            let mut bgp_listen_futures = FuturesUnordered::new();
            for incoming in &mut incomings {
                bgp_listen_futures.push(incoming.next());
            }
            futures::select_biased! {
                stream = bgp_listen_futures.next() => {
                    if let Some(Some(Ok(stream))) = stream {
                        if let Some(r) = Global::accept_connection(stream).await {
                            let _ = conn_tx[next_peer_taker].send(r);
                            next_peer_taker = (next_peer_taker + 1) % nr_takers;
                        }
                    }
                }
                stream = active_rx.recv().fuse() => {
                    if let Some(stream) = stream {
                        if let Some(r) = Global::accept_connection(stream).await {
                            let _ = conn_tx[next_peer_taker].send(r);
                            next_peer_taker = (next_peer_taker + 1) % nr_takers;
                        }
                    }
                }
            }
        }
    }
}

enum TableEvent {
    // BGP events
    PassUpdate(
        Arc<table::Source>,
        packet::Family,
        Vec<packet::Net>,
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
    bmp_event_tx: FnvHashMap<IpAddr, mpsc::UnboundedSender<bmp::Message>>,

    // global->ptable copies
    global_import_policy: Option<Arc<table::PolicyAssignment>>,
    global_export_policy: Option<Arc<table::PolicyAssignment>>,
}

impl Table {
    fn dealer<T: Hash>(a: T) -> usize {
        let mut hasher = FnvHasher::default();
        a.hash(&mut hasher);
        hasher.finish() as usize % *NUM_TABLES
    }

    async fn serve(idx: usize, mut v: Vec<UnboundedReceiverStream<TableEvent>>) {
        loop {
            let mut futures: FuturesUnordered<_> = v.iter_mut().map(|rx| rx.next()).collect();
            if let Some(Some(msg)) = futures.next().await {
                match msg {
                    TableEvent::PassUpdate(source, family, nets, attrs) => match attrs {
                        Some(attrs) => {
                            let mut t = TABLE[idx].lock().await;
                            // FIXME: non ipv4
                            if family == packet::Family::IPV4 {
                                for bmp_tx in t.bmp_event_tx.values() {
                                    let _ = bmp_tx.send(bmp::Message::RouteMonitoring {
                                        header: bmp::PerPeerHeader::new(
                                            source.remote_asn,
                                            Ipv4Addr::from(source.router_id),
                                            0,
                                            source.peer_addr,
                                            source.uptime as u32,
                                        ),
                                        update: packet::bgp::Message::Update {
                                            reach: nets.to_owned(),
                                            unreach: Vec::new(),
                                            attr: attrs.clone(),
                                            mp_reach: None,
                                            mp_attr: Arc::new(Vec::new()),
                                            mp_unreach: None,
                                        },
                                    });
                                }
                            }
                            for net in nets {
                                let mut filtered = false;
                                if let Some(a) = t.global_import_policy.as_ref() {
                                    if t.rtable.apply_policy(a, &source, &net, &attrs)
                                        == table::Disposition::Reject
                                    {
                                        filtered = true;
                                    }
                                }
                                if let Some(ri) = t.rtable.insert(
                                    source.clone(),
                                    family,
                                    net,
                                    attrs.clone(),
                                    filtered,
                                ) {
                                    if let Some(a) = t.global_export_policy.as_ref() {
                                        if t.rtable.apply_policy(a, &source, &net, &attrs)
                                            == table::Disposition::Reject
                                        {
                                            continue;
                                        }
                                    }
                                    for c in t.peer_event_tx.values() {
                                        let _ = c.send(ToPeerEvent::Advertise(ri.clone()));
                                    }
                                }
                            }
                        }
                        None => {
                            let mut t = TABLE[idx].lock().await;
                            // FIXME: non ipv4
                            if family == packet::Family::IPV4 {
                                for bmp_tx in t.bmp_event_tx.values() {
                                    let _ = bmp_tx.send(bmp::Message::RouteMonitoring {
                                        header: bmp::PerPeerHeader::new(
                                            source.remote_asn,
                                            Ipv4Addr::from(source.router_id),
                                            0,
                                            source.peer_addr,
                                            source.uptime as u32,
                                        ),
                                        update: packet::bgp::Message::Update {
                                            reach: Vec::new(),
                                            unreach: nets.to_owned(),
                                            attr: Arc::new(Vec::new()),
                                            mp_reach: None,
                                            mp_attr: Arc::new(Vec::new()),
                                            mp_unreach: None,
                                        },
                                    });
                                }
                            }
                            for net in nets {
                                if let Some(ri) = t.rtable.remove(source.clone(), family, net) {
                                    for c in t.peer_event_tx.values() {
                                        let _ = c.send(ToPeerEvent::Advertise(ri.clone()));
                                    }
                                }
                            }
                        }
                    },
                    TableEvent::Disconnected(source) => {
                        let mut t = TABLE[idx].lock().await;
                        for change in t.rtable.drop(source) {
                            for c in t.peer_event_tx.values() {
                                let _ = c.send(ToPeerEvent::Advertise(change.clone()));
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

                            tokio::spawn(async move {
                                let peer_addr = h.peer_addr;
                                let _ = h.run(mgmt_rx).await;
                                let mut server = GLOBAL.write().await;
                                if let Some(peer) = server.peers.get_mut(&peer_addr) {
                                    if peer.delete_on_disconnected {
                                        server.peers.remove(&peer_addr);
                                    } else {
                                        peer.reset();
                                        enable_active_connect(peer, active_conn_tx.clone());
                                    }
                                }
                            });
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
    peer_addr: IpAddr,
    local_addr: IpAddr,

    local_as: u32,

    local_router_id: Ipv4Addr,

    state: Arc<PeerState>,

    counter_tx: Arc<MessageCounter>,
    counter_rx: Arc<MessageCounter>,

    local_cap: Vec<packet::Capability>,

    local_holdtime: u64,
    negotiated_holdtime: u64,
    rs_client: bool,

    family_cap: FnvHashMap<packet::Family, packet::FamilyCapability>,

    stream: Option<TcpStream>,
    keepalive_timer: tokio::time::Interval,
    source: Option<Arc<table::Source>>,
    table_tx: Vec<mpsc::UnboundedSender<TableEvent>>,
    peer_event_tx: Vec<mpsc::UnboundedSender<ToPeerEvent>>,
    holdtimer_renewed: Instant,
    shutdown: Option<bmp::PeerDownReason>,
}

impl Handler {
    fn new(
        stream: TcpStream,
        peer_addr: IpAddr,
        local_as: u32,
        local_router_id: Ipv4Addr,
        local_cap: Vec<packet::Capability>,
        local_holdtime: u64,
        rs_client: bool,
        state: Arc<PeerState>,
        counter_tx: Arc<MessageCounter>,
        counter_rx: Arc<MessageCounter>,
    ) -> Option<Self> {
        let local_sockaddr = stream.local_addr().ok()?;
        Some(Handler {
            peer_addr,
            local_addr: local_sockaddr.ip(),
            local_router_id,
            local_as,
            state,
            counter_tx,
            counter_rx,
            local_cap,
            local_holdtime,
            negotiated_holdtime: 0,
            rs_client,
            family_cap: FnvHashMap::default(),
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
        })
    }

    async fn rx_update(
        &mut self,
        reach: Vec<packet::Net>,
        unreach: Vec<packet::Net>,
        attr: Arc<Vec<packet::Attribute>>,
        mp_reach: Option<(packet::Family, Vec<packet::Net>)>,
        mp_attr: Arc<Vec<packet::Attribute>>,
        mp_unreach: Option<(packet::Family, Vec<packet::Net>)>,
    ) {
        let mut add = FnvHashMap::default();
        for net in reach {
            add.entry(packet::Family::IPV4)
                .or_insert_with(FnvHashMap::default)
                .entry(Table::dealer(&net))
                .or_insert_with(Vec::new)
                .push(net);
        }
        if let Some((family, mp_reach)) = mp_reach {
            for net in mp_reach {
                add.entry(family)
                    .or_insert_with(FnvHashMap::default)
                    .entry(Table::dealer(&net))
                    .or_insert_with(Vec::new)
                    .push(net);
            }
        }
        let mut del = FnvHashMap::default();
        for net in unreach {
            del.entry(packet::Family::IPV4)
                .or_insert_with(FnvHashMap::default)
                .entry(Table::dealer(&net))
                .or_insert_with(Vec::new)
                .push(net);
        }
        if let Some((family, mp_unreach)) = mp_unreach {
            for net in mp_unreach {
                del.entry(family)
                    .or_insert_with(FnvHashMap::default)
                    .entry(Table::dealer(&net))
                    .or_insert_with(Vec::new)
                    .push(net);
            }
        }
        for (family, v) in add {
            for (idx, nets) in v {
                let _ = self.table_tx[idx].send(TableEvent::PassUpdate(
                    self.source.as_ref().unwrap().clone(),
                    family,
                    nets,
                    {
                        if family == packet::Family::IPV4 {
                            Some(attr.clone())
                        } else {
                            Some(mp_attr.clone())
                        }
                    },
                ));
            }
        }
        for (family, v) in del {
            for (idx, nets) in v {
                let _ = self.table_tx[idx].send(TableEvent::PassUpdate(
                    self.source.as_ref().unwrap().clone(),
                    family,
                    nets,
                    None,
                ));
            }
        }
    }

    async fn rx_msg(
        &mut self,
        local_sockaddr: SocketAddr,
        remote_sockaddr: SocketAddr,
        msg: bgp::Message,
        pending: &mut PendingTx,
    ) -> std::result::Result<(), Error> {
        match msg {
            bgp::Message::Open {
                version: _,
                as_number,
                holdtime,
                router_id,
                mut capability,
            } => {
                pending.urgent.push(bgp::Message::Keepalive);
                self.state
                    .remote_holdtime
                    .store(holdtime, Ordering::Relaxed);
                self.state
                    .remote_id
                    .store(router_id.into(), Ordering::Relaxed);
                let remote_asn = self.state.remote_asn.load(Ordering::Relaxed);
                if remote_asn != 0 && remote_asn != as_number {
                    pending.urgent.insert(
                        0,
                        bgp::Message::Notification {
                            code: 2,
                            subcode: 2,
                            data: Vec::new(),
                        },
                    );
                    return Ok(());
                }
                self.state.remote_asn.store(as_number, Ordering::Relaxed);
                self.family_cap = packet::bgp::family_capabilities(&self.local_cap, &capability);
                self.state.remote_cap.write().await.append(&mut capability);
                self.negotiated_holdtime = std::cmp::min(self.local_holdtime, holdtime as u64);
                if self.negotiated_holdtime != 0 {
                    self.keepalive_timer =
                        tokio::time::interval(Duration::from_secs(self.negotiated_holdtime / 3));
                }
                self.state
                    .fsm
                    .store(SessionState::OpenConfirm as u8, Ordering::Release);
                Ok(())
            }
            bgp::Message::Update {
                reach,
                attr,
                unreach,
                mp_reach,
                mp_attr,
                mp_unreach,
            } => {
                let session_state = self.state.fsm.load(Ordering::Relaxed);
                if session_state != SessionState::Established as u8 {
                    return Err(Error::InvalidMessageFormat {
                        code: 5,
                        subcode: session_state,
                        data: Vec::new(),
                    });
                }
                self.holdtimer_renewed = Instant::now();
                self.rx_update(reach, unreach, attr, mp_reach, mp_attr, mp_unreach)
                    .await;
                Ok(())
            }
            bgp::Message::Notification {
                code,
                subcode,
                data,
            } => {
                println!("{}: notification {} {}", self.peer_addr, code, subcode);
                self.shutdown = Some(bmp::PeerDownReason::RemoteNotification(
                    bgp::Message::Notification {
                        code,
                        subcode,
                        data,
                    },
                ));
                Ok(())
            }
            bgp::Message::Keepalive => {
                self.holdtimer_renewed = Instant::now();
                if self.state.fsm.load(Ordering::Relaxed) == SessionState::OpenConfirm as u8 {
                    let uptime = SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    self.state.uptime.store(uptime, Ordering::Relaxed);
                    let remote_asn = self.state.remote_asn.load(Ordering::Relaxed);
                    let t = if self.local_as == self.state.remote_asn.load(Ordering::Relaxed) {
                        table::PeerType::Ibgp
                    } else {
                        table::PeerType::Ebgp
                    };
                    self.state
                        .fsm
                        .store(SessionState::Established as u8, Ordering::Release);
                    self.source = Some(Arc::new(table::Source::new(
                        self.peer_addr,
                        Ipv4Addr::from(self.state.remote_id.load(Ordering::Relaxed)),
                        t,
                        self.local_addr,
                        self.local_as,
                        remote_asn,
                        self.rs_client,
                        uptime,
                    )));

                    let d = Table::dealer(&self.peer_addr);
                    for i in 0..*NUM_TABLES {
                        let mut t = TABLE[i].lock().await;
                        for f in self.family_cap.keys() {
                            if f == &packet::Family::IPV4 {
                                for c in t.rtable.best(f).into_iter() {
                                    pending.insert_change(c);
                                }
                            } else {
                                pending.urgent.append(
                                    &mut t.rtable.best(f).into_iter().map(|x| x.into()).collect(),
                                );
                            }
                        }
                        t.peer_event_tx
                            .insert(self.peer_addr, self.peer_event_tx.remove(0));

                        let tx = t.table_event_tx[d].clone();
                        self.table_tx.push(tx);

                        if i == 0 {
                            for bmp_tx in t.bmp_event_tx.values() {
                                let bmp_msg = bmp::Message::PeerUp {
                                    header: bmp::PerPeerHeader::new(
                                        remote_asn,
                                        Ipv4Addr::from(
                                            self.state.remote_id.load(Ordering::Relaxed),
                                        ),
                                        0,
                                        remote_sockaddr.ip(),
                                        uptime as u32,
                                    ),
                                    local_addr: self.local_addr,
                                    local_port: local_sockaddr.port(),
                                    remote_port: remote_sockaddr.port(),
                                    remote_open: bgp::Message::Open {
                                        version: 4,
                                        as_number: remote_asn,
                                        holdtime: self
                                            .state
                                            .remote_holdtime
                                            .load(Ordering::Relaxed),
                                        router_id: Ipv4Addr::from(
                                            self.state.remote_id.load(Ordering::Relaxed),
                                        ),
                                        capability: self.state.remote_cap.read().await.to_owned(),
                                    },
                                    local_open: bgp::Message::Open {
                                        version: 4,
                                        as_number: remote_asn,
                                        holdtime: self
                                            .state
                                            .remote_holdtime
                                            .load(Ordering::Relaxed),
                                        router_id: Ipv4Addr::from(
                                            self.state.remote_id.load(Ordering::Relaxed),
                                        ),
                                        capability: self.local_cap.to_owned(),
                                    },
                                };
                                let _ = bmp_tx.send(bmp_msg);
                            }
                        }
                    }
                    pending.sync = true;
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
        let mut stream = self.stream.take().unwrap();
        let remote_sockaddr = stream.peer_addr()?;
        let local_sockaddr = stream.local_addr()?;
        let rxbuf_size = 1 << 16;
        let mut txbuf_size = 1 << 16;
        if let Ok(r) =
            nix::sys::socket::getsockopt(stream.as_raw_fd(), nix::sys::socket::sockopt::SndBuf)
        {
            txbuf_size = std::cmp::min(txbuf_size, r / 2);
        }

        let mut codec = packet::bgp::BgpCodec::new()
            .local_as(self.local_as)
            .local_addr(self.local_addr);
        if self.rs_client {
            codec = codec.keep_aspath(true).keep_nexthop(true);
        }

        let mut peer_event_rx = Vec::new();
        for _ in 0..*NUM_TABLES {
            let (tx, rx) = mpsc::unbounded_channel();
            self.peer_event_tx.push(tx);
            peer_event_rx.push(UnboundedReceiverStream::new(rx));
        }

        let mut pending = PendingTx {
            urgent: vec![bgp::Message::Open {
                version: 4,
                as_number: self.local_as,
                holdtime: self.local_holdtime as u16,
                router_id: self.local_router_id,
                capability: self.local_cap.to_owned(),
            }],
            ..Default::default()
        };

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
            let interest = if pending.is_empty() {
                tokio::io::Interest::READABLE
            } else {
                tokio::io::Interest::READABLE | tokio::io::Interest::WRITABLE
            };

            let oldstate = self.state.fsm.load(Ordering::Relaxed);
            futures::select_biased! {
                _ = self.keepalive_timer.tick().fuse() => {
                    if self.state.fsm.load(Ordering::Relaxed) == SessionState::Established as u8 {
                        pending.urgent.insert(0, bgp::Message::Keepalive);
                    }
                }
                msg = mgmt_rx.recv().fuse() => {
                    if let Some(PeerMgmtMsg::Notification(msg)) = msg {
                        pending.urgent.insert(0, msg);
                    }
                }
                _ = holdtime_futures.next() => {
                    let elapsed = self.holdtimer_renewed.elapsed().as_secs();
                    if elapsed > self.negotiated_holdtime + 20 {
                        println!("{}: holdtime expired {}", self.peer_addr, self.holdtimer_renewed.elapsed().as_secs());
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
                                if !self.family_cap.contains_key(&ri.family) {
                                    continue;
                                }
                                if ri.family == packet::Family::IPV4 {
                                    pending.insert_change(ri);
                                } else {
                                    pending.urgent.push(ri.into());
                                }
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
                                    match codec.decode(&mut rxbuf) {
                                    Ok(msg) => match msg {
                                        Some(msg) => {
                                            (*self.counter_rx).sync(&msg);
                                            let _ = self.rx_msg(local_sockaddr, remote_sockaddr, msg, &mut pending).await;
                                        }
                                        None => {
                                            // partial read
                                            break;
                                        },
                                    }
                                    Err(e) => {
                                        if let Error::InvalidMessageFormat{code, subcode, data} = e {
                                            pending.urgent.insert(0, bgp::Message::Notification{code, subcode, data: data.to_owned()});
                                            self.shutdown = Some(bmp::PeerDownReason::LocalNotification(bgp::Message::Notification{code, subcode, data}));
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
                        let mut txbuf = bytes::BytesMut::with_capacity(txbuf_size);
                        for _ in 0..pending.urgent.len() {
                            let msg = pending.urgent.remove(0);
                            let _ = codec.encode(&msg, &mut txbuf);
                            (*self.counter_tx).sync(&msg);

                            if txbuf.len() > txbuf_size {
                                let buf = txbuf.freeze();
                                txbuf = bytes::BytesMut::with_capacity(txbuf_size);
                                if stream.write_all(&buf).await.is_err() {
                                    self.shutdown = Some(bmp::PeerDownReason::RemoteUnexpected);
                                    break;
                                }
                            }
                        }
                        if !txbuf.is_empty() && stream.write_all(&txbuf.freeze()).await.is_err() {
                            self.shutdown = Some(bmp::PeerDownReason::RemoteUnexpected);
                        }

                        let unreach: Vec<packet::Net> = pending.unreach.drain().collect();
                        if !unreach.is_empty() {
                            txbuf = bytes::BytesMut::with_capacity(txbuf_size);
                            let msg = bgp::Message::Update{
                                reach: Vec::new(),
                                attr: Arc::new(Vec::new()),
                                unreach,
                                mp_reach: None,
                                mp_attr: Arc::new(Vec::new()),
                                mp_unreach: None,
                            };
                            let _ = codec.encode(&msg, &mut txbuf);
                            self.counter_tx.sync(&msg);
                            if !txbuf.is_empty() && stream.write_all(&txbuf.freeze()).await.is_err() {
                                self.shutdown = Some(bmp::PeerDownReason::RemoteUnexpected);
                            }
                        }

                        txbuf = bytes::BytesMut::with_capacity(txbuf_size);
                        let max_tx_count = 2048;
                        let mut sent = Vec::with_capacity(max_tx_count);
                        for (attr, reach) in pending.bucket.iter() {
                            let msg = bgp::Message::Update{
                                reach: reach.iter().copied().collect(),
                                attr: attr.clone(),
                                unreach: Vec::new(),
                                mp_reach: None,
                                mp_attr: Arc::new(Vec::new()),
                                mp_unreach: None,
                            };
                            let _ = codec.encode(&msg, &mut txbuf);
                            self.counter_tx.sync(&msg);
                            sent.push(attr.clone());

                            if txbuf.len() > txbuf_size {
                                let buf = txbuf.freeze();
                                txbuf = bytes::BytesMut::with_capacity(txbuf_size);
                                if stream.write_all(&buf).await.is_err() {
                                    self.shutdown = Some(bmp::PeerDownReason::RemoteUnexpected);
                                    break;
                                }
                            }

                            if sent.len() > max_tx_count {
                                break;
                            }
                        }
                        if !txbuf.is_empty() && stream.write_all(&txbuf.freeze()).await.is_err() {
                            self.shutdown = Some(bmp::PeerDownReason::RemoteUnexpected);
                        }

                        for attr in sent.drain(..) {
                            let mut bucket = pending.bucket.remove(&attr).unwrap();
                            for net in bucket.drain() {
                                let _ = pending.reach.remove(&net).unwrap();
                            }
                        }

                        if pending.sync && pending.is_empty() && self.state.fsm.load(Ordering::Relaxed) == SessionState::Established as u8 {
                            pending.sync = false;
                            let mut b = bytes::BytesMut::with_capacity(txbuf_size);
                            for msg in  self.family_cap.iter().map(|(k,_)| bgp::Message::eor(*k)) {
                                let _ = codec.encode(&msg, &mut b);
                            }
                            if stream.write_all(&b.freeze()).await.is_err() {
                                self.shutdown = Some(bmp::PeerDownReason::RemoteUnexpected);
                                break;
                            }
                        }
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
            for i in 0..*NUM_TABLES {
                let mut t = TABLE[i].lock().await;
                t.peer_event_tx.remove(&self.peer_addr);
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
                                source.peer_addr,
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

#[derive(Default)]
struct PendingTx {
    urgent: Vec<bgp::Message>,
    reach: FnvHashMap<packet::Net, Arc<Vec<packet::Attribute>>>,
    unreach: FnvHashSet<packet::Net>,
    bucket: FnvHashMap<Arc<Vec<packet::Attribute>>, FnvHashSet<packet::Net>>,
    sync: bool,
}

impl PendingTx {
    fn is_empty(&self) -> bool {
        self.urgent.is_empty() && self.reach.is_empty() && self.unreach.is_empty()
    }

    fn insert_change(&mut self, change: table::Change) {
        if change.attr.is_empty() {
            if let Some(attr) = self.reach.remove(&change.net) {
                let set = self.bucket.get_mut(&attr).unwrap();
                let b = set.remove(&change.net);
                assert!(b);
                if set.is_empty() {
                    self.bucket.remove(&attr);
                }
            }
            self.unreach.insert(change.net);
        } else {
            self.unreach.remove(&change.net);

            // a) net doesn't exists in reach
            // a-1) the attr exists in bucket (with other nets)
            //  -> add the net to reach with the attr
            //  -> add the net to the attr bucket
            // a-2) the attr doesn't exist either in bucket
            //  -> add the net to reach with the attr
            //  -> create attr bucket and the net to add it
            //
            // b) net already exists in reach
            // b-1) the old attr in reach same to the attr
            //  -> nothing to do
            // b-2) the old attr in reach not same to the attr
            // b-2-1) the attr exists in bucket
            //  -> update the net's attr in reach
            //  -> remove the net from the old attr bucket
            //  -> add the net to the attr bucket
            // b-2-2) the attr doesn't exist in bucket
            //  -> update the net's attr in reach
            //  -> remove the net from the old attr bucket
            //  -> create attr bucket add he net to it

            if let Some(old_attr) = self.reach.insert(change.net, change.attr.clone()) {
                // b-1)
                if old_attr == change.attr {
                    return;
                }

                // b-2-1) and b-2-2)
                let old_bucket = self.bucket.get_mut(&old_attr).unwrap();
                let b = old_bucket.remove(&change.net);
                assert!(b);
                if old_bucket.is_empty() {
                    self.bucket.remove(&old_attr);
                }

                let bucket = self
                    .bucket
                    .entry(change.attr)
                    .or_insert_with(FnvHashSet::default);
                bucket.insert(change.net);
            } else {
                // a-1) and a-2)
                let bucket = self
                    .bucket
                    .entry(change.attr)
                    .or_insert_with(FnvHashSet::default);
                bucket.insert(change.net);
            }
        }
    }
}

#[test]
fn bucket() {
    let src = Arc::new(table::Source::new(
        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 1)),
        Ipv4Addr::new(127, 0, 0, 1),
        table::PeerType::Ebgp,
        IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
        1,
        2,
        false,
        0,
    ));
    let family = packet::Family::IPV4;

    let net1 = packet::Net::from_str("10.0.0.0/24").unwrap();
    let net2 = packet::Net::from_str("20.0.0.0/24").unwrap();

    let attr1 = vec![packet::Attribute::new_with_value(packet::Attribute::ORIGIN, 0).unwrap()];

    let mut pending = PendingTx::default();

    pending.insert_change(table::Change {
        source: src.clone(),
        family,
        net: net1,
        attr: Arc::new(attr1.clone()),
    });

    pending.insert_change(table::Change {
        source: src.clone(),
        family: packet::Family::IPV4,
        net: net2,
        attr: Arc::new(vec![packet::Attribute::new_with_value(
            packet::Attribute::ORIGIN,
            0,
        )
        .unwrap()]),
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
        attr: Arc::new(vec![packet::Attribute::new_with_value(
            packet::Attribute::ORIGIN,
            0,
        )
        .unwrap()]),
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
        attr: Arc::new(vec![packet::Attribute::new_with_value(
            packet::Attribute::ORIGIN,
            1,
        )
        .unwrap()]),
    });
    assert_eq!(2, pending.bucket.len());
    assert_eq!(&Arc::new(attr2), pending.reach.get(&net2).unwrap());
    assert_eq!(
        1,
        pending.bucket.get(&Arc::new(attr1.clone())).unwrap().len()
    );
}
