// Copyright (C) 2019 The RustyBGP Authors.
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

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr},
    pin::Pin,
    str::FromStr,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant, SystemTime},
};

use tokio::{
    codec::{Decoder, Encoder, Framed},
    net::{TcpListener, TcpStream},
    prelude::*,
    sync::{mpsc, Mutex},
};
use tokio_timer::{timer::Handle, Delay};

use bytes::{BufMut, BytesMut};
use clap::{App, Arg};
use prost;

mod api {
    tonic::include_proto!("gobgpapi");
}
use api::server::{GobgpApi, GobgpApiServer};

use proto::bgp;

fn to_any<T: prost::Message>(m: T, name: &str) -> prost_types::Any {
    let mut v = Vec::new();
    m.encode(&mut v).unwrap();
    prost_types::Any {
        type_url: format!("type.googleapis.com/gobgpapi.{}", name),
        value: v,
    }
}

trait ToApi<T: prost::Message> {
    fn to_api(&self) -> T;
}

impl ToApi<prost_types::Timestamp> for SystemTime {
    fn to_api(&self) -> prost_types::Timestamp {
        let unix = self.duration_since(SystemTime::UNIX_EPOCH).unwrap();
        prost_types::Timestamp {
            seconds: unix.as_secs() as i64,
            nanos: unix.subsec_nanos() as i32,
        }
    }
}

impl ToApi<api::Family> for bgp::Family {
    fn to_api(&self) -> api::Family {
        match self {
            bgp::Family::Ipv4Uc => api::Family {
                afi: api::family::Afi::Ip as i32,
                safi: api::family::Safi::Unicast as i32,
            },
            bgp::Family::Ipv6Uc => api::Family {
                afi: api::family::Afi::Ip as i32,
                safi: api::family::Safi::Unicast as i32,
            },
            bgp::Family::Unknown(v) => api::Family {
                afi: (v >> 16) as i32,
                safi: (v & 0xff) as i32,
            },
        }
    }
}

#[derive(Clone)]
pub struct PathAttr {
    pub entry: Vec<bgp::Attribute>,
}

#[derive(Clone)]
pub struct Path {
    pub source: IpAddr,
    pub timestamp: SystemTime,
    pub as_number: u32,
    pub nexthop: IpAddr,
    pub attrs: Arc<PathAttr>,
}

impl Path {
    fn new(source: IpAddr, nexthop: IpAddr, attrs: Arc<PathAttr>) -> Path {
        Path {
            source: source,
            timestamp: SystemTime::now(),
            as_number: 0,
            attrs,
            nexthop,
        }
    }

    fn to_api(&self, net: &bgp::Nlri) -> api::Path {
        let mut path: api::Path = Default::default();

        match net {
            bgp::Nlri::Ip(ipnet) => {
                let nlri = api::IpAddressPrefix {
                    prefix: ipnet.addr.to_string(),
                    prefix_len: ipnet.mask as u32,
                };
                path.nlri = Some(to_any(nlri, "IPAddressPrefix"));
            }
        }

        path.family = match net {
            bgp::Nlri::Ip(ipnet) => match ipnet.addr {
                IpAddr::V4(_) => Some(bgp::Family::Ipv4Uc.to_api()),
                IpAddr::V6(_) => Some(bgp::Family::Ipv6Uc.to_api()),
            },
        };

        path.age = Some(self.timestamp.to_api());

        let mut attrs = Vec::new();
        attrs.push(to_any(
            api::NextHopAttribute {
                next_hop: self.nexthop.to_string(),
            },
            "NextHopAttribute",
        ));
        for attr in &self.attrs.entry {
            match attr {
                bgp::Attribute::Origin { origin } => {
                    let a = api::OriginAttribute {
                        origin: *origin as u32,
                    };
                    attrs.push(to_any(a, "OriginAttribute"));
                }
                bgp::Attribute::AsPath { segments } => {
                    let l: Vec<api::AsSegment> = segments
                        .iter()
                        .map(|segment| api::AsSegment {
                            r#type: segment.segment_type as u32,
                            numbers: segment.number.iter().map(|x| *x).collect(),
                        })
                        .collect();
                    let a = api::AsPathAttribute {
                        segments: From::from(l),
                    };
                    attrs.push(to_any(a, "AsPathAttribute"));
                }
                bgp::Attribute::Nexthop { nexthop } => {
                    let a = api::NextHopAttribute {
                        next_hop: nexthop.to_string(),
                    };
                    attrs.push(to_any(a, "NextHopAttribute"));
                }
                bgp::Attribute::MultiExitDesc { descriptor } => {
                    let a = api::MultiExitDiscAttribute { med: *descriptor };
                    attrs.push(to_any(a, "MultiExitDiscAttribute"));
                }
                bgp::Attribute::LocalPref { preference } => {
                    let a = api::LocalPrefAttribute {
                        local_pref: *preference,
                    };
                    attrs.push(to_any(a, "LocalPrefAttribute"));
                }
                bgp::Attribute::AtomicAggregate => {
                    attrs.push(to_any(
                        api::AtomicAggregateAttribute {},
                        "AtomicAggregateAttribute",
                    ));
                }
                bgp::Attribute::Aggregator {
                    four_byte: _,
                    number,
                    address,
                } => {
                    let a = api::AggregatorAttribute {
                        r#as: *number,
                        address: address.to_string(),
                    };
                    attrs.push(to_any(a, "AggregatorAttribute"));
                }
                bgp::Attribute::Community { communities } => {
                    let a = api::CommunitiesAttribute {
                        communities: communities.iter().map(|x| *x).collect(),
                    };
                    attrs.push(to_any(a, "CommunitiesAttribute"));
                }
                bgp::Attribute::OriginatorId { address } => {
                    let a = api::OriginatorIdAttribute {
                        id: address.to_string(),
                    };
                    attrs.push(to_any(a, "OriginatorIdAttribute"));
                }
                bgp::Attribute::ClusterList { addresses } => {
                    let a = api::ClusterListAttribute {
                        ids: addresses.iter().map(|x| x.to_string()).collect(),
                    };
                    attrs.push(to_any(a, "ClusterListAttribute"));
                }
                _ => {}
            }
        }
        path.pattrs = attrs;

        path
    }

    pub fn get_local_preference(&self) -> u32 {
        const DEFAULT: u32 = 100;
        for a in &self.attrs.entry {
            match a {
                bgp::Attribute::LocalPref { preference } => return *preference,
                _ => {}
            }
        }
        return DEFAULT;
    }

    pub fn get_as_len(&self) -> u32 {
        for a in &self.attrs.entry {
            match a {
                bgp::Attribute::AsPath { segments } => {
                    let mut l: usize = 0;
                    for s in segments {
                        l += s.as_len();
                    }
                    return l as u32;
                }
                _ => {}
            }
        }
        0
    }

    pub fn get_origin(&self) -> u8 {
        for a in &self.attrs.entry {
            match a {
                bgp::Attribute::Origin { origin } => return *origin,
                _ => {}
            }
        }
        0
    }

    pub fn get_med(&self) -> u32 {
        for a in &self.attrs.entry {
            match a {
                bgp::Attribute::MultiExitDesc { descriptor } => return *descriptor,
                _ => {}
            }
        }
        return 0;
    }
}

#[derive(Clone)]
pub struct Destination {
    pub net: bgp::Nlri,
    pub entry: Vec<Path>,
}

impl Destination {
    pub fn new(net: bgp::Nlri) -> Destination {
        Destination {
            net: net,
            entry: Vec::new(),
        }
    }

    pub fn to_api(&self, paths: Vec<api::Path>) -> api::Destination {
        api::Destination {
            prefix: self.net.to_string(),
            paths: From::from(paths),
        }
    }
}

pub enum TableUpdate {
    NewBest(bgp::Nlri, Arc<PathAttr>),
    Withdrawn(bgp::Nlri),
}

type Tx = mpsc::UnboundedSender<TableUpdate>;
type Rx = mpsc::UnboundedReceiver<TableUpdate>;

#[derive(Clone)]
pub struct Table {
    pub disable_best_path_selection: bool,
    pub master: HashMap<bgp::Family, HashMap<bgp::Nlri, Destination>>,

    pub active_peers: HashMap<IpAddr, Tx>,
}

impl Table {
    pub fn new() -> Table {
        Table {
            disable_best_path_selection: false,
            master: HashMap::new(),
            active_peers: HashMap::new(),
        }
    }

    pub fn insert(
        &mut self,
        family: bgp::Family,
        net: bgp::Nlri,
        source: IpAddr,
        nexthop: IpAddr,
        attrs: Arc<PathAttr>,
    ) -> (Option<TableUpdate>, bool) {
        let t = self.master.get_mut(&family);
        let t = match t {
            Some(t) => t,
            None => {
                self.master.insert(family, HashMap::new());
                self.master.get_mut(&family).unwrap()
            }
        };

        let mut replaced = false;
        let mut new_best = false;
        let attrs = match t.get_mut(&net) {
            Some(d) => {
                for i in 0..d.entry.len() {
                    if d.entry[i].source == source {
                        d.entry.remove(i);
                        replaced = true;
                        if i == 0 {
                            new_best = true;
                        }
                        break;
                    }
                }

                let b = Path::new(source, nexthop, attrs);

                let idx = if self.disable_best_path_selection == true {
                    0
                } else {
                    let mut idx = d.entry.len();
                    for i in 0..d.entry.len() {
                        let a = &d.entry[i];

                        if b.get_local_preference() > a.get_local_preference() {
                            idx = i;
                            break;
                        }

                        if b.get_as_len() < a.get_as_len() {
                            idx = i;
                            break;
                        }

                        if b.get_origin() < a.get_origin() {
                            idx = i;
                            break;
                        }

                        if b.get_med() < a.get_med() {
                            idx = i;
                            break;
                        }
                    }
                    idx
                };
                if idx == 0 {
                    new_best = true;
                }
                d.entry.insert(idx, b);
                d.entry[0].attrs.clone()
            }

            None => {
                let mut d = Destination::new(net);
                let a = attrs.clone();
                d.entry.push(Path::new(source, nexthop, attrs));
                t.insert(net, d);
                new_best = true;
                a
            }
        };
        if self.disable_best_path_selection == false && new_best {
            (Some(TableUpdate::NewBest(net, attrs)), !replaced)
        } else {
            (None, !replaced)
        }
    }

    pub fn remove(
        &mut self,
        family: bgp::Family,
        net: bgp::Nlri,
        source: IpAddr,
    ) -> (Option<TableUpdate>, bool) {
        let t = self.master.get_mut(&family);
        if t.is_none() {
            return (None, false);
        }
        let t = t.unwrap();
        match t.get_mut(&net) {
            Some(d) => {
                for i in 0..d.entry.len() {
                    if d.entry[i].source == source {
                        d.entry.remove(i);
                        if d.entry.len() == 0 {
                            t.remove(&net);
                            return (Some(TableUpdate::Withdrawn(net)), true);
                        }
                        if i == 0 {
                            return (
                                Some(TableUpdate::NewBest(net, d.entry[0].attrs.clone())),
                                true,
                            );
                        } else {
                            return (None, true);
                        }
                    }
                }
            }
            None => {}
        }
        return (None, false);
    }

    pub fn clear(&mut self, source: IpAddr) -> Vec<TableUpdate> {
        let mut update = Vec::new();
        let mut m: HashMap<bgp::Family, Vec<bgp::Nlri>> = HashMap::new();
        for f in self.master.keys() {
            m.insert(*f, Vec::new());
        }

        for (f, t) in self.master.iter_mut() {
            for (n, d) in t {
                for i in 0..d.entry.len() {
                    if d.entry[i].source == source {
                        d.entry.remove(i);
                        if d.entry.len() == 0 {
                            update.push(TableUpdate::Withdrawn(*n));
                        } else if i == 0 {
                            update.push(TableUpdate::NewBest(*n, d.entry[0].attrs.clone()));
                        }
                        break;
                    }
                }

                if d.entry.len() == 0 {
                    m.get_mut(f).unwrap().push(*n);
                }
            }
        }

        for (f, l) in m.iter() {
            let t = self.master.get_mut(&f).unwrap();
            for n in l {
                t.remove(n);
            }
        }
        update
    }

    pub async fn broadcast(&mut self, source: IpAddr, msg: &TableUpdate) {
        for peer in self.active_peers.iter_mut() {
            if *peer.0 != source {
                match msg {
                    TableUpdate::NewBest(nlri, attrs) => {
                        peer.1
                            .send(TableUpdate::NewBest(*nlri, attrs.clone()))
                            .await
                            .unwrap();
                    }
                    TableUpdate::Withdrawn(nlri) => {
                        peer.1.send(TableUpdate::Withdrawn(*nlri)).await.unwrap();
                    }
                }
            }
        }
    }
}

#[derive(Default)]
pub struct MessageCounter {
    pub open: u64,
    pub update: u64,
    pub notification: u64,
    pub keepalive: u64,
    pub refresh: u64,
    pub discarded: u64,
    pub total: u64,
    pub withdraw_update: u64,
    pub withdraw_prefix: u64,
}

impl ToApi<api::Message> for MessageCounter {
    fn to_api(&self) -> api::Message {
        api::Message {
            open: self.open,
            update: self.update,
            notification: self.notification,
            keepalive: self.keepalive,
            refresh: self.refresh,
            discarded: self.discarded,
            total: self.total,
            withdraw_update: self.withdraw_update,
            withdraw_prefix: self.withdraw_prefix,
        }
    }
}

impl MessageCounter {
    pub fn sync(&mut self, msg: &bgp::Message) {
        match msg {
            bgp::Message::Open(_) => self.open += 1,
            bgp::Message::Update(update) => {
                self.update += 1;
                self.withdraw_prefix += update.withdrawns.len() as u64;
                if update.withdrawns.len() > 0 {
                    self.withdraw_update += 1;
                }
            }
            bgp::Message::Notification(_) => self.notification += 1,
            bgp::Message::Keepalive => self.keepalive += 1,
            bgp::Message::RouteRefresh(_) => self.refresh += 1,
            _ => self.discarded += 1,
        }
        self.total += 1;
    }
}

pub struct Peer {
    pub address: IpAddr,
    pub remote_as: u32,
    pub router_id: Ipv4Addr,
    pub local_as: u32,
    pub peer_type: u8,
    pub state: bgp::State,
    pub uptime: SystemTime,
    pub downtime: SystemTime,

    pub counter_tx: MessageCounter,
    pub counter_rx: MessageCounter,

    pub accepted: u64,

    pub remote_cap: Vec<bgp::Capability>,
    pub local_cap: Vec<bgp::Capability>,
}

impl Peer {
    fn addr(&self) -> String {
        self.address.to_string()
    }

    pub fn new(address: IpAddr) -> Peer {
        Peer {
            address: address,
            remote_as: 0,
            router_id: Ipv4Addr::new(0, 0, 0, 0),
            local_as: 0,
            peer_type: 0,
            state: bgp::State::Idle,
            uptime: SystemTime::UNIX_EPOCH,
            downtime: SystemTime::UNIX_EPOCH,
            counter_tx: Default::default(),
            counter_rx: Default::default(),
            accepted: 0,
            remote_cap: Vec::new(),
            local_cap: Vec::new(),
        }
    }

    fn reset(&mut self) {
        self.state = bgp::State::Idle;
        self.downtime = SystemTime::now();
        self.accepted = 0;
        self.remote_cap = Vec::new();
    }
}

impl ToApi<api::Peer> for Peer {
    fn to_api(&self) -> api::Peer {
        let mut ps = api::PeerState {
            neighbor_address: self.addr(),
            peer_as: self.remote_as,
            router_id: self.router_id.to_string(),
            messages: Some(api::Messages {
                received: Some(self.counter_rx.to_api()),
                sent: Some(self.counter_tx.to_api()),
            }),
            queues: Some(Default::default()),
            remote_cap: self.remote_cap.iter().map(|c| c.to_api()).collect(),
            local_cap: self.local_cap.iter().map(|c| c.to_api()).collect(),
            ..Default::default()
        };
        ps.session_state = match self.state {
            bgp::State::Idle => api::peer_state::SessionState::Idle as i32,
            bgp::State::Active => api::peer_state::SessionState::Active as i32,
            bgp::State::Connect => api::peer_state::SessionState::Connect as i32,
            bgp::State::OpenSent => api::peer_state::SessionState::Opensent as i32,
            bgp::State::OpenConfirm => api::peer_state::SessionState::Openconfirm as i32,
            bgp::State::Established => api::peer_state::SessionState::Established as i32,
        };
        let mut tm = api::Timers {
            config: Some(Default::default()),
            state: Some(Default::default()),
        };
        if self.uptime != SystemTime::UNIX_EPOCH {
            let ts = api::TimersState {
                uptime: Some(self.uptime.to_api()),
                ..Default::default()
            };
            tm.state = Some(ts);
        }
        let afisafis = vec![api::AfiSafi {
            state: Some(api::AfiSafiState {
                family: Some(bgp::Family::Ipv4Uc {}.to_api()),
                enabled: true,
                received: self.accepted,
                accepted: self.accepted,
                ..Default::default()
            }),
            ..Default::default()
        }];
        api::Peer {
            state: Some(ps),
            conf: Some(Default::default()),
            timers: Some(tm),
            route_reflector: Some(Default::default()),
            route_server: Some(Default::default()),
            afi_safis: afisafis,
            ..Default::default()
        }
    }
}

impl ToApi<prost_types::Any> for bgp::Capability {
    fn to_api(&self) -> prost_types::Any {
        match self {
            bgp::Capability::MultiProtocol { family } => to_any(
                api::MultiProtocolCapability {
                    family: Some(family.to_api()),
                },
                "MultiProtocolCapability",
            ),
            bgp::Capability::RouteRefresh => {
                to_any(api::RouteRefreshCapability {}, "RouteRefreshCapability")
            }
            bgp::Capability::CarryingLabelInfo => to_any(
                api::CarryingLabelInfoCapability {},
                "CarryingLabelInfoCapability",
            ),
            bgp::Capability::ExtendedNexthop { values } => {
                let mut v = Vec::new();
                for t in values {
                    let e = api::ExtendedNexthopCapabilityTuple {
                        nlri_family: Some(t.0.to_api()),
                        nexthop_family: Some(t.1.to_api()),
                    };
                    v.push(e);
                }
                to_any(
                    api::ExtendedNexthopCapability {
                        tuples: From::from(v),
                    },
                    "ExtendedNexthopCapability",
                )
            }
            bgp::Capability::GracefulRestart {
                flags,
                time,
                values,
            } => {
                let mut v = Vec::new();
                for t in values {
                    let e = api::GracefulRestartCapabilityTuple {
                        family: Some(t.0.to_api()),
                        flags: t.1 as u32,
                    };
                    v.push(e);
                }
                to_any(
                    api::GracefulRestartCapability {
                        tuples: v,
                        flags: *flags as u32,
                        time: *time as u32,
                    },
                    "GracefulRestartCapability",
                )
            }
            bgp::Capability::FourOctetAsNumber { as_number } => {
                let c = api::FourOctetAsNumberCapability { r#as: *as_number };
                to_any(c, "FourOctetASNumberCapability")
            }
            bgp::Capability::AddPath { values } => {
                let mut v = Vec::new();
                for t in values {
                    let e = api::AddPathCapabilityTuple {
                        family: Some(t.0.to_api()),
                        mode: t.1 as i32,
                    };
                    v.push(e);
                }
                to_any(
                    api::AddPathCapability {
                        tuples: From::from(v),
                    },
                    "AddPathCapability",
                )
            }
            bgp::Capability::EnhanshedRouteRefresh => to_any(
                api::EnhancedRouteRefreshCapability {},
                "EnhancedRouteRefreshCapability",
            ),
            bgp::Capability::LongLivedGracefulRestart { values } => {
                let mut v = Vec::new();
                for t in values {
                    let e = api::LongLivedGracefulRestartCapabilityTuple {
                        family: Some(t.0.to_api()),
                        flags: t.1 as u32,
                        time: t.2 as u32,
                    };
                    v.push(e);
                }
                let c = api::LongLivedGracefulRestartCapability {
                    tuples: From::from(v),
                };
                to_any(c, "LongLivedGracefulRestartCapability")
            }
            bgp::Capability::RouteRefreshCisco => to_any(
                api::RouteRefreshCiscoCapability {},
                "RouteRefreshCiscoCapability",
            ),
            _ => Default::default(),
        }
    }
}

pub struct DynamicPeer {
    pub prefix: bgp::IpNet,
}

pub struct PeerGroup {
    pub as_number: u32,
    pub dynamic_peers: Vec<DynamicPeer>,
}

pub struct Global {
    pub as_number: u32,
    pub id: Ipv4Addr,

    pub peers: HashMap<IpAddr, Peer>,
    pub peer_group: HashMap<String, PeerGroup>,
}

impl ToApi<api::Global> for Global {
    fn to_api(&self) -> api::Global {
        api::Global {
            r#as: self.as_number,
            router_id: self.id.to_string(),
            listen_port: 0,
            listen_addresses: Vec::new(),
            families: Vec::new(),
            use_multiple_paths: false,
            route_selection_options: None,
            default_route_distance: None,
            confederation: None,
            graceful_restart: None,
            apply_policy: None,
        }
    }
}

impl Global {
    pub fn new(asn: u32, id: Ipv4Addr) -> Global {
        Global {
            as_number: asn,
            id: id,
            peers: HashMap::new(),
            peer_group: HashMap::new(),
        }
    }
}

pub struct Service {
    global: Arc<Mutex<Global>>,
    table: Arc<Mutex<Table>>,
}

#[tonic::async_trait]
impl GobgpApi for Service {
    async fn start_bgp(
        &self,
        _request: tonic::Request<api::StartBgpRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
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
        Ok(tonic::Response::new(api::GetBgpResponse {
            global: Some(self.global.lock().await.to_api()),
        }))
    }
    async fn add_peer(
        &self,
        request: tonic::Request<api::AddPeerRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        if let Some(peer) = request.into_inner().peer {
            if let Some(conf) = peer.conf {
                if let Ok(addr) = IpAddr::from_str(&conf.neighbor_address) {
                    let mut p = Peer::new(addr);
                    p.remote_as = conf.peer_as;
                    let peers = &mut self.global.lock().await.peers;
                    if peers.contains_key(&addr) {
                    } else {
                        peers.insert(addr, p);
                    }
                    return Ok(tonic::Response::new(()));
                }
            }
        }
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }
    async fn delete_peer(
        &self,
        _request: tonic::Request<api::DeletePeerRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }
    type ListPeerStream = mpsc::Receiver<Result<api::ListPeerResponse, tonic::Status>>;
    async fn list_peer(
        &self,
        _request: tonic::Request<api::ListPeerRequest>,
    ) -> Result<tonic::Response<Self::ListPeerStream>, tonic::Status> {
        let (mut tx, rx) = mpsc::channel(1024);
        let global = self.global.clone();

        tokio::spawn(async move {
            let global = global.lock().await;

            for (_, p) in &global.peers {
                let rsp = api::ListPeerResponse {
                    peer: Some(p.to_api()),
                };
                tx.send(Ok(rsp)).await.unwrap();
            }
        });
        Ok(tonic::Response::new(rx))
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
        _request: tonic::Request<api::EnablePeerRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }
    async fn disable_peer(
        &self,
        _request: tonic::Request<api::DisablePeerRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }

    type MonitorPeerStream = mpsc::Receiver<Result<api::MonitorPeerResponse, tonic::Status>>;
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
        match request.into_inner().peer_group {
            Some(pg) => {
                if let Some(conf) = pg.conf {
                    let mut global = self.global.lock().await;

                    if global.peer_group.contains_key(&conf.peer_group_name) {
                        return Err(tonic::Status::new(
                            tonic::Code::AlreadyExists,
                            "peer group name already exists",
                        ));
                    } else {
                        let p = PeerGroup {
                            as_number: conf.peer_as,
                            dynamic_peers: Vec::new(),
                        };
                        global.peer_group.insert(conf.peer_group_name, p);
                        return Ok(tonic::Response::new(()));
                    }
                }
            }
            None => {}
        }
        Err(tonic::Status::new(
            tonic::Code::InvalidArgument,
            "peer group conf is empty",
        ))
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
    async fn add_dynamic_neighbor(
        &self,
        request: tonic::Request<api::AddDynamicNeighborRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        let dynamic = request
            .into_inner()
            .dynamic_neighbor
            .ok_or(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "conf is empty",
            ))?;

        let prefix = bgp::IpNet::from_str(&dynamic.prefix)
            .map_err(|_| tonic::Status::new(tonic::Code::InvalidArgument, "prefix is invalid"))?;

        let mut global = self.global.lock().await;

        let pg = global
            .peer_group
            .get_mut(&dynamic.peer_group)
            .ok_or(tonic::Status::new(
                tonic::Code::NotFound,
                "peer group isn't found",
            ))?;

        for p in &pg.dynamic_peers {
            if p.prefix == prefix {
                return Err(tonic::Status::new(
                    tonic::Code::AlreadyExists,
                    "prefix already exists",
                ));
            }
        }
        pg.dynamic_peers.push(DynamicPeer { prefix });
        return Ok(tonic::Response::new(()));
    }
    async fn add_path(
        &self,
        _request: tonic::Request<api::AddPathRequest>,
    ) -> Result<tonic::Response<api::AddPathResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }
    async fn delete_path(
        &self,
        _request: tonic::Request<api::DeletePathRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }
    type ListPathStream = mpsc::Receiver<Result<api::ListPathResponse, tonic::Status>>;
    async fn list_path(
        &self,
        request: tonic::Request<api::ListPathRequest>,
    ) -> Result<tonic::Response<Self::ListPathStream>, tonic::Status> {
        let (mut tx, rx) = mpsc::channel(1024);
        let table = self.table.clone();
        tokio::spawn(async move {
            let mut v = Vec::new();

            let prefixes: Vec<_> = request
                .into_inner()
                .prefixes
                .iter()
                .filter_map(|p| bgp::IpNet::from_str(&p.prefix).ok())
                .collect();

            let prefix_filter = |ipnet: bgp::IpNet| -> bool {
                if prefixes.len() == 0 {
                    return false;
                }
                for prefix in &prefixes {
                    if ipnet == *prefix {
                        return false;
                    }
                }
                true
            };
            {
                let family = bgp::Family::Ipv4Uc;
                let table = table.lock().await;
                let t = table.master.get(&family);
                if !t.is_none() {
                    for (_, dst) in t.unwrap() {
                        match dst.net {
                            bgp::Nlri::Ip(net) => {
                                if prefix_filter(net) {
                                    continue;
                                }
                            }
                        }
                        let mut r = Vec::new();
                        for p in &dst.entry {
                            r.push(p.to_api(&dst.net));
                        }
                        //let mut rsp = api::gobgp::ListPathResponse::new();
                        // let mut r: Vec<api::Path> =
                        //     dst.entry.iter().map(|p| p.to_api(&dst.net).await).collect();
                        r[0].best = true;
                        //rsp.set_destination(dst.to_api(r));
                        v.push(api::ListPathResponse {
                            destination: Some(dst.to_api(r)),
                        });
                    }
                }
            }
            for r in v {
                tx.send(Ok(r)).await.unwrap();
            }
        });
        Ok(tonic::Response::new(rx))
    }
    async fn add_path_stream(
        &self,
        _request: tonic::Request<tonic::Streaming<api::AddPathStreamRequest>>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }
    async fn get_table(
        &self,
        _request: tonic::Request<api::GetTableRequest>,
    ) -> Result<tonic::Response<api::GetTableResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }
    type MonitorTableStream = mpsc::Receiver<Result<api::MonitorTableResponse, tonic::Status>>;
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
    type ListVrfStream = mpsc::Receiver<Result<api::ListVrfResponse, tonic::Status>>;
    async fn list_vrf(
        &self,
        _request: tonic::Request<api::ListVrfRequest>,
    ) -> Result<tonic::Response<Self::ListVrfStream>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }
    async fn add_policy(
        &self,
        _request: tonic::Request<api::AddPolicyRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }
    async fn delete_policy(
        &self,
        _request: tonic::Request<api::DeletePolicyRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }
    type ListPolicyStream = mpsc::Receiver<Result<api::ListPolicyResponse, tonic::Status>>;
    async fn list_policy(
        &self,
        _request: tonic::Request<api::ListPolicyRequest>,
    ) -> Result<tonic::Response<Self::ListPolicyStream>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }
    async fn set_policies(
        &self,
        _request: tonic::Request<api::SetPoliciesRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }
    async fn add_defined_set(
        &self,
        _request: tonic::Request<api::AddDefinedSetRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }
    async fn delete_defined_set(
        &self,
        _request: tonic::Request<api::DeleteDefinedSetRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }
    type ListDefinedSetStream = mpsc::Receiver<Result<api::ListDefinedSetResponse, tonic::Status>>;
    async fn list_defined_set(
        &self,
        _request: tonic::Request<api::ListDefinedSetRequest>,
    ) -> Result<tonic::Response<Self::ListDefinedSetStream>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }
    async fn add_statement(
        &self,
        _request: tonic::Request<api::AddStatementRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }
    async fn delete_statement(
        &self,
        _request: tonic::Request<api::DeleteStatementRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }
    type ListStatementStream = mpsc::Receiver<Result<api::ListStatementResponse, tonic::Status>>;
    async fn list_statement(
        &self,
        _request: tonic::Request<api::ListStatementRequest>,
    ) -> Result<tonic::Response<Self::ListStatementStream>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }
    async fn add_policy_assignment(
        &self,
        _request: tonic::Request<api::AddPolicyAssignmentRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }
    async fn delete_policy_assignment(
        &self,
        _request: tonic::Request<api::DeletePolicyAssignmentRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }
    type ListPolicyAssignmentStream =
        mpsc::Receiver<Result<api::ListPolicyAssignmentResponse, tonic::Status>>;
    async fn list_policy_assignment(
        &self,
        _request: tonic::Request<api::ListPolicyAssignmentRequest>,
    ) -> Result<tonic::Response<Self::ListPolicyAssignmentStream>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }
    async fn set_policy_assignment(
        &self,
        _request: tonic::Request<api::SetPolicyAssignmentRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }
    async fn add_rpki(
        &self,
        _request: tonic::Request<api::AddRpkiRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }
    async fn delete_rpki(
        &self,
        _request: tonic::Request<api::DeleteRpkiRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }
    type ListRpkiStream = mpsc::Receiver<Result<api::ListRpkiResponse, tonic::Status>>;
    async fn list_rpki(
        &self,
        _request: tonic::Request<api::ListRpkiRequest>,
    ) -> Result<tonic::Response<Self::ListRpkiStream>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
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
    type ListRpkiTableStream = mpsc::Receiver<Result<api::ListRpkiTableResponse, tonic::Status>>;
    async fn list_rpki_table(
        &self,
        _request: tonic::Request<api::ListRpkiTableRequest>,
    ) -> Result<tonic::Response<Self::ListRpkiTableStream>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
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
        _request: tonic::Request<api::AddBmpRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }
    async fn delete_bmp(
        &self,
        _request: tonic::Request<api::DeleteBmpRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Hello, RustyBGP!");

    let args = App::new("rustybgp")
        .arg(
            Arg::with_name("asn")
                .long("as-number")
                .takes_value(true)
                .required(true)
                .help("specify as number"),
        )
        .arg(
            Arg::with_name("id")
                .long("router-id")
                .takes_value(true)
                .required(true)
                .help("specify router id"),
        )
        .arg(
            Arg::with_name("collector")
                .long("disable-best")
                .help("disable best path selection"),
        )
        .arg(
            Arg::with_name("any")
                .long("any-peers")
                .help("accept any peers"),
        )
        .get_matches();

    let asn = args.value_of("asn").unwrap().parse()?;
    let router_id = Ipv4Addr::from_str(args.value_of("id").unwrap())?;

    let global = Arc::new(Mutex::new(Global::new(asn, router_id)));
    if args.is_present("any") {
        let mut global = global.lock().await;
        global.peer_group.insert(
            "any".to_string(),
            PeerGroup {
                as_number: 0,
                dynamic_peers: vec![DynamicPeer {
                    prefix: bgp::IpNet::from_str("0.0.0.0/0").unwrap(),
                }],
            },
        );
    }

    let mut table = Table::new();
    table.disable_best_path_selection = args.is_present("collector");
    let table = Arc::new(Mutex::new(table));

    let addr = "127.0.0.1:50051".parse()?;
    let service = Service {
        global: Arc::clone(&global),
        table: Arc::clone(&table),
    };

    tokio::spawn(async move {
        if let Err(e) = tonic::transport::Server::builder()
            .add_service(GobgpApiServer::new(service))
            .serve(addr)
            .await
        {
            println!("failed to listen on grpc {}", e);
        }
    });

    let addr = "[::]:179".to_string();
    let mut listener = TcpListener::bind(&addr).await?;

    let f = |sock: std::net::SocketAddr| -> IpAddr {
        let mut addr = sock.ip();
        if let IpAddr::V6(a) = addr {
            if let Some(a) = a.to_ipv4() {
                addr = IpAddr::V4(a);
            }
        }
        addr
    };

    loop {
        let (stream, sock) = listener.accept().await?;
        let addr = f(sock);
        println!("got new connection {:?}", addr);
        let local_addr = {
            if let Ok(l) = stream.local_addr() {
                f(l)
            } else {
                continue;
            }
        };

        let mut g = global.lock().await;
        let mut is_dynamic = false;
        if g.peers.contains_key(&addr) == true {
        } else {
            for p in &g.peer_group {
                for d in &*p.1.dynamic_peers {
                    if d.prefix.contains(addr) {
                        println!("found dynamic neighbor conf {} {:?}", p.0, d.prefix);
                        is_dynamic = true;
                        break;
                    }
                }
            }

            if is_dynamic == false {
                println!(
                    "can't find configuration for a new passive connection from {}",
                    addr
                );
                continue;
            }
            let peer = Peer::new(addr);
            g.peers.insert(addr, peer);
        }

        let global = Arc::clone(&global);
        let table = Arc::clone(&table);
        tokio::spawn(async move {
            handle_session(global, table, stream, addr, local_addr, is_dynamic).await;
        });
    }
}

async fn set_state(global: &Arc<Mutex<Global>>, addr: IpAddr, state: bgp::State) {
    let peers = &mut global.lock().await.peers;
    peers.get_mut(&addr).unwrap().state = state;
}

struct Bgp {
    param: bgp::ParseParam,
}

impl Encoder for Bgp {
    type Item = bgp::Message;
    type Error = io::Error;

    fn encode(&mut self, item: bgp::Message, dst: &mut BytesMut) -> io::Result<()> {
        let buf = item.to_bytes().unwrap();
        dst.reserve(buf.len());
        dst.put(buf);
        Ok(())
    }
}

impl Decoder for Bgp {
    type Item = bgp::Message;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> io::Result<Option<bgp::Message>> {
        match bgp::Message::from_bytes(&self.param, src) {
            Ok(m) => {
                src.split_to(m.length());
                Ok(Some(m))
            }
            Err(_) => Ok(None),
        }
    }
}

enum Event {
    Message(bgp::Message),
    Holdtimer,
    Broadcast(TableUpdate),
}

struct Session {
    lines: Framed<TcpStream, Bgp>,
    delay: Delay,
    rx: Rx,
    families: Vec<bgp::Family>,
    local_as: u32,
    local_addr: IpAddr,
}

impl Session {
    async fn send_update(&mut self, updates: Vec<TableUpdate>) -> Result<(), io::Error> {
        for update in updates {
            match update {
                TableUpdate::NewBest(nlri, attrs) => {
                    let mut v = Vec::new();
                    let mut nexthop_idx = 0;
                    let mut segments = Vec::new();

                    for i in 0..attrs.entry.len() {
                        let a = &attrs.entry[i];
                        let t = a.attr();
                        if t < bgp::Attribute::NEXTHOP {
                            nexthop_idx += 1;
                        }
                        if !a.is_transitive() {
                            continue;
                        }
                        match t {
                            bgp::Attribute::CLUSTER_LIST => continue,
                            bgp::Attribute::ORIGINATOR_ID => continue,
                            _ => {}
                        }
                        match a {
                            bgp::Attribute::AsPath { segments: segs } => {
                                for s in segs {
                                    segments
                                        .insert(0, bgp::Segment::new(s.segment_type, &s.number));
                                }
                            }
                            _ => {}
                        }
                        v.push(a);
                    }
                    let n = bgp::Attribute::Nexthop {
                        nexthop: self.local_addr,
                    };
                    v.insert(nexthop_idx, &n);

                    let aspath_found = !(segments.len() == 0);

                    let aspath = if segments.len() == 0 {
                        bgp::Attribute::AsPath {
                            segments: vec![bgp::Segment {
                                segment_type: bgp::Segment::TYPE_SEQ,
                                number: vec![self.local_as],
                            }],
                        }
                    } else {
                        if segments[0].segment_type != bgp::Segment::TYPE_SEQ
                            || segments[0].number.len() == 255
                        {
                            segments.insert(
                                0,
                                bgp::Segment {
                                    segment_type: bgp::Segment::TYPE_SEQ,
                                    number: vec![self.local_as],
                                },
                            );
                        } else {
                            segments[0].number.insert(0, self.local_as);
                        }
                        bgp::Attribute::AsPath { segments }
                    };
                    v.insert(nexthop_idx, &aspath);
                    if aspath_found {
                        v.swap_remove(nexthop_idx - 1);
                    }

                    let buf = bgp::UpdateMessage::to_bytes(vec![nlri], Vec::new(), v).unwrap();
                    self.lines.get_mut().write_all(&buf).await?;
                }
                TableUpdate::Withdrawn(nlri) => {
                    let buf =
                        bgp::UpdateMessage::to_bytes(Vec::new(), vec![nlri], Vec::new()).unwrap();
                    self.lines.get_mut().write_all(&buf).await?;
                }
            }
        }
        Ok(())
    }
}

impl Stream for Session {
    type Item = Result<Event, io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Poll::Ready(()) = self.delay.poll_unpin(cx) {
            return Poll::Ready(Some(Ok(Event::Holdtimer)));
        }

        if let Poll::Ready(Some(v)) = Pin::new(&mut self.rx).poll_next(cx) {
            return Poll::Ready(Some(Ok(Event::Broadcast(v))));
        }

        let result: Option<_> = futures::ready!(self.lines.poll_next_unpin(cx));
        Poll::Ready(match result {
            Some(Ok(message)) => Some(Ok(Event::Message(message))),
            Some(Err(e)) => Some(Err(e)),
            None => None,
        })
    }
}

async fn handle_session(
    global: Arc<Mutex<Global>>,
    table: Arc<Mutex<Table>>,
    stream: TcpStream,
    addr: IpAddr,
    local_addr: IpAddr,
    is_dynamic: bool,
) {
    let (as_number, router_id) = {
        let global = global.lock().await;
        (global.as_number, global.id)
    };

    let mut keepalive_interval = bgp::OpenMessage::HOLDTIME / 3;
    let (_, rx) = mpsc::unbounded_channel();
    let mut session = Session {
        lines: Framed::new(
            stream,
            Bgp {
                param: bgp::ParseParam {
                    local_as: as_number,
                },
            },
        ),
        delay: Handle::default().delay(Instant::now()),
        rx: rx,
        families: vec![bgp::Family::Ipv4Uc],
        local_addr: local_addr,
        local_as: as_number,
    };

    let open = bgp::OpenMessage::new(as_number, router_id);
    {
        let peers = &mut global.lock().await.peers;
        let mut peer = peers.get_mut(&addr).unwrap();
        peer.local_cap = open
            .get_parameters()
            .into_iter()
            .filter_map(|p| match p {
                bgp::OpenParam::CapabilityParam(c) => Some(c),
                _ => None,
            })
            .collect();
    }
    if session.lines.send(bgp::Message::Open(open)).await.is_err() {
        // in this case, the bellow session.next() will fail.
    }
    let mut state = bgp::State::OpenSent;
    set_state(&global, addr, state).await;
    while let Some(event) = session.next().await {
        match event {
            Ok(Event::Holdtimer) => {
                session
                    .delay
                    .reset(Instant::now() + Duration::from_secs(keepalive_interval as u64));

                if state == bgp::State::Established {
                    let msg = bgp::Message::Keepalive;
                    {
                        let peers = &mut global.lock().await.peers;
                        let peer = peers.get_mut(&addr).unwrap();
                        peer.counter_tx.sync(&msg);
                    }
                    if session.lines.send(msg).await.is_err() {
                        break;
                    }
                }
            }
            Ok(Event::Broadcast(msg)) => match msg {
                TableUpdate::NewBest(_, _) => {
                    if session.send_update(vec![msg]).await.is_err() {
                        break;
                    }
                }
                TableUpdate::Withdrawn(nlri) => {
                    let buf =
                        bgp::UpdateMessage::to_bytes(Vec::new(), vec![nlri], Vec::new()).unwrap();
                    if session.lines.get_mut().write_all(&buf).await.is_err() {
                        break;
                    }
                }
            },
            Ok(Event::Message(msg)) => {
                {
                    let peers = &mut global.lock().await.peers;
                    let peer = peers.get_mut(&addr).unwrap();
                    peer.counter_rx.sync(&msg);
                }
                match msg {
                    bgp::Message::Open(open) => {
                        {
                            let peers = &mut global.lock().await.peers;
                            let peer = peers.get_mut(&addr).unwrap();
                            peer.router_id = open.id;
                            peer.remote_as = open.get_as_number();

                            peer.remote_cap = open
                                .params
                                .into_iter()
                                .filter_map(|p| match p {
                                    bgp::OpenParam::CapabilityParam(c) => Some(c),
                                    _ => None,
                                })
                                .collect();

                            let interval = open.holdtime / 3;
                            if interval < keepalive_interval {
                                keepalive_interval = interval;
                            }
                        }

                        state = bgp::State::OpenConfirm;
                        set_state(&global, addr, state).await;

                        let msg = bgp::Message::Keepalive;
                        {
                            let peers = &mut global.lock().await.peers;
                            let peer = peers.get_mut(&addr).unwrap();
                            peer.counter_tx.sync(&msg);
                        }
                        if session.lines.send(msg).await.is_err() {
                            break;
                        }
                        session
                            .delay
                            .reset(Instant::now() + Duration::from_secs(keepalive_interval as u64));
                    }
                    bgp::Message::Update(mut update) => {
                        let mut accept: i64 = 0;
                        if update.attrs.len() > 0 {
                            update.attrs.sort_by_key(|a| a.attr());
                            let pa = Arc::new(PathAttr {
                                entry: update.attrs,
                            });
                            let mut t = table.lock().await;
                            for r in update.routes {
                                let (u, added) = t.insert(
                                    bgp::Family::Ipv4Uc,
                                    r,
                                    addr,
                                    update.nexthop,
                                    pa.clone(),
                                );
                                if let Some(u) = u {
                                    t.broadcast(addr, &u).await;
                                }
                                if added {
                                    accept += 1;
                                }
                            }
                        }
                        if update.withdrawns.len() > 0 {
                            let mut t = table.lock().await;
                            for r in update.withdrawns {
                                let (u, deleted) = t.remove(bgp::Family::Ipv4Uc, r, addr);
                                if let Some(u) = u {
                                    t.broadcast(addr, &u).await;
                                }
                                if deleted {
                                    accept -= 1;
                                }
                            }
                        }
                        {
                            let peers = &mut global.lock().await.peers;
                            if accept > 0 {
                                peers.get_mut(&addr).unwrap().accepted += accept as u64;
                            } else {
                                peers.get_mut(&addr).unwrap().accepted -= accept.abs() as u64;
                            }
                        }
                    }
                    bgp::Message::Notification(_) => {
                        break;
                    }
                    bgp::Message::Keepalive => {
                        if state != bgp::State::Established {
                            state = bgp::State::Established;
                            set_state(&global, addr, state).await;
                            {
                                let peers = &mut global.lock().await.peers;
                                peers.get_mut(&addr).unwrap().uptime = SystemTime::now();
                            }

                            session.delay.reset(
                                Instant::now() + Duration::from_secs(keepalive_interval as u64),
                            );

                            let mut v = Vec::new();
                            {
                                let (tx, rx) = mpsc::unbounded_channel();
                                let mut t = table.lock().await;
                                t.active_peers.insert(addr, tx);
                                session.rx = rx;

                                if t.disable_best_path_selection == false {
                                    for family in &session.families {
                                        if let Some(m) = t.master.get_mut(&family) {
                                            for route in m {
                                                let u = TableUpdate::NewBest(
                                                    *route.0,
                                                    route.1.entry[0].attrs.clone(),
                                                );
                                                v.push(u);
                                            }
                                        }
                                    }
                                }
                            }
                            if session.send_update(v).await.is_err() {
                                break;
                            }
                        }
                    }
                    bgp::Message::RouteRefresh(m) => println!("{:?}", m.family),
                    bgp::Message::Unknown { length: _, code } => {
                        println!("unknown message type {}", code)
                    }
                }
            }
            Err(e) => {
                println!("{}", e);
                break;
            }
        }
    }

    println!("disconnected {}", addr);
    {
        let peers = &mut global.lock().await.peers;
        if is_dynamic {
            peers.remove(&addr);
        } else {
            peers.get_mut(&addr).unwrap().reset();
        }
    }
    {
        let mut t = table.lock().await;
        t.active_peers.remove(&addr);
        for u in t.clear(addr) {
            t.broadcast(addr, &u).await;
        }
    }
}
