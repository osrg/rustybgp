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

use futures::*;
use grpcio::*;
use log::*;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::mpsc;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use api;
use proto::bgp;

fn to_any<T: protobuf::Message>(m: T) -> protobuf::well_known_types::Any {
    let mut a = protobuf::well_known_types::Any::new();
    a.set_type_url(format!(
        "type.googleapis.com/{}",
        m.descriptor().full_name()
    ));
    a.set_value(m.write_to_bytes().unwrap());
    a
}

trait ToApi<T: protobuf::Message> {
    fn to_api(&self) -> T;
}

impl ToApi<protobuf::well_known_types::Timestamp> for SystemTime {
    fn to_api(&self) -> protobuf::well_known_types::Timestamp {
        let mut ts = protobuf::well_known_types::Timestamp::new();
        let unix = self.duration_since(SystemTime::UNIX_EPOCH).unwrap();
        ts.set_seconds(unix.as_secs() as i64);
        ts.set_nanos(unix.subsec_nanos() as i32);
        ts
    }
}

impl ToApi<api::gobgp::Family> for bgp::Family {
    fn to_api(&self) -> api::gobgp::Family {
        let mut f = api::gobgp::Family::new();
        match self {
            bgp::Family::Ipv4Uc => f.set_afi(api::gobgp::Family_Afi::AFI_IP),
            bgp::Family::Ipv6Uc => f.set_afi(api::gobgp::Family_Afi::AFI_IP6),
            _ => {}
        }
        f.set_safi(api::gobgp::Family_Safi::SAFI_UNICAST);
        f
    }
}

#[derive(Clone)]
pub struct PathAttr {
    pub attrs: Vec<bgp::Attribute>,
}

#[derive(Clone)]
pub struct Path {
    pub source: IpAddr,
    pub timestamp: SystemTime,
    as_number: u32,
    pub attrs: Arc<RwLock<PathAttr>>,
}

impl Path {
    fn new(source: IpAddr, attrs: Arc<RwLock<PathAttr>>) -> Path {
        Path {
            source: source,
            timestamp: SystemTime::now(),
            as_number: 0,
            attrs,
        }
    }

    fn to_api(&self, net: &bgp::Nlri) -> api::gobgp::Path {
        let mut path = api::gobgp::Path::new();

        match net {
            bgp::Nlri::Ip(ipnet) => {
                let mut nlri = api::attribute::IPAddressPrefix::new();
                nlri.set_prefix(ipnet.addr.to_string());
                nlri.set_prefix_len(ipnet.mask as u32);
                path.set_nlri(to_any(nlri));
            }
        }

        match net {
            bgp::Nlri::Ip(ipnet) => match ipnet.addr {
                IpAddr::V4(_) => path.set_family(bgp::Family::Ipv4Uc.to_api()),
                IpAddr::V6(_) => path.set_family(bgp::Family::Ipv6Uc.to_api()),
            },
        }

        path.set_age(self.timestamp.to_api());

        let mut attrs = protobuf::RepeatedField::new();
        let a = self.attrs.read().unwrap();
        for attr in &a.attrs {
            match attr {
                bgp::Attribute::Origin { origin } => {
                    let mut a = api::attribute::OriginAttribute::new();
                    a.set_origin(*origin as u32);
                    attrs.push(to_any(a));
                }
                bgp::Attribute::AsPath { segments } => {
                    let mut a = api::attribute::AsPathAttribute::new();
                    let l: Vec<api::attribute::AsSegment> = segments
                        .iter()
                        .map(|segment| {
                            let mut s = api::attribute::AsSegment::new();
                            s.set_field_type(segment.segment_type as u32);
                            let v: Vec<u32> = segment.number.iter().map(|x| *x).collect();
                            s.set_numbers(v);
                            s
                        })
                        .collect();
                    a.set_segments(From::from(l));
                    attrs.push(to_any(a));
                }
                bgp::Attribute::Nexthop { nexthop } => {
                    let mut a = api::attribute::NextHopAttribute::new();
                    a.set_next_hop(nexthop.to_string());
                    attrs.push(to_any(a));
                }
                bgp::Attribute::MultiExitDesc { descriptor } => {
                    let mut a = api::attribute::MultiExitDiscAttribute::new();
                    a.set_med(*descriptor);
                    attrs.push(to_any(a));
                }
                bgp::Attribute::LocalPref { preference } => {
                    let mut a = api::attribute::LocalPrefAttribute::new();
                    a.set_local_pref(*preference);
                    attrs.push(to_any(a));
                }
                bgp::Attribute::AtomicAggregate => {
                    let a = api::attribute::AtomicAggregateAttribute::new();
                    attrs.push(to_any(a));
                }
                bgp::Attribute::Aggregator {
                    four_byte: _,
                    number,
                    address,
                } => {
                    let mut a = api::attribute::AggregatorAttribute::new();
                    a.set_field_as(*number);
                    a.set_address(address.to_string());
                    attrs.push(to_any(a));
                }
                bgp::Attribute::Community { communities } => {
                    let mut a = api::attribute::CommunitiesAttribute::new();
                    let v: Vec<u32> = communities.iter().map(|x| *x).collect();
                    a.set_communities(v);
                    attrs.push(to_any(a));
                }
                bgp::Attribute::OriginatorId { address } => {
                    let mut a = api::attribute::OriginatorIdAttribute::new();
                    a.set_id(address.to_string());
                    attrs.push(to_any(a));
                }
                bgp::Attribute::ClusterList { addresses } => {
                    let mut a = api::attribute::ClusterListAttribute::new();
                    let l: Vec<String> = addresses.iter().map(|x| x.to_string()).collect();
                    a.set_ids(From::from(l));
                    attrs.push(to_any(a));
                }
                _ => {}
            }
        }
        path.set_pattrs(attrs);

        path
    }

    pub fn get_local_preference(&self) -> u32 {
        const DEFAULT: u32 = 100;
        for a in &self.attrs.read().unwrap().attrs {
            match a {
                bgp::Attribute::LocalPref { preference } => return *preference,
                _ => {}
            }
        }
        return DEFAULT;
    }

    pub fn get_as_len(&self) -> u32 {
        for a in &self.attrs.read().unwrap().attrs {
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
        for a in &self.attrs.read().unwrap().attrs {
            match a {
                bgp::Attribute::Origin { origin } => return *origin,
                _ => {}
            }
        }
        0
    }

    pub fn get_med(&self) -> u32 {
        for a in &self.attrs.read().unwrap().attrs {
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

    pub fn to_api(&self, paths: Vec<api::gobgp::Path>) -> api::gobgp::Destination {
        let mut dst = api::gobgp::Destination::new();
        dst.set_paths(From::from(paths));
        dst.set_prefix(self.net.to_string());
        dst
    }
}

#[derive(Clone)]
pub struct Table {
    pub master: HashMap<bgp::Family, HashMap<bgp::Nlri, Destination>>,
}

impl Table {
    pub fn new() -> Table {
        Table {
            master: HashMap::new(),
        }
    }

    pub fn insert(
        &mut self,
        family: bgp::Family,
        net: bgp::Nlri,
        source: IpAddr,
        attrs: Arc<RwLock<PathAttr>>,
    ) -> bool {
        let t = self.master.get_mut(&family);
        let t = match t {
            Some(t) => t,
            None => {
                self.master.insert(family, HashMap::new());
                self.master.get_mut(&family).unwrap()
            }
        };

        match t.get_mut(&net) {
            Some(d) => {
                for i in 0..d.entry.len() {
                    if d.entry[i].source == source {
                        d.entry[i] = Path::new(source, attrs);
                        return false;
                    }
                }
                d.entry.push(Path::new(source, attrs));
                d.entry.sort_by(|a, b| {
                    // local

                    // ibgp vs ebgp

                    // local pref
                    let x = a.get_local_preference();
                    let y = b.get_local_preference();
                    if x != y {
                        return x.cmp(&y);
                    }

                    // as length
                    let x = a.get_as_len();
                    let y = b.get_as_len();
                    if x != y {
                        return y.cmp(&x);
                    }

                    // origin
                    let x = a.get_origin();
                    let y = b.get_origin();
                    if x != y {
                        return y.cmp(&x);
                    }

                    // med
                    let x = a.get_med();
                    let y = b.get_med();
                    y.cmp(&x)
                });
            }
            None => {
                let mut d = Destination::new(net);
                d.entry.push(Path::new(source, attrs));
                t.insert(net, d);
            }
        }
        true
    }

    pub fn remove(&mut self, family: bgp::Family, net: bgp::Nlri, source: IpAddr) -> bool {
        let t = self.master.get_mut(&family);
        if t.is_none() {
            return false;
        }
        let t = t.unwrap();
        match t.get_mut(&net) {
            Some(d) => {
                for i in 0..d.entry.len() {
                    if d.entry[i].source == source {
                        d.entry.remove(i);
                        if d.entry.len() == 0 {
                            t.remove(&net);
                            return true;
                        }
                    }
                }
            }
            None => {}
        }
        false
    }

    pub fn clear(&mut self, source: IpAddr) {
        let mut m: HashMap<bgp::Family, Vec<bgp::Nlri>> = HashMap::new();
        for f in self.master.keys() {
            m.insert(*f, Vec::new());
        }

        for (f, t) in self.master.iter_mut() {
            for (n, d) in t {
                for i in 0..d.entry.len() {
                    if d.entry[i].source == source {
                        d.entry.remove(i);
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
    }
}

impl ToApi<protobuf::well_known_types::Any> for bgp::Capability {
    fn to_api(&self) -> protobuf::well_known_types::Any {
        match self {
            bgp::Capability::MultiProtocol { family } => {
                let mut c = api::capability::MultiProtocolCapability::new();
                c.set_family(family.to_api());
                to_any(c)
            }
            bgp::Capability::RouteRefresh => to_any(api::capability::RouteRefreshCapability::new()),
            bgp::Capability::CarryingLabelInfo => {
                to_any(api::capability::CarryingLabelInfoCapability::new())
            }
            bgp::Capability::ExtendedNexthop { values } => {
                let mut c = api::capability::ExtendedNexthopCapability::new();
                let mut v = Vec::new();
                for t in values {
                    let mut e = api::capability::ExtendedNexthopCapabilityTuple::new();
                    e.set_nlri_family(t.0.to_api());
                    e.set_nexthop_family(t.1.to_api());
                    v.push(e);
                }
                c.set_tuples(From::from(v));
                to_any(c)
            }
            bgp::Capability::GracefulRestart {
                flags,
                time,
                values,
            } => {
                let mut c = api::capability::GracefulRestartCapability::new();
                let mut v = Vec::new();
                for t in values {
                    let mut e = api::capability::GracefulRestartCapabilityTuple::new();
                    e.set_family(t.0.to_api());
                    e.set_flags(t.1 as u32);
                    v.push(e);
                }
                c.set_flags(*flags as u32);
                c.set_time(*time as u32);
                c.set_tuples(From::from(v));
                to_any(c)
            }
            bgp::Capability::FourOctetAsNumber { as_number } => {
                let mut c = api::capability::FourOctetASNumberCapability::new();
                c.set_field_as(*as_number);
                to_any(c)
            }
            bgp::Capability::AddPath { values } => {
                let mut c = api::capability::AddPathCapability::new();
                let mut v = Vec::new();
                for t in values {
                    let mut e = api::capability::AddPathCapabilityTuple::new();
                    e.set_family(t.0.to_api());
                    match t.1 {
                        1 => e.set_mode(api::capability::AddPathMode::MODE_RECEIVE),
                        2 => e.set_mode(api::capability::AddPathMode::MODE_SEND),
                        3 => e.set_mode(api::capability::AddPathMode::MODE_BOTH),
                        _ => e.set_mode(api::capability::AddPathMode::MODE_NONE),
                    }
                    v.push(e);
                }
                c.set_tuples(From::from(v));
                to_any(c)
            }
            bgp::Capability::EnhanshedRouteRefresh => {
                to_any(api::capability::EnhancedRouteRefreshCapability::new())
            }
            bgp::Capability::LongLivedGracefulRestart { values } => {
                let mut c = api::capability::LongLivedGracefulRestartCapability::new();
                let mut v = Vec::new();
                for t in values {
                    let mut e = api::capability::LongLivedGracefulRestartCapabilityTuple::new();
                    e.set_family(t.0.to_api());
                    e.set_flags(t.1 as u32);
                    e.set_time(t.2 as u32);
                    v.push(e);
                }
                c.set_tuples(From::from(v));
                to_any(c)
            }
            bgp::Capability::RouteRefreshCisco => {
                to_any(api::capability::RouteRefreshCiscoCapability::new())
            }
            _ => protobuf::well_known_types::Any::new(),
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

impl ToApi<api::gobgp::Message> for MessageCounter {
    fn to_api(&self) -> api::gobgp::Message {
        let mut m = api::gobgp::Message::new();

        m.set_open(self.open);
        m.set_update(self.update);
        m.set_keepalive(self.keepalive);
        m.set_refresh(self.refresh);
        m.set_discarded(self.discarded);
        m.set_total(self.total);
        m.set_withdraw_update(self.withdraw_update);
        m.set_withdraw_prefix(self.withdraw_prefix);
        m
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

pub struct PeerState {
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

impl PeerState {
    fn addr(&self) -> String {
        match self.address {
            IpAddr::V4(_) => self.address.to_string(),
            IpAddr::V6(addr) => match addr.to_ipv4() {
                Some(x) => x.to_string(),
                None => self.address.to_string(),
            },
        }
    }

    pub fn new(address: IpAddr) -> PeerState {
        PeerState {
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
}

impl ToApi<api::gobgp::Peer> for PeerState {
    fn to_api(&self) -> api::gobgp::Peer {
        let mut peer = api::gobgp::Peer::new();

        let mut ts = api::gobgp::TimersState::new();
        if self.uptime != SystemTime::UNIX_EPOCH {
            ts.set_uptime(self.uptime.to_api());
        }
        let mut t = api::gobgp::Timers::new();
        t.set_state(ts);
        t.set_config(api::gobgp::TimersConfig::new());
        peer.set_timers(t);

        let mut ps = api::gobgp::PeerState::new();
        ps.peer_as = self.remote_as;
        ps.set_neighbor_address(self.addr());
        ps.set_router_id(self.router_id.to_string());
        ps.set_queues(api::gobgp::Queues::new());

        let mut m = api::gobgp::Messages::new();
        m.set_received(self.counter_rx.to_api());
        m.set_sent(self.counter_tx.to_api());
        ps.set_messages(m);

        let to_state_api = || match self.state {
            bgp::State::Idle => api::gobgp::PeerState_SessionState::IDLE,
            bgp::State::Active => api::gobgp::PeerState_SessionState::ACTIVE,
            bgp::State::Connect => api::gobgp::PeerState_SessionState::CONNECT,
            bgp::State::OpenSent => api::gobgp::PeerState_SessionState::OPENSENT,
            bgp::State::OpenConfirm => api::gobgp::PeerState_SessionState::OPENCONFIRM,
            bgp::State::Established => api::gobgp::PeerState_SessionState::ESTABLISHED,
        };

        ps.set_session_state(to_state_api());
        let cap: protobuf::RepeatedField<protobuf::well_known_types::Any> =
            self.remote_cap.iter().map(|c| c.to_api()).collect();
        ps.set_remote_cap(cap);

        let cap: protobuf::RepeatedField<protobuf::well_known_types::Any> =
            self.local_cap.iter().map(|c| c.to_api()).collect();
        ps.set_local_cap(cap);

        peer.set_state(ps);
        peer.set_conf(api::gobgp::PeerConf::new());

        peer.set_route_reflector(api::gobgp::RouteReflector::new());
        peer.set_transport(api::gobgp::Transport::new());
        peer.set_route_server(api::gobgp::RouteServer::new());
        peer.set_graceful_restart(api::gobgp::GracefulRestart::new());

        let mut f = api::gobgp::AfiSafi::new();
        f.set_config(api::gobgp::AfiSafiConfig::new());
        let mut fs = api::gobgp::AfiSafiState::new();
        fs.set_enabled(true);

        fs.set_family(bgp::Family::Ipv4Uc.to_api());
        fs.set_accepted(self.accepted);
        fs.set_received(self.accepted);
        f.set_state(fs);

        peer.set_afi_safis(From::from(vec![f]));

        peer
    }
}

pub struct Global {
    pub as_number: u32,
    pub id: Ipv4Addr,

    pub peer: HashMap<IpAddr, PeerState>,
}

impl Global {
    pub fn new() -> Global {
        Global {
            as_number: 0,
            id: Ipv4Addr::new(0, 0, 0, 0),
            peer: HashMap::new(),
        }
    }
}

#[derive(Clone)]
pub struct Service {
    global: Arc<RwLock<Global>>,
    table: Arc<RwLock<Table>>,
    init_sender: mpsc::Sender<bool>,
}

impl Service {
    pub fn new(
        global: Arc<RwLock<Global>>,
        table: Arc<RwLock<Table>>,
        init_sender: mpsc::Sender<bool>,
    ) -> Service {
        Service {
            global,
            table,
            init_sender,
        }
    }
}

impl api::gobgp_grpc::GobgpApi for Service {
    fn start_bgp(
        &mut self,
        ctx: grpcio::RpcContext,
        req: api::gobgp::StartBgpRequest,
        sink: grpcio::UnarySink<api::empty::Empty>,
    ) {
        let rsp = api::empty::Empty::new();
        let g = req.get_global();
        {
            let mut global = self.global.write().unwrap();

            if g.get_field_as() != 0 && global.as_number == 0 {
                match Ipv4Addr::from_str(g.get_router_id()) {
                    Ok(addr) => {
                        global.id = addr;
                        global.as_number = g.get_field_as();
                        self.init_sender.send(true).unwrap();
                    }
                    Err(e) => println!("{}", e),
                }
            }
        }

        ctx.spawn(
            sink.success(rsp)
                .map_err(move |e| error!("failed to reply {:#?}: {:?}", req, e)),
        );
    }
    fn stop_bgp(
        &mut self,
        ctx: grpcio::RpcContext,
        req: api::gobgp::StopBgpRequest,
        sink: grpcio::UnarySink<api::empty::Empty>,
    ) {
    }
    fn get_bgp(
        &mut self,
        ctx: grpcio::RpcContext,
        req: api::gobgp::GetBgpRequest,
        sink: grpcio::UnarySink<api::gobgp::GetBgpResponse>,
    ) {
        let g = self.global.read().unwrap();

        let mut rsp = api::gobgp::GetBgpResponse::new();
        let mut v = api::gobgp::Global::new();
        v.set_field_as(g.as_number);
        v.set_router_id(g.id.to_string());
        rsp.set_global(v);

        ctx.spawn(
            sink.success(rsp)
                .map_err(move |e| error!("failed to reply {:?}: {:?}", req, e)),
        );
    }
    fn add_peer(
        &mut self,
        ctx: grpcio::RpcContext,
        req: api::gobgp::AddPeerRequest,
        sink: grpcio::UnarySink<api::empty::Empty>,
    ) {
        let rsp = api::empty::Empty::new();
        let conf = req.get_peer().get_conf();
        match IpAddr::from_str(conf.get_neighbor_address()) {
            Ok(addr) => {
                let mut peer_state = PeerState::new(addr);
                peer_state.remote_as = conf.get_peer_as();
                let peer = &mut self.global.write().unwrap().peer;
                peer.insert(addr, peer_state);
            }
            Err(_) => {}
        }
        ctx.spawn(
            sink.success(rsp)
                .map_err(move |e| error!("failed to reply {:?}: {:?}", req, e)),
        );
    }
    fn delete_peer(
        &mut self,
        ctx: grpcio::RpcContext,
        req: api::gobgp::DeletePeerRequest,
        sink: grpcio::UnarySink<api::empty::Empty>,
    ) {
    }
    fn list_peer(
        &mut self,
        ctx: grpcio::RpcContext,
        req: api::gobgp::ListPeerRequest,
        sink: grpcio::ServerStreamingSink<api::gobgp::ListPeerResponse>,
    ) {
        let mut rsps: Vec<api::gobgp::ListPeerResponse> = Vec::new();
        {
            let global = self.global.read().unwrap();

            for (_, v) in &global.peer {
                let mut rsp = api::gobgp::ListPeerResponse::new();
                rsp.set_peer(v.to_api());
                rsps.push(rsp);
            }
        }
        let rsp: Vec<_> = rsps
            .iter()
            .filter_map(move |f| Some((f.to_owned(), WriteFlags::default())))
            .collect();
        let f = sink
            .send_all(stream::iter_ok::<_, Error>(rsp))
            .map(|_| {})
            .map_err(move |e| error!("failed to handle list_peer request {:?}: {:?}", req, e));
        ctx.spawn(f)
    }
    fn update_peer(
        &mut self,
        ctx: grpcio::RpcContext,
        req: api::gobgp::UpdatePeerRequest,
        sink: grpcio::UnarySink<api::gobgp::UpdatePeerResponse>,
    ) {
    }
    fn reset_peer(
        &mut self,
        ctx: grpcio::RpcContext,
        req: api::gobgp::ResetPeerRequest,
        sink: grpcio::UnarySink<api::empty::Empty>,
    ) {
    }
    fn shutdown_peer(
        &mut self,
        ctx: grpcio::RpcContext,
        req: api::gobgp::ShutdownPeerRequest,
        sink: grpcio::UnarySink<api::empty::Empty>,
    ) {
    }
    fn enable_peer(
        &mut self,
        ctx: grpcio::RpcContext,
        req: api::gobgp::EnablePeerRequest,
        sink: grpcio::UnarySink<api::empty::Empty>,
    ) {
    }
    fn disable_peer(
        &mut self,
        ctx: grpcio::RpcContext,
        req: api::gobgp::DisablePeerRequest,
        sink: grpcio::UnarySink<api::empty::Empty>,
    ) {
    }
    fn monitor_peer(
        &mut self,
        ctx: grpcio::RpcContext,
        req: api::gobgp::MonitorPeerRequest,
        sink: grpcio::ServerStreamingSink<api::gobgp::MonitorPeerResponse>,
    ) {
    }
    fn add_peer_group(
        &mut self,
        ctx: grpcio::RpcContext,
        req: api::gobgp::AddPeerGroupRequest,
        sink: grpcio::UnarySink<api::empty::Empty>,
    ) {
    }
    fn delete_peer_group(
        &mut self,
        ctx: grpcio::RpcContext,
        req: api::gobgp::DeletePeerGroupRequest,
        sink: grpcio::UnarySink<api::empty::Empty>,
    ) {
    }
    fn update_peer_group(
        &mut self,
        ctx: grpcio::RpcContext,
        req: api::gobgp::UpdatePeerGroupRequest,
        sink: grpcio::UnarySink<api::gobgp::UpdatePeerGroupResponse>,
    ) {
    }
    fn add_dynamic_neighbor(
        &mut self,
        ctx: grpcio::RpcContext,
        req: api::gobgp::AddDynamicNeighborRequest,
        sink: grpcio::UnarySink<api::empty::Empty>,
    ) {
    }
    fn add_path(
        &mut self,
        ctx: grpcio::RpcContext,
        req: api::gobgp::AddPathRequest,
        sink: grpcio::UnarySink<api::gobgp::AddPathResponse>,
    ) {
    }
    fn delete_path(
        &mut self,
        ctx: grpcio::RpcContext,
        req: api::gobgp::DeletePathRequest,
        sink: grpcio::UnarySink<api::empty::Empty>,
    ) {
    }
    fn list_path(
        &mut self,
        ctx: grpcio::RpcContext,
        req: api::gobgp::ListPathRequest,
        sink: grpcio::ServerStreamingSink<api::gobgp::ListPathResponse>,
    ) {
        let mut rsps: Vec<api::gobgp::ListPathResponse> = Vec::new();

        let prefix_filter = |ipnet: bgp::IpNet| -> bool {
            let prefixes: Vec<_> = req
                .get_prefixes()
                .iter()
                .filter_map(|p| bgp::IpNet::from_str(&p.prefix).ok())
                .collect();

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
            let table = self.table.read().unwrap();
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

                    let mut rsp = api::gobgp::ListPathResponse::new();
                    let mut r: Vec<api::gobgp::Path> =
                        dst.entry.iter().map(|p| p.to_api(&dst.net)).collect();
                    r[0].set_best(true);
                    rsp.set_destination(dst.to_api(r));
                    rsps.push(rsp);
                }
            }
        }

        let rsp: Vec<_> = rsps
            .iter()
            .filter_map(move |f| Some((f.to_owned(), WriteFlags::default())))
            .collect();

        let f = sink
            .send_all(stream::iter_ok::<_, Error>(rsp))
            .map(|_| {})
            .map_err(move |e| error!("failed to handle list_path request {:?}: {:?}", req, e));

        ctx.spawn(f)
    }
    fn add_path_stream(
        &mut self,
        ctx: grpcio::RpcContext,
        stream: grpcio::RequestStream<api::gobgp::AddPathStreamRequest>,
        sink: grpcio::ClientStreamingSink<api::empty::Empty>,
    ) {
    }
    fn get_table(
        &mut self,
        ctx: grpcio::RpcContext,
        req: api::gobgp::GetTableRequest,
        sink: grpcio::UnarySink<api::gobgp::GetTableResponse>,
    ) {
    }
    fn monitor_table(
        &mut self,
        ctx: grpcio::RpcContext,
        req: api::gobgp::MonitorTableRequest,
        sink: grpcio::ServerStreamingSink<api::gobgp::MonitorTableResponse>,
    ) {
    }
    fn add_vrf(
        &mut self,
        ctx: grpcio::RpcContext,
        req: api::gobgp::AddVrfRequest,
        sink: grpcio::UnarySink<api::empty::Empty>,
    ) {
    }
    fn delete_vrf(
        &mut self,
        ctx: grpcio::RpcContext,
        req: api::gobgp::DeleteVrfRequest,
        sink: grpcio::UnarySink<api::empty::Empty>,
    ) {
    }
    fn list_vrf(
        &mut self,
        ctx: grpcio::RpcContext,
        req: api::gobgp::ListVrfRequest,
        sink: grpcio::ServerStreamingSink<api::gobgp::ListVrfResponse>,
    ) {
    }
    fn add_policy(
        &mut self,
        ctx: grpcio::RpcContext,
        req: api::gobgp::AddPolicyRequest,
        sink: grpcio::UnarySink<api::empty::Empty>,
    ) {
    }
    fn delete_policy(
        &mut self,
        ctx: grpcio::RpcContext,
        req: api::gobgp::DeletePolicyRequest,
        sink: grpcio::UnarySink<api::empty::Empty>,
    ) {
    }
    fn list_policy(
        &mut self,
        ctx: grpcio::RpcContext,
        req: api::gobgp::ListPolicyRequest,
        sink: grpcio::ServerStreamingSink<api::gobgp::ListPolicyResponse>,
    ) {
    }
    fn set_policies(
        &mut self,
        ctx: grpcio::RpcContext,
        req: api::gobgp::SetPoliciesRequest,
        sink: grpcio::UnarySink<api::empty::Empty>,
    ) {
    }
    fn add_defined_set(
        &mut self,
        ctx: grpcio::RpcContext,
        req: api::gobgp::AddDefinedSetRequest,
        sink: grpcio::UnarySink<api::empty::Empty>,
    ) {
    }
    fn delete_defined_set(
        &mut self,
        ctx: grpcio::RpcContext,
        req: api::gobgp::DeleteDefinedSetRequest,
        sink: grpcio::UnarySink<api::empty::Empty>,
    ) {
    }
    fn list_defined_set(
        &mut self,
        ctx: grpcio::RpcContext,
        req: api::gobgp::ListDefinedSetRequest,
        sink: grpcio::ServerStreamingSink<api::gobgp::ListDefinedSetResponse>,
    ) {
    }
    fn add_statement(
        &mut self,
        ctx: grpcio::RpcContext,
        req: api::gobgp::AddStatementRequest,
        sink: grpcio::UnarySink<api::empty::Empty>,
    ) {
    }
    fn delete_statement(
        &mut self,
        ctx: grpcio::RpcContext,
        req: api::gobgp::DeleteStatementRequest,
        sink: grpcio::UnarySink<api::empty::Empty>,
    ) {
    }
    fn list_statement(
        &mut self,
        ctx: grpcio::RpcContext,
        req: api::gobgp::ListStatementRequest,
        sink: grpcio::ServerStreamingSink<api::gobgp::ListStatementResponse>,
    ) {
    }
    fn add_policy_assignment(
        &mut self,
        ctx: grpcio::RpcContext,
        req: api::gobgp::AddPolicyAssignmentRequest,
        sink: grpcio::UnarySink<api::empty::Empty>,
    ) {
    }
    fn delete_policy_assignment(
        &mut self,
        ctx: grpcio::RpcContext,
        req: api::gobgp::DeletePolicyAssignmentRequest,
        sink: grpcio::UnarySink<api::empty::Empty>,
    ) {
    }
    fn list_policy_assignment(
        &mut self,
        ctx: grpcio::RpcContext,
        req: api::gobgp::ListPolicyAssignmentRequest,
        sink: grpcio::ServerStreamingSink<api::gobgp::ListPolicyAssignmentResponse>,
    ) {
    }
    fn set_policy_assignment(
        &mut self,
        ctx: grpcio::RpcContext,
        req: api::gobgp::SetPolicyAssignmentRequest,
        sink: grpcio::UnarySink<api::empty::Empty>,
    ) {
    }
    fn add_rpki(
        &mut self,
        ctx: grpcio::RpcContext,
        req: api::gobgp::AddRpkiRequest,
        sink: grpcio::UnarySink<api::empty::Empty>,
    ) {
    }
    fn delete_rpki(
        &mut self,
        ctx: grpcio::RpcContext,
        req: api::gobgp::DeleteRpkiRequest,
        sink: grpcio::UnarySink<api::empty::Empty>,
    ) {
    }
    fn list_rpki(
        &mut self,
        ctx: grpcio::RpcContext,
        req: api::gobgp::ListRpkiRequest,
        sink: grpcio::ServerStreamingSink<api::gobgp::ListRpkiResponse>,
    ) {
    }
    fn enable_rpki(
        &mut self,
        ctx: grpcio::RpcContext,
        req: api::gobgp::EnableRpkiRequest,
        sink: grpcio::UnarySink<api::empty::Empty>,
    ) {
    }
    fn disable_rpki(
        &mut self,
        ctx: grpcio::RpcContext,
        req: api::gobgp::DisableRpkiRequest,
        sink: grpcio::UnarySink<api::empty::Empty>,
    ) {
    }
    fn reset_rpki(
        &mut self,
        ctx: grpcio::RpcContext,
        req: api::gobgp::ResetRpkiRequest,
        sink: grpcio::UnarySink<api::empty::Empty>,
    ) {
    }
    fn list_rpki_table(
        &mut self,
        ctx: grpcio::RpcContext,
        req: api::gobgp::ListRpkiTableRequest,
        sink: grpcio::ServerStreamingSink<api::gobgp::ListRpkiTableResponse>,
    ) {
    }
    fn enable_zebra(
        &mut self,
        ctx: grpcio::RpcContext,
        req: api::gobgp::EnableZebraRequest,
        sink: grpcio::UnarySink<api::empty::Empty>,
    ) {
    }
    fn enable_mrt(
        &mut self,
        ctx: grpcio::RpcContext,
        req: api::gobgp::EnableMrtRequest,
        sink: grpcio::UnarySink<api::empty::Empty>,
    ) {
    }
    fn disable_mrt(
        &mut self,
        ctx: grpcio::RpcContext,
        req: api::gobgp::DisableMrtRequest,
        sink: grpcio::UnarySink<api::empty::Empty>,
    ) {
    }
    fn add_bmp(
        &mut self,
        ctx: grpcio::RpcContext,
        req: api::gobgp::AddBmpRequest,
        sink: grpcio::UnarySink<api::empty::Empty>,
    ) {
    }
    fn delete_bmp(
        &mut self,
        ctx: grpcio::RpcContext,
        req: api::gobgp::DeleteBmpRequest,
        sink: grpcio::UnarySink<api::empty::Empty>,
    ) {
    }
}
