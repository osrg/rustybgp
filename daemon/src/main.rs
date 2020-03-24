// Copyright (C) 2019-2020 The RustyBGP Authors.
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
    collections::{HashMap, HashSet},
    io,
    io::Cursor,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    str::FromStr,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, SystemTime},
};

use futures::{FutureExt, SinkExt};

use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    stream::{Stream, StreamExt},
    sync::{mpsc, Barrier, Mutex},
    time::{delay_for, DelayQueue, Instant},
};
use tokio_util::codec::{BytesCodec, Decoder, Encoder, Framed};

use bytes::{BufMut, BytesMut};
use clap::{App, Arg};

use prost;

mod api {
    tonic::include_proto!("gobgpapi");
}
use api::gobgp_api_server::{GobgpApi, GobgpApiServer};

use proto::{bgp, bmp};

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
                afi: api::family::Afi::Ip6 as i32,
                safi: api::family::Safi::Unicast as i32,
            },
            bgp::Family::Unknown(v) => api::Family {
                afi: (v >> 16) as i32,
                safi: (v & 0xff) as i32,
            },
        }
    }
}

trait SocketAddrToIpAddr {
    fn to_ipaddr(&self) -> IpAddr;
}

impl SocketAddrToIpAddr for SocketAddr {
    // convert IPv4-mapped IPv6 address to IPv4 address
    fn to_ipaddr(&self) -> IpAddr {
        let mut addr = self.ip();
        if let IpAddr::V6(a) = addr {
            if let Some(a) = a.to_ipv4() {
                addr = IpAddr::V4(a);
            }
        }
        addr
    }
}

trait FromFamilyApi {
    fn to_proto(&self) -> bgp::Family;
}

impl FromFamilyApi for api::Family {
    fn to_proto(&self) -> bgp::Family {
        if self.safi == api::family::Safi::Unicast as i32 {
            if self.afi == api::family::Afi::Ip as i32 {
                return bgp::Family::Ipv4Uc;
            } else if self.afi == api::family::Afi::Ip6 as i32 {
                return bgp::Family::Ipv6Uc;
            }
        }
        return bgp::Family::Unknown((self.afi as u32) << 16 | self.safi as u32);
    }
}

trait FromNlriApi {
    fn to_proto(&self) -> Option<bgp::Nlri>;
}

impl FromNlriApi for prost_types::Any {
    fn to_proto(&self) -> Option<bgp::Nlri> {
        if self.type_url == "type.googleapis.com/gobgpapi.IPAddressPrefix" {
            let n = prost::Message::decode(Cursor::new(&self.value));
            match n {
                Ok(n) => {
                    let api_nlri: api::IpAddressPrefix = n;
                    match IpAddr::from_str(&api_nlri.prefix) {
                        Ok(addr) => {
                            return Some(bgp::Nlri::Ip(bgp::IpNet {
                                addr: addr,
                                mask: api_nlri.prefix_len as u8,
                            }));
                        }
                        Err(_) => {}
                    }
                }
                Err(_) => {}
            }
        }
        None
    }
}

#[derive(Clone)]
pub struct PathAttr {
    pub entry: Vec<bgp::Attribute>,
}

#[derive(Clone)]
pub struct Path {
    pub source: Arc<Source>,
    pub timestamp: SystemTime,
    pub as_number: u32,
    pub nexthop: IpAddr,
    pub attrs: Arc<PathAttr>,
}

impl Path {
    fn new(source: Arc<Source>, nexthop: IpAddr, attrs: Arc<PathAttr>) -> Path {
        Path {
            source: source,
            timestamp: SystemTime::now(),
            as_number: 0,
            attrs,
            nexthop,
        }
    }

    fn to_api(&self, net: &bgp::Nlri, nexthop: IpAddr, pattrs: Vec<&bgp::Attribute>) -> api::Path {
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
        for attr in pattrs {
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
                bgp::Attribute::Nexthop { .. } => {}
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
        attrs.push(to_any(
            api::NextHopAttribute {
                next_hop: nexthop.to_string(),
            },
            "NextHopAttribute",
        ));

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
    NewBest(bgp::Nlri, IpAddr, Arc<PathAttr>, Arc<Source>),
    Withdrawn(bgp::Nlri, Arc<Source>),
}

#[derive(Clone)]
pub struct Table {
    pub local_source: Arc<Source>,
    pub disable_best_path_selection: bool,
    pub master: HashMap<bgp::Family, HashMap<bgp::Nlri, Destination>>,

    pub active_peers: HashMap<IpAddr, (Sender<PeerEvent>, Arc<Source>)>,
    pub bmp_sessions: HashMap<SocketAddr, Sender<bmp::Message>>,
}

impl Table {
    pub fn new() -> Table {
        Table {
            local_source: Arc::new(Source {
                address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                ibgp: false,
                local_as: 0,
                local_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                state: bgp::State::Idle,
            }),
            disable_best_path_selection: false,
            master: HashMap::new(),
            active_peers: HashMap::new(),
            bmp_sessions: HashMap::new(),
        }
    }

    pub fn insert(
        &mut self,
        family: bgp::Family,
        net: bgp::Nlri,
        source: Arc<Source>,
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
        let (attrs, src) = match t.get_mut(&net) {
            Some(d) => {
                for i in 0..d.entry.len() {
                    if d.entry[i].source.address == source.address {
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
                (d.entry[0].attrs.clone(), d.entry[0].source.clone())
            }

            None => {
                let mut d = Destination::new(net);
                let a = attrs.clone();
                let src = source.clone();
                d.entry.push(Path::new(source, nexthop, attrs));
                t.insert(net, d);
                new_best = true;
                (a, src)
            }
        };
        if self.disable_best_path_selection == false && new_best {
            (
                Some(TableUpdate::NewBest(net, nexthop, attrs, src)),
                !replaced,
            )
        } else {
            (None, !replaced)
        }
    }

    pub fn remove(
        &mut self,
        family: bgp::Family,
        net: bgp::Nlri,
        source: Arc<Source>,
    ) -> (Option<TableUpdate>, bool) {
        let t = self.master.get_mut(&family);
        if t.is_none() {
            return (None, false);
        }
        let t = t.unwrap();
        match t.get_mut(&net) {
            Some(d) => {
                for i in 0..d.entry.len() {
                    if d.entry[i].source.address == source.address {
                        d.entry.remove(i);
                        if d.entry.len() == 0 {
                            t.remove(&net);
                            return (Some(TableUpdate::Withdrawn(net, source.clone())), true);
                        }
                        if i == 0 {
                            return (
                                Some(TableUpdate::NewBest(
                                    net,
                                    d.entry[0].nexthop,
                                    d.entry[0].attrs.clone(),
                                    d.entry[0].source.clone(),
                                )),
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

    pub fn clear(&mut self, source: Arc<Source>) -> Vec<TableUpdate> {
        let mut update = Vec::new();
        let mut m: HashMap<bgp::Family, Vec<bgp::Nlri>> = HashMap::new();
        for f in self.master.keys() {
            m.insert(*f, Vec::new());
        }

        for (f, t) in self.master.iter_mut() {
            for (n, d) in t {
                for i in 0..d.entry.len() {
                    if d.entry[i].source.address == source.address {
                        d.entry.remove(i);
                        if d.entry.len() == 0 {
                            update.push(TableUpdate::Withdrawn(*n, source.clone()));
                        } else if i == 0 {
                            update.push(TableUpdate::NewBest(
                                *n,
                                d.entry[0].nexthop,
                                d.entry[0].attrs.clone(),
                                source.clone(),
                            ));
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

    pub async fn broadcast(&mut self, from: Arc<Source>, msg: &TableUpdate) {
        for (addr, (tx, target)) in self.active_peers.iter_mut() {
            if target.state == bgp::State::Established
                && *addr != from.address
                && !(from.ibgp && target.ibgp)
            {
                match msg {
                    TableUpdate::NewBest(nlri, nexthop, attrs, source) => {
                        let _ = tx.send(PeerEvent::Broadcast(TableUpdate::NewBest(
                            *nlri,
                            *nexthop,
                            attrs.clone(),
                            source.clone(),
                        )));
                    }
                    TableUpdate::Withdrawn(nlri, source) => {
                        let _ = tx.send(PeerEvent::Broadcast(TableUpdate::Withdrawn(
                            *nlri,
                            source.clone(),
                        )));
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

impl api::Peer {
    pub fn get_passive_mode(&self) -> bool {
        if let Some(transport) = &self.transport {
            return transport.passive_mode;
        }
        false
    }

    pub fn get_remote_port(&self) -> u16 {
        if let Some(transport) = &self.transport {
            if transport.remote_port != 0 {
                return transport.remote_port as u16;
            }
        }
        return bgp::BGP_PORT;
    }

    pub fn get_local_as(&self) -> u32 {
        if let Some(conf) = &self.conf {
            return conf.local_as;
        }
        0
    }

    pub fn get_remote_as(&self) -> u32 {
        if let Some(conf) = &self.conf {
            return conf.peer_as;
        }
        0
    }

    pub fn get_connect_retry_time(&self) -> u64 {
        if let Some(timers) = &self.timers {
            if let Some(conf) = &timers.config {
                return conf.connect_retry;
            }
        }
        0
    }

    pub fn get_hold_time(&self) -> u64 {
        if let Some(timers) = &self.timers {
            if let Some(conf) = &timers.config {
                return conf.hold_time;
            }
        }
        0
    }

    pub fn get_families(&self) -> Vec<bgp::Family> {
        let mut v = Vec::new();
        for afisafi in &self.afi_safis {
            if let Some(conf) = &afisafi.config {
                if let Some(family) = &conf.family {
                    let f =
                        bgp::Family::from((family.afi as u32) << 16 | (family.safi as u32 & 0xff));
                    match f {
                        bgp::Family::Ipv4Uc | bgp::Family::Ipv6Uc => v.push(f),
                        _ => {}
                    }
                }
            }
        }
        if v.len() == 0 {
            if let Some(conf) = &self.conf {
                if let Ok(addr) = IpAddr::from_str(&conf.neighbor_address) {
                    match addr {
                        IpAddr::V4(_) => return vec![bgp::Family::Ipv4Uc],
                        IpAddr::V6(_) => return vec![bgp::Family::Ipv6Uc],
                    }
                }
            }
        }
        v
    }
}

pub struct Peer {
    pub address: IpAddr,
    pub local_port: u16,
    pub remote_port: u16,
    pub remote_as: u32,
    pub router_id: Ipv4Addr,
    pub local_as: u32,
    pub peer_type: u8,
    pub passive: bool,
    pub delete_on_disconnected: bool,

    pub hold_time: u64,
    pub connect_retry_time: u64,

    pub state: bgp::State,
    pub uptime: SystemTime,
    pub downtime: SystemTime,

    pub counter_tx: MessageCounter,
    pub counter_rx: MessageCounter,

    pub accepted: HashMap<bgp::Family, u64>,

    pub remote_cap: Vec<bgp::Capability>,
    pub local_cap: Vec<bgp::Capability>,
}

impl Peer {
    const DEFAULT_HOLD_TIME: u64 = 180;
    const DEFAULT_CONNECT_RETRY_TIME: u64 = 3;

    fn addr(&self) -> String {
        self.address.to_string()
    }

    pub fn new(address: IpAddr, as_number: u32) -> Peer {
        Peer {
            address: address,
            local_port: 0,
            remote_port: 0,
            remote_as: 0,
            router_id: Ipv4Addr::new(0, 0, 0, 0),
            local_as: as_number,
            peer_type: 0,
            passive: false,
            delete_on_disconnected: false,
            hold_time: Self::DEFAULT_HOLD_TIME,
            connect_retry_time: Self::DEFAULT_CONNECT_RETRY_TIME,
            state: bgp::State::Idle,
            uptime: SystemTime::UNIX_EPOCH,
            downtime: SystemTime::UNIX_EPOCH,
            counter_tx: Default::default(),
            counter_rx: Default::default(),
            accepted: HashMap::new(),
            remote_cap: Vec::new(),
            local_cap: vec![
                bgp::Capability::RouteRefresh,
                bgp::Capability::FourOctetAsNumber {
                    as_number: as_number,
                },
            ],
        }
    }

    pub fn families(mut self, families: Vec<bgp::Family>) -> Self {
        let mut v: Vec<bgp::Capability> = families
            .iter()
            .map(|family| bgp::Capability::MultiProtocol { family: *family })
            .collect();
        self.local_cap.append(&mut v);
        self
    }

    pub fn remote_port(mut self, remote_port: u16) -> Self {
        self.remote_port = remote_port;
        self
    }

    pub fn remote_as(mut self, remote_as: u32) -> Self {
        self.remote_as = remote_as;
        self
    }

    pub fn passive(mut self, passive: bool) -> Self {
        self.passive = passive;
        self
    }

    pub fn delete_on_disconnected(mut self, delete: bool) -> Self {
        self.delete_on_disconnected = delete;
        self
    }

    pub fn state(mut self, state: bgp::State) -> Self {
        self.state = state;
        self
    }

    pub fn hold_time(mut self, t: u64) -> Self {
        if t != 0 {
            self.hold_time = t;
        }
        self
    }

    pub fn connect_retry_time(mut self, t: u64) -> Self {
        if t != 0 {
            self.connect_retry_time = t;
        }
        self
    }

    fn reset(&mut self) {
        self.state = bgp::State::Idle;
        self.downtime = SystemTime::now();
        self.accepted = HashMap::new();
        self.remote_cap = Vec::new();
    }

    fn update_accepted(&mut self, family: bgp::Family, delta: i64) {
        match self.accepted.get_mut(&family) {
            Some(v) => {
                if delta > 0 {
                    *v += delta as u64;
                } else {
                    *v -= delta.abs() as u64;
                }
            }
            None => {
                // ignore bogus withdrawn
                if delta > 0 {
                    self.accepted.insert(family, delta as u64);
                }
            }
        }
    }

    fn to_bmp_up(&self, router_id: Ipv4Addr, local_address: IpAddr) -> bmp::PeerUpNotification {
        let sent = bgp::Message::Open(bgp::OpenMessage::new(
            router_id,
            self.local_cap.iter().cloned().collect(),
        ))
        .to_bytes()
        .unwrap();
        let recv = bgp::Message::Open(bgp::OpenMessage::new(
            self.router_id,
            self.remote_cap.iter().cloned().collect(),
        ))
        .to_bytes()
        .unwrap();
        bmp::PeerUpNotification {
            peer_header: bmp::PeerHeader::new(
                0,
                0,
                self.address,
                self.remote_as,
                self.router_id,
                self.uptime,
            ),
            local_address: local_address,
            local_port: self.local_port,
            remote_port: self.remote_port,
            sent_open: sent,
            received_open: recv,
        }
    }

    fn to_bmp_down(&self, r: u8) -> bmp::PeerDownNotification {
        bmp::PeerDownNotification {
            peer_header: bmp::PeerHeader::new(
                0,
                0,
                self.address,
                self.remote_as,
                self.router_id,
                self.uptime,
            ),
            reason: r,
            payload: Vec::new(),
            data: Vec::new(),
        }
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
            let mut ts = api::TimersState {
                uptime: Some(self.uptime.to_api()),
                ..Default::default()
            };
            if self.downtime != SystemTime::UNIX_EPOCH {
                ts.downtime = Some(self.downtime.to_api());
            }
            tm.state = Some(ts);
        }
        let afisafis = self
            .accepted
            .iter()
            .map(|x| api::AfiSafi {
                state: Some(api::AfiSafiState {
                    family: Some(x.0.to_api()),
                    enabled: true,
                    received: *x.1,
                    accepted: *x.1,
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
    pub listen_port: u16,

    pub peers: HashMap<IpAddr, Peer>,
    pub peer_group: HashMap<String, PeerGroup>,

    pub server_event_tx: Sender<SrvEvent>,
}

impl ToApi<api::Global> for Global {
    fn to_api(&self) -> api::Global {
        api::Global {
            r#as: self.as_number,
            router_id: self.id.to_string(),
            listen_port: self.listen_port as i32,
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
    pub fn new(asn: u32, id: Ipv4Addr, tx: Sender<SrvEvent>) -> Global {
        Global {
            as_number: asn,
            id: id,
            listen_port: bgp::BGP_PORT,
            peers: HashMap::new(),
            peer_group: HashMap::new(),
            server_event_tx: tx,
        }
    }
}

pub struct Service {
    global: Arc<Mutex<Global>>,
    table: Arc<Mutex<Table>>,
    init_tx: Arc<Barrier>,
}

fn to_native_attrs(api_attrs: Vec<prost_types::Any>) -> (Vec<bgp::Attribute>, IpAddr) {
    let mut v = Vec::new();
    let mut nexthop = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    for a in &api_attrs {
        match &*a.type_url {
            "type.googleapis.com/gobgpapi.OriginAttribute" => {
                let a: api::OriginAttribute =
                    prost::Message::decode(Cursor::new(&a.value)).unwrap();
                v.push(bgp::Attribute::Origin {
                    origin: a.origin as u8,
                });
            }
            "type.googleapis.com/gobgpapi.AsPathAttribute" => {
                let a: api::AsPathAttribute =
                    prost::Message::decode(Cursor::new(&a.value)).unwrap();
                let mut s = Vec::new();
                for seg in &a.segments {
                    s.push(bgp::Segment {
                        segment_type: (seg.r#type) as u8,
                        number: seg.numbers.iter().cloned().collect(),
                    });
                }
                v.push(bgp::Attribute::AsPath { segments: s });
            }
            "type.googleapis.com/gobgpapi.NextHopAttribute" => {
                let a: api::NextHopAttribute =
                    prost::Message::decode(Cursor::new(&a.value)).unwrap();
                match IpAddr::from_str(&a.next_hop) {
                    Ok(addr) => {
                        nexthop = addr;
                    }
                    Err(_) => {}
                }
            }
            "type.googleapis.com/gobgpapi.MultiExitDiscAttribute" => {
                let a: api::MultiExitDiscAttribute =
                    prost::Message::decode(Cursor::new(&a.value)).unwrap();
                v.push(bgp::Attribute::MultiExitDesc { descriptor: a.med });
            }
            "type.googleapis.com/gobgpapi.LocalPrefAttribute" => {
                let a: api::LocalPrefAttribute =
                    prost::Message::decode(Cursor::new(&a.value)).unwrap();
                v.push(bgp::Attribute::LocalPref {
                    preference: a.local_pref,
                });
            }
            "type.googleapis.com/gobgpapi.AtomicAggregateAttribute" => {
                v.push(bgp::Attribute::AtomicAggregate);
            }
            "type.googleapis.com/gobgpapi.AggregateAttribute" => {
                let a: api::AggregatorAttribute =
                    prost::Message::decode(Cursor::new(&a.value)).unwrap();
                match IpAddr::from_str(&a.address) {
                    Ok(addr) => v.push(bgp::Attribute::Aggregator {
                        four_byte: true,
                        number: a.r#as,
                        address: addr,
                    }),
                    Err(_) => {}
                }
            }
            "type.googleapis.com/gobgpapi.CommunitiesAttribute" => {
                let a: api::CommunitiesAttribute =
                    prost::Message::decode(Cursor::new(&a.value)).unwrap();
                v.push(bgp::Attribute::Community {
                    communities: a.communities.iter().cloned().collect(),
                });
            }
            "type.googleapis.com/gobgpapi.OriginatorIdAttribute" => {
                let a: api::OriginatorIdAttribute =
                    prost::Message::decode(Cursor::new(&a.value)).unwrap();
                match IpAddr::from_str(&a.id) {
                    Ok(addr) => v.push(bgp::Attribute::OriginatorId { address: addr }),
                    Err(_) => {}
                }
            }
            "type.googleapis.com/gobgpapi.ClusterListAttribute" => {}
            _ => {
                let a: api::ClusterListAttribute =
                    prost::Message::decode(Cursor::new(&a.value)).unwrap();
                let mut addrs = Vec::new();
                for addr in &a.ids {
                    match IpAddr::from_str(addr) {
                        Ok(addr) => addrs.push(addr),
                        Err(_) => {}
                    }
                }
                v.push(bgp::Attribute::ClusterList {
                    addresses: addrs.iter().cloned().collect(),
                });
            }
        }
    }
    (v, nexthop)
}

#[tonic::async_trait]
impl GobgpApi for Service {
    async fn start_bgp(
        &self,
        request: tonic::Request<api::StartBgpRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        match request.into_inner().global {
            Some(global) => {
                let g = &mut self.global.lock().await;
                if g.as_number != 0 {
                    return Err(tonic::Status::new(
                        tonic::Code::InvalidArgument,
                        "already started",
                    ));
                }
                if global.r#as == 0 {
                    return Err(tonic::Status::new(
                        tonic::Code::InvalidArgument,
                        "invalid as number",
                    ));
                }
                match Ipv4Addr::from_str(&global.router_id) {
                    Ok(addr) => {
                        g.as_number = global.r#as;
                        g.id = addr;
                        if global.listen_port != 0 {
                            g.listen_port = global.listen_port as u16;
                        }
                        self.init_tx.wait().await;
                    }
                    Err(_) => {
                        return Err(tonic::Status::new(
                            tonic::Code::InvalidArgument,
                            "invalid router id",
                        ));
                    }
                }
            }
            None => {
                return Err(tonic::Status::new(
                    tonic::Code::InvalidArgument,
                    "empty configuration",
                ));
            }
        }
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
        Ok(tonic::Response::new(api::GetBgpResponse {
            global: Some(self.global.lock().await.to_api()),
        }))
    }
    async fn add_peer(
        &self,
        request: tonic::Request<api::AddPeerRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        if let Some(peer) = request.into_inner().peer {
            if let Some(conf) = &peer.conf {
                if let Ok(addr) = IpAddr::from_str(&conf.neighbor_address) {
                    let as_number = {
                        let local = peer.get_local_as();
                        if local == 0 {
                            self.global.lock().await.as_number
                        } else {
                            local
                        }
                    };

                    let g = &mut self.global.lock().await;
                    if g.peers.contains_key(&addr) {
                        return Err(tonic::Status::new(
                            tonic::Code::AlreadyExists,
                            "peer address already exists",
                        ));
                    } else {
                        let passive = peer.get_passive_mode();
                        let remote_port = peer.get_remote_port();
                        g.peers.insert(
                            addr,
                            Peer::new(addr, as_number)
                                .remote_as(peer.get_remote_as())
                                .remote_port(remote_port)
                                .families(peer.get_families())
                                .passive(passive)
                                .hold_time(peer.get_hold_time())
                                .connect_retry_time(peer.get_connect_retry_time()),
                        );

                        if !passive {
                            let _ = g.server_event_tx.send(SrvEvent::EnableActive {
                                proto: Proto::Bgp,
                                sockaddr: SocketAddr::new(addr, remote_port),
                            });
                        }
                        return Ok(tonic::Response::new(()));
                    }
                }
            }
        }
        Err(tonic::Status::new(
            tonic::Code::InvalidArgument,
            "invalid parameters",
        ))
    }
    async fn delete_peer(
        &self,
        request: tonic::Request<api::DeletePeerRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        if let Ok(addr) = IpAddr::from_str(&request.into_inner().address) {
            let g = &mut self.global.lock().await;
            if g.peers.contains_key(&addr) {
                let _ = g.server_event_tx.send(SrvEvent::Deconfigured(addr));
                return Ok(tonic::Response::new(()));
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
    type ListPeerStream = mpsc::Receiver<Result<api::ListPeerResponse, tonic::Status>>;
    async fn list_peer(
        &self,
        request: tonic::Request<api::ListPeerRequest>,
    ) -> Result<tonic::Response<Self::ListPeerStream>, tonic::Status> {
        let request = request.into_inner();
        let addr = IpAddr::from_str(&request.address);

        let (mut tx, rx) = mpsc::channel(1024);
        let global = self.global.clone();

        tokio::spawn(async move {
            let global = global.lock().await;

            for (a, p) in &global.peers {
                if let Ok(addr) = addr {
                    if &addr != a {
                        continue;
                    }
                }

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
        request: tonic::Request<api::AddPathRequest>,
    ) -> Result<tonic::Response<api::AddPathResponse>, tonic::Status> {
        let r = request.into_inner();

        let api_path = r.path.ok_or(tonic::Status::new(
            tonic::Code::InvalidArgument,
            "empty path",
        ))?;

        let family = api_path
            .family
            .ok_or(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "empty family",
            ))?
            .to_proto();

        let nlri = api_path
            .nlri
            .ok_or(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "empty nlri",
            ))?
            .to_proto()
            .ok_or(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "unknown nlri",
            ))?;

        let (attrs, nexthop) = to_native_attrs(api_path.pattrs);
        let table = self.table.clone();
        let mut t = table.lock().await;
        let s = t.local_source.clone();
        let (u, _) = t.insert(
            family,
            nlri,
            s.clone(),
            nexthop,
            Arc::new(PathAttr { entry: attrs }),
        );
        if let Some(u) = u {
            t.broadcast(s.clone(), &u).await;
        }

        Ok(tonic::Response::new(api::AddPathResponse {
            uuid: Vec::new(),
        }))
    }
    async fn delete_path(
        &self,
        request: tonic::Request<api::DeletePathRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        let r = request.into_inner();

        let api_path = r.path.ok_or(tonic::Status::new(
            tonic::Code::InvalidArgument,
            "empty path",
        ))?;

        let family = api_path
            .family
            .ok_or(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "empty family",
            ))?
            .to_proto();

        let nlri = api_path
            .nlri
            .ok_or(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "empty nlri",
            ))?
            .to_proto()
            .ok_or(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "unknown nlri",
            ))?;

        let table = self.table.clone();
        let mut t = table.lock().await;
        let s = t.local_source.clone();
        let (u, _) = t.remove(family, nlri, s.clone());
        if let Some(u) = u {
            t.broadcast(s.clone(), &u).await;
        }
        Ok(tonic::Response::new(()))
    }
    type ListPathStream = mpsc::Receiver<Result<api::ListPathResponse, tonic::Status>>;
    async fn list_path(
        &self,
        request: tonic::Request<api::ListPathRequest>,
    ) -> Result<tonic::Response<Self::ListPathStream>, tonic::Status> {
        let request = request.into_inner();
        let (table_type, source_addr) =
            if let Some(t) = api::TableType::from_i32(request.table_type) {
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

        let (mut tx, rx) = mpsc::channel(1024);
        let table = self.table.clone();
        tokio::spawn(async move {
            let mut v = Vec::new();

            let prefixes: Vec<_> = request
                .prefixes
                .iter()
                .filter_map(|p| bgp::IpNet::from_str(&p.prefix).ok())
                .collect();

            let family = if let Some(family) = request.family {
                bgp::Family::new(family.afi as u16, family.safi as u8)
            } else {
                bgp::Family::Ipv4Uc
            };

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

            let adjin_filter = |src: IpAddr| -> bool {
                if table_type != api::TableType::AdjIn {
                    false
                } else if source_addr.unwrap() == src {
                    false
                } else {
                    true
                }
            };

            let table = table.lock().await;
            let source = if table_type == api::TableType::AdjOut {
                table.active_peers.get(&source_addr.unwrap())
            } else {
                None
            };

            let adjout_filter = |from: Arc<Source>| -> bool {
                if table_type != api::TableType::AdjOut {
                    return false;
                }

                match source {
                    Some(s) => {
                        let (_, source) = s;
                        if (source.ibgp && from.ibgp) || (source_addr.unwrap() == from.address) {
                            return true;
                        }

                        false
                    }
                    None => true,
                }
            };

            {
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
                            if adjin_filter(p.source.address) {
                                continue;
                            }
                            if adjout_filter(p.source.clone()) {
                                continue;
                            }
                            if table_type == api::TableType::AdjOut {
                                let (_, my) = source.unwrap();
                                let nexthop = if my.ibgp { p.nexthop } else { my.local_addr };
                                let (mut v, n) = update_attrs(
                                    my.ibgp,
                                    dst.net.is_mp(),
                                    my.local_as,
                                    dst.net,
                                    p.nexthop,
                                    my.local_addr,
                                    p.attrs.entry.iter().collect(),
                                );
                                v.append(&mut n.iter().collect());
                                v.sort_by_key(|a| a.attr());
                                r.push(p.to_api(&dst.net, nexthop, v));
                            } else {
                                r.push(p.to_api(
                                    &dst.net,
                                    p.nexthop,
                                    p.attrs.entry.iter().collect(),
                                ));
                            }
                        }
                        if r.len() > 0 {
                            r[0].best = true;
                            v.push(api::ListPathResponse {
                                destination: Some(dst.to_api(r)),
                            });
                        }
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
        request: tonic::Request<tonic::Streaming<api::AddPathStreamRequest>>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        let mut stream = request.into_inner();

        let (mut tx, mut rx) = mpsc::channel(1024);
        tokio::spawn(async move {
            while let Some(req) = stream.next().await {
                match req {
                    Ok(req) => {
                        for api_path in req.paths {
                            tx.send(api_path).await.unwrap();
                        }
                    }
                    Err(_) => {}
                }
            }
        });

        while let Some(api_path) = rx.next().await {
            let family = api_path
                .family
                .ok_or(tonic::Status::new(
                    tonic::Code::InvalidArgument,
                    "empty family",
                ))?
                .to_proto();

            let nlri = api_path
                .nlri
                .ok_or(tonic::Status::new(
                    tonic::Code::InvalidArgument,
                    "empty nlri",
                ))?
                .to_proto()
                .ok_or(tonic::Status::new(
                    tonic::Code::InvalidArgument,
                    "unknown nlri",
                ))?;

            let (attrs, nexthop) = to_native_attrs(api_path.pattrs);
            let table = self.table.clone();
            let mut t = table.lock().await;
            let s = t.local_source.clone();
            let (u, _) = t.insert(
                family,
                nlri,
                s.clone(),
                nexthop,
                Arc::new(PathAttr { entry: attrs }),
            );
            if let Some(u) = u {
                t.broadcast(s.clone(), &u).await;
            }
        }

        Ok(tonic::Response::new(()))
    }
    async fn get_table(
        &self,
        request: tonic::Request<api::GetTableRequest>,
    ) -> Result<tonic::Response<api::GetTableResponse>, tonic::Status> {
        let r = request.into_inner();
        let mut family = bgp::Family::Ipv4Uc;
        if let Some(f) = r.family {
            family = f.to_proto();
        }

        let table = self.table.clone();
        let t = table.lock().await;
        let t = t.master.get(&family);
        let mut nr_dst: u64 = 0;
        let mut nr_path: u64 = 0;
        match t {
            Some(t) => {
                for (_, dst) in t {
                    nr_path += dst.entry.len() as u64;
                }
                nr_dst = t.len() as u64;
            }
            None => {}
        }
        Ok(tonic::Response::new(api::GetTableResponse {
            num_destination: nr_dst,
            num_path: nr_path,
            num_accepted: 0,
        }))
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
        request: tonic::Request<api::AddBmpRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        let request = request.into_inner();
        if let Ok(addr) = IpAddr::from_str(&request.address) {
            let g = &mut self.global.lock().await;
            let mut port = request.port as u16;
            if port == 0 {
                port = bmp::DEFAULT_PORT;
            }
            let _ = g.server_event_tx.send(SrvEvent::EnableActive {
                proto: Proto::Bmp,
                sockaddr: SocketAddr::new(addr, port),
            });
            return Ok(tonic::Response::new(()));
        }
        Err(tonic::Status::new(
            tonic::Code::InvalidArgument,
            "invalid parameters",
        ))
    }
    async fn delete_bmp(
        &self,
        _request: tonic::Request<api::DeleteBmpRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        Err(tonic::Status::unimplemented("Not yet implemented"))
    }
}

type Sender<T> = mpsc::UnboundedSender<T>;
type Receiver<T> = mpsc::UnboundedReceiver<T>;

#[derive(PartialEq, Clone, Copy, Debug)]
pub enum Proto {
    Bgp,
    Bmp,
    // Rpki,
}

pub enum DisconnectedProto {
    Bgp(Arc<Source>),
    Bmp(SocketAddr),
}

pub enum SrvEvent {
    EnableActive { proto: Proto, sockaddr: SocketAddr },
    Disconnected(DisconnectedProto),
    Deconfigured(IpAddr),
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Hello, RustyBGP!");

    let args = App::new("rustybgp")
        .arg(
            Arg::with_name("asn")
                .long("as-number")
                .takes_value(true)
                .help("specify as number"),
        )
        .arg(
            Arg::with_name("id")
                .long("router-id")
                .takes_value(true)
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

    let asn = if let Some(asn) = args.value_of("asn") {
        asn.parse()?
    } else {
        0
    };
    let router_id = if let Some(id) = args.value_of("id") {
        Ipv4Addr::from_str(id)?
    } else {
        Ipv4Addr::new(0, 0, 0, 0)
    };

    let (srv_event_tx, mut srv_event_rx) = mpsc::unbounded_channel();

    let global = Arc::new(Mutex::new(Global::new(asn, router_id, srv_event_tx)));
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
    let init_tx = Arc::new(Barrier::new(2));
    let addr = "[::]:50051".parse()?;
    let service = Service {
        global: Arc::clone(&global),
        table: Arc::clone(&table),
        init_tx: init_tx.clone(),
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
    if asn == 0 {
        init_tx.wait().await;
    }

    let mut listener =
        TcpListener::bind(format!("[::]:{}", global.lock().await.listen_port)).await?;

    let mut expirations: DelayQueue<(Proto, SocketAddr)> = DelayQueue::new();
    let mut incoming = listener.incoming();
    loop {
        let (proto, stream, sock) = tokio::select! {
            Some(stream) = incoming.next().fuse() => {
                match stream {
                    Ok(stream) =>{
                        match stream.peer_addr() {
                            Ok(sock) => {
                                let t = table.lock().await;
                                if t.active_peers.contains_key(&sock.ip()) {
                                    // already connected
                                    continue;
                                }
                                (Proto::Bgp, stream, sock)
                            },
                            Err(_) => continue,
                        }
                    }
                    Err(_) =>continue,
                }
            }
            Some(v) = expirations.next().fuse() => {
                    match v {
                        Ok(v)=>{
                            let (proto, sockaddr) = v.into_inner();
                            let t = table.lock().await;
                            if proto == Proto::Bgp {
                                if t.active_peers.contains_key(&sockaddr.ip()) {
                                    // already connected
                                    continue;
                                }
                            }
                            match TcpStream::connect(sockaddr).await {
                                Ok(stream) => (proto, stream, sockaddr),
                                Err(_) => {
                                    expirations.insert((proto, sockaddr), Duration::from_secs(5));
                                    continue;
                                }
                            }
                        }
                        Err(_)=>{
                            continue;
                        }
                    }
            }
            Some(event) = srv_event_rx.next().fuse() =>{
                match event {
                    SrvEvent::EnableActive{proto, sockaddr} => {
                        expirations.insert((proto, sockaddr), Duration::from_secs(5));
                        continue;
                    }
                    SrvEvent::Disconnected(p) =>{
                        match p {
                            DisconnectedProto::Bgp(source) => {
                                let addr = source.address;
                                {
                                    let mut t = table.lock().await;
                                    t.active_peers.remove(&addr);
                                    for u in t.clear(source.clone()) {
                                        t.broadcast(source.clone(), &u).await;
                                    }
                                }
                                {
                                    let mut g = global.lock().await;
                                    for (_, tx) in &table.lock().await.bmp_sessions {
                                        let peer = g.peers.get_mut(&addr).unwrap();
                                        let _ = tx.send(bmp::Message::PeerDownNotification(peer.to_bmp_down(bmp::PeerDownNotification::REASON_UNKNOWN)));
                                    }
                                    let peer = g.peers.get_mut(&addr).unwrap();
                                    if peer.delete_on_disconnected {
                                        g.peers.remove(&addr);
                                    } else {
                                        let peer = g.peers.get_mut(&addr).unwrap();
                                        peer.reset();
                                        if !peer.passive {
                                            expirations.insert((Proto::Bgp, SocketAddr::new(addr, peer.remote_port)), Duration::from_secs(5));
                                        }
                                    }
                                }
                            }
                            DisconnectedProto::Bmp(sockaddr) =>{
                                let mut t = table.lock().await;
                                t.bmp_sessions.remove(&sockaddr);
                                expirations.insert((Proto::Bmp, sockaddr), Duration::from_secs(5));
                            }
                        }
                        continue;
                    }
                    SrvEvent::Deconfigured(addr) =>{
                        let mut g = global.lock().await;
                        let t = table.lock().await;

                        match g.peers.get_mut(&addr) {
                            Some(peer) =>{
                                if t.active_peers.contains_key(&addr) {
                                    peer.delete_on_disconnected = true;
                                    let (tx, _) = t.active_peers.get(&addr).unwrap();
                                    let _=tx.send(PeerEvent::Notification(
                                        bgp::NotificationMessage::new(
                                            bgp::NotificationCode::PeerDeconfigured,
                                        )
                                    ));
                                } else {
                                    g.peers.remove(&addr);
                                }
                            }
                            None => continue,
                        }

                        continue;
                    }
                }
            }
        };

        let addr = sock.to_ipaddr();
        println!("got new connection {:?} {:?}", proto, addr);

        if proto == Proto::Bmp {
            let global = Arc::clone(&global);
            let g1 = Arc::clone(&global);
            let g = g1.lock().await;
            let mut t = table.lock().await;
            if !t.bmp_sessions.contains_key(&sock) {
                let (tx, mut rx) = mpsc::unbounded_channel();

                let _ = tx.send(bmp::Message::Initiation(
                    bmp::Initiation::new()
                        .tlv(
                            bmp::Initiation::TLV_SYS_NAME,
                            format!("RusytBGP").as_bytes().to_vec(),
                        )
                        .tlv(
                            bmp::Initiation::TLV_SYS_DESCR,
                            format!("master").as_bytes().to_vec(),
                        ),
                ));

                for (_, (_, source)) in t.active_peers.iter() {
                    if source.state != bgp::State::Established {
                        continue;
                    }
                    let p = g.peers.get(&source.address).unwrap();
                    let _ = tx.send(bmp::Message::PeerUpNotification(
                        p.to_bmp_up(g.id, source.address),
                    ));
                }

                t.bmp_sessions.insert(sock, tx);
                tokio::spawn(async move {
                    handle_bmp_session(Arc::clone(&global), &mut rx, stream, sock).await;
                });
            }
            continue;
        }

        let local_addr = match stream.local_addr() {
            Ok(addr) => addr.to_ipaddr(),
            Err(_) => {
                continue;
            }
        };

        let mut g = global.lock().await;
        if g.peers.contains_key(&addr) == true {
        } else {
            let mut is_dynamic = false;
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

            let families = match addr {
                IpAddr::V4(_) => vec![bgp::Family::Ipv4Uc],
                IpAddr::V6(_) => vec![bgp::Family::Ipv6Uc],
            };
            let peer = Peer::new(addr, g.as_number)
                .families(families)
                .state(bgp::State::Active)
                .delete_on_disconnected(true);
            g.peers.insert(addr, peer);
        }

        let global = Arc::clone(&global);
        let table = Arc::clone(&table);
        let source = Arc::new(Source {
            local_addr: local_addr,
            local_as: 0,
            address: addr,
            ibgp: false,
            state: bgp::State::Active,
        });
        let mut rx = {
            let mut t = table.lock().await;
            let (tx, rx) = mpsc::unbounded_channel();
            t.active_peers.insert(addr, (tx, source.clone()));
            rx
        };
        tokio::spawn(async move {
            handle_session(global, table, &mut rx, stream, addr, local_addr).await;
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

    fn encode(&mut self, item: bgp::Message, dst: &mut BytesMut) -> Result<(), io::Error> {
        let buf = item.to_bytes().unwrap();
        dst.reserve(buf.len());
        dst.put_slice(&buf);
        Ok(())
    }
}

impl Decoder for Bgp {
    type Item = bgp::Message;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> io::Result<Option<bgp::Message>> {
        match bgp::Message::from_bytes(&self.param, src) {
            Ok(m) => {
                let _ = src.split_to(m.length());
                Ok(Some(m))
            }
            Err(_) => Ok(None),
        }
    }
}

pub enum PeerEvent {
    Broadcast(TableUpdate),
    Notification(bgp::NotificationMessage),
}

fn update_attrs(
    is_ibgp: bool,
    is_mp: bool,
    local_as: u32,
    nlri: bgp::Nlri,
    original_nexthop: IpAddr,
    local_addr: IpAddr,
    attrs: Vec<&bgp::Attribute>,
) -> (Vec<&bgp::Attribute>, Vec<bgp::Attribute>) {
    let mut seen = HashSet::new();
    let mut v = Vec::new();
    let mut n = Vec::new();

    for attr in attrs {
        seen.insert(attr.attr());
        if !attr.is_transitive() {
            continue;
        }
        if !is_ibgp {
            match attr {
                bgp::Attribute::AsPath { segments: segs } => {
                    let mut segments = Vec::new();

                    for s in segs {
                        segments.insert(0, bgp::Segment::new(s.segment_type, &s.number));
                    }

                    let aspath = if segments.len() == 0 {
                        bgp::Attribute::AsPath {
                            segments: vec![bgp::Segment {
                                segment_type: bgp::Segment::TYPE_SEQ,
                                number: vec![local_as],
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
                                    number: vec![local_as],
                                },
                            );
                        } else {
                            segments[0].number.insert(0, local_as);
                        }
                        bgp::Attribute::AsPath { segments }
                    };

                    n.push(aspath);
                    continue;
                }
                bgp::Attribute::MultiExitDesc { .. } => {
                    continue;
                }
                _ => {}
            }
        }

        v.push(attr);
    }

    let nexthop = if is_ibgp {
        original_nexthop
    } else {
        local_addr
    };
    if is_mp {
        n.push(bgp::Attribute::MpReach {
            family: bgp::Family::Ipv6Uc,
            nexthop,
            nlri: vec![nlri],
        })
    } else {
        n.push(bgp::Attribute::Nexthop { nexthop });
    }

    if !seen.contains(&bgp::Attribute::AS_PATH) {
        if is_ibgp {
            n.push(bgp::Attribute::AsPath {
                segments: Vec::new(),
            });
        } else {
            n.push(bgp::Attribute::AsPath {
                segments: vec![bgp::Segment {
                    segment_type: bgp::Segment::TYPE_SEQ,
                    number: vec![local_as],
                }],
            });
        }
    }
    if !seen.contains(&bgp::Attribute::LOCAL_PREF) {
        if is_ibgp {
            n.push(bgp::Attribute::LocalPref {
                preference: bgp::Attribute::DEFAULT_LOCAL_PREF,
            });
        }
    }

    return (v, n);
}

#[derive(Clone)]
pub struct Source {
    address: IpAddr,
    ibgp: bool,
    local_as: u32,
    local_addr: IpAddr,
    state: bgp::State,
}

struct Session {
    lines: Framed<TcpStream, Bgp>,
    families: HashSet<bgp::Family>,
}

impl Session {
    fn new(stream: TcpStream, as_number: u32) -> Session {
        Session {
            lines: Framed::new(
                stream,
                Bgp {
                    param: bgp::ParseParam {
                        local_as: as_number,
                    },
                },
            ),
            families: HashSet::new(),
        }
    }

    fn is_family_enabled(&self, is_mp: bool) -> bool {
        if (is_mp && !self.families.contains(&bgp::Family::Ipv6Uc))
            || !is_mp && !self.families.contains(&bgp::Family::Ipv4Uc)
        {
            return false;
        }
        true
    }

    async fn send_update(
        &mut self,
        my: Arc<Source>,
        updates: Vec<TableUpdate>,
    ) -> Result<(), io::Error> {
        for update in updates {
            match update {
                TableUpdate::NewBest(nlri, nexthop, attrs, _source) => {
                    let is_mp = nlri.is_mp();

                    if !Session::is_family_enabled(self, is_mp) {
                        continue;
                    }

                    let (mut v, n) = update_attrs(
                        my.ibgp,
                        is_mp,
                        my.local_as,
                        nlri,
                        nexthop,
                        my.local_addr,
                        attrs.entry.iter().collect(),
                    );
                    v.append(&mut n.iter().collect());

                    v.sort_by_key(|a| a.attr());

                    let routes = if is_mp { Vec::new() } else { vec![nlri] };
                    let buf = bgp::UpdateMessage::to_bytes(routes, Vec::new(), v).unwrap();
                    self.lines.get_mut().write_all(&buf).await?;
                }
                TableUpdate::Withdrawn(nlri, _source) => {
                    if !Session::is_family_enabled(self, nlri.is_mp()) {
                        continue;
                    }

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
    type Item = Result<bgp::Message, io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let result: Option<_> = futures::ready!(Pin::new(&mut self.lines).poll_next(cx));
        Poll::Ready(match result {
            Some(Ok(message)) => Some(Ok(message)),
            Some(Err(e)) => Some(Err(e)),
            None => None,
        })
    }
}

async fn handle_session(
    global: Arc<Mutex<Global>>,
    table: Arc<Mutex<Table>>,
    peer_event_rx: &mut Receiver<PeerEvent>,
    stream: TcpStream,
    addr: IpAddr,
    local_addr: IpAddr,
) {
    let (as_number, router_id) = {
        let global = global.lock().await;
        (global.as_number, global.id)
    };

    let mut keepalive_interval = bgp::OpenMessage::HOLDTIME / 3;
    let mut session = Session::new(stream, as_number);
    {
        let peers = &mut global.lock().await.peers;
        let peer = peers.get_mut(&addr).unwrap();

        let _ = session
            .lines
            .send(bgp::Message::Open(bgp::OpenMessage::new(
                router_id,
                peer.local_cap.iter().cloned().collect(),
            )))
            .await;
    }

    let mut state = bgp::State::OpenSent;
    let mut source = {
        let t = table.lock().await;
        let (_, source) = t.active_peers.get(&addr).unwrap();
        source.clone()
    };
    let mut delay = delay_for(Duration::from_secs(0));

    loop {
        tokio::select! {
            _ = &mut delay => {
                delay.reset(Instant::now() + Duration::from_secs(keepalive_interval as u64));

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
            Some(msg) = peer_event_rx.next().fuse() =>{
                match msg {
                    PeerEvent::Broadcast(msg) => {
                       if session
                            .send_update(source.clone(), vec![msg])
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    PeerEvent::Notification(msg) => {
                        let _ = session.lines.send(bgp::Message::Notification(msg)).await;
                        break;
                    }
                }
            }
            msg = session.lines.next().fuse() => {
                let msg = match msg {
                    Some(msg) => {
                        match msg {
                            Ok(msg) => msg,
                            Err(_) => break,
                        }
                    }
                    None => break,
                };

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
                                let remote_as = open.get_as_number();
                                if peer.remote_as != 0 && peer.remote_as != remote_as {
                                    peer.state = bgp::State::Idle;
                                    let msg =
                                        bgp::Message::Notification(bgp::NotificationMessage::new(
                                            bgp::NotificationCode::OpenMessageBadPeerAs,
                                        ));
                                    let _ = session.lines.send(msg).await;
                                    break;
                                }
                                peer.remote_as = remote_as;

                                peer.remote_cap = open
                                    .params
                                    .into_iter()
                                    .filter_map(|p| match p {
                                        bgp::OpenParam::CapabilityParam(c) => Some(c),
                                        _ => None,
                                    })
                                    .collect();

                                let remote_families: HashSet<_> = peer
                                    .remote_cap
                                    .iter()
                                    .filter_map(|c| match c {
                                        bgp::Capability::MultiProtocol { family } => Some(family),
                                        _ => None,
                                    })
                                    .collect();
                                session.families = peer
                                    .local_cap
                                    .iter()
                                    .filter_map(|c| match c {
                                        bgp::Capability::MultiProtocol { family } => Some(family),
                                        _ => None,
                                    })
                                    .filter_map(|f| {
                                        if remote_families.contains(&f) {
                                            Some(*f)
                                        } else {
                                            None
                                        }
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
                            delay
                                .reset(Instant::now() + Duration::from_secs(keepalive_interval as u64));
                        }
                        bgp::Message::Update(mut update) => {
                            let mut accept_v4: i64 = 0;
                            let mut accept_v6: i64 = 0;
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
                                        source.clone(),
                                        update.nexthop,
                                        pa.clone(),
                                    );
                                    if let Some(u) = u {
                                        t.broadcast(source.clone(), &u).await;
                                    }
                                    if added {
                                        accept_v4 += 1;
                                    }
                                }
                                for f in update.mp_routes {
                                    for r in f.0 {
                                        let (u, added) = t.insert(
                                            bgp::Family::Ipv6Uc,
                                            r,
                                            source.clone(),
                                            f.1,
                                            pa.clone(),
                                        );
                                        if let Some(u) = u {
                                            t.broadcast(source.clone(), &u).await;
                                        }
                                        if added {
                                            accept_v6 += 1;
                                        }
                                    }
                                }
                            }
                            if update.withdrawns.len() > 0 {
                                let mut t = table.lock().await;
                                for r in update.withdrawns {
                                    let bgp::Nlri::Ip(net) = r;
                                    let family = match net.addr {
                                        IpAddr::V4(_) => bgp::Family::Ipv4Uc,
                                        IpAddr::V6(_) => bgp::Family::Ipv6Uc,
                                    };
                                    let (u, deleted) = t.remove(family, r, source.clone());
                                    if let Some(u) = u {
                                        t.broadcast(source.clone(), &u).await;
                                    }
                                    if deleted {
                                        if family == bgp::Family::Ipv4Uc {
                                            accept_v4 -= 1;
                                        } else {
                                            accept_v6 -= 1;
                                        }
                                    }
                                }
                            }
                            {
                                let peers = &mut global.lock().await.peers;
                                peers
                                    .get_mut(&addr)
                                    .unwrap()
                                    .update_accepted(bgp::Family::Ipv4Uc, accept_v4);
                                peers
                                    .get_mut(&addr)
                                    .unwrap()
                                    .update_accepted(bgp::Family::Ipv6Uc, accept_v6);
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
                                    let peer = peers.get_mut(&addr).unwrap();
                                    peer.uptime = SystemTime::now();

                                    source = Arc::new(Source {
                                        local_addr: local_addr,
                                        local_as: peer.local_as,
                                        address: addr,
                                        ibgp: peer.local_as == peer.remote_as,
                                        state: bgp::State::Established,
                                    });
                                }

                                delay.reset(
                                    Instant::now() + Duration::from_secs(keepalive_interval as u64),
                                );
                                let mut v = Vec::new();
                                {
                                    let g = global.lock().await;
                                    let mut t = table.lock().await;
                                    let (tx, _) = t.active_peers.remove(&addr).unwrap();
                                    t.active_peers.insert(addr, (tx, source.clone()));

                                    for (_, tx) in t.bmp_sessions.iter_mut() {
                                        let p = g.peers.get(&addr).unwrap();
                                        let _ = tx.send(bmp::Message::PeerUpNotification(
                                        p.to_bmp_up(g.id, source.address)));
                                    }

                                    if t.disable_best_path_selection == false {
                                        for family in &session.families {
                                            if let Some(m) = t.master.get_mut(&family) {
                                                for route in m {
                                                    let u = TableUpdate::NewBest(
                                                        *route.0,
                                                        route.1.entry[0].nexthop,
                                                        route.1.entry[0].attrs.clone(),
                                                        source.clone(),
                                                    );
                                                    v.push(u);
                                                }
                                            }
                                        }
                                    }
                                }
                                if session.send_update(source.clone(), v).await.is_err() {
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
        }
    }

    println!("disconnected {}", addr);
    let g = &mut global.lock().await;
    let _ = g
        .server_event_tx
        .send(SrvEvent::Disconnected(DisconnectedProto::Bgp(source)));
}

async fn handle_bmp_session(
    global: Arc<Mutex<Global>>,
    rx: &mut Receiver<bmp::Message>,
    stream: TcpStream,
    sockaddr: SocketAddr,
) {
    let mut lines = Framed::new(stream, BytesCodec::new());
    loop {
        tokio::select! {
            Some(msg) = rx.next().fuse() => {
                match msg.to_bytes() {
                    Ok(buf) => {
                        if lines.get_mut().write_all(&buf).await.is_err() {
                            break;
                        }
                    }
                    Err(_) =>{
                        break;
                    }
                }
            }
            v = lines.next().fuse() => {
                if let Some(_)= v {
                } else {
                    break;
                }
            }
        }
    }
    println!("bmp connection is closed");
    let g = &mut global.lock().await;
    let _ = g
        .server_event_tx
        .send(SrvEvent::Disconnected(DisconnectedProto::Bmp(sockaddr)));
}
