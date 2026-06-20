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

use super::*;

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
            bfd_config: p.bfd.as_ref().and_then(|b| {
                if b.enabled {
                    Some(crate::bfd::BfdPeerConfig {
                        desired_min_tx_interval_us: b.desired_minimum_tx_interval,
                        required_min_rx_interval_us: b.required_minimum_receive,
                        detect_multiplier: b.detection_multiplier as u8,
                        port: b.port as u16,
                    })
                } else {
                    None
                }
            }),
        })
    }
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

pub(super) struct GrpcService {
    init: Arc<tokio::sync::Notify>,
    policy_assignment_sem: tokio::sync::Semaphore,
    active_conn_tx: mpsc::UnboundedSender<TcpStream>,
    pub(super) global: GlobalHandle,
    pub(super) tables: TableHandle,
    path_uuid_map: tokio::sync::Mutex<FnvHashMap<uuid::Uuid, (Family, Vec<packet::PathNlri>)>>,
}

impl GrpcService {
    pub(super) fn new(
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
        let net = convert::net_from_api(path.nlri.ok_or(Error::EmptyArgument)?, family)
            .map_err(|_| tonic::Status::new(tonic::Code::InvalidArgument, "prefix is invalid"))?;
        let mut attr = Vec::new();
        let mut nexthop = None;
        for a in path.pattrs {
            let a = convert::attr_from_api(a).map_err(|_| {
                tonic::Status::new(tonic::Code::InvalidArgument, "invalid attribute")
            })?;
            match a.code() {
                bgp::Attribute::MP_REACH => {
                    // MP_REACH binary: [AFI:2][SAFI:1][NH_LEN:1][nexthop:NH_LEN][reserved:1][NLRI...]
                    // Extract just the nexthop.
                    let nh_len = a.binary().and_then(|b| b.get(3).copied()).unwrap_or(1) as usize;
                    nexthop = a.binary().and_then(|b| {
                        let len = *b.get(3)? as usize;
                        if b.len() < 5 + len {
                            return None;
                        }
                        bgp::Nexthop::from_bytes(&b[4..4 + len])
                    });
                    // Flowspec carries no nexthop (RFC 8955 §4): nexthop_len=0 is valid.
                    let flowspec_no_nexthop = nh_len == 0
                        && matches!(
                            family,
                            Family::IPV4_FLOWSPEC
                                | Family::IPV6_FLOWSPEC
                                | Family::IPV4_FLOWSPEC_VPN
                                | Family::IPV6_FLOWSPEC_VPN
                        );
                    if nexthop.is_none() && !flowspec_no_nexthop {
                        return Err(tonic::Status::new(
                            tonic::Code::InvalidArgument,
                            "malformed MP_REACH nexthop",
                        ));
                    }
                }
                bgp::Attribute::NEXTHOP => {
                    nexthop = a.binary().and_then(|b| bgp::Nexthop::from_bytes(b));
                }
                // RR attributes are added on reflection and must not be set by operators.
                // MP_UNREACH has no meaning in an add_path request.
                bgp::Attribute::ORIGINATOR_ID
                | bgp::Attribute::CLUSTER_LIST
                | bgp::Attribute::MP_UNREACH => {}
                _ => attr.push(a),
            }
        }
        if !attr.iter().any(|a| a.code() == bgp::Attribute::ORIGIN) {
            attr.push(bgp::Attribute::new_with_value(bgp::Attribute::ORIGIN, 0).unwrap());
        }
        if !attr.iter().any(|a| a.code() == bgp::Attribute::AS_PATH) {
            attr.push(bgp::Attribute::empty_as_path());
        }
        let attrs = Some(Arc::new(attr));
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
        let cease =
            bgp::Message::Notification(rustybgp_packet::Notification::CeasePeerDeconfigured);

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
        global.kernel_service.take();
        self.tables.kernel_handle.store(None);
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
                            rustybgp_packet::Notification::CeasePeerDeconfigured,
                        )),
                        true,
                    );
                }
                if p.config.password.is_some() {
                    for fd in &global.listen_sockets {
                        auth::set_md5sig(*fd, &peer_addr, "");
                    }
                }
                if let Some(bfd) = &global.bfd_handle {
                    bfd.remove_peer(peer_addr);
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
        let all_stats = self.tables.collect_peer_stats(&addrs);
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
                        rustybgp_packet::Notification::CeasePeerDeconfigured,
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
                    rustybgp_packet::Notification::CeasePeerDeconfigured,
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
            self.tables.soft_reset_in(peer_addr);
        }
        if do_out {
            self.tables.soft_reset_out(peer_addr);
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
        let subscription = self.tables.subscribe_live();
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
            tables2.unsubscribe(sub_id);
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
        let inner = request.into_inner();
        let table_type =
            api::TableType::try_from(inner.table_type).unwrap_or(api::TableType::Global);
        let (mut family, nets, attrs, nexthop) =
            self.local_path(inner.path.ok_or(Error::EmptyArgument)?)?;
        let mut insert_nets = nets.clone();
        let mut insert_attrs = attrs;
        if table_type == api::TableType::Vrf {
            let vrf_id = inner.vrf_id;
            if vrf_id.is_empty() {
                return Err(Error::InvalidArgument(
                    "vrf_id is required for VRF table type".to_string(),
                )
                .into());
            }
            let vrf = self
                .tables
                .list_vrfs(Some(&vrf_id))
                .into_iter()
                .next()
                .ok_or_else(|| tonic::Status::not_found(format!("VRF '{}' not found", vrf_id)))?;
            let (vpn_family, vpn_nets, vpn_attrs) =
                vrf_export_path(family, insert_nets, insert_attrs, &vrf)?;
            family = vpn_family;
            insert_nets = vpn_nets;
            insert_attrs = vpn_attrs;
        }
        let map_nets = insert_nets.clone();
        let timestamp = std::time::SystemTime::now();
        let source = table::Source::local();
        if let Some(attrs) = insert_attrs {
            for net in insert_nets {
                self.tables.insert_route(
                    source.clone(),
                    family,
                    net,
                    nexthop,
                    attrs.clone(),
                    None,
                    timestamp,
                );
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
                .remove_route(source.clone(), family, net, None, timestamp);
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

        let query = if let Ok(t) = api::TableType::try_from(request.table_type) {
            match t {
                api::TableType::Unspecified => {
                    return Err(tonic::Status::new(
                        tonic::Code::InvalidArgument,
                        "table type unspecified",
                    ));
                }
                api::TableType::Global => table::TableQuery::Global,
                api::TableType::Local => {
                    if request.name.is_empty() {
                        table::TableQuery::Global
                    } else {
                        let peer_addr = IpAddr::from_str(&request.name).map_err(|_| {
                            tonic::Status::new(
                                tonic::Code::InvalidArgument,
                                "invalid neighbor name",
                            )
                        })?;
                        let global = self.global.read().await;
                        let peer = global.peers.get(&peer_addr).ok_or_else(|| {
                            tonic::Status::not_found(format!("neighbor {} not found", peer_addr))
                        })?;
                        if !peer.config.route_server_client {
                            return Err(tonic::Status::new(
                                tonic::Code::InvalidArgument,
                                format!("neighbor {} does not have local rib", peer_addr),
                            ));
                        }
                        table::TableQuery::RsLocal(peer_addr)
                    }
                }
                api::TableType::Vrf => {
                    let vrf_name = request.name.clone();
                    if vrf_name.is_empty() {
                        return Err(tonic::Status::new(
                            tonic::Code::InvalidArgument,
                            "name (vrf name) is required",
                        ));
                    }
                    if !matches!(family, Family::IPV4 | Family::IPV6) {
                        return Err(tonic::Status::new(
                            tonic::Code::InvalidArgument,
                            format!("unsupported VRF family: {:?}", family),
                        ));
                    }
                    let entries = self
                        .tables
                        .collect_vrf_paths(&vrf_name, family, prefixes, enable_filtered)
                        .ok_or_else(|| {
                            tonic::Status::not_found(format!("VRF '{}' not found", vrf_name))
                        })?;
                    let (tx, rx) = mpsc::channel(1024);
                    tokio::spawn(async move {
                        for d in entries {
                            let r = api::ListPathResponse {
                                destination: Some(convert::destination_to_api(d, family, &binary)),
                            };
                            if tx.send(Ok(r)).await.is_err() {
                                break;
                            }
                        }
                    });
                    return Ok(tonic::Response::new(Box::pin(
                        tokio_stream::wrappers::ReceiverStream::new(rx),
                    )));
                }
                api::TableType::AdjIn => IpAddr::from_str(&request.name)
                    .map(table::TableQuery::AdjIn)
                    .map_err(|_| {
                        tonic::Status::new(tonic::Code::InvalidArgument, "invalid neighbor name")
                    })?,
                api::TableType::AdjOut => {
                    let peer_addr = IpAddr::from_str(&request.name).map_err(|_| {
                        tonic::Status::new(tonic::Code::InvalidArgument, "invalid neighbor name")
                    })?;
                    let (export_ctx, cluster_id, effective_max) = {
                        let global = self.global.read().await;
                        global
                            .peers
                            .get(&peer_addr)
                            .map(|p| {
                                (
                                    p.adj_out_export_ctx(&global),
                                    p.adj_out_cluster_id(&global),
                                    p.adj_out_effective_max(family),
                                )
                            })
                            .ok_or_else(|| {
                                tonic::Status::new(
                                    tonic::Code::NotFound,
                                    format!("neighbor {} not found", peer_addr),
                                )
                            })?
                    };
                    let Some(effective_max) = effective_max else {
                        let (tx, rx) = mpsc::channel(1);
                        drop(tx);
                        return Ok(tonic::Response::new(Box::pin(
                            tokio_stream::wrappers::ReceiverStream::new(rx),
                        )));
                    };
                    let export_policy = self.tables.export_policy.load_full();
                    let changes = self.tables.collect_loc_rib_paths(family);
                    let rpki = self.tables.rpki.read().unwrap();
                    let mut sink = AdjOutSink::default();
                    let mut export_map = ExportMap::new();
                    for change in changes {
                        process_nlri_change(
                            &change,
                            effective_max,
                            peer_addr,
                            &mut export_map,
                            &mut sink,
                            &export_ctx,
                            export_policy.as_deref(),
                            cluster_id,
                            Some(&rpki),
                        );
                    }
                    let destinations = sink.destinations;
                    let mut path_count = 0u64;
                    let v: Vec<_> = destinations
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
                    return Ok(tonic::Response::new(Box::pin(
                        tokio_stream::wrappers::ReceiverStream::new(rx),
                    )));
                }
            }
        } else {
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "invalid table type",
            ));
        };
        let mut path_count = 0u64;
        let v: Vec<_> = self
            .tables
            .collect_paths(query, family, prefixes, enable_filtered)
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
                        self.tables.insert_route(
                            source.clone(),
                            family,
                            net,
                            nexthop,
                            attrs.clone(),
                            None,
                            timestamp,
                        );
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
        let info = self.tables.table_state(family);
        Ok(tonic::Response::new(convert::routing_table_state_to_api(
            info,
        )))
    }
    async fn add_vrf(
        &self,
        request: tonic::Request<api::AddVrfRequest>,
    ) -> Result<tonic::Response<api::AddVrfResponse>, tonic::Status> {
        self.is_available(true).await?;
        let vrf = request.into_inner().vrf.ok_or(Error::EmptyArgument)?;
        let name = vrf.name.clone();
        if name.is_empty() {
            return Err(Error::InvalidArgument("vrf name is empty".to_string()).into());
        }
        let rd = convert::rd_from_api(
            vrf.rd
                .as_ref()
                .ok_or_else(|| Error::InvalidArgument("missing rd".to_string()))?,
        )?;
        let import_rt = vrf
            .import_rt
            .iter()
            .map(convert::rt_from_api)
            .collect::<Result<std::collections::HashSet<_>, _>>()?;
        let export_rt = vrf
            .export_rt
            .iter()
            .map(convert::rt_from_api)
            .collect::<Result<Vec<_>, _>>()?;
        self.tables
            .add_vrf(name, rd, import_rt, export_rt, vrf.id)
            .map_err(Error::Table)?;
        Ok(tonic::Response::new(api::AddVrfResponse {}))
    }

    async fn delete_vrf(
        &self,
        request: tonic::Request<api::DeleteVrfRequest>,
    ) -> Result<tonic::Response<api::DeleteVrfResponse>, tonic::Status> {
        self.is_available(true).await?;
        let name = request.into_inner().name;
        if name.is_empty() {
            return Err(Error::InvalidArgument("vrf name is empty".to_string()).into());
        }
        self.tables.delete_vrf(&name).map_err(Error::Table)?;
        Ok(tonic::Response::new(api::DeleteVrfResponse {}))
    }

    type ListVrfStream = Pin<
        Box<dyn Stream<Item = Result<api::ListVrfResponse, tonic::Status>> + Send + Sync + 'static>,
    >;

    async fn list_vrf(
        &self,
        request: tonic::Request<api::ListVrfRequest>,
    ) -> Result<tonic::Response<Self::ListVrfStream>, tonic::Status> {
        self.is_available(false).await?;
        let name_filter = request.into_inner().name;
        let filter = if name_filter.is_empty() {
            None
        } else {
            Some(name_filter.as_str())
        };
        let vrfs = self.tables.list_vrfs(filter);
        let responses: Vec<_> = vrfs
            .iter()
            .map(|v| {
                Ok(api::ListVrfResponse {
                    vrf: Some(convert::vrf_to_api(v)),
                })
            })
            .collect();
        let (tx, rx) = mpsc::channel(32);
        tokio::spawn(async move {
            for r in responses {
                if tx.send(r).await.is_err() {
                    break;
                }
            }
        });
        Ok(tonic::Response::new(Box::pin(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        )))
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
        self.global
            .write()
            .await
            .add_policy_assignment(self.tables.clone(), request)?;
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
            let s = self.tables.rpki_state(addr);
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
        self.tables.rpki_drop_all(Arc::new(addr));
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
        request: tonic::Request<api::EnableZebraRequest>,
    ) -> Result<tonic::Response<api::EnableZebraResponse>, tonic::Status> {
        if self.tables.kernel_handle.load().is_some() {
            return Ok(tonic::Response::new(api::EnableZebraResponse {}));
        }
        let request = request.into_inner();
        let redistribute: Vec<kernel::Protocol> = request
            .route_types
            .iter()
            .filter_map(|s| kernel::route_type_to_protocol(s))
            .collect();
        let mut global = self.global.write().await;
        let event_tx = global.kernel_event_tx.clone();
        let (service, handle) =
            kernel::KernelService::start(redistribute, event_tx).map_err(|e| {
                tonic::Status::internal(format!(
                    "failed to enable kernel route integration: {:?}",
                    e
                ))
            })?;
        global.kernel_service = Some(service);
        drop(global);
        self.tables.kernel_handle.store(Some(Arc::new(handle)));
        log::info!("kernel route integration enabled");
        Ok(tonic::Response::new(api::EnableZebraResponse {}))
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
