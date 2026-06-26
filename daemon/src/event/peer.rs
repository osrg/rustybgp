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

use std::convert::TryFrom;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;

use fnv::FnvHashMap;

use crate::config;
use crate::convert;
use rustybgp_packet::{self as packet, Family};

use super::*;

/// Maximum number of Add-Path paths to advertise per prefix (send_max).
/// Matches the u8 upper bound used in the config file representation.
/// RFC 7911 imposes no limit; this matches FRR's uint16 range in practice
/// and is well above any realistic deployment need.
pub(crate) const ADDPATH_SEND_MAX_LIMIT: usize = u8::MAX as usize;

/// Static GR configuration for a single peer, set at peer creation.
/// `None` in `PeerConfig::graceful_restart` means GR is disabled for this peer.
/// Cloned into capability negotiation at each session open.
#[derive(Clone)]
pub(crate) struct GrPeerConfig {
    /// Restart Time advertised in our OPEN (12-bit, max 4095 s).
    pub(crate) restart_time: u16,
    /// Whether to set the N-bit (RFC 8538): GR applies to NOTIFICATION and Hold Timer expiry.
    pub(crate) notification_enabled: bool,
    /// Families included in the GR capability (non-empty by construction).
    pub(crate) families: Vec<Family>,
}

/// Static LLGR configuration for a single peer (RFC 9494), set at peer creation.
/// `None` in `PeerConfig::llgr` means LLGR is disabled for this peer.
#[derive(Clone)]
pub(crate) struct LlgrPeerConfig {
    /// Per-family LLGR stale times advertised in our OPEN (24-bit, max ~16 million seconds).
    /// Only families with a non-zero stale time are included; non-empty by construction.
    pub(crate) families: Vec<(Family, u32)>,
}

/// RFC 4456 Route Reflector configuration for a single peer.
#[derive(Clone, Default)]
pub(crate) struct RouteReflectorConfig {
    pub(crate) route_reflector_client: bool,
    /// Per-peer cluster ID; None means fall back to the local router-id.
    pub(crate) route_reflector_cluster_id: Option<Ipv4Addr>,
}

/// Static per-peer configuration.  Set at peer creation (via `PeerParams::build`)
/// and immutable for the lifetime of the peer.  Cloned into `PeerSession` at
/// session start so the session task can access it without the global lock.
#[derive(Clone)]
pub(crate) struct PeerConfig {
    pub(crate) remote_addr: IpAddr,
    pub(crate) remote_port: u16,
    /// Expected AS number from configuration; 0 means "accept any".
    /// The actual negotiated ASN lives in PeerState.remote_asn (session-scoped).
    pub(crate) expected_remote_asn: u32,
    pub(crate) local_asn: u32,
    pub(crate) passive: bool,
    pub(crate) delete_on_disconnected: bool,
    pub(crate) holdtime: u64,
    pub(crate) connect_retry_time: u64,
    pub(crate) local_cap: Vec<packet::Capability>,
    pub(crate) route_server_client: bool,
    pub(crate) route_reflector: RouteReflectorConfig,
    /// Snapshot of the global router-id taken at peer creation.
    /// Immutable for the lifetime of the peer; used for RR ORIGINATOR_ID loop
    /// detection without holding the global lock.
    pub(crate) local_router_id: Ipv4Addr,
    pub(crate) multihop_ttl: Option<u8>,
    /// GTSM minimum TTL (RFC 5082); None = GTSM disabled.
    /// When set, outgoing TTL is 255 and incoming packets below this value are dropped.
    /// Takes priority over multihop_ttl when both are configured.
    pub(crate) ttl_security: Option<u8>,
    pub(crate) password: Option<String>,
    /// Per-family prefix limits from config.
    /// Used to initialize PeerSession::prefix_counters in accept_connection().
    pub(crate) prefix_limits: FnvHashMap<Family, u32>,
    /// GR helper config; None = GR disabled.
    pub(crate) graceful_restart: Option<GrPeerConfig>,
    /// LLGR helper config; None = LLGR disabled.
    // Read in Step 6 (export) to attach LLGR_STALE community.
    #[allow(dead_code)]
    pub(crate) llgr: Option<LlgrPeerConfig>,
    /// Interface name for unnumbered BGP (RFC 7938).
    /// When set, the TCP connection uses the link-local address discovered via
    /// NDP at peer-add time, with the interface index as the socket scope ID.
    pub(crate) neighbor_interface: Option<String>,
}

/// Plain-struct replacement for the old PeerBuilder.
///
/// Both TryFrom<&api::Peer> and TryFrom<&config::Neighbor> construct this as
/// an exhaustive struct literal so that adding a new field causes a compile
/// error at every construction site.
pub(crate) struct PeerParams {
    pub(crate) remote_addr: IpAddr,
    pub(crate) remote_port: u16,
    pub(crate) expected_remote_asn: u32,
    pub(crate) local_asn: u32,
    pub(crate) passive: bool,
    pub(crate) rs_client: bool,
    pub(crate) route_reflector: RouteReflectorConfig,
    pub(crate) delete_on_disconnected: bool,
    pub(crate) admin_down: bool,
    pub(crate) state: SessionState,
    pub(crate) holdtime: u64,
    pub(crate) connect_retry_time: u64,
    pub(crate) multihop_ttl: Option<u8>,
    pub(crate) ttl_security: Option<u8>,
    pub(crate) password: Option<String>,
    /// Per-family add-path mode (RFC 7911 2-bit flags); mode 0 means plain MP.
    pub(crate) families: FnvHashMap<Family, u8>,
    pub(crate) send_max: FnvHashMap<Family, usize>,
    pub(crate) prefix_limits: FnvHashMap<Family, u32>,
    pub(crate) graceful_restart: Option<GrPeerConfig>,
    pub(crate) llgr: Option<LlgrPeerConfig>,
    pub(crate) bfd_config: Option<crate::bfd::BfdPeerConfig>,
    /// Interface name for unnumbered BGP (RFC 7938); None for normal peers.
    pub(crate) neighbor_interface: Option<String>,
}

impl PeerParams {
    pub(crate) const DEFAULT_HOLD_TIME: u64 = 180;
    pub(crate) const DEFAULT_CONNECT_RETRY_TIME: u64 = 3;

    /// Derive the local capability list from peer configuration.
    ///
    /// Separated from `build()` so the capability logic can be tested
    /// independently of struct construction.
    pub(crate) fn build_local_cap(
        remote_addr: IpAddr,
        local_asn: u32,
        families: &FnvHashMap<Family, u8>,
        graceful_restart: Option<&GrPeerConfig>,
        llgr: Option<&LlgrPeerConfig>,
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
            // with IPv4 address family configured.
            // SR Policy (SAFI 73) is excluded: its nexthop is always the
            // originator address in the same AFI, not an IPv6-mapped address.
            if matches!(remote_addr, IpAddr::V6(_)) {
                let enh_families: Vec<(Family, u16)> = families
                    .keys()
                    .filter(|f| f.afi() == Family::AFI_IP && **f != Family::IPV4_SRPOLICY)
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
        if let Some(llgr) = llgr {
            // F-bit (0x80): forwarding preserved during LLGR stale period.
            // We always advertise F=0 (forwarding may not be preserved).
            local_cap.push(packet::Capability::LongLivedGracefulRestart(
                llgr.families.iter().map(|(f, t)| (*f, 0u8, *t)).collect(),
            ));
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
        // Always advertise RFC 8654 Extended Message support.
        local_cap.push(packet::Capability::ExtendedMessage);
        local_cap
    }

    /// Apply peer group settings as fallback for fields not explicitly set on
    /// this peer.  Called after constructing `PeerParams` from a config or API
    /// request when the peer belongs to a named peer group.
    pub(crate) fn apply_peer_group(&mut self, pg: &PeerGroup) {
        if self.expected_remote_asn == 0 && pg.as_number != 0 {
            self.expected_remote_asn = pg.as_number;
        }
        if self.local_asn == 0 && pg.local_asn != 0 {
            self.local_asn = pg.local_asn;
        }
        if self.holdtime == Self::DEFAULT_HOLD_TIME
            && let Some(h) = pg.holdtime
        {
            self.holdtime = h;
        }
        if self.connect_retry_time == Self::DEFAULT_CONNECT_RETRY_TIME
            && let Some(t) = pg.connect_retry_time
        {
            self.connect_retry_time = t;
        }
        if self.password.is_none() {
            self.password = pg.auth_password.clone();
        }
        if self.multihop_ttl.is_none() {
            self.multihop_ttl = pg.multihop_ttl;
        }
        if self.ttl_security.is_none() {
            self.ttl_security = pg.ttl_security;
        }
        if self.families.is_empty() {
            self.families = pg.families.clone();
            self.send_max = pg.send_max.clone();
        }
        if self.graceful_restart.is_none() {
            self.graceful_restart = pg.graceful_restart.clone();
        }
        if self.llgr.is_none() {
            self.llgr = pg.llgr.clone();
        }
        if !self.passive && pg.passive {
            self.passive = true;
        }
        if !self.rs_client && pg.route_server_client {
            self.rs_client = true;
        }
        if !self.route_reflector.route_reflector_client && pg.route_reflector.route_reflector_client
        {
            self.route_reflector = pg.route_reflector.clone();
        }
    }

    /// Build a `Peer` from these params.
    ///
    /// `local_router_id` is needed to construct `PeerFsm` for collision
    /// detection; it is only known once `Global::router_id` is set, so callers
    /// always go through `Global::add_peer` rather than calling this directly.
    pub(crate) fn build(mut self, local_router_id: u32, global_asn: u32) -> Peer {
        if self.local_asn == 0 {
            self.local_asn = global_asn;
        }

        let local_cap = Self::build_local_cap(
            self.remote_addr,
            self.local_asn,
            &self.families,
            self.graceful_restart.as_ref(),
            self.llgr.as_ref(),
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
                llgr: self.llgr,
                neighbor_interface: self.neighbor_interface,
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
                llgr_family_timers: FnvHashMap::default(),
                rtc_state: crate::rtc::RtcState::new(),
                rtc_eor_timer: None,
            })),
        }
    }
}

/// Parse an afi-safis slice from YAML config into (families, send_max) maps.
///
/// Returns a map of Family -> add-path mode (RFC 7911 2-bit: bit0=RX, bit1=TX)
/// and a separate send_max map for families where add-path TX is configured.
pub(crate) fn parse_afi_safis(
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

pub(crate) fn parse_gr_config(
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

pub(crate) fn parse_llgr_config(afi_safis: &[config::AfiSafi]) -> Option<LlgrPeerConfig> {
    const DEFAULT_STALE_TIME: u32 = 600;
    let families: Vec<(Family, u32)> = afi_safis
        .iter()
        .filter(|a| {
            a.long_lived_graceful_restart
                .as_ref()
                .and_then(|llgr| llgr.config.as_ref())
                .and_then(|c| c.enabled)
                .unwrap_or(false)
        })
        .filter_map(|a| {
            let family =
                convert::family_from_config(a.config.as_ref()?.afi_safi_name.as_ref()?).ok()?;
            let stale_time = a
                .long_lived_graceful_restart
                .as_ref()
                .and_then(|llgr| llgr.config.as_ref())
                .and_then(|c| c.restart_time)
                .unwrap_or(DEFAULT_STALE_TIME);
            Some((family, stale_time))
        })
        .collect();
    if families.is_empty() {
        return None;
    }
    Some(LlgrPeerConfig { families })
}

impl TryFrom<&config::Neighbor> for PeerParams {
    type Error = String;

    fn try_from(n: &config::Neighbor) -> Result<PeerParams, Self::Error> {
        let c = n.config.as_ref().ok_or("missing neighbor config")?;
        let afi_safis = n.afi_safis.as_deref().unwrap_or_default();

        // Unnumbered BGP: neighbor-interface replaces neighbor-address.
        // The actual link-local address is resolved via NDP asynchronously
        // in the config loading loop after try_from returns.
        let neighbor_interface = c.neighbor_interface.clone();
        let (remote_addr, peer_as) = if neighbor_interface.is_some() {
            (&IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0u32)
        } else {
            let addr = c
                .neighbor_address
                .as_ref()
                .ok_or("missing neighbor address")?;
            // peer_as may be absent when the peer belongs to a peer group;
            // apply_peer_group() fills it in from the group's as_number.
            let asn = if c.peer_group.is_some() {
                c.peer_as.unwrap_or(0)
            } else {
                c.peer_as.ok_or("missing peer-as")?
            };
            (addr, asn)
        };

        let transport_config = n.transport.as_ref().and_then(|t| t.config.as_ref());
        let timer_config = n.timers.as_ref().and_then(|t| t.config.as_ref());

        let (families, send_max) = parse_afi_safis(afi_safis);
        let graceful_restart = parse_gr_config(
            afi_safis,
            n.graceful_restart
                .as_ref()
                .and_then(|gr| gr.config.as_ref()),
        );
        let llgr = parse_llgr_config(afi_safis);

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
            llgr,
            bfd_config: n
                .bfd
                .as_ref()
                .and_then(|b| b.config.as_ref())
                .and_then(|bc| {
                    if bc.enabled.unwrap_or(false) {
                        Some(crate::bfd::BfdPeerConfig {
                            desired_min_tx_interval_us: bc.desired_minimum_tx_interval.unwrap_or(0),
                            required_min_rx_interval_us: bc.required_minimum_receive.unwrap_or(0),
                            detect_multiplier: bc.detection_multiplier.unwrap_or(0),
                            port: 0,
                        })
                    } else {
                        None
                    }
                }),
            neighbor_interface,
        })
    }
}

pub(crate) struct DynamicPeer {
    pub(crate) prefix: packet::IpNet,
}

pub(crate) struct PeerGroup {
    pub(crate) as_number: u32,
    pub(crate) dynamic_peers: Vec<DynamicPeer>,
    pub(crate) route_server_client: bool,
    pub(crate) holdtime: Option<u64>,
    pub(crate) local_asn: u32,
    pub(crate) passive: bool,
    pub(crate) route_reflector: RouteReflectorConfig,
    pub(crate) multihop_ttl: Option<u8>,
    pub(crate) ttl_security: Option<u8>,
    pub(crate) auth_password: Option<String>,
    pub(crate) connect_retry_time: Option<u64>,
    pub(crate) families: FnvHashMap<Family, u8>,
    pub(crate) send_max: FnvHashMap<Family, usize>,
    pub(crate) graceful_restart: Option<GrPeerConfig>,
    pub(crate) llgr: Option<LlgrPeerConfig>,
}

impl From<&config::PeerGroup> for PeerGroup {
    fn from(pg: &config::PeerGroup) -> Self {
        let timer_config = pg.timers.as_ref().and_then(|t| t.config.as_ref());
        let afi_safis = pg.afi_safis.as_deref().unwrap_or_default();
        let (families, send_max) = parse_afi_safis(afi_safis);
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
            graceful_restart: parse_gr_config(
                afi_safis,
                pg.graceful_restart
                    .as_ref()
                    .and_then(|gr| gr.config.as_ref()),
            ),
            llgr: parse_llgr_config(afi_safis),
        }
    }
}
