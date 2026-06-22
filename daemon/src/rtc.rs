// Copyright (C) 2024 The RustyBGP Authors.
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

//! RTC (Route Target Membership, RFC 4684) per-peer state machine.
//!
//! Pure logic -- no async, no I/O.  All types process events and return
//! actions that the driver translates into real I/O and table mutations.
//!
//! # State diagram
//!
//!   Inactive
//!     + SessionEstablished(families containing RTC)
//!         suspended = VPN families from negotiated set
//!         output: [StartTimer(60s)]
//!         --> AwaitingEor { suspended }
//!     + SessionEstablished(families NOT containing RTC)
//!         --> Inactive  (no-op)
//!
//!   AwaitingEor { suspended }  (VPN export held back)
//!     + EorReceived
//!         output: [StopTimer, ExportFamilies(suspended)]
//!         --> Active
//!     + TimerExpired
//!         output: [ExportFamilies(suspended)]
//!         --> Active
//!     + SessionDropped
//!         output: [StopTimer]
//!         --> Inactive
//!
//!   Active  (RT filter in effect; caller queries RIB[RTC] for filter)
//!     + SessionDropped
//!         --> Inactive
//!
//!   All other (state, input) combinations are no-ops.
//!
//! # GR interaction
//!
//! When a session drops with GR active for RTC, the caller does NOT send
//! SessionDropped.  The state stays Active and the caller uses the stale
//! RTC routes retained in the RIB (via GrState) as the outbound VPN filter.
//! SessionDropped is only sent on a complete drop (no GR, or GR timed out).

use rustybgp_packet::bgp::{Attribute, Family, Nlri};
use rustybgp_packet::rtc::MatchType;
use rustybgp_table::SoftResetPath;
use std::collections::HashSet;
use std::time::Duration;

/// Upper bound on how long VPN advertisement may be delayed waiting for
/// an RTC End-of-RIB marker (RFC 4684 §6 default: 60 seconds).
pub(crate) const EOR_TIMER: Duration = Duration::from_secs(60);

/// Events fed into the RTC state machine.
pub(crate) enum RtcInput {
    /// A BGP session established with these negotiated families.
    /// The machine activates only when RTC (AFI=1/SAFI=132) is present.
    SessionEstablished { negotiated_families: Vec<Family> },
    /// End-of-RIB received for the RTC address family (AFI=1/SAFI=132).
    EorReceived,
    /// The 60-second EOR timer fired before EOR was received.
    TimerExpired,
    /// Complete session drop: no GR active, or GR recovery timed out.
    SessionDropped,
    /// Session dropped and GR helper mode has started for this peer.
    /// The machine keeps the RT filter active (if any) so stale RTC routes
    /// in the RIB can continue to gate VPN advertisement during recovery.
    /// If EOR had not yet arrived the machine resets to Inactive instead,
    /// since no confirmed RT interests are available to form a filter.
    GrHelperStarted,
}

/// Actions the driver should perform in response to an RTC input.
pub(crate) enum RtcOutput {
    /// Start the EOR timer with the given duration.
    StartTimer(Duration),
    /// Cancel the EOR timer.
    StopTimer,
    /// The RT filter is now ready; export these VPN families to the peer.
    /// The driver performs a full RIB walk for each family and sends
    /// all routes whose RTs match the peer's current RTC filter.
    ExportFamilies(Vec<Family>),
}

pub(crate) fn is_vpn_family(f: Family) -> bool {
    matches!(
        f,
        Family::IPV4_VPN
            | Family::IPV6_VPN
            | Family::L2VPN_EVPN
            | Family::IPV4_FLOWSPEC_VPN
            | Family::IPV6_FLOWSPEC_VPN
    )
}

/// RT filter built from a peer's adj-in RTC paths (RFC 4684 §5).
/// Used to gate VPN route export once the peer's RT interests are known.
pub(crate) struct RtcFilter {
    accept_all: bool,
    rts: HashSet<[u8; 8]>,
}

impl RtcFilter {
    /// Build a filter from the peer's current adj-in RTC paths.
    ///
    /// Stale-aware: `paths` must include both stale and fresh entries so that
    /// GR-reconnect state can be detected.  If any stale path is present, the
    /// peer has reconnected under GR but has not yet sent an RTC EOR in the new
    /// session.  In that case only the stale (pre-disconnect) RT interests are
    /// used: fresh paths that have arrived before EOR represent partial,
    /// unconfirmed interests and must not yet gate VPN export.  Once the GR
    /// helper deletes the stale entries on RTC EOR reception, all remaining
    /// paths are fresh and this branch is not taken.
    pub(crate) fn from_paths(paths: &[SoftResetPath]) -> Self {
        let has_stale = paths.iter().any(|(_, _, _, _, src, _, _)| src.is_stale());
        let mut accept_all = false;
        let mut rts = HashSet::new();
        for (_, nlri, _, _, src, _, _) in paths {
            // Skip fresh paths during GR reconnect (before RTC EOR).
            if has_stale && !src.is_stale() {
                continue;
            }
            if let Nlri::Rtc(rtc) = nlri {
                match &rtc.match_type {
                    MatchType::Wildcard | MatchType::AsWildcard { .. } => {
                        accept_all = true;
                    }
                    MatchType::ExactMatch { route_target, .. } => {
                        rts.insert(*route_target);
                    }
                }
            }
        }
        Self { accept_all, rts }
    }

    /// Returns true when a VPN route with these attributes should be forwarded
    /// to the peer. A route is forwarded when any of its RT extended communities
    /// matches one of the peer's advertised RTs (or the peer sent a wildcard).
    pub(crate) fn allows(&self, attrs: &[Attribute]) -> bool {
        if self.accept_all {
            return true;
        }
        for attr in attrs {
            if attr.code() == Attribute::EXTENDED_COMMUNITY {
                let Some(data) = attr.binary() else {
                    continue;
                };
                for chunk in data.chunks_exact(8) {
                    let bytes: [u8; 8] = chunk.try_into().unwrap();
                    if self.rts.contains(&bytes) {
                        return true;
                    }
                }
            }
        }
        false
    }
}

fn vpn_families(families: &[Family]) -> Vec<Family> {
    families
        .iter()
        .copied()
        .filter(|f| is_vpn_family(*f))
        .collect()
}

enum Inner {
    Inactive,
    AwaitingEor { suspended: Vec<Family> },
    Active,
}

/// RTC per-peer state machine.
pub(crate) struct RtcState {
    state: Inner,
}

impl RtcState {
    pub(crate) fn new() -> Self {
        RtcState {
            state: Inner::Inactive,
        }
    }

    pub(crate) fn is_awaiting_eor(&self) -> bool {
        matches!(self.state, Inner::AwaitingEor { .. })
    }

    pub(crate) fn is_active(&self) -> bool {
        matches!(self.state, Inner::Active)
    }

    pub(crate) fn process(&mut self, input: RtcInput) -> Vec<RtcOutput> {
        let state = std::mem::replace(&mut self.state, Inner::Inactive);
        let (new_state, outputs) = match (state, input) {
            // New session: activate when RTC is among the negotiated families.
            (
                Inner::Inactive,
                RtcInput::SessionEstablished {
                    negotiated_families,
                },
            ) => {
                let suspended = vpn_families(&negotiated_families);
                if negotiated_families.contains(&Family::RTC) && !suspended.is_empty() {
                    (
                        Inner::AwaitingEor { suspended },
                        vec![RtcOutput::StartTimer(EOR_TIMER)],
                    )
                } else {
                    (Inner::Inactive, vec![])
                }
            }

            // EOR arrived before the timer: stop timer, enable filter, export.
            (Inner::AwaitingEor { suspended }, RtcInput::EorReceived) => (
                Inner::Active,
                vec![RtcOutput::StopTimer, RtcOutput::ExportFamilies(suspended)],
            ),

            // Timer fired before EOR: enable filter, export (no StopTimer needed).
            (Inner::AwaitingEor { suspended }, RtcInput::TimerExpired) => {
                (Inner::Active, vec![RtcOutput::ExportFamilies(suspended)])
            }

            // Complete drop while waiting for EOR: cancel timer, reset.
            (Inner::AwaitingEor { .. }, RtcInput::SessionDropped) => {
                (Inner::Inactive, vec![RtcOutput::StopTimer])
            }

            // Complete drop while filter was active: reset silently.
            (Inner::Active, RtcInput::SessionDropped) => (Inner::Inactive, vec![]),

            // GR helper started while filter was active: keep Active so stale
            // RTC routes continue to gate VPN advertisement during recovery.
            (Inner::Active, RtcInput::GrHelperStarted) => (Inner::Active, vec![]),

            // GR helper started while still waiting for EOR: no confirmed RT
            // interests exist, so reset to Inactive and cancel the timer.
            (Inner::AwaitingEor { .. }, RtcInput::GrHelperStarted) => {
                (Inner::Inactive, vec![RtcOutput::StopTimer])
            }

            // All other (state, input) combinations are no-ops.
            (state, _) => (state, vec![]),
        };
        self.state = new_state;
        outputs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rtc_only() -> Vec<Family> {
        vec![Family::RTC]
    }

    fn rtc_with_vpn() -> Vec<Family> {
        vec![Family::RTC, Family::IPV4_VPN, Family::IPV6_VPN]
    }

    fn no_rtc() -> Vec<Family> {
        vec![Family::IPV4, Family::IPV6]
    }

    fn establish(rtc: &mut RtcState, families: Vec<Family>) -> Vec<RtcOutput> {
        rtc.process(RtcInput::SessionEstablished {
            negotiated_families: families,
        })
    }

    // -------------------------------------------------------------------------
    // SessionEstablished
    // -------------------------------------------------------------------------

    #[test]
    fn established_with_rtc_only_stays_inactive() {
        // No VPN families to suspend: RTC alone does not activate the filter.
        let mut rtc = RtcState::new();
        let out = establish(&mut rtc, rtc_only());
        assert!(out.is_empty());
        assert!(!rtc.is_awaiting_eor());
        assert!(!rtc.is_active());
    }

    #[test]
    fn established_without_rtc_stays_inactive() {
        let mut rtc = RtcState::new();
        let out = establish(&mut rtc, no_rtc());
        assert!(out.is_empty());
        assert!(!rtc.is_awaiting_eor());
        assert!(!rtc.is_active());
    }

    #[test]
    fn established_with_rtc_and_vpn_suspends_vpn_families() {
        let mut rtc = RtcState::new();
        let out = establish(&mut rtc, rtc_with_vpn());
        assert_eq!(out.len(), 1);
        assert!(matches!(&out[0], RtcOutput::StartTimer(_)));
        assert!(rtc.is_awaiting_eor());
    }

    // -------------------------------------------------------------------------
    // EorReceived
    // -------------------------------------------------------------------------

    #[test]
    fn eor_received_stops_timer_and_exports() {
        let mut rtc = RtcState::new();
        establish(&mut rtc, rtc_with_vpn());

        let out = rtc.process(RtcInput::EorReceived);
        assert_eq!(out.len(), 2);
        assert!(matches!(&out[0], RtcOutput::StopTimer));
        assert!(matches!(&out[1], RtcOutput::ExportFamilies(f)
            if f.contains(&Family::IPV4_VPN) && f.contains(&Family::IPV6_VPN)));
        assert!(rtc.is_active());
    }

    #[test]
    fn eor_received_after_rtc_only_is_noop() {
        // RTC only (no VPN families) → Inactive; EOR is a no-op.
        let mut rtc = RtcState::new();
        establish(&mut rtc, rtc_only());
        assert!(!rtc.is_active());

        let out = rtc.process(RtcInput::EorReceived);
        assert!(out.is_empty());
        assert!(!rtc.is_active());
    }

    #[test]
    fn eor_received_in_inactive_is_noop() {
        let mut rtc = RtcState::new();
        let out = rtc.process(RtcInput::EorReceived);
        assert!(out.is_empty());
        assert!(!rtc.is_active());
    }

    #[test]
    fn eor_received_in_active_is_noop() {
        let mut rtc = RtcState::new();
        establish(&mut rtc, rtc_with_vpn());
        rtc.process(RtcInput::EorReceived);
        assert!(rtc.is_active());

        let out = rtc.process(RtcInput::EorReceived);
        assert!(out.is_empty());
        assert!(rtc.is_active());
    }

    // -------------------------------------------------------------------------
    // TimerExpired
    // -------------------------------------------------------------------------

    #[test]
    fn timer_expired_exports_without_stop_timer() {
        let mut rtc = RtcState::new();
        establish(&mut rtc, rtc_with_vpn());

        let out = rtc.process(RtcInput::TimerExpired);
        assert_eq!(out.len(), 1);
        assert!(matches!(&out[0], RtcOutput::ExportFamilies(f)
            if f.contains(&Family::IPV4_VPN) && f.contains(&Family::IPV6_VPN)));
        assert!(rtc.is_active());
    }

    #[test]
    fn timer_expired_in_inactive_is_noop() {
        let mut rtc = RtcState::new();
        let out = rtc.process(RtcInput::TimerExpired);
        assert!(out.is_empty());
    }

    #[test]
    fn timer_expired_in_active_is_noop() {
        let mut rtc = RtcState::new();
        establish(&mut rtc, rtc_with_vpn());
        rtc.process(RtcInput::EorReceived);
        assert!(rtc.is_active());

        let out = rtc.process(RtcInput::TimerExpired);
        assert!(out.is_empty());
        assert!(rtc.is_active());
    }

    // -------------------------------------------------------------------------
    // SessionDropped
    // -------------------------------------------------------------------------

    #[test]
    fn dropped_during_awaiting_eor_cancels_timer() {
        let mut rtc = RtcState::new();
        establish(&mut rtc, rtc_with_vpn());

        let out = rtc.process(RtcInput::SessionDropped);
        assert_eq!(out.len(), 1);
        assert!(matches!(&out[0], RtcOutput::StopTimer));
        assert!(!rtc.is_awaiting_eor());
        assert!(!rtc.is_active());
    }

    #[test]
    fn dropped_during_active_resets_silently() {
        let mut rtc = RtcState::new();
        establish(&mut rtc, rtc_with_vpn());
        rtc.process(RtcInput::EorReceived);
        assert!(rtc.is_active());

        let out = rtc.process(RtcInput::SessionDropped);
        assert!(out.is_empty());
        assert!(!rtc.is_active());
    }

    #[test]
    fn dropped_in_inactive_is_noop() {
        let mut rtc = RtcState::new();
        let out = rtc.process(RtcInput::SessionDropped);
        assert!(out.is_empty());
    }

    // -------------------------------------------------------------------------
    // Re-establish after drop
    // -------------------------------------------------------------------------

    #[test]
    fn re_establish_after_drop_restarts_correctly() {
        let mut rtc = RtcState::new();
        establish(&mut rtc, rtc_with_vpn());
        rtc.process(RtcInput::EorReceived);
        assert!(rtc.is_active());

        rtc.process(RtcInput::SessionDropped);
        assert!(!rtc.is_active());

        let out = establish(&mut rtc, rtc_with_vpn());
        assert_eq!(out.len(), 1);
        assert!(matches!(&out[0], RtcOutput::StartTimer(_)));
        assert!(rtc.is_awaiting_eor());
    }

    // -------------------------------------------------------------------------
    // GrHelperStarted
    // -------------------------------------------------------------------------

    #[test]
    fn gr_helper_started_in_active_keeps_active() {
        let mut rtc = RtcState::new();
        establish(&mut rtc, rtc_with_vpn());
        rtc.process(RtcInput::EorReceived);
        assert!(rtc.is_active());

        let out = rtc.process(RtcInput::GrHelperStarted);
        assert!(out.is_empty());
        assert!(rtc.is_active());
    }

    #[test]
    fn gr_helper_started_during_awaiting_eor_resets_to_inactive() {
        let mut rtc = RtcState::new();
        establish(&mut rtc, rtc_with_vpn());
        assert!(rtc.is_awaiting_eor());

        let out = rtc.process(RtcInput::GrHelperStarted);
        assert_eq!(out.len(), 1);
        assert!(matches!(&out[0], RtcOutput::StopTimer));
        assert!(!rtc.is_awaiting_eor());
        assert!(!rtc.is_active());
    }

    #[test]
    fn gr_helper_started_in_inactive_is_noop() {
        let mut rtc = RtcState::new();
        let out = rtc.process(RtcInput::GrHelperStarted);
        assert!(out.is_empty());
    }

    #[test]
    fn reconnect_after_gr_helper_from_awaiting_eor_restarts_eor_wait() {
        // AwaitingEor -> GrHelperStarted -> Inactive -> reconnect -> AwaitingEor
        let mut rtc = RtcState::new();
        establish(&mut rtc, rtc_with_vpn());
        assert!(rtc.is_awaiting_eor());

        rtc.process(RtcInput::GrHelperStarted);
        assert!(!rtc.is_awaiting_eor());
        assert!(!rtc.is_active());

        let out = establish(&mut rtc, rtc_with_vpn());
        assert_eq!(out.len(), 1);
        assert!(matches!(&out[0], RtcOutput::StartTimer(_)));
        assert!(rtc.is_awaiting_eor());
    }

    #[test]
    fn reconnect_after_gr_helper_from_active_stays_active() {
        // Active -> GrHelperStarted -> Active -> reconnect -> still Active (no-op)
        let mut rtc = RtcState::new();
        establish(&mut rtc, rtc_with_vpn());
        rtc.process(RtcInput::EorReceived);
        assert!(rtc.is_active());

        rtc.process(RtcInput::GrHelperStarted);
        assert!(rtc.is_active());

        // SessionEstablished in Active is a no-op: stale filter stays in effect.
        let out = establish(&mut rtc, rtc_with_vpn());
        assert!(out.is_empty());
        assert!(rtc.is_active());
    }

    // -------------------------------------------------------------------------
    // VPN family filtering
    // -------------------------------------------------------------------------

    #[test]
    fn only_vpn_families_are_suspended() {
        let mut rtc = RtcState::new();
        let families = vec![
            Family::RTC,
            Family::IPV4,
            Family::IPV6,
            Family::IPV4_VPN,
            Family::L2VPN_EVPN,
        ];
        establish(&mut rtc, families);

        let out = rtc.process(RtcInput::EorReceived);
        let exported = match &out[1] {
            RtcOutput::ExportFamilies(f) => f,
            _ => panic!("expected ExportFamilies"),
        };
        assert!(exported.contains(&Family::IPV4_VPN));
        assert!(exported.contains(&Family::L2VPN_EVPN));
        assert!(!exported.contains(&Family::IPV4));
        assert!(!exported.contains(&Family::IPV6));
        assert!(!exported.contains(&Family::RTC));
    }

    // --- RtcFilter tests ---

    use rustybgp_packet::bgp::Attribute;
    use rustybgp_table::SoftResetPath;
    use std::sync::Arc;
    use std::time::SystemTime;

    fn make_rtc_path(match_type: MatchType) -> SoftResetPath {
        let nlri = Nlri::Rtc(rustybgp_packet::rtc::RtcNlri { match_type });
        (
            Family::RTC,
            nlri,
            0,
            None,
            rustybgp_table::Source::local(),
            Arc::new(vec![]),
            SystemTime::UNIX_EPOCH,
        )
    }

    fn ext_community_attr(rts: &[[u8; 8]]) -> Attribute {
        let mut data = Vec::with_capacity(rts.len() * 8);
        for rt in rts {
            data.extend_from_slice(rt);
        }
        Attribute::new_with_bin(Attribute::EXTENDED_COMMUNITY, data).unwrap()
    }

    #[test]
    fn filter_empty_paths_allows_nothing() {
        let filter = RtcFilter::from_paths(&[]);
        let rt: [u8; 8] = [0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x64];
        let attrs = [ext_community_attr(&[rt])];
        assert!(!filter.allows(&attrs));
    }

    #[test]
    fn filter_wildcard_allows_any_rt() {
        let path = make_rtc_path(MatchType::Wildcard);
        let filter = RtcFilter::from_paths(&[path]);
        let rt: [u8; 8] = [0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x64];
        let attrs = [ext_community_attr(&[rt])];
        assert!(filter.allows(&attrs));
    }

    #[test]
    fn filter_as_wildcard_allows_any_rt() {
        let path = make_rtc_path(MatchType::AsWildcard { origin_as: 65001 });
        let filter = RtcFilter::from_paths(&[path]);
        let rt: [u8; 8] = [0x00, 0x02, 0xfd, 0xea, 0x00, 0x00, 0x00, 0x64];
        let attrs = [ext_community_attr(&[rt])];
        assert!(filter.allows(&attrs));
    }

    #[test]
    fn filter_exact_match_allows_matching_rt() {
        let rt: [u8; 8] = [0x00, 0x02, 0xfd, 0xe9, 0x00, 0x00, 0x00, 0x64];
        let path = make_rtc_path(MatchType::ExactMatch {
            origin_as: 65001,
            route_target: rt,
        });
        let filter = RtcFilter::from_paths(&[path]);
        let attrs = [ext_community_attr(&[rt])];
        assert!(filter.allows(&attrs));
    }

    #[test]
    fn filter_exact_match_rejects_different_rt() {
        let rt1: [u8; 8] = [0x00, 0x02, 0xfd, 0xe9, 0x00, 0x00, 0x00, 0x64];
        let rt2: [u8; 8] = [0x00, 0x02, 0xfd, 0xea, 0x00, 0x00, 0x00, 0x65];
        let path = make_rtc_path(MatchType::ExactMatch {
            origin_as: 65001,
            route_target: rt1,
        });
        let filter = RtcFilter::from_paths(&[path]);
        let attrs = [ext_community_attr(&[rt2])];
        assert!(!filter.allows(&attrs));
    }

    #[test]
    fn filter_no_ext_community_attr_is_rejected() {
        let rt: [u8; 8] = [0x00, 0x02, 0xfd, 0xe9, 0x00, 0x00, 0x00, 0x64];
        let path = make_rtc_path(MatchType::ExactMatch {
            origin_as: 65001,
            route_target: rt,
        });
        let filter = RtcFilter::from_paths(&[path]);
        assert!(!filter.allows(&[]));
    }

    fn make_stale_rtc_path(match_type: MatchType) -> SoftResetPath {
        use std::net::{IpAddr, Ipv4Addr};
        let nlri = Nlri::Rtc(rustybgp_packet::rtc::RtcNlri { match_type });
        // Use Source::new (not Source::local) to avoid mutating the global static.
        let src = Arc::new(rustybgp_table::Source::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            65001,
            65000,
            Ipv4Addr::new(192, 168, 1, 1),
            rustybgp_table::PeerRole::Ebgp,
        ));
        src.mark_stale();
        (
            Family::RTC,
            nlri,
            0,
            None,
            src,
            Arc::new(vec![]),
            SystemTime::UNIX_EPOCH,
        )
    }

    #[test]
    fn filter_uses_stale_paths_when_stale_present() {
        // GR reconnect: stale path (pre-disconnect RT) + fresh path (new RT, before EOR).
        // The filter must use only the stale path so that fresh RT interests, which have
        // not yet been confirmed by RTC EOR, do not prematurely gate VPN export.
        let stale_rt: [u8; 8] = [0x00, 0x02, 0xfd, 0xe9, 0x00, 0x00, 0x00, 0x64];
        let fresh_rt: [u8; 8] = [0x00, 0x02, 0xfd, 0xea, 0x00, 0x00, 0x00, 0x65];

        let stale_path = make_stale_rtc_path(MatchType::ExactMatch {
            origin_as: 65001,
            route_target: stale_rt,
        });
        let fresh_path = make_rtc_path(MatchType::ExactMatch {
            origin_as: 65002,
            route_target: fresh_rt,
        });

        let filter = RtcFilter::from_paths(&[stale_path, fresh_path]);
        // Pre-disconnect RT: allowed (stale path is the confirmed interest).
        assert!(filter.allows(&[ext_community_attr(&[stale_rt])]));
        // New RT from new session, before EOR: must be blocked.
        assert!(!filter.allows(&[ext_community_attr(&[fresh_rt])]));
    }

    #[test]
    fn filter_uses_all_paths_when_no_stale() {
        // Normal Active state or after GR stale deletion: all paths are fresh and
        // all are used for the filter.
        let rt1: [u8; 8] = [0x00, 0x02, 0xfd, 0xe9, 0x00, 0x00, 0x00, 0x64];
        let rt2: [u8; 8] = [0x00, 0x02, 0xfd, 0xea, 0x00, 0x00, 0x00, 0x65];

        let path1 = make_rtc_path(MatchType::ExactMatch {
            origin_as: 65001,
            route_target: rt1,
        });
        let path2 = make_rtc_path(MatchType::ExactMatch {
            origin_as: 65002,
            route_target: rt2,
        });

        let filter = RtcFilter::from_paths(&[path1, path2]);
        assert!(filter.allows(&[ext_community_attr(&[rt1])]));
        assert!(filter.allows(&[ext_community_attr(&[rt2])]));
    }
}
