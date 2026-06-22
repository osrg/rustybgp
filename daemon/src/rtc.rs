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

use rustybgp_packet::bgp::Family;
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
    #[allow(dead_code)]
    SessionDropped,
    /// Session dropped and GR helper mode has started for this peer.
    /// The machine keeps the RT filter active (if any) so stale RTC routes
    /// in the RIB can continue to gate VPN advertisement during recovery.
    /// If EOR had not yet arrived the machine resets to Inactive instead,
    /// since no confirmed RT interests are available to form a filter.
    #[allow(dead_code)]
    GrHelperStarted,
}

/// Actions the driver should perform in response to an RTC input.
#[allow(dead_code)]
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

fn vpn_families(families: &[Family]) -> Vec<Family> {
    families
        .iter()
        .filter(|f| {
            matches!(
                **f,
                Family::IPV4_VPN
                    | Family::IPV6_VPN
                    | Family::L2VPN_EVPN
                    | Family::IPV4_FLOWSPEC_VPN
                    | Family::IPV6_FLOWSPEC_VPN
            )
        })
        .copied()
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

    #[allow(dead_code)]
    pub(crate) fn is_awaiting_eor(&self) -> bool {
        matches!(self.state, Inner::AwaitingEor { .. })
    }

    #[allow(dead_code)]
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
}
