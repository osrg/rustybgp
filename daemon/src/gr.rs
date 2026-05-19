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

//! Graceful Restart helper state machine (RFC 4724).
//!
//! Pure logic — no async, no I/O. Processes [`GrInput`] events and returns
//! [`GrOutput`] actions that the driver translates into real I/O and table
//! mutations.
//!
//! This implements the *helper* side of GR: the local speaker preserves stale
//! routes from a restarting peer until the peer either reconnects and sends
//! End-of-RIB, or the restart timer expires.

use fnv::FnvHashSet;
use rustybgp_packet::bgp::Family;
use std::time::Duration;

/// Events fed into the GR state machine.
pub(crate) enum GrInput {
    /// The peer session dropped while GR was negotiated for these families.
    /// The caller provides the restart_time from the last OPEN exchange.
    SessionDropped {
        families: Vec<Family>,
        restart_time: Duration,
    },
    /// The peer reconnected and GR was re-negotiated for these families.
    /// The restart timer is stopped; the machine waits for EOR per family.
    /// `deferral_time` is a local config value (RFC 4724 §4.1 Selection
    /// Deferral Timer); if EOR is not received within this duration, all
    /// remaining stale routes are deleted.
    SessionEstablished {
        gr_families: Vec<Family>,
        deferral_time: Duration,
    },
    /// End-of-RIB received for this family; stale routes for it can be removed.
    EorReceived(Family),
    /// The restart timer fired; all stale routes must be removed.
    TimerExpired,
    /// The Selection Deferral Timer fired; delete all remaining stale routes.
    DeferralTimerExpired,
    /// We are the restarting speaker; this peer reconnected as our helper.
    /// Track EOR receipt per family (RFC 4724 §4.2).  If `gr_families` is
    /// empty the machine stays Idle (no tracking needed for this peer).
    LocalRestartEstablished { gr_families: Vec<Family> },
}

/// Actions the driver should perform in response to a GR input.
pub(crate) enum GrOutput {
    /// Start (or restart) the restart timer with the given duration.
    StartTimer(Duration),
    /// Cancel the restart timer.
    StopTimer,
    /// Start the Selection Deferral Timer with the given duration.
    StartDeferralTimer(Duration),
    /// Cancel the Selection Deferral Timer.
    StopDeferralTimer,
    /// Delete stale routes for the given families.
    DeleteStaleRoutes(Vec<Family>),
    /// All expected EOR has been received from this peer (restarting-speaker
    /// side).  The driver should check whether all local-restarting peers have
    /// completed and call `clear_restarting` if so.
    PeerEorComplete,
}

enum Inner {
    /// No GR in progress.
    Idle,
    /// Peer dropped; restart timer running. Stale routes have been marked.
    Restarting { stale_families: Vec<Family> },
    /// Peer reconnected; Selection Deferral Timer running; waiting for EOR.
    WaitingEor { pending: FnvHashSet<Family> },
    /// We are the restarting speaker; waiting for EOR from this helper peer.
    LocalRestarting { pending: FnvHashSet<Family> },
}

/// GR helper state machine for a single BGP peer.
pub(crate) struct GrState {
    state: Inner,
}

impl GrState {
    pub(crate) fn new() -> Self {
        GrState { state: Inner::Idle }
    }

    /// Returns true while waiting for EOR from a helper peer (restarting-speaker side).
    pub(crate) fn is_local_restarting(&self) -> bool {
        matches!(self.state, Inner::LocalRestarting { .. })
    }

    /// Returns true while the remote peer is restarting (helper side: restart
    /// timer running or waiting for EOR).
    pub(crate) fn is_peer_restarting(&self) -> bool {
        matches!(
            self.state,
            Inner::Restarting { .. } | Inner::WaitingEor { .. }
        )
    }

    pub(crate) fn process(&mut self, input: GrInput) -> Vec<GrOutput> {
        let state = std::mem::replace(&mut self.state, Inner::Idle);
        let (new_state, outputs) = match (state, input) {
            // LocalRestarting + SessionDropped: peer dropped before sending all EOR;
            // give up waiting (no stale routes to mark on our side).
            (Inner::LocalRestarting { .. }, GrInput::SessionDropped { .. }) => {
                (Inner::Idle, vec![])
            }

            // LocalRestartEstablished from Idle: enter LocalRestarting if families
            // are non-empty, otherwise stay Idle.
            (Inner::Idle, GrInput::LocalRestartEstablished { gr_families }) => {
                let pending: FnvHashSet<Family> = gr_families.into_iter().collect();
                if pending.is_empty() {
                    (Inner::Idle, vec![])
                } else {
                    (Inner::LocalRestarting { pending }, vec![])
                }
            }

            // EOR received while we are the restarting speaker.
            (Inner::LocalRestarting { mut pending }, GrInput::EorReceived(family)) => {
                pending.remove(&family);
                if pending.is_empty() {
                    (Inner::Idle, vec![GrOutput::PeerEorComplete])
                } else {
                    (Inner::LocalRestarting { pending }, vec![])
                }
            }

            // Session drop from any state: mark stale and start restart timer.
            // If dropping from WaitingEor, also stop the deferral timer.
            (
                state,
                GrInput::SessionDropped {
                    families,
                    restart_time,
                },
            ) => {
                let mut outputs = Vec::new();
                if matches!(state, Inner::WaitingEor { .. }) {
                    outputs.push(GrOutput::StopDeferralTimer);
                }
                outputs.push(GrOutput::StartTimer(restart_time));
                (
                    Inner::Restarting {
                        stale_families: families,
                    },
                    outputs,
                )
            }

            // Peer reconnected while restart timer was running.
            (
                Inner::Restarting { stale_families },
                GrInput::SessionEstablished {
                    gr_families,
                    deferral_time,
                },
            ) => {
                let gr_set: FnvHashSet<Family> = gr_families.into_iter().collect();

                // Families that were stale but are no longer in the new GR capability
                // must be deleted immediately (RFC 4724 §4.2).
                let dropped: Vec<Family> = stale_families
                    .into_iter()
                    .filter(|f| !gr_set.contains(f))
                    .collect();

                let mut outputs = vec![GrOutput::StopTimer];
                if !dropped.is_empty() {
                    outputs.push(GrOutput::DeleteStaleRoutes(dropped));
                }

                let new_state = if gr_set.is_empty() {
                    Inner::Idle
                } else {
                    outputs.push(GrOutput::StartDeferralTimer(deferral_time));
                    Inner::WaitingEor { pending: gr_set }
                };
                (new_state, outputs)
            }

            // Restart timer fired before peer reconnected.
            (Inner::Restarting { stale_families }, GrInput::TimerExpired) => (
                Inner::Idle,
                vec![GrOutput::DeleteStaleRoutes(stale_families)],
            ),

            // EOR received for one family while waiting for all families.
            (Inner::WaitingEor { mut pending }, GrInput::EorReceived(family)) => {
                pending.remove(&family);
                let mut outputs = vec![GrOutput::DeleteStaleRoutes(vec![family])];
                let new_state = if pending.is_empty() {
                    outputs.push(GrOutput::StopDeferralTimer);
                    Inner::Idle
                } else {
                    Inner::WaitingEor { pending }
                };
                (new_state, outputs)
            }

            // Selection Deferral Timer fired; delete all remaining stale routes.
            (Inner::WaitingEor { pending }, GrInput::DeferralTimerExpired) => {
                let families: Vec<Family> = pending.into_iter().collect();
                (Inner::Idle, vec![GrOutput::DeleteStaleRoutes(families)])
            }

            // All other combinations are no-ops (e.g., EOR in Idle/Restarting,
            // TimerExpired in WaitingEor, SessionEstablished in Idle).
            (state, _) => (state, vec![]),
        };
        self.state = new_state;
        outputs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4() -> Family {
        Family::IPV4
    }

    fn ipv6() -> Family {
        Family::IPV6
    }

    fn restart_time() -> Duration {
        Duration::from_secs(120)
    }

    fn deferral_time() -> Duration {
        Duration::from_secs(360)
    }

    fn drop_ipv4(gr: &mut GrState) -> Vec<GrOutput> {
        gr.process(GrInput::SessionDropped {
            families: vec![ipv4()],
            restart_time: restart_time(),
        })
    }

    fn establish_ipv4(gr: &mut GrState) -> Vec<GrOutput> {
        gr.process(GrInput::SessionEstablished {
            gr_families: vec![ipv4()],
            deferral_time: deferral_time(),
        })
    }

    #[test]
    fn session_dropped_starts_timer() {
        let mut gr = GrState::new();
        let outputs = drop_ipv4(&mut gr);

        assert_eq!(outputs.len(), 1);
        assert!(matches!(&outputs[0], GrOutput::StartTimer(d) if *d == restart_time()));
        assert!(matches!(gr.state, Inner::Restarting { .. }));
    }

    #[test]
    fn timer_expiry_deletes_stale_routes() {
        let mut gr = GrState::new();
        drop_ipv4(&mut gr);

        let outputs = gr.process(GrInput::TimerExpired);

        assert_eq!(outputs.len(), 1);
        assert!(matches!(&outputs[0], GrOutput::DeleteStaleRoutes(f) if f == &[ipv4()]));
        assert!(matches!(gr.state, Inner::Idle));
    }

    #[test]
    fn reconnect_stops_timer_starts_deferral_timer() {
        let mut gr = GrState::new();
        drop_ipv4(&mut gr);

        let outputs = establish_ipv4(&mut gr);

        assert_eq!(outputs.len(), 2);
        assert!(matches!(outputs[0], GrOutput::StopTimer));
        assert!(matches!(outputs[1], GrOutput::StartDeferralTimer(d) if d == deferral_time()));
        assert!(matches!(gr.state, Inner::WaitingEor { .. }));
    }

    #[test]
    fn eor_deletes_stale_routes_and_stops_deferral_timer() {
        let mut gr = GrState::new();
        drop_ipv4(&mut gr);
        establish_ipv4(&mut gr);

        let outputs = gr.process(GrInput::EorReceived(ipv4()));

        assert_eq!(outputs.len(), 2);
        assert!(matches!(&outputs[0], GrOutput::DeleteStaleRoutes(f) if f == &[ipv4()]));
        assert!(matches!(outputs[1], GrOutput::StopDeferralTimer));
        assert!(matches!(gr.state, Inner::Idle));
    }

    #[test]
    fn partial_eor_does_not_stop_deferral_timer() {
        let mut gr = GrState::new();
        gr.process(GrInput::SessionDropped {
            families: vec![ipv4(), ipv6()],
            restart_time: restart_time(),
        });
        gr.process(GrInput::SessionEstablished {
            gr_families: vec![ipv4(), ipv6()],
            deferral_time: deferral_time(),
        });

        // First EOR: still waiting for IPv6
        let outputs = gr.process(GrInput::EorReceived(ipv4()));
        assert_eq!(outputs.len(), 1);
        assert!(matches!(&outputs[0], GrOutput::DeleteStaleRoutes(f) if f == &[ipv4()]));
        assert!(matches!(gr.state, Inner::WaitingEor { .. }));

        // Second EOR: all done, deferral timer stopped
        let outputs = gr.process(GrInput::EorReceived(ipv6()));
        assert_eq!(outputs.len(), 2);
        assert!(matches!(&outputs[0], GrOutput::DeleteStaleRoutes(f) if f == &[ipv6()]));
        assert!(matches!(outputs[1], GrOutput::StopDeferralTimer));
        assert!(matches!(gr.state, Inner::Idle));
    }

    #[test]
    fn deferral_timer_expired_deletes_remaining_stale_routes() {
        let mut gr = GrState::new();
        gr.process(GrInput::SessionDropped {
            families: vec![ipv4(), ipv6()],
            restart_time: restart_time(),
        });
        gr.process(GrInput::SessionEstablished {
            gr_families: vec![ipv4(), ipv6()],
            deferral_time: deferral_time(),
        });
        // Only IPv4 EOR received; IPv6 never arrives
        gr.process(GrInput::EorReceived(ipv4()));

        let outputs = gr.process(GrInput::DeferralTimerExpired);

        assert_eq!(outputs.len(), 1);
        assert!(matches!(&outputs[0], GrOutput::DeleteStaleRoutes(f) if f == &[ipv6()]));
        assert!(matches!(gr.state, Inner::Idle));
    }

    #[test]
    fn eor_in_idle_is_noop() {
        let mut gr = GrState::new();
        let outputs = gr.process(GrInput::EorReceived(ipv4()));
        assert!(outputs.is_empty());
        assert!(matches!(gr.state, Inner::Idle));
    }

    #[test]
    fn session_dropped_again_during_restarting_restarts_gr() {
        let mut gr = GrState::new();
        drop_ipv4(&mut gr);

        let outputs = gr.process(GrInput::SessionDropped {
            families: vec![ipv4(), ipv6()],
            restart_time: Duration::from_secs(60),
        });

        assert_eq!(outputs.len(), 1);
        assert!(matches!(&outputs[0], GrOutput::StartTimer(d) if *d == Duration::from_secs(60)));
        assert!(matches!(gr.state, Inner::Restarting { .. }));
    }

    #[test]
    fn reconnect_with_fewer_gr_families_deletes_dropped_families() {
        // Stale: IPv4 + IPv6; new OPEN only declares IPv4 for GR.
        // IPv6 stale routes must be deleted immediately (RFC 4724 §4.2).
        let mut gr = GrState::new();
        gr.process(GrInput::SessionDropped {
            families: vec![ipv4(), ipv6()],
            restart_time: restart_time(),
        });

        let outputs = gr.process(GrInput::SessionEstablished {
            gr_families: vec![ipv4()],
            deferral_time: deferral_time(),
        });

        // StopTimer + DeleteStaleRoutes([IPv6]) + StartDeferralTimer
        assert_eq!(outputs.len(), 3);
        assert!(matches!(outputs[0], GrOutput::StopTimer));
        assert!(matches!(&outputs[1], GrOutput::DeleteStaleRoutes(f) if f == &[ipv6()]));
        assert!(matches!(outputs[2], GrOutput::StartDeferralTimer(d) if d == deferral_time()));
        assert!(matches!(gr.state, Inner::WaitingEor { .. }));
    }

    #[test]
    fn reconnect_with_no_gr_families_deletes_all_and_goes_idle() {
        // New OPEN carries no GR families at all → all stale routes deleted.
        let mut gr = GrState::new();
        gr.process(GrInput::SessionDropped {
            families: vec![ipv4(), ipv6()],
            restart_time: restart_time(),
        });

        let outputs = gr.process(GrInput::SessionEstablished {
            gr_families: vec![],
            deferral_time: deferral_time(),
        });

        // StopTimer + DeleteStaleRoutes([IPv4, IPv6]); no StartDeferralTimer
        assert_eq!(outputs.len(), 2);
        assert!(matches!(outputs[0], GrOutput::StopTimer));
        assert!(matches!(&outputs[1], GrOutput::DeleteStaleRoutes(f) if f.len() == 2));
        assert!(matches!(gr.state, Inner::Idle));
    }

    #[test]
    fn session_dropped_during_waiting_eor_stops_deferral_timer() {
        let mut gr = GrState::new();
        drop_ipv4(&mut gr);
        establish_ipv4(&mut gr);
        assert!(matches!(gr.state, Inner::WaitingEor { .. }));

        let outputs = drop_ipv4(&mut gr);

        // StopDeferralTimer + StartTimer
        assert_eq!(outputs.len(), 2);
        assert!(matches!(outputs[0], GrOutput::StopDeferralTimer));
        assert!(matches!(outputs[1], GrOutput::StartTimer(d) if d == restart_time()));
        assert!(matches!(gr.state, Inner::Restarting { .. }));
    }

    // --- restarting-speaker side ---

    #[test]
    fn local_restart_single_family_eor_emits_peer_eor_complete() {
        let mut gr = GrState::new();
        let outputs = gr.process(GrInput::LocalRestartEstablished {
            gr_families: vec![ipv4()],
        });
        assert!(outputs.is_empty());
        assert!(gr.is_local_restarting());

        let outputs = gr.process(GrInput::EorReceived(ipv4()));
        assert_eq!(outputs.len(), 1);
        assert!(matches!(outputs[0], GrOutput::PeerEorComplete));
        assert!(!gr.is_local_restarting());
        assert!(matches!(gr.state, Inner::Idle));
    }

    #[test]
    fn local_restart_two_families_partial_eor_no_complete() {
        let mut gr = GrState::new();
        gr.process(GrInput::LocalRestartEstablished {
            gr_families: vec![ipv4(), ipv6()],
        });
        assert!(gr.is_local_restarting());

        // First EOR: still waiting for IPv6
        let outputs = gr.process(GrInput::EorReceived(ipv4()));
        assert!(outputs.is_empty());
        assert!(gr.is_local_restarting());

        // Second EOR: all done
        let outputs = gr.process(GrInput::EorReceived(ipv6()));
        assert_eq!(outputs.len(), 1);
        assert!(matches!(outputs[0], GrOutput::PeerEorComplete));
        assert!(!gr.is_local_restarting());
    }

    #[test]
    fn local_restart_empty_families_stays_idle() {
        let mut gr = GrState::new();
        let outputs = gr.process(GrInput::LocalRestartEstablished {
            gr_families: vec![],
        });
        assert!(outputs.is_empty());
        assert!(!gr.is_local_restarting());
        assert!(matches!(gr.state, Inner::Idle));
    }

    #[test]
    fn local_restart_session_dropped_goes_idle_without_peer_eor_complete() {
        let mut gr = GrState::new();
        gr.process(GrInput::LocalRestartEstablished {
            gr_families: vec![ipv4()],
        });
        assert!(gr.is_local_restarting());

        let outputs = gr.process(GrInput::SessionDropped {
            families: vec![ipv4()],
            restart_time: restart_time(),
        });
        assert!(outputs.is_empty());
        assert!(!gr.is_local_restarting());
        assert!(matches!(gr.state, Inner::Idle));
    }

    #[test]
    fn local_restart_established_from_non_idle_is_noop() {
        // LocalRestartEstablished only works from Idle; from Restarting it is ignored.
        let mut gr = GrState::new();
        drop_ipv4(&mut gr);
        assert!(matches!(gr.state, Inner::Restarting { .. }));

        let outputs = gr.process(GrInput::LocalRestartEstablished {
            gr_families: vec![ipv4()],
        });
        assert!(outputs.is_empty());
        assert!(matches!(gr.state, Inner::Restarting { .. }));
    }
}
