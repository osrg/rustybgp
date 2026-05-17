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
#[allow(dead_code)]
pub(crate) enum GrInput {
    /// The peer session dropped while GR was negotiated for these families.
    /// The caller provides the restart_time from the last OPEN exchange.
    SessionDropped {
        families: Vec<Family>,
        restart_time: Duration,
    },
    /// The peer reconnected and GR was re-negotiated for these families.
    /// The timer should be stopped; the machine waits for EOR per family.
    SessionEstablished { gr_families: Vec<Family> },
    /// End-of-RIB received for this family; stale routes for it can be removed.
    EorReceived(Family),
    /// The restart timer fired; all stale routes must be removed.
    TimerExpired,
}

/// Actions the driver should perform in response to a GR input.
#[allow(dead_code)]
pub(crate) enum GrOutput {
    /// Mark routes from this peer stale for the given families.
    MarkStale(Vec<Family>),
    /// Start (or restart) the restart timer with the given duration.
    StartTimer(Duration),
    /// Cancel the restart timer.
    StopTimer,
    /// Delete stale routes for the given families.
    DeleteStaleRoutes(Vec<Family>),
}

enum Inner {
    /// No GR in progress.
    Idle,
    /// Peer dropped; restart timer running. Stale routes have been marked.
    Restarting { stale_families: Vec<Family> },
    /// Peer reconnected; waiting for EOR for each family in `pending`.
    WaitingEor { pending: FnvHashSet<Family> },
}

/// GR helper state machine for a single BGP peer.
#[allow(dead_code)]
pub(crate) struct GrState {
    state: Inner,
}

#[allow(dead_code)]
impl GrState {
    pub(crate) fn new() -> Self {
        GrState { state: Inner::Idle }
    }

    pub(crate) fn process(&mut self, input: GrInput) -> Vec<GrOutput> {
        let state = std::mem::replace(&mut self.state, Inner::Idle);
        let (new_state, outputs) = match (state, input) {
            // Session drop from any state: mark stale and start restart timer.
            (
                _,
                GrInput::SessionDropped {
                    families,
                    restart_time,
                },
            ) => (
                Inner::Restarting {
                    stale_families: families.clone(),
                },
                vec![
                    GrOutput::MarkStale(families),
                    GrOutput::StartTimer(restart_time),
                ],
            ),

            // Peer reconnected while restart timer was running.
            (Inner::Restarting { stale_families }, GrInput::SessionEstablished { gr_families }) => {
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
                let new_state = if pending.is_empty() {
                    Inner::Idle
                } else {
                    Inner::WaitingEor { pending }
                };
                (new_state, vec![GrOutput::DeleteStaleRoutes(vec![family])])
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

    fn drop_ipv4(gr: &mut GrState) -> Vec<GrOutput> {
        gr.process(GrInput::SessionDropped {
            families: vec![ipv4()],
            restart_time: restart_time(),
        })
    }

    #[test]
    fn session_dropped_marks_stale_and_starts_timer() {
        let mut gr = GrState::new();
        let outputs = drop_ipv4(&mut gr);

        assert_eq!(outputs.len(), 2);
        assert!(matches!(&outputs[0], GrOutput::MarkStale(f) if f == &[ipv4()]));
        assert!(matches!(&outputs[1], GrOutput::StartTimer(d) if *d == restart_time()));
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
    fn reconnect_stops_timer_and_waits_for_eor() {
        let mut gr = GrState::new();
        drop_ipv4(&mut gr);

        let outputs = gr.process(GrInput::SessionEstablished {
            gr_families: vec![ipv4()],
        });

        assert_eq!(outputs.len(), 1);
        assert!(matches!(outputs[0], GrOutput::StopTimer));
        assert!(matches!(gr.state, Inner::WaitingEor { .. }));
    }

    #[test]
    fn eor_deletes_stale_routes_for_family() {
        let mut gr = GrState::new();
        drop_ipv4(&mut gr);
        gr.process(GrInput::SessionEstablished {
            gr_families: vec![ipv4()],
        });

        let outputs = gr.process(GrInput::EorReceived(ipv4()));

        assert_eq!(outputs.len(), 1);
        assert!(matches!(&outputs[0], GrOutput::DeleteStaleRoutes(f) if f == &[ipv4()]));
        assert!(matches!(gr.state, Inner::Idle));
    }

    #[test]
    fn all_eor_received_returns_to_idle() {
        let mut gr = GrState::new();
        gr.process(GrInput::SessionDropped {
            families: vec![ipv4(), ipv6()],
            restart_time: restart_time(),
        });
        gr.process(GrInput::SessionEstablished {
            gr_families: vec![ipv4(), ipv6()],
        });

        gr.process(GrInput::EorReceived(ipv4()));
        assert!(matches!(gr.state, Inner::WaitingEor { .. }));

        gr.process(GrInput::EorReceived(ipv6()));
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

        // Session drops again before reconnection
        let outputs = gr.process(GrInput::SessionDropped {
            families: vec![ipv4(), ipv6()],
            restart_time: Duration::from_secs(60),
        });

        assert_eq!(outputs.len(), 2);
        assert!(matches!(&outputs[0], GrOutput::MarkStale(f) if f.len() == 2));
        assert!(matches!(&outputs[1], GrOutput::StartTimer(d) if *d == Duration::from_secs(60)));
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
        });

        // StopTimer + DeleteStaleRoutes([IPv6])
        assert_eq!(outputs.len(), 2);
        assert!(matches!(outputs[0], GrOutput::StopTimer));
        assert!(matches!(&outputs[1], GrOutput::DeleteStaleRoutes(f) if f == &[ipv6()]));
        // IPv4 still waiting for EOR
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
        });

        assert_eq!(outputs.len(), 2);
        assert!(matches!(outputs[0], GrOutput::StopTimer));
        assert!(matches!(&outputs[1], GrOutput::DeleteStaleRoutes(f) if f.len() == 2));
        assert!(matches!(gr.state, Inner::Idle));
    }

    #[test]
    fn session_dropped_during_waiting_eor_restarts_gr() {
        let mut gr = GrState::new();
        drop_ipv4(&mut gr);
        gr.process(GrInput::SessionEstablished {
            gr_families: vec![ipv4()],
        });
        assert!(matches!(gr.state, Inner::WaitingEor { .. }));

        // Session drops again while waiting for EOR
        let outputs = drop_ipv4(&mut gr);

        assert_eq!(outputs.len(), 2);
        assert!(matches!(&outputs[0], GrOutput::MarkStale(f) if f == &[ipv4()]));
        assert!(matches!(gr.state, Inner::Restarting { .. }));
    }
}
