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

//! Graceful Restart state machines (RFC 4724).
//!
//! Pure logic — no async, no I/O. All types process events and return actions
//! that the driver translates into real I/O and table mutations.
//!
//! Two independent state machines live here:
//!
//! * [`GrState`] — **Helper side**, one instance per peer.  Preserves stale
//!   routes from a restarting remote peer until the peer reconnects and sends
//!   End-of-RIB, or the restart timer expires.
//!
//! * [`RestartingDeferral`] — **Restarting Speaker side**, one global instance.
//!   Defers best-path selection for GR families until EOR is received from all
//!   configured helper peers, or the Selection Deferral Timer fires.
//!
//! # GrState state diagram
//!
//!   Idle
//!     + SessionDropped(families, restart_time)
//!         mark routes stale; output: [StartTimer(restart_time)]
//!         --> Restarting { stale_families }
//!
//!   Restarting
//!     + SessionEstablished(gr_families, deferral_time)
//!         output: [StopTimer, DeleteStaleRoutes(dropped)?, StartDeferralTimer?]
//!         if gr_families empty: --> Idle
//!         else:                 --> WaitingEor { pending = gr_families }
//!     + TimerExpired
//!         output: [DeleteStaleRoutes(stale_families)] --> Idle
//!     + SessionDropped
//!         output: [StartTimer] --> Restarting  (restart timer reset)
//!
//!   WaitingEor
//!     + EorReceived(family)
//!         output: [DeleteStaleRoutes([family])]
//!         if all families done: output += [StopDeferralTimer] --> Idle
//!         else:                                               --> WaitingEor
//!     + DeferralTimerExpired
//!         output: [DeleteStaleRoutes(remaining)] --> Idle
//!     + SessionDropped
//!         output: [StopDeferralTimer, StartTimer] --> Restarting
//!
//!   All other (state, input) combinations are no-ops.

use fnv::{FnvHashMap, FnvHashSet};
use rustybgp_packet::bgp::Family;
use std::net::IpAddr;
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
}

enum Inner {
    /// No GR in progress.
    Idle,
    /// Peer dropped; restart timer running. Stale routes have been marked.
    Restarting { stale_families: Vec<Family> },
    /// Peer reconnected; Selection Deferral Timer running; waiting for EOR.
    WaitingEor { pending: FnvHashSet<Family> },
}

/// GR helper state machine for a single BGP peer.
pub(crate) struct GrState {
    state: Inner,
}

impl GrState {
    pub(crate) fn new() -> Self {
        GrState { state: Inner::Idle }
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

// ============================================================================
// Restarting Speaker deferral state machine (RFC 4724 §4.2)
// ============================================================================

/// Events for the Restarting Speaker deferral state machine.
#[allow(dead_code)]
pub(crate) enum RestartingInput {
    /// A peer session established.  `families` is the set of GR families
    /// negotiated in the OPEN; empty means this peer does not support GR.
    PeerEstablished(IpAddr, Vec<Family>),
    /// End-of-RIB received from `addr` for `family`.
    EorReceived(IpAddr, Family),
    /// The peer dropped or was removed from configuration.
    PeerWithdrawn(IpAddr),
    /// The global Selection Deferral Timer expired.
    TimerExpired,
}

/// Actions the driver performs for the Restarting Speaker deferral machine.
#[allow(dead_code)]
pub(crate) enum RestartingOutput {
    /// Emitted from `new()`: set the table deferral flag for these families.
    DeferFamilies(Vec<Family>),
    /// Start the global Selection Deferral Timer with this duration.
    StartDeferralTimer(Duration),
    /// This family is fully acknowledged: clear its table flag and re-advertise.
    FamilyDeferralComplete(Family),
    /// All deferral is done.  Remaining families (non-empty only on timer expiry)
    /// need their table flags cleared; driver must then call `clear_restarting()`.
    EndDeferral(Vec<Family>),
}

// Restarting Speaker state diagram:
//
//   new(gr_peers={p:fams,...}) --> AwaitingStart
//     output: [DeferFamilies(all_families)]
//
//   new(gr_peers={}) --> Completed  (no output)
//
//   AwaitingStart
//     + PeerEstablished(addr, non-empty, known)
//         update pending[addr] = negotiated families
//         output: [FamilyDeferralComplete*, StartDeferralTimer]
//         --> Deferring
//     + PeerWithdrawn(addr) | PeerEstablished(addr, [])
//         remove addr from pending; check newly-complete families
//         output: [FamilyDeferralComplete*]
//         if pending empty: output += [EndDeferral([])]  --> Completed
//         else:                                          --> AwaitingStart
//     + EorReceived | TimerExpired: no-op
//
//   Deferring
//     + EorReceived(addr, fam)
//         remove fam from pending[addr] (drop entry if empty)
//         if fam no longer in any pending entry: output [FamilyDeferralComplete(fam)]
//         if pending empty: output += [EndDeferral([])]  --> Completed
//         else:                                          --> Deferring
//     + PeerWithdrawn(addr) | PeerEstablished(addr, [])
//         remove addr from pending; check newly-complete families
//         output: [FamilyDeferralComplete*]
//         if pending empty: output += [EndDeferral([])]  --> Completed
//         else:                                          --> Deferring
//     + TimerExpired
//         output: [EndDeferral(remaining_families)]  --> Completed
//
//   Completed: all inputs are no-ops

#[allow(dead_code)]
enum RestartingInner {
    AwaitingStart {
        pending: FnvHashMap<IpAddr, FnvHashSet<Family>>,
        duration: Duration,
    },
    Deferring {
        pending: FnvHashMap<IpAddr, FnvHashSet<Family>>,
    },
    Completed,
}

/// Restarting Speaker Selection Deferral state machine (RFC 4724 §4.2).
///
/// Created at startup with the configured GR-capable peers.  Emits
/// `DeferFamilies` immediately so the driver can flag the right table families
/// before any peer connects.  Advances to `Completed` once all expected EOR
/// has arrived or the timer fires.
#[allow(dead_code)]
pub(crate) struct RestartingDeferral {
    state: RestartingInner,
}

#[allow(dead_code)]
impl RestartingDeferral {
    /// Create the state machine.
    ///
    /// `gr_peers`: each peer's configured GR families (peers with an empty
    /// list are skipped).  Returns `(machine, outputs)` where outputs contains
    /// at most one `DeferFamilies` action.
    pub(crate) fn new(
        gr_peers: FnvHashMap<IpAddr, Vec<Family>>,
        duration: Duration,
    ) -> (Self, Vec<RestartingOutput>) {
        let pending: FnvHashMap<IpAddr, FnvHashSet<Family>> = gr_peers
            .into_iter()
            .filter_map(|(addr, fams)| {
                if fams.is_empty() {
                    None
                } else {
                    Some((addr, fams.into_iter().collect()))
                }
            })
            .collect();

        if pending.is_empty() {
            return (
                Self {
                    state: RestartingInner::Completed,
                },
                vec![],
            );
        }

        let all_families: FnvHashSet<Family> = pending.values().flatten().copied().collect();
        let mut fam_vec: Vec<Family> = all_families.into_iter().collect();
        fam_vec.sort_unstable_by_key(|f| (f.afi(), f.safi()));

        (
            Self {
                state: RestartingInner::AwaitingStart { pending, duration },
            },
            vec![RestartingOutput::DeferFamilies(fam_vec)],
        )
    }

    pub(crate) fn is_completed(&self) -> bool {
        matches!(self.state, RestartingInner::Completed)
    }

    pub(crate) fn process(&mut self, input: RestartingInput) -> Vec<RestartingOutput> {
        let state = std::mem::replace(&mut self.state, RestartingInner::Completed);
        let (new_state, outputs) = match (state, input) {
            // AwaitingStart: first GR peer establishes -> transition to Deferring
            (
                RestartingInner::AwaitingStart {
                    mut pending,
                    duration,
                },
                RestartingInput::PeerEstablished(addr, families),
            ) => {
                if families.is_empty() {
                    let out = Self::remove_peer(&mut pending, addr);
                    Self::finish_awaiting(pending, duration, out)
                } else if let std::collections::hash_map::Entry::Occupied(mut e) =
                    pending.entry(addr)
                {
                    let new_set: FnvHashSet<Family> = families.into_iter().collect();
                    let old_set = e.insert(new_set);
                    let removed: Vec<Family> = old_set
                        .iter()
                        .filter(|f| !e.get().contains(f))
                        .copied()
                        .collect();
                    let mut out = Self::complete_for(&pending, &removed);
                    out.push(RestartingOutput::StartDeferralTimer(duration));
                    (RestartingInner::Deferring { pending }, out)
                } else {
                    // Unknown peer: ignore
                    (RestartingInner::AwaitingStart { pending, duration }, vec![])
                }
            }

            // AwaitingStart: peer withdrawn before any establish
            (
                RestartingInner::AwaitingStart {
                    mut pending,
                    duration,
                },
                RestartingInput::PeerWithdrawn(addr),
            ) => {
                let out = Self::remove_peer(&mut pending, addr);
                Self::finish_awaiting(pending, duration, out)
            }

            // Deferring: EOR received for one family from one peer
            (
                RestartingInner::Deferring { mut pending },
                RestartingInput::EorReceived(addr, family),
            ) => {
                let mut out = vec![];
                if let Some(peer_set) = pending.get_mut(&addr) {
                    peer_set.remove(&family);
                    if peer_set.is_empty() {
                        pending.remove(&addr);
                    }
                    if !pending.values().any(|fs| fs.contains(&family)) {
                        out.push(RestartingOutput::FamilyDeferralComplete(family));
                    }
                }
                if pending.is_empty() {
                    out.push(RestartingOutput::EndDeferral(vec![]));
                    (RestartingInner::Completed, out)
                } else {
                    (RestartingInner::Deferring { pending }, out)
                }
            }

            // Deferring: peer established without GR or re-established with GR
            (
                RestartingInner::Deferring { mut pending },
                RestartingInput::PeerEstablished(addr, families),
            ) => {
                if families.is_empty() {
                    let out = Self::remove_peer(&mut pending, addr);
                    Self::finish_deferring(pending, out)
                } else if let std::collections::hash_map::Entry::Occupied(mut e) =
                    pending.entry(addr)
                {
                    // Update to negotiated families; emit completions for dropped families
                    let new_set: FnvHashSet<Family> = families.into_iter().collect();
                    let old_set = e.insert(new_set);
                    let removed: Vec<Family> = old_set
                        .iter()
                        .filter(|f| !e.get().contains(f))
                        .copied()
                        .collect();
                    let out = Self::complete_for(&pending, &removed);
                    (RestartingInner::Deferring { pending }, out)
                } else {
                    // Unknown peer: ignore
                    (RestartingInner::Deferring { pending }, vec![])
                }
            }

            // Deferring: peer dropped
            (RestartingInner::Deferring { mut pending }, RestartingInput::PeerWithdrawn(addr)) => {
                let out = Self::remove_peer(&mut pending, addr);
                Self::finish_deferring(pending, out)
            }

            // Deferring: timer fired; end all remaining deferral immediately
            (RestartingInner::Deferring { pending }, RestartingInput::TimerExpired) => {
                let remaining: Vec<Family> = pending
                    .into_values()
                    .flatten()
                    .collect::<FnvHashSet<Family>>()
                    .into_iter()
                    .collect();
                (
                    RestartingInner::Completed,
                    vec![RestartingOutput::EndDeferral(remaining)],
                )
            }

            // Completed: all inputs are no-ops
            (RestartingInner::Completed, _) => (RestartingInner::Completed, vec![]),

            // Everything else (e.g. EorReceived/TimerExpired in AwaitingStart) is a no-op
            (state, _) => (state, vec![]),
        };
        self.state = new_state;
        outputs
    }

    /// Remove `addr` from `pending` and return `FamilyDeferralComplete` for
    /// each family no longer present in any remaining pending entry.
    fn remove_peer(
        pending: &mut FnvHashMap<IpAddr, FnvHashSet<Family>>,
        addr: IpAddr,
    ) -> Vec<RestartingOutput> {
        if let Some(removed_set) = pending.remove(&addr) {
            let candidates: Vec<Family> = removed_set.into_iter().collect();
            Self::complete_for(pending, &candidates)
        } else {
            vec![]
        }
    }

    /// For each family in `candidates` not found in any `pending` entry,
    /// emit `FamilyDeferralComplete`.
    fn complete_for(
        pending: &FnvHashMap<IpAddr, FnvHashSet<Family>>,
        candidates: &[Family],
    ) -> Vec<RestartingOutput> {
        candidates
            .iter()
            .filter(|f| !pending.values().any(|fs| fs.contains(f)))
            .map(|&f| RestartingOutput::FamilyDeferralComplete(f))
            .collect()
    }

    fn finish_awaiting(
        pending: FnvHashMap<IpAddr, FnvHashSet<Family>>,
        duration: Duration,
        mut outputs: Vec<RestartingOutput>,
    ) -> (RestartingInner, Vec<RestartingOutput>) {
        if pending.is_empty() {
            outputs.push(RestartingOutput::EndDeferral(vec![]));
            (RestartingInner::Completed, outputs)
        } else {
            (
                RestartingInner::AwaitingStart { pending, duration },
                outputs,
            )
        }
    }

    fn finish_deferring(
        pending: FnvHashMap<IpAddr, FnvHashSet<Family>>,
        mut outputs: Vec<RestartingOutput>,
    ) -> (RestartingInner, Vec<RestartingOutput>) {
        if pending.is_empty() {
            outputs.push(RestartingOutput::EndDeferral(vec![]));
            (RestartingInner::Completed, outputs)
        } else {
            (RestartingInner::Deferring { pending }, outputs)
        }
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

    // =========================================================================
    // RestartingDeferral tests
    // =========================================================================

    use std::net::{IpAddr, Ipv4Addr};

    fn peer(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, n))
    }

    fn make_deferral(
        peers: &[(IpAddr, Vec<Family>)],
    ) -> (RestartingDeferral, Vec<RestartingOutput>) {
        let map: FnvHashMap<IpAddr, Vec<Family>> = peers.iter().cloned().collect();
        RestartingDeferral::new(map, deferral_time())
    }

    fn rd_deferred_families(outputs: &[RestartingOutput]) -> Vec<Family> {
        for o in outputs {
            if let RestartingOutput::DeferFamilies(v) = o {
                return v.clone();
            }
        }
        vec![]
    }

    fn rd_complete_families(outputs: &[RestartingOutput]) -> Vec<Family> {
        outputs
            .iter()
            .filter_map(|o| {
                if let RestartingOutput::FamilyDeferralComplete(f) = o {
                    Some(*f)
                } else {
                    None
                }
            })
            .collect()
    }

    fn rd_end_deferral(outputs: &[RestartingOutput]) -> Option<Vec<Family>> {
        for o in outputs {
            if let RestartingOutput::EndDeferral(v) = o {
                return Some(v.clone());
            }
        }
        None
    }

    fn has_start_timer(outputs: &[RestartingOutput]) -> bool {
        outputs
            .iter()
            .any(|o| matches!(o, RestartingOutput::StartDeferralTimer(_)))
    }

    #[test]
    fn rd_new_empty_peers_returns_completed() {
        let (rd, outputs) = make_deferral(&[]);
        assert!(outputs.is_empty());
        assert!(rd.is_completed());
    }

    #[test]
    fn rd_new_all_empty_families_returns_completed() {
        let (rd, outputs) = make_deferral(&[(peer(1), vec![])]);
        assert!(outputs.is_empty());
        assert!(rd.is_completed());
    }

    #[test]
    fn rd_new_single_peer_emits_defer_families() {
        let (rd, outputs) = make_deferral(&[(peer(1), vec![ipv4()])]);
        assert_eq!(outputs.len(), 1);
        assert_eq!(rd_deferred_families(&outputs), vec![ipv4()]);
        assert!(!rd.is_completed());
        assert!(matches!(rd.state, RestartingInner::AwaitingStart { .. }));
    }

    #[test]
    fn rd_new_two_peers_union_of_families() {
        let (rd, outputs) = make_deferral(&[(peer(1), vec![ipv4()]), (peer(2), vec![ipv6()])]);
        let mut fams = rd_deferred_families(&outputs);
        fams.sort_unstable_by_key(|f| (f.afi(), f.safi()));
        assert_eq!(fams, vec![ipv4(), ipv6()]);
        assert!(!rd.is_completed());
    }

    #[test]
    fn rd_awaiting_first_establish_starts_timer() {
        let (mut rd, _) = make_deferral(&[(peer(1), vec![ipv4()])]);
        let outputs = rd.process(RestartingInput::PeerEstablished(peer(1), vec![ipv4()]));
        assert!(has_start_timer(&outputs));
        assert!(matches!(
            outputs.last(),
            Some(RestartingOutput::StartDeferralTimer(d)) if *d == deferral_time()
        ));
        assert!(matches!(rd.state, RestartingInner::Deferring { .. }));
    }

    #[test]
    fn rd_awaiting_unknown_peer_noop() {
        let (mut rd, _) = make_deferral(&[(peer(1), vec![ipv4()])]);
        let outputs = rd.process(RestartingInput::PeerEstablished(peer(9), vec![ipv4()]));
        assert!(outputs.is_empty());
        assert!(matches!(rd.state, RestartingInner::AwaitingStart { .. }));
    }

    #[test]
    fn rd_awaiting_withdraw_only_peer_completes() {
        let (mut rd, _) = make_deferral(&[(peer(1), vec![ipv4()])]);
        let outputs = rd.process(RestartingInput::PeerWithdrawn(peer(1)));
        // FamilyDeferralComplete(IPv4) + EndDeferral([])
        let complete = rd_complete_families(&outputs);
        assert!(complete.contains(&ipv4()));
        assert!(rd_end_deferral(&outputs).is_some());
        assert!(rd.is_completed());
    }

    #[test]
    fn rd_awaiting_withdraw_one_of_two_stays_awaiting() {
        let (mut rd, _) = make_deferral(&[(peer(1), vec![ipv4()]), (peer(2), vec![ipv4()])]);
        let outputs = rd.process(RestartingInput::PeerWithdrawn(peer(1)));
        // IPv4 still pending in peer(2): no FamilyDeferralComplete
        assert!(rd_complete_families(&outputs).is_empty());
        assert!(rd_end_deferral(&outputs).is_none());
        assert!(matches!(rd.state, RestartingInner::AwaitingStart { .. }));
    }

    #[test]
    fn rd_awaiting_establish_empty_families_same_as_withdraw() {
        let (mut rd, _) = make_deferral(&[(peer(1), vec![ipv4()])]);
        let outputs = rd.process(RestartingInput::PeerEstablished(peer(1), vec![]));
        assert!(rd_end_deferral(&outputs).is_some());
        assert!(rd.is_completed());
    }

    #[test]
    fn rd_awaiting_establish_negotiated_subset_emits_complete_for_dropped() {
        // Configured: IPv4+IPv6 for peer(1). Negotiated: only IPv4.
        // IPv6 should become FamilyDeferralComplete immediately.
        let (mut rd, _) = make_deferral(&[(peer(1), vec![ipv4(), ipv6()])]);
        let outputs = rd.process(RestartingInput::PeerEstablished(peer(1), vec![ipv4()]));
        let complete = rd_complete_families(&outputs);
        assert!(complete.contains(&ipv6()));
        assert!(!complete.contains(&ipv4()));
        assert!(has_start_timer(&outputs));
        assert!(matches!(rd.state, RestartingInner::Deferring { .. }));
    }

    #[test]
    fn rd_awaiting_timer_expired_noop() {
        let (mut rd, _) = make_deferral(&[(peer(1), vec![ipv4()])]);
        let outputs = rd.process(RestartingInput::TimerExpired);
        assert!(outputs.is_empty());
        assert!(matches!(rd.state, RestartingInner::AwaitingStart { .. }));
    }

    #[test]
    fn rd_deferring_eor_single_peer_single_family_completes() {
        let (mut rd, _) = make_deferral(&[(peer(1), vec![ipv4()])]);
        rd.process(RestartingInput::PeerEstablished(peer(1), vec![ipv4()]));

        let outputs = rd.process(RestartingInput::EorReceived(peer(1), ipv4()));
        assert!(rd_complete_families(&outputs).contains(&ipv4()));
        assert!(rd_end_deferral(&outputs).is_some());
        assert!(rd.is_completed());
    }

    #[test]
    fn rd_deferring_partial_eor_stays_deferring() {
        let (mut rd, _) = make_deferral(&[(peer(1), vec![ipv4(), ipv6()])]);
        rd.process(RestartingInput::PeerEstablished(
            peer(1),
            vec![ipv4(), ipv6()],
        ));

        let outputs = rd.process(RestartingInput::EorReceived(peer(1), ipv4()));
        assert!(rd_complete_families(&outputs).contains(&ipv4()));
        assert!(rd_end_deferral(&outputs).is_none());
        assert!(matches!(rd.state, RestartingInner::Deferring { .. }));

        let outputs = rd.process(RestartingInput::EorReceived(peer(1), ipv6()));
        assert!(rd_complete_families(&outputs).contains(&ipv6()));
        assert!(rd_end_deferral(&outputs).is_some());
        assert!(rd.is_completed());
    }

    #[test]
    fn rd_deferring_shared_family_waits_for_all_peers() {
        // Both peers carry IPv4. EOR from peer(1) alone does not complete IPv4.
        let (mut rd, _) = make_deferral(&[(peer(1), vec![ipv4()]), (peer(2), vec![ipv4()])]);
        rd.process(RestartingInput::PeerEstablished(peer(1), vec![ipv4()]));
        rd.process(RestartingInput::PeerEstablished(peer(2), vec![ipv4()]));

        let outputs = rd.process(RestartingInput::EorReceived(peer(1), ipv4()));
        assert!(rd_complete_families(&outputs).is_empty());
        assert!(rd_end_deferral(&outputs).is_none());
        assert!(matches!(rd.state, RestartingInner::Deferring { .. }));

        let outputs = rd.process(RestartingInput::EorReceived(peer(2), ipv4()));
        assert!(rd_complete_families(&outputs).contains(&ipv4()));
        assert!(rd_end_deferral(&outputs).is_some());
        assert!(rd.is_completed());
    }

    #[test]
    fn rd_deferring_withdraw_frees_exclusive_family() {
        // peer(1):{IPv4}, peer(2):{IPv6}. Withdraw peer(2) -> IPv6 complete.
        let (mut rd, _) = make_deferral(&[(peer(1), vec![ipv4()]), (peer(2), vec![ipv6()])]);
        rd.process(RestartingInput::PeerEstablished(peer(1), vec![ipv4()]));
        rd.process(RestartingInput::PeerEstablished(peer(2), vec![ipv6()]));

        let outputs = rd.process(RestartingInput::PeerWithdrawn(peer(2)));
        assert!(rd_complete_families(&outputs).contains(&ipv6()));
        assert!(rd_end_deferral(&outputs).is_none());
        assert!(matches!(rd.state, RestartingInner::Deferring { .. }));
    }

    #[test]
    fn rd_deferring_withdraw_last_peer_completes() {
        let (mut rd, _) = make_deferral(&[(peer(1), vec![ipv4()])]);
        rd.process(RestartingInput::PeerEstablished(peer(1), vec![ipv4()]));

        let outputs = rd.process(RestartingInput::PeerWithdrawn(peer(1)));
        assert!(rd_complete_families(&outputs).contains(&ipv4()));
        assert!(rd_end_deferral(&outputs).is_some());
        assert!(rd.is_completed());
    }

    #[test]
    fn rd_deferring_timer_expired_ends_remaining() {
        let (mut rd, _) = make_deferral(&[(peer(1), vec![ipv4(), ipv6()])]);
        rd.process(RestartingInput::PeerEstablished(
            peer(1),
            vec![ipv4(), ipv6()],
        ));
        rd.process(RestartingInput::EorReceived(peer(1), ipv4()));

        let outputs = rd.process(RestartingInput::TimerExpired);
        assert!(rd_end_deferral(&outputs).is_some());
        let remaining = rd_end_deferral(&outputs).unwrap();
        assert!(remaining.contains(&ipv6()));
        assert!(!remaining.contains(&ipv4()));
        assert!(rd.is_completed());
    }

    #[test]
    fn rd_completed_all_inputs_noop() {
        let (mut rd, _) = make_deferral(&[]);
        assert!(rd.is_completed());

        assert!(
            rd.process(RestartingInput::PeerEstablished(peer(1), vec![ipv4()]))
                .is_empty()
        );
        assert!(
            rd.process(RestartingInput::EorReceived(peer(1), ipv4()))
                .is_empty()
        );
        assert!(
            rd.process(RestartingInput::PeerWithdrawn(peer(1)))
                .is_empty()
        );
        assert!(rd.process(RestartingInput::TimerExpired).is_empty());
        assert!(rd.is_completed());
    }

    #[test]
    fn rd_deferring_eor_unknown_peer_noop() {
        let (mut rd, _) = make_deferral(&[(peer(1), vec![ipv4()])]);
        rd.process(RestartingInput::PeerEstablished(peer(1), vec![ipv4()]));

        let outputs = rd.process(RestartingInput::EorReceived(peer(9), ipv4()));
        assert!(outputs.is_empty());
        assert!(matches!(rd.state, RestartingInner::Deferring { .. }));
    }

    #[test]
    fn rd_second_establish_in_deferring_updates_families() {
        // peer(1) re-establishes with fewer GR families; dropped ones become complete.
        let (mut rd, _) = make_deferral(&[(peer(1), vec![ipv4(), ipv6()])]);
        rd.process(RestartingInput::PeerEstablished(
            peer(1),
            vec![ipv4(), ipv6()],
        ));

        // Re-establish with only IPv4
        let outputs = rd.process(RestartingInput::PeerEstablished(peer(1), vec![ipv4()]));
        assert!(rd_complete_families(&outputs).contains(&ipv6()));
        assert!(matches!(rd.state, RestartingInner::Deferring { .. }));
    }
}
