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

//! Graceful Restart state machines (RFC 4724 / RFC 9494).
//!
//! Pure logic — no async, no I/O. All types process events and return actions
//! that the driver translates into real I/O and table mutations.
//!
//! Two independent state machines live here:
//!
//! * [`GrState`] — **Helper side**, one instance per peer.  Preserves stale
//!   routes from a restarting remote peer until the peer reconnects and sends
//!   End-of-RIB, or the restart/LLGR stale timer expires.
//!
//! * [`RestartingDeferral`] — **Restarting Speaker side**, one global instance.
//!   Defers best-path selection for GR families until EOR is received from all
//!   configured helper peers, or the Selection Deferral Timer fires.
//!
//! # GrState state diagram
//!
//!   Idle
//!     + SessionDropped { gr: Some(gp), llgr }
//!         mark routes stale; output: [StartTimer(gp.restart_time)]
//!         --> PeerRestarting { stale_families: gp.families, llgr }
//!     + SessionDropped { gr: None, llgr: Some(lp) }
//!         output: [StartLlgrTimers(lp.families)]
//!         --> LlgrStaling { remaining: lp.families.keys }
//!
//!   PeerRestarting  (remote peer has restarted; we are the helper)
//!     + SessionEstablished(gr_families)
//!         output: [StopTimer, DeleteStaleRoutes(dropped)?]
//!         if gr_families empty: --> Idle
//!         else:                 --> PeerReconnected { pending, from_llgr: false }
//!     + TimerExpired, llgr: Some(lp)
//!         output: [StartLlgrTimers(lp.families)]  (driver also marks source LLGR stale,
//!                                                   deletes NO_LLGR routes)
//!         --> LlgrStaling { remaining: lp.families.keys }
//!     + TimerExpired, llgr: None
//!         output: [DeleteStaleRoutes(stale_families)] --> Idle
//!     + SessionDropped { gr: Some(gp), llgr }
//!         output: [StartTimer(gp.restart_time)] --> PeerRestarting (timer reset)
//!
//!   LlgrStaling  (GR timer expired; LLGR stale period running per family)
//!     + SessionEstablished(gr_families)
//!         output: [StopLlgrTimers]
//!         if gr_families empty: --> Idle
//!         else:                 --> PeerReconnected { pending, from_llgr: true }
//!     + LlgrTimerExpired(family)
//!         output: [DeleteLlgrStaleRoutes([family])]
//!         if remaining empty: --> Idle
//!         else:               --> LlgrStaling { remaining - family }
//!     + SessionDropped: no-op (timers keep running; session was already down)
//!
//!   PeerReconnected  (remote peer reconnected; waiting for EOR per family)
//!     + EorReceived(family), from_llgr: false
//!         output: [DeleteStaleRoutes([family])]
//!         if all families done: --> Idle
//!     + EorReceived(family), from_llgr: true
//!         output: [DeleteLlgrStaleRoutes([family])]
//!         if all families done: --> Idle
//!     + SessionDropped { gr: Some(gp), llgr }
//!         output: [StartTimer(gp.restart_time)] --> PeerRestarting
//!
//!   All other (state, input) combinations are no-ops.

use fnv::{FnvHashMap, FnvHashSet};
use rustybgp_packet::bgp::Family;
use std::net::IpAddr;
use std::time::Duration;

/// GR parameters carried in a session-drop event.
pub(crate) struct GrParams {
    pub families: Vec<Family>,
    pub restart_time: Duration,
}

/// LLGR parameters: per-family stale times negotiated in the peer's OPEN.
pub(crate) struct LlgrParams {
    /// `(family, stale_time)` for each LLGR-negotiated family.
    pub families: Vec<(Family, Duration)>,
}

/// Events fed into the GR/LLGR state machine.
pub(crate) enum GrInput {
    /// The peer session dropped.
    ///
    /// `gr` is `Some` when GR was negotiated (provides families + restart_time).
    /// `llgr` is `Some` when LLGR was negotiated (provides per-family stale times).
    /// At least one of `gr` / `llgr` must be `Some`; both `None` is a no-op.
    SessionDropped {
        gr: Option<GrParams>,
        llgr: Option<LlgrParams>,
    },
    /// The peer reconnected and GR was re-negotiated for these families.
    /// The restart timer is stopped; the machine waits for EOR per family.
    SessionEstablished { gr_families: Vec<Family> },
    /// End-of-RIB received for this family; stale routes for it can be removed.
    EorReceived(Family),
    /// The GR restart timer fired.
    TimerExpired,
    /// The LLGR stale timer for `family` fired.
    // Used in Step 5 when per-family tokio timers fire.
    #[allow(dead_code)]
    LlgrTimerExpired(Family),
}

/// Actions the driver should perform in response to a GR/LLGR input.
pub(crate) enum GrOutput {
    /// Start (or restart) the GR restart timer with the given duration.
    StartTimer(Duration),
    /// Cancel the GR restart timer.
    StopTimer,
    /// Delete GR stale routes for the given families.
    DeleteStaleRoutes(Vec<Family>),
    /// Start per-family LLGR stale timers.
    ///
    /// The driver must also mark the source as LLGR stale and delete any
    /// routes that carry the NO_LLGR community (0xFFFF0007).
    // Fields consumed by the driver in Step 5.
    #[allow(dead_code)]
    StartLlgrTimers(Vec<(Family, Duration)>),
    /// Cancel all pending LLGR family timers.
    StopLlgrTimers,
    /// Delete LLGR stale routes for the given families (LLGR timer expired
    /// or peer reconnected during the LLGR stale period).
    // Field consumed by the driver in Step 5.
    #[allow(dead_code)]
    DeleteLlgrStaleRoutes(Vec<Family>),
}

enum Inner {
    /// No GR or LLGR in progress.
    Idle,
    /// Remote peer dropped; GR restart timer running. Stale routes have been marked.
    PeerRestarting {
        stale_families: Vec<Family>,
        /// LLGR params to activate if the GR timer expires without reconnection.
        llgr: Option<LlgrParams>,
    },
    /// LLGR stale period: per-family timers running, source marked LLGR stale.
    LlgrStaling { remaining: FnvHashSet<Family> },
    /// Remote peer reconnected; waiting for EOR per family.
    PeerReconnected {
        pending: FnvHashSet<Family>,
        /// True when this reconnect follows an LLGR stale period (routes are
        /// LLGR stale, not GR stale), so EOR triggers DeleteLlgrStaleRoutes.
        from_llgr: bool,
    },
}

/// GR/LLGR helper state machine for a single BGP peer.
pub(crate) struct GrState {
    state: Inner,
}

impl GrState {
    pub(crate) fn new() -> Self {
        GrState { state: Inner::Idle }
    }

    /// Returns true while the remote peer is restarting or in the LLGR stale
    /// period (helper side: GR/LLGR timer running or waiting for EOR).
    pub(crate) fn is_peer_restarting(&self) -> bool {
        matches!(
            self.state,
            Inner::PeerRestarting { .. }
                | Inner::PeerReconnected { .. }
                | Inner::LlgrStaling { .. }
        )
    }

    pub(crate) fn process(&mut self, input: GrInput) -> Vec<GrOutput> {
        let state = std::mem::replace(&mut self.state, Inner::Idle);
        let (new_state, outputs) = match (state, input) {
            // LlgrStaling: session drop is a no-op (LLGR timers keep running;
            // the session was already down when LLGR started).
            (s @ Inner::LlgrStaling { .. }, GrInput::SessionDropped { .. }) => (s, vec![]),

            // Session drop with GR (from any non-LlgrStaling state): start/restart timer.
            (_, GrInput::SessionDropped { gr: Some(gp), llgr }) => (
                Inner::PeerRestarting {
                    stale_families: gp.families,
                    llgr,
                },
                vec![GrOutput::StartTimer(gp.restart_time)],
            ),

            // Session drop with LLGR only (no GR): enter LLGR stale immediately.
            (
                _,
                GrInput::SessionDropped {
                    gr: None,
                    llgr: Some(lp),
                },
            ) => {
                let remaining = lp.families.iter().map(|(f, _)| *f).collect();
                (
                    Inner::LlgrStaling { remaining },
                    vec![GrOutput::StartLlgrTimers(lp.families)],
                )
            }

            // GR timer expired with LLGR configured: transition to LLGR stale period.
            // The driver is responsible for marking the source LLGR stale and deleting
            // NO_LLGR routes when it sees StartLlgrTimers.
            (Inner::PeerRestarting { llgr: Some(lp), .. }, GrInput::TimerExpired) => {
                let remaining = lp.families.iter().map(|(f, _)| *f).collect();
                (
                    Inner::LlgrStaling { remaining },
                    vec![GrOutput::StartLlgrTimers(lp.families)],
                )
            }

            // GR timer expired without LLGR: delete stale routes and return to Idle.
            (
                Inner::PeerRestarting {
                    stale_families,
                    llgr: None,
                },
                GrInput::TimerExpired,
            ) => (
                Inner::Idle,
                vec![GrOutput::DeleteStaleRoutes(stale_families)],
            ),

            // Peer reconnected while GR restart timer was running.
            (
                Inner::PeerRestarting { stale_families, .. },
                GrInput::SessionEstablished { gr_families },
            ) => {
                let gr_set: FnvHashSet<Family> = gr_families.into_iter().collect();
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
                    Inner::PeerReconnected {
                        pending: gr_set,
                        from_llgr: false,
                    }
                };
                (new_state, outputs)
            }

            // Peer reconnected during LLGR stale period.
            (Inner::LlgrStaling { .. }, GrInput::SessionEstablished { gr_families }) => {
                let gr_set: FnvHashSet<Family> = gr_families.into_iter().collect();
                let new_state = if gr_set.is_empty() {
                    Inner::Idle
                } else {
                    Inner::PeerReconnected {
                        pending: gr_set,
                        from_llgr: true,
                    }
                };
                (new_state, vec![GrOutput::StopLlgrTimers])
            }

            // LLGR stale timer expired for one family.
            (Inner::LlgrStaling { mut remaining }, GrInput::LlgrTimerExpired(family)) => {
                remaining.remove(&family);
                let new_state = if remaining.is_empty() {
                    Inner::Idle
                } else {
                    Inner::LlgrStaling { remaining }
                };
                (
                    new_state,
                    vec![GrOutput::DeleteLlgrStaleRoutes(vec![family])],
                )
            }

            // EOR received while waiting after GR reconnect: delete GR stale routes.
            (
                Inner::PeerReconnected {
                    mut pending,
                    from_llgr: false,
                },
                GrInput::EorReceived(family),
            ) => {
                pending.remove(&family);
                let new_state = if pending.is_empty() {
                    Inner::Idle
                } else {
                    Inner::PeerReconnected {
                        pending,
                        from_llgr: false,
                    }
                };
                (new_state, vec![GrOutput::DeleteStaleRoutes(vec![family])])
            }

            // EOR received while waiting after LLGR reconnect: delete LLGR stale routes.
            (
                Inner::PeerReconnected {
                    mut pending,
                    from_llgr: true,
                },
                GrInput::EorReceived(family),
            ) => {
                pending.remove(&family);
                let new_state = if pending.is_empty() {
                    Inner::Idle
                } else {
                    Inner::PeerReconnected {
                        pending,
                        from_llgr: true,
                    }
                };
                (
                    new_state,
                    vec![GrOutput::DeleteLlgrStaleRoutes(vec![family])],
                )
            }

            // All other combinations are no-ops.
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
pub(crate) enum RestartingOutput {
    /// Emitted from `new()`: set the table deferral flag for these families.
    DeferFamilies(Vec<Family>),
    /// Start the global Selection Deferral Timer.
    /// `None` means the timer is disabled (wait indefinitely for EOR).
    StartDeferralTimer(Option<Duration>),
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

enum RestartingInner {
    AwaitingStart {
        pending: FnvHashMap<IpAddr, FnvHashSet<Family>>,
        /// `None` means the Selection Deferral Timer is disabled.
        duration: Option<Duration>,
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
pub(crate) struct RestartingDeferral {
    state: RestartingInner,
}

impl RestartingDeferral {
    /// Create the state machine.
    ///
    /// `gr_peers`: each peer's configured GR families (peers with an empty
    /// list are skipped).  Returns `(machine, outputs)` where outputs contains
    /// at most one `DeferFamilies` action.
    /// `duration`: how long to run the Selection Deferral Timer after the first
    /// peer establishes.  `None` disables the timer (EOR is awaited indefinitely).
    pub(crate) fn new(
        gr_peers: FnvHashMap<IpAddr, Vec<Family>>,
        duration: Option<Duration>,
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
        duration: Option<Duration>,
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

    fn llgr_time() -> Duration {
        Duration::from_secs(3600)
    }

    fn drop_gr(gr: &mut GrState, families: Vec<Family>) -> Vec<GrOutput> {
        gr.process(GrInput::SessionDropped {
            gr: Some(GrParams {
                families,
                restart_time: restart_time(),
            }),
            llgr: None,
        })
    }

    fn drop_gr_llgr(gr: &mut GrState, families: Vec<Family>) -> Vec<GrOutput> {
        gr.process(GrInput::SessionDropped {
            gr: Some(GrParams {
                families: families.clone(),
                restart_time: restart_time(),
            }),
            llgr: Some(LlgrParams {
                families: families.into_iter().map(|f| (f, llgr_time())).collect(),
            }),
        })
    }

    fn drop_llgr_only(gr: &mut GrState, families: Vec<Family>) -> Vec<GrOutput> {
        gr.process(GrInput::SessionDropped {
            gr: None,
            llgr: Some(LlgrParams {
                families: families.into_iter().map(|f| (f, llgr_time())).collect(),
            }),
        })
    }

    fn establish(gr: &mut GrState, families: Vec<Family>) -> Vec<GrOutput> {
        gr.process(GrInput::SessionEstablished {
            gr_families: families,
        })
    }

    // =========================================================================
    // GR-only tests (existing behavior, updated API)
    // =========================================================================

    #[test]
    fn session_dropped_starts_timer() {
        let mut gr = GrState::new();
        let outputs = drop_gr(&mut gr, vec![ipv4()]);

        assert_eq!(outputs.len(), 1);
        assert!(matches!(&outputs[0], GrOutput::StartTimer(d) if *d == restart_time()));
        assert!(matches!(gr.state, Inner::PeerRestarting { .. }));
    }

    #[test]
    fn timer_expiry_deletes_stale_routes() {
        let mut gr = GrState::new();
        drop_gr(&mut gr, vec![ipv4()]);

        let outputs = gr.process(GrInput::TimerExpired);

        assert_eq!(outputs.len(), 1);
        assert!(matches!(&outputs[0], GrOutput::DeleteStaleRoutes(f) if f == &[ipv4()]));
        assert!(matches!(gr.state, Inner::Idle));
    }

    #[test]
    fn reconnect_stops_timer() {
        let mut gr = GrState::new();
        drop_gr(&mut gr, vec![ipv4()]);

        let outputs = establish(&mut gr, vec![ipv4()]);

        assert_eq!(outputs.len(), 1);
        assert!(matches!(outputs[0], GrOutput::StopTimer));
        assert!(matches!(
            gr.state,
            Inner::PeerReconnected {
                from_llgr: false,
                ..
            }
        ));
    }

    #[test]
    fn eor_deletes_stale_routes() {
        let mut gr = GrState::new();
        drop_gr(&mut gr, vec![ipv4()]);
        establish(&mut gr, vec![ipv4()]);

        let outputs = gr.process(GrInput::EorReceived(ipv4()));

        assert_eq!(outputs.len(), 1);
        assert!(matches!(&outputs[0], GrOutput::DeleteStaleRoutes(f) if f == &[ipv4()]));
        assert!(matches!(gr.state, Inner::Idle));
    }

    #[test]
    fn partial_eor_stays_reconnected() {
        let mut gr = GrState::new();
        drop_gr(&mut gr, vec![ipv4(), ipv6()]);
        establish(&mut gr, vec![ipv4(), ipv6()]);

        let outputs = gr.process(GrInput::EorReceived(ipv4()));
        assert_eq!(outputs.len(), 1);
        assert!(matches!(&outputs[0], GrOutput::DeleteStaleRoutes(f) if f == &[ipv4()]));
        assert!(matches!(gr.state, Inner::PeerReconnected { .. }));

        let outputs = gr.process(GrInput::EorReceived(ipv6()));
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
        drop_gr(&mut gr, vec![ipv4()]);

        let outputs = gr.process(GrInput::SessionDropped {
            gr: Some(GrParams {
                families: vec![ipv4(), ipv6()],
                restart_time: Duration::from_secs(60),
            }),
            llgr: None,
        });

        assert_eq!(outputs.len(), 1);
        assert!(matches!(&outputs[0], GrOutput::StartTimer(d) if *d == Duration::from_secs(60)));
        assert!(matches!(gr.state, Inner::PeerRestarting { .. }));
    }

    #[test]
    fn reconnect_with_fewer_gr_families_deletes_dropped_families() {
        let mut gr = GrState::new();
        drop_gr(&mut gr, vec![ipv4(), ipv6()]);

        let outputs = establish(&mut gr, vec![ipv4()]);

        assert_eq!(outputs.len(), 2);
        assert!(matches!(outputs[0], GrOutput::StopTimer));
        assert!(matches!(&outputs[1], GrOutput::DeleteStaleRoutes(f) if f == &[ipv6()]));
        assert!(matches!(gr.state, Inner::PeerReconnected { .. }));
    }

    #[test]
    fn reconnect_with_no_gr_families_deletes_all_and_goes_idle() {
        let mut gr = GrState::new();
        drop_gr(&mut gr, vec![ipv4(), ipv6()]);

        let outputs = establish(&mut gr, vec![]);

        assert_eq!(outputs.len(), 2);
        assert!(matches!(outputs[0], GrOutput::StopTimer));
        assert!(matches!(&outputs[1], GrOutput::DeleteStaleRoutes(f) if f.len() == 2));
        assert!(matches!(gr.state, Inner::Idle));
    }

    #[test]
    fn session_dropped_during_waiting_eor_restarts_gr() {
        let mut gr = GrState::new();
        drop_gr(&mut gr, vec![ipv4()]);
        establish(&mut gr, vec![ipv4()]);
        assert!(matches!(gr.state, Inner::PeerReconnected { .. }));

        let outputs = drop_gr(&mut gr, vec![ipv4()]);

        assert_eq!(outputs.len(), 1);
        assert!(matches!(outputs[0], GrOutput::StartTimer(d) if d == restart_time()));
        assert!(matches!(gr.state, Inner::PeerRestarting { .. }));
    }

    // =========================================================================
    // LLGR tests
    // =========================================================================

    #[test]
    fn gr_timer_expiry_with_llgr_starts_llgr_timers() {
        let mut gr = GrState::new();
        drop_gr_llgr(&mut gr, vec![ipv4()]);

        let outputs = gr.process(GrInput::TimerExpired);

        assert_eq!(outputs.len(), 1);
        assert!(
            matches!(&outputs[0], GrOutput::StartLlgrTimers(v) if v == &[(ipv4(), llgr_time())])
        );
        assert!(matches!(gr.state, Inner::LlgrStaling { .. }));
    }

    #[test]
    fn llgr_timer_expiry_deletes_llgr_stale_routes() {
        let mut gr = GrState::new();
        drop_gr_llgr(&mut gr, vec![ipv4()]);
        gr.process(GrInput::TimerExpired);

        let outputs = gr.process(GrInput::LlgrTimerExpired(ipv4()));

        assert_eq!(outputs.len(), 1);
        assert!(matches!(&outputs[0], GrOutput::DeleteLlgrStaleRoutes(f) if f == &[ipv4()]));
        assert!(matches!(gr.state, Inner::Idle));
    }

    #[test]
    fn llgr_partial_timer_stays_staling() {
        let mut gr = GrState::new();
        drop_gr_llgr(&mut gr, vec![ipv4(), ipv6()]);
        gr.process(GrInput::TimerExpired);

        let outputs = gr.process(GrInput::LlgrTimerExpired(ipv4()));
        assert!(matches!(&outputs[0], GrOutput::DeleteLlgrStaleRoutes(f) if f == &[ipv4()]));
        assert!(matches!(gr.state, Inner::LlgrStaling { .. }));

        let outputs = gr.process(GrInput::LlgrTimerExpired(ipv6()));
        assert!(matches!(&outputs[0], GrOutput::DeleteLlgrStaleRoutes(f) if f == &[ipv6()]));
        assert!(matches!(gr.state, Inner::Idle));
    }

    #[test]
    fn llgr_only_session_drop_enters_llgr_staling_directly() {
        let mut gr = GrState::new();
        let outputs = drop_llgr_only(&mut gr, vec![ipv4()]);

        assert_eq!(outputs.len(), 1);
        assert!(
            matches!(&outputs[0], GrOutput::StartLlgrTimers(v) if v == &[(ipv4(), llgr_time())])
        );
        assert!(matches!(gr.state, Inner::LlgrStaling { .. }));
    }

    #[test]
    fn session_drop_during_llgr_staling_is_noop() {
        let mut gr = GrState::new();
        drop_llgr_only(&mut gr, vec![ipv4()]);

        let outputs = gr.process(GrInput::SessionDropped {
            gr: None,
            llgr: Some(LlgrParams {
                families: vec![(ipv4(), llgr_time())],
            }),
        });

        assert!(outputs.is_empty());
        assert!(matches!(gr.state, Inner::LlgrStaling { .. }));
    }

    #[test]
    fn reconnect_during_llgr_stops_timers_and_waits_for_eor() {
        let mut gr = GrState::new();
        drop_gr_llgr(&mut gr, vec![ipv4()]);
        gr.process(GrInput::TimerExpired);

        let outputs = establish(&mut gr, vec![ipv4()]);

        assert_eq!(outputs.len(), 1);
        assert!(matches!(outputs[0], GrOutput::StopLlgrTimers));
        assert!(matches!(
            gr.state,
            Inner::PeerReconnected {
                from_llgr: true,
                ..
            }
        ));
    }

    #[test]
    fn eor_after_llgr_reconnect_deletes_llgr_stale_routes() {
        let mut gr = GrState::new();
        drop_gr_llgr(&mut gr, vec![ipv4()]);
        gr.process(GrInput::TimerExpired);
        establish(&mut gr, vec![ipv4()]);

        let outputs = gr.process(GrInput::EorReceived(ipv4()));

        assert_eq!(outputs.len(), 1);
        assert!(matches!(&outputs[0], GrOutput::DeleteLlgrStaleRoutes(f) if f == &[ipv4()]));
        assert!(matches!(gr.state, Inner::Idle));
    }

    #[test]
    fn reconnect_during_llgr_with_no_gr_goes_idle() {
        let mut gr = GrState::new();
        drop_llgr_only(&mut gr, vec![ipv4()]);

        let outputs = establish(&mut gr, vec![]);

        assert_eq!(outputs.len(), 1);
        assert!(matches!(outputs[0], GrOutput::StopLlgrTimers));
        assert!(matches!(gr.state, Inner::Idle));
    }

    #[test]
    fn is_peer_restarting_true_in_llgr_staling() {
        let mut gr = GrState::new();
        drop_llgr_only(&mut gr, vec![ipv4()]);
        assert!(gr.is_peer_restarting());
    }

    #[test]
    fn llgr_only_reconnect_with_gr_families_eor_deletes_llgr_stale_routes() {
        // LLGR-only: LlgrStaling -> reconnect with GR families -> EOR
        // should delete LLGR stale routes (not GR stale routes).
        let mut gr = GrState::new();
        drop_llgr_only(&mut gr, vec![ipv4()]);

        let outputs = establish(&mut gr, vec![ipv4()]);
        assert_eq!(outputs.len(), 1);
        assert!(matches!(outputs[0], GrOutput::StopLlgrTimers));
        assert!(matches!(
            gr.state,
            Inner::PeerReconnected {
                from_llgr: true,
                ..
            }
        ));

        let outputs = gr.process(GrInput::EorReceived(ipv4()));
        assert_eq!(outputs.len(), 1);
        assert!(matches!(&outputs[0], GrOutput::DeleteLlgrStaleRoutes(f) if f == &[ipv4()]));
        assert!(matches!(gr.state, Inner::Idle));
    }

    #[test]
    fn gr_llgr_session_drop_during_restarting_resets_timer_with_new_params() {
        // GR+LLGR: second session drop while PeerRestarting{llgr:Some} must
        // reset the GR timer and carry the new LLGR params forward.
        let mut gr = GrState::new();
        drop_gr_llgr(&mut gr, vec![ipv4()]);
        assert!(matches!(gr.state, Inner::PeerRestarting { .. }));

        // Second drop with updated GR+LLGR params (e.g. different restart_time).
        let outputs = gr.process(GrInput::SessionDropped {
            gr: Some(GrParams {
                families: vec![ipv4(), ipv6()],
                restart_time: Duration::from_secs(60),
            }),
            llgr: Some(LlgrParams {
                families: vec![(ipv4(), Duration::from_secs(7200))],
            }),
        });

        assert_eq!(outputs.len(), 1);
        assert!(matches!(&outputs[0], GrOutput::StartTimer(d) if *d == Duration::from_secs(60)));
        // Still in PeerRestarting; GR timer expiry should now use new LLGR params.
        assert!(matches!(gr.state, Inner::PeerRestarting { .. }));

        // Verify the new LLGR params survive by checking timer expiry output.
        let outputs = gr.process(GrInput::TimerExpired);
        assert_eq!(outputs.len(), 1);
        assert!(matches!(
            &outputs[0],
            GrOutput::StartLlgrTimers(v) if v == &[(ipv4(), Duration::from_secs(7200))]
        ));
        assert!(matches!(gr.state, Inner::LlgrStaling { .. }));
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
        RestartingDeferral::new(map, Some(Duration::from_secs(360)))
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
            Some(RestartingOutput::StartDeferralTimer(Some(d))) if *d == Duration::from_secs(360)
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
        let complete = rd_complete_families(&outputs);
        assert!(complete.contains(&ipv4()));
        assert!(rd_end_deferral(&outputs).is_some());
        assert!(rd.is_completed());
    }

    #[test]
    fn rd_awaiting_withdraw_one_of_two_stays_awaiting() {
        let (mut rd, _) = make_deferral(&[(peer(1), vec![ipv4()]), (peer(2), vec![ipv4()])]);
        let outputs = rd.process(RestartingInput::PeerWithdrawn(peer(1)));
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
        let (mut rd, _) = make_deferral(&[(peer(1), vec![ipv4(), ipv6()])]);
        rd.process(RestartingInput::PeerEstablished(
            peer(1),
            vec![ipv4(), ipv6()],
        ));

        let outputs = rd.process(RestartingInput::PeerEstablished(peer(1), vec![ipv4()]));
        assert!(rd_complete_families(&outputs).contains(&ipv6()));
        assert!(matches!(rd.state, RestartingInner::Deferring { .. }));
    }
}
