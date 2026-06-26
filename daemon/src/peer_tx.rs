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

//! Outbound UPDATE batching for a BGP peer.
//!
//! Pure logic — no async, no I/O. Accumulates route changes and produces
//! BGP UPDATE messages ready for encoding.

use fnv::{FnvHashMap, FnvHashSet};
use rustybgp_packet::bgp::{self, Family, Nexthop};
use rustybgp_packet::{self as packet};
use std::sync::Arc;

type AttrKey = (Arc<Vec<packet::Attribute>>, Option<Nexthop>);

pub(crate) struct PendingTx {
    reach: FnvHashMap<packet::PathNlri, (Arc<Vec<packet::Attribute>>, Option<Nexthop>)>,
    unreach: FnvHashSet<packet::PathNlri>,
    pending_eor: bool,
    addpath_tx: bool,
    /// Pre-built UPDATE messages from the initial dump.  Drained first by
    /// `drain_messages()` before incremental reach/unreach processing.
    buffered: Vec<bgp::Message>,
}

impl PendingTx {
    pub(crate) fn new(addpath_tx: bool) -> Self {
        PendingTx {
            reach: FnvHashMap::default(),
            unreach: FnvHashSet::default(),
            pending_eor: false,
            addpath_tx,
            buffered: Vec::new(),
        }
    }

    pub(crate) fn addpath_tx(&self) -> bool {
        self.addpath_tx
    }

    /// Enqueue pre-built UPDATE messages from the initial dump.
    /// These are emitted before any incremental reach/unreach in `drain_messages()`.
    pub(crate) fn buffer_messages(&mut self, msgs: Vec<bgp::Message>) {
        self.buffered.extend(msgs);
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.buffered.is_empty() && self.reach.is_empty() && self.unreach.is_empty()
    }

    pub(crate) fn schedule_eor(&mut self) {
        self.pending_eor = true;
    }

    pub(crate) fn reach(
        &mut self,
        nlri: packet::Nlri,
        path_id: u32,
        nexthop: Option<Nexthop>,
        attr: Arc<Vec<packet::Attribute>>,
    ) {
        let key = packet::PathNlri {
            path_id: if self.addpath_tx { path_id } else { 0 },
            nlri,
        };
        self.unreach.remove(&key);
        self.reach.insert(key, (attr, nexthop));
    }

    pub(crate) fn unreach(&mut self, nlri: packet::Nlri, path_id: u32) {
        let key = packet::PathNlri {
            path_id: if self.addpath_tx { path_id } else { 0 },
            nlri,
        };
        self.reach.remove(&key);
        self.unreach.insert(key);
    }

    /// Drain pending changes into BGP UPDATE messages.
    ///
    /// Returns a list of UPDATE messages ready for encoding. The caller is
    /// responsible for encoding and writing them to the wire.
    pub(crate) fn drain_messages(&mut self, family: Family) -> Vec<bgp::Message> {
        // Start with pre-built messages from the initial dump (GroupedSink).
        let mut messages = std::mem::take(&mut self.buffered);

        // 1. Withdrawals
        if !self.unreach.is_empty() {
            let entries: Vec<packet::PathNlri> = self.unreach.drain().collect();
            messages.push(bgp::Message::Update(bgp::Update::Unreach {
                family,
                entries,
            }));
        }

        // 2. Reach updates: drain reach into a temporary (attr, nexthop) grouping,
        //    then emit one UPDATE per group.
        if !self.reach.is_empty() {
            let mut grouped: FnvHashMap<AttrKey, Vec<packet::PathNlri>> = FnvHashMap::default();
            for (key, (attr, nexthop)) in self.reach.drain() {
                grouped.entry((attr, nexthop)).or_default().push(key);
            }

            for ((attr, nexthop), entries) in grouped {
                messages.push(bgp::Message::Update(bgp::Update::Reach {
                    family,
                    entries,
                    nexthop,
                    attr,
                }));
            }
        }

        // EOR: reach and unreach are fully drained above, so emit EOR if scheduled.
        if self.pending_eor {
            self.pending_eor = false;
            messages.push(bgp::Message::eor(family));
        }

        messages
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    fn nlri(net: &str) -> packet::Nlri {
        packet::Nlri::from_str(net).unwrap()
    }

    fn attr(origin: u32) -> Arc<Vec<packet::Attribute>> {
        Arc::new(vec![
            packet::Attribute::new_with_value(packet::Attribute::ORIGIN, origin).unwrap(),
        ])
    }

    fn nh() -> Option<Nexthop> {
        Some(Nexthop::V4(Ipv4Addr::new(10, 0, 0, 1)))
    }

    #[test]
    fn insert_and_drain_reach() {
        let mut p = PendingTx::new(false);
        p.reach(nlri("10.0.0.0/24"), 0, nh(), attr(0));
        p.reach(nlri("20.0.0.0/24"), 0, nh(), attr(0));

        assert!(!p.is_empty());
        let msgs = p.drain_messages(Family::IPV4);
        // Same attributes → batched into 1 UPDATE
        assert_eq!(msgs.len(), 1);
        if let bgp::Message::Update(bgp::Update::Reach { entries, .. }) = &msgs[0] {
            assert_eq!(entries.len(), 2);
        } else {
            panic!("expected Update");
        }
        assert!(p.is_empty());
    }

    #[test]
    fn insert_and_drain_withdrawal() {
        let mut p = PendingTx::new(false);
        p.unreach(nlri("10.0.0.0/24"), 0);

        let msgs = p.drain_messages(Family::IPV4);
        // withdrawal
        assert_eq!(msgs.len(), 1);
        if let bgp::Message::Update(bgp::Update::Unreach { entries, .. }) = &msgs[0] {
            assert!(!entries.is_empty());
        } else {
            panic!("expected Update");
        }
        assert!(p.is_empty());
    }

    #[test]
    fn withdrawal_cancels_pending_reach() {
        let mut p = PendingTx::new(false);
        p.reach(nlri("10.0.0.0/24"), 0, nh(), attr(0));
        p.unreach(nlri("10.0.0.0/24"), 0);

        let msgs = p.drain_messages(Family::IPV4);
        // withdrawal
        assert_eq!(msgs.len(), 1);
        if let bgp::Message::Update(bgp::Update::Unreach { entries, .. }) = &msgs[0] {
            assert!(!entries.is_empty());
        } else {
            panic!("expected Update");
        }
    }

    #[test]
    fn different_attrs_separate_buckets() {
        let mut p = PendingTx::new(false);
        p.reach(nlri("10.0.0.0/24"), 0, nh(), attr(0)); // origin=IGP
        p.reach(nlri("20.0.0.0/24"), 0, nh(), attr(1)); // origin=EGP

        let msgs = p.drain_messages(Family::IPV4);
        // Different attributes → 2 UPDATEs
        assert_eq!(msgs.len(), 2);
    }

    #[test]
    fn same_attr_reinsert_is_noop() {
        let mut p = PendingTx::new(true);
        p.reach(nlri("10.0.0.0/24"), 1, nh(), attr(0));
        p.reach(nlri("20.0.0.0/24"), 1, nh(), attr(0));

        // Re-insert 20.0.0.0/24 with same attr → no duplicate in drain
        p.reach(nlri("20.0.0.0/24"), 1, nh(), attr(0));

        let msgs = p.drain_messages(Family::IPV4);
        // 1 UPDATE (both prefixes, same attr)
        assert_eq!(msgs.len(), 1);
        if let bgp::Message::Update(bgp::Update::Reach { entries, .. }) = &msgs[0] {
            assert_eq!(entries.len(), 2);
        } else {
            panic!("expected reach Update");
        }
    }

    #[test]
    fn attr_update_moves_between_buckets() {
        let mut p = PendingTx::new(true);
        p.reach(nlri("10.0.0.0/24"), 1, nh(), attr(0)); // origin=IGP
        p.reach(nlri("20.0.0.0/24"), 1, nh(), attr(0)); // origin=IGP

        // Change 20.0.0.0/24 to origin=EGP → separate UPDATE
        p.reach(nlri("20.0.0.0/24"), 1, nh(), attr(1));

        // Drain and verify: 2 UPDATEs with correct NLRIs
        let msgs = p.drain_messages(Family::IPV4);
        let mut origins: Vec<u32> = Vec::new();
        for msg in &msgs {
            if let bgp::Message::Update(bgp::Update::Reach { entries, attr, .. }) = msg
                && !entries.is_empty()
            {
                let origin = attr
                    .iter()
                    .find(|a| a.code() == packet::Attribute::ORIGIN)
                    .and_then(|a| a.value())
                    .unwrap();
                origins.push(origin);
            }
        }
        origins.sort();
        assert_eq!(origins, vec![0, 1]); // both IGP and EGP present
    }

    #[test]
    fn withdraw_then_readvertise() {
        let mut p = PendingTx::new(false);
        p.reach(nlri("10.0.0.0/24"), 0, nh(), attr(0));
        p.unreach(nlri("10.0.0.0/24"), 0);
        p.reach(nlri("10.0.0.0/24"), 0, nh(), attr(0));

        // The final state is a reach (withdrawal was cancelled by re-advertisement)
        let msgs = p.drain_messages(Family::IPV4);
        assert!(msgs
            .iter()
            .any(|m| matches!(m, bgp::Message::Update(bgp::Update::Reach { entries, .. }) if !entries.is_empty())));
        assert!(
            !msgs
                .iter()
                .any(|m| matches!(m, bgp::Message::Update(bgp::Update::Unreach { .. })))
        );
    }

    #[test]
    fn eor_generated_when_empty() {
        let mut p = PendingTx::new(false);
        // No auto-EOR: new() starts with pending_eor=false
        assert!(p.drain_messages(Family::IPV4).is_empty());
        // schedule_eor causes EOR to be emitted
        p.schedule_eor();
        let msgs = p.drain_messages(Family::IPV4);
        assert_eq!(msgs.len(), 1);
        assert!(
            matches!(
                &msgs[0],
                bgp::Message::Update(bgp::Update::EndOfRib(Family::IPV4))
            ),
            "expected EndOfRib(IPV4)"
        );
        // Not generated again
        let msgs = p.drain_messages(Family::IPV4);
        assert!(msgs.is_empty());
    }

    #[test]
    fn eor_follows_last_reach() {
        let mut p = PendingTx::new(false);
        p.reach(nlri("10.0.0.0/24"), 0, nh(), attr(0));
        p.schedule_eor();
        // Drain produces reach UPDATE + EOR
        let msgs = p.drain_messages(Family::IPV4);
        assert_eq!(msgs.len(), 2);
        // First: reach
        if let bgp::Message::Update(bgp::Update::Reach { entries, .. }) = &msgs[0] {
            assert!(!entries.is_empty());
        } else {
            panic!("expected reach Update");
        }
        // Second: EOR
        assert!(
            matches!(
                &msgs[1],
                bgp::Message::Update(bgp::Update::EndOfRib(Family::IPV4))
            ),
            "expected EndOfRib(IPV4)"
        );
    }

    #[test]
    fn same_attr_different_nexthop_separate_updates() {
        let mut p = PendingTx::new(false);
        let nh1 = Some(Nexthop::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let nh2 = Some(Nexthop::V4(Ipv4Addr::new(10, 0, 0, 2)));
        // Two NLRIs, same attr, different nexthop (MP families: nexthop not in attr)
        p.reach(nlri("10.0.0.0/24"), 0, nh1, attr(0));
        p.reach(nlri("20.0.0.0/24"), 0, nh2, attr(0));

        let msgs = p.drain_messages(Family::IPV4);
        // Must produce 2 separate Reach UPDATEs + EOR
        let reach_msgs: Vec<_> = msgs
            .iter()
            .filter(|m| matches!(m, bgp::Message::Update(bgp::Update::Reach { .. })))
            .collect();
        assert_eq!(reach_msgs.len(), 2, "expected 2 separate Reach UPDATEs");
        // Each UPDATE carries exactly one NLRI with the correct nexthop
        for m in reach_msgs {
            if let bgp::Message::Update(bgp::Update::Reach {
                entries, nexthop, ..
            }) = m
            {
                assert_eq!(entries.len(), 1);
                let nlri_str = format!("{}", entries[0].nlri);
                if nlri_str.contains("10.0.0.0") {
                    assert_eq!(*nexthop, nh1);
                } else {
                    assert_eq!(*nexthop, nh2);
                }
            }
        }
    }

    #[test]
    fn nexthop_change_updates_pending() {
        let mut p = PendingTx::new(false);
        let nh1 = Some(Nexthop::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let nh2 = Some(Nexthop::V4(Ipv4Addr::new(10, 0, 0, 2)));
        p.reach(nlri("10.0.0.0/24"), 0, nh1, attr(0));
        // Same attr, different nexthop — must not be a no-op
        p.reach(nlri("10.0.0.0/24"), 0, nh2, attr(0));

        let msgs = p.drain_messages(Family::IPV4);
        if let bgp::Message::Update(bgp::Update::Reach { nexthop, .. }) = &msgs[0] {
            assert_eq!(*nexthop, nh2);
        } else {
            panic!("expected reach Update");
        }
    }

    #[test]
    fn schedule_eor_triggers_again() {
        let mut p = PendingTx::new(false);
        // No auto-EOR: first drain returns empty
        assert!(p.drain_messages(Family::IPV4).is_empty());
        // schedule_eor causes EOR to be emitted
        p.schedule_eor();
        let msgs = p.drain_messages(Family::IPV4);
        assert_eq!(msgs.len(), 1);
        assert!(matches!(
            &msgs[0],
            bgp::Message::Update(bgp::Update::EndOfRib(Family::IPV4))
        ));
        // No EOR on subsequent drain
        assert!(p.drain_messages(Family::IPV4).is_empty());
        // schedule_eor causes EOR to be emitted again
        p.schedule_eor();
        let msgs = p.drain_messages(Family::IPV4);
        assert_eq!(msgs.len(), 1);
        assert!(matches!(
            &msgs[0],
            bgp::Message::Update(bgp::Update::EndOfRib(Family::IPV4))
        ));
    }

    #[test]
    fn addpath_false_normalizes_path_id_to_zero() {
        let mut p = PendingTx::new(false);
        // path_id=42 with addpath disabled → key is path_id=0
        p.reach(nlri("10.0.0.0/24"), 42, nh(), attr(0));
        // path_id=0 → same key, overwrites with attr(1)
        p.reach(nlri("10.0.0.0/24"), 0, nh(), attr(1));

        let msgs = p.drain_messages(Family::IPV4);
        let reach_msgs: Vec<_> = msgs
            .iter()
            .filter(|m| matches!(m, bgp::Message::Update(bgp::Update::Reach { .. })))
            .collect();
        // One entry, not two — both inserts hit the same key
        assert_eq!(reach_msgs.len(), 1);
        if let bgp::Message::Update(bgp::Update::Reach { entries, attr, .. }) = reach_msgs[0] {
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].path_id, 0);
            // attr(1) (the second insert) wins
            let origin: u32 = attr
                .iter()
                .find(|a| a.code() == packet::Attribute::ORIGIN)
                .and_then(|a| a.value())
                .unwrap();
            assert_eq!(origin, 1);
        } else {
            panic!("expected reach Update");
        }
    }

    #[test]
    fn addpath_different_path_ids_are_separate_entries() {
        let mut p = PendingTx::new(true);
        // Same NLRI, different path_ids → separate keys under Add-Path
        p.reach(nlri("10.0.0.0/24"), 1, nh(), attr(0));
        p.reach(nlri("10.0.0.0/24"), 2, nh(), attr(0));

        let msgs = p.drain_messages(Family::IPV4);
        let reach_msgs: Vec<_> = msgs
            .iter()
            .filter(|m| matches!(m, bgp::Message::Update(bgp::Update::Reach { .. })))
            .collect();
        // Same attr+nexthop → batched into 1 UPDATE with 2 path entries
        assert_eq!(reach_msgs.len(), 1);
        if let bgp::Message::Update(bgp::Update::Reach { entries, .. }) = reach_msgs[0] {
            assert_eq!(entries.len(), 2);
            let mut ids: Vec<u32> = entries.iter().map(|e| e.path_id).collect();
            ids.sort();
            assert_eq!(ids, vec![1, 2]);
        } else {
            panic!("expected reach Update");
        }
    }

    #[test]
    fn buffered_messages_drained_before_reach() {
        let mut p = PendingTx::new(false);
        p.drain_messages(Family::IPV4); // no-op (pending_eor starts false)
        // Simulate pre-built messages from GroupedSink (initial dump).
        p.buffer_messages(vec![bgp::Message::Update(bgp::Update::Reach {
            family: Family::IPV4,
            entries: vec![packet::PathNlri::new(nlri("10.0.0.0/24"))],
            nexthop: nh(),
            attr: attr(0),
        })]);
        // An incremental reach that arrived after the initial dump.
        p.reach(nlri("20.0.0.0/24"), 0, nh(), attr(0));

        let msgs = p.drain_messages(Family::IPV4);
        // buffered (10.0.0.0/24) must come before incremental (20.0.0.0/24).
        assert_eq!(msgs.len(), 2);
        let first_nlri = if let bgp::Message::Update(bgp::Update::Reach { entries, .. }) = &msgs[0]
        {
            entries[0].nlri.to_string()
        } else {
            panic!("expected Reach");
        };
        assert!(first_nlri.contains("10.0.0.0"), "buffered must be first");
    }

    #[test]
    fn buffered_emptied_after_drain() {
        let mut p = PendingTx::new(false);
        p.drain_messages(Family::IPV4); // no-op (pending_eor starts false)
        p.buffer_messages(vec![bgp::Message::Update(bgp::Update::Reach {
            family: Family::IPV4,
            entries: vec![packet::PathNlri::new(nlri("10.0.0.0/24"))],
            nexthop: nh(),
            attr: attr(0),
        })]);

        assert!(!p.is_empty());
        p.drain_messages(Family::IPV4);
        assert!(p.is_empty());
    }

    #[test]
    fn addpath_includes_path_id() {
        let mut p = PendingTx::new(true);
        p.reach(nlri("10.0.0.0/24"), 42, nh(), attr(0));

        let msgs = p.drain_messages(Family::IPV4);
        if let bgp::Message::Update(bgp::Update::Reach { entries, .. }) = &msgs[0] {
            assert_eq!(entries[0].path_id, 42);
        } else {
            panic!("expected Update");
        }
    }
}
