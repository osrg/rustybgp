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

/// Key for PendingTx maps: (NLRI, path_id). path_id distinguishes
/// multiple paths for the same prefix under RFC 7911 Add-Path.
#[allow(dead_code)]
type PendingKey = (packet::Nlri, u32);

/// Maximum number of UPDATE messages produced per drain_messages() call.
#[allow(dead_code)]
const MAX_TX_COUNT: usize = 2048;

#[allow(dead_code)]
pub(crate) struct PendingTx {
    reach: FnvHashMap<PendingKey, (Arc<Vec<packet::Attribute>>, Nexthop)>,
    unreach: FnvHashSet<PendingKey>,
    bucket: FnvHashMap<Arc<Vec<packet::Attribute>>, FnvHashSet<PendingKey>>,
    pending_eor: bool,
    addpath_tx: bool,
}

#[allow(dead_code)]
impl PendingTx {
    pub(crate) fn new(addpath_tx: bool) -> Self {
        PendingTx {
            reach: FnvHashMap::default(),
            unreach: FnvHashSet::default(),
            bucket: FnvHashMap::default(),
            pending_eor: true,
            addpath_tx,
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.reach.is_empty() && self.unreach.is_empty()
    }

    pub(crate) fn insert_change(&mut self, change: rustybgp_table::Change) {
        let pid = if self.addpath_tx { change.path_id } else { 0 };
        let key: PendingKey = (change.net, pid);
        if change.attr.is_empty() {
            if let Some((attr, _)) = self.reach.remove(&key) {
                let set = self.bucket.get_mut(&attr).unwrap();
                let b = set.remove(&key);
                assert!(b);
                if set.is_empty() {
                    self.bucket.remove(&attr);
                }
            }
            self.unreach.insert(key);
        } else {
            self.unreach.remove(&key);

            if let Some((old_attr, _)) = self
                .reach
                .insert(key, (change.attr.clone(), change.nexthop))
            {
                // b-1) same attr → no-op
                if old_attr == change.attr {
                    return;
                }

                // b-2) different attr → move between buckets
                let old_bucket = self.bucket.get_mut(&old_attr).unwrap();
                let b = old_bucket.remove(&key);
                assert!(b);
                if old_bucket.is_empty() {
                    self.bucket.remove(&old_attr);
                }

                let bucket = self.bucket.entry(change.attr).or_default();
                bucket.insert(key);
            } else {
                // a) new key
                let bucket = self.bucket.entry(change.attr).or_default();
                bucket.insert(key);
            }
        }
    }

    /// Drain pending changes into BGP UPDATE messages.
    ///
    /// `family` is the address family for this PendingTx.
    /// `addpath_tx` controls whether path_id is included in NLRI encoding.
    /// `use_mp` controls whether IPv4 uses MP_REACH (RFC 8950 extended nexthop).
    ///
    /// Returns a list of UPDATE messages ready for encoding. The caller is
    /// responsible for encoding and writing them to the wire.
    pub(crate) fn drain_messages(&mut self, family: Family, use_mp: bool) -> Vec<bgp::Message> {
        let mut messages = Vec::new();

        // 1. Withdrawals
        if !self.unreach.is_empty() {
            let unreach: Vec<packet::PathNlri> = self
                .unreach
                .drain()
                .map(|(nlri, pid)| packet::PathNlri {
                    path_id: if self.addpath_tx { pid } else { 0 },
                    nlri,
                })
                .collect();
            messages.push(bgp::Message::Update(bgp::Update {
                reach: None,
                mp_reach: None,
                attr: Arc::new(Vec::new()),
                unreach: None,
                mp_unreach: Some(packet::NlriSet {
                    family,
                    entries: unreach,
                }),
                nexthop: None,
            }));
        }

        // 2. Reach updates (batched by attribute)
        let mut sent_attrs: Vec<Arc<Vec<packet::Attribute>>> = Vec::new();
        let mut count = 0;

        for (attr, keys) in self.bucket.iter() {
            let nlri_set = packet::NlriSet {
                family,
                entries: keys
                    .iter()
                    .copied()
                    .map(|(nlri, pid)| packet::PathNlri {
                        path_id: if self.addpath_tx { pid } else { 0 },
                        nlri,
                    })
                    .collect(),
            };
            // Look up nexthop from the first entry in this bucket
            let nexthop = keys
                .iter()
                .next()
                .and_then(|k| self.reach.get(k).map(|(_, nh)| *nh));

            let (reach, mp_reach) = if use_mp {
                (None, Some(nlri_set))
            } else {
                (Some(nlri_set), None)
            };
            messages.push(bgp::Message::Update(bgp::Update {
                reach,
                mp_reach,
                attr: attr.clone(),
                unreach: None,
                mp_unreach: None,
                nexthop,
            }));
            sent_attrs.push(attr.clone());

            count += 1;
            if count >= MAX_TX_COUNT {
                break;
            }
        }

        // Remove sent entries from pending maps
        for attr in sent_attrs {
            if let Some(mut keys) = self.bucket.remove(&attr) {
                for key in keys.drain() {
                    self.reach.remove(&key);
                }
            }
        }

        // EOR: once all initial routes have been drained, append End-of-RIB
        if self.pending_eor && self.is_empty() {
            self.pending_eor = false;
            messages.push(bgp::Message::eor(family));
        }

        messages
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustybgp_table as table;
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;

    fn src() -> Arc<table::Source> {
        Arc::new(table::Source::new(
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
            1,
            2,
            Ipv4Addr::new(127, 0, 0, 1),
            0,
            false,
        ))
    }

    fn change(net: &str, path_id: u32, origin: u32, withdraw: bool) -> table::Change {
        table::Change {
            source: src(),
            family: Family::IPV4,
            net: packet::Nlri::from_str(net).unwrap(),
            nexthop: Nexthop::V4(Ipv4Addr::new(10, 0, 0, 1)),
            attr: if withdraw {
                Arc::new(Vec::new())
            } else {
                Arc::new(vec![
                    packet::Attribute::new_with_value(packet::Attribute::ORIGIN, origin).unwrap(),
                ])
            },
            path_id,
            rank: 1,
            old_rank: 0,
        }
    }

    #[test]
    fn insert_and_drain_reach() {
        let mut p = PendingTx::new(false);
        p.insert_change(change("10.0.0.0/24", 0, 0, false));
        p.insert_change(change("20.0.0.0/24", 0, 0, false));

        assert!(!p.is_empty());
        let msgs = p.drain_messages(Family::IPV4, false);
        // Same attributes → batched into 1 UPDATE + EOR
        assert_eq!(msgs.len(), 2);
        if let bgp::Message::Update(u) = &msgs[0] {
            assert!(u.reach.is_some());
            assert_eq!(u.reach.as_ref().unwrap().entries.len(), 2);
        } else {
            panic!("expected Update");
        }
        assert!(p.is_empty());
    }

    #[test]
    fn insert_and_drain_withdrawal() {
        let mut p = PendingTx::new(false);
        p.insert_change(change("10.0.0.0/24", 0, 0, true));

        let msgs = p.drain_messages(Family::IPV4, false);
        // withdrawal + EOR
        assert_eq!(msgs.len(), 2);
        if let bgp::Message::Update(u) = &msgs[0] {
            assert!(u.mp_unreach.is_some());
        } else {
            panic!("expected Update");
        }
        assert!(p.is_empty());
    }

    #[test]
    fn withdrawal_cancels_pending_reach() {
        let mut p = PendingTx::new(false);
        p.insert_change(change("10.0.0.0/24", 0, 0, false));
        p.insert_change(change("10.0.0.0/24", 0, 0, true));

        let msgs = p.drain_messages(Family::IPV4, false);
        // withdrawal + EOR
        assert_eq!(msgs.len(), 2);
        if let bgp::Message::Update(u) = &msgs[0] {
            assert!(u.mp_unreach.is_some());
            assert!(u.reach.is_none());
        } else {
            panic!("expected Update");
        }
    }

    #[test]
    fn different_attrs_separate_buckets() {
        let mut p = PendingTx::new(false);
        p.insert_change(change("10.0.0.0/24", 0, 0, false)); // origin=IGP
        p.insert_change(change("20.0.0.0/24", 0, 1, false)); // origin=EGP

        let msgs = p.drain_messages(Family::IPV4, false);
        // Different attributes → 2 UPDATEs + EOR
        assert_eq!(msgs.len(), 3);
    }

    #[test]
    fn attr_update_moves_between_buckets() {
        let mut p = PendingTx::new(true);
        p.insert_change(change("10.0.0.0/24", 1, 0, false));
        p.insert_change(change("20.0.0.0/24", 1, 0, false));
        assert_eq!(p.bucket.len(), 1);

        // Change 20.0.0.0/24 to different origin → moves to new bucket
        p.insert_change(change("20.0.0.0/24", 1, 1, false));
        assert_eq!(p.bucket.len(), 2);
    }

    #[test]
    fn eor_generated_when_empty() {
        let mut p = PendingTx::new(false);
        let msgs = p.drain_messages(Family::IPV4, false);
        assert_eq!(msgs.len(), 1);
        // Should be an EOR (empty UPDATE with reach for IPv4)
        if let bgp::Message::Update(u) = &msgs[0] {
            assert!(u.reach.as_ref().is_some_and(|r| r.entries.is_empty()));
        } else {
            panic!("expected EOR Update");
        }

        // Not generated again
        let msgs = p.drain_messages(Family::IPV4, false);
        assert!(msgs.is_empty());
    }

    #[test]
    fn eor_follows_last_reach() {
        let mut p = PendingTx::new(false);
        p.insert_change(change("10.0.0.0/24", 0, 0, false));
        // Drain produces reach UPDATE + EOR
        let msgs = p.drain_messages(Family::IPV4, false);
        assert_eq!(msgs.len(), 2);
        // First: reach
        if let bgp::Message::Update(u) = &msgs[0] {
            assert!(u.reach.as_ref().is_some_and(|r| !r.entries.is_empty()));
        } else {
            panic!("expected reach Update");
        }
        // Second: EOR
        if let bgp::Message::Update(u) = &msgs[1] {
            assert!(u.reach.as_ref().is_some_and(|r| r.entries.is_empty()));
        } else {
            panic!("expected EOR Update");
        }
    }

    #[test]
    fn use_mp_routes_through_mp_reach() {
        let mut p = PendingTx::new(false);
        p.insert_change(change("10.0.0.0/24", 0, 0, false));

        let msgs = p.drain_messages(Family::IPV4, true);
        // reach via MP_REACH + EOR
        assert_eq!(msgs.len(), 2);
        if let bgp::Message::Update(u) = &msgs[0] {
            assert!(u.reach.is_none());
            assert!(u.mp_reach.is_some());
        } else {
            panic!("expected Update");
        }
    }

    #[test]
    fn addpath_includes_path_id() {
        let mut p = PendingTx::new(true);
        p.insert_change(change("10.0.0.0/24", 42, 0, false));

        let msgs = p.drain_messages(Family::IPV4, false);
        if let bgp::Message::Update(u) = &msgs[0] {
            assert_eq!(u.reach.as_ref().unwrap().entries[0].path_id, 42);
        } else {
            panic!("expected Update");
        }
    }
}
