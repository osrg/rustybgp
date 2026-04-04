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

//! Export policy filtering and kernel route selection.
//!
//! Pure logic — no async, no I/O. Takes route changes from the routing table
//! and determines which should be advertised to peers and installed in the kernel.

use rustybgp_table::{Change, Disposition, PolicyAssignment, RoutingTable};

/// Apply export policy to route changes and return those that should
/// be advertised to peers.
///
/// - Withdrawal changes (empty attrs) always pass (RFC 4271 §9.1.3).
/// - Reach changes are filtered by `export_policy`; rejected ones are skipped.
/// - Nexthop may be rewritten by policy actions.
pub(crate) fn filter_changes(
    changes: Vec<Change>,
    export_policy: Option<&PolicyAssignment>,
    rtable: &RoutingTable,
) -> Vec<Change> {
    let mut peer_changes = Vec::with_capacity(changes.len());

    for mut change in changes {
        // Withdrawals are always propagated (RFC 4271 §9.1.3).
        if change.attr.is_empty() {
            peer_changes.push(change);
            continue;
        }

        // Apply export policy to reach changes.
        if let Some(policy) = export_policy
            && rtable.apply_policy(
                policy,
                &change.source,
                &change.net,
                &change.attr,
                &mut change.nexthop,
                change.source.local_addr,
            ) == Disposition::Reject
        {
            continue;
        }

        peer_changes.push(change);
    }

    peer_changes
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustybgp_packet::bgp::{self, Family, Nexthop};
    use rustybgp_packet::{self as packet};
    use rustybgp_table as table;
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;
    use std::sync::Arc;

    fn source(addr: u8) -> Arc<table::Source> {
        Arc::new(table::Source::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, addr)),
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            65001,
            65000,
            Ipv4Addr::new(10, 0, 0, addr),
            0,
            false,
        ))
    }

    fn reach_change(net: &str, rank: usize) -> Change {
        Change {
            source: source(1),
            family: Family::IPV4,
            net: packet::Nlri::from_str(net).unwrap(),
            nexthop: Nexthop::V4(Ipv4Addr::new(10, 0, 0, 1)),
            attr: Arc::new(vec![
                packet::Attribute::new_with_value(packet::Attribute::ORIGIN, 0).unwrap(),
            ]),
            path_id: 0,
            rank,
            old_rank: 0,
        }
    }

    fn withdrawal_change(net: &str, rank: usize) -> Change {
        Change {
            source: source(1),
            family: Family::IPV4,
            net: packet::Nlri::from_str(net).unwrap(),
            nexthop: Nexthop::V4(Ipv4Addr::new(10, 0, 0, 1)),
            attr: Arc::new(Vec::new()),
            path_id: 0,
            rank,
            old_rank: 1,
        }
    }

    fn reject_policy() -> Arc<PolicyAssignment> {
        let mut ptable = table::PolicyTable::new();
        ptable
            .add_defined_set(table::DefinedSetConfig::Prefix {
                name: "all".to_string(),
                prefixes: vec![table::PrefixConfig {
                    ip_prefix: "0.0.0.0/0".to_string(),
                    mask_length_min: 0,
                    mask_length_max: 32,
                }],
            })
            .unwrap();
        ptable
            .add_statement(
                "reject-all",
                vec![table::ConditionConfig::PrefixSet(
                    "all".to_string(),
                    table::MatchOption::Any,
                )],
                Some(Disposition::Reject),
                table::Actions::default(),
            )
            .unwrap();
        ptable
            .add_policy("reject-policy", vec!["reject-all".to_string()])
            .unwrap();
        let (_, assignment) = ptable
            .add_assignment(
                "global",
                table::PolicyDirection::Export,
                Disposition::Accept,
                vec!["reject-policy".to_string()],
            )
            .unwrap();
        assignment
    }

    fn nexthop_self_policy() -> Arc<PolicyAssignment> {
        let mut ptable = table::PolicyTable::new();
        ptable
            .add_defined_set(table::DefinedSetConfig::Prefix {
                name: "all".to_string(),
                prefixes: vec![table::PrefixConfig {
                    ip_prefix: "0.0.0.0/0".to_string(),
                    mask_length_min: 0,
                    mask_length_max: 32,
                }],
            })
            .unwrap();
        ptable
            .add_statement(
                "nexthop-self",
                vec![table::ConditionConfig::PrefixSet(
                    "all".to_string(),
                    table::MatchOption::Any,
                )],
                Some(Disposition::Accept),
                table::Actions {
                    nexthop: Some(table::NexthopAction::PeerSelf),
                },
            )
            .unwrap();
        ptable
            .add_policy("nh-self-policy", vec!["nexthop-self".to_string()])
            .unwrap();
        let (_, assignment) = ptable
            .add_assignment(
                "global",
                table::PolicyDirection::Export,
                Disposition::Accept,
                vec!["nh-self-policy".to_string()],
            )
            .unwrap();
        assignment
    }

    #[test]
    fn reach_passes_without_policy() {
        let rtable = RoutingTable::new();
        let changes = vec![reach_change("10.0.0.0/24", 1)];
        let result = filter_changes(changes, None, &rtable);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn reach_rejected_by_export_policy() {
        let rtable = RoutingTable::new();
        let policy = reject_policy();
        let changes = vec![reach_change("10.0.0.0/24", 1)];
        let result = filter_changes(changes, Some(&policy), &rtable);
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn withdrawal_always_propagated() {
        let rtable = RoutingTable::new();
        let policy = reject_policy();
        let changes = vec![withdrawal_change("10.0.0.0/24", 1)];
        let result = filter_changes(changes, Some(&policy), &rtable);
        assert_eq!(result.len(), 1);
        assert!(result[0].attr.is_empty());
    }

    #[test]
    fn no_policy_passes_all() {
        let rtable = RoutingTable::new();
        let changes = vec![
            reach_change("10.0.0.0/24", 1),
            reach_change("20.0.0.0/24", 2),
            withdrawal_change("30.0.0.0/24", 1),
        ];
        let result = filter_changes(changes, None, &rtable);
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn nexthop_rewritten_by_policy() {
        let rtable = RoutingTable::new();
        let policy = nexthop_self_policy();
        let changes = vec![reach_change("10.0.0.0/24", 1)];
        let result = filter_changes(changes, Some(&policy), &rtable);
        assert_eq!(result.len(), 1);
        // local_addr in source is 1.1.1.1 → nexthop should be rewritten to self
        assert_eq!(result[0].nexthop, Nexthop::V4(Ipv4Addr::new(1, 1, 1, 1)));
    }
}
