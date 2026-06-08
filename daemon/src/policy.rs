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

//! Import and export policy application.
//!
//! Pure logic — no async, no I/O.

use rustybgp_packet::bgp::Nexthop;
use rustybgp_table::{Disposition, PolicyAssignment};
use std::sync::Arc;

/// Apply import policy to a route and return whether it should be filtered
/// (rejected). Also applies any nexthop rewriting action.
pub(crate) fn apply_import(
    import_policy: Option<&PolicyAssignment>,
    source: &Arc<rustybgp_table::Source>,
    nlri: &rustybgp_packet::Nlri,
    attrs: &Arc<Vec<rustybgp_packet::Attribute>>,
    nexthop: &mut Nexthop,
) -> bool {
    import_policy.is_some_and(|a| {
        let mut attr = Arc::clone(attrs);
        rustybgp_table::Table::apply_policy(a, source, nlri, &mut attr, nexthop, source.local_addr)
            == Disposition::Reject
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustybgp_packet::bgp::Nexthop;
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

    // --- import policy tests ---

    #[test]
    fn import_no_policy_accepts() {
        let attrs = Arc::new(vec![
            packet::Attribute::new_with_value(packet::Attribute::ORIGIN, 0).unwrap(),
        ]);
        let mut nh = Nexthop::V4(Ipv4Addr::new(10, 0, 0, 1));
        let filtered = apply_import(
            None,
            &source(1),
            &packet::Nlri::from_str("10.0.0.0/24").unwrap(),
            &attrs,
            &mut nh,
        );
        assert!(!filtered);
    }

    #[test]
    fn import_rejected_by_policy() {
        let policy = reject_policy();
        let attrs = Arc::new(vec![
            packet::Attribute::new_with_value(packet::Attribute::ORIGIN, 0).unwrap(),
        ]);
        let mut nh = Nexthop::V4(Ipv4Addr::new(10, 0, 0, 1));
        let filtered = apply_import(
            Some(&policy),
            &source(1),
            &packet::Nlri::from_str("10.0.0.0/24").unwrap(),
            &attrs,
            &mut nh,
        );
        assert!(filtered);
    }
}
