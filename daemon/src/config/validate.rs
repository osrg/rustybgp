// Copyright (C) 2021 The RustyBGP Authors.
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

#![allow(dead_code)]
use crate::api;
use crate::config::*;
use crate::error::Error;

use regex::Regex;
use serde::Deserialize;
use std::convert::TryFrom;
use uuid::Uuid;

#[derive(Deserialize, Debug, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct BgpConfig {
    pub(crate) global: Option<Global>,
    pub(crate) neighbors: Option<Vec<Neighbor>>,
    #[serde(rename = "peer-groups")]
    pub(crate) peer_groups: Option<Vec<PeerGroup>>,
    #[serde(rename = "rpki-servers")]
    pub(crate) rpki_servers: Option<Vec<RpkiServer>>,
    #[serde(rename = "bmp-servers")]
    pub(crate) bmp_servers: Option<Vec<BmpServer>>,
    pub(crate) vrfs: Option<Vec<Vrf>>,
    #[serde(rename = "mrt-dump")]
    pub(crate) mrt_dump: Option<Vec<Mrt>>,
    pub(crate) zebra: Option<Zebra>,
    pub(crate) collector: Option<Collector>,
    #[serde(rename = "defined-sets")]
    pub(crate) defined_sets: Option<DefinedSets>,
    #[serde(rename = "policy-definitions")]
    pub(crate) policy_definitions: Option<Vec<PolicyDefinition>>,
    #[serde(rename = "dynamic-neighbors")]
    pub(crate) dynamic_neighbors: Option<Vec<DynamicNeighbor>>,
}

impl BgpConfig {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        let g =
            self.global.as_ref().take().ok_or_else(|| {
                Error::InvalidConfiguration("empty global configuration".to_string())
            })?;

        let global_config =
            g.config.as_ref().take().ok_or_else(|| {
                Error::InvalidConfiguration("empty global configuration".to_string())
            })?;

        let asn = global_config
            .r#as
            .as_ref()
            .take()
            .ok_or_else(|| Error::InvalidConfiguration("empty global as number".to_string()))?;
        if *asn == 0 {
            return Err(Error::InvalidConfiguration("zero as number".to_string()));
        }

        let router_id = global_config
            .router_id
            .as_ref()
            .take()
            .ok_or_else(|| Error::InvalidConfiguration("empty router-id".to_string()))?;
        let _: std::net::Ipv4Addr = router_id
            .parse()
            .map_err(|_| Error::InvalidConfiguration("can't parse router-id".to_string()))?;

        if let Some(peers) = self.neighbors.as_ref().take() {
            for n in peers {
                n.validate()?;
            }
        }

        if let Some(bmp_servers) = self.bmp_servers.as_ref().take() {
            for n in bmp_servers {
                n.validate()?;
            }
        }

        Ok(())
    }
}

impl BmpServer {
    fn validate(&self) -> Result<(), Error> {
        let config = self.config.as_ref().take().ok_or_else(|| {
            Error::InvalidConfiguration("empty bmp server configuration".to_string())
        })?;
        let addr = config
            .address
            .as_ref()
            .take()
            .ok_or_else(|| Error::InvalidConfiguration("empty bmp address".to_string()))?;
        let _: std::net::IpAddr = addr
            .parse()
            .map_err(|_| Error::InvalidConfiguration("can't parse neighbor address".to_string()))?;
        let port = config
            .port
            .as_ref()
            .take()
            .ok_or_else(|| Error::InvalidConfiguration("empty bmp port".to_string()))?;
        if *port > u16::MAX as u32 {
            return Err(Error::InvalidConfiguration(
                "port number is too big".to_string(),
            ));
        }
        if let Some(policy) = &config.route_monitoring_policy {
            if policy != &BmpRouteMonitoringPolicyType::PrePolicy {
                return Err(Error::InvalidConfiguration(
                    "unsupported monitoring policy".to_string(),
                ));
            }
        }
        Ok(())
    }
}

impl Neighbor {
    fn validate(&self) -> Result<(), Error> {
        let config =
            self.config.as_ref().take().ok_or_else(|| {
                Error::InvalidConfiguration("empty peer configuration".to_string())
            })?;

        let asn = config
            .peer_as
            .as_ref()
            .take()
            .ok_or_else(|| Error::InvalidConfiguration("empty peer as".to_string()))?;
        if *asn == 0 {
            return Err(Error::InvalidConfiguration("zero as number".to_string()));
        }

        let addr = config
            .neighbor_address
            .as_ref()
            .take()
            .ok_or_else(|| Error::InvalidConfiguration("empty neighbor address".to_string()))?;
        let _: std::net::IpAddr = addr
            .parse()
            .map_err(|_| Error::InvalidConfiguration("can't parse neighbor address".to_string()))?;

        Ok(())
    }
}

impl TryFrom<&PrefixSet> for api::DefinedSet {
    type Error = Error;

    fn try_from(p: &PrefixSet) -> Result<Self, Self::Error> {
        let name = p
            .prefix_set_name
            .as_ref()
            .ok_or_else(|| Error::InvalidConfiguration("empty name".to_string()))?
            .to_string();

        let mut prefixes = Vec::new();
        for s in p
            .prefix_list
            .as_ref()
            .ok_or_else(|| Error::InvalidConfiguration("empty prefix list".to_string()))?
        {
            let ip_prefix = s
                .ip_prefix
                .as_ref()
                .ok_or_else(|| Error::InvalidConfiguration("empty prefix".to_string()))?
                .to_string();
            let range = s
                .masklength_range
                .as_ref()
                .ok_or_else(|| Error::InvalidConfiguration("empty mask".to_string()))?;

            let caps = Regex::new(r"^([0-9]+)\.\.([0-9]+)$")
                .unwrap()
                .captures(range)
                .ok_or_else(|| Error::InvalidConfiguration("invalid mask format".to_string()))?;

            if caps.len() != 3 {
                return Err(Error::InvalidConfiguration(
                    "invalid prefix mask format".to_string(),
                ));
            }
            let mask_length_min = caps[1]
                .parse()
                .map_err(|_| Error::InvalidConfiguration("invalid mask format".to_string()))?;
            let mask_length_max = caps[2]
                .parse()
                .map_err(|_| Error::InvalidConfiguration("invalid mask format".to_string()))?;
            prefixes.push(api::Prefix {
                ip_prefix,
                mask_length_min,
                mask_length_max,
            });
        }

        Ok(api::DefinedSet {
            defined_type: api::DefinedType::Prefix as i32,
            name,
            list: Vec::new(),
            prefixes,
        })
    }
}

impl TryFrom<&BgpDefinedSets> for Vec<api::DefinedSet> {
    type Error = Error;

    fn try_from(sets: &BgpDefinedSets) -> Result<Self, Self::Error> {
        let mut v = Vec::new();
        if let Some(sets) = sets.as_path_sets.as_ref() {
            for set in sets {
                let name = set
                    .as_path_set_name
                    .as_ref()
                    .ok_or_else(|| Error::InvalidConfiguration("empty name".to_string()))?
                    .to_string();
                let list = set
                    .as_path_list
                    .as_ref()
                    .ok_or_else(|| Error::InvalidConfiguration("empty as path list".to_string()))?
                    .to_vec();
                v.push(api::DefinedSet {
                    defined_type: api::DefinedType::AsPath as i32,
                    name,
                    list,
                    prefixes: Vec::new(),
                })
            }
        }
        Ok(v)
    }
}

impl TryFrom<&DefinedSets> for Vec<api::DefinedSet> {
    type Error = Error;

    fn try_from(sets: &DefinedSets) -> Result<Self, Self::Error> {
        let mut v = Vec::new();
        if let Some(sets) = &sets.prefix_sets {
            for s in sets {
                v.push(api::DefinedSet::try_from(s)?);
            }
        }
        if let Some(sets) = &sets.bgp_defined_sets {
            v.append(&mut Vec::<api::DefinedSet>::try_from(sets)?);
        }
        Ok(v)
    }
}

impl From<&MatchSetOptionsType> for i32 {
    fn from(o: &MatchSetOptionsType) -> i32 {
        match o {
            MatchSetOptionsType::Any => 0,
            MatchSetOptionsType::All => 1,
            MatchSetOptionsType::Invert => 2,
        }
    }
}

impl From<&MatchSetOptionsRestrictedType> for i32 {
    fn from(o: &MatchSetOptionsRestrictedType) -> i32 {
        match o {
            MatchSetOptionsRestrictedType::Any => 0,
            MatchSetOptionsRestrictedType::Invert => 2,
        }
    }
}

impl From<&AttributeComparison> for i32 {
    fn from(c: &AttributeComparison) -> i32 {
        match c {
            AttributeComparison::AttributeEq => 0,
            AttributeComparison::AttributeGe => 1,
            AttributeComparison::AttributeLe => 2,
            AttributeComparison::Eq => 0,
            AttributeComparison::Ge => 1,
            AttributeComparison::Le => 2,
        }
    }
}

impl TryFrom<&Conditions> for api::Conditions {
    type Error = Error;

    fn try_from(c: &Conditions) -> Result<Self, Self::Error> {
        let mut conditions = api::Conditions {
            ..Default::default()
        };
        if let Some(set) = c.match_prefix_set.as_ref() {
            let name = set
                .prefix_set
                .as_ref()
                .ok_or_else(|| Error::InvalidConfiguration("empty name".to_string()))?
                .to_string();
            let set_option = set
                .match_set_options
                .as_ref()
                .ok_or_else(|| Error::InvalidConfiguration("empty match option".to_string()))?;
            conditions.prefix_set = Some(api::MatchSet {
                r#type: set_option.into(),
                name,
            });
        }

        if let Some(set) = c.bgp_conditions.as_ref() {
            if let Some(set) = set.match_as_path_set.as_ref() {
                let match_type = match &set.match_set_options {
                    Some(v) => v.into(),
                    None => 0,
                };
                if let Some(name) = &set.as_path_set {
                    conditions.as_path_set = Some(api::MatchSet {
                        r#type: match_type,
                        name: name.to_string(),
                    });
                }
            }
            if let Some(l) = set.as_path_length.as_ref() {
                let op = l.operator.as_ref().ok_or_else(|| {
                    Error::InvalidConfiguration("empty as path length operator".to_string())
                })?;
                let length = l.value.ok_or_else(|| {
                    Error::InvalidConfiguration("empty as path length".to_string())
                })?;
                conditions.as_path_length = Some(api::AsPathLength {
                    r#type: op.into(),
                    length,
                });
            }
        }
        Ok(conditions)
    }
}

impl From<&RouteDisposition> for i32 {
    fn from(r: &RouteDisposition) -> i32 {
        match r {
            RouteDisposition::None => 0,
            RouteDisposition::AcceptRoute => 1,
            RouteDisposition::RejectRoute => 2,
        }
    }
}

impl TryFrom<&Statement> for api::Statement {
    type Error = Error;

    fn try_from(s: &Statement) -> Result<Self, Self::Error> {
        let u = Uuid::new_v4().to_string();
        let name = match s.name.as_ref() {
            Some(n) => n.to_string(),
            None => u,
        };

        let conditions = if let Some(c) = &s.conditions {
            Some(api::Conditions::try_from(c)?)
        } else {
            None
        };

        let actions = s.actions.as_ref().map(|a| api::Actions {
            route_action: match a.route_disposition.as_ref() {
                Some(a) => a.into(),
                None => 0,
            },
            community: None,
            med: None,
            as_prepend: None,
            ext_community: None,
            nexthop: None,
            local_pref: None,
            large_community: None,
        });

        Ok(api::Statement {
            name,
            conditions,
            actions,
        })
    }
}

impl From<&DefaultPolicyType> for i32 {
    fn from(t: &DefaultPolicyType) -> i32 {
        match t {
            DefaultPolicyType::AcceptRoute => 1,
            DefaultPolicyType::RejectRoute => 2,
        }
    }
}
