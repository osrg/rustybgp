// Copyright (C) 2021-2022 The RustyBGP Authors.
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
use crate::generate::*;

use serde::Deserialize;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("invalid configuration: {0}")]
    InvalidConfiguration(String),
}

#[derive(Deserialize, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct BgpConfig {
    pub global: Option<Global>,
    pub neighbors: Option<Vec<Neighbor>>,
    #[serde(rename = "peer-groups")]
    pub peer_groups: Option<Vec<PeerGroup>>,
    #[serde(rename = "rpki-servers")]
    pub rpki_servers: Option<Vec<RpkiServer>>,
    #[serde(rename = "bmp-servers")]
    pub bmp_servers: Option<Vec<BmpServer>>,
    pub vrfs: Option<Vec<Vrf>>,
    #[serde(rename = "mrt-dump")]
    pub mrt_dump: Option<Vec<Mrt>>,
    pub zebra: Option<Zebra>,
    pub collector: Option<Collector>,
    #[serde(rename = "defined-sets")]
    pub defined_sets: Option<DefinedSets>,
    #[serde(rename = "policy-definitions")]
    pub policy_definitions: Option<Vec<PolicyDefinition>>,
    #[serde(rename = "dynamic-neighbors")]
    pub dynamic_neighbors: Option<Vec<DynamicNeighbor>>,
}

impl BgpConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        let g = self.global.as_ref().ok_or_else(|| {
            ConfigError::InvalidConfiguration("empty global configuration".to_string())
        })?;

        let global_config = g.config.as_ref().ok_or_else(|| {
            ConfigError::InvalidConfiguration("empty global configuration".to_string())
        })?;

        let asn = global_config.r#as.as_ref().ok_or_else(|| {
            ConfigError::InvalidConfiguration("empty global as number".to_string())
        })?;
        if *asn == 0 {
            return Err(ConfigError::InvalidConfiguration(
                "zero as number".to_string(),
            ));
        }

        let router_id = global_config
            .router_id
            .as_ref()
            .ok_or_else(|| ConfigError::InvalidConfiguration("empty router-id".to_string()))?;
        let _: std::net::Ipv4Addr = router_id
            .parse()
            .map_err(|_| ConfigError::InvalidConfiguration("can't parse router-id".to_string()))?;

        if let Some(peers) = self.neighbors.as_ref() {
            for n in peers {
                n.validate()?;
            }
        }

        if let Some(bmp_servers) = self.bmp_servers.as_ref() {
            for n in bmp_servers {
                n.validate()?;
            }
        }

        Ok(())
    }
}

impl BmpServer {
    fn validate(&self) -> Result<(), ConfigError> {
        let config = self.config.as_ref().ok_or_else(|| {
            ConfigError::InvalidConfiguration("empty bmp server configuration".to_string())
        })?;
        let addr = config
            .address
            .as_ref()
            .ok_or_else(|| ConfigError::InvalidConfiguration("empty bmp address".to_string()))?;
        let _: std::net::IpAddr = addr.parse().map_err(|_| {
            ConfigError::InvalidConfiguration("can't parse neighbor address".to_string())
        })?;
        let port = config
            .port
            .as_ref()
            .ok_or_else(|| ConfigError::InvalidConfiguration("empty bmp port".to_string()))?;
        if *port > u16::MAX as u32 {
            return Err(ConfigError::InvalidConfiguration(
                "port number is too big".to_string(),
            ));
        }
        if let Some(policy) = &config.route_monitoring_policy
            && policy != &BmpRouteMonitoringPolicyType::PrePolicy
        {
            return Err(ConfigError::InvalidConfiguration(
                "unsupported monitoring policy".to_string(),
            ));
        }
        Ok(())
    }
}

impl Neighbor {
    fn validate(&self) -> Result<(), ConfigError> {
        let config = self.config.as_ref().ok_or_else(|| {
            ConfigError::InvalidConfiguration("empty peer configuration".to_string())
        })?;

        let asn = config
            .peer_as
            .as_ref()
            .ok_or_else(|| ConfigError::InvalidConfiguration("empty peer as".to_string()))?;
        if *asn == 0 {
            return Err(ConfigError::InvalidConfiguration(
                "zero as number".to_string(),
            ));
        }

        let addr = config.neighbor_address.as_ref().ok_or_else(|| {
            ConfigError::InvalidConfiguration("empty neighbor address".to_string())
        })?;
        let _: std::net::IpAddr = addr.parse().map_err(|_| {
            ConfigError::InvalidConfiguration("can't parse neighbor address".to_string())
        })?;

        if self.add_paths.is_some() {
            return Err(ConfigError::InvalidConfiguration(
                "use per-family addpath config".to_string(),
            ));
        }

        // Validate per-family add-paths send_max
        if let Some(afi_safis) = self.afi_safis.as_ref() {
            for afi_safi in afi_safis {
                if let Some(ap) = afi_safi.add_paths.as_ref()
                    && let Some(c) = ap.config.as_ref()
                    && let Some(sm) = c.send_max
                    && sm > 32
                {
                    return Err(ConfigError::InvalidConfiguration(format!(
                        "send-max {} exceeds maximum of 32",
                        sm
                    )));
                }
            }
        }

        Ok(())
    }
}
