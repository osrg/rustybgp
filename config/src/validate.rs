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

        let _router_id = global_config
            .router_id
            .as_ref()
            .ok_or_else(|| ConfigError::InvalidConfiguration("empty router-id".to_string()))?;

        if let Some(peers) = self.neighbors.as_ref() {
            for n in peers {
                n.validate()?;
            }
        }

        if let Some(peer_groups) = self.peer_groups.as_ref() {
            for pg in peer_groups {
                pg.validate()?;
            }
        }

        if let Some(bmp_servers) = self.bmp_servers.as_ref() {
            for n in bmp_servers {
                n.validate()?;
            }
        }

        if let Some(vrfs) = self.vrfs.as_ref() {
            for v in vrfs {
                v.validate()?;
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
        let _addr = config
            .address
            .as_ref()
            .ok_or_else(|| ConfigError::InvalidConfiguration("empty bmp address".to_string()))?;
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

impl Vrf {
    fn validate(&self) -> Result<(), ConfigError> {
        let name = self
            .config
            .as_ref()
            .and_then(|c| c.name.as_deref())
            .unwrap_or("");
        if name.is_empty() {
            return Err(ConfigError::InvalidConfiguration(
                "vrf name is empty".to_string(),
            ));
        }
        Ok(())
    }
}

/// RFC 4271 §4.2: hold time is a 2-byte field.  Valid values are 0
/// (disabled) or 3–65535.  Values 1 and 2 are explicitly forbidden.
fn validate_hold_time(hold_time: f64) -> Result<(), ConfigError> {
    if hold_time != 0.0 && !(3.0..=65535.0).contains(&hold_time) {
        return Err(ConfigError::InvalidConfiguration(format!(
            "hold-time {hold_time} is invalid: must be 0 or 3-65535"
        )));
    }
    Ok(())
}

/// RFC 4724 §3: restart_time is a 12-bit field in the OPEN message.
/// Values 0–4095 are valid; larger values cannot be encoded.
fn validate_gr_restart_time(restart_time: u16) -> Result<(), ConfigError> {
    if restart_time > 4095 {
        return Err(ConfigError::InvalidConfiguration(format!(
            "graceful-restart restart-time {restart_time} exceeds maximum of 4095"
        )));
    }
    Ok(())
}

/// The Linux TCP_MD5SIG key buffer is 80 bytes; passwords longer than that
/// cannot be set via setsockopt and must be rejected.
fn validate_auth_password(password: &str) -> Result<(), ConfigError> {
    if password.len() > 80 {
        return Err(ConfigError::InvalidConfiguration(format!(
            "auth-password length {} exceeds maximum of 80 bytes",
            password.len()
        )));
    }
    Ok(())
}

/// RFC 9494 §3: the LLGR stale time is a 24-bit field in the capability.
/// Values 0-16777215 (0xFF_FFFF) are valid.
fn validate_llgr_stale_time(stale_time: u32) -> Result<(), ConfigError> {
    if stale_time > 0xFF_FFFF {
        return Err(ConfigError::InvalidConfiguration(format!(
            "long-lived-graceful-restart restart-time {stale_time} exceeds maximum of 16777215"
        )));
    }
    Ok(())
}

impl Neighbor {
    fn validate(&self) -> Result<(), ConfigError> {
        let config = self.config.as_ref().ok_or_else(|| {
            ConfigError::InvalidConfiguration("empty peer configuration".to_string())
        })?;

        // Unnumbered BGP peers (RFC 7938) identify the peer by interface name
        // rather than by address+AS.  Skip address/AS validation for them.
        if config.neighbor_interface.is_some() {
            return Ok(());
        }

        // Peers in a peer group may omit peer_as (ASN=0) and inherit the AS
        // from the group; peer_as=0 is also valid when the group accepts any AS.
        if config.peer_group.is_none() {
            let asn = config
                .peer_as
                .as_ref()
                .ok_or_else(|| ConfigError::InvalidConfiguration("empty peer as".to_string()))?;
            if *asn == 0 {
                return Err(ConfigError::InvalidConfiguration(
                    "zero as number".to_string(),
                ));
            }
        }

        let addr = config.neighbor_address.as_ref().ok_or_else(|| {
            ConfigError::InvalidConfiguration("empty neighbor address".to_string())
        })?;

        if let Some(h) = self
            .timers
            .as_ref()
            .and_then(|t| t.config.as_ref())
            .and_then(|c| c.hold_time)
        {
            validate_hold_time(h)?;
        }

        if let Some(rt) = self
            .graceful_restart
            .as_ref()
            .and_then(|gr| gr.config.as_ref())
            .and_then(|c| c.restart_time)
        {
            validate_gr_restart_time(rt)?;
        }

        if let Some(afi_safis) = self.afi_safis.as_ref() {
            for a in afi_safis {
                if let Some(st) = a
                    .long_lived_graceful_restart
                    .as_ref()
                    .and_then(|llgr| llgr.config.as_ref())
                    .and_then(|c| c.restart_time)
                {
                    validate_llgr_stale_time(st)?;
                }
            }
        }

        if let Some(pw) = config.auth_password.as_deref().filter(|s| !s.is_empty()) {
            validate_auth_password(pw)?;
        }

        if self.add_paths.is_some() {
            return Err(ConfigError::InvalidConfiguration(
                "use per-family addpath config".to_string(),
            ));
        }

        if self.apply_policy.is_some() {
            return Err(ConfigError::InvalidConfiguration(format!(
                "neighbor {}: per-neighbor apply-policy is not supported; configure policy under global",
                addr
            )));
        }

        Ok(())
    }
}

impl PeerGroup {
    fn validate(&self) -> Result<(), ConfigError> {
        if let Some(h) = self
            .timers
            .as_ref()
            .and_then(|t| t.config.as_ref())
            .and_then(|c| c.hold_time)
        {
            validate_hold_time(h)?;
        }
        if let Some(rt) = self
            .graceful_restart
            .as_ref()
            .and_then(|gr| gr.config.as_ref())
            .and_then(|c| c.restart_time)
        {
            validate_gr_restart_time(rt)?;
        }
        if let Some(afi_safis) = self.afi_safis.as_ref() {
            for a in afi_safis {
                if let Some(st) = a
                    .long_lived_graceful_restart
                    .as_ref()
                    .and_then(|llgr| llgr.config.as_ref())
                    .and_then(|c| c.restart_time)
                {
                    validate_llgr_stale_time(st)?;
                }
            }
        }
        if let Some(pw) = self
            .config
            .as_ref()
            .and_then(|c| c.auth_password.as_deref())
            .filter(|s| !s.is_empty())
        {
            validate_auth_password(pw)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_global() -> Global {
        Global {
            config: Some(GlobalConfig {
                r#as: Some(65001),
                router_id: Some(std::net::Ipv4Addr::new(10, 0, 0, 1)),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn neighbor(peer_group: Option<&str>, peer_as: Option<u32>, addr: Option<&str>) -> Neighbor {
        Neighbor {
            config: Some(NeighborConfig {
                peer_group: peer_group.map(str::to_string),
                peer_as,
                neighbor_address: addr.and_then(|a| a.parse().ok()),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn neighbor_in_peer_group_missing_peer_as_passes() {
        assert!(
            neighbor(Some("grp"), None, Some("10.0.0.1"))
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn neighbor_in_peer_group_zero_peer_as_passes() {
        assert!(
            neighbor(Some("grp"), Some(0), Some("10.0.0.1"))
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn neighbor_without_peer_group_missing_peer_as_fails() {
        assert!(neighbor(None, None, Some("10.0.0.1")).validate().is_err());
    }

    #[test]
    fn neighbor_without_peer_group_zero_peer_as_fails() {
        assert!(
            neighbor(None, Some(0), Some("10.0.0.1"))
                .validate()
                .is_err()
        );
    }

    #[test]
    fn bgp_config_with_peer_group_zero_peer_as_passes() {
        let cfg = BgpConfig {
            global: Some(valid_global()),
            neighbors: Some(vec![neighbor(Some("grp"), Some(0), Some("10.0.0.1"))]),
            ..Default::default()
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn bgp_config_with_peer_group_missing_peer_as_passes() {
        let cfg = BgpConfig {
            global: Some(valid_global()),
            neighbors: Some(vec![neighbor(Some("grp"), None, Some("10.0.0.1"))]),
            ..Default::default()
        };
        assert!(cfg.validate().is_ok());
    }

    fn neighbor_with_hold_time(peer_as: u32, hold_time: f64) -> Neighbor {
        Neighbor {
            config: Some(NeighborConfig {
                neighbor_address: Some("10.0.0.1".parse().unwrap()),
                peer_as: Some(peer_as),
                ..Default::default()
            }),
            timers: Some(Timers {
                config: Some(TimersConfig {
                    hold_time: Some(hold_time),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn peer_group_with_hold_time(hold_time: f64) -> PeerGroup {
        PeerGroup {
            timers: Some(Timers {
                config: Some(TimersConfig {
                    hold_time: Some(hold_time),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    // --- hold_time: Neighbor ---

    #[test]
    fn neighbor_hold_time_zero_passes() {
        assert!(neighbor_with_hold_time(65001, 0.0).validate().is_ok());
    }

    #[test]
    fn neighbor_hold_time_3_passes() {
        assert!(neighbor_with_hold_time(65001, 3.0).validate().is_ok());
    }

    #[test]
    fn neighbor_hold_time_65535_passes() {
        assert!(neighbor_with_hold_time(65001, 65535.0).validate().is_ok());
    }

    #[test]
    fn neighbor_hold_time_1_fails() {
        assert!(neighbor_with_hold_time(65001, 1.0).validate().is_err());
    }

    #[test]
    fn neighbor_hold_time_2_fails() {
        assert!(neighbor_with_hold_time(65001, 2.0).validate().is_err());
    }

    #[test]
    fn neighbor_hold_time_65536_fails() {
        assert!(neighbor_with_hold_time(65001, 65536.0).validate().is_err());
    }

    // --- hold_time: PeerGroup ---

    #[test]
    fn peer_group_hold_time_90_passes() {
        assert!(peer_group_with_hold_time(90.0).validate().is_ok());
    }

    #[test]
    fn peer_group_hold_time_2_fails() {
        assert!(peer_group_with_hold_time(2.0).validate().is_err());
    }

    #[test]
    fn peer_group_hold_time_65536_fails() {
        assert!(peer_group_with_hold_time(65536.0).validate().is_err());
    }

    // --- BgpConfig: peer_groups hold_time propagated ---

    #[test]
    fn bgp_config_peer_group_invalid_hold_time_fails() {
        let cfg = BgpConfig {
            global: Some(valid_global()),
            peer_groups: Some(vec![peer_group_with_hold_time(1.0)]),
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    // --- graceful_restart restart_time ---

    fn neighbor_with_gr_restart_time(peer_as: u32, restart_time: u16) -> Neighbor {
        Neighbor {
            config: Some(NeighborConfig {
                neighbor_address: Some("10.0.0.1".parse().unwrap()),
                peer_as: Some(peer_as),
                ..Default::default()
            }),
            graceful_restart: Some(GracefulRestart {
                config: Some(GracefulRestartConfig {
                    restart_time: Some(restart_time),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn peer_group_with_gr_restart_time(restart_time: u16) -> PeerGroup {
        PeerGroup {
            graceful_restart: Some(GracefulRestart {
                config: Some(GracefulRestartConfig {
                    restart_time: Some(restart_time),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn neighbor_gr_restart_time_4095_passes() {
        assert!(
            neighbor_with_gr_restart_time(65001, 4095)
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn neighbor_gr_restart_time_0_passes() {
        assert!(neighbor_with_gr_restart_time(65001, 0).validate().is_ok());
    }

    #[test]
    fn neighbor_gr_restart_time_4096_fails() {
        assert!(
            neighbor_with_gr_restart_time(65001, 4096)
                .validate()
                .is_err()
        );
    }

    #[test]
    fn peer_group_gr_restart_time_4095_passes() {
        assert!(peer_group_with_gr_restart_time(4095).validate().is_ok());
    }

    #[test]
    fn peer_group_gr_restart_time_4096_fails() {
        assert!(peer_group_with_gr_restart_time(4096).validate().is_err());
    }

    // --- LLGR stale_time ---

    fn neighbor_with_llgr_stale_time(peer_as: u32, stale_time: u32) -> Neighbor {
        Neighbor {
            config: Some(NeighborConfig {
                neighbor_address: Some("10.0.0.1".parse().unwrap()),
                peer_as: Some(peer_as),
                ..Default::default()
            }),
            afi_safis: Some(vec![AfiSafi {
                config: Some(AfiSafiConfig {
                    afi_safi_name: Some(AfiSafiType::Ipv4Unicast),
                    ..Default::default()
                }),
                long_lived_graceful_restart: Some(LongLivedGracefulRestart {
                    config: Some(LongLivedGracefulRestartConfig {
                        enabled: Some(true),
                        restart_time: Some(stale_time),
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }]),
            ..Default::default()
        }
    }

    fn peer_group_with_llgr_stale_time(stale_time: u32) -> PeerGroup {
        PeerGroup {
            afi_safis: Some(vec![AfiSafi {
                config: Some(AfiSafiConfig {
                    afi_safi_name: Some(AfiSafiType::Ipv4Unicast),
                    ..Default::default()
                }),
                long_lived_graceful_restart: Some(LongLivedGracefulRestart {
                    config: Some(LongLivedGracefulRestartConfig {
                        enabled: Some(true),
                        restart_time: Some(stale_time),
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }]),
            ..Default::default()
        }
    }

    #[test]
    fn neighbor_llgr_stale_time_max_passes() {
        assert!(
            neighbor_with_llgr_stale_time(65001, 0xFF_FFFF)
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn neighbor_llgr_stale_time_0_passes() {
        assert!(neighbor_with_llgr_stale_time(65001, 0).validate().is_ok());
    }

    #[test]
    fn neighbor_llgr_stale_time_overflow_fails() {
        assert!(
            neighbor_with_llgr_stale_time(65001, 0x100_0000)
                .validate()
                .is_err()
        );
    }

    #[test]
    fn peer_group_llgr_stale_time_max_passes() {
        assert!(
            peer_group_with_llgr_stale_time(0xFF_FFFF)
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn peer_group_llgr_stale_time_overflow_fails() {
        assert!(
            peer_group_with_llgr_stale_time(0x100_0000)
                .validate()
                .is_err()
        );
    }

    // --- auth_password length ---

    fn neighbor_with_auth_password(peer_as: u32, password: &str) -> Neighbor {
        Neighbor {
            config: Some(NeighborConfig {
                neighbor_address: Some("10.0.0.1".parse().unwrap()),
                peer_as: Some(peer_as),
                auth_password: Some(password.to_string()),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn peer_group_with_auth_password(password: &str) -> PeerGroup {
        PeerGroup {
            config: Some(PeerGroupConfig {
                auth_password: Some(password.to_string()),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn neighbor_auth_password_80_bytes_passes() {
        assert!(
            neighbor_with_auth_password(65001, &"a".repeat(80))
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn neighbor_auth_password_empty_passes() {
        assert!(neighbor_with_auth_password(65001, "").validate().is_ok());
    }

    #[test]
    fn neighbor_auth_password_81_bytes_fails() {
        assert!(
            neighbor_with_auth_password(65001, &"a".repeat(81))
                .validate()
                .is_err()
        );
    }

    #[test]
    fn peer_group_auth_password_80_bytes_passes() {
        assert!(
            peer_group_with_auth_password(&"a".repeat(80))
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn peer_group_auth_password_81_bytes_fails() {
        assert!(
            peer_group_with_auth_password(&"a".repeat(81))
                .validate()
                .is_err()
        );
    }

    // --- VRF name ---

    fn bgp_config_with_vrf(name: Option<&str>) -> BgpConfig {
        BgpConfig {
            global: Some(valid_global()),
            vrfs: Some(vec![Vrf {
                config: Some(VrfConfig {
                    name: name.map(str::to_string),
                    ..Default::default()
                }),
                ..Default::default()
            }]),
            ..Default::default()
        }
    }

    #[test]
    fn vrf_with_name_passes() {
        assert!(bgp_config_with_vrf(Some("vrf1")).validate().is_ok());
    }

    #[test]
    fn vrf_with_empty_name_fails() {
        assert!(bgp_config_with_vrf(Some("")).validate().is_err());
    }

    #[test]
    fn vrf_with_missing_name_fails() {
        assert!(bgp_config_with_vrf(None).validate().is_err());
    }
}
