use crate::api;
use crate::config::*;
use crate::error::Error;

use regex::Regex;
use serde::Deserialize;
use std::convert::TryFrom;

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
                .captures(&range)
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
