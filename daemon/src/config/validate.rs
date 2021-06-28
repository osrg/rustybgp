use crate::config::*;
use crate::error::Error;

impl Bgp {
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
