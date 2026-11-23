// Copyright (C) 2019-2022 The RustyBGP Authors.
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

//! Loads the parts of the config file that the gRPC API can also change:
//! peer groups, policies, dynamic neighbors and neighbors. Each part goes
//! through the same `Global` method as the matching gRPC handler.

use std::net::IpAddr;
use std::str::FromStr;

use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::config;
use crate::convert;
use crate::error::Error;
use rustybgp_kernel as kernel;
use rustybgp_packet as packet;

use super::{GlobalHandle, PeerGroup, PeerParams, TableHandle};

pub(super) async fn apply_peer_policy_config(
    global: &GlobalHandle,
    tables: &TableHandle,
    active_tx: &mpsc::UnboundedSender<TcpStream>,
    config: &config::BgpConfig,
) -> Result<(), Error> {
    {
        let mut server = global.write().await;

        for pg in config.peer_groups.iter().flatten() {
            if let Some(name) = pg.config.as_ref().and_then(|x| x.peer_group_name.clone())
                && let Err(e) = server.add_peer_group(name.clone(), PeerGroup::from(pg))
            {
                log::warn!("skipping peer group {name}: {e:?}");
            }
        }

        let (ptable, (import, export)) = convert::policy_table_from_config(config)?;
        server.replace_policies(tables, ptable, import, export)?;

        for n in config.dynamic_neighbors.iter().flatten() {
            let Some((prefix, name)) = n
                .config
                .as_ref()
                .and_then(|c| c.prefix.as_deref().zip(c.peer_group.as_deref()))
            else {
                log::warn!("skipping dynamic neighbor without prefix or peer group");
                continue;
            };
            let Ok(net) = packet::IpNet::from_str(prefix) else {
                log::warn!("skipping dynamic neighbor {prefix}: invalid prefix");
                continue;
            };
            if let Err(e) = server.add_dynamic_neighbor(name, net) {
                log::warn!("skipping dynamic neighbor {prefix}: {e:?}");
            }
        }
    }

    // Resolve params outside the write lock so that async NDP lookups
    // for unnumbered peers (neighbor-interface) do not hold the lock.
    let mut resolved: Vec<(PeerParams, Option<String>)> = Vec::new();
    for p in config.neighbors.iter().flatten() {
        match PeerParams::try_from(p) {
            Ok(mut params) => {
                if let Some(ifname) = params.neighbor_interface.as_deref() {
                    match kernel::get_link_local_neighbor(ifname).await {
                        Ok(ll) => params.remote_addr = IpAddr::V6(ll),
                        Err(e) => {
                            log::warn!("skipping unnumbered peer {ifname}: NDP lookup failed: {e}");
                            continue;
                        }
                    }
                }
                let pg = p.config.as_ref().and_then(|c| c.peer_group.clone());
                resolved.push((params, pg));
            }
            Err(e) => log::warn!("skipping invalid peer config: {}", e),
        }
    }
    let mut server = global.write().await;
    for (params, pg_name) in resolved {
        if let Err(e) = server.add_static_peer(params, pg_name.as_deref(), Some(active_tx.clone()))
        {
            log::error!("failed to add peer from config: {}", e);
        }
    }
    Ok(())
}
