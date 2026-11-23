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
use std::path::PathBuf;
use std::str::FromStr;

use tokio::net::TcpStream;
use tokio::signal::unix::{SignalKind, signal};
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

/// Reloads the config file at `path` on SIGHUP. `current` is the config
/// loaded at startup. Each reload compares the new file with the last one
/// that was applied, as GoBGP does, and applies only what changed.
///
/// Only policies are reloaded: defined sets, policy definitions and the
/// global apply-policy. Routes already in the tables are not re-evaluated;
/// a soft reset applies the new policies to them.
pub(super) fn spawn_reloader(
    global: GlobalHandle,
    tables: TableHandle,
    path: PathBuf,
    mut current: config::BgpConfig,
) {
    let mut hup = match signal(SignalKind::hangup()) {
        Ok(s) => s,
        Err(e) => {
            log::error!("failed to install the SIGHUP handler: {e}");
            return;
        }
    };
    tokio::spawn(async move {
        while hup.recv().await.is_some() {
            log::info!("reloading config file {}", path.display());
            let new = match config::read_from_file(&path) {
                Ok(c) => c,
                Err(e) => {
                    log::warn!("failed to read config file {}: {e}", path.display());
                    continue;
                }
            };
            match reload(&global, &tables, &current, &new).await {
                Ok(()) => current = new,
                Err(e) => log::warn!("failed to reload config file {}: {e:?}", path.display()),
            }
        }
    });
}

fn global_apply_policy(c: &config::BgpConfig) -> Option<&config::generate::ApplyPolicy> {
    c.global.as_ref().and_then(|g| g.apply_policy.as_ref())
}

fn policy_changed(old: &config::BgpConfig, new: &config::BgpConfig) -> bool {
    old.defined_sets != new.defined_sets
        || old.policy_definitions != new.policy_definitions
        || global_apply_policy(old) != global_apply_policy(new)
}

/// Applies the difference between `old` and `new`. On error nothing is
/// changed, so the next reload compares against `old` again.
async fn reload(
    global: &GlobalHandle,
    tables: &TableHandle,
    old: &config::BgpConfig,
    new: &config::BgpConfig,
) -> Result<(), Error> {
    if policy_changed(old, new) {
        let (ptable, (import, export)) = convert::policy_table_from_config(new)?;
        global
            .write()
            .await
            .replace_policies(tables, ptable, import, export)?;
        log::info!("policies are updated");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::event::Global;
    use crate::table_manager::TableManager;

    fn make_global() -> GlobalHandle {
        let (tx, _rx) = mpsc::unbounded_channel();
        let (bfd_tx, _bfd_rx) = mpsc::unbounded_channel();
        Arc::new(tokio::sync::RwLock::new(Global::new(tx, bfd_tx)))
    }

    fn conf(import_policy: &str, statement: &str) -> config::BgpConfig {
        let text = format!(
            r#"
[global.config]
as = 65001
router-id = "192.0.2.1"
[global.apply-policy.config]
import-policy-list = ["{import_policy}"]

[[policy-definitions]]
name = "p1"
[[policy-definitions.statements]]
name = "{statement}"
"#
        );
        toml::from_str(&text).unwrap()
    }

    fn import_statement(tables: &TableHandle) -> String {
        tables.import_policy.load_full().unwrap().policies[0].statements[0]
            .name
            .to_string()
    }

    #[tokio::test]
    async fn reload_policies() {
        let global = make_global();
        let tables: TableHandle = Arc::new(TableManager::new(1));
        let c1 = conf("p1", "s1");
        reload(&global, &tables, &config::BgpConfig::default(), &c1)
            .await
            .unwrap();
        assert_eq!(import_statement(&tables), "s1");

        // No change: the assignment is not rebuilt.
        let before = tables.import_policy.load_full().unwrap();
        reload(&global, &tables, &c1, &conf("p1", "s1"))
            .await
            .unwrap();
        assert!(Arc::ptr_eq(
            &before,
            &tables.import_policy.load_full().unwrap()
        ));

        let c2 = conf("p1", "s2");
        reload(&global, &tables, &c1, &c2).await.unwrap();
        assert_eq!(import_statement(&tables), "s2");

        // An unknown policy name fails and keeps the current policies.
        assert!(
            reload(&global, &tables, &c2, &conf("p9", "s3"))
                .await
                .is_err()
        );
        assert_eq!(import_statement(&tables), "s2");
    }
}
