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

use std::collections::BTreeMap;
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
/// loaded at startup. Each reload compares the new file with the config that
/// runs now, as GoBGP does, and applies only what changed.
///
/// Reloaded: policies (defined sets, policy definitions and the global
/// apply-policy), and added or deleted neighbors, peer groups and dynamic
/// neighbors. A changed neighbor or peer group, an unnumbered neighbor and
/// the other sections are not applied; a warning is logged instead. Routes
/// already in the tables are not re-evaluated with new policies; a soft reset
/// applies them.
pub(super) fn spawn_reloader(
    global: GlobalHandle,
    tables: TableHandle,
    active_tx: mpsc::UnboundedSender<TcpStream>,
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
            let old = std::mem::take(&mut current);
            current = reload(&global, &tables, &active_tx, old, new).await;
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

/// Logs a warning for each section that differs between `old` and `new` but
/// is not reloaded.
fn warn_not_reloaded(old: &mut config::BgpConfig, new: &mut config::BgpConfig) {
    // global is compared without apply-policy, which is reloaded.
    let take = |c: &mut config::BgpConfig| c.global.as_mut().and_then(|g| g.apply_policy.take());
    let (old_ap, new_ap) = (take(old), take(new));
    let mut changed = Vec::new();
    if old.global != new.global {
        changed.push("global");
    }
    if let Some(g) = old.global.as_mut() {
        g.apply_policy = old_ap;
    }
    if let Some(g) = new.global.as_mut() {
        g.apply_policy = new_ap;
    }
    if old.rpki_servers != new.rpki_servers {
        changed.push("rpki-servers");
    }
    if old.bmp_servers != new.bmp_servers {
        changed.push("bmp-servers");
    }
    if old.vrfs != new.vrfs {
        changed.push("vrfs");
    }
    if old.mrt_dump != new.mrt_dump {
        changed.push("mrt-dump");
    }
    if old.zebra != new.zebra {
        changed.push("zebra");
    }
    if old.collector != new.collector {
        changed.push("collector");
    }
    for section in changed {
        log::warn!("{section} is changed; it is not applied until restart");
    }
}

fn is_unnumbered(n: &config::generate::Neighbor) -> bool {
    n.config
        .as_ref()
        .is_some_and(|c| c.neighbor_interface.is_some())
}

fn neighbor_address(n: &config::generate::Neighbor) -> Option<IpAddr> {
    n.config.as_ref().and_then(|c| c.neighbor_address)
}

fn peer_group_name(pg: &config::generate::PeerGroup) -> Option<&str> {
    pg.config
        .as_ref()
        .and_then(|c| c.peer_group_name.as_deref())
}

/// Returns the (peer group, prefix) pair of a dynamic neighbor.
fn dynamic_neighbor_key(n: &config::generate::DynamicNeighbor) -> Option<(String, String)> {
    let c = n.config.as_ref()?;
    Some((c.peer_group.clone()?, c.prefix.clone()?))
}

/// Applies the difference between `old`, the config that runs now, and
/// `new`, and returns the config that runs after the reload. An entry that
/// failed to be added is left out of the result, so the next reload tries
/// it again. A changed entry is not applied and the result keeps the old
/// one.
async fn reload(
    global: &GlobalHandle,
    tables: &TableHandle,
    active_tx: &mpsc::UnboundedSender<TcpStream>,
    old: config::BgpConfig,
    mut new: config::BgpConfig,
) -> config::BgpConfig {
    let mut applied = old;
    warn_not_reloaded(&mut applied, &mut new);

    // Unnumbered neighbors are not reloaded.
    let (old_unnumbered, old_neighbors): (Vec<_>, Vec<_>) = applied
        .neighbors
        .take()
        .unwrap_or_default()
        .into_iter()
        .partition(is_unnumbered);
    let (new_unnumbered, new_neighbors): (Vec<_>, Vec<_>) = new
        .neighbors
        .take()
        .unwrap_or_default()
        .into_iter()
        .partition(is_unnumbered);
    if old_unnumbered != new_unnumbered {
        log::warn!("unnumbered neighbors are changed; they are not applied until restart");
    }
    let mut neighbors = old_unnumbered;
    let old_neighbors: BTreeMap<_, _> = old_neighbors
        .into_iter()
        .filter_map(|n| Some((neighbor_address(&n)?, n)))
        .collect();
    let mut new_neighbors: BTreeMap<_, _> = new_neighbors
        .into_iter()
        .filter_map(|n| Some((neighbor_address(&n)?, n)))
        .collect();

    let old_groups: BTreeMap<_, _> = applied
        .peer_groups
        .take()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|pg| Some((peer_group_name(&pg)?.to_string(), pg)))
        .collect();
    let mut new_groups: BTreeMap<_, _> = new
        .peer_groups
        .take()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|pg| Some((peer_group_name(&pg)?.to_string(), pg)))
        .collect();
    let mut groups = Vec::new();

    let old_dynamic: BTreeMap<_, _> = applied
        .dynamic_neighbors
        .take()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|n| Some((dynamic_neighbor_key(&n)?, n)))
        .collect();
    let mut new_dynamic: BTreeMap<_, _> = new
        .dynamic_neighbors
        .take()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|n| Some((dynamic_neighbor_key(&n)?, n)))
        .collect();
    let mut dynamic = Vec::new();

    let mut server = global.write().await;

    // Delete first, so that the policies of a deleted neighbor do not
    // block a new policy table that no longer has them.
    for (addr, n) in old_neighbors {
        match new_neighbors.remove(&addr) {
            None => match server.delete_peer(addr) {
                Ok(()) => log::info!("neighbor {addr} is deleted"),
                Err(e) => log::warn!("failed to delete neighbor {addr}: {e:?}"),
            },
            Some(new) => {
                if new != n {
                    log::warn!("neighbor {addr} is changed; it is not applied until restart");
                }
                neighbors.push(n);
            }
        }
    }
    for ((pg, prefix), n) in old_dynamic {
        if new_dynamic.remove(&(pg.clone(), prefix.clone())).is_some() {
            dynamic.push(n);
            continue;
        }
        let r = packet::IpNet::from_str(&prefix)
            .map_err(|_| Error::InvalidArgument("invalid prefix".to_string()))
            .and_then(|net| server.delete_dynamic_neighbor(&pg, net));
        match r {
            Ok(()) => log::info!("dynamic neighbor {prefix} in {pg} is deleted"),
            Err(e) => log::warn!("failed to delete dynamic neighbor {prefix} in {pg}: {e:?}"),
        }
    }
    for (name, pg) in old_groups {
        match new_groups.remove(&name) {
            None => match server.delete_peer_group(&name) {
                Ok(()) => log::info!("peer group {name} is deleted"),
                Err(e) => {
                    log::warn!("failed to delete peer group {name}: {e:?}");
                    if server.peer_group.contains_key(&name) {
                        groups.push(pg);
                    }
                }
            },
            Some(new) => {
                if new != pg {
                    log::warn!("peer group {name} is changed; it is not applied until restart");
                }
                groups.push(pg);
            }
        }
    }

    if policy_changed(&applied, &new) {
        let r = convert::policy_table_from_config(&new).and_then(|(ptable, (import, export))| {
            server.replace_policies(tables, ptable, import, export)
        });
        match r {
            Ok(()) => {
                log::info!("policies are updated");
                applied.defined_sets = new.defined_sets.take();
                applied.policy_definitions = new.policy_definitions.take();
                if let (Some(a), Some(n)) = (applied.global.as_mut(), new.global.as_mut()) {
                    a.apply_policy = n.apply_policy.take();
                }
            }
            Err(e) => log::warn!("failed to update policies: {e:?}"),
        }
    }

    for (name, pg) in new_groups {
        match server.add_peer_group(name.clone(), PeerGroup::from(&pg)) {
            Ok(()) => {
                log::info!("peer group {name} is added");
                groups.push(pg);
            }
            Err(e) => log::warn!("failed to add peer group {name}: {e:?}"),
        }
    }
    for ((pg, prefix), n) in new_dynamic {
        let r = packet::IpNet::from_str(&prefix)
            .map_err(|_| Error::InvalidArgument("invalid prefix".to_string()))
            .and_then(|net| server.add_dynamic_neighbor(&pg, net));
        match r {
            Ok(()) => {
                log::info!("dynamic neighbor {prefix} in {pg} is added");
                dynamic.push(n);
            }
            Err(e) => log::warn!("failed to add dynamic neighbor {prefix} in {pg}: {e:?}"),
        }
    }
    for (addr, n) in new_neighbors {
        let pg = n.config.as_ref().and_then(|c| c.peer_group.as_deref());
        let r = PeerParams::try_from(&n)
            .map_err(|e| Error::InvalidArgument(e.to_string()))
            .and_then(|params| server.add_static_peer(params, pg, Some(active_tx.clone())));
        match r {
            Ok(()) => {
                log::info!("neighbor {addr} is added");
                neighbors.push(n);
            }
            Err(e) => log::warn!("failed to add neighbor {addr}: {e:?}"),
        }
    }

    applied.neighbors = (!neighbors.is_empty()).then_some(neighbors);
    applied.peer_groups = (!groups.is_empty()).then_some(groups);
    applied.dynamic_neighbors = (!dynamic.is_empty()).then_some(dynamic);
    applied
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::event::Global;
    use crate::table_manager::TableManager;

    struct Env {
        global: GlobalHandle,
        tables: TableHandle,
        active_tx: mpsc::UnboundedSender<TcpStream>,
    }

    impl Env {
        fn new() -> Self {
            let (tx, _rx) = mpsc::unbounded_channel();
            let (bfd_tx, _bfd_rx) = mpsc::unbounded_channel();
            let (active_tx, _) = mpsc::unbounded_channel();
            Env {
                global: Arc::new(tokio::sync::RwLock::new(Global::new(tx, bfd_tx))),
                tables: Arc::new(TableManager::new(1)),
                active_tx,
            }
        }

        async fn reload(&self, old: config::BgpConfig, new: &str) -> config::BgpConfig {
            reload(&self.global, &self.tables, &self.active_tx, old, conf(new)).await
        }
    }

    const GLOBAL: &str = r#"
[global.config]
as = 65001
router-id = "192.0.2.1"
"#;

    fn conf(body: &str) -> config::BgpConfig {
        toml::from_str(&format!("{GLOBAL}{body}")).unwrap()
    }

    // Passive, so that the tests do not try to connect.
    fn neighbor(addr: &str, extra: &str) -> String {
        format!(
            r#"
[[neighbors]]
[neighbors.config]
neighbor-address = "{addr}"
peer-as = 65002
[neighbors.transport.config]
passive-mode = true
{extra}
"#
        )
    }

    fn policies(import_policy: &str, statement: &str) -> String {
        format!(
            r#"
[global.apply-policy.config]
import-policy-list = ["{import_policy}"]

[[policy-definitions]]
name = "p1"
[[policy-definitions.statements]]
name = "{statement}"
"#
        )
    }

    fn import_statement(tables: &TableHandle) -> String {
        tables.import_policy.load_full().unwrap().policies[0].statements[0]
            .name
            .to_string()
    }

    fn addrs(c: &config::BgpConfig) -> Vec<IpAddr> {
        c.neighbors
            .iter()
            .flatten()
            .filter_map(neighbor_address)
            .collect()
    }

    async fn peers(env: &Env) -> Vec<IpAddr> {
        let mut v: Vec<_> = env.global.read().await.peers.keys().copied().collect();
        v.sort();
        v
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[tokio::test]
    async fn reload_policies() {
        let env = Env::new();
        let c = env.reload(conf(""), &policies("p1", "s1")).await;
        assert_eq!(import_statement(&env.tables), "s1");

        // No change: the assignment is not rebuilt.
        let before = env.tables.import_policy.load_full().unwrap();
        let c = env.reload(c, &policies("p1", "s1")).await;
        assert!(Arc::ptr_eq(
            &before,
            &env.tables.import_policy.load_full().unwrap()
        ));

        let c = env.reload(c, &policies("p1", "s2")).await;
        assert_eq!(import_statement(&env.tables), "s2");

        // An unknown policy name fails; the policies and the returned
        // config stay as they were.
        let c = env.reload(c, &policies("p9", "s3")).await;
        assert_eq!(import_statement(&env.tables), "s2");
        assert_eq!(c, conf(&policies("p1", "s2")));
    }

    #[tokio::test]
    async fn reload_neighbors() {
        let env = Env::new();
        let c = env
            .reload(
                conf(""),
                &(neighbor("10.0.0.1", "") + &neighbor("10.0.0.2", "")),
            )
            .await;
        assert_eq!(peers(&env).await, vec![ip("10.0.0.1"), ip("10.0.0.2")]);

        // Delete .1, change .2, add .3. The change is not applied.
        let changed = "[neighbors.timers.config]\nhold-time = 30.0\n";
        let c = env
            .reload(
                c,
                &(neighbor("10.0.0.2", changed) + &neighbor("10.0.0.3", "")),
            )
            .await;
        assert_eq!(peers(&env).await, vec![ip("10.0.0.2"), ip("10.0.0.3")]);
        let mut a = addrs(&c);
        a.sort();
        assert_eq!(a, vec![ip("10.0.0.2"), ip("10.0.0.3")]);
        let old = conf(&neighbor("10.0.0.2", "")).neighbors.unwrap().remove(0);
        assert!(c.neighbors.iter().flatten().any(|n| *n == old));

        // A neighbor that cannot be added is left out of the result, so the
        // next reload tries it again.
        let bad = "[neighbors.apply-policy.config]\nexport-policy-list = [\"none\"]\n";
        let c = env.reload(c, &neighbor("10.0.0.4", bad)).await;
        assert_eq!(peers(&env).await, Vec::<IpAddr>::new());
        assert!(addrs(&c).is_empty());
    }

    #[tokio::test]
    async fn reload_peer_groups_and_dynamic_neighbors() {
        let group = |name: &str| {
            format!(
                "\n[[peer-groups]]\n[peer-groups.config]\npeer-group-name = \"{name}\"\npeer-as = 65002\n"
            )
        };
        let dynamic = |pg: &str| {
            format!(
                "\n[[dynamic-neighbors]]\n[dynamic-neighbors.config]\nprefix = \"10.1.0.0/16\"\npeer-group = \"{pg}\"\n"
            )
        };
        let env = Env::new();
        let c = env.reload(conf(""), &(group("g1") + &dynamic("g1"))).await;
        assert_eq!(
            env.global.read().await.peer_group["g1"].dynamic_peers.len(),
            1
        );

        // Move the prefix to a new group and delete the old group.
        let c = env.reload(c, &(group("g2") + &dynamic("g2"))).await;
        {
            let g = env.global.read().await;
            assert!(!g.peer_group.contains_key("g1"));
            assert_eq!(g.peer_group["g2"].dynamic_peers.len(), 1);
        }
        assert_eq!(c, conf(&(group("g2") + &dynamic("g2"))));
    }

    #[tokio::test]
    async fn reload_deletes_neighbor_before_its_policy() {
        let p1 = "\n[[policy-definitions]]\nname = \"p1\"\n[[policy-definitions.statements]]\nname = \"s1\"\n";
        let export = "[neighbors.apply-policy.config]\nexport-policy-list = [\"p1\"]\n";
        let env = Env::new();
        let c = env
            .reload(conf(""), &(neighbor("10.0.0.1", export) + p1))
            .await;
        assert_eq!(peers(&env).await, vec![ip("10.0.0.1")]);

        // The neighbor and the only policy it uses are removed together.
        let c = env.reload(c, "").await;
        assert!(peers(&env).await.is_empty());
        assert!(
            env.global
                .read()
                .await
                .ptable
                .iter_policies("p1".to_string())
                .next()
                .is_none()
        );
        assert_eq!(c, conf(""));
    }
}
