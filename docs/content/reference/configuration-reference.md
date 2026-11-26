# Configuration reference

This page lists the configuration keys RustyBGP reads, and those it accepts
for GoBGP compatibility but ignores. Keys outside the GoBGP schema are
rejected at startup.

Keys are written as YAML paths. In TOML, `neighbors[].config.peer-as` becomes:

```toml
[[neighbors]]
  [neighbors.config]
    peer-as = 65002
```

**Legend:** :material-check:{ .ok } read and applied ·
:material-minus:{ .partial } accepted but ignored ·
:material-close:{ .no } rejected by validation

## `global`

| Key | Status | Notes |
|---|---|---|
| `config.as` | :material-check:{ .ok } | Required, non-zero. |
| `config.router-id` | :material-check:{ .ok } | Required. |
| `config.port` | :material-check:{ .ok } | Default 179. `-1` disables the listener. `0` is rejected. |
| `config.local-address-list` | :material-check:{ .ok } | Default `0.0.0.0` and `::`. |
| `config.bind-to-device` | :material-check:{ .ok } | |
| `confederation.config.enabled`, `identifier`, `member-as-list` | :material-check:{ .ok } | |
| `route-selection-options.config.always-compare-med` | :material-check:{ .ok } | |
| `route-selection-options.config.external-compare-router-id` | :material-check:{ .ok } | |
| `apply-policy.config.import-policy-list`, `default-import-policy` | :material-check:{ .ok } | Reloadable. |
| `apply-policy.config.export-policy-list`, `default-export-policy` | :material-check:{ .ok } | Reloadable. |
| `graceful-restart.config.stale-routes-time` | :material-check:{ .ok } | Selection deferral timer with `--graceful-restart`. Default 360; `0` waits forever. |
| `graceful-restart.config.*` (other keys) | :material-minus:{ .partial } | Including `deferral-time`. |
| `use-multiple-paths` | :material-minus:{ .partial } | |
| `afi-safis`, `default-route-distance` | :material-minus:{ .partial } | |

## `neighbors[]`

| Key | Status | Notes |
|---|---|---|
| `config.neighbor-address` | :material-check:{ .ok } | Required unless `neighbor-interface` is set. |
| `config.neighbor-interface` | :material-check:{ .ok } | Unnumbered BGP over IPv6 link-local. |
| `config.peer-as` | :material-check:{ .ok } | Required unless inherited from a peer group. |
| `config.local-as` | :material-check:{ .ok } | Default: global AS. |
| `config.auth-password` | :material-check:{ .ok } | TCP MD5, up to 80 bytes. |
| `config.peer-group` | :material-check:{ .ok } | |
| `config.admin-down` | :material-check:{ .ok } | |
| `config.description`, `peer-type`, `remove-private-as`, `route-flap-damping`, `send-community`, `vrf` | :material-minus:{ .partial } | |
| `timers.config.hold-time` | :material-check:{ .ok } | Default 180. `0` or 3 to 65535. |
| `timers.config.connect-retry` | :material-check:{ .ok } | Default 3. |
| `timers.config.keepalive-interval`, `minimum-advertisement-interval`, `idle-hold-time-after-reset` | :material-minus:{ .partial } | Keepalive is always hold time / 3. |
| `transport.config.local-address` | :material-check:{ .ok } | See [Neighbors](../user-guide/neighbors.md#source-address). |
| `transport.config.passive-mode` | :material-check:{ .ok } | |
| `transport.config.remote-port` | :material-check:{ .ok } | Default 179. |
| `transport.config.bind-interface` | :material-check:{ .ok } | |
| `transport.config.tcp-mss`, `mtu-discovery`, `local-port` | :material-minus:{ .partial } | |
| `ebgp-multihop.config.enabled`, `multihop-ttl` | :material-check:{ .ok } | Both must be set. |
| `ttl-security.config.enabled`, `ttl-min` | :material-check:{ .ok } | `ttl-min` defaults to 255. |
| `route-reflector.config.route-reflector-client`, `route-reflector-cluster-id` | :material-check:{ .ok } | Cluster ID defaults to the router ID. |
| `route-server.config.route-server-client` | :material-check:{ .ok } | |
| `graceful-restart.config.enabled`, `restart-time`, `notification-enabled` | :material-check:{ .ok } | `restart-time` default 120, at most 4095. |
| `bfd.config.enabled`, `desired-minimum-tx-interval`, `required-minimum-receive`, `detection-multiplier` | :material-check:{ .ok } | Microseconds. Defaults 1000000, 1000000, 3. |
| `apply-policy.config.export-policy-list`, `default-export-policy` | :material-check:{ .ok } | |
| `apply-policy.config.import-policy-list`, `default-import-policy` | :material-close:{ .no } | Use the global import policy. |
| `add-paths` (neighbor level) | :material-close:{ .no } | Use `afi-safis[].add-paths`. |
| `error-handling`, `logging-options`, `as-path-options`, `use-multiple-paths` | :material-minus:{ .partial } | |

### `neighbors[].afi-safis[]`

| Key | Status | Notes |
|---|---|---|
| `config.afi-safi-name` | :material-check:{ .ok } | See [Address families](../user-guide/address-families.md#supported-families). |
| `add-paths.config.receive`, `send-max` | :material-check:{ .ok } | `send-max` at most 255. |
| `mp-graceful-restart.config.enabled` | :material-check:{ .ok } | Required for GR to be advertised. |
| `long-lived-graceful-restart.config.enabled`, `restart-time` | :material-check:{ .ok } | Default stale time 600. |
| `ipv4-unicast.prefix-limit.config.max-prefixes` | :material-check:{ .ok } | Also under `ipv6-unicast`. |
| `*.prefix-limit.config.shutdown-threshold-pct`, `restart-timer` | :material-minus:{ .partial } | |
| `apply-policy` | :material-close:{ .no } | |

## `peer-groups[]`

Accepts the same keys as a neighbor, identified by `config.peer-group-name`.
Groups pass on: `peer-as`, `local-as`, `auth-password`, `local-address`,
`passive-mode`, timers, route-server and route-reflector settings, eBGP
multihop, TTL security, address families with Add-Path, Graceful Restart and
LLGR. BFD, `bind-interface`, `remote-port` and prefix limits are not inherited.
Any `apply-policy` on a group is rejected.

## `dynamic-neighbors[]`

| Key | Status | Notes |
|---|---|---|
| `config.prefix` | :material-check:{ .ok } | Address range allowed to connect. |
| `config.peer-group` | :material-check:{ .ok } | Group used to create the neighbor. |

## `defined-sets` and `policy-definitions`

| Key | Status |
|---|---|
| `defined-sets.prefix-sets`, `neighbor-sets` | :material-check:{ .ok } |
| `defined-sets.bgp-defined-sets.as-path-sets`, `community-sets`, `ext-community-sets`, `large-community-sets` | :material-check:{ .ok } |
| `policy-definitions[].statements[].conditions.match-prefix-set`, `match-neighbor-set` | :material-check:{ .ok } |
| `conditions.bgp-conditions.match-as-path-set`, `match-community-set`, `match-ext-community-set`, `match-large-community-set` | :material-check:{ .ok } |
| `conditions.bgp-conditions.next-hop-in-list`, `route-type`, `rpki-validation-result`, `as-path-length` | :material-check:{ .ok } |
| `actions.route-disposition` | :material-check:{ .ok } |
| `actions.bgp-actions.set-as-path-prepend`, `set-community`, `set-ext-community`, `set-large-community`, `set-local-pref`, `set-med`, `set-next-hop`, `set-route-origin` | :material-check:{ .ok } |

## `rpki-servers[]`

| Key | Status | Notes |
|---|---|---|
| `config.address` | :material-check:{ .ok } | |
| `config.port` | :material-check:{ .ok } | Default 323. |
| `config.refresh-time`, `hold-time`, `record-lifetime`, `preference` | :material-minus:{ .partial } | |

## `bmp-servers[]`

| Key | Status | Notes |
|---|---|---|
| `config.address`, `config.port` | :material-check:{ .ok } | Both required. |
| `config.route-monitoring-policy` | :material-check:{ .ok } | Only `pre-policy`; other values are rejected. |
| `config.statistics-timeout`, `route-mirroring-enabled`, `sys-name`, `sys-descr` | :material-minus:{ .partial } | |

## `mrt-dump[]`

| Key | Status | Notes |
|---|---|---|
| `config.dump-type` | :material-check:{ .ok } | `updates` or `table`. |
| `config.file-name` | :material-check:{ .ok } | `strftime` pattern when rotating. |
| `config.rotation-interval` | :material-check:{ .ok } | Seconds. Also the snapshot interval for `table`. |
| `config.dump-interval`, `table-name` | :material-minus:{ .partial } | |

## `zebra`

| Key | Status | Notes |
|---|---|---|
| `config.enabled` | :material-check:{ .ok } | Enables native kernel integration. |
| `config.redistribute-route-type-list` | :material-check:{ .ok } | See [Kernel FIB](../user-guide/kernel-fib.md#redistribution-into-bgp). |
| `config.url`, `version`, `nexthop-trigger-enable`, `nexthop-trigger-delay`, `mpls-label-range-size`, `software-name` | :material-minus:{ .partial } | |

## `vrfs` and `collector`

Accepted for compatibility and validated (a VRF needs a name), but not
loaded. Create VRFs with `gobgp vrf add` or the `AddVrf` RPC.
