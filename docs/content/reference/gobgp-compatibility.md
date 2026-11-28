# GoBGP compatibility

RustyBGP aims to be a drop-in replacement for `gobgpd`. This page lists what
carries over unchanged and where the two differ.

## What is the same

| Area | Compatibility |
|---|---|
| gRPC API | The GoBGP v4 `GoBgpService` (protobuf package `api`). All 55 RPCs are implemented. |
| CLI | The GoBGP v4 `gobgp` client works unchanged. |
| Configuration schema | The GoBGP schema (OpenConfig BGP and routing policy plus GoBGP extensions), in TOML or YAML. |
| Default ports | BGP on 179, gRPC on 50051. |
| SIGHUP | Reloads the configuration file and applies differences, as `gobgpd` does. |

## Differences

### Platform

- RustyBGP runs on **Linux only**.

### Configuration

| Topic | GoBGP | RustyBGP |
|---|---|---|
| File formats | TOML, YAML, JSON, HCL | TOML and YAML only. The format is chosen by extension. |
| Unknown keys | Ignored | Rejected at startup |
| Per-neighbor import policy | Supported | Rejected. Use a global import policy with a neighbor-set condition. |
| Policy on peer groups | Supported | Rejected |
| BMP `route-monitoring-policy` in the file | All policies | `pre-policy` only. Use `gobgp bmp add` for the others. |
| `vrfs` section | Creates VRFs | Accepted but not loaded. Create VRFs through the API. |
| GR selection deferral timer | `deferral-time` | `stale-routes-time` |
| MRT table dump interval | `dump-interval` | `rotation-interval` |
| Neighbor `keepalive-interval` | Honored | Ignored; always one third of the hold time |
| `use-multiple-paths` | Controls multipath | Ignored; the kernel FIB always receives the ECMP set |
| `remove-private-as`, `route-flap-damping` | Supported | Accepted, no effect |
| RPKI `refresh-time`, `hold-time`, `record-lifetime` | Honored | Ignored |

See the [configuration reference](configuration-reference.md) for the full
list.

### FIB programming

GoBGP relies on an external Zebra daemon (FRR) to program routes. RustyBGP
programs the Linux kernel directly over netlink. The `zebra` section and the
`EnableZebra` RPC turn on the built-in integration; the Zebra protocol
settings (`url`, `version` and so on) are ignored. See
[Kernel FIB](../user-guide/kernel-fib.md).

### API behavior

- Per-neighbor policy assignments apply to export only.
- `ResetPeer` takes a single neighbor address; `all` is not accepted.
- `WatchEvent` ignores `batch_size` and `peer_group`.
- `ListPath` treats `batch_size` as a cap on the total number of paths.
- `GetBgp` does not return listen addresses, families, Graceful Restart or
  `bind_to_device`.
- `UpdatePeer` cannot change route-reflector-client or route-server-client
  status, and never reports `needs_soft_reset_in`.
- `ShutdownPeer` does not send the shutdown communication text.
- The API has no TLS option.

See [gRPC API](../automation/grpc-api.md) for the full status table.

### Policy changes

GoBGP v4 soft-resets every neighbor after a policy change. RustyBGP does not;
run a soft reset explicitly. This matches the behavior proposed for GoBGP v5.

### Not supported

- VPLS
- MPLS VPN multicast (MVPN)
- The EVPN control plane (route-target-based MAC-VRF import and export). EVPN
  route types 1 to 5 are carried and relayed.
- Zebra protocol integration (replaced by native netlink)

## Migrating from gobgpd

1. Convert JSON or HCL configuration to TOML or YAML.
2. Start `rustybgpd -f <file>` once in a test environment, or on a host with
   the listener disabled (`port = -1`), and fix any validation errors.
3. Move per-neighbor import policies to the global import policy, using
   `match-neighbor-set` conditions.
4. Replace `vrfs` in the file with `gobgp vrf add` calls in your provisioning.
5. Replace `zebra` settings with `enabled = true` and the redistribution list.
6. Stop `gobgpd`, start `rustybgpd`, and compare `gobgp neighbor` and table
   sizes with the values recorded before the switch.
