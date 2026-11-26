# Configuration basics

## File format

RustyBGP uses GoBGP's configuration schema, which is derived from the
OpenConfig BGP and routing-policy models. The format is chosen by the file
extension:

| Extension | Format |
|---|---|
| `.yaml`, `.yml` | YAML |
| Anything else (`.toml`, `.conf`, ...) | TOML |

JSON and HCL, which GoBGP also accepts, are not supported.

!!! warning "Unknown keys are errors"

    Every section rejects keys it does not recognize. A misspelled option
    stops `rustybgpd` at startup with an error rather than being ignored.
    Some keys exist in the GoBGP schema but have no effect in RustyBGP; they
    are listed in the
    [configuration reference](../reference/configuration-reference.md).

## Top-level sections

| Section | Purpose | Reloadable with SIGHUP |
|---|---|---|
| `global` | Local AS, router ID, listening sockets, confederation, route selection, global policy | Only `apply-policy` |
| `neighbors` | Static BGP neighbors | Additions and removals |
| `peer-groups` | Shared settings for neighbors | Additions and removals |
| `dynamic-neighbors` | Address ranges that may connect, mapped to a peer group | Additions and removals |
| `defined-sets` | Prefix, neighbor, AS-path and community sets | Yes |
| `policy-definitions` | Routing policies | Yes |
| `rpki-servers` | RTR caches | No |
| `bmp-servers` | BMP stations | No |
| `mrt-dump` | MRT dump files | No |
| `zebra` | Kernel FIB integration | No |
| `vrfs` | Accepted for compatibility, but not loaded; create VRFs through the API | No |
| `collector` | Accepted for compatibility, not used | No |

## Global settings

=== "TOML"

    ```toml
    [global.config]
      as = 65001
      router-id = "192.0.2.1"
      port = 179                                # -1 disables the listener
      local-address-list = ["192.0.2.1", "2001:db8::1"]

    [global.route-selection-options.config]
      always-compare-med = false
      external-compare-router-id = false
    ```

=== "YAML"

    ```yaml
    global:
      config:
        as: 65001
        router-id: "192.0.2.1"
        port: 179
        local-address-list: ["192.0.2.1", "2001:db8::1"]
      route-selection-options:
        config:
          always-compare-med: false
          external-compare-router-id: false
    ```

| Option | Default | Description |
|---|---|---|
| `as` | required | Local AS number. Must not be 0. |
| `router-id` | required | BGP identifier, an IPv4 address. |
| `port` | `179` | BGP listening port. `-1` disables the listener so the daemon only makes outbound connections. `0` is rejected. |
| `local-address-list` | `0.0.0.0` and `::` | Addresses to listen on. If the host has no IPv6, the default `::` socket is skipped. |
| `bind-to-device` | none | Bind the listening sockets to a network device, such as a VRF. |
| `route-selection-options.always-compare-med` | `false` | Compare MED between paths from different neighboring ASes. |
| `route-selection-options.external-compare-router-id` | `false` | Use the router ID to choose between eBGP paths instead of keeping the current best (RFC 5004). |

### Confederation

```toml
[global.confederation.config]
  enabled = true
  identifier = 65000
  member-as-list = [65001, 65002]
```

`identifier` is the confederation's AS number as seen by external peers.
`member-as-list` lists the member AS numbers; neighbors in those ASes are
treated as confederation eBGP peers.

## Validation

At startup the file is parsed and validated. Any error stops the daemon. The
validator checks, among other things:

- `global` with a non-zero `as` and a `router-id` is present.
- Each neighbor has a `neighbor-address` (or `neighbor-interface`) and a
  non-zero `peer-as`, unless it belongs to a peer group.
- `hold-time` is 0 or between 3 and 65535.
- Graceful Restart `restart-time` is at most 4095, and the LLGR
  `restart-time` is at most 16777215.
- `auth-password` is at most 80 bytes.
- Per-neighbor import policy, any peer-group policy, and the neighbor-level
  `add-paths` container are rejected, with a message pointing to the supported
  alternative.
- BMP stations have an address and a port, and use `pre-policy` monitoring.

A neighbor that passes validation but cannot be created (for example, an
unnumbered neighbor whose link-local address cannot be found) is logged and
skipped. The rest of the configuration still loads.

## Precedence of command-line options

If `-f` is given, the file is authoritative, and `--as-number` and
`--router-id` are ignored. Without `-f`, `--as-number` and `--router-id`
together start BGP with no neighbors. With neither, the daemon serves only the
API and waits for a `StartBgp` call.
