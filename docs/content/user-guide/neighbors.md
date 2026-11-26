# Neighbors

## Static neighbors

A minimal neighbor needs an address and a peer AS:

=== "TOML"

    ```toml
    [[neighbors]]
      [neighbors.config]
        neighbor-address = "198.51.100.2"
        peer-as = 65002
        description = "transit-a"
    ```

=== "YAML"

    ```yaml
    neighbors:
      - config:
          neighbor-address: "198.51.100.2"
          peer-as: 65002
    ```

A neighbor whose `peer-as` equals the local AS is iBGP; otherwise it is eBGP,
or confederation eBGP if the AS is in the confederation's member list.

### Common options

| Option | Default | Description |
|---|---|---|
| `config.local-as` | Global AS | AS number presented to this neighbor. |
| `config.auth-password` | none | TCP MD5 signature key (RFC 2385), up to 80 bytes. |
| `config.admin-down` | `false` | Start with the session administratively disabled. |
| `config.peer-group` | none | Inherit settings from a peer group. |
| `timers.config.hold-time` | `180` | Proposed hold time in seconds. `0` disables keepalives and the hold timer. |
| `timers.config.connect-retry` | `3` | Seconds between outbound connection attempts. |
| `transport.config.passive-mode` | `false` | Never initiate the TCP connection. |
| `transport.config.local-address` | automatic | Source address for the session. See [below](#source-address). |
| `transport.config.remote-port` | `179` | Neighbor's TCP port. |
| `transport.config.bind-interface` | none | Bind the session socket to a device, such as a Linux VRF. |

The keepalive interval is always one third of the negotiated hold time;
`keepalive-interval` is ignored.

### Source address

Set the TCP source address with the GoBGP-compatible transport setting:

```toml
[neighbors.transport.config]
  local-address = "192.0.2.1"
```

- The address must exist on the host. If binding fails, the session keeps
  retrying; RustyBGP does not fall back to another source address.
- Inbound connections from the neighbor must target this address, unless
  `bind-interface` is also set.
- IPv4, IPv6 and scoped IPv6 addresses (`fe80::1%eth0`) are accepted. The
  address family must match the neighbor's.
- An empty string or a wildcard address (`0.0.0.0`, `::`) selects the source
  automatically.
- A peer group can provide the value; an explicit neighbor setting wins.
- Through the API, changing `Transport.local_address` with `UpdatePeer`
  restarts the session.

### eBGP multihop and TTL security

By default, eBGP sessions send with TTL 1, which only works with directly
connected neighbors. For loopback peering or multihop eBGP, either raise the
TTL:

```toml
[neighbors.ebgp-multihop.config]
  enabled = true
  multihop-ttl = 3
```

or, preferably, use GTSM (RFC 5082), which sends with TTL 255 and drops
incoming packets below a minimum TTL:

```toml
[neighbors.ttl-security.config]
  enabled = true
  ttl-min = 254          # accept peers up to two hops away
```

When `ttl-min` is omitted it defaults to 255 (directly connected only).

### Prefix limits

```toml
[[neighbors.afi-safis]]
  [neighbors.afi-safis.config]
    afi-safi-name = "ipv4-unicast"
  [neighbors.afi-safis.ipv4-unicast.prefix-limit.config]
    max-prefixes = 1000
```

When the neighbor exceeds the limit, the session is closed with a Cease
(Maximum Number of Prefixes Reached) NOTIFICATION. The same option exists
under `ipv6-unicast`. `shutdown-threshold-pct` and `restart-timer` are not
supported.

## Peer groups

A peer group holds settings shared by many neighbors.

```toml
[[peer-groups]]
  [peer-groups.config]
    peer-group-name = "customers"
    peer-as = 65100
  [peer-groups.timers.config]
    hold-time = 90
  [[peer-groups.afi-safis]]
    [peer-groups.afi-safis.config]
      afi-safi-name = "ipv4-unicast"

[[neighbors]]
  [neighbors.config]
    neighbor-address = "203.0.113.10"
    peer-group = "customers"
```

Inheritance rules:

- A value set explicitly on the neighbor wins.
- `hold-time` and `connect-retry` are inherited only when the neighbor uses
  the default.
- Address families are inherited only when the neighbor lists none.

Peer groups can carry `peer-as`, `local-as`, `auth-password`, transport
`local-address` and `passive-mode`, timers, route-server and route-reflector
settings, eBGP multihop, TTL security, address families with Add-Path,
Graceful Restart and LLGR. They cannot carry BFD, `bind-interface`,
`remote-port`, prefix limits, or policy.

## Dynamic neighbors

Dynamic neighbors accept inbound sessions from any address in a range and
create the neighbor on the fly from a peer group:

```toml
[[dynamic-neighbors]]
  [dynamic-neighbors.config]
    prefix = "10.1.0.0/16"
    peer-group = "customers"
```

Dynamic neighbors are passive, are removed when their session closes, and use
the global export policy. Start `rustybgpd` with `--any-peers` to accept
sessions from any address (`0.0.0.0/0` and `::/0`), which is convenient for
route collectors and labs.

## Unnumbered BGP

On point-to-point links, RustyBGP can peer over the interface's IPv6
link-local address without configuring addresses (RFC 8950 next hops carry
IPv4 routes):

```yaml
neighbors:
  - config:
      neighbor-interface: "eth0"
    afi-safis:
      - config:
          afi-safi-name: ipv4-unicast
```

At startup RustyBGP looks up the neighbor's link-local address in the
interface's IPv6 neighbor table. If no entry is found the neighbor is skipped
with a warning, so make sure the link is up and the neighbor has sent router
or neighbor advertisements (for example, ping `ff02::1%eth0`).

Changes to unnumbered neighbors are not applied on SIGHUP; restart the daemon.

## Managing neighbors at runtime

```bash
gobgp neighbor add 198.51.100.3 as 65003
gobgp neighbor del 198.51.100.3
gobgp neighbor 198.51.100.2 disable
gobgp neighbor 198.51.100.2 enable
```

See [Operations](../administration/operations.md) for resets and shutdowns.
