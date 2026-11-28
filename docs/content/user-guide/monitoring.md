# Monitoring: BMP and MRT

RustyBGP can export its view of the routing system in two standard formats:
live streams to a BMP collector, and MRT files on disk.

## BMP

The BGP Monitoring Protocol (RFC 7854) streams peer state changes and routes
to a collector such as OpenBMP, pmacct or a custom receiver. RustyBGP connects
to the station and reconnects automatically (every 10 seconds) if the
connection drops.

### From the configuration file

```yaml
bmp-servers:
  - config:
      address: "192.0.2.60"
      port: 11019
      route-monitoring-policy: pre-policy
```

The configuration file supports only `pre-policy` monitoring. Other
values are rejected at startup. `statistics-timeout`,
`route-mirroring-enabled`, `sys-name` and `sys-descr` are ignored.

### From the API

Every monitoring policy is available through the API:

```bash
gobgp bmp add 192.0.2.60 pre        # Adj-RIB-In, before import policy
gobgp bmp add 192.0.2.60 post       # Adj-RIB-In, after import policy
gobgp bmp add 192.0.2.60 both       # pre and post
gobgp bmp add 192.0.2.60 local-rib  # Loc-RIB (RFC 9069)
gobgp bmp add 192.0.2.60 all        # pre, post, Loc-RIB and Adj-RIB-Out (RFC 8671)
gobgp bmp del 192.0.2.60
```

To use one of these modes permanently, add the station from a startup script
or configuration management after `rustybgpd` is up.

### What is sent

On connect, RustyBGP sends an Initiation message, a Peer Up message for every
established neighbor, the current routes according to the policy followed by
End-of-RIB, and then live updates. Statistics Reports and Route Mirroring are
not implemented.

## MRT

MRT (RFC 6396) files are the standard archive format for BGP data and can be
read with tools such as `bgpdump`, `bgpkit-parser` and `pybgpstream`.

```yaml
mrt-dump:
  - config:
      dump-type: updates
      file-name: /var/lib/rustybgp/updates.%Y%m%d.%H%M.mrt
      rotation-interval: 300
  - config:
      dump-type: table
      file-name: /var/lib/rustybgp/rib.%Y%m%d.%H%M.mrt
      rotation-interval: 3600
```

| Option | Description |
|---|---|
| `dump-type` | `updates` writes every received UPDATE as a BGP4MP record. `table` writes TABLE_DUMP_V2 RIB snapshots. |
| `file-name` | Output path. When `rotation-interval` is set, it is a `strftime` pattern and a new file is opened each interval. |
| `rotation-interval` | Seconds between file rotations. For `table` dumps it is also the snapshot interval. |

GoBGP's `dump-interval` and `table-name` are ignored. MRT dumps can also be
started and stopped through the `EnableMrt` and `DisableMrt` RPCs.

## Streaming over gRPC

For custom tooling, the `WatchEvent` RPC streams peer state changes and route
changes (pre-policy, post-policy or best path) directly over the API. See
[Programmatic clients](../automation/programmatic-clients.md#watching-for-changes).
