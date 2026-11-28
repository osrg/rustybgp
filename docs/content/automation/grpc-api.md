# gRPC API

`rustybgpd` serves the GoBGP v4 gRPC API. The service definition lives in
[`api/proto/gobgp.proto`](https://github.com/osrg/rustybgp/blob/master/api/proto/gobgp.proto):
the protobuf package is `api`, the service is `GoBgpService`, and the
`go_package` option is `github.com/osrg/gobgp/v4/api`. Any client generated
from the GoBGP v4 protobuf files can talk to RustyBGP.

## Endpoint

The gRPC server listens on `0.0.0.0:50051` by default. Change it with
`--api-hosts`:

```bash
rustybgpd -f /etc/rustybgp/rustybgpd.toml --api-hosts 127.0.0.1:50051
```

`--api-hosts` takes a single `address:port`. Use brackets for IPv6, for
example `--api-hosts [::1]:50051`. A malformed value, or an address that cannot
be bound, stops the daemon at startup.

!!! danger "The API is unauthenticated"

    The gRPC server has no TLS, no authentication and no authorization. Anyone
    who can reach the port can reconfigure the router, inject routes, or shut
    down sessions. Bind the API to loopback or a management address and
    restrict access with a host firewall. See
    [Security hardening](../administration/security.md).

## Errors

RustyBGP maps internal errors to standard gRPC status codes:

| Status code | Typical cause |
|---|---|
| `UNAVAILABLE` | BGP has not been started yet (no `global` configuration and no `StartBgp`). |
| `INVALID_ARGUMENT` | Malformed request, unsupported table type, or a field that cannot be changed. |
| `ALREADY_EXISTS` | The peer, VRF, BMP station, MRT file or other object already exists. |
| `NOT_FOUND` | The referenced peer, policy, defined set or other object does not exist. |
| `FAILED_PRECONDITION` | The operation does not apply in the current state, for example `StopBgp` when BGP is not running. |

## Implementation status

All 55 RPCs of `GoBgpService` are implemented; none returns `UNIMPLEMENTED`.
Some ignore optional request fields or accept only a subset of table types.
The notes below list every known difference from GoBGP.

### Global

| RPC | Status | Notes |
|---|---|---|
| `StartBgp` | :material-check-circle:{ .ok } Implemented | Requires a non-zero ASN and a valid router ID. `listen_port: 0` means 179; a negative port disables the BGP listener. Honors `listen_addresses`, `bind_to_device`, confederation and route selection options. |
| `StopBgp` | :material-check-circle:{ .ok } Implemented | Sends Cease to peers (or closes silently toward GR-capable peers when `allow_graceful_restart` is set), and stops BMP, RPKI, MRT and `WatchEvent` streams. |
| `GetBgp` | :material-alert-circle:{ .partial } Partial | Returns ASN, router ID, listen port, confederation and route selection options. `listen_addresses`, `families`, `graceful_restart` and `bind_to_device` are always empty. |
| `SetLogLevel` | :material-check-circle:{ .ok } Implemented | `PANIC`, `FATAL` and `ERROR` all map to the error level. |
| `WatchEvent` | :material-alert-circle:{ .partial } Partial | Peer state, Adj-RIB-In, post-policy, best-path and End-of-RIB events. `batch_size` and `peer_group` are ignored; each event is sent in its own message. |

### Peers

| RPC | Status | Notes |
|---|---|---|
| `AddPeer` | :material-check-circle:{ .ok } Implemented | Supports `neighbor_interface` (unnumbered BGP). The IPv6 link-local address is discovered through the neighbor table. |
| `DeletePeer` | :material-check-circle:{ .ok } Implemented | |
| `ListPeer` | :material-check-circle:{ .ok } Implemented | Optional address filter. Includes message and route counters. |
| `UpdatePeer` | :material-alert-circle:{ .partial } Partial | Full replace. `route_server_client` and `route_reflector_client` cannot be changed. Changing transport, ASN, capabilities, hold time, TTL or password restarts the session. `needs_soft_reset_in` is always `false`. |
| `ResetPeer` | :material-check-circle:{ .ok } Implemented | A hard reset sends Cease and keeps the peer configured. A soft reset requires direction `IN`, `OUT` or `BOTH`. |
| `ShutdownPeer` | :material-alert-circle:{ .partial } Partial | Administrative shutdown. The `communication` text (RFC 9003) is not sent. |
| `EnablePeer`, `DisablePeer` | :material-check-circle:{ .ok } Implemented | |
| `AddPeerGroup`, `DeletePeerGroup`, `UpdatePeerGroup`, `ListPeerGroup` | :material-check-circle:{ .ok } Implemented | |
| `AddDynamicNeighbor`, `DeleteDynamicNeighbor`, `ListDynamicNeighbor` | :material-check-circle:{ .ok } Implemented | |

### Routes and tables

| RPC | Status | Notes |
|---|---|---|
| `AddPath` | :material-check-circle:{ .ok } Implemented | Global or VRF table. Returns a 16-byte UUID for the path; a withdraw returns an empty UUID. |
| `DeletePath` | :material-check-circle:{ .ok } Implemented | By UUID, by path, or all paths of a family. VRF delete-all supports IPv4 and IPv6 unicast. |
| `AddPathStream` | :material-check-circle:{ .ok } Implemented | Client streaming. Each message is applied atomically: all of its paths are validated before any is installed. The first error ends the stream. `table_type` must be set to global or VRF. |
| `ListPath` | :material-alert-circle:{ .partial } Partial | Global, local (route-server clients), Adj-RIB-In, Adj-RIB-Out and VRF (IPv4/IPv6) tables. Exact, longer-prefix and shorter-prefix lookups. `batch_size` caps the **total** number of paths returned, not the size of each message. |
| `GetTable` | :material-check-circle:{ .ok } Implemented | |
| `AddVrf`, `DeleteVrf`, `ListVrf` | :material-check-circle:{ .ok } Implemented | Import route targets are also originated as RT-Constraint (RFC 4684) NLRI. |

### Policy

| RPC | Status | Notes |
|---|---|---|
| `AddDefinedSet`, `DeleteDefinedSet`, `ListDefinedSet` | :material-check-circle:{ .ok } Implemented | `AddDefinedSet` supports `replace`. |
| `AddStatement`, `DeleteStatement`, `ListStatement` | :material-check-circle:{ .ok } Implemented | |
| `AddPolicy`, `DeletePolicy`, `ListPolicy`, `SetPolicies` | :material-check-circle:{ .ok } Implemented | `SetPolicies` replaces all policies atomically. |
| `AddPolicyAssignment`, `DeletePolicyAssignment`, `ListPolicyAssignment`, `SetPolicyAssignment` | :material-alert-circle:{ .partial } Partial | Per-peer assignments apply to export only. Import policy is global. |

### RPKI

| RPC | Status | Notes |
|---|---|---|
| `AddRpki`, `DeleteRpki`, `ListRpki` | :material-check-circle:{ .ok } Implemented | |
| `EnableRpki`, `DisableRpki`, `ResetRpki` | :material-check-circle:{ .ok } Implemented | `ResetRpki` supports soft and hard resets. |
| `ListRpkiTable` | :material-check-circle:{ .ok } Implemented | Family defaults to IPv4. |

### Monitoring and FIB

| RPC | Status | Notes |
|---|---|---|
| `AddBmp`, `DeleteBmp`, `ListBmp` | :material-check-circle:{ .ok } Implemented | Monitoring policies `PRE`, `POST`, `BOTH`, `LOCAL` and `ALL`. |
| `EnableMrt`, `DisableMrt` | :material-check-circle:{ .ok } Implemented | `UPDATES` and `TABLE` dumps with rotation. |
| `EnableZebra` | :material-swap-horizontal:{ .partial } Different semantics | RustyBGP does not speak the Zebra protocol. This RPC starts the built-in Linux netlink integration instead; `route_types` selects which kernel routes are redistributed into BGP. See [Kernel FIB integration](../user-guide/kernel-fib.md). |

## Streaming behavior

Server-streaming RPCs (`ListPath`, `ListPeer`, `ListDefinedSet` and so on)
take a snapshot of the requested state and send it from a background task
through a bounded channel. `ListPath` converts routes to protobuf lazily, so a
slow client applies backpressure instead of forcing the daemon to buffer the
whole table. If the client disconnects, the task stops.

`ListPath` on the Adj-RIB-Out is computed on demand by running export
processing over the Loc-RIB for that peer, so its cost is proportional to the
size of the table.

`WatchEvent` proceeds in phases:

1. With a peer filter, an `INIT` event for each established peer, followed by
   `END_OF_INIT`.
2. With `init` set on a table filter, a snapshot of the Adj-RIB-In,
   post-policy or best-path table.
3. A live stream of peer state changes, path updates and End-of-RIB markers.

`StopBgp` ends all active `WatchEvent` streams.
