# Subsystems

Beyond the core BGP pipeline, `rustybgpd` contains several independent
services. Each one runs as its own task and connects to the table through
subscriptions or direct calls.

## BMP (BGP Monitoring Protocol)

`daemon/src/bmp.rs` is a BMP client (RFC 7854). For each configured station it:

1. Connects over TCP, with a 5-second connect timeout and a 10-second retry
   interval.
2. Sends an Initiation message.
3. Subscribes to the table with a snapshot, and sends Peer Up for every
   established peer, Route Monitoring for the current routes according to the
   monitoring policy, and End-of-RIB.
4. Streams live events: peer state changes and route changes.

| Policy | Content |
|---|---|
| `pre` | Adj-RIB-In before import policy |
| `post` | Adj-RIB-In after import policy |
| `both` | Pre- and post-policy |
| `local` | Loc-RIB (RFC 9069) |
| `all` | Pre-policy, post-policy, Loc-RIB and Adj-RIB-Out (RFC 8671) |

Adj-RIB-Out monitoring is fed from each peer's export path, so it reflects
exactly what was sent.

## BFD (Bidirectional Forwarding Detection)

`daemon/src/bfd.rs` implements single-hop BFD (RFC 5880, RFC 5881). The
receive socket is bound to `0.0.0.0`, so only IPv4 sessions work today. A UDP server on port 3784 receives control packets, and each
BFD-enabled neighbor has its own state machine task. Packets are sent with
TTL 255, and on Linux the receive socket drops packets with a lower TTL.

When a BFD session goes down, the BGP session is closed immediately without a
NOTIFICATION (RFC 5882), and Graceful Restart is not invoked for that failure.
The BFD service starts lazily when the first BFD-enabled neighbor is added.

## RPKI (RTR client)

`daemon/src/rpki.rs` connects to RPKI-to-Router caches (RFC 6810, RFC 8210):

1. On connect it sends an RTR version 1 Reset Query, collects prefix records until End of
   Data, and replaces that cache's ROAs in the table atomically.
2. It then applies incremental announcements and withdrawals.
3. A Serial Notify from the cache, or a soft reset from the API, triggers a
   Serial Query.
4. When the connection drops, the cache's ROAs are removed.

ROAs are kept in a read-write-locked table shared by all shards. Origin
validation (RFC 6811) runs when routes are listed through the API and when a
policy uses the `rpki-validation-result` condition.

## MRT

`daemon/src/mrt.rs` writes MRT files (RFC 6396):

| Dump type | Content |
|---|---|
| `updates` | Every received UPDATE as a BGP4MP message, from the Adj-RIB-In event stream. |
| `table` | Periodic TABLE_DUMP_V2 snapshots of the RIB. |

When a rotation interval is set, the file name is treated as a `strftime`
pattern, and a new file is opened every interval. For table dumps, the rotation
interval is also the snapshot interval.

## TCP authentication and TTL security

`daemon/src/auth.rs` configures sockets:

- **TCP MD5** (RFC 2385) with `TCP_MD5SIG_EXT`, applied to outbound sockets and
  to the listening sockets for each configured peer. When a neighbor is bound
  to an interface, the key is scoped to that interface.
- **GTSM** (RFC 5082) with `IP_MINTTL` or `IPV6_MINHOPCOUNT`, together with an
  outgoing TTL of 255.

## Configuration loading and reload

The configuration file is parsed by the `config` crate, which accepts TOML or
YAML in the GoBGP schema and rejects unknown keys. At startup the daemon
applies, in order: global settings and listening sockets, MRT, kernel
integration, BMP, peer groups, policies, dynamic neighbors, neighbors, RPKI,
and Graceful Restart deferral.

On SIGHUP, the reloader re-reads the file, computes the difference with the
running configuration, and applies the parts that can change at runtime.
See [Configuration reload](../administration/configuration-reload.md).

## gRPC service

`daemon/src/event/grpc.rs` implements `GoBgpService` with tonic, and
`daemon/src/convert.rs` converts between protobuf messages and internal types.
See [gRPC API](../automation/grpc-api.md).
