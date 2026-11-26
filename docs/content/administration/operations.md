# Operations

Day-two tasks, using the `gobgp` CLI. Every command maps to a gRPC call, so the
same operations can be automated; see [Automation](../automation/index.md).

## Checking health

```bash
gobgp global                       # AS, router ID: confirms BGP is running
gobgp neighbor                     # session states and prefix counts
gobgp neighbor 198.51.100.2        # timers, capabilities, message counters
gobgp global rib summary -a ipv4   # table size
gobgp rpki server                  # RTR cache sessions
```

## Soft reset

A soft reset re-applies policy without tearing the session down.

| Command | Effect |
|---|---|
| `gobgp neighbor <addr> softresetin` | Re-runs import policy over the neighbor's stored, pre-policy routes. No ROUTE-REFRESH is sent. |
| `gobgp neighbor <addr> softresetout` | Re-runs export policy and re-advertises to the neighbor. |
| `gobgp neighbor <addr> softreset` | Both. |

`ResetPeer` accepts one neighbor address per call. To reset every neighbor:

```bash
gobgp -j neighbor | jq -r '.[].state.neighbor_address' |
  while read -r peer; do gobgp neighbor "$peer" softreset; done
```

Run a soft reset after changing policies, and after an RPKI data change if you
filter on validation state.

## Hard reset

```bash
gobgp neighbor 198.51.100.2 reset
```

Sends a Cease NOTIFICATION, closes the session, and reconnects. The neighbor
stays configured.

## Taking a neighbor out of service

```bash
gobgp neighbor 198.51.100.2 disable     # close the session and keep it down
gobgp neighbor 198.51.100.2 enable      # allow it to reconnect
```

A disabled neighbor also refuses inbound connections. To start a neighbor
disabled, set `admin-down: true` in its configuration.

### Draining traffic first

To move traffic away before maintenance, make the router's paths less
preferred before disabling sessions, for example by tagging exports with the
`graceful-shutdown` community (RFC 8326) through an export policy, applying it
with SIGHUP, and running `softresetout`. Neighbors that honor the community
lower the LOCAL_PREF of those routes.

## Planned shutdown

RustyBGP does not handle SIGTERM or SIGINT: the process exits at once, and
neighbors see the TCP connection close without a NOTIFICATION. For a clean
shutdown, stop BGP through the API first. Every neighbor then receives a Cease
NOTIFICATION:

```bash
grpcurl -plaintext -d '{}' 127.0.0.1:50051 api.GoBgpService/StopBgp
sudo systemctl stop rustybgpd
```

To let neighbors keep forwarding while RustyBGP restarts (Graceful Restart),
call `StopBgp` with `allow_graceful_restart` set, so that sessions with
GR-capable neighbors are closed without a NOTIFICATION, then start the new
process with `--graceful-restart`:

```bash
grpcurl -plaintext -d '{"allow_graceful_restart": true}' \
  127.0.0.1:50051 api.GoBgpService/StopBgp
sudo systemctl restart rustybgpd   # unit runs rustybgpd ... --graceful-restart
```

!!! note

    `grpcurl` needs the protobuf definitions, because RustyBGP does not
    enable gRPC server reflection. Pass them with
    `-import-path api/proto -proto gobgp.proto`.

## Upgrades

1. Download and verify the new binary.
2. Replace `/usr/local/bin/rustybgpd`.
3. Restart, gracefully if neighbors support it (see above).
4. Check `rustybgpd --version`, `gobgp neighbor`, and table sizes.

Routes installed in the kernel stay in place during the restart, and the new
process replaces them as it relearns best paths.

## Prefix limits

When a neighbor exceeds `max-prefixes`, its session is closed with a Cease
(Maximum Number of Prefixes Reached) NOTIFICATION. RustyBGP reconnects after
the connect-retry interval; there is no automatic restart timer. Investigate
before re-enabling, or raise the limit.

## Managing RPKI caches

```bash
gobgp rpki server 192.0.2.50 add
gobgp rpki server 192.0.2.50 reset       # hard reset: drop and re-fetch ROAs
gobgp rpki server 192.0.2.50 softreset   # request incremental update
gobgp rpki server 192.0.2.50 disable
gobgp rpki server 192.0.2.50 enable
```
