# Troubleshooting

Start with the logs. Increase the level with `RUST_LOG=debug` when needed;
see [Command line](command-line.md#logging).

## The daemon does not start

| Symptom | Cause and fix |
|---|---|
| `invalid configuration` | The file failed to parse or validate. The message names the problem. Typical causes: a misspelled key (unknown keys are rejected), a missing `global.config.as` or `router-id`, `hold-time` between 1 and 2, or a per-neighbor import policy. |
| `port 0 is not valid in config` | Use `port: -1` to disable the listener, or omit `port` for 179. |
| Error binding the listener | Port 179 is in use (another BGP daemon, such as `gobgpd` or `bird`) or the process lacks `CAP_NET_BIND_SERVICE`. Check with `ss -ltnp 'sport = :179'`. |
| `failed to listen on grpc` | The `--api-hosts` address is in use or does not exist on the host. |
| `invalid API host address` | `--api-hosts` needs `address:port`, with brackets for IPv6. |

## A session does not establish

Check the state:

```bash
gobgp neighbor
gobgp neighbor 198.51.100.2
```

| State | Likely cause |
|---|---|
| `Idle` (admin) | The neighbor is disabled. Run `gobgp neighbor <addr> enable`. |
| `Active` / `Connect` | No TCP connection. Check reachability, firewalls on TCP 179, and that the neighbor is configured to peer with this address. For eBGP over more than one hop, configure `ebgp-multihop` or `ttl-security`. With `local-address`, make sure the address exists locally and the neighbor targets it. |
| `OpenSent` then back to `Active` | The neighbor rejected the OPEN. Look for the NOTIFICATION in the log. Common causes: wrong AS (Bad Peer AS), mismatched router ID, MD5 password mismatch (the connection is silently dropped), or GTSM on the neighbor dropping the SYN. |
| `Established`, then flapping | Hold timer expiry: check for packet loss or CPU starvation. A BFD failure closes the session without a NOTIFICATION. Exceeding `max-prefixes` sends Cease subcode 1. |

Capture the exchange if needed:

```bash
sudo tcpdump -ni any 'tcp port 179 and host 198.51.100.2' -w bgp.pcap
```

### Unnumbered neighbors

If the log shows `skipping unnumbered peer <if>: NDP lookup failed`, no IPv6
neighbor entry existed for the interface when the configuration was loaded.
Bring the link up and populate the neighbor table (`ping -6 ff02::1%eth0`),
then restart `rustybgpd`. Changes to unnumbered neighbors are not applied on
reload.

## Routes are missing

Follow the route through each stage:

```bash
gobgp neighbor 198.51.100.2 adj-in 203.0.113.0/24      # received?
gobgp global rib 203.0.113.0/24                         # in the Loc-RIB? best?
gobgp neighbor 198.51.100.3 adj-out 203.0.113.0/24     # sent to the other neighbor?
```

| Received but not in the RIB | Possible reason |
|---|---|
| Rejected by import policy | Check `gobgp policy` and the global import assignment. |
| Loop detected | The AS_PATH contains the local AS, or the ORIGINATOR_ID or CLUSTER_LIST matches this router. |
| Next hop unreachable | With kernel integration, nexthop tracking marks paths whose next hop has no non-BGP route as ineligible. Check `ip route get <nexthop>`. |
| Treated as withdrawn | A malformed attribute triggered RFC 7606 treat-as-withdraw. Check the log. |

| In the RIB but not advertised | Possible reason |
|---|---|
| Not the best path | Without Add-Path, only the best path is advertised. |
| Export policy | Check the neighbor's export assignment, or the global one. |
| iBGP split horizon | iBGP-learned routes are not sent to other iBGP neighbors unless this router is a route reflector. |
| Well-known community | `NO_EXPORT`, `NO_ADVERTISE` or `NO_EXPORT_SUBCONFED` blocks it. |
| Family not negotiated | Check the negotiated capabilities in `gobgp neighbor <addr>`. |
| RT-Constraint | For VPN routes, the neighbor has not advertised interest in the route targets. |

After changing policies, run a soft reset: existing routes are not
re-evaluated automatically.

## Routes are not in the kernel

- Check that kernel integration is enabled (`zebra.config.enabled = true`) and
  that the log shows `kernel route integration enabled`.
- Only best paths for IPv4 and IPv6 unicast learned from BGP neighbors are
  installed. Routes added with `gobgp global rib add` are not.
- The process needs `CAP_NET_ADMIN`.
- `ip route show proto bgp` lists what RustyBGP installed.

## Stale routes in the kernel after a crash

RustyBGP does not remove its kernel routes on exit. They are replaced as the
next instance learns best paths. To clear them:

```bash
sudo ip route flush proto bgp
sudo ip -6 route flush proto bgp
```

## Reporting a bug

Include:

- `rustybgpd --version`
- The configuration, with passwords removed
- Logs at `RUST_LOG=debug` around the event
- A packet capture of the affected session if the problem is on the wire

Open an issue on the [repository](https://github.com/osrg/rustybgp/issues).
