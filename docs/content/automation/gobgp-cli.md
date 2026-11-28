# GoBGP CLI

Because RustyBGP implements the GoBGP v4 gRPC API, the standard
[`gobgp`](https://github.com/osrg/gobgp/releases) command-line client is the
primary interactive tool. The project's end-to-end tests use `gobgp` v4.3.0
against `rustybgpd`; any v4 release should work.

!!! note "Use a v4 client"

    GoBGP v3 and earlier use a different protobuf package and cannot talk to
    RustyBGP. Check with `gobgp --version`.

## Connecting

By default `gobgp` connects to `127.0.0.1:50051`. Use `-u` (host) and `-p`
(port) to reach another endpoint:

```bash
gobgp -u 192.0.2.10 -p 50051 neighbor
```

Add `-j` to any read command to get JSON output for scripts:

```bash
gobgp -j global rib -a ipv4 | jq '.[] | length'
```

## Global state

```bash
# Show the local AS, router ID and listen port
gobgp global

# Show the global RIB for a family
gobgp global rib -a ipv4
gobgp global rib -a ipv6
gobgp global rib -a evpn
```

## Neighbors

```bash
# Summary of all neighbors
gobgp neighbor

# Detailed state of one neighbor
gobgp neighbor 198.51.100.2

# Routes received from, accepted from, and advertised to a neighbor
gobgp neighbor 198.51.100.2 adj-in
gobgp neighbor 198.51.100.2 local
gobgp neighbor 198.51.100.2 adj-out

# Soft reset: re-run policy without tearing the session down
gobgp neighbor 198.51.100.2 softresetin
gobgp neighbor 198.51.100.2 softresetout

# Hard reset, administrative shutdown, and re-enable
gobgp neighbor 198.51.100.2 reset
gobgp neighbor 198.51.100.2 disable
gobgp neighbor 198.51.100.2 enable
```

## Originating routes

```bash
# IPv4 unicast with an explicit next hop
gobgp global rib add 10.0.1.0/24 nexthop 172.30.50.1

# With communities and a path identifier (Add-Path)
gobgp global rib add 198.51.100.42/32 community 65000:100 identifier 1

# Withdraw a single route, or every route of a family
gobgp global rib del 198.51.100.42/32 identifier 1
gobgp global rib del all -a ipv4
```

Deleting a route that does not exist is not an error, so withdraw commands are
safe to repeat.

## FlowSpec

```bash
# Drop traffic to a prefix (IPv4)
gobgp global rib add -a ipv4-flowspec \
  match destination 203.0.113.0/24 then discard

# Drop DNS to a host (IPv6)
gobgp global rib add -a ipv6-flowspec \
  match destination 2001:db8::42/128 protocol udp destination-port ==53 \
  then discard

gobgp global rib -a ipv4-flowspec
```

## VRFs

```bash
gobgp vrf add blue rd 65001:1 rt both 65001:1
gobgp vrf blue rib add 198.51.100.42/32
gobgp vrf blue rib -a ipv4
gobgp vrf blue rib del 198.51.100.42/32
gobgp vrf del blue
```

## RPKI

```bash
# Cache servers and their session state
gobgp rpki server

# Validated ROA payloads received from the caches
gobgp rpki table
```

## BMP

```bash
# Stream to a BMP collector; the last argument is the monitoring policy
gobgp bmp add 192.0.2.50 pre
gobgp bmp add 192.0.2.50 both
gobgp bmp add 192.0.2.50 local-rib
gobgp bmp add 192.0.2.50 all
```

## Scripting patterns

### Wait for the daemon to come up

`gobgp global` fails until the API is serving and BGP is started. The test
harness uses this as a readiness probe:

```bash
for _ in $(seq 1 30); do
  gobgp global >/dev/null 2>&1 && break
  sleep 1
done
```

### Wait for a session to establish

```bash
peer=198.51.100.2
until gobgp neighbor "$peer" | grep -iE 'BGP state = .*established' >/dev/null; do
  sleep 1
done
```

### Machine-readable output

Any read command accepts `-j`:

```bash
gobgp -j neighbor | jq .
gobgp -j global rib -a ipv4 | jq 'length'
```

!!! tip

    JSON field names follow the protobuf messages in `gobgp.proto`. When a
    `jq` filter returns nothing, inspect the raw output with `gobgp -j ... | jq .`
    first.
