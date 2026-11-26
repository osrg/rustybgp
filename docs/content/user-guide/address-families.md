# Address families

Each neighbor negotiates a list of address families (AFI/SAFI) with the
Multiprotocol Extensions capability (RFC 4760). List them under `afi-safis`:

```yaml
neighbors:
  - config:
      neighbor-address: "2001:db8::2"
      peer-as: 65002
    afi-safis:
      - config: { afi-safi-name: ipv6-unicast }
      - config: { afi-safi-name: ipv4-unicast }
```

Without `afi-safis`, the neighbor negotiates the unicast family matching its
own address family.

## Supported families

| `afi-safi-name` | Family | Specification |
|---|---|---|
| `ipv4-unicast`, `ipv6-unicast` | IP unicast | RFC 4271, RFC 4760, RFC 2545 |
| `ipv4-multicast`, `ipv6-multicast` | IP multicast (RPF) | RFC 4760 |
| `ipv4-labelled-unicast`, `ipv6-labelled-unicast` | Labeled unicast | RFC 8277 |
| `l3vpn-ipv4-unicast`, `l3vpn-ipv6-unicast` | BGP/MPLS IP VPN | RFC 4364, RFC 4659 |
| `l2vpn-evpn` | EVPN route types 1 to 5 | RFC 7432, RFC 9136 |
| `ipv4-flowspec`, `ipv6-flowspec` | Flow specification | RFC 8955, RFC 8956 |
| `l3vpn-ipv4-flowspec`, `l3vpn-ipv6-flowspec` | VPN flow specification | RFC 8955, RFC 8956 |
| `ls` | BGP Link-State | RFC 9552 |
| `ipv4-srpolicy`, `ipv6-srpolicy` | Segment Routing Policy | RFC 9830 |
| `ipv4-mup`, `ipv6-mup` | Mobile User Plane | draft-ietf-bess-mup-safi |
| `rtc` | Route Target Constraint | RFC 4684 |

The GoBGP schema also contains names such as `l2vpn-vpls`,
`l3vpn-ipv4-multicast`, `ipv4-encap` and `opaque`. RustyBGP accepts them in
the file but does not negotiate them.

!!! note "EVPN"

    RustyBGP carries and relays EVPN routes of types 1 to 5. It does not
    implement an EVPN control plane: there is no MAC-VRF import or export
    based on route targets.

## Capabilities advertised automatically

Every session advertises:

- 4-octet AS numbers (RFC 6793)
- Route Refresh (RFC 2918)
- Extended Messages (RFC 8654)
- Extended Next Hop encoding for IPv4 families (RFC 8950), so IPv4 routes can
  carry IPv6 next hops

## Add-Path

Add-Path (RFC 7911) lets a session carry more than one path per prefix. It is
configured per family:

```yaml
afi-safis:
  - config:
      afi-safi-name: ipv4-unicast
    add-paths:
      config:
        receive: true      # accept multiple paths from this neighbor
        send-max: 2        # advertise up to 2 paths to this neighbor
```

`send-max` is limited to 255. Sending is enabled only if the neighbor
advertised that it can receive. The neighbor-level `add-paths` container is
rejected; use the per-family setting.

## Route Target Constraint

With the `rtc` family negotiated, RustyBGP advertises membership for the
import route targets of its VRFs, and sends VPN routes to a neighbor only if
they match route targets the neighbor has advertised. The initial VPN table
dump waits for the neighbor's RTC End-of-RIB (or 60 seconds).

## Originating routes in other families

Use the `gobgp` CLI or the API. For example, a FlowSpec rule:

```bash
gobgp global rib add -a ipv4-flowspec match destination 203.0.113.0/24 then discard
```

or an EVPN route, SR Policy or BGP-LS NLRI through `AddPath`. See
[GoBGP CLI](../automation/gobgp-cli.md) and
[Programmatic clients](../automation/programmatic-clients.md).
