# Kernel FIB

RustyBGP can install its best paths into the Linux routing table and
redistribute kernel routes into BGP. It does this natively over netlink; no
Zebra or FRR daemon is involved. For the internals, see
[Kernel integration](../architecture/kernel-integration.md).

## Enabling it

The integration is enabled through GoBGP's `zebra` section, kept for
compatibility:

=== "TOML"

    ```toml
    [zebra.config]
      enabled = true
      redistribute-route-type-list = ["connect", "static"]
    ```

=== "YAML"

    ```yaml
    zebra:
      config:
        enabled: true
        redistribute-route-type-list: [connect, static]
    ```

Or at runtime with the `EnableZebra` RPC. Other `zebra` options (`url`,
`version`, `nexthop-trigger-enable` and so on) are ignored. The daemon needs
`CAP_NET_ADMIN`.

## What gets installed

- Best paths for **IPv4 and IPv6 unicast** prefixes learned from BGP
  neighbors.
- **ECMP** routes when several paths tie with the best path up to the
  router-ID comparison.
- **L3VPN** routes, into the routing table of each VRF whose import route
  targets match.

Routes are tagged `proto bgp` and use the best path's MED as their metric:

```console
$ ip route show proto bgp
192.0.2.0/24 proto bgp metric 0
        nexthop via 198.51.100.2 dev eth0 weight 1
        nexthop via 198.51.100.6 dev eth1 weight 1
203.0.113.0/24 via 198.51.100.2 dev eth0 proto bgp metric 50
```

Routes originated through the API or redistributed from the kernel are not
written back to the kernel.

## Nexthop tracking

With the integration enabled, RustyBGP watches every BGP next hop. A path
whose next hop is not reachable through a non-BGP route (connected, static,
or an IGP) becomes ineligible for best-path selection, and an alternative is
chosen. When the next hop becomes reachable again the path is restored.

## Redistribution into BGP

`redistribute-route-type-list` selects kernel routes to inject into BGP:

| Value | Kernel routes with protocol |
|---|---|
| `connect` | `kernel` |
| `static` | `static` |
| `ospf`, `isis`, `rip`, `eigrp`, `babel`, `zebra` | The protocol of the same name |

An empty or missing list redistributes routes of every protocol except BGP.

Interface addresses are always redistributed as connected routes while the
integration is enabled (loopback and link-local addresses excluded). Control
what is actually advertised with an export policy, for example:

```yaml
defined-sets:
  prefix-sets:
    - prefix-set-name: advertise
      prefix-list:
        - ip-prefix: 203.0.113.0/24
policy-definitions:
  - name: only-advertise
    statements:
      - name: allow
        conditions:
          match-prefix-set: { prefix-set: advertise }
        actions:
          route-disposition: accept-route
      - name: deny-local
        conditions:
          bgp-conditions: { route-type: local }
        actions:
          route-disposition: reject-route
```

## VRFs

Create a VRF with a non-zero ID through the API to have RustyBGP create a Linux
VRF device with the matching routing table:

```bash
gobgp vrf add blue id 100 rd 65001:100 rt both 65001:100
ip -d link show type vrf
```

Bind sessions to the VRF with `transport.config.bind-interface`, and the
listening sockets with `global.config.bind-to-device`.

## Operational notes

- Changing the `zebra` section requires a restart.
- RustyBGP does not remove its routes from the kernel when it exits. They stay
  until the next instance replaces them or you flush them:

    ```bash
    sudo ip route flush proto bgp
    sudo ip -6 route flush proto bgp
    ```
