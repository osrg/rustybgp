# Route reflection and route servers

## Route reflector

A route reflector (RFC 4456) removes the need for a full iBGP mesh. Mark each
client with `route-reflector-client`:

```yaml
global:
  config:
    as: 65001
    router-id: "172.30.10.1"

neighbors:
  - config:
      neighbor-address: "172.30.10.2"
      peer-as: 65001
    route-reflector:
      config:
        route-reflector-client: true
        route-reflector-cluster-id: "172.30.10.1"
    afi-safis:
      - config: { afi-safi-name: ipv4-unicast }

  - config:
      neighbor-address: "172.30.10.3"
      peer-as: 65001
    route-reflector:
      config:
        route-reflector-client: true
    afi-safis:
      - config: { afi-safi-name: ipv4-unicast }

  - config:                                # a regular eBGP neighbor
      neighbor-address: "172.30.11.2"
      peer-as: 65002
```

| Option | Default | Description |
|---|---|---|
| `route-reflector-client` | `false` | Reflect routes to and from this iBGP neighbor. |
| `route-reflector-cluster-id` | Router ID | Cluster ID, as an IPv4 address. |

Reflection rules:

- Routes from a client are reflected to all other clients and to non-clients.
- Routes from a non-client are reflected to clients only.
- When reflecting, RustyBGP sets ORIGINATOR_ID if it is absent and prepends its
  cluster ID to CLUSTER_LIST.
- A received route whose ORIGINATOR_ID equals the local router ID, or whose
  CLUSTER_LIST contains the local cluster ID, is treated as a loop and
  withdrawn.
- ORIGINATOR_ID and CLUSTER_LIST are removed before advertising to eBGP
  neighbors.

Whether a neighbor is a route-reflector client cannot be changed with
`UpdatePeer`; delete and re-add the neighbor.

## Confederation

A confederation (RFC 5065) splits an AS into member sub-ASes:

```yaml
global:
  config:
    as: 65001                 # this router's member AS
    router-id: "172.30.20.1"
  confederation:
    config:
      enabled: true
      identifier: 65000       # the AS the outside world sees
      member-as-list: [65001, 65002]

neighbors:
  - config:                   # another member AS: confederation eBGP
      neighbor-address: "172.30.20.2"
      peer-as: 65002
  - config:                   # outside the confederation: plain eBGP
      neighbor-address: "172.30.21.2"
      peer-as: 65100
```

Toward other members, RustyBGP prepends its member AS in an
`AS_CONFED_SEQUENCE` segment and keeps LOCAL_PREF and MED. At the
confederation boundary it removes the confederation segments and prepends the
confederation identifier. Confederation segments do not count toward AS_PATH
length in best-path selection.

## Route server

A route server (RFC 7947) at an internet exchange passes routes between its
clients without inserting itself into the path:

```yaml
global:
  config:
    as: 65000
    router-id: "172.30.30.1"

neighbors:
  - config:
      neighbor-address: "172.30.30.2"
      peer-as: 65001
    route-server:
      config:
        route-server-client: true
  - config:
      neighbor-address: "172.30.30.3"
      peer-as: 65002
    route-server:
      config:
        route-server-client: true
```

Toward route-server clients, RustyBGP does not prepend its own AS and leaves
NEXT_HOP and MED unchanged.

!!! warning "Single best path"

    RustyBGP computes one best path per prefix for all clients. It does not
    keep a separate Loc-RIB per client, so when a client's export policy
    rejects the overall best path, that client does not receive the next-best
    alternative. This is the "path hiding" problem described in RFC 7947
    §2.3.2.1. Add-Path toward clients can mitigate it.

As with route-reflector clients, `route-server-client` cannot be changed with
`UpdatePeer`.
