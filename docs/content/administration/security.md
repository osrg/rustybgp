# Security hardening

A BGP speaker is part of the network's control plane, and an attacker who can
reach its sessions or its API can redirect traffic. Use the measures on this
page together.

## Protect the gRPC API

The gRPC API has **no authentication, authorization or TLS**, and by default
it listens on every address (`0.0.0.0:50051`). Anyone who can connect can add
neighbors, inject routes and stop BGP.

1. Bind it to loopback:

    ```bash
    rustybgpd -f /etc/rustybgp/rustybgpd.yaml --api-hosts 127.0.0.1:50051
    ```

2. If remote access is required, bind to a management address and allow only
   trusted sources with a host firewall:

    ```bash
    nft add rule inet filter input tcp dport 50051 ip saddr 192.0.2.0/28 accept
    nft add rule inet filter input tcp dport 50051 drop
    ```

3. For authenticated remote access, put a TLS-terminating proxy with client
   certificates (for example Envoy or nginx with gRPC support) in front of a
   loopback-only API, or use an SSH tunnel:

    ```bash
    ssh -N -L 50051:127.0.0.1:50051 router1
    gobgp neighbor        # now reaches router1 through the tunnel
    ```

## Protect BGP sessions

### TCP MD5

```yaml
neighbors:
  - config:
      neighbor-address: "198.51.100.2"
      peer-as: 65002
      auth-password: "use-a-long-random-secret"
```

!!! warning

    If the kernel rejects the key, RustyBGP logs nothing and the session
    proceeds without authentication. Verify with a packet capture that the
    session's TCP segments carry the MD5 signature option (`tcpdump -nv`
    prints `md5` in the TCP options). Passwords on peer groups used for dynamic neighbors are not
    installed. TCP-AO (RFC 5925) is not supported.

### GTSM

For directly connected eBGP neighbors, enable TTL security so that packets
from more than the expected number of hops away are dropped:

```yaml
    ttl-security:
      config:
        enabled: true
        ttl-min: 255
```

GTSM is applied after the TCP connection is established, so RustyBGP's own
outbound SYN is sent with the default TTL. If the neighbor enforces GTSM on
the SYN, let it initiate the session (`passive-mode` on RustyBGP).

### Limit who can connect

- Prefer explicit neighbors over `--any-peers` and broad dynamic-neighbor
  ranges.
- Filter TCP 179 at the host firewall to known neighbor addresses.
- Set `max-prefixes` on every eBGP session.

## Filter routes

RustyBGP accepts all routes by default when no policy is configured. It does
not apply RFC 8212's reject-by-default rule for eBGP. On internet-facing
routers:

- Configure explicit import and export policies, and set
  `default-import-policy` and `default-export-policy` to `reject-route`.
- Reject bogon prefixes and bogon ASNs on import.
- Enable [RPKI origin validation](../user-guide/rpki.md) and reject `invalid`
  routes.
- Strip or reject communities you do not want to honor from customers.

## Reduce privileges

Run as an unprivileged user with only the capabilities you need. See
[Deployment](deployment.md#privileges) for a hardened systemd unit.

## Keep current

Fixes for malformed-input handling land regularly. Track the
[RFC support](../reference/rfc-support.md#known-gaps) page for known robustness
issues and upgrade promptly.
