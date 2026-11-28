# BFD

Bidirectional Forwarding Detection (RFC 5880) detects a failed forwarding path
in well under a second, much faster than the BGP hold timer. RustyBGP runs
single-hop BFD (RFC 5881) and tears down the BGP session as soon as BFD
reports the path down (RFC 5882).

## Configuration

```yaml
neighbors:
  - config:
      neighbor-address: 172.30.9.2
      peer-as: 65002
    bfd:
      config:
        enabled: true
        desired-minimum-tx-interval: 300000   # microseconds
        required-minimum-receive: 300000      # microseconds
        detection-multiplier: 3
```

| Option | Default | Description |
|---|---|---|
| `enabled` | `false` | Run a BFD session with this neighbor. |
| `desired-minimum-tx-interval` | `1000000` | Interval between transmitted control packets, in microseconds. |
| `required-minimum-receive` | `1000000` | Shortest interval at which this system can receive packets, in microseconds. |
| `detection-multiplier` | `3` | Missed packets before the session is declared down. |

With the values above, a failure is detected in about 900 ms.

BFD control packets use UDP destination port 3784 and source ports 49152 to
65535. They are sent with TTL 255, and on Linux packets received with a lower
TTL are dropped (GTSM). The `port` option is ignored.

## Behavior on failure

When the BFD session goes down, RustyBGP closes the BGP session immediately
without sending a NOTIFICATION, and does not start Graceful Restart for that
failure: routes from the neighbor are withdrawn at once.

## Limitations

- Only single-hop IPv4 sessions work. The receive socket is bound to
  `0.0.0.0`, so IPv6 control packets are never received. Multihop BFD
  (RFC 5883) is not supported.
- A neighbor that signals AdminDown in BFD also brings the BGP session down.
- BFD settings cannot be inherited from a peer group.
- Dynamic neighbors do not run BFD.

Check the [RFC support](../reference/rfc-support.md#bfd) page for known
conformance gaps.

## Firewall

Allow UDP 3784 between the neighbors in both directions:

```bash
nft add rule inet filter input udp dport 3784 ip saddr 172.30.9.2 accept
```
