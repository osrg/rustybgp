# Graceful Restart

Graceful Restart (RFC 4724) lets forwarding continue while a BGP speaker
restarts. Long-Lived Graceful Restart (RFC 9494) extends this with a second,
much longer phase in which stale routes are kept but less preferred.

RustyBGP supports both roles:

- **Helper (receiving speaker):** when a neighbor restarts, keep its routes,
  marked stale, until it comes back and sends End-of-RIB.
- **Restarting speaker:** when RustyBGP itself restarts, ask neighbors to keep
  its routes, and defer best-path selection until they have resent theirs.

## Helper mode

Enable Graceful Restart on the neighbor, and on each family that should be
preserved:

```yaml
neighbors:
  - config:
      neighbor-address: "172.30.5.2"
      peer-as: 65002
    graceful-restart:
      config:
        enabled: true
        restart-time: 120          # seconds, at most 4095
        notification-enabled: true # RFC 8538: also keep routes after a NOTIFICATION
    afi-safis:
      - config:
          afi-safi-name: ipv4-unicast
        mp-graceful-restart:
          config:
            enabled: true
```

The Graceful Restart capability is advertised only when at least one family
has `mp-graceful-restart` enabled.

When a session with a GR-capable neighbor drops:

1. Its routes in the negotiated families are marked stale and kept.
2. If it does not reconnect within the restart time it advertised, the stale
   routes are removed.
3. When it reconnects, it resends its routes. On End-of-RIB for a family, any
   routes that are still stale are removed.

A session closed by BFD is torn down without Graceful Restart.

## Long-Lived Graceful Restart

LLGR adds a second phase after the GR restart time expires:

```yaml
afi-safis:
  - config:
      afi-safi-name: ipv4-unicast
    mp-graceful-restart:
      config:
        enabled: true
    long-lived-graceful-restart:
      config:
        enabled: true
        restart-time: 3600         # long-lived stale time, at most 16777215
```

During the long-lived phase:

- Routes carry the `LLGR_STALE` community and are least preferred in
  best-path selection.
- Routes that carry the `NO_LLGR` community are removed when the phase starts.
- If `restart-time` is omitted, the stale time defaults to 600 seconds.

## Restarting mode

To restart RustyBGP without disrupting forwarding at its neighbors, start it
with `--graceful-restart`:

```bash
sudo rustybgpd -f /etc/rustybgp/rustybgpd.yaml --graceful-restart
```

RustyBGP then:

1. Sets the Restart State (R) bit in its Graceful Restart capability.
2. Accepts routes from neighbors but defers best-path selection for GR
   families.
3. Ends the deferral when every GR neighbor has sent End-of-RIB, or when the
   selection deferral timer expires, then sends its own routes and
   End-of-RIB.

The deferral timer is set by `global.graceful-restart.config.stale-routes-time`
(default 360 seconds; `0` waits indefinitely). `--graceful-restart` has an
effect only when a configuration file is given.

```yaml
global:
  config:
    as: 65001
    router-id: "172.30.5.1"
  graceful-restart:
    config:
      stale-routes-time: 120
```

!!! note

    GoBGP uses `deferral-time` for this timer. RustyBGP reads
    `stale-routes-time` instead and ignores `deferral-time`.

To stop RustyBGP without sending NOTIFICATIONs (so that neighbors enter
helper mode), call `StopBgp` with `allow_graceful_restart` set, or stop the
process with a signal. See [Operations](../administration/operations.md).
