---
hide:
  - navigation
---

# RustyBGP

**RustyBGP** is a BGP implementation written in Rust and built for multicore
systems. It speaks the same gRPC API and reads the same configuration file
format as [GoBGP](https://github.com/osrg/gobgp), so `rustybgpd` can replace
`gobgpd` without changing your tooling, and it programs the Linux kernel's
forwarding table directly.

<div class="grid cards" markdown>

-   :lucide-rocket: **Getting started**

    ---

    Download a static binary, write a ten-line configuration, and bring up
    your first session.

    [:octicons-arrow-right-24: Quick start](getting-started/quick-start.md)

-   :lucide-layers: **Architecture**

    ---

    Sharded routing table, per-connection tasks, the route pipeline and
    kernel integration.

    [:octicons-arrow-right-24: How it works](architecture/index.md)

-   :lucide-book-open: **User guide**

    ---

    Neighbors, address families, policy, route reflection, Graceful Restart,
    RPKI, BFD, BMP and the kernel FIB.

    [:octicons-arrow-right-24: Configure RustyBGP](user-guide/index.md)

-   :lucide-server-cog: **Administration**

    ---

    Deployment, command-line flags, live reload, day-two operations,
    hardening and troubleshooting.

    [:octicons-arrow-right-24: Run it in production](administration/index.md)

-   :lucide-bot: **Automation**

    ---

    The GoBGP v4 gRPC API, the `gobgp` CLI, programmatic clients and the CI
    pipeline.

    [:octicons-arrow-right-24: Drive it from code](automation/index.md)

-   :lucide-list-checks: **RFC support**

    ---

    Every BGP-related RFC, with what is supported, partial, or missing.

    [:octicons-arrow-right-24: Compliance matrix](reference/rfc-support.md)

</div>

## Highlights

- **Built for many cores.** The routing table is split into one shard per CPU,
  and every BGP connection is an independent task. Prefixes in different
  shards are processed in parallel with no shared lock.
- **GoBGP compatible.** The GoBGP v4 gRPC API, the GoBGP configuration schema
  in TOML or YAML, and the `gobgp` CLI all work unchanged.
- **Native Linux FIB.** Best paths are installed into the kernel over netlink,
  with ECMP, VRFs, nexthop tracking and redistribution of connected and kernel
  routes. No Zebra or FRR is required.
- **Broad protocol coverage.** IPv4/IPv6 unicast and multicast, labeled
  unicast, L3VPN, EVPN, FlowSpec, BGP-LS, SR Policy, MUP and RT-Constraint;
  route reflection, confederations and route servers; Add-Path, Graceful
  Restart and Long-Lived Graceful Restart; RPKI, BFD, BMP and MRT.
- **Tested against real implementations.** End-to-end scenarios run RustyBGP
  against GoBGP, FRR and BIRD on every pull request.

## At a glance

=== "Start the daemon"

    ```bash
    sudo ./rustybgpd -f rustybgpd.toml
    ```

=== "Check sessions"

    ```console
    $ gobgp neighbor
    Peer            AS  Up/Down State       |#Received  Accepted
    198.51.100.2 65002 00:01:12 Establ      |       12        12
    ```

=== "Originate a route"

    ```bash
    gobgp global rib add 203.0.113.0/24 nexthop 198.51.100.1
    ```

## Project status

RustyBGP is under active development. The
[RFC support matrix](reference/rfc-support.md) lists what is implemented and
the known gaps. Bug reports and contributions are welcome; see
[Contributing](contributing.md).
