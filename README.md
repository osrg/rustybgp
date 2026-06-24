# RustyBGP

RustyBGP is a BGP implementation written in Rust, designed for high performance on multicore systems. It supports most of [GoBGP](https://github.com/osrg/gobgp)'s features with the same gRPC API and configuration file format, so you can replace gobgpd with rustybgpd without changing your tooling or configuration.

## Quick Start

Download the latest nightly binary ([x86_64](https://github.com/osrg/rustybgp/releases/download/nightly/rustybgp-nightly-linux-x86_64.tar.gz) / [aarch64](https://github.com/osrg/rustybgp/releases/download/nightly/rustybgp-nightly-linux-aarch64.tar.gz)):

```bash
curl -LO https://github.com/osrg/rustybgp/releases/download/nightly/rustybgp-nightly-linux-x86_64.tar.gz
tar xf rustybgp-nightly-linux-x86_64.tar.gz
```

Start the daemon with your GoBGP configuration file:

```bash
sudo ./rustybgpd -f gobgpd.conf
Hello, RustyBGP (32 cpus)!
```

You can manage it with the [GoBGP CLI](https://github.com/osrg/gobgp/releases):

```bash
$ gobgp neighbor
Peer            AS Up/Down State       |#Received  Accepted
198.51.100.2 65002   never Idle        |        0         0
```

## Supported Features

- Route Reflector (RFC 4456)
- BGP Confederation (RFC 5065)
- Route Server (RFC 7947)
- Add-Path (RFC 7911)
- Graceful Restart (RFC 4724)
- RPKI (RFC 6810, RFC 8210)
- BFD (RFC 5880 / RFC 5881)
- BMP (RFC 7854, RFC 9069) — all monitoring policies (Pre/Post/Loc-RIB/Adj-Out)
- MRT (RFC 6396)
- Policy (OpenConfig model)
- Dynamic neighbor
- Peer group
- Address families: IPv4/IPv6 unicast/multicast, L3VPN (RFC 4364), EVPN Types 1–5 (RFC 7432), BGP-LS (RFC 7752), Flowspec (RFC 8955), SR Policy (RFC 9256), MUP ([draft-ietf-bess-mup-safi](https://datatracker.ietf.org/doc/draft-ietf-bess-mup-safi/))

## Differences from GoBGP

RustyBGP is Linux-only and integrates directly with the Linux kernel for FIB management instead of Zebra/FRR. The kernel integration supports:

- Route injection and withdrawal (IPv4/IPv6, VRF)
- ECMP (multiple nexthops via RTA_MULTIPATH)
- Nexthop tracking (NHT) — monitors nexthop reachability and withdraws affected routes
- Connected route redistribution — detects interface address changes and injects connected routes into BGP

The following GoBGP features are not supported:

- VPLS
- MPLS VPN Multicast
- EVPN control plane (RT-based MAC-VRF import/export; Types 1–5 NLRI relay is supported)
- LLGR (RFC 9494)

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for how to build, test, and submit patches.
