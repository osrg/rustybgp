# User guide

This guide explains how to configure RustyBGP for common deployments. Each
page covers one feature area and shows working configuration in both TOML and
YAML where it helps.

| Page | Topics |
|---|---|
| [Configuration basics](configuration-basics.md) | File formats, structure, global settings, validation |
| [Neighbors](neighbors.md) | Static neighbors, timers, transport, multihop, peer groups, dynamic and unnumbered neighbors |
| [Address families](address-families.md) | Supported AFI/SAFIs, Add-Path, prefix limits, Extended Next Hop |
| [Policy](policy.md) | Defined sets, policy definitions, import and export assignment |
| [Route reflection and route servers](route-reflection-and-route-servers.md) | Route reflectors, confederations, route servers |
| [Graceful Restart](graceful-restart.md) | Helper mode, restarting mode, Long-Lived Graceful Restart |
| [RPKI](rpki.md) | RTR caches and origin validation policy |
| [BFD](bfd.md) | Fast failure detection |
| [Monitoring](monitoring.md) | BMP and MRT |
| [Kernel FIB](kernel-fib.md) | Installing routes, ECMP, VRFs, redistribution |

Every setting shown here can also be applied at runtime through the
[gRPC API](../automation/grpc-api.md). For example, `gobgp neighbor add` is
equivalent to adding a `neighbors` entry.
