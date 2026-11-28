# Administration

This section is for operators who deploy and run RustyBGP in production.

| Page | Contents |
|---|---|
| [Deployment](deployment.md) | Filesystem layout, systemd, privileges, containers |
| [Command line](command-line.md) | `rustybgpd` flags, logging, ports |
| [Configuration reload](configuration-reload.md) | Applying configuration changes with SIGHUP |
| [Operations](operations.md) | Day-two tasks: resets, shutdowns, maintenance, upgrades |
| [Security hardening](security.md) | Protecting the API, sessions and host |
| [Troubleshooting](troubleshooting.md) | Diagnosing sessions that do not establish, missing routes, and kernel issues |

## Ports at a glance

| Port | Protocol | Direction | Purpose |
|---|---|---|---|
| 179 | TCP | Inbound and outbound | BGP sessions |
| 50051 | TCP | Inbound | gRPC API (default; see `--api-hosts`) |
| 3784 | UDP | Inbound and outbound | BFD control packets |
| 323 (default) | TCP | Outbound | RPKI-RTR caches |
| As configured | TCP | Outbound | BMP collectors |
