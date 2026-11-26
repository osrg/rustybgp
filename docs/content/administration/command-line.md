# Command line

```text
rustybgpd [OPTIONS]
```

## Options

| Option | Default | Description |
|---|---|---|
| `-f`, `--config-file <PATH>` | none | Configuration file, TOML or YAML. If it fails to parse or validate, the daemon exits. |
| `--as-number <ASN>` | none | Local AS. Used only without `-f`, and requires `--router-id`. |
| `--router-id <IPV4>` | none | Router ID. Used only without `-f`. |
| `--api-hosts <ADDR:PORT>` | `0.0.0.0:50051` | gRPC listen address. One address with a port; IPv6 in brackets, for example `[::1]:50051`. |
| `--any-peers` | off | Accept BGP sessions from any address, by adding a dynamic-neighbor peer group named `any` that covers `0.0.0.0/0` and `::/0`. |
| `--graceful-restart` | off | Start as a restarting speaker: set the Restart State bit and defer best-path selection until neighbors send End-of-RIB. Needs `-f`. See [Graceful Restart](../user-guide/graceful-restart.md#restarting-mode). |
| `-V`, `--version` | | Print the version, for example `v0.2.0-1688d16f9b`. |
| `-h`, `--help` | | Print help. |

## Startup modes

| Invocation | Result |
|---|---|
| `rustybgpd -f FILE` | BGP starts with the configuration in `FILE`. SIGHUP reloads it. |
| `rustybgpd --as-number ASN --router-id ID` | BGP starts with no neighbors. Configure everything through the API. |
| `rustybgpd` | Only the API runs. BGP starts when a client calls `StartBgp`, for example `gobgp global as 65001 router-id 192.0.2.1`. |

## Logging

RustyBGP logs to standard error through
[`env_logger`](https://docs.rs/env_logger). The default level is `info`. Set
`RUST_LOG` to change it:

```bash
RUST_LOG=debug rustybgpd -f /etc/rustybgp/rustybgpd.yaml
RUST_LOG=rustybgpd=debug,info rustybgpd -f /etc/rustybgp/rustybgpd.yaml
```

The level can also be changed at runtime with the `SetLogLevel` RPC
(`gobgp` does not expose it, but any gRPC client can call it). The runtime
level cannot be raised above what `RUST_LOG` allowed at startup, so start with
a permissive `RUST_LOG` if you expect to need debug logs.

## Exit behavior

| Condition | Behavior |
|---|---|
| Invalid configuration at startup | Exits with an error message. |
| Cannot bind the BGP listening socket | Logs an error and exits with status 1. |
| Cannot bind the gRPC address | Exits with an error message. |
| SIGHUP with `-f` | Reloads the configuration. |
| SIGHUP without `-f` | Terminates (default signal action). |
| SIGTERM, SIGINT | Terminates immediately without sending NOTIFICATIONs. |
