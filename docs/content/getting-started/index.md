# Getting started

This section takes you from nothing to an established BGP session.

1. **[Installation](installation.md):** download a release binary or build
   from source.
2. **[Quick start](quick-start.md):** write a minimal configuration, start
   `rustybgpd`, peer with a neighbor, and exchange routes.

## Requirements

| Requirement | Notes |
|---|---|
| Linux on x86_64 or aarch64 | RustyBGP is Linux-only. It uses netlink and Linux socket options. |
| Privileges to bind TCP port 179 | Root, or `CAP_NET_BIND_SERVICE`. Not needed if you disable the listener or use another port. |
| `CAP_NET_ADMIN` | Only for kernel FIB integration, VRF devices, and TCP MD5. |
| GoBGP v4 CLI (`gobgp`) | Optional but strongly recommended for operation. |

## Coming from GoBGP?

If you already run `gobgpd`, you can usually point `rustybgpd` at your
existing configuration file:

```bash
sudo rustybgpd -f /etc/gobgpd.conf
```

Check [GoBGP compatibility](../reference/gobgp-compatibility.md) first. A few
settings are not supported (for example per-neighbor import policy, and
Zebra, which is replaced by native kernel integration). The configuration
parser rejects unknown keys, so a typo stops the daemon at startup instead of
being silently ignored.
