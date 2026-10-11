# Configuration

## TCP source address

Set the source address for a neighbor's outgoing BGP connection using the
GoBGP-compatible transport setting:

```toml
[neighbors.transport.config]
  local-address = "11.22.33.44"
```

The address must be available locally. A bind failure keeps the peer retrying;
it does not fall back to another source. Incoming connections must target this
address, except when `bind-interface` is configured, matching GoBGP's behavior.
This setting does not change the global listener addresses.

IPv4, IPv6, and scoped IPv6 addresses such as `fe80::1%eth0` are supported.
Omitting the setting, using an empty string, or using a wildcard address
(`0.0.0.0` or `::`) allows automatic source selection. Peer groups can provide
the setting; an explicit neighbor setting takes precedence. The gRPC
`Transport.local_address` field has the same behavior, and changing it through
`UpdatePeer` restarts the session.

