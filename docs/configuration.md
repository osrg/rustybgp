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


## Reloading the configuration file

Send SIGHUP to rustybgpd to reload the file given with `-f`. As in GoBGP,
rustybgpd compares the new file with the configuration that runs now, and
applies only the changes.

These changes are applied:

- `defined-sets`, `policy-definitions` and `global.apply-policy`
- added and removed `neighbors`. A removed neighbor gets a Cease
  NOTIFICATION (Peer De-configured).
- added and removed `peer-groups`
- added and removed `dynamic-neighbors`. Sessions of dynamic peers that are
  already up are not affected.

These changes are not applied until rustybgpd is restarted, and a warning
is logged for each of them:

- a changed neighbor or peer group (the same address or name with
  different settings)
- any change to unnumbered neighbors (`neighbor-interface`)
- changes to the other sections, such as `global`, `bmp-servers` and
  `rpki-servers`

A per-neighbor export policy keeps its policy names and uses the new
definitions of those policies.

Routes already in the tables are not evaluated again with the new policies.
Run a soft reset to apply the new policies to them. GoBGP v4 runs a soft
reset in for every peer after a policy change. rustybgpd does not, as
proposed for GoBGP v5 (osrg/gobgp#3851).

If the file cannot be read, nothing is changed and a warning is logged. If
one change fails, for example a neighbor that cannot be added or policies
that are not valid, a warning is logged and the other changes are still
applied. A neighbor, peer group or dynamic neighbor that could not be added
is tried again at the next reload. When the policies are not valid, the
old policies stay.

When rustybgpd is started without `-f`, SIGHUP is not handled and stops the
process.
