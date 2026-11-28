# Configuration reload

Send SIGHUP to `rustybgpd` to reload the file given with `-f`:

```bash
sudo systemctl reload rustybgpd     # with the provided systemd unit
sudo kill -HUP "$(pidof rustybgpd)"
```

As in GoBGP, RustyBGP compares the new file with the configuration that is
running now and applies only the differences.

## What is applied

| Change | Effect |
|---|---|
| `defined-sets`, `policy-definitions`, `global.apply-policy` | The new policies replace the old ones atomically. |
| Neighbor added | The neighbor is created and starts connecting. |
| Neighbor removed | The session is closed with a Cease (Peer De-configured) NOTIFICATION, and its routes are withdrawn. |
| Peer group added or removed | Applied. |
| Dynamic neighbor range added or removed | Applied. Established sessions of dynamic peers are not affected. |

Removals are processed before additions. A per-neighbor export policy keeps its
policy names and uses the new definitions of those policies.

## What requires a restart

These changes are not applied. A warning is logged for each one:

- A changed neighbor or peer group: the same address or name with different
  settings.
- Any change to unnumbered neighbors (`neighbor-interface`).
- Changes to other sections: `global` (except `apply-policy`), `rpki-servers`,
  `bmp-servers`, `vrfs`, `mrt-dump`, `zebra` and `collector`.

To change a neighbor's settings without restarting the daemon, either remove
it in one reload and add it back in the next, or change it through the API
with `UpdatePeer`.

## Existing routes and new policies

Routes already in the tables are not evaluated again with the new policies.
Run a soft reset to apply them:

```bash
for peer in $(gobgp -j neighbor | jq -r '.[].state.neighbor_address'); do
  gobgp neighbor "$peer" softresetin
  gobgp neighbor "$peer" softresetout
done
```

GoBGP v4 runs a soft reset for every peer after a policy change. RustyBGP does
not, following the behavior proposed for GoBGP v5
([osrg/gobgp#3851](https://github.com/osrg/gobgp/issues/3851)).

## Errors

- If the file cannot be read or parsed, nothing changes and a warning is
  logged.
- If one change fails (for example, a neighbor that cannot be added, or
  policies that are not valid), a warning is logged and the other changes are
  still applied.
- A neighbor, peer group or dynamic neighbor that could not be added is tried
  again at the next reload.
- When the new policies are not valid, the old policies stay in effect.

!!! warning

    When `rustybgpd` was started without `-f`, SIGHUP is not handled and
    terminates the process.
