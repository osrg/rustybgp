# Policy

RustyBGP implements GoBGP's OpenConfig-based routing policy. A policy is built
from three parts:

1. **Defined sets**: named lists of prefixes, neighbors, AS paths or
   communities.
2. **Policy definitions**: ordered statements of the form *if conditions match,
   apply actions, then accept or reject*.
3. **Assignments**: which policies run on import and export, and the default
   decision.

For how evaluation works internally, see [Policy engine](../architecture/policy-engine.md).

## Example: filter and tag customer routes

```yaml
defined-sets:
  prefix-sets:
    - prefix-set-name: customer-prefixes
      prefix-list:
        - ip-prefix: 203.0.113.0/24
          masklength-range: "24..28"
  neighbor-sets:
    - neighbor-set-name: customers
      neighbor-info-list: ["198.51.100.10", "198.51.100.11"]
  bgp-defined-sets:
    community-sets:
      - community-set-name: blackhole
        community-list: ["65535:666"]

policy-definitions:
  - name: customer-in
    statements:
      - name: drop-blackhole
        conditions:
          bgp-conditions:
            match-community-set:
              community-set: blackhole
        actions:
          route-disposition: reject-route
      - name: accept-and-tag
        conditions:
          match-prefix-set:
            prefix-set: customer-prefixes
          match-neighbor-set:
            neighbor-set: customers
        actions:
          route-disposition: accept-route
          bgp-actions:
            set-local-pref: 200
            set-community:
              options: add
              set-community-method:
                communities-list: ["65001:100"]

global:
  config:
    as: 65001
    router-id: 192.0.2.1
  apply-policy:
    config:
      import-policy-list: [customer-in]
      default-import-policy: accept-route
```

The same configuration in TOML:

```toml
[[defined-sets.prefix-sets]]
  prefix-set-name = "customer-prefixes"
  [[defined-sets.prefix-sets.prefix-list]]
    ip-prefix = "203.0.113.0/24"
    masklength-range = "24..28"

[[policy-definitions]]
  name = "customer-in"
  [[policy-definitions.statements]]
    name = "accept-and-tag"
    [policy-definitions.statements.conditions.match-prefix-set]
      prefix-set = "customer-prefixes"
    [policy-definitions.statements.actions]
      route-disposition = "accept-route"
    [policy-definitions.statements.actions.bgp-actions]
      set-local-pref = 200

[global.apply-policy.config]
  import-policy-list = ["customer-in"]
  default-import-policy = "accept-route"
```

## Conditions

| Key | Description |
|---|---|
| `match-prefix-set` | `prefix-set` and `match-set-options` (`any` or `invert`) |
| `match-neighbor-set` | `neighbor-set` and `match-set-options` |
| `bgp-conditions.match-as-path-set` | AS-path regular expressions, with `any`, `all` or `invert` |
| `bgp-conditions.match-community-set` | Standard communities |
| `bgp-conditions.match-ext-community-set` | Extended communities |
| `bgp-conditions.match-large-community-set` | Large communities |
| `bgp-conditions.next-hop-in-list` | Next-hop addresses |
| `bgp-conditions.as-path-length` | `operator` (`eq`, `ge`, `le`) and `value` |
| `bgp-conditions.route-type` | `internal`, `external` or `local` |
| `bgp-conditions.rpki-validation-result` | `valid`, `invalid` or `not-found` |

## Actions

| Key | Description |
|---|---|
| `route-disposition` | `accept-route`, `reject-route`, or `none` to continue |
| `bgp-actions.set-local-pref` | Set LOCAL_PREF |
| `bgp-actions.set-med` | Set MED, or adjust it with `+n` / `-n` |
| `bgp-actions.set-next-hop` | An address, `self`, or `unchanged` (export only) |
| `bgp-actions.set-as-path-prepend` | `as` (a number or `last-as`) and `repeat-n` |
| `bgp-actions.set-community` | `add`, `remove` or `replace` communities |
| `bgp-actions.set-ext-community` | Same, for extended communities |
| `bgp-actions.set-large-community` | Same, for large communities |
| `bgp-actions.set-route-origin` | `igp`, `egp` or `incomplete` |

## Where policies apply

| Assignment | Where | Notes |
|---|---|---|
| `global.apply-policy` import | All routes received from any neighbor | Runs before a route enters the table. |
| `global.apply-policy` export | All routes sent to any neighbor | |
| `neighbors[].apply-policy` export | Routes sent to that neighbor | Replaces the global export policy for that neighbor. |

When no default policy is configured, routes are **accepted**. RustyBGP does
not apply the RFC 8212 "reject by default for eBGP" behavior. If you need it,
set the default explicitly:

```yaml
global:
  apply-policy:
    config:
      default-import-policy: reject-route
      default-export-policy: reject-route
```

!!! warning "Not supported"

    - Per-neighbor import policy. Use a global import policy with a
      `match-neighbor-set` condition instead.
    - Policy on peer groups.

## Changing policy

Policies can be changed by editing the file and sending SIGHUP, or through the
API (`gobgp policy`, `SetPolicies`). New policies apply to routes that arrive
after the change. To re-evaluate existing routes, run a soft reset on each
neighbor:

```bash
gobgp neighbor 198.51.100.2 softresetin
gobgp neighbor 198.51.100.2 softresetout
```
