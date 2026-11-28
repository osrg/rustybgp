# RPKI

RustyBGP validates route origins against RPKI data (RFC 6811). It fetches
Validated ROA Payloads from one or more RPKI-to-Router (RTR) caches, such as
Routinator or rpki-client with StayRTR. The client speaks RTR version 1
(RFC 8210) and does not fall back to version 0, so use a cache that supports
version 1.

## Configuring caches

```yaml
rpki-servers:
  - config:
      address: "192.0.2.50"
      port: 3323
  - config:
      address: "192.0.2.51"       # port defaults to 323
```

Only `address` and `port` are used. `refresh-time`, `hold-time`,
`record-lifetime` and `preference` are accepted for compatibility but ignored.
Caches can also be managed at runtime:

```bash
gobgp rpki server 192.0.2.52 add
gobgp rpki server
gobgp rpki table
```

When a cache connection drops, the ROAs learned from that cache are removed
immediately; they are not kept until an expire timer runs out. Cache Reset
PDUs and the refresh, retry and expire timers are not yet implemented. See
[RFC support](../reference/rfc-support.md#rpki-and-origin-validation).
With several caches, a ROA remains while any cache provides it.

## Validation states

| State | Meaning |
|---|---|
| `valid` | A ROA covers the prefix, its maximum length allows the prefix length, and its AS matches the route's origin AS. |
| `invalid` | At least one ROA covers the prefix, but none matches both the origin AS and the length. |
| `not-found` | No ROA covers the prefix. |

The origin AS is the last AS in the AS_PATH. A route whose AS_PATH ends in an
AS_SET has no origin AS and can never be `valid`.

## Acting on validation results

Validation results do not change routing by themselves. Use the
`rpki-validation-result` policy condition. To drop invalid routes on import:

```yaml
policy-definitions:
  - name: reject-rpki-invalid
    statements:
      - name: reject
        conditions:
          bgp-conditions:
            rpki-validation-result: invalid
        actions:
          route-disposition: reject-route

global:
  config:
    as: 65000
    router-id: "192.0.2.1"
  apply-policy:
    config:
      import-policy-list: [reject-rpki-invalid]
      default-import-policy: accept-route
```

!!! note

    Routes are validated when policy is evaluated. When the ROA set changes,
    routes already in the table are not re-validated automatically; run a
    soft reset in to apply the new data.

Common variations:

- Lower LOCAL_PREF for `not-found` routes instead of rejecting them.
- Tag routes with a community per validation state for downstream visibility.
