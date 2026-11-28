# RFC support

This page tracks RustyBGP's support for the RFCs and drafts relevant to a BGP
speaker. It is maintained by hand: whenever a pull request changes protocol
behavior, it should update this page too.

!!! info "Last verified"

    Against commit `1688d16` on `master`, 26 November 2026. Each status was
    checked by reading the code. The **E2E** column names the
    end-to-end scenario under `tests/e2e/` that exercises the feature, if any.

**Legend:**
:material-check-circle:{ .ok } **Supported**: implemented, with no known
conformance gaps that affect interoperability.
:material-alert-circle:{ .partial } **Partial**: implemented with known gaps,
listed in the notes and under [Known gaps](#known-gaps).
:material-close-circle:{ .no } **Not supported**: not implemented. The
attribute or capability may still be passed through or ignored.

## Summary

| Area | Supported | Partial | Not supported |
|---|:-:|:-:|:-:|
| [Base protocol and session](#base-protocol-and-session) | 4 | 3 | 4 |
| [Capabilities](#capabilities) | 4 | 2 | 1 |
| [Security](#security) | 0 | 3 | 3 |
| [Address families](#address-families) | 7 | 11 | 1 |
| [Route selection and propagation](#route-selection-and-propagation) | 3 | 3 | 0 |
| [Communities and attributes](#communities-and-attributes) | 3 | 4 | 3 |
| [Policy](#policy) | 0 | 0 | 2 |
| [Graceful Restart](#graceful-restart) | 0 | 3 | 0 |
| [Monitoring: BMP and MRT](#monitoring-bmp-and-mrt) | 2 | 3 | 0 |
| [RPKI and origin validation](#rpki-and-origin-validation) | 1 | 3 | 1 |
| [BFD](#bfd) | 0 | 3 | 1 |

## Base protocol and session

| RFC | Title | Status | Notes | E2E |
|---|---|---|---|---|
| [4271](https://www.rfc-editor.org/rfc/rfc4271) | A Border Gateway Protocol 4 (BGP-4) | :material-alert-circle:{ .partial } Partial | Core FSM, messages and decision process are implemented. Missing: MinRouteAdvertisementInterval, DelayOpen, IdleHoldTime and connect back-off, semantic NEXT_HOP validation, and the IGP-cost decision step. NLRI errors use subcode 3/1 instead of 3/10. | All scenarios |
| [6793](https://www.rfc-editor.org/rfc/rfc6793) | Four-Octet AS Number Space | :material-check-circle:{ .ok } Supported | Negotiation, AS4_PATH and AS4_AGGREGATOR merge, AS_TRANS toward 2-octet speakers. | `two-byte-as` |
| [6286](https://www.rfc-editor.org/rfc/rfc6286) | AS-Wide Unique BGP Identifier | :material-check-circle:{ .ok } Supported | Collisions between equal identifiers are resolved by AS number. | Unit tests |
| [6608](https://www.rfc-editor.org/rfc/rfc6608) | Subcodes for BGP FSM Error | :material-check-circle:{ .ok } Supported | | Unit tests |
| [8654](https://www.rfc-editor.org/rfc/rfc8654) | Extended Message Support | :material-check-circle:{ .ok } Supported | Always advertised. | |
| [4486](https://www.rfc-editor.org/rfc/rfc4486) | Subcodes for BGP Cease Notification | :material-alert-circle:{ .partial } Partial | All subcodes are decoded. Maximum Prefixes and Connection Collision are sent correctly. Administrative reset, peer update and `StopBgp` all send Peer De-configured (6/3). | |
| [7606](https://www.rfc-editor.org/rfc/rfc7606) | Revised Error Handling for BGP UPDATE Messages | :material-alert-circle:{ .partial } Partial | Treat-as-withdraw and attribute discard are implemented, but the action is chosen from the received attribute flags rather than each attribute's rule. MP_REACH/MP_UNREACH with bad flags are not parsed for withdrawal. | Unit tests |
| [7607](https://www.rfc-editor.org/rfc/rfc7607) | Codification of AS 0 Processing | :material-close-circle:{ .no } Not supported | AS 0 is accepted in OPEN when `peer-as` is not configured, and in AS_PATH. | |
| [8203](https://www.rfc-editor.org/rfc/rfc8203) / [9003](https://www.rfc-editor.org/rfc/rfc9003) | BGP Administrative Shutdown Communication | :material-close-circle:{ .no } Not supported | Received text is discarded; none is sent. | |
| [9072](https://www.rfc-editor.org/rfc/rfc9072) | Extended Optional Parameters Length for BGP OPEN | :material-close-circle:{ .no } Not supported | A received extended-length OPEN is rejected with NOTIFICATION 2/4. | |
| [9687](https://www.rfc-editor.org/rfc/rfc9687) | BGP Send Hold Timer | :material-close-circle:{ .no } Not supported | A peer that stops reading can stall its session task. | |

## Capabilities

| RFC | Title | Status | Notes | E2E |
|---|---|---|---|---|
| [5492](https://www.rfc-editor.org/rfc/rfc5492) | Capabilities Advertisement with BGP-4 | :material-check-circle:{ .ok } Supported | Obsoletes RFC 3392. Unknown capabilities are tolerated. | All scenarios |
| [4760](https://www.rfc-editor.org/rfc/rfc4760) | Multiprotocol Extensions for BGP-4 | :material-check-circle:{ .ok } Supported | Error handling gaps are listed under RFC 7606. | All scenarios |
| [2918](https://www.rfc-editor.org/rfc/rfc2918) | Route Refresh Capability | :material-check-circle:{ .ok } Supported | Advertised, and received refreshes re-send the Adj-RIB-Out. RustyBGP never needs to send a refresh: inbound soft reset replays the stored pre-policy routes. | |
| [8950](https://www.rfc-editor.org/rfc/rfc8950) | IPv4 NLRI with an IPv6 Next Hop | :material-check-circle:{ .ok } Supported | Obsoletes RFC 5549. IPv6 next hops are also accepted when the capability was not negotiated. | `extended-nexthop`, `unnumbered-bgp` |
| [7911](https://www.rfc-editor.org/rfc/rfc7911) | Advertisement of Multiple Paths | :material-alert-circle:{ .partial } Partial | Negotiation, path IDs, receive and send work. The top *N* paths are chosen before export policy and RT-Constraint, so a filtered path is not replaced by the next one. | `add-path` |
| [8277](https://www.rfc-editor.org/rfc/rfc8277) | Using BGP to Bind MPLS Labels to Address Prefixes | :material-alert-circle:{ .partial } Partial | Obsoletes RFC 3107. Labels are part of the route key, so a withdrawal with a different label does not match. No Multiple Labels capability. | |
| [7313](https://www.rfc-editor.org/rfc/rfc7313) | Enhanced Route Refresh | :material-close-circle:{ .no } Not supported | The capability is recognized but not advertised; BoRR and EoRR are not handled. | |

## Security

| RFC | Title | Status | Notes | E2E |
|---|---|---|---|---|
| [2385](https://www.rfc-editor.org/rfc/rfc2385) | TCP MD5 Signature Option | :material-alert-circle:{ .partial } Partial | Works for static neighbors and peer groups. If the kernel rejects the key, the session continues without it. Passwords on dynamic-neighbor peer groups are not installed. | |
| [5082](https://www.rfc-editor.org/rfc/rfc5082) | Generalized TTL Security Mechanism | :material-alert-circle:{ .partial } Partial | Inbound TTL checking works. Outgoing connections send their SYN with the default TTL, so a peer that enforces GTSM on the SYN drops it. | |
| [8212](https://www.rfc-editor.org/rfc/rfc8212) | Default eBGP Route Propagation Behavior without Policies | :material-alert-circle:{ .partial } Partial | Reject-by-default can be configured with `default-import-policy` and `default-export-policy`, but the default is accept, as in GoBGP. | |
| [5925](https://www.rfc-editor.org/rfc/rfc5925) | TCP Authentication Option | :material-close-circle:{ .no } Not supported | | |
| [9234](https://www.rfc-editor.org/rfc/rfc9234) | Route Leak Prevention Using Roles | :material-close-circle:{ .no } Not supported | No Role capability, no OTC attribute. | |
| [draft-ietf-sidrops-aspa-verification](https://datatracker.ietf.org/doc/draft-ietf-sidrops-aspa-verification/) | AS_PATH Verification Based on ASPA | :material-close-circle:{ .no } Not supported | | |

## Address families

| RFC | Title | Status | Notes | E2E |
|---|---|---|---|---|
| [2545](https://www.rfc-editor.org/rfc/rfc2545) | BGP-4 Multiprotocol Extensions for IPv6 | :material-check-circle:{ .ok } Supported | Global and link-local next hops. | `unnumbered-bgp` |
| [4364](https://www.rfc-editor.org/rfc/rfc4364) | BGP/MPLS IP Virtual Private Networks | :material-alert-circle:{ .partial } Partial | VPNv4 routes, VRFs created through the API with RD and route targets, and kernel VRF installation. No per-VRF neighbors. Labels are part of the route key, and a withdrawal carrying label 0x800000 resets the session. | `rtc`, `grpc-paths` |
| [4659](https://www.rfc-editor.org/rfc/rfc4659) | BGP-MPLS IP VPN Extension for IPv6 VPN | :material-alert-circle:{ .partial } Partial | Same gaps as RFC 4364. | |
| [4684](https://www.rfc-editor.org/rfc/rfc4684) | Constrained Route Distribution (RT-Constraint) | :material-alert-circle:{ .partial } Partial | Membership exchange and filtering work. A route that stops matching a peer's route targets is not withdrawn. Prefix lengths 33 to 95 are rejected. | `rtc` |
| [7432](https://www.rfc-editor.org/rfc/rfc7432) | BGP MPLS-Based Ethernet VPN | :material-alert-circle:{ .partial } Partial | Route types 1 to 5 are carried and relayed. No MAC-VRF control plane. The route-length field is not checked against the parsed length, and an unknown route type resets the session. | `evpn` |
| [9136](https://www.rfc-editor.org/rfc/rfc9136) | IP Prefix Advertisement in EVPN | :material-alert-circle:{ .partial } Partial | Type 5 relay. Same gaps as RFC 7432. | `evpn` |
| [8955](https://www.rfc-editor.org/rfc/rfc8955) | Dissemination of Flow Specification Rules | :material-alert-circle:{ .partial } Partial | Obsoletes RFC 5575. IPv4 and VPN FlowSpec in the control plane only; rules are not installed in the kernel. Component ordering is not enforced, and the §6 validation procedure is missing. | `flowspec` |
| [8956](https://www.rfc-editor.org/rfc/rfc8956) | Dissemination of Flow Specification Rules for IPv6 | :material-alert-circle:{ .partial } Partial | The IPv6 prefix offset is ignored when sizing the pattern. | `flowspec` |
| [9552](https://www.rfc-editor.org/rfc/rfc9552) | Distribution of Link-State and TE Information Using BGP | :material-alert-circle:{ .partial } Partial | Obsoletes RFC 7752. Node, link and prefix NLRI and the BGP-LS attribute. Unknown node-descriptor sub-TLVs are lost when the NLRI is re-encoded. | `link-state` |
| [9085](https://www.rfc-editor.org/rfc/rfc9085) | BGP-LS Extensions for Segment Routing | :material-check-circle:{ .ok } Supported | SR TLVs are decoded. | `link-state` |
| [9514](https://www.rfc-editor.org/rfc/rfc9514) | BGP-LS Extensions for SRv6 | :material-alert-circle:{ .partial } Partial | The SRv6 SID NLRI (TLV 518) layout is incorrect. | |
| [9830](https://www.rfc-editor.org/rfc/rfc9830) | Advertising Segment Routing Policies in BGP | :material-check-circle:{ .ok } Supported | SAFI 73 with the Tunnel Encapsulation SR Policy sub-TLVs. Control plane only (RFC 9256 architecture). | `sr-policy` |
| [9012](https://www.rfc-editor.org/rfc/rfc9012) | BGP Tunnel Encapsulation Attribute | :material-alert-circle:{ .partial } Partial | Only the SR Policy tunnel type is decoded; other types are carried opaquely. | `sr-policy` |
| [8669](https://www.rfc-editor.org/rfc/rfc8669) | Segment Routing Prefix SID Extensions | :material-check-circle:{ .ok } Supported | Unknown TLVs are preserved. | |
| [9252](https://www.rfc-editor.org/rfc/rfc9252) | BGP Overlay Services Based on SRv6 | :material-check-circle:{ .ok } Supported | SRv6 L3 and L2 Service TLVs. | |
| [draft-ietf-bess-mup-safi](https://datatracker.ietf.org/doc/draft-ietf-bess-mup-safi/) | BGP Extensions for the Mobile User Plane | :material-check-circle:{ .ok } Supported | SAFI 85, encoded per draft -00. | |
| [4760](https://www.rfc-editor.org/rfc/rfc4760) multicast | IPv4/IPv6 multicast SAFI | :material-check-circle:{ .ok } Supported | SAFI 2 for RPF information. | |
| [6514](https://www.rfc-editor.org/rfc/rfc6514) | BGP Encodings and Procedures for Multicast in MPLS/BGP IP VPNs | :material-close-circle:{ .no } Not supported | | |
| [8277](https://www.rfc-editor.org/rfc/rfc8277) | Labeled unicast | :material-alert-circle:{ .partial } Partial | See [Capabilities](#capabilities). | |

## Route selection and propagation

| RFC | Title | Status | Notes | E2E |
|---|---|---|---|---|
| [4271 §9.1](https://www.rfc-editor.org/rfc/rfc4271#section-9.1) | Decision process | :material-alert-circle:{ .partial } Partial | LOCAL_PREF, AS_PATH, ORIGIN, MED, eBGP over iBGP, router ID, CLUSTER_LIST, peer address. No IGP-cost step. See [Route processing](../architecture/route-processing.md#4-best-path-selection). | |
| [5004](https://www.rfc-editor.org/rfc/rfc5004) | Avoid BGP Best Path Transitions from One External to Another | :material-check-circle:{ .ok } Supported | Disabled by `external-compare-router-id`. | Unit tests |
| [4456](https://www.rfc-editor.org/rfc/rfc4456) | BGP Route Reflection | :material-check-circle:{ .ok } Supported | | `route-reflector` |
| [5065](https://www.rfc-editor.org/rfc/rfc5065) | Autonomous System Confederations for BGP | :material-check-circle:{ .ok } Supported | Confederation segments received from non-confederation eBGP peers are not rejected. | `confederation` |
| [7947](https://www.rfc-editor.org/rfc/rfc7947) | Internet Exchange BGP Route Server | :material-alert-circle:{ .partial } Partial | Transparent AS_PATH, NEXT_HOP and MED. One best path for all clients, so path hiding can occur. LOCAL_PREF from clients is not removed. | `route-server` |
| [7311](https://www.rfc-editor.org/rfc/rfc7311) | Accumulated IGP Metric Attribute | :material-alert-circle:{ .partial } Partial | Validated and removed toward eBGP. Not used in best-path selection and cannot be originated. | Unit tests |

## Communities and attributes

| RFC | Title | Status | Notes | E2E |
|---|---|---|---|---|
| [1997](https://www.rfc-editor.org/rfc/rfc1997) | BGP Communities Attribute | :material-check-circle:{ .ok } Supported | NO_EXPORT, NO_ADVERTISE and NO_EXPORT_SUBCONFED are honored on export (route-server clients are exempt). Well-known names match correctly in policy. | |
| [8092](https://www.rfc-editor.org/rfc/rfc8092) | BGP Large Communities Attribute | :material-check-circle:{ .ok } Supported | Match and set in policy. | |
| [5668](https://www.rfc-editor.org/rfc/rfc5668) | 4-Octet AS Specific Extended Community | :material-check-circle:{ .ok } Supported | | |
| [4360](https://www.rfc-editor.org/rfc/rfc4360) | BGP Extended Communities Attribute | :material-alert-circle:{ .partial } Partial | Match and set in policy; route targets drive VRFs and RTC. Non-transitive extended communities are not removed toward eBGP. | `rtc`, `evpn` |
| [7999](https://www.rfc-editor.org/rfc/rfc7999) | BLACKHOLE Community | :material-alert-circle:{ .partial } Partial | The well-known name can be used in policy; there is no automatic handling. | |
| [8326](https://www.rfc-editor.org/rfc/rfc8326) | Graceful BGP Session Shutdown | :material-alert-circle:{ .partial } Partial | `GRACEFUL_SHUTDOWN` can be matched and set in policy. LOCAL_PREF is not lowered automatically. | |
| [8097](https://www.rfc-editor.org/rfc/rfc8097) | BGP Prefix Origin Validation State Extended Community | :material-alert-circle:{ .partial } Partial | Can be matched and set in policy; never attached automatically. | |
| [5701](https://www.rfc-editor.org/rfc/rfc5701) | IPv6 Address Specific Extended Community | :material-close-circle:{ .no } Not supported | Passed through as an unknown attribute. | |
| [6368](https://www.rfc-editor.org/rfc/rfc6368) | Internal BGP as PE-CE Protocol (ATTR_SET) | :material-close-circle:{ .no } Not supported | | |
| [6996](https://www.rfc-editor.org/rfc/rfc6996) | Autonomous System Reservation for Private Use | :material-close-circle:{ .no } Not supported | `remove-private-as` is accepted in the configuration but has no effect. | |

## Policy

| RFC | Title | Status | Notes | E2E |
|---|---|---|---|---|
| [2439](https://www.rfc-editor.org/rfc/rfc2439) | BGP Route Flap Damping | :material-close-circle:{ .no } Not supported | `route-flap-damping` is accepted in the configuration but has no effect. | |
| [5291](https://www.rfc-editor.org/rfc/rfc5291) / [5292](https://www.rfc-editor.org/rfc/rfc5292) | Outbound Route Filtering | :material-close-circle:{ .no } Not supported | | |

RustyBGP implements the OpenConfig routing-policy model as extended by GoBGP.
See [Policy](../user-guide/policy.md).

## Graceful Restart

| RFC | Title | Status | Notes | E2E |
|---|---|---|---|---|
| [4724](https://www.rfc-editor.org/rfc/rfc4724) | Graceful Restart Mechanism for BGP | :material-alert-circle:{ .partial } Partial | Helper and restarting roles. Stale routes can remain after some disconnects that do not qualify for GR. The restarting side sends its routes and End-of-RIB before selection deferral ends. The Forwarding State (F) bit is ignored. | `graceful-restart-helper`, `graceful-restart-restarting` |
| [8538](https://www.rfc-editor.org/rfc/rfc8538) | Notification Message Support for BGP Graceful Restart | :material-alert-circle:{ .partial } Partial | The N bit is negotiated and honored on receipt. Hard Reset is never sent. | `graceful-restart-helper` |
| [9494](https://www.rfc-editor.org/rfc/rfc9494) | Long-Lived Graceful Restart for BGP | :material-alert-circle:{ .partial } Partial | LLGR_STALE routes are least preferred and NO_LLGR routes are removed. LLGR_STALE routes are still sent to peers that did not negotiate LLGR. A peer's stale time of 0 is replaced with the local value. | `long-lived-graceful-restart` |

## Monitoring: BMP and MRT

| RFC | Title | Status | Notes | E2E |
|---|---|---|---|---|
| [7854](https://www.rfc-editor.org/rfc/rfc7854) | BGP Monitoring Protocol | :material-alert-circle:{ .partial } Partial | Initiation, Peer Up/Down and Route Monitoring. No Statistics Reports, Termination or Route Mirroring. The "sent OPEN" in a live Peer Up carries the remote side's values. | `bmp-pre`, `bmp-post` |
| [8671](https://www.rfc-editor.org/rfc/rfc8671) | Support for Adj-RIB-Out in BMP | :material-check-circle:{ .ok } Supported | Through the `all` policy. | `bmp-all` |
| [9069](https://www.rfc-editor.org/rfc/rfc9069) | Support for Local RIB in BMP | :material-alert-circle:{ .partial } Partial | No VRF/Table Name TLV. | `bmp-local` |
| [6396](https://www.rfc-editor.org/rfc/rfc6396) | MRT Routing Information Export Format | :material-check-circle:{ .ok } Supported | TABLE_DUMP_V2 and BGP4MP. | |
| [8050](https://www.rfc-editor.org/rfc/rfc8050) | MRT Format with BGP Additional Path Extensions | :material-alert-circle:{ .partial } Partial | AS4 Add-Path messages are written with subtype 8 instead of 9. No RIB Add-Path subtypes. | |

## RPKI and origin validation

| RFC | Title | Status | Notes | E2E |
|---|---|---|---|---|
| [6811](https://www.rfc-editor.org/rfc/rfc6811) | BGP Prefix Origin Validation | :material-check-circle:{ .ok } Supported | Covering-ROA lookup; AS_SET-terminated paths have no origin. | `rpki` |
| [8210](https://www.rfc-editor.org/rfc/rfc8210) | RPKI to Router Protocol, Version 1 | :material-alert-circle:{ .partial } Partial | Reset and Serial queries, incremental updates, Serial Notify. Cache Reset and session-ID changes are not handled; refresh, retry and expire timers are ignored; ROAs are dropped on disconnect instead of at expiry. | `rpki` |
| [6810](https://www.rfc-editor.org/rfc/rfc6810) | RPKI to Router Protocol (version 0) | :material-alert-circle:{ .partial } Partial | Version 0 PDUs are decoded, but the client always sends version 1 and does not downgrade. | |
| [8481](https://www.rfc-editor.org/rfc/rfc8481) | Clarifications to BGP Origin Validation | :material-alert-circle:{ .partial } Partial | Routes are not re-evaluated when ROAs change; run a soft reset. | |
| [8205](https://www.rfc-editor.org/rfc/rfc8205) | BGPsec Protocol Specification | :material-close-circle:{ .no } Not supported | | |

## BFD

| RFC | Title | Status | Notes | E2E |
|---|---|---|---|---|
| [5880](https://www.rfc-editor.org/rfc/rfc5880) | Bidirectional Forwarding Detection | :material-alert-circle:{ .partial } Partial | Detection time is computed from local values instead of the negotiated ones. No transmit jitter. The §6.8.6 discard rules are not applied. | `bfd` |
| [5881](https://www.rfc-editor.org/rfc/rfc5881) | BFD for IPv4 and IPv6 (Single Hop) | :material-alert-circle:{ .partial } Partial | IPv4 only: IPv6 control packets are not received. | `bfd` |
| [5882](https://www.rfc-editor.org/rfc/rfc5882) | Generic Application of BFD | :material-alert-circle:{ .partial } Partial | BFD down closes the BGP session. A remote AdminDown also closes it, which the RFC advises against. | `bfd` |
| [5883](https://www.rfc-editor.org/rfc/rfc5883) | BFD for Multihop Paths | :material-close-circle:{ .no } Not supported | | |

## Known gaps

Open issues found by code review, grouped by impact. Each is a candidate for a
`fix/` branch.

### Robustness

- A peer that stops reading (zero TCP window) can block its session task,
  including its hold and keepalive timers. There is no RFC 9687 send hold
  timer.
- A VPN withdrawal carrying the compatibility label `0x800000`, an RTC route
  with a prefix length between 33 and 95, or an EVPN route of an unknown type
  resets the session.
- EVPN route lengths are not checked against the bytes consumed, so a
  malformed route can cause the following NLRI to be misparsed.

### UPDATE error handling (RFC 7606)

- The error action is derived from the received attribute flags instead of
  the per-attribute rule.
- MP_REACH_NLRI and MP_UNREACH_NLRI with bad flags, or after a length overrun,
  are not parsed, so treat-as-withdraw has no NLRI to withdraw.
- NEXT_HOP is not semantically validated (length, `0.0.0.0`, multicast, own
  address), and the MP_REACH next-hop length is not checked against the AFI.
- NLRI errors send subcode 3/1 instead of 3/10.

### Session and transport

- No connect back-off or jitter, no MinRouteAdvertisementInterval, no
  DelayOpen.
- TCP MD5 fails open if the kernel rejects the key; dynamic-neighbor passwords
  are not installed.
- GTSM is applied after the outbound connection is established.
- AS 0 is accepted in OPEN when `peer-as` is not configured.
- Administrative resets send Cease subcode 3 instead of 4 or 6.

### Routing

- No IGP-cost step in best-path selection.
- Route server: one best path for all clients (path hiding); LOCAL_PREF from
  clients is forwarded.
- RT-Constraint: a route that stops matching a peer's route targets is not
  withdrawn.
- Add-Path: paths are chosen before export policy, so filtered paths are not
  replaced.
- Labels (and EVPN ESI, label and gateway fields) are part of the route key.
- Non-transitive extended communities are sent to eBGP peers.

### Graceful Restart

- Stale routes can remain after disconnects that do not qualify for GR, and
  for GR-only families once LLGR takes over.
- The restarting speaker sends routes and End-of-RIB before selection deferral
  finishes.
- The Forwarding State bit is ignored.
- LLGR_STALE routes are sent to peers that did not negotiate LLGR.

### RPKI, BFD, BMP and MRT

- RTR: no Cache Reset, session-ID or timer handling; no version downgrade;
  ROAs dropped on disconnect; no revalidation when ROAs change.
- BFD: detection time negotiation, jitter, discard rules, IPv6 receive, and
  AdminDown handling.
- BMP: no Statistics Reports, Termination or Route Mirroring; incorrect sent
  OPEN in live Peer Up; no RFC 9069 Table Name TLV. The configuration file
  supports only pre-policy monitoring.
- MRT: incorrect AS4 Add-Path subtype; no RIB Add-Path subtypes.

### Missing features

TCP-AO, BGP Roles and OTC, ASPA, BGPsec, Shutdown Communication, Enhanced Route
Refresh, RFC 9072, route flap damping, ORF, `remove-private-as`, multihop BFD,
MVPN, and per-VRF (PE-CE) neighbors.

## Recently fixed

Conformance fixes merged recently:

| Fix | Commit |
|---|---|
| UPDATE length check overflow on malformed input | `1c274cf` |
| MPLS label stack bounded by the NLRI length | `201079a` |
| Malformed RPKI-RTR PDUs no longer stall the session | `f923070` |
| Covering-ROA lookup and AS_SET origin in origin validation | `bb20d78` |
| Hold time 0 disables the hold and keepalive timers | `64b37d9` |
| RFC 6608 FSM error subcodes | `b82c5e7` |
| BGP header marker validation | `6d54614` |
| OPEN capability length sizing | `4b8678e` |
| Route Refresh capability advertised | `899114a` |
| Equal BGP identifier collisions resolved by AS number (RFC 6286) | `9e3232e` |
| Looped UPDATEs treated as implicit withdrawals | `3914dc7` |
| Empty AS_PATH segments rejected | `2f9a637`, `4d197d1` |
| MED comparison in best-path selection | `9da5314` |
| Router ID compared before CLUSTER_LIST length | `19ed839` |
| Peer address and path ID as final tie-breakers | `5470451` |
| LLGR_STALE routes least preferred | `5d92c48` |
| Keep the current eBGP best path (RFC 5004) | `36627f9` |
| RFC 1997 well-known communities honored on export | `283701e` |
| Well-known community names in policy matching | `f1c1949` |
| Route-server view shows the best path | `361c0b9` |
| Oversized attributes now cause withdrawal instead of a malformed UPDATE | `263b894` |
| Path attributes sent in type-code order, MP_REACH_NLRI first | `cb23f2f`, `f344530`, `f8fbdcc` |

## Updating this page

When a change adds or fixes protocol behavior:

1. Update the row's status and notes, and the **E2E** column if you added a
   scenario.
2. Remove the item from [Known gaps](#known-gaps), and add it to
   [Recently fixed](#recently-fixed) with the commit.
3. Update the counts in [Summary](#summary).
4. Update the commit and date under **Last verified**.
