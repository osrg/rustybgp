#!/bin/bash
# Unnumbered BGP (RFC 7938) End-to-End Test
#
# Topology:
#   [unnumbered-rusty (rustybgpd)] --link-local BGP over eth0-- [unnumbered-frr (FRR)]
#     AS 65001, advertises 10.0.0.1/32                 AS 65002, advertises 10.0.0.2/32
#
# rustybgpd is configured with "neighbor-interface: eth0": it discovers the
# peer's link-local via NDP and accepts any remote AS.  FRR's entrypoint
# reconfigures bgpd dynamically with the actual link-local address after ARP
# resolves rusty's IPv4 address.
#
# Verifies:
#   1. BGP session establishes over IPv6 link-local without a configured peer address
#   2. Extended Next Hop capability is negotiated
#   3. Routes are exchanged in both directions

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"
source ../shared/helpers.sh

PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

cleanup() {
    echo ""
    echo "Cleaning up..."
    docker compose down --volumes --remove-orphans 2>/dev/null || true
}
trap cleanup EXIT

echo "=== Unnumbered BGP (RFC 7938) End-to-End Test ==="
echo ""

echo "Building and starting containers..."
docker compose up -d --build 2>&1

# Wait for FRR to establish a BGP session.
# FRR reconfigures dynamically after startup; poll "show bgp summary" and
# look for any Established peer (the peer address changes each run).
echo "Waiting for BGP convergence..."
MAX_WAIT=120
ESTABLISHED=0
PEER_ADDR=""
for i in $(seq 1 $MAX_WAIT); do
    PEER_ADDR=$(docker exec unnumbered-frr vtysh -c "show bgp summary json" 2>/dev/null \
        | python3 -c "
import json,sys
d = json.load(sys.stdin)
peers = d.get('ipv4Unicast',{}).get('peers',{})
for addr,info in peers.items():
    if info.get('state') == 'Established':
        print(addr)
        break
" 2>/dev/null || true)
    if [ -n "$PEER_ADDR" ]; then
        echo "BGP session established with $PEER_ADDR after ${i}s"
        ESTABLISHED=1
        break
    fi
    if [ "$i" -eq "$MAX_WAIT" ]; then
        echo "BGP session did not establish within ${MAX_WAIT}s"
        echo ""
        echo "--- FRR BGP summary ---"
        docker exec unnumbered-frr vtysh -c "show bgp summary" 2>/dev/null || true
        echo ""
        echo "--- rustybgpd logs ---"
        docker logs unnumbered-rusty 2>&1 | tail -30
        echo ""
        echo "--- FRR logs ---"
        docker logs unnumbered-frr 2>&1 | tail -20
        fail "BGP session establishment"
    fi
    sleep 1
done

echo ""
echo "--- Test Results ---"

# Test 1: BGP session established over link-local
if [ "$ESTABLISHED" -eq 1 ]; then
    pass "BGP session established over IPv6 link-local"
else
    fail "BGP session established over IPv6 link-local"
fi

# Test 2: Extended Next Hop capability negotiated
if [ -n "$PEER_ADDR" ]; then
    ENH=$(docker exec unnumbered-frr vtysh -c "show bgp neighbor ${PEER_ADDR} json" 2>/dev/null \
        | python3 -c "
import json,sys
d = json.load(sys.stdin)
peer = list(d.values())[0]
caps = peer.get('neighborCapabilities',{})
enh = caps.get('extendedNexthop',{})
print('yes' if enh else 'no')
" 2>/dev/null || echo "no")
    if [ "$ENH" = "yes" ]; then
        pass "Extended Next Hop capability negotiated"
    else
        fail "Extended Next Hop capability negotiated"
    fi
else
    fail "Extended Next Hop capability negotiated"
fi

# Test 3: FRR received 10.0.0.1/32 from rustybgpd
sleep 2
ROUTE_FROM_RUSTY=$(docker exec unnumbered-frr vtysh -c "show bgp ipv4 unicast 10.0.0.1/32 json" 2>/dev/null \
    | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d.get('paths',[])))" 2>/dev/null || echo "0")
if [ "${ROUTE_FROM_RUSTY}" -gt 0 ]; then
    pass "FRR received 10.0.0.1/32 from rustybgpd"
else
    fail "FRR received 10.0.0.1/32 from rustybgpd"
    echo ""
    echo "--- FRR IPv4 unicast RIB ---"
    docker exec unnumbered-frr vtysh -c "show bgp ipv4 unicast" 2>/dev/null || true
fi

# Test 4: rustybgpd received 10.0.0.2/32 from FRR
ROUTE_FROM_FRR=$(docker exec unnumbered-rusty gobgp global rib -a ipv4 2>/dev/null \
    | grep -c "10.0.0.2/32" || true)
if [ "${ROUTE_FROM_FRR}" -gt 0 ]; then
    pass "rustybgpd received 10.0.0.2/32 from FRR"
else
    fail "rustybgpd received 10.0.0.2/32 from FRR"
    echo ""
    echo "--- rustybgpd IPv4 RIB ---"
    docker exec unnumbered-rusty gobgp global rib -a ipv4 2>/dev/null || true
fi

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
