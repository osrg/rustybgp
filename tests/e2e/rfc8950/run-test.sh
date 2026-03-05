#!/bin/bash
# RFC 8950 End-to-End Test
#
# Topology:
#   [client1] --IPv4-- [router-rusty (rustybgpd)] --IPv6-only-- [router-frr (FRR)] --IPv4-- [client4]
#
# Verifies:
#   1. BGP session establishes between rustybgpd and FRR over IPv6
#   2. Extended Next Hop capability is negotiated
#   3. IPv4 routes are exchanged with IPv6 next hops
#   4. client1 can ping client4 through the routers

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

PASS=0
FAIL=0

pass() {
    echo "  PASS: $1"
    PASS=$((PASS + 1))
}

fail() {
    echo "  FAIL: $1"
    FAIL=$((FAIL + 1))
}

cleanup() {
    echo ""
    echo "Cleaning up..."
    docker compose down --volumes --remove-orphans 2>/dev/null || true
}
trap cleanup EXIT

echo "=== RFC 8950 End-to-End Test ==="
echo ""

# Build and start containers
echo "Building and starting containers..."
docker compose up -d --build 2>&1

# Wait for BGP to converge
echo "Waiting for BGP convergence..."
MAX_WAIT=60
for i in $(seq 1 $MAX_WAIT); do
    # Check if FRR's BGP session is established
    STATE=$(docker exec router-frr vtysh -c "show bgp neighbor fd00:1::2 json" 2>/dev/null \
        | grep -o '"bgpState":"[^"]*"' | head -1 | cut -d'"' -f4) || true
    if [ "$STATE" = "Established" ]; then
        echo "BGP session established after ${i}s"
        break
    fi
    if [ "$i" -eq "$MAX_WAIT" ]; then
        echo "BGP session did not establish within ${MAX_WAIT}s (state: ${STATE:-unknown})"
        echo ""
        echo "--- FRR BGP summary ---"
        docker exec router-frr vtysh -c "show bgp summary" 2>/dev/null || true
        echo ""
        echo "--- rustybgpd logs ---"
        docker logs router-rusty 2>&1 | tail -20
        fail "BGP session establishment"
    fi
    sleep 1
done

echo ""
echo "--- Test Results ---"

# Test 1: BGP session is established
if [ "$STATE" = "Established" ]; then
    pass "BGP session established over IPv6"
else
    fail "BGP session established over IPv6"
fi

# Test 2: Extended Next Hop capability negotiated
ENH=$(docker exec router-frr vtysh -c "show bgp neighbor fd00:1::2 json" 2>/dev/null \
    | grep -c "extendedNexthop" || true)
if [ "$ENH" -gt 0 ]; then
    pass "Extended Next Hop capability negotiated"
else
    fail "Extended Next Hop capability negotiated"
fi

# Test 3: FRR received 172.30.1.0/24 from rustybgpd via BGP
ROUTE_RUSTY=$(docker exec router-frr vtysh -c "show bgp ipv4 unicast 172.30.1.0/24 json" 2>/dev/null \
    | grep -c "172.30.1.0" || true)
if [ "$ROUTE_RUSTY" -gt 0 ]; then
    pass "FRR received 172.30.1.0/24 from rustybgpd via BGP"
else
    fail "FRR received 172.30.1.0/24 from rustybgpd via BGP"
fi

# Test 4: End-to-end ping from client1 to client4
sleep 2  # allow route installation to complete
if docker exec client1 ping -c 3 -W 5 172.30.4.10 >/dev/null 2>&1; then
    pass "client1 can ping client4 (172.30.4.10)"
else
    fail "client1 can ping client4 (172.30.4.10)"
    echo ""
    echo "--- Debug: routing tables ---"
    echo "router-rusty routes:"
    docker exec router-rusty ip route 2>/dev/null || true
    echo "router-frr routes:"
    docker exec router-frr ip route 2>/dev/null || true
fi

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
