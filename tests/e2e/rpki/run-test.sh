#!/bin/bash
# BGP RPKI/ROV End-to-End Test
#
# Topology (single L2 network 172.30.30.0/24):
#
#   [stayrtr (172.30.30.10)] --- RTR ---+
#                                       |
#   [frr-adv (AS 65001)]  --- eBGP --- [rusty (AS 65000)] --- eBGP --- [frr-recv (AS 65002)]
#
# ROA data:
#   10.0.1.0/24 max 24 from AS65001  -> frr-adv originates with AS65001 -> VALID
#   10.0.2.0/24 max 24 from AS65099  -> frr-adv originates with AS65001 -> INVALID
#   (no ROA for 10.0.3.0/24)         -> frr-adv originates             -> NOT_FOUND
#
# Export policy on rusty: reject routes with rpki-validation-result: invalid
#
# Test scenarios:
#   1. BGP session established with frr-adv
#   2. BGP session established with frr-recv
#   3. VALID route (10.0.1.0/24) reaches frr-recv
#   4. INVALID route (10.0.2.0/24) does NOT reach frr-recv
#   5. NOT_FOUND route (10.0.3.0/24) reaches frr-recv

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"
source ../shared/helpers.sh

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

echo "=== BGP RPKI/ROV End-to-End Test ==="
echo ""

echo "Building and starting containers..."
docker compose up -d --build --force-recreate 2>&1

echo "Waiting for BGP convergence..."
MAX_WAIT=60
ADV_OK=false
RECV_OK=false

for i in $(seq 1 $MAX_WAIT); do
    if ! $ADV_OK && [ "$(frr_bgp_state frr-adv 172.30.30.1)" = "Established" ]; then
        ADV_OK=true
        echo "  frr-adv <-> rusty established after ${i}s"
    fi
    if ! $RECV_OK && [ "$(frr_bgp_state frr-recv 172.30.30.1)" = "Established" ]; then
        RECV_OK=true
        echo "  frr-recv <-> rusty established after ${i}s"
    fi
    if $ADV_OK && $RECV_OK; then
        break
    fi
    if [ "$i" -eq "$MAX_WAIT" ]; then
        echo "BGP sessions did not fully establish within ${MAX_WAIT}s"
        echo ""
        echo "--- frr-adv BGP summary ---"
        docker exec frr-adv vtysh -c "show bgp summary" 2>/dev/null || true
        echo "--- frr-recv BGP summary ---"
        docker exec frr-recv vtysh -c "show bgp summary" 2>/dev/null || true
        echo "--- rusty logs ---"
        docker logs rusty 2>&1 | tail -20
    fi
    sleep 1
done

# Allow additional time for RPKI session and ROV evaluation
sleep 5

echo ""
echo "--- Test Results ---"

# Test 1: frr-adv session established
if $ADV_OK; then
    pass "frr-adv <-> rusty BGP session established"
else
    fail "frr-adv <-> rusty BGP session established"
fi

# Test 2: frr-recv session established
if $RECV_OK; then
    pass "frr-recv <-> rusty BGP session established"
else
    fail "frr-recv <-> rusty BGP session established"
fi

# Test 3: VALID route (10.0.1.0/24) reaches frr-recv
PATHS=$(docker exec frr-recv vtysh -c "show bgp ipv4 unicast 10.0.1.0/24 json" 2>/dev/null \
    | jq '.paths | length' 2>/dev/null || echo "0")
if [ "$PATHS" -ge 1 ]; then
    pass "VALID route 10.0.1.0/24 reaches frr-recv"
else
    fail "VALID route 10.0.1.0/24 reaches frr-recv"
    echo "    Debug: frr-recv RIB for 10.0.1.0/24:"
    docker exec frr-recv vtysh -c "show bgp ipv4 unicast 10.0.1.0/24" 2>/dev/null || true
fi

# Test 4: INVALID route (10.0.2.0/24) does NOT reach frr-recv
PATHS=$(docker exec frr-recv vtysh -c "show bgp ipv4 unicast 10.0.2.0/24 json" 2>/dev/null \
    | jq '.paths | length' 2>/dev/null || echo "0")
if [ "$PATHS" -eq 0 ]; then
    pass "INVALID route 10.0.2.0/24 does not reach frr-recv"
else
    fail "INVALID route 10.0.2.0/24 does not reach frr-recv (ROV policy not applied)"
    echo "    Debug: frr-recv RIB for 10.0.2.0/24:"
    docker exec frr-recv vtysh -c "show bgp ipv4 unicast 10.0.2.0/24" 2>/dev/null || true
fi

# Test 5: NOT_FOUND route (10.0.3.0/24) reaches frr-recv
PATHS=$(docker exec frr-recv vtysh -c "show bgp ipv4 unicast 10.0.3.0/24 json" 2>/dev/null \
    | jq '.paths | length' 2>/dev/null || echo "0")
if [ "$PATHS" -ge 1 ]; then
    pass "NOT_FOUND route 10.0.3.0/24 reaches frr-recv"
else
    fail "NOT_FOUND route 10.0.3.0/24 reaches frr-recv"
    echo "    Debug: frr-recv RIB for 10.0.3.0/24:"
    docker exec frr-recv vtysh -c "show bgp ipv4 unicast 10.0.3.0/24" 2>/dev/null || true
fi

echo ""
echo "--- BGP Tables ---"
echo ""
echo "frr-recv RIB:"
docker exec frr-recv vtysh -c "show bgp ipv4 unicast" 2>/dev/null || true
echo ""
echo "rusty RPKI server:"
docker exec rusty gobgp rpki server 2>/dev/null || true
echo ""
echo "rusty RPKI table:"
docker exec rusty gobgp rpki table 2>/dev/null || true
echo ""

echo "=== Results: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
