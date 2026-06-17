#!/bin/bash
# BGP Confederation End-to-End Test (RFC 5065)
#
# Topology:
#   [frr-member (AS 65002, confed member)] ---- confed-eBGP ---- [rusty-conf (AS 65001, Confederation 65000)]
#                                                                  |
#                                                                eBGP
#                                                                  |
#                                                         [frr-ext (AS 65100)]
#
# Networks:
#   confed-net: 172.30.20.0/24  (rusty-conf .1, frr-member .2)
#   ext-net:    172.30.21.0/24  (rusty-conf .1, frr-ext .2)
#
# Test scenarios:
#   1. Confederation-eBGP session established (frr-member <-> rusty-conf)
#   2. External eBGP session established (frr-ext uses AS 65000)
#   3. frr-member's prefix (10.0.1.0/24) reaches frr-ext
#   4. AS_PATH for 10.0.1.0/24 at frr-ext shows 65000 only (member ASes stripped)
#   5. frr-ext's prefix (10.0.2.0/24) reaches frr-member

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

echo "=== BGP Confederation (RFC 5065) End-to-End Test ==="
echo ""

echo "Building and starting containers..."
docker compose up -d --build --force-recreate 2>&1

echo "Waiting for BGP convergence..."
MAX_WAIT=60
MEMBER_OK=false
EXT_OK=false

for i in $(seq 1 $MAX_WAIT); do
    if ! $MEMBER_OK && [ "$(frr_bgp_state frr-member 172.30.20.1)" = "Established" ]; then
        MEMBER_OK=true
        echo "  frr-member <-> rusty-conf established after ${i}s"
    fi
    if ! $EXT_OK && [ "$(frr_bgp_state frr-ext 172.30.21.1)" = "Established" ]; then
        EXT_OK=true
        echo "  frr-ext <-> rusty-conf established after ${i}s"
    fi
    if $MEMBER_OK && $EXT_OK; then
        break
    fi
    if [ "$i" -eq "$MAX_WAIT" ]; then
        echo "BGP sessions did not fully establish within ${MAX_WAIT}s"
        echo ""
        echo "--- frr-member BGP summary ---"
        docker exec frr-member vtysh -c "show bgp summary" 2>/dev/null || true
        echo "--- frr-ext BGP summary ---"
        docker exec frr-ext vtysh -c "show bgp summary" 2>/dev/null || true
        echo "--- rusty-conf logs ---"
        docker logs rusty-conf 2>&1 | tail -20
    fi
    sleep 1
done

# Allow additional convergence time for route propagation
sleep 3

echo ""
echo "--- Test Results ---"

# Test 1: Confederation-eBGP session established
if $MEMBER_OK; then
    pass "frr-member <-> rusty-conf confederation-eBGP session established"
else
    fail "frr-member <-> rusty-conf confederation-eBGP session established"
fi

# Test 2: External eBGP session established (frr-ext uses AS 65000)
if $EXT_OK; then
    pass "frr-ext <-> rusty-conf external eBGP session established (AS 65000)"
else
    fail "frr-ext <-> rusty-conf external eBGP session established (AS 65000)"
fi

# Test 3: frr-member's prefix (10.0.1.0/24) reaches frr-ext
PATHS_EXT=$(docker exec frr-ext vtysh -c "show bgp ipv4 unicast 10.0.1.0/24 json" 2>/dev/null \
    | jq '.paths | length' 2>/dev/null || echo "0")
if [ "$PATHS_EXT" -ge 1 ]; then
    pass "frr-ext received frr-member's prefix 10.0.1.0/24"
else
    fail "frr-ext received frr-member's prefix 10.0.1.0/24"
    echo "    Debug: frr-ext RIB for 10.0.1.0/24:"
    docker exec frr-ext vtysh -c "show bgp ipv4 unicast 10.0.1.0/24" 2>/dev/null || true
fi

# Test 4: AS_PATH at frr-ext shows only 65000, not member ASes (65001 or 65002)
ASPATH_JSON=$(docker exec frr-ext vtysh -c "show bgp ipv4 unicast 10.0.1.0/24 json" 2>/dev/null \
    | jq -r '.paths[0].aspath.string // empty' 2>/dev/null || echo "")
if [ -n "$ASPATH_JSON" ]; then
    # AS_PATH should contain 65000 and must not contain 65001 or 65002
    if echo "$ASPATH_JSON" | grep -qw "65000" \
        && ! echo "$ASPATH_JSON" | grep -qw "65001" \
        && ! echo "$ASPATH_JSON" | grep -qw "65002"; then
        pass "AS_PATH at frr-ext shows confederation AS (65000), member ASes stripped (path: $ASPATH_JSON)"
    else
        fail "AS_PATH at frr-ext is wrong (expected 65000 only, got: $ASPATH_JSON)"
    fi
else
    fail "AS_PATH at frr-ext could not be read for 10.0.1.0/24"
fi

# Test 5: frr-ext's prefix (10.0.2.0/24) reaches frr-member
PATHS_MEMBER=$(docker exec frr-member vtysh -c "show bgp ipv4 unicast 10.0.2.0/24 json" 2>/dev/null \
    | jq '.paths | length' 2>/dev/null || echo "0")
if [ "$PATHS_MEMBER" -ge 1 ]; then
    pass "frr-member received frr-ext's prefix 10.0.2.0/24"
else
    fail "frr-member received frr-ext's prefix 10.0.2.0/24"
    echo "    Debug: frr-member RIB for 10.0.2.0/24:"
    docker exec frr-member vtysh -c "show bgp ipv4 unicast 10.0.2.0/24" 2>/dev/null || true
fi

echo ""
echo "--- BGP Tables ---"
echo ""
echo "frr-member RIB:"
docker exec frr-member vtysh -c "show bgp ipv4 unicast" 2>/dev/null || true
echo ""
echo "frr-ext RIB:"
docker exec frr-ext vtysh -c "show bgp ipv4 unicast" 2>/dev/null || true
echo ""

echo "=== Results: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
