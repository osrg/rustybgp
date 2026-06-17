#!/bin/bash
# BGP Route Server End-to-End Test (RFC 7947)
#
# Topology (single L2 network 172.30.30.0/24):
#   [frr-a (AS 65001, RS client)] \
#                                  -- [rusty-rs (AS 65000, Route Server)]
#   [frr-b (AS 65002, RS client)] /          |
#                                        regular eBGP
#                                             |
#                                    [frr-ext (AS 65100)]
#
# Test scenarios:
#   1. RS session established with frr-a
#   2. RS session established with frr-b
#   3. Regular eBGP session established with frr-ext
#   4. frr-a's prefix (10.0.1.0/24) reaches frr-b via RS
#   5. frr-b's prefix (10.0.2.0/24) reaches frr-a via RS
#   6. AS_PATH for 10.0.1.0/24 at frr-b is "65001" (RS does not prepend its AS)
#   7. NEXT_HOP for 10.0.1.0/24 at frr-b is frr-a's address (RS transparent)
#   8. frr-ext's prefix (10.0.3.0/24) does NOT reach RS clients (RS isolation)
#   9. frr-a's prefix (10.0.1.0/24) does NOT reach frr-ext (RS isolation)

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

echo "=== BGP Route Server (RFC 7947) End-to-End Test ==="
echo ""

echo "Building and starting containers..."
docker compose up -d --build --force-recreate 2>&1

echo "Waiting for BGP convergence..."
MAX_WAIT=60
A_OK=false
B_OK=false
EXT_OK=false

for i in $(seq 1 $MAX_WAIT); do
    if ! $A_OK && [ "$(frr_bgp_state frr-a 172.30.30.1)" = "Established" ]; then
        A_OK=true
        echo "  frr-a <-> rusty-rs established after ${i}s"
    fi
    if ! $B_OK && [ "$(frr_bgp_state frr-b 172.30.30.1)" = "Established" ]; then
        B_OK=true
        echo "  frr-b <-> rusty-rs established after ${i}s"
    fi
    if ! $EXT_OK && [ "$(frr_bgp_state frr-ext 172.30.30.1)" = "Established" ]; then
        EXT_OK=true
        echo "  frr-ext <-> rusty-rs established after ${i}s"
    fi
    if $A_OK && $B_OK && $EXT_OK; then
        break
    fi
    if [ "$i" -eq "$MAX_WAIT" ]; then
        echo "BGP sessions did not fully establish within ${MAX_WAIT}s"
        echo ""
        echo "--- frr-a BGP summary ---"
        docker exec frr-a vtysh -c "show bgp summary" 2>/dev/null || true
        echo "--- frr-b BGP summary ---"
        docker exec frr-b vtysh -c "show bgp summary" 2>/dev/null || true
        echo "--- frr-ext BGP summary ---"
        docker exec frr-ext vtysh -c "show bgp summary" 2>/dev/null || true
        echo "--- rusty-rs logs ---"
        docker logs rusty-rs 2>&1 | tail -20
    fi
    sleep 1
done

# Allow additional convergence time for route propagation
sleep 3

echo ""
echo "--- Test Results ---"

# Test 1: frr-a RS session established
if $A_OK; then
    pass "frr-a <-> rusty-rs RS session established"
else
    fail "frr-a <-> rusty-rs RS session established"
fi

# Test 2: frr-b RS session established
if $B_OK; then
    pass "frr-b <-> rusty-rs RS session established"
else
    fail "frr-b <-> rusty-rs RS session established"
fi

# Test 3: frr-ext regular eBGP session established
if $EXT_OK; then
    pass "frr-ext <-> rusty-rs regular eBGP session established"
else
    fail "frr-ext <-> rusty-rs regular eBGP session established"
fi

# Test 4: frr-a's prefix (10.0.1.0/24) reaches frr-b via RS
PATHS_B=$(docker exec frr-b vtysh -c "show bgp ipv4 unicast 10.0.1.0/24 json" 2>/dev/null \
    | jq '.paths | length' 2>/dev/null || echo "0")
if [ "$PATHS_B" -ge 1 ]; then
    pass "frr-b received frr-a's prefix 10.0.1.0/24 via RS"
else
    fail "frr-b received frr-a's prefix 10.0.1.0/24 via RS"
    echo "    Debug: frr-b RIB for 10.0.1.0/24:"
    docker exec frr-b vtysh -c "show bgp ipv4 unicast 10.0.1.0/24" 2>/dev/null || true
fi

# Test 5: frr-b's prefix (10.0.2.0/24) reaches frr-a via RS
PATHS_A=$(docker exec frr-a vtysh -c "show bgp ipv4 unicast 10.0.2.0/24 json" 2>/dev/null \
    | jq '.paths | length' 2>/dev/null || echo "0")
if [ "$PATHS_A" -ge 1 ]; then
    pass "frr-a received frr-b's prefix 10.0.2.0/24 via RS"
else
    fail "frr-a received frr-b's prefix 10.0.2.0/24 via RS"
    echo "    Debug: frr-a RIB for 10.0.2.0/24:"
    docker exec frr-a vtysh -c "show bgp ipv4 unicast 10.0.2.0/24" 2>/dev/null || true
fi

# Test 6: AS_PATH for 10.0.1.0/24 at frr-b is "65001" (no RS AS prepend)
ASPATH=$(docker exec frr-b vtysh -c "show bgp ipv4 unicast 10.0.1.0/24 json" 2>/dev/null \
    | jq -r '.paths[0].aspath.string // empty' 2>/dev/null || echo "")
if [ -n "$ASPATH" ]; then
    if [ "$ASPATH" = "65001" ]; then
        pass "AS_PATH at frr-b is 65001 only (RS did not prepend its AS)"
    else
        fail "AS_PATH at frr-b is wrong (expected '65001', got '$ASPATH')"
    fi
else
    fail "AS_PATH at frr-b could not be read for 10.0.1.0/24"
fi

# Test 7: NEXT_HOP for 10.0.1.0/24 at frr-b is frr-a's address (172.30.30.2)
NEXTHOP=$(docker exec frr-b vtysh -c "show bgp ipv4 unicast 10.0.1.0/24 json" 2>/dev/null \
    | jq -r '.paths[0].nexthops[0].ip // empty' 2>/dev/null || echo "")
if [ "$NEXTHOP" = "172.30.30.2" ]; then
    pass "NEXT_HOP at frr-b is frr-a's address 172.30.30.2 (RS transparent)"
else
    fail "NEXT_HOP at frr-b is wrong (expected 172.30.30.2, got '$NEXTHOP')"
fi

# Test 8: RS isolation - frr-ext's prefix (10.0.3.0/24) must NOT reach frr-a
PATHS_A_EXT=$(docker exec frr-a vtysh -c "show bgp ipv4 unicast 10.0.3.0/24 json" 2>/dev/null \
    | jq '.paths | length' 2>/dev/null || echo "0")
if [ "$PATHS_A_EXT" -eq 0 ]; then
    pass "RS isolation: frr-ext's prefix 10.0.3.0/24 not forwarded to frr-a"
else
    fail "RS isolation: frr-ext's prefix 10.0.3.0/24 incorrectly reached frr-a"
fi

# Test 9: RS isolation - frr-a's prefix (10.0.1.0/24) must NOT reach frr-ext
PATHS_EXT=$(docker exec frr-ext vtysh -c "show bgp ipv4 unicast 10.0.1.0/24 json" 2>/dev/null \
    | jq '.paths | length' 2>/dev/null || echo "0")
if [ "$PATHS_EXT" -eq 0 ]; then
    pass "RS isolation: frr-a's prefix 10.0.1.0/24 not forwarded to frr-ext"
else
    fail "RS isolation: frr-a's prefix 10.0.1.0/24 incorrectly reached frr-ext"
fi

echo ""
echo "--- BGP Tables ---"
echo ""
echo "frr-a RIB:"
docker exec frr-a vtysh -c "show bgp ipv4 unicast" 2>/dev/null || true
echo ""
echo "frr-b RIB:"
docker exec frr-b vtysh -c "show bgp ipv4 unicast" 2>/dev/null || true
echo ""
echo "frr-ext RIB:"
docker exec frr-ext vtysh -c "show bgp ipv4 unicast" 2>/dev/null || true
echo ""

echo "=== Results: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
