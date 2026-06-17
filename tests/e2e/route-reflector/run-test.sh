#!/bin/bash
# Route Reflector End-to-End Test (RFC 4456)
#
# Topology:
#   [frr-a (AS 65001, iBGP)] \
#                             -- [rusty-rr (AS 65001, RR)] -- [frr-ext (AS 65002, eBGP)]
#   [frr-b (AS 65001, iBGP)] /
#
# Networks:
#   ibgp-net: 172.30.10.0/24  (rusty-rr .1, frr-a .2, frr-b .3)
#   ext-net:  172.30.11.0/24  (rusty-rr .1, frr-ext .2)
#
# Test scenarios:
#   1. iBGP sessions established (frr-a and frr-b to rusty-rr)
#   2. eBGP session established (frr-ext to rusty-rr)
#   3. frr-a's prefix (10.0.1.0/24) is reflected to frr-b
#   4. frr-b's prefix (10.0.2.0/24) is reflected to frr-a
#   5. frr-ext's prefix (10.0.3.0/24) reaches frr-a and frr-b
#   6. Reflected routes carry ORIGINATOR_ID (RFC 4456 §8)
#   7. Reflected routes carry CLUSTER_LIST (RFC 4456 §8)

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

echo "=== Route Reflector (RFC 4456) End-to-End Test ==="
echo ""

echo "Building and starting containers..."
docker compose up -d --build --force-recreate 2>&1

echo "Waiting for BGP convergence..."
MAX_WAIT=60
A_OK=false
B_OK=false
EXT_OK=false

for i in $(seq 1 $MAX_WAIT); do
    if ! $A_OK && [ "$(frr_bgp_state frr-a 172.30.10.1)" = "Established" ]; then
        A_OK=true
        echo "  frr-a <-> rusty-rr established after ${i}s"
    fi
    if ! $B_OK && [ "$(frr_bgp_state frr-b 172.30.10.1)" = "Established" ]; then
        B_OK=true
        echo "  frr-b <-> rusty-rr established after ${i}s"
    fi
    if ! $EXT_OK && [ "$(frr_bgp_state frr-ext 172.30.11.1)" = "Established" ]; then
        EXT_OK=true
        echo "  frr-ext <-> rusty-rr established after ${i}s"
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
        echo "--- rusty-rr logs ---"
        docker logs rusty-rr 2>&1 | tail -20
    fi
    sleep 1
done

# Allow additional convergence time for route propagation
sleep 3

echo ""
echo "--- Test Results ---"

# Test 1: frr-a iBGP session established
if $A_OK; then
    pass "frr-a <-> rusty-rr iBGP session established"
else
    fail "frr-a <-> rusty-rr iBGP session established"
fi

# Test 2: frr-b iBGP session established
if $B_OK; then
    pass "frr-b <-> rusty-rr iBGP session established"
else
    fail "frr-b <-> rusty-rr iBGP session established"
fi

# Test 3: frr-ext eBGP session established
if $EXT_OK; then
    pass "frr-ext <-> rusty-rr eBGP session established"
else
    fail "frr-ext <-> rusty-rr eBGP session established"
fi

# Test 4: frr-a's prefix (10.0.1.0/24) is reflected to frr-b
PATHS_B=$(docker exec frr-b vtysh -c "show bgp ipv4 unicast 10.0.1.0/24 json" 2>/dev/null \
    | jq '.paths | length' 2>/dev/null || echo "0")
if [ "$PATHS_B" -ge 1 ]; then
    pass "frr-b received frr-a's prefix 10.0.1.0/24 via RR"
else
    fail "frr-b received frr-a's prefix 10.0.1.0/24 via RR"
    echo "    Debug: frr-b RIB for 10.0.1.0/24:"
    docker exec frr-b vtysh -c "show bgp ipv4 unicast 10.0.1.0/24" 2>/dev/null || true
fi

# Test 5: frr-b's prefix (10.0.2.0/24) is reflected to frr-a
PATHS_A=$(docker exec frr-a vtysh -c "show bgp ipv4 unicast 10.0.2.0/24 json" 2>/dev/null \
    | jq '.paths | length' 2>/dev/null || echo "0")
if [ "$PATHS_A" -ge 1 ]; then
    pass "frr-a received frr-b's prefix 10.0.2.0/24 via RR"
else
    fail "frr-a received frr-b's prefix 10.0.2.0/24 via RR"
    echo "    Debug: frr-a RIB for 10.0.2.0/24:"
    docker exec frr-a vtysh -c "show bgp ipv4 unicast 10.0.2.0/24" 2>/dev/null || true
fi

# Test 6: frr-ext's prefix (10.0.3.0/24) reaches frr-a
PATHS_A_EXT=$(docker exec frr-a vtysh -c "show bgp ipv4 unicast 10.0.3.0/24 json" 2>/dev/null \
    | jq '.paths | length' 2>/dev/null || echo "0")
if [ "$PATHS_A_EXT" -ge 1 ]; then
    pass "frr-a received frr-ext's prefix 10.0.3.0/24"
else
    fail "frr-a received frr-ext's prefix 10.0.3.0/24"
fi

# Test 7: frr-ext's prefix (10.0.3.0/24) reaches frr-b
PATHS_B_EXT=$(docker exec frr-b vtysh -c "show bgp ipv4 unicast 10.0.3.0/24 json" 2>/dev/null \
    | jq '.paths | length' 2>/dev/null || echo "0")
if [ "$PATHS_B_EXT" -ge 1 ]; then
    pass "frr-b received frr-ext's prefix 10.0.3.0/24"
else
    fail "frr-b received frr-ext's prefix 10.0.3.0/24"
fi

# Test 8: Reflected routes carry ORIGINATOR_ID (RFC 4456 §8)
# frr-b receives frr-a's route (10.0.1.0/24); the RR must set ORIGINATOR_ID = frr-a's router-id
ORIGINATOR=$(docker exec frr-b vtysh -c "show bgp ipv4 unicast 10.0.1.0/24 json" 2>/dev/null \
    | jq -r '.paths[0].originatorId // empty' 2>/dev/null || echo "")
if [ -n "$ORIGINATOR" ]; then
    pass "ORIGINATOR_ID present on reflected route (value: $ORIGINATOR)"
else
    fail "ORIGINATOR_ID missing on reflected route 10.0.1.0/24 at frr-b"
    echo "    Debug: frr-b path details:"
    docker exec frr-b vtysh -c "show bgp ipv4 unicast 10.0.1.0/24 json" 2>/dev/null \
        | jq '.' 2>/dev/null || true
fi

# Test 9: Reflected routes carry CLUSTER_LIST (RFC 4456 §8)
CLUSTER=$(docker exec frr-b vtysh -c "show bgp ipv4 unicast 10.0.1.0/24 json" 2>/dev/null \
    | jq '.paths[0].clusterList | length' 2>/dev/null || echo "0")
if [ "$CLUSTER" -ge 1 ]; then
    pass "CLUSTER_LIST present on reflected route (length: $CLUSTER)"
else
    fail "CLUSTER_LIST missing on reflected route 10.0.1.0/24 at frr-b"
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
