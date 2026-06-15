#!/bin/bash
# BGP Flowspec End-to-End Test (RFC 8955/8956)
#
# Topology:
#   [gobgp-a (AS 65002)] -- eBGP --> [router-rusty (AS 65001)] -- eBGP --> [gobgp-b (AS 65003)]
#                            left-net                              right-net
#                          172.30.5.0/24                         172.30.6.0/24
#
# Test scenarios:
#   1. BGP sessions establish with Flowspec AFI-SAFI on both legs
#   2. IPv4 Flowspec routes injected on A propagate through C to B
#   3. IPv6 Flowspec routes injected on A propagate through C to B
#   4. Flowspec route injected locally on C (via gobgp CLI) propagates to B
#   5. Flowspec route withdrawal on A removes the route from B

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

echo "=== BGP Flowspec (RFC 8955/8956) End-to-End Test ==="
echo ""

# Build and start containers
echo "Building and starting containers..."
docker compose up -d --build 2>&1

# Wait for BGP sessions to converge
echo "Waiting for BGP convergence..."
MAX_WAIT=60
A_OK=false
B_OK=false

for i in $(seq 1 $MAX_WAIT); do
    if ! $A_OK; then
        if [ "$(gobgp_bgp_state gobgp-a 172.30.5.1)" = "Established" ]; then
            A_OK=true
            echo "gobgp-a <-> rustybgp session established after ${i}s"
        fi
    fi

    if ! $B_OK; then
        if [ "$(gobgp_bgp_state gobgp-b 172.30.6.1)" = "Established" ]; then
            B_OK=true
            echo "gobgp-b <-> rustybgp session established after ${i}s"
        fi
    fi

    if $A_OK && $B_OK; then
        break
    fi

    if [ "$i" -eq "$MAX_WAIT" ]; then
        echo "BGP sessions did not fully establish within ${MAX_WAIT}s"
        echo ""
        echo "--- gobgp-a neighbors ---"
        docker exec gobgp-a gobgp neighbor 2>/dev/null || true
        echo ""
        echo "--- gobgp-b neighbors ---"
        docker exec gobgp-b gobgp neighbor 2>/dev/null || true
        echo ""
        echo "--- rustybgpd logs ---"
        docker logs router-rusty 2>&1 | tail -30
    fi
    sleep 1
done

echo ""
echo "--- Test Results ---"

# Test 1: gobgp-a session established
if $A_OK; then
    pass "gobgp-a <-> rustybgp BGP session established (ipv4-flowspec + ipv6-flowspec)"
else
    fail "gobgp-a <-> rustybgp BGP session established"
fi

# Test 2: gobgp-b session established
if $B_OK; then
    pass "gobgp-b <-> rustybgp BGP session established (ipv4-flowspec + ipv6-flowspec)"
else
    fail "gobgp-b <-> rustybgp BGP session established"
fi

# Inject IPv4 Flowspec routes on A
echo ""
echo "Injecting IPv4 Flowspec routes on gobgp-a..."
docker exec gobgp-a gobgp global rib add -a ipv4-flowspec \
    match destination 192.0.2.0/24 protocol tcp destination-port 80 then discard
docker exec gobgp-a gobgp global rib add -a ipv4-flowspec \
    match source 198.51.100.0/24 protocol udp then discard

# Inject IPv6 Flowspec route on A
echo "Injecting IPv6 Flowspec route on gobgp-a..."
docker exec gobgp-a gobgp global rib add -a ipv6-flowspec \
    match destination 2001:db8::/32 then discard

# Allow propagation
sleep 5

# Test 3: rustybgp RIB has IPv4 Flowspec routes from A
RUSTY_IPV4_COUNT=$(docker exec router-rusty gobgp global rib -a ipv4-flowspec 2>/dev/null \
    | grep -c "^\*" || true)
if [ "$RUSTY_IPV4_COUNT" -ge 2 ]; then
    pass "rustybgp has $RUSTY_IPV4_COUNT IPv4 Flowspec routes from gobgp-a (expected >= 2)"
else
    fail "rustybgp has $RUSTY_IPV4_COUNT IPv4 Flowspec routes from gobgp-a (expected >= 2)"
    echo "    Debug: rustybgp IPv4 Flowspec RIB:"
    docker exec router-rusty gobgp global rib -a ipv4-flowspec 2>/dev/null || true
fi

# Test 4: gobgp-b receives IPv4 Flowspec routes propagated through rustybgp
B_IPV4_COUNT=$(docker exec gobgp-b gobgp global rib -a ipv4-flowspec 2>/dev/null \
    | grep -c "^\*" || true)
if [ "$B_IPV4_COUNT" -ge 2 ]; then
    pass "gobgp-b has $B_IPV4_COUNT IPv4 Flowspec routes from A via rustybgp (expected >= 2)"
else
    fail "gobgp-b has $B_IPV4_COUNT IPv4 Flowspec routes from A via rustybgp (expected >= 2)"
    echo "    Debug: gobgp-b IPv4 Flowspec RIB:"
    docker exec gobgp-b gobgp global rib -a ipv4-flowspec 2>/dev/null || true
fi

# Test 5: rustybgp RIB has IPv6 Flowspec route from A
RUSTY_IPV6_COUNT=$(docker exec router-rusty gobgp global rib -a ipv6-flowspec 2>/dev/null \
    | grep -c "^\*" || true)
if [ "$RUSTY_IPV6_COUNT" -ge 1 ]; then
    pass "rustybgp has $RUSTY_IPV6_COUNT IPv6 Flowspec route from gobgp-a (expected >= 1)"
else
    fail "rustybgp has $RUSTY_IPV6_COUNT IPv6 Flowspec route from gobgp-a (expected >= 1)"
    echo "    Debug: rustybgp IPv6 Flowspec RIB:"
    docker exec router-rusty gobgp global rib -a ipv6-flowspec 2>/dev/null || true
fi

# Test 6: gobgp-b receives IPv6 Flowspec route propagated through rustybgp
B_IPV6_COUNT=$(docker exec gobgp-b gobgp global rib -a ipv6-flowspec 2>/dev/null \
    | grep -c "^\*" || true)
if [ "$B_IPV6_COUNT" -ge 1 ]; then
    pass "gobgp-b has $B_IPV6_COUNT IPv6 Flowspec route from A via rustybgp (expected >= 1)"
else
    fail "gobgp-b has $B_IPV6_COUNT IPv6 Flowspec route from A via rustybgp (expected >= 1)"
    echo "    Debug: gobgp-b IPv6 Flowspec RIB:"
    docker exec gobgp-b gobgp global rib -a ipv6-flowspec 2>/dev/null || true
fi

# Test 7: Local IPv4 Flowspec injection on C (rustybgp) via gobgp global rib add
echo ""
echo "Injecting local IPv4 Flowspec route on rustybgp (C)..."
docker exec router-rusty gobgp global rib add -a ipv4-flowspec \
    match destination 203.0.113.0/24 then discard
sleep 3

B_IPV4_COUNT_AFTER=$(docker exec gobgp-b gobgp global rib -a ipv4-flowspec 2>/dev/null \
    | grep -c "^\*" || true)
if [ "$B_IPV4_COUNT_AFTER" -ge "$((B_IPV4_COUNT + 1))" ]; then
    pass "gobgp-b has $B_IPV4_COUNT_AFTER IPv4 Flowspec routes after local injection on rustybgp (expected >= $((B_IPV4_COUNT + 1)))"
else
    fail "gobgp-b has $B_IPV4_COUNT_AFTER IPv4 Flowspec routes after local injection on rustybgp (expected >= $((B_IPV4_COUNT + 1)))"
    echo "    Debug: gobgp-b IPv4 Flowspec RIB after local injection:"
    docker exec gobgp-b gobgp global rib -a ipv4-flowspec 2>/dev/null || true
fi

# Test 8: Flowspec withdrawal - remove one route from A and verify it disappears from B
echo ""
echo "Withdrawing IPv4 Flowspec route from gobgp-a..."
docker exec gobgp-a gobgp global rib del -a ipv4-flowspec \
    match destination 192.0.2.0/24 protocol tcp destination-port 80 then discard
sleep 3

B_IPV4_AFTER_DEL=$(docker exec gobgp-b gobgp global rib -a ipv4-flowspec 2>/dev/null \
    | grep -c "^\*" || true)
if [ "$B_IPV4_AFTER_DEL" -lt "$B_IPV4_COUNT_AFTER" ]; then
    pass "gobgp-b has $B_IPV4_AFTER_DEL IPv4 Flowspec routes after withdrawal (expected < $B_IPV4_COUNT_AFTER)"
else
    fail "gobgp-b has $B_IPV4_AFTER_DEL IPv4 Flowspec routes after withdrawal (expected < $B_IPV4_COUNT_AFTER)"
    echo "    Debug: gobgp-b IPv4 Flowspec RIB after withdrawal:"
    docker exec gobgp-b gobgp global rib -a ipv4-flowspec 2>/dev/null || true
fi

echo ""
echo "--- BGP Tables ---"
echo ""
echo "rustybgp RIB (ipv4-flowspec):"
docker exec router-rusty gobgp global rib -a ipv4-flowspec 2>/dev/null || true
echo ""
echo "rustybgp RIB (ipv6-flowspec):"
docker exec router-rusty gobgp global rib -a ipv6-flowspec 2>/dev/null || true
echo ""
echo "gobgp-b RIB (ipv4-flowspec):"
docker exec gobgp-b gobgp global rib -a ipv4-flowspec 2>/dev/null || true
echo ""
echo "gobgp-b RIB (ipv6-flowspec):"
docker exec gobgp-b gobgp global rib -a ipv6-flowspec 2>/dev/null || true
echo ""

echo "=== Results: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
