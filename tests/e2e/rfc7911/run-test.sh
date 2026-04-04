#!/bin/bash
# RFC 7911 End-to-End Test (BGP Add-Path)
#
# Topology:
#   [frr-sender  (AS 65002)] --\
#                                --> [router-rusty (AS 65001)] --addpath-tx(2)--> [frr-receiver (AS 65003)]
#   [frr-sender2 (AS 65004)] --/
#
# Both senders advertise 192.168.100.0/24 with different AS paths.
# rustybgp receives 2 paths and re-advertises both (send-max: 2) to the receiver.
#
# Verifies:
#   1. All BGP sessions establish
#   2. Add-Path capability is negotiated
#   3. rustybgp RIB has 2 paths for 192.168.100.0/24
#   4. frr-receiver sees 2 paths for 192.168.100.0/24 via Add-Path

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

echo "=== RFC 7911 (Add-Path) End-to-End Test ==="
echo ""

# Build and start containers
echo "Building and starting containers..."
docker compose up -d --build 2>&1

# Wait for BGP sessions to converge
echo "Waiting for BGP convergence..."
MAX_WAIT=60
SENDER1_OK=false
SENDER2_OK=false
RECEIVER_OK=false

for i in $(seq 1 $MAX_WAIT); do
    if ! $SENDER1_OK; then
        if [ "$(frr_bgp_state frr-sender 172.30.5.1)" = "Established" ]; then
            SENDER1_OK=true
            echo "Sender1 BGP session established after ${i}s"
        fi
    fi

    if ! $SENDER2_OK; then
        if [ "$(frr_bgp_state frr-sender2 172.30.5.1)" = "Established" ]; then
            SENDER2_OK=true
            echo "Sender2 BGP session established after ${i}s"
        fi
    fi

    if ! $RECEIVER_OK; then
        if [ "$(frr_bgp_state frr-receiver 172.30.6.1)" = "Established" ]; then
            RECEIVER_OK=true
            echo "Receiver BGP session established after ${i}s"
        fi
    fi

    if $SENDER1_OK && $SENDER2_OK && $RECEIVER_OK; then
        break
    fi

    if [ "$i" -eq "$MAX_WAIT" ]; then
        echo "BGP sessions did not fully establish within ${MAX_WAIT}s"
        echo ""
        echo "--- frr-sender BGP summary ---"
        docker exec frr-sender vtysh -c "show bgp summary" 2>/dev/null || true
        echo ""
        echo "--- frr-sender2 BGP summary ---"
        docker exec frr-sender2 vtysh -c "show bgp summary" 2>/dev/null || true
        echo ""
        echo "--- frr-receiver BGP summary ---"
        docker exec frr-receiver vtysh -c "show bgp summary" 2>/dev/null || true
        echo ""
        echo "--- rustybgpd logs ---"
        docker logs router-rusty 2>&1 | tail -30
    fi
    sleep 1
done

# Allow routes to propagate after sessions are up
sleep 3

echo ""
echo "--- Test Results ---"

# Test 1: Sender1 session established
if $SENDER1_OK; then
    pass "Sender1 BGP session established (frr-sender <-> rustybgp)"
else
    fail "Sender1 BGP session established (frr-sender <-> rustybgp)"
fi

# Test 2: Sender2 session established
if $SENDER2_OK; then
    pass "Sender2 BGP session established (frr-sender2 <-> rustybgp)"
else
    fail "Sender2 BGP session established (frr-sender2 <-> rustybgp)"
fi

# Test 3: Receiver session established
if $RECEIVER_OK; then
    pass "Receiver BGP session established (rustybgp <-> frr-receiver)"
else
    fail "Receiver BGP session established (rustybgp <-> frr-receiver)"
fi

# Test 4: Add-Path capability negotiated with sender1
ADDPATH_SENDER=$(docker exec frr-sender vtysh -c "show bgp neighbor 172.30.5.1 json" 2>/dev/null \
    | jq '[.. | objects | select(has("addPath"))] | length' 2>/dev/null || echo "0")
if [ "$ADDPATH_SENDER" -gt 0 ]; then
    pass "Add-Path capability negotiated with sender1"
else
    fail "Add-Path capability negotiated with sender1"
    echo "    Debug: frr-sender neighbor details:"
    docker exec frr-sender vtysh -c "show bgp neighbor 172.30.5.1 json" 2>/dev/null | jq . || true
fi

# Test 5: Add-Path capability negotiated with receiver
ADDPATH_RECEIVER=$(docker exec frr-receiver vtysh -c "show bgp neighbor 172.30.6.1 json" 2>/dev/null \
    | jq '[.. | objects | select(has("addPath"))] | length' 2>/dev/null || echo "0")
if [ "$ADDPATH_RECEIVER" -gt 0 ]; then
    pass "Add-Path capability negotiated with receiver"
else
    fail "Add-Path capability negotiated with receiver"
    echo "    Debug: frr-receiver neighbor details:"
    docker exec frr-receiver vtysh -c "show bgp neighbor 172.30.6.1 json" 2>/dev/null | jq . || true
fi

# Test 6: rustybgp RIB has 2 paths for 192.168.100.0/24
RIB_PATHS=$(docker exec router-rusty gobgp global rib -a ipv4 2>/dev/null \
    | grep -c "192.168.100.0/24" || true)
if [ "$RIB_PATHS" -ge 2 ]; then
    pass "rustybgp RIB has $RIB_PATHS paths for 192.168.100.0/24 (expected >= 2)"
else
    fail "rustybgp RIB has $RIB_PATHS paths for 192.168.100.0/24 (expected >= 2)"
    echo "    Debug: rustybgp RIB:"
    docker exec router-rusty gobgp global rib -a ipv4 2>/dev/null || true
fi

# Test 7: frr-receiver sees 2 paths for 192.168.100.0/24 via Add-Path
RECEIVER_PATHS=$(docker exec frr-receiver vtysh -c "show bgp ipv4 unicast 192.168.100.0/24 json" 2>/dev/null \
    | jq '.paths | length' 2>/dev/null || echo "0")
if [ "$RECEIVER_PATHS" -ge 2 ]; then
    pass "frr-receiver has $RECEIVER_PATHS paths for 192.168.100.0/24 via Add-Path (expected >= 2)"
else
    fail "frr-receiver has $RECEIVER_PATHS paths for 192.168.100.0/24 via Add-Path (expected >= 2)"
    echo "    Debug: frr-receiver BGP table for 192.168.100.0/24:"
    docker exec frr-receiver vtysh -c "show bgp ipv4 unicast 192.168.100.0/24 json" 2>/dev/null | jq . || true
    echo ""
    echo "    Debug: frr-receiver full BGP table:"
    docker exec frr-receiver vtysh -c "show bgp ipv4 unicast" 2>/dev/null || true
fi

echo ""
echo "--- BGP Tables ---"
echo ""
echo "rustybgp RIB (ipv4):"
docker exec router-rusty gobgp global rib -a ipv4 2>/dev/null || true
echo ""
echo "frr-receiver BGP table (192.168.100.0/24):"
docker exec frr-receiver vtysh -c "show bgp ipv4 unicast 192.168.100.0/24" 2>/dev/null || true
echo ""

echo "=== Results: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
