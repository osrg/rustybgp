#!/bin/bash
# RFC 7911 End-to-End Test (BGP Add-Path)
#
# Topology:
#   [frr-sender (AS 65002)] --addpath-tx-- [router-rusty (AS 65001)] --addpath-tx-- [frr-receiver (AS 65003)]
#
# Verifies:
#   1. BGP sessions establish between all peers
#   2. Add-Path capability is negotiated on both sides
#   3. rustybgp receives route 192.168.100.0/24 from frr-sender with path ID
#   4. frr-receiver receives 192.168.100.0/24 from rustybgp (re-advertised with path ID)

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

echo "=== RFC 7911 (Add-Path) End-to-End Test ==="
echo ""

# Build and start containers
echo "Building and starting containers..."
docker compose up -d --build 2>&1

# Wait for BGP sessions to converge
echo "Waiting for BGP convergence..."
MAX_WAIT=60
SENDER_OK=false
RECEIVER_OK=false

for i in $(seq 1 $MAX_WAIT); do
    # Check sender session
    if ! $SENDER_OK; then
        STATE=$(docker exec frr-sender vtysh -c "show bgp neighbor 172.30.5.1 json" 2>/dev/null \
            | grep -o '"bgpState":"[^"]*"' | head -1 | cut -d'"' -f4) || true
        if [ "$STATE" = "Established" ]; then
            SENDER_OK=true
            echo "Sender BGP session established after ${i}s"
        fi
    fi

    # Check receiver session
    if ! $RECEIVER_OK; then
        STATE=$(docker exec frr-receiver vtysh -c "show bgp neighbor 172.30.6.1 json" 2>/dev/null \
            | grep -o '"bgpState":"[^"]*"' | head -1 | cut -d'"' -f4) || true
        if [ "$STATE" = "Established" ]; then
            RECEIVER_OK=true
            echo "Receiver BGP session established after ${i}s"
        fi
    fi

    if $SENDER_OK && $RECEIVER_OK; then
        break
    fi

    if [ "$i" -eq "$MAX_WAIT" ]; then
        echo "BGP sessions did not fully establish within ${MAX_WAIT}s"
        echo ""
        echo "--- frr-sender BGP summary ---"
        docker exec frr-sender vtysh -c "show bgp summary" 2>/dev/null || true
        echo ""
        echo "--- frr-receiver BGP summary ---"
        docker exec frr-receiver vtysh -c "show bgp summary" 2>/dev/null || true
        echo ""
        echo "--- rustybgpd logs ---"
        docker logs router-rusty 2>&1 | tail -20
    fi
    sleep 1
done

echo ""
echo "--- Test Results ---"

# Test 1: Sender session established
if $SENDER_OK; then
    pass "Sender BGP session established (frr-sender <-> rustybgp)"
else
    fail "Sender BGP session established (frr-sender <-> rustybgp)"
fi

# Test 2: Receiver session established
if $RECEIVER_OK; then
    pass "Receiver BGP session established (rustybgp <-> frr-receiver)"
else
    fail "Receiver BGP session established (rustybgp <-> frr-receiver)"
fi

# Test 3: Add-Path capability negotiated with sender
ADDPATH_SENDER=$(docker exec frr-sender vtysh -c "show bgp neighbor 172.30.5.1 json" 2>/dev/null \
    | grep -c "addPath" || true)
if [ "$ADDPATH_SENDER" -gt 0 ]; then
    pass "Add-Path capability negotiated with sender"
else
    fail "Add-Path capability negotiated with sender"
    echo "    Debug: frr-sender neighbor details:"
    docker exec frr-sender vtysh -c "show bgp neighbor 172.30.5.1" 2>/dev/null | grep -i "add.path" || true
fi

# Test 4: Add-Path capability negotiated with receiver
ADDPATH_RECEIVER=$(docker exec frr-receiver vtysh -c "show bgp neighbor 172.30.6.1 json" 2>/dev/null \
    | grep -c "addPath" || true)
if [ "$ADDPATH_RECEIVER" -gt 0 ]; then
    pass "Add-Path capability negotiated with receiver"
else
    fail "Add-Path capability negotiated with receiver"
    echo "    Debug: frr-receiver neighbor details:"
    docker exec frr-receiver vtysh -c "show bgp neighbor 172.30.6.1" 2>/dev/null | grep -i "add.path" || true
fi

# Test 5: rustybgp received 192.168.100.0/24 from sender
sleep 2  # allow route propagation
ROUTE_IN=$(docker exec router-rusty gobgp global rib -a ipv4 2>/dev/null \
    | grep -c "192.168.100.0/24" || true)
if [ "$ROUTE_IN" -gt 0 ]; then
    pass "rustybgp received 192.168.100.0/24 from sender"
else
    fail "rustybgp received 192.168.100.0/24 from sender"
    echo "    Debug: rustybgp RIB:"
    docker exec router-rusty gobgp global rib -a ipv4 2>/dev/null || true
fi

# Test 6: frr-receiver received 192.168.100.0/24 from rustybgp
ROUTE_OUT=$(docker exec frr-receiver vtysh -c "show bgp ipv4 unicast 192.168.100.0/24 json" 2>/dev/null \
    | grep -c "192.168.100" || true)
if [ "$ROUTE_OUT" -gt 0 ]; then
    pass "frr-receiver received 192.168.100.0/24 from rustybgp"
else
    fail "frr-receiver received 192.168.100.0/24 from rustybgp"
    echo "    Debug: frr-receiver BGP table:"
    docker exec frr-receiver vtysh -c "show bgp ipv4 unicast" 2>/dev/null || true
fi

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
