#!/bin/bash
# SR Policy (RFC 9830) End-to-End Test
#
# Topology:
#   [gobgp-a (AS 65002)] - left-net - [router-rusty (AS 65001)] - right-net - [gobgp-b (AS 65003)]
#                       172.30.5.0/24                               172.30.6.0/24
#   [sr-tools]          172.30.5.4 / 172.30.6.4  (gRPC inject/verify)
#
# Test scenarios:
#   1. BGP sessions establish with ipv4-srpolicy AFI-SAFI
#   2. gobgp-a injects an SR Policy route (preference only)
#   3. gobgp-a injects an SR Policy route with MPLS binding SID and segment list
#   4. Both routes appear in gobgp-b (propagated through rustybgp)
#   5. Both routes appear in rustybgp RIB
#   6. Withdrawal of route 1 propagates to gobgp-b

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

echo "=== SR Policy (RFC 9830) End-to-End Test ==="
echo ""

echo "Building and starting containers..."
docker compose up -d --build 2>&1

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

# Tests 1-2: Session establishment
if $A_OK; then
    pass "gobgp-a <-> rustybgp session established (ipv4-srpolicy)"
else
    fail "gobgp-a <-> rustybgp session established"
fi
if $B_OK; then
    pass "gobgp-b <-> rustybgp session established (ipv4-srpolicy)"
else
    fail "gobgp-b <-> rustybgp session established"
fi

echo ""
echo "Injecting SR Policy routes from gobgp-a..."

# Route 1: preference only (d=1, c=100, ep=10.0.0.1)
docker exec sr-tools sr-inject \
    -host gobgp-a:50051 \
    -distinguisher 1 -color 100 -endpoint 10.0.0.1 \
    -nexthop 172.30.5.2 -preference 100

# Route 2: with MPLS binding SID and TypeA segment list (d=2, c=200, ep=10.0.0.2)
docker exec sr-tools sr-inject \
    -host gobgp-a:50051 \
    -distinguisher 2 -color 200 -endpoint 10.0.0.2 \
    -nexthop 172.30.5.2 -preference 200 -bsid 16001 -segment 16001

echo "Waiting for propagation..."
sleep 5

# Test 3: gobgp-b has route 1 (with preference check)
if docker exec sr-tools sr-verify \
    -host gobgp-b:50051 \
    -distinguisher 1 -color 100 -endpoint 10.0.0.1 -preference 100; then
    pass "gobgp-b has SR Policy route d=1 c=100 (preference=100)"
else
    fail "gobgp-b missing SR Policy route d=1 c=100"
    echo "    Debug: gobgp-a global rib:"
    docker exec gobgp-a gobgp global rib 2>/dev/null || true
    echo "    Debug: rustybgpd logs:"
    docker logs router-rusty 2>&1 | tail -20
fi

# Test 4: gobgp-b has route 2 (with MPLS BSID check)
if docker exec sr-tools sr-verify \
    -host gobgp-b:50051 \
    -distinguisher 2 -color 200 -endpoint 10.0.0.2 \
    -preference 200 -bsid 16001; then
    pass "gobgp-b has SR Policy route d=2 c=200 (MPLS BSID=16001)"
else
    fail "gobgp-b missing SR Policy route d=2 c=200"
fi

# Test 5: rustybgp RIB contains both routes
RUSTY_OK=0
if docker exec sr-tools sr-verify \
    -host 172.30.5.1:50051 \
    -distinguisher 1 -color 100 -endpoint 10.0.0.1 2>/dev/null; then
    RUSTY_OK=$((RUSTY_OK + 1))
fi
if docker exec sr-tools sr-verify \
    -host 172.30.5.1:50051 \
    -distinguisher 2 -color 200 -endpoint 10.0.0.2 2>/dev/null; then
    RUSTY_OK=$((RUSTY_OK + 1))
fi
if [ "$RUSTY_OK" -eq 2 ]; then
    pass "rustybgp RIB contains both SR Policy routes"
else
    fail "rustybgp RIB missing SR Policy routes ($RUSTY_OK/2 found)"
fi

# Test 6: Withdrawal propagation
echo ""
echo "Withdrawing SR Policy route d=1 c=100 from gobgp-a..."
docker exec sr-tools sr-inject \
    -host gobgp-a:50051 \
    -delete \
    -distinguisher 1 -color 100 -endpoint 10.0.0.1 \
    -nexthop 172.30.5.2 -preference 100

sleep 3

if docker exec sr-tools sr-verify \
    -host gobgp-b:50051 \
    -absent \
    -distinguisher 1 -color 100 -endpoint 10.0.0.1; then
    pass "withdrawn SR Policy route d=1 c=100 absent from gobgp-b"
else
    fail "withdrawn SR Policy route d=1 c=100 still present in gobgp-b"
fi

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
