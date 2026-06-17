#!/bin/bash
# BGP-LS (RFC 7752) End-to-End Test
#
# Topology:
#   [gobgp-a (AS 65002)] - left-net - [router-rusty (AS 65001)] - right-net - [gobgp-b (AS 65003)]
#                       172.30.7.0/24                               172.30.8.0/24
#   [ls-tools]          172.30.7.4 / 172.30.8.4  (gRPC inject/verify)
#
# Test scenarios:
#   1. BGP sessions establish with ls AFI-SAFI
#   2. gobgp-a injects a Node NLRI with BGP-LS node attribute (node name)
#   3. gobgp-a injects a Link NLRI
#   4. gobgp-a injects a PrefixV4 NLRI
#   5. All three NLRIs propagate through rustybgp to gobgp-b
#   6. BGP-LS attribute (type 29) is forwarded with the Node NLRI
#   7. All three NLRIs appear in rustybgp RIB
#   8. Withdrawal of Node NLRI propagates to gobgp-b

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

echo "=== BGP-LS (RFC 7752) End-to-End Test ==="
echo ""

echo "Building and starting containers..."
docker compose up -d --build 2>&1

echo "Waiting for BGP convergence..."
MAX_WAIT=60
A_OK=false
B_OK=false

for i in $(seq 1 $MAX_WAIT); do
    if ! $A_OK; then
        if [ "$(gobgp_bgp_state gobgp-a 172.30.7.1)" = "Established" ]; then
            A_OK=true
            echo "gobgp-a <-> rustybgp session established after ${i}s"
        fi
    fi
    if ! $B_OK; then
        if [ "$(gobgp_bgp_state gobgp-b 172.30.8.1)" = "Established" ]; then
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
    pass "gobgp-a <-> rustybgp session established (ls)"
else
    fail "gobgp-a <-> rustybgp session did not establish"
fi
if $B_OK; then
    pass "gobgp-b <-> rustybgp session established (ls)"
else
    fail "gobgp-b <-> rustybgp session did not establish"
fi

echo ""
echo "Injecting BGP-LS NLRIs from gobgp-a..."

# Node NLRI: router 1.0.0.1 with node name for BGP-LS attribute check
docker exec ls-tools ls-inject \
    -host gobgp-a:50051 \
    -type node \
    -nexthop 172.30.7.2 \
    -local-router-id 1.0.0.1 \
    -node-name test-router-a

# Link NLRI: 1.0.0.1 <-> 1.0.0.2 via 10.0.12.1/10.0.12.2
docker exec ls-tools ls-inject \
    -host gobgp-a:50051 \
    -type link \
    -nexthop 172.30.7.2 \
    -local-router-id 1.0.0.1 \
    -remote-router-id 1.0.0.2 \
    -iface-addr 10.0.12.1 \
    -neighbor-addr 10.0.12.2

# PrefixV4 NLRI: 192.168.1.0/24 reachable via 1.0.0.1
docker exec ls-tools ls-inject \
    -host gobgp-a:50051 \
    -type prefix \
    -nexthop 172.30.7.2 \
    -local-router-id 1.0.0.1 \
    -prefix 192.168.1.0/24

echo "Waiting for propagation..."
sleep 5

# Test 3: Node NLRI at gobgp-b
if docker exec ls-tools ls-verify \
    -host gobgp-b:50051 \
    -type node \
    -local-router-id 1.0.0.1; then
    pass "gobgp-b has Node NLRI (local=1.0.0.1)"
else
    fail "gobgp-b missing Node NLRI"
    echo "    Debug: rustybgpd logs:"
    docker logs router-rusty 2>&1 | tail -20
fi

# Test 4: BGP-LS attribute (type 29) forwarded with Node NLRI
if docker exec ls-tools ls-verify \
    -host gobgp-b:50051 \
    -type node \
    -local-router-id 1.0.0.1 \
    -node-name test-router-a; then
    pass "gobgp-b has BGP-LS node attribute (name=test-router-a) forwarded end-to-end"
else
    fail "gobgp-b missing BGP-LS node attribute or name mismatch"
fi

# Test 5: Link NLRI at gobgp-b
if docker exec ls-tools ls-verify \
    -host gobgp-b:50051 \
    -type link \
    -local-router-id 1.0.0.1 \
    -remote-router-id 1.0.0.2; then
    pass "gobgp-b has Link NLRI (1.0.0.1 <-> 1.0.0.2)"
else
    fail "gobgp-b missing Link NLRI"
fi

# Test 6: PrefixV4 NLRI at gobgp-b
if docker exec ls-tools ls-verify \
    -host gobgp-b:50051 \
    -type prefix \
    -local-router-id 1.0.0.1 \
    -prefix 192.168.1.0/24; then
    pass "gobgp-b has PrefixV4 NLRI (192.168.1.0/24)"
else
    fail "gobgp-b missing PrefixV4 NLRI"
fi

# Test 7: All three NLRIs in rustybgp RIB
RUSTY_OK=0
docker exec ls-tools ls-verify \
    -host 172.30.7.1:50051 \
    -type node \
    -local-router-id 1.0.0.1 2>/dev/null && RUSTY_OK=$((RUSTY_OK + 1)) || true
docker exec ls-tools ls-verify \
    -host 172.30.7.1:50051 \
    -type link \
    -local-router-id 1.0.0.1 \
    -remote-router-id 1.0.0.2 2>/dev/null && RUSTY_OK=$((RUSTY_OK + 1)) || true
docker exec ls-tools ls-verify \
    -host 172.30.7.1:50051 \
    -type prefix \
    -local-router-id 1.0.0.1 \
    -prefix 192.168.1.0/24 2>/dev/null && RUSTY_OK=$((RUSTY_OK + 1)) || true
if [ "$RUSTY_OK" -eq 3 ]; then
    pass "rustybgp RIB contains all three BGP-LS NLRIs"
else
    fail "rustybgp RIB missing BGP-LS NLRIs ($RUSTY_OK/3 found)"
fi

# Test 8: Withdrawal propagation
echo ""
echo "Withdrawing Node NLRI from gobgp-a..."
docker exec ls-tools ls-inject \
    -host gobgp-a:50051 \
    -delete \
    -type node \
    -nexthop 172.30.7.2 \
    -local-router-id 1.0.0.1 \
    -node-name test-router-a

sleep 3

if docker exec ls-tools ls-verify \
    -host gobgp-b:50051 \
    -absent \
    -type node \
    -local-router-id 1.0.0.1; then
    pass "withdrawn Node NLRI absent from gobgp-b"
else
    fail "withdrawn Node NLRI still present in gobgp-b"
fi

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
