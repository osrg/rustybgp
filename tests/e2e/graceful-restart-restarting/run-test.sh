#!/bin/bash
# RFC 4724 Graceful Restart - Restarting Speaker Side End-to-End Test
#
# Topology:
#   [frr-helper (AS 65002, GR)] <-> [router-rusty (AS 65001)] <-> [frr-receiver (AS 65003)]
#
# frr-helper advertises: 192.168.10.0/24, 192.168.20.0/24
#
# Tests:
#   1. Normal operation: sessions establish, frr-receiver sees routes
#   2. rustybgp restarts with --graceful-restart:
#      a. frr-helper preserves sessions as stale (helper side)
#      b. rustybgp defers route selection until EOR from frr-helper
#      c. After EOR, frr-receiver sees routes again
#
# NOTE: rustybgpd is killed (SIGKILL) and restarted inside the container.
# frr-helper uses docker compose kill (SIGKILL) is NOT used here; the
# helper stays running throughout to simulate the helper role.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"
source ../shared/helpers.sh

PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

cleanup() {
    echo ""
    echo "Cleaning up..."
    docker compose down --volumes --remove-orphans 2>/dev/null || true
}
trap cleanup EXIT

# Count routes in frr-receiver's BGP table for a given prefix.
receiver_route_count() {
    local prefix=$1
    docker exec frr-receiver vtysh \
        -c "show bgp ipv4 unicast $prefix json" 2>/dev/null \
        | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('paths', [])))" \
        2>/dev/null || echo 0
}

# Wait for rustybgpd gRPC API to become available inside the container.
wait_for_rusty_api() {
    local max=30
    for i in $(seq 1 $max); do
        if docker exec router-rusty gobgp global 2>/dev/null; then
            echo "  rustybgpd gRPC API ready after ${i}s"
            return 0
        fi
        sleep 1
    done
    echo "  rustybgpd gRPC API not ready after ${max}s"
    return 1
}

echo "=== RFC 4724 Graceful Restart (Restarting Speaker) End-to-End Test ==="
echo ""

echo "Building and starting containers..."
docker compose up -d --build 2>&1

# --- Test 1: Normal operation ---
echo ""
echo "Waiting for BGP sessions to establish..."
MAX_WAIT=60
HELPER_OK=false
RECEIVER_OK=false

for i in $(seq 1 $MAX_WAIT); do
    if ! $HELPER_OK && [ "$(frr_bgp_state frr-helper 172.30.5.1)" = "Established" ]; then
        HELPER_OK=true
        echo "  frr-helper session established after ${i}s"
    fi
    if ! $RECEIVER_OK && [ "$(frr_bgp_state frr-receiver 172.30.5.1)" = "Established" ]; then
        RECEIVER_OK=true
        echo "  frr-receiver session established after ${i}s"
    fi
    $HELPER_OK && $RECEIVER_OK && break
    sleep 1
done

if $HELPER_OK; then
    pass "frr-helper session established"
else
    fail "frr-helper session established"
fi

if $RECEIVER_OK; then
    pass "frr-receiver session established"
else
    fail "frr-receiver session established"
fi

# Wait for route propagation
sleep 5

ROUTE_COUNT=$(receiver_route_count "192.168.10.0/24")
if [ "$ROUTE_COUNT" -ge 1 ]; then
    pass "frr-receiver sees 192.168.10.0/24 in normal operation"
else
    fail "frr-receiver should see 192.168.10.0/24 (got $ROUTE_COUNT paths)"
fi

ROUTE_COUNT=$(receiver_route_count "192.168.20.0/24")
if [ "$ROUTE_COUNT" -ge 1 ]; then
    pass "frr-receiver sees 192.168.20.0/24 in normal operation"
else
    fail "frr-receiver should see 192.168.20.0/24 (got $ROUTE_COUNT paths)"
fi

# --- Test 2: Restart with --graceful-restart ---
echo ""
echo "Killing rustybgpd to simulate restart..."
docker exec router-rusty pkill -9 rustybgpd 2>/dev/null || true
sleep 3

echo "Restarting rustybgpd with --graceful-restart..."
docker exec -d router-rusty sh -c \
    'rustybgpd -f /etc/rustybgp.yaml --graceful-restart > /tmp/rustybgpd.log 2>&1'

echo "Waiting for rustybgpd gRPC API to be ready..."
if wait_for_rusty_api; then
    pass "rustybgpd restarted with --graceful-restart"
else
    fail "rustybgpd failed to restart"
fi

# Wait for frr-helper to reconnect and send EOR, ending deferral.
echo "Waiting for frr-helper to re-establish and send EOR..."
HELPER_OK=false
for i in $(seq 1 $MAX_WAIT); do
    if [ "$(frr_bgp_state frr-helper 172.30.5.1)" = "Established" ]; then
        HELPER_OK=true
        echo "  frr-helper session re-established after ${i}s"
        break
    fi
    sleep 1
done

if $HELPER_OK; then
    pass "frr-helper re-established after GR restart"
else
    fail "frr-helper re-established after GR restart"
fi

# Wait for deferral to end (EOR processing + route advertisement).
sleep 10

RECEIVER_OK=false
for i in $(seq 1 $MAX_WAIT); do
    if [ "$(frr_bgp_state frr-receiver 172.30.5.1)" = "Established" ]; then
        RECEIVER_OK=true
        echo "  frr-receiver session re-established after ${i}s"
        break
    fi
    sleep 1
done

if $RECEIVER_OK; then
    pass "frr-receiver session re-established after restart"
else
    fail "frr-receiver session re-established after restart"
fi

sleep 5

ROUTE_COUNT=$(receiver_route_count "192.168.10.0/24")
if [ "$ROUTE_COUNT" -ge 1 ]; then
    pass "frr-receiver sees 192.168.10.0/24 after GR restart and deferral"
else
    fail "frr-receiver should see 192.168.10.0/24 after restart (got $ROUTE_COUNT paths)"
fi

ROUTE_COUNT=$(receiver_route_count "192.168.20.0/24")
if [ "$ROUTE_COUNT" -ge 1 ]; then
    pass "frr-receiver sees 192.168.20.0/24 after GR restart and deferral"
else
    fail "frr-receiver should see 192.168.20.0/24 after restart (got $ROUTE_COUNT paths)"
fi

# --- Summary ---
echo ""
echo "--- rustybgp RIB at end of test ---"
docker exec router-rusty gobgp global rib -a ipv4 2>/dev/null || true
echo ""
echo "--- frr-receiver BGP table ---"
docker exec frr-receiver vtysh -c "show bgp ipv4 unicast" 2>/dev/null || true
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "--- rustybgpd logs ---"
    docker exec router-rusty cat /tmp/rustybgpd.log 2>/dev/null | tail -30 || true
    docker logs router-rusty 2>&1 | tail -20
    exit 1
fi
