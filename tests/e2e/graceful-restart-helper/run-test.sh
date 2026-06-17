#!/bin/bash
# RFC 4724 Graceful Restart - Helper Side End-to-End Test
#
# Topology:
#   [frr-peer (AS 65002, GR enabled)] <--> [router-rusty (AS 65001, GR helper)]
#
# frr-peer advertises: 192.168.10.0/24, 192.168.20.0/24
# restart-time: 30 seconds
#
# Tests:
#   1. Session establishes and routes are present (not stale)
#   2. frr-peer killed: rustybgp marks routes stale, retains them
#   3. frr-peer restarts: rustybgp clears stale routes after EOR
#   4. frr-peer killed again: restart timer expires, routes deleted
#
# NOTE: docker compose kill (SIGKILL) is used instead of stop (SIGTERM).
# SIGTERM allows FRR to send a graceful CEASE NOTIFICATION, which per
# RFC 4724 does NOT trigger GR helper mode (only unexpected TCP drops do).
# SIGKILL simulates a sudden crash without NOTIFICATION.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"
source ../shared/helpers.sh

RESTART_TIME=30
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

# Count all routes: lines starting with '*' (active) or 'S' (stale).
# gobgp output format:
#   *> 192.168.10.0/24   172.30.5.2   65002   ...   (active)
#   S* 192.168.10.0/24   fictitious   65002   ...   (stale)
# Use wc -l instead of grep -c to avoid exit-code issues when there
# are no matching lines (grep -c exits 1 on no match, causing || echo 0
# to run and producing duplicate output).
rusty_rib_count() {
    docker exec router-rusty gobgp global rib -a ipv4 2>/dev/null \
        | { grep -E "^[*S]" || true; } | wc -l
}

rusty_stale_count() {
    docker exec router-rusty gobgp global rib -a ipv4 2>/dev/null \
        | { grep -E "^S" || true; } | wc -l
}

rusty_non_stale_count() {
    docker exec router-rusty gobgp global rib -a ipv4 2>/dev/null \
        | { grep -E "^\*" || true; } | wc -l
}

echo "=== RFC 4724 Graceful Restart (Helper Side) End-to-End Test ==="
echo ""

echo "Building and starting containers..."
docker compose up -d --build 2>&1

# --- Test 1: Session establishment ---
echo ""
echo "Waiting for BGP session to establish..."
MAX_WAIT=60
SESSION_OK=false
for i in $(seq 1 $MAX_WAIT); do
    if [ "$(frr_bgp_state frr-peer 172.30.5.1)" = "Established" ]; then
        SESSION_OK=true
        echo "Session established after ${i}s"
        break
    fi
    sleep 1
done

if $SESSION_OK; then
    pass "BGP session established (frr-peer <-> rustybgp)"
else
    fail "BGP session established (frr-peer <-> rustybgp)"
fi

# Wait for route propagation
sleep 3

ROUTE_COUNT=$(rusty_rib_count)
if [ "$ROUTE_COUNT" -ge 2 ]; then
    pass "Routes present in rustybgp RIB ($ROUTE_COUNT paths)"
else
    fail "Routes present in rustybgp RIB (got $ROUTE_COUNT, expected >= 2)"
fi

STALE_COUNT=$(rusty_stale_count)
if [ "$STALE_COUNT" -eq 0 ]; then
    pass "Routes are not stale before peer disconnect"
else
    fail "Routes should not be stale before disconnect (got $STALE_COUNT stale)"
fi

# --- Test 2: GR helper - stale routes preserved after peer stops ---
echo ""
echo "Killing frr-peer (SIGKILL) to simulate sudden crash..."
docker compose kill frr-peer

# Wait for session to drop and stale marking to happen.
sleep 5

STALE_COUNT=$(rusty_stale_count)
TOTAL_COUNT=$(rusty_rib_count)
if [ "$STALE_COUNT" -ge 2 ]; then
    pass "Routes marked stale after peer disconnect ($STALE_COUNT stale)"
else
    fail "Routes should be stale after disconnect (got $STALE_COUNT stale, $TOTAL_COUNT total)"
fi

if [ "$TOTAL_COUNT" -ge 2 ]; then
    pass "Stale routes retained in RIB (not deleted immediately)"
else
    fail "Stale routes should be retained ($TOTAL_COUNT routes in RIB)"
fi

# --- Test 3: GR recovery - stale routes cleared after EOR ---
echo ""
echo "Restarting frr-peer (GR recovery)..."
docker compose up -d frr-peer

echo "Waiting for session to re-establish..."
SESSION_OK=false
for i in $(seq 1 $MAX_WAIT); do
    if [ "$(frr_bgp_state frr-peer 172.30.5.1)" = "Established" ]; then
        SESSION_OK=true
        echo "Session re-established after ${i}s"
        break
    fi
    sleep 1
done

if $SESSION_OK; then
    pass "Session re-established after GR recovery"
else
    fail "Session re-established after GR recovery"
fi

# Wait for EOR and stale route cleanup.
sleep 10

STALE_COUNT=$(rusty_stale_count)
NON_STALE=$(rusty_non_stale_count)
if [ "$STALE_COUNT" -eq 0 ]; then
    pass "Stale routes cleared after EOR ($NON_STALE active routes remain)"
else
    fail "Stale routes should be cleared after EOR (got $STALE_COUNT still stale)"
fi

if [ "$NON_STALE" -ge 2 ]; then
    pass "Routes are active (not stale) after recovery"
else
    fail "Expected active routes after recovery (got $NON_STALE)"
fi

# --- Test 4: Restart timer expiry ---
echo ""
echo "Killing frr-peer again to test restart timer expiry..."
docker compose kill frr-peer
sleep 5

# Verify routes are stale again
STALE_COUNT=$(rusty_stale_count)
if [ "$STALE_COUNT" -ge 2 ]; then
    pass "Routes marked stale again after second disconnect"
else
    fail "Routes should be stale after second disconnect (got $STALE_COUNT)"
fi

echo "Waiting for restart timer to expire ($((RESTART_TIME + 10))s)..."
sleep $((RESTART_TIME + 10))

ROUTE_COUNT=$(rusty_rib_count)
if [ "$ROUTE_COUNT" -eq 0 ]; then
    pass "Stale routes deleted after restart timer expiry"
else
    fail "Stale routes should be deleted after timer expiry (got $ROUTE_COUNT routes)"
fi

# --- Summary ---
echo ""
echo "--- RIB state at end of test ---"
docker exec router-rusty gobgp global rib -a ipv4 2>/dev/null || true
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "--- rustybgpd logs (last 30 lines) ---"
    docker logs router-rusty 2>&1 | tail -30
    exit 1
fi
