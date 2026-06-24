#!/bin/bash
# RFC 9494 Long-Lived Graceful Restart (LLGR) - Helper Side End-to-End Test
#
# Topology:
#   [frr-peer (AS 65002, GR+LLGR enabled)] <--> [router-rusty (AS 65001, LLGR helper)]
#
# frr-peer advertises:
#   192.168.10.0/24  - normal route; retained during GR and LLGR stale periods
#   192.168.20.0/24  - route with NO_LLGR community (0xffff0007=65535:7);
#                      dropped immediately when LLGR starts (RFC 9494 s4.2 MUST)
#
# Timers:
#   GR restart-time:   10 seconds
#   LLGR stale-time:   20 seconds
#
# Tests:
#   1. Session establishes; both routes present and not stale
#   2. frr-peer killed: both routes go GR-stale (retained)
#   3. GR timer expires: LLGR takes over
#      - 192.168.20.0/24 (NO_LLGR) is deleted
#      - 192.168.10.0/24 is kept as LLGR-stale
#   4. LLGR timer expires: remaining LLGR-stale route deleted
#   5. frr-peer killed again; restarts during LLGR: routes recovered after EOR
#
# NOTE: docker compose kill (SIGKILL) is used to simulate a sudden crash.
# SIGTERM lets FRR send a CEASE NOTIFICATION, which per RFC 4724 s8 does NOT
# trigger GR helper mode (only unexpected TCP drops do).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"
source ../shared/helpers.sh

GR_TIME=10
LLGR_TIME=20
MAX_WAIT=60
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

# Count all routes in rustybgp global RIB (active + stale).
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

# Return 1 if 'prefix' appears in the RIB, 0 otherwise.
rusty_has_prefix() {
    docker exec router-rusty gobgp global rib -a ipv4 2>/dev/null \
        | { grep -F "$1" || true; } | wc -l
}

echo "=== RFC 9494 Long-Lived Graceful Restart (Helper Side) End-to-End Test ==="
echo ""

echo "Building and starting containers..."
docker compose up -d --build 2>&1

# --- Test 1: Session establishment ---
echo ""
echo "Waiting for BGP session to establish..."
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

sleep 3

ROUTE_COUNT=$(rusty_rib_count)
if [ "$ROUTE_COUNT" -ge 2 ]; then
    pass "Both routes present in rustybgp RIB ($ROUTE_COUNT paths)"
else
    fail "Routes present in rustybgp RIB (got $ROUTE_COUNT, expected >= 2)"
fi

STALE_COUNT=$(rusty_stale_count)
if [ "$STALE_COUNT" -eq 0 ]; then
    pass "Routes are not stale before peer disconnect"
else
    fail "Routes should not be stale before disconnect (got $STALE_COUNT stale)"
fi

# --- Test 2: GR stale phase - both routes retained ---
echo ""
echo "Killing frr-peer (SIGKILL) to trigger GR helper mode..."
docker compose kill frr-peer
sleep 5

STALE_COUNT=$(rusty_stale_count)
TOTAL_COUNT=$(rusty_rib_count)
if [ "$STALE_COUNT" -ge 2 ]; then
    pass "Both routes GR-stale after disconnect ($STALE_COUNT stale)"
else
    fail "Expected GR-stale routes (got $STALE_COUNT stale, $TOTAL_COUNT total)"
fi

# --- Test 3: LLGR phase begins after GR timer ---
echo ""
echo "Waiting for GR timer to expire and LLGR to start ($((GR_TIME + 3))s)..."
sleep $((GR_TIME + 3))

# After GR timer, LLGR starts:
# - 192.168.10.0/24 (normal) remains as LLGR-stale
# - 192.168.20.0/24 (NO_LLGR community) is deleted (RFC 9494 s4.2)
HAS_NORMAL=$(rusty_has_prefix "192.168.10.0")
HAS_NO_LLGR=$(rusty_has_prefix "192.168.20.0")
TOTAL_COUNT=$(rusty_rib_count)

if [ "$HAS_NORMAL" -ge 1 ]; then
    pass "Normal route (192.168.10.0/24) retained after LLGR starts"
else
    fail "Normal route (192.168.10.0/24) should be kept as LLGR-stale (got 0)"
fi

if [ "$HAS_NO_LLGR" -eq 0 ]; then
    pass "NO_LLGR route (192.168.20.0/24) deleted when LLGR started"
else
    fail "NO_LLGR route (192.168.20.0/24) should be dropped when LLGR starts (still present)"
fi

STALE_COUNT=$(rusty_stale_count)
if [ "$STALE_COUNT" -ge 1 ]; then
    pass "LLGR-stale route present in RIB during LLGR stale period ($STALE_COUNT stale)"
else
    fail "LLGR-stale route should be in RIB during stale period (got $STALE_COUNT)"
fi

# --- Test 4: LLGR timer expires - remaining route deleted ---
echo ""
echo "Waiting for LLGR timer to expire ($((LLGR_TIME + 3))s)..."
sleep $((LLGR_TIME + 3))

ROUTE_COUNT=$(rusty_rib_count)
if [ "$ROUTE_COUNT" -eq 0 ]; then
    pass "All LLGR-stale routes deleted after LLGR timer expiry"
else
    fail "LLGR-stale routes should be deleted after timer (got $ROUTE_COUNT routes)"
fi

# --- Test 5: Recovery during LLGR stale period ---
echo ""
echo "Restarting frr-peer to test recovery..."
docker compose up -d frr-peer

echo "Waiting for BGP session to re-establish..."
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
    pass "Session re-established after frr-peer restart"
else
    fail "Session should re-establish after frr-peer restart"
fi

sleep 5

ROUTE_COUNT=$(rusty_rib_count)
NON_STALE=$(rusty_non_stale_count)
if [ "$NON_STALE" -ge 2 ]; then
    pass "Routes active (not stale) after recovery ($NON_STALE routes)"
else
    fail "Expected active routes after recovery (got $NON_STALE non-stale, $ROUTE_COUNT total)"
fi

# Kill peer a second time to test LLGR stale → recovery flow
echo ""
echo "Killing frr-peer again and restarting during LLGR phase..."
docker compose kill frr-peer
sleep 5

STALE_COUNT=$(rusty_stale_count)
if [ "$STALE_COUNT" -ge 1 ]; then
    pass "Routes GR-stale after second disconnect ($STALE_COUNT stale)"
else
    fail "Expected GR-stale routes after second disconnect"
fi

# Restart during GR stale period (before GR timer fires)
docker compose up -d frr-peer

echo "Waiting for session recovery after GR..."
SESSION_OK=false
for i in $(seq 1 $MAX_WAIT); do
    if [ "$(frr_bgp_state frr-peer 172.30.5.1)" = "Established" ]; then
        SESSION_OK=true
        echo "Session recovered after ${i}s"
        break
    fi
    sleep 1
done

if $SESSION_OK; then
    pass "Session recovered during GR stale period"
else
    fail "Session should recover during GR stale period"
fi

sleep 5

NON_STALE=$(rusty_non_stale_count)
STALE_COUNT=$(rusty_stale_count)
if [ "$STALE_COUNT" -eq 0 ] && [ "$NON_STALE" -ge 2 ]; then
    pass "Stale routes cleared and routes active after EOR ($NON_STALE active)"
else
    fail "Expected all routes active after EOR (got $NON_STALE active, $STALE_COUNT stale)"
fi

# --- Summary ---
echo ""
echo "--- RIB state at end of test ---"
docker exec router-rusty gobgp global rib -a ipv4 2>/dev/null || true
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "--- rustybgpd logs (last 40 lines) ---"
    docker logs router-rusty 2>&1 | tail -40
    exit 1
fi
