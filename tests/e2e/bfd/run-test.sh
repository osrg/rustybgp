#!/bin/bash
# BFD (RFC 5880/5881/5882) End-to-End Test
#
# Topology:
#   [router-rusty (AS65001)]  ---- bfd-net (172.30.9.0/24) ----  [bfd-peer (AS65002)]
#        172.30.9.1                                                    172.30.9.2
#    RustyBGP + BFD enabled                              GoBGP (BGP) + bfd-stub (BFD)
#
# The peer container runs two independent processes at the same IP:
#   gobgpd  — speaks BGP on port 179, no BFD configured
#   bfd-stub — speaks BFD on port 3784, controlled via signals
#
# This separation lets the test stop BFD without touching the BGP TCP
# connection, proving it was specifically BFD that triggered the BGP teardown
# (RFC 5882: BFD session Down SHOULD cause BGP to close WITHOUT NOTIFICATION).
#
# Test scenarios:
#   1. BGP session establishes while BFD session is Up
#   2. Killing bfd-stub (sudden loss) causes BGP to go Down after BFD timeout
#   3. No NOTIFICATION is sent to the peer (RFC 5882 compliance)
#   4. Restarting bfd-stub re-establishes both BFD and BGP
#   5. SIGUSR1 to bfd-stub sends AdminDown; BGP tears down immediately

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

# Detection timeout = detect_mult * rx_interval = 3 * 300 ms = 900 ms.
# We wait 3 s to account for scheduling jitter in Docker.
BFD_TIMEOUT_WAIT=3

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Wait up to $1 seconds for the BFD stub logs to contain $2.
wait_for_bfd_log() {
    local timeout=$1 pattern=$2
    for i in $(seq 1 "$timeout"); do
        if docker logs bfd-peer 2>&1 | grep -q "$pattern"; then
            return 0
        fi
        sleep 1
    done
    return 1
}

# Wait up to $1 seconds for GoBGP to see BGP state $2 toward router-rusty.
wait_for_bgp_state() {
    local timeout=$1 expected=$2
    for i in $(seq 1 "$timeout"); do
        state=$(gobgp_bgp_state bfd-peer 172.30.9.1)
        if [ "$state" = "$expected" ]; then
            return 0
        fi
        sleep 1
    done
    return 1
}

# Number of NOTIFICATION messages received by GoBGP from router-rusty.
gobgp_recv_notification_count() {
    docker exec bfd-peer gobgp neighbor 172.30.9.1 -j 2>/dev/null \
        | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(d.get('state',{}).get('messages',{}).get('received',{}).get('notification', 0))
" 2>/dev/null || echo 0
}

# Restart bfd-stub inside the peer container (detached).
restart_bfd_stub() {
    docker exec -d bfd-peer bfd-stub \
        --remote 172.30.9.1 \
        --tx-interval 300000 \
        --rx-interval 300000 \
        --detect-mult 3
}

# ---------------------------------------------------------------------------
# Start
# ---------------------------------------------------------------------------

echo "=== BFD (RFC 5880/5881/5882) End-to-End Test ==="
echo ""

echo "RUST_TARGET=$RUST_TARGET"

echo "Building and starting containers..."
docker compose up -d --build 2>&1

# ---- Scenario 1: BFD Up + BGP Established ----
echo ""
echo "--- Scenario 1: BFD session Up + BGP Established ---"

echo "Waiting for BFD session to reach Up state..."
if wait_for_bfd_log 20 "BFD STATE:.*-> Up"; then
    pass "BFD session reached Up"
else
    fail "BFD session did not reach Up within 20s"
    docker logs bfd-peer 2>&1 | tail -20
fi

echo "Waiting for BGP session to establish..."
if wait_for_bgp_state 30 "Established"; then
    pass "BGP session Established (BFD Up + BGP Established)"
else
    fail "BGP session did not establish within 30s"
    docker exec bfd-peer gobgp neighbor 2>/dev/null || true
    docker logs router-rusty 2>&1 | tail -20
fi

# Record baseline notification count before the teardown test.
NOTIF_BEFORE=$(gobgp_recv_notification_count)

# ---- Scenario 2: BFD sudden loss -> BGP teardown ----
echo ""
echo "--- Scenario 2: BFD sudden loss -> BGP teardown (RFC 5882) ---"

echo "Killing bfd-stub (sudden loss, no AdminDown)..."
docker exec bfd-peer pkill bfd-stub 2>/dev/null || true

echo "Waiting ${BFD_TIMEOUT_WAIT}s for BFD detection timeout..."
sleep "$BFD_TIMEOUT_WAIT"

# BGP should be down.
BGP_STATE=$(gobgp_bgp_state bfd-peer 172.30.9.1)
if [ "$BGP_STATE" != "Established" ]; then
    pass "BGP session torn down after BFD timeout (state: $BGP_STATE)"
else
    fail "BGP session still Established after BFD timeout"
fi

# ---- Scenario 3: No NOTIFICATION (RFC 5882) ----
echo ""
echo "--- Scenario 3: No NOTIFICATION sent (RFC 5882) ---"

NOTIF_AFTER=$(gobgp_recv_notification_count)
if [ "$NOTIF_AFTER" -le "$NOTIF_BEFORE" ]; then
    pass "No NOTIFICATION received by peer (NOTIFICATION count: $NOTIF_AFTER)"
else
    fail "Unexpected NOTIFICATION received (count before=$NOTIF_BEFORE after=$NOTIF_AFTER)"
fi

# ---- Scenario 4: Recovery ----
echo ""
echo "--- Scenario 4: Recovery (BFD + BGP re-establish) ---"

echo "Restarting bfd-stub..."
restart_bfd_stub

echo "Waiting for BFD Up after restart..."
# Check router-rusty's BFD log: the restarted stub runs via docker exec -d
# so its stdout is not captured by docker logs bfd-peer.
BFD_RECOVERED=false
for i in $(seq 1 20); do
    UP_COUNT=$(docker logs router-rusty 2>&1 | grep -c "BFD:.*-> Up" || true)
    if [ "$UP_COUNT" -ge 2 ]; then
        BFD_RECOVERED=true
        break
    fi
    sleep 1
done

if $BFD_RECOVERED; then
    pass "BFD session re-established after recovery"
else
    fail "BFD session did not re-establish within 20s"
fi

if wait_for_bgp_state 30 "Established"; then
    pass "BGP session re-established after recovery"
else
    fail "BGP session did not re-establish within 30s"
    docker logs router-rusty 2>&1 | tail -20
fi

# ---- Scenario 5: AdminDown ----
echo ""
echo "--- Scenario 5: AdminDown (SIGUSR1) -> BGP teardown ---"

# Record notification count before AdminDown.
NOTIF_BEFORE_ADMIN=$(gobgp_recv_notification_count)

echo "Sending SIGUSR1 (AdminDown) to bfd-stub..."
docker exec bfd-peer pkill -USR1 bfd-stub 2>/dev/null || true

echo "Waiting for BGP to go down after AdminDown..."
BGP_DOWN=false
for i in $(seq 1 10); do
    if [ "$(gobgp_bgp_state bfd-peer 172.30.9.1)" != "Established" ]; then
        BGP_DOWN=true
        break
    fi
    sleep 1
done

if $BGP_DOWN; then
    pass "BGP session torn down after BFD AdminDown"
else
    fail "BGP session still Established after BFD AdminDown"
fi

NOTIF_AFTER_ADMIN=$(gobgp_recv_notification_count)
if [ "$NOTIF_AFTER_ADMIN" -le "$NOTIF_BEFORE_ADMIN" ]; then
    pass "No NOTIFICATION sent for AdminDown-triggered teardown"
else
    fail "Unexpected NOTIFICATION for AdminDown teardown"
fi

# ---- Summary ----
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "--- Debug: router-rusty logs (last 30 lines) ---"
    docker logs router-rusty 2>&1 | tail -30
    echo ""
    echo "--- Debug: bfd-peer logs (last 30 lines) ---"
    docker logs bfd-peer 2>&1 | tail -30
    exit 1
fi
