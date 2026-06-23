#!/bin/bash
# BMP Pre-Policy End-to-End Test
#
# Topology:
#   [gobgp-peer (AS 65002)] -- [rusty (AS 65001)] --> [bmp-receiver :11019]
#
# Network: bmp-net 172.30.20.0/24
#   rusty:        172.30.20.1
#   gobgp-peer:   172.30.20.2
#   bmp-receiver: 172.30.20.10
#
# BMP policy: pre-policy (configured in rustybgp.yaml from start)
#
# Test scenarios:
#   1. Initiation message received from rusty
#   2. PeerUp for gobgp-peer (live event)
#   3. RouteMonitoring pre-policy for 10.1.0.0/24 (live event)
#   4. End-of-RIB for IPv4 unicast (live event)
#   5. Live: new route 10.2.0.0/24 announced
#   6. Live: route 10.1.0.0/24 withdrawn
#   7. Live: PeerDown when gobgp-peer stops

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

bmp_has() {
    local desc="$1"
    local filter="$2"
    local count
    count=$(docker logs bmp-receiver 2>/dev/null | jq -c "select($filter)" | wc -l)
    if [ "$count" -ge 1 ]; then
        pass "$desc"
    else
        fail "$desc"
        echo "    Filter: $filter"
        echo "    BMP log (last 20):"
        docker logs bmp-receiver 2>/dev/null | tail -20 | sed 's/^/      /'
    fi
}

bmp_absent() {
    local desc="$1"
    local filter="$2"
    local count
    count=$(docker logs bmp-receiver 2>/dev/null | jq -c "select($filter)" | wc -l)
    if [ "$count" -eq 0 ]; then
        pass "$desc"
    else
        fail "$desc"
        echo "    Filter: $filter"
        echo "    Unexpected matches:"
        docker logs bmp-receiver 2>/dev/null | jq -c "select($filter)" | head -5 | sed 's/^/      /'
    fi
}

cleanup() {
    echo ""
    echo "Cleaning up..."
    docker compose down --volumes --remove-orphans 2>/dev/null || true
}
trap cleanup EXIT

echo "=== BMP Pre-Policy End-to-End Test ==="
echo ""

echo "Building and starting containers..."
docker compose up -d --build --force-recreate 2>&1

echo "Waiting for BGP session..."
MAX_WAIT=60
PEER_OK=false
for i in $(seq 1 $MAX_WAIT); do
    if [ "$(gobgp_bgp_state gobgp-peer 172.30.20.1)" = "Established" ]; then
        PEER_OK=true
        echo "  gobgp-peer <-> rusty established after ${i}s"
        break
    fi
    if [ "$i" -eq "$MAX_WAIT" ]; then
        echo "BGP session did not establish within ${MAX_WAIT}s"
        docker logs rusty 2>&1 | tail -20
    fi
    sleep 1
done

# Wait for BMP messages to arrive (Initiation + PeerUp + RouteMonitoring + EoR)
echo "Waiting for BMP Initiation..."
for i in $(seq 1 30); do
    if docker logs bmp-receiver 2>/dev/null | jq -e 'select(.type == "Initiation")' >/dev/null 2>&1; then
        echo "  BMP Initiation received after ${i}s"
        break
    fi
    sleep 1
done

# Wait for EoR to confirm all initial messages delivered
for i in $(seq 1 30); do
    if docker logs bmp-receiver 2>/dev/null | jq -e 'select(.type == "RouteMonitoring" and .eor == true)' >/dev/null 2>&1; then
        echo "  BMP EoR received after ${i}s"
        break
    fi
    sleep 1
done

echo ""
echo "--- Test Results (initial BMP messages) ---"

# Test 1: Initiation message received
bmp_has "Initiation received" '.type == "Initiation"'

# Test 2: PeerUp for gobgp-peer
bmp_has "PeerUp for 172.30.20.2" '.type == "PeerUp" and .peer_addr == "172.30.20.2" and .peer_asn == 65002'

# Test 3: RouteMonitoring pre-policy for 10.1.0.0/24
bmp_has "RouteMonitoring pre-policy 10.1.0.0/24" \
    '.type == "RouteMonitoring" and .prefix == "10.1.0.0/24" and .post_policy == false and .adj_rib_out == false and .withdraw == false'

# Test 4: No post-policy messages (pre-policy only)
bmp_absent "No post-policy RouteMonitoring" '.type == "RouteMonitoring" and .post_policy == true'

# Test 5: EoR for IPv4 unicast
bmp_has "EoR for IPv4 unicast (pre-policy)" \
    '.type == "RouteMonitoring" and .eor == true and .afi == 1 and .safi == 1 and .post_policy == false'

# --- Live event tests ---
echo ""
echo "--- Live event tests ---"

echo "Injecting new route 10.2.0.0/24..."
docker exec gobgp-peer gobgp global rib add 10.2.0.0/24 nexthop 172.30.20.2
sleep 3

# Test 6: Live RouteMonitoring for new route
bmp_has "Live RouteMonitoring for 10.2.0.0/24" \
    '.type == "RouteMonitoring" and .prefix == "10.2.0.0/24" and .post_policy == false and .withdraw == false'

echo "Withdrawing 10.1.0.0/24..."
docker exec gobgp-peer gobgp global rib del 10.1.0.0/24
sleep 3

# Test 7: Live RouteMonitoring withdraw for 10.1.0.0/24
bmp_has "Live RouteMonitoring withdraw 10.1.0.0/24" \
    '.type == "RouteMonitoring" and .prefix == "10.1.0.0/24" and .withdraw == true'

echo "Stopping gobgp-peer..."
docker compose stop gobgp-peer
sleep 5

# Test 8: PeerDown received
bmp_has "PeerDown for 172.30.20.2" \
    '.type == "PeerDown" and .peer_addr == "172.30.20.2"'

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
