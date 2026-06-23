#!/bin/bash
# BMP All-Policy End-to-End Test
#
# Topology:
#   [gobgp-peer-a (AS 65002)] -- [rusty (AS 65001)] --> [bmp-receiver :11019]
#                               [gobgp-peer-b (AS 65003)]
#
# Network: bmp-net 172.30.20.0/24
#   rusty:         172.30.20.1
#   gobgp-peer-a:  172.30.20.2  (announces routes)
#   gobgp-peer-b:  172.30.20.3  (receives only)
#   bmp-receiver:  172.30.20.10
#
# Export policy: deny 10.2.0.0/24 to gobgp-peer-b (allow everything else)
# BMP policy: all (pre + post + local-rib + adj-rib-out pre + adj-rib-out post)
#
# Test flow:
#   - peer-a announces 10.1.0.0/24 before BMP connects
#   - BMP added with 'all' policy -> snapshot: pre, post, loc-rib for 10.1.0.0/24
#   - peer-a announces 10.2.0.0/24 (denied by export to peer-b) -> live events
#   - peer-a announces 10.3.0.0/24 (allowed by export to peer-b) -> live events
#
# Snapshot test scenarios:
#   1. Initiation received
#   2. PeerUp for peer-a and peer-b
#   3. Pre-policy RouteMonitoring for 10.1.0.0/24 (snapshot)
#   4. Post-policy RouteMonitoring for 10.1.0.0/24 (snapshot)
#   5. Loc-RIB RouteMonitoring for 10.1.0.0/24 (snapshot)
#   6. No Adj-RIB-Out in snapshot
#
# Live event test scenarios:
#   7. Pre-policy RouteMonitoring for 10.2.0.0/24 (live)
#   8. Post-policy RouteMonitoring for 10.2.0.0/24 (live)
#   9. Loc-RIB RouteMonitoring for 10.2.0.0/24 (live)
#  10. Adj-RIB-Out pre to peer-b for 10.2.0.0/24 (live; before export policy)
#  11. Adj-RIB-Out post to peer-b for 10.2.0.0/24 absent (denied by export policy)
#  12. Adj-RIB-Out pre to peer-b for 10.3.0.0/24 (live)
#  13. Adj-RIB-Out post to peer-b for 10.3.0.0/24 (live; passes export policy)

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
        echo "    BMP log (last 30):"
        docker logs bmp-receiver 2>/dev/null | tail -30 | sed 's/^/      /'
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

echo "=== BMP All-Policy End-to-End Test ==="
echo ""

echo "Building and starting containers..."
docker compose up -d --build --force-recreate 2>&1

echo "Waiting for BGP sessions..."
MAX_WAIT=60
A_OK=false
B_OK=false
for i in $(seq 1 $MAX_WAIT); do
    if ! $A_OK && [ "$(gobgp_bgp_state gobgp-peer-a 172.30.20.1)" = "Established" ]; then
        A_OK=true
        echo "  gobgp-peer-a <-> rusty established after ${i}s"
    fi
    if ! $B_OK && [ "$(gobgp_bgp_state gobgp-peer-b 172.30.20.1)" = "Established" ]; then
        B_OK=true
        echo "  gobgp-peer-b <-> rusty established after ${i}s"
    fi
    if $A_OK && $B_OK; then
        break
    fi
    if [ "$i" -eq "$MAX_WAIT" ]; then
        echo "BGP sessions did not fully establish within ${MAX_WAIT}s"
        docker logs rusty 2>&1 | tail -20
    fi
    sleep 1
done

# Wait for 10.1.0.0/24 to propagate before connecting BMP
sleep 5

echo "Adding BMP with 'all' policy (snapshot)..."
docker exec rusty gobgp bmp add 172.30.20.10 all

echo "Waiting for BMP snapshot (Loc-RIB EoR expected)..."
for i in $(seq 1 30); do
    if docker logs bmp-receiver 2>/dev/null | jq -e 'select(.type == "RouteMonitoring" and .eor == true and .peer_type == 3)' >/dev/null 2>&1; then
        echo "  Loc-RIB EoR received after ${i}s"
        break
    fi
    sleep 1
done

echo ""
echo "--- Test Results (snapshot) ---"

# Test 1: Initiation
bmp_has "Initiation received" '.type == "Initiation"'

# Test 2: PeerUp for peer-a
bmp_has "PeerUp for peer-a (172.30.20.2)" \
    '.type == "PeerUp" and .peer_addr == "172.30.20.2" and .peer_asn == 65002'

# Test 3: PeerUp for peer-b
bmp_has "PeerUp for peer-b (172.30.20.3)" \
    '.type == "PeerUp" and .peer_addr == "172.30.20.3" and .peer_asn == 65003'

# Test 4: Pre-policy RouteMonitoring for 10.1.0.0/24 (snapshot)
bmp_has "Snapshot: pre-policy 10.1.0.0/24" \
    '.type == "RouteMonitoring" and .prefix == "10.1.0.0/24" and .post_policy == false and .adj_rib_out == false and .withdraw == false'

# Test 5: Post-policy RouteMonitoring for 10.1.0.0/24 (snapshot)
bmp_has "Snapshot: post-policy 10.1.0.0/24" \
    '.type == "RouteMonitoring" and .prefix == "10.1.0.0/24" and .post_policy == true and .adj_rib_out == false and .withdraw == false'

# Test 6: Loc-RIB RouteMonitoring for 10.1.0.0/24 (snapshot)
bmp_has "Snapshot: Loc-RIB 10.1.0.0/24" \
    '.type == "RouteMonitoring" and .prefix == "10.1.0.0/24" and .peer_type == 3 and .withdraw == false'

# Test 7: No Adj-RIB-Out for 10.1.0.0/24 in snapshot (adj-out only in live events)
bmp_absent "Snapshot: no Adj-RIB-Out for 10.1.0.0/24 (adj-out is live-only)" \
    '.type == "RouteMonitoring" and .prefix == "10.1.0.0/24" and .adj_rib_out == true'

echo ""
echo "--- Live event tests ---"

echo "Injecting 10.2.0.0/24 from peer-a (denied by export to peer-b)..."
docker exec gobgp-peer-a gobgp global rib add 10.2.0.0/24 nexthop 172.30.20.2

echo "Injecting 10.3.0.0/24 from peer-a (allowed by export to peer-b)..."
docker exec gobgp-peer-a gobgp global rib add 10.3.0.0/24 nexthop 172.30.20.2

echo "Waiting for live Adj-RIB-Out events..."
for i in $(seq 1 30); do
    if docker logs bmp-receiver 2>/dev/null | jq -e 'select(.type == "RouteMonitoring" and .adj_rib_out == true and .prefix == "10.3.0.0/24" and .post_policy == true)' >/dev/null 2>&1; then
        echo "  Adj-RIB-Out post for 10.3.0.0/24 received after ${i}s"
        break
    fi
    sleep 1
done

# Test 8: Pre-policy RouteMonitoring for 10.2.0.0/24 (live)
bmp_has "Live: pre-policy 10.2.0.0/24 from peer-a" \
    '.type == "RouteMonitoring" and .prefix == "10.2.0.0/24" and .post_policy == false and .adj_rib_out == false and .withdraw == false'

# Test 9: Post-policy RouteMonitoring for 10.2.0.0/24 (live, accepted by import policy)
bmp_has "Live: post-policy 10.2.0.0/24 from peer-a" \
    '.type == "RouteMonitoring" and .prefix == "10.2.0.0/24" and .post_policy == true and .adj_rib_out == false and .withdraw == false'

# Test 10: Loc-RIB RouteMonitoring for 10.2.0.0/24 (live)
bmp_has "Live: Loc-RIB 10.2.0.0/24" \
    '.type == "RouteMonitoring" and .prefix == "10.2.0.0/24" and .peer_type == 3 and .withdraw == false'

# Test 11: Adj-RIB-Out pre to peer-b for 10.2.0.0/24 (before export policy)
bmp_has "Live: Adj-RIB-Out pre to peer-b for 10.2.0.0/24" \
    '.type == "RouteMonitoring" and .prefix == "10.2.0.0/24" and .adj_rib_out == true and .post_policy == false and .peer_addr == "172.30.20.3"'

# Test 12: Adj-RIB-Out post to peer-b for 10.2.0.0/24 must be absent (denied by export policy).
# Withdraw events are expected (route denied = withdrawn from post view); check only REACH is absent.
bmp_absent "Live: Adj-RIB-Out post to peer-b for 10.2.0.0/24 absent (denied by export)" \
    '.type == "RouteMonitoring" and .prefix == "10.2.0.0/24" and .adj_rib_out == true and .post_policy == true and .peer_addr == "172.30.20.3" and .withdraw == false'

# Test 13: Adj-RIB-Out pre to peer-b for 10.3.0.0/24
bmp_has "Live: Adj-RIB-Out pre to peer-b for 10.3.0.0/24" \
    '.type == "RouteMonitoring" and .prefix == "10.3.0.0/24" and .adj_rib_out == true and .post_policy == false and .peer_addr == "172.30.20.3"'

# Test 14: Adj-RIB-Out post to peer-b for 10.3.0.0/24 (passes export policy)
bmp_has "Live: Adj-RIB-Out post to peer-b for 10.3.0.0/24 (passes export)" \
    '.type == "RouteMonitoring" and .prefix == "10.3.0.0/24" and .adj_rib_out == true and .post_policy == true and .peer_addr == "172.30.20.3"'

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
