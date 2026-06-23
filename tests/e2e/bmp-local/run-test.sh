#!/bin/bash
# BMP Local-RIB End-to-End Test (RFC 9069)
#
# Topology:
#   [gobgp-peer-a (AS 65002, router-id 172.30.20.2)] \
#                                                      -- [rusty (AS 65001)] --> [bmp-receiver :11019]
#   [gobgp-peer-b (AS 65003, router-id 172.30.20.3)] /
#
# Network: bmp-net 172.30.20.0/24
#   rusty:         172.30.20.1
#   gobgp-peer-a:  172.30.20.2
#   gobgp-peer-b:  172.30.20.3
#   bmp-receiver:  172.30.20.10
#
# peer-a announces: 10.1.0.0/24 and 10.2.0.0/24
# peer-b announces: 10.1.0.0/24 (duplicate; peer-a wins via lower router-id 172.30.20.2 < 172.30.20.3)
# BMP policy: local-rib, added via gobgp CLI after BGP convergence
#
# Test scenarios:
#   1. Initiation received
#   2. PeerUp for virtual Loc-RIB peer (peer_type=3, peer_addr=0.0.0.0)
#   3. Loc-RIB RouteMonitoring for 10.1.0.0/24 with nexthop 172.30.20.2 (peer-a won)
#   4. Loc-RIB RouteMonitoring for 10.2.0.0/24 with nexthop 172.30.20.2 (only from peer-a)
#   5. EoR for Loc-RIB (peer_type=3)

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

echo "=== BMP Local-RIB (RFC 9069) End-to-End Test ==="
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

# Wait for routes to propagate and best-path selection to complete
sleep 5

echo "Adding BMP with 'local-rib' policy (snapshot)..."
docker exec rusty gobgp bmp add 172.30.20.10 local-rib

echo "Waiting for BMP Loc-RIB EoR..."
for i in $(seq 1 30); do
    if docker logs bmp-receiver 2>/dev/null | jq -e 'select(.type == "RouteMonitoring" and .eor == true and .peer_type == 3)' >/dev/null 2>&1; then
        echo "  Loc-RIB EoR received after ${i}s"
        break
    fi
    sleep 1
done

echo ""
echo "--- Test Results ---"

# Test 1: Initiation message
bmp_has "Initiation received" '.type == "Initiation"'

# Test 2: PeerUp for virtual Loc-RIB peer (peer_type=3, peer_addr=0.0.0.0)
bmp_has "PeerUp for Loc-RIB virtual peer (peer_type=3)" \
    '.type == "PeerUp" and .peer_type == 3 and .peer_addr == "0.0.0.0"'

# Test 3: Loc-RIB RouteMonitoring for 10.1.0.0/24 with nexthop from peer-a (best path)
bmp_has "Loc-RIB RouteMonitoring 10.1.0.0/24 nexthop=172.30.20.2 (peer-a wins)" \
    '.type == "RouteMonitoring" and .peer_type == 3 and .prefix == "10.1.0.0/24" and .nexthop == "172.30.20.2" and .withdraw == false'

# Test 4: Loc-RIB RouteMonitoring for 10.1.0.0/24 must not use peer-b's nexthop
bmp_absent "Loc-RIB 10.1.0.0/24 with nexthop=172.30.20.3 absent (peer-b lost)" \
    '.type == "RouteMonitoring" and .peer_type == 3 and .prefix == "10.1.0.0/24" and .nexthop == "172.30.20.3"'

# Test 5: Loc-RIB RouteMonitoring for 10.2.0.0/24 from peer-a
bmp_has "Loc-RIB RouteMonitoring 10.2.0.0/24" \
    '.type == "RouteMonitoring" and .peer_type == 3 and .prefix == "10.2.0.0/24" and .withdraw == false'

# Test 6: EoR for Loc-RIB
bmp_has "EoR for Loc-RIB (peer_type=3, afi=1, safi=1)" \
    '.type == "RouteMonitoring" and .eor == true and .peer_type == 3 and .afi == 1 and .safi == 1'

# Test 7: No adj-rib-in messages (local-rib only)
bmp_absent "No pre-policy adj-rib-in messages" \
    '.type == "RouteMonitoring" and .peer_type == 0 and .post_policy == false and .adj_rib_out == false'

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
