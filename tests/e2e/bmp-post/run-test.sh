#!/bin/bash
# BMP Both-Policy End-to-End Test
#
# Topology:
#   [gobgp-peer (AS 65002)] -- [rusty (AS 65001)] --> [bmp-receiver :11019]
#
# Network: bmp-net 172.30.20.0/24
#   rusty:        172.30.20.1
#   gobgp-peer:   172.30.20.2
#   bmp-receiver: 172.30.20.10
#
# Import policy on rusty: deny 10.2.0.0/24 from gobgp-peer
# BMP policy: both (pre + post), added via gobgp CLI after BGP convergence
#
# Test scenarios:
#   1. Initiation received
#   2. PeerUp for gobgp-peer (snapshot)
#   3. Pre-policy RouteMonitoring for 10.1.0.0/24 (accepted by import policy)
#   4. Pre-policy RouteMonitoring for 10.2.0.0/24 (denied by import policy, visible pre)
#   5. Post-policy RouteMonitoring for 10.1.0.0/24 (accepted)
#   6. Post-policy RouteMonitoring for 10.2.0.0/24 absent (denied by import policy)
#   7. EoR for pre-policy
#   8. EoR for post-policy

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

echo "=== BMP Both-Policy End-to-End Test ==="
echo ""

echo "Building and starting containers..."
docker compose up -d --build --force-recreate 2>&1

echo "Waiting for BGP session..."
MAX_WAIT=60
for i in $(seq 1 $MAX_WAIT); do
    if [ "$(gobgp_bgp_state gobgp-peer 172.30.20.1)" = "Established" ]; then
        echo "  gobgp-peer <-> rusty established after ${i}s"
        break
    fi
    if [ "$i" -eq "$MAX_WAIT" ]; then
        echo "BGP session did not establish within ${MAX_WAIT}s"
        docker logs rusty 2>&1 | tail -20
    fi
    sleep 1
done

# Wait for routes to propagate before adding BMP
sleep 5

echo "Adding BMP with 'both' policy (snapshot)..."
docker exec rusty gobgp bmp add 172.30.20.10 both

echo "Waiting for BMP snapshot (EoR for post-policy expected)..."
for i in $(seq 1 30); do
    if docker logs bmp-receiver 2>/dev/null | jq -e 'select(.type == "RouteMonitoring" and .eor == true and .post_policy == true)' >/dev/null 2>&1; then
        echo "  BMP post-policy EoR received after ${i}s"
        break
    fi
    sleep 1
done

echo ""
echo "--- Test Results ---"

# Test 1: Initiation message
bmp_has "Initiation received" '.type == "Initiation"'

# Test 2: PeerUp for gobgp-peer
bmp_has "PeerUp for 172.30.20.2" '.type == "PeerUp" and .peer_addr == "172.30.20.2" and .peer_asn == 65002'

# Test 3: Pre-policy RouteMonitoring for 10.1.0.0/24 (accepted by import policy)
bmp_has "Pre-policy RouteMonitoring 10.1.0.0/24" \
    '.type == "RouteMonitoring" and .prefix == "10.1.0.0/24" and .post_policy == false and .withdraw == false'

# Test 4: Pre-policy RouteMonitoring for 10.2.0.0/24 (denied, but visible pre-policy)
bmp_has "Pre-policy RouteMonitoring 10.2.0.0/24 (denied route visible pre-policy)" \
    '.type == "RouteMonitoring" and .prefix == "10.2.0.0/24" and .post_policy == false and .withdraw == false'

# Test 5: Post-policy RouteMonitoring for 10.1.0.0/24 (accepted)
bmp_has "Post-policy RouteMonitoring 10.1.0.0/24" \
    '.type == "RouteMonitoring" and .prefix == "10.1.0.0/24" and .post_policy == true and .withdraw == false'

# Test 6: Post-policy RouteMonitoring for 10.2.0.0/24 must be absent (denied by import policy)
bmp_absent "Post-policy RouteMonitoring 10.2.0.0/24 absent (denied by import policy)" \
    '.type == "RouteMonitoring" and .prefix == "10.2.0.0/24" and .post_policy == true and .withdraw == false'

# Test 7: EoR for pre-policy
bmp_has "EoR for pre-policy (afi=1, safi=1)" \
    '.type == "RouteMonitoring" and .eor == true and .afi == 1 and .safi == 1 and .post_policy == false'

# Test 8: EoR for post-policy
bmp_has "EoR for post-policy (afi=1, safi=1)" \
    '.type == "RouteMonitoring" and .eor == true and .afi == 1 and .safi == 1 and .post_policy == true'

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
