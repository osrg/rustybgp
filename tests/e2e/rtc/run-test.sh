#!/bin/bash
# RTC (Route Target Membership, RFC 4684) End-to-End Test
#
# Topology:
#   [gobgp-src (AS 65002)] - left-net - [router-rusty (AS 65001)] - right-net - [gobgp-a (AS 65003)]
#                          172.30.5.0/24                           172.30.6.0/24  [gobgp-b (AS 65004)]
#
# gobgp-src injects two VPN routes:
#   10.1.0.0/24  RT:65001:100  (matches gobgp-a's VRF interest only)
#   10.2.0.0/24  RT:65001:200  (matches gobgp-b's VRF interest only)
#
# Test scenarios:
#   1. Basic RT filter: gobgp-a receives only RT:65001:100 route; gobgp-b receives only RT:65001:200
#   2. Dynamic RT addition: gobgp-a adds a VRF for RT:65001:200; it then receives 10.2.0.0/24 too
#   3. RT withdrawal: gobgp-a removes the VRF; 10.2.0.0/24 is withdrawn from gobgp-a

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

echo "=== RTC (RFC 4684) End-to-End Test ==="
echo ""

echo "Building and starting containers..."
docker compose up -d --build 2>&1

echo "Waiting for BGP convergence..."
MAX_WAIT=60
SRC_OK=false
A_OK=false
B_OK=false

for i in $(seq 1 $MAX_WAIT); do
    if ! $SRC_OK && [ "$(gobgp_bgp_state gobgp-src 172.30.5.1)" = "Established" ]; then
        SRC_OK=true
        echo "  gobgp-src <-> rustybgp established after ${i}s"
    fi
    if ! $A_OK && [ "$(gobgp_bgp_state gobgp-a 172.30.6.1)" = "Established" ]; then
        A_OK=true
        echo "  gobgp-a   <-> rustybgp established after ${i}s"
    fi
    if ! $B_OK && [ "$(gobgp_bgp_state gobgp-b 172.30.6.1)" = "Established" ]; then
        B_OK=true
        echo "  gobgp-b   <-> rustybgp established after ${i}s"
    fi
    $SRC_OK && $A_OK && $B_OK && break
    if [ "$i" -eq "$MAX_WAIT" ]; then
        echo "Sessions did not fully establish within ${MAX_WAIT}s"
        echo "--- rustybgpd logs ---"
        docker logs router-rusty 2>&1 | tail -20
    fi
    sleep 1
done

echo ""
echo "--- Session establishment ---"
$SRC_OK && pass "gobgp-src <-> rustybgp session established (ipv4-vpn)" \
          || fail "gobgp-src <-> rustybgp session established"
$A_OK   && pass "gobgp-a   <-> rustybgp session established (ipv4-vpn + rtc)" \
          || fail "gobgp-a   <-> rustybgp session established"
$B_OK   && pass "gobgp-b   <-> rustybgp session established (ipv4-vpn + rtc)" \
          || fail "gobgp-b   <-> rustybgp session established"

# Inject two VPN routes from gobgp-src with different RTs.
echo ""
echo "Injecting VPN routes from gobgp-src..."
docker exec gobgp-src gobgp global rib add -a vpnv4 \
    10.1.0.0/24 label 100 rd 65002:100 rt 65001:100 nexthop 172.30.5.2
docker exec gobgp-src gobgp global rib add -a vpnv4 \
    10.2.0.0/24 label 200 rd 65002:200 rt 65001:200 nexthop 172.30.5.2

echo "Waiting for propagation..."
sleep 5

# --- Scenario 1: Basic RT filter ---
echo ""
echo "--- Scenario 1: Basic RT filter ---"

A_RIB=$(docker exec gobgp-a gobgp global rib -a vpnv4 2>/dev/null || true)
B_RIB=$(docker exec gobgp-b gobgp global rib -a vpnv4 2>/dev/null || true)

if echo "$A_RIB" | grep -q "10.1.0.0/24"; then
    pass "gobgp-a received 10.1.0.0/24 (RT:65001:100 matches its VRF)"
else
    fail "gobgp-a did not receive 10.1.0.0/24 (RT:65001:100)"
    echo "    gobgp-a VPN RIB: $A_RIB"
fi

if ! echo "$A_RIB" | grep -q "10.2.0.0/24"; then
    pass "gobgp-a did NOT receive 10.2.0.0/24 (RT:65001:200 filtered by RTC)"
else
    fail "gobgp-a wrongly received 10.2.0.0/24 (RT:65001:200 should be filtered)"
    echo "    gobgp-a VPN RIB: $A_RIB"
fi

if echo "$B_RIB" | grep -q "10.2.0.0/24"; then
    pass "gobgp-b received 10.2.0.0/24 (RT:65001:200 matches its VRF)"
else
    fail "gobgp-b did not receive 10.2.0.0/24 (RT:65001:200)"
    echo "    gobgp-b VPN RIB: $B_RIB"
fi

if ! echo "$B_RIB" | grep -q "10.1.0.0/24"; then
    pass "gobgp-b did NOT receive 10.1.0.0/24 (RT:65001:100 filtered by RTC)"
else
    fail "gobgp-b wrongly received 10.1.0.0/24 (RT:65001:100 should be filtered)"
    echo "    gobgp-b VPN RIB: $B_RIB"
fi

# --- Scenario 2: Dynamic RT addition ---
echo ""
echo "--- Scenario 2: Dynamic RT addition ---"
echo "Adding vrf-ab (RT:65001:200) to gobgp-a..."
docker exec gobgp-a gobgp vrf add vrf-ab rd 65003:2 rt both 65001:200

echo "Waiting for RTC NLRI propagation and VPN route delivery..."
sleep 5

A_RIB2=$(docker exec gobgp-a gobgp global rib -a vpnv4 2>/dev/null || true)
if echo "$A_RIB2" | grep -q "10.2.0.0/24"; then
    pass "gobgp-a now receives 10.2.0.0/24 after adding VRF for RT:65001:200"
else
    fail "gobgp-a still missing 10.2.0.0/24 after adding VRF for RT:65001:200"
    echo "    gobgp-a VPN RIB: $A_RIB2"
fi

if echo "$A_RIB2" | grep -q "10.1.0.0/24"; then
    pass "gobgp-a still receives 10.1.0.0/24 (RT:65001:100 unchanged)"
else
    fail "gobgp-a lost 10.1.0.0/24 after adding second VRF"
fi

# --- Scenario 3: RT withdrawal (VRF deletion) ---
echo ""
echo "--- Scenario 3: RT withdrawal (VRF deletion) ---"
echo "Deleting vrf-ab from gobgp-a..."
docker exec gobgp-a gobgp vrf del vrf-ab

echo "Waiting for RTC NLRI withdrawal and VPN route withdrawal..."
sleep 5

A_RIB3=$(docker exec gobgp-a gobgp global rib -a vpnv4 2>/dev/null || true)
if ! echo "$A_RIB3" | grep -q "10.2.0.0/24"; then
    pass "gobgp-a no longer receives 10.2.0.0/24 after deleting VRF for RT:65001:200"
else
    fail "gobgp-a still has 10.2.0.0/24 after deleting VRF for RT:65001:200"
    echo "    gobgp-a VPN RIB: $A_RIB3"
fi

if echo "$A_RIB3" | grep -q "10.1.0.0/24"; then
    pass "gobgp-a still receives 10.1.0.0/24 (RT:65001:100 unchanged)"
else
    fail "gobgp-a lost 10.1.0.0/24 after deleting second VRF"
fi

echo ""
echo "--- RIB Summary ---"
echo ""
echo "gobgp-a VPN RIB (final):"
docker exec gobgp-a gobgp global rib -a vpnv4 2>/dev/null || true
echo ""
echo "gobgp-b VPN RIB (final):"
docker exec gobgp-b gobgp global rib -a vpnv4 2>/dev/null || true

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
