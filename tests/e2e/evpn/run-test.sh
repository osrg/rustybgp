#!/bin/bash
# EVPN (RFC 7432 / RFC 9136) End-to-End Test with AddPath
#
# Topology:
#   [gobgp-a (AS 65002)] -+
#                          +- left-net - [router-rusty (AS 65001)] - right-net - [gobgp-b (AS 65003)]
#   [gobgp-c (AS 65004)] -+
#                       172.30.5.0/24                                172.30.6.0/24
#
# Test scenarios:
#   1. BGP sessions establish with l2vpn-evpn AFI-SAFI and AddPath capability
#   2. gobgp-a injects one route of each EVPN type (Types 1-5)
#   3. All 5 types appear in rustybgp RIB (list_path verification)
#   4. All 5 types propagate through rustybgp to gobgp-b
#   5. gobgp-c injects same Type-5 NLRI as gobgp-a; gobgp-b receives both via AddPath
#   6. Type-2 withdrawal from gobgp-a is propagated to gobgp-b

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

echo "=== EVPN (RFC 7432 / RFC 9136) End-to-End Test ==="
echo ""

# Build and start containers
echo "Building and starting containers..."
docker compose up -d --build 2>&1

# Wait for BGP sessions to converge
echo "Waiting for BGP convergence..."
MAX_WAIT=60
A_OK=false
B_OK=false
C_OK=false

for i in $(seq 1 $MAX_WAIT); do
    if ! $A_OK; then
        if [ "$(gobgp_bgp_state gobgp-a 172.30.5.1)" = "Established" ]; then
            A_OK=true
            echo "gobgp-a <-> rustybgp session established after ${i}s"
        fi
    fi
    if ! $B_OK; then
        if [ "$(gobgp_bgp_state gobgp-b 172.30.6.1)" = "Established" ]; then
            B_OK=true
            echo "gobgp-b <-> rustybgp session established after ${i}s"
        fi
    fi
    if ! $C_OK; then
        if [ "$(gobgp_bgp_state gobgp-c 172.30.5.1)" = "Established" ]; then
            C_OK=true
            echo "gobgp-c <-> rustybgp session established after ${i}s"
        fi
    fi
    if $A_OK && $B_OK && $C_OK; then
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
        echo "--- gobgp-c neighbors ---"
        docker exec gobgp-c gobgp neighbor 2>/dev/null || true
        echo ""
        echo "--- rustybgpd logs ---"
        docker logs router-rusty 2>&1 | tail -30
    fi
    sleep 1
done

echo ""
echo "--- Test Results ---"

# Tests 1-3: Session establishment
if $A_OK; then
    pass "gobgp-a <-> rustybgp session established (l2vpn-evpn + AddPath)"
else
    fail "gobgp-a <-> rustybgp session established"
fi
if $B_OK; then
    pass "gobgp-b <-> rustybgp session established (l2vpn-evpn + AddPath)"
else
    fail "gobgp-b <-> rustybgp session established"
fi
if $C_OK; then
    pass "gobgp-c <-> rustybgp session established (l2vpn-evpn)"
else
    fail "gobgp-c <-> rustybgp session established"
fi

# Inject one EVPN route of each type (Types 1-5) from gobgp-a
echo ""
echo "Injecting EVPN routes (Types 1-5) from gobgp-a..."

# Type-1: Ethernet Auto-Discovery (EAD) - RFC 7432 §7.1
# GoBGP subcommand: a-d; esi type "arbitrary" = all-zeros ESI (type 0)
docker exec gobgp-a gobgp global rib add -a evpn a-d \
    esi arbitrary etag 100 label 200 rd 65002:100 rt 65002:100

# Type-2: MAC/IP Advertisement with IPv4 - RFC 7432 §7.2
# GoBGP subcommand: macadv; mac and ip are positional
docker exec gobgp-a gobgp global rib add -a evpn macadv \
    aa:bb:cc:dd:ee:01 10.0.1.1 etag 0 label 200 rd 65002:200 rt 65002:200

# Type-3: Inclusive Multicast Ethernet Tag (IMET) - RFC 7432 §7.3
# GoBGP subcommand: multicast; ip is positional
docker exec gobgp-a gobgp global rib add -a evpn multicast \
    172.30.5.2 etag 0 rd 65002:300 rt 65002:300

# Type-4: Ethernet Segment (ES) - RFC 7432 §7.4
# GoBGP subcommand: esi; originator ip is positional
docker exec gobgp-a gobgp global rib add -a evpn esi \
    172.30.5.2 esi arbitrary rd 65002:400 rt 65002:400

# Type-5: IP Prefix - RFC 9136 §5
# Same NLRI (rd 1:100, 10.100.0.0/24, gw 0.0.0.0) will also be injected by gobgp-c
docker exec gobgp-a gobgp global rib add -a evpn prefix \
    10.100.0.0/24 gw 0.0.0.0 etag 0 label 200 rd 1:100 rt 1:100

echo "Waiting for propagation..."
sleep 5

# Tests 4-8: rustybgp RIB has one route of each type (list_path verification)
RUSTY_RIB=$(docker exec router-rusty gobgp global rib -a evpn 2>/dev/null || true)

check_rusty_type() {
    local type_label=$1 grep_pattern=$2
    COUNT=$(echo "$RUSTY_RIB" | grep -c "$grep_pattern" || true)
    if [ "$COUNT" -ge 1 ]; then
        pass "rustybgp list_path: $type_label route present ($COUNT path(s))"
    else
        fail "rustybgp list_path: $type_label route missing"
        echo "    Debug: rustybgp EVPN RIB:"
        echo "$RUSTY_RIB"
    fi
}

check_rusty_type "Type-1 EAD"     "type:A-D"
check_rusty_type "Type-2 MAC/IP"  "type:macadv"
check_rusty_type "Type-3 IMET"    "type:multicast"
check_rusty_type "Type-4 ES"      "type:esi"
check_rusty_type "Type-5 IP Prefix" "type:Prefix"

# Tests 9-13: gobgp-b receives all 5 types propagated through rustybgp
B_RIB=$(docker exec gobgp-b gobgp global rib -a evpn 2>/dev/null || true)

check_b_type() {
    local type_label=$1 grep_pattern=$2
    COUNT=$(echo "$B_RIB" | grep -c "$grep_pattern" || true)
    if [ "$COUNT" -ge 1 ]; then
        pass "gobgp-b received $type_label route via rustybgp ($COUNT path(s))"
    else
        fail "gobgp-b did not receive $type_label route"
        echo "    Debug: gobgp-b EVPN RIB:"
        echo "$B_RIB"
    fi
}

check_b_type "Type-1 EAD"      "type:A-D"
check_b_type "Type-2 MAC/IP"   "type:macadv"
check_b_type "Type-3 IMET"     "type:multicast"
check_b_type "Type-4 ES"       "type:esi"
check_b_type "Type-5 IP Prefix" "type:Prefix"

# Test 14: AddPath - gobgp-c injects same Type-5 NLRI as gobgp-a
# (same rd 1:100, prefix 10.100.0.0/24, etag 0, label 200, gw 0.0.0.0)
# rustybgp stores two paths (different next-hops) and sends both to gobgp-b via AddPath
echo ""
echo "Injecting same Type-5 IP Prefix (rd 1:100, 10.100.0.0/24) from gobgp-c for AddPath test..."
docker exec gobgp-c gobgp global rib add -a evpn prefix \
    10.100.0.0/24 gw 0.0.0.0 etag 0 label 200 rd 1:100 rt 1:100

sleep 3

B_TYPE5_COUNT=$(docker exec gobgp-b gobgp global rib -a evpn 2>/dev/null \
    | grep -c "type:Prefix" || true)
if [ "$B_TYPE5_COUNT" -ge 2 ]; then
    pass "gobgp-b has $B_TYPE5_COUNT Type-5 paths via AddPath (expected >= 2)"
else
    fail "gobgp-b has $B_TYPE5_COUNT Type-5 path(s) via AddPath (expected >= 2)"
    echo "    Debug: gobgp-b EVPN RIB after gobgp-c injection:"
    docker exec gobgp-b gobgp global rib -a evpn 2>/dev/null || true
fi

# Test 15: Withdrawal - remove Type-2 from gobgp-a, verify it disappears from gobgp-b
echo ""
echo "Withdrawing Type-2 MAC/IP route from gobgp-a..."
docker exec gobgp-a gobgp global rib del -a evpn macadv \
    aa:bb:cc:dd:ee:01 10.0.1.1 etag 0 label 200 rd 65002:200 rt 65002:200

sleep 3

B_TYPE2_AFTER=$(docker exec gobgp-b gobgp global rib -a evpn 2>/dev/null \
    | grep -c "type:macadv" || true)
if [ "$B_TYPE2_AFTER" -eq 0 ]; then
    pass "Type-2 MAC/IP route correctly withdrawn from gobgp-b"
else
    fail "Type-2 MAC/IP route still present on gobgp-b after withdrawal ($B_TYPE2_AFTER route(s))"
    echo "    Debug: gobgp-b EVPN RIB after withdrawal:"
    docker exec gobgp-b gobgp global rib -a evpn 2>/dev/null || true
fi

echo ""
echo "--- EVPN RIB Summary ---"
echo ""
echo "rustybgp RIB (l2vpn-evpn):"
docker exec router-rusty gobgp global rib -a evpn 2>/dev/null || true
echo ""
echo "gobgp-b RIB (l2vpn-evpn):"
docker exec gobgp-b gobgp global rib -a evpn 2>/dev/null || true
echo ""

echo "=== Results: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
