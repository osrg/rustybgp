#!/bin/bash
# Config reload (SIGHUP) End-to-End Test
#
# Topology:
#   [gobgp-a (AS 65002)] --eBGP-- [rusty (AS 65001)] --eBGP-- [gobgp-b (AS 65003)]
#      172.30.50.2                   172.30.50.1                  172.30.50.3
#
# rusty originates 10.0.1.0/24 and 10.0.2.0/24. Both GoBGP peers always
# have rusty configured. run-test.sh replaces rusty's config file and sends
# SIGHUP:
#
#   step1.toml: neighbor gobgp-a only, no policy.
#   step2.toml: adds neighbor gobgp-b, and a global export policy that
#               rejects 10.0.2.0/24.
#   step3.toml: deletes neighbor gobgp-a, and changes the hold time of
#               gobgp-b (a changed neighbor is not applied).
#
# Test scenarios:
#   1. step1: gobgp-a is up and gets both routes. gobgp-b is not up.
#   2. step2: gobgp-b comes up and gets only 10.0.1.0/24.
#   3. step2: gobgp-a keeps 10.0.2.0/24 (a reload does not run a soft reset)
#      and loses it after a soft reset out on rusty.
#   4. step3: the gobgp-a session goes down and rusty no longer has it.
#   5. step3: the gobgp-b session stays up (no flop), and rusty logs that
#      the change of gobgp-b is not applied.

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

RUSTY=172.30.50.1
GOBGP_A=172.30.50.2
GOBGP_B=172.30.50.3

# Replace rusty's config file with the given step and send SIGHUP.
reload() {
    docker exec rusty sh -c \
        "cp /etc/rustybgp/$1 /tmp/rustybgp.toml && kill -HUP \$(pidof rustybgpd)"
}

# has_route <container> <prefix>
has_route() {
    docker exec "$1" gobgp global rib 2>/dev/null | grep "$2" >/dev/null
}

# wait_for <seconds> <command...>: returns 0 once the command succeeds.
wait_for() {
    local max=$1
    shift
    for _ in $(seq 1 "$max"); do
        if "$@"; then
            return 0
        fi
        sleep 1
    done
    return 1
}

established() {
    [ "$(gobgp_bgp_state "$1" "$RUSTY")" = "Established" ]
}

not_established() {
    ! established "$1"
}

no_route() {
    ! has_route "$1" "$2"
}

flops() {
    docker exec "$1" gobgp neighbor "$RUSTY" 2>/dev/null \
        | sed -n 's/.*Flops = \([0-9]*\).*/\1/p'
}

echo "=== Config Reload (SIGHUP) End-to-End Test ==="
echo ""

echo "Building and starting containers..."
docker compose up -d --build --force-recreate 2>&1

echo ""
echo "--- Step 1: gobgp-a only ---"

if wait_for 60 established gobgp-a; then
    pass "gobgp-a <-> rusty established"
else
    fail "gobgp-a <-> rusty established"
    docker logs rusty 2>&1 | tail -20
fi

if wait_for 30 has_route gobgp-a 10.0.2.0/24 && has_route gobgp-a 10.0.1.0/24; then
    pass "gobgp-a has 10.0.1.0/24 and 10.0.2.0/24"
else
    fail "gobgp-a has 10.0.1.0/24 and 10.0.2.0/24"
fi

# gobgp-b retries every 5 seconds; give it a chance to get in.
sleep 10
if not_established gobgp-b; then
    pass "gobgp-b is not established (rusty does not have it)"
else
    fail "gobgp-b is not established (rusty does not have it)"
fi

echo ""
echo "--- Step 2: add gobgp-b and an export policy ---"
reload step2.toml

if wait_for 60 established gobgp-b; then
    pass "gobgp-b <-> rusty established after reload"
else
    fail "gobgp-b <-> rusty established after reload"
    docker logs rusty 2>&1 | tail -20
fi

if wait_for 30 has_route gobgp-b 10.0.1.0/24 && no_route gobgp-b 10.0.2.0/24; then
    pass "gobgp-b has 10.0.1.0/24 but not 10.0.2.0/24 (new export policy)"
else
    fail "gobgp-b has 10.0.1.0/24 but not 10.0.2.0/24 (new export policy)"
    docker exec gobgp-b gobgp global rib 2>/dev/null || true
fi

if has_route gobgp-a 10.0.2.0/24; then
    pass "gobgp-a still has 10.0.2.0/24 (reload does not run a soft reset)"
else
    fail "gobgp-a still has 10.0.2.0/24 (reload does not run a soft reset)"
fi

docker exec rusty gobgp neighbor "$GOBGP_A" softresetout
if wait_for 30 no_route gobgp-a 10.0.2.0/24 && has_route gobgp-a 10.0.1.0/24; then
    pass "gobgp-a loses 10.0.2.0/24 after soft reset out"
else
    fail "gobgp-a loses 10.0.2.0/24 after soft reset out"
    docker exec gobgp-a gobgp global rib 2>/dev/null || true
fi

echo ""
echo "--- Step 3: delete gobgp-a, change gobgp-b ---"
FLOPS_BEFORE=$(flops gobgp-b)
reload step3.toml

if wait_for 30 not_established gobgp-a; then
    pass "gobgp-a session is down after reload"
else
    fail "gobgp-a session is down after reload"
fi

if docker exec rusty gobgp neighbor 2>/dev/null | grep "$GOBGP_A" >/dev/null; then
    fail "rusty no longer has neighbor gobgp-a"
    docker exec rusty gobgp neighbor 2>/dev/null || true
else
    pass "rusty no longer has neighbor gobgp-a"
fi

# Give a wrongly applied change time to reset the session.
sleep 5
if established gobgp-b && [ "$(flops gobgp-b)" = "$FLOPS_BEFORE" ]; then
    pass "gobgp-b session stays up (changed neighbor is not applied)"
else
    fail "gobgp-b session stays up (changed neighbor is not applied)"
    docker exec gobgp-b gobgp neighbor "$RUSTY" 2>/dev/null || true
fi

if docker logs rusty 2>&1 | grep "neighbor $GOBGP_B is changed" >/dev/null; then
    pass "rusty logs that the change of gobgp-b is not applied"
else
    fail "rusty logs that the change of gobgp-b is not applied"
fi

echo ""
echo "--- rusty logs ---"
docker logs rusty 2>&1 | tail -30
echo ""

echo "=== Results: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
