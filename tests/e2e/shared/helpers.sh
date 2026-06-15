#!/bin/bash
# Shared test helper functions for e2e tests.

# Query FRR BGP neighbor state via vtysh JSON output.
frr_bgp_state() {
    local container=$1 neighbor=$2
    docker exec "$container" vtysh -c "show bgp neighbor $neighbor json" 2>/dev/null \
        | jq -r --arg nb "$neighbor" '.[$nb].bgpState // empty' 2>/dev/null || true
}

# Query GoBGP daemon neighbor state via gobgp CLI text output.
# Returns "Established" or "Idle".
gobgp_bgp_state() {
    local container=$1 neighbor=$2
    if docker exec "$container" gobgp neighbor "$neighbor" 2>/dev/null \
        | grep -qE "BGP state = .*ESTABLISHED"; then
        echo "Established"
    else
        echo "Idle"
    fi
}
