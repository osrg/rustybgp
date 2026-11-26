#!/bin/bash
# Shared test helper functions for e2e tests.

# Auto-detect RUST_TARGET from host architecture if the caller did not set it.
# All docker-compose.yml files reference ${RUST_TARGET} when building the
# rustybgpd container, so this must be set before "docker compose up --build".
if [ -z "${RUST_TARGET:-}" ]; then
    case "$(uname -m)" in
        x86_64)  export RUST_TARGET=x86_64-unknown-linux-musl ;;
        aarch64) export RUST_TARGET=aarch64-unknown-linux-musl ;;
        *) echo "helpers.sh: unsupported host arch: $(uname -m)" >&2; exit 1 ;;
    esac
fi

# The run-test.sh scripts use "set -o pipefail". Do not end a pipeline with
# a command that exits before it reads all input, such as "grep -q", "head" or
# "awk '{...; exit}'". The command that writes to the pipe can then get
# SIGPIPE, and pipefail makes the whole pipeline fail even when the pattern
# matched. Use "grep ... >/dev/null" instead of "grep -q".

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
        | grep -E "BGP state = .*ESTABLISHED" >/dev/null; then
        echo "Established"
    else
        echo "Idle"
    fi
}

# Query a BIRD BGP protocol's state via birdc text output.
# Returns "Established" or "Idle".
bird_bgp_state() {
    local container=$1 protocol=$2
    if docker exec "$container" birdc show protocols "$protocol" 2>/dev/null \
        | grep -E "^${protocol}[[:space:]]+BGP[[:space:]].*Established" >/dev/null; then
        echo "Established"
    else
        echo "Idle"
    fi
}
