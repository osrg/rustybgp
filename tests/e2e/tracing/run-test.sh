#!/bin/bash
# Tracing / Logging End-to-End Test
#
# Topology:
#   [frr-peer (AS 65002)] <---BGP---> [router-rusty (AS 65001)]
#
# Verifies:
#   1. --log-level error suppresses info messages
#   2. --log-level debug shows debug messages
#   3. RUST_LOG env var overrides --log-level CLI flag
#   4. Runtime log level change via gRPC SetLogLevel
#   5. Peer session logs include addr= span context

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

PASS=0
FAIL=0
LOGFILE=""

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

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Start rustybgpd inside the container. Logs go to /tmp/<logfile>.
# Usage: start_bgpd <logfile> [extra rustybgpd args...]
start_bgpd() {
    LOGFILE=$1; shift
    # shellcheck disable=SC2068
    docker exec -d tracing-rusty sh -c "rustybgpd $@ >/tmp/${LOGFILE} 2>&1"
}

# Start with a custom env var prepended.
# Usage: start_bgpd_env <env> <logfile> [extra rustybgpd args...]
start_bgpd_env() {
    local env=$1; shift
    LOGFILE=$1; shift
    # shellcheck disable=SC2068
    docker exec -d tracing-rusty sh -c "${env} rustybgpd $@ >/tmp/${LOGFILE} 2>&1"
}

stop_bgpd() {
    docker exec tracing-rusty sh -c "pkill -x rustybgpd 2>/dev/null || true"
    sleep 2
}

wait_grpc() {
    local logfile=${1:-}
    for _ in $(seq 1 30); do
        if docker exec tracing-rusty gobgp global >/dev/null 2>&1; then
            sleep 1  # allow log buffers to flush
            return 0
        fi
        sleep 1
    done
    echo "    WARNING: gRPC not ready after 30s"
    echo "    --- daemon process check ---"
    docker exec tracing-rusty ps aux 2>/dev/null | grep -E "rustybgp|PID" || true
    if [ -n "$logfile" ]; then
        echo "    --- $logfile contents ---"
        docker exec tracing-rusty cat "/tmp/$logfile" 2>/dev/null | tail -20 || true
    fi
    return 1
}

wait_session() {
    for _ in $(seq 1 60); do
        if docker exec tracing-rusty gobgp neighbor 172.30.10.2 2>/dev/null \
            | grep -qi "established"; then
            return 0
        fi
        sleep 1
    done
    echo "    WARNING: BGP session not established after 60s"
    return 1
}

# Read a log file stripping ANSI escape codes (tracing uses colors by default).
# cat -v converts ESC to ^[, then sed strips ^[[...m sequences on the host.
read_log() {
    docker exec tracing-rusty cat -v "/tmp/$1" | sed 's/\^\[\[[0-9;]*m//g'
}

install_grpcurl() {
    # Install grpcurl inside the container for SetLogLevel gRPC call.
    # Only installs once (idempotent).
    if docker exec tracing-rusty which grpcurl >/dev/null 2>&1; then
        return 0
    fi
    echo "Installing grpcurl in container..."
    docker exec tracing-rusty sh -c '
        ARCH=$(uname -m)
        case "$ARCH" in
            x86_64)  GA=x86_64 ;;
            aarch64) GA=arm64 ;;
            *) echo "unsupported arch: $ARCH"; exit 1 ;;
        esac
        curl -sSL "https://github.com/fullstorydev/grpcurl/releases/download/v1.9.1/grpcurl_1.9.1_linux_${GA}.tar.gz" \
            | tar -xz -C /usr/local/bin grpcurl
    '
    # Copy proto files so grpcurl can parse the service definition.
    docker cp "$SCRIPT_DIR/../../../api/proto" tracing-rusty:/etc/proto
}

grpc_set_log_level() {
    # Levels from gobgp.proto: PANIC=1, FATAL=2, ERROR=3, WARN=4, INFO=5, DEBUG=6, TRACE=7
    local level_num=$1
    docker exec tracing-rusty grpcurl -plaintext \
        -import-path /etc/proto -proto gobgp.proto \
        -d "{\"level\": ${level_num}}" \
        localhost:50051 api.GoBgpService/SetLogLevel
}

# ---------------------------------------------------------------------------
# Build and start containers
# ---------------------------------------------------------------------------

echo "=== Tracing / Logging End-to-End Test ==="
echo ""
echo "Building and starting containers..."
docker compose up -d --build 2>&1

# Give FRR time to start bgpd
sleep 3

install_grpcurl

# ===================================================================
# TEST 1: --log-level error suppresses info messages
# ===================================================================
echo ""
echo "--- Test 1: --log-level error suppresses info messages ---"

start_bgpd test1.log -f /etc/rustybgp.yaml --log-level error
wait_grpc $LOGFILE

if read_log test1.log | grep -q "starting RustyBGPd"; then
    fail "--log-level error should suppress info-level 'starting RustyBGPd'"
else
    pass "--log-level error suppresses info messages"
fi
stop_bgpd

# ===================================================================
# TEST 2: --log-level debug shows debug-level output
# ===================================================================
echo ""
echo "--- Test 2: --log-level debug shows debug-level output ---"

start_bgpd test2.log -f /etc/rustybgp.yaml --log-level debug
wait_grpc $LOGFILE

if read_log test2.log | grep -q "starting RustyBGPd"; then
    pass "--log-level debug shows info messages"
else
    fail "--log-level debug should show info messages"
fi

# At debug level, accept_connection or session handler should produce DEBUG lines
if read_log test2.log | grep -qi "DEBUG"; then
    pass "--log-level debug shows DEBUG-level output"
else
    fail "--log-level debug should show DEBUG-level output"
fi
stop_bgpd

# ===================================================================
# TEST 3: RUST_LOG env var overrides --log-level CLI flag
# ===================================================================
echo ""
echo "--- Test 3: RUST_LOG overrides --log-level ---"

start_bgpd_env "RUST_LOG=info" test3.log -f /etc/rustybgp.yaml --log-level error
wait_grpc $LOGFILE

if read_log test3.log | grep -q "starting RustyBGPd"; then
    pass "RUST_LOG=info overrides --log-level error"
else
    fail "RUST_LOG=info should override --log-level error"
fi
stop_bgpd

# ===================================================================
# TEST 4: Runtime log level change via gRPC SetLogLevel
# ===================================================================
echo ""
echo "--- Test 4: Runtime log level change via gRPC ---"

start_bgpd test4.log -f /etc/rustybgp.yaml --log-level error
wait_grpc $LOGFILE

# Confirm no info-level output yet
if read_log test4.log | grep -q "starting RustyBGPd"; then
    fail "should have no info output at error level (before change)"
else
    pass "no info output at error level (before gRPC change)"
fi

# Change to info level via gRPC (INFO = 5 in the proto enum)
grpc_set_log_level 5

# The SetLogLevel handler logs "log level changed via gRPC" at info level.
# Give it a moment to flush.
sleep 2

if read_log test4.log | grep -q "log level changed"; then
    pass "runtime gRPC SetLogLevel changes log level"
else
    fail "expected 'log level changed' message after gRPC SetLogLevel"
    echo "    Debug: last 10 lines of test4.log:"
    read_log test4.log | tail -10 || true
fi
stop_bgpd

# ===================================================================
# TEST 5: Peer session logs include addr= span context
# ===================================================================
echo ""
echo "--- Test 5: Peer session logs include addr= span context ---"

start_bgpd test5.log -f /etc/rustybgp.yaml --log-level debug
wait_grpc $LOGFILE
wait_session

# The peer span attaches addr=<ip> to all handler logs.
# Look for the span format: peer{addr=172.30.10.2}
if read_log test5.log | grep -Fq "peer{addr=172.30.10.2}"; then
    pass "peer session logs include addr= span context"
else
    # Tracing may format the span differently; try a looser match
    if read_log test5.log | grep -Fq "addr=172.30.10.2"; then
        pass "peer session logs include addr= context (alternate format)"
    else
        fail "peer session logs should include addr=172.30.10.2 context"
        echo "    Debug: grep for '172.30.10.2' in test5.log:"
        read_log test5.log | grep "172.30.10.2" | head -5 || true
    fi
fi

# Also verify that a session-level message (e.g. "BGP session established") appears
# within the peer span context.
if read_log test5.log | grep "BGP session established" | grep -q "172.30.10.2"; then
    pass "BGP session established message carries peer addr context"
else
    fail "BGP session established message should carry peer addr context"
    echo "    Debug: lines containing 'established':"
    read_log test5.log | grep "established" | head -5 || true
fi
stop_bgpd

# ===================================================================
# Results
# ===================================================================
echo ""
echo "===================="
echo "Results: $PASS passed, $FAIL failed"
echo "===================="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
