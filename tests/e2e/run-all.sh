#!/bin/bash
# Run all RustyBGP e2e tests against a single prebuilt binary.
#
# Usage:
#   tests/e2e/run-all.sh [test-name ...]
#
# With no arguments every test under tests/e2e/ is run in order.
# With arguments only the named tests are run, e.g.:
#   tests/e2e/run-all.sh evpn sr-policy
#
# The script builds rustybgpd once with the musl target and reuses the
# binary for all tests (same approach as CI).  Docker layer caching makes
# subsequent runs fast.
#
# Environment variables:
#   RUST_TARGET   musl target triple (default: autodetected from uname -m)
#   SKIP_BUILD    set to 1 to skip cargo build and reuse a previous binary

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PREBUILT_DIR="$(mktemp -d /tmp/rustybgp-prebuilt-XXXXXX)"

# Detect musl target from host architecture
if [ -z "${RUST_TARGET:-}" ]; then
    ARCH="$(uname -m)"
    case "$ARCH" in
        x86_64)  RUST_TARGET=x86_64-unknown-linux-musl ;;
        aarch64) RUST_TARGET=aarch64-unknown-linux-musl ;;
        arm64)   RUST_TARGET=aarch64-unknown-linux-musl ;;
        *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
    esac
fi

cleanup() {
    rm -rf "$PREBUILT_DIR"
}
trap cleanup EXIT

# --- Build ---

if [ "${SKIP_BUILD:-0}" != "1" ]; then
    echo "=== Building rustybgpd (target: $RUST_TARGET) ==="
    cd "$REPO_ROOT"
    cargo build --release --target "$RUST_TARGET"
fi

BINARY="$REPO_ROOT/target/$RUST_TARGET/release/rustybgpd"
if [ ! -x "$BINARY" ]; then
    echo "Binary not found: $BINARY" >&2
    echo "Run without SKIP_BUILD=1 or build manually first." >&2
    exit 1
fi

cp "$BINARY" "$PREBUILT_DIR/rustybgpd"
cp "$SCRIPT_DIR/shared/Dockerfile.rustybgp-prebuilt" "$PREBUILT_DIR/Dockerfile"

export RUSTYBGP_BUILD_CONTEXT="$PREBUILT_DIR"
export RUSTYBGP_DOCKERFILE="Dockerfile"

# --- Test list ---

ALL_TESTS=(
    add-path
    confederation
    evpn
    extended-nexthop
    flowspec
    graceful-restart-helper
    graceful-restart-restarting
    link-state
    long-lived-graceful-restart
    route-reflector
    route-server
    rpki
    rtc
    sr-policy
    unnumbered-bgp
)

if [ "$#" -gt 0 ]; then
    TESTS=("$@")
else
    TESTS=("${ALL_TESTS[@]}")
fi

# --- Run ---

PASS=()
FAIL=()

for test in "${TESTS[@]}"; do
    dir="$SCRIPT_DIR/$test"
    if [ ! -f "$dir/run-test.sh" ]; then
        echo "WARNING: $test/run-test.sh not found, skipping" >&2
        continue
    fi

    echo ""
    echo "========================================"
    echo "  $test"
    echo "========================================"

    if (cd "$dir" && bash run-test.sh); then
        PASS+=("$test")
    else
        FAIL+=("$test")
    fi
done

# --- Summary ---

echo ""
echo "========================================"
echo "  Summary"
echo "========================================"
echo ""
for t in "${PASS[@]}"; do echo "  PASS  $t"; done
for t in "${FAIL[@]}"; do echo "  FAIL  $t"; done
echo ""
echo "  ${#PASS[@]} passed, ${#FAIL[@]} failed"
echo ""

if [ "${#FAIL[@]}" -gt 0 ]; then
    exit 1
fi
