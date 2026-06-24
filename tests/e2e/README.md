# RustyBGP End-to-End Tests

Each subdirectory is a self-contained test scenario. Every test starts its
own Docker Compose topology, runs assertions against live BGP sessions, and
tears everything down on exit.

## Prerequisites

- Docker with Compose v2 (`docker compose`)
- Rust toolchain with a musl target (for local builds)

On x86_64:

```
rustup target add x86_64-unknown-linux-musl
sudo apt-get install musl-tools   # Debian/Ubuntu
```

On aarch64 (Apple Silicon, ARM servers):

```
rustup target add aarch64-unknown-linux-musl
```

## Running all tests locally

```
tests/e2e/run-all.sh
```

The script builds `rustybgpd` once with the musl target, then runs every test
in sequence and prints a pass/fail summary.  Docker layer caching makes
repeated runs fast.

To run a subset of tests, pass their directory names as arguments:

```
tests/e2e/run-all.sh evpn sr-policy
```

To skip the build and reuse the binary from a previous run:

```
SKIP_BUILD=1 tests/e2e/run-all.sh
```

To override the target triple:

```
RUST_TARGET=x86_64-unknown-linux-musl tests/e2e/run-all.sh
```

## Running a single test locally

```
cd tests/e2e/<test-name>
./run-test.sh
```

The script builds a fresh `rustybgpd` image from the workspace root, starts
the containers, runs the assertions, and removes the containers on exit.

On x86_64 the image build defaults to `aarch64-unknown-linux-musl`; pass the
correct target explicitly:

```
RUST_TARGET=x86_64-unknown-linux-musl ./run-test.sh
```

To skip the build and use a prebuilt binary (faster for repeated runs):

```
# Build once
cargo build --release --target x86_64-unknown-linux-musl

# Point the test at the binary
mkdir -p /tmp/rusty-prebuilt
cp target/x86_64-unknown-linux-musl/release/rustybgpd /tmp/rusty-prebuilt/
cp tests/e2e/shared/Dockerfile.rustybgp-prebuilt /tmp/rusty-prebuilt/Dockerfile

RUSTYBGP_BUILD_CONTEXT=/tmp/rusty-prebuilt \
RUSTYBGP_DOCKERFILE=Dockerfile \
  tests/e2e/<test-name>/run-test.sh
```

## Test directory overview

| Directory | Feature | RFC(s) |
|---|---|---|
| `add-path` | ADD-PATH (multiple paths per prefix) | RFC 7911 |
| `bfd` | BFD session down triggers BGP teardown without NOTIFICATION | RFC 5880, RFC 5881, RFC 5882 |
| `bmp-pre` | BMP pre-policy monitoring | RFC 7854 |
| `bmp-post` | BMP pre+post-policy monitoring | RFC 7854 |
| `bmp-local` | BMP Loc-RIB monitoring | RFC 7854, RFC 9069 |
| `bmp-all` | BMP all policies (pre+post+Loc-RIB+Adj-Out) | RFC 7854, RFC 9069 |
| `confederation` | BGP Confederation | RFC 5065 |
| `evpn` | EVPN Types 1-5, AddPath | RFC 7432, RFC 9136 |
| `extended-nexthop` | Extended Nexthop Encoding | RFC 8950 |
| `flowspec` | BGP Flowspec (IPv4 and IPv6) | RFC 8955, RFC 8956 |
| `graceful-restart-helper` | Graceful Restart — helper side | RFC 4724 |
| `graceful-restart-restarting` | Graceful Restart — restarting speaker | RFC 4724 |
| `link-state` | BGP-LS (Node, Link, PrefixV4 NLRIs + BGP-LS attribute) | RFC 7752 |
| `route-reflector` | Route Reflector | RFC 4456 |
| `route-server` | BGP Route Server | RFC 7947 |
| `rpki` | RPKI Route Origin Validation | RFC 6811, RFC 8210 |
| `rtc` | Route Target Membership — RT-based VPN route filtering | RFC 4684 |
| `sr-policy` | SR Policy (IPv4, MPLS binding SID, segment list) | RFC 9830 |
| `unnumbered-bgp` | Unnumbered BGP over IPv6 link-local + Extended Nexthop | RFC 7938, RFC 8950 |

## Shared infrastructure

`shared/` contains Dockerfiles and helpers used by all tests:

- `Dockerfile.rustybgp` — builds `rustybgpd` from source (used by default locally)
- `Dockerfile.rustybgp-prebuilt` — copies a prebuilt binary (used by CI)
- `Dockerfile.gobgp` — GoBGP image used as a BGP peer in most tests
- `helpers.sh` — shell functions sourced by every `run-test.sh`
