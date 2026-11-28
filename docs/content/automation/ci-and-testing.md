# CI and testing

RustyBGP is tested at three levels: unit tests inside each crate, kernel
integration tests that run in a private network namespace, and end-to-end
scenarios that run `rustybgpd` against real BGP implementations in Docker.
GitHub Actions runs all three on every pull request and publishes release
binaries automatically.

## GitHub Actions workflows

| Workflow | Trigger | What it does |
|---|---|---|
| `build.yml` (CI) | Pull request | Runs `cargo clippy --tests -- -D warnings`, `cargo test --all` and `cargo fmt -- --check`, then the kernel integration tests inside `unshare -n`. |
| `e2e.yml` | Pull request | Builds a static `x86_64-unknown-linux-musl` binary once, then runs 14 end-to-end scenarios in parallel jobs against that binary. |
| `release-nightly.yml` | Push to `master` | Builds static binaries for x86_64 and aarch64, packages them, moves the `nightly` tag and publishes a GitHub prerelease. |
| `release-stable.yml` | Tag `v*` | Builds the same binaries and attaches `rustybgp-<tag>-linux-<arch>.tar.gz` to the tag's release. |
| `docs.yml` | Pull request or push touching `docs/` | Builds this site with `zensical build --strict`. Pushes to `master` also publish it to GitHub Pages. |

Dependabot checks Cargo dependencies daily.

### Release artifacts

Each release archive contains the `rustybgpd` binary, `LICENSE` and
`README.md`. Binaries are statically linked against musl and run on any
recent Linux distribution.

| Channel | URL pattern |
|---|---|
| Nightly | `https://github.com/osrg/rustybgp/releases/download/nightly/rustybgp-nightly-linux-<arch>.tar.gz` |
| Stable | `https://github.com/osrg/rustybgp/releases/download/<tag>/rustybgp-<tag>-linux-<arch>.tar.gz` |

`<arch>` is `x86_64` or `aarch64`.

## Unit tests

```bash
cargo test --all
```

The `packet` crate has an extensive suite of encode and decode tests. Some
fixtures under `packet/tests/gen/` are generated with small Go programs that
use GoBGP's own encoder, so RustyBGP's wire format is checked against an
independent implementation.

## Kernel integration tests

The `rustybgp-kernel` crate has tests that program real routes through
netlink. They are marked `#[ignore]` and must run in a throwaway network
namespace so they cannot touch the host's routing table:

```bash
sudo unshare -n cargo test -p rustybgp-kernel -- --ignored --test-threads=1
```

## End-to-end tests

Each directory under `tests/e2e/` is a self-contained scenario: a Docker
Compose topology, a RustyBGP configuration, and a `run-test.sh` script that
waits for convergence, runs assertions, and tears everything down on exit.

### Scenarios

| Scenario | Feature | Peers | In CI |
|---|---|---|---|
| `add-path` | Add-Path (RFC 7911) | FRR | Yes |
| `bfd` | BFD-triggered session teardown (RFC 5880/5881/5882) | GoBGP + BFD stub | No |
| `bmp-pre`, `bmp-post`, `bmp-local`, `bmp-all` | BMP monitoring policies (RFC 7854, RFC 9069) | GoBGP + BMP receiver | No |
| `confederation` | Confederations (RFC 5065) | GoBGP | Yes |
| `config-reload` | SIGHUP configuration reload | GoBGP | Yes |
| `evpn` | EVPN route types 1-5 (RFC 7432, RFC 9136) | GoBGP | No |
| `extended-nexthop` | IPv4 NLRI with IPv6 next hop (RFC 8950) | GoBGP | Yes |
| `flowspec` | FlowSpec IPv4 and IPv6 (RFC 8955, RFC 8956) | GoBGP | Yes |
| `graceful-restart-helper` | Graceful Restart, helper side (RFC 4724) | GoBGP | Yes |
| `graceful-restart-restarting` | Graceful Restart, restarting side (RFC 4724) | GoBGP | Yes |
| `grpc-paths` | gRPC path operations through the `gobgp` CLI | none (no Docker) | No |
| `link-state` | BGP-LS (RFC 9552) | GoBGP | Yes |
| `long-lived-graceful-restart` | LLGR (RFC 9494) | GoBGP | Yes |
| `route-reflector` | Route reflection (RFC 4456) | GoBGP | Yes |
| `route-server` | Route server (RFC 7947) | GoBGP | Yes |
| `rpki` | Origin validation (RFC 6811, RFC 8210) | GoBGP + RTR cache | Yes |
| `rtc` | Route Target Constraint (RFC 4684) | GoBGP | Yes |
| `sr-policy` | SR Policy (RFC 9830) | GoBGP + Go gRPC tools | Yes |
| `two-byte-as` | 2-octet AS speaker interop (RFC 6793) | BIRD | No |
| `unnumbered-bgp` | Unnumbered BGP over IPv6 link-local (RFC 8950) | FRR | No |

### Running scenarios locally

You need Docker with Compose v2 and a Rust musl target:

```bash
rustup target add x86_64-unknown-linux-musl   # or aarch64-unknown-linux-musl
```

Run the default set, which builds `rustybgpd` once and prints a summary:

```bash
tests/e2e/run-all.sh
```

Run a subset, or reuse an existing build:

```bash
tests/e2e/run-all.sh evpn sr-policy
SKIP_BUILD=1 tests/e2e/run-all.sh
```

Run a single scenario:

```bash
cd tests/e2e/route-reflector
RUST_TARGET=x86_64-unknown-linux-musl ./run-test.sh
```

### Environment variables

| Variable | Default | Effect |
|---|---|---|
| `RUST_TARGET` | Detected from `uname -m` | Target triple used to build `rustybgpd`. |
| `SKIP_BUILD` | unset | With `run-all.sh`, reuse the binary from a previous build. |
| `RUSTYBGP_BUILD_CONTEXT` | repository root | Docker build context for the RustyBGP image. |
| `RUSTYBGP_DOCKERFILE` | `tests/e2e/shared/Dockerfile.rustybgp` | Dockerfile for the RustyBGP image. Point both variables at a directory holding a prebuilt binary and `Dockerfile.rustybgp-prebuilt` to skip compiling inside Docker. |

### gRPC path test without Docker

`tests/e2e/grpc-paths` starts `rustybgpd` with no BGP listener and exercises
path operations through the `gobgp` CLI:

```bash
cargo build -p rustybgpd
python3 tests/e2e/grpc-paths/run-test.py --gobgp /path/to/gobgp
```

### Writing a new scenario

Copy an existing directory and adapt it. A scenario contains:

- `docker-compose.yml` with fixed-subnet bridge networks. The RustyBGP service
  builds from `${RUSTYBGP_BUILD_CONTEXT}` with `${RUSTYBGP_DOCKERFILE}`.
- `rustybgp.yaml`, the configuration under test.
- `entrypoint-rusty.sh`, which starts `rustybgpd -f`, waits for `gobgp global`
  to succeed, and optionally injects routes.
- `run-test.sh`, which sources `../shared/helpers.sh`, brings the topology up,
  waits for convergence, asserts, and cleans up through a `trap`.

!!! warning "Pipelines under `pipefail`"

    The scripts run with `set -o pipefail`. Do not end a pipeline with a
    command that stops reading early, such as `grep -q` or `head`: the writer
    can receive SIGPIPE and fail the pipeline even when the pattern matched,
    which makes negative checks pass by mistake. Use `grep ... >/dev/null`.

Add the scenario to `run-all.sh` and as a job in `.github/workflows/e2e.yml`.
