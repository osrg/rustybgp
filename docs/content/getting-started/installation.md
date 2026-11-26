# Installation

## Release binaries

Statically linked binaries for x86_64 and aarch64 Linux are published on
GitHub. They have no runtime dependencies and run on any recent distribution.

=== "x86_64"

    ```bash
    curl -LO https://github.com/osrg/rustybgp/releases/download/nightly/rustybgp-nightly-linux-x86_64.tar.gz
    tar xf rustybgp-nightly-linux-x86_64.tar.gz
    sudo install -m 0755 rustybgpd /usr/local/bin/
    ```

=== "aarch64"

    ```bash
    curl -LO https://github.com/osrg/rustybgp/releases/download/nightly/rustybgp-nightly-linux-aarch64.tar.gz
    tar xf rustybgp-nightly-linux-aarch64.tar.gz
    sudo install -m 0755 rustybgpd /usr/local/bin/
    ```

| Channel | Built from | Archive name |
|---|---|---|
| Nightly | Every push to `master` | `rustybgp-nightly-linux-<arch>.tar.gz` under the `nightly` release |
| Stable | Tags matching `v*` | `rustybgp-<tag>-linux-<arch>.tar.gz` under the tag's release |

Each archive contains `rustybgpd`, `LICENSE` and `README.md`.

Verify the binary:

```bash
rustybgpd --version
```

## Building from source

### Prerequisites

- A stable Rust toolchain with 2024 edition support (Rust 1.85 or newer).
- The protobuf compiler and the well-known protobuf includes. On Debian or
  Ubuntu:

    ```bash
    sudo apt-get install protobuf-compiler libprotobuf-dev
    ```

- `git`. The build embeds the commit hash in the version string.

### Build

```bash
git clone https://github.com/osrg/rustybgp.git
cd rustybgp
cargo build --release
```

The binary is `target/release/rustybgpd`.

### Static (musl) build

To produce a portable binary like the release artifacts:

```bash
rustup target add x86_64-unknown-linux-musl
sudo apt-get install musl-tools
cargo build --release --target x86_64-unknown-linux-musl
```

For aarch64, use the `aarch64-unknown-linux-musl` target.

## Installing the GoBGP CLI

RustyBGP has no CLI of its own. Use the `gobgp` client from any
[GoBGP v4 release](https://github.com/osrg/gobgp/releases):

```bash
curl -LO https://github.com/osrg/gobgp/releases/download/v4.3.0/gobgp_4.3.0_linux_amd64.tar.gz
tar xf gobgp_4.3.0_linux_amd64.tar.gz gobgp
sudo install -m 0755 gobgp /usr/local/bin/
```

!!! tip

    Only the `gobgp` client is needed. Do not run `gobgpd` on the same host:
    it would compete with `rustybgpd` for TCP port 179 and the gRPC port
    50051.

## Next steps

Continue with the [quick start](quick-start.md), or see
[Deployment](../administration/deployment.md) for running RustyBGP as a
systemd service or in a container.
