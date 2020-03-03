# RustyBGP: BGP implementation in Rust

The mission is to develop a high-performance, low-memory-footprint, and safe BGP implementation; an experiment to implement aged and rusty BGP protocol in a modern language.

RustyBGP supports the gRPC APIs same as GoBGP; GoBGP's CLI command allows you to manage RustyBGP. Currently, the very basic BGP features are supported; eBGP and iBGP, only v4 and v6 families, showing tables via the gRPC API, etc. No policy, route server support, fancy families, etc.

## Get Started

You can easily build RusyBGP on any system that has Docker running. You don't need Rust development environment. You can build the x86_64 statically-linked binary as follows:

```bash
$ git clone https://github.com/osrg/rustybgp.git
$ cd rustybgp
$ docker run --rm -it -v "$(pwd)":/home/rust/src ekidd/rust-musl-builder cargo build --release
$ ls -hl target/x86_64-unknown-linux-musl/release/daemon
-rwxr-xr-x 2 fujita fujita 8.1M Dec  6 12:26 target/x86_64-unknown-linux-musl/release/daemon
```

No configuration file support; only via the gRPC API. You can use GoBGP's CLI command.

```bash
$ sudo ./target/debug/daemon
Hello, RustyBGP!
```

Then you can manage the daemon on a different terminal.

```bash
$ gobgp global as 65001 router-id 1.1.1.1
$ gobgp neighbor add 10.0.0.2 as 65002
$ gobgp neighbor
Peer        AS Up/Down State       |#Received  Accepted
10.0.0.2 65002   never Idle        |        0         0
```

If you just want to check out the performance, start the daemon with `--any-peers` option. The daemon accepts any peers without configuration.

```bash
$ sudo ./target/debug/daemon --as-number 65001 --router-id 1.1.1.1 --any-peers
Hello, RustyBGP!
```

## Community, discussion and support

You have code or documentation for RustyBGP? Awesome! Send a pull request. No CLA, board members, governance, or other mess. See [`BUILD.md`](BUILD.md) for info on code contributing.
