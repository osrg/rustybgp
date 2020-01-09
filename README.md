# RustyBGP: BGP implementation in Rust

The mission is to develop a high-performance, low-memory-footprint, and safe BGP implementation; an experiment to implement aged and rusty BGP protocol in a modern language.

RustyBGP supports the gRPC APIs same as GoBGP; GoBGP's CLI command allows you to manage RustyBGP. Currently, all RustyBGP can do is accept peers, get routes, select the best paths, advertise the best paths, and show you routes via the gRPC API. No active connection, policy, etc.

## Get Started

You can easily build RusyBGP on any system that has Docker running. You don't need Rust development environment. You can build the x86_64 statically-linked binary as follows:

```bash
$ git clone https://github.com/osrg/rustybgp.git
$ cd rustybgp
$ docker run --rm -it -v "$(pwd)":/home/rust/src ekidd/rust-musl-builder cargo build --release
$ ls -hl target/x86_64-unknown-linux-musl/release/daemon
-rwxr-xr-x 2 fujita fujita 8.1M Dec  6 12:26 target/x86_64-unknown-linux-musl/release/daemon
```

No configuration file support.

```bash
$ sudo ./target/debug/daemon --as-number 65001 --router-id 1.1.1.1
Hello, RustyBGP!
grpc: listening on 127.0.0.1:50051
```

Then you set up peer configuration.

```bash
$ gobgp neighbor add 10.0.0.2 as 65001
$ gobgp neighbor
Peer        AS Up/Down State       |#Received  Accepted
10.0.0.2 65001   never Idle        |        0         0
```

If you just want to check out the performance, start the daemon with `--any-peers` option. The daemon starts immediately with AS number 65001, then accepts any peers.
