# RustyBGP: BGP implementation in Rust

The mission is to develop a high-perofrmance, low-memory-footprint, and safe BGP implementaiton; an experiment to implement aged and rusty BGP protocol in a modern language.

RustyBGP supports the gRPC APIs same as GoBGP; GoBGP's CLI command enables you to manage RustyBGP. Currently, all RustyBGP can do is accepting peers, getting routes, doing the best path selection, and showing you these routes via the gRPC API. No active connection, advertisement, policy, etc.

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
$ sudo ./target/debug/daemon
Hello, RustyBGP!
grpc: listening on 127.0.0.1:50051
```

After starting the RustyBGP daemon, you need to configure the AS number and the router ID then the daemon starts accepting peers.

```bash
$ gobgp global as 65000 router-id 10.0.0.1
```

Then you set up peer configuration.

```bash
$ gobgp neighbor add 10.0.0.2 as 65001
$ gobgp neighbor
Peer        AS Up/Down State       |#Received  Accepted
10.0.0.2 65001   never Idle        |        0         0
```

If you just want to check out the performance, start the daemon with `--perf` option. The daemon starts immediately with AS number 65001, then accepts any peers.
