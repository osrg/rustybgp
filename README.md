# RustyBGP: BGP implementation in Rust

The mission is to develop a high-performance, low-memory-footprint, and safe BGP implementation; an experiment to implement aged and rusty BGP protocol in a modern language.

RustyBGP supports the gRPC APIs same as GoBGP; your code to manage GoBGP via the APIs should work with RustyBGP. If you need CLI, GoBGP's CLI command allows you to manage RustyBGP.

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

## Supported Features

Currently, the very basic BGP features are supported; eBGP and iBGP, acstive/passive connection, etc with the following gRPC APIs.

|API           |Relevant CLI                                           | Note        |
|--------------|-------------------------------------------------------|-------------|
|start_bgp|`gobgp global as <VALUE> router-id <IP>`||
|get_bgp|`gobgp global`||
|add_peer|`gobgp neighbor add <IP> as <VALUE> router-id <IP>`| only v4/v6 families supported, no fancy capabilities like addpath|
|delete_peer|`gobgp neighbor del <IP>`||
|list_peer|`gobgp neighbor`/`gobgp neighbor <IP>`||
|enable_peer|`gobgp neighbor <IP> enable`||
|disable_peer|`gobgp neighbor <IP> disable`||
|add_path|`gobgp global rib add <PREFIX>`||
|delete_path|`gobgp global rib del <PREFIX>`||
|list_path|`gobgp global rib`/`gobgp neighbor <IP> [adj-in\|adj-out]`||
|add_path_stream|`gobgp mrt global inject [FILE]`||
|get_table|`gobgp global rib summary`||
|add_rpki|`gobgp rpki server <IP> add`||
|list_rpki|`gobgp rpki server`||
|list_rpki_table|`gobgp rpki table`||

## Community, discussion and support

You have code or documentation for RustyBGP? Awesome! Send a pull request. No CLA, board members, governance, or other mess. See [`BUILD.md`](BUILD.md) for info on code contributing.
