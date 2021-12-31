# RustyBGP: BGP implementation in Rust

The mission is to develop a high-performance and safe BGP implementation; an experiment to implement aged and rusty BGP protocol in a modern language. RustyBGP is [much faster](https://elegantnetwork.github.io/posts/bgp-perf5-1000-internet-neighbors/) than other OSS implementations. One reason of the high peformance is that RustyBGP is designed to exploit multicore processors. Here is a CPU usage comparison with FRR 7.5 during processing 32 peers with 800K prefixes each; RustyBGP (left) uses all the cores while FRR uses only few.

![](.github/assets/htop.gif)

RustyBGP supports the gRPC APIs same as GoBGP; your code to manage GoBGP via the APIs should work with RustyBGP. If you need CLI, GoBGP's CLI command allows you to manage RustyBGP. RustyBGP also supports the same configuration file format as GoBGP (only toml for now).

## Get Started

You can easily build RusyBGP on any system that has Docker running. You don't need Rust development environment. You can build the x86_64 statically-linked binary as follows:

```bash
$ git clone https://github.com/osrg/rustybgp.git
$ cd rustybgp
$ docker run --rm -it -v "$(pwd)":/home/rust/src ekidd/rust-musl-builder cargo build --release
$ ls -lh target/x86_64-unknown-linux-musl/release/rustybgpd
-rwxr-xr-x 2 ubuntu ubuntu 12M May 10 14:52 target/x86_64-unknown-linux-musl/release/rustybgpd
```

```bash
$ sudo ./target/x86_64-unknown-linux-musl/release/rustybgpd -f gobgpd.conf
Hello, RustyBGP (32 cpus)!
```

Then you can manage the daemon on a different terminal with GoBGP's CLI command.

```bash
$ gobgp neighbor
Peer            AS Up/Down State       |#Received  Accepted
198.51.100.2 65002   never Idle        |        0         0
```

If you just want to check out the performance, start the daemon with `--any-peers` option. The daemon accepts any peers without configuration.

```bash
$ sudo ./target/x86_64-unknown-linux-musl/release/rustybgpd --as-number 65001 --router-id 203.0.113.1 --any-peers
Hello, RustyBGP (32 cpus)!
```

## Supported Features

Currently, the very basic BGP features are supported; eBGP and iBGP, acstive/passive connection, etc with the following gRPC APIs.

| API             | Relevant CLI                                               | Note                                                              |
| --------------- | ---------------------------------------------------------- | ----------------------------------------------------------------- |
| start_bgp       | `gobgp global as <VALUE> router-id <IP>`                   |                                                                   |
| get_bgp         | `gobgp global`                                             |                                                                   |
| add_peer        | `gobgp neighbor add <IP> as <VALUE> router-id <IP>`        | only v4/v6 families supported, no fancy capabilities like addpath |
| delete_peer     | `gobgp neighbor del <IP>`                                  |                                                                   |
| list_peer       | `gobgp neighbor`/`gobgp neighbor <IP>`                     |                                                                   |
| enable_peer     | `gobgp neighbor <IP> enable`                               |                                                                   |
| disable_peer    | `gobgp neighbor <IP> disable`                              |                                                                   |
| add_path        | `gobgp global rib add <PREFIX>`                            |                                                                   |
| delete_path     | `gobgp global rib del <PREFIX>`                            |                                                                   |
| list_path       | `gobgp global rib`/`gobgp neighbor <IP> [adj-in\|adj-out]` |                                                                   |
| add_path_stream | `gobgp mrt global inject [FILE]`                           |                                                                   |
| get_table       | `gobgp global rib summary`                                 |                                                                   |
| add_rpki        | `gobgp rpki server <IP> add`                               |                                                                   |
| list_rpki       | `gobgp rpki server`                                        |                                                                   |
| list_rpki_table | `gobgp rpki table`                                         |                                                                   |
| add_bmp         | `gobgp bmp add`                                            | routemonitoring is supported only with adjin                      |

## Community, discussion and support

You have code or documentation for RustyBGP? Awesome! Send a pull request. No CLA, board members, governance, or other mess. See [`BUILD.md`](BUILD.md) for info on code contributing.
