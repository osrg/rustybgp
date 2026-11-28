# Quick start

This walkthrough brings up an eBGP session between RustyBGP (AS 65001,
`198.51.100.1`) and a neighbor (AS 65002, `198.51.100.2`), then originates a
route and checks that it is advertised.

## 1. Write a configuration

RustyBGP reads GoBGP-format configuration in TOML or YAML. Files ending in
`.yaml` or `.yml` are parsed as YAML; any other extension is parsed as TOML.

=== "TOML"

    ```toml title="/etc/rustybgp/rustybgpd.toml"
    [global.config]
      as = 65001
      router-id = "198.51.100.1"

    [[neighbors]]
      [neighbors.config]
        neighbor-address = "198.51.100.2"
        peer-as = 65002
      [[neighbors.afi-safis]]
        [neighbors.afi-safis.config]
          afi-safi-name = "ipv4-unicast"
    ```

=== "YAML"

    ```yaml title="/etc/rustybgp/rustybgpd.yaml"
    global:
      config:
        as: 65001
        router-id: "198.51.100.1"

    neighbors:
      - config:
          neighbor-address: "198.51.100.2"
          peer-as: 65002
        afi-safis:
          - config:
              afi-safi-name: ipv4-unicast
    ```

If you omit `afi-safis`, the session negotiates the unicast family that
matches the neighbor's address family.

## 2. Start the daemon

```console
$ sudo rustybgpd -f /etc/rustybgp/rustybgpd.toml
[2026-11-26T09:00:00Z INFO  rustybgpd] Hello, RustyBGPd (8 cpus)!
```

`rustybgpd` runs in the foreground and logs to standard error. It listens for
BGP on TCP port 179 and for the gRPC API on `0.0.0.0:50051`. For production,
bind the API to loopback with `--api-hosts 127.0.0.1:50051`; see
[Command line](../administration/command-line.md).

## 3. Check the session

In another terminal:

```console
$ gobgp global
AS:        65001
Router-ID: 198.51.100.1

$ gobgp neighbor
Peer            AS  Up/Down State       |#Received  Accepted
198.51.100.2 65002 00:00:31 Establ      |        3         3
```

If the state stays `Active` or `Idle`, see
[Troubleshooting](../administration/troubleshooting.md).

## 4. Exchange routes

Originate a prefix and check what the neighbor receives:

```bash
gobgp global rib add 203.0.113.0/24
gobgp neighbor 198.51.100.2 adj-out
```

Routes learned from the neighbor:

```bash
gobgp neighbor 198.51.100.2 adj-in
gobgp global rib
```

Withdraw the prefix:

```bash
gobgp global rib del 203.0.113.0/24
```

## 5. Install routes into the kernel (optional)

To program learned best paths into the Linux routing table, enable kernel
integration and restart:

```toml
[zebra.config]
  enabled = true
```

```console
$ ip route show proto bgp
192.0.2.0/24 via 198.51.100.2 dev eth0 metric 0
```

See [Kernel FIB](../user-guide/kernel-fib.md) for ECMP, VRFs and
redistribution.

## Running without a configuration file

For quick experiments, start with only an AS number and router ID, then add
neighbors through the API:

```bash
sudo rustybgpd --as-number 65001 --router-id 198.51.100.1
gobgp neighbor add 198.51.100.2 as 65002
```

Without `-f`, there is no configuration to reload, so SIGHUP terminates the
process.
