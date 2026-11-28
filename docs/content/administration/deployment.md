# Deployment

## Filesystem layout

RustyBGP is a single static binary. A conventional layout:

| Path | Contents |
|---|---|
| `/usr/local/bin/rustybgpd` | Daemon |
| `/usr/local/bin/gobgp` | GoBGP v4 CLI |
| `/etc/rustybgp/rustybgpd.yaml` | Configuration |
| `/var/lib/rustybgp/` | MRT dumps, if enabled |

## Privileges

`rustybgpd` needs the following Linux capabilities, depending on the features
you use:

| Capability | Needed for |
|---|---|
| `CAP_NET_BIND_SERVICE` | Listening on TCP port 179. Not needed with `port = -1` or a port above 1023. |
| `CAP_NET_ADMIN` | Kernel FIB integration, creating VRF devices, TCP MD5 keys, and `IP_MINTTL`. |
| `CAP_NET_RAW` | Binding sockets to a device (`bind-interface`, `bind-to-device`) on kernels older than 5.7. |

Running as root grants all of these. A dedicated user with only the needed
capabilities is preferable.

## systemd

```ini title="/etc/systemd/system/rustybgpd.service"
[Unit]
Description=RustyBGP daemon
Documentation=https://osrg.github.io/rustybgp/
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=rustybgp
Group=rustybgp
ExecStart=/usr/local/bin/rustybgpd -f /etc/rustybgp/rustybgpd.yaml --api-hosts 127.0.0.1:50051
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
Environment=RUST_LOG=info

AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/rustybgp
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin rustybgp
sudo install -d -o rustybgp -g rustybgp /var/lib/rustybgp
sudo systemctl daemon-reload
sudo systemctl enable --now rustybgpd
```

`systemctl reload rustybgpd` sends SIGHUP and applies supported configuration
changes; see [Configuration reload](configuration-reload.md). Logs go to the
journal:

```bash
journalctl -u rustybgpd -f
```

!!! warning "Stopping the service"

    RustyBGP handles only SIGHUP. `systemctl stop` sends SIGTERM, which ends the
    process immediately without sending NOTIFICATIONs, so neighbors notice only
    when the TCP connection closes. Neighbors with Graceful Restart enabled
    keep the routes as stale. To shut down cleanly, stop BGP through the API
    first. See [Operations](operations.md#planned-shutdown).

## Containers

The project does not publish a container image. A minimal image built from
the release binary:

```dockerfile title="Dockerfile"
FROM alpine:3.21
RUN apk add --no-cache iproute2 ca-certificates
ARG ARCH=x86_64
ADD https://github.com/osrg/rustybgp/releases/download/nightly/rustybgp-nightly-linux-${ARCH}.tar.gz /tmp/
RUN tar -xzf /tmp/rustybgp-nightly-linux-${ARCH}.tar.gz -C /usr/local/bin rustybgpd \
 && rm /tmp/*.tar.gz
EXPOSE 179/tcp
ENTRYPOINT ["/usr/local/bin/rustybgpd"]
CMD ["-f", "/etc/rustybgp/rustybgpd.yaml", "--api-hosts", "127.0.0.1:50051"]
```

Run it in the host network namespace so that sessions use the host's
addresses and, if enabled, routes go into the host's FIB:

```bash
docker run -d --name rustybgp --network host \
  --cap-add NET_ADMIN --cap-add NET_BIND_SERVICE \
  -v /etc/rustybgp:/etc/rustybgp:ro \
  rustybgp:latest
```

The end-to-end tests contain Dockerfiles for building from source and from a
prebuilt binary under `tests/e2e/shared/`.

## Sizing

- **CPU.** The routing table is split into one shard per CPU, up to 255. More
  cores let more prefixes be processed in parallel during convergence. Pinning
  the process to fewer CPUs (for example with `taskset` or a cgroup) does not
  reduce the shard count, because it is based on the number of CPUs in the
  system.
- **Memory.** Each path stores both its post-policy and its original
  attributes, so that soft resets need no route refresh. Plan memory for
  roughly the number of paths times the attribute size, plus Adj-RIB-Out state
  per neighbor.
