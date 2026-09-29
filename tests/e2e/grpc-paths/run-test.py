#!/usr/bin/env python3
"""Exercise the real GoBGP CLI against a local RustyBGP gRPC server."""

import argparse
import json
import pathlib
import socket
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rustybgpd", default="target/debug/rustybgpd")
    parser.add_argument("--gobgp", default="gobgp")
    args = parser.parse_args()
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]

    def cli(*command):
        result = subprocess.run(
            [args.gobgp, "-u", "127.0.0.1", "-p", str(port), *command],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode:
            raise RuntimeError(f"{' '.join(command)}: {result.stderr or result.stdout}")
        return result.stdout

    def rib(family, *scope):
        return json.loads(cli("-j", *scope, "rib", "-a", family))

    def check(condition, description):
        if not condition:
            raise AssertionError(description)
        print(f"PASS: {description}", flush=True)

    with tempfile.TemporaryDirectory(prefix="rustybgp-grpc-paths-") as directory:
        config = pathlib.Path(directory) / "rustybgp.toml"
        config.write_text(
            '[global.config]\nas = 65001\nrouter-id = "192.0.2.1"\nport = -1\n'
        )
        with (pathlib.Path(directory) / "daemon.log").open("w+") as log:
            daemon = subprocess.Popen(
                [args.rustybgpd, "-f", str(config), "--api-hosts", f"127.0.0.1:{port}"],
                stdout=log,
                stderr=subprocess.STDOUT,
            )
            try:
                for _ in range(100):
                    if daemon.poll() is not None:
                        raise RuntimeError("rustybgpd exited during startup")
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                            pass
                        break
                    except OSError:
                        time.sleep(0.1)
                else:
                    raise RuntimeError("gRPC server did not become ready")
                cli("global")

                for family, prefix in [
                    ("ipv4", "198.51.100.42/32"),
                    ("ipv6", "2001:db8::42/128"),
                ]:
                    cli("global", "rib", "add", prefix, "-a", family)
                    check(
                        len(rib(family, "global")) == 1,
                        f"{family} announcement installed",
                    )
                    cli("global", "rib", "del", prefix, "-a", family)
                    cli("global", "rib", "del", prefix, "-a", family)
                    check(not rib(family, "global"), f"{family} rib del is idempotent")

                prefix = "198.51.100.42/32"
                for identifier in [1, 2]:
                    cli("global", "rib", "add", prefix, "identifier", str(identifier))
                cli("global", "rib", "del", prefix, "identifier", "1")
                destinations = rib("ipv4", "global")
                check(
                    len(destinations) == 1
                    and len(next(iter(destinations.values()))) == 1,
                    "rib del preserves the other path identifier",
                )
                cli("global", "rib", "add", "198.51.100.43/32")
                cli("global", "rib", "add", "2001:db8::42/128", "-a", "ipv6")
                cli("global", "rib", "del", "all", "-a", "ipv4")
                check(
                    not rib("ipv4", "global") and len(rib("ipv6", "global")) == 1,
                    "rib del all respects the address family",
                )
                cli("global", "rib", "del", "all", "-a", "ipv6")

                for family in ["ipv4-flowspec", "ipv6-flowspec"]:
                    destination = (
                        "198.51.100.42/32"
                        if family == "ipv4-flowspec"
                        else "2001:db8::42/128"
                    )
                    rule = [
                        "match",
                        "destination",
                        destination,
                        "protocol",
                        "udp",
                        "destination-port",
                        "==53",
                        "then",
                        "discard",
                    ]
                    cli("global", "rib", "add", "-a", family, *rule)
                    check(len(rib(family, "global")) == 1, f"{family} rule installed")
                    cli("global", "rib", "del", "-a", family, *rule)
                    check(
                        not rib(family, "global"),
                        f"{family} rib del withdraws the rule",
                    )

                for name, rd in [("blue", "65001:1"), ("red", "65001:2")]:
                    cli("vrf", "add", name, "rd", rd, "rt", "both", rd)
                    cli("vrf", name, "rib", "add", prefix)
                cli("vrf", "blue", "rib", "del", prefix)
                check(
                    not rib("ipv4", "vrf", "blue")
                    and len(rib("ipv4", "vrf", "red")) == 1,
                    "VRF rib del preserves the other VRF",
                )
                print("GoBGP CLI path deletion checks passed.", flush=True)
            except Exception:
                log.seek(0)
                print(log.read(), flush=True)
                raise
            finally:
                daemon.terminate()
                try:
                    daemon.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    daemon.kill()
                    daemon.wait()


if __name__ == "__main__":
    main()
