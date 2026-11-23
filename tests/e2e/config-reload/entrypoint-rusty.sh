#!/bin/bash
set -e

# rustybgpd reads a writable copy, so that run-test.sh can replace it and
# send SIGHUP.
cp /etc/rustybgp/step1.toml /tmp/rustybgp.toml
rustybgpd -f /tmp/rustybgp.toml &
BGPD_PID=$!

MAX_ATTEMPTS=30
for i in $(seq 1 $MAX_ATTEMPTS); do
    if gobgp global 2>/dev/null; then
        echo "rustybgpd gRPC API is ready"
        break
    fi
    if [ "$i" -eq "$MAX_ATTEMPTS" ]; then
        echo "rustybgpd gRPC API not ready after $MAX_ATTEMPTS attempts"
        exit 1
    fi
    sleep 1
done

gobgp global rib add 10.0.1.0/24 nexthop 172.30.50.1
gobgp global rib add 10.0.2.0/24 nexthop 172.30.50.1

wait $BGPD_PID
