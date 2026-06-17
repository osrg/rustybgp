#!/bin/bash
set -e

sysctl -w net.ipv4.ip_forward=1 2>/dev/null || true

rustybgpd -f /etc/rustybgp.yaml &
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

wait $BGPD_PID
