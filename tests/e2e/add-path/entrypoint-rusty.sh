#!/bin/bash
set -e

# Start rustybgpd in the background
rustybgpd -f /etc/rustybgp.yaml &
BGPD_PID=$!

# Wait for gRPC API to become available
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

# Keep container running
wait $BGPD_PID
