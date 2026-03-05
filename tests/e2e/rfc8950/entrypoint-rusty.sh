#!/bin/bash
set -e

# Enable IP forwarding (may already be set via docker-compose sysctls)
sysctl -w net.ipv4.ip_forward=1 2>/dev/null || true
sysctl -w net.ipv6.conf.all.forwarding=1 2>/dev/null || true

# Start rustybgpd in the background
rustybgpd -f /etc/rustybgp.yaml &
BGPD_PID=$!

# Wait for daemon to start listening
sleep 2

# Install static route for the remote client network via IPv6 next hop.
# This is the data-plane equivalent of what a FIB manager would do after
# receiving the IPv4 route with an IPv6 next hop from BGP (RFC 8950).
# The transit interface is discovered dynamically.
TRANSIT_IF=$(ip -6 route show fd00:1::/64 | awk '{print $3}')

MAX_ATTEMPTS=30
for i in $(seq 1 $MAX_ATTEMPTS); do
    # Try to install the route — the neighbor might not be reachable yet
    if ip route add 172.30.4.0/24 via inet6 fd00:1::3 dev "$TRANSIT_IF" 2>/dev/null; then
        echo "Installed route 172.30.4.0/24 via inet6 fd00:1::3 dev $TRANSIT_IF"
        break
    fi
    if [ "$i" -eq "$MAX_ATTEMPTS" ]; then
        echo "Failed to install route after $MAX_ATTEMPTS attempts"
        exit 1
    fi
    sleep 1
done

# Keep container running
wait $BGPD_PID
