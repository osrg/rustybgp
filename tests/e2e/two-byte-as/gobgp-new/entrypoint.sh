#!/bin/sh
set -e

gobgpd -f /etc/gobgpd.conf &
BGPD_PID=$!

for i in $(seq 1 30); do
    if gobgp global 2>/dev/null; then
        break
    fi
    sleep 1
done

# Originates with AS 4200000000 (> 65535): forces AS4_PATH downgrade on any
# hop that talks to an OLD BGP speaker further downstream (RFC 6793 SS4.2.2).
gobgp global rib add 10.0.1.0/24 nexthop 172.30.40.2

wait $BGPD_PID
