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

# Announce 10.1.0.0/24 (competes with peer-b) and 10.2.0.0/24 (unique)
gobgp global rib add 10.1.0.0/24 nexthop 172.30.20.2
gobgp global rib add 10.2.0.0/24 nexthop 172.30.20.2

wait $BGPD_PID
