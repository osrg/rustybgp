#!/bin/bash
set -e

sysctl -w net.ipv6.conf.all.forwarding=1 2>/dev/null || true

# Step 1: wait until the FRR entrypoint has configured its BGP peer.  FRR
# touches /frr-signal/ready after running vtysh to add the explicit peer.
# Starting rustybgpd before FRR has a peer configured would cause BGP to
# reject our OPEN and put us into exponential backoff.
echo "Waiting for FRR to signal readiness..."
for i in $(seq 1 60); do
    if [ -f /frr-signal/ready ]; then
        echo "FRR ready signal received after ${i}s"
        break
    fi
    if [ "$i" -eq 60 ]; then
        echo "WARNING: FRR readiness timeout; proceeding anyway"
    fi
    sleep 1
done

# Step 2: Derive FRR's link-local from its IPv4 MAC (EUI-64, same technique
# FRR uses to learn rusty's link-local).  Using IPv4 ARP avoids picking up
# the Docker bridge gateway's link-local, which also appears in the NDP cache.
FRR_IPV4="172.30.20.2"
echo "Deriving FRR link-local from IPv4 ARP ($FRR_IPV4)..."
PEER_LL=""
for i in $(seq 1 30); do
    ping -c 1 -W 1 "$FRR_IPV4" >/dev/null 2>&1 || true
    PEER_MAC=$(ip neigh show "$FRR_IPV4" 2>/dev/null \
        | awk '{for(i=1;i<=NF;i++) if($i=="lladdr") {print $(i+1); exit}}')
    if [ -n "$PEER_MAC" ] && [ "$PEER_MAC" != "<incomplete>" ]; then
        IFS=':' read -r m1 m2 m3 m4 m5 m6 <<< "$PEER_MAC"
        m1_int=$((16#${m1}))
        m1_mod=$(printf "%02x" "$((m1_int ^ 2))")
        PEER_LL="fe80::${m1_mod}${m2}:${m3}ff:fe${m4}:${m5}${m6}"
        echo "Peer MAC $PEER_MAC -> derived link-local $PEER_LL"
        break
    fi
    sleep 1
done

if [ -z "$PEER_LL" ]; then
    echo "WARNING: could not derive FRR link-local; rustybgpd may fail to discover peer"
else
    # Step 3: flush all IPv6 neighbor entries on eth0, then re-ping only
    # FRR's link-local so that the NDP cache has exactly one link-local entry
    # when rustybgpd starts.  This prevents get_link_local_neighbor from
    # mistakenly selecting the Docker bridge gateway's link-local.
    ip -6 neigh flush dev eth0 2>/dev/null || true
    ping6 -c 3 -W 1 "${PEER_LL}%eth0" >/dev/null 2>&1 || true
    echo "NDP cache seeded with $PEER_LL"
fi

# Start rustybgpd in background; the config already contains the
# unnumbered peer (neighbor-interface: eth0).
rustybgpd -f /etc/rustybgp.yaml &
BGPD_PID=$!

# Wait for gRPC API to be ready.
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

# Advertise a local prefix into BGP.
gobgp global rib add 10.0.0.1/32 -a ipv4
echo "Injected 10.0.0.1/32 into BGP RIB"

wait $BGPD_PID
