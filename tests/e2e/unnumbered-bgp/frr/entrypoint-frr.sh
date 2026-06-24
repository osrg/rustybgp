#!/bin/bash
# FRR entrypoint for unnumbered-bgp e2e test.
#
# FRR's interface-based unnumbered BGP ("neighbor eth0 interface") relies on
# zebra to push the peer's link-local via RTM_NEWNEIGH kernel events.  In a
# Docker bridge this event race is unreliable, so this script dynamically
# reconfigures FRR to use the explicit link-local that it learns from ARP/NDP
# after startup.  The rustybgpd side uses interface-based unnumbered mode
# (neighbor-interface: eth0) and accepts any AS — that is what the test
# actually exercises.
set -e

# Start FRR using its normal docker-start script in the background.
/usr/lib/frr/docker-start &
FRR_PID=$!

# Wait for bgpd to be ready.
echo "Waiting for FRR bgpd..."
for i in $(seq 1 30); do
    if vtysh -c "show version" >/dev/null 2>&1; then
        echo "FRR bgpd ready after ${i}s"
        break
    fi
    sleep 1
done

# Find the rustybgpd peer's MAC via ARP using its known IPv4 address.
# Rusty has IPv4 172.30.20.1; FRR has 172.30.20.2.
echo "Resolving peer link-local (rusty IPv4 172.30.20.1)..."
PEER_LL=""
for i in $(seq 1 30); do
    # Trigger ARP for the peer's IPv4.
    ping -c 1 -W 1 172.30.20.1 >/dev/null 2>&1 || true
    PEER_MAC=$(ip neigh show 172.30.20.1 2>/dev/null \
        | grep "lladdr" | awk '{for(i=1;i<=NF;i++) if($i=="lladdr") {print $(i+1); exit}}')
    if [ -n "$PEER_MAC" ] && [ "$PEER_MAC" != "<incomplete>" ]; then
        echo "Peer MAC: $PEER_MAC (after ${i}s)"
        # Derive the link-local from the EUI-64 of the MAC.
        # Toggle bit 6 (0x02) of the first octet and insert ff:fe in the middle.
        IFS=':' read -r m1 m2 m3 m4 m5 m6 <<< "$PEER_MAC"
        m1_int=$((16#${m1}))
        m1_mod=$(printf "%02x" "$((m1_int ^ 2))")
        PEER_LL="fe80::${m1_mod}${m2}:${m3}ff:fe${m4}:${m5}${m6}"
        echo "Derived peer link-local: $PEER_LL"
        break
    fi
    sleep 1
done

if [ -z "$PEER_LL" ]; then
    echo "WARNING: could not resolve peer link-local, BGP may not establish"
    wait $FRR_PID
    exit 0
fi

# Ping the peer's link-local to populate our kernel NDP table so bgpd
# can reach it, and to ensure the peer's NDP table knows our link-local.
echo "Pinging peer link-local $PEER_LL..."
ping6 -c 3 -W 1 "${PEER_LL}%eth0" >/dev/null 2>&1 || true

# Dynamically reconfigure FRR's BGP to use the explicit link-local instead
# of the interface-based unnumbered mode, which is unreliable in Docker.
# The link-local address uses %eth0 as scope; in vtysh it is specified plain.
echo "Reconfiguring FRR BGP with explicit peer $PEER_LL (interface eth0)..."
vtysh << EOF
configure terminal
router bgp 65002
 no neighbor eth0 interface remote-as 65001
 neighbor ${PEER_LL} remote-as 65001
 neighbor ${PEER_LL} interface eth0
 neighbor ${PEER_LL} capability extended-nexthop
 !
 address-family ipv4 unicast
  neighbor ${PEER_LL} activate
 exit-address-family
end
EOF
echo "BGP reconfigured"

# Signal to the rusty container that FRR is ready so it can start rustybgpd.
touch /frr-signal/ready
echo "Signalled readiness to rusty container"

wait $FRR_PID
