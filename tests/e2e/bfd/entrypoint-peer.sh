#!/bin/bash
# Peer container entrypoint.
#
# Starts GoBGP (BGP, port 179) and bfd-stub (BFD, port 3784) as separate
# processes at the same IP so RustyBGP sees one peer that speaks both
# protocols.
#
# The test script can selectively stop BFD without touching BGP:
#   docker exec bfd-peer pkill bfd-stub        # sudden loss (no AdminDown)
#   docker exec bfd-peer pkill -USR1 bfd-stub  # graceful AdminDown

set -e

gobgpd -f /etc/gobgpd.conf &

bfd-stub \
    --remote 172.30.9.1 \
    --tx-interval 300000 \
    --rx-interval 300000 \
    --detect-mult 3 &

# Save PID so the test can kill only the stub.
echo $! > /tmp/bfd-stub.pid

wait
