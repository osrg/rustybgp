#!/bin/bash
set -e

# Start zebra and bgpd
/usr/lib/frr/zebra -d -f /etc/frr/frr.conf -u frr -g frr
/usr/lib/frr/bgpd -d -f /etc/frr/frr.conf -u frr -g frr

# Keep container running
tail -f /dev/null
