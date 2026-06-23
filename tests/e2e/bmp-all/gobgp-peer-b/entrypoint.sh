#!/bin/sh
set -e

# peer-b only receives routes; no announcements
gobgpd -f /etc/gobgpd.conf
