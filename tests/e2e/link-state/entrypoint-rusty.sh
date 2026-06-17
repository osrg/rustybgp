#!/bin/bash
set -e

sysctl -w net.ipv4.ip_forward=1

exec rustybgpd -f /etc/rustybgp.yaml
