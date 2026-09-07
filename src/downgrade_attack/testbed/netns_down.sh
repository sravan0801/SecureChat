#!/usr/bin/env bash
# Tear down the network-namespace topology built by netns_up.sh
#   sudo bash netns_down.sh
set -u
for ns in alice1 bob1 trudy1; do
    ip netns del "$ns"      2>/dev/null || true
    ip link  del "p-$ns"    2>/dev/null || true
    rm -rf "/etc/netns/$ns"
done
ip link del br-sc 2>/dev/null || true
echo "topology removed"
