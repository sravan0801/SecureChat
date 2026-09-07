#!/usr/bin/env bash
# Emulate Trudy's DNS poisoning (same effect as the TAs' poison-dns script):
#   alice1 resolves bob1  -> Trudy
#   bob1   resolves alice1 -> Trudy
#   trudy1 keeps the truthful map
#   sudo bash netns_poison.sh
set -eu
NET=10.13.0

cat > /etc/netns/alice1/hosts <<EOF
127.0.0.1 localhost
$NET.1 alice1
$NET.3 bob1
$NET.3 trudy1
EOF

cat > /etc/netns/bob1/hosts <<EOF
127.0.0.1 localhost
$NET.3 alice1
$NET.2 bob1
$NET.3 trudy1
EOF

echo "DNS poisoned:  alice1:bob1 -> Trudy   bob1:alice1 -> Trudy"
