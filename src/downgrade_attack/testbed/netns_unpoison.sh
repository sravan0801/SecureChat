#!/usr/bin/env bash
# Restore truthful /etc/hosts in every namespace.
#   sudo bash netns_unpoison.sh
set -eu
NET=10.13.0
for ns in alice1 bob1 trudy1; do
    cat > "/etc/netns/$ns/hosts" <<EOF
127.0.0.1 localhost
$NET.1 alice1
$NET.2 bob1
$NET.3 trudy1
EOF
done
echo "DNS restored"
