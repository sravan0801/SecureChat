#!/usr/bin/env bash
# Build the Alice / Bob / Trudy star topology with Linux network namespaces.
#   sudo bash netns_up.sh
#
# Result:  alice1=10.13.0.1  bob1=10.13.0.2  trudy1=10.13.0.3  on bridge br-sc,
# each namespace with its own /etc/hosts (see netns_poison.sh / netns_unpoison.sh).
set -eu

BR=br-sc
NET=10.13.0
NAMES=(alice1 bob1 trudy1)
declare -A OCTET=( [alice1]=1 [bob1]=2 [trudy1]=3 )

ip link add "$BR" type bridge 2>/dev/null || true
ip link set "$BR" up

for ns in "${NAMES[@]}"; do
    ip netns add "$ns" 2>/dev/null || true
    ip link add "v-$ns" type veth peer name "p-$ns"
    ip link set "p-$ns" master "$BR"
    ip link set "p-$ns" up
    ip link set "v-$ns" netns "$ns"
    ip netns exec "$ns" ip link set lo up
    ip netns exec "$ns" ip link set "v-$ns" name eth0
    ip netns exec "$ns" ip addr add "$NET.${OCTET[$ns]}/24" dev eth0
    ip netns exec "$ns" ip link set eth0 up

    mkdir -p "/etc/netns/$ns"
    cat > "/etc/netns/$ns/hosts" <<EOF
127.0.0.1 localhost
$NET.1 alice1
$NET.2 bob1
$NET.3 trudy1
EOF
done

echo "topology up:"
for ns in "${NAMES[@]}"; do
    printf '  %-7s ' "$ns"
    ip netns exec "$ns" ip -4 -o addr show eth0 | awk '{print $4}'
done
ip netns exec alice1 ping -c1 -W1 bob1 >/dev/null 2>&1 \
    && echo "  alice1 -> bob1 reachable" \
    || echo "  WARNING: alice1 cannot reach bob1"
