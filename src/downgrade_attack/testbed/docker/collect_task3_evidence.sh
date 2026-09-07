#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Runs the Task 3 scenarios inside the docker test-bed (alice1 / bob1 /
# trudy1) and collects console logs + pcap traces into  <repo>/data/task3/.
#
#   cd src/downgrade_attack/testbed/docker
#   docker compose up -d --build          # once
#   ./collect_task3_evidence.sh
# ---------------------------------------------------------------------------
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../../.." && pwd)"
HOST_OUT="$REPO/data/task3"                 # on the laptop
BOX_OUT="/work/data/task3"                  # same dir seen from inside a container
APP=./secure_chat_app
INT=./secure_chat_interceptor

dex() { docker exec "$@"; }
quiet_kill() {
    for c in alice1 bob1 trudy1; do
        dex "$c" sh -c 'pkill -9 -x secure_chat_app; pkill -9 -x secure_chat_interceptor; pkill -INT -x tcpdump; true' 2>/dev/null
    done
    sleep 1
}
unpoison() {   # drop the injected 10.13.0.4 lines (in-place: /etc/hosts is a bind mount)
    for c in alice1 bob1; do
        dex "$c" sh -c 'grep -v "^10\.13\.0\.4[[:space:]]" /etc/hosts > /tmp/h && cat /tmp/h > /etc/hosts'
    done
}
caps_start() { for c in alice1 bob1 trudy1; do
    dex -d "$c" sh -c "tcpdump -i eth0 -U -w $BOX_OUT/$1/${c}.pcap 'udp port 8080' 2>/dev/null"
  done; sleep 1; }
caps_stop() { sleep 1
    for c in alice1 bob1 trudy1; do dex "$c" pkill -INT -x tcpdump 2>/dev/null || true; done
    sleep 1
    for c in alice1 bob1 trudy1; do
        dex "$c" sh -c "tcpdump -n -r $BOX_OUT/$1/${c}.pcap -A 2>/dev/null" > "$HOST_OUT/$1/${c}.pcap.txt"
    done; }

echo "== prepare =="
quiet_kill
dex bob1 sh -c "rm -rf $BOX_OUT && mkdir -p $BOX_OUT/1_normal $BOX_OUT/2_downgrade $BOX_OUT/3_packet_loss $BOX_OUT/3b_light_loss"
docker compose exec -T bob1 make >/dev/null
unpoison

# ── 1. normal run ────────────────────────────────────────────────────────
echo "== [1] normal DTLS run =="
caps_start 1_normal
dex -d bob1 sh -c "sleep 12 | $APP -s > $BOX_OUT/1_normal/bob.log 2>&1"
sleep 1
printf 'hello Bob, this line is inside DTLS\nsecret code 4242\nexit\n' \
  | dex -i alice1 $APP -c bob1 > "$HOST_OUT/1_normal/alice.log" 2>&1 || true
sleep 2
caps_stop 1_normal
quiet_kill

# ── 2. downgrade attack ─────────────────────────────────────────────────
echo "== [2] downgrade attack =="
dex alice1 sh -c 'echo "10.13.0.4  bob1"   >> /etc/hosts'
dex bob1   sh -c 'echo "10.13.0.4  alice1" >> /etc/hosts'
{ dex alice1 getent hosts bob1; dex trudy1 getent hosts bob1; } > "$HOST_OUT/2_downgrade/etc_hosts_view_alice1.txt"
caps_start 2_downgrade
dex -d bob1   sh -c "sleep 15 | $APP -s > $BOX_OUT/2_downgrade/bob.log 2>&1"
dex -d trudy1 sh -c "$INT -d alice1 bob1 > $BOX_OUT/2_downgrade/trudy.log 2>&1"
sleep 1
printf 'is this line encrypted?\nno - Trudy reads it in the clear\nexit\n' \
  | dex -i alice1 $APP -c bob1 > "$HOST_OUT/2_downgrade/alice.log" 2>&1 || true
sleep 2
caps_stop 2_downgrade
quiet_kill
unpoison

# ── 3. heavy control-message loss (retransmission) ──────────────────────
echo "== [3] 40% loss — control-message retries =="
dex alice1 tc qdisc add dev eth0 root netem loss 40%
caps_start 3_packet_loss
dex -d bob1 sh -c "sleep 25 | $APP -s > $BOX_OUT/3_packet_loss/bob.log 2>&1"
sleep 1
printf 'delivered despite 40 percent loss\nexit\n' \
  | dex -i alice1 $APP -c bob1 > "$HOST_OUT/3_packet_loss/alice.log" 2>&1 || true
sleep 2
caps_stop 3_packet_loss
dex alice1 tc qdisc del dev eth0 root netem
quiet_kill

# ── 3b. light loss (end-to-end still works) ─────────────────────────────
echo "== [3b] 10% loss — full flow still completes =="
dex alice1 tc qdisc add dev eth0 root netem loss 10%
dex bob1   tc qdisc add dev eth0 root netem loss 10%
caps_start 3b_light_loss
dex -d bob1 sh -c "sleep 20 | $APP -s > $BOX_OUT/3b_light_loss/bob.log 2>&1"
sleep 1
printf 'this line survives 10 percent loss end to end\nexit\n' \
  | dex -i alice1 $APP -c bob1 > "$HOST_OUT/3b_light_loss/alice.log" 2>&1 || true
sleep 2
caps_stop 3b_light_loss
dex alice1 tc qdisc del dev eth0 root netem
dex bob1   tc qdisc del dev eth0 root netem
quiet_kill

echo
echo "== evidence written under: $HOST_OUT =="
find "$HOST_OUT" -type f -printf '%P\n' | sort
