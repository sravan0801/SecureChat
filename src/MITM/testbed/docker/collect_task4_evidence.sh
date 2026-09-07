#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Runs the Task 4 scenarios in the docker test-bed and collects console logs
# + pcap traces into  <repo>/data/task4/.
#
#   cd src/MITM/testbed/docker
#   docker compose up -d --build
#   ./collect_task4_evidence.sh
# ---------------------------------------------------------------------------
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../../.." && pwd)"
HOST_OUT="$REPO/data/task4"
BOX_OUT="/work/data/task4"
APP=./secure_chat_app
INT=./secure_chat_active_interceptor

dex(){ docker exec "$@"; }
quiet_kill(){ for c in alice1 bob1 trudy1; do
    dex "$c" sh -c 'pkill -9 -x secure_chat_app; pkill -9 -x secure_chat_active_interceptor; pkill -INT -x tcpdump; true' 2>/dev/null
  done; sleep 1; }
unpoison(){ for c in alice1 bob1; do
    dex "$c" sh -c 'grep -v "^10\.14\.0\.4[[:space:]]" /etc/hosts > /tmp/h && cat /tmp/h > /etc/hosts'
  done; }
caps_start(){ for c in alice1 bob1 trudy1; do
    dex -d "$c" sh -c "tcpdump -i eth0 -U -w $BOX_OUT/$1/${c}.pcap 'udp port 8080' 2>/dev/null"
  done; sleep 1; }
caps_stop(){ sleep 1
    for c in alice1 bob1 trudy1; do dex "$c" pkill -INT -x tcpdump 2>/dev/null || true; done; sleep 1
    for c in alice1 bob1 trudy1; do
        dex "$c" sh -c "tcpdump -n -r $BOX_OUT/$1/${c}.pcap -A 2>/dev/null" > "$HOST_OUT/$1/${c}.pcap.txt"
    done; }

echo "== prepare =="
quiet_kill
for c in alice1 bob1 trudy1; do
    dex "$c" sh -c "rm -rf $BOX_OUT && mkdir -p $BOX_OUT/1_normal $BOX_OUT/2_mitm_transparent $BOX_OUT/3_mitm_tamper $BOX_OUT/4_dtls_loss"
done
docker compose exec -T bob1 sh -c 'make >/dev/null && (ls fake_certs/fakebob.crt >/dev/null 2>&1 || bash fake_certs/gen_fake_certs.sh)' > "$HOST_OUT/build.txt" 2>&1
unpoison

# ── 1. baseline, no attacker ────────────────────────────────────────────
echo "== [1] normal DTLS 1.2 run (no MITM) =="
caps_start 1_normal
dex -d bob1 sh -c "sleep 12 | $APP -s > $BOX_OUT/1_normal/bob.log 2>&1"
sleep 1
printf 'hello Bob, this is end-to-end encrypted\nsecret 4242\nexit\n' \
  | dex -i alice1 $APP -c bob1 > "$HOST_OUT/1_normal/alice.log" 2>&1 || true
sleep 2
caps_stop 1_normal
quiet_kill

# ── 2. transparent MITM ────────────────────────────────────────────────
echo "== [2] active MITM, transparent proxy =="
dex alice1 sh -c 'echo "10.14.0.4  bob1"   >> /etc/hosts'
dex bob1   sh -c 'echo "10.14.0.4  alice1" >> /etc/hosts'
{ dex alice1 getent hosts bob1; dex bob1 getent hosts alice1; dex trudy1 getent hosts bob1; } \
  > "$HOST_OUT/2_mitm_transparent/etc_hosts_views.txt"
caps_start 2_mitm_transparent
dex -d bob1   sh -c "sleep 15 | $APP -s > $BOX_OUT/2_mitm_transparent/bob.log 2>&1"
dex -d trudy1 sh -c "$INT -m alice1 bob1 > $BOX_OUT/2_mitm_transparent/trudy.log 2>&1"
sleep 1
printf 'hello Bob, are we really secure?\nmy PIN is 4242\nexit\n' \
  | dex -i alice1 $APP -c bob1 > "$HOST_OUT/2_mitm_transparent/alice.log" 2>&1 || true
sleep 2
caps_stop 2_mitm_transparent
quiet_kill

# ── 3. tampering MITM ──────────────────────────────────────────────────
echo "== [3] active MITM, tampering Alice->Bob (-t) =="
caps_start 3_mitm_tamper
dex -d bob1   sh -c "sleep 15 | $APP -s > $BOX_OUT/3_mitm_tamper/bob.log 2>&1"
dex -d trudy1 sh -c "$INT -m alice1 bob1 -t > $BOX_OUT/3_mitm_tamper/trudy.log 2>&1"
sleep 1
printf 'transfer 100 rupees to Bob\nexit\n' \
  | dex -i alice1 $APP -c bob1 > "$HOST_OUT/3_mitm_tamper/alice.log" 2>&1 || true
sleep 2
caps_stop 3_mitm_tamper
quiet_kill
unpoison

# ── 4. DTLS handshake under packet loss ────────────────────────────────
echo "== [4] DTLS handshake with 20% loss (built-in retransmission) =="
dex alice1 tc qdisc add dev eth0 root netem loss 20%
dex bob1   tc qdisc add dev eth0 root netem loss 20%
caps_start 4_dtls_loss
dex -d bob1 sh -c "sleep 30 | $APP -s > $BOX_OUT/4_dtls_loss/bob.log 2>&1"
sleep 1
printf 'made it through the lossy handshake\nexit\n' \
  | dex -i alice1 $APP -c bob1 > "$HOST_OUT/4_dtls_loss/alice.log" 2>&1 || true
sleep 3
caps_stop 4_dtls_loss
dex alice1 tc qdisc del dev eth0 root netem
dex bob1   tc qdisc del dev eth0 root netem
quiet_kill

echo
echo "== evidence written under: $HOST_OUT =="
find "$HOST_OUT" -type f -printf '%P\n' | sort
