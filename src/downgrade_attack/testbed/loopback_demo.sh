#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Rootless local test of the Task 3 downgrade attack — NO containers, NO sudo.
#
# Alice, Bob and Trudy run as three ordinary processes on distinct loopback
# addresses:
#     Bob     127.0.0.2:8080
#     Trudy   127.0.0.3:8080   (this is where Alice's poisoned DNS points)
#     Alice   127.0.0.1  (ephemeral)  ->  connects to 127.0.0.3 == "bob1"
#
# The SC_BIND_ADDR env var (test-only hook in the two programs) lets Bob and
# Trudy each own :8080 on the same machine. Trudy still forwards to the real
# Bob at 127.0.0.2. Passing an IP where a hostname is expected just stands in
# for the /etc/hosts poisoning you would do in the container demo.
# ---------------------------------------------------------------------------
set -u
cd "$(dirname "$0")/.."                 # -> src/downgrade_attack
make >/dev/null || { echo "build failed"; exit 1; }

OUT=$(mktemp -d)
echo "== logs in $OUT =="

# `sleep | ` keeps Bob's stdin open for the run (in a real 3-terminal demo
# this is just your keyboard); otherwise Bob's chat loop hits EOF and exits.
sleep 8 | SC_BIND_ADDR=127.0.0.2 ./secure_chat_app -s                      >"$OUT/bob.log"   2>&1 &
BOB=$!
SC_BIND_ADDR=127.0.0.3 ./secure_chat_interceptor  -d 127.0.0.1 127.0.0.2   >"$OUT/trudy.log" 2>&1 &
TRU=$!
sleep 1

{ printf 'hello bob, is this line secure?\n'; sleep 1;
  printf 'guess not — plaintext it is\n';     sleep 1;
  printf 'exit\n';                             sleep 1; } \
  | ./secure_chat_app -c 127.0.0.3 >"$OUT/alice.log" 2>&1

sleep 1
kill -9 "$BOB" "$TRU" 2>/dev/null
wait 2>/dev/null

for r in trudy alice bob; do
    echo
    echo "=================== $r ==================="
    cat "$OUT/$r.log"
done

echo
echo "PASS criteria:"
echo "  * trudy.log shows 'blocked chat_START_SSL' and prints the chat lines in clear"
echo "  * alice.log shows 'chat_START_SSL_NOT_SUPPORTED' then '[!] ... PLAINTEXT'"
echo "  * bob.log   shows '[!] ... PLAINTEXT' and 'Alice: ...'  (never 'DTLS 1.2 session established')"
