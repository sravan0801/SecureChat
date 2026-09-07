# Task 3 — `chat_START_SSL` Downgrade Attack

Trudy sits between Alice and Bob (via `/etc/hosts` poisoning), blocks the
`chat_START_SSL` control message, and forges a `chat_START_SSL_NOT_SUPPORTED`
reply. Alice and Bob then fall back to an **unencrypted** chat that Trudy
reads and relays in the clear.

Everything here is built on `../secure_chat_app.cpp` (Task 2). The original
file is **unchanged**; this directory has its own downgrade-aware copy.

## Files

| File | Purpose |
|------|---------|
| `secure_chat_app.cpp` | Alice/Bob chat app. Same DTLS 1.2 logic as Task 2, plus: plaintext fallback on `chat_START_SSL_NOT_SUPPORTED`, control-message timers/retries, server binds all interfaces. |
| `secure_chat_interceptor.cpp` | Trudy. `-d <alice_host> <bob_host>` — relays everything, tampers only with `chat_START_SSL`. |
| `makefile` | `make` builds both binaries; `make clean` removes them. |

## What changed vs. `../secure_chat_app.cpp`

1. **Plaintext fallback (Task 3a).**
   - Client: after `chat_START_SSL`, if the reply is `chat_START_SSL_NOT_SUPPORTED`
     it prints a warning and enters `runPlainChat()` (raw UDP, no DTLS).
   - Server: after `chat_reply_ok`, it waits for `chat_START_SSL`; on
     `chat_START_SSL_NOT_SUPPORTED` **or** on timeout it enters `runPlainChat()`.
2. **Control-message reliability.** `recvControl()` arms `SO_RCVTIMEO`
   (`CTRL_WAIT` = 2 s) and retransmits the last control message up to
   `CTRL_TRIES` = 5 times before giving up. Covers real packet loss and
   Trudy silently dropping a datagram.
3. **Server bind.** Binds `INADDR_ANY:8080` instead of resolving `bob1`, so
   Bob still starts when its own hostname points at Trudy after poisoning.
4. **Cipher list.** `ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384`
   (Bob's certificate is ECC, Alice's is RSA — both PFS).
5. Receiver threads are `detach()`ed so a clean exit doesn't abort; `cout`
   is unit-buffered so piped logs / pcap demos stay in order.
6. **`SC_BIND_ADDR`** (env var, unset in normal use): test-only override for
   the listen address, so Bob and Trudy can share one host on `127.0.0.x`
   during the loopback demo. The container/netns runs never set it.

The certificate-name check is deliberately **not** added — Task 4 needs a
CA-signed cert to pass verification. Cert paths point at `../../certs/...`.

## Chat protocol (control plane, all plaintext UDP)

```
Alice  --------- chat_hello --------->  Bob
Alice  <-------- chat_reply_ok -------  Bob
Alice  ------- chat_START_SSL ------->  Bob
Alice  <---- chat_START_SSL_ACK ------  Bob      then DTLS 1.2 handshake + encrypted chat
```

Downgrade case:

```
Alice  ------- chat_START_SSL ---->X  Trudy   (blocked, never reaches Bob)
Alice  <-- chat_START_SSL_NOT_SUPPORTED --  Trudy   (forged, looks like Bob)
Bob    <-- chat_START_SSL_NOT_SUPPORTED --  Trudy   (forged, looks like Alice)
Alice  <====== plaintext chat ======>  Trudy  <======>  Bob      (Trudy logs every line)
```

## Build

```
make
```

## Run — the real setup (3 LXD containers)

`secure_chat_app` must be present in the alice1 and bob1 containers,
`secure_chat_interceptor` in trudy1, with the `certs/` tree two levels up
from the binary (or adjust the paths in `configureCredentials()`).

```sh
# 1. Bob (server)
lxc exec bob1 -- bash -c 'cd ~/task3 && ./secure_chat_app -s'

# 2. Trudy (attacker) — DNS already poisoned, see step 4
lxc exec trudy1 -- bash -c 'cd ~/task3 && ./secure_chat_interceptor -d alice1 bob1 | tee ~/downgrade_attack.log'

# 3. Alice (client)
lxc exec alice1 -- bash -c 'cd ~/task3 && ./secure_chat_app -c bob1'
```

Poison / restore DNS from **inside the VM**:

```sh
bash ~/poison-dns-alice1-bob1.sh      # alice1:bob1 -> trudy, bob1:alice1 -> trudy
bash ~/unpoison-dns-alice1-bob1.sh
```

### Pcap evidence (Task 3b)

```sh
lxc exec alice1 -- tcpdump -i eth0 -w /root/alice_downgrade.pcap  udp port 8080 &
lxc exec bob1   -- tcpdump -i eth0 -w /root/bob_downgrade.pcap    udp port 8080 &
lxc exec trudy1 -- tcpdump -i eth0 -w /root/trudy_downgrade.pcap  udp port 8080 &
```

Expected in the traces: the `chat_hello` / `chat_reply_ok` /
`chat_START_SSL` / `chat_START_SSL_NOT_SUPPORTED` control messages **and the
chat text itself** appear as readable ASCII — no DTLS `ClientHello`, no
`Application Data` records. Trudy's console prints every forwarded line.

Inject packet loss to show the retry timers:

```sh
lxc exec alice1 -- tc qdisc add dev eth0 root netem loss 30%
# ... run the chat, watch "[timeout] resending ..." lines ...
lxc exec alice1 -- tc qdisc del dev eth0 root netem
```

## Testing without LXD containers

Trudy tells Alice and Bob apart by source IP, so the three roles need
distinct addresses with a separate `:8080` listener each. Two ways to get
that on one laptop:

### 1. Loopback demo — no root, one command (recommended first check)

```
bash testbed/loopback_demo.sh
```

Runs Bob on `127.0.0.2:8080`, Trudy on `127.0.0.3:8080`, and Alice pointed
at `127.0.0.3` (standing in for `bob1` after poisoning). The `SC_BIND_ADDR`
env var (a test-only hook in both programs) is what lets Bob and Trudy share
one host. Prints all three logs and the pass criteria. This exercises the
**real** `secure_chat_interceptor`, not a stub.

For a live session instead of the scripted one, use three terminals:

```
SC_BIND_ADDR=127.0.0.2 ./secure_chat_app         -s
SC_BIND_ADDR=127.0.0.3 ./secure_chat_interceptor -d 127.0.0.1 127.0.0.2
                       ./secure_chat_app         -c 127.0.0.3
```

Capture a pcap (needs sudo for the capture only):

```
sudo tcpdump -i lo -w trudy_t3.pcap 'udp port 8080'
```

### 2. Network-namespace testbed — faithful, needs sudo

Real `eth0` interfaces on a bridge, per-namespace `/etc/hosts`, works with
`tc` packet loss and (for Task 5) ARP. Mirrors the assignment's LXD layout.

```
make
sudo bash testbed/netns_up.sh          # alice1/bob1/trudy1 on 10.13.0.0/24
sudo bash testbed/netns_poison.sh      # alice1:bob1 & bob1:alice1 -> Trudy

# three terminals (cwd = src/downgrade_attack, so ../../certs resolves):
sudo ip netns exec bob1   ./secure_chat_app         -s
sudo ip netns exec trudy1 ./secure_chat_interceptor -d alice1 bob1
sudo ip netns exec alice1 ./secure_chat_app         -c bob1

# evidence
sudo ip netns exec trudy1 tcpdump -i eth0 -w trudy_t3.pcap 'udp port 8080'
sudo ip netns exec alice1 tc qdisc add dev eth0 root netem loss 30%
sudo ip netns exec alice1 tc qdisc del dev eth0 root netem

sudo bash testbed/netns_unpoison.sh
sudo bash testbed/netns_down.sh        # tear everything down
```

Here Alice and Bob use the real hostnames `alice1` / `bob1` and no
`SC_BIND_ADDR` — exactly the assignment invocation.

### 3. Docker — faithful, no sudo (files in `testbed/docker/`)

Three containers on one private bridge network, same layout as the LXD
star. Each container has its own IP, its own network stack and its own
`/etc/hosts`, so nothing here is faked.

```
gateway 10.13.0.1   alice1 10.13.0.2   bob1 10.13.0.3   trudy1 10.13.0.4
```

```sh
cd testbed/docker
docker compose up -d --build          # start alice1 / bob1 / trudy1
docker compose exec bob1 make         # build the two binaries into the shared mount

# --- normal run: names resolve via Docker's DNS, chat is encrypted ---
docker exec -it bob1   ./secure_chat_app -s
docker exec -it alice1 ./secure_chat_app -c bob1

# --- downgrade attack ---
# 1. poison: make alice1 see "bob1" as Trudy, and bob1 see "alice1" as Trudy
docker exec alice1 sh -c 'echo "10.13.0.4  bob1"   >> /etc/hosts'
docker exec bob1   sh -c 'echo "10.13.0.4  alice1" >> /etc/hosts'
# 2. run, one command per terminal
docker exec -it bob1   ./secure_chat_app         -s
docker exec -it trudy1 ./secure_chat_interceptor -d alice1 bob1
docker exec -it alice1 ./secure_chat_app         -c bob1
# 3. undo poison when done
docker restart alice1 bob1

# evidence
mkdir -p ../../../../data
docker exec trudy1 tcpdump -i eth0 -w /work/data/trudy_t3.pcap 'udp port 8080'
docker exec alice1 tc qdisc add dev eth0 root netem loss 30%
docker exec alice1 tc qdisc del dev eth0 root netem

docker compose down                   # remove everything
```

`docker compose exec` and `docker exec -it` give the app a real terminal, so
the chat loop keeps running until you type `exit` — same as a normal shell.

### Regression check (secure path still works)

With `127.0.0.1 bob1` in `/etc/hosts`, no Trudy:

```
./secure_chat_app -s
./secure_chat_app -c bob1
```

Expect a full DTLS 1.2 handshake negotiating
`ECDHE-ECDSA-AES256-GCM-SHA384` with both certificates verified.
