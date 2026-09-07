# Task 4 — Active MITM attack (fake certificates)

Trudy places herself between Alice and Bob (via `/etc/hosts` poisoning) and,
instead of downgrading the session, terminates **two real DTLS 1.2 pipes**
using shadow certificates issued by the compromised intermediate CA. Both
ends complete mutual authentication and believe the channel is secure; Trudy
decrypts, logs, and (optionally) rewrites every message.

Built on the Task 3 code — `secure_chat_app.cpp` here is a **verbatim copy**
of `../downgrade_attack/secure_chat_app.cpp` (nothing in `downgrade_attack/`
was changed).

## Files

| file | purpose |
|------|---------|
| `secure_chat_app.cpp` | Alice/Bob chat app — unchanged from Task 3. The attack works precisely because the app trusts any cert that chains to the root and does **not** pin the peer hostname. |
| `secure_chat_active_interceptor.cpp` | Trudy. `-m <alice_host> <bob_host> [-t]` |
| `fake_certs/gen_fake_certs.sh` | (re)generates the shadow certs (Task 4a) |
| `fake_certs/fake{alice,bob}*` | shadow key/CSR/cert/fullchain, already generated |
| `makefile` | `make` builds both binaries; `make clean` removes them |
| `testbed/docker/` | 3-container test-bed + evidence collector |

## Task 4(a) — the shadow certificates

```
bash fake_certs/gen_fake_certs.sh
```

For each identity it makes `fake<name>.key.pem`, `fake<name>.csr`,
`fake<name>.crt` and `fake<name>-fullchain.pem`. Each keeps the real
subject / SAN / EKU (`CN=Alice1.com` + `alice1`, `CN=Bob1.com` + `bob1`,
`serverAuth,clientAuth`) and the real key type (Alice RSA‑1024, Bob EC
P‑256), but carries a **new key pair** and is re‑signed by `iTS CA 1R3`.

```
openssl verify -CAfile ../../certs/chain.pem fake_certs/fakealice.crt   # OK
openssl verify -CAfile ../../certs/chain.pem fake_certs/fakebob.crt     # OK
```

## Task 4(b)/(c) — how the interceptor works

```
./secure_chat_active_interceptor -m alice1 bob1        # transparent proxy
./secure_chat_active_interceptor -m alice1 bob1 -t     # also tamper Alice->Bob
```

1. **Plaintext control relay.** `chat_hello / chat_reply_ok / chat_START_SSL
   / chat_START_SSL_ACK` are forwarded untouched (no downgrade).
2. **Pipe 1 — Trudy as DTLS server toward Alice.** Presents
   `fakebob-fullchain.pem`. Alice verifies it → chains to the trusted root →
   `Server (Bob) certificate verified!`.
3. **Pipe 2 — Trudy as DTLS client toward Bob.** Presents
   `fakealice-fullchain.pem`. Bob verifies it → `Client (Alice) certificate
   verified!`. Trudy also verifies Bob's *real* cert.
4. **Relay.** `SSL_read` on one pipe → log the plaintext → `SSL_write` on the
   other. With `-t`, Alice→Bob messages get `  [tampered by Trudy]` appended
   before re‑encryption.

Two sockets are used: `sA` (bound `:8080`, faces Alice) and `sB`
(`connect()`ed to Bob). `SC_BIND_ADDR` is a test‑only bind override; the
container/VM runs never set it.

### What Alice and Bob see

Both apps print `DTLS 1.2 session established!` and `… certificate
verified!` — identical to an un‑attacked session. Nothing on their side
reveals the MITM, because a shadow cert signed by the trusted intermediate
passes every check the app makes.

## Task 4 closing question — DTLS handshake message loss

> *Does your secure application have to implement any reliable data transfer
> mechanism for exchanging DTLS handshake messages?*

**No — DTLS 1.2 already provides it.** Unlike TLS (which relies on TCP),
DTLS defines its own handshake reliability: messages carry
`message_seq` numbers, each flight is retransmitted on a timer until the
next flight is received, and out‑of‑order / duplicate handshake records are
reordered and de‑duplicated by the stack. The application only has to
*drive* the timer — call `DTLSv1_get_timeout()` / `DTLSv1_handle_timeout()`
(or give the datagram BIO a receive timeout, as the server side here does).
It must **not** implement its own ACK/retransmit scheme for handshake
messages.

Application chat DATA is different: it needs no reliability at all (the
assignment says only fast delivery matters), so lost `SSL_write` records are
simply lost.

Show it with `tc` on a link, e.g.:

```
# inside a container / netns
tc qdisc add dev eth0 root netem loss 20%
# run the app; in Wireshark you will see DTLS handshake records with
# repeated message_seq values = DTLS's built-in retransmission
tc qdisc del dev eth0 root netem
```

(Our blocking client uses `SSL_connect` without a timeout loop, so under
heavy loss it can stall waiting for a lost flight — that is a limitation of
*this* implementation's I/O style, not of DTLS. Driving the timeout as
above fixes it without any app‑level RDT.)

## Build & run

```
make
bash fake_certs/gen_fake_certs.sh          # if the fake_certs/*.crt are missing

# real setup (hostnames, DNS poisoned so alice1/bob1 -> Trudy):
./secure_chat_app -s                       # on bob1
./secure_chat_active_interceptor -m alice1 bob1   # on trudy1
./secure_chat_app -c bob1                   # on alice1
```

See `testbed/docker/README` notes for a container-based run with pcaps, and
`../downgrade_attack/testbed/` for the loopback / network-namespace options
(same mechanics, point them at `src/MITM`).
