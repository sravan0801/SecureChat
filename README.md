# SecureChat — DTLS 1.2 Chat + MITM Attack Suite

A peer-to-peer chat application secured with **DTLS 1.2 over UDP** and mutual
X.509 certificate authentication, built for a networking course assignment
on OpenSSL and man-in-the-middle attacks. The project has four parts: a
CA hierarchy, the chat app itself, and two attacker programs that show how
trust in that PKI can be subverted.

| Task | What | Where |
|---|---|---|
| 1 — Certificates | Root → Intermediate → leaf (Alice/Bob) CA chain | [`certs/`](certs/) |
| 2 — Secure chat app | Alice/Bob DTLS 1.2 peer-to-peer chat, mutual auth | [`src/secure_chat_app.cpp`](src/secure_chat_app.cpp) |
| 3 — Downgrade attack | Trudy strips `chat_START_SSL` to force plaintext chat | [`src/downgrade_attack/`](src/downgrade_attack/) |
| 4 — Active MITM | Trudy terminates two DTLS pipes with forged, CA-signed shadow certs | [`src/MITM/`](src/MITM/) |

Test evidence already collected for Tasks 3 and 4 (logs + pcaps) is in
[`data/`](data/) — see [Test results](#test-results-already-executed) below.

## How it works

- Alice (client) and Bob (server) exchange a short plaintext control
  handshake (`chat_hello` → `chat_reply_ok` → `chat_START_SSL` →
  `chat_START_SSL_ACK`) over UDP, then perform a DTLS 1.2 handshake with
  **mutual certificate authentication** and a PFS-only cipher suite
  (ECDHE‑ECDSA/RSA‑AES256‑GCM‑SHA384).
- Trudy sits on the network path (simulated via `/etc/hosts` poisoning) and
  runs one of two attack programs against that handshake:
  - **`secure_chat_interceptor -d`** (Task 3) blocks `chat_START_SSL` and
    forges `chat_START_SSL_NOT_SUPPORTED`, so both sides fall back to an
    unencrypted chat that Trudy reads in the clear.
  - **`secure_chat_active_interceptor -m`** (Task 4) instead lets the
    handshake proceed but presents *fake* certificates — for Alice a shadow
    `Bob1.com` cert, for Bob a shadow `Alice1.com` cert — both re-signed by
    the real (compromised) intermediate CA. Two independent DTLS sessions
    come up (Alice↔Trudy, Trudy↔Bob); Trudy decrypts, logs, and optionally
    tampers with every message while both endpoints still report the
    channel as verified.

## Repository layout

```
certs/                    Task 1 — root/intermediate/Alice/Bob CA chain
src/
  secure_chat_app.cpp      Task 2 — base chat app (run from src/)
  makefile
  downgrade_attack/        Task 3 — downgrade attack + its own app/makefile/README
    secure_chat_app.cpp
    secure_chat_interceptor.cpp
    testbed/                 loopback, network-namespace and Docker test rigs
  MITM/                    Task 4 — active MITM + its own app/makefile/README
    secure_chat_app.cpp
    secure_chat_active_interceptor.cpp
    fake_certs/              shadow certs + generation script
    testbed/docker/
data/
  task3/INDEX.md           Task 3 evidence (logs + pcaps), indexed
  task4/INDEX.md           Task 4 evidence (logs + pcaps), indexed
```

Each of `src/downgrade_attack/README.md` and `src/MITM/README.md` has the
full protocol write-up and attack explanation; this file covers the project
as a whole.

## How to execute

### Prerequisites

```sh
sudo apt install g++ make libssl-dev openssl
```

Docker (with `docker compose`) is needed only for the containerized
Alice/Bob/Trudy test-beds described below.

### Task 2 — plain secure chat (no attacker)

```sh
cd src
make
./securechat -s          # on Bob's host
./securechat -c bob1      # on Alice's host — bob1 must resolve via DNS/hosts
```

> **Known issue:** this build pins the cipher list to
> `ECDHE-RSA-AES256-GCM-SHA384` only, but Bob's certificate is EC
> (`prime256v1`), so the handshake fails with `handshake failure` unless the
> cipher list also offers `ECDHE-ECDSA-AES256-GCM-SHA384`. The copies used
> for Tasks 3 and 4 (below) already carry that fix — see
> `src/downgrade_attack/secure_chat_app.cpp`.

### Task 3 — downgrade attack

```sh
cd src/downgrade_attack
make
./secure_chat_app -s                        # Bob
./secure_chat_interceptor -d alice1 bob1    # Trudy (needs Alice/Bob DNS poisoned toward her)
./secure_chat_app -c bob1                   # Alice
```

Three ways to run the full three-party scenario without the assignment's
LXD setup are documented in `src/downgrade_attack/README.md`:
a **loopback script** (`testbed/loopback_demo.sh`, no root), a **network
namespace** rig (`testbed/netns_*.sh`, needs `sudo`), and a **Docker**
test-bed (`testbed/docker/`, three containers on a private bridge).

### Task 4 — active MITM

```sh
cd src/MITM
make
bash fake_certs/gen_fake_certs.sh           # generates the shadow certs once
./secure_chat_app -s                        # Bob
./secure_chat_active_interceptor -m alice1 bob1 [-t]   # Trudy (-t also tampers)
./secure_chat_app -c bob1                   # Alice
```

Same Docker test-bed pattern as Task 3, in `src/MITM/testbed/docker/`.

## Test results (already executed)

Both attacks were run end-to-end in the Docker test-beds (three containers,
one per role, on a private bridge network) and the logs + pcaps are
committed under `data/`. Full breakdowns and file-by-file explanations are
in `data/task3/INDEX.md` and `data/task4/INDEX.md`; the headline results:

### Task 3 — downgrade attack (`data/task3/`)

| Scenario | Result |
|---|---|
| `1_normal` — no attacker | DTLS 1.2 handshake succeeds, mutual cert verification, chat encrypted; Trudy's capture is empty (not on path) |
| `2_downgrade` — DNS poisoned, interceptor running | Trudy blocks `chat_START_SSL`, forges `chat_START_SSL_NOT_SUPPORTED`; both sides fall back to plaintext; Trudy's pcap shows the chat text **in the clear** |
| `3_packet_loss` — 40% loss on Alice's link | Application-layer control messages (`chat_hello`, `chat_START_SSL`) are retried up to 5× and get through; DTLS handshake retransmission itself is not driven by this build and can stall under heavy loss |
| `3b_light_loss` — 10% loss both ends | Full flow (control handshake + DTLS + encrypted chat) completes after one retry |

### Task 4 — active MITM (`data/task4/`)

| Scenario | Result |
|---|---|
| `1_normal` — no attacker | Same as above baseline |
| `2_mitm_transparent` — active interceptor | Alice logs `Server (Bob) certificate verified!`, Bob logs `Client (Alice) certificate verified!` — **both fooled**; Trudy's pcap shows two independent DTLS sessions; her log shows every message decrypted |
| `3_mitm_tamper` — interceptor with `-t` | Bob actually receives `Alice: transfer 100 rupees to Bob  [tampered by Trudy]` while still reporting the certificate as verified |
| `4_dtls_loss` — 8% loss, no attacker | DTLS handshake **completes** under loss via DTLS's own flight retransmission (repeated equal-size datagrams in the capture) — no application-level reliability code was involved |

**Take-away:** a downgrade attack is a blunt, easily-noticed instrument (the
chat becomes visibly unencrypted); the active MITM is the dangerous one —
because the shadow certificates chain to the real, trusted root, neither
Alice nor Bob has any indication that their "secure" session is being read
and altered.

## References

- `src/downgrade_attack/README.md` — Task 3 protocol details, run/testing instructions
- `src/MITM/README.md` — Task 4 mechanism, run instructions, and the write-up on DTLS handshake reliability under packet loss
