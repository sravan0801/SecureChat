# Task 4 — evidence (active MITM with fake certificates)

Collected with `src/MITM/testbed/docker/collect_task4_evidence.sh` on the
3-container docker test-bed:

| role   | container | IP         |
|--------|-----------|------------|
| Alice  | `alice1`  | 10.14.0.2  |
| Bob    | `bob1`    | 10.14.0.3  |
| Trudy  | `trudy1`  | 10.14.0.4  |

Binaries: `src/MITM/secure_chat_app` (verbatim copy of the Task 3 build) and
`src/MITM/secure_chat_active_interceptor`. Shadow certs:
`src/MITM/fake_certs/fake{alice,bob}*`. Every `*.pcap` is also rendered to
`*.pcap.txt` (`tcpdump -A`). Capture filter: `udp port 8080`.

---

## 1_normal/ — baseline, no attacker

`alice1 ./secure_chat_app -c bob1` ↔ `bob1 ./secure_chat_app -s`, DNS clean.

| file | shows |
|------|-------|
| `alice.log`, `bob.log` | DTLS 1.2, **mutual** cert verification, `ECDHE-ECDSA-AES256-GCM-SHA384` |
| `alice1.pcap` / `bob1.pcap` | control messages in clear; then only DTLS records — `secret 4242` never appears |
| `trudy1.pcap` | **empty** (24-byte header) — Trudy is not on the path when DNS is clean |

## 2_mitm_transparent/ — the attack (Task 4b)

DNS poisoned (`alice1:bob1 → 10.14.0.4`, `bob1:alice1 → 10.14.0.4`), then
`trudy1 ./secure_chat_active_interceptor -m alice1 bob1`.

| file | shows |
|------|-------|
| `etc_hosts_views.txt` | how alice1 / bob1 resolve their peer (→ Trudy) vs. how trudy1 resolves them (→ real) |
| `trudy.log` | `pipe 1 UP … (fakebob)` + `pipe 2 UP … (fakealice)`, both `ECDHE-ECDSA-AES256-GCM-SHA384`; Trudy verified Alice's **real** cert (`CN=Alice1.com`) and Bob's **real** cert (`CN=Bob1.com`); then every message printed `(decrypted)` |
| `alice.log` | `DTLS 1.2 session established!` + **`Server (Bob) certificate verified!`** — Alice sees nothing wrong |
| `bob.log` | **`Client (Alice) certificate verified!`** + `Alice: my PIN is 4242` |
| `trudy1.pcap` | **two** independent DTLS sessions: `10.14.0.2 ↔ 10.14.0.4:8080` (Alice–Trudy) and `10.14.0.4 ↔ 10.14.0.3:8080` (Trudy–Bob) — separate ClientHellos, separate keys |

## 3_mitm_tamper/ — active tampering (Task 4b "…altering message contents…")

Same as scenario 2 but `-m alice1 bob1 -t`.

| file | shows |
|------|-------|
| `trudy.log` | `Alice -> Bob (decrypted): transfer 100 rupees to Bob` → `re-encrypted as: transfer 100 rupees to Bob  [tampered by Trudy]` |
| `bob.log` | Bob actually receives **`Alice: transfer 100 rupees to Bob  [tampered by Trudy]`** while still reporting `Client (Alice) certificate verified!` |

## 4_dtls_loss/ — DTLS handshake under packet loss (Task 4 closing question)

`tc qdisc add dev eth0 root netem loss 8%` on `alice1`, no attacker.

| file | shows |
|------|-------|
| `alice.log` / `bob.log` | the DTLS 1.2 handshake **completes** despite the loss — `DTLS 1.2 session established!`, both certs verified, `Alice: through the lossy DTLS handshake` delivered |
| `*.pcap` | the handshake window contains many repeated equal-size datagrams (≈19× one flight, ≈17× another) = **DTLS's own flight retransmission**. Open in Wireshark → the retransmitted records carry the *same* `message_seq`. |

**Answer:** the application does **not** implement (or need) any reliable
transfer for handshake messages — DTLS 1.2 provides it (per-message
`message_seq`, per-flight timers, reorder/dedup). The app only drives the
timer. Chat *data* needs no reliability and lost data records are just lost.

Note: an earlier attempt at 20% loss on **both** links failed at the
*plaintext* `chat_START_SSL` step — that is the Task 3 application-level
retry (`[timeout] resending … (5/5)`) being exhausted, which is separate
from DTLS. And because this build's client does a blocking `SSL_connect`
with no timeout loop, very heavy handshake loss can still stall it — a
limitation of the I/O style, not of DTLS (drive `DTLSv1_handle_timeout()`
to fix without any app-level RDT).

---

## Re-generating

```sh
cd src/MITM/testbed/docker
docker compose up -d --build
docker compose exec bob1 make
./collect_task4_evidence.sh          # rewrites data/task4/ only
docker compose down
```
