# Task 3 — evidence (`chat_START_SSL` downgrade attack)

Collected with `src/downgrade_attack/testbed/docker/collect_task3_evidence.sh`
on the 3-container docker test-bed:

| role   | container | IP         |
|--------|-----------|------------|
| Alice  | `alice1`  | 10.13.0.2  |
| Bob    | `bob1`    | 10.13.0.3  |
| Trudy  | `trudy1`  | 10.13.0.4  |

Binaries: `src/downgrade_attack/secure_chat_app` and `secure_chat_interceptor`.
Each `*.pcap` was also rendered to `*.pcap.txt` (`tcpdump -A`) so it can be
read without Wireshark. Capture filter on every host: `udp port 8080`.

---

## 1_normal/ — baseline, no attacker

`alice1 ./secure_chat_app -c bob1`  ↔  `bob1 ./secure_chat_app -s`, DNS clean.

| file | shows |
|------|-------|
| `alice.log`, `bob.log` | full DTLS 1.2 handshake, **mutual** certificate verification, PFS suite `ECDHE-ECDSA-AES256-GCM-SHA384` |
| `alice1.pcap` / `bob1.pcap` (+ `.txt`) | `chat_hello`, `chat_reply_ok`, `chat_START_SSL`, `chat_START_SSL_ACK` in **clear text**; after that only DTLS records — the string `secret code 4242` typed by Alice does **not** appear anywhere |
| `trudy1.pcap` | **empty** (24-byte header, 0 packets). With DNS un-poisoned Trudy is not on the path — the pcap proves it. |

## 2_downgrade/ — the attack

DNS poisoned (`alice1:bob1 → Trudy`, `bob1:alice1 → Trudy`), then
`trudy1 ./secure_chat_interceptor -d alice1 bob1`.

| file | shows |
|------|-------|
| `etc_hosts_view_alice1.txt` | line 1 = how `alice1` now resolves `bob1` (`10.13.0.4`, Trudy); line 2 = how `trudy1` still resolves it (`10.13.0.3`, real Bob) |
| `trudy.log` | `blocked chat_START_SSL from Alice — injecting chat_START_SSL_NOT_SUPPORTED`, then every chat line printed as Trudy relays it |
| `alice.log` | `Received chat_START_SSL_NOT_SUPPORTED …` → `[!] … continuing in PLAINTEXT` |
| `bob.log` | `[!] … continuing in PLAINTEXT`, then `Alice: is this line encrypted?` / `Alice: no - Trudy reads it in the clear` |
| `trudy1.pcap` (+ `.txt`) | `chat_hello`, `chat_reply_ok`, `chat_START_SSL`, the forged `chat_START_SSL_NOT_SUPPORTED`, **and the chat text itself** — all readable. No DTLS `ClientHello`. |
| `alice1.pcap`, `bob1.pcap` | same conversation seen from each end |

## 3_packet_loss/ — control-message timers & retries (`tc netem loss 40%` on `alice1`)

| file | shows |
|------|-------|
| `alice.log` | `Sending chat_hello` → `[timeout] resending chat_hello (1/5) … (3/5)` → succeeds → `Sending chat_START_SSL`. The application-layer control handshake is retransmitted until it gets through. |
| `alice1.pcap` / `bob1.pcap` | ~100 packets on port 8080 — the repeated control datagrams plus DTLS flights |
| `bob.log` | Bob receives `chat_hello`, replies |

Note: at 40 % loss the **DTLS handshake** that follows does not always
finish — this code retransmits its own control messages but does not drive
OpenSSL's DTLS handshake-retransmission timer
(`DTLSv1_get_timeout` / `DTLSv1_handle_timeout`). Task 3 only requires
reliable delivery of the *application* control messages, which is shown
here; the DTLS-handshake-under-loss question belongs to Task 4.

## 3b_light_loss/ — end-to-end under mild loss (`tc netem loss 10%` on `alice1` and `bob1`)

| file | shows |
|------|-------|
| `alice.log` | one `[timeout] resending chat_hello (1/5)`, then the **whole** flow completes: DTLS handshake, cert verification, PFS cipher |
| `bob.log` | `Alice: this line survives 10% loss end to end` received over the encrypted channel |

Everything works end-to-end when loss is moderate; heavier loss degrades the
DTLS handshake as noted above.

---

## Re-generating

```sh
cd src/downgrade_attack/testbed/docker
docker compose up -d --build
./collect_task3_evidence.sh          # rewrites data/task3/
docker compose down
```
