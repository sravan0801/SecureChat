// secure_chat_app.cpp  (Task 3 build — downgrade-aware)
//
// Derived from ../secure_chat_app.cpp (Task 2). Same DTLS 1.2 chat between
// Alice (client) and Bob (server); the only additions here are the pieces
// Task 3 needs:
//
//   * Alice/Bob fall back to a PLAINTEXT chat when the secure handshake is
//     refused with chat_START_SSL_NOT_SUPPORTED (Task 3a).
//   * The pre-handshake control messages are retransmitted on a timer so a
//     dropped datagram (or a datagram swallowed by Trudy) does not wedge
//     either side.
//   * The server binds every local interface, so it still comes up even when
//     its own hostname has been redirected by /etc/hosts poisoning.
//
// Run:
//   Bob   (server): ./secure_chat_app -s
//   Alice (client): ./secure_chat_app -c <hostname>
//
// Build:
//   g++ -o secure_chat_app secure_chat_app.cpp -lssl -lcrypto -lpthread

#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <thread>

// C++ standard headers
#include <iostream>
#include <string>
#include <arpa/inet.h>

// OpenSSL headers used for the DTLS layer
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#define BUF_SIZE  1024   // Largest chat/control message we handle
#define CHAT_PORT 8080   // UDP port shared by both roles
#define SOCKADDR  struct sockaddr

#define CTRL_WAIT   2    // Seconds to wait for a control reply before resending
#define CTRL_TRIES  5    // How many times to resend before giving up

using namespace std;

// ─── Process-wide state ───────────────────────────────────────────────────────

int udp_sock;                        // The UDP socket carrying DTLS
struct sockaddr_in peer_addr;        // Remote peer's address
struct timeval recv_tv;              // Receive timeout handed to the BIO
socklen_t peer_addr_len = sizeof(peer_addr);
char rx_buf[BUF_SIZE];               // Buffer used by the reader threads
bool acting_as_client;               // Set when this instance is Alice

SSL_CTX* dtls_ctx = nullptr;         // Context shared by the session
SSL*     dtls_conn = nullptr;        // The live DTLS session
BIO*     dgram_bio = nullptr;        // Datagram BIO wrapping udp_sock (server)

// ─── Helpers ──────────────────────────────────────────────────────────────────

// Turns a hostname into a dotted-quad IPv4 string.
string resolveHost(const char* hostname) {
    struct hostent* entry = gethostbyname(hostname);
    if (entry == NULL) {
        herror("gethostbyname");
        exit(EXIT_FAILURE);
    }
    struct in_addr** addresses = (struct in_addr**)entry->h_addr_list;
    return inet_ntoa(*addresses[0]);
}

// Fires off one plain UDP datagram (pre-handshake signaling and, after a
// downgrade, the plaintext chat itself).
void sendPlainDatagram(const string& payload) {
    sendto(udp_sock, payload.c_str(), payload.length(), MSG_CONFIRM,
           (const struct sockaddr*)&peer_addr, peer_addr_len);
}

// Blocks for one plain UDP datagram.
string recvPlainDatagram(bool echo) {
    char inbound[BUF_SIZE];
    int n = recvfrom(udp_sock, inbound, BUF_SIZE - 1, MSG_WAITALL,
                     (struct sockaddr*)&peer_addr, &peer_addr_len);
    inbound[n] = '\0';
    if (echo)
        printf("Received: %s\n", inbound);
    return string(inbound);
}

// Arms (sec > 0) or clears (sec == 0) a receive timeout on the UDP socket.
void setRecvTimeout(int sec) {
    struct timeval tv;
    tv.tv_sec  = sec;
    tv.tv_usec = 0;
    setsockopt(udp_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

// Waits for one control datagram, retransmitting `resend` every CTRL_WAIT
// seconds. Returns the datagram received, or "" if nothing arrived in time.
string recvControl(const string& resend) {
    setRecvTimeout(CTRL_WAIT);
    string got;
    for (int attempt = 0; attempt <= CTRL_TRIES; attempt++) {
        char b[BUF_SIZE];
        int n = recvfrom(udp_sock, b, BUF_SIZE - 1, 0,
                         (struct sockaddr*)&peer_addr, &peer_addr_len);
        if (n > 0) {
            b[n] = '\0';
            got.assign(b);
            break;
        }
        if (attempt < CTRL_TRIES) {
            cout << "[timeout] resending " << resend
                 << " (" << (attempt + 1) << "/" << CTRL_TRIES << ")\n";
            sendPlainDatagram(resend);
        }
    }
    setRecvTimeout(0);
    return got;
}

// Pushes one message through the encrypted DTLS session.
void sendEncrypted(const string& text) {
    SSL_write(dtls_conn, text.c_str(), text.length());
}

// ─── DTLS cookie callbacks ───────────────────────────────────────────────────

int onCookieGenerate(SSL*, unsigned char* cookie, unsigned int* len) {
    memcpy(cookie, "ses_co", 6);
    *len = 6;
    return 1;
}

int onCookieVerify(SSL*, const unsigned char*, unsigned int) {
    return 1;
}

// ─── Certificate / context configuration ─────────────────────────────────────

void configureCredentials() {
    const char* certPath;
    const char* keyPath;

    if (acting_as_client) {
        certPath = "../../certs/alice/alice-fullchain.pem";
        keyPath  = "../../certs/alice/alice.key.pem";
    } else {
        certPath = "../../certs/bob/bob-fullchain.pem";
        keyPath  = "../../certs/bob/bob.key.pem";
    }

    if (SSL_CTX_use_certificate_file(dtls_ctx, certPath, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(dtls_ctx, keyPath, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        cerr << "Error loading certificate or private key\n";
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_check_private_key(dtls_ctx)) {
        cerr << "Private key does not match the certificate!\n";
        exit(EXIT_FAILURE);
    }
    cout << "Certificate and private key loaded successfully.\n";

    if (!SSL_CTX_load_verify_locations(dtls_ctx, "../../certs/chain.pem", NULL)) {
        ERR_print_errors_fp(stderr);
        cerr << "Failed to load CA chain.\n";
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_verify(dtls_ctx,
                       SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       NULL);

    // PFS-only cipher list: ECDHE key exchange with AES-256-GCM. Both an
    // ECDSA variant (Bob's EC certificate) and an RSA variant (Alice's) are
    // offered so either role can be the server.
    if (SSL_CTX_set_cipher_list(dtls_ctx,
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384") != 1) {
        ERR_print_errors_fp(stderr);
        cerr << "Error setting cipher list.\n";
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_options(dtls_ctx, SSL_OP_NO_TICKET);
}

void setupDtlsContext() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    ERR_load_crypto_strings();

    dtls_ctx = SSL_CTX_new(DTLS_method());
    if (!dtls_ctx) {
        perror("Error creating SSL context");
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_min_proto_version(dtls_ctx, DTLS1_2_VERSION);
    SSL_CTX_set_security_level(dtls_ctx, 1);
    SSL_CTX_set_verify(dtls_ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_session_cache_mode(dtls_ctx, SSL_SESS_CACHE_OFF);

    if (!acting_as_client) {
        SSL_CTX_set_cookie_generate_cb(dtls_ctx, onCookieGenerate);
        SSL_CTX_set_cookie_verify_cb(dtls_ctx, &onCookieVerify);
    }

    configureCredentials();
}

// ─── Cipher suite reporting ──────────────────────────────────────────────────

void listOfferedCipherSuites() {
    STACK_OF(SSL_CIPHER)* suites = SSL_get_ciphers(dtls_conn);
    if (suites) {
        cout << "Supported Cipher Suites:\n";
        for (int i = 0; i < sk_SSL_CIPHER_num(suites); i++) {
            const SSL_CIPHER* s = sk_SSL_CIPHER_value(suites, i);
            cout << "  - " << SSL_CIPHER_get_name(s) << "\n";
        }
    } else {
        cout << "No cipher suites found.\n";
    }
}

void reportNegotiatedCipher() {
    const char* name = SSL_get_cipher(dtls_conn);
    if (name)
        cout << "Negotiated Cipher Suite: " << name << "\n";
    else
        cout << "Could not retrieve negotiated cipher suite.\n";
}

// ─── DTLS handshake ─────────────────────────────────────────────────────────

void performHandshake() {
    dtls_conn = SSL_new(dtls_ctx);

    if (acting_as_client) {
        SSL_set_fd(dtls_conn, udp_sock);
        int rc = SSL_connect(dtls_conn);
        if (rc <= 0) {
            ERR_print_errors_fp(stderr);
            cerr << "SSL_connect failed! Error code: "
                 << SSL_get_error(dtls_conn, rc) << "\n";
            exit(EXIT_FAILURE);
        }
    } else {
        dgram_bio = BIO_new_dgram(udp_sock, BIO_NOCLOSE);
        BIO_ctrl(dgram_bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &recv_tv);
        if (!dgram_bio) {
            cerr << "Failed to create BIO.\n";
            exit(EXIT_FAILURE);
        }
        SSL_set_bio(dtls_conn, dgram_bio, dgram_bio);

        int rc = DTLSv1_listen(dtls_conn, (BIO_ADDR*)&peer_addr);
        if (rc < 0) {
            ERR_print_errors_fp(stderr);
            cerr << "DTLSv1_listen failed.\n";
            exit(EXIT_FAILURE);
        }
        SSL_accept(dtls_conn);
    }
}

// ─── Encrypted chat loops ───────────────────────────────────────────────────

void secureReaderLoop(const string& who) {
    while (true) {
        int got = SSL_read(dtls_conn, rx_buf, sizeof(rx_buf));
        if (got <= 0) {
            ERR_print_errors_fp(stderr);
            break;
        }
        rx_buf[got] = '\0';
        cout << who << ": " << rx_buf << "\n";
        if (strncmp(rx_buf, "exit", 4) == 0) {
            cout << "Connection closed by peer.\n";
            break;
        }
    }
}

void runSecureChat(const string& who) {
    cout << "You can start chatting. Type 'exit' to quit.\n";
    thread reader(secureReaderLoop, who);
    string line;
    while (getline(cin, line)) {
        sendEncrypted(line);
        if (line == "exit") {
            sendPlainDatagram("exit");
            break;
        }
    }
    reader.detach();
}

// ─── Plaintext chat loop (used after a downgrade) ───────────────────────────

void plainReaderLoop(const string& who) {
    char b[BUF_SIZE];
    while (true) {
        int n = recvfrom(udp_sock, b, BUF_SIZE - 1, 0, NULL, NULL);
        if (n <= 0)
            break;
        b[n] = '\0';
        if (strncmp(b, "exit", 4) == 0 || strncmp(b, "chat_close", 10) == 0) {
            cout << "Connection closed by peer.\n";
            break;
        }
        cout << who << ": " << b << "\n";
    }
}

void runPlainChat(const string& who) {
    cout << "[!] Secure chat is unavailable — continuing in PLAINTEXT.\n";
    cout << "You can start chatting. Type 'exit' to quit.\n";
    thread reader(plainReaderLoop, who);
    string line;
    while (getline(cin, line)) {
        sendPlainDatagram(line);
        if (line == "exit")
            break;
    }
    reader.detach();
}

// ─── Server role (Bob) ──────────────────────────────────────────────────────

void runAsServer() {
    acting_as_client = false;

    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port   = htons(CHAT_PORT);

    // Bind every interface (survives DNS poisoning of bob1). SC_BIND_ADDR is a
    // test-only override so several roles can share one host on 127.0.0.x.
    const char* bindEnv = getenv("SC_BIND_ADDR");
    local_addr.sin_addr.s_addr = bindEnv ? inet_addr(bindEnv) : htonl(INADDR_ANY);

    if (bind(udp_sock, (SOCKADDR*)&local_addr, sizeof(local_addr)) != 0) {
        perror("socket bind failed");
        exit(EXIT_FAILURE);
    }
    cout << "Bob is listening on port " << CHAT_PORT
         << (bindEnv ? string(" (") + bindEnv + ")" : string(" (all interfaces)")) << "\n\n";

    // ── Plain-text application signaling ────────────────────────────────────
    if (recvPlainDatagram(true) != "chat_hello") {
        cerr << "Expected chat_hello from client.\n";
        exit(EXIT_FAILURE);
    }
    cout << "Sending chat_reply_ok\n";
    sendPlainDatagram("chat_reply_ok");

    // Wait for chat_START_SSL, resending chat_reply_ok if it goes missing.
    string ctrl = recvControl("chat_reply_ok");

    if (ctrl == "chat_START_SSL") {
        cout << "Sending chat_START_SSL_ACK\n";
        sendPlainDatagram("chat_START_SSL_ACK");

        cout << "\nInitializing OpenSSL...\n";
        setupDtlsContext();
        cout << "OpenSSL initialized.\n";

        cout << "Performing DTLS handshake...\n";
        performHandshake();
        reportNegotiatedCipher();
        cout << "DTLS 1.2 session established!\n";

        if (SSL_get_peer_certificate(dtls_conn) &&
            SSL_get_verify_result(dtls_conn) == X509_V_OK)
            cout << "Client (Alice) certificate verified!\n\n";

        runSecureChat("Alice");
    } else {
        // chat_START_SSL_NOT_SUPPORTED, silence, or anything else → plaintext.
        if (!ctrl.empty() && ctrl != "chat_START_SSL_NOT_SUPPORTED")
            cout << "Alice: " << ctrl << "\n";
        runPlainChat("Alice");
    }
}

// ─── Client role (Alice) ────────────────────────────────────────────────────

void runAsClient(const char* IP) {
    acting_as_client = true;

    peer_addr.sin_family      = AF_INET;
    peer_addr.sin_port        = htons(CHAT_PORT);
    peer_addr.sin_addr.s_addr = inet_addr(IP);

    if (connect(udp_sock, (struct sockaddr*)&peer_addr, sizeof(peer_addr)) < 0) {
        perror("Error connecting socket");
        exit(EXIT_FAILURE);
    }
    cout << "Alice connected to " << IP << ":" << CHAT_PORT << "\n\n";

    // ── Plain-text application signaling ────────────────────────────────────
    cout << "Sending chat_hello\n";
    sendPlainDatagram("chat_hello");
    if (recvControl("chat_hello") != "chat_reply_ok") {
        cerr << "No chat_reply_ok from server — aborting.\n";
        exit(EXIT_FAILURE);
    }

    cout << "Sending chat_START_SSL\n";
    sendPlainDatagram("chat_START_SSL");
    string reply = recvControl("chat_START_SSL");

    if (reply == "chat_START_SSL_NOT_SUPPORTED") {
        // Task 3a: assume the peer cannot do secure chat, drop to plaintext.
        cout << "Received chat_START_SSL_NOT_SUPPORTED — server has no secure chat.\n";
        runPlainChat("Bob");
        return;
    }
    if (reply != "chat_START_SSL_ACK") {
        cerr << "No usable reply to chat_START_SSL — aborting.\n";
        exit(EXIT_FAILURE);
    }

    cout << "\nInitializing OpenSSL...\n";
    setupDtlsContext();
    cout << "OpenSSL initialized.\n";

    cout << "Performing DTLS handshake...\n";
    performHandshake();
    cout << "DTLS 1.2 session established!\n";

    listOfferedCipherSuites();
    reportNegotiatedCipher();

    if (SSL_get_peer_certificate(dtls_conn) &&
        SSL_get_verify_result(dtls_conn) == X509_V_OK)
        cout << "Server (Bob) certificate verified!\n\n";

    runSecureChat("Bob");
}

// ─── Entry point ────────────────────────────────────────────────────────────

int main(int argc, char** argv) {
    cout << unitbuf;   // flush every line so piped logs / pcap demos stay in sync

    if (argc < 2 ||
        (strcmp(argv[1], "-s") != 0 && strcmp(argv[1], "-c") != 0)) {
        printf("Usage:\n");
        printf("  Server: %s -s\n", argv[0]);
        printf("  Client: %s -c <hostname>\n", argv[0]);
        return 1;
    }

    udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sock < 0) {
        perror("Socket creation failed");
        return 1;
    }
    printf("UDP socket created.\n");

    bzero(&peer_addr, sizeof(peer_addr));

    if (strcmp(argv[1], "-s") == 0) {
        runAsServer();
    } else if (strcmp(argv[1], "-c") == 0 && argc == 3) {
        const string ip = resolveHost(argv[2]);
        runAsClient(ip.c_str());
    } else {
        printf("Usage:\n");
        printf("  Server: %s -s\n", argv[0]);
        printf("  Client: %s -c <hostname>\n", argv[0]);
        return 1;
    }

    return 0;
}
