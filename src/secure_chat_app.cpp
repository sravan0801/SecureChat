// secure_chat_app.cpp
// Task 2 — Peer-to-peer secure chat over DTLS 1.2 (UDP transport)
//
// A minimal two-party messenger: Alice runs the client side, Bob runs the
// server side. Both ends present X.509 certificates and authenticate each
// other before any chat text crosses the wire, and every message afterwards
// travels inside a DTLS 1.2 record layer.
//
// Run:
//   Bob   (server): ./securechat -s
//   Alice (client): ./securechat -c <hostname>
//
// Build:
//   g++ -o securechat secure_chat_app.cpp -lssl -lcrypto -lpthread

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

// Fires off one plain UDP datagram (only for the pre-handshake signaling).
void sendPlainDatagram(const string& payload) {
    sendto(udp_sock, payload.c_str(), payload.length(), MSG_CONFIRM,
           (const struct sockaddr*)&peer_addr, peer_addr_len);
}

// Blocks for one plain UDP datagram (only for the pre-handshake signaling).
string recvPlainDatagram(bool echo) {
    char inbound[BUF_SIZE];
    int n = recvfrom(udp_sock, inbound, BUF_SIZE - 1, MSG_WAITALL,
                     (struct sockaddr*)&peer_addr, &peer_addr_len);
    inbound[n] = '\0';
    if (echo)
        printf("Received: %s\n", inbound);
    return string(inbound);
}

// Pushes one message through the encrypted DTLS session.
void sendEncrypted(const string& text) {
    SSL_write(dtls_conn, text.c_str(), text.length());
}

// ─── DTLS cookie callbacks ───────────────────────────────────────────────────
// The server needs these so OpenSSL can run the stateless DTLS cookie
// exchange, which blunts IP-spoofed handshake floods.

// Hands back a fixed demo cookie (a real deployment would HMAC it).
int onCookieGenerate(SSL*, unsigned char* cookie, unsigned int* len) {
    memcpy(cookie, "ses_co", 6);
    *len = 6;
    return 1;
}

// Accepts whatever cookie the client echoes back (demo only).
int onCookieVerify(SSL*, const unsigned char*, unsigned int) {
    return 1;
}

// ─── Certificate / context configuration ─────────────────────────────────────

// Installs this role's cert + key and turns on mutual certificate checking.
void configureCredentials() {
    const char* certPath;
    const char* keyPath;

    // Alice is the client, Bob is the server — each carries its own pair.
    if (acting_as_client) {
        certPath = "../certs/alice/alice-fullchain.pem";
        keyPath  = "../certs/alice/alice.key.pem";
    } else {
        certPath = "../certs/bob/bob-fullchain.pem";
        keyPath  = "../certs/bob/bob.key.pem";
    }

    // Bring in the certificate and its matching private key.
    if (SSL_CTX_use_certificate_file(dtls_ctx, certPath, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(dtls_ctx, keyPath, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        cerr << "Error loading certificate or private key\n";
        exit(EXIT_FAILURE);
    }

    // Make sure the key actually goes with the certificate.
    if (!SSL_CTX_check_private_key(dtls_ctx)) {
        cerr << "Private key does not match the certificate!\n";
        exit(EXIT_FAILURE);
    }
    cout << "Certificate and private key loaded successfully.\n";

    // Trust anchors so the peer's chain can be validated.
    if (!SSL_CTX_load_verify_locations(dtls_ctx, "../certs/chain.pem", NULL)) {
        ERR_print_errors_fp(stderr);
        cerr << "Failed to load CA chain.\n";
        exit(EXIT_FAILURE);
    }

    // Demand a valid peer certificate on both ends (two-way auth).
    SSL_CTX_set_verify(dtls_ctx,
                       SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       NULL);

    // Offer PFS ciphers only: ECDHE key exchange plus AES-256-GCM AEAD,
    // covering both RSA (Alice) and ECDSA (Bob) server certificates.
    if (SSL_CTX_set_cipher_list(dtls_ctx,
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384") != 1) {
        ERR_print_errors_fp(stderr);
        cerr << "Error setting cipher list.\n";
        exit(EXIT_FAILURE);
    }

    // Turn off session tickets so every connection does a fresh handshake.
    SSL_CTX_set_options(dtls_ctx, SSL_OP_NO_TICKET);
}

// Builds the DTLS 1.2 context and then loads the credentials into it.
void setupDtlsContext() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    ERR_load_crypto_strings();

    // DTLS_method() negotiates a version; we clamp it to 1.2 right below.
    dtls_ctx = SSL_CTX_new(DTLS_method());
    if (!dtls_ctx) {
        perror("Error creating SSL context");
        exit(EXIT_FAILURE);
    }

    // Refuse anything older than DTLS 1.2.
    SSL_CTX_set_min_proto_version(dtls_ctx, DTLS1_2_VERSION);

    SSL_CTX_set_security_level(dtls_ctx, 1);
    SSL_CTX_set_verify(dtls_ctx, SSL_VERIFY_PEER, NULL);

    // No session cache — nothing is resumed, each connection re-handshakes.
    SSL_CTX_set_session_cache_mode(dtls_ctx, SSL_SESS_CACHE_OFF);

    // Only the server wires up the cookie exchange callbacks.
    if (!acting_as_client) {
        SSL_CTX_set_cookie_generate_cb(dtls_ctx, onCookieGenerate);
        SSL_CTX_set_cookie_verify_cb(dtls_ctx, &onCookieVerify);
    }

    configureCredentials();
}

// ─── Cipher suite reporting ──────────────────────────────────────────────────

// Dumps every cipher suite this SSL object is willing to offer.
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

// Prints whichever cipher suite the handshake settled on.
void reportNegotiatedCipher() {
    const char* name = SSL_get_cipher(dtls_conn);
    if (name)
        cout << "Negotiated Cipher Suite: " << name << "\n";
    else
        cout << "Could not retrieve negotiated cipher suite.\n";
}

// ─── DTLS handshake ─────────────────────────────────────────────────────────

// Drives the handshake for whichever role we are:
//   client → SSL_connect()
//   server → DTLSv1_listen() for the cookie round-trip, then SSL_accept()
void performHandshake() {
    dtls_conn = SSL_new(dtls_ctx);

    if (acting_as_client) {
        // Bind the socket straight onto the SSL object.
        SSL_set_fd(dtls_conn, udp_sock);
        int rc = SSL_connect(dtls_conn);
        if (rc <= 0) {
            ERR_print_errors_fp(stderr);
            cerr << "SSL_connect failed! Error code: "
                 << SSL_get_error(dtls_conn, rc) << "\n";
            exit(EXIT_FAILURE);
        }
    } else {
        // Wrap the socket in a datagram BIO before the DTLS layer touches it.
        dgram_bio = BIO_new_dgram(udp_sock, BIO_NOCLOSE);
        BIO_ctrl(dgram_bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &recv_tv);
        if (!dgram_bio) {
            cerr << "Failed to create BIO.\n";
            exit(EXIT_FAILURE);
        }
        SSL_set_bio(dtls_conn, dgram_bio, dgram_bio);

        // Stateless cookie exchange filters out spoofed ClientHellos.
        int rc = DTLSv1_listen(dtls_conn, (BIO_ADDR*)&peer_addr);
        if (rc < 0) {
            ERR_print_errors_fp(stderr);
            cerr << "DTLSv1_listen failed.\n";
            exit(EXIT_FAILURE);
        }
        // Finish the rest of the handshake.
        SSL_accept(dtls_conn);
    }
}

// ─── Reader threads ─────────────────────────────────────────────────────────
// While the main thread waits on stdin, a background thread keeps draining
// inbound DTLS records so incoming chat text shows up immediately.

void serverReaderLoop() {
    while (true) {
        int got = SSL_read(dtls_conn, rx_buf, sizeof(rx_buf));
        if (got <= 0) {
            ERR_print_errors_fp(stderr);
            break;
        }
        rx_buf[got] = '\0';
        cout << "Alice: " << rx_buf << "\n";

        if (strncmp(rx_buf, "exit", 4) == 0) {
            cout << "Connection closed by client.\n";
            break;
        }
    }
}

void clientReaderLoop() {
    while (true) {
        int got = SSL_read(dtls_conn, rx_buf, sizeof(rx_buf));
        if (got <= 0) {
            ERR_print_errors_fp(stderr);
            break;
        }
        rx_buf[got] = '\0';
        cout << "Bob: " << rx_buf << "\n";

        if (strncmp(rx_buf, "exit", 4) == 0) {
            cout << "Connection closed by server.\n";
            break;
        }
    }
}

// ─── Server role (Bob) ──────────────────────────────────────────────────────

void runAsServer() {
    acting_as_client = false;

    struct sockaddr_in local_addr;
    local_addr.sin_family = AF_INET;
    local_addr.sin_port   = htons(CHAT_PORT);

    // Bind to bob1's own address (resolved from the hostname).
    const string ip = resolveHost("bob1");
    local_addr.sin_addr.s_addr = inet_addr(ip.c_str());

    if (bind(udp_sock, (SOCKADDR*)&local_addr, sizeof(local_addr)) != 0) {
        perror("socket bind failed");
        exit(EXIT_FAILURE);
    }
    cout << "Bob is listening on port " << CHAT_PORT << " (" << ip << ")\n\n";

    // ── Plain-text application signaling ────────────────────────────────────
    // A short clear-text exchange agrees to start DTLS before any OpenSSL
    // call runs — a tiny protocol negotiation phase.

    if (recvPlainDatagram(true) != "chat_hello") {
        cerr << "Expected chat_hello from client.\n";
        exit(EXIT_FAILURE);
    }
    cout << "Sending chat_reply_ok\n";
    sendPlainDatagram("chat_reply_ok");

    if (recvPlainDatagram(true) != "chat_START_SSL") {
        cerr << "Expected chat_START_SSL from client.\n";
        exit(EXIT_FAILURE);
    }
    cout << "Sending chat_START_SSL_ACK\n";
    sendPlainDatagram("chat_START_SSL_ACK");

    // ── DTLS setup and handshake ───────────────────────────────────────────
    cout << "\nInitializing OpenSSL...\n";
    setupDtlsContext();
    cout << "OpenSSL initialized.\n";

    cout << "Performing DTLS handshake...\n";
    performHandshake();
    reportNegotiatedCipher();
    cout << "DTLS 1.2 session established!\n";

    // Check Alice's certificate now that the handshake is done.
    if (SSL_get_peer_certificate(dtls_conn) &&
        SSL_get_verify_result(dtls_conn) == X509_V_OK)
        cout << "Client (Alice) certificate verified!\n\n";

    // ── Chat loop ──────────────────────────────────────────────────────────
    cout << "You can start chatting. Type 'exit' to quit.\n";
    thread reader(serverReaderLoop);
    while (true) {
        string line;
        getline(cin, line);
        sendEncrypted(line);
        if (line == "exit") {
            sendPlainDatagram("exit");
            break;
        }
    }
}

// ─── Client role (Alice) ────────────────────────────────────────────────────

void runAsClient(const char* IP) {
    acting_as_client = true;

    peer_addr.sin_family      = AF_INET;
    peer_addr.sin_port        = htons(CHAT_PORT);
    peer_addr.sin_addr.s_addr = inet_addr(IP);

    // connect() on a UDP socket just fixes the default destination.
    if (connect(udp_sock, (struct sockaddr*)&peer_addr, sizeof(peer_addr)) < 0) {
        perror("Error connecting socket");
        exit(EXIT_FAILURE);
    }
    cout << "Alice connected to " << IP << ":" << CHAT_PORT << "\n\n";

    // ── Plain-text application signaling ────────────────────────────────────
    cout << "Sending chat_hello\n";
    sendPlainDatagram("chat_hello");

    if (recvPlainDatagram(true) != "chat_reply_ok") {
        cerr << "Expected chat_reply_ok from server.\n";
        exit(EXIT_FAILURE);
    }

    cout << "Sending chat_START_SSL\n";
    sendPlainDatagram("chat_START_SSL");

    if (recvPlainDatagram(true) != "chat_START_SSL_ACK") {
        cerr << "Expected chat_START_SSL_ACK from server.\n";
        exit(EXIT_FAILURE);
    }

    // ── DTLS setup and handshake ───────────────────────────────────────────
    cout << "\nInitializing OpenSSL...\n";
    setupDtlsContext();
    cout << "OpenSSL initialized.\n";

    cout << "Performing DTLS handshake...\n";
    performHandshake();
    cout << "DTLS 1.2 session established!\n";

    listOfferedCipherSuites();
    reportNegotiatedCipher();

    // Check Bob's certificate now that the handshake is done.
    if (SSL_get_peer_certificate(dtls_conn) &&
        SSL_get_verify_result(dtls_conn) == X509_V_OK)
        cout << "Server (Bob) certificate verified!\n\n";

    // ── Chat loop ──────────────────────────────────────────────────────────
    cout << "You can start chatting. Type 'exit' to quit.\n";
    thread reader(clientReaderLoop);
    while (true) {
        string line;
        getline(cin, line);
        sendEncrypted(line);
        if (line == "exit") {
            sendPlainDatagram("exit");
            break;
        }
    }
}

// ─── Entry point ────────────────────────────────────────────────────────────

int main(int argc, char** argv) {
    if (argc < 2 ||
        (strcmp(argv[1], "-s") != 0 && strcmp(argv[1], "-c") != 0)) {
        printf("Usage:\n");
        printf("  Server: %s -s\n", argv[0]);
        printf("  Client: %s -c <hostname>\n", argv[0]);
        return 1;
    }

    // DTLS rides on UDP, so open a datagram socket.
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
