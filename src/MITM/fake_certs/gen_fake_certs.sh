#!/usr/bin/env bash
# Task 4(a): "Trudy hacks into the intermediate CA and issues fake/shadow
# certificates for Alice and Bob."
#
# Produces, next to this script:
#   fake{alice,bob}.key.pem   fake{alice,bob}.csr   fake{alice,bob}.crt
#   fake{alice,bob}-fullchain.pem   (leaf + intermediate, presented on the wire)
#
# Each shadow cert keeps the real subject / SAN / EKU but carries a NEW key
# pair and is re-signed by the intermediate CA (iTS CA 1R3).  Nothing under
# certs/ is modified — the CA serial file is kept local.
set -eu
cd "$(dirname "$0")"

INT_CRT=../../../certs/intermediate/int.crt
INT_KEY=../../../certs/intermediate/int.key.pem
CHAIN=../../../certs/chain.pem

# ---- fakealice : shadow of Alice1.com (RSA-1024, like the real cert) -----
openssl genrsa -out fakealice.key.pem 1024
openssl req -new -key fakealice.key.pem \
  -config ../../../certs/alice/alice.cnf -out fakealice.csr
openssl x509 -req -in fakealice.csr \
  -CA "$INT_CRT" -CAkey "$INT_KEY" -CAserial int.srl -CAcreateserial \
  -days 825 -sha256 \
  -extfile ../../../certs/alice/alice.cnf -extensions v3_alice_req \
  -out fakealice.crt
cat fakealice.crt "$INT_CRT" > fakealice-fullchain.pem

# ---- fakebob : shadow of Bob1.com (EC prime256v1, like the real cert) ---
openssl ecparam -name prime256v1 -genkey -noout -out fakebob.key.pem
openssl req -new -key fakebob.key.pem \
  -config ../../../certs/bob/bob.cnf -out fakebob.csr
openssl x509 -req -in fakebob.csr \
  -CA "$INT_CRT" -CAkey "$INT_KEY" -CAserial int.srl -CAcreateserial \
  -days 825 -sha256 \
  -extfile ../../../certs/bob/bob.cnf -extensions v3_bob_req \
  -out fakebob.crt
cat fakebob.crt "$INT_CRT" > fakebob-fullchain.pem

chmod 600 fakealice.key.pem fakebob.key.pem

echo "=== verification ==="
openssl verify -CAfile "$CHAIN" fakealice.crt
openssl verify -CAfile "$CHAIN" fakebob.crt
for c in fakealice fakebob; do
  echo "-- $c --"
  openssl x509 -in $c.crt -noout -subject -issuer
done
