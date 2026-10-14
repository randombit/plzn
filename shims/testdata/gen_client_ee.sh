#!/usr/bin/env bash
# Regenerates the CA-issued test client credentials (client_ee_*) and the
# file-backed server bundles plzn's runtime cannot generate itself
# (`--cert ecdsa-p521`, `--cert rsa-pss`). Run from this directory:
#
#   ./gen_client_ee.sh
#
# Every client credential is an end-entity certificate issued by
# client_ee_ca (whose key is kept here so more can be added later); the shim
# servers trust client_ee_ca.pem. `plzn` picks one with
# `send Certificate { credential: <name> }`:
#
#   client_ee            ECDSA P-256 (the default, `credential: valid`)
#   client_ee_rsa        RSA-2048          (`credential: rsa`)
#   client_ee_rsa_pss    RSA-2048, id-RSASSA-PSS key (`credential: rsa_pss`)
#   client_ee_ecdsa_p384 ECDSA P-384       (`credential: ecdsa_p384`)
#   client_ee_ecdsa_p521 ECDSA P-521       (`credential: ecdsa_p521`)
#   client_ee_ed25519    Ed25519           (`credential: ed25519`)
#
# The server bundles are self-signed for "localhost", like the ones
# `CertBundle::generate` makes at runtime.
set -euo pipefail
cd "$(dirname "$0")"

days=3650
ca_subj="/CN=plzn-client-ca"

# ---- the client CA (ECDSA P-256), key kept for later additions ----
if [ ! -f client_ee_ca_key.pem ]; then
  openssl ecparam -name prime256v1 -genkey -noout -out client_ee_ca_key.pem
fi
openssl req -x509 -new -key client_ee_ca_key.pem -sha256 -days $days \
  -subj "$ca_subj" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out client_ee_ca.pem

issue() {
  # issue <basename> <subject CN> <genpkey args...>
  local base=$1 cn=$2; shift 2
  openssl genpkey "$@" -out "$base"_key.pem
  openssl req -new -key "$base"_key.pem -subj "/CN=$cn" -out "$base".csr
  cat > "$base".ext <<EXT
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
EXT
  openssl x509 -req -in "$base".csr -CA client_ee_ca.pem -CAkey client_ee_ca_key.pem \
    -CAcreateserial -sha256 -days $days -extfile "$base".ext -out "$base"_cert.pem
  openssl x509 -in "$base"_cert.pem -outform DER -out "$base"_cert.der
  openssl pkcs8 -topk8 -nocrypt -in "$base"_key.pem -outform DER -out "$base"_key.pkcs8.der
  rm -f "$base".csr "$base".ext
}

issue client_ee            plzn-client            -algorithm EC -pkeyopt ec_paramgen_curve:P-256
issue client_ee_rsa        plzn-client-rsa        -algorithm RSA -pkeyopt rsa_keygen_bits:2048
issue client_ee_rsa_pss    plzn-client-rsa-pss    -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048
issue client_ee_ecdsa_p384 plzn-client-p384       -algorithm EC -pkeyopt ec_paramgen_curve:P-384
issue client_ee_ecdsa_p521 plzn-client-p521       -algorithm EC -pkeyopt ec_paramgen_curve:P-521
issue client_ee_ed25519    plzn-client-ed25519    -algorithm ED25519
rm -f client_ee_ca.srl

# ---- self-signed server bundles for the key types rcgen cannot make ----
server() {
  # server <basename> <genpkey args...>
  local base=$1; shift
  openssl genpkey "$@" -out "$base"_key.pem
  openssl req -x509 -new -key "$base"_key.pem -sha256 -days $days \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" \
    -addext "basicConstraints=CA:FALSE" \
    -addext "keyUsage=critical,digitalSignature" \
    -addext "extendedKeyUsage=serverAuth" \
    -out "$base"_cert.pem
}
server server_ecdsa_p384 -algorithm EC -pkeyopt ec_paramgen_curve:P-384   # chains track: a second ECDSA curve
server server_ecdsa_p521 -algorithm EC -pkeyopt ec_paramgen_curve:P-521
server server_rsa_pss    -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048
# The run's RSA chain (no per-run keygen): static-RSA key exchange needs
# keyEncipherment on top of digitalSignature (Botan checks: bad_certificate).
server_rsa() {
  local base=$1; shift
  openssl genpkey "$@" -out "$base"_key.pem
  openssl req -x509 -new -key "$base"_key.pem -sha256 -days $days \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" \
    -addext "basicConstraints=CA:FALSE" \
    -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
    -addext "extendedKeyUsage=serverAuth" \
    -out "$base"_cert.pem
}
server_rsa server_rsa_2048 -algorithm RSA -pkeyopt rsa_keygen_bits:2048

echo "regenerated client_ee_* and server_{ecdsa_p384,ecdsa_p521,rsa_pss,rsa_2048}_* in $(pwd)"
