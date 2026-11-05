#!/bin/sh
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
UI_SSL_DIR="${PROJECT_ROOT}/ui-ssl"
KEY_FILE="${UI_SSL_DIR}/server.key"
CERT_FILE="${UI_SSL_DIR}/server.crt"
EXT_FILE="${UI_SSL_DIR}/server-extensions.cnf"

if [ -f "${KEY_FILE}" ] && [ -f "${CERT_FILE}" ]; then
  rm -f "${EXT_FILE}"
  echo "UI SSL certificate already exists in ui-ssl/"
  exit 0
fi

mkdir -p "${UI_SSL_DIR}"

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "${KEY_FILE}"
chmod 600 "${KEY_FILE}"

cat > "${EXT_FILE}" <<EOF
[req]
distinguished_name = dn
x509_extensions = v3_server
prompt = no

[dn]

[v3_server]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

openssl req -x509 -new -nodes \
  -key "${KEY_FILE}" \
  -sha256 \
  -days 825 \
  -out "${CERT_FILE}" \
  -subj "/C=US/ST=Local/L=Local/O=SSL Gen UI/OU=Web Interface/CN=localhost" \
  -config "${EXT_FILE}" \
  -extensions v3_server

chmod 644 "${CERT_FILE}"
rm -f "${EXT_FILE}"
echo "UI SSL certificate created in ui-ssl/"