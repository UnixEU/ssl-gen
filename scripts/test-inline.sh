#!/bin/sh
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TEST_ENV="${PROJECT_ROOT}/.env.test"
TEST_CA_NAME="test-root-ca"
TEST_OUTPUT_DIR="${PROJECT_ROOT}/certs/${TEST_CA_NAME}"

cd "${PROJECT_ROOT}"

cleanup() {
  rm -rf "${TEST_OUTPUT_DIR}"
  rm -f "${TEST_ENV}"
}

trap cleanup EXIT

cp .env.example "${TEST_ENV}"
sed \
  -e "s/^ROOT_CA_NAME=.*/ROOT_CA_NAME=${TEST_CA_NAME}/" \
  -e "s/^CERT_NAME=.*/CERT_NAME=test-local-cert/" \
  -e "s/^FORCE_REGENERATE=.*/FORCE_REGENERATE=yes/" \
  "${TEST_ENV}" > "${TEST_ENV}.tmp"
mv "${TEST_ENV}.tmp" "${TEST_ENV}"

echo "Running certificate generation..."
ENV_FILE="${TEST_ENV}" /bin/sh "${PROJECT_ROOT}/scripts/generate-certs.sh"

required_files="
${TEST_OUTPUT_DIR}/${TEST_CA_NAME}.key
${TEST_OUTPUT_DIR}/${TEST_CA_NAME}.crt
${TEST_OUTPUT_DIR}/test-local-cert.key
${TEST_OUTPUT_DIR}/test-local-cert.csr
${TEST_OUTPUT_DIR}/test-local-cert.crt
${TEST_OUTPUT_DIR}/test-local-cert.pem
${TEST_OUTPUT_DIR}/test-local-cert-fullchain.pem
${TEST_OUTPUT_DIR}/test-local-cert.p12
"

for file in ${required_files}; do
  if [ ! -f "${file}" ]; then
    echo "Error: expected file not found: ${file}" >&2
    exit 1
  fi
done

echo "Verifying certificate chain..."
openssl verify -CAfile "${TEST_OUTPUT_DIR}/${TEST_CA_NAME}.crt" \
  "${TEST_OUTPUT_DIR}/test-local-cert.crt"

echo "Verifying IP SAN entry..."
openssl x509 -in "${TEST_OUTPUT_DIR}/test-local-cert.crt" -noout -ext subjectAltName \
  | grep -q 'IP Address:127.0.0.1'

echo "Testing skip-on-existing behavior..."
sed 's/^FORCE_REGENERATE=.*/FORCE_REGENERATE=no/' "${TEST_ENV}" > "${TEST_ENV}.tmp"
mv "${TEST_ENV}.tmp" "${TEST_ENV}"
ENV_FILE="${TEST_ENV}" /bin/sh "${PROJECT_ROOT}/scripts/generate-certs.sh" | grep -q "already exists"

echo "All tests passed."