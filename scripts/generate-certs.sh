#!/bin/sh
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${ENV_FILE:-${PROJECT_ROOT}/.env}"

fail() {
  echo "Error: $1" >&2
  exit 1
}

trim() {
  printf '%s\n' "$1" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

is_truthy() {
  case "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" in
    1|yes|true) return 0 ;;
    *) return 1 ;;
  esac
}

is_ipv4() {
  echo "$1" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$'
}

is_ipv6() {
  echo "$1" | grep -Eq '^[0-9a-fA-F:]+$' && echo "$1" | grep -q ':'
}

is_ip() {
  is_ipv4 "$1" || is_ipv6 "$1"
}

load_env() {
  env_file="$1"
  while IFS= read -r line || [ -n "${line}" ]; do
    case "${line}" in
      ''|'#'*) continue ;;
    esac

    line=$(printf '%s\n' "${line}" | sed 's/^[[:space:]]*export[[:space:]]*//')
    key=${line%%=*}
    value=${line#*=}

    key=$(trim "${key}")
    value=$(trim "${value}")

    case "${value}" in
      \"*\") value=${value#\"}; value=${value%\"} ;;
      \'*\') value=${value#\'}; value=${value%\'} ;;
    esac

    if [ -n "${key}" ]; then
      export "${key}=${value}"
    fi
  done < "${env_file}"
}

validate_country() {
  label="$1"
  value="$2"
  echo "${value}" | grep -Eq '^[A-Za-z]{2}$' \
    || fail "${label} must be a two-letter country code (e.g. US)"
}

validate_positive_int() {
  label="$1"
  value="$2"
  echo "${value}" | grep -Eq '^[0-9]+$' \
    || fail "${label} must be a positive integer"
  [ "${value}" -gt 0 ] || fail "${label} must be greater than 0"
}

validate_safe_name() {
  label="$1"
  value="$2"
  echo "${value}" | grep -Eq '^[a-zA-Z0-9._-]+$' \
    || fail "${label} may only contain letters, numbers, dots, underscores, and hyphens"
}

append_san_entry() {
  entry="$1"
  if is_ip "${entry}"; then
    echo "IP.${ip_index} = ${entry}" >> "${EXT_FILE}"
    ip_index=$((ip_index + 1))
    has_san=1
  else
    echo "DNS.${dns_index} = ${entry}" >> "${EXT_FILE}"
    dns_index=$((dns_index + 1))
    has_san=1
  fi
}

process_csv_entries() {
  csv_value="$1"
  OLD_IFS="${IFS}"
  IFS=','
  for entry in ${csv_value}; do
    entry=$(trim "${entry}")
    if [ -n "${entry}" ]; then
      append_san_entry "${entry}"
    fi
  done
  IFS="${OLD_IFS}"
}

generate_private_key() {
  output_key="$1"
  role="$2"

  if [ "${KEY_TYPE}" = "rsa" ]; then
    bits=4096
    [ "${role}" = "cert" ] && bits=2048
    if [ -n "${passphrase}" ]; then
      openssl genrsa -aes256 -passout pass:"${passphrase}" -out "${output_key}" "${bits}"
    else
      openssl genrsa -out "${output_key}" "${bits}"
    fi
  else
    if [ -n "${passphrase}" ]; then
      openssl genpkey -algorithm EC -aes256 -pass pass:"${passphrase}" \
        -pkeyopt ec_paramgen_curve:prime256v1 -out "${output_key}"
    else
      openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "${output_key}"
    fi
  fi
  chmod 600 "${output_key}"
}

openssl_ca_sign_args() {
  if [ -n "${ROOT_CA_PASSPHRASE:-}" ]; then
    printf '%s' "-passin pass:${ROOT_CA_PASSPHRASE}"
  fi
}

print_cert_dates() {
  label="$1"
  cert_path="$2"
  start_date=$(openssl x509 -in "${cert_path}" -noout -startdate | sed 's/notBefore=//')
  end_date=$(openssl x509 -in "${cert_path}" -noout -enddate | sed 's/notAfter=//')
  echo "  ${label}:"
  echo "    Valid from: ${start_date}"
  echo "    Valid until: ${end_date}"
}

if [ -f "${ENV_FILE}" ]; then
  load_env "${ENV_FILE}"
else
  fail ".env file not found at ${ENV_FILE}. Run 'docker compose run --rm ssl-gen setup' or start the web UI to create it from .env.example."
fi

require_var() {
  var_name="$1"
  eval "value=\${$var_name:-}"
  if [ -z "${value}" ]; then
    fail "required variable '${var_name}' is not set in .env"
  fi
}

require_var ROOT_CA_NAME
require_var ROOT_CA_COUNTRY
require_var ROOT_CA_STATE
require_var ROOT_CA_LOCALITY
require_var ROOT_CA_ORGANIZATION
require_var ROOT_CA_ORGANIZATIONAL_UNIT
require_var ROOT_CA_COMMON_NAME
require_var ROOT_CA_VALIDITY_DAYS
require_var CERT_NAME
require_var CERT_COUNTRY
require_var CERT_STATE
require_var CERT_LOCALITY
require_var CERT_ORGANIZATION
require_var CERT_ORGANIZATIONAL_UNIT
require_var CERT_COMMON_NAME
require_var CERT_DNS_NAMES
require_var CERT_VALIDITY_DAYS

KEY_TYPE="${KEY_TYPE:-ec}"
FORCE_REGENERATE="${FORCE_REGENERATE:-no}"
EXPORT_P12="${EXPORT_P12:-yes}"
P12_PASSWORD="${P12_PASSWORD:-changeit}"
CERT_IP_ADDRESSES="${CERT_IP_ADDRESSES:-}"
ROOT_CA_PASSPHRASE="${ROOT_CA_PASSPHRASE:-}"

case "${KEY_TYPE}" in
  ec|rsa) ;;
  *) fail "KEY_TYPE must be 'ec' or 'rsa'" ;;
esac

validate_safe_name "ROOT_CA_NAME" "${ROOT_CA_NAME}"
validate_safe_name "CERT_NAME" "${CERT_NAME}"
validate_country "ROOT_CA_COUNTRY" "${ROOT_CA_COUNTRY}"
validate_country "CERT_COUNTRY" "${CERT_COUNTRY}"
validate_positive_int "ROOT_CA_VALIDITY_DAYS" "${ROOT_CA_VALIDITY_DAYS}"
validate_positive_int "CERT_VALIDITY_DAYS" "${CERT_VALIDITY_DAYS}"

CERTS_DIR="${PROJECT_ROOT}/certs"
OUTPUT_DIR="${CERTS_DIR}/${ROOT_CA_NAME}"
mkdir -p "${OUTPUT_DIR}"

ROOT_CA_KEY="${OUTPUT_DIR}/${ROOT_CA_NAME}.key"
ROOT_CA_CERT="${OUTPUT_DIR}/${ROOT_CA_NAME}.crt"
CA_EXT_FILE="${OUTPUT_DIR}/${ROOT_CA_NAME}-extensions.cnf"
CERT_KEY="${OUTPUT_DIR}/${CERT_NAME}.key"
CERT_CSR="${OUTPUT_DIR}/${CERT_NAME}.csr"
CERT_CRT="${OUTPUT_DIR}/${CERT_NAME}.crt"
CERT_PEM="${OUTPUT_DIR}/${CERT_NAME}.pem"
CERT_FULLCHAIN="${OUTPUT_DIR}/${CERT_NAME}-fullchain.pem"
CERT_P12="${OUTPUT_DIR}/${CERT_NAME}.p12"
EXT_FILE="${OUTPUT_DIR}/${CERT_NAME}-extensions.cnf"

root_ca_subject="/C=${ROOT_CA_COUNTRY}/ST=${ROOT_CA_STATE}/L=${ROOT_CA_LOCALITY}/O=${ROOT_CA_ORGANIZATION}/OU=${ROOT_CA_ORGANIZATIONAL_UNIT}/CN=${ROOT_CA_COMMON_NAME}"
cert_subject="/C=${CERT_COUNTRY}/ST=${CERT_STATE}/L=${CERT_LOCALITY}/O=${CERT_ORGANIZATION}/OU=${CERT_ORGANIZATIONAL_UNIT}/CN=${CERT_COMMON_NAME}"

cn_in_san=0
OLD_IFS="${IFS}"
IFS=','
for entry in ${CERT_DNS_NAMES}; do
  entry=$(trim "${entry}")
  if [ "${entry}" = "${CERT_COMMON_NAME}" ]; then
    cn_in_san=1
    break
  fi
done
IFS="${OLD_IFS}"
[ "${cn_in_san}" -eq 1 ] || fail "CERT_COMMON_NAME (${CERT_COMMON_NAME}) must appear in CERT_DNS_NAMES"

if [ -f "${CERT_CRT}" ] && [ -f "${CERT_KEY}" ]; then
  if is_truthy "${FORCE_REGENERATE}"; then
    echo "FORCE_REGENERATE enabled — overwriting existing certificate '${CERT_NAME}'."
  else
    echo "Certificate '${CERT_NAME}' already exists in '${OUTPUT_DIR}'."
    echo "Set FORCE_REGENERATE=yes in .env to overwrite."
    exit 0
  fi
fi

if [ -f "${ROOT_CA_KEY}" ] && [ -f "${ROOT_CA_CERT}" ]; then
  echo "Found existing Root CA in '${OUTPUT_DIR}'. Reusing it."
  if [ -n "${ROOT_CA_PASSPHRASE}" ]; then
    openssl pkey -in "${ROOT_CA_KEY}" -passin pass:"${ROOT_CA_PASSPHRASE}" -noout >/dev/null 2>&1 \
      || fail "Could not unlock existing Root CA key. Check ROOT_CA_PASSPHRASE."
  fi
else
  echo "Generating new Root CA '${ROOT_CA_NAME}' (${KEY_TYPE} key)..."
  passphrase="${ROOT_CA_PASSPHRASE}"
  generate_private_key "${ROOT_CA_KEY}" "ca"

  cat > "${CA_EXT_FILE}" <<EOF
[req]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no

[dn]

[v3_ca]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
EOF

  if [ -n "${ROOT_CA_PASSPHRASE}" ]; then
    openssl req -x509 -new \
      -key "${ROOT_CA_KEY}" \
      -passin pass:"${ROOT_CA_PASSPHRASE}" \
      -sha256 \
      -days "${ROOT_CA_VALIDITY_DAYS}" \
      -out "${ROOT_CA_CERT}" \
      -subj "${root_ca_subject}" \
      -config "${CA_EXT_FILE}" \
      -extensions v3_ca
  else
    openssl req -x509 -new -nodes \
      -key "${ROOT_CA_KEY}" \
      -sha256 \
      -days "${ROOT_CA_VALIDITY_DAYS}" \
      -out "${ROOT_CA_CERT}" \
      -subj "${root_ca_subject}" \
      -config "${CA_EXT_FILE}" \
      -extensions v3_ca
  fi
  echo "Root CA created: ${ROOT_CA_CERT}"
fi

cat > "${EXT_FILE}" <<EOF
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
EOF

dns_index=1
ip_index=1
has_san=0
process_csv_entries "${CERT_DNS_NAMES}"
if [ -n "${CERT_IP_ADDRESSES}" ]; then
  process_csv_entries "${CERT_IP_ADDRESSES}"
fi
[ "${has_san}" -eq 1 ] || fail "At least one SAN entry (DNS or IP) is required in CERT_DNS_NAMES or CERT_IP_ADDRESSES"

echo "Generating certificate '${CERT_NAME}' (${KEY_TYPE} key)..."
passphrase=""
generate_private_key "${CERT_KEY}" "cert"

openssl req -new \
  -key "${CERT_KEY}" \
  -out "${CERT_CSR}" \
  -subj "${cert_subject}"

sign_pass_arg=$(openssl_ca_sign_args)
# shellcheck disable=SC2086
openssl x509 -req \
  -in "${CERT_CSR}" \
  -CA "${ROOT_CA_CERT}" \
  -CAkey "${ROOT_CA_KEY}" \
  ${sign_pass_arg} \
  -CAcreateserial \
  -out "${CERT_CRT}" \
  -days "${CERT_VALIDITY_DAYS}" \
  -sha256 \
  -extfile "${EXT_FILE}"

cp "${CERT_CRT}" "${CERT_PEM}"
cat "${CERT_CRT}" "${ROOT_CA_CERT}" > "${CERT_FULLCHAIN}"

if is_truthy "${EXPORT_P12}"; then
  openssl pkcs12 -export \
    -out "${CERT_P12}" \
    -inkey "${CERT_KEY}" \
    -in "${CERT_CRT}" \
    -certfile "${ROOT_CA_CERT}" \
    -passout pass:"${P12_PASSWORD}"
  chmod 600 "${CERT_P12}"
fi

openssl verify -CAfile "${ROOT_CA_CERT}" "${CERT_CRT}" >/dev/null \
  || fail "Generated certificate failed openssl verify"

relative_output="./certs/${ROOT_CA_NAME}"
relative_root_ca="${relative_output}/${ROOT_CA_NAME}.crt"

echo ""
echo "Certificate generation complete."
echo "Output directory: ${OUTPUT_DIR}"
echo "  Root CA:     ${ROOT_CA_CERT}"
echo "  Key:         ${CERT_KEY}"
echo "  CSR:         ${CERT_CSR}"
echo "  Cert:        ${CERT_CRT}"
echo "  PEM:         ${CERT_PEM}"
echo "  Full chain:  ${CERT_FULLCHAIN}"
if is_truthy "${EXPORT_P12}"; then
  echo "  PKCS#12:     ${CERT_P12} (password: ${P12_PASSWORD})"
fi
echo ""
echo "Validity:"
print_cert_dates "Root CA" "${ROOT_CA_CERT}"
print_cert_dates "Certificate" "${CERT_CRT}"
echo ""
echo "Trust the Root CA:"
echo "  macOS:"
echo "    sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ${relative_root_ca}"
echo "  Linux (Debian/Ubuntu):"
echo "    sudo cp ${relative_root_ca} /usr/local/share/ca-certificates/${ROOT_CA_NAME}.crt"
echo "    sudo update-ca-certificates"
echo "  Windows:"
echo "    Import ${relative_root_ca} into Trusted Root Certification Authorities via certmgr.msc"