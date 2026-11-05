#!/bin/sh
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

is_reserved_dir() {
  case "$1" in
    .git|.github|scripts|webui|ui-ssl|certs|node_modules) return 0 ;;
    .* ) return 0 ;;
    *) return 1 ;;
  esac
}

is_certificate_store() {
  store_name="$1"
  store_path="$1"

  case "${store_name}" in
    "${PROJECT_ROOT}"/*) store_path="${store_name}" ;;
    *) store_path="${PROJECT_ROOT}/${store_name}" ;;
  esac

  store_name=$(basename "${store_path}")
  [ -d "${store_path}" ] || return 1
  [ -f "${store_path}/${store_name}.crt" ] || return 1
  [ -f "${store_path}/${store_name}.key" ] || return 1
}

echo "Resetting project to template defaults..."

if [ -d "${PROJECT_ROOT}/ui-ssl" ]; then
  rm -rf "${PROJECT_ROOT}/ui-ssl"
  echo "  Removed ui-ssl/"
fi

if [ -d "${PROJECT_ROOT}/certs" ]; then
  rm -rf "${PROJECT_ROOT}/certs"
  echo "  Removed certs/"
fi

mkdir -p "${PROJECT_ROOT}/certs"
: > "${PROJECT_ROOT}/certs/.gitkeep"
echo "  Recreated empty certs/"

if [ -f "${PROJECT_ROOT}/.env.test" ]; then
  rm -f "${PROJECT_ROOT}/.env.test"
  echo "  Removed .env.test"
fi

if [ -f "${PROJECT_ROOT}/.env.run" ]; then
  rm -f "${PROJECT_ROOT}/.env.run"
  echo "  Removed .env.run"
fi

if [ -f "${PROJECT_ROOT}/.env" ]; then
  rm -f "${PROJECT_ROOT}/.env"
  echo "  Removed .env"
fi

cp "${PROJECT_ROOT}/.env.example" "${PROJECT_ROOT}/.env"
echo "  Restored .env from .env.example"

for entry in "${PROJECT_ROOT}"/*; do
  [ -e "${entry}" ] || continue

  store_name=$(basename "${entry}")
  if is_reserved_dir "${store_name}"; then
    continue
  fi

  if is_certificate_store "${entry}"; then
    rm -rf "${entry}"
    echo "  Removed legacy certificate store ${store_name}/"
  fi
done

for pattern in "*.key" "*.crt" "*.csr" "*.srl" "*.pem" "*.p12" "*.pfx" "*-extensions.cnf"; do
  for file in ${PROJECT_ROOT}/${pattern}; do
    [ -e "${file}" ] || continue
    rm -f "${file}"
    echo "  Removed $(basename "${file}")"
  done
done

echo ""
echo "Project reset complete."
echo "  - .env restored to defaults"
echo "  - Generated Root CAs and certificates removed from certs/"
echo "  - Web UI TLS material removed (regenerated on next webui start)"
echo ""
echo "Next steps:"
echo "  docker compose up --build -d webui"
echo "  docker compose run --rm ssl-gen generate"