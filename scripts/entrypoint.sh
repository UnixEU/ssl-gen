#!/bin/sh
set -eu

PROJECT_ROOT="${PROJECT_ROOT:-/project}"
cd "${PROJECT_ROOT}"

cmd="${1:-generate}"

case "${cmd}" in
  setup)
    /bin/sh "${PROJECT_ROOT}/scripts/ensure-env.sh"
    ;;
  generate)
    /bin/sh "${PROJECT_ROOT}/scripts/ensure-env.sh"
    exec /bin/sh "${PROJECT_ROOT}/scripts/generate-certs.sh"
    ;;
  test)
    # test-inline.sh copies .env.example to .env.test and does not read .env
    exec /bin/sh "${PROJECT_ROOT}/scripts/test-inline.sh"
    ;;
  reset)
    exec /bin/sh "${PROJECT_ROOT}/scripts/reset-project.sh"
    ;;
  *)
    echo "Unknown command: ${cmd}" >&2
    echo "Usage: docker compose run --rm ssl-gen [setup|generate|test|reset]" >&2
    exit 1
    ;;
esac