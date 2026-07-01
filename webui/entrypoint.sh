#!/bin/sh
set -eu

PROJECT_ROOT="${PROJECT_ROOT:-/project}"

/bin/sh "${PROJECT_ROOT}/scripts/ensure-env.sh"
/bin/sh "${PROJECT_ROOT}/scripts/generate-ui-ssl.sh"
exec node /app/server.js