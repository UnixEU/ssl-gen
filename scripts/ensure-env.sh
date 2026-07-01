#!/bin/sh
set -eu

PROJECT_ROOT="${PROJECT_ROOT:-/project}"

if [ ! -f "${PROJECT_ROOT}/.env" ]; then
  cp "${PROJECT_ROOT}/.env.example" "${PROJECT_ROOT}/.env"
  echo "Created .env from .env.example"
fi