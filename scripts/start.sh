#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ ! -f .env ]]; then
  cp .env.example .env
  echo "Created .env. Edit its secrets, then run this script again."
  exit 1
fi
docker compose build --pull
docker compose up -d
docker compose ps
