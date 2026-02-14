#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [ ! -f .env ]; then
    echo "[setup] Generating .env with random SMP_DB_PASSWORD..."
    password=$(openssl rand -base64 32)
    cat > .env <<EOF
SMP_DB_PASSWORD=${password}
SMP_PORT=5223
SMP_DB_PATH=/data/smp.db
SMP_TLS_CERT=/data/server.crt
SMP_TLS_KEY=/data/server.key
EOF
    echo "[setup] .env created"
else
    echo "[setup] .env already exists, skipping"
fi

echo "[setup] Starting containers..."
docker compose up -d --build

echo "[setup] Done. Run ./scripts/show-address.sh to get your .b32.i2p address."
