#!/usr/bin/env bash
set -euo pipefail

# Read the destination from i2pd volume and compute .b32.i2p address
CONTAINER=$(docker compose ps -q i2pd 2>/dev/null || true)

if [ -z "$CONTAINER" ]; then
    echo "Error: i2pd container is not running. Run ./scripts/setup.sh first."
    exit 1
fi

# The tunnel key file contains the destination
DEST=$(docker exec "$CONTAINER" sh -c \
    'if [ -f /var/lib/i2pd/simplex-smp.dat ]; then
        head -c 387 /var/lib/i2pd/simplex-smp.dat | base64 -w0
    fi' 2>/dev/null)

if [ -z "$DEST" ]; then
    echo "Tunnel key not yet generated. Wait for i2pd to start and try again."
    echo "Check status: docker compose logs i2pd"
    exit 1
fi

# Compute b32 address from destination hash
ADDR=$(docker exec "$CONTAINER" sh -c \
    'cat /var/lib/i2pd/simplex-smp.dat 2>/dev/null | head -c 387 | sha256sum | cut -d" " -f1 | xxd -r -p | base32 | tr "A-Z" "a-z" | tr -d "="' 2>/dev/null)

if [ -n "$ADDR" ]; then
    echo "Your SMP server I2P address:"
    echo "  ${ADDR}.b32.i2p"
    echo ""
    echo "SimpleX connection string:"
    echo "  smp://<fingerprint>@${ADDR}.b32.i2p:5223"
else
    echo "Could not compute address. Check i2pd logs:"
    echo "  docker compose logs i2pd"
fi
