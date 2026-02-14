#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

# Get .b32.i2p address from i2pd web console
for PORT in 7072 7070 7071; do
    ADDR=$(curl -s "http://localhost:${PORT}/?page=local_destinations" 2>/dev/null \
        | grep -oP 'b32=\K[a-z0-9]+' | head -1)
    [ -n "$ADDR" ] && break
done

if [ -z "$ADDR" ]; then
    echo "Could not determine .b32.i2p address."
    echo "i2pd may still be starting. Wait a few minutes and try again."
    exit 1
fi

echo "Your SMP server I2P address:"
echo "  ${ADDR}.b32.i2p"
echo ""

# Get TLS fingerprint (base64url-encoded SHA256 of DER cert)
TMPCERT=$(mktemp)
trap "rm -f $TMPCERT" EXIT

# Try docker cp first, then direct path
CONTAINER=$(docker compose ps -q smp-server 2>/dev/null || true)
if [ -n "$CONTAINER" ]; then
    docker cp "$CONTAINER:/data/server.crt" "$TMPCERT" 2>/dev/null || true
fi

if [ ! -s "$TMPCERT" ] && [ -f /data/server.crt ]; then
    cp /data/server.crt "$TMPCERT"
fi

if [ -s "$TMPCERT" ]; then
    FINGERPRINT=$(openssl x509 -in "$TMPCERT" -outform der 2>/dev/null \
        | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '=')
    echo "SimpleX connection string:"
    echo "  smp://${FINGERPRINT}@${ADDR}.b32.i2p"
else
    echo "SimpleX connection string:"
    echo "  smp://<fingerprint>@${ADDR}.b32.i2p"
    echo ""
    echo "Could not read TLS cert. Get fingerprint manually:"
    echo "  docker compose exec smp-server cat /data/server.crt"
fi
