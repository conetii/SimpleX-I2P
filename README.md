# SimpleX-I2P

SMP-compatible messaging server over I2P with encrypted storage.

A C++ implementation of the SimpleX Messaging Protocol (SMP) server that runs as an I2P hidden service. Messages are stored in SQLCipher (encrypted SQLite).

## Quick Start

```bash
# First-time setup: generates .env with random DB password, starts containers
./scripts/setup.sh

# Show your .b32.i2p address (available after i2pd tunnel is ready)
./scripts/show-address.sh
```

## Architecture

- **i2pd** container — I2P router creating an inbound tunnel to the SMP server
- **simplex-i2p-smp** container — C++ SMP server with SQLCipher storage

Clients connect via `smp://fingerprint@address.b32.i2p` through an I2P SOCKS proxy.

## Building Locally

```bash
# Dependencies: cmake, g++, libssl-dev, libsqlcipher-dev, libsodium-dev
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build
```

## Docker

```bash
docker compose up --build
```

## Configuration

Copy `.env.example` to `.env` and adjust values, or use `scripts/setup.sh` for automatic setup.

## SMP Commands Supported

| Command | Description |
|---------|-------------|
| NEW     | Create a new message queue |
| KEY     | Secure queue with sender key |
| SEND    | Send message to queue |
| SUB     | Subscribe to queue (push) |
| GET     | Get next message (pull) |
| ACK     | Acknowledge message |
| OFF     | Suspend queue |
| DEL     | Delete queue |
