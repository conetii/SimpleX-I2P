#include "smp_server.hpp"

#include <csignal>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sodium.h>

static smp::SmpServer* g_server = nullptr;

static void signalHandler(int) {
    if (g_server) g_server->stop();
}

int main(int argc, char* argv[]) {
    // Init libsodium
    if (sodium_init() < 0) {
        std::cerr << "[smp] Failed to initialize libsodium" << std::endl;
        return 1;
    }

    // Read config from env
    const char* dbPath = std::getenv("SMP_DB_PATH");
    const char* dbPass = std::getenv("SMP_DB_PASSWORD");
    const char* portStr = std::getenv("SMP_PORT");
    const char* certPath = std::getenv("SMP_TLS_CERT");
    const char* keyPath = std::getenv("SMP_TLS_KEY");

    std::string db = dbPath ? dbPath : "/data/smp.db";
    std::string pass = dbPass ? dbPass : "";
    uint16_t port = portStr ? static_cast<uint16_t>(std::atoi(portStr)) : 5223;
    std::string cert = certPath ? certPath : "/data/server.crt";
    std::string key = keyPath ? keyPath : "/data/server.key";

    if (pass.empty()) {
        std::cerr << "[smp] SMP_DB_PASSWORD is required" << std::endl;
        return 1;
    }

    // Generate TLS cert if missing
    {
        std::ifstream cf(cert);
        if (!cf.good()) {
            smp::generateSelfSignedCert(cert, key);
        }
    }

    // Open store
    std::cerr << "[smp] Opening database: " << db << std::endl;
    smp::SmpStore store(db, pass);

    // Start server
    smp::SmpServer server(store, cert, key, port);
    g_server = &server;

    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    server.run();

    std::cerr << "[smp] Shutdown complete" << std::endl;
    return 0;
}
