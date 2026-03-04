#include "smp_server.hpp"
#include "sam_client.hpp"

#include <csignal>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <thread>
#include <sodium.h>

static smp::SmpServer* g_server = nullptr;
static smp::SamClient* g_sam = nullptr;

static void signalHandler(int) {
    if (g_server) g_server->stop();
    if (g_sam) g_sam->stop();
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

    // Initialize SAM client for I2P
    std::cerr << "[smp] Connecting to SAM bridge..." << std::endl;
    smp::SamClient sam("127.0.0.1", 7656);
    g_sam = &sam;

    if (!sam.connect()) {
        std::cerr << "[smp] Failed to connect to SAM bridge" << std::endl;
        std::cerr << "[smp] Make sure i2pd is running with SAM enabled" << std::endl;
        return 1;
    }

    // Create I2P destination
    std::cerr << "[smp] Creating I2P destination..." << std::endl;
    std::string destination = sam.createSession("simplex-smp", "TRANSIENT");
    if (destination.empty()) {
        std::cerr << "[smp] Failed to create I2P destination" << std::endl;
        return 1;
    }

    std::cerr << "[smp] I2P destination created successfully!" << std::endl;
    std::cerr << "[smp] Check i2pd web console for .b32.i2p address:" << std::endl;
    std::cerr << "[smp]   http://localhost:7070/?page=local_destinations" << std::endl;

    // Start SAM accept loop in background thread
    std::thread samThread([&sam, port]() {
        sam.startAcceptLoop("127.0.0.1", port);
    });

    // Start server
    smp::SmpServer server(store, cert, key, port);
    g_server = &server;

    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    server.run();

    // Stop SAM and wait for thread
    sam.stop();
    if (samThread.joinable()) {
        samThread.join();
    }

    std::cerr << "[smp] Shutdown complete" << std::endl;
    return 0;
}
