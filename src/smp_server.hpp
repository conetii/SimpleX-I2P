#pragma once

#include "smp_store.hpp"
#include "smp_protocol.hpp"

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <openssl/ssl.h>

namespace smp {

class SmpServer {
public:
    SmpServer(SmpStore& store,
              const std::string& certPath,
              const std::string& keyPath,
              uint16_t port);
    ~SmpServer();

    SmpServer(const SmpServer&) = delete;
    SmpServer& operator=(const SmpServer&) = delete;

    void run();   // Blocking: accept loop
    void stop();  // Signal shutdown

private:
    struct ClientSession {
        SSL* ssl;
        std::vector<uint8_t> session_id;
        // Subscriptions: recipient_id -> active
        std::unordered_map<std::string, bool> subscriptions;
    };

    void handleClient(SSL* ssl, int fd);
    ResponseBlock processCommand(const TransmissionBlock& block, ClientSession& session);

    // Generate random 24-byte ID
    std::vector<uint8_t> generateId();

    SmpStore& store_;
    SSL_CTX* ctx_ = nullptr;
    int listen_fd_ = -1;
    uint16_t port_;
    std::atomic<bool> running_{false};

    // Active subscriptions: key = hex(recipient_id), value = SSL* to push to
    std::mutex subs_mutex_;
    std::unordered_map<std::string, SSL*> subscriptions_;
};

// Generate self-signed TLS certificate if files don't exist
void generateSelfSignedCert(const std::string& certPath, const std::string& keyPath);

} // namespace smp
