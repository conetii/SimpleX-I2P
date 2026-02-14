#include "smp_server.hpp"

#include <arpa/inet.h>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <sodium.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

namespace smp {

namespace {

std::string hexEncode(const std::vector<uint8_t>& data) {
    std::string out;
    out.reserve(data.size() * 2);
    for (uint8_t b : data) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", b);
        out += buf;
    }
    return out;
}

} // anonymous namespace

SmpServer::SmpServer(SmpStore& store,
                     const std::string& certPath,
                     const std::string& keyPath,
                     uint16_t port)
    : store_(store), port_(port) {

    // Init OpenSSL
    ctx_ = SSL_CTX_new(TLS_server_method());
    if (!ctx_) throw std::runtime_error("SSL_CTX_new failed");

    SSL_CTX_set_min_proto_version(ctx_, TLS1_3_VERSION);

    // Set ALPN
    static const unsigned char alpn[] = {4, 's', 'm', 'p', '1'};
    SSL_CTX_set_alpn_protos(ctx_, alpn, sizeof(alpn));

    if (SSL_CTX_use_certificate_file(ctx_, certPath.c_str(), SSL_FILETYPE_PEM) <= 0) {
        throw std::runtime_error("Failed to load TLS certificate: " + certPath);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx_, keyPath.c_str(), SSL_FILETYPE_PEM) <= 0) {
        throw std::runtime_error("Failed to load TLS key: " + keyPath);
    }
}

SmpServer::~SmpServer() {
    stop();
    if (ctx_) SSL_CTX_free(ctx_);
    if (listen_fd_ >= 0) close(listen_fd_);
}

std::vector<uint8_t> SmpServer::generateId() {
    std::vector<uint8_t> id(24);
    randombytes_buf(id.data(), id.size());
    return id;
}

void SmpServer::run() {
    listen_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd_ < 0) throw std::runtime_error("socket() failed");

    int opt = 1;
    setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port_);

    if (bind(listen_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        throw std::runtime_error("bind() failed on port " + std::to_string(port_));
    }
    if (listen(listen_fd_, 16) < 0) {
        throw std::runtime_error("listen() failed");
    }

    running_ = true;
    std::cerr << "[smp] Listening on 0.0.0.0:" << port_ << std::endl;

    while (running_) {
        struct sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(listen_fd_, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) {
            if (!running_) break;
            continue;
        }

        SSL* ssl = SSL_new(ctx_);
        SSL_set_fd(ssl, client_fd);

        // Spawn thread per connection
        std::thread([this, ssl, client_fd]() {
            if (SSL_accept(ssl) <= 0) {
                SSL_free(ssl);
                close(client_fd);
                return;
            }
            handleClient(ssl, client_fd);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client_fd);
        }).detach();
    }
}

void SmpServer::stop() {
    running_ = false;
    if (listen_fd_ >= 0) {
        shutdown(listen_fd_, SHUT_RDWR);
    }
}

void SmpServer::handleClient(SSL* ssl, int /*fd*/) {
    ClientSession session;
    session.ssl = ssl;
    // Generate session ID
    session.session_id.resize(32);
    randombytes_buf(session.session_id.data(), 32);

    while (running_) {
        // Read a full BLOCK_SIZE transmission
        std::vector<uint8_t> buf(BLOCK_SIZE);
        int total = 0;
        while (total < (int)BLOCK_SIZE) {
            int n = SSL_read(ssl, buf.data() + total, BLOCK_SIZE - total);
            if (n <= 0) return; // Connection closed or error
            total += n;
        }

        auto block = parseTransmission(buf);
        if (!block) {
            // Send ERR CMD_SYNTAX
            ResponseBlock rsp;
            rsp.response = RspErr{ErrorCode::CMD_SYNTAX};
            auto out = serializeResponse(rsp);
            SSL_write(ssl, out.data(), (int)out.size());
            continue;
        }

        auto rsp = processCommand(*block, session);
        auto out = serializeResponse(rsp);
        SSL_write(ssl, out.data(), (int)out.size());
    }
}

ResponseBlock SmpServer::processCommand(const TransmissionBlock& block, ClientSession& session) {
    ResponseBlock rsp;
    rsp.corr_id = block.corr_id;
    rsp.entity_id = block.entity_id;

    std::visit([&](auto&& cmd) {
        using T = std::decay_t<decltype(cmd)>;

        if constexpr (std::is_same_v<T, CmdNew>) {
            auto rid = generateId();
            auto sid = generateId();

            // Generate server X25519 keypair
            std::vector<uint8_t> sdhPub(crypto_box_PUBLICKEYBYTES);
            std::vector<uint8_t> sdhPriv(crypto_box_SECRETKEYBYTES);
            crypto_box_keypair(sdhPub.data(), sdhPriv.data());

            if (store_.createQueue(rid, sid, cmd.recipient_key, cmd.recipient_dh_key, sdhPub, sdhPriv)) {
                rsp.entity_id = rid;
                rsp.response = RspIds{rid, sid, sdhPub};
            } else {
                rsp.response = RspErr{ErrorCode::INTERNAL};
            }

        } else if constexpr (std::is_same_v<T, CmdKey>) {
            if (block.entity_id.empty()) {
                rsp.response = RspErr{ErrorCode::NO_QUEUE};
                return;
            }
            if (store_.secureQueue(block.entity_id, cmd.sender_key)) {
                rsp.response = RspOk{};
            } else {
                rsp.response = RspErr{ErrorCode::AUTH};
            }

        } else if constexpr (std::is_same_v<T, CmdSend>) {
            if (block.entity_id.empty()) {
                rsp.response = RspErr{ErrorCode::NO_QUEUE};
                return;
            }
            // Sender uses sender_id to address the queue
            auto queue = store_.getQueue(block.entity_id, false);
            if (!queue || queue->status != "active") {
                rsp.response = RspErr{ErrorCode::NO_QUEUE};
                return;
            }

            auto msgId = generateId();
            int64_t ts = std::time(nullptr);

            if (!store_.pushMessage(queue->recipient_id, msgId, ts, cmd.msg_body)) {
                rsp.response = RspErr{ErrorCode::INTERNAL};
                return;
            }

            // Check if there's an active subscriber to push to
            std::string key = hexEncode(queue->recipient_id);
            {
                std::lock_guard<std::mutex> lock(subs_mutex_);
                auto it = subscriptions_.find(key);
                if (it != subscriptions_.end()) {
                    // Push MSG to subscriber
                    ResponseBlock push;
                    push.entity_id = queue->recipient_id;
                    push.response = RspMsg{msgId, ts, cmd.msg_body};
                    auto out = serializeResponse(push);
                    SSL_write(it->second, out.data(), (int)out.size());
                }
            }

            rsp.response = RspOk{};

        } else if constexpr (std::is_same_v<T, CmdSub>) {
            if (block.entity_id.empty()) {
                rsp.response = RspErr{ErrorCode::NO_QUEUE};
                return;
            }
            std::string key = hexEncode(block.entity_id);
            {
                std::lock_guard<std::mutex> lock(subs_mutex_);
                subscriptions_[key] = session.ssl;
            }
            session.subscriptions[key] = true;
            rsp.response = RspOk{};

        } else if constexpr (std::is_same_v<T, CmdGet>) {
            if (block.entity_id.empty()) {
                rsp.response = RspErr{ErrorCode::NO_QUEUE};
                return;
            }
            auto msg = store_.popMessage(block.entity_id);
            if (msg) {
                rsp.response = RspMsg{msg->msg_id, msg->timestamp, msg->msg_body};
            } else {
                rsp.response = RspOk{}; // No messages
            }

        } else if constexpr (std::is_same_v<T, CmdAck>) {
            if (block.entity_id.empty()) {
                rsp.response = RspErr{ErrorCode::NO_QUEUE};
                return;
            }
            if (store_.ackMessage(block.entity_id, cmd.msg_id)) {
                rsp.response = RspOk{};
            } else {
                rsp.response = RspErr{ErrorCode::NO_MSG};
            }

        } else if constexpr (std::is_same_v<T, CmdOff>) {
            if (block.entity_id.empty()) {
                rsp.response = RspErr{ErrorCode::NO_QUEUE};
                return;
            }
            if (store_.suspendQueue(block.entity_id)) {
                // Remove subscription if any
                std::string key = hexEncode(block.entity_id);
                {
                    std::lock_guard<std::mutex> lock(subs_mutex_);
                    subscriptions_.erase(key);
                }
                rsp.response = RspOk{};
            } else {
                rsp.response = RspErr{ErrorCode::NO_QUEUE};
            }

        } else if constexpr (std::is_same_v<T, CmdDel>) {
            if (block.entity_id.empty()) {
                rsp.response = RspErr{ErrorCode::NO_QUEUE};
                return;
            }
            if (store_.deleteQueue(block.entity_id)) {
                std::string key = hexEncode(block.entity_id);
                {
                    std::lock_guard<std::mutex> lock(subs_mutex_);
                    subscriptions_.erase(key);
                }
                rsp.response = RspOk{};
            } else {
                rsp.response = RspErr{ErrorCode::NO_QUEUE};
            }
        }
    }, block.command);

    return rsp;
}

// Self-signed cert generation
void generateSelfSignedCert(const std::string& certPath, const std::string& keyPath) {
    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_keygen(pctx, &pkey);
    EVP_PKEY_CTX_free(pctx);

    X509* x509 = X509_new();
    X509_set_version(x509, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_getm_notBefore(x509), 0);
    X509_gmtime_adj(X509_getm_notAfter(x509), 365 * 24 * 3600L);
    X509_set_pubkey(x509, pkey);

    X509_NAME* name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        (const unsigned char*)"simplex-i2p-smp", -1, -1, 0);
    X509_set_issuer_name(x509, name);

    X509_sign(x509, pkey, nullptr); // Ed25519 doesn't use a digest

    // Write cert
    FILE* f = fopen(certPath.c_str(), "wb");
    if (f) { PEM_write_X509(f, x509); fclose(f); }

    // Write key
    f = fopen(keyPath.c_str(), "wb");
    if (f) { PEM_write_PrivateKey(f, pkey, nullptr, nullptr, 0, nullptr, nullptr); fclose(f); }

    X509_free(x509);
    EVP_PKEY_free(pkey);

    std::cerr << "[smp] Generated self-signed TLS certificate" << std::endl;
}

} // namespace smp
