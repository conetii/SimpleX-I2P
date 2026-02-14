#include "smp_server.hpp"

#include <arpa/inet.h>
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

// SMP protocol version range
static constexpr uint16_t SMP_VERSION_MIN = 6;
static constexpr uint16_t SMP_VERSION_MAX = 17;

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

// Build a padded 16384-byte SMP transport block
// Format: BE16(contentLen) + content + '#' padding
std::vector<uint8_t> padBlock(const std::vector<uint8_t>& content) {
    std::vector<uint8_t> block(BLOCK_SIZE, '#');
    uint16_t len = static_cast<uint16_t>(content.size());
    block[0] = static_cast<uint8_t>(len >> 8);
    block[1] = static_cast<uint8_t>(len & 0xFF);
    std::copy(content.begin(), content.end(), block.begin() + 2);
    return block;
}

// Read exactly n bytes from SSL
bool sslReadExact(SSL* ssl, std::vector<uint8_t>& buf, size_t n) {
    buf.resize(n);
    size_t total = 0;
    while (total < n) {
        int r = SSL_read(ssl, buf.data() + total, static_cast<int>(n - total));
        if (r <= 0) return false;
        total += r;
    }
    return true;
}

// Get TLS tls-unique channel binding (RFC 5929)
// For TLS 1.3, use Finished message as session binding
std::vector<uint8_t> getTlsUnique(SSL* ssl) {
    // For TLS 1.3, tls-unique is not directly available.
    // Use SSL_get_peer_finished / SSL_get_finished as approximation.
    // Server side: getPeerFinished gives the client's Finished message
    uint8_t buf[128];

    // Try getPeerFinished first (what Haskell simplexmq uses for server)
    size_t len = SSL_get_peer_finished(ssl, buf, sizeof(buf));
    if (len > 0) {
        return std::vector<uint8_t>(buf, buf + len);
    }

    // Fallback to getFinished
    len = SSL_get_finished(ssl, buf, sizeof(buf));
    if (len > 0) {
        return std::vector<uint8_t>(buf, buf + len);
    }

    // Last resort: random session ID
    std::vector<uint8_t> sid(32);
    randombytes_buf(sid.data(), sid.size());
    return sid;
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

    // Set ALPN callback (server-side)
    SSL_CTX_set_alpn_select_cb(ctx_, [](SSL*, const unsigned char** out,
            unsigned char* outlen, const unsigned char* in, unsigned int inlen,
            void*) -> int {
        // Look for "smp1" in client's ALPN list
        static const unsigned char smp1[] = {4, 's', 'm', 'p', '1'};
        if (SSL_select_next_proto(const_cast<unsigned char**>(out), outlen,
                smp1, sizeof(smp1), in, inlen) == OPENSSL_NPN_NEGOTIATED) {
            return SSL_TLSEXT_ERR_OK;
        }
        return SSL_TLSEXT_ERR_NOACK;
    }, nullptr);

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

    // Perform SMP handshake
    if (!performHandshake(ssl, session)) {
        std::cerr << "[smp] Handshake failed" << std::endl;
        return;
    }
    std::cerr << "[smp] Handshake complete, sessionId="
              << hexEncode(session.session_id) << std::endl;

    while (running_) {
        // Read a full BLOCK_SIZE transmission
        std::vector<uint8_t> buf;
        if (!sslReadExact(ssl, buf, BLOCK_SIZE)) return;

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

bool SmpServer::performHandshake(SSL* ssl, ClientSession& session) {
    // Step 1: Derive session ID from TLS channel binding
    session.session_id = getTlsUnique(ssl);

    // Step 2: Build ServerHandshake content
    // Format: BE16(minVer) + BE16(maxVer) + byte(sessionIdLen) + sessionId
    std::vector<uint8_t> serverContent;

    // Version range: two BE16 values
    serverContent.push_back(static_cast<uint8_t>(SMP_VERSION_MIN >> 8));
    serverContent.push_back(static_cast<uint8_t>(SMP_VERSION_MIN & 0xFF));
    serverContent.push_back(static_cast<uint8_t>(SMP_VERSION_MAX >> 8));
    serverContent.push_back(static_cast<uint8_t>(SMP_VERSION_MAX & 0xFF));

    // Session ID: 1-byte length prefix + data
    serverContent.push_back(static_cast<uint8_t>(session.session_id.size()));
    serverContent.insert(serverContent.end(),
                         session.session_id.begin(),
                         session.session_id.end());

    // Pad and send server hello
    auto serverBlock = padBlock(serverContent);
    if (SSL_write(ssl, serverBlock.data(), (int)serverBlock.size()) <= 0) {
        return false;
    }

    // Step 3: Read client hello (16384 bytes)
    std::vector<uint8_t> clientBlock;
    if (!sslReadExact(ssl, clientBlock, BLOCK_SIZE)) {
        return false;
    }

    // Parse client hello: BE16(contentLen) + BE16(version) + byte(keyHashLen) + keyHash + ...
    if (clientBlock.size() < 2) return false;
    uint16_t contentLen = (uint16_t(clientBlock[0]) << 8) | clientBlock[1];
    if (contentLen < 4) return false; // at least version + 1 byte keyhash len + something

    size_t off = 2;
    // Client selected version
    uint16_t clientVersion = (uint16_t(clientBlock[off]) << 8) | clientBlock[off + 1];
    off += 2;

    std::cerr << "[smp] Client selected SMP version " << clientVersion << std::endl;

    if (clientVersion < SMP_VERSION_MIN || clientVersion > SMP_VERSION_MAX) {
        std::cerr << "[smp] Unsupported client version: " << clientVersion << std::endl;
        return false;
    }

    // Key hash: 1-byte length prefix + data (we accept but don't validate for now)
    if (off >= 2 + contentLen) return true; // minimal client hello
    uint8_t khLen = clientBlock[off];
    off += 1;
    // Skip key hash bytes
    off += khLen;

    return true;
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
