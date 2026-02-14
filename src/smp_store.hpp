#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

struct sqlite3;

namespace smp {

struct QueueRec {
    std::vector<uint8_t> recipient_id;  // 24 bytes
    std::vector<uint8_t> sender_id;     // 24 bytes
    std::vector<uint8_t> recipient_key; // Ed25519 public key
    std::vector<uint8_t> sender_key;    // Ed25519 public key (may be empty)
    std::vector<uint8_t> recipient_dh_key; // X25519 public key
    std::vector<uint8_t> server_dh_key;    // X25519 public key
    std::vector<uint8_t> server_dh_private; // X25519 private key (encrypted)
    std::string status;                 // active | off | deleted
    int64_t created_at;
};

struct Message {
    int64_t id;
    std::vector<uint8_t> queue_recipient_id;
    std::vector<uint8_t> msg_id;  // 24 bytes
    int64_t timestamp;
    std::vector<uint8_t> msg_body;
};

class SmpStore {
public:
    SmpStore(const std::string& path, const std::string& password);
    ~SmpStore();

    SmpStore(const SmpStore&) = delete;
    SmpStore& operator=(const SmpStore&) = delete;

    bool createQueue(const std::vector<uint8_t>& rid,
                     const std::vector<uint8_t>& sid,
                     const std::vector<uint8_t>& rk,
                     const std::vector<uint8_t>& rdh,
                     const std::vector<uint8_t>& sdh,
                     const std::vector<uint8_t>& sdhPriv);

    std::optional<QueueRec> getQueue(const std::vector<uint8_t>& id, bool byRecipient);

    bool secureQueue(const std::vector<uint8_t>& rid,
                     const std::vector<uint8_t>& senderKey);

    bool pushMessage(const std::vector<uint8_t>& rid,
                     const std::vector<uint8_t>& msgId,
                     int64_t timestamp,
                     const std::vector<uint8_t>& body);

    std::optional<Message> popMessage(const std::vector<uint8_t>& rid);

    bool ackMessage(const std::vector<uint8_t>& rid,
                    const std::vector<uint8_t>& msgId);

    bool suspendQueue(const std::vector<uint8_t>& rid);
    bool deleteQueue(const std::vector<uint8_t>& rid);

private:
    void initSchema();
    sqlite3* db_ = nullptr;
};

} // namespace smp
