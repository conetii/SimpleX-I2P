#include "smp_store.hpp"
#define SQLITE_HAS_CODEC
#include <sqlite3.h>
#include <stdexcept>
#include <ctime>

namespace smp {

namespace {

void check(int rc, sqlite3* db, const char* context) {
    if (rc != SQLITE_OK && rc != SQLITE_DONE && rc != SQLITE_ROW) {
        std::string msg = std::string(context) + ": " + sqlite3_errmsg(db);
        throw std::runtime_error(msg);
    }
}

std::vector<uint8_t> blobCol(sqlite3_stmt* stmt, int col) {
    auto ptr = static_cast<const uint8_t*>(sqlite3_column_blob(stmt, col));
    int len = sqlite3_column_bytes(stmt, col);
    if (!ptr || len <= 0) return {};
    return {ptr, ptr + len};
}

std::string textCol(sqlite3_stmt* stmt, int col) {
    auto ptr = reinterpret_cast<const char*>(sqlite3_column_text(stmt, col));
    if (!ptr) return {};
    return ptr;
}

// RAII wrapper for sqlite3_stmt
struct Stmt {
    sqlite3_stmt* s = nullptr;
    Stmt(sqlite3* db, const char* sql) {
        check(sqlite3_prepare_v2(db, sql, -1, &s, nullptr), db, "prepare");
    }
    ~Stmt() { if (s) sqlite3_finalize(s); }
    Stmt(const Stmt&) = delete;
    Stmt& operator=(const Stmt&) = delete;
    operator sqlite3_stmt*() { return s; }
};

} // anonymous namespace

SmpStore::SmpStore(const std::string& path, const std::string& password) {
    int rc = sqlite3_open(path.c_str(), &db_);
    if (rc != SQLITE_OK) {
        throw std::runtime_error("Failed to open database: " + path);
    }
    // Set encryption key
    rc = sqlite3_key(db_, password.c_str(), static_cast<int>(password.size()));
    check(rc, db_, "sqlite3_key");

    // Verify the key works
    Stmt verify(db_, "SELECT count(*) FROM sqlite_master");
    rc = sqlite3_step(verify);
    if (rc != SQLITE_ROW) {
        throw std::runtime_error("Invalid database password or corrupt database");
    }

    initSchema();
}

SmpStore::~SmpStore() {
    if (db_) sqlite3_close(db_);
}

void SmpStore::initSchema() {
    const char* sql = R"(
        CREATE TABLE IF NOT EXISTS queues (
            recipient_id BLOB PRIMARY KEY,
            sender_id BLOB UNIQUE NOT NULL,
            recipient_key BLOB NOT NULL,
            sender_key BLOB,
            recipient_dh_key BLOB NOT NULL,
            server_dh_key BLOB NOT NULL,
            server_dh_private BLOB NOT NULL,
            status TEXT DEFAULT 'active',
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            queue_recipient_id BLOB NOT NULL REFERENCES queues(recipient_id),
            msg_id BLOB NOT NULL,
            timestamp INTEGER NOT NULL,
            msg_body BLOB NOT NULL,
            UNIQUE(queue_recipient_id, msg_id)
        );

        CREATE INDEX IF NOT EXISTS idx_messages_queue
            ON messages(queue_recipient_id, id);
    )";
    char* err = nullptr;
    int rc = sqlite3_exec(db_, sql, nullptr, nullptr, &err);
    if (rc != SQLITE_OK) {
        std::string msg = err ? err : "unknown error";
        sqlite3_free(err);
        throw std::runtime_error("initSchema: " + msg);
    }
}

bool SmpStore::createQueue(const std::vector<uint8_t>& rid,
                           const std::vector<uint8_t>& sid,
                           const std::vector<uint8_t>& rk,
                           const std::vector<uint8_t>& rdh,
                           const std::vector<uint8_t>& sdh,
                           const std::vector<uint8_t>& sdhPriv) {
    Stmt stmt(db_,
        "INSERT INTO queues (recipient_id, sender_id, recipient_key, "
        "recipient_dh_key, server_dh_key, server_dh_private, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)");

    sqlite3_bind_blob(stmt, 1, rid.data(), (int)rid.size(), SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, sid.data(), (int)sid.size(), SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 3, rk.data(), (int)rk.size(), SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 4, rdh.data(), (int)rdh.size(), SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 5, sdh.data(), (int)sdh.size(), SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 6, sdhPriv.data(), (int)sdhPriv.size(), SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 7, std::time(nullptr));

    return sqlite3_step(stmt) == SQLITE_DONE;
}

std::optional<QueueRec> SmpStore::getQueue(const std::vector<uint8_t>& id, bool byRecipient) {
    const char* sql = byRecipient
        ? "SELECT * FROM queues WHERE recipient_id = ?"
        : "SELECT * FROM queues WHERE sender_id = ?";

    Stmt stmt(db_, sql);
    sqlite3_bind_blob(stmt, 1, id.data(), (int)id.size(), SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_ROW) return std::nullopt;

    QueueRec q;
    q.recipient_id     = blobCol(stmt, 0);
    q.sender_id        = blobCol(stmt, 1);
    q.recipient_key    = blobCol(stmt, 2);
    q.sender_key       = blobCol(stmt, 3);
    q.recipient_dh_key = blobCol(stmt, 4);
    q.server_dh_key    = blobCol(stmt, 5);
    q.server_dh_private = blobCol(stmt, 6);
    q.status           = textCol(stmt, 7);
    q.created_at       = sqlite3_column_int64(stmt, 8);
    return q;
}

bool SmpStore::secureQueue(const std::vector<uint8_t>& rid,
                           const std::vector<uint8_t>& senderKey) {
    Stmt stmt(db_,
        "UPDATE queues SET sender_key = ? WHERE recipient_id = ? AND sender_key IS NULL");
    sqlite3_bind_blob(stmt, 1, senderKey.data(), (int)senderKey.size(), SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, rid.data(), (int)rid.size(), SQLITE_STATIC);
    return sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(db_) > 0;
}

bool SmpStore::pushMessage(const std::vector<uint8_t>& rid,
                           const std::vector<uint8_t>& msgId,
                           int64_t timestamp,
                           const std::vector<uint8_t>& body) {
    Stmt stmt(db_,
        "INSERT INTO messages (queue_recipient_id, msg_id, timestamp, msg_body) "
        "VALUES (?, ?, ?, ?)");
    sqlite3_bind_blob(stmt, 1, rid.data(), (int)rid.size(), SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, msgId.data(), (int)msgId.size(), SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, timestamp);
    sqlite3_bind_blob(stmt, 4, body.data(), (int)body.size(), SQLITE_STATIC);
    return sqlite3_step(stmt) == SQLITE_DONE;
}

std::optional<Message> SmpStore::popMessage(const std::vector<uint8_t>& rid) {
    Stmt stmt(db_,
        "SELECT id, queue_recipient_id, msg_id, timestamp, msg_body "
        "FROM messages WHERE queue_recipient_id = ? ORDER BY id ASC LIMIT 1");
    sqlite3_bind_blob(stmt, 1, rid.data(), (int)rid.size(), SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_ROW) return std::nullopt;

    Message m;
    m.id                 = sqlite3_column_int64(stmt, 0);
    m.queue_recipient_id = blobCol(stmt, 1);
    m.msg_id             = blobCol(stmt, 2);
    m.timestamp          = sqlite3_column_int64(stmt, 3);
    m.msg_body           = blobCol(stmt, 4);
    return m;
}

bool SmpStore::ackMessage(const std::vector<uint8_t>& rid,
                          const std::vector<uint8_t>& msgId) {
    Stmt stmt(db_,
        "DELETE FROM messages WHERE queue_recipient_id = ? AND msg_id = ?");
    sqlite3_bind_blob(stmt, 1, rid.data(), (int)rid.size(), SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, msgId.data(), (int)msgId.size(), SQLITE_STATIC);
    return sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(db_) > 0;
}

bool SmpStore::suspendQueue(const std::vector<uint8_t>& rid) {
    Stmt stmt(db_,
        "UPDATE queues SET status = 'off' WHERE recipient_id = ? AND status = 'active'");
    sqlite3_bind_blob(stmt, 1, rid.data(), (int)rid.size(), SQLITE_STATIC);
    return sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(db_) > 0;
}

bool SmpStore::deleteQueue(const std::vector<uint8_t>& rid) {
    // Delete messages first, then the queue
    {
        Stmt stmt(db_, "DELETE FROM messages WHERE queue_recipient_id = ?");
        sqlite3_bind_blob(stmt, 1, rid.data(), (int)rid.size(), SQLITE_STATIC);
        sqlite3_step(stmt);
    }
    Stmt stmt(db_,
        "UPDATE queues SET status = 'deleted' WHERE recipient_id = ?");
    sqlite3_bind_blob(stmt, 1, rid.data(), (int)rid.size(), SQLITE_STATIC);
    return sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(db_) > 0;
}

} // namespace smp
