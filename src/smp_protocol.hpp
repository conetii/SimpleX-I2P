#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace smp {

// SMP command types
enum class CmdType : uint8_t {
    NEW, KEY, SEND, SUB, GET, ACK, OFF, DEL,
    // Server responses
    IDS, OK, MSG, ERR
};

// Error codes
enum class ErrorCode : uint8_t {
    BLOCK_SIZE = 1,
    CMD_SYNTAX = 2,
    AUTH       = 3,
    NO_QUEUE   = 4,
    DUPLICATE  = 5,
    NO_MSG     = 6,
    INTERNAL   = 7,
};

// Parsed SMP commands
struct CmdNew {
    std::vector<uint8_t> recipient_key;    // Ed25519 public key
    std::vector<uint8_t> recipient_dh_key; // X25519 public key
};

struct CmdKey {
    std::vector<uint8_t> sender_key; // Ed25519 public key
};

struct CmdSend {
    std::vector<uint8_t> msg_body;
};

struct CmdAck {
    std::vector<uint8_t> msg_id; // 24 bytes
};

struct CmdSub {};
struct CmdGet {};
struct CmdOff {};
struct CmdDel {};

// Server response structs
struct RspIds {
    std::vector<uint8_t> recipient_id;
    std::vector<uint8_t> sender_id;
    std::vector<uint8_t> server_dh_key;
};

struct RspOk {};

struct RspMsg {
    std::vector<uint8_t> msg_id;
    int64_t timestamp;
    std::vector<uint8_t> msg_body;
};

struct RspErr {
    ErrorCode code;
};

using SmpCommand = std::variant<
    CmdNew, CmdKey, CmdSend, CmdSub, CmdGet, CmdAck, CmdOff, CmdDel>;

using SmpResponse = std::variant<RspIds, RspOk, RspMsg, RspErr>;

// Transmission block (fixed 16384 bytes)
constexpr size_t BLOCK_SIZE = 16384;

struct TransmissionBlock {
    std::vector<uint8_t> session_id;   // 32 bytes
    std::vector<uint8_t> corr_id;      // 24 bytes
    std::vector<uint8_t> entity_id;    // 24 bytes (queue id)
    SmpCommand command;
};

struct ResponseBlock {
    std::vector<uint8_t> corr_id;
    std::vector<uint8_t> entity_id;
    SmpResponse response;
};

// Parse a raw block into a TransmissionBlock
// Returns nullopt on parse error
std::optional<TransmissionBlock> parseTransmission(const std::vector<uint8_t>& data);

// Serialize a response into a padded block
std::vector<uint8_t> serializeResponse(const ResponseBlock& rsp);

// Helpers for command name strings
const char* cmdName(CmdType type);
CmdType parseCmdType(const std::string& name);

} // namespace smp
