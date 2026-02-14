#include "smp_protocol.hpp"
#include <cstring>
#include <stdexcept>
#include <unordered_map>

namespace smp {

namespace {

// Read N bytes from data at offset, advance offset
bool readBytes(const std::vector<uint8_t>& data, size_t& off, size_t n, std::vector<uint8_t>& out) {
    if (off + n > data.size()) return false;
    out.assign(data.begin() + off, data.begin() + off + n);
    off += n;
    return true;
}

// Read a 2-byte big-endian length-prefixed blob
bool readLenPrefixed(const std::vector<uint8_t>& data, size_t& off, std::vector<uint8_t>& out) {
    if (off + 2 > data.size()) return false;
    uint16_t len = (uint16_t(data[off]) << 8) | data[off + 1];
    off += 2;
    return readBytes(data, off, len, out);
}

// Read a command name (space-terminated or end-of-content)
bool readCmdName(const std::vector<uint8_t>& data, size_t& off, std::string& name) {
    size_t start = off;
    while (off < data.size() && data[off] != ' ' && data[off] != '\n' && data[off] != 0) {
        off++;
    }
    if (off == start) return false;
    name.assign(data.begin() + start, data.begin() + off);
    if (off < data.size() && data[off] == ' ') off++; // skip space
    return true;
}

void writeBE16(std::vector<uint8_t>& buf, uint16_t val) {
    buf.push_back(static_cast<uint8_t>(val >> 8));
    buf.push_back(static_cast<uint8_t>(val & 0xFF));
}

void writeBE64(std::vector<uint8_t>& buf, int64_t val) {
    for (int i = 56; i >= 0; i -= 8) {
        buf.push_back(static_cast<uint8_t>((val >> i) & 0xFF));
    }
}

void writeLenPrefixed(std::vector<uint8_t>& buf, const std::vector<uint8_t>& data) {
    writeBE16(buf, static_cast<uint16_t>(data.size()));
    buf.insert(buf.end(), data.begin(), data.end());
}

void writeString(std::vector<uint8_t>& buf, const std::string& s) {
    buf.insert(buf.end(), s.begin(), s.end());
}

} // anonymous namespace

const char* cmdName(CmdType type) {
    switch (type) {
        case CmdType::NEW:  return "NEW";
        case CmdType::KEY:  return "KEY";
        case CmdType::SEND: return "SEND";
        case CmdType::SUB:  return "SUB";
        case CmdType::GET:  return "GET";
        case CmdType::ACK:  return "ACK";
        case CmdType::OFF:  return "OFF";
        case CmdType::DEL:  return "DEL";
        case CmdType::IDS:  return "IDS";
        case CmdType::OK:   return "OK";
        case CmdType::MSG:  return "MSG";
        case CmdType::ERR:  return "ERR";
    }
    return "UNKNOWN";
}

CmdType parseCmdType(const std::string& name) {
    static const std::unordered_map<std::string, CmdType> map = {
        {"NEW", CmdType::NEW}, {"KEY", CmdType::KEY}, {"SEND", CmdType::SEND},
        {"SUB", CmdType::SUB}, {"GET", CmdType::GET}, {"ACK", CmdType::ACK},
        {"OFF", CmdType::OFF}, {"DEL", CmdType::DEL},
    };
    auto it = map.find(name);
    if (it == map.end()) {
        throw std::runtime_error("Unknown command: " + name);
    }
    return it->second;
}

std::optional<TransmissionBlock> parseTransmission(const std::vector<uint8_t>& data) {
    if (data.size() < 4) return std::nullopt;

    size_t off = 0;

    // Read content length (first 2 bytes, big-endian)
    uint16_t contentLen = (uint16_t(data[0]) << 8) | data[1];
    off = 2;

    if (off + contentLen > data.size()) return std::nullopt;

    // Content boundary
    size_t contentEnd = off + contentLen;

    TransmissionBlock block;

    // Session ID: 32 bytes
    if (!readBytes(data, off, 32, block.session_id)) return std::nullopt;

    // Correlation ID: length-prefixed
    if (!readLenPrefixed(data, off, block.corr_id)) return std::nullopt;

    // Entity ID: length-prefixed
    if (!readLenPrefixed(data, off, block.entity_id)) return std::nullopt;

    // Command name
    std::string name;
    if (!readCmdName(data, off, name)) return std::nullopt;

    CmdType type;
    try {
        type = parseCmdType(name);
    } catch (...) {
        return std::nullopt;
    }

    switch (type) {
        case CmdType::NEW: {
            CmdNew cmd;
            if (!readLenPrefixed(data, off, cmd.recipient_key)) return std::nullopt;
            if (!readLenPrefixed(data, off, cmd.recipient_dh_key)) return std::nullopt;
            block.command = cmd;
            break;
        }
        case CmdType::KEY: {
            CmdKey cmd;
            if (!readLenPrefixed(data, off, cmd.sender_key)) return std::nullopt;
            block.command = cmd;
            break;
        }
        case CmdType::SEND: {
            CmdSend cmd;
            // Rest of content is the message body
            size_t remaining = contentEnd - off;
            cmd.msg_body.assign(data.begin() + off, data.begin() + off + remaining);
            off += remaining;
            block.command = cmd;
            break;
        }
        case CmdType::ACK: {
            CmdAck cmd;
            if (!readBytes(data, off, 24, cmd.msg_id)) return std::nullopt;
            block.command = cmd;
            break;
        }
        case CmdType::SUB: block.command = CmdSub{}; break;
        case CmdType::GET: block.command = CmdGet{}; break;
        case CmdType::OFF: block.command = CmdOff{}; break;
        case CmdType::DEL: block.command = CmdDel{}; break;
        default:
            return std::nullopt;
    }

    return block;
}

std::vector<uint8_t> serializeResponse(const ResponseBlock& rsp) {
    // Build content first
    std::vector<uint8_t> content;

    // Correlation ID (length-prefixed)
    writeLenPrefixed(content, rsp.corr_id);

    // Entity ID (length-prefixed)
    writeLenPrefixed(content, rsp.entity_id);

    // Response body
    std::visit([&content](auto&& r) {
        using T = std::decay_t<decltype(r)>;

        if constexpr (std::is_same_v<T, RspIds>) {
            writeString(content, "IDS ");
            writeLenPrefixed(content, r.recipient_id);
            writeLenPrefixed(content, r.sender_id);
            writeLenPrefixed(content, r.server_dh_key);
        } else if constexpr (std::is_same_v<T, RspOk>) {
            writeString(content, "OK");
        } else if constexpr (std::is_same_v<T, RspMsg>) {
            writeString(content, "MSG ");
            content.insert(content.end(), r.msg_id.begin(), r.msg_id.end());
            writeBE64(content, r.timestamp);
            content.insert(content.end(), r.msg_body.begin(), r.msg_body.end());
        } else if constexpr (std::is_same_v<T, RspErr>) {
            writeString(content, "ERR ");
            content.push_back(static_cast<uint8_t>(r.code));
        }
    }, rsp.response);

    // Build final block: 2-byte length + content + padding to BLOCK_SIZE
    std::vector<uint8_t> block;
    block.reserve(BLOCK_SIZE);
    writeBE16(block, static_cast<uint16_t>(content.size()));
    block.insert(block.end(), content.begin(), content.end());

    // Pad to BLOCK_SIZE
    if (block.size() < BLOCK_SIZE) {
        block.resize(BLOCK_SIZE, 0);
    }

    return block;
}

} // namespace smp
