#include "smp_protocol.hpp"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <vector>

using namespace smp;

// Helper: build a minimal transmission block for testing
static std::vector<uint8_t> buildBlock(
    const std::vector<uint8_t>& sessionId,
    const std::vector<uint8_t>& corrId,
    const std::vector<uint8_t>& entityId,
    const std::string& cmdName,
    const std::vector<uint8_t>& cmdPayload = {})
{
    // Build content: sessionId(32) + len+corrId + len+entityId + cmd + payload
    std::vector<uint8_t> content;

    // Session ID (32 bytes, padded)
    content.insert(content.end(), sessionId.begin(), sessionId.end());
    content.resize(32, 0); // pad to 32

    // Correlation ID (length-prefixed, 2 bytes BE)
    uint16_t clen = static_cast<uint16_t>(corrId.size());
    content.push_back(static_cast<uint8_t>(clen >> 8));
    content.push_back(static_cast<uint8_t>(clen & 0xFF));
    content.insert(content.end(), corrId.begin(), corrId.end());

    // Entity ID (length-prefixed)
    uint16_t elen = static_cast<uint16_t>(entityId.size());
    content.push_back(static_cast<uint8_t>(elen >> 8));
    content.push_back(static_cast<uint8_t>(elen & 0xFF));
    content.insert(content.end(), entityId.begin(), entityId.end());

    // Command name
    content.insert(content.end(), cmdName.begin(), cmdName.end());

    // Space + payload if present
    if (!cmdPayload.empty()) {
        content.push_back(' ');
        content.insert(content.end(), cmdPayload.begin(), cmdPayload.end());
    }

    // Build block: 2-byte content length + content + padding
    std::vector<uint8_t> block;
    uint16_t contentLen = static_cast<uint16_t>(content.size());
    block.push_back(static_cast<uint8_t>(contentLen >> 8));
    block.push_back(static_cast<uint8_t>(contentLen & 0xFF));
    block.insert(block.end(), content.begin(), content.end());
    block.resize(BLOCK_SIZE, 0);

    return block;
}

static std::vector<uint8_t> makeLenPrefixed(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> out;
    uint16_t len = static_cast<uint16_t>(data.size());
    out.push_back(static_cast<uint8_t>(len >> 8));
    out.push_back(static_cast<uint8_t>(len & 0xFF));
    out.insert(out.end(), data.begin(), data.end());
    return out;
}

static void test_parse_sub() {
    std::cout << "test_parse_sub... ";

    std::vector<uint8_t> sid(32, 0xAA);
    std::vector<uint8_t> cid = {1, 2, 3, 4};
    std::vector<uint8_t> eid(24, 0xBB);

    auto block = buildBlock(sid, cid, eid, "SUB");
    auto result = parseTransmission(block);

    assert(result.has_value());
    assert(result->session_id == sid);
    assert(result->corr_id == cid);
    assert(result->entity_id == eid);
    assert(std::holds_alternative<CmdSub>(result->command));

    std::cout << "OK" << std::endl;
}

static void test_parse_get() {
    std::cout << "test_parse_get... ";

    std::vector<uint8_t> sid(32, 0x11);
    std::vector<uint8_t> cid = {5, 6};
    std::vector<uint8_t> eid(24, 0x22);

    auto block = buildBlock(sid, cid, eid, "GET");
    auto result = parseTransmission(block);

    assert(result.has_value());
    assert(std::holds_alternative<CmdGet>(result->command));

    std::cout << "OK" << std::endl;
}

static void test_parse_send() {
    std::cout << "test_parse_send... ";

    std::vector<uint8_t> sid(32, 0x33);
    std::vector<uint8_t> cid = {7, 8, 9};
    std::vector<uint8_t> eid(24, 0x44);
    std::vector<uint8_t> body = {'h', 'e', 'l', 'l', 'o'};

    auto block = buildBlock(sid, cid, eid, "SEND", body);
    auto result = parseTransmission(block);

    assert(result.has_value());
    assert(std::holds_alternative<CmdSend>(result->command));
    auto& cmd = std::get<CmdSend>(result->command);
    assert(cmd.msg_body == body);

    std::cout << "OK" << std::endl;
}

static void test_parse_new() {
    std::cout << "test_parse_new... ";

    std::vector<uint8_t> sid(32, 0x55);
    std::vector<uint8_t> cid = {10};
    std::vector<uint8_t> eid; // empty for NEW

    // Build payload: len-prefixed recipient_key + len-prefixed dh_key
    std::vector<uint8_t> rk(32, 0xAA); // Ed25519 key
    std::vector<uint8_t> dhk(32, 0xBB); // X25519 key
    std::vector<uint8_t> payload;
    auto lrk = makeLenPrefixed(rk);
    auto ldhk = makeLenPrefixed(dhk);
    payload.insert(payload.end(), lrk.begin(), lrk.end());
    payload.insert(payload.end(), ldhk.begin(), ldhk.end());

    auto block = buildBlock(sid, cid, eid, "NEW", payload);
    auto result = parseTransmission(block);

    assert(result.has_value());
    assert(std::holds_alternative<CmdNew>(result->command));
    auto& cmd = std::get<CmdNew>(result->command);
    assert(cmd.recipient_key == rk);
    assert(cmd.recipient_dh_key == dhk);

    std::cout << "OK" << std::endl;
}

static void test_parse_ack() {
    std::cout << "test_parse_ack... ";

    std::vector<uint8_t> sid(32, 0x66);
    std::vector<uint8_t> cid = {11, 12};
    std::vector<uint8_t> eid(24, 0x77);
    std::vector<uint8_t> msgId(24, 0x99);

    auto block = buildBlock(sid, cid, eid, "ACK", msgId);
    auto result = parseTransmission(block);

    assert(result.has_value());
    assert(std::holds_alternative<CmdAck>(result->command));
    auto& cmd = std::get<CmdAck>(result->command);
    assert(cmd.msg_id == msgId);

    std::cout << "OK" << std::endl;
}

static void test_parse_invalid() {
    std::cout << "test_parse_invalid... ";

    // Too short
    std::vector<uint8_t> tiny = {0, 1, 0};
    auto result = parseTransmission(tiny);
    assert(!result.has_value());

    // Unknown command
    std::vector<uint8_t> sid(32, 0);
    std::vector<uint8_t> cid = {1};
    std::vector<uint8_t> eid;
    auto block = buildBlock(sid, cid, eid, "BOGUS");
    result = parseTransmission(block);
    assert(!result.has_value());

    std::cout << "OK" << std::endl;
}

static void test_serialize_ok() {
    std::cout << "test_serialize_ok... ";

    ResponseBlock rsp;
    rsp.corr_id = {1, 2, 3};
    rsp.entity_id = std::vector<uint8_t>(24, 0xAA);
    rsp.response = RspOk{};

    auto out = serializeResponse(rsp);
    assert(out.size() == BLOCK_SIZE);

    // First 2 bytes = content length
    uint16_t len = (uint16_t(out[0]) << 8) | out[1];
    assert(len > 0);

    std::cout << "OK" << std::endl;
}

static void test_serialize_err() {
    std::cout << "test_serialize_err... ";

    ResponseBlock rsp;
    rsp.corr_id = {4, 5};
    rsp.entity_id = {};
    rsp.response = RspErr{ErrorCode::AUTH};

    auto out = serializeResponse(rsp);
    assert(out.size() == BLOCK_SIZE);

    std::cout << "OK" << std::endl;
}

static void test_serialize_ids() {
    std::cout << "test_serialize_ids... ";

    ResponseBlock rsp;
    rsp.corr_id = {6};
    rsp.entity_id = std::vector<uint8_t>(24, 0xCC);
    rsp.response = RspIds{
        std::vector<uint8_t>(24, 0xDD),
        std::vector<uint8_t>(24, 0xEE),
        std::vector<uint8_t>(32, 0xFF)
    };

    auto out = serializeResponse(rsp);
    assert(out.size() == BLOCK_SIZE);

    std::cout << "OK" << std::endl;
}

int main() {
    test_parse_sub();
    test_parse_get();
    test_parse_send();
    test_parse_new();
    test_parse_ack();
    test_parse_invalid();
    test_serialize_ok();
    test_serialize_err();
    test_serialize_ids();

    std::cout << "\nAll protocol tests passed." << std::endl;
    return 0;
}
