#pragma once

#include <string>
#include <vector>

namespace smp {

class SamClient {
public:
    SamClient(const std::string& host = "127.0.0.1", uint16_t port = 7656);
    ~SamClient();

    // Connect to SAM bridge and perform HELLO handshake
    bool connect();

    // Create a STREAM session with given ID
    // Returns destination (base64) on success, empty string on failure
    std::string createSession(const std::string& sessionId,
                              const std::string& destination = "TRANSIENT");

    // Get base32 address from destination
    std::string getBase32Address() const;

    // Start accepting incoming I2P connections and forward to local address
    void startAcceptLoop(const std::string& forwardHost, uint16_t forwardPort);

    // Stop accept loop
    void stop();

private:
    std::string host_;
    uint16_t port_;
    int sock_fd_;
    std::string destination_;  // base64 destination
    std::string session_id_;
    bool running_;

    // Send command and read response
    bool sendCommand(const std::string& cmd, std::string& response);

    // Parse SAM response for RESULT=OK
    bool isResultOk(const std::string& response) const;

    // Extract value from SAM response (e.g., "DESTINATION=...")
    std::string extractValue(const std::string& response, const std::string& key) const;

    // Forward I2P stream to local port
    void forwardConnection(int i2p_fd, const std::string& host, uint16_t port);
};

} // namespace smp
