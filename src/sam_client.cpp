#include "sam_client.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <iostream>
#include <sstream>
#include <thread>
#include <chrono>

namespace smp {

SamClient::SamClient(const std::string& host, uint16_t port)
    : host_(host), port_(port), sock_fd_(-1), running_(false) {}

SamClient::~SamClient() {
    stop();
    if (sock_fd_ >= 0) {
        close(sock_fd_);
    }
}

bool SamClient::connect() {
    sock_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd_ < 0) {
        std::cerr << "[sam] Failed to create socket" << std::endl;
        return false;
    }

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port_);
    inet_pton(AF_INET, host_.c_str(), &addr.sin_addr);

    if (::connect(sock_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "[sam] Failed to connect to " << host_ << ":" << port_ << std::endl;
        close(sock_fd_);
        sock_fd_ = -1;
        return false;
    }

    // Perform HELLO handshake
    std::string response;
    if (!sendCommand("HELLO VERSION MIN=3.1 MAX=3.1\n", response)) {
        std::cerr << "[sam] HELLO failed" << std::endl;
        return false;
    }

    if (!isResultOk(response)) {
        std::cerr << "[sam] HELLO response not OK: " << response << std::endl;
        return false;
    }

    std::cerr << "[sam] Connected to SAM bridge: " << response;
    return true;
}

std::string SamClient::createSession(const std::string& sessionId,
                                     const std::string& destination) {
    session_id_ = sessionId;

    // SESSION CREATE STYLE=STREAM ID=<id> DESTINATION=<dest> SIGNATURE_TYPE=<type>
    // Try DSA_SHA1 (type 0) - old but widely supported
    std::ostringstream cmd;
    cmd << "SESSION CREATE STYLE=STREAM ID=" << sessionId
        << " DESTINATION=" << destination
        << " SIGNATURE_TYPE=0"  // DSA_SHA1 - old, compatible
        << "\n";

    std::string response;
    if (!sendCommand(cmd.str(), response)) {
        std::cerr << "[sam] SESSION CREATE failed" << std::endl;
        return "";
    }

    if (!isResultOk(response)) {
        std::cerr << "[sam] SESSION CREATE response not OK: " << response << std::endl;
        return "";
    }

    // Extract DESTINATION from response
    destination_ = extractValue(response, "DESTINATION");
    if (destination_.empty()) {
        std::cerr << "[sam] Failed to extract DESTINATION from response" << std::endl;
        return "";
    }

    std::cerr << "[sam] Session created: " << session_id_ << std::endl;
    std::cerr << "[sam] Destination (base64): " << destination_.substr(0, 60) << "..." << std::endl;

    return destination_;
}

std::string SamClient::getBase32Address() const {
    // TODO: Convert base64 destination to base32.i2p address
    // For now, we'll need to check i2pd web console or use external tool
    // The destination is created and should appear in local destinations
    return "";
}

void SamClient::startAcceptLoop(const std::string& forwardHost, uint16_t forwardPort) {
    running_ = true;

    std::cerr << "[sam] Starting accept loop, forwarding to " << forwardHost << ":" << forwardPort << std::endl;

    while (running_) {
        // Create new connection to SAM for STREAM ACCEPT
        int accept_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (accept_fd < 0) {
            std::cerr << "[sam] Failed to create accept socket" << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(5));
            continue;
        }

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port_);
        inet_pton(AF_INET, host_.c_str(), &addr.sin_addr);

        if (::connect(accept_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            std::cerr << "[sam] Failed to connect for STREAM ACCEPT" << std::endl;
            close(accept_fd);
            std::this_thread::sleep_for(std::chrono::seconds(5));
            continue;
        }

        // Send STREAM ACCEPT command
        std::ostringstream cmd;
        cmd << "STREAM ACCEPT ID=" << session_id_ << " SILENT=false\n";

        ssize_t sent = send(accept_fd, cmd.str().c_str(), cmd.str().size(), 0);
        if (sent < 0) {
            std::cerr << "[sam] Failed to send STREAM ACCEPT" << std::endl;
            close(accept_fd);
            std::this_thread::sleep_for(std::chrono::seconds(5));
            continue;
        }

        std::cerr << "[sam] Waiting for incoming I2P connection..." << std::endl;

        // Wait for incoming connection (blocking)
        // SAM will send "STREAM STATUS RESULT=OK\n" when connection arrives
        char buf[1024];
        ssize_t received = recv(accept_fd, buf, sizeof(buf) - 1, 0);
        if (received <= 0) {
            std::cerr << "[sam] STREAM ACCEPT connection closed" << std::endl;
            close(accept_fd);
            std::this_thread::sleep_for(std::chrono::seconds(5));
            continue;
        }

        buf[received] = '\0';
        std::string response(buf);

        if (response.find("RESULT=OK") == std::string::npos) {
            std::cerr << "[sam] STREAM ACCEPT failed: " << response;
            close(accept_fd);
            continue;
        }

        std::cerr << "[sam] Incoming I2P connection accepted!" << std::endl;

        // Now accept_fd is the I2P stream, forward it to local SMP server
        std::thread([this, accept_fd, forwardHost, forwardPort]() {
            forwardConnection(accept_fd, forwardHost, forwardPort);
        }).detach();
    }
}

void SamClient::stop() {
    running_ = false;
}

bool SamClient::sendCommand(const std::string& cmd, std::string& response) {
    if (sock_fd_ < 0) return false;

    // Send command
    ssize_t sent = send(sock_fd_, cmd.c_str(), cmd.size(), 0);
    if (sent < 0) {
        std::cerr << "[sam] Failed to send command" << std::endl;
        return false;
    }

    // Read response (up to 4KB)
    char buf[4096];
    ssize_t received = recv(sock_fd_, buf, sizeof(buf) - 1, 0);
    if (received <= 0) {
        std::cerr << "[sam] Failed to receive response" << std::endl;
        return false;
    }

    buf[received] = '\0';
    response = std::string(buf);
    return true;
}

bool SamClient::isResultOk(const std::string& response) const {
    return response.find("RESULT=OK") != std::string::npos;
}

std::string SamClient::extractValue(const std::string& response, const std::string& key) const {
    std::string searchKey = key + "=";
    size_t pos = response.find(searchKey);
    if (pos == std::string::npos) return "";

    pos += searchKey.size();
    size_t end = response.find_first_of(" \n\r", pos);
    if (end == std::string::npos) {
        return response.substr(pos);
    }
    return response.substr(pos, end - pos);
}

void SamClient::forwardConnection(int i2p_fd, const std::string& host, uint16_t port) {
    // Connect to local SMP server
    int local_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (local_fd < 0) {
        std::cerr << "[sam] Failed to create local socket for forwarding" << std::endl;
        close(i2p_fd);
        return;
    }

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host.c_str(), &addr.sin_addr);

    if (::connect(local_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "[sam] Failed to connect to local SMP server at " << host << ":" << port << std::endl;
        close(i2p_fd);
        close(local_fd);
        return;
    }

    std::cerr << "[sam] Forwarding I2P stream to " << host << ":" << port << std::endl;

    // Bidirectional forwarding
    std::thread i2p_to_local([i2p_fd, local_fd]() {
        char buf[8192];
        ssize_t n;
        while ((n = recv(i2p_fd, buf, sizeof(buf), 0)) > 0) {
            if (send(local_fd, buf, n, 0) <= 0) break;
        }
        shutdown(local_fd, SHUT_WR);
    });

    std::thread local_to_i2p([i2p_fd, local_fd]() {
        char buf[8192];
        ssize_t n;
        while ((n = recv(local_fd, buf, sizeof(buf), 0)) > 0) {
            if (send(i2p_fd, buf, n, 0) <= 0) break;
        }
        shutdown(i2p_fd, SHUT_WR);
    });

    i2p_to_local.join();
    local_to_i2p.join();

    close(i2p_fd);
    close(local_fd);

    std::cerr << "[sam] Connection closed" << std::endl;
}

} // namespace smp
