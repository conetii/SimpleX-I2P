#include "sam_client.hpp"
#include <iostream>
#include <thread>
#include <chrono>

int main() {
    std::cout << "[test] Testing SAM client..." << std::endl;

    smp::SamClient sam("127.0.0.1", 7656);

    // Step 1: Connect and HELLO
    if (!sam.connect()) {
        std::cerr << "[test] Failed to connect to SAM" << std::endl;
        return 1;
    }

    // Step 2: Create session
    std::string destination = sam.createSession("simplex-smp-test", "TRANSIENT");
    if (destination.empty()) {
        std::cerr << "[test] Failed to create session" << std::endl;
        return 1;
    }

    std::cout << "[test] Session created successfully!" << std::endl;
    std::cout << "[test] Destination: " << destination << std::endl;
    std::cout << "[test] Check i2pd web console for base32 address" << std::endl;
    std::cout << "[test] http://localhost:7072/?page=local_destinations" << std::endl;

    // Wait a bit to let LeaseSet publish
    std::cout << "[test] Waiting 30 seconds for LeaseSet to publish..." << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(30));

    std::cout << "[test] Check LeaseSet status in web console" << std::endl;
    std::cout << "[test] Press Ctrl+C to exit" << std::endl;

    // Keep running
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(10));
    }

    return 0;
}
