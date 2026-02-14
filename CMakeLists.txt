cmake_minimum_required(VERSION 3.16)
project(simplex-i2p-smp VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Dependencies
find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SQLCIPHER REQUIRED sqlcipher)
pkg_check_modules(SODIUM REQUIRED libsodium)

# Server executable
add_executable(simplex-i2p-smp
    src/main.cpp
    src/smp_store.cpp
    src/smp_protocol.cpp
    src/smp_server.cpp
)

target_include_directories(simplex-i2p-smp PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${SQLCIPHER_INCLUDE_DIRS}
    ${SODIUM_INCLUDE_DIRS}
)

target_link_libraries(simplex-i2p-smp PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    ${SQLCIPHER_LIBRARIES}
    ${SODIUM_LIBRARIES}
    pthread
)

target_link_directories(simplex-i2p-smp PRIVATE
    ${SQLCIPHER_LIBRARY_DIRS}
    ${SODIUM_LIBRARY_DIRS}
)

# Tests
option(SMP_DISABLE_TESTS "Disable building tests" OFF)
if(NOT SMP_DISABLE_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
