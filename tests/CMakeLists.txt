function(make_test name)
    add_executable(${name} ${name}.cpp
        ${CMAKE_SOURCE_DIR}/src/smp_protocol.cpp
        ${CMAKE_SOURCE_DIR}/src/smp_store.cpp
    )
    target_include_directories(${name} PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${SQLCIPHER_INCLUDE_DIRS}
        ${SODIUM_INCLUDE_DIRS}
    )
    target_link_libraries(${name} PRIVATE
        ${SQLCIPHER_LIBRARIES}
        ${SODIUM_LIBRARIES}
        pthread
    )
    target_link_directories(${name} PRIVATE
        ${SQLCIPHER_LIBRARY_DIRS}
        ${SODIUM_LIBRARY_DIRS}
    )
    add_test(NAME ${name} COMMAND ${name})
endfunction()

make_test(smp_protocol_test)
