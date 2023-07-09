cmake_minimum_required(VERSION 3.16)


set(XSR express-scion-router)

add_custom_target(xsr ALL DEPENDS ${XSR})
add_custom_command(
    OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/${XSR}"
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}/go/xsr"
    COMMAND ${GO} build -o "${CMAKE_CURRENT_BINARY_DIR}/${XSR}"
)
