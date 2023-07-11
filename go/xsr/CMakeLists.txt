cmake_minimum_required(VERSION 3.16)


set(XSR express-scion-router)
set(XSR_SRC
    bpf/bpf_kernel.go
    bpf/bpf_user.go
    bpf/control.go
    config/config.go
    topology/topology.go
)

add_custom_target(xsr ALL DEPENDS aes_copy xsr_native_copy ${XSR})
add_custom_command(
    OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/${XSR}"
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}/go/xsr"
    COMMAND ${GO} build -o "${CMAKE_CURRENT_BINARY_DIR}/${XSR}"
    DEPENDS ${XSR_SRC}
)
