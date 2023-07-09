cmake_minimum_required(VERSION 3.16)


# XDP router (kernel version)

set(XDP_KERNEL_SRC bpf/xdp.c)
if (ENABLE_HF_CHECK)
    list(APPEND XDP_KERNEL_SRC bpf/aes.c)
endif (ENABLE_HF_CHECK)

add_library(xdp_kernel_objs OBJECT # compile without linking
    ${XDP_KERNEL_SRC}
)
target_compile_options(xdp_kernel_objs PRIVATE -target bpf -O2 -g)
target_include_directories(xdp_kernel_objs PRIVATE ${CMAKE_SOURCE_DIR}/src)

add_custom_target(xdp_kernel ALL DEPENDS xdp_kernel.o) # custom target for linking
add_dependencies(xdp_kernel xdp_kernel_objs)
add_custom_command(
    OUTPUT xdp_kernel.o
    COMMAND ${BPFTOOL} gen object xdp_kernel.o "$<TARGET_OBJECTS:xdp_kernel_objs>"
    COMMAND_EXPAND_LISTS
    DEPENDS "$<TARGET_OBJECTS:xdp_kernel_objs>"
)


# XDP router (userspace version)
# TODO


# Configure optional features
if(ENABLE_DEBUG_PRINT)
    target_compile_definitions(xdp_kernel_objs PUBLIC XDP_DEBUG_PRINT)
endif()
if(ENABLE_IPV4)
    target_compile_definitions(xdp_kernel_objs PUBLIC ENABLE_IPV4)
endif()
if(ENABLE_IPV6)
    target_compile_definitions(xdp_kernel_objs PUBLIC ENABLE_IPV6)
endif()
if(ENABLE_SCION_PATH)
    target_compile_definitions(xdp_kernel_objs PUBLIC ENABLE_SCION_PATH)
endif()
if(ENABLE_HF_CHECK)
    target_compile_definitions(xdp_kernel_objs PUBLIC ENABLE_HF_CHECK)
endif()
