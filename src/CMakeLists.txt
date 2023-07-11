cmake_minimum_required(VERSION 3.16)


########################
# AES library (native) #
########################

add_library(aes STATIC
    bpf/aes.c
    user/aes_hw_accel.c
)
target_include_directories(aes PUBLIC "${CMAKE_SOURCE_DIR}/src")

# Copy library into Go package for linking
set(AES_LIB_SRC "${CMAKE_CURRENT_BINARY_DIR}/libaes.a")
set(AES_LIB_DST "${CMAKE_SOURCE_DIR}/go/xsr/libaes.a")
add_custom_target(aes_copy ALL DEPENDS "${AES_LIB_SRC}" "${AES_LIB_DST}")
add_dependencies(aes_copy aes)
add_custom_command(
    OUTPUT ${AES_LIB_DST}
    DEPENDS ${AES_LIB_SRC}
    COMMAND ${CMAKE_COMMAND} -E copy "${AES_LIB_SRC}" "${AES_LIB_DST}"
)


#######################
# XDP router (native) #
#######################

set(XSR_NATIVE_OUT "xsr_native.a")

add_library(xsr_native
    bpf/xdp.c
)
set_target_properties(xsr_native PROPERTIES PREFIX "")
target_include_directories(xsr_native PRIVATE "${CMAKE_SOURCE_DIR}/src")
if (ENABLE_HF_CHECK)
    target_link_libraries(xsr_native PUBLIC aes)
endif (ENABLE_HF_CHECK)

# Copy library into Go package for linking
set(XDP_NATIVE_SRC "${CMAKE_CURRENT_BINARY_DIR}/xsr_native.a")
set(XDP_NATIVE_DST "${CMAKE_SOURCE_DIR}/go/xsr/xsr_native.a")
add_custom_target(xsr_native_copy ALL DEPENDS "${XDP_NATIVE_SRC}" "${XDP_NATIVE_DST}")
add_dependencies(xsr_native_copy xsr_native)
add_custom_command(
    OUTPUT ${XDP_NATIVE_DST}
    DEPENDS ${XDP_NATIVE_SRC}
    COMMAND ${CMAKE_COMMAND} -E copy "${XDP_NATIVE_SRC}" "${XDP_NATIVE_DST}"
)

# Configure optional features
if(ENABLE_DEBUG_PRINT)
    target_compile_definitions(xsr_native PUBLIC XDP_DEBUG_PRINT)
endif()
if(ENABLE_IPV4)
    target_compile_definitions(xsr_native PUBLIC ENABLE_IPV4)
endif()
if(ENABLE_IPV6)
    target_compile_definitions(xsr_native PUBLIC ENABLE_IPV6)
endif()
if(ENABLE_SCION_PATH)
    target_compile_definitions(xsr_native PUBLIC ENABLE_SCION_PATH)
endif()
if(ENABLE_HF_CHECK)
    target_compile_definitions(xsr_native PUBLIC ENABLE_HF_CHECK)
endif()


#####################
# XDP router (eBPF) #
#####################

set(XDP_EBPF_SRC bpf/xdp.c)
if (ENABLE_HF_CHECK)
    list(APPEND XDP_EBPF_SRC bpf/aes.c)
endif (ENABLE_HF_CHECK)

add_library(xsr_ebpf_objs OBJECT # compile without linking
    ${XDP_EBPF_SRC}
)
target_compile_options(xsr_ebpf_objs PRIVATE -target bpf -O2 -g)
target_include_directories(xsr_ebpf_objs PRIVATE ${CMAKE_SOURCE_DIR}/src)

# custom target for linking
set(XDP_EBPF_OBJ "${CMAKE_CURRENT_BINARY_DIR}/xsr_ebpf.o")
set(XDP_EBPF_EMBED "${CMAKE_SOURCE_DIR}/go/xsr/bpf/xsr_ebpf.o")
add_custom_target(xsr_ebpf ALL DEPENDS "${XDP_EBPF_OBJ}" "${XDP_EBPF_EMBED}")
add_dependencies(xsr_ebpf xsr_ebpf_objs)
add_custom_command(
    OUTPUT ${XDP_EBPF_OBJ}
    COMMAND ${BPFTOOL} gen object xsr_ebpf.o "$<TARGET_OBJECTS:xsr_ebpf_objs>"
    COMMAND_EXPAND_LISTS
    DEPENDS "$<TARGET_OBJECTS:xsr_ebpf_objs>"
)
add_custom_command( # copy xdp object into Go package for embedding
    OUTPUT ${XDP_EBPF_EMBED}
    DEPENDS ${XDP_EBPF_OBJ}
    COMMAND ${CMAKE_COMMAND} -E copy "${XDP_EBPF_OBJ}" "${XDP_EBPF_EMBED}"
)

# Configure optional features
if(ENABLE_DEBUG_PRINT)
    # target_compile_definitions(xdp_user PUBLIC XDP_DEBUG_PRINT)
    target_compile_definitions(xsr_ebpf_objs PUBLIC XDP_DEBUG_PRINT)
endif()
if(ENABLE_IPV4)
    # target_compile_definitions(xdp_user PUBLIC ENABLE_IPV4)
    target_compile_definitions(xsr_ebpf_objs PUBLIC ENABLE_IPV4)
endif()
if(ENABLE_IPV6)
    # target_compile_definitions(xdp_user PUBLIC ENABLE_IPV6)
    target_compile_definitions(xsr_ebpf_objs PUBLIC ENABLE_IPV6)
endif()
if(ENABLE_SCION_PATH)
    # target_compile_definitions(xdp_user PUBLIC ENABLE_SCION_PATH)
    target_compile_definitions(xsr_ebpf_objs PUBLIC ENABLE_SCION_PATH)
endif()
if(ENABLE_HF_CHECK)
    # target_compile_definitions(xdp_user PUBLIC ENABLE_HF_CHECK)
    target_compile_definitions(xsr_ebpf_objs PUBLIC ENABLE_HF_CHECK)
endif()



add_executable(test test/test.c)
target_link_libraries(test xsr_native)
