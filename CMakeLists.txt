cmake_minimum_required(VERSION 3.16)

project(express-scion-router)

set(BPFTOOL bpftool CACHE STRING "bpftool")
set(ENABLE_DEBUG_PRINT ON CACHE BOOL "Enable debug messages from dataplane (slow)")
set(ENABLE_IPV4 ON CACHE BOOL "Enable IPv4 support")
set(ENABLE_IPV6 ON CACHE BOOL "Enable IPv6 support")
set(ENABLE_SCION_PATH ON CACHE BOOL "Enable support for standard SCION paths")
set(ENABLE_HF_CHECK ON CACHE BOOL "Enable cryptographic hop field verification")

if (NOT CMAKE_C_COMPILER_ID STREQUAL "Clang")
    message(FATAL_ERROR
        "BPF source files must be compiled by clang.\n"
        "Specify '-DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++' on the command line."
    )
endif()

add_compile_options(-Wall -Werror -march=native)

add_subdirectory(src)
