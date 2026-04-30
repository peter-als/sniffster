cmake_minimum_required(VERSION 3.28)

# ─────────────────────────────────────────────────────────────────────────────
# Language standard and library selection — before project()
# ─────────────────────────────────────────────────────────────────────────────
cmake_policy(SET CMP0167 OLD)

set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ─────────────────────────────────────────────────────────────────────────────
# Would love to use CMAKE_CXX_STANDARD_LIBRARIES to support `import std;` across
# the board, but it doesn't seem towork smoothly just yet. Leaving it alone for
# the time being and using old good `#include` for standard libraries for now.
# ─────────────────────────────────────────────────────────────────────────────

set(SNIFFSTER_CXX_STDLIB "libc++" CACHE STRING
    "C++ standard library to use (empty, libstdc++, or libc++)")
set_property(CACHE SNIFFSTER_CXX_STDLIB PROPERTY STRINGS "" "libstdc++" "libc++")

set(SNIFFSTER_LIBCPP_EXTRA_FLAGS "")
if(SNIFFSTER_CXX_STDLIB)
    set(CMAKE_CXX_FLAGS_INIT "-stdlib=${SNIFFSTER_CXX_STDLIB}")
    set(CMAKE_EXE_LINKER_FLAGS_INIT "-stdlib=${SNIFFSTER_CXX_STDLIB}")
    set(CMAKE_SHARED_LINKER_FLAGS_INIT "-stdlib=${SNIFFSTER_CXX_STDLIB}")

    if(SNIFFSTER_CXX_STDLIB STREQUAL "libc++")
        string(APPEND SNIFFSTER_LIBCPP_EXTRA_FLAGS " -fexperimental-library")
        string(APPEND CMAKE_CXX_FLAGS_INIT "${SNIFFSTER_LIBCPP_EXTRA_FLAGS}")
    endif()
endif()

project(sniffster LANGUAGES C CXX)

# ─────────────────────────────────────────────────────────────────────────────
# General build settings
# ─────────────────────────────────────────────────────────────────────────────

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include_directories(${CMAKE_SOURCE_DIR})

include(CheckCXXSourceCompiles)

option(SNIFFSTER_ENABLE_SANITIZERS
    "Enable AddressSanitizer and UndefinedBehaviorSanitizer for host builds" OFF)

set(SNIFFSTER_BOOST_ROOT "" CACHE PATH
    "Preferred Boost installation prefix. Set this to a libc++-built Boost when using Boost.Log with libc++.")
option(SNIFFSTER_BOOST_NO_SYSTEM_PATHS
    "Restrict Boost discovery to SNIFFSTER_BOOST_ROOT/BOOST_ROOT and CMake hints" OFF)

if(SNIFFSTER_BOOST_ROOT
   AND EXISTS "${SNIFFSTER_BOOST_ROOT}/boost/version.hpp"
   AND EXISTS "${SNIFFSTER_BOOST_ROOT}/stage/lib"
   AND NOT EXISTS "${SNIFFSTER_BOOST_ROOT}/include/boost/version.hpp")
    set(SNIFFSTER_BOOST_ROOT "" CACHE PATH
        "Preferred Boost installation prefix. Set this to a libc++-built Boost when using Boost.Log with libc++." FORCE)
    set(SNIFFSTER_BOOST_NO_SYSTEM_PATHS OFF CACHE BOOL
        "Restrict Boost discovery to SNIFFSTER_BOOST_ROOT/BOOST_ROOT and CMake hints" FORCE)
endif()

if(NOT SNIFFSTER_BOOST_ROOT AND SNIFFSTER_CXX_STDLIB STREQUAL "libc++")
    set(_sniffster_boost_candidates
        "/usr/local"
        "/opt/boost-libcpp"
        "/opt/boost-1.83-libcpp"
        "/usr/local/boost-libcpp"
        "/usr/local/boost-1.83-libcpp"
        "$ENV{HOME}/opt/boost-libcpp"
        "$ENV{HOME}/opt/boost-1.83-libcpp"
        "$ENV{HOME}/local/boost-libcpp"
        "$ENV{HOME}/local/boost-1.83-libcpp")

    foreach(_sniffster_boost_candidate IN LISTS _sniffster_boost_candidates)
        if(EXISTS "${_sniffster_boost_candidate}/include/boost/version.hpp")
            set(SNIFFSTER_BOOST_ROOT "${_sniffster_boost_candidate}" CACHE PATH
                "Preferred Boost installation prefix. Set this to a libc++-built Boost when using Boost.Log with libc++." FORCE)
            set(SNIFFSTER_BOOST_NO_SYSTEM_PATHS ON CACHE BOOL
                "Restrict Boost discovery to SNIFFSTER_BOOST_ROOT/BOOST_ROOT and CMake hints" FORCE)
            break()
        endif()
    endforeach()
endif()

if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
    add_compile_options(-march=x86-64-v2)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "i[3-6]86")
    add_compile_options(-msse4.2)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
    add_compile_options(-march=armv8-a+crc)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm")
    add_compile_options(-march=armv8-a+crc -mfpu=crypto-neon-fp-armv8)
endif()

if(SNIFFSTER_ENABLE_SANITIZERS)
    add_compile_options(
        -fsanitize=address,undefined
        -fno-omit-frame-pointer
        -g
    )
    add_link_options(-fsanitize=address,undefined)
endif()

if(SNIFFSTER_LIBCPP_EXTRA_FLAGS)
    separate_arguments(SNIFFSTER_LIBCPP_EXTRA_FLAGS_LIST NATIVE_COMMAND "${SNIFFSTER_LIBCPP_EXTRA_FLAGS}")
    add_compile_options(${SNIFFSTER_LIBCPP_EXTRA_FLAGS_LIST})
endif()

# ─────────────────────────────────────────────────────────────────────────────
# Feature detection
# ─────────────────────────────────────────────────────────────────────────────

set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} -std=c++${CMAKE_CXX_STANDARD}")
if(SNIFFSTER_CXX_STDLIB)
    set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} -stdlib=${SNIFFSTER_CXX_STDLIB}")
    if(SNIFFSTER_LIBCPP_EXTRA_FLAGS)
        set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS}${SNIFFSTER_LIBCPP_EXTRA_FLAGS}")
    endif()
endif()

unset(SNIFFSTER_HAVE_STD_PRINT CACHE)
check_cxx_source_compiles("
    #include <print>
    int main()
    {
        std::println(\"sniffster\");
        return 0;
    }
" SNIFFSTER_HAVE_STD_PRINT)

if(NOT SNIFFSTER_HAVE_STD_PRINT)
    if(SNIFFSTER_CXX_STDLIB STREQUAL "libc++")
        set(SNIFFSTER_STD_PRINT_HINT
            "libc++ is selected but <print> did not compile. "
            "Verify libc++ headers and libraries are installed correctly.")
    elseif(SNIFFSTER_CXX_STDLIB STREQUAL "libstdc++")
        set(SNIFFSTER_STD_PRINT_HINT
            "libstdc++ is selected but the configured version does not provide <print>. "
            "Use a newer libstdc++ or switch to libc++.")
    else()
        set(SNIFFSTER_STD_PRINT_HINT
            "No standard library is explicitly selected. On this machine clang++ may "
            "default to a libstdc++ that does not ship <print>. Configure with "
            "-DSNIFFSTER_CXX_STDLIB=libc++ or use a newer libstdc++.")
    endif()

    message(FATAL_ERROR
        "The configured C++ toolchain does not provide <print>.\n"
        "Compiler: ${CMAKE_CXX_COMPILER}\n"
        "Requested stdlib: ${SNIFFSTER_CXX_STDLIB}\n"
        "${SNIFFSTER_STD_PRINT_HINT}")
endif()

# ─────────────────────────────────────────────────────────────────────────────
# External tools (BPF toolchain)
# ─────────────────────────────────────────────────────────────────────────────

find_program(CLANG_EXECUTABLE
    NAMES clang-22 clang-21 clang-20 clang-19 clang-18 clang
    REQUIRED)
find_program(BPFTOOL_EXECUTABLE NAMES bpftool REQUIRED)

# ─────────────────────────────────────────────────────────────────────────────
# Main executable
# ─────────────────────────────────────────────────────────────────────────────

add_executable(sniffster
    main.cpp
)

target_include_directories(sniffster PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
)

set(SNIFFER_XDPCOPY_LOADER_MODULE ${CMAKE_SOURCE_DIR}/sniffer/xdp_copy_mode_loader.cppm)

target_sources(sniffster
PRIVATE
)

target_sources(sniffster
PRIVATE
FILE_SET CXX_MODULES FILES
    platform/arch_detect.cppm
    platform/clock.cppm
    platform/decorated_throw.cppm
    platform/debug.cppm
    platform/platform.cppm
    sniffer/sniffer.cppm
    sniffer/runtime_control.cppm
    sniffer/threading_config.cppm
    processors/format_data.cppm
    processors/queue_processor.cppm
    processors/packet_processor.cppm
    processors/packet_print.cppm
    processors/logger_processor.cppm
    processors/packet_meta_event.cppm
    processors/logger_event.cppm
    ${SNIFFER_XDPCOPY_LOADER_MODULE}
    sniffer/packet_handler.cppm
    sniffer/xdp_copy_handler.cppm
    network/addresses.cppm
    network/config.cppm
    network/nicq_detector.cppm
    network/nicq_ethtool.cppm
    network/nicq_fs.cppm
)

# ─────────────────────────────────────────────────────────────────────────────
# Third-party dependencies
# ─────────────────────────────────────────────────────────────────────────────

include(FetchContent)

set(CLI11_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(CLI11_BUILD_EXAMPLES_JSON OFF CACHE BOOL "" FORCE)
set(CLI11_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(CLI11_BUILD_DOCS OFF CACHE BOOL "" FORCE)

fetchcontent_declare(
    cli11
    GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
    GIT_TAG v2.6.2
)
fetchcontent_makeavailable(cli11)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)
pkg_check_modules(LIBBPF REQUIRED libbpf)
pkg_check_modules(LIBELF REQUIRED libelf)
pkg_check_modules(ZLIB REQUIRED zlib)

if(SNIFFSTER_BOOST_ROOT)
    set(BOOST_ROOT "${SNIFFSTER_BOOST_ROOT}" CACHE PATH
        "Boost root directory" FORCE)
    set(Boost_ROOT "${SNIFFSTER_BOOST_ROOT}" CACHE PATH
        "Boost root directory" FORCE)

    if(EXISTS "${SNIFFSTER_BOOST_ROOT}/include/boost/version.hpp")
        set(BOOST_INCLUDEDIR "${SNIFFSTER_BOOST_ROOT}/include" CACHE PATH
            "Boost include directory" FORCE)
        set(Boost_INCLUDE_DIR "${SNIFFSTER_BOOST_ROOT}/include" CACHE PATH
            "Boost include directory" FORCE)
    endif()

    if(EXISTS "${SNIFFSTER_BOOST_ROOT}/lib")
        set(BOOST_LIBRARYDIR "${SNIFFSTER_BOOST_ROOT}/lib" CACHE PATH
            "Boost library directory" FORCE)
        set(Boost_LIBRARY_DIR "${SNIFFSTER_BOOST_ROOT}/lib" CACHE PATH
            "Boost library directory" FORCE)
    endif()
endif()

if(SNIFFSTER_BOOST_NO_SYSTEM_PATHS)
    set(Boost_NO_SYSTEM_PATHS ON)
endif()

set(Boost_NO_BOOST_CMAKE ON)

find_package(Boost REQUIRED COMPONENTS program_options filesystem log log_setup)

message(STATUS
    "Boost_ROOT=${Boost_ROOT}; BOOST_INCLUDEDIR=${BOOST_INCLUDEDIR}; BOOST_LIBRARYDIR=${BOOST_LIBRARYDIR}; "
    "Boost_NO_SYSTEM_PATHS=${Boost_NO_SYSTEM_PATHS}; Boost_INCLUDE_DIRS=${Boost_INCLUDE_DIRS}")

# ─────────────────────────────────────────────────────────────────────────────
# BPF object and skeleton generation
# ─────────────────────────────────────────────────────────────────────────────

set(SNIFFER_XDPCOPY_SOURCE   ${CMAKE_SOURCE_DIR}/sniffer/xdp_copy_mode.c)
set(SNIFFER_XDPCOPY_OBJECT   ${CMAKE_CURRENT_BINARY_DIR}/sniffer/xdp_copy_mode.bpf.o)
set(SNIFFER_XDPCOPY_SKELETON ${CMAKE_CURRENT_BINARY_DIR}/sniffer/xdp_copy_mode.skel.h)

find_path(SNIFFER_BPF_ARCH_INCLUDE_DIR
    NAMES asm/types.h
    PATHS
        /usr/include/${CMAKE_SYSTEM_PROCESSOR}-linux-gnu
        /usr/include/x86_64-linux-gnu
        /usr/include/aarch64-linux-gnu
        /usr/include/arm-linux-gnueabihf
    NO_DEFAULT_PATH
)

if(NOT SNIFFER_BPF_ARCH_INCLUDE_DIR)
    message(FATAL_ERROR
        "Could not find arch-specific Linux headers for BPF build (missing asm/types.h)")
endif()

add_custom_command(
    OUTPUT ${SNIFFER_XDPCOPY_OBJECT}
    COMMAND ${CLANG_EXECUTABLE}
            -target bpf
            -O2
            -g
            -I${CMAKE_SOURCE_DIR}
            -I${SNIFFER_BPF_ARCH_INCLUDE_DIR}
            ${LIBBPF_CFLAGS}
            -c ${SNIFFER_XDPCOPY_SOURCE}
            -o ${SNIFFER_XDPCOPY_OBJECT}
    DEPENDS ${SNIFFER_XDPCOPY_SOURCE}
    VERBATIM
    COMMENT "Building BPF object ${SNIFFER_XDPCOPY_OBJECT}"
)

add_custom_command(
    OUTPUT ${SNIFFER_XDPCOPY_SKELETON}
    COMMAND ${BPFTOOL_EXECUTABLE} gen skeleton ${SNIFFER_XDPCOPY_OBJECT}
            > ${SNIFFER_XDPCOPY_SKELETON}
    DEPENDS ${SNIFFER_XDPCOPY_OBJECT}
    VERBATIM
    COMMENT "Generating BPF skeleton ${SNIFFER_XDPCOPY_SKELETON}"
)

add_custom_target(sniffer_xdpcopy ALL
    DEPENDS ${SNIFFER_XDPCOPY_OBJECT} ${SNIFFER_XDPCOPY_SKELETON}
)

set_source_files_properties(${SNIFFER_XDPCOPY_SKELETON} PROPERTIES GENERATED TRUE)
set_source_files_properties(${SNIFFER_XDPCOPY_LOADER_MODULE} PROPERTIES
    OBJECT_DEPENDS "${SNIFFER_XDPCOPY_SKELETON}"
)

add_dependencies(sniffster sniffer_xdpcopy)

# ─────────────────────────────────────────────────────────────────────────────
# Linking
# ─────────────────────────────────────────────────────────────────────────────

target_link_libraries(sniffster PRIVATE
    Boost::program_options
    Boost::filesystem
    Boost::log
    Boost::log_setup
    ${PCAP_LIBRARIES}
    ${LIBBPF_LIBRARIES}
    ${LIBELF_LIBRARIES}
    ${ZLIB_LIBRARIES}
    CLI11::CLI11
)

target_compile_definitions(sniffster PRIVATE
    BOOST_ATOMIC_DYN_LINK
    BOOST_ATOMIC_NO_LIB
    BOOST_CHRONO_DYN_LINK
    BOOST_CHRONO_NO_LIB
    BOOST_FILESYSTEM_DYN_LINK
    BOOST_FILESYSTEM_NO_LIB
    BOOST_LOG_DYN_LINK
    BOOST_LOG_NO_LIB
    BOOST_LOG_SETUP_DYN_LINK
    BOOST_LOG_SETUP_NO_LIB
    BOOST_PROGRAM_OPTIONS_DYN_LINK
    BOOST_PROGRAM_OPTIONS_NO_LIB
    BOOST_REGEX_DYN_LINK
    BOOST_REGEX_NO_LIB
    BOOST_THREAD_DYN_LINK
    BOOST_THREAD_NO_LIB
)

target_include_directories(sniffster PRIVATE
    ${PCAP_INCLUDE_DIRS}
    ${LIBBPF_INCLUDE_DIRS}
    ${LIBELF_INCLUDE_DIRS}
    ${ZLIB_INCLUDE_DIRS}
)

target_link_directories(sniffster PRIVATE
    ${PCAP_LIBRARY_DIRS}
    ${LIBBPF_LIBRARY_DIRS}
    ${LIBELF_LIBRARY_DIRS}
    ${ZLIB_LIBRARY_DIRS}
)

# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

enable_testing()
add_subdirectory(tests)
