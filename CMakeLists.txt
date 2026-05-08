cmake_minimum_required(VERSION 3.28)

# ─────────────────────────────────────────────────────────────────────────────
# Language standard and library selection — before project()
# ─────────────────────────────────────────────────────────────────────────────
cmake_policy(SET CMP0167 OLD)

if(NOT DEFINED CMAKE_CXX_STANDARD)
    set(CMAKE_CXX_STANDARD 26)
endif()
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Prefer the default clang++ first when the user did not explicitly choose a
# compiler via cache, preset, or environment. If that clang++ cannot satisfy
# the requested language level, walk versioned clang++ installs from the lowest
# major upward until one works. This avoids a silent fallback to GCC here while
# still keeping the project portable across machines with different Clang
# versions installed.
if(NOT DEFINED CMAKE_C_COMPILER
   AND NOT DEFINED CMAKE_CXX_COMPILER
   AND NOT DEFINED ENV{CC}
   AND NOT DEFINED ENV{CXX})
    set(_sniffster_cxx_standard_probe
        "${CMAKE_CURRENT_BINARY_DIR}/sniffster-cxx-standard-probe.cpp")
    file(WRITE "${_sniffster_cxx_standard_probe}" "int main() { return 0; }\n")

    function(_sniffster_clang_supports_required_standard compiler out_var)
        execute_process(
            COMMAND "${compiler}" -x c++ "-std=c++${CMAKE_CXX_STANDARD}"
                    -fsyntax-only "${_sniffster_cxx_standard_probe}"
            RESULT_VARIABLE _sniffster_probe_result
            OUTPUT_QUIET
            ERROR_QUIET
        )

        set(${out_var} FALSE PARENT_SCOPE)
        if(_sniffster_probe_result EQUAL 0)
            set(${out_var} TRUE PARENT_SCOPE)
        endif()
    endfunction()

    function(_sniffster_select_matching_clang_toolchain clangxx)
        get_filename_component(_sniffster_clang_bindir "${clangxx}" DIRECTORY)
        get_filename_component(_sniffster_clangxx_name "${clangxx}" NAME)

        string(REGEX MATCH "clang\\+\\+-([0-9]+)$"
            _sniffster_clangxx_version_match
            "${_sniffster_clangxx_name}")

        set(_sniffster_clang_candidates clang)
        set(_sniffster_clang_scan_deps_candidates clang-scan-deps)
        if(CMAKE_MATCH_1)
            list(PREPEND _sniffster_clang_candidates "clang-${CMAKE_MATCH_1}")
            list(PREPEND _sniffster_clang_scan_deps_candidates
                "clang-scan-deps-${CMAKE_MATCH_1}")
        endif()

        find_program(_sniffster_clang
            NAMES ${_sniffster_clang_candidates}
            HINTS "${_sniffster_clang_bindir}")
        find_program(_sniffster_clang_scan_deps
            NAMES ${_sniffster_clang_scan_deps_candidates}
            HINTS "${_sniffster_clang_bindir}")

        if(_sniffster_clang)
            set(CMAKE_C_COMPILER "${_sniffster_clang}" CACHE FILEPATH
                "Preferred C compiler for sniffster")
            set(CMAKE_CXX_COMPILER "${clangxx}" CACHE FILEPATH
                "Preferred C++ compiler for sniffster")

            if(_sniffster_clang_scan_deps)
                set(CMAKE_CXX_COMPILER_CLANG_SCAN_DEPS
                    "${_sniffster_clang_scan_deps}" CACHE FILEPATH
                    "clang-scan-deps executable matched to the selected Clang")
            endif()
        endif()
    endfunction()

    set(_sniffster_selected_clangxx "")

    find_program(_sniffster_default_clangxx NAMES clang++)
    if(_sniffster_default_clangxx)
        _sniffster_clang_supports_required_standard(
            "${_sniffster_default_clangxx}" _sniffster_default_clangxx_works)
        if(_sniffster_default_clangxx_works)
            set(_sniffster_selected_clangxx "${_sniffster_default_clangxx}")
        endif()
    endif()

    # if(NOT _sniffster_selected_clangxx)
    #     foreach(_sniffster_clang_version RANGE 10 40)
    #         unset(_sniffster_versioned_clangxx CACHE)
    #         unset(_sniffster_versioned_clangxx)
    #         find_program(_sniffster_versioned_clangxx
    #             NAMES "clang++-${_sniffster_clang_version}")

    #         if(_sniffster_versioned_clangxx)
    #             _sniffster_clang_supports_required_standard(
    #                 "${_sniffster_versioned_clangxx}"
    #                 _sniffster_versioned_clangxx_works)
    #             if(_sniffster_versioned_clangxx_works)
    #                 set(_sniffster_selected_clangxx
    #                     "${_sniffster_versioned_clangxx}")
    #                 break()
    #             endif()
    #         endif()
    #     endforeach()
    # endif()

    if(_sniffster_selected_clangxx)
        _sniffster_select_matching_clang_toolchain(
            "${_sniffster_selected_clangxx}")
    endif()
endif()

# ─────────────────────────────────────────────────────────────────────────────
# Would love to use CMAKE_CXX_STANDARD_LIBRARIES to support `import std;` across
# the board, but it doesn't seem towork smoothly just yet. Leaving it alone for
# the time being and using old good `#include` for standard libraries for now.
# ─────────────────────────────────────────────────────────────────────────────

set(SNIFFSTER_CXX_STDLIB "" CACHE STRING
    "C++ standard library to use (empty, libstdc++, or libc++)")
set_property(CACHE SNIFFSTER_CXX_STDLIB PROPERTY STRINGS "" "libstdc++" "libc++")
set(SNIFFSTER_GCC_INSTALL_DIR "" CACHE PATH
    "Exact GCC install dir to pair with Clang, e.g. /usr/lib/gcc/x86_64-linux-gnu/14")
set(SNIFFSTER_BOOST_ROOT "" CACHE PATH
    "Preferred Boost installation prefix when selecting a non-default Boost build")

set(SNIFFSTER_STDLIB_COMPILE_OPTIONS "")
set(SNIFFSTER_STDLIB_LINK_OPTIONS "")
set(SNIFFSTER_STDLIB_REQUIRED_FLAGS "")
set(SNIFFSTER_STDLIB_STD_PRINT_HINT
    "No standard library is explicitly selected. On this machine clang++ may "
    "default to a libstdc++ that does not ship <print>. Configure with "
    "-DSNIFFSTER_CXX_STDLIB=libc++ or use a newer libstdc++.")
# set(SNIFFSTER_STDLIB_BOOST_CANDIDATES "")

if(SNIFFSTER_CXX_STDLIB STREQUAL "libc++")
    set(SNIFFSTER_STDLIB_COMPILE_OPTIONS
        -stdlib=libc++
        -fexperimental-library)
    set(SNIFFSTER_STDLIB_LINK_OPTIONS
        -stdlib=libc++)
    set(SNIFFSTER_STDLIB_STD_PRINT_HINT
        "libc++ is selected but <print> did not compile. "
        "Verify libc++ headers and libraries are installed correctly.")
elseif(SNIFFSTER_CXX_STDLIB STREQUAL "libstdc++")
    set(SNIFFSTER_STDLIB_COMPILE_OPTIONS
        -stdlib=libstdc++)
    set(SNIFFSTER_STDLIB_LINK_OPTIONS
        -stdlib=libstdc++)
    set(SNIFFSTER_STDLIB_STD_PRINT_HINT
        "libstdc++ is selected but the configured version does not provide <print>. "
        "Use a newer libstdc++ or switch to libc++.")
elseif(SNIFFSTER_CXX_STDLIB)
    message(FATAL_ERROR
        "Unsupported SNIFFSTER_CXX_STDLIB='${SNIFFSTER_CXX_STDLIB}'. "
        "Expected empty, libstdc++, or libc++.")
endif()

if(SNIFFSTER_STDLIB_COMPILE_OPTIONS)
    string(JOIN " " SNIFFSTER_STDLIB_REQUIRED_FLAGS
        ${SNIFFSTER_STDLIB_COMPILE_OPTIONS})
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

if(SNIFFSTER_GCC_INSTALL_DIR)
    if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        list(APPEND SNIFFSTER_STDLIB_COMPILE_OPTIONS
            "--gcc-install-dir=${SNIFFSTER_GCC_INSTALL_DIR}")
        list(APPEND SNIFFSTER_STDLIB_LINK_OPTIONS
            "--gcc-install-dir=${SNIFFSTER_GCC_INSTALL_DIR}")
        string(APPEND SNIFFSTER_STDLIB_REQUIRED_FLAGS
            " --gcc-install-dir=${SNIFFSTER_GCC_INSTALL_DIR}")
    else()
        message(WARNING
            "SNIFFSTER_GCC_INSTALL_DIR is set to '${SNIFFSTER_GCC_INSTALL_DIR}', "
            "but the current C++ compiler is ${CMAKE_CXX_COMPILER_ID}. "
            "Ignoring this Clang-specific setting.")
    endif()
endif()

if(SNIFFSTER_BOOST_ROOT)
    set(Boost_ROOT "${SNIFFSTER_BOOST_ROOT}" CACHE PATH
        "Boost root directory selected by sniffster" FORCE)
    set(BOOST_ROOT "${SNIFFSTER_BOOST_ROOT}" CACHE PATH
        "Boost root directory selected by sniffster" FORCE)
    set(Boost_NO_SYSTEM_PATHS ON CACHE BOOL
        "Restrict Boost discovery to the selected sniffster Boost root" FORCE)
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

if(SNIFFSTER_STDLIB_COMPILE_OPTIONS)
    add_compile_options(${SNIFFSTER_STDLIB_COMPILE_OPTIONS})
endif()

if(SNIFFSTER_STDLIB_LINK_OPTIONS)
    add_link_options(${SNIFFSTER_STDLIB_LINK_OPTIONS})
endif()

# ─────────────────────────────────────────────────────────────────────────────
# Feature detection
# ─────────────────────────────────────────────────────────────────────────────

set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} -std=c++${CMAKE_CXX_STANDARD}")
if(SNIFFSTER_STDLIB_REQUIRED_FLAGS)
    set(CMAKE_REQUIRED_FLAGS
        "${CMAKE_REQUIRED_FLAGS} ${SNIFFSTER_STDLIB_REQUIRED_FLAGS}")
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
    message(FATAL_ERROR
        "The configured C++ toolchain does not provide <print>.\n"
        "Compiler: ${CMAKE_CXX_COMPILER}\n"
        "Requested stdlib: ${SNIFFSTER_CXX_STDLIB}\n"
        "${SNIFFSTER_STDLIB_STD_PRINT_HINT}")
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
    sniffer/sniffer.cppm
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


find_package(Boost REQUIRED COMPONENTS program_options filesystem log log_setup)
find_package(Threads REQUIRED)

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

function(sniffster_add_module_library target)
    add_library(${target} STATIC)
    target_link_libraries(${target}
        PUBLIC
        Threads::Threads
    )
    target_sources(${target}
        PUBLIC
        FILE_SET CXX_MODULES
        BASE_DIRS ${CMAKE_SOURCE_DIR}
        FILES
            ${ARGN}
    )
    target_include_directories(${target}
        PUBLIC
        ${CMAKE_SOURCE_DIR}
    )
endfunction()

function(sniffster_enable_boost_log_compilation target)
    target_compile_definitions(${target}
        PRIVATE
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
endfunction()

sniffster_add_module_library(sniffster_platform_modules
    ${CMAKE_SOURCE_DIR}/platform/arch_detect.cppm
    ${CMAKE_SOURCE_DIR}/platform/decorated_throw.cppm
    ${CMAKE_SOURCE_DIR}/platform/debug.cppm
    ${CMAKE_SOURCE_DIR}/platform/platform.cppm
)

sniffster_add_module_library(sniffster_addresses_modules
    ${CMAKE_SOURCE_DIR}/network/addresses.cppm
)

sniffster_add_module_library(sniffster_config_modules
    ${CMAKE_SOURCE_DIR}/network/config.cppm
)
target_link_libraries(sniffster_config_modules
    PUBLIC
    sniffster_addresses_modules
    sniffster_platform_modules
)

sniffster_add_module_library(sniffster_network_misc_modules
    ${CMAKE_SOURCE_DIR}/network/nicq_ethtool.cppm
    ${CMAKE_SOURCE_DIR}/network/nicq_fs.cppm
    ${CMAKE_SOURCE_DIR}/network/nicq_detector.cppm
)

sniffster_add_module_library(sniffster_format_modules
    ${CMAKE_SOURCE_DIR}/processors/format_data.cppm
)
target_link_libraries(sniffster_format_modules
    PUBLIC
    sniffster_platform_modules
)

sniffster_add_module_library(sniffster_runtime_modules
    ${CMAKE_SOURCE_DIR}/sniffer/runtime_control.cppm
)

sniffster_add_module_library(sniffster_packet_meta_modules
    ${CMAKE_SOURCE_DIR}/processors/packet_meta_event.cppm
)
target_link_libraries(sniffster_packet_meta_modules
    PUBLIC
    sniffster_addresses_modules
    sniffster_platform_modules
)

sniffster_add_module_library(sniffster_packet_print_modules
    ${CMAKE_SOURCE_DIR}/processors/packet_print.cppm
)
target_link_libraries(sniffster_packet_print_modules
    PUBLIC
    sniffster_addresses_modules
    sniffster_format_modules
    sniffster_packet_meta_modules
    sniffster_platform_modules
)

sniffster_add_module_library(sniffster_queue_modules
    ${CMAKE_SOURCE_DIR}/processors/queue_processor.cppm
)
target_link_libraries(sniffster_queue_modules
    PUBLIC
    sniffster_platform_modules
    sniffster_runtime_modules
)

sniffster_add_module_library(sniffster_logger_modules
    ${CMAKE_SOURCE_DIR}/processors/logger_event.cppm
    ${CMAKE_SOURCE_DIR}/processors/logger_processor.cppm
)
target_link_libraries(sniffster_logger_modules
    PUBLIC
    sniffster_packet_meta_modules
    sniffster_platform_modules
    sniffster_queue_modules
    Boost::log
)
sniffster_enable_boost_log_compilation(sniffster_logger_modules)

sniffster_add_module_library(sniffster_packet_processor_modules
    ${CMAKE_SOURCE_DIR}/processors/packet_processor.cppm
)
target_link_libraries(sniffster_packet_processor_modules
    PUBLIC
    sniffster_logger_modules
    sniffster_packet_print_modules
    sniffster_platform_modules
    sniffster_queue_modules
)

sniffster_add_module_library(sniffster_packet_handler_modules
    ${CMAKE_SOURCE_DIR}/sniffer/packet_handler.cppm
)
target_include_directories(sniffster_packet_handler_modules
    PRIVATE
    ${LIBBPF_INCLUDE_DIRS}
)
target_link_libraries(sniffster_packet_handler_modules
    PUBLIC
    sniffster_logger_modules
    sniffster_packet_print_modules
    sniffster_packet_processor_modules
    sniffster_platform_modules
)

sniffster_add_module_library(sniffster_xdp_copy_handler_modules
    ${CMAKE_SOURCE_DIR}/sniffer/xdp_copy_handler.cppm
)
target_include_directories(sniffster_xdp_copy_handler_modules
    PRIVATE
    ${LIBBPF_INCLUDE_DIRS}
)
target_link_libraries(sniffster_xdp_copy_handler_modules
    PUBLIC
    sniffster_format_modules
    sniffster_packet_handler_modules
    sniffster_platform_modules
    sniffster_runtime_modules
)

sniffster_add_module_library(sniffster_xdp_loader_modules
    ${CMAKE_SOURCE_DIR}/sniffer/threading_config.cppm
    ${SNIFFER_XDPCOPY_LOADER_MODULE}
)
target_include_directories(sniffster_xdp_loader_modules
    PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${LIBBPF_INCLUDE_DIRS}
)
target_link_libraries(sniffster_xdp_loader_modules
    PUBLIC
    sniffster_config_modules
    sniffster_platform_modules
)
add_dependencies(sniffster_xdp_loader_modules sniffer_xdpcopy)

add_dependencies(sniffster sniffer_xdpcopy)

# ─────────────────────────────────────────────────────────────────────────────
# Linking
# ─────────────────────────────────────────────────────────────────────────────

target_link_libraries(sniffster PRIVATE
    sniffster_config_modules
    sniffster_logger_modules
    sniffster_network_misc_modules
    sniffster_platform_modules
    sniffster_runtime_modules
    sniffster_xdp_loader_modules
    sniffster_xdp_copy_handler_modules
    sniffster_packet_handler_modules
    sniffster_packet_processor_modules
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
