include(FetchContent)

fetchcontent_declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.15.2
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
fetchcontent_makeavailable(googletest)

include(GoogleTest)

add_executable(config_tests
    config_test.cpp
)

target_sources(config_tests
    PRIVATE
    FILE_SET CXX_MODULES
    BASE_DIRS ${CMAKE_SOURCE_DIR}
    FILES
        ${CMAKE_SOURCE_DIR}/platform/decorated_throw.cppm
        ${CMAKE_SOURCE_DIR}/network/addresses.cppm
        ${CMAKE_SOURCE_DIR}/network/config.cppm
)

target_link_libraries(config_tests PRIVATE
    GTest::gtest_main
)

gtest_discover_tests(config_tests DISCOVERY_MODE PRE_TEST)

add_executable(network_misc_tests
    network_misc_test.cpp
)

target_sources(network_misc_tests
    PRIVATE
    FILE_SET CXX_MODULES
    BASE_DIRS ${CMAKE_SOURCE_DIR}
    FILES
        ${CMAKE_SOURCE_DIR}/platform/arch_detect.cppm
        ${CMAKE_SOURCE_DIR}/platform/clock.cppm
        ${CMAKE_SOURCE_DIR}/platform/decorated_throw.cppm
        ${CMAKE_SOURCE_DIR}/platform/debug.cppm
        ${CMAKE_SOURCE_DIR}/platform/platform.cppm
        ${CMAKE_SOURCE_DIR}/network/nicq_ethtool.cppm
        ${CMAKE_SOURCE_DIR}/network/nicq_fs.cppm
        ${CMAKE_SOURCE_DIR}/network/nicq_detector.cppm
)

target_link_libraries(network_misc_tests PRIVATE
    GTest::gtest_main
)

gtest_discover_tests(network_misc_tests DISCOVERY_MODE PRE_TEST)

add_executable(platform_tests
    platform_test.cpp
)

target_sources(platform_tests
    PRIVATE
    FILE_SET CXX_MODULES
    BASE_DIRS ${CMAKE_SOURCE_DIR}
    FILES
        ${CMAKE_SOURCE_DIR}/platform/arch_detect.cppm
        ${CMAKE_SOURCE_DIR}/platform/clock.cppm
        ${CMAKE_SOURCE_DIR}/platform/decorated_throw.cppm
        ${CMAKE_SOURCE_DIR}/platform/debug.cppm
        ${CMAKE_SOURCE_DIR}/platform/platform.cppm
)

target_link_libraries(platform_tests PRIVATE
    GTest::gtest_main
)

gtest_discover_tests(platform_tests DISCOVERY_MODE PRE_TEST)

add_executable(manual_nic_detect_queues
    manual/nic_detect_queues.cpp
)

target_sources(manual_nic_detect_queues
    PRIVATE
    FILE_SET CXX_MODULES
    BASE_DIRS ${CMAKE_SOURCE_DIR}
    FILES
        ${CMAKE_SOURCE_DIR}/network/nicq_ethtool.cppm
        ${CMAKE_SOURCE_DIR}/network/nicq_fs.cppm
        ${CMAKE_SOURCE_DIR}/network/nicq_detector.cppm
)

add_executable(manual_arch_bits
    manual/arch_bits.cpp
)

add_executable(manual_network_config
    manual/network_config.cpp
)

target_sources(manual_network_config
    PRIVATE
    FILE_SET CXX_MODULES
    BASE_DIRS ${CMAKE_SOURCE_DIR}
    FILES
        ${CMAKE_SOURCE_DIR}/platform/arch_detect.cppm
        ${CMAKE_SOURCE_DIR}/platform/clock.cppm
        ${CMAKE_SOURCE_DIR}/platform/decorated_throw.cppm
        ${CMAKE_SOURCE_DIR}/platform/platform.cppm
        ${CMAKE_SOURCE_DIR}/network/addresses.cppm
        ${CMAKE_SOURCE_DIR}/network/config.cppm
        ${CMAKE_SOURCE_DIR}/processors/format_data.cppm
)

add_executable(manual_demo_decorated_errors
    manual/demo_decorated_errors.cpp
)

target_sources(manual_demo_decorated_errors
    PRIVATE
    FILE_SET CXX_MODULES
    BASE_DIRS ${CMAKE_SOURCE_DIR}
    FILES
        ${CMAKE_SOURCE_DIR}/platform/decorated_throw.cppm
)

add_executable(clock_tests
    clock_test.cppm
)

target_sources(clock_tests
    PRIVATE
    FILE_SET CXX_MODULES
    BASE_DIRS ${CMAKE_SOURCE_DIR}
    FILES
        ${CMAKE_SOURCE_DIR}/platform/arch_detect.cppm
        ${CMAKE_SOURCE_DIR}/platform/clock.cppm
        ${CMAKE_SOURCE_DIR}/platform/decorated_throw.cppm
        ${CMAKE_SOURCE_DIR}/platform/debug.cppm
        ${CMAKE_SOURCE_DIR}/platform/platform.cppm
)

set_source_files_properties(clock_test.cppm PROPERTIES LANGUAGE CXX)

target_link_libraries(clock_tests PRIVATE
    GTest::gtest_main
)

gtest_discover_tests(clock_tests DISCOVERY_MODE PRE_TEST)

add_executable(packet_print_tests
    packet_print_test.cpp
)

target_sources(packet_print_tests
    PRIVATE
    FILE_SET CXX_MODULES
    BASE_DIRS ${CMAKE_SOURCE_DIR}
    FILES
        ${CMAKE_SOURCE_DIR}/platform/arch_detect.cppm
        ${CMAKE_SOURCE_DIR}/platform/clock.cppm
        ${CMAKE_SOURCE_DIR}/platform/decorated_throw.cppm
        ${CMAKE_SOURCE_DIR}/platform/debug.cppm
        ${CMAKE_SOURCE_DIR}/platform/platform.cppm
        ${CMAKE_SOURCE_DIR}/network/addresses.cppm
        ${CMAKE_SOURCE_DIR}/processors/format_data.cppm
        ${CMAKE_SOURCE_DIR}/processors/packet_meta_event.cppm
        ${CMAKE_SOURCE_DIR}/processors/packet_print.cppm
)

target_link_libraries(packet_print_tests PRIVATE
    GTest::gtest_main
)

gtest_discover_tests(packet_print_tests DISCOVERY_MODE PRE_TEST)

add_executable(runtime_control_tests
    runtime_control_test.cpp
)

target_sources(runtime_control_tests
    PRIVATE
    FILE_SET CXX_MODULES
    BASE_DIRS ${CMAKE_SOURCE_DIR}
    FILES
        ${CMAKE_SOURCE_DIR}/sniffer/runtime_control.cppm
)

target_link_libraries(runtime_control_tests PRIVATE
    GTest::gtest_main
)

gtest_discover_tests(runtime_control_tests DISCOVERY_MODE PRE_TEST)

add_executable(logger_processor_tests
    logger_processor_test.cpp
)

target_sources(logger_processor_tests
    PRIVATE
    FILE_SET CXX_MODULES
    BASE_DIRS ${CMAKE_SOURCE_DIR}
    FILES
        ${CMAKE_SOURCE_DIR}/platform/arch_detect.cppm
        ${CMAKE_SOURCE_DIR}/platform/clock.cppm
        ${CMAKE_SOURCE_DIR}/platform/decorated_throw.cppm
        ${CMAKE_SOURCE_DIR}/platform/debug.cppm
        ${CMAKE_SOURCE_DIR}/platform/platform.cppm
        ${CMAKE_SOURCE_DIR}/network/addresses.cppm
        ${CMAKE_SOURCE_DIR}/processors/packet_meta_event.cppm
        ${CMAKE_SOURCE_DIR}/processors/logger_event.cppm
        ${CMAKE_SOURCE_DIR}/processors/queue_processor.cppm
        ${CMAKE_SOURCE_DIR}/processors/logger_processor.cppm
        ${CMAKE_SOURCE_DIR}/sniffer/runtime_control.cppm
)

target_link_libraries(logger_processor_tests PRIVATE
    GTest::gtest_main
    Boost::log
    Boost::log_setup
)

target_compile_definitions(logger_processor_tests PRIVATE
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

gtest_discover_tests(logger_processor_tests DISCOVERY_MODE PRE_TEST)

add_executable(queue_processor_tests
    queue_processor_test.cpp
)

target_sources(queue_processor_tests
    PRIVATE
    FILE_SET CXX_MODULES
    BASE_DIRS ${CMAKE_SOURCE_DIR}
    FILES
        ${CMAKE_SOURCE_DIR}/platform/arch_detect.cppm
        ${CMAKE_SOURCE_DIR}/platform/clock.cppm
        ${CMAKE_SOURCE_DIR}/platform/decorated_throw.cppm
        ${CMAKE_SOURCE_DIR}/platform/debug.cppm
        ${CMAKE_SOURCE_DIR}/platform/platform.cppm
        ${CMAKE_SOURCE_DIR}/processors/queue_processor.cppm
        ${CMAKE_SOURCE_DIR}/sniffer/runtime_control.cppm
)

target_link_libraries(queue_processor_tests PRIVATE
    GTest::gtest_main
)

gtest_discover_tests(queue_processor_tests DISCOVERY_MODE PRE_TEST)

add_executable(packet_processor_tests
    packet_processor_test.cpp
)

target_sources(packet_processor_tests
    PRIVATE
    FILE_SET CXX_MODULES
    BASE_DIRS ${CMAKE_SOURCE_DIR}
    FILES
        ${CMAKE_SOURCE_DIR}/platform/arch_detect.cppm
        ${CMAKE_SOURCE_DIR}/platform/clock.cppm
        ${CMAKE_SOURCE_DIR}/platform/decorated_throw.cppm
        ${CMAKE_SOURCE_DIR}/platform/debug.cppm
        ${CMAKE_SOURCE_DIR}/platform/platform.cppm
        ${CMAKE_SOURCE_DIR}/network/addresses.cppm
        ${CMAKE_SOURCE_DIR}/processors/format_data.cppm
        ${CMAKE_SOURCE_DIR}/processors/packet_meta_event.cppm
        ${CMAKE_SOURCE_DIR}/processors/packet_print.cppm
        ${CMAKE_SOURCE_DIR}/processors/logger_event.cppm
        ${CMAKE_SOURCE_DIR}/processors/queue_processor.cppm
        ${CMAKE_SOURCE_DIR}/processors/logger_processor.cppm
        ${CMAKE_SOURCE_DIR}/processors/packet_processor.cppm
        ${CMAKE_SOURCE_DIR}/sniffer/runtime_control.cppm
)

target_link_libraries(packet_processor_tests PRIVATE
    GTest::gtest_main
    Boost::log
)

target_compile_definitions(packet_processor_tests PRIVATE
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

gtest_discover_tests(packet_processor_tests DISCOVERY_MODE PRE_TEST)

add_executable(xdp_copy_mode_loader_tests
    xdp_copy_mode_loader_test.cpp
)

target_include_directories(xdp_copy_mode_loader_tests PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}/..
)

target_sources(xdp_copy_mode_loader_tests
    PRIVATE
    FILE_SET CXX_MODULES
    BASE_DIRS ${CMAKE_SOURCE_DIR}
    FILES
        ${CMAKE_SOURCE_DIR}/platform/arch_detect.cppm
        ${CMAKE_SOURCE_DIR}/platform/clock.cppm
        ${CMAKE_SOURCE_DIR}/platform/decorated_throw.cppm
        ${CMAKE_SOURCE_DIR}/platform/debug.cppm
        ${CMAKE_SOURCE_DIR}/platform/platform.cppm
        ${CMAKE_SOURCE_DIR}/network/addresses.cppm
        ${CMAKE_SOURCE_DIR}/network/config.cppm
        ${CMAKE_SOURCE_DIR}/sniffer/threading_config.cppm
        ${CMAKE_SOURCE_DIR}/sniffer/xdp_copy_mode_loader.cppm
)

target_link_libraries(xdp_copy_mode_loader_tests PRIVATE
    GTest::gtest_main
)

gtest_discover_tests(xdp_copy_mode_loader_tests DISCOVERY_MODE PRE_TEST)

add_executable(sniffer_runtime_tests
    sniffer_runtime_test.cpp
)

target_sources(sniffer_runtime_tests
    PRIVATE
    FILE_SET CXX_MODULES
    BASE_DIRS ${CMAKE_SOURCE_DIR}
    FILES
        ${CMAKE_SOURCE_DIR}/platform/arch_detect.cppm
        ${CMAKE_SOURCE_DIR}/platform/clock.cppm
        ${CMAKE_SOURCE_DIR}/platform/decorated_throw.cppm
        ${CMAKE_SOURCE_DIR}/platform/debug.cppm
        ${CMAKE_SOURCE_DIR}/platform/platform.cppm
        ${CMAKE_SOURCE_DIR}/network/addresses.cppm
        ${CMAKE_SOURCE_DIR}/processors/format_data.cppm
        ${CMAKE_SOURCE_DIR}/processors/packet_meta_event.cppm
        ${CMAKE_SOURCE_DIR}/processors/packet_print.cppm
        ${CMAKE_SOURCE_DIR}/processors/logger_event.cppm
        ${CMAKE_SOURCE_DIR}/processors/queue_processor.cppm
        ${CMAKE_SOURCE_DIR}/processors/logger_processor.cppm
        ${CMAKE_SOURCE_DIR}/processors/packet_processor.cppm
        ${CMAKE_SOURCE_DIR}/sniffer/runtime_control.cppm
        ${CMAKE_SOURCE_DIR}/sniffer/packet_handler.cppm
        ${CMAKE_SOURCE_DIR}/sniffer/xdp_copy_handler.cppm
)

target_link_libraries(sniffer_runtime_tests PRIVATE
    GTest::gtest_main
    Boost::log
    Boost::log_setup
)

target_compile_definitions(sniffer_runtime_tests PRIVATE
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

gtest_discover_tests(sniffer_runtime_tests DISCOVERY_MODE PRE_TEST)

add_executable(packet_handler_tests
    packet_handler_test.cpp
)

target_sources(packet_handler_tests
    PRIVATE
    FILE_SET CXX_MODULES
    BASE_DIRS ${CMAKE_SOURCE_DIR}
    FILES
        ${CMAKE_SOURCE_DIR}/platform/arch_detect.cppm
        ${CMAKE_SOURCE_DIR}/platform/clock.cppm
        ${CMAKE_SOURCE_DIR}/platform/decorated_throw.cppm
        ${CMAKE_SOURCE_DIR}/platform/debug.cppm
        ${CMAKE_SOURCE_DIR}/platform/platform.cppm
        ${CMAKE_SOURCE_DIR}/network/addresses.cppm
        ${CMAKE_SOURCE_DIR}/processors/format_data.cppm
        ${CMAKE_SOURCE_DIR}/processors/packet_meta_event.cppm
        ${CMAKE_SOURCE_DIR}/processors/packet_print.cppm
        ${CMAKE_SOURCE_DIR}/processors/logger_event.cppm
        ${CMAKE_SOURCE_DIR}/processors/queue_processor.cppm
        ${CMAKE_SOURCE_DIR}/processors/logger_processor.cppm
        ${CMAKE_SOURCE_DIR}/processors/packet_processor.cppm
        ${CMAKE_SOURCE_DIR}/sniffer/runtime_control.cppm
        ${CMAKE_SOURCE_DIR}/sniffer/packet_handler.cppm
)

target_link_libraries(packet_handler_tests PRIVATE
    GTest::gtest_main
    Boost::log
    Boost::log_setup
)

target_compile_definitions(packet_handler_tests PRIVATE
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

gtest_discover_tests(packet_handler_tests DISCOVERY_MODE PRE_TEST)
