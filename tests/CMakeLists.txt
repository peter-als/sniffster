include(FetchContent)

fetchcontent_declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.15.2
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
fetchcontent_makeavailable(googletest)

include(GoogleTest)

function(sniffster_init_test_target target)
    target_include_directories(${target}
        PRIVATE
        ${CMAKE_SOURCE_DIR}
    )
endfunction()

add_executable(config_tests
    config_test.cpp
)
sniffster_init_test_target(config_tests)
target_link_libraries(config_tests PRIVATE
    GTest::gtest_main
    sniffster_config_modules
)
gtest_discover_tests(config_tests DISCOVERY_MODE PRE_TEST)

add_executable(network_misc_tests
    network_misc_test.cpp
)
sniffster_init_test_target(network_misc_tests)
target_link_libraries(network_misc_tests PRIVATE
    GTest::gtest_main
    sniffster_network_misc_modules
)
gtest_discover_tests(network_misc_tests DISCOVERY_MODE PRE_TEST)

add_executable(platform_tests
    platform_test.cpp
)
sniffster_init_test_target(platform_tests)
target_link_libraries(platform_tests PRIVATE
    GTest::gtest_main
    sniffster_platform_modules
)
gtest_discover_tests(platform_tests DISCOVERY_MODE PRE_TEST)

add_executable(manual_nic_detect_queues
    manual/nic_detect_queues.cpp
)
sniffster_init_test_target(manual_nic_detect_queues)
target_link_libraries(manual_nic_detect_queues PRIVATE
    sniffster_network_misc_modules
)

add_executable(manual_arch_bits
    manual/arch_bits.cpp
)
sniffster_init_test_target(manual_arch_bits)

add_executable(manual_network_config
    manual/network_config.cpp
)
sniffster_init_test_target(manual_network_config)
target_link_libraries(manual_network_config PRIVATE
    sniffster_config_modules
    sniffster_format_modules
)

add_executable(manual_demo_decorated_errors
    manual/demo_decorated_errors.cpp
)
sniffster_init_test_target(manual_demo_decorated_errors)
target_link_libraries(manual_demo_decorated_errors PRIVATE
    sniffster_platform_modules
)

add_executable(packet_print_tests
    packet_print_test.cpp
)
sniffster_init_test_target(packet_print_tests)
target_link_libraries(packet_print_tests PRIVATE
    GTest::gtest_main
    sniffster_packet_meta_modules
    sniffster_packet_print_modules
)
gtest_discover_tests(packet_print_tests DISCOVERY_MODE PRE_TEST)

add_executable(runtime_control_tests
    runtime_control_test.cpp
)
sniffster_init_test_target(runtime_control_tests)
target_link_libraries(runtime_control_tests PRIVATE
    GTest::gtest_main
    sniffster_runtime_modules
)
gtest_discover_tests(runtime_control_tests DISCOVERY_MODE PRE_TEST)

add_executable(logger_processor_tests
    logger_processor_test.cpp
)
sniffster_init_test_target(logger_processor_tests)
target_link_libraries(logger_processor_tests PRIVATE
    GTest::gtest_main
    Boost::log
    Boost::log_setup
    sniffster_logger_modules
    sniffster_runtime_modules
)
sniffster_enable_boost_log_compilation(logger_processor_tests)
gtest_discover_tests(logger_processor_tests DISCOVERY_MODE PRE_TEST)

add_executable(queue_processor_tests
    queue_processor_test.cpp
)
sniffster_init_test_target(queue_processor_tests)
target_link_libraries(queue_processor_tests PRIVATE
    GTest::gtest_main
    sniffster_queue_modules
    sniffster_runtime_modules
)
gtest_discover_tests(queue_processor_tests DISCOVERY_MODE PRE_TEST)

add_executable(packet_processor_tests
    packet_processor_test.cpp
)
sniffster_init_test_target(packet_processor_tests)
target_link_libraries(packet_processor_tests PRIVATE
    GTest::gtest_main
    Boost::log
    sniffster_logger_modules
    sniffster_packet_processor_modules
)
sniffster_enable_boost_log_compilation(packet_processor_tests)
gtest_discover_tests(packet_processor_tests DISCOVERY_MODE PRE_TEST)

add_executable(xdp_copy_mode_loader_tests
    xdp_copy_mode_loader_test.cpp
)
sniffster_init_test_target(xdp_copy_mode_loader_tests)
target_link_libraries(xdp_copy_mode_loader_tests PRIVATE
    GTest::gtest_main
    sniffster_config_modules
    sniffster_xdp_loader_modules
)
gtest_discover_tests(xdp_copy_mode_loader_tests DISCOVERY_MODE PRE_TEST)

add_executable(sniffer_runtime_tests
    sniffer_runtime_test.cpp
)
sniffster_init_test_target(sniffer_runtime_tests)
target_link_libraries(sniffer_runtime_tests PRIVATE
    GTest::gtest_main
    Boost::log
    Boost::log_setup
    sniffster_logger_modules
    sniffster_packet_handler_modules
    sniffster_packet_processor_modules
    sniffster_runtime_modules
    sniffster_xdp_copy_handler_modules
)
sniffster_enable_boost_log_compilation(sniffer_runtime_tests)
gtest_discover_tests(sniffer_runtime_tests DISCOVERY_MODE PRE_TEST)

add_executable(packet_handler_tests
    packet_handler_test.cpp
)
sniffster_init_test_target(packet_handler_tests)
target_link_libraries(packet_handler_tests PRIVATE
    GTest::gtest_main
    Boost::log
    Boost::log_setup
    sniffster_logger_modules
    sniffster_packet_handler_modules
    sniffster_packet_processor_modules
    sniffster_runtime_modules
)
sniffster_enable_boost_log_compilation(packet_handler_tests)
gtest_discover_tests(packet_handler_tests DISCOVERY_MODE PRE_TEST)
