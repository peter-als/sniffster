#include <iostream>
#include <fstream>
#include <string>
#include <format>
#include <cstdint>
#include <csignal>
#include <chrono>
#include <thread>
#include <filesystem>
#include <vector>
#include <CLI/CLI.hpp>
#include <print>
#include <boost/log/trivial.hpp>
#include <boost/log/utility/setup/console.hpp>
#include <boost/log/utility/setup/file.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>

// Network/Kernel headers
#include <net/if.h>
#include <linux/if_link.h>

// BPF headers
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <ostream>

import sniffster.sniffer;
import sniffster.network.config;
import sniffster.network.nicq_detector;
import sniffster.threading_config;
import sniffster.logger_processor;
import sniffster.platform.decorated_throw;
import sniffster.runtime_control;

namespace {

std::string normalize_output_path(std::string_view raw_path, std::string_view default_filename) {
    namespace fs = std::filesystem;

    fs::path candidate(raw_path);
    if (candidate.empty()) {
        platform::throw_runtime_error("output path must not be empty");
    }

    if (fs::exists(candidate)) {
        if (fs::is_directory(candidate)) {
            candidate /= default_filename;
        } else if (!fs::is_regular_file(candidate)) {
            platform::throw_runtime_error(
                std::format("output path is neither a file nor a directory: {}",
                            candidate.string()));
        }
    }

    const fs::path parent = candidate.has_parent_path() ? candidate.parent_path() : fs::current_path();
    if (!fs::exists(parent)) {
        platform::throw_runtime_error(
            std::format("destination directory does not exist: {}",
                        parent.string()));
    }

    if (!fs::is_directory(parent)) {
        platform::throw_runtime_error(
            std::format("destination parent is not a directory: {}",
                        parent.string()));
    }

    if (fs::exists(candidate) && fs::is_directory(candidate)) {
        platform::throw_runtime_error(
            std::format("resolved output path is a directory: {}",
                        candidate.string()));
    }

    return candidate.string();
}

} // namespace


// --- Main Execution ---
int main(int argc, char **argv) {
    try {
        CLI::App app{R"(
                Sniffster
                ============
                A tool for collecting network traffic statistics.
                )"};

        argv = app.ensure_utf8(argv);

        std::string iface {};
        std::string log_path {"/var/log/sniffster.log"};
        std::string report_path {"/var/log/sniffster.traffic.log"};
        std::uint32_t requested_thread_count {0};
        std::vector<std::uint32_t> requested_cpu_ids {};

        app.add_option("-i,--network-interface", iface,
          "Network interface to collect traffic from (mandatory).")->required();

        app.add_option("-l,--log", log_path, "Path to status log file");
        app.add_option("-r,--report", report_path, "Path to traffic report file");
        auto* thread_count_option = app.add_option(
            "-t,--thread-count",
            requested_thread_count,
            "Number of handler threads to create"
        );
        thread_count_option->check(CLI::PositiveNumber);

        auto* cpus_option = app.add_option(
            "-u,--cpus",
            requested_cpu_ids,
            "Comma-separated CPU ids to assign to handler threads"
        );
        cpus_option->delimiter(',');
        thread_count_option->excludes(cpus_option);

        CLI11_PARSE(app, argc, argv);

        log_path = normalize_output_path(log_path, "sniffster.log");
        report_path = normalize_output_path(report_path, "sniffster.traffic.log");

        namespace logging = boost::log;
        namespace keywords = boost::log::keywords;

        logging::add_console_log(std::cout,
            keywords::format = "[%TimeStamp%] [%Severity%] %Message%");

        logging::add_file_log(
            keywords::file_name = log_path,
            keywords::auto_flush = true,
            keywords::format = "[%TimeStamp%] [%Severity%] %Message%"
        );

        logging::add_common_attributes();

        sniffster::logger_t boost_logger{sniffster::severity_level::debug};

        auto log_startup = [&](std::string_view message) {
            BOOST_LOG_SEV(boost_logger, sniffster::severity_level::debug) << message;
        };

        log_startup(std::format("Starting sniffster with interface: {}", iface));
        const sniffster::network_interface interface_config(iface);
        // Initialize the detector from our module
        sniffster::nic_queue_detector detector(interface_config.name);

        log_startup(std::format("Detecting queues for interface: {}", iface));

        // Detect the hardware parallelism available
        const auto detected_queue_count = detector.detect_queues();
        if (detected_queue_count) {
            log_startup(std::format("Detected {} queues for interface: {}",
                                    *detected_queue_count,
                                    iface));
        } else {
            log_startup(std::format("Failed to detect queues for interface: {}", iface));
        }
        
        log_startup(std::format("Creating sniffer for interface: {}", iface));
        const sniffster::threading_config threading_config (requested_thread_count, requested_cpu_ids);

        // running it in the main thread context.
        log_startup("Starting sniffer");

        // The runtime control object acts as a barrier (among other things).
        // One barrier guards both edges of the queue-lifetime contract:
        // - startup: processors do not drain until every handler has
        //   finished self-registering its queues
        // - shutdown: handlers do not destroy those queues until processors
        //   have stopped touching them
        
        // The runtime control object manages the barrier and the shutdown signal.
        // The number of threads to sync is the number of handler threads plus
        // the main thread and the processor thread.
        sniffster::runtime_control runtime_ctrl(threading_config.thread_count + 2);

        sniffster::sniffer sniff(interface_config,
                                 boost_logger,
                                 report_path,
                                 runtime_ctrl,
                                 threading_config);
        
        log_startup(std::format("Status log file: {}", log_path));
        log_startup(std::format("Report log file: {}", report_path));
        sniff.run();

        log_startup("All done. Exiting now. See you next time!");

        return 0;
    } catch (const std::exception& err) {
        std::println(std::cerr, "ERROR: {}", err.what());
    } catch (...) {
        std::println(std::cerr, "ERROR: unknown exception");
    }

    return EXIT_FAILURE;
}
