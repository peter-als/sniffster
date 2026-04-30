module;
#include <atomic>
#include <barrier>
#include <cstddef>
#include <csignal>
#include <exception>
#include <string>
#include <sstream>
#include <thread>
#include <utility>
#include <print>
#include <vector>

#include "platform/arch_macros.h"

export module sniffster.sniffer;

import sniffster.bpf_loader.xdp_copy_mode_loader;
import sniffster.bpf_handler.xdp_copy_handler;
import sniffster.packet_handler;
import sniffster.network.config;
import sniffster.threading_config;
import sniffster.logger_processor;
import sniffster.packet_processor;
import sniffster.runtime_control;
import sniffster.platform.decorated_throw;

static std::string join_cpu_ids(const std::vector<std::uint32_t>& cpu_ids) {
    std::ostringstream out;
    bool first = true;
    for (auto cpu : cpu_ids) {
        if (!first) {
            out << ',';
        }
        first = false;
        out << cpu;
    }
    return out.str();
}

export namespace sniffster {

class sniffer {
public:
    explicit sniffer(network_interface interface,
                     logger_t& boost_logger,
                     std::string report_path,
                     runtime_control& runtime_ctrl,
                     const threading_config& threading_config = {}) :

        interface_(std::move(interface)),
        runtime_control_(runtime_ctrl),
        threading_config_(threading_config),
        loader_(interface_),
        logger_(boost_logger),
        packet_processor_(logger_, report_path.c_str()) {}

    void run() {
        try {
            auto thread_count = threading_config_.thread_count;
            auto cpu_ids_per_thread = threading_config_.cpu_ids_per_thread();
            auto perf_map_fd = loader_.perf_map_fd();
            logger_.log_message("Successfully attached to {}  (Auto/Native Mode)", interface_.name);
            logger_.log_message("Listening on {} CPU perf buffers with {} handler threads.",
                                 threading_config_.cpu_ids.size(),
                                 thread_count);

            handlers_.reserve(thread_count);

            for (const auto& thread_cpu_ids : cpu_ids_per_thread) {
                const auto cpu_list = join_cpu_ids(thread_cpu_ids);
                logger_.log_message("starting handler for CPUs {}", cpu_list);

                // Each per-thread packet handler owns and self-registers its
                // queues in its constructor. Keeping registration local avoids
                // extra worker plumbing, while the barrier above still seals
                // the transition into steady-state processing.
                handlers_.emplace_back([this, perf_map_fd, thread_cpu_ids] {
                    packet_handler pkt_handler{packet_processor_, logger_};
                    xdp_copy_handler xdp_handler{perf_map_fd, thread_cpu_ids, pkt_handler};
                    xdp_handler.run(runtime_control_);
                });
            }

            std::jthread logger_thread([this] {
                logger_.run(runtime_control_);
            });

            // The packet event processor is running in the sniffer main thread.
            // Reusing the main thread, instead of creating a useless busy wait
            // or timeout sleep loop.
            logger_.log_message("Monitoring traffic across {} CPUs. Press Ctrl+C to stop.",
                                 threading_config_.cpu_ids.size());
            packet_processor_.run(runtime_control_);

            logger_.log_message("\nDetaching and exiting the main (processor) thread...");
            logger_.log_message("Waiting for the logger and all the handlers threads to join.");
        } catch (const std::exception& e) {
            platform::throw_runtime_error(e.what());
        }
    }

private:
    const network_interface interface_;
    runtime_control& runtime_control_;
    const threading_config& threading_config_;
    sniffster::xdp_copy_mode_loader loader_;
    logger_processor logger_;
    packet_processor packet_processor_;
    std::vector<std::jthread> handlers_;
}; // class sniffer

} // namespace sniffster
