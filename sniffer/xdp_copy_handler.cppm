module;

#include <array>
#include <barrier>
#include <cstdio>
#include <cstdint>
#include <format>
#include <string>
#include <string_view>
#include <stop_token>
#include <print>
#include <bpf/libbpf.h>
#include <linux/perf_event.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <boost/circular_buffer.hpp>
#include <boost/lockfree/spsc_queue.hpp>
#include <thread>

#include "platform/arch_macros.h"
#include "network/packet_offsets.h"

export module sniffster.bpf_handler.xdp_copy_handler;

import sniffster.processors.format_data;
import sniffster.platform;
import sniffster.platform.decorated_throw;
import sniffster.debug;
import sniffster.packet_handler;
import sniffster.runtime_control;

namespace sniffster {

export class xdp_copy_handler {
public:
    explicit xdp_copy_handler(int perf_map_fd,
                              std::vector<std::uint32_t> cpu_ids,
                              packet_handler& packet_handler) :

                cpu_ids_(std::move(cpu_ids)),
                packet_handler_(packet_handler),
                cpu_ids_str_(cpu_ids_description()) {

        if (cpu_ids_.empty()) {
            platform::throw_runtime_error("xdp_copy_handler requires at least one CPU id");
        }

        init_perf_queue(perf_map_fd);
    }

    ~xdp_copy_handler() {
        if (perf_buffer_) {
            perf_buffer__free(perf_buffer_);
        }
    }

    xdp_copy_handler(const xdp_copy_handler&) = delete;
    xdp_copy_handler& operator=(const xdp_copy_handler&) = delete;

    xdp_copy_handler(xdp_copy_handler&&) = delete;
    xdp_copy_handler& operator=(xdp_copy_handler&&) = delete;

    void run(runtime_control& runtime_ctrl) {
        // Do not start polling until every handler has finished constructing
        // and every processor thread is ready to observe a fully-registered
        // queue set.
        runtime_ctrl.arrive_and_wait();

        while (!runtime_ctrl.stop_requested()) {
            const int err = perf_buffer__poll(perf_buffer_, poll_timeout_ms_);
            if (err < 0) {
                platform::throw_runtime_error(std::format("Failed to poll perf buffer for CPUs {}",
                                                          cpu_ids_str_));
            }

            packet_handler_.finish_loop();
        }

        // Wake waiting consumers so they can observe the stop request and finish
        // draining while the packet handler and its registered queues are still
        // alive.
        packet_handler_.we_are_done();

        // Only after processors have also left their run loops may this handler
        // and the packet handler tear down and destroy their queues.
        runtime_ctrl.arrive_and_wait();
    }

private:

    static enum bpf_perf_event_ret handle_event(void* ctx,
                                                int cpu,
                                                struct perf_event_header* event);

    static void handle_lost(void *ctx, int cpu, __u64 count) {
        auto *self = static_cast<xdp_copy_handler *>(ctx);
        self->packet_handler_.log_message("Lost {} events on queue/cpu {}",
                                         static_cast<unsigned long long>(count), cpu);
    }

    // For debugging convenience and throwing exceptions
    [[nodiscard]] std::string cpu_ids_description() const {
        std::string description;
        for (std::size_t i = 0; i < cpu_ids_.size(); ++i) {
            if (i > 0) {
                description += ",";
            }
            description += std::to_string(cpu_ids_[i]);
        }
        return description;
    }

    void init_perf_queue(int perf_map_fd) {
        // Perf event attributes
        struct perf_event_attr attr{};  // zero-initialize
        attr.size = sizeof(attr);       // this tells the kernel the perf_event_attr versin (size)
        attr.type = PERF_TYPE_SOFTWARE; // we're doing software perf events (and not hardware)
        attr.config = PERF_COUNT_SW_BPF_OUTPUT; // specify how the event is expected to be sent
        attr.sample_type = PERF_SAMPLE_RAW;     // events are raw blobs prefixed by their size
        attr.sample_period = 1;         // wake userspace after every sample written
        attr.wakeup_events = 1;         // request a wakeup on every event (rather than batching)

        // Perf event options
        perf_buffer_raw_opts opts{};    // zero-initialize
        opts.sz = sizeof(opts);         // size of options struct
        opts.cpu_cnt = static_cast<int>(cpu_ids_.size());

        cpu_keys_.reserve(cpu_ids_.size());
        map_keys_.reserve(cpu_ids_.size());
        for (const auto cpu_id : cpu_ids_) {
            cpu_keys_.push_back(static_cast<int>(cpu_id));
            map_keys_.push_back(static_cast<int>(cpu_id));
        }

        opts.cpus = cpu_keys_.data();
        opts.map_keys = map_keys_.data();

        // Create one raw perf-buffer reader
        perf_buffer_ = perf_buffer__new_raw(perf_map_fd,
                                            page_cnt_,
                                            &attr,
                                            handle_event,
                                            this,
                                            &opts);

        // Fail fast if libbpf could not create or mmap the per-handler buffer.
        if (!perf_buffer_) {
            platform::throw_runtime_error(std::format("Failed to setup perf buffer for CPUs {}",
                                                      cpu_ids_str_));
        }
    }

private:
    const std::vector<std::uint32_t> cpu_ids_;
    packet_handler& packet_handler_;
    std::string cpu_ids_str_; // for slow path / exceptions
    std::vector<int> cpu_keys_{};
    std::vector<int> map_keys_{};
    struct perf_buffer* perf_buffer_ = nullptr;
    static constexpr size_t page_cnt_ = 64;
    static constexpr int poll_timeout_ms_ = 100;
};

enum bpf_perf_event_ret
xdp_copy_handler::handle_event(void *ctx, int cpu, struct perf_event_header *event) {
    auto *self = static_cast<xdp_copy_handler *>(ctx);

    if (event->type == PERF_RECORD_SAMPLE) {
        const uint8_t* data = reinterpret_cast<const uint8_t*>(event) + sizeof(*event);

        std::uint32_t size;
        // perf data (not from the wire), no need to check byte order.
        memcpy_(&size, data, sizeof(size));
        data += sizeof(size);

        self->packet_handler_.process_sample(cpu, data, size);
        return LIBBPF_PERF_EVENT_CONT;
    }

    if (event->type == PERF_RECORD_LOST) {
        self->packet_handler_.log_message("Lost perf events on CPU {}", cpu);
        return LIBBPF_PERF_EVENT_CONT;
    }

    return LIBBPF_PERF_EVENT_CONT;
}

} // namespace sniff
