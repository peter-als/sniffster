module;

#include <fstream>
#include <format>
#include <string>
#include <string_view>
#include <filesystem>
#include <chrono>
#include <functional>
#include <linux/if_ether.h>
#include <thread>
#include <utility>
#include <stop_token>
#include <span>

#include "platform/arch_macros.h"

export module sniffster.packet_processor;

import sniffster.queue_processor;
export import sniffster.packet_meta_event;
import sniffster.logger_processor;
import sniffster.logger_event;
import sniffster.packet_print;
import sniffster.platform.decorated_throw;

export namespace sniffster {

class packet_processor : public queue_processor<packet_processor, packet_meta_event> {
public:
    // using queue_processor<packet_processor, packet_meta_event>::queue_processor;
    using event_type = packet_meta_event;

    explicit
    packet_processor(logger_processor& logger, const char* traffic_log_path) : 
            queue_processor<packet_processor, packet_meta_event>::queue_processor(),
            tell_logger_(logger),
            report_file_(traffic_log_path ? traffic_log_path : "traffic.log", std::ios::app | std::ios::out) {
        tell_logger_.register_producer(logger_event_queue_);

        if (!report_file_) {
            platform::throw_runtime_error(std::format("failed to open traffic log file: {}",
                                                      traffic_log_path ? traffic_log_path : "traffic.log"));
        }

        batch_buffer_view_ = std::span<char>(batch_buffer_.data(), batch_buffer_.size());
    }
    
    void handle(const event_type& value) {

        batch_buffer_view_ = append_event_jsonl(batch_buffer_view_, value);
        ++batched_event_count_;

        if (batched_event_count_ >= min_batched_events_) {
            flush_pending_();
        }
    }

    ~packet_processor() {
        try {
            flush_pending_();
        } catch (...) {
        }
    }

private:
    force_inline_
    void flush_pending_() {
        if (batched_event_count_ == 0) {
            return;
        }

        auto used_buffer_size = batch_buffer_.size() - batch_buffer_view_.size();
        report_file_.write((const char*)batch_buffer_.data(),
                           static_cast<std::streamsize>(used_buffer_size));
                           
        report_file_.flush();
        if (!report_file_) {
            platform::throw_runtime_error("failed to write traffic log batch");
        }

        batched_event_count_ = 0;
        batch_buffer_view_ = std::span<char>(batch_buffer_.data(), batch_buffer_.size());
    }

    constexpr static std::size_t min_batched_events_ = 10;
    constexpr static std::size_t batch_buffer_reserve_bytes_ = 8192;
    constexpr static std::size_t logger_event_queue_max_size_ = 50;
    constexpr static std::size_t extra_buffer_space = 10; // for corner cases; 1 could be enough

    logger_processor& tell_logger_;
    logger_processor::queue_t logger_event_queue_{logger_event_queue_max_size_ + extra_buffer_space};
    std::ofstream report_file_;
    std::array<char, batch_buffer_reserve_bytes_> batch_buffer_;
    std::span<char> batch_buffer_view_;
    std::size_t batched_event_count_ = 0;
};

} // namespace sniffster
