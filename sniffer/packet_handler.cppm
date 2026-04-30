module;

#include <algorithm>
#include <boost/circular_buffer.hpp>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstddef>
#include <format>
#include <string_view>

#include <bpf/libbpf.h>

#include <print>
#include <linux/if_ether.h>
#include <linux/perf_event.h>

#include "platform/arch_macros.h"
#include "network/packet_offsets.h"

export module sniffster.packet_handler;

// Implementation only, nothing gets exported.
import sniffster.packet_print;
import sniffster.packet_meta_event;
import sniffster.platform;
import sniffster.packet_processor;
import sniffster.logger_processor;

namespace sniffster {

force_inline_
bool process_ip4(packet_meta_event& event, const uint8_t* packet, size_t packet_sz) {
    if (packet_sz < ETH_HEADER_BYTES + IPV4_MIN_HEADER_BYTES) unlikely_ {
        return false;
    }

    const auto *ipv4_header = packet + ETH_HEADER_BYTES;
    const uint8_t ihl_words = ipv4_header[0] & IPV4_IHL_MASK;
    if (ihl_words < IPV4_MIN_IHL_WORDS) unlikely_ {
        return false;
    }

    event.packet_identity.transport_proto = ipv4_header[IPV4_PROTO_OFFSET];

    memcpy_(event.packet_identity.src_ip.data(),
            ipv4_header + IPV4_SRC_ADDR_OFFSET, IPV4_ADDR_BYTES);

    memcpy_(event.packet_identity.dst_ip.data(),
            ipv4_header + IPV4_DST_ADDR_OFFSET, IPV4_ADDR_BYTES);

    return true;
}

force_inline_
bool process_ip6(packet_meta_event& event, const uint8_t* packet, size_t packet_sz) {
    if (packet_sz < ETH_HEADER_BYTES + IPV6_HEADER_BYTES) unlikely_ {
        return false;
    }

    const auto *ipv6_header = packet + ETH_HEADER_BYTES;
    event.packet_identity.transport_proto = ipv6_header[IPV6_PROTO_OFFSET];

    memcpy_(event.packet_identity.src_ip.data(),
            ipv6_header + IPV6_SRC_ADDR_OFFSET, IPV6_ADDR_BYTES);

    memcpy_(event.packet_identity.dst_ip.data(),
            ipv6_header + IPV6_DST_ADDR_OFFSET, IPV6_ADDR_BYTES);

    return true;
}

force_inline_
bool process_arp(packet_meta_event& event, const uint8_t* packet, size_t packet_sz) {
    if (packet_sz < ETH_HEADER_BYTES + ARP_HEADER_BYTES) unlikely_ {
        return false;
    }

    const auto *arp_header = packet + ETH_HEADER_BYTES;
    const uint16_t hw_type = load_net16_from_bytes_(arp_header + ARP_HW_TYPE_OFFSET);
    const uint16_t proto_type = load_net16_from_bytes_(arp_header + ARP_PROTO_TYPE_OFFSET);
    const uint8_t hw_len = arp_header[ARP_HW_LEN_OFFSET];
    const uint8_t proto_len = arp_header[ARP_PROTO_LEN_OFFSET];

    if (hw_type != ARPHRD_ETHER_BPF || proto_type != ETH_P_IP ||
        hw_len != ETH_ALEN || proto_len != ARP_IPV4_PROTO_LEN) unlikely_ {
        return false;
    }

    memcpy_(event.packet_identity.src_ip.data(),
            arp_header + ARP_SRC_IP_OFFSET, IPV4_ADDR_BYTES);

    memcpy_(event.packet_identity.dst_ip.data(),
            arp_header + ARP_DST_IP_OFFSET, IPV4_ADDR_BYTES);

    return true;
}

force_inline_
bool copy_packet_metadata(packet_meta_event& event,
                          int cpu,
                          const uint8_t* data,
                          size_t data_sz) {
    event.first_timestamp = event.latest_timestamp = std::chrono::system_clock::now();
    event.packet_identity.src_ip.fill(0);
    event.packet_identity.dst_ip.fill(0);
    event.packet_identity.transport_proto = 0;

    const uint8_t* packet = data + RX_QUEUE_BYTES;
    const size_t packet_sz = data_sz - RX_QUEUE_BYTES;

    memcpy_(&event.rx_queue, data, sizeof(event.rx_queue));
    event.packet_size = packet_sz;
    event.cpu_id = static_cast<__u16>(cpu);

    // The wire header is dst/src/ethertype, but packet_meta_event stores src/dst,
    // so these fixed-size copies must stay split to preserve the frozen ABI.
    memcpy_(event.packet_identity.dst_mac, packet, sizeof(event.packet_identity.dst_mac));
    memcpy_(event.packet_identity.src_mac, packet + ETH_ALEN, sizeof(event.packet_identity.src_mac));
    memcpy_(&event.packet_identity.eth_proto_net,
            packet + ETH_PROTO_OFFSET,
            sizeof(event.packet_identity.eth_proto_net));

    const uint16_t eth_proto = ntoh16_(event.packet_identity.eth_proto_net);

    bool res = false;

    switch (eth_proto) {
    case ETH_P_IP:
        res = process_ip4(event, packet, packet_sz);
        break;
    case ETH_P_IPV6:
        res = process_ip6(event, packet, packet_sz);
        break;
    case ETH_P_ARP:
    case ETH_P_RARP:
        res = process_arp(event, packet, packet_sz);
        break;
    default:
        break;
    }

    return res;
}
} // namespace sniffster

export namespace sniffster {

class packet_handler {
    using coalesced_buffer_t = boost::circular_buffer<packet_meta_event>;

public:
    explicit packet_handler(packet_processor& processor,
                            logger_processor& logger) :
                tell_packet_processor_(processor),
                tell_logger_(logger),
                next_counters_log_at_(std::chrono::steady_clock::now() + std::chrono::minutes(1)) {

        // The packet handler owns the concrete SPSC queues and publishes them
        // during startup. Processor objects only borrow these queues; sniffer's
        // start and stop barriers are what make that lifetime contract safe.
        tell_packet_processor_.register_producer(outbound_events_);
        tell_logger_.register_producer(logger_events_);
    }

    void we_are_done() {
        finish_loop();
        tell_packet_processor_.we_are_done();
        tell_logger_.we_are_done();
    }

    void process_sample(int cpu, const uint8_t* data, size_t data_sz);
    void finish_loop();

    void log_event_error(const packet_meta_event& event, std::string_view error_msg) {
        logger_event l_event;
        memcpy_(&l_event.packet_identity, &event.packet_identity, sizeof(packet_identity_t));

        static constexpr std::size_t max_msg_len = logger_event::max_text_len;
        const std::size_t msg_len = std::min(error_msg.size(), max_msg_len);
        memcpy_(l_event.message, error_msg.data(), msg_len);
        l_event.message[msg_len] = '\0';

        if (!logger_events_.push(l_event)) {
            // If the logger queue is full, there's not much we can do. We could
            // consider logging to a fallback file here, but that might also fail
            // and would add complexity. For now, we'll just drop the log event.
            // TBD: create counter for dropped log events and print it periodically
            // in the logger thread.
        } else {
            tell_logger_.about_new_events_available();
        }
    }

    template<typename... Args>
    void log_message(const char* fmt, Args&&... args) {
        const std::string msg = std::vformat(fmt, std::make_format_args(args...));
        log_message_(msg);
    }

    void log_message(std::string_view message) {
        log_message_(message);
    }

private:
    force_inline_
    void log_message_(std::string_view message) {
        logger_event l_event{};

        static constexpr std::size_t max_msg_len = logger_event::max_text_len;
        const std::size_t msg_len = std::min(message.size(), max_msg_len);
        memcpy_(l_event.message, message.data(), msg_len);
        l_event.message[msg_len] = '\0';

        if (logger_events_.push(l_event)) {
            tell_logger_.about_new_events_available();
        }
    }

    force_inline_
    void maybe_log_counters_() {
        const auto now = std::chrono::steady_clock::now();
        if (now < next_counters_log_at_) {
            return;
        }

        while (next_counters_log_at_ <= now) {
            next_counters_log_at_ += std::chrono::minutes(1);
        }

        char msg[logger_event::max_text_len + 1];
        const int written = std::snprintf(msg, sizeof(msg),
            "Packet handler counters: processed=%llu sent=%llu",
            static_cast<unsigned long long>(processed_event_count_),
            static_cast<unsigned long long>(sent_event_count_));

        if (written > 0) {
            log_message_(std::string_view{msg, static_cast<std::size_t>(written)});
        }
    }

    force_inline_
    void flush_dropped_events_() {
        if (dropped_event_count_ == 0) {
            return;
        }

        char msg[logger_event::max_text_len + 1];
        const int written = std::snprintf(msg, sizeof(msg),
            "Packet handler dropped events: %llu",
            static_cast<unsigned long long>(dropped_event_count_));

        dropped_event_count_ = 0;

        if (written > 0) {
            log_message_(std::string_view{msg, static_cast<std::size_t>(written)});
        }
    }

    packet_processor& tell_packet_processor_;
    logger_processor& tell_logger_;
    constexpr static std::size_t coalesced_events_max_size_ = 10; // this buffer is searched linearly, so it should remain within 10.
    constexpr static std::size_t outbound_events_max_size_ = 1000; // this is the only "real" buffer
    constexpr static std::size_t logger_events_max_size_ = 5; // should be used rarely from here
    constexpr static std::size_t extra_buffer_space = 1; // for corner cases; 1 could be enough

    // Both containers below are circular buffers
    coalesced_buffer_t coalesced_events_{coalesced_events_max_size_ + extra_buffer_space};
    packet_processor::queue_t outbound_events_{outbound_events_max_size_ + extra_buffer_space};
    logger_processor::queue_t logger_events_{logger_events_max_size_ + extra_buffer_space};
    std::uint64_t processed_event_count_ = 0;
    std::uint64_t sent_event_count_ = 0;
    std::uint64_t dropped_event_count_ = 0;
    std::chrono::steady_clock::time_point next_counters_log_at_;
};

force_inline_
void packet_handler::process_sample(int cpu, const uint8_t* data, size_t data_sz) {
    if (data_sz < RX_QUEUE_BYTES + ETH_HEADER_BYTES) unlikely_ {
        return;
    }
    packet_meta_event new_event;

    if (!copy_packet_metadata(new_event, cpu, data, data_sz)) {
        // TBD: add event details to the log (the event struct supports this)
        log_message_("packet too short or malformed -- skipping");

        tell_logger_.about_new_events_available();
        return; // Packet too short or malformed; skip this sample.
    }

    ++processed_event_count_;

    bool found = false;
    for (auto& event : coalesced_events_) {
        if (event.packet_identity.same_as(new_event.packet_identity)) {
            event.latest_timestamp = new_event.latest_timestamp;
            event.coalesced_count++;
            found = true;
        }
    }

    if (!found) {
        new_event.coalesced_count = 1;
        coalesced_events_.push_back(new_event);
    }

    if (coalesced_events_.size() >= coalesced_events_max_size_) {
        const auto& event = coalesced_events_.front();

        if (!outbound_events_.push(event)) {
            ++dropped_event_count_;
        } else {
            ++sent_event_count_;
            tell_packet_processor_.about_new_events_available();
        }
        coalesced_events_.pop_front();
    }
}

force_inline_
void packet_handler::finish_loop() {
    maybe_log_counters_();
    flush_dropped_events_();
}

} // export namespace sniffster
