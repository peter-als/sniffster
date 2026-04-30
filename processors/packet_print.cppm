module;

#include <array>
#include <cstdint>
#include <format>
#include <iterator>
#include <span>
#include <string>

#include <print>
#include <linux/if_ether.h>
#include <netinet/in.h>

#include "platform/arch_macros.h"

export module sniffster.packet_print;

import sniffster.network.addresses;
import sniffster.processors.format_data;
import sniffster.packet_meta_event;
import sniffster.platform;
import sniffster.platform.decorated_throw;

namespace sniffster {

force_inline_
void assert_buffer_capacity(const std::format_to_n_result<char*>& result,
                            std::size_t remaining) {
    if (static_cast<std::size_t>(result.size) > remaining) {
        platform::throw_runtime_error("batch buffer overflow");
    }
}

force_inline_
std::span<char> append_byte(std::span<char> buffer, char ch) {
    if (buffer.empty()) {
        platform::throw_runtime_error("batch buffer overflow");
    }

    buffer[0] = static_cast<char>(ch);
    return buffer.subspan(1);
}

template<class... Args>
force_inline_
std::span<char> append_format(std::span<char> buffer,
                              std::format_string<Args...> fmt,
                              Args&&... args) {
    const auto result = std::format_to_n(
        buffer.data(),
        buffer.size(),
        fmt,
        std::forward<Args>(args)...);

    assert_buffer_capacity(result, buffer.size());
    return buffer.subspan(static_cast<std::size_t>(result.out - buffer.data()));
}

std::span<char> append_transport_description(std::span<char> buffer,
                                                char transport_proto) {
    if (transport_proto == 0) {
        return buffer;
    }

    buffer = append_format(buffer,
                           ", \"l4_proto\": {}",
                           static_cast<unsigned>(transport_proto));

    const auto l4_name = transport_proto_to_str(transport_proto);
    if (!l4_name.empty()) {
        buffer = append_format(buffer, ", \"l4_name\": \"{}\"", l4_name);
    }

    return buffer;
}

std::span<char>  append_ip4_description(std::span<char> buffer, const packet_meta_event& event) {
    const auto& identity = event.packet_identity;
    const auto src_ip = ipv4_addr_const_view{identity.src_ip};
    const auto dst_ip = ipv4_addr_const_view{identity.dst_ip};
    buffer = append_format(buffer,
        ", \"l3_type\": \"IPv4\", \"ip_src\": \"{}\", \"ip_dst\": \"{}\"",
        ip_to_str(AF_INET, src_ip.data()),
        ip_to_str(AF_INET, dst_ip.data()));

    buffer = append_transport_description(buffer, identity.transport_proto);
    return buffer;
}

std::span<char>  append_ip6_description(std::span<char> buffer, const packet_meta_event& event) {
    const auto& identity = event.packet_identity;
    const auto src_ip = ipv6_addr_const_view{identity.src_ip};
    const auto dst_ip = ipv6_addr_const_view{identity.dst_ip};
    buffer = append_format(buffer,
        ", \"l3_type\": \"IPv6\", \"ip_src\": \"{}\", \"ip_dst\": \"{}\"",
        ip_to_str(AF_INET6, src_ip.data()),
        ip_to_str(AF_INET6, dst_ip.data()));

    buffer = append_transport_description(buffer, identity.transport_proto);
    return buffer;
}

std::span<char>  append_arp_description(std::span<char> buffer, const packet_meta_event& event, __u16 eth_proto) {
    const auto& identity = event.packet_identity;
    const auto src_ip = ipv4_addr_const_view{identity.src_ip};
    const auto dst_ip = ipv4_addr_const_view{identity.dst_ip};
    buffer = append_format(buffer,
        ", \"l3_type\": \"{}\", \"ip_src\": \"{}\", \"ip_dst\": \"{}\"",
        eth_proto == ETH_P_ARP ? "ARP" : (eth_proto == ETH_P_RARP ? "RARP" : "Unknown"),
        ip_to_str(AF_INET, src_ip.data()),
        ip_to_str(AF_INET, dst_ip.data()));
    return buffer;
}

export std::span<char> // returns the remaining buffer after appending
append_event_jsonl(std::span<char> buffer, const packet_meta_event& event) {

    const auto& identity = event.packet_identity;
    const __u16 eth_proto = ntoh16_(identity.eth_proto_net);
    const auto first_ts = event.first_timestamp.time_since_epoch().count();
    const auto latest_ts = event.latest_timestamp.time_since_epoch().count();

    buffer = append_format(buffer,
        "{{\"cpu\": {}, \"q\": {}, \"sample_len\": {}, \"l2_type\": \"{:#x}\"",
        event.cpu_id,
        event.rx_queue,
        event.packet_size,
        eth_proto);

    const auto eth_name = eth_proto_to_str(eth_proto);
    if (!eth_name.empty()) {
        buffer = append_format(buffer, ", \"l2_name\": \"{}\"", eth_name);
    }

    buffer = append_format(buffer,
        ", \"coalesced\": {}",
        event.coalesced_count);

    buffer = append_format(buffer,
        ", \"mac_src\": \"{}\", \"mac_dst\": \"{}\"",
        mac_to_str(identity.src_mac),
        mac_to_str(identity.dst_mac));

    switch (eth_proto) {
    case ETH_P_IP:
        buffer = append_ip4_description(buffer, event);
        break;
    case ETH_P_IPV6:
        buffer = append_ip6_description(buffer, event);
        break;
    case ETH_P_ARP:
    case ETH_P_RARP:
        buffer = append_arp_description(buffer, event, eth_proto);
        break;
    default:
        // unknown or unsupported L3, but still try to print IPs if possible.
        buffer = append_arp_description(buffer, event, eth_proto);
        break;
    }

    buffer = append_format(buffer,
        ", \"first_ts\": {}, \"latest_ts\": {}}}",
        first_ts,
        latest_ts);

    buffer = append_byte(buffer, '\n');
    return buffer;
}

export void append_event_jsonl(std::string& output, const packet_meta_event& event) {
    std::array<char, 10240> line{};
    auto remaining = append_event_jsonl(std::span<char>{line}, event);
    const auto used = line.size() - remaining.size();
    output.append(line.data(), used);
}

// Mostly a debugging helper. Production report writing should use
// append_event_jsonl() and choose its own output sink/buffering policy.
export void print_event_jsonl(const packet_meta_event& event) {
    std::array<char, 10240> line{};
    auto remaining = append_event_jsonl(std::span<char>{line}, event);
    const auto used = line.size() - remaining.size();
    std::println("{}", std::string_view{line.data(), used});
}

} // namespace sniffster
