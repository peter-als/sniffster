module;

#include <array>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <cstdint>
#include <type_traits>
#include "network/packet_offsets.h"
#include "platform/arch_macros.h"

export module sniffster.packet_meta_event;

import sniffster.network.addresses;
import sniffster.platform;

export namespace sniffster {

struct alignas(16) packet_identity_t {
    ip_addr         src_ip;                 // 16 bytes: source IP bytes; IPv4 uses the first 4 bytes and zero tail.
    ip_addr         dst_ip;                 // 16 bytes: destination IP bytes; IPv4 uses the first 4 bytes and zero tail.
    std::uint8_t    src_mac[ETH_ALEN];      // 6 bytes: Ethernet source MAC from the wire header.
    std::uint8_t    dst_mac[ETH_ALEN];      // 6 bytes: Ethernet destination MAC from the wire header.
                                        // 44 bytes
    std::uint16_t   eth_proto_net;          // 2 bytes, align 2: Ethernet EtherType in network byte order.
    std::uint8_t    transport_proto;        // 1 byte, align 1: IPv4 protocol or IPv6 next-header value; zero for non-IP traffic.
                                        // 47 bytes

    [[nodiscard]] force_inline_ bool same_as(const packet_identity_t& other) const noexcept;

    bool operator==(const packet_identity_t& other) const = delete;
    bool operator!=(const packet_identity_t& other) const = delete;

};

struct alignas(16) packet_meta_event {
    packet_identity_t packet_identity;      // 47 useful bytes, padded to 48 by alignment.
    std::chrono::system_clock::time_point first_timestamp;    // 8 bytes (uint64_t)
    std::chrono::system_clock::time_point latest_timestamp;   // 8 bytes (uint64_t)
                                        // 64 bytes
    std::uint32_t   rx_queue;               // 4 bytes, align 4: NIC RX queue index from ctx->rx_queue_index.
    std::uint32_t   packet_size;            // 4 bytes, align 4: captured packet bytes, excluding the leading RX queue prefix.
                                        // 72 bytes
    std::uint16_t   cpu_id;                 // 2 bytes, align 2: perf callback CPU that delivered this sample.
    std::uint16_t   coalesced_count;        // 2 bytes, align 2: counted of coalesced events.
                                        // total 76 bytes payload
                                        // padded to 80, because ip_addr is 16 bytes

    bool operator==(const packet_meta_event& other) const = delete;
    bool operator!=(const packet_meta_event& other) const = delete;
};

inline constexpr std::size_t packet_identity_compare_size =
    offsetof(packet_identity_t, transport_proto) + sizeof(std::uint8_t);

bool packet_identity_t::same_as(const packet_identity_t& other) const noexcept {
    return memcmp_(this, &other, packet_identity_compare_size) == 0;
}

static_assert(std::is_standard_layout_v<packet_identity_t>);
static_assert(std::is_trivially_copyable_v<packet_identity_t>);
static_assert(std::is_standard_layout_v<packet_meta_event>);
static_assert(std::is_trivially_copyable_v<packet_meta_event>);
static_assert(offsetof(packet_identity_t, transport_proto) == 46,
    "packet_identity_t::transport_proto offset changed; verify identity ABI");
static_assert(packet_identity_compare_size == 47,
    "packet_identity_compare_size changed; verify compared identity bytes");
static_assert(sizeof(packet_meta_event) == 80,
    "packet_meta_event size changed; verify BPF/userspace ABI before updating size");
static_assert(sizeof(packet_identity_t) == 48,
    "packet_identity_t size changed; verify identity layout and tail padding");
static_assert(offsetof(packet_meta_event, packet_identity) == 0,
    "packet_meta_event::packet_identity must remain the first field");
static_assert(offsetof(packet_meta_event, first_timestamp) == sizeof(packet_identity_t),
    "packet_meta_event payload must begin immediately after packet_identity_t");

} // namespace sniff
