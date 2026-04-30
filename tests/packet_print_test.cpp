#include <array>
#include <chrono>
#include <cstdint>
#include <string>

#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <linux/if_ether.h>
#include <netinet/in.h>

import sniffster.packet_print;
import sniffster.packet_meta_event;

namespace {

sniffster::packet_meta_event make_base_event(std::uint16_t eth_proto_host) {
    sniffster::packet_meta_event event{};
    event.cpu_id = 3;
    event.rx_queue = 7;
    event.packet_size = 128;
    event.coalesced_count = 4;
    event.first_timestamp = std::chrono::system_clock::time_point{std::chrono::seconds{123}};
    event.latest_timestamp = std::chrono::system_clock::time_point{std::chrono::seconds{456}};
    event.packet_identity.eth_proto_net = htons(eth_proto_host);

    const std::array<std::uint8_t, ETH_ALEN> src_mac{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    const std::array<std::uint8_t, ETH_ALEN> dst_mac{0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    std::copy(src_mac.begin(), src_mac.end(), event.packet_identity.src_mac);
    std::copy(dst_mac.begin(), dst_mac.end(), event.packet_identity.dst_mac);
    return event;
}

TEST(PacketPrintJsonl, FormatsIpv4JsonLine) {
    auto event = make_base_event(ETH_P_IP);
    event.packet_identity.transport_proto = IPPROTO_TCP;

    const std::array<std::uint8_t, 4> src_ip{192, 168, 1, 10};
    const std::array<std::uint8_t, 4> dst_ip{10, 0, 0, 5};
    std::copy(src_ip.begin(), src_ip.end(), event.packet_identity.src_ip.data());
    std::copy(dst_ip.begin(), dst_ip.end(), event.packet_identity.dst_ip.data());

    std::string line;
    sniffster::append_event_jsonl(line, event);

    const auto first_ts = event.first_timestamp.time_since_epoch().count();
    const auto latest_ts = event.latest_timestamp.time_since_epoch().count();
    const std::string expected =
        std::format(
            "{{\"cpu\": 3, \"q\": 7, \"sample_len\": 128, \"l2_type\": \"0x800\", "
            "\"l2_name\": \"IPv4\", \"coalesced\": 4, \"mac_src\": \"aa:bb:cc:dd:ee:ff\", "
            "\"mac_dst\": \"00:11:22:33:44:55\", \"l3_type\": \"IPv4\", "
            "\"ip_src\": \"192.168.1.10\", \"ip_dst\": \"10.0.0.5\", "
            "\"l4_proto\": 6, \"l4_name\": \"TCP\", \"first_ts\": {}, "
            "\"latest_ts\": {}}}\n",
            first_ts,
            latest_ts);

    EXPECT_EQ(line, expected);
}

TEST(PacketPrintJsonl, FormatsIpv6JsonLine) {
    auto event = make_base_event(ETH_P_IPV6);
    event.packet_identity.transport_proto = IPPROTO_ICMPV6;

    const std::array<std::uint8_t, 16> src_ip{
        0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    const std::array<std::uint8_t, 16> dst_ip{
        0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
    std::copy(src_ip.begin(), src_ip.end(), event.packet_identity.src_ip.data());
    std::copy(dst_ip.begin(), dst_ip.end(), event.packet_identity.dst_ip.data());

    std::string line;
    sniffster::append_event_jsonl(line, event);

    EXPECT_NE(line.find("\"l2_name\": \"IPv6\""), std::string::npos);
    EXPECT_NE(line.find("\"l3_type\": \"IPv6\""), std::string::npos);
    EXPECT_NE(line.find("\"ip_src\": \"2001:db8::1\""), std::string::npos);
    EXPECT_NE(line.find("\"ip_dst\": \"2001:db8::2\""), std::string::npos);
    EXPECT_NE(line.find("\"l4_proto\": 58"), std::string::npos);
    EXPECT_NE(line.find("\"l4_name\": \"ICMPv6\""), std::string::npos);
    ASSERT_FALSE(line.empty());
    EXPECT_EQ(line.back(), '\n');
}

TEST(PacketPrintJsonl, FormatsArpWithoutL4Fields) {
    auto event = make_base_event(ETH_P_ARP);

    const std::array<std::uint8_t, 4> src_ip{192, 168, 1, 10};
    const std::array<std::uint8_t, 4> dst_ip{10, 0, 0, 5};
    std::copy(src_ip.begin(), src_ip.end(), event.packet_identity.src_ip.data());
    std::copy(dst_ip.begin(), dst_ip.end(), event.packet_identity.dst_ip.data());

    std::string line;
    sniffster::append_event_jsonl(line, event);

    EXPECT_NE(line.find("\"l2_name\": \"ARP\""), std::string::npos);
    EXPECT_NE(line.find("\"l3_type\": \"ARP\""), std::string::npos);
    EXPECT_EQ(line.find("\"l4_proto\""), std::string::npos);
    EXPECT_EQ(line.find("\"l4_name\""), std::string::npos);
}

TEST(PacketPrintJsonl, FormatsUnknownEtherTypeWithoutL2Name) {
    auto event = make_base_event(0x1234);

    std::string line;
    sniffster::append_event_jsonl(line, event);

    EXPECT_NE(line.find("\"l2_type\": \"0x1234\""), std::string::npos);
    EXPECT_EQ(line.find("\"l2_name\""), std::string::npos);
    EXPECT_NE(line.find("\"l3_type\": \"Unknown\""), std::string::npos);
}

} // namespace
