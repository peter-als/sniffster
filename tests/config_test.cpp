#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>

#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <array>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

import sniffster.network.config;

namespace {

sniffster::ip_addr make_ipv4(std::uint32_t ip_host_order) {
    sniffster::ip_addr value{};
    const auto net_order = htonl(ip_host_order);
    std::memcpy(value.data(), &net_order, 4);
    return value;
}

sniffster::ip_addr parse_ipv6(const char* text) {
    sniffster::ip_addr value{};
    EXPECT_EQ(inet_pton(AF_INET6, text, value.data()), 1);
    return value;
}

void expect_ipv4_eq(const sniffster::ip_addr& actual, const sniffster::ip_addr& expected) {
    EXPECT_EQ(std::memcmp(actual.data(),
                          expected.data(),
                          actual.size()),
              0);
}

void expect_ipv6_eq(const sniffster::ip_addr& actual, const sniffster::ip_addr& expected) {
    EXPECT_EQ(std::memcmp(actual.data(),
                          expected.data(),
                          actual.size()),
              0);
}

struct FakeIfaddrsEntry {
    ifaddrs      node{};
    sockaddr_in  addr{};
    sockaddr_in  netmask{};
    sockaddr_in  broadaddr{};
    sockaddr_in6 addr6{};
    sockaddr_in6 netmask6{};
    std::string  name;
};

struct FakeIfaddrsState {
    int                           getifaddrs_result = 0;
    std::vector<std::pair<std::string, unsigned int>> indices;
    std::vector<FakeIfaddrsEntry> entries;
    ifaddrs*                      head = nullptr;
    int                           freeifaddrs_calls = 0;

    void rebuild_links() {
        head = entries.empty() ? nullptr : &entries.front().node;

        for (std::size_t i = 0; i < entries.size(); ++i) {
            auto& entry = entries[i];
            entry.node = {};
            entry.node.ifa_name = entry.name.empty() ? nullptr : entry.name.data();
            entry.node.ifa_addr = entry.addr6.sin6_family != 0
                ? reinterpret_cast<sockaddr*>(&entry.addr6)
                : reinterpret_cast<sockaddr*>(&entry.addr);
            entry.node.ifa_netmask = entry.netmask6.sin6_family != 0
                ? reinterpret_cast<sockaddr*>(&entry.netmask6)
                : reinterpret_cast<sockaddr*>(&entry.netmask);
            entry.node.ifa_broadaddr = reinterpret_cast<sockaddr*>(&entry.broadaddr);
            entry.node.ifa_next = (i + 1 < entries.size()) ? &entries[i + 1].node : nullptr;
        }
    }

    FakeIfaddrsEntry& add_ipv4(std::string ifname, uint32_t ip_host_order, uint32_t netmask_host_order) {
        auto& entry = entries.emplace_back();
        entry.name = std::move(ifname);
        entry.addr.sin_family = AF_INET;
        entry.addr.sin_addr.s_addr = htonl(ip_host_order);
        entry.netmask.sin_family = AF_INET;
        entry.netmask.sin_addr.s_addr = htonl(netmask_host_order);
        entry.broadaddr.sin_family = AF_INET;
        rebuild_links();
        return entries.back();
    }

    FakeIfaddrsEntry& add_ipv6(std::string ifname, const char* ip, const char* netmask) {
        auto& entry = entries.emplace_back();
        entry.name = std::move(ifname);
        entry.addr6.sin6_family = AF_INET6;
        entry.netmask6.sin6_family = AF_INET6;
        EXPECT_EQ(inet_pton(AF_INET6, ip, &entry.addr6.sin6_addr), 1);
        EXPECT_EQ(inet_pton(AF_INET6, netmask, &entry.netmask6.sin6_addr), 1);
        rebuild_links();
        return entries.back();
    }

    FakeIfaddrsEntry& add_non_ipv4(std::string ifname, sa_family_t family) {
        auto& entry = entries.emplace_back();
        entry.name = std::move(ifname);
        entry.addr.sin_family = family;
        entry.netmask.sin_family = AF_INET;
        rebuild_links();
        return entries.back();
    }

    void add_index(std::string ifname, unsigned int ifindex) {
        indices.emplace_back(std::move(ifname), ifindex);
    }
};

FakeIfaddrsState g_fake_ifaddrs;

extern "C" int getifaddrs(ifaddrs** ifap) {
    if (g_fake_ifaddrs.getifaddrs_result != 0) {
        return g_fake_ifaddrs.getifaddrs_result;
    }

    *ifap = g_fake_ifaddrs.head;
    return 0;
}

extern "C" void freeifaddrs(ifaddrs* ifa) {
    EXPECT_EQ(ifa, g_fake_ifaddrs.head);
    ++g_fake_ifaddrs.freeifaddrs_calls;
}

extern "C" unsigned int if_nametoindex(const char* ifname) {
    const std::string_view needle = ifname == nullptr ? std::string_view{} : std::string_view{ifname};
    for (const auto& [name, ifindex] : g_fake_ifaddrs.indices) {
        if (name == needle) {
            return ifindex;
        }
    }
    return 0;
}

class ConfigInterfaceTest : public ::testing::Test {
protected:
    void SetUp() override {
        g_fake_ifaddrs = {};
    }
};

TEST_F(ConfigInterfaceTest, ThrowsWhenGetifaddrsFails) {
    g_fake_ifaddrs.getifaddrs_result = -1;
    g_fake_ifaddrs.add_index("eth0", 7);

    EXPECT_THROW((void)sniffster::network_interface("eth0"), std::runtime_error);
    EXPECT_EQ(g_fake_ifaddrs.freeifaddrs_calls, 0);
}

TEST_F(ConfigInterfaceTest, ThrowsWhenInterfaceIsMissing) {
    g_fake_ifaddrs.add_ipv4("eth1", 0xC0A8010A, 0xFFFFFF00);
    g_fake_ifaddrs.add_index("eth0", 7);

    EXPECT_THROW((void)sniffster::network_interface("eth0"), std::runtime_error);
    EXPECT_EQ(g_fake_ifaddrs.freeifaddrs_calls, 1);
}

TEST_F(ConfigInterfaceTest, SkipsEntriesWithoutAddress) {
    auto& entry = g_fake_ifaddrs.add_ipv4("eth0", 0xC0A8010A, 0xFFFFFF00);
    entry.node.ifa_addr = nullptr;
    g_fake_ifaddrs.add_index("eth0", 7);

    EXPECT_THROW((void)sniffster::network_interface("eth0"), std::runtime_error);
    EXPECT_EQ(g_fake_ifaddrs.freeifaddrs_calls, 1);
}

TEST_F(ConfigInterfaceTest, SkipsEntriesWithoutName) {
    auto& entry = g_fake_ifaddrs.add_ipv4("eth0", 0xC0A8010A, 0xFFFFFF00);
    entry.node.ifa_name = nullptr;
    g_fake_ifaddrs.add_index("eth0", 7);

    EXPECT_THROW((void)sniffster::network_interface("eth0"), std::runtime_error);
    EXPECT_EQ(g_fake_ifaddrs.freeifaddrs_calls, 1);
}

TEST_F(ConfigInterfaceTest, SkipsNonIpv4Addresses) {
    g_fake_ifaddrs.add_non_ipv4("eth0", AF_UNSPEC);
    g_fake_ifaddrs.add_ipv4("eth0", 0xC0A8010A, 0xFFFFFF00);
    g_fake_ifaddrs.add_index("eth0", 7);

    auto iface = sniffster::network_interface("eth0");
    EXPECT_EQ(iface.ifindex, 7u);
    expect_ipv4_eq(iface.ipv4, make_ipv4(0xC0A8010Au));
    expect_ipv4_eq(iface.ipv4_netmask, make_ipv4(0xFFFFFF00u));
    EXPECT_EQ(g_fake_ifaddrs.freeifaddrs_calls, 1);
}

TEST_F(ConfigInterfaceTest, CapturesIpv6AddressAndNetmaskWhenPresent) {
    g_fake_ifaddrs.add_ipv6("eth0", "2001:db8::1234", "ffff:ffff:ffff:ffff::");
    g_fake_ifaddrs.add_ipv4("eth0", 0xC0A8010A, 0xFFFFFF00);
    g_fake_ifaddrs.add_index("eth0", 7);

    auto iface = sniffster::network_interface("eth0");

    EXPECT_TRUE(iface.has_ipv6);
    expect_ipv6_eq(iface.ipv6, parse_ipv6("2001:db8::1234"));
    expect_ipv6_eq(iface.ipv6_netmask, parse_ipv6("ffff:ffff:ffff:ffff::"));
    EXPECT_EQ(iface.ipv6_prefix_len, 64u);
    EXPECT_EQ(g_fake_ifaddrs.freeifaddrs_calls, 1);
}

TEST_F(ConfigInterfaceTest, IgnoresIpv6EntryWithoutIpv6Netmask) {
    g_fake_ifaddrs.add_ipv6("eth0", "2001:db8::1234", "ffff:ffff:ffff:ffff::");
    g_fake_ifaddrs.add_ipv4("eth0", 0xC0A8010A, 0xFFFFFF00);
    g_fake_ifaddrs.add_index("eth0", 7);
    g_fake_ifaddrs.entries.front().node.ifa_netmask =
        reinterpret_cast<sockaddr*>(&g_fake_ifaddrs.entries.front().netmask);

    auto iface = sniffster::network_interface("eth0");

    EXPECT_FALSE(iface.has_ipv6);
    EXPECT_EQ(iface.ipv6_prefix_len, 0u);
}

TEST_F(ConfigInterfaceTest, IgnoresIpv6EntryWithoutAddress) {
    g_fake_ifaddrs.add_ipv6("eth0", "2001:db8::1234", "ffff:ffff:ffff:ffff::");
    g_fake_ifaddrs.add_ipv4("eth0", 0xC0A8010A, 0xFFFFFF00);
    g_fake_ifaddrs.add_index("eth0", 7);
    g_fake_ifaddrs.entries.front().node.ifa_addr = nullptr;

    auto iface = sniffster::network_interface("eth0");

    EXPECT_FALSE(iface.has_ipv6);
    EXPECT_EQ(iface.ipv6_prefix_len, 0u);
}

TEST_F(ConfigInterfaceTest, SkipsEntriesWithoutNetmask) {
    auto& entry = g_fake_ifaddrs.add_ipv4("eth0", 0xC0A8010A, 0xFFFFFF00);
    entry.node.ifa_netmask = nullptr;
    g_fake_ifaddrs.add_index("eth0", 7);

    EXPECT_THROW((void)sniffster::network_interface("eth0"), std::runtime_error);
    EXPECT_EQ(g_fake_ifaddrs.freeifaddrs_calls, 1);
}

TEST_F(ConfigInterfaceTest, SkipsEntriesWithNonIpv4Netmask) {
    auto& entry = g_fake_ifaddrs.add_ipv4("eth0", 0xC0A8010A, 0xFFFFFF00);
    entry.node.ifa_netmask->sa_family = AF_INET6;
    g_fake_ifaddrs.add_index("eth0", 7);

    EXPECT_THROW((void)sniffster::network_interface("eth0"), std::runtime_error);
    EXPECT_EQ(g_fake_ifaddrs.freeifaddrs_calls, 1);
}

TEST_F(ConfigInterfaceTest, ThrowsWhenInterfaceIndexIsMissing) {
    g_fake_ifaddrs.add_ipv4("eth0", 0xC0A8010A, 0xFFFFFF00);

    EXPECT_THROW((void)sniffster::network_interface("eth0"), std::runtime_error);
    EXPECT_EQ(g_fake_ifaddrs.freeifaddrs_calls, 0);
}

TEST_F(ConfigInterfaceTest, ComputesDerivedIpv4Fields) {
    auto& entry = g_fake_ifaddrs.add_ipv4("eth0", 0xC0A8010A, 0xFFFFFF00);
    entry.node.ifa_flags = IFF_UP | IFF_RUNNING;
    g_fake_ifaddrs.add_index("eth0", 7);

    auto iface = sniffster::network_interface("eth0");

    EXPECT_EQ(iface.name, "eth0");
    EXPECT_EQ(iface.ifindex, 7u);
    expect_ipv4_eq(iface.ipv4, make_ipv4(0xC0A8010Au));
    expect_ipv4_eq(iface.ipv4_netmask, make_ipv4(0xFFFFFF00u));
    expect_ipv4_eq(iface.ipv4_network, make_ipv4(0xC0A80100u));
    EXPECT_EQ(iface.flags, static_cast<std::uint32_t>(IFF_UP | IFF_RUNNING));
    EXPECT_EQ(iface.ipv4_prefix_len, 24u);
    EXPECT_TRUE(iface.has_ipv4);
    EXPECT_FALSE(iface.has_ipv4_broadcast);
    EXPECT_EQ(g_fake_ifaddrs.freeifaddrs_calls, 1);
}

TEST_F(ConfigInterfaceTest, PopulatesBroadcastWhenFlagAndAddressArePresent) {
    auto& entry = g_fake_ifaddrs.add_ipv4("eth0", 0xC0A8010A, 0xFFFFFF00);
    entry.node.ifa_flags = IFF_BROADCAST;
    entry.broadaddr.sin_addr.s_addr = htonl(0xC0A801FFu);
    g_fake_ifaddrs.add_index("eth0", 7);

    auto iface = sniffster::network_interface("eth0");

    EXPECT_TRUE(iface.has_ipv4_broadcast);
    expect_ipv4_eq(iface.ipv4_broadcast, make_ipv4(0xC0A801FFu));
    EXPECT_EQ(g_fake_ifaddrs.freeifaddrs_calls, 1);
}

TEST_F(ConfigInterfaceTest, IgnoresBroadcastWithoutFlag) {
    auto& entry = g_fake_ifaddrs.add_ipv4("eth0", 0xC0A8010A, 0xFFFFFF00);
    entry.broadaddr.sin_addr.s_addr = htonl(0xC0A801FFu);
    g_fake_ifaddrs.add_index("eth0", 7);

    auto iface = sniffster::network_interface("eth0");

    EXPECT_FALSE(iface.has_ipv4_broadcast);
    expect_ipv4_eq(iface.ipv4_broadcast, make_ipv4(0u));
}

TEST_F(ConfigInterfaceTest, IgnoresBroadcastWhenAddressIsMissing) {
    auto& entry = g_fake_ifaddrs.add_ipv4("eth0", 0xC0A8010A, 0xFFFFFF00);
    entry.node.ifa_flags = IFF_BROADCAST;
    entry.node.ifa_broadaddr = nullptr;
    g_fake_ifaddrs.add_index("eth0", 7);

    auto iface = sniffster::network_interface("eth0");

    EXPECT_FALSE(iface.has_ipv4_broadcast);
    expect_ipv4_eq(iface.ipv4_broadcast, make_ipv4(0u));
}

TEST_F(ConfigInterfaceTest, Ipv6PrefixLengthCanBeZero) {
    g_fake_ifaddrs.add_ipv6("eth0", "2001:db8::1234", "::");
    g_fake_ifaddrs.add_ipv4("eth0", 0xC0A8010A, 0xFFFFFF00);
    g_fake_ifaddrs.add_index("eth0", 7);

    auto iface = sniffster::network_interface("eth0");

    EXPECT_TRUE(iface.has_ipv6);
    EXPECT_EQ(iface.ipv6_prefix_len, 0u);
}

TEST_F(ConfigInterfaceTest, Ipv6PrefixLengthCanBe128) {
    g_fake_ifaddrs.add_ipv6("eth0", "2001:db8::1234", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
    g_fake_ifaddrs.add_ipv4("eth0", 0xC0A8010A, 0xFFFFFF00);
    g_fake_ifaddrs.add_index("eth0", 7);

    auto iface = sniffster::network_interface("eth0");

    EXPECT_TRUE(iface.has_ipv6);
    EXPECT_EQ(iface.ipv6_prefix_len, 128u);
}

TEST_F(ConfigInterfaceTest, Ipv6PrefixLengthCountsBitsInNonContiguousMask) {
    g_fake_ifaddrs.add_ipv6("eth0", "2001:db8::1234", "ffff:0:ffff::");
    g_fake_ifaddrs.add_ipv4("eth0", 0xC0A8010A, 0xFFFFFF00);
    g_fake_ifaddrs.add_index("eth0", 7);

    auto iface = sniffster::network_interface("eth0");

    EXPECT_TRUE(iface.has_ipv6);
    EXPECT_EQ(iface.ipv6_prefix_len, 32u);
}

TEST_F(ConfigInterfaceTest, ReturnsFirstMatchingIpv4Interface) {
    g_fake_ifaddrs.add_ipv4("eth0", 0x0A000001, 0xFF000000);
    g_fake_ifaddrs.add_ipv4("eth0", 0xC0A8010A, 0xFFFFFF00);
    g_fake_ifaddrs.add_index("eth0", 7);

    auto iface = sniffster::network_interface("eth0");

    expect_ipv4_eq(iface.ipv4, make_ipv4(0x0A000001u));
    expect_ipv4_eq(iface.ipv4_netmask, make_ipv4(0xFF000000u));
    EXPECT_EQ(iface.ipv4_prefix_len, 8u);
}

TEST_F(ConfigInterfaceTest, ReturnsFirstMatchingIpv6Interface) {
    g_fake_ifaddrs.add_ipv6("eth0", "2001:db8::1", "ffff:ffff:ffff:ffff::");
    g_fake_ifaddrs.add_ipv6("eth0", "2001:db8::2", "ffff:ffff:ffff:ffff:ffff::");
    g_fake_ifaddrs.add_ipv4("eth0", 0xC0A8010A, 0xFFFFFF00);
    g_fake_ifaddrs.add_index("eth0", 7);

    auto iface = sniffster::network_interface("eth0");

    EXPECT_TRUE(iface.has_ipv6);
    expect_ipv6_eq(iface.ipv6, parse_ipv6("2001:db8::1"));
    EXPECT_EQ(iface.ipv6_prefix_len, 64u);
}

} // namespace
