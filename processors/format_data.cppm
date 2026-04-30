module;

#include <arpa/inet.h>
#include <cstdint>
#include <iomanip>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <print>
#include <sstream>
#include <string>
#include <string_view>

export module sniffster.processors.format_data;

import sniffster.platform;

export namespace sniffster {

std::string ip_to_str(int family, const void *addr) {
    char buf[INET6_ADDRSTRLEN] = {};
    if (!inet_ntop(family, addr, buf, sizeof(buf))) {
        return {};
    }

    return buf;
}

std::string mac_to_str(const std::uint8_t mac[ETH_ALEN]) {
    std::ostringstream out;
    out << std::hex << std::setfill('0')
        << std::setw(2) << static_cast<unsigned>(mac[0]) << ':'
        << std::setw(2) << static_cast<unsigned>(mac[1]) << ':'
        << std::setw(2) << static_cast<unsigned>(mac[2]) << ':'
        << std::setw(2) << static_cast<unsigned>(mac[3]) << ':'
        << std::setw(2) << static_cast<unsigned>(mac[4]) << ':'
        << std::setw(2) << static_cast<unsigned>(mac[5]);
    return out.str();
}

[[nodiscard]] constexpr std::string_view
eth_proto_to_str(std::uint16_t eth_proto) {
    switch (eth_proto) {
    case ETH_P_IP:
        return "IPv4";
    case ETH_P_IPV6:
        return "IPv6";
    case ETH_P_ARP:
        return "ARP";
    case ETH_P_RARP:
        return "RARP";
    default:
        return {};
    }
}

[[nodiscard]] constexpr std::string_view
transport_proto_to_str(std::uint8_t transport_proto) {
    switch (transport_proto) {
    case IPPROTO_ICMP:
        return "ICMP";
    case IPPROTO_TCP:
        return "TCP";
    case IPPROTO_UDP:
        return "UDP";
    case IPPROTO_ICMPV6:
        return "ICMPv6";
    default:
        return {};
    }
}

} // namespace sniff
