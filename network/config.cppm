module;

#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>

#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <format>
#include <memory>
#include <string>

#include "network/packet_offsets.h"

export module sniffster.network.config;
export import sniffster.network.addresses;
import sniffster.platform.decorated_throw;

export namespace sniffster {

struct network_interface {
    std::string     name;
    std::uint32_t   ifindex{};
    ip_addr         ipv4{};
    ip_addr         ipv4_netmask{};
    ip_addr         ipv4_network{};
    ip_addr         ipv4_broadcast{};
    std::uint32_t   flags{};
    std::uint32_t   ipv4_prefix_len{};
    bool            has_ipv4{};
    bool            has_ipv4_broadcast{};
    ip_addr         ipv6{};
    ip_addr         ipv6_netmask{};
    std::uint32_t   ipv6_prefix_len{};
    bool            has_ipv6{};

    explicit network_interface(const std::string& ifname) : name(ifname) {
        ifindex = if_nametoindex(name.c_str());
        if (ifindex == 0) {
            platform::throw_runtime_error(std::format("Interface index not found: {}", name));
        }

        ifaddrs* raw{};
        if (getifaddrs(&raw) == -1) {
            platform::throw_runtime_error("getifaddrs failed");
        }

        const std::unique_ptr<ifaddrs, decltype(&freeifaddrs)> ifaddr(raw, freeifaddrs);

        for (auto* it = ifaddr.get(); it; it = it->ifa_next) {
            if (!it->ifa_name || name != it->ifa_name) continue;
            fill_ipv4_fields(it);
            fill_ipv6_fields(it);
        }

        if (!has_ipv4) {
            platform::throw_runtime_error(std::format("IPv4 interface not found: {}", name));
        }
    }

private:
    static void copy_ipv4(ip_addr& dst, std::uint32_t src) noexcept {
        dst.fill(0);
        auto ipv4 = ipv4_addr_view{dst};
        std::memcpy(ipv4.data(), &src, ipv4.size());
    }

    static void copy_ipv6(ip_addr& dst, const std::uint8_t* src) noexcept {
        dst.fill(0);
        auto ipv6 = ipv6_addr_view{dst};
        std::memcpy(ipv6.data(), src, ipv6.size());
    }

    static void apply_ipv4_netmask(ip_addr& addr, const ip_addr& netmask) noexcept {
        auto ipv4_addr = ipv4_addr_view{addr};
        const auto ipv4_netmask = ipv4_addr_const_view{netmask};
        for (std::size_t i = 0; i < ipv4_addr.size(); ++i) {
            ipv4_addr[i] &= ipv4_netmask[i];
        }
    }

    static std::uint32_t count_prefix_bits(const ip_addr& addr, std::size_t byte_count) {
        const auto bytes = ipv6_addr_const_view{addr};
        std::uint32_t bits = 0;
        for (std::size_t i = 0; i < byte_count; ++i) {
            bits += std::popcount(static_cast<unsigned int>(bytes[i]));
        }
        return bits;
    }

    void fill_ipv4_fields(const ifaddrs* ifaddr) {
        if (has_ipv4 || !ifaddr->ifa_addr || !ifaddr->ifa_netmask) return;
        if (ifaddr->ifa_addr->sa_family != AF_INET || ifaddr->ifa_netmask->sa_family != AF_INET) return;

        flags = ifaddr->ifa_flags;
        copy_ipv4(ipv4, reinterpret_cast<const sockaddr_in*>(ifaddr->ifa_addr)->sin_addr.s_addr);
        copy_ipv4(ipv4_netmask, reinterpret_cast<const sockaddr_in*>(ifaddr->ifa_netmask)->sin_addr.s_addr);
        
        ipv4_network = ipv4;
        apply_ipv4_netmask(ipv4_network, ipv4_netmask);

        ipv4_prefix_len = count_prefix_bits(ipv4_netmask, IPV4_ADDR_BYTES);
        has_ipv4 = true;

        if ((flags & IFF_BROADCAST) && ifaddr->ifa_broadaddr &&
            ifaddr->ifa_broadaddr->sa_family == AF_INET) {
            copy_ipv4(ipv4_broadcast,
                      reinterpret_cast<const sockaddr_in*>(ifaddr->ifa_broadaddr)->sin_addr.s_addr);
            has_ipv4_broadcast = true;
        }
    }

    void fill_ipv6_fields(const ifaddrs* ifaddr) {
        if (has_ipv6 || !ifaddr->ifa_addr || !ifaddr->ifa_netmask) return;
        if (ifaddr->ifa_addr->sa_family != AF_INET6 || ifaddr->ifa_netmask->sa_family != AF_INET6) return;

        const auto* addr = reinterpret_cast<const sockaddr_in6*>(ifaddr->ifa_addr);
        const auto* mask = reinterpret_cast<const sockaddr_in6*>(ifaddr->ifa_netmask);

        copy_ipv6(ipv6, addr->sin6_addr.s6_addr);
        copy_ipv6(ipv6_netmask, mask->sin6_addr.s6_addr);
        ipv6_prefix_len = count_prefix_bits(ipv6_netmask, IPV6_ADDR_BYTES);
        has_ipv6 = true;
    }
};

}
