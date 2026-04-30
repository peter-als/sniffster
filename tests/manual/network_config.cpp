#include <cstdlib>
#include <net/if.h>
#include <netinet/in.h>
#include <print>

import sniffster.network.config;
import sniffster.processors.format_data;

void print_flags(unsigned flags)
{
    if (flags & IFF_UP)             std::print("UP ");
    if (flags & IFF_RUNNING)        std::print("RUNNING ");
    if (flags & IFF_LOOPBACK)       std::print("LOOPBACK ");
    if (flags & IFF_PROMISC)        std::print("PROMISC ");
    if (flags & IFF_BROADCAST)      std::print("BROADCAST ");
    if (flags & IFF_MULTICAST)      std::print("MULTICAST ");
    if (flags & IFF_POINTOPOINT)    std::print("POINTOPOINT ");
    if (flags & IFF_NOARP)          std::print("NOARP ");
    std::println("");
}

int main(int argc, char* argv[])
{
    if (argc < 2) {
        std::println(stderr, "usage: {}  <interface>", argv[0]);
        return EXIT_FAILURE;
    }

    try {
        sniffster::network_interface nic(argv[1]);

        std::println("name:          {}", nic.name);
        std::println("ifindex:       {}", nic.ifindex);
        std::println("ipv4:          {}", sniffster::ip_to_str(AF_INET, sniffster::ipv4_addr_const_view{nic.ipv4}.data()));
        std::println("ipv4_netmask:  {}", sniffster::ip_to_str(AF_INET, sniffster::ipv4_addr_const_view{nic.ipv4_netmask}.data()));
        std::println("ipv4_network:  {}", sniffster::ip_to_str(AF_INET, sniffster::ipv4_addr_const_view{nic.ipv4_network}.data()));
        std::println("ipv4_prefix:   {}", nic.ipv4_prefix_len);
        std::println("flags:         {:#x}: ", nic.flags);
        print_flags(nic.flags);

        if (nic.has_ipv4_broadcast) {
            std::println("ipv4_broadcast:{}", sniffster::ip_to_str(AF_INET, sniffster::ipv4_addr_const_view{nic.ipv4_broadcast}.data()));
        }

        if (nic.has_ipv6) {
            std::println("ipv6:          {}", sniffster::ip_to_str(AF_INET6, sniffster::ipv6_addr_const_view{nic.ipv6}.data()));
            std::println("ipv6_netmask:  {}", sniffster::ip_to_str(AF_INET6, sniffster::ipv6_addr_const_view{nic.ipv6_netmask}.data()));
            std::println("ipv6_prefix:   {}", nic.ipv6_prefix_len);
        }
    }
    catch (const std::exception& e) {
        std::println(stderr, "error: {}", e.what());
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
