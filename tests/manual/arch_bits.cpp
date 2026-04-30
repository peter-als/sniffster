#include <boost/asio/ip/address_v4.hpp>
#include <bit>
#include <cstdint>
#include <ios>
#include <iostream>
#include <print>

int main() {
    // 255.0.0.0 in network byte order
    boost::asio::ip::address_v4::bytes_type bytes = {0xFF, 0x00, 0x00, 0x00};
    boost::asio::ip::address_v4 addr(bytes);
    std::println("{}", addr.to_string());
    std::println("{:#x}", addr.to_uint());

    uint8_t bytes_array[4] = {0xFF, 0x00, 0x00, 0x00};
    uint32_t value = std::bit_cast<uint32_t>(bytes_array);
    std::println("{:#x}", value);

    // Need to test if bytes are not aligned.
    uint32_t value2 = *reinterpret_cast<uint32_t*>(bytes_array);
    std::println("{:#x}", value2);
}
