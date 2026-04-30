module;

#include <array>
#include <cstdint>
#include <span>
#include <type_traits>
#include <cstddef>

#include "network/packet_offsets.h"

export module sniffster.network.addresses;

export namespace sniffster {

using mac_addr = std::array<std::uint8_t, ETH_ALEN>;
using ip_addr = std::array<std::uint8_t, IP_STORAGE_SIZE>;

template<class T>
concept ip_addr_byte =
    std::same_as<std::remove_const_t<T>, std::uint8_t>;

template<std::size_t N>
concept ip_addr_size = (N == IPV4_ADDR_BYTES) || (N == IPV6_ADDR_BYTES);

template<class T, std::size_t N>
concept ip_addr_raw_bytes =
    std::same_as<std::remove_cvref_t<T>, std::uint8_t> &&
    ip_addr_byte<T> &&
    ip_addr_size<N>;

template<class Storage>
concept ip_addr_storage = std::same_as<std::remove_cvref_t<Storage>, ip_addr>;

template<class T, std::size_t N>
requires ip_addr_byte<T> && ip_addr_size<N>
class ip_addr_view : public std::span<T, N> {
public:

    // Constructor for ip_addr storage type (const or non-const)
    template<class U>
    requires ip_addr_storage<U>
    explicit ip_addr_view(U& ip_storage) noexcept :
    std::span<T, N>(ip_storage.data(), N) {}

    // Constructor for raw uchar8_t array (const or non-const)
    template<class U>
    requires ip_addr_raw_bytes<U, N>
    explicit ip_addr_view(U (&byte_storage)[N]) noexcept :
    std::span<T, N>(byte_storage, N) {}

    // Constructor for raw uchar8_t* (const or non-const);
    // assumes the length is available!
    template<class U>
    requires ip_addr_raw_bytes<U, N>
    explicit ip_addr_view(U* byte_storage) noexcept :
    std::span<T, N>(byte_storage, N) {}
};

using ipv4_addr_view = ip_addr_view<std::uint8_t, IPV4_ADDR_BYTES>;
using ipv4_addr_const_view = ip_addr_view<const std::uint8_t, IPV4_ADDR_BYTES>;
using ipv6_addr_view = ip_addr_view<std::uint8_t, IPV6_ADDR_BYTES>;
using ipv6_addr_const_view = ip_addr_view<const std::uint8_t, IPV6_ADDR_BYTES>;

} // namespace sniffster
