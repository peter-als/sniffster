#pragma once

#include <array>

#if defined(__SSE4_2__)
#include <immintrin.h> // For x86 intrinsics
#endif

#if defined(__ARM_FEATURE_CRC32)
#include <arm_acle.h>  // For ARM intrinsics
#endif

#include "platform/arch_macros.h"

#if defined(__SSE4_2__) || defined(__ARM_FEATURE_CRC32)
    constexpr bool crc32_enabled = true;
#else
    constexpr bool crc32_enabled = false;
#endif

namespace sniffster::platform::detail {
    inline constexpr auto crc32c_table = [] {
        std::array<uint32_t, 256> t{};
        constexpr uint32_t poly = 0x82f63b78;  // CRC32C reflected polynomial
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int k = 0; k < 8; ++k) {
                c = (c & 1) ? (c >> 1) ^ poly : c >> 1;
            }
            t[i] = c;
        }
        return t;
    }();   
} // namespace sniffster::platform::detail
    
namespace sniffster::platform {

[[nodiscard]] inline
uint32_t crc32_u64_software(uint32_t crc, uint64_t value) noexcept {
    for (int i = 0; i < 8; ++i) {
        crc = detail::crc32c_table[(crc ^ static_cast<uint8_t>(value)) & 0xff]
        ^ (crc >> 8);
        value >>= 8;
    }
    return crc;
}

[[nodiscard]] inline
uint32_t crc32_u64(uint32_t crc, uint64_t value) noexcept {
    if constexpr (crc32_enabled) {
        #if defined(__SSE4_2__)
            #if defined(__x86_64__) || defined(_M_X64)
                return static_cast<uint32_t>(_mm_crc32_u64(crc, value));
            #elif defined(__i386__) || defined(_M_IX86)
                crc = _mm_crc32_u32(crc, static_cast<uint32_t>(value));
                return _mm_crc32_u32(crc, static_cast<uint32_t>(value >> 32));
            #endif
        #elif defined(__ARM_FEATURE_CRC32)
            #if defined(__aarch64__)
                return __crc32cd(crc, value);
            #elif defined(__arm__) || defined(__thumb__) || defined(_M_ARM)
                crc = __crc32cw(crc, static_cast<uint32_t>(value));
                return __crc32cw(crc, static_cast<uint32_t>(value >> 32));
            #endif
        #endif
    }

    return crc32_u64_software(crc, value);
}

} // namespace sniffster::platform
