#include <array>
#include <bit>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <format>
#include <iostream>
#include <regex>
#include <source_location>
#include <string>

#include <gtest/gtest.h>

#include "platform/arch_macros.h"
#include "platform/crc32_u64.hpp"

import sniffster.platform;
import sniffster.platform.decorated_throw;

namespace {

[[nodiscard]] force_inline_
std::string now_in_local_time() {
    using namespace std::chrono;
    const auto now = floor<milliseconds>(system_clock::now());
    const auto secs = system_clock::to_time_t(now);
    std::tm local_tm{};
#if defined(_WIN32)
    localtime_s(&local_tm, &secs);
#else
    localtime_r(&secs, &local_tm);
#endif
    char buf[20]{};
    std::strftime(buf, sizeof(buf), "%F %T", &local_tm);
    return buf;
}

force_inline_ int force_inline_increment(int value) {
    return value + 1;
}

never_inline_ int never_inline_double(int value) {
    return value * 2;
}

struct align_64_ aligned_value {
    std::uint64_t value;
};

template<typename Fn>
[[nodiscard]] std::uint32_t run_crc32_vectors(Fn&& fn) {
    constexpr std::array<std::uint32_t, 6> seeds{
        0u,
        1u,
        0x12345678u,
        0xFFFFFFFFu,
        0xA5A5A5A5u,
        0xDEADBEEFu,
    };
    constexpr std::array<std::uint64_t, 8> values{
        0ULL,
        1ULL,
        0x0123456789ABCDEFULL,
        0xFEDCBA9876543210ULL,
        0x00000000FFFFFFFFULL,
        0xFFFFFFFF00000000ULL,
        0xAAAAAAAA55555555ULL,
        0x13579BDF2468ACE0ULL,
    };

    std::uint32_t crc = 0;
    for (std::uint32_t seed : seeds) {
        for (std::uint64_t value : values) {
            crc ^= fn(seed, value);
        }
    }
    return crc;
}

[[nodiscard]] constexpr std::string_view basename(std::string_view path) noexcept {
    const std::size_t pos = path.find_last_of("/\\");
    return pos == std::string_view::npos ? path : path.substr(pos + 1);
}

[[noreturn]] void throw_plain_runtime_error_here(std::uint_least32_t& line_out) {
    line_out = std::source_location::current().line() + 1;
    platform::throw_runtime_error("plain failure");
}

[[noreturn]] void throw_formatted_runtime_error_here(std::uint_least32_t& line_out, int value) {
    line_out = std::source_location::current().line() + 1;
    platform::throw_runtime_error(std::format("formatted failure {}", value));
}

[[nodiscard]] std::string runtime_error_message_here(std::uint_least32_t& line_out) {
    line_out = std::source_location::current().line() + 1;
    return platform::runtime_error_msg("message-only helper");
}

TEST(PlatformArchDetect, CurrentCompilerAndArchitectureConstantsMatchBuild) {
#if defined(__clang__)
    EXPECT_EQ(platform::toolchain, "clang");
    EXPECT_EQ(platform::dialect, "unknown");
#elif defined(__GNUC__)
    EXPECT_EQ(platform::toolchain, "gnu");
    EXPECT_EQ(platform::dialect, "unknown");
#elif defined(_MSC_VER)
    EXPECT_EQ(platform::toolchain, "microsoft");
    EXPECT_EQ(platform::dialect, "msvc");
#endif

#if defined(__x86_64__)
    EXPECT_EQ(platform::architecture, "x86_64");
    EXPECT_EQ(platform::arch_bits, 64u);
    EXPECT_TRUE(platform::allow_unaligned_load);
#elif defined(__i386__)
    EXPECT_EQ(platform::architecture, "x86");
    EXPECT_EQ(platform::arch_bits, 32u);
    EXPECT_TRUE(platform::allow_unaligned_load);
#elif defined(__aarch64__)
    EXPECT_EQ(platform::architecture, "aarch64");
    EXPECT_EQ(platform::arch_bits, 64u);
    EXPECT_FALSE(platform::allow_unaligned_load);
#elif defined(__arm__) || defined(__thumb__)
    EXPECT_EQ(platform::architecture, "arm32");
    EXPECT_EQ(platform::arch_bits, 32u);
    EXPECT_FALSE(platform::allow_unaligned_load);
#elif defined(__riscv)
    EXPECT_EQ(platform::architecture, "riscv");
    EXPECT_EQ(platform::arch_bits, sizeof(void*) * 8u);
    EXPECT_FALSE(platform::allow_unaligned_load);
#endif
}

TEST(PlatformByteOrder, ToNetworkAndFromNetworkRoundTrip) {
    const std::uint16_t v16 = 0x1234;
    const std::uint32_t v32 = 0x12345678;
    const std::uint64_t v64 = 0x0123456789ABCDEFULL;

    EXPECT_EQ(platform::from_network(platform::to_network(v16)), v16);
    EXPECT_EQ(platform::from_network(platform::to_network(v32)), v32);
    EXPECT_EQ(platform::from_network(platform::to_network(v64)), v64);

    if constexpr (std::endian::native == std::endian::little) {
        EXPECT_EQ(platform::to_network(v16), std::byteswap(v16));
        EXPECT_EQ(platform::to_network(v32), std::byteswap(v32));
        EXPECT_EQ(platform::to_network(v64), std::byteswap(v64));
    } else {
        EXPECT_EQ(platform::to_network(v16), v16);
        EXPECT_EQ(platform::to_network(v32), v32);
        EXPECT_EQ(platform::to_network(v64), v64);
    }
}

TEST(PlatformCpuCount, ReturnsPositiveCountByDefault) {
    EXPECT_GT(platform::detect_cpu_count(), 0u);
}

TEST(PlatformThrowRuntimeError, PlainMessageIncludesCallSiteContext) {
    const auto this_file = basename(std::source_location::current().file_name());
    std::uint_least32_t expected_line = 0;

    try {
        throw_plain_runtime_error_here(expected_line);
        FAIL() << "expected std::runtime_error";
    } catch (const std::runtime_error& err) {
        const std::string message = err.what();
        EXPECT_NE(message.find("plain failure"), std::string::npos);
        EXPECT_NE(message.find(std::format("{}:{}", this_file, expected_line)), std::string::npos);
        EXPECT_NE(message.find("throw_plain_runtime_error_here"), std::string::npos);
        EXPECT_EQ(message.find("decorated_throw.cppm"), std::string::npos);
    }
}

TEST(PlatformThrowRuntimeError, FormattedMessageUsesCallerLocation) {
    const auto this_file = basename(std::source_location::current().file_name());
    std::uint_least32_t expected_line = 0;

    try {
        throw_formatted_runtime_error_here(expected_line, 42);
        FAIL() << "expected std::runtime_error";
    } catch (const std::runtime_error& err) {
        const std::string message = err.what();
        EXPECT_NE(message.find("formatted failure 42"), std::string::npos);
        EXPECT_NE(message.find(std::format("{}:{}", this_file, expected_line)), std::string::npos);
        EXPECT_NE(message.find("throw_formatted_runtime_error_here"), std::string::npos);
        EXPECT_EQ(message.find("decorated_throw.cppm"), std::string::npos);
    }
}

TEST(PlatformThrowRuntimeError, ThrowContextDefaultBracesUseCallerLocation) {
    const auto this_file = basename(std::source_location::current().file_name());
    std::uint_least32_t expected_line = 0;

    const std::string message = runtime_error_message_here(expected_line);
    EXPECT_NE(message.find("message-only helper"), std::string::npos);
    EXPECT_NE(message.find(std::format("{}:{}", this_file, expected_line)), std::string::npos);
    EXPECT_NE(message.find("runtime_error_message_here"), std::string::npos);
    EXPECT_EQ(message.find("decorated_throw.cppm"), std::string::npos);
}

TEST(PlatformTime, DefaultFormatMatchesTimestampShape) {
    const std::regex pattern{R"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"};

    EXPECT_TRUE(std::regex_match(now_in_local_time(), pattern));
}

TEST(PlatformMacros, EndianAndLoadHelpersBehaveAsExpected) {
    static_assert(target_little_endian_ == (std::endian::native == std::endian::little ? 1 : 0));

    EXPECT_EQ(ntoh16_(static_cast<__u16>(0x1234)),
              std::endian::native == std::endian::little ? 0x3412 : 0x1234);

    const std::array<std::uint8_t, 2> bytes{0xAB, 0xCD};
    EXPECT_EQ(load_net16_from_bytes_(bytes.data()), 0xABCD);
}

TEST(PlatformMacros, MemcpyMemsetAndAlignmentMacrosCompileAndWork) {
    std::array<std::uint8_t, 4> src{1, 2, 3, 4};
    std::array<std::uint8_t, 4> dst{0, 0, 0, 0};

    memcpy_(dst.data(), src.data(), src.size());
    EXPECT_EQ(dst, src);

    memset_(dst.data(), 0x7F, dst.size());
    EXPECT_EQ(dst, (std::array<std::uint8_t, 4>{0x7F, 0x7F, 0x7F, 0x7F}));

    EXPECT_GE(alignof(aligned_value), alignof(std::uint64_t));
}

TEST(PlatformMacros, InlineAndBranchHintMacrosCompileViaCallSites) {
    if (true) likely_ {
        EXPECT_EQ(force_inline_increment(4), 5);
    }

    if (false) unlikely_ {
        FAIL();
    }

    EXPECT_EQ(never_inline_double(6), 12);
}

TEST(PlatformCrc32, SoftwareAndOptimizedImplementationsMatch) {
    constexpr std::array<std::uint32_t, 6> seeds{
        0u,
        1u,
        0x12345678u,
        0xFFFFFFFFu,
        0xA5A5A5A5u,
        0xDEADBEEFu,
    };
    constexpr std::array<std::uint64_t, 8> values{
        0ULL,
        1ULL,
        0x0123456789ABCDEFULL,
        0xFEDCBA9876543210ULL,
        0x00000000FFFFFFFFULL,
        0xFFFFFFFF00000000ULL,
        0xAAAAAAAA55555555ULL,
        0x13579BDF2468ACE0ULL,
    };

    for (std::uint32_t seed : seeds) {
        for (std::uint64_t value : values) {
            EXPECT_EQ(sniffster::platform::crc32_u64(seed, value),
                      sniffster::platform::crc32_u64_software(seed, value))
                << "seed=" << seed << " value=" << value;
        }
    }
}

TEST(PlatformCrc32, ReportsSoftwareAndOptimizedTiming) {
    constexpr int iterations = 250000;

    volatile std::uint32_t optimized_sink = 0;
    volatile std::uint32_t software_sink = 0;

    const auto optimized_start = std::chrono::steady_clock::now();
    for (int i = 0; i < iterations; ++i) {
        optimized_sink ^= run_crc32_vectors([i](std::uint32_t seed, std::uint64_t value) {
            return sniffster::platform::crc32_u64(seed ^ static_cast<std::uint32_t>(i),
                                              value ^ static_cast<std::uint64_t>(i));
        });
    }
    const auto optimized_elapsed =
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - optimized_start);

    const auto software_start = std::chrono::steady_clock::now();
    for (int i = 0; i < iterations; ++i) {
        software_sink ^= run_crc32_vectors([i](std::uint32_t seed, std::uint64_t value) {
            return sniffster::platform::crc32_u64_software(seed ^ static_cast<std::uint32_t>(i),
                                                       value ^ static_cast<std::uint64_t>(i));
        });
    }
    const auto software_elapsed =
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - software_start);

    EXPECT_EQ(optimized_sink, software_sink);

    std::cout << "crc32 optimized: " << optimized_elapsed.count()
              << " us, software: " << software_elapsed.count() << " us\n";

    RecordProperty("crc32_iterations", iterations);
    RecordProperty("crc32_optimized_us", static_cast<int>(optimized_elapsed.count()));
    RecordProperty("crc32_software_us", static_cast<int>(software_elapsed.count()));
}

} // namespace
