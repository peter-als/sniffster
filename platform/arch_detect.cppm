module;
#include <string_view>

export module sniffster.platform:arch_detect;

// Fully compile time 
export namespace platform {
#if defined(_MSC_VER)
    constexpr std::string_view name      = "windows";
    constexpr std::string_view toolchain = "microsoft";
    constexpr std::string_view dialect   = "msvc";
#elif defined(__clang__)
    constexpr std::string_view name =      "unix";
    constexpr std::string_view toolchain = "clang";
    constexpr std::string_view dialect   = "unknown";
#elif defined(__GNUC__)
    constexpr std::string_view name      = "unix";
    constexpr std::string_view toolchain = "gnu";
    constexpr std::string_view dialect   = "unknown";
#else
    constexpr std::string_view name      = "unknown";
    constexpr std::string_view toolchain = "unknown";
    constexpr std::string_view dialect   = "unknown";
#endif

#if defined(__x86_64__)
    constexpr std::string_view architecture = "x86_64";
    constexpr unsigned arch_bits = 64;
    constexpr bool allow_unaligned_load = true;
#elif defined(__i386__)
    constexpr std::string_view architecture = "x86";
    constexpr unsigned arch_bits = 32;
    constexpr bool allow_unaligned_load = true;
#elif defined(__aarch64__)
    constexpr std::string_view architecture = "aarch64";
    constexpr unsigned arch_bits = 64;
    constexpr bool allow_unaligned_load = false;
#elif defined(__arm__) || defined(__thumb__)
    constexpr std::string_view architecture = "arm32";
    constexpr unsigned arch_bits = 32;
    constexpr bool allow_unaligned_load = false;
#elif defined(__riscv)
    constexpr std::string_view architecture = "riscv";
    constexpr unsigned arch_bits = sizeof(void*) * 8;
    constexpr bool allow_unaligned_load = false;
#else
    #error "Unsupported or unknown target architecture"
#endif

} // namespace platform
