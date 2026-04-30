module;

#include <bit>
#include <cstdint>
#include <thread>
#include <vector>

#if defined(_POSIX_VERSION) || defined(__unix__) || defined(__APPLE__)
#include <unistd.h>
#endif

#include "platform/arch_macros.h"

export module sniffster.platform;
import sniffster.platform.decorated_throw;
export import :arch_detect;
export import :clock;

export namespace platform {

template<typename T>
constexpr T to_network(T val) {
    if constexpr (std::endian::native == std::endian::little) {
        return std::byteswap(val);
    }

    return val;
}

template<typename T>
constexpr T from_network(T val) {
    return to_network(val);
}

[[nodiscard]] force_inline_
uint32_t detect_cpu_count() {
    const unsigned int thread_count = std::thread::hardware_concurrency();

    if (thread_count != 0) {
        return thread_count;
    }

    // Apparently, C++ standard still allows hardware_concurrency() to fail and return 0.
    // Fall back to POSIX sysconf:
    #if defined(_SC_NPROCESSORS_ONLN)
    const long online_cpus = sysconf(_SC_NPROCESSORS_ONLN);

    if (online_cpus > 0) {
        return static_cast<uint32_t>(online_cpus);
    }
    #endif

    throw_runtime_error("Unable to detect the number of online CPUs");
}

[[nodiscard]] force_inline_
std::vector<std::uint32_t>
detect_cpu_ids() {
    const std::uint32_t detected_cpu_count = detect_cpu_count();
    std::vector<std::uint32_t> ids(detected_cpu_count);
    for (std::uint32_t cpu = 0; cpu < detected_cpu_count; ++cpu) {
        ids[cpu] = cpu;
    }
    return ids;
}

} // namespace platform
