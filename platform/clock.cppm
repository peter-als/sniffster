module;

#include <chrono>
#include <cstdint>
#include <ratio>

export module sniffster.platform:clock;

export namespace sniffster {

// There is currently no way around it. Template specializations won't spare us
// from parsing __builtin_ia32_rdtsc() on non-x86 platforms.
#if defined(__x86_64__) || defined(__i386__)

// On x86/x86_64 use RDTSC directly — single instruction, ~7 cycles overhead.
// period is 1:1 (raw ticks), not nanoseconds. To convert to wall time,
// calibrate the TSC frequency once at startup and divide.
struct performance_tick_counter {
    using rep        = uint64_t;
    using period     = std::ratio<1, 1>; // one tick per count
    using duration   = std::chrono::duration<rep, period>;
    using time_point = std::chrono::time_point<performance_tick_counter>;
    static constexpr bool is_steady = true;

    [[nodiscard]] static time_point now() noexcept {
        return time_point{duration{__builtin_ia32_rdtsc()}};
    }
};

#else

// On all other platforms (ARM, Apple Silicon, RISC-V, …) defer to the
// standard high_resolution_clock which maps to the best available
// platform primitive (CNTVCT_EL0, mach_absolute_time, etc.)
using performance_tick_counter = std::chrono::high_resolution_clock;

#endif

} // namespace sniff
