#include <chrono>
#include <cstdint>
#include <ratio>
#include <thread>
#include <type_traits>

#include <gtest/gtest.h>

import sniffster.platform;

namespace {

using clock_t = sniffster::performance_tick_counter;

// ---------------------------------------------------------------------------
// Compile-time API conformance
// ---------------------------------------------------------------------------

static_assert(std::is_same_v<clock_t::rep, clock_t::duration::rep>);
static_assert(std::is_same_v<clock_t::period, clock_t::duration::period>);
static_assert(std::is_same_v<
    clock_t::time_point,
    std::chrono::time_point<clock_t, clock_t::duration>>);
static_assert(std::is_same_v<decltype(clock_t::is_steady), const bool>);
static_assert(clock_t::is_steady);

// if period is ratio<1,1> (raw ticks), rep must be uint64_t
static_assert(!std::is_same_v<clock_t::period, std::ratio<1, 1>> ||
              std::is_same_v<clock_t::rep, uint64_t>);

// ---------------------------------------------------------------------------
// now() basic behaviour
// ---------------------------------------------------------------------------

TEST(PrecisionClock, NowReturnsTimePoint) {
    auto t = clock_t::now();
    (void)t; // just must compile and not crash
}

TEST(PrecisionClock, NowIsNonZero) {
    // TSC and system clocks both return non-zero values post-boot
    auto t = clock_t::now();
    EXPECT_GT(t.time_since_epoch().count(), 0);
}

TEST(PrecisionClock, TwoCallsAreNonDecreasing) {
    auto t1 = clock_t::now();
    auto t2 = clock_t::now();
    EXPECT_LE(t1, t2);
}

TEST(PrecisionClock, ClockAdvancesOverTime) {
    auto t1 = clock_t::now();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    auto t2 = clock_t::now();
    EXPECT_GT(t2, t1);
}

// ---------------------------------------------------------------------------
// Duration arithmetic
// ---------------------------------------------------------------------------

TEST(PrecisionClock, DurationBetweenTwoPointsIsPositive) {
    auto t1 = clock_t::now();
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    auto t2 = clock_t::now();
    auto delta = t2 - t1;
    EXPECT_GT(delta.count(), 0);
}

TEST(PrecisionClock, EarlierTimepointSubtractedFromLaterIsPositive) {
    auto t1 = clock_t::now();
    auto t2 = clock_t::now();
    EXPECT_GE((t2 - t1).count(), 0);
}

TEST(PrecisionClock, TimePointArithmeticRoundTrips) {
    auto t1 = clock_t::now();
    auto t2 = clock_t::now();
    auto delta = t2 - t1;
    EXPECT_EQ(t1 + delta, t2);
}

// ---------------------------------------------------------------------------
// Performance: measured delay matches sleep duration
// ---------------------------------------------------------------------------

TEST(PrecisionClock, MeasuredDelayMatchesSleep) {
    constexpr auto sleep_ms  = 50;
    constexpr auto tolerance = 0.5; // 50% — generous to account for OS scheduling

    // Use steady_clock as ground truth for elapsed wall time
    auto ref_t1 = std::chrono::steady_clock::now();
    auto t1     = clock_t::now();

    std::this_thread::sleep_for(std::chrono::milliseconds(sleep_ms));

    auto t2     = clock_t::now();
    auto ref_t2 = std::chrono::steady_clock::now();

    // Ground truth: we actually slept for roughly sleep_ms
    auto ref_ms = std::chrono::duration_cast<std::chrono::milliseconds>(ref_t2 - ref_t1).count();
    EXPECT_GE(ref_ms, sleep_ms * (1.0 - tolerance));
    EXPECT_LE(ref_ms, sleep_ms * (1.0 + tolerance));

    // performance_tick_counter must have advanced
    EXPECT_GT((t2 - t1).count(), 0);

    // On nanosecond-period clocks we can compare directly
    if constexpr (!std::is_same_v<clock_t::period, std::ratio<1, 1>>) {
        auto measured_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();
        EXPECT_GE(measured_ms, sleep_ms * (1.0 - tolerance));
        EXPECT_LE(measured_ms, sleep_ms * (1.0 + tolerance));
    }
}

} // namespace
