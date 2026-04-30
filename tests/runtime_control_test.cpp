#include <csignal>
#include <chrono>
#include <thread>
#include <barrier>

#include <gtest/gtest.h>

import sniffster.runtime_control;

namespace {

TEST(RuntimeControl, StopRequestedReflectsExitSignal) {
    sniffster::runtime_control ctrl(1);

    EXPECT_FALSE(ctrl.stop_requested());
    ASSERT_EQ(std::raise(SIGINT), 0);

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(100);
    while (std::chrono::steady_clock::now() < deadline) {
        if (ctrl.stop_requested()) {
            SUCCEED();
            return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    EXPECT_TRUE(ctrl.stop_requested());
}

} // namespace
