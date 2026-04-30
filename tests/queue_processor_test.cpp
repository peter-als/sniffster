#include <barrier>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <mutex>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

import sniffster.queue_processor;
import sniffster.runtime_control;

namespace {

class recording_queue_processor
    : public sniffster::queue_processor<recording_queue_processor, int, 4> {
public:
    using event_type = int;

    void handle(const event_type& value) {
        std::lock_guard<std::mutex> lock(mutex_);
        handled_.push_back(value);
    }

    [[nodiscard]] std::vector<int> handled_values() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return handled_;
    }

private:
    mutable std::mutex mutex_;
    std::vector<int> handled_;
};

void stop_and_join(recording_queue_processor& processor,
                   sniffster::runtime_control& runtime_ctrl,
                   std::thread& thread) {
    ASSERT_EQ(std::raise(SIGINT), 0);
    processor.we_are_done();
    runtime_ctrl.arrive_and_wait();
    thread.join();
}

TEST(QueueProcessorTest, WakesAndDrainsSingleRegisteredQueue) {
    recording_queue_processor processor;
    recording_queue_processor::queue_t queue{16};
    processor.register_producer(queue);

    sniffster::runtime_control runtime_ctrl(2);

    std::thread worker([&processor, &runtime_ctrl] {
        processor.run(runtime_ctrl);
    });

    runtime_ctrl.arrive_and_wait();

    ASSERT_TRUE(queue.push(1));
    ASSERT_TRUE(queue.push(2));
    ASSERT_TRUE(queue.push(3));
    processor.about_new_events_available();

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
    while (std::chrono::steady_clock::now() < deadline) {
        const auto handled = processor.handled_values();
        if (handled.size() == 3) {
            EXPECT_EQ(handled, (std::vector<int>{1, 2, 3}));
            stop_and_join(processor, runtime_ctrl, worker);
            return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    stop_and_join(processor, runtime_ctrl, worker);
    FAIL() << "queue_processor did not drain the single producer queue";
}

TEST(QueueProcessorTest, DrainsMultipleQueuesAcrossRepeatedPasses) {
    recording_queue_processor processor;
    recording_queue_processor::queue_t queue_a{16};
    recording_queue_processor::queue_t queue_b{16};
    processor.register_producer(queue_a);
    processor.register_producer(queue_b);

    sniffster::runtime_control runtime_ctrl(2);

    std::thread worker([&processor, &runtime_ctrl] {
        processor.run(runtime_ctrl);
    });

    runtime_ctrl.arrive_and_wait();

    for (int value : {1, 2, 3, 4, 5}) {
        ASSERT_TRUE(queue_a.push(value));
    }
    for (int value : {10, 11, 12}) {
        ASSERT_TRUE(queue_b.push(value));
    }
    processor.about_new_events_available();

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
    while (std::chrono::steady_clock::now() < deadline) {
        const auto handled = processor.handled_values();
        if (handled.size() == 8) {
            EXPECT_EQ(handled, (std::vector<int>{1, 2, 3, 4, 10, 11, 12, 5}));
            stop_and_join(processor, runtime_ctrl, worker);
            return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    stop_and_join(processor, runtime_ctrl, worker);
    FAIL() << "queue_processor did not fully drain both producer queues";
}

} // namespace
