module;

#include <barrier>
#include <csignal>
#include <print>

export module sniffster.runtime_control;

static void stop_on_signal(int);
// static volatile std::sig_atomic_t g_exit_signal = 0;

export namespace sniffster {

class runtime_control {
public:
    runtime_control(std::size_t threads_to_sync) :
                    lifetime_barrier(threads_to_sync) {
        
        if (++instance_count > 1) {
            throw std::runtime_error(
                "multiple runtime_control instances are not allowed");
        }

        // Register signals for graceful shutdown
        std::signal(SIGINT, stop_on_signal);
        std::signal(SIGTERM, stop_on_signal);
    }

    runtime_control(runtime_control&&) = delete;
    runtime_control& operator=(runtime_control&&) = delete;
    runtime_control(const runtime_control&) = delete;
    runtime_control& operator=(const runtime_control&) = delete;

    void arrive_and_wait() {
        lifetime_barrier.arrive_and_wait();
    }

    ~runtime_control() {
        // Restore default signal handlers
        std::signal(SIGINT, SIG_DFL);
        std::signal(SIGTERM, SIG_DFL);
    }

    [[nodiscard]] static
    bool stop_requested() noexcept {
        return g_exit_signal != 0;
    }

private:
    std::barrier<> lifetime_barrier;
    static size_t instance_count;
    static volatile std::sig_atomic_t g_exit_signal;
    friend void ::stop_on_signal(int);
}; // class runtime_control

volatile std::sig_atomic_t runtime_control::g_exit_signal = 0;
size_t runtime_control::instance_count = 0;

} // namespace sniffster

static void stop_on_signal(int) {
    sniffster::runtime_control::g_exit_signal = 1;
}
