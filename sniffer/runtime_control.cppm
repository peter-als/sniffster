module;

#include <barrier>
#include <csignal>
#include <print>

export module sniffster.runtime_control;

static volatile std::sig_atomic_t g_exit_signal = 0;
static void stop_on_signal(int) {
    g_exit_signal = 1;
}

export namespace sniffster {

class runtime_control {
public:
    runtime_control(std::size_t threads_to_sync) :
                    exit_signal(g_exit_signal),
                    lifetime_barrier(threads_to_sync) {
        // Register signals for graceful shutdown
        std::signal(SIGINT, stop_on_signal);
        std::signal(SIGTERM, stop_on_signal);
    }

    void arrive_and_wait() {
        lifetime_barrier.arrive_and_wait();
    }

    ~runtime_control() {
        // Restore default signal handlers
        std::signal(SIGINT, SIG_DFL);
        std::signal(SIGTERM, SIG_DFL);
    }

    runtime_control(const runtime_control&) = delete;
    runtime_control& operator=(const runtime_control&) = delete;

    [[nodiscard]] static
    bool stop_requested() noexcept {
        return g_exit_signal != 0;
    }

private:    
    volatile std::sig_atomic_t& exit_signal;
    std::barrier<> lifetime_barrier;

}; // class runtime_control

} // namespace sniffster
