module;

#include <array>
#include <barrier>
#include <vector>
#include <atomic>
#include <functional>
#include <print>
#include <mutex>
#include <concepts>
#include <utility>
#include <boost/lockfree/spsc_queue.hpp>
#include "platform/arch_macros.h"

export module sniffster.queue_processor;

import sniffster.platform;
import sniffster.debug;
import sniffster.runtime_control;

template<class derived_class>
concept has_event_type = requires {
    typename derived_class::event_type;
};

template<class derived_class, class event>
concept handles_event = has_event_type<derived_class> &&
    std::same_as<std::remove_cvref_t<event>, typename derived_class::event_type> &&
    requires(derived_class& d, const typename derived_class::event_type& ev) {
        { d.handle(ev) } -> std::same_as<void>;
    };

export namespace sniffster {

template<typename derived_child, typename event_type, std::size_t batch_size = 10>
class queue_processor {
public:
    using base_type = queue_processor;
    using queue_t = boost::lockfree::spsc_queue<event_type>;

    queue_processor() = default;

    force_inline_
    void register_producer(std::reference_wrapper<queue_t> queue) {
        // Startup-only path: handlers may register concurrently while they are
        // being constructed, so mutation of the registration list is serialized
        // here. After the startup barrier in run(), queues_ is treated as fixed.
        std::lock_guard<std::mutex> lock(queues_mutex_);
        queues_.push_back(queue);
    }

    force_inline_
    void about_new_events_available() { work_to_do(); }

    force_inline_
    void we_are_done() { work_to_do(); }

protected:
    // wake the consumer
    force_inline_
    void work_to_do() {
        nothing_to_do_.store(false, std::memory_order_release);
        nothing_to_do_.notify_one();
    }

    template<class event> requires handles_event<derived_child, event>
    force_inline_
    void handle_event(const event& evt) {
        static_cast<derived_child*>(this)->handle(evt);
    }

    force_inline_
    bool still_nothing_to_do() {
        nothing_to_do_.wait(true, std::memory_order_acquire);
        return nothing_to_do_.exchange(true, std::memory_order_acq_rel);
    }

public:
    void run(runtime_control& runtime_ctrl) {
        std::array<event_type, batch_size> batch;

        // Contract boundary:
        // - before this returns, handlers are still free to self-register queues
        // - after this returns, registration is complete and queues_ is immutable
        // - on shutdown, the matching barrier keeps handlers alive until we stop
        //   touching their registered queues
        runtime_ctrl.arrive_and_wait();

        while (!runtime_ctrl.stop_requested()) {

            if (still_nothing_to_do())  // either work available or spurious wakeup
                continue;

            // Attempt to drain all queues. If any event was drained,
            // repeat the process to check for more events until all
            // queues are empty.

            bool drained_any = true;
            while (drained_any) {
                drained_any = false;

                // queues_ is immutable and thread safe by this point
                for (queue_t& queue : queues_) {
                    const std::size_t n_popped = queue.pop(batch.data(), batch.size());
                    if (n_popped > 0) {
                        drained_any = true;
                        
                        for (std::size_t i = 0; i < n_popped; ++i) {
                            handle_event(batch[i]);
                        }
                    }
                }
            } // nothing to drain, return to check whether the exit was requested
        }

        runtime_ctrl.arrive_and_wait();
    }

private:
    std::mutex queues_mutex_;
    std::atomic<bool> nothing_to_do_ = true;

    // Registered producer queues are borrowed, not owned. Safety comes from:
    // - mutex-serialized startup registration
    // - no draining before the startup barrier releases
    // - no handler teardown until the shutdown barrier releases
    std::vector<std::reference_wrapper<queue_t>> queues_;
};

} // namespace sniff
