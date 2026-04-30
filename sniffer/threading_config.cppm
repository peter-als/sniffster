module;

#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

export module sniffster.threading_config;

import sniffster.platform;
import sniffster.platform.decorated_throw;

export namespace sniffster {

struct threading_config {
    const std::vector<std::uint32_t> cpu_ids;
    const std::uint32_t thread_count;

    threading_config() : threading_config(0, {}) {}

    explicit threading_config(std::uint32_t requested_thread_count)
        : threading_config(requested_thread_count, {}) {}

    explicit threading_config(const std::vector<std::uint32_t>& requested_cpu_ids)
        : threading_config(0, requested_cpu_ids) {}

    explicit threading_config(std::uint32_t requested_thread_count,
                              const std::vector<std::uint32_t>& requested_cpu_ids) :

        cpu_ids(normalize_cpu_ids_(requested_thread_count,
                                   requested_cpu_ids)),

        thread_count(normalize_thread_count_(requested_thread_count,
                                             requested_cpu_ids))
    {}

    [[nodiscard]] std::vector<std::vector<std::uint32_t>>
    cpu_ids_per_thread() const {
        std::vector<std::vector<std::uint32_t>> distributed_cpu_ids(thread_count);
        const std::size_t cpus_per_thread = cpu_ids.size() / thread_count;
        const std::size_t extra_cpus = cpu_ids.size() % thread_count;

        auto next_cpu = cpu_ids.begin();
        for (std::size_t thread_index = 0; thread_index < thread_count; ++thread_index) {
            const std::size_t cpu_count_for_this_thread =
                cpus_per_thread + (thread_index < extra_cpus ? 1u : 0u);

            auto& assigned_cpus = distributed_cpu_ids[thread_index];
            assigned_cpus.reserve(cpu_count_for_this_thread);
            for (std::size_t cpu_index = 0; cpu_index < cpu_count_for_this_thread; ++cpu_index) {
                assigned_cpus.push_back(*next_cpu);
                ++next_cpu;
            }
        }

        return distributed_cpu_ids;
    }

private:
    static std::vector<std::uint32_t>
    normalize_cpu_ids_(std::uint32_t requested_thread_count,
                       const std::vector<std::uint32_t>& cpu_ids) {

        if (!cpu_ids.empty()) {
            if (requested_thread_count > cpu_ids.size()) {
                platform::throw_runtime_error(
                    "Requested thread count exceeds the number of CPU ids provided");
            }
            return cpu_ids;
        }

        auto found_cpus = platform::detect_cpu_ids();
        if (requested_thread_count > found_cpus.size()) {
            platform::throw_runtime_error(
                "Requested thread count exceeds the number of detected CPUs");
        }

        return found_cpus;
    }

    static std::uint32_t
    normalize_thread_count_(std::uint32_t requested_thread_count,
                            const std::vector<std::uint32_t>& cpu_ids) {
                            
        if (requested_thread_count > 0) {
            return requested_thread_count;
        }
        if (cpu_ids.size() > 0) {
            return cpu_ids.size();
        }
        return platform::detect_cpu_count();
    }
};

} // namespace sniffster
