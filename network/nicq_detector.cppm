module;

#include <cstdint>
#include <optional>
#include <string>

export module sniffster.network.nicq_detector;

import sniffster.network.nicq_ethtool;
import sniffster.network.nicq_fs;

export namespace sniffster {
class nic_queue_detector {
public:
    explicit nic_queue_detector(std::string ifname) : interface_name_(std::move(ifname)) {}

    std::optional<std::uint32_t> detect_queues() const {
        // 1. Try Ethtool first (The source of truth for high-end NICs)
        if (const auto count = ethtool_queue_detector::get_queue_count(interface_name_)) {
            return count;
        }

        // 2. Try Filesystem (The reliable fallback for consumer/virtual drivers)
        if (const auto count = fs_queue_detector::get_queue_count(interface_name_)) {
            return count;
        }

        return std::nullopt;
    }

private:
    std::string interface_name_;
}; // class nic_queue_detector
} // namespace sniff
