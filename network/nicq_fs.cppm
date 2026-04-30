module;

#include <cstdlib>
#include <filesystem>
#include <optional>
#include <string>

namespace fs = std::filesystem;

const fs::path queue_root_path_on_linux = fs::path{"/sys/class/net"};

export module sniffster.network.nicq_fs;

export namespace sniffster {
class fs_queue_detector {
public:
    static std::optional<std::uint32_t> get_queue_count(
        const std::string& ifname,
        const fs::path& root_path = queue_root_path_on_linux
    ) {

        const fs::path path = root_path / ifname / "queues";
        if (!fs::exists(path) || !fs::is_directory(path)) return std::nullopt;

        std::uint32_t count = 0;
        for (const auto& entry : fs::directory_iterator(path)) {
            if (entry.is_directory() &&
                entry.path().filename().string().compare(0, 3, "rx-") == 0) {
                count++;
            }
        }

        return (count > 0) ? std::optional<std::uint32_t>{count}
                           : std::nullopt;
    }
}; // class fs_queue_detector
} // namespace sniff
