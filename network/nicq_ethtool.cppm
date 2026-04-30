module;

#include <optional>
#include <string>
#include <cstring>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <unistd.h>

export module sniffster.network.nicq_ethtool;

export namespace sniffster {
class ethtool_queue_detector {
public:
    static std::optional<std::uint32_t> get_queue_count(const std::string& ifname) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) return std::nullopt;

        struct ethtool_channels channels = {};
        channels.cmd = ETHTOOL_GCHANNELS;

        struct ifreq ifr = {};
        std::strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ - 1);
        ifr.ifr_data = reinterpret_cast<char*>(&channels);

        int ret = ioctl(sock, SIOCETHTOOL, &ifr);
        close(sock);

        if (ret < 0) return std::nullopt;

        // On many NICs, channels are 'combined'. On others, they are separate.
        // We sum them to get the total number of paths available for RX.
        const std::uint32_t total_rx = channels.combined_count + channels.rx_count;
        return (total_rx > 0) ? std::optional<std::uint32_t>{total_rx}
                              : std::nullopt;
    }
}; // class ethtool_queue_detector
} // namespace sniff
