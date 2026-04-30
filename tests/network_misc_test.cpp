#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <net/if.h>

#include <array>
#include <bit>
#include <cstdarg>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unistd.h>

#include <gtest/gtest.h>

import sniffster.network.nicq_detector;
import sniffster.network.nicq_ethtool;
import sniffster.network.nicq_fs;

namespace fs = std::filesystem;

namespace {

struct FakeSocketState {
    int socket_result = 9;
    int ioctl_result = 0;
    int close_result = 0;
    std::uint32_t combined_count = 0;
    std::uint32_t rx_count = 0;
    int socket_calls = 0;
    int ioctl_calls = 0;
    int close_calls = 0;
    int last_domain = 0;
    int last_type = 0;
    int last_protocol = 0;
    int last_fd = -1;
    unsigned long last_request = 0;
    std::string last_ifname;
    std::uint32_t last_cmd = 0;
};

FakeSocketState g_fake_socket;

extern "C" int socket(int domain, int type, int protocol) {
    ++g_fake_socket.socket_calls;
    g_fake_socket.last_domain = domain;
    g_fake_socket.last_type = type;
    g_fake_socket.last_protocol = protocol;
    return g_fake_socket.socket_result;
}

extern "C" int close(int fd) {
    ++g_fake_socket.close_calls;
    g_fake_socket.last_fd = fd;
    return g_fake_socket.close_result;
}

extern "C" int ioctl(int fd, unsigned long request, ...) {
    ++g_fake_socket.ioctl_calls;
    g_fake_socket.last_fd = fd;
    g_fake_socket.last_request = request;

    va_list args;
    va_start(args, request);
    auto* ifr = va_arg(args, struct ifreq*);
    va_end(args);

    if (ifr != nullptr) {
        g_fake_socket.last_ifname = ifr->ifr_name;
        auto* channels = reinterpret_cast<ethtool_channels*>(ifr->ifr_data);
        if (channels != nullptr) {
            g_fake_socket.last_cmd = channels->cmd;
            channels->combined_count = g_fake_socket.combined_count;
            channels->rx_count = g_fake_socket.rx_count;
        }
    }

    return g_fake_socket.ioctl_result;
}

class TempDir {
public:
    TempDir() {
        const auto unique = std::to_string(::getpid()) + "-" + std::to_string(counter_++);
        path_ = fs::temp_directory_path() / ("sniffster-network-tests-" + unique);
        fs::create_directories(path_);
    }

    ~TempDir() {
        std::error_code ec;
        fs::remove_all(path_, ec);
    }

    [[nodiscard]] const fs::path& path() const noexcept { return path_; }

private:
    inline static std::uint64_t counter_ = 0;
    fs::path path_;
};

using network_key_bytes = std::array<std::uint8_t, 24>;

network_key_bytes make_v4_network_key_bytes(
    std::array<std::uint8_t, 6> mac,
    std::array<std::uint8_t, 4> ipv4
) {
    network_key_bytes bytes{};
    std::copy(mac.begin(), mac.end(), bytes.begin());
    std::copy(ipv4.begin(), ipv4.end(), bytes.begin() + 6);
    return bytes;
}

network_key_bytes make_v6_network_key_bytes(
    std::array<std::uint8_t, 6> mac,
    std::array<std::uint8_t, 16> ipv6
) {
    network_key_bytes bytes{};
    std::copy(mac.begin(), mac.end(), bytes.begin());
    std::copy(ipv6.begin(), ipv6.end(), bytes.begin() + 6);
    return bytes;
}

class NetworkMiscTest : public ::testing::Test {
protected:
    void SetUp() override {
        g_fake_socket = {};
    }
};

// Obsolete after the hash/local_host refactor:
// - sniffer.hash no longer exports hash_network_key / IPVer.
// - local_host no longer exposes the old precomputed key path.

TEST_F(NetworkMiscTest, FsQueueDetectorReturnsMinusOneWhenQueueRootMissing) {
    TempDir temp;

    EXPECT_EQ(sniffster::fs_queue_detector::get_queue_count("eth0", temp.path() / "missing-root"),
              std::nullopt);
}

TEST_F(NetworkMiscTest, FsQueueDetectorCountsOnlyRxDirectories) {
    TempDir temp;
    fs::create_directories(temp.path() / "eth0" / "queues" / "rx-0");
    fs::create_directories(temp.path() / "eth0" / "queues" / "rx-1");
    fs::create_directories(temp.path() / "eth0" / "queues" / "tx-0");
    std::ofstream(temp.path() / "eth0" / "queues" / "rx-file").put('x');

    EXPECT_EQ(sniffster::fs_queue_detector::get_queue_count("eth0", temp.path()), 2u);
}

TEST_F(NetworkMiscTest, FsQueueDetectorReturnsMinusOneForExistingNonDirectoryQueuePath) {
    TempDir temp;
    fs::create_directories(temp.path() / "eth0");
    std::ofstream(temp.path() / "eth0" / "queues").put('x');

    EXPECT_EQ(sniffster::fs_queue_detector::get_queue_count("eth0", temp.path()), std::nullopt);
}

TEST_F(NetworkMiscTest, EthtoolQueueDetectorReturnsNulloptWhenSocketCreationFails) {
    g_fake_socket.socket_result = -1;

    EXPECT_EQ(sniffster::ethtool_queue_detector::get_queue_count("eth0"), std::nullopt);
    EXPECT_EQ(g_fake_socket.socket_calls, 1);
    EXPECT_EQ(g_fake_socket.ioctl_calls, 0);
    EXPECT_EQ(g_fake_socket.close_calls, 0);
}

TEST_F(NetworkMiscTest, EthtoolQueueDetectorReturnsNulloptOnIoctlFailureAndClosesSocket) {
    g_fake_socket.socket_result = 17;
    g_fake_socket.ioctl_result = -1;

    EXPECT_EQ(sniffster::ethtool_queue_detector::get_queue_count("eth0"), std::nullopt);
    EXPECT_EQ(g_fake_socket.ioctl_calls, 1);
    EXPECT_EQ(g_fake_socket.close_calls, 1);
    EXPECT_EQ(g_fake_socket.last_fd, 17);
    EXPECT_EQ(g_fake_socket.last_request, static_cast<unsigned long>(SIOCETHTOOL));
}

TEST_F(NetworkMiscTest, EthtoolQueueDetectorSumsCombinedAndRxQueues) {
    g_fake_socket.socket_result = 21;
    g_fake_socket.ioctl_result = 0;
    g_fake_socket.combined_count = 4;
    g_fake_socket.rx_count = 2;

    EXPECT_EQ(sniffster::ethtool_queue_detector::get_queue_count("enp0s31f6"), 6u);
    EXPECT_EQ(g_fake_socket.last_ifname, "enp0s31f6");
    EXPECT_EQ(g_fake_socket.last_cmd, static_cast<std::uint32_t>(ETHTOOL_GCHANNELS));
    EXPECT_EQ(g_fake_socket.close_calls, 1);
}

TEST_F(NetworkMiscTest, EthtoolQueueDetectorTruncatesInterfaceNameToIfreqLimit) {
    g_fake_socket.socket_result = 21;
    g_fake_socket.ioctl_result = 0;
    g_fake_socket.combined_count = 1;
    g_fake_socket.rx_count = 0;

    const std::string long_ifname = "very-long-interface-name";

    EXPECT_EQ(sniffster::ethtool_queue_detector::get_queue_count(long_ifname), 1u);
    EXPECT_EQ(g_fake_socket.last_ifname, long_ifname.substr(0, IFNAMSIZ - 1));
    EXPECT_EQ(g_fake_socket.last_ifname.size(), static_cast<std::size_t>(IFNAMSIZ - 1));
}

TEST_F(NetworkMiscTest, EthtoolQueueDetectorReturnsNulloptWhenDriverReportsZeroQueues) {
    g_fake_socket.socket_result = 21;
    g_fake_socket.ioctl_result = 0;
    g_fake_socket.combined_count = 0;
    g_fake_socket.rx_count = 0;

    EXPECT_EQ(sniffster::ethtool_queue_detector::get_queue_count("eth0"), std::nullopt);
}

TEST_F(NetworkMiscTest, NicQueueDetectorPrefersEthtoolWhenAvailable) {
    g_fake_socket.socket_result = 8;
    g_fake_socket.ioctl_result = 0;
    g_fake_socket.combined_count = 3;
    g_fake_socket.rx_count = 1;

    EXPECT_EQ(sniffster::nic_queue_detector{"eth0"}.detect_queues(), 4u);
}

TEST_F(NetworkMiscTest, FsQueueDetectorFindsQueuesWhenEthtoolStylePathIsPreparedInTempRoot) {
    TempDir temp;
    fs::create_directories(temp.path() / "eth0" / "queues" / "rx-0");
    fs::create_directories(temp.path() / "eth0" / "queues" / "rx-1");

    EXPECT_EQ(sniffster::fs_queue_detector::get_queue_count("eth0", temp.path()), 2u);
}

TEST_F(NetworkMiscTest, FsQueueDetectorReturnsNulloptWhenTempRootLacksQueues) {
    TempDir temp;

    EXPECT_EQ(sniffster::fs_queue_detector::get_queue_count("eth0", temp.path()), std::nullopt);
}

} // namespace
