#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>

#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <linux/if_ether.h>
#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <cstdlib>
#include <unistd.h>

import sniffster.packet_processor;
import sniffster.logger_processor;

namespace fs = std::filesystem;

namespace {

class TempFile {
public:
    explicit TempFile(std::string stem) {
        auto template_path = (fs::temp_directory_path() /
                              (std::move(stem) + "-XXXXXX.log")).string();
        const int fd = mkstemps(template_path.data(), 4);
        if (fd == -1) {
            throw std::system_error(errno, std::generic_category(), "mkstemps failed");
        }
        close(fd);
        path_ = template_path;
    }

    ~TempFile() {
        std::error_code ec;
        fs::remove(path_, ec);
    }

    [[nodiscard]] const fs::path& path() const noexcept { return path_; }

private:
    fs::path path_;
};

sniffster::packet_meta_event make_event(std::uint8_t octet) {
    sniffster::packet_meta_event event{};
    event.cpu_id = 3;
    event.rx_queue = 7;
    event.packet_size = 128;
    event.coalesced_count = 1;
    event.first_timestamp = std::chrono::system_clock::time_point{std::chrono::seconds{100 + octet}};
    event.latest_timestamp = std::chrono::system_clock::time_point{std::chrono::seconds{200 + octet}};
    event.packet_identity.eth_proto_net = htons(ETH_P_IP);
    event.packet_identity.transport_proto = IPPROTO_TCP;

    const std::array<std::uint8_t, ETH_ALEN> src_mac{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, octet};
    const std::array<std::uint8_t, ETH_ALEN> dst_mac{0x00, 0x11, 0x22, 0x33, 0x44, octet};
    std::copy(src_mac.begin(), src_mac.end(), event.packet_identity.src_mac);
    std::copy(dst_mac.begin(), dst_mac.end(), event.packet_identity.dst_mac);

    const std::array<std::uint8_t, 4> src_ip{192, 168, 1, octet};
    const std::array<std::uint8_t, 4> dst_ip{10, 0, 0, octet};
    std::copy(src_ip.begin(), src_ip.end(), event.packet_identity.src_ip.data());
    std::copy(dst_ip.begin(), dst_ip.end(), event.packet_identity.dst_ip.data());
    return event;
}

std::vector<std::string> read_lines(const fs::path& path) {
    std::ifstream in(path);
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(in, line)) {
        lines.push_back(line);
    }
    return lines;
}

TEST(PacketProcessorTest, FlushesOnlyAfterBatchThreshold) {
    TempFile report_file{"sniffster-packet-processor-report"};
    sniffster::logger_t boost_logger{boost::log::trivial::debug};
    sniffster::logger_processor logger{boost_logger};
    sniffster::packet_processor processor{logger, report_file.path().c_str()};

    for (std::uint8_t i = 1; i <= 9; ++i) {
        processor.handle(make_event(i));
    }

    EXPECT_TRUE(read_lines(report_file.path()).empty());

    processor.handle(make_event(10));

    const auto lines = read_lines(report_file.path());
    ASSERT_EQ(lines.size(), 10u);
    EXPECT_NE(lines.front().find("\"ip_src\": \"192.168.1.1\""), std::string::npos);
    EXPECT_NE(lines.back().find("\"ip_src\": \"192.168.1.10\""), std::string::npos);
}

TEST(PacketProcessorTest, DestructorFlushesPendingPartialBatch) {
    TempFile report_file{"sniffster-packet-processor-report"};
    sniffster::logger_t boost_logger{boost::log::trivial::debug};
    sniffster::logger_processor logger{boost_logger};

    {
        sniffster::packet_processor processor{logger, report_file.path().c_str()};
        processor.handle(make_event(42));
        EXPECT_TRUE(read_lines(report_file.path()).empty());
    }

    const auto lines = read_lines(report_file.path());
    ASSERT_EQ(lines.size(), 1u);
    EXPECT_NE(lines.front().find("\"ip_src\": \"192.168.1.42\""), std::string::npos);
}

} // namespace
