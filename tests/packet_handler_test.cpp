#include <array>
#include <barrier>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <thread>
#include <vector>
#include <cstdlib>
#include <unistd.h>

#include <gtest/gtest.h>
#include <linux/if_ether.h>

#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/utility/setup/file.hpp>

#include "network/packet_offsets.h"

import sniffster.logger_processor;
import sniffster.packet_handler;
import sniffster.packet_processor;
import sniffster.runtime_control;

namespace fs = std::filesystem;
namespace logging = boost::log;
namespace keywords = boost::log::keywords;

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

void reset_logging_to_file(const fs::path& path) {
    logging::core::get()->remove_all_sinks();
    logging::add_file_log(
        keywords::file_name = path.string(),
        keywords::auto_flush = true,
        keywords::format = "%Message%"
    );
    logging::add_common_attributes();
}

std::vector<std::uint8_t> make_ipv4_sample(
    std::uint32_t rx_queue,
    std::uint8_t src_hi,
    std::uint8_t src_lo,
    std::uint8_t dst_hi,
    std::uint8_t dst_lo
) {
    const std::array<std::uint8_t, ETH_HEADER_BYTES + IPV4_MIN_HEADER_BYTES> packet{
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x08, 0x00,
        0x45, 0x00, 0x00, 0x14,
        0x12, 0x34, 0x00, 0x00,
        0x40, 0x06, 0x00, 0x00,
        192, 168, src_hi, src_lo,
        10, 0, dst_hi, dst_lo,
    };

    std::vector<std::uint8_t> bytes(RX_QUEUE_BYTES + packet.size());
    std::memcpy(bytes.data(), &rx_queue, RX_QUEUE_BYTES);
    std::memcpy(bytes.data() + RX_QUEUE_BYTES, packet.data(), packet.size());
    return bytes;
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

class PacketHandlerTest : public ::testing::Test {
protected:
    void TearDown() override {
        logging::core::get()->remove_all_sinks();
    }
};

TEST_F(PacketHandlerTest, LogsMalformedPacketsToLoggerPath) {
    TempFile report_file{"sniffster-packet-handler-report"};
    TempFile log_file{"sniffster-packet-handler-log"};
    reset_logging_to_file(log_file.path());

    sniffster::logger_t boost_logger{boost::log::trivial::debug};
    sniffster::logger_processor logger{boost_logger};
    sniffster::packet_processor processor{logger, report_file.path().c_str()};
    sniffster::packet_handler handler{processor, logger};

    sniffster::runtime_control runtime_ctrl(2);

    std::thread logger_thread([&logger, &runtime_ctrl] {
        logger.run(runtime_ctrl);
    });

    runtime_ctrl.arrive_and_wait();

    const std::vector<std::uint8_t> malformed(RX_QUEUE_BYTES + ETH_HEADER_BYTES + IPV4_MIN_HEADER_BYTES - 1, 0xAB);
    handler.process_sample(2, malformed.data(), malformed.size());

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
    while (std::chrono::steady_clock::now() < deadline) {
        const auto lines = read_lines(log_file.path());
        if (!lines.empty()) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    ASSERT_EQ(std::raise(SIGINT), 0);
    logger.we_are_done();
    runtime_ctrl.arrive_and_wait();
    logger_thread.join();

    const auto lines = read_lines(log_file.path());
    ASSERT_FALSE(lines.empty());
    EXPECT_NE(lines.back().find("packet too short or malformed -- skipping"), std::string::npos);
}

TEST_F(PacketHandlerTest, CoalescesRepeatedPacketsBeforeTheyReachProcessorOutput) {
    TempFile report_file{"sniffster-packet-handler-report"};
    TempFile log_file{"sniffster-packet-handler-log"};
    reset_logging_to_file(log_file.path());

    sniffster::logger_t boost_logger{boost::log::trivial::debug};
    sniffster::logger_processor logger{boost_logger};
    sniffster::packet_processor processor{logger, report_file.path().c_str()};
    sniffster::packet_handler handler{processor, logger};

    sniffster::runtime_control runtime_ctrl(2);

    std::thread processor_thread([&processor, &runtime_ctrl] {
        processor.run(runtime_ctrl);
    });

    runtime_ctrl.arrive_and_wait();

    handler.process_sample(3, make_ipv4_sample(7, 1, 1, 1, 101).data(), RX_QUEUE_BYTES + ETH_HEADER_BYTES + IPV4_MIN_HEADER_BYTES);
    handler.process_sample(3, make_ipv4_sample(7, 1, 1, 1, 101).data(), RX_QUEUE_BYTES + ETH_HEADER_BYTES + IPV4_MIN_HEADER_BYTES);

    for (std::uint16_t i = 2; i <= 19; ++i) {
        const auto sample = make_ipv4_sample(
            7,
            static_cast<std::uint8_t>(i / 256),
            static_cast<std::uint8_t>(i % 256),
            static_cast<std::uint8_t>((100 + i) / 256),
            static_cast<std::uint8_t>((100 + i) % 256));
        handler.process_sample(3, sample.data(), sample.size());
    }

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
    while (std::chrono::steady_clock::now() < deadline) {
        const auto lines = read_lines(report_file.path());
        if (lines.size() >= 10) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    ASSERT_EQ(std::raise(SIGINT), 0);
    processor.we_are_done();
    runtime_ctrl.arrive_and_wait();
    processor_thread.join();

    const auto lines = read_lines(report_file.path());
    ASSERT_EQ(lines.size(), 10u);
    EXPECT_NE(lines.front().find("\"coalesced\": 2"), std::string::npos);
    EXPECT_NE(lines.front().find("\"ip_src\": \"192.168.1.1\""), std::string::npos);
    EXPECT_NE(lines.front().find("\"ip_dst\": \"10.0.1.101\""), std::string::npos);
}

TEST_F(PacketHandlerTest, ReportsDroppedOutboundEventsWhenProcessorQueueOverflows) {
    TempFile report_file{"sniffster-packet-handler-report"};
    TempFile log_file{"sniffster-packet-handler-log"};
    reset_logging_to_file(log_file.path());

    sniffster::logger_t boost_logger{boost::log::trivial::debug};
    sniffster::logger_processor logger{boost_logger};
    sniffster::packet_processor processor{logger, report_file.path().c_str()};
    sniffster::packet_handler handler{processor, logger};

    sniffster::runtime_control runtime_ctrl(2);

    std::thread logger_thread([&logger, &runtime_ctrl] {
        logger.run(runtime_ctrl);
    });

    runtime_ctrl.arrive_and_wait();

    for (std::uint16_t i = 0; i < 1020; ++i) {
        const auto sample = make_ipv4_sample(
            7,
            static_cast<std::uint8_t>(i / 256),
            static_cast<std::uint8_t>(i % 256),
            static_cast<std::uint8_t>((200 + i) / 256),
            static_cast<std::uint8_t>((200 + i) % 256));
        handler.process_sample(3, sample.data(), sample.size());
    }

    handler.finish_loop();

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
    while (std::chrono::steady_clock::now() < deadline) {
        const auto lines = read_lines(log_file.path());
        for (const auto& line : lines) {
            if (line.find("Packet handler dropped events:") != std::string::npos) {
                ASSERT_EQ(std::raise(SIGINT), 0);
                logger.we_are_done();
                runtime_ctrl.arrive_and_wait();
                logger_thread.join();
                EXPECT_NE(line.find("Packet handler dropped events: "), std::string::npos);
                return;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    ASSERT_EQ(std::raise(SIGINT), 0);
    logger.we_are_done();
    runtime_ctrl.arrive_and_wait();
    logger_thread.join();
    FAIL() << "Expected dropped-event log entry was not written";
}

} // namespace
