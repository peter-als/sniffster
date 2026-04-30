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

#include <bpf/libbpf.h>
#include <gtest/gtest.h>
#include <linux/if_ether.h>
#include <linux/perf_event.h>
#include <netinet/in.h>

#include <boost/log/trivial.hpp>

#include "network/packet_offsets.h"

import sniffster.bpf_handler.xdp_copy_handler;
import sniffster.logger_processor;
import sniffster.packet_handler;
import sniffster.packet_processor;
import sniffster.runtime_control;

struct perf_buffer {
    int tag = 0;
};

namespace fs = std::filesystem;

namespace {

struct FakePerfBufferState {
    bool new_raw_returns_null = false;
    int new_raw_calls = 0;
    int poll_calls = 0;
    int free_calls = 0;
    int last_map_fd = -1;
    size_t last_page_count = 0;
    int last_timeout_ms = 0;
    int last_cpu_count = 0;
    int last_cpu_key = -1;
    int last_map_key = -1;
    std::uint32_t attr_type = 0;
    std::uint64_t attr_config = 0;
    std::uint64_t attr_sample_type = 0;
    std::uint64_t attr_sample_period = 0;
    std::uint32_t attr_wakeup_events = 0;
    int poll_return = 0;
    perf_buffer_event_fn event_cb = nullptr;
    void* event_ctx = nullptr;
    perf_buffer instance{};
};

FakePerfBufferState g_perf_buffer;

extern "C" struct perf_buffer* perf_buffer__new_raw(
    int map_fd,
    size_t page_cnt,
    struct perf_event_attr* attr,
    perf_buffer_event_fn event_cb,
    void* ctx,
    const struct perf_buffer_raw_opts* opts
) {
    ++g_perf_buffer.new_raw_calls;
    g_perf_buffer.last_map_fd = map_fd;
    g_perf_buffer.last_page_count = page_cnt;
    g_perf_buffer.event_cb = event_cb;
    g_perf_buffer.event_ctx = ctx;

    if (attr != nullptr) {
        g_perf_buffer.attr_type = attr->type;
        g_perf_buffer.attr_config = attr->config;
        g_perf_buffer.attr_sample_type = attr->sample_type;
        g_perf_buffer.attr_sample_period = attr->sample_period;
        g_perf_buffer.attr_wakeup_events = attr->wakeup_events;
    }

    if (opts != nullptr) {
        g_perf_buffer.last_cpu_count = opts->cpu_cnt;
        g_perf_buffer.last_cpu_key = (opts->cpus != nullptr) ? opts->cpus[0] : -1;
        g_perf_buffer.last_map_key = (opts->map_keys != nullptr) ? opts->map_keys[0] : -1;
    }

    if (g_perf_buffer.new_raw_returns_null) {
        return nullptr;
    }

    return &g_perf_buffer.instance;
}

extern "C" void perf_buffer__free(struct perf_buffer* pb) {
    if (pb != nullptr) {
        ++g_perf_buffer.free_calls;
    }
}

extern "C" int perf_buffer__poll(struct perf_buffer* pb, int timeout_ms) {
    ++g_perf_buffer.poll_calls;
    g_perf_buffer.last_timeout_ms = timeout_ms;

    if (pb == nullptr) {
        return -1;
    }

    return g_perf_buffer.poll_return;
}

class TempFile {
public:
    TempFile() {
        auto template_path = (fs::temp_directory_path() /
                              "sniffster-sniffer-runtime-XXXXXX.jsonl").string();
        const int fd = mkstemps(template_path.data(), 6);
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

std::vector<std::uint8_t> make_perf_sample_event(const std::vector<std::uint8_t>& sample_bytes) {
    std::vector<std::uint8_t> bytes(
        sizeof(perf_event_header) + sizeof(std::uint32_t) + sample_bytes.size()
    );

    auto* header = reinterpret_cast<perf_event_header*>(bytes.data());
    header->type = PERF_RECORD_SAMPLE;
    header->misc = 0;
    header->size = static_cast<std::uint16_t>(bytes.size());

    const std::uint32_t raw_size = static_cast<std::uint32_t>(sample_bytes.size());
    std::memcpy(bytes.data() + sizeof(perf_event_header), &raw_size, sizeof(raw_size));
    std::memcpy(bytes.data() + sizeof(perf_event_header) + sizeof(raw_size),
                sample_bytes.data(),
                sample_bytes.size());

    return bytes;
}

std::vector<std::uint8_t> make_ipv4_sample(
    std::uint32_t rx_queue,
    std::uint8_t src_host_octet,
    std::uint8_t dst_host_octet
) {
    const std::array<std::uint8_t, ETH_HEADER_BYTES + IPV4_MIN_HEADER_BYTES> packet{
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x08, 0x00,
        0x45, 0x00, 0x00, 0x14,
        0x12, 0x34, 0x00, 0x00,
        0x40, 0x06, 0x00, 0x00,
        192, 168, 1, src_host_octet,
        10, 0, 0, dst_host_octet,
    };

    std::vector<std::uint8_t> bytes(RX_QUEUE_BYTES + packet.size());
    std::memcpy(bytes.data(), &rx_queue, RX_QUEUE_BYTES);
    std::memcpy(bytes.data() + RX_QUEUE_BYTES, packet.data(), packet.size());
    return bytes;
}

void dispatch_sample(const std::vector<std::uint8_t>& sample_bytes, int cpu) {
    const auto event_bytes = make_perf_sample_event(sample_bytes);
    const auto result = g_perf_buffer.event_cb(
        g_perf_buffer.event_ctx,
        cpu,
        reinterpret_cast<perf_event_header*>(const_cast<std::uint8_t*>(event_bytes.data()))
    );
    EXPECT_EQ(result, LIBBPF_PERF_EVENT_CONT);
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

class SnifferRuntimeTest : public ::testing::Test {
protected:
    void SetUp() override {
        g_perf_buffer = {};
    }
};

TEST_F(SnifferRuntimeTest, ConstructorConfiguresPerfBufferAndDestructorFreesIt) {
    TempFile report_file;
    sniffster::logger_t boost_logger{boost::log::trivial::debug};
    sniffster::logger_processor logger{boost_logger};
    sniffster::packet_processor processor{logger, report_file.path().c_str()};

    {
        sniffster::packet_handler packet_handler{processor, logger};
        sniffster::xdp_copy_handler handler(42, {7}, packet_handler);

        EXPECT_EQ(g_perf_buffer.new_raw_calls, 1);
        EXPECT_EQ(g_perf_buffer.last_map_fd, 42);
        EXPECT_EQ(g_perf_buffer.last_page_count, 64u);
        EXPECT_EQ(g_perf_buffer.last_cpu_count, 1);
        EXPECT_EQ(g_perf_buffer.last_cpu_key, 7);
        EXPECT_EQ(g_perf_buffer.last_map_key, 7);
        EXPECT_EQ(g_perf_buffer.attr_type, PERF_TYPE_SOFTWARE);
        EXPECT_EQ(g_perf_buffer.attr_config, PERF_COUNT_SW_BPF_OUTPUT);
        EXPECT_EQ(g_perf_buffer.attr_sample_type, PERF_SAMPLE_RAW);
        EXPECT_EQ(g_perf_buffer.attr_sample_period, 1u);
        EXPECT_EQ(g_perf_buffer.attr_wakeup_events, 1u);
        ASSERT_NE(g_perf_buffer.event_cb, nullptr);
        ASSERT_NE(g_perf_buffer.event_ctx, nullptr);
    }

    EXPECT_EQ(g_perf_buffer.free_calls, 1);
}

TEST_F(SnifferRuntimeTest, RunThrowsOnNegativePollResult) {
    TempFile report_file;
    sniffster::logger_t boost_logger{boost::log::trivial::debug};
    sniffster::logger_processor logger{boost_logger};
    sniffster::packet_processor processor{logger, report_file.path().c_str()};
    sniffster::packet_handler packet_handler{processor, logger};
    sniffster::xdp_copy_handler handler(5, {1}, packet_handler);

    g_perf_buffer.poll_return = -7;
    sniffster::runtime_control runtime_ctrl(1);

    EXPECT_THROW(handler.run(runtime_ctrl), std::runtime_error);
    EXPECT_EQ(g_perf_buffer.poll_calls, 1);
    EXPECT_EQ(g_perf_buffer.last_timeout_ms, 100);
}

TEST_F(SnifferRuntimeTest, SampleCallbackWritesJsonlThroughProcessorPipeline) {
    TempFile report_file;
    {
        sniffster::logger_t boost_logger{boost::log::trivial::debug};
        sniffster::logger_processor logger{boost_logger};
        sniffster::packet_processor processor{logger, report_file.path().c_str()};
        sniffster::packet_handler packet_handler{processor, logger};
        sniffster::xdp_copy_handler handler(17, {4}, packet_handler);

        sniffster::runtime_control runtime_ctrl(2);

        std::thread processor_thread([&processor, &runtime_ctrl] {
            processor.run(runtime_ctrl);
        });

        runtime_ctrl.arrive_and_wait();

        for (std::uint8_t i = 1; i <= 19; ++i) {
            dispatch_sample(make_ipv4_sample(7, i, static_cast<std::uint8_t>(100 + i)), 3);
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
    }

    const auto lines = read_lines(report_file.path());
    ASSERT_EQ(lines.size(), 10u);
    EXPECT_NE(lines.front().find("\"cpu\": 3"), std::string::npos);
    EXPECT_NE(lines.front().find("\"q\": 7"), std::string::npos);
    EXPECT_NE(lines.front().find("\"l2_name\": \"IPv4\""), std::string::npos);
    EXPECT_NE(lines.front().find("\"ip_src\": \"192.168.1.1\""), std::string::npos);
    EXPECT_NE(lines.front().find("\"ip_dst\": \"10.0.0.101\""), std::string::npos);
    EXPECT_NE(lines.front().find("\"l4_name\": \"TCP\""), std::string::npos);
    EXPECT_NE(lines.front().find("\"coalesced\": 1"), std::string::npos);
}

} // namespace
