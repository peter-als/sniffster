#include <barrier>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <thread>
#include <vector>
#include <cstdlib>
#include <unistd.h>

#include <gtest/gtest.h>

#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/utility/setup/file.hpp>

import sniffster.logger_processor;
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

std::vector<std::string> read_lines(const fs::path& path) {
    std::ifstream in(path);
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(in, line)) {
        lines.push_back(line);
    }
    return lines;
}

class LoggerProcessorTest : public ::testing::Test {
protected:
    void TearDown() override {
        logging::core::get()->remove_all_sinks();
    }
};

TEST_F(LoggerProcessorTest, LogMessageFormatsDirectMessages) {
    TempFile log_file{"sniffster-logger-processor"};
    reset_logging_to_file(log_file.path());

    sniffster::logger_t boost_logger{boost::log::trivial::debug};
    sniffster::logger_processor logger{boost_logger};

    logger.log_message("cpu {} handled {}", 3, "packet");

    const auto lines = read_lines(log_file.path());
    ASSERT_EQ(lines.size(), 1u);
    EXPECT_EQ(lines.front(), "cpu 3 handled packet");
}

TEST_F(LoggerProcessorTest, RunDrainsQueuedLoggerEvents) {
    TempFile log_file{"sniffster-logger-processor"};
    reset_logging_to_file(log_file.path());

    sniffster::logger_t boost_logger{boost::log::trivial::debug};
    sniffster::logger_processor logger{boost_logger};
    sniffster::logger_processor::queue_t queue{16};
    logger.register_producer(queue);

    sniffster::runtime_control runtime_ctrl(2);

    std::thread worker([&logger, &runtime_ctrl] {
        logger.run(runtime_ctrl);
    });

    runtime_ctrl.arrive_and_wait();

    sniffster::logger_event first{};
    std::snprintf(first.message, sizeof(first.message), "queued message one");
    sniffster::logger_event second{};
    std::snprintf(second.message, sizeof(second.message), "queued message two");

    ASSERT_TRUE(queue.push(first));
    ASSERT_TRUE(queue.push(second));
    logger.about_new_events_available();

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
    while (std::chrono::steady_clock::now() < deadline) {
        const auto lines = read_lines(log_file.path());
        if (lines.size() >= 2) {
            ASSERT_EQ(std::raise(SIGINT), 0);
            logger.we_are_done();
            runtime_ctrl.arrive_and_wait();
            worker.join();

            EXPECT_EQ(lines[0], "queued message one");
            EXPECT_EQ(lines[1], "queued message two");
            return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    ASSERT_EQ(std::raise(SIGINT), 0);
    logger.we_are_done();
    runtime_ctrl.arrive_and_wait();
    worker.join();
    FAIL() << "logger_processor did not drain queued log events";
}

} // namespace
