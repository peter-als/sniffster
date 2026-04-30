module;

#include <fstream>
#include <sstream>
#include <string>
#include <filesystem>
#include <chrono>
#include <iostream>
#include <print>
#include <thread>
#include <format>
#include <stop_token>
#include <boost/log/sources/severity_logger.hpp>
#include <boost/log/sources/record_ostream.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/utility/setup/console.hpp>
#include <boost/log/utility/setup/file.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include "platform/arch_macros.h"

export module sniffster.logger_processor;

import sniffster.queue_processor;
export import sniffster.logger_event;

export namespace sniffster {

using severity_level = boost::log::trivial::severity_level;
using logger_t = boost::log::sources::severity_logger_mt<severity_level>;
namespace logging = boost::log;
namespace keywords = boost::log::keywords;

class logger_processor : public queue_processor<logger_processor, logger_event> {
public:
    using event_type = logger_event;

    explicit
    logger_processor(logger_t& logger) :
        queue_processor<logger_processor, logger_event>::queue_processor(),
        logger_(logger) {}

    template<typename... Args>
    void log_message(const char* fmt, Args&&... args) {
        log_impl_(boost::log::trivial::debug, fmt, std::forward<Args>(args)...);
    }

    void log_message(std::string_view msg) {
        log_impl_(boost::log::trivial::debug, "{}", msg);
    }

    void handle(const event_type& value) {
        log_message(value.message);
    }

protected:
    template<typename... Args>
    force_inline_ 
    void log_impl_(severity_level level, const char* fmt, Args&&... args) {
        // TBD: check that the thread is the same where the run() method was called.
        BOOST_LOG_SEV(logger_, level) << std::vformat(fmt, std::make_format_args(args...));
    }

private:
    char msg_[logger_event::max_text_len + 1];
    logger_t& logger_;
};

} // namespace sniffster
