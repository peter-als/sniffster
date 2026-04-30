module;

#include <cstddef>
#include <cstring>
#include <cstdint>
#include <type_traits>
#include <boost/log/trivial.hpp>
#include "network/packet_offsets.h"
#include "platform/arch_macros.h"

export module sniffster.logger_event;

import sniffster.platform;
import sniffster.packet_meta_event;

export namespace sniffster {

using boost::log::trivial::severity_level;
using boost::log::core;

struct alignas(16) logger_event {
    packet_identity_t packet_identity;  // 47 useful bytes, padded to 48 by alignment.
    std::uint32_t     severity;         // 4 bytes; sizeof(severity_level) is not guaranteed
                                        // 52 bytes before message

    static constexpr size_t max_text_len = 95;    // 95 payload chars + 1 NUL = 96 bytes

    char            message[max_text_len + 1];

    force_inline_
    void set_message(const std::string_view& msg) {
        size_t len = msg.size();
        if (len > logger_event::max_text_len) {
            memcpy_(message, msg.data(), logger_event::max_text_len);
            message[logger_event::max_text_len] = '\0';
            // Not logging here, as this might not be running in the logging thread.
            // => Messages might be truncated if they are too long.
        }
    }
};                                  // 148 bytes payload, padded to 160 by 16-byte alignment

static_assert(std::is_standard_layout_v<logger_event>);
static_assert(std::is_trivially_copyable_v<logger_event>);
static_assert(offsetof(logger_event, severity) == sizeof(packet_identity_t),
    "logger_event::severity must remain immediately after packet_identity_t");
static_assert(offsetof(logger_event, message) == 52,
    "logger_event::message offset changed; verify logger event ABI");
static_assert(sizeof(logger_event::message) == 96,
    "logger_event::message buffer size changed; verify truncation assumptions");
static_assert(sizeof(logger_event) == 160,
    "logger_event size changed; verify logger event layout and tail padding");


} // namespace sniffster
