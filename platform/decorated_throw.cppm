module;

#include <format>
#include <source_location>
#include <stdexcept>
#include <string>
#include <string_view>

export module sniffster.platform.decorated_throw;

namespace platform_detail {

[[nodiscard]] constexpr
std::string_view basename(std::string_view path) noexcept {
    const std::size_t pos = path.find_last_of("/\\");
    return pos == std::string_view::npos ? path : path.substr(pos + 1);
}

[[nodiscard]] inline
std::string decorate_error_msg(
    std::string_view message,
    const std::source_location& where) {

    return std::format("{} ({}:{} in {})",
                       message,
                       basename(where.file_name()),
                       where.line(),
                       where.function_name());
}

} // namespace platform_detail

export namespace platform {

struct throw_context {
    std::source_location where = std::source_location::current();
};

[[nodiscard]] inline std::string
runtime_error_msg(std::string_view message, throw_context ctx = {}) {
    return platform_detail::decorate_error_msg(message, ctx.where);
}

[[noreturn]] inline
void throw_runtime_error(std::string_view message,
                         throw_context ctx = {}) {
    throw std::runtime_error(runtime_error_msg(message, ctx));
}

} // namespace platform
