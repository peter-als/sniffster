#include <cstdint>
#include <format>
#include <print>
#include <source_location>
#include <string_view>

import sniffster.platform.decorated_throw;

namespace {

[[noreturn]] void throw_plain_demo() {
    platform::throw_runtime_error("plain decorated error");
}

[[noreturn]] void throw_formatted_demo(int value) {
    platform::throw_runtime_error(std::format("formatted decorated error {}", value));
}

[[nodiscard]] std::string_view current_function_name(
    std::source_location where = std::source_location::current()) {
    return where.function_name();
}

[[noreturn]] void throw_with_explicit_context() {
    platform::throw_runtime_error(
        "explicit context decorated error",
        platform::throw_context{.where = std::source_location::current()});
}

template<typename Fn>
void print_demo(std::string_view label, Fn&& fn) {
    std::println("== {} ==", label);
    try {
        fn();
    } catch (const std::exception& err) {
        std::println("{}", err.what());
    }
    std::println("");
}

} // namespace

int main() {
    std::println("decorated throw demo");
    std::println("caller function marker: {}", current_function_name());
    std::println("");

    print_demo("plain", [] {
        throw_plain_demo();
    });

    print_demo("formatted", [] {
        throw_formatted_demo(42);
    });

    print_demo("explicit context", [] {
        throw_with_explicit_context();
    });

    return 0;
}
