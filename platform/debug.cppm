module;

#include <string_view>

#include <cxxabi.h>
#include <cstdlib>
#include <memory>
#include <string>
#include <typeinfo>

#include <boost/type_index.hpp>
#include <boost/core/demangle.hpp>


export module sniffster.debug;

import sniffster.platform;

export template<class T>
std::string type_name() {
    if constexpr (platform::toolchain == "clang" || platform::toolchain == "gnu") {
        auto demangled = boost::core::demangle(typeid(T).name());
        auto pos = demangled.find('@');

        std::string type_name;
        type_name = (pos == std::string::npos)? demangled : demangled.substr(0, pos);
        return type_name;
    }
    else {
        return boost::typeindex::type_id_with_cvr<T>().pretty_name();
    }
}
