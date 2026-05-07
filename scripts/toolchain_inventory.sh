#!/usr/bin/env bash

set -u

SCRIPT_NAME="$(basename "$0")"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

readonly TRIVIAL_CPP="$TMP_DIR/trivial.cpp"
readonly PRINT_CPP="$TMP_DIR/print.cpp"

cat >"$TRIVIAL_CPP" <<'EOF'
int main() { return 0; }
EOF

cat >"$PRINT_CPP" <<'EOF'
#include <print>
int main() {
    std::println("sniffster");
    return 0;
}
EOF

PATH_DIRS=()
BINARY_DIRS=()
LIB_DIRS=()
INCLUDE_DIRS=()
GCC_INSTALL_DIRS=()

COMPILER_PATHS=()
CLANG_TIDY_PATHS=()
CLANG_FORMAT_PATHS=()
CLANG_SCAN_DEPS_PATHS=()
CMAKE_PATHS=()
CMAKE_FORMAT_PATHS=()

LIBCXX_HEADER_DIRS=()
LIBSTDCXX_HEADER_DIRS=()
LIBCXX_LIBS=()
LIBCXXABI_LIBS=()
LIBSTDCXX_LIBS=()
BOOST_VERSION_HEADERS=()
BOOST_CONFIGS=()
BOOST_LIBS=()

add_unique() {
    local -n target_ref="$1"
    local candidate="$2"
    local existing

    [[ -n "$candidate" ]] || return 0

    for existing in "${target_ref[@]:-}"; do
        [[ "$existing" == "$candidate" ]] && return 0
    done

    target_ref+=("$candidate")
}

append_existing_dirs() {
    local array_name="$1"
    local -n target_ref="$array_name"
    shift

    local pattern resolved
    local expanded=()

    shopt -s nullglob
    for pattern in "$@"; do
        expanded=($pattern)
        if ((${#expanded[@]} == 0)); then
            continue
        fi

        for resolved in "${expanded[@]}"; do
            [[ -d "$resolved" ]] || continue
            resolved="$(readlink -f "$resolved" 2>/dev/null || printf '%s' "$resolved")"
            add_unique "$array_name" "$resolved"
        done
    done
    shopt -u nullglob
}

append_matching_files() {
    local array_name="$1"
    local -n target_ref="$array_name"
    shift

    local dir pattern candidate resolved

    shopt -s nullglob
    for dir in "$@"; do
        [[ -d "$dir" ]] || continue
        for pattern in "${MATCH_PATTERNS[@]}"; do
            for candidate in "$dir"/$pattern; do
                [[ -e "$candidate" ]] || continue
                [[ -x "$candidate" || -f "$candidate" ]] || continue
                add_unique "$array_name" "$candidate"
            done
        done
    done
    shopt -u nullglob
}

collect_path_dirs() {
    local dir
    local raw_path_dirs=()

    IFS=: read -r -a raw_path_dirs <<<"${PATH:-}"
    PATH_DIRS=()
    for dir in "${raw_path_dirs[@]}"; do
        [[ -d "$dir" ]] || continue
        dir="$(readlink -f "$dir" 2>/dev/null || printf '%s' "$dir")"
        add_unique PATH_DIRS "$dir"
    done
}

collect_search_dirs() {
    collect_path_dirs

    append_existing_dirs BINARY_DIRS \
        "${PATH_DIRS[@]}" \
        /usr/bin \
        /usr/local/bin \
        /bin \
        /sbin \
        /usr/sbin \
        /snap/bin \
        /opt/bin \
        /opt/*/bin \
        /usr/lib/llvm-*/bin \
        /usr/local/llvm*/bin \
        "$HOME/.local/bin" \
        "$HOME/local/bin" \
        "$HOME/opt/bin"

    append_existing_dirs LIB_DIRS \
        /usr/lib \
        /usr/local/lib \
        /usr/lib64 \
        /usr/local/lib64 \
        /lib \
        /lib64 \
        /usr/lib/x86_64-linux-gnu \
        /lib/x86_64-linux-gnu \
        /opt/lib \
        /opt/lib64 \
        /opt/*/lib \
        /opt/*/lib64 \
        "$HOME/local/lib" \
        "$HOME/local/lib64" \
        "$HOME/opt/lib" \
        "$HOME/opt/lib64"

    append_existing_dirs GCC_INSTALL_DIRS \
        /usr/lib/gcc/*/* \
        /usr/local/lib/gcc/*/* \
        /opt/*/lib/gcc/*/* \
        "$HOME/local/lib/gcc/"*/* \
        "$HOME/opt/lib/gcc/"*/*

    append_existing_dirs LIB_DIRS \
        "${GCC_INSTALL_DIRS[@]}"

    append_existing_dirs INCLUDE_DIRS \
        /usr/include \
        /usr/local/include \
        /opt/include \
        /opt/*/include \
        "$HOME/local/include" \
        "$HOME/opt/include"
}

collect_tools() {
    MATCH_PATTERNS=('clang++' 'clang++-[0-9]*' 'g++' 'g++-[0-9]*' 'clang' 'clang-[0-9]*' 'gcc' 'gcc-[0-9]*')
    append_matching_files COMPILER_PATHS "${BINARY_DIRS[@]}"

    MATCH_PATTERNS=('clang-tidy' 'clang-tidy-[0-9]*')
    append_matching_files CLANG_TIDY_PATHS "${BINARY_DIRS[@]}"

    MATCH_PATTERNS=('clang-format' 'clang-format-[0-9]*')
    append_matching_files CLANG_FORMAT_PATHS "${BINARY_DIRS[@]}"

    MATCH_PATTERNS=('clang-scan-deps' 'clang-scan-deps-[0-9]*')
    append_matching_files CLANG_SCAN_DEPS_PATHS "${BINARY_DIRS[@]}"

    MATCH_PATTERNS=('cmake' 'cmake-[0-9]*')
    append_matching_files CMAKE_PATHS "${BINARY_DIRS[@]}"

    MATCH_PATTERNS=('cmake-format' 'cmake-format-[0-9]*')
    append_matching_files CMAKE_FORMAT_PATHS "${BINARY_DIRS[@]}"
}

collect_libraries() {
    local include_dir dir candidate resolved

    for include_dir in "${INCLUDE_DIRS[@]}"; do
        [[ -d "$include_dir" ]] || continue

        if [[ -d "$include_dir/c++/v1" ]]; then
            add_unique LIBCXX_HEADER_DIRS "$include_dir/c++/v1"
        fi

        if [[ -d "$include_dir/boost" && -f "$include_dir/boost/version.hpp" ]]; then
            add_unique BOOST_VERSION_HEADERS "$include_dir/boost/version.hpp"
        fi
    done

    shopt -s nullglob
    for candidate in /usr/include/c++/[0-9]* /usr/local/include/c++/[0-9]* "$HOME/local/include/c++/"[0-9]* "$HOME/opt/include/c++/"[0-9]*; do
        [[ -d "$candidate" ]] || continue
        add_unique LIBSTDCXX_HEADER_DIRS "$candidate"
    done

    for dir in "${LIB_DIRS[@]}"; do
        [[ -d "$dir" ]] || continue

        for candidate in "$dir"/libc++.so* "$dir"/libc++.a; do
            [[ -e "$candidate" ]] || continue
            resolved="$(readlink -f "$candidate" 2>/dev/null || printf '%s' "$candidate")"
            add_unique LIBCXX_LIBS "$resolved"
        done

        for candidate in "$dir"/libc++abi.so* "$dir"/libc++abi.a; do
            [[ -e "$candidate" ]] || continue
            resolved="$(readlink -f "$candidate" 2>/dev/null || printf '%s' "$candidate")"
            add_unique LIBCXXABI_LIBS "$resolved"
        done

        for candidate in "$dir"/libstdc++.so* "$dir"/libstdc++.a; do
            [[ -e "$candidate" ]] || continue
            resolved="$(readlink -f "$candidate" 2>/dev/null || printf '%s' "$candidate")"
            add_unique LIBSTDCXX_LIBS "$resolved"
        done

        for candidate in "$dir"/libboost_*.so* "$dir"/libboost_*.a; do
            [[ -e "$candidate" ]] || continue
            resolved="$(readlink -f "$candidate" 2>/dev/null || printf '%s' "$candidate")"
            add_unique BOOST_LIBS "$resolved"
        done
    done

    for candidate in /usr/lib*/cmake/Boost-* /usr/local/lib*/cmake/Boost-* /usr/lib/x86_64-linux-gnu/cmake/Boost-*; do
        [[ -d "$candidate" ]] || continue
        add_unique BOOST_CONFIGS "$candidate"
    done
    shopt -u nullglob
}

dir_in_path() {
    local dir="$1"
    local path_dir

    for path_dir in "${PATH_DIRS[@]}"; do
        [[ "$dir" == "$path_dir" ]] && return 0
    done

    return 1
}

origin_label() {
    local dir="$1"
    if dir_in_path "$dir"; then
        printf 'PATH'
    else
        printf 'standard'
    fi
}

first_line() {
    local file="$1"
    head -n 1 "$file" 2>/dev/null || true
}

version_line() {
    local cmd="$1"
    "$cmd" --version 2>/dev/null | head -n 1
}

probe_cpp_standard() {
    local compiler="$1"
    local std="$2"

    "$compiler" -x c++ "-std=c++${std}" -fsyntax-only "$TRIVIAL_CPP" >/dev/null 2>&1
}

probe_print_support() {
    local compiler="$1"
    local std="$2"
    shift 2

    "$compiler" -x c++ "-std=c++${std}" "$@" -fsyntax-only "$PRINT_CPP" >/dev/null 2>&1
}

probe_trivial_with_flags() {
    local compiler="$1"
    shift

    "$compiler" -x c++ "$@" -fsyntax-only "$TRIVIAL_CPP" >/dev/null 2>&1
}

yes_no() {
    if "$@"; then
        printf 'yes'
    else
        printf 'no'
    fi
}

print_section() {
    printf '\n== %s ==\n' "$1"
}

print_kv() {
    printf '  %-18s %s\n' "$1" "$2"
}

print_tool_list() {
    local title="$1"
    shift
    local -n values_ref="$1"
    local path dir version

    print_section "$title"
    if ((${#values_ref[@]} == 0)); then
        printf '  none found\n'
        return 0
    fi

    for path in "${values_ref[@]}"; do
        dir="$(dirname "$path")"
        version="$(version_line "$path")"
        printf '  - %s\n' "$path"
        print_kv "origin" "$(origin_label "$dir")"
        print_kv "version" "${version:-unknown}"
    done
}

print_compiler_report() {
    local path name dir version is_clangxx is_gxx
    local std23 std26 print23 print26 libstdcxx_flag libcxx_flag libstdcxx_print libcxx_print

    print_section "C and C++ Compilers"
    if ((${#COMPILER_PATHS[@]} == 0)); then
        printf '  none found\n'
        return 0
    fi

    for path in "${COMPILER_PATHS[@]}"; do
        name="$(basename "$path")"
        case "$name" in
            clang|clang-[0-9]*|clang++|clang++-[0-9]*|gcc|gcc-[0-9]*|g++|g++-[0-9]*) ;;
            *) continue ;;
        esac

        dir="$(dirname "$path")"
        version="$(version_line "$path")"
        printf '\n  - %s\n' "$path"
        print_kv "origin" "$(origin_label "$dir")"
        print_kv "version" "${version:-unknown}"

        if [[ "$name" == clang++* || "$name" == g++* ]]; then
            std23="$(yes_no probe_cpp_standard "$path" 23)"
            std26="$(yes_no probe_cpp_standard "$path" 26)"
            print23="$(yes_no probe_print_support "$path" 23)"
            print26="$(yes_no probe_print_support "$path" 26)"

            print_kv "supports c++23" "$std23"
            print_kv "supports c++26" "$std26"
            print_kv "<print> c++23" "$print23"
            print_kv "<print> c++26" "$print26"

            if [[ "$name" == clang++* ]]; then
                libstdcxx_flag="$(yes_no probe_trivial_with_flags "$path" -std=c++23 -stdlib=libstdc++)"
                libcxx_flag="$(yes_no probe_trivial_with_flags "$path" -std=c++23 -stdlib=libc++)"
                libstdcxx_print="$(yes_no probe_print_support "$path" 23 -stdlib=libstdc++)"
                libcxx_print="$(yes_no probe_print_support "$path" 23 -stdlib=libc++)"

                print_kv "libstdc++ flag" "$libstdcxx_flag"
                print_kv "libc++ flag" "$libcxx_flag"
                print_kv "<print> libstdc++" "$libstdcxx_print"
                print_kv "<print> libc++" "$libcxx_print"
            fi
        fi
    done
}

header_has_print() {
    local header_dir="$1"
    [[ -f "$header_dir/print" ]]
}

boost_version_from_header() {
    local header="$1"
    local version lib_version

    version="$(grep -E '^#define BOOST_VERSION ' "$header" 2>/dev/null | awk '{print $3}')"
    lib_version="$(grep -E '^#define BOOST_LIB_VERSION ' "$header" 2>/dev/null | sed -E 's/.*"([^"]+)".*/\1/')"

    if [[ -n "$lib_version" ]]; then
        printf '%s (%s)' "$lib_version" "${version:-unknown}"
    elif [[ -n "$version" ]]; then
        printf '%s' "$version"
    else
        printf 'unknown'
    fi
}

print_header_dirs() {
    local title="$1"
    shift
    local -n values_ref="$1"
    local dir

    print_section "$title"
    if ((${#values_ref[@]} == 0)); then
        printf '  none found\n'
        return 0
    fi

    for dir in "${values_ref[@]}"; do
        printf '  - %s\n' "$dir"
        if [[ "$title" == "libc++ Headers" || "$title" == "libstdc++ Headers" ]]; then
            print_kv "has <print>" "$( [[ -f "$dir/print" ]] && printf yes || printf no )"
        fi
    done
}

print_library_files() {
    local title="$1"
    shift
    local -n values_ref="$1"
    local path

    print_section "$title"
    if ((${#values_ref[@]} == 0)); then
        printf '  none found\n'
        return 0
    fi

    for path in "${values_ref[@]}"; do
        printf '  - %s\n' "$path"
    done
}

print_gcc_install_dirs() {
    local dir

    print_section "GCC Install Dirs"
    if ((${#GCC_INSTALL_DIRS[@]} == 0)); then
        printf '  none found\n'
        return 0
    fi

    for dir in "${GCC_INSTALL_DIRS[@]}"; do
        printf '  - %s\n' "$dir"
    done
}

print_boost_report() {
    local header
    local lib key_count

    print_section "Boost Headers"
    if ((${#BOOST_VERSION_HEADERS[@]} == 0)); then
        printf '  none found\n'
    else
        for header in "${BOOST_VERSION_HEADERS[@]}"; do
            printf '  - %s\n' "$header"
            print_kv "version" "$(boost_version_from_header "$header")"
        done
    fi

    print_section "Boost CMake Configs"
    if ((${#BOOST_CONFIGS[@]} == 0)); then
        printf '  none found\n'
    else
        for lib in "${BOOST_CONFIGS[@]}"; do
            printf '  - %s\n' "$lib"
        done
    fi

    print_section "Boost Libraries"
    if ((${#BOOST_LIBS[@]} == 0)); then
        printf '  none found\n'
    else
        key_count=0
        for lib in "${BOOST_LIBS[@]}"; do
            printf '  - %s\n' "$lib"
            case "$(basename "$lib")" in
                libboost_log*|libboost_filesystem*|libboost_program_options*)
                    key_count=$((key_count + 1))
                    ;;
            esac
        done
        print_kv "key libs seen" "$key_count"
    fi
}

main() {
    collect_search_dirs
    collect_tools
    collect_libraries

    printf '%s\n' "$SCRIPT_NAME"
    printf 'Scanned %d binary dirs, %d include dirs, %d library dirs.\n' \
        "${#BINARY_DIRS[@]}" "${#INCLUDE_DIRS[@]}" "${#LIB_DIRS[@]}"

    print_compiler_report
    print_tool_list "CMake" CMAKE_PATHS
    print_tool_list "clang-tidy" CLANG_TIDY_PATHS
    print_tool_list "clang-format" CLANG_FORMAT_PATHS
    print_tool_list "clang-scan-deps" CLANG_SCAN_DEPS_PATHS
    print_tool_list "cmake-format" CMAKE_FORMAT_PATHS
    print_gcc_install_dirs
    print_header_dirs "libc++ Headers" LIBCXX_HEADER_DIRS
    print_header_dirs "libstdc++ Headers" LIBSTDCXX_HEADER_DIRS
    print_library_files "libc++ Libraries" LIBCXX_LIBS
    print_library_files "libc++abi Libraries" LIBCXXABI_LIBS
    print_library_files "libstdc++ Libraries" LIBSTDCXX_LIBS
    print_boost_report
}

main "$@"
