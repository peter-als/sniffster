# sniffster

`sniffster` is an observing-only network traffic sniffer built around XDP, libbpf, and C++26 • named modules.

It observes live traffic, extracts compact metadata, and logs those observations while keeping the runtime intentionally lightweight.

## Goals

- observe traffic without taking packets away from the normal host stack
- coalesce similar packet observations early, near the capture path
- keep CPU and memory overhead low enough for routine use on a normal development box
- preserve explicit runtime ownership and synchronization instead of relying on shared ownership machinery

## Architecture

At a high level, the runtime looks like this:

- an XDP program observes packets and emits compact metadata into a perf event array
- userspace receives those samples through libbpf perf buffers
- handler threads decode and coalesce events before pushing them downstream
- processor threads consume the reduced event stream for reporting and logging

The packet metadata layout is intentionally split in two parts. `packet_identity_t` contains only the bytes that define "same network observation" for coalescing, while `packet_meta_event` embeds that identity object as its first field and appends timestamps and runtime metadata after it. That identity boundary is guarded with `static_assert`s on size, alignment, and field offsets.

Source is organized as C++26 • named modules (`.cppm`) under `network/`, `sniffer/`, and `processors/`.

## Design Notes

The current runtime prefers fixed topology and explicit thread coordination over shared ownership machinery.

Producer queues are registered into processor objects as non-owning references. Queue safety comes from a strict runtime contract:

- producer registration is serialized during startup
- processors do not start draining until the startup barrier releases
- processor objects outlive the handler threads that publish into them
- shutdown is synchronized explicitly, and handler threads exit before processor teardown

Some implementation details around this contract are still intentionally explicit and low-level. A few `TBD` markers remain in the runtime code around queue-adjacent logging and observability; those are known follow-up items, not accidental omissions.

## Dependencies

- **libbpf** - XDP program loading and perf-buffer delivery
- **Boost** - `log`, `log_setup`, `lockfree`
- **CLI11** - command-line argument parsing, fetched automatically by CMake
- **GoogleTest** - test framework, fetched automatically by CMake

## Current Toolchain

The repository is currently configured around this build setup:

- **CMake** - 3.28+ required
- **Generator** - Ninja via the checked-in CMake presets
- **Compiler presets** - controlled through `CMakePresets.json`
- **C++ language level** - C++26, with extensions disabled
- **Standard library selection** - controlled through `SNIFFSTER_CXX_STDLIB`
- **Compile database** - `CMAKE_EXPORT_COMPILE_COMMANDS=ON`
- **Build presets** - `debug`, `release`, and `sanitized`

The current build assumes host-installed `libbpf`, `bpftool`, Boost, and whichever C++ standard library the selected toolchain uses. The project already fetches CLI11 and GoogleTest, but not Boost or the C++ standard library.

## Toolchain Customization

The checked-in presets use `configurePresets.base.cacheVariables` in [CMakePresets.json](CMakePresets.json) as the single place to customize the toolchain.

The real variables are:

- `CMAKE_C_COMPILER` - C compiler binary, for example `/usr/bin/clang-22`
- `CMAKE_CXX_COMPILER` - C++ compiler binary, for example `/usr/bin/clang++-22`
- `CMAKE_CXX_COMPILER_CLANG_SCAN_DEPS` - matching `clang-scan-deps` binary when using Clang modules
- `CMAKE_CXX_STANDARD` - language level such as `23` or `26`
- `SNIFFSTER_CXX_STDLIB` - standard library choice: empty, `libstdc++`, or `libc++`
- `SNIFFSTER_GCC_INSTALL_DIR` - exact GCC install directory to pair with Clang when selecting `libstdc++`, for example `/usr/lib/gcc/x86_64-linux-gnu/14`
- `SNIFFSTER_BOOST_ROOT` - Boost installation prefix when you want a non-default Boost build

Typical combinations:

- Clang 22 + `libstdc++` 14:
  `CMAKE_CXX_COMPILER=/usr/bin/clang++-22`, `SNIFFSTER_CXX_STDLIB=libstdc++`, `SNIFFSTER_GCC_INSTALL_DIR=/usr/lib/gcc/x86_64-linux-gnu/14`
- Clang + `libc++`:
  `CMAKE_CXX_COMPILER=/usr/bin/clang++-22`, `SNIFFSTER_CXX_STDLIB=libc++`
- Non-default Boost:
  `SNIFFSTER_BOOST_ROOT=/path/to/boost-prefix`

`SNIFFSTER_BOOST_ROOT` must point to a real Boost prefix, typically containing both:

- `<prefix>/include/boost/version.hpp`
- `<prefix>/lib/libboost_log.so` or equivalent Boost libraries

If you change compiler, standard library, GCC install dir, or Boost root, clear the build tree first so CMake does not reuse stale cache entries:

```sh
make clean
make debug
```

## Usage

Build, run, output-file handling, report rotation, test flows, and manual helper commands now live in [docs/usage.md](docs/usage.md).

If you want the sanitizer-specific testing caveats, see [docs/limitations.md](docs/limitations.md).

## Status

This is an actively developed implementation. The XDP/libbpf path is in place, the runtime is covered by an expanding automated test suite, and deeper profiling and further runtime cleanup remain on the roadmap.
