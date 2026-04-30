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
- **Compiler presets** - `/usr/bin/clang-22`, `/usr/bin/clang++-22`, and `/usr/bin/clang-scan-deps-22`
- **C++ language level** - C++26, with extensions disabled
- **Standard library default** - `libc++` via `SNIFFSTER_CXX_STDLIB=libc++`
- **Current libc++ extra flag** - `-fexperimental-library` is enabled for the repo's libc++ flow
- **Compile database** - `CMAKE_EXPORT_COMPILE_COMMANDS=ON`
- **Build presets** - `debug`, `release`, and `sanitized`

The current build also assumes host-installed `libbpf`, `bpftool`, and a `libc++`-compatible Boost installation discoverable by CMake. The project already fetches CLI11 and GoogleTest, but not Boost or libc++.

## Usage

Build, run, output-file handling, report rotation, test flows, and manual helper commands now live in [docs/usage.md](docs/usage.md).

If you want the sanitizer-specific testing caveats, see [docs/limitations.md](docs/limitations.md).

## Status

This is an actively developed implementation. The XDP/libbpf path is in place, the runtime is covered by an expanding automated test suite, and deeper profiling and further runtime cleanup remain on the roadmap.
