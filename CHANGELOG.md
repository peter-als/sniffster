# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased]

### Added

- **Toolchain inventory script** — added `scripts/toolchain_inventory.sh` to
  inspect available compilers, Clang tooling, Boost, `libc++`, and
  `libstdc++`, including capability probes for C++23, C++26, and `<print>`.
- **Preset-level toolchain knobs** — documented and wired support for selecting
  compiler binaries, `clang-scan-deps`, language level, standard library,
  exact GCC install dir for Clang + `libstdc++`, and a non-default Boost
  prefix from `CMakePresets.json`.
- **README toolchain customization guide** — documented the real cache
  variables used to customize the build and the expected shape of a valid
  non-default Boost install prefix.

### Changed

- **Standard library selection** — restored `SNIFFSTER_CXX_STDLIB` as the
  single repo-level switch for `libstdc++` vs `libc++`, including the
  corresponding compile, link, and feature-probe flags.
- **Clang + GNU stdlib pairing** — added `SNIFFSTER_GCC_INSTALL_DIR` so Clang
  builds can be pinned to a specific GCC/libstdc++ install such as
  `/usr/lib/gcc/x86_64-linux-gnu/14`.
- **Boost selection** — added `SNIFFSTER_BOOST_ROOT` and forward it to
  `Boost_ROOT` / `BOOST_ROOT` so a non-default Boost install can be selected
  without reviving the earlier path-guessing logic.

### Fixed

- **Toolchain inventory coverage** — taught the inventory script to report GCC
  install directories such as `/usr/lib/gcc/x86_64-linux-gnu/14` instead of
  only broad library roots.
- **Toolchain diagnostics** — clarified that a bad `clang-scan-deps` path can
  make CMake report a misleading `<print>` failure even when the selected
  compiler and standard library actually support it.

## [0.0.1] - 2026-04-29

### Added

- **XDP/libbpf capture path** — passive packet observation via an XDP program that
  emits compact metadata and passes every packet unmodified to the host stack.
- **Per-CPU handler threads** — one handler thread per CPU-group polls its perf
  buffer and feeds a coalescing stage before events reach downstream consumers.
- **Coalescing** — repeated observations of the same network flow are merged early,
  near the capture path, to keep downstream volume low.
- **Inventory reporting** — a packet processor drains the event stream and writes
  batched JSONL inventory reports.
- **Structured logging** — a dedicated logger thread drains log events through
  Boost.Log.
- **Explicit startup/shutdown coordination** — queue registration, processor startup,
  and teardown follow a strict ordering contract enforced at runtime.
- **C++26 named-module layout** — source is organized as named modules (`.cppm`)
  under `network/`, `sniffer/`, and `processors/`.
- **CLI argument parsing** via CLI11 (fetched automatically by CMake).
- **CMake build presets** — `debug`, `release`, and `sanitized`, exposed through a
  top-level `Makefile`.
- **Automated test suite** — 105 tests covering the capture, coalescing, processing,
  and logging layers; passing under `debug` and `release` presets.

[0.1.0]: https://github.com/peterals/sniffster/releases/tag/v0.1.0
