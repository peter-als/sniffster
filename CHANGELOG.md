# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased]

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
