# Usage

This document collects the day-to-day ways to build, run, test, and inspect `sniffster`.

## Build

Requires CMake 3.28+, a C++26-capable compiler, `libbpf`, and Boost. CMake fetches CLI11 and GoogleTest automatically.

Fast path:

```bash
make debug
make release
make sanitized
```

Equivalent CMake preset flow:

```bash
cmake --preset debug
cmake --build --preset debug

cmake --preset release
cmake --build --preset release

cmake --preset sanitized
cmake --build --preset sanitized
```

The main executable is produced at `./build/<preset>/sniffster`.

## Run `sniffster`

Basic run:

```bash
./build/debug/sniffster --network-interface eth0
```

Show CLI help:

```bash
./build/debug/sniffster --help
```

By default, `sniffster` writes:

- status logs to `/var/log/sniffster.log`
- traffic reports to `/var/log/sniffster.traffic.log`

The runtime attaches an XDP program to the selected NIC and, with the default paths, writes under `/var/log`, so in practice this usually means running with sufficient privileges.

## Output path scenarios

Write both outputs into a local directory:

```bash
mkdir -p ./out
./build/debug/sniffster --network-interface eth0 --log ./out --report ./out
```

That resolves to:

- `./out/sniffster.log`
- `./out/sniffster.traffic.log`

Write to explicit files instead:

```bash
./build/debug/sniffster \
  --network-interface eth0 \
  --log ./out/status.log \
  --report ./out/traffic.jsonl
```

Path rules from the CLI:

- an existing directory gets the default filename appended
- an existing regular file is used as-is
- the parent directory must already exist
- a path that resolves to a non-regular special file is rejected

## Thread placement scenarios

Let `sniffster` choose its default handler layout:

```bash
./build/debug/sniffster --network-interface eth0
```

Request a fixed number of handler threads:

```bash
./build/debug/sniffster --network-interface eth0 --thread-count 4
```

Pin handlers to specific CPUs:

```bash
./build/debug/sniffster --network-interface eth0 --cpus 0,2,4,6
```

`--thread-count` and `--cpus` are mutually exclusive.

## Report and log handling

The report file and status log are opened once and kept open. Rotating by rename alone is not enough: the running process will keep writing to the old inode until it restarts or learns to reopen the path.

Current recommended external rotation approach:

- rotate with your normal tool, such as `logrotate`
- use `copytruncate`
- accept the usual `copytruncate` tradeoff: a small race window may lose or duplicate a few writes

## Report post-processing

The traffic report is newline-delimited JSON. To rewrite known timestamp fields into readable local time strings:

```bash
./format-timestamps.py /var/log/sniffster.traffic.log
```

Show script help:

```bash
./format-timestamps.py --help
```

Write the transformed output to a file:

```bash
./format-timestamps.py /var/log/sniffster.traffic.log --output ./out/traffic.pretty.jsonl
```

If you omit the report path, the script probes these defaults in order:

- `/var/log/sniffster.traffic.log`
- `./sniffster.traffic.log`
- `./traffic.log`

## Test scenarios

Run all tests through the Makefile:

```bash
make test-debug
make test-release
make test-sanitized
```

Run all tests through CTest:

```bash
ctest --preset debug --output-on-failure
ctest --preset release --output-on-failure
ctest --preset sanitized --output-on-failure
```

List discovered CTest tests:

```bash
ctest --preset debug -N
python3 run-tests.py --list
```

Run one discovered CTest test exactly:

```bash
ctest --preset debug --output-on-failure -R '^PacketHandlerTest.CoalescesRepeatedPacketsBeforeTheyReachProcessorOutput$'
```

Run tests by discovered-name prefix through the helper script:

```bash
python3 run-tests.py PacketHandlerTest
python3 run-tests.py PacketHandlerTest.CoalescesRepeatedPacketsBeforeTheyReachProcessorOutput
python3 run-tests.py --preset sanitized PacketProcessorTest
```

Run a test binary directly:

```bash
./build/debug/tests/packet_handler_tests
./build/debug/tests/packet_handler_tests --gtest_filter='PacketHandlerTest.CoalescesRepeatedPacketsBeforeTheyReachProcessorOutput'
```

Sanitized-preset caveats are documented in [limitations.md](./limitations.md).

## Manual helper binaries

The debug build also produces a few small manual helpers under `./build/debug/tests/`:

Inspect queue detection for an interface:

```bash
./build/debug/tests/manual_nic_detect_queues eth0
```

Print resolved interface/network config:

```bash
./build/debug/tests/manual_network_config eth0
```

Show decorated exception formatting:

```bash
./build/debug/tests/manual_demo_decorated_errors
```

Run the architecture/bit-casting scratch helper:

```bash
./build/debug/tests/manual_arch_bits
```
