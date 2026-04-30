# Limitations

## Sanitized build: decorated `std::runtime_error` throw/catch tests

The sanitized preset currently excludes two `platform_tests` cases:

- `PlatformThrowRuntimeError.PlainMessageIncludesCallSiteContext`
- `PlatformThrowRuntimeError.FormattedMessageUsesCallerLocation`

Reason:

- on this machine/toolchain, AddressSanitizer reports an `alloc-dealloc-mismatch`
  while catching the thrown `std::runtime_error`
- the failure happens inside the libc++ / libc++abi exception runtime during
  `__cxa_end_catch`, before the test can finish its assertions
- this is not caused by the repository's source-location formatting logic itself

Observed behavior:

- the formatting-only test
  `PlatformThrowRuntimeError.ThrowContextDefaultBracesUseCallerLocation`
  remains valid under the sanitized preset because it builds the decorated
  message string without actually throwing and catching the exception

Practical implication:

- use the debug preset for full decorated throw/catch behavior tests
- use the sanitized preset for message-formatting coverage, but not for the two
  throw/catch validation cases listed above

## Toolchain packaging

The current build still depends on pre-installed toolchain pieces on the host:

- `libc++` for the default C++26 build configuration
- a matching installed Boost build, especially for Boost.Log when building against `libc++`
- external tools such as `bpftool` and the BPF-capable Clang toolchain

A future migration may move more of that setup under CMake control, especially Boost and possibly a more self-contained libc++ story, so fresh-machine setup is less fragile and less dependent on whatever the host distro packaged. That migration has not happened yet, and the current repo should still be treated as relying on installed system or locally-installed toolchain components rather than fetching them automatically.

## Promiscuous mode

`sniffster` does not currently enable or manage NIC promiscuous mode.

Practical implication:

- on a normal switched network, the current runtime usually sees traffic addressed
  to the host, plus broadcast and multicast traffic that already reaches the NIC
- if the intended deployment depends on observing additional third-party traffic
  delivered to the interface, a future version will likely need explicit
  promiscuous-mode support and corresponding setup/restore handling

This is separate from the XDP capture path itself: enabling promiscuous mode can
allow the NIC to deliver more ingress frames to the host, but it does not by
itself make a switched network send unrelated traffic to that port.
