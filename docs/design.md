# Design Diagram

This diagram reflects the current runtime structure in the codebase.

## High-Level Runtime

```text
                                   sniffster
                                        |
                                        v
                        +----------------------------------+
                        | sniffer                          |
                        |                                  |
                        | - owns global exit flag          |
                        | - creates loader                 |
                        | - starts logger thread           |
                        | - starts one handler per         |
                        |   CPU-group                      |
                        | - runs packet_processor on main  |
                        |   thread                         |
                        +----------------+-----------------+
                                         |
                                         v
                        +----------------------------------+
                        | xdp_copy_mode_loader             |
                        |                                  |
                        | - opens BPF skeleton             |
                        | - sizes perf map to CPU count    |
                        | - loads XDP program              |
                        | - attaches XDP to NIC            |
                        | - exposes perf_map_fd()          |
                        +----------------+-----------------+
                                         |
                                         v
                              +----------------------+
                              | NIC + XDP program    |
                              |                      |
                              | xdp_copy_mode.c      |
                              | returns XDP_PASS     |
                              | emits metadata to    |
                              | PERF_EVENT_ARRAY     |
                              +----------+-----------+
                                         |
                                         v
                  +-----------------------------------------------+
                  | one handler thread per CPU-group              |
                  |                                               |
                  | xdp_copy_handler                              |
                  | - owns one raw perf buffer                    |
                  | - polls perf_buffer__poll()                   |
                  | - forwards samples into packet_handler        |
                  +-------------------+---------------------------+
                                      |
                                      v
                  +-----------------------------------------------+
                  | packet_handler                                |
                  | - self-registers producer queues at startup   |
                  | - decodes raw samples into packet_meta_event  |
                  | - compares packet_identity_t for coalescing   |
                  | - stores local coalesced window               |
                  | - pushes reduced packet/log events downstream |
                  +-------------------+-------------------+-------+
                                      |                   |
                                      |                   |
                                      v                   v
                    +-------------------------+   +-------------------------+
                    | outbound_events_        |   | logger_events_          |
                    | SPSC queue              |   | SPSC queue              |
                    | packet_meta_event       |   | logger_event            |
                    +------------+------------+   +------------+------------+
                                 |                             |
                                 | registered by borrowed ref  | registered by borrowed ref
                                 v                             v
                 +-------------------------------+   +-------------------------------+
                 | packet_processor              |   | logger_processor              |
                 |                               |   |                               |
                 | queue_processor<...> base     |   | queue_processor<...> base     |
                 | runs on sniffer main thread   |   | runs on dedicated jthread     |
                 | drains registered SPSC queues |   | drains registered SPSC queues |
                 | batches JSONL report writes   |   | writes logs via Boost.Log     |
                 +-------------------------------+   +-------------------------------+
```

## Event Layout

```text
packet_meta_event
+---------------------------------------------------------------+
| packet_identity_t                                             |
|                                                               |
|   src_ip | dst_ip | src_mac | dst_mac | eth_proto | l4 proto |
|                                                               |
|   compared with memcmp over the first 47 meaningful bytes     |
+---------------------------------------------------------------+
| first_timestamp                                               |
| latest_timestamp                                              |
| rx_queue                                                      |
| packet_size                                                   |
| cpu_id                                                        |
| coalesced_count                                               |
+---------------------------------------------------------------+

sizeof(packet_identity_t) = 48 bytes
sizeof(packet_meta_event) = 80 bytes
```

## Threading Model

```text
main thread
  |
  +--> constructs sniffer
  +--> constructs loader and attaches XDP
  +--> starts logger thread
  +--> starts N handler threads, one per CPU-group
  +--> runs packet_processor::run()

logger thread
  |
  +--> logger_processor::run()

handler thread i
  |
  +--> packet_handler self-registers queues during construction
  +--> xdp_copy_handler(cpu-group=i).run()
  +--> perf_buffer__poll()
  +--> decode/coalesce
  +--> push packet/log events
```

## Ownership / Lifetime Notes

```text
queue ownership:
  packet_handler owns outbound_events_ and logger_events_

queue visibility:
  processors store borrowed queue references after registration

safety model:
  no shared_ptr / heap-managed queue ownership in the hot path
  correctness depends on strict startup and shutdown ordering
  plus a shared start/stop barrier around queue registration and teardown

required contract:
  1. handlers finish queue self-registration before processors start draining
  2. registration is immutable after the startup barrier releases
  3. processors outlive the handlers that publish into them
  4. handler threads exit before queue-owning packet_handler objects are destroyed
```

## Current Module Map

```text
sniffer/
  sniffer.cppm                  top-level runtime orchestration
  xdp_copy_mode_loader.cppm     BPF skeleton load/attach lifecycle
  xdp_copy_handler.cppm         perf-buffer poller and sample dispatch
  packet_handler.cppm           decode + coalesce + queue publish path
  xdp_copy_mode.c               XDP-side metadata emission

processors/
  packet_meta_event.cppm        packet_identity_t + packet_meta_event
  queue_processor.cppm          generic queue-draining processor base
  packet_processor.cppm         packet event consumer
  logger_processor.cppm         logger event consumer
  logger_event.cppm             logging event payload
  packet_print.cppm             packet/event pretty-print helpers
```
