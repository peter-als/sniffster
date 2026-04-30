#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include "platform/arch_macros.h"
#include "network/packet_offsets.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} perf_map SEC(".maps");

static force_inline_ void inline__bpf_send(struct xdp_md *ctx, unsigned char *to_be_sent, unsigned payload_len) {
    const unsigned total_len = RX_QUEUE_BYTES + payload_len;
    bpf_perf_event_output(ctx, &perf_map, BPF_F_CURRENT_CPU, to_be_sent, total_len);
}

SEC("xdp")
int xdp_copy_handle_packet(struct xdp_md *ctx) {
    unsigned char *data = (unsigned char *)(long)ctx->data;
    unsigned char *data_end = (unsigned char *)(long)ctx->data_end;
    unsigned char to_be_sent[RX_QUEUE_BYTES + ETH_HEADER_BYTES + IPV6_HEADER_BYTES];
    __u32 rx_queue = ctx->rx_queue_index;

    if (data + ETH_HEADER_BYTES > data_end) {
        return XDP_PASS;
    }

    // Emit the hardware RX queue index ahead of the copied packet bytes.
    memcpy_(to_be_sent, &rx_queue, RX_QUEUE_BYTES);

    __u16 eth_proto_net;
    // Copy EtherType bytes out of packet header before endian conversion.
    memcpy_(&eth_proto_net, data + ETH_PROTO_OFFSET, sizeof(eth_proto_net));

    const __u16 eth_proto = ntoh16_(eth_proto_net);
    const __u8* dest_start = to_be_sent + RX_QUEUE_BYTES;

    // XDP packet memory cannot be passed straight to bpf_perf_event_output()
    // here: the helper wants stack-backed data, and the verifier rejects a
    // direct packet pointer. So we copy only the small protocol-specific
    // prefix we care about into a temporary stack buffer, then emit that.
    // Copy the selected raw Ethernet+IPv4 prefix into a stack buffer before perf output.

    if (eth_proto == ETH_P_IP) {
        const unsigned ip4_data_len = ETH_HEADER_BYTES + IPV4_MIN_HEADER_BYTES;
        if (data + ip4_data_len > data_end) unlikely_ {
            return XDP_PASS;
        }

        memcpy_(dest_start, data, ip4_data_len);
        inline__bpf_send(ctx, to_be_sent, ip4_data_len);
    } else if (eth_proto == ETH_P_IPV6) {
        const unsigned ip6_data_len = ETH_HEADER_BYTES + IPV6_HEADER_BYTES;
        if (data + ip6_data_len > data_end) unlikely_ {
            return XDP_PASS;
        }

        memcpy_(dest_start, data, ip6_data_len);
        inline__bpf_send(ctx, to_be_sent, ip6_data_len);
    } else if (eth_proto == ETH_P_ARP || eth_proto == ETH_P_RARP) {
        const unsigned arp_data_len = ETH_HEADER_BYTES + ARP_HEADER_BYTES;
        if (data + arp_data_len > data_end) unlikely_ {
            return XDP_PASS;
        }

        memcpy_(dest_start, data, arp_data_len);
        inline__bpf_send(ctx, to_be_sent, arp_data_len);
    } else {
        memcpy_(dest_start, data, ETH_HEADER_BYTES);
        inline__bpf_send(ctx, to_be_sent, ETH_HEADER_BYTES);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
