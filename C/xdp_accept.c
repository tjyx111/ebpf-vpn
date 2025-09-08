#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>


struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

struct icmp_event {
    __u32 src;
    __u32 dst;
};

SEC("xdp")

int xdp_firewall(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    // 只处理IP包
    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
        bpf_trace_printk("Not IP\n", sizeof("Not IP\n"));
        return XDP_PASS;
    }
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    // 检查是否为ICMP协议
    if (ip->protocol == IPPROTO_ICMP) {
        struct icmp_event evt = {};
        evt.src = ip->saddr;
        evt.dst = ip->daddr;
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
        bpf_trace_printk("ICMP packet detected\n", sizeof("ICMP packet detected\n"));
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";