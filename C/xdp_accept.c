#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "udp_echo.h"
#include "trace.h"

#define UDP_ECHO_PORT 18080

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 32);
} config_map SEC(".maps");

SEC("xdp")
int xdp_firewall(struct xdp_md *ctx) {
    __u32 key_port = 0, key_trace = 1;
    __u32 *udp_port = bpf_map_lookup_elem(&config_map, &key_port);
    __u32 *trace_flag = bpf_map_lookup_elem(&config_map, &key_trace);
    __u16 filter_port = UDP_ECHO_PORT;
    if (udp_port != NULL && *udp_port != 0) {
        filter_port = (__u16)(*udp_port);
    }
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    int trace_enabled = (trace_flag && *trace_flag == 1);
    if (trace_enabled) {
        bpf_trace_printk("trace_in\n", sizeof("trace_in\n"));
        send_trace_event(ctx, data, data_end, XDP_PASS, 0);
    }

    // 只处理IP包
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }
    
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    // 检查是否为ICMP协议
    if (ip->protocol == IPPROTO_ICMP) {
        bpf_trace_printk("ICMP packet detected\n", sizeof("ICMP packet detected\n"));
        return XDP_PASS;
    }

    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) > data_end) return XDP_PASS;
        if (udp->dest == bpf_htons(filter_port)) {
            // 调用udp_echo服务
            int ret = xdp_udpecho(eth, ip, udp, data_end);
            if (trace_enabled) {
                bpf_trace_printk("trace_out %d\n", sizeof("trace_out %d\n"), ret);
                send_trace_event(ctx, data, data_end, ret, 0);
            }
            return ret;
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";