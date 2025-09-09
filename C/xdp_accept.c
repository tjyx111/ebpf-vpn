#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define UDP_ECHO_PORT 18080

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

struct icmp_event {
    __u32 src;
    __u32 dst;
};

struct udp_echo_event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u16 length;
};

static __always_inline __u16 csum_fold_helper(__u64 csum)
{
    int i;
#pragma unroll
    for (i = 0; i < 4; i++) {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

static __always_inline __u16 ipv4_csum(struct iphdr *iph)
{
    iph->check = 0;
    unsigned long long csum = bpf_csum_diff(0, 0, (unsigned int *)iph, sizeof(struct iphdr), 0);
    return csum_fold_helper(csum);
}

SEC("xdp")
int xdp_firewall(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    // 只处理IP包
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
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
        return XDP_PASS;
    }

    // 处理UDP包
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) > data_end) return XDP_PASS;

        // 检查是否为目标端口的UDP包
        if (udp->dest == bpf_htons(UDP_ECHO_PORT)) {
            // 记录事件
            struct udp_echo_event evt = {};
            evt.src_ip = ip->saddr;
            evt.dst_ip = ip->daddr;
            evt.src_port = bpf_ntohs(udp->source);
            evt.dst_port = bpf_ntohs(udp->dest);
            evt.length = bpf_ntohs(udp->len);
            bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));

            // 交换以太网地址（L2）
            __u8 tmp_mac[6];
            __builtin_memcpy(tmp_mac, eth->h_dest, 6);
            __builtin_memcpy(eth->h_dest, eth->h_source, 6);
            __builtin_memcpy(eth->h_source, tmp_mac, 6);

            // 交换IP地址（L3）
            __u32 tmp_ip = ip->saddr;
            ip->saddr = ip->daddr;
            ip->daddr = tmp_ip;

            // 交换UDP端口
            __u16 tmp_port = udp->source;
            udp->source = udp->dest;
            udp->dest = tmp_port;

            // 重新计算IP校验和
            ip->check = 0;
            ip->check = ipv4_csum(ip);

            // UDP校验和设置为0（可选，让网卡硬件处理）
            udp->check = 0;

            bpf_trace_printk("UDP Echo: port %d\n", sizeof("UDP Echo: port %d\n"), UDP_ECHO_PORT);
            
            // 直接从同一接口发送回去
            return XDP_TX;
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";