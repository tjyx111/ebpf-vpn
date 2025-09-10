#ifndef TRACE_H
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/bpf.h>

#define MAX_PACKET_SIZE 1500 // 以太网标准 MTU

// 过滤规则
struct filter_rule {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol; // IPPROTO_UDP, IPPROTO_TCP, etc.
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct filter_rule));
    __uint(max_entries, 1);
} filter_rule_map SEC(".maps");

// 数据包
struct trace_event {
    __u32 pkt_len;
    __u32 pkt_real_len;
   __u8 packet_data[MAX_PACKET_SIZE];
    __u32 xdp_action;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1MB，可根据需要调整
} events_ringbuf SEC(".maps");

static __always_inline int match_filter_rule(struct iphdr *ip, struct udphdr *udp, void *data_end) {
    __u32 key = 0;
    struct filter_rule *rule = bpf_map_lookup_elem(&filter_rule_map, &key);
    if (!rule) return 0;

    // 检查协议
    if (rule->protocol && ip->protocol != rule->protocol)
        return 0;

    // 检查源IP
    if (rule->src_ip && ip->saddr != rule->src_ip)
        return 0;

    // 检查目的IP
    if (rule->dst_ip && ip->daddr != rule->dst_ip)
        return 0;

    // 检查端口（仅UDP/TCP）
    if (ip->protocol == IPPROTO_UDP || ip->protocol == IPPROTO_TCP) {
        struct udphdr *hdr = (void *)(ip + 1);
        if ((void *)(hdr + 1) > data_end) return 0;
        if (rule->src_port && hdr->source != bpf_htons(rule->src_port))
            return 0;
        if (rule->dst_port && hdr->dest != bpf_htons(rule->dst_port))
            return 0;
    }

    return 1;
}

static __always_inline void send_trace_event(struct xdp_md *ctx, void *data, void *data_end, __u32 xdp_action, __u32 trace_key) {
    // 只处理ip包
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return; // 只处理IP包
   
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return;

     // 五元组过滤
    if (!match_filter_rule(ip, (void *)(ip + 1), data_end)) return;

    __u32 pkt_real_len = data_end - data;
    __u32 pkt_len = pkt_real_len > MAX_PACKET_SIZE ? MAX_PACKET_SIZE : pkt_real_len;

    // 1. 检查数据包是否超过我们定义的大小
    if (pkt_len > MAX_PACKET_SIZE) {
        bpf_printk("Packet too large: %d", pkt_len);
        return;
    }

    // 2. 在 ringbuf 中为事件申请空间
    struct trace_event *event;
    event = bpf_ringbuf_reserve(&events_ringbuf, sizeof(*event), 0);
    if (!event) {
        // 申请失败（通常是用户空间消费太慢，ringbuf 满了）
        return;
    }

    event->pkt_real_len = pkt_real_len;
    event->pkt_len = pkt_len;

    // 4. 关键步骤：将完整数据包拷贝到用户态缓冲区
    //    使用 bpf_probe_read_kernel 或直接指针操作（如果类型正确）
    long err = bpf_probe_read_kernel(
        event->packet_data, 
        event->pkt_len, // 拷贝源长度
        data         // 源地址（数据包起始位置）
    );
    if (err) {
        // 拷贝失败，释放预留的 ringbuf 空间
        bpf_ringbuf_discard(event, 0);
        return;
    }

    event->xdp_action = xdp_action;

    bpf_ringbuf_submit(event, 0);
}

#endif // TRACE_H