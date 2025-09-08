//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct packet_info {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u16 length;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

SEC("tc")
int monitor_udp(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
        
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;
        
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;
        
    if (ip->protocol != 17)
        return TC_ACT_OK;
        
    struct udphdr *udp = (void *)(ip + 1);
    if ((void *)(udp + 1) > data_end)
        return TC_ACT_OK;
        
    __u16 src_port = bpf_ntohs(udp->source);
    __u16 dst_port = bpf_ntohs(udp->dest);
    
    // 过滤端口 18082
    if (src_port == 18082 || dst_port == 18082) {
        struct packet_info info = {
            .src_ip = bpf_ntohl(ip->saddr),
            .dst_ip = bpf_ntohl(ip->daddr),
            .src_port = src_port,
            .dst_port = dst_port,
            .length = bpf_ntohs(udp->len),
        };
        
        bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, &info, sizeof(info));
    }
    
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
