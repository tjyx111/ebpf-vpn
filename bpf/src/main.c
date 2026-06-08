#include <linux/bpf.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include <xdp/app/udp_echo.h>
#include <xdp/common/unified_config.h>
#include <xdp/utils/csum.h>
#include <xdp/utils/stats.h>

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct unified_config));
    __uint(max_entries, 1);
} unified_config_map SEC(".maps");

volatile __u64 stat_counters[256] = {0};

static __always_inline int snat_vpn_icmp(struct xdp_md *ctx, struct iphdr *outer_ip,
                                         __u32 outer_ip_hlen, struct udphdr *outer_udp,
                                         struct unified_config *cfg, void *data_end)
{
    struct vpn_header *vpn = (void *)(outer_udp + 1);
    if ((void *)(vpn + 1) > data_end) {
        inc_pkt_stats(STATS_TYPE_VPN_HEADER_ERROR);
        return XDP_PASS;
    }

    if ((vpn->first_byte & VPN_MAGIC_MASK) != VPN_MAGIC_VALUE) {
        inc_pkt_stats(STATS_TYPE_XDP_PASS);
        return XDP_PASS;
    }

    inc_pkt_stats(STATS_TYPE_VPN);

    struct iphdr *inner_ip = (void *)(vpn + 1);
    if ((void *)(inner_ip + 1) > data_end) {
        inc_pkt_stats(STATS_TYPE_VPN_INNER_IP_ERROR);
        return XDP_PASS;
    }

    __u32 inner_ip_hlen = inner_ip->ihl * 4;
    if (inner_ip_hlen < sizeof(struct iphdr) || (void *)inner_ip + inner_ip_hlen > data_end) {
        inc_pkt_stats(STATS_TYPE_VPN_INNER_IP_ERROR);
        return XDP_PASS;
    }

    if (inner_ip->protocol != IPPROTO_ICMP) {
        inc_pkt_stats(STATS_TYPE_VPN_NON_ICMP);
        return XDP_PASS;
    }

    struct icmphdr *icmp = (void *)inner_ip + inner_ip_hlen;
    if ((void *)(icmp + 1) > data_end) {
        inc_pkt_stats(STATS_TYPE_VPN_INNER_ICMP_ERROR);
        return XDP_PASS;
    }

    if (cfg->egress_ip_count == 0 || cfg->egress_ips[0] == 0) {
        inc_pkt_stats(STATS_TYPE_VPN_NO_EGRESS_IP);
        return XDP_PASS;
    }

    __u32 public_ip = cfg->egress_ips[0];
    __u32 remove_len = sizeof(struct ethhdr) + outer_ip_hlen + sizeof(struct udphdr) +
                       sizeof(struct vpn_header);

    if (bpf_xdp_adjust_head(ctx, remove_len)) {
        inc_pkt_stats(STATS_TYPE_VPN_ADJUST_HEAD_ERROR);
        return XDP_DROP;
    }
    if (bpf_xdp_adjust_head(ctx, 0 - (int)sizeof(struct ethhdr))) {
        inc_pkt_stats(STATS_TYPE_VPN_ADJUST_HEAD_ERROR);
        return XDP_DROP;
    }

    void *new_data = (void *)(long)ctx->data;
    void *new_data_end = (void *)(long)ctx->data_end;

    struct ethhdr *new_eth = new_data;
    if ((void *)(new_eth + 1) > new_data_end) {
        inc_pkt_stats(STATS_TYPE_VPN_NEW_ETH_ERROR);
        return XDP_DROP;
    }

    struct iphdr *new_ip = (void *)(new_eth + 1);
    if ((void *)(new_ip + 1) > new_data_end) {
        inc_pkt_stats(STATS_TYPE_VPN_NEW_IP_ERROR);
        return XDP_DROP;
    }

    new_ip->saddr = public_ip;
    update_iph_checksum(new_ip);

    struct bpf_fib_lookup fib = {};
    fib.family = AF_INET;
    fib.tos = new_ip->tos;
    fib.l4_protocol = IPPROTO_ICMP;
    fib.tot_len = bpf_ntohs(new_ip->tot_len);
    fib.ipv4_src = new_ip->saddr;
    fib.ipv4_dst = new_ip->daddr;
    fib.ifindex = ctx->ingress_ifindex;

    int rc = bpf_fib_lookup(ctx, &fib, sizeof(fib), 0);
    if (rc != BPF_FIB_LKUP_RET_SUCCESS) {
        inc_pkt_stats(STATS_TYPE_VPN_FIB_LOOKUP_ERROR);
        return XDP_DROP;
    }

    __builtin_memcpy(new_eth->h_dest, fib.dmac, ETH_ALEN);
    __builtin_memcpy(new_eth->h_source, fib.smac, ETH_ALEN);
    new_eth->h_proto = bpf_htons(ETH_P_IP);

    inc_pkt_stats(STATS_TYPE_VPN_ICMP_ECHO);
    inc_pkt_stats(STATS_TYPE_VPN_ICMP_SNAT);
    return bpf_redirect(fib.ifindex, 0);
}

SEC("xdp")
int xdp_gateway(struct xdp_md *ctx) {
    inc_pkt_stats(STATS_TYPE_TOTAL_PACKETS);

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        inc_pkt_stats(STATS_TYPE_XDP_PASS);
        return XDP_PASS;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        inc_pkt_stats(STATS_TYPE_XDP_PASS);
        return XDP_PASS;
    }

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        inc_pkt_stats(STATS_TYPE_XDP_PASS);
        return XDP_PASS;
    }

    __u32 cfg_key = 0;
    struct unified_config *cfg = bpf_map_lookup_elem(&unified_config_map, &cfg_key);
    if (!cfg) {
        inc_pkt_stats(STATS_TYPE_XDP_PASS);
        return XDP_PASS;
    }

    if (ip->protocol != IPPROTO_UDP) {
        inc_pkt_stats(STATS_TYPE_XDP_PASS);
        return XDP_PASS;
    }

    __u32 outer_ip_hlen = ip->ihl * 4;
    if (outer_ip_hlen < sizeof(struct iphdr) || (void *)ip + outer_ip_hlen > data_end) {
        inc_pkt_stats(STATS_TYPE_XDP_PASS);
        return XDP_PASS;
    }

    struct udphdr *udp = (void *)ip + outer_ip_hlen;
    if ((void *)(udp + 1) > data_end) {
        inc_pkt_stats(STATS_TYPE_UDP_HEADER_ERROR);
        return XDP_PASS;
    }

    if (udp->dest == cfg->vpn_port) {
        return snat_vpn_icmp(ctx, ip, outer_ip_hlen, udp, cfg, data_end);
    }

    if (likely(cfg->flags & CFG_FLAG_UDP_ECHO_ENABLED) && udp->dest == cfg->udp_echo_port) {
        inc_pkt_stats(STATS_TYPE_UDP_ECHO);
        return xdp_udpecho(eth, ip, udp, data_end);
    }

    inc_pkt_stats(STATS_TYPE_XDP_PASS);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
