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

#define DNAT_CAPTURE_MAX_BYTES 1600

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct unified_config));
    __uint(max_entries, 1);
} unified_config_map SEC(".maps");

struct icmp_nat_key {
    __u32 egress_ip;
    __u32 remote_ip;
    __u16 icmp_id;
    __u16 reserved;
} __attribute__((packed));

struct icmp_nat_entry {
    __u32 inner_src_ip;
    __u32 remote_ip;
    __u32 outer_src_ip;
    __u32 outer_dst_ip;
    __u16 inner_icmp_id;
    __u16 egress_icmp_id;
    __u16 outer_src_port;
    __u16 outer_dst_port;
    __u32 egress_ip;
    __u32 ingress_ifindex;
    __u8 vpn_first_byte;
    __u8 vpn_next_protocol;
    __u16 vpn_flags;
    __u32 vpn_session_id;
    __u64 timestamp;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct icmp_nat_key));
    __uint(value_size, sizeof(struct icmp_nat_entry));
    __uint(max_entries, 65536);
} icmp_dnat_map SEC(".maps");

struct dnat_capture_event {
    __u64 timestamp_ns;
    __u32 ifindex;
    __u32 packet_len;
    __u32 cap_len;
    __u32 reserved;
    __u8 data[DNAT_CAPTURE_MAX_BYTES];
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} dnat_capture_events SEC(".maps");

volatile __u64 stat_counters[256] = {0};

static __always_inline int is_first_egress_ip(struct unified_config *cfg, __u32 ip)
{
    return cfg->egress_ip_count > 0 && cfg->egress_ips[0] == ip;
}

static __always_inline void capture_dnat_packet(struct xdp_md *ctx, __u32 ifindex)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 packet_len64 = data_end - data;
    __u32 packet_len = (__u32)packet_len64;
    __u32 cap_len = DNAT_CAPTURE_MAX_BYTES;

    if (packet_len64 < DNAT_CAPTURE_MAX_BYTES) {
        cap_len = (__u32)packet_len64;
    }
    if (cap_len == 0) {
        return;
    }

    struct dnat_capture_event *event = bpf_ringbuf_reserve(&dnat_capture_events,
                                                           sizeof(*event), 0);
    if (!event) {
        return;
    }

    event->timestamp_ns = bpf_ktime_get_ns();
    event->ifindex = ifindex;
    event->packet_len = packet_len;
    event->cap_len = cap_len;
    event->reserved = 0;

    if (bpf_xdp_load_bytes(ctx, 0, event->data, cap_len)) {
        bpf_ringbuf_discard(event, 0);
        return;
    }

    bpf_ringbuf_submit(event, 0);
}

static __always_inline int dnat_public_icmp(struct xdp_md *ctx, struct iphdr *ip,
                                           struct unified_config *cfg,
                                           void *data_end)
{
    if (!is_first_egress_ip(cfg, ip->daddr)) {
        inc_pkt_stats(STATS_TYPE_XDP_PASS);
        return XDP_PASS;
    }

    __u32 ip_hlen = ip->ihl * 4;
    if (ip_hlen < sizeof(struct iphdr) || (void *)ip + ip_hlen > data_end) {
        inc_pkt_stats(STATS_TYPE_VPN_INNER_IP_ERROR);
        return XDP_PASS;
    }

    struct icmphdr *icmp = (void *)ip + ip_hlen;
    if ((void *)(icmp + 1) > data_end) {
        inc_pkt_stats(STATS_TYPE_VPN_INNER_ICMP_ERROR);
        return XDP_PASS;
    }
    if (icmp->type != ICMP_ECHOREPLY) {
        inc_pkt_stats(STATS_TYPE_XDP_PASS);
        return XDP_PASS;
    }

    struct icmp_nat_key key = {
        .egress_ip = ip->daddr,
        .remote_ip = ip->saddr,
        .icmp_id = icmp->un.echo.id,
    };

    struct icmp_nat_entry *entry = bpf_map_lookup_elem(&icmp_dnat_map, &key);
    if (!entry) {
        inc_pkt_stats(STATS_TYPE_VPN_ICMP_DNAT_MISS);
        return XDP_PASS;
    }

    __u16 inner_len = bpf_ntohs(ip->tot_len);
    if (inner_len < ip_hlen || inner_len > DNAT_CAPTURE_MAX_BYTES) {
        inc_pkt_stats(STATS_TYPE_VPN_INNER_IP_ERROR);
        return XDP_PASS;
    }

    __u32 inner_src_ip = entry->inner_src_ip;
    __u32 outer_src_ip = entry->outer_src_ip;
    __u32 outer_dst_ip = entry->outer_dst_ip;
    __u16 outer_src_port = entry->outer_src_port;
    __u16 outer_dst_port = entry->outer_dst_port;
    __u32 ingress_ifindex = entry->ingress_ifindex;
    __u8 vpn_first_byte = entry->vpn_first_byte;
    __u8 vpn_next_protocol = entry->vpn_next_protocol;
    __u16 vpn_flags = entry->vpn_flags;
    __u32 vpn_session_id = entry->vpn_session_id;

    ip->daddr = inner_src_ip;
    update_iph_checksum(ip);

    __u16 outer_payload_len = sizeof(struct udphdr) + sizeof(struct vpn_header) + inner_len;
    __u16 outer_total_len = sizeof(struct iphdr) + outer_payload_len;

    struct bpf_fib_lookup fib = {};
    fib.family = AF_INET;
    fib.tos = 0;
    fib.l4_protocol = IPPROTO_UDP;
    fib.tot_len = outer_total_len;
    fib.ipv4_src = outer_dst_ip;
    fib.ipv4_dst = outer_src_ip;
    fib.ifindex = ingress_ifindex;

    int rc = bpf_fib_lookup(ctx, &fib, sizeof(fib), BPF_FIB_LOOKUP_DIRECT);
    if (rc != BPF_FIB_LKUP_RET_SUCCESS) {
        inc_pkt_stats(STATS_TYPE_VPN_DNAT_FIB_LOOKUP_ERROR);
        return XDP_DROP;
    }

    int add_len = sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct vpn_header);
    if (bpf_xdp_adjust_head(ctx, 0 - add_len)) {
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

    struct iphdr *outer_ip = (void *)(new_eth + 1);
    if ((void *)(outer_ip + 1) > new_data_end) {
        inc_pkt_stats(STATS_TYPE_VPN_NEW_IP_ERROR);
        return XDP_DROP;
    }

    struct udphdr *outer_udp = (void *)(outer_ip + 1);
    if ((void *)(outer_udp + 1) > new_data_end) {
        inc_pkt_stats(STATS_TYPE_UDP_HEADER_ERROR);
        return XDP_DROP;
    }

    struct vpn_header *vpn = (void *)(outer_udp + 1);
    if ((void *)(vpn + 1) > new_data_end) {
        inc_pkt_stats(STATS_TYPE_VPN_HEADER_ERROR);
        return XDP_DROP;
    }

    struct iphdr *inner_ip = (void *)(vpn + 1);
    if ((void *)(inner_ip + 1) > new_data_end) {
        inc_pkt_stats(STATS_TYPE_VPN_INNER_IP_ERROR);
        return XDP_DROP;
    }

    __builtin_memset(outer_ip, 0, sizeof(*outer_ip));
    outer_ip->version = 4;
    outer_ip->ihl = 5;
    outer_ip->ttl = 64;
    outer_ip->protocol = IPPROTO_UDP;
    outer_ip->tot_len = bpf_htons(outer_total_len);
    outer_ip->saddr = outer_dst_ip;
    outer_ip->daddr = outer_src_ip;
    update_iph_checksum(outer_ip);

    outer_udp->source = outer_dst_port;
    outer_udp->dest = outer_src_port;
    outer_udp->len = bpf_htons(outer_payload_len);
    outer_udp->check = 0;

    vpn->first_byte = vpn_first_byte;
    vpn->next_protocol = vpn_next_protocol;
    vpn->flags = vpn_flags;
    vpn->session_id = vpn_session_id;

    __builtin_memcpy(new_eth->h_dest, fib.dmac, ETH_ALEN);
    __builtin_memcpy(new_eth->h_source, fib.smac, ETH_ALEN);
    new_eth->h_proto = bpf_htons(ETH_P_IP);

    inc_pkt_stats(STATS_TYPE_VPN_ICMP_DNAT);
    capture_dnat_packet(ctx, ingress_ifindex);
    return bpf_redirect(ingress_ifindex, 0);
}

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
    if (icmp->type != ICMP_ECHO) {
        inc_pkt_stats(STATS_TYPE_XDP_PASS);
        return XDP_PASS;
    }

    if (cfg->egress_ip_count == 0 || cfg->egress_ips[0] == 0) {
        inc_pkt_stats(STATS_TYPE_VPN_NO_EGRESS_IP);
        return XDP_PASS;
    }

    __u32 public_ip = cfg->egress_ips[0];
    __u16 icmp_id = icmp->un.echo.id;
    struct icmp_nat_key dnat_key = {
        .egress_ip = public_ip,
        .remote_ip = inner_ip->daddr,
        .icmp_id = icmp_id,
    };
    struct icmp_nat_entry dnat_entry = {
        .inner_src_ip = inner_ip->saddr,
        .remote_ip = inner_ip->daddr,
        .outer_src_ip = outer_ip->saddr,
        .outer_dst_ip = outer_ip->daddr,
        .inner_icmp_id = icmp_id,
        .egress_icmp_id = icmp_id,
        .outer_src_port = outer_udp->source,
        .outer_dst_port = outer_udp->dest,
        .egress_ip = public_ip,
        .ingress_ifindex = ctx->ingress_ifindex,
        .vpn_first_byte = vpn->first_byte,
        .vpn_next_protocol = vpn->next_protocol,
        .vpn_flags = vpn->flags,
        .vpn_session_id = vpn->session_id,
        .timestamp = bpf_ktime_get_ns(),
    };

    bpf_map_update_elem(&icmp_dnat_map, &dnat_key, &dnat_entry, BPF_ANY);

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

    if (ip->protocol == IPPROTO_ICMP) {
        return dnat_public_icmp(ctx, ip, cfg, data_end);
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
