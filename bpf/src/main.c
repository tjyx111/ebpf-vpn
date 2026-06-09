#include <linux/bpf.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
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

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#define DNAT_CAPTURE_MAX_BYTES 1600
#define VPN_ENCAP_OVERHEAD (sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct vpn_header))
#define NAT_PORT_START 20000
#define NAT_PORT_END 50000
#define NAT_PORT_COUNT (NAT_PORT_END - NAT_PORT_START + 1)
#define NAT_PORT_PROBES 8
#define IPV4_MF 0x2000
#define IPV4_OFFSET_MASK 0x1fff

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct unified_config));
    __uint(max_entries, 1);
} unified_config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, MAX_EGRESS_IPS);
} egress_ip_map SEC(".maps");

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

struct l4_flow_key {
    __u8 protocol;
    __u8 reserved1;
    __u16 inner_src_port;
    __u32 inner_src_ip;
    __u32 remote_ip;
    __u16 remote_port;
    __u16 reserved2;
} __attribute__((packed));

struct l4_dnat_key {
    __u8 protocol;
    __u8 reserved1;
    __u16 egress_port;
    __u32 egress_ip;
    __u32 remote_ip;
    __u16 remote_port;
    __u16 reserved2;
} __attribute__((packed));

struct l4_nat_entry {
    __u32 inner_src_ip;
    __u32 remote_ip;
    __u32 outer_src_ip;
    __u32 outer_dst_ip;
    __u32 egress_ip;
    __u32 ingress_ifindex;
    __u16 inner_src_port;
    __u16 remote_port;
    __u16 egress_port;
    __u16 outer_src_port;
    __u16 outer_dst_port;
    __u8 protocol;
    __u8 vpn_first_byte;
    __u8 vpn_next_protocol;
    __u8 reserved;
    __u16 vpn_flags;
    __u16 reserved2;
    __u32 vpn_session_id;
    __u64 timestamp;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct l4_flow_key));
    __uint(value_size, sizeof(struct l4_nat_entry));
    __uint(max_entries, 65536);
} l4_snat_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct l4_dnat_key));
    __uint(value_size, sizeof(struct l4_nat_entry));
    __uint(max_entries, 65536);
} l4_dnat_map SEC(".maps");

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

static __always_inline int is_egress_ip(struct unified_config *cfg, __u32 ip)
{
    __u32 count = cfg->egress_ip_count;
    if (count == 0) {
        return 0;
    }
    if (count > MAX_EGRESS_IPS) {
        count = MAX_EGRESS_IPS;
    }

    __u32 target = bpf_ntohl(ip);
    __u32 left = 0;
    __u32 right = count - 1;

    for (__u32 i = 0; i < 6; i++) {
        if (left > right) {
            break;
        }

        __u32 mid = (left + right) >> 1;
        if (mid >= MAX_EGRESS_IPS) {
            break;
        }
        __u32 *current_ip = bpf_map_lookup_elem(&egress_ip_map, &mid);
        if (!current_ip) {
            break;
        }
        __u32 current = bpf_ntohl(*current_ip);
        if (target == current) {
            return 1;
        }
        if (target < current) {
            if (mid == 0) {
                break;
            }
            right = mid - 1;
        } else {
            left = mid + 1;
        }
    }

    return 0;
}

static __always_inline int is_ipv4_fragment(struct iphdr *ip)
{
    return ip->frag_off & bpf_htons(IPV4_MF | IPV4_OFFSET_MASK);
}

static __always_inline __u16 csum_replace2(__u16 csum, __u16 from, __u16 to)
{
    __u32 tmp = csum_sub((__u32)from, ~((__u32)csum));
    return csum_fold_helper(csum_add((__u32)to, tmp));
}

static __always_inline void update_l4_checksum(__u8 protocol, __u16 *check,
                                               __u32 old_ip, __u32 new_ip,
                                               __u16 old_port, __u16 new_port)
{
    if (protocol == IPPROTO_UDP && *check == 0) {
        return;
    }

    *check = csum_diff4(old_ip, new_ip, *check);
    *check = csum_replace2(*check, old_port, new_port);

    if (protocol == IPPROTO_UDP && *check == 0) {
        *check = 0xffff;
    }
}

static __always_inline __u32 hash_l4_flow(struct l4_flow_key *key)
{
    __u32 hash = 2166136261u;
    hash = (hash ^ key->protocol) * 16777619u;
    hash = (hash ^ key->inner_src_ip) * 16777619u;
    hash = (hash ^ key->remote_ip) * 16777619u;
    hash = (hash ^ key->inner_src_port) * 16777619u;
    hash = (hash ^ key->remote_port) * 16777619u;
    return hash;
}

static __always_inline int same_l4_flow(struct l4_nat_entry *entry, struct l4_flow_key *key)
{
    return entry->protocol == key->protocol &&
           entry->inner_src_ip == key->inner_src_ip &&
           entry->remote_ip == key->remote_ip &&
           entry->inner_src_port == key->inner_src_port &&
           entry->remote_port == key->remote_port;
}

static __always_inline __u16 allocate_l4_port(struct unified_config *cfg,
                                              struct l4_flow_key *flow_key,
                                              __u32 public_ip)
{
    __u32 hash = hash_l4_flow(flow_key);

#pragma clang loop unroll(full)
    for (__u32 i = 0; i < NAT_PORT_PROBES; i++) {
        __u32 port_host = NAT_PORT_START + ((hash + i) % NAT_PORT_COUNT);
        if (port_host == bpf_ntohs(cfg->vpn_port) || port_host == bpf_ntohs(cfg->udp_echo_port)) {
            continue;
        }

        __u16 port = bpf_htons((__u16)port_host);
        struct l4_dnat_key dnat_key = {
            .protocol = flow_key->protocol,
            .egress_port = port,
            .egress_ip = public_ip,
            .remote_ip = flow_key->remote_ip,
            .remote_port = flow_key->remote_port,
        };
        struct l4_nat_entry *existing = bpf_map_lookup_elem(&l4_dnat_map, &dnat_key);
        if (!existing || same_l4_flow(existing, flow_key)) {
            return port;
        }
    }

    return 0;
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
    if (!is_egress_ip(cfg, ip->daddr)) {
        inc_pkt_stats(STATS_TYPE_XDP_PASS);
        return XDP_PASS;
    }
    if (is_ipv4_fragment(ip)) {
        inc_pkt_stats(STATS_TYPE_VPN_FRAGMENT_PASS);
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
    if (inner_len + VPN_ENCAP_OVERHEAD > cfg->mtu) {
        inc_pkt_stats(STATS_TYPE_VPN_MTU_PASS);
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
    if (unlikely(cfg->flags & CFG_FLAG_DNAT_CAPTURE_ENABLED)) {
        capture_dnat_packet(ctx, ingress_ifindex);
    }
    return bpf_redirect(ingress_ifindex, 0);
}

static __always_inline int dnat_public_l4(struct xdp_md *ctx, struct iphdr *ip,
                                         struct unified_config *cfg,
                                         void *data_end)
{
    if (!is_egress_ip(cfg, ip->daddr)) {
        inc_pkt_stats(STATS_TYPE_XDP_PASS);
        return XDP_PASS;
    }
    if (is_ipv4_fragment(ip)) {
        inc_pkt_stats(STATS_TYPE_VPN_FRAGMENT_PASS);
        return XDP_PASS;
    }

    __u8 protocol = ip->protocol;
    if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) {
        inc_pkt_stats(STATS_TYPE_XDP_PASS);
        return XDP_PASS;
    }

    __u32 ip_hlen = ip->ihl * 4;
    if (ip_hlen < sizeof(struct iphdr) || (void *)ip + ip_hlen > data_end) {
        inc_pkt_stats(STATS_TYPE_VPN_INNER_IP_ERROR);
        return XDP_PASS;
    }

    __u16 src_port = 0;
    __u16 dst_port = 0;
    __u16 *l4_check = 0;

    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip_hlen;
        if ((void *)(tcp + 1) > data_end) {
            inc_pkt_stats(STATS_TYPE_UDP_HEADER_ERROR);
            return XDP_PASS;
        }
        src_port = tcp->source;
        dst_port = tcp->dest;
        l4_check = &tcp->check;
    } else {
        struct udphdr *udp = (void *)ip + ip_hlen;
        if ((void *)(udp + 1) > data_end) {
            inc_pkt_stats(STATS_TYPE_UDP_HEADER_ERROR);
            return XDP_PASS;
        }
        src_port = udp->source;
        dst_port = udp->dest;
        l4_check = &udp->check;
    }

    struct l4_dnat_key key = {
        .protocol = protocol,
        .egress_port = dst_port,
        .egress_ip = ip->daddr,
        .remote_ip = ip->saddr,
        .remote_port = src_port,
    };

    struct l4_nat_entry *entry = bpf_map_lookup_elem(&l4_dnat_map, &key);
    if (!entry) {
        inc_pkt_stats(STATS_TYPE_VPN_ICMP_DNAT_MISS);
        return XDP_PASS;
    }

    __u16 inner_len = bpf_ntohs(ip->tot_len);
    if (inner_len < ip_hlen || inner_len > DNAT_CAPTURE_MAX_BYTES) {
        inc_pkt_stats(STATS_TYPE_VPN_INNER_IP_ERROR);
        return XDP_PASS;
    }
    if (inner_len + VPN_ENCAP_OVERHEAD > cfg->mtu) {
        inc_pkt_stats(STATS_TYPE_VPN_MTU_PASS);
        return XDP_PASS;
    }

    __u32 old_dst_ip = ip->daddr;
    __u16 old_dst_port = dst_port;
    __u32 inner_src_ip = entry->inner_src_ip;
    __u16 inner_src_port = entry->inner_src_port;
    __u32 outer_src_ip = entry->outer_src_ip;
    __u32 outer_dst_ip = entry->outer_dst_ip;
    __u16 outer_src_port = entry->outer_src_port;
    __u16 outer_dst_port = entry->outer_dst_port;
    __u32 ingress_ifindex = entry->ingress_ifindex;
    __u8 vpn_first_byte = entry->vpn_first_byte;
    __u8 vpn_next_protocol = entry->vpn_next_protocol;
    __u16 vpn_flags = entry->vpn_flags;
    __u32 vpn_session_id = entry->vpn_session_id;

    update_l4_checksum(protocol, l4_check, old_dst_ip, inner_src_ip,
                       old_dst_port, inner_src_port);
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip_hlen;
        tcp->dest = inner_src_port;
    } else {
        struct udphdr *udp = (void *)ip + ip_hlen;
        udp->dest = inner_src_port;
    }
    ip->daddr = inner_src_ip;
    update_iph_checksum(ip);

    __u16 outer_payload_len = sizeof(struct udphdr) + sizeof(struct vpn_header) + inner_len;
    __u16 outer_total_len = sizeof(struct iphdr) + outer_payload_len;

    int add_len = VPN_ENCAP_OVERHEAD;
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

    __builtin_memset(new_eth->h_dest, 0, ETH_ALEN);
    __builtin_memset(new_eth->h_source, 0, ETH_ALEN);
    new_eth->h_proto = bpf_htons(ETH_P_IP);

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
        if (unlikely(cfg->flags & CFG_FLAG_DNAT_CAPTURE_ENABLED)) {
            capture_dnat_packet(ctx, ingress_ifindex);
        }
        inc_pkt_stats(STATS_TYPE_VPN_DNAT_FIB_LOOKUP_ERROR);
        return XDP_DROP;
    }

    __builtin_memcpy(new_eth->h_dest, fib.dmac, ETH_ALEN);
    __builtin_memcpy(new_eth->h_source, fib.smac, ETH_ALEN);

    inc_pkt_stats(STATS_TYPE_VPN_L4_DNAT);
    if (unlikely(cfg->flags & CFG_FLAG_DNAT_CAPTURE_ENABLED)) {
        capture_dnat_packet(ctx, ingress_ifindex);
    }
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

    if (is_ipv4_fragment(inner_ip)) {
        inc_pkt_stats(STATS_TYPE_VPN_FRAGMENT_PASS);
        return XDP_PASS;
    }

    if (inner_ip->protocol != IPPROTO_ICMP &&
        inner_ip->protocol != IPPROTO_TCP &&
        inner_ip->protocol != IPPROTO_UDP) {
        inc_pkt_stats(STATS_TYPE_VPN_NON_ICMP);
        return XDP_PASS;
    }

    if (cfg->egress_ip_count == 0 || cfg->egress_ips[0] == 0) {
        inc_pkt_stats(STATS_TYPE_VPN_NO_EGRESS_IP);
        return XDP_PASS;
    }

    __u32 public_ip = cfg->egress_ips[0];

    if (inner_ip->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmp = (void *)inner_ip + inner_ip_hlen;
        if ((void *)(icmp + 1) > data_end) {
            inc_pkt_stats(STATS_TYPE_VPN_INNER_ICMP_ERROR);
            return XDP_PASS;
        }
        if (icmp->type != ICMP_ECHO) {
            inc_pkt_stats(STATS_TYPE_XDP_PASS);
            return XDP_PASS;
        }

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
    } else {
        __u8 protocol = inner_ip->protocol;
        __u16 inner_src_port = 0;
        __u16 remote_port = 0;
        __u16 *l4_check = 0;

        if (protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)inner_ip + inner_ip_hlen;
            if ((void *)(tcp + 1) > data_end) {
                inc_pkt_stats(STATS_TYPE_UDP_HEADER_ERROR);
                return XDP_PASS;
            }
            inner_src_port = tcp->source;
            remote_port = tcp->dest;
            l4_check = &tcp->check;
        } else {
            struct udphdr *udp = (void *)inner_ip + inner_ip_hlen;
            if ((void *)(udp + 1) > data_end) {
                inc_pkt_stats(STATS_TYPE_UDP_HEADER_ERROR);
                return XDP_PASS;
            }
            inner_src_port = udp->source;
            remote_port = udp->dest;
            l4_check = &udp->check;
        }

        struct l4_flow_key flow_key = {
            .protocol = protocol,
            .inner_src_port = inner_src_port,
            .inner_src_ip = inner_ip->saddr,
            .remote_ip = inner_ip->daddr,
            .remote_port = remote_port,
        };

        struct l4_nat_entry *existing = bpf_map_lookup_elem(&l4_snat_map, &flow_key);
        __u16 egress_port = 0;
        struct l4_nat_entry nat_entry = {};

        if (existing) {
            egress_port = existing->egress_port;
            __builtin_memcpy(&nat_entry, existing, sizeof(nat_entry));
            nat_entry.timestamp = bpf_ktime_get_ns();
        } else {
            egress_port = allocate_l4_port(cfg, &flow_key, public_ip);
            if (egress_port == 0) {
                inc_pkt_stats(STATS_TYPE_VPN_PORT_ALLOC_MISS);
                return XDP_PASS;
            }

            nat_entry.inner_src_ip = inner_ip->saddr;
            nat_entry.remote_ip = inner_ip->daddr;
            nat_entry.outer_src_ip = outer_ip->saddr;
            nat_entry.outer_dst_ip = outer_ip->daddr;
            nat_entry.egress_ip = public_ip;
            nat_entry.ingress_ifindex = ctx->ingress_ifindex;
            nat_entry.inner_src_port = inner_src_port;
            nat_entry.remote_port = remote_port;
            nat_entry.egress_port = egress_port;
            nat_entry.outer_src_port = outer_udp->source;
            nat_entry.outer_dst_port = outer_udp->dest;
            nat_entry.protocol = protocol;
            nat_entry.vpn_first_byte = vpn->first_byte;
            nat_entry.vpn_next_protocol = vpn->next_protocol;
            nat_entry.vpn_flags = vpn->flags;
            nat_entry.vpn_session_id = vpn->session_id;
            nat_entry.timestamp = bpf_ktime_get_ns();
        }

        struct l4_dnat_key dnat_key = {
            .protocol = protocol,
            .egress_port = egress_port,
            .egress_ip = public_ip,
            .remote_ip = inner_ip->daddr,
            .remote_port = remote_port,
        };

        bpf_map_update_elem(&l4_snat_map, &flow_key, &nat_entry, BPF_ANY);
        bpf_map_update_elem(&l4_dnat_map, &dnat_key, &nat_entry, BPF_ANY);

        update_l4_checksum(protocol, l4_check, inner_ip->saddr, public_ip,
                           inner_src_port, egress_port);
        if (protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)inner_ip + inner_ip_hlen;
            tcp->source = egress_port;
        } else {
            struct udphdr *udp = (void *)inner_ip + inner_ip_hlen;
            udp->source = egress_port;
        }
    }

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
    fib.l4_protocol = new_ip->protocol;
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

    if (new_ip->protocol == IPPROTO_ICMP) {
        inc_pkt_stats(STATS_TYPE_VPN_ICMP_ECHO);
        inc_pkt_stats(STATS_TYPE_VPN_ICMP_SNAT);
    } else {
        inc_pkt_stats(STATS_TYPE_VPN_L4_SNAT);
    }
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
        inc_pkt_stats(STATS_TYPE_NON_IPV4_PASS);
        inc_pkt_stats(STATS_TYPE_XDP_PASS);
        return XDP_PASS;
    }

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        inc_pkt_stats(STATS_TYPE_XDP_PASS);
        return XDP_PASS;
    }

    __u32 ip_hlen = ip->ihl * 4;
    if (ip->version != 4 || ip_hlen < sizeof(struct iphdr) ||
        (void *)ip + ip_hlen > data_end) {
        inc_pkt_stats(STATS_TYPE_XDP_PASS);
        return XDP_PASS;
    }

    if (is_ipv4_fragment(ip)) {
        inc_pkt_stats(STATS_TYPE_IPV4_FRAGMENT_PASS);
        inc_pkt_stats(STATS_TYPE_XDP_PASS);
        return XDP_PASS;
    }

    __u32 cfg_key = 0;
    struct unified_config *cfg = bpf_map_lookup_elem(&unified_config_map, &cfg_key);
    if (!cfg) {
        inc_pkt_stats(STATS_TYPE_XDP_PASS);
        return XDP_PASS;
    }

    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + ip_hlen;
        if ((void *)(udp + 1) > data_end) {
            inc_pkt_stats(STATS_TYPE_UDP_HEADER_ERROR);
            return XDP_PASS;
        }

        if (udp->dest == cfg->vpn_port) {
            return snat_vpn_icmp(ctx, ip, ip_hlen, udp, cfg, data_end);
        }

        if (unlikely((cfg->flags & CFG_FLAG_UDP_ECHO_ENABLED) &&
                     udp->dest == cfg->udp_echo_port)) {
            inc_pkt_stats(STATS_TYPE_UDP_ECHO);
            return xdp_udpecho(eth, ip, udp, data_end);
        }
    }

    if (!is_egress_ip(cfg, ip->daddr)) {
        inc_pkt_stats(STATS_TYPE_XDP_PASS);
        return XDP_PASS;
    }

    if (ip->protocol == IPPROTO_ICMP) {
        return dnat_public_icmp(ctx, ip, cfg, data_end);
    }

    if (ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP) {
        return dnat_public_l4(ctx, ip, cfg, data_end);
    }

    inc_pkt_stats(STATS_TYPE_XDP_PASS);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
