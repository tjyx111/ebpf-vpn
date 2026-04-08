#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <xdp/app/udp_echo.h>
#include <xdp/app/trace.h>
#include <xdp/common/all.h>

// 引入结构体定义
#include <xdp/common/unified_config.h>
#include <xdp/common/capture_rule.h>

// 统一配置 Map（包含所有配置，只有一个条目）
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct unified_config));
    __uint(max_entries, 1);
} unified_config_map SEC(".maps");

// 抓包规则 Map（保持16条规则不变）
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct capture_rule));
    __uint(max_entries, 16);  // 支持最多 16 条抓包规则
} capture_rule_map SEC(".maps");

// SNAT 映射表（key: 内层五元组 hash）
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(struct snat_entry));
    __uint(max_entries, 65536);
} snat_map SEC(".maps");

// DNAT 映射表（key: 外层五元组 hash）
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(struct dnat_entry));
    __uint(max_entries, 65536);
} dnat_map SEC(".maps");

// Helper 函数：匹配单条抓包规则
static __always_inline int match_single_rule(struct capture_rule *rule,
                                              __u32 src_ip,
                                              __u32 dst_ip,
                                              __u16 src_port,
                                              __u16 dst_port,
                                              __u8 protocol) {
    if (!rule)
        return 0;

    // 检查规则是否已设置（reserved[0] 作为标志位）
    if (rule->reserved[0] == 0) {
        return 0;  // 未设置的槽位，跳过
    }

    // 检查协议
    if (rule->protocol && protocol != rule->protocol)
        return 0;

    // 检查源IP
    if (rule->src_ip && ((src_ip & rule->src_ip_mask) != (rule->src_ip & rule->src_ip_mask)))
        return 0;

    // 检查目标IP
    if (rule->dst_ip && ((dst_ip & rule->dst_ip_mask) != (rule->dst_ip & rule->dst_ip_mask)))
        return 0;

    // 检查源端口
    if (rule->src_port && ((src_port & rule->src_port_mask) != (rule->src_port & rule->src_port_mask)))
        return 0;

    // 检查目标端口
    if (rule->dst_port && ((dst_port & rule->dst_port_mask) != (rule->dst_port & rule->dst_port_mask)))
        return 0;

    return 1;  // 匹配成功
}

// Helper 函数：匹配所有抓包规则（遍历所有规则）
static __always_inline int match_any_capture_rule(__u32 src_ip,
                                                   __u32 dst_ip,
                                                   __u16 src_port,
                                                   __u16 dst_port,
                                                   __u8 protocol) {
    int matched = 0;
    int has_rules = 0;

    // 遍历所有规则，只要有一条匹配就返回 1
    for (int i = 0; i < 16; i++) {
        __u32 key = i;
        struct capture_rule *rule = bpf_map_lookup_elem(&capture_rule_map, &key);
        if (rule && rule->reserved[0]) {
            has_rules = 1;
            if (match_single_rule(rule, src_ip, dst_ip, src_port, dst_port, protocol)) {
                matched = 1;
                break;
            }
        }
    }

    // 如果没有配置任何规则，默认不抓取（返回 0）
    if (!has_rules)
        return 0;

    return matched;
}

// Helper 函数：计算五元组 hash
static __always_inline __u64 hash_tuple(__u32 src_ip, __u16 src_port,
                                         __u32 dst_ip, __u16 dst_port,
                                         __u8 protocol) {
    __u64 hash = 0;
    hash = (__u64)src_ip * 31 + dst_ip;
    hash = hash * 31 + src_port;
    hash = hash * 31 + dst_port;
    hash = hash * 31 + protocol;
    return hash;
}

// 检测并记录 SNAT 会话（VPN 报文 → 公网报文）
static __always_inline int detect_and_log_snat(struct xdp_md *ctx,
                                                  struct iphdr *outer_ip,
                                                  struct udphdr *outer_udp,
                                                  void *data_end,
                                                  struct unified_config *cfg) {
    // 1. 检查 VPN 头部
    struct vpn_header *vpn = (void *)(outer_udp + 1);
    if ((void *)(vpn + 1) > data_end)
        return XDP_PASS;

    if ((vpn->first_byte & VPN_MAGIC_MASK) != VPN_MAGIC_VALUE)
        return XDP_PASS;  // 不是 VPN 报文

    bpf_trace_printk("=== SNAT DETECTED ===\n", sizeof("=== SNAT DETECTED ===\n"));

    // 2. 提取内层 IP 包
    struct iphdr *inner_ip = (void *)(vpn + 1);
    if ((void *)(inner_ip + 1) > data_end)
        return XDP_PASS;

    if (inner_ip->protocol != IPPROTO_UDP && inner_ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // 3. 提取内层端口
    __u16 inner_src_port = 0, inner_dst_port = 0;
    if (inner_ip->protocol == IPPROTO_UDP) {
        struct udphdr *inner_udp = (void *)(inner_ip + 1);
        if ((void *)(inner_udp + 1) > data_end) return XDP_PASS;
        inner_src_port = inner_udp->source;
        inner_dst_port = inner_udp->dest;
    } else if (inner_ip->protocol == IPPROTO_TCP) {
        struct tcphdr *inner_tcp = (void *)(inner_ip + 1);
        if ((void *)(inner_tcp + 1) > data_end) return XDP_PASS;
        inner_src_port = inner_tcp->source;
        inner_dst_port = inner_tcp->dest;
    }

    // 5. 打印内层五元组
    bpf_trace_printk("Inner: %x:%d -> %x:%d\n",
                     sizeof("Inner: %x:%d -> %x:%d\n"),
                     inner_ip->saddr, bpf_ntohs(inner_src_port),
                     inner_ip->daddr);
    bpf_trace_printk("Inner dst: %d proto=%d\n",
                     sizeof("Inner dst: %d proto=%d\n"),
                     bpf_ntohs(inner_dst_port), inner_ip->protocol);

    // 6. 检查端口范围
    __u16 outer_src_port = bpf_ntohs(inner_src_port);
    if (outer_src_port < cfg->port_start || outer_src_port > cfg->port_end) {
        bpf_trace_printk("Port %d not in range [%d,%d]\n",
                         sizeof("Port %d not in range [%d,%d]\n"),
                         outer_src_port, cfg->port_start, cfg->port_end);
        return XDP_PASS;
    }

    // 检查预留端口（展开循环）
    if (cfg->reserved_count > 0 && cfg->reserved_ports[0] == outer_src_port)
        { bpf_trace_printk("Port %d reserved\n", sizeof("Port %d reserved\n"), outer_src_port); return XDP_PASS; }
    if (cfg->reserved_count > 1 && cfg->reserved_ports[1] == outer_src_port)
        { bpf_trace_printk("Port %d reserved\n", sizeof("Port %d reserved\n"), outer_src_port); return XDP_PASS; }
    if (cfg->reserved_count > 2 && cfg->reserved_ports[2] == outer_src_port)
        { bpf_trace_printk("Port %d reserved\n", sizeof("Port %d reserved\n"), outer_src_port); return XDP_PASS; }
    if (cfg->reserved_count > 3 && cfg->reserved_ports[3] == outer_src_port)
        { bpf_trace_printk("Port %d reserved\n", sizeof("Port %d reserved\n"), outer_src_port); return XDP_PASS; }
    if (cfg->reserved_count > 4 && cfg->reserved_ports[4] == outer_src_port)
        { bpf_trace_printk("Port %d reserved\n", sizeof("Port %d reserved\n"), outer_src_port); return XDP_PASS; }
    if (cfg->reserved_count > 5 && cfg->reserved_ports[5] == outer_src_port)
        { bpf_trace_printk("Port %d reserved\n", sizeof("Port %d reserved\n"), outer_src_port); return XDP_PASS; }
    if (cfg->reserved_count > 6 && cfg->reserved_ports[6] == outer_src_port)
        { bpf_trace_printk("Port %d reserved\n", sizeof("Port %d reserved\n"), outer_src_port); return XDP_PASS; }
    if (cfg->reserved_count > 7 && cfg->reserved_ports[7] == outer_src_port)
        { bpf_trace_printk("Port %d reserved\n", sizeof("Port %d reserved\n"), outer_src_port); return XDP_PASS; }
    if (cfg->reserved_count > 8 && cfg->reserved_ports[8] == outer_src_port)
        { bpf_trace_printk("Port %d reserved\n", sizeof("Port %d reserved\n"), outer_src_port); return XDP_PASS; }
    if (cfg->reserved_count > 9 && cfg->reserved_ports[9] == outer_src_port)
        { bpf_trace_printk("Port %d reserved\n", sizeof("Port %d reserved\n"), outer_src_port); return XDP_PASS; }
    if (cfg->reserved_count > 10 && cfg->reserved_ports[10] == outer_src_port)
        { bpf_trace_printk("Port %d reserved\n", sizeof("Port %d reserved\n"), outer_src_port); return XDP_PASS; }
    if (cfg->reserved_count > 11 && cfg->reserved_ports[11] == outer_src_port)
        { bpf_trace_printk("Port %d reserved\n", sizeof("Port %d reserved\n"), outer_src_port); return XDP_PASS; }
    if (cfg->reserved_count > 12 && cfg->reserved_ports[12] == outer_src_port)
        { bpf_trace_printk("Port %d reserved\n", sizeof("Port %d reserved\n"), outer_src_port); return XDP_PASS; }
    if (cfg->reserved_count > 13 && cfg->reserved_ports[13] == outer_src_port)
        { bpf_trace_printk("Port %d reserved\n", sizeof("Port %d reserved\n"), outer_src_port); return XDP_PASS; }
    if (cfg->reserved_count > 14 && cfg->reserved_ports[14] == outer_src_port)
        { bpf_trace_printk("Port %d reserved\n", sizeof("Port %d reserved\n"), outer_src_port); return XDP_PASS; }
    if (cfg->reserved_count > 15 && cfg->reserved_ports[15] == outer_src_port)
        { bpf_trace_printk("Port %d reserved\n", sizeof("Port %d reserved\n"), outer_src_port); return XDP_PASS; }

    // 7. 选择公网 IP（通过 hash）
    __u32 ip_count = cfg->egress_ip_count;
    if (ip_count == 0) {
        bpf_trace_printk("No egress IPs configured\n", sizeof("No egress IPs configured\n"));
        return XDP_PASS;
    }

    __u32 ip_index = inner_ip->saddr % ip_count;
    __u32 outer_src_ip = cfg->egress_ips[ip_index];

    bpf_trace_printk("Selected public IP: %x (index=%d)\n",
                     sizeof("Selected public IP: %x (index=%d)\n"),
                     outer_src_ip, ip_index);

    // 8. 计算内层五元组 hash，查找/创建 SNAT 条目
    __u64 snat_key = hash_tuple(inner_ip->saddr, inner_src_port,
                                 inner_ip->daddr, inner_dst_port,
                                 inner_ip->protocol);

    struct snat_entry *snat = bpf_map_lookup_elem(&snat_map, &snat_key);

    if (snat) {
        // 检查超时
        __u64 now = bpf_ktime_get_ns();
        if (now - snat->timestamp > cfg->timeout_ns) {
            bpf_trace_printk("SNAT entry expired, deleting\n", sizeof("SNAT entry expired, deleting\n"));
            bpf_map_delete_elem(&snat_map, &snat_key);
            snat = NULL;
        } else {
            bpf_trace_printk("Existing SNAT entry found, timestamp=%llu\n",
                             sizeof("Existing SNAT entry found, timestamp=%llu\n"),
                             snat->timestamp);
        }
    }

    if (!snat) {
        // 9. 创建新的 SNAT 条目
        struct snat_entry new_snat = {
            .inner_src_ip = inner_ip->saddr,
            .inner_src_port = inner_src_port,
            .inner_dst_ip = inner_ip->daddr,
            .inner_dst_port = inner_dst_port,
            .inner_protocol = inner_ip->protocol,
            .outer_src_ip = outer_src_ip,
            .outer_src_port = inner_src_port,
            .egress_iface = cfg->egress_iface,
            .timestamp = bpf_ktime_get_ns(),
        };

        if (bpf_map_update_elem(&snat_map, &snat_key, &new_snat, BPF_ANY) == 0) {
            bpf_trace_printk("Created SNAT entry\n", sizeof("Created SNAT entry\n"));
            bpf_trace_printk("  inner src: %x:%d\n",
                             sizeof("  inner src: %x:%d\n"),
                             new_snat.inner_src_ip, bpf_ntohs(new_snat.inner_src_port));
            bpf_trace_printk("  inner dst: %x:%d\n",
                             sizeof("  inner dst: %x:%d\n"),
                             new_snat.inner_dst_ip, bpf_ntohs(new_snat.inner_dst_port));
            bpf_trace_printk("  outer: %x:%d iface=%d\n",
                             sizeof("  outer: %x:%d iface=%d\n"),
                             new_snat.outer_src_ip, bpf_ntohs(new_snat.outer_src_port),
                             new_snat.egress_iface);
        } else {
            bpf_trace_printk("Failed to create SNAT entry\n", sizeof("Failed to create SNAT entry\n"));
        }
    }

    // 丢弃数据包（只记录会话，不做实际转发）
    bpf_trace_printk("SNAT: Dropping packet after logging session\n",
                     sizeof("SNAT: Dropping packet after logging session\n"));

    return XDP_DROP;
}

// 检测并记录 DNAT 会话（公网报文 → VPN 报文）
static __always_inline int detect_and_log_dnat(struct iphdr *ip,
                                                  void *data_end,
                                                  struct unified_config *cfg) {
    // 只处理 TCP/UDP
    if (ip->protocol != IPPROTO_UDP && ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // 提取传输层
    void *l4 = (void *)(ip + 1);
    __u16 src_port = 0, dst_port = 0;

    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end) return XDP_PASS;
        src_port = udp->source;
        dst_port = udp->dest;
    } else if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end) return XDP_PASS;
        src_port = tcp->source;
        dst_port = tcp->dest;
    }

    // 1. 检查目标 IP 是否是我们的公网 IP
    __u32 is_public_ip = 0;
    if (cfg->egress_ip_count > 0 && ip->daddr == cfg->egress_ips[0])
        { is_public_ip = 1; }
    if (cfg->egress_ip_count > 1 && ip->daddr == cfg->egress_ips[1])
        { is_public_ip = 1; }
    if (cfg->egress_ip_count > 2 && ip->daddr == cfg->egress_ips[2])
        { is_public_ip = 1; }
    if (cfg->egress_ip_count > 3 && ip->daddr == cfg->egress_ips[3])
        { is_public_ip = 1; }
    if (cfg->egress_ip_count > 4 && ip->daddr == cfg->egress_ips[4])
        { is_public_ip = 1; }
    if (cfg->egress_ip_count > 5 && ip->daddr == cfg->egress_ips[5])
        { is_public_ip = 1; }
    if (cfg->egress_ip_count > 6 && ip->daddr == cfg->egress_ips[6])
        { is_public_ip = 1; }
    if (cfg->egress_ip_count > 7 && ip->daddr == cfg->egress_ips[7])
        { is_public_ip = 1; }
    if (cfg->egress_ip_count > 8 && ip->daddr == cfg->egress_ips[8])
        { is_public_ip = 1; }
    if (cfg->egress_ip_count > 9 && ip->daddr == cfg->egress_ips[9])
        { is_public_ip = 1; }
    if (cfg->egress_ip_count > 10 && ip->daddr == cfg->egress_ips[10])
        { is_public_ip = 1; }
    if (cfg->egress_ip_count > 11 && ip->daddr == cfg->egress_ips[11])
        { is_public_ip = 1; }
    if (cfg->egress_ip_count > 12 && ip->daddr == cfg->egress_ips[12])
        { is_public_ip = 1; }
    if (cfg->egress_ip_count > 13 && ip->daddr == cfg->egress_ips[13])
        { is_public_ip = 1; }
    if (cfg->egress_ip_count > 14 && ip->daddr == cfg->egress_ips[14])
        { is_public_ip = 1; }
    if (cfg->egress_ip_count > 15 && ip->daddr == cfg->egress_ips[15])
        { is_public_ip = 1; }

    if (!is_public_ip)
        return XDP_PASS;

    bpf_trace_printk("=== DNAT DETECTED ===\n", sizeof("=== DNAT DETECTED ===\n"));

    // 2. 打印外层五元组
    bpf_trace_printk("Outer src: %x:%d\n",
                     sizeof("Outer src: %x:%d\n"),
                     ip->saddr, bpf_ntohs(src_port));
    bpf_trace_printk("Outer dst: %x:%d proto=%d\n",
                     sizeof("Outer dst: %x:%d proto=%d\n"),
                     ip->daddr, bpf_ntohs(dst_port),
                     ip->protocol);

    // 3. 查找 DNAT 条目
    __u64 dnat_key = hash_tuple(ip->saddr, src_port, ip->daddr, dst_port, ip->protocol);
    struct dnat_entry *dnat = bpf_map_lookup_elem(&dnat_map, &dnat_key);

    if (!dnat) {
        bpf_trace_printk("No DNAT entry found\n", sizeof("No DNAT entry found\n"));
        return XDP_PASS;
    }

    // 4. 检查超时
    __u64 now = bpf_ktime_get_ns();
    if (now - dnat->timestamp > cfg->timeout_ns) {
        bpf_trace_printk("DNAT entry expired\n", sizeof("DNAT entry expired\n"));
        // 删除过期条目
        bpf_map_delete_elem(&dnat_map, &dnat_key);
        // 删除对应的 SNAT 条目
        __u64 snat_key = hash_tuple(dnat->inner_src_ip, dnat->inner_src_port,
                                     dnat->inner_dst_ip, dnat->inner_dst_port,
                                     dnat->inner_protocol);
        bpf_map_delete_elem(&snat_map, &snat_key);
        return XDP_PASS;
    }

    // 5. 打印 DNAT 映射信息
    bpf_trace_printk("DNAT entry found:\n", sizeof("DNAT entry found:\n"));
    bpf_trace_printk("  outer src: %x:%d\n",
                     sizeof("  outer src: %x:%d\n"),
                     dnat->outer_src_ip, bpf_ntohs(dnat->outer_src_port));
    bpf_trace_printk("  outer dst: %x:%d\n",
                     sizeof("  outer dst: %x:%d\n"),
                     dnat->outer_dst_ip, bpf_ntohs(dnat->outer_dst_port));
    bpf_trace_printk("  inner src: %x:%d\n",
                     sizeof("  inner src: %x:%d\n"),
                     dnat->inner_src_ip, bpf_ntohs(dnat->inner_src_port));
    bpf_trace_printk("  inner dst: %x:%d\n",
                     sizeof("  inner dst: %x:%d\n"),
                     dnat->inner_dst_ip, bpf_ntohs(dnat->inner_dst_port));
    bpf_trace_printk("  vpn: %x:%d iface=%d\n",
                     sizeof("  vpn: %x:%d iface=%d\n"),
                     dnat->vpn_server_ip, dnat->vpn_server_port,
                     dnat->ingress_iface);

    // 丢弃数据包（只记录会话，不做实际转发）
    bpf_trace_printk("DNAT: Dropping packet after logging session\n",
                     sizeof("DNAT: Dropping packet after logging session\n"));

    return XDP_DROP;
}

SEC("xdp")
int xdp_gateway(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    // ========== 入口处一次性加载配置 ==========
    __u32 cfg_key = 0;
    struct unified_config *cfg = bpf_map_lookup_elem(&unified_config_map, &cfg_key);
    if (!cfg) {
        return XDP_PASS;
    }

    // 复制到栈变量（避免验证器边界检查）
    __u8 flags = cfg->flags;

    // 抓包逻辑（只有开启时才查询抓包规则 Map）
    if (flags & CFG_FLAG_TRACE_ENABLED) {
        if (ip->protocol == IPPROTO_UDP || ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_ICMP) {
            struct udphdr *udp = (void *)(ip + 1);
            if ((void *)(udp + 1) > data_end) return XDP_PASS;

            // 检查是否匹配抓包规则（如果没有规则则抓取所有）
            if (match_any_capture_rule(ip->saddr, ip->daddr,
                                       udp->source, udp->dest, ip->protocol)) {
                send_trace_event(ctx, data, data_end, XDP_PASS, 0);
            }
        }
    }

    // NAT 逻辑（SNAT 和 DNAT）
    if (flags & CFG_FLAG_NAT_ENABLED) {
        // 检查是否为 VPN 报文（UDP 18080）
        if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (void *)(ip + 1);
            if ((void *)(udp + 1) > data_end) return XDP_PASS;

            if (udp->dest == bpf_htons(cfg->vpn_port)) {
                // 检查 VPN magic，如果是 VPN 报文则处理 SNAT
                struct vpn_header *vpn = (void *)(udp + 1);
                if ((void *)(vpn + 1) > data_end) return XDP_PASS;

                if ((vpn->first_byte & VPN_MAGIC_MASK) == VPN_MAGIC_VALUE) {
                    return detect_and_log_snat(ctx, ip, udp, data_end, cfg);
                }
            }
        }

        // 检查是否为发给公网 IP 的报文（需要 DNAT）
        // 检查目标 IP 是否是公网 IP
        __u32 is_public_ip = 0;
        if (cfg->egress_ip_count > 0 && ip->daddr == cfg->egress_ips[0])
            { is_public_ip = 1; }
        if (cfg->egress_ip_count > 1 && ip->daddr == cfg->egress_ips[1])
            { is_public_ip = 1; }
        if (cfg->egress_ip_count > 2 && ip->daddr == cfg->egress_ips[2])
            { is_public_ip = 1; }
        if (cfg->egress_ip_count > 3 && ip->daddr == cfg->egress_ips[3])
            { is_public_ip = 1; }
        if (cfg->egress_ip_count > 4 && ip->daddr == cfg->egress_ips[4])
            { is_public_ip = 1; }
        if (cfg->egress_ip_count > 5 && ip->daddr == cfg->egress_ips[5])
            { is_public_ip = 1; }
        if (cfg->egress_ip_count > 6 && ip->daddr == cfg->egress_ips[6])
            { is_public_ip = 1; }
        if (cfg->egress_ip_count > 7 && ip->daddr == cfg->egress_ips[7])
            { is_public_ip = 1; }
        if (cfg->egress_ip_count > 8 && ip->daddr == cfg->egress_ips[8])
            { is_public_ip = 1; }
        if (cfg->egress_ip_count > 9 && ip->daddr == cfg->egress_ips[9])
            { is_public_ip = 1; }
        if (cfg->egress_ip_count > 10 && ip->daddr == cfg->egress_ips[10])
            { is_public_ip = 1; }
        if (cfg->egress_ip_count > 11 && ip->daddr == cfg->egress_ips[11])
            { is_public_ip = 1; }
        if (cfg->egress_ip_count > 12 && ip->daddr == cfg->egress_ips[12])
            { is_public_ip = 1; }
        if (cfg->egress_ip_count > 13 && ip->daddr == cfg->egress_ips[13])
            { is_public_ip = 1; }
        if (cfg->egress_ip_count > 14 && ip->daddr == cfg->egress_ips[14])
            { is_public_ip = 1; }
        if (cfg->egress_ip_count > 15 && ip->daddr == cfg->egress_ips[15])
            { is_public_ip = 1; }

        if (is_public_ip) {
            return detect_and_log_dnat(ip, data_end, cfg);
        }
    }

    // UDP Echo
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) > data_end) return XDP_PASS;

        if (flags & CFG_FLAG_UDP_ECHO_ENABLED) {
            if (udp->dest == bpf_htons(cfg->udp_echo_port)) {
                int ret = xdp_udpecho(eth, ip, udp, data_end);
                if (flags & CFG_FLAG_TRACE_ENABLED) {
                    send_trace_event(ctx, data, data_end, ret, 0);
                }
                return ret;
            }
        }
    }

    // AF_XDP 重定向
    if (flags & CFG_FLAG_AFXDP_REDIRECT) {
        if (match_filter_rule(ip, (void *)(ip + 1), data_end)) {
            __u32 index = 0;
            return bpf_redirect_map(&xsks_map, index, 0);
        }
    }

    // ICMP
    if (ip->protocol == IPPROTO_ICMP) {
        return XDP_PASS;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
