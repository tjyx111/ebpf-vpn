#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/if_packet.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <xdp/app/udp_echo.h>
#include <xdp/app/trace.h>
#include <xdp/common/all.h>
#include <linux/bpf.h>

// Branch prediction hints for logging/capture (cold paths)
#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

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

// Debug 事件 Ring Buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  // 256KB
} debug_events SEC(".maps");

// 全局变量：配置是否已打印（需要 Linux 5.2+）
volatile int config_printed = 0;

// Helper 函数：打印详细配置信息（仅在首次启用 LOG_FLG_CFG 时打印）
static __always_inline void print_config(struct unified_config *cfg) {
    if (!(cfg->log_flags & LOG_FLG_CFG)) {
        return;
    }

    bpf_trace_printk("========== XDP Configuration ==========\n", 42);

    // 功能标志位
    bpf_trace_printk("Flags: 0x%x\n", 13, cfg->flags);
    bpf_trace_printk("LogFlags: 0x%x\n", 15, cfg->log_flags);

    // 抓包配置
    bpf_trace_printk("Capture_Enabled: %d\n", 21, cfg->capture_enabled);
    bpf_trace_printk("Dump_Pkg_Flags: 0x%x\n", 22, cfg->dump_pkg_flags);

    // UDP Echo 配置
    bpf_trace_printk("UDP_Echo_Port: %d\n", 20, bpf_ntohs(cfg->udp_echo_port));
    bpf_trace_printk("MTU: %u\n", 9, cfg->mtu);
    bpf_trace_printk("Mirror_Sample_Rate: %u\n", 25, cfg->mirror_sample_rate);

    // NAT/VPN 配置
    bpf_trace_printk("Timeout: %llu ns\n", 18, cfg->timeout_ns);
    bpf_trace_printk("VPN_Server_IP: 0x%x\n", 21, bpf_ntohl(cfg->vpn_server_ip));
    bpf_trace_printk("VPN_Port: %d\n", 15, bpf_ntohs(cfg->vpn_port));
    bpf_trace_printk("Port_Range: %d-%d\n", 20, bpf_ntohs(cfg->port_start), bpf_ntohs(cfg->port_end));
    bpf_trace_printk("Reserved_Ports_Count: %d\n", 26, cfg->reserved_count);

    // 网卡配置
    bpf_trace_printk("Ingress_Iface: %d\n", 20, cfg->ingress_iface);
    bpf_trace_printk("Egress_Iface: %d\n", 19, cfg->egress_iface);
    bpf_trace_printk("Egress_IP_Count: %d\n", 21, cfg->egress_ip_count);

    // 打印出口 IP 列表（前4个，避免过多日志）
    if (cfg->egress_ip_count > 0) {
        bpf_trace_printk("Egress_IP[0]: 0x%x\n", 21, bpf_ntohl(cfg->egress_ips[0]));
    }
    if (cfg->egress_ip_count > 1) {
        bpf_trace_printk("Egress_IP[1]: 0x%x\n", 21, bpf_ntohl(cfg->egress_ips[1]));
    }
    if (cfg->egress_ip_count > 2) {
        bpf_trace_printk("Egress_IP[2]: 0x%x\n", 21, bpf_ntohl(cfg->egress_ips[2]));
    }
    if (cfg->egress_ip_count > 3) {
        bpf_trace_printk("Egress_IP[3]: 0x%x\n", 21, bpf_ntohl(cfg->egress_ips[3]));
    }

    bpf_trace_printk("========== End Configuration ==========\n", 43);
}

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

// Helper 函数：尝试抓包（检查规则并匹配）
// force: 如果为 1，则强制抓包不检查规则
static __always_inline void try_capture_packet(struct xdp_md *ctx,
                                               void *data,
                                               void *data_end,
                                               struct iphdr *ip,
                                               __u32 xdp_action,
                                               __u8 capture_enabled,
                                               __u8 dump_pkg_flags,
                                               int force) {
    // 检查是否启用了抓包功能（使用独立的 capture_enabled 配置）
    if (likely(!capture_enabled)) {
        return;
    }

    // 只处理支持协议
    if (ip->protocol != IPPROTO_UDP &&
        ip->protocol != IPPROTO_TCP &&
        ip->protocol != IPPROTO_ICMP) {
        return;
    }

    // 提取传输层头部
    void *l4 = (void *)(ip + 1);
    __u16 src_port = 0, dst_port = 0;

    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end) return;
        src_port = udp->source;
        dst_port = udp->dest;
    } else if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end) return;
        src_port = tcp->source;
        dst_port = tcp->dest;
    }

    // 检查是否匹配抓包规则（force=1 时跳过规则检查）
    if (!force && !match_any_capture_rule(ip->saddr, ip->daddr,
                                          src_port, dst_port,
                                          ip->protocol)) {
        return;
    }

    // 发送抓包事件（原始包数据）
    send_trace_event(ctx, data, data_end, xdp_action, 0);
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

// Helper 函数：检查目标 IP 是否是配置的公网 IP
// 返回值：1=是公网IP, 0=不是公网IP
static __always_inline __u8 is_public_ip(__u32 dst_ip,
                                          __u8 egress_ip_count,
                                          const __u32 *egress_ips) {
    __u32 is_public = 0;

    // 展开循环以避免验证器问题（最多16个公网IP）
    if (egress_ip_count > 0 && dst_ip == egress_ips[0])
        { is_public = 1; }
    if (egress_ip_count > 1 && dst_ip == egress_ips[1])
        { is_public = 1; }
    if (egress_ip_count > 2 && dst_ip == egress_ips[2])
        { is_public = 1; }
    if (egress_ip_count > 3 && dst_ip == egress_ips[3])
        { is_public = 1; }
    if (egress_ip_count > 4 && dst_ip == egress_ips[4])
        { is_public = 1; }
    if (egress_ip_count > 5 && dst_ip == egress_ips[5])
        { is_public = 1; }
    if (egress_ip_count > 6 && dst_ip == egress_ips[6])
        { is_public = 1; }
    if (egress_ip_count > 7 && dst_ip == egress_ips[7])
        { is_public = 1; }
    if (egress_ip_count > 8 && dst_ip == egress_ips[8])
        { is_public = 1; }
    if (egress_ip_count > 9 && dst_ip == egress_ips[9])
        { is_public = 1; }
    if (egress_ip_count > 10 && dst_ip == egress_ips[10])
        { is_public = 1; }
    if (egress_ip_count > 11 && dst_ip == egress_ips[11])
        { is_public = 1; }
    if (egress_ip_count > 12 && dst_ip == egress_ips[12])
        { is_public = 1; }
    if (egress_ip_count > 13 && dst_ip == egress_ips[13])
        { is_public = 1; }
    if (egress_ip_count > 14 && dst_ip == egress_ips[14])
        { is_public = 1; }
    if (egress_ip_count > 15 && dst_ip == egress_ips[15])
        { is_public = 1; }

    return is_public;
}

// Debug 函数：发送数据包信息到 Ring Buffer
static __always_inline void debug_packet(struct xdp_md *ctx,
                                         void *data,
                                         void *data_end,
                                         __u32 log_flags) {

    if (unlikely(log_flags & LOG_FLG_DEBUG_PKT)) {
        bpf_trace_printk("[DEBUG CHECK] enter", sizeof("[DEBUG CHECK] enter"));
    }

    // 分配 Ring Buffer 空间
    struct debug_event *e = bpf_ringbuf_reserve(&debug_events, sizeof(*e), 0);
    if (!e) {
        if (unlikely(log_flags & LOG_FLG_DEBUG_PKT)) {
            bpf_trace_printk("[DEBUG CHECK] bpf_ringbuf_reserve failed", sizeof("[DEBUG CHECK] bpf_ringbuf_reserve failed"));
        }
        return;  // 分配失败，直接返回
    }


    // 填充固定的测试数据
    __builtin_memset(e, 0, sizeof(*e));

    // 外层 MAC (固定值: AA:BB:CC:DD:EE:FF -> 11:22:33:44:55:66)
    e->outer_src_mac[0] = 0xAA; e->outer_src_mac[1] = 0xBB;
    e->outer_src_mac[2] = 0xCC; e->outer_src_mac[3] = 0xDD;
    e->outer_src_mac[4] = 0xEE; e->outer_src_mac[5] = 0xFF;

    e->outer_dst_mac[0] = 0x11; e->outer_dst_mac[1] = 0x22;
    e->outer_dst_mac[2] = 0x33; e->outer_dst_mac[3] = 0x44;
    e->outer_dst_mac[4] = 0x55; e->outer_dst_mac[5] = 0x66;

    // 外层 IP (固定值: 192.168.1.1 -> 10.0.0.1)
    e->outer_src_ip = 0xC0A80101;  // 192.168.1.1
    e->outer_dst_ip = 0x0A000001;  // 10.0.0.1
    e->outer_protocol = 17;        // UDP
    e->outer_src_port = 12345;
    e->outer_dst_port = 18080;     // VPN 端口

    // VPN 头 (固定值)
    e->vpn_first_byte = 0x90;
    e->vpn_next_proto = 1;         // IPv4
    e->vpn_flags = 0;
    e->vpn_session_id = 12345;

    // 内层 IP (固定值: 172.16.0.1 -> 8.8.8.8)
    e->inner_src_ip = 0xAC100001;  // 172.16.0.1
    e->inner_dst_ip = 0x08080808;  // 8.8.8.8
    e->inner_protocol = 6;         // TCP
    e->inner_src_port = 8080;
    e->inner_dst_port = 443;

    // 路由信息 (固定值)
    e->fib_ifindex = 2;            // eth2
    e->fib_src_mac[0] = 0x22; e->fib_src_mac[1] = 0x33;
    e->fib_src_mac[2] = 0x44; e->fib_src_mac[3] = 0x55;
    e->fib_src_mac[4] = 0x66; e->fib_src_mac[5] = 0x77;

    e->fib_dst_mac[0] = 0xAA; e->fib_dst_mac[1] = 0xBB;
    e->fib_dst_mac[2] = 0xCC; e->fib_dst_mac[3] = 0xDD;
    e->fib_dst_mac[4] = 0xEE; e->fib_dst_mac[5] = 0xFF;

    e->fib_result = 0;             // 成功

    // 时间戳
    e->timestamp = bpf_ktime_get_ns();
    if (unlikely(log_flags & LOG_FLG_DEBUG_PKT)) {
        bpf_trace_printk("[DEBUG CHECK] filled event, timestamp=%llu", sizeof("[DEBUG CHECK] filled event, timestamp=%llu"), e->timestamp);
    }
    bpf_ringbuf_submit(e, 0);
}

// 处理 VPN ICMP 包并打印详细信息
static __always_inline int handle_vpn_icmp(struct xdp_md *ctx,
                                           struct iphdr *outer_ip,
                                           struct udphdr *outer_udp,
                                           void *data_end,
                                           struct unified_config *cfg,
                                           __u32 log_flags) {
    // 1. 检查 VPN 头部
    struct vpn_header *vpn = (void *)(outer_udp + 1);
    if ((void *)(vpn + 1) > data_end)
        return XDP_PASS;

    if ((vpn->first_byte & VPN_MAGIC_MASK) != VPN_MAGIC_VALUE)
        return XDP_PASS;  // 不是 VPN 报文

    // 2. 提取内层 IP 包
    struct iphdr *inner_ip = (void *)(vpn + 1);
    if ((void *)(inner_ip + 1) > data_end)
        return XDP_PASS;

    // 只处理 ICMP 包
    if (inner_ip->protocol != IPPROTO_ICMP)
        return XDP_PASS;

    // 3. 提取 ICMP 头部
    struct icmphdr *icmp = (void *)(inner_ip + 1);
    if ((void *)(icmp + 1) > data_end)
        return XDP_PASS;

    // 4. 打印 VPN ICMP 信息（通过 LOG_FLG_ICMP 控制）
    if (unlikely(log_flags & LOG_FLG_ICMP)) {
        bpf_trace_printk("=== VPN ICMP DETECTED ===\n", sizeof("=== VPN ICMP DETECTED ===\n"));

        // 打印 VPN 头部信息
        bpf_trace_printk("VPN Header: Magic=0x%x, Proto=%d, SessionID=%d\n",
                         sizeof("VPN Header: Magic=0x%x, Proto=%d, SessionID=%d\n"),
                         vpn->first_byte, vpn->next_protocol, vpn->session_id);

        // 打印内层 IP 头部信息
        bpf_trace_printk("Inner IP: Src=%x, Dst=%x, Proto=%d\n",
                         sizeof("Inner IP: Src=%x, Dst=%x, Proto=%d\n"),
                         bpf_ntohl(inner_ip->saddr), bpf_ntohl(inner_ip->daddr), inner_ip->protocol);
        bpf_trace_printk("Inner IP: TTL=%d, ID=%d\n",
                         sizeof("Inner IP: TTL=%d, ID=%d\n"),
                         inner_ip->ttl, bpf_ntohs(inner_ip->id));

        // 打印 ICMP 头部信息
        bpf_trace_printk("ICMP: Type=%d, Code=%d, ID=%d\n",
                         sizeof("ICMP: Type=%d, Code=%d, ID=%d\n"),
                         icmp->type, icmp->code, bpf_ntohs(icmp->un.echo.id));
        bpf_trace_printk("ICMP: Seq=%d\n",
                         sizeof("ICMP: Seq=%d\n"),
                         bpf_ntohs(icmp->un.echo.sequence));
    }

    // 5. 使用 bpf_fib_lookup 查找路由
    struct bpf_fib_lookup fib_params = {};
    int rc;

    // 初始化 FIB 查找参数
    fib_params.family = AF_INET;
    fib_params.tos = inner_ip->tos;
    fib_params.l4_protocol = inner_ip->protocol;
    fib_params.sport = 0;
    fib_params.dport = 0;
    fib_params.tot_len = bpf_ntohs(inner_ip->tot_len);
    fib_params.ipv4_src = inner_ip->saddr;  // 内层源 IP
    fib_params.ipv4_dst = inner_ip->daddr;  // 内层目标 IP

    // 设置输入接口
    fib_params.ifindex = ctx->ingress_ifindex;

    // 执行 FIB 查找
    rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), BPF_FIB_LOOKUP_OUTPUT);

    if (unlikely(log_flags & LOG_FLG_ICMP)) {
        if (rc == 0) {
            // 查找成功
            bpf_trace_printk("FIB Lookup: Success\n", sizeof("FIB Lookup: Success\n"));
            bpf_trace_printk("  IfIndex: %d\n", sizeof("  IfIndex: %d\n"), fib_params.ifindex);
            bpf_trace_printk("  Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                             sizeof("  Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n"),
                             fib_params.smac[0], fib_params.smac[1]);
            bpf_trace_printk("  Src MAC2: %02x:%02x:%02x:%02x\n",
                             sizeof("  Src MAC2: %02x:%02x:%02x:%02x\n"),
                             fib_params.smac[2], fib_params.smac[3]);
            bpf_trace_printk("  Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                             sizeof("  Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n"),
                             fib_params.dmac[0], fib_params.dmac[1]);
            bpf_trace_printk("  Dst MAC2: %02x:%02x:%02x:%02x\n",
                             sizeof("  Dst MAC2: %02x:%02x:%02x:%02x\n"),
                             fib_params.dmac[2], fib_params.dmac[3]);
            bpf_trace_printk("  Src IP: %x\n", sizeof("  Src IP: %x\n"), bpf_ntohl(fib_params.ipv4_src));
            bpf_trace_printk("  Dst IP: %x\n", sizeof("  Dst IP: %x\n"), bpf_ntohl(fib_params.ipv4_dst));
        } else {
            // 查找失败
            bpf_trace_printk("FIB Lookup: Failed, rc=%d\n", sizeof("FIB Lookup: Failed, rc=%d\n"), rc);

            // 打印失败原因
            switch (rc) {
                case BPF_FIB_LKUP_RET_SUCCESS:
                    break;
                case BPF_FIB_LKUP_RET_BLACKHOLE:
                    bpf_trace_printk("  Reason: Blackhole\n", sizeof("  Reason: Blackhole\n"));
                    break;
                case BPF_FIB_LKUP_RET_UNREACHABLE:
                    bpf_trace_printk("  Reason: Unreachable\n", sizeof("  Reason: Unreachable\n"));
                    break;
                case BPF_FIB_LKUP_RET_NO_NEIGH:
                    bpf_trace_printk("  Reason: No neighbor\n", sizeof("  Reason: No neighbor\n"));
                    break;
                case BPF_FIB_LKUP_RET_FRAG_NEEDED:
                    bpf_trace_printk("  Reason: Fragment needed\n", sizeof("  Reason: Fragment needed\n"));
                    break;
                default:
                    bpf_trace_printk("  Reason: Unknown error (rc=%d)\n", sizeof("  Reason: Unknown error (rc=%d)\n"), rc);
                    break;
            }
        }
    }

    // 6. 打印 ICMP 数据负载（最多 16 字节，避免复杂栈操作）
    if (unlikely(log_flags & LOG_FLG_ICMP)) {
        void *icmp_data = (void *)(icmp + 1);

        // 使用显式边界检查，让验证器能够正确跟踪
        if (icmp_data + 8 <= data_end) {
            __u32 val0 = *(__u32 *)(icmp_data);
            __u32 val4 = *(__u32 *)(icmp_data + 4);
            bpf_trace_printk("Data: %08x %08x\n", sizeof("Data: %08x %08x\n"), val0, val4);
        }
    }

    // 丢弃数据包（只打印信息，不做实际转发）
    if (unlikely(log_flags & LOG_FLG_ICMP)) {
        bpf_trace_printk("VPN ICMP: Dropping packet after logging\n",
                         sizeof("VPN ICMP: Dropping packet after logging\n"));
    }

    return XDP_DROP;
}

// 检测并记录 SNAT 会话（VPN 报文 → 公网报文）
static __always_inline int detect_and_log_snat(struct xdp_md *ctx,
                                                  struct iphdr *outer_ip,
                                                  struct udphdr *outer_udp,
                                                  void *data_end,
                                                  struct unified_config *cfg,
                                                  __u32 log_flags,
                                                  __u16 port_start,
                                                  __u16 port_end,
                                                  __u64 timeout_ns,
                                                  __u8 egress_iface,
                                                  __u8 egress_ip_count) {
    // 1. 检查 VPN 头部
    struct vpn_header *vpn = (void *)(outer_udp + 1);
    if ((void *)(vpn + 1) > data_end)
        return XDP_PASS;

    if ((vpn->first_byte & VPN_MAGIC_MASK) != VPN_MAGIC_VALUE)
        return XDP_PASS;  // 不是 VPN 报文

    if (unlikely(log_flags & LOG_FLG_SNAT)) {
        bpf_trace_printk("=== SNAT DETECTED ===\n", sizeof("=== SNAT DETECTED ===\n"));
    }

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
    if (unlikely(log_flags & LOG_FLG_SNAT)) {
        bpf_trace_printk("Inner: %x:%d -> %x:%d\n",
                         sizeof("Inner: %x:%d -> %x:%d\n"),
                         inner_ip->saddr, bpf_ntohs(inner_src_port),
                         inner_ip->daddr);
        bpf_trace_printk("Inner dst: %d proto=%d\n",
                         sizeof("Inner dst: %d proto=%d\n"),
                         bpf_ntohs(inner_dst_port), inner_ip->protocol);
    }

    // 6. 检查端口范围（直接使用网络字节序比较）
    if (inner_src_port < port_start || inner_src_port > port_end) {
        if (unlikely(log_flags & LOG_FLG_SNAT)) {
            bpf_trace_printk("Port %d not in range [%d,%d]\n",
                             sizeof("Port %d not in range [%d,%d]\n"),
                             bpf_ntohs(inner_src_port),
                             bpf_ntohs(port_start),
                             bpf_ntohs(port_end));
        }
        return XDP_PASS;
    }

    // 检查预留端口（展开循环，最多8个，网络字节序直接比较）
    if (cfg->reserved_count > 0 && cfg->reserved_ports[0] == inner_src_port)
        { if (cfg->log_flags & LOG_FLG_SNAT) { bpf_trace_printk("Port %d reserved\n", sizeof("Port %d reserved\n"), bpf_ntohs(inner_src_port)); } return XDP_PASS; }
    if (cfg->reserved_count > 1 && cfg->reserved_ports[1] == inner_src_port)
        { if (cfg->log_flags & LOG_FLG_SNAT) { bpf_trace_printk("Port %d reserved\n", sizeof("Port %d reserved\n"), bpf_ntohs(inner_src_port)); } return XDP_PASS; }
    if (cfg->reserved_count > 2 && cfg->reserved_ports[2] == inner_src_port)
        { if (cfg->log_flags & LOG_FLG_SNAT) { bpf_trace_printk("Port %d reserved\n", sizeof("Port %d reserved\n"), bpf_ntohs(inner_src_port)); } return XDP_PASS; }
    if (cfg->reserved_count > 3 && cfg->reserved_ports[3] == inner_src_port)
        { if (cfg->log_flags & LOG_FLG_SNAT) { bpf_trace_printk("Port %d reserved\n", sizeof("Port %d reserved\n"), bpf_ntohs(inner_src_port)); } return XDP_PASS; }
    if (cfg->reserved_count > 4 && cfg->reserved_ports[4] == inner_src_port)
        { if (cfg->log_flags & LOG_FLG_SNAT) { bpf_trace_printk("Port %d reserved\n", sizeof("Port %d reserved\n"), bpf_ntohs(inner_src_port)); } return XDP_PASS; }
    if (cfg->reserved_count > 5 && cfg->reserved_ports[5] == inner_src_port)
        { if (cfg->log_flags & LOG_FLG_SNAT) { bpf_trace_printk("Port %d reserved\n", sizeof("Port %d reserved\n"), bpf_ntohs(inner_src_port)); } return XDP_PASS; }
    if (cfg->reserved_count > 6 && cfg->reserved_ports[6] == inner_src_port)
        { if (cfg->log_flags & LOG_FLG_SNAT) { bpf_trace_printk("Port %d reserved\n", sizeof("Port %d reserved\n"), bpf_ntohs(inner_src_port)); } return XDP_PASS; }
    if (cfg->reserved_count > 7 && cfg->reserved_ports[7] == inner_src_port)
        { if (cfg->log_flags & LOG_FLG_SNAT) { bpf_trace_printk("Port %d reserved\n", sizeof("Port %d reserved\n"), bpf_ntohs(inner_src_port)); } return XDP_PASS; }

    // 7. 选择公网 IP（通过 hash，直接比较选择）
    __u32 ip_count = egress_ip_count;
    if (ip_count == 0) {
        if (unlikely(log_flags & LOG_FLG_SNAT)) {
            bpf_trace_printk("No egress IPs configured\n", sizeof("No egress IPs configured\n"));
        }
        return XDP_PASS;
    }

    __u32 ip_index = inner_ip->saddr % ip_count;
    __u32 outer_src_ip;
    // 直接展开选择，避免动态索引
    if (ip_index == 0) outer_src_ip = cfg->egress_ips[0];
    else if (ip_index == 1) outer_src_ip = cfg->egress_ips[1];
    else if (ip_index == 2) outer_src_ip = cfg->egress_ips[2];
    else if (ip_index == 3) outer_src_ip = cfg->egress_ips[3];
    else if (ip_index == 4) outer_src_ip = cfg->egress_ips[4];
    else if (ip_index == 5) outer_src_ip = cfg->egress_ips[5];
    else if (ip_index == 6) outer_src_ip = cfg->egress_ips[6];
    else if (ip_index == 7) outer_src_ip = cfg->egress_ips[7];
    else if (ip_index == 8) outer_src_ip = cfg->egress_ips[8];
    else if (ip_index == 9) outer_src_ip = cfg->egress_ips[9];
    else if (ip_index == 10) outer_src_ip = cfg->egress_ips[10];
    else if (ip_index == 11) outer_src_ip = cfg->egress_ips[11];
    else if (ip_index == 12) outer_src_ip = cfg->egress_ips[12];
    else if (ip_index == 13) outer_src_ip = cfg->egress_ips[13];
    else if (ip_index == 14) outer_src_ip = cfg->egress_ips[14];
    else outer_src_ip = cfg->egress_ips[15];

    if (unlikely(log_flags & LOG_FLG_SNAT)) {
        bpf_trace_printk("Selected public IP: %x (index=%d)\n",
                         sizeof("Selected public IP: %x (index=%d)\n"),
                         outer_src_ip, ip_index);
    }

    // 8. 计算内层五元组 hash，查找/创建 SNAT 条目
    __u64 snat_key = hash_tuple(inner_ip->saddr, inner_src_port,
                                 inner_ip->daddr, inner_dst_port,
                                 inner_ip->protocol);

    struct snat_entry *snat = bpf_map_lookup_elem(&snat_map, &snat_key);

    if (snat) {
        // 检查超时
        __u64 now = bpf_ktime_get_ns();
        if (now - snat->timestamp > timeout_ns) {
            if (unlikely(log_flags & LOG_FLG_SNAT)) {
                bpf_trace_printk("SNAT entry expired, deleting\n", sizeof("SNAT entry expired, deleting\n"));
            }
            bpf_map_delete_elem(&snat_map, &snat_key);
            snat = NULL;
        } else {
            if (unlikely(log_flags & LOG_FLG_SNAT)) {
                bpf_trace_printk("Existing SNAT entry found, timestamp=%llu\n",
                                 sizeof("Existing SNAT entry found, timestamp=%llu\n"),
                                 snat->timestamp);
            }
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
            .egress_iface = egress_iface,
            .timestamp = bpf_ktime_get_ns(),
        };

        if (bpf_map_update_elem(&snat_map, &snat_key, &new_snat, BPF_ANY) == 0) {
            if (unlikely(log_flags & LOG_FLG_SNAT)) {
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
            }
        } else {
            if (unlikely(log_flags & LOG_FLG_SNAT)) {
                bpf_trace_printk("Failed to create SNAT entry\n", sizeof("Failed to create SNAT entry\n"));
            }
        }
    }

    // 丢弃数据包（只记录会话，不做实际转发）
    if (unlikely(log_flags & LOG_FLG_SNAT)) {
        bpf_trace_printk("SNAT: Dropping packet after logging session\n",
                         sizeof("SNAT: Dropping packet after logging session\n"));
    }

    return XDP_DROP;
}

// 检测并记录 DNAT 会话（公网报文 → VPN 报文）
static __always_inline int detect_and_log_dnat(struct iphdr *ip,
                                                  void *data_end,
                                                  struct unified_config *cfg,
                                                  __u32 log_flags,
                                                  __u64 timeout_ns) {
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

    if (unlikely(log_flags & LOG_FLG_DNAT)) {
        bpf_trace_printk("=== DNAT DETECTED ===\n", sizeof("=== DNAT DETECTED ===\n"));
    }

    // 1. 打印外层五元组
    if (unlikely(log_flags & LOG_FLG_DNAT)) {
        bpf_trace_printk("Outer src: %x:%d\n",
                         sizeof("Outer src: %x:%d\n"),
                         ip->saddr, bpf_ntohs(src_port));
        bpf_trace_printk("Outer dst: %x:%d proto=%d\n",
                         sizeof("Outer dst: %x:%d proto=%d\n"),
                         ip->daddr, bpf_ntohs(dst_port),
                         ip->protocol);
    }

    // 3. 查找 DNAT 条目
    __u64 dnat_key = hash_tuple(ip->saddr, src_port, ip->daddr, dst_port, ip->protocol);
    struct dnat_entry *dnat = bpf_map_lookup_elem(&dnat_map, &dnat_key);

    if (!dnat) {
        if (unlikely(log_flags & LOG_FLG_DNAT)) {
            bpf_trace_printk("No DNAT entry found\n", sizeof("No DNAT entry found\n"));
        }
        return XDP_PASS;
    }

    // 4. 检查超时
    __u64 now = bpf_ktime_get_ns();
    if (now - dnat->timestamp > timeout_ns) {
        if (unlikely(log_flags & LOG_FLG_DNAT)) {
            bpf_trace_printk("DNAT entry expired\n", sizeof("DNAT entry expired\n"));
        }
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
    if (unlikely(log_flags & LOG_FLG_DNAT)) {
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
    }

    // 丢弃数据包（只记录会话，不做实际转发）
    if (unlikely(log_flags & LOG_FLG_DNAT)) {
        bpf_trace_printk("DNAT: Dropping packet after logging session\n",
                         sizeof("DNAT: Dropping packet after logging session\n"));
    }

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

    // 复制到栈变量（避免验证器边界检查，提升性能）
    __u8 flags = cfg->flags;
    __u32 log_flags = cfg->log_flags;
    __u8 capture_enabled = cfg->capture_enabled;
    __u8 dump_pkg_flags = cfg->dump_pkg_flags;
    __u16 udp_echo_port = cfg->udp_echo_port;
    __u16 vpn_port = cfg->vpn_port;
    __u16 port_start = cfg->port_start;
    __u16 port_end = cfg->port_end;
    __u64 timeout_ns = cfg->timeout_ns;
    __u8 egress_iface = cfg->egress_iface;
    __u8 egress_ip_count = cfg->egress_ip_count;

    // 打印配置信息（仅首次，当 LOG_FLG_CFG 开启时）
    if (unlikely(log_flags & LOG_FLG_CFG) && !config_printed) {
        config_printed = 1;
        print_config(cfg);
    }

    // ========== 入口处抓包（检查规则） ==========
        // 检查抓包标志位（是否在 XDP 入口抓包）
    if (unlikely(dump_pkg_flags & DUMP_PKG_XDP_ENTRY)) {
        try_capture_packet(ctx, data, data_end, ip, XDP_PASS, capture_enabled, dump_pkg_flags, 0);
    }

    // Debug 模式：打印数据包详细信息
    if (unlikely(flags & CFG_FLAG_DEBUG_ENABLED)) {
        debug_packet(ctx, data, data_end, log_flags);
    }

    // UDP Echo
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) > data_end) {
            return XDP_PASS;
        }

        // udp echo默认启用
        if (likely(flags & CFG_FLAG_UDP_ECHO_ENABLED)) {
            if (udp->dest == udp_echo_port) {
                int ret = xdp_udpecho(eth, ip, udp, data_end, cfg);
                // UDP Echo 处理完成后强制抓包（不检查规则）
                try_capture_packet(ctx, data, data_end, ip, ret, capture_enabled, dump_pkg_flags, 1);
                return ret;
            }
        }

        if (udp->dest == vpn_port) {
            // 检查 VPN magic，如果是 VPN 报文则处理
            struct vpn_header *vpn = (void *)(udp + 1);
            if ((void *)(vpn + 1) > data_end) return XDP_PASS;

            // 上行流量
            if ((vpn->first_byte & VPN_MAGIC_MASK) == VPN_MAGIC_VALUE) {
                // 优先处理 VPN ICMP 包
                int ret = handle_vpn_icmp(ctx, ip, udp, data_end, cfg, log_flags);
                if (ret != XDP_PASS) {
                    return ret;  // 如果是 ICMP 包且已处理，直接返回
                }

                // 其他协议走 SNAT 处理
                return detect_and_log_snat(ctx, ip, udp, data_end, cfg, log_flags, port_start, port_end, timeout_ns, egress_iface, egress_ip_count);
            }

            // 下行流量
            if (is_public_ip(ip->daddr, egress_ip_count, cfg->egress_ips)) {
                return detect_and_log_dnat(ip, data_end, cfg, log_flags, timeout_ns);
            }
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
