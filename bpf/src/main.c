#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <xdp/app/udp_echo.h>
#include <xdp/app/trace.h>
#include <xdp/common/all.h>

// 引入结构体定义
#include <xdp/common/vpn_config.h>
#include <xdp/common/capture_rule.h>

// 配置 Map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct vpn_config));
    __uint(max_entries, 1);
} config_map SEC(".maps");

// 抓包规则 Map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct capture_rule));
    __uint(max_entries, 16);  // 支持最多 16 条抓包规则
} capture_rule_map SEC(".maps");

// Helper 函数：获取配置
static __always_inline struct vpn_config* get_vpn_config(void) {
    __u32 key = 0;
    return bpf_map_lookup_elem(&config_map, &key);
}

// Helper 函数：检查标志位
static __always_inline int cfg_flag_enabled(struct vpn_config *cfg, __u8 flag) {
    return cfg && (cfg->flags & flag);
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

    // 读取配置
    struct vpn_config *cfg = get_vpn_config();
    if (!cfg) {
        return XDP_PASS;
    }

    // 抓包逻辑
    if (cfg_flag_enabled(cfg, CFG_FLAG_TRACE_ENABLED)) {
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

    // UDP Echo
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) > data_end) return XDP_PASS;

        if (cfg_flag_enabled(cfg, CFG_FLAG_UDP_ECHO_ENABLED)) {
            if (udp->dest == bpf_htons(cfg->udp_echo_port)) {
                int ret = xdp_udpecho(eth, ip, udp, data_end);
                if (cfg_flag_enabled(cfg, CFG_FLAG_TRACE_ENABLED)) {
                    send_trace_event(ctx, data, data_end, ret, 0);
                }
                return ret;
            }
        }
    }

    // AF_XDP 重定向
    if (cfg_flag_enabled(cfg, CFG_FLAG_AFXDP_REDIRECT)) {
        if (match_filter_rule(ip, (void *)(ip + 1), data_end)) {
            __u32 index = 0;
            return bpf_redirect_map(&xsks_map, index, 0);
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
