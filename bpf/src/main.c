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

#define UDP_ECHO_PORT 18080

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
    __uint(max_entries, 1);
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

// Helper 函数：获取抓包规则
static __always_inline struct capture_rule* get_capture_rule(void) {
    __u32 key = 0;
    return bpf_map_lookup_elem(&capture_rule_map, &key);
}

// Helper 函数：判断是否需要镜像
static __always_inline int should_mirror_packet(struct vpn_config *cfg) {
    if (!cfg_flag_enabled(cfg, CFG_FLAG_TRACE_ENABLED))
        return 0;
    
    if (cfg->mirror_sample_rate < 100) {
        __u32 rand = bpf_get_prandom_u32();
        if ((rand % 100) >= cfg->mirror_sample_rate)
            return 0;
    }
    
    return 1;
}

// Helper 函数：匹配抓包规则
static __always_inline int match_capture_rule(struct capture_rule *rule,
                                               __u32 src_ip,
                                               __u32 dst_ip,
                                               __u16 src_port,
                                               __u16 dst_port,
                                               __u8 protocol) {
    if (!rule)
        return 0;
    
    if (rule->src_ip && ((src_ip & rule->src_ip_mask) != (rule->src_ip & rule->src_ip_mask)))
        return 0;
    
    if (rule->dst_ip && ((dst_ip & rule->dst_ip_mask) != (rule->dst_ip & rule->dst_ip_mask)))
        return 0;
    
    if (rule->src_port && ((src_port & rule->src_port_mask) != (rule->src_port & rule->src_port_mask)))
        return 0;
    
    if (rule->dst_port && ((dst_port & rule->dst_port_mask) != (rule->dst_port & rule->dst_port_mask)))
        return 0;
    
    if (rule->protocol && protocol != rule->protocol)
        return 0;
    
    return 1;
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
        struct capture_rule *rule = get_capture_rule();

        if (ip->protocol == IPPROTO_UDP || ip->protocol == IPPROTO_TCP) {
            struct udphdr *udp = (void *)(ip + 1);
            if ((void *)(udp + 1) > data_end) return XDP_PASS;

            if (rule && match_capture_rule(rule, ip->saddr, ip->daddr,
                                            udp->source, udp->dest, ip->protocol)) {
                if (should_mirror_packet(cfg)) {
                    send_trace_event(ctx, data, data_end, XDP_PASS, 0);
                }
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

    // ICMP
    if (ip->protocol == IPPROTO_ICMP) {
        return XDP_PASS;
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

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
