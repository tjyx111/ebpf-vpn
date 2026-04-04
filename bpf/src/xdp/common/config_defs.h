#ifndef CONFIG_DEFS_H
#define CONFIG_DEFS_H

#include <linux/types.h>

// VPN 配置结构
struct vpn_config {
    __u32 udp_echo_port;
    __u32 mtu;
    __u8 flags;
    __u8 mirror_sample_rate;
    __u8 reserved[2];
} __attribute__((packed));

// 抓包规则结构
struct capture_rule {
    __u32 src_ip;
    __u32 src_ip_mask;
    __u32 dst_ip;
    __u32 dst_ip_mask;
    __u16 src_port;
    __u16 src_port_mask;
    __u16 dst_port;
    __u16 dst_port_mask;
    __u8 protocol;
    __u8 reserved[6];
} __attribute__((packed));

#endif
