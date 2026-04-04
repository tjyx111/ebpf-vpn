#ifndef VPN_CONFIG_H
#define VPN_CONFIG_H

#include <linux/types.h>

// VPN 配置结构
struct vpn_config {
    __u32 udp_echo_port;
    __u32 mtu;
    __u8 flags;
    __u8 mirror_sample_rate;
    __u8 reserved[2];
} __attribute__((packed));

// 配置标志位定义
#define CFG_FLAG_TRACE_ENABLED          (1 << 0)
#define CFG_FLAG_AFXDP_REDIRECT        (1 << 1)
#define CFG_FLAG_UDP_ECHO_ENABLED      (1 << 2)
#define CFG_FLAG_FORWARDING_ENABLED    (1 << 3)
#define CFG_FLAG_NAT_ENABLED           (1 << 4)
#define CFG_FLAG_MIRROR_ENABLED        (1 << 5)

// 配置键
#define CFG_KEY 0

#endif // VPN_CONFIG_H
