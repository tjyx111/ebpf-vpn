#ifndef VPN_CONFIG_H
#define VPN_CONFIG_H

#include <linux/types.h>

// VPN 配置结构
struct vpn_config {
    __u32 udp_echo_port;
    __u32 mtu;
    __u8 flags;
    __u8 log_flags;
    __u8 mirror_sample_rate;
    __u8 reserved[1];
} __attribute__((packed));

// 配置标志位定义
#define CFG_FLAG_CAPTURE_ENABLED       (1 << 0)  // 抓包功能启用
#define CFG_FLAG_AFXDP_REDIRECT        (1 << 1)
#define CFG_FLAG_UDP_ECHO_ENABLED      (1 << 2)
#define CFG_FLAG_FORWARDING_ENABLED    (1 << 3)
#define CFG_FLAG_NAT_ENABLED           (1 << 4)

// 日志标志位定义
#define CFG_LOG_ICMP                   (1 << 0)  // ICMP 相关日志
#define CFG_LOG_UDP                    (1 << 1)  // UDP 相关日志
#define CFG_LOG_TCP                    (1 << 2)  // TCP 相关日志
#define CFG_LOG_NAT                    (1 << 3)  // NAT 相关日志

// 配置键
#define CFG_KEY 0

#endif // VPN_CONFIG_H
