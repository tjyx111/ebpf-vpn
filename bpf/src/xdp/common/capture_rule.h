#ifndef CAPTURE_RULE_H
#define CAPTURE_RULE_H

#include <linux/types.h>

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

// 规则键
#define CAPTURE_RULE_KEY 0

#endif // CAPTURE_RULE_H
