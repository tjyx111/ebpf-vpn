#ifndef UNIFIED_CONFIG_H
#define UNIFIED_CONFIG_H

#include <linux/types.h>

// 配置标志位定义
#define CFG_FLAG_UDP_ECHO_ENABLED      (1 << 2)
#define CFG_FLAG_NAT_ENABLED           (1 << 4)
#define CFG_FLAG_DEBUG_ENABLED          (1 << 6)

// 日志标志位定义（用于控制 bpf_trace_printk 输出）
// 使用 32 位标志位，每一位代表一种日志类型
#define LOG_FLG_DEBUG_PKT                (1 << 0)  // 调试数据包处理
#define LOG_FLG_SNAT                     (1 << 2)  // SNAT 处理日志
#define LOG_FLG_DNAT                     (1 << 3)  // DNAT 处理日志
#define LOG_FLG_CFG                      (1 << 4)  // 配置相关日志
#define LOG_FLG_ICMP                     (1 << 7)  // ICMP 处理日志
#define LOG_FLG_ALL                      0xFFFFFFFF  // 所有日志

// 兼容旧的宏定义（逐步迁移）
#define LOG_DEBUG_PKG                    LOG_FLG_DEBUG_PKT
#define LOG_SNAT                         LOG_FLG_SNAT
#define LOG_DNAT                         LOG_FLG_DNAT
#define LOG_CFG                          LOG_FLG_CFG

// VPN 头部（简化版）
struct vpn_header {
    __u8 first_byte;      // 前4位 = 1001 (0x90)，后4位保留
    __u8 next_protocol;   // 下层协议 (1 = IPv4)
    __u16 flags;          // 标志位
    __u32 session_id;     // 会话 ID
} __attribute__((packed));

#define VPN_MAGIC_MASK  0xF0
#define VPN_MAGIC_VALUE 0x90  // 1001

// SNAT 映射条目（内 → 外）
struct snat_entry {
    // 内层五元组
    __u32 inner_src_ip;
    __u16 inner_src_port;
    __u32 inner_dst_ip;
    __u16 inner_dst_port;
    __u8  inner_protocol;
    __u8  reserved1;

    // 映射后的信息
    __u32 outer_src_ip;     // 选中的公网 IP
    __u16 outer_src_port;   // 使用内层 src_port
    __u8  egress_iface;     // 出口网卡索引
    __u8  reserved2[1];

    __u64 timestamp;        // 创建时间（ns）
    __u8  reserved3[8];
} __attribute__((packed));

// DNAT 映射条目（外 → 内）
struct dnat_entry {
    // 外层完整五元组（公网侧）
    __u32 outer_src_ip;     // 客户端 IP（公网侧）
    __u16 outer_src_port;   // 客户端端口
    __u32 outer_dst_ip;     // 本机公网 IP
    __u16 outer_dst_port;   // 分配的公网端口
    __u8  outer_protocol;
    __u8  reserved1;

    // 内层原始五元组
    __u32 inner_src_ip;
    __u16 inner_src_port;
    __u32 inner_dst_ip;
    __u16 inner_dst_port;
    __u8  inner_protocol;
    __u8  reserved2;

    // 回包信息
    __u8  ingress_iface;    // 回包入口网卡（原始入包网卡）
    __u32 vpn_server_ip;    // VPN 服务器 IP
    __u16 vpn_server_port;  // VPN 端口 (18080)
    __u8  reserved3;

    __u64 timestamp;
    __u8  reserved4[8];
} __attribute__((packed));

// 抓包标志位定义
#define DUMP_PKG_XDP_ENTRY        (1 << 0)  // 在 XDP 入口抓原始包

// 统一配置结构
struct unified_config {
    // 功能标志位
    __u8 flags;
    __u8 reserved1[3];
    __u32 log_flags;  // 日志标志位（控制 bpf_trace_printk 输出）

    // UDP Echo 配置
    __u16 udp_echo_port;
    __u16 reserved2;
    __u32 mtu;
    __u8 mirror_sample_rate;
    __u8 reserved3[3];

    // NAT/VPN 配置
    __u64 timeout_ns;       // 超时时间（60秒 = 60000000000ns）
    __u32 vpn_server_ip;    // VPN 服务器 IP
    __u16 vpn_port;         // VPN 端口 (18080)
    __u16 port_start;       // 端口范围起始 (10000)
    __u16 port_end;         // 端口范围结束 (65535)
    __u16 reserved_ports[8]; // 预留端口列表（最多8个）
    __u16 reserved_count;   // 预留端口数量

    // 网卡映射配置
    __u8 ingress_iface;    // 入口网卡（如 eth0 = 0）
    __u8 egress_iface;     // 出口网卡（如 eth2 = 2）
    __u8 egress_ip_count;  // 出口网卡公网 IP 数量
    __u8 reserved4;
    __u32 egress_ips[16];  // 出口网卡的公网 IP 列表（最多16个）

    // 抓包配置
    __u8 capture_enabled;   // 是否开启抓包功能（0/1）
    __u8 dump_pkg_flags;    // 抓包标志位（1=在 XDP 入口抓原始包）
    __u8 reserved5[10];
} __attribute__((packed));

// Debug 事件结构体（通过 Ring Buffer 发送到用户空间）
struct debug_event {
    // 外层以太网头
    __u8 outer_src_mac[6];
    __u8 outer_dst_mac[6];

    // 外层 IP
    __u32 outer_src_ip;
    __u32 outer_dst_ip;
    __u8  outer_protocol;
    __u16 outer_src_port;
    __u16 outer_dst_port;

    // VPN 头
    __u8  vpn_first_byte;
    __u8  vpn_next_proto;
    __u16 vpn_flags;
    __u32 vpn_session_id;

    // 内层 IP
    __u32 inner_src_ip;
    __u32 inner_dst_ip;
    __u8  inner_protocol;
    __u16 inner_src_port;
    __u16 inner_dst_port;

    // 路由信息
    __u32 fib_ifindex;        // 出接口索引
    __u8  fib_src_mac[6];     // 源 MAC
    __u8  fib_dst_mac[6];     // 目标 MAC (下一跳)
    __s32 fib_result;         // FIB 查询结果

    __u64 timestamp;
} __attribute__((packed));

#endif // UNIFIED_CONFIG_H
