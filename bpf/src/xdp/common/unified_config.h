#ifndef UNIFIED_CONFIG_H
#define UNIFIED_CONFIG_H

#include <linux/types.h>

// 配置标志位定义
#define CFG_FLAG_TRACE_ENABLED          (1 << 0)
#define CFG_FLAG_AFXDP_REDIRECT        (1 << 1)
#define CFG_FLAG_UDP_ECHO_ENABLED      (1 << 2)
#define CFG_FLAG_FORWARDING_ENABLED    (1 << 3)
#define CFG_FLAG_NAT_ENABLED           (1 << 4)
#define CFG_FLAG_MIRROR_ENABLED        (1 << 5)
#define CFG_FLAG_DEBUG_ENABLED          (1 << 6)

// 日志标志位定义（用于控制 bpf_trace_printk 输出）
#define LOG_DEBUG_PKG                   (1 << 0)  // 调试数据包处理
#define LOG_UDPECHO                     (1 << 1)  // UDP Echo 相关日志
#define LOG_SNAT                        (1 << 2)  // SNAT 处理日志
#define LOG_DNAT                        (1 << 3)  // DNAT 处理日志
#define LOG_ALL                         0xFF      // 所有日志

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

    __u8 reserved5[12];
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

// ========== ICMP VPN 相关定义 ==========

// ICMP 连接标识（SNAT Map Key）
struct icmp_conn_key {
    __u32 inner_src_ip;  // 内层源 IP
    __u32 inner_dst_ip;  // 内层目标 IP
    __u16 icmp_id;       // ICMP Identifier
    __u16 reserved;
} __attribute__((packed));

// ICMP DNAT 标识（DNAT Map Key）
struct icmp_dnat_key {
    __u32 wan_ip;        // SNAT 后的公网 IP
    __u32 inner_dst_ip;  // 内层目标 IP
    __u16 icmp_id;       // ICMP Identifier
    __u16 reserved;
} __attribute__((packed));

// ICMP SNAT 条目（内 → 外）
struct icmp_snat_entry {
    __u32 wan_ip;        // SNAT 后的公网 IP
    __u32 ifs_index;     // 出口接口索引

    // 转发所需的以太网头信息（避免出站时重复 FIB 查询）
    __u8 src_mac[6];     // 出口接口的源 MAC
    __u8 dst_mac[6];     // 下一跳的目标 MAC

    __u64 timestamp;     // 创建时间
    __u8 reserved[8];
} __attribute__((packed));

// ICMP DNAT 条目（外 → 内）
struct icmp_dnat_entry {
    // 内层信息
    __u32 inner_src_ip;  // 原始内层源 IP

    // VPN 头信息（用于重构 VPN 封装）
    __u32 vpn_session_id;     // VPN 会话 ID
    __u8 vpn_next_proto;      // VPN 下层协议 (IPPROTO_ICMP = 1)
    __u16 vpn_flags;          // VPN 标志位
    __u8 reserved1;

    // 外层 IP 信息
    __u32 outer_src_ip;       // 原始外层源 IP（客户端公网 IP）
    __u32 outer_dst_ip;       // 原始外层目标 IP（VPN 服务器 IP）
    __u16 outer_src_port;     // 原始外层源端口
    __u16 outer_dst_port;     // 原始外层目标端口（VPN 端口 18080）

    // 外层以太网头信息（避免出站时重复查询）
    __u8 outer_src_mac[6];    // 原始外层源 MAC（客户端 MAC）
    __u8 outer_dst_mac[6];    // 原始外层目标 MAC（VPN 服务器 MAC）

    // 入口接口信息（出站时从同一接口发送）
    __u32 ingress_ifindex;    // 原始入包接口索引（用于回包）

    __u64 timestamp;          // 创建时间
    __u8 reserved2[4];
} __attribute__((packed));

// 接口 IP 配置
struct ifs_ip_config {
    __u32 ip_list[32];   // 该接口的 IP 列表（最多 32 个）
    __u32 ip_count;      // IP 数量
    __u8 reserved[12];
} __attribute__((packed));

#endif // UNIFIED_CONFIG_H
