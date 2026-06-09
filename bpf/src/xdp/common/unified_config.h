#ifndef UNIFIED_CONFIG_H
#define UNIFIED_CONFIG_H

#include <linux/types.h>

#define CFG_FLAG_UDP_ECHO_ENABLED     (1 << 0)
#define CFG_FLAG_DNAT_CAPTURE_ENABLED (1 << 1)

struct vpn_header {
    __u8 first_byte;
    __u8 next_protocol;
    __u16 flags;
    __u32 session_id;
} __attribute__((packed));

#define VPN_MAGIC_MASK  0xF0
#define VPN_MAGIC_VALUE 0x90
#define MAX_EGRESS_IPS 63

struct unified_config {
    __u8 flags;
    __u8 reserved1[3];

    __u16 udp_echo_port;
    __u16 vpn_port;
    __u32 mtu;

    __u8 egress_ip_count;
    __u8 reserved2[3];
    __u32 egress_ips[MAX_EGRESS_IPS];
} __attribute__((packed));

enum stat_index {
    STAT_TOTAL_PACKETS = 0,
    STAT_UDP_ECHO_COUNT,
    STAT_VPN_COUNT,
    STAT_VPN_ICMP_ECHO_COUNT,
    STAT_VPN_ICMP_SNAT_COUNT,
    STAT_VPN_ICMP_DNAT_COUNT,
    STAT_VPN_ICMP_DNAT_MISS_COUNT,
    STAT_VPN_L4_SNAT_COUNT,
    STAT_VPN_L4_DNAT_COUNT,
    STAT_VPN_FRAGMENT_PASS_COUNT,
    STAT_VPN_MTU_PASS_COUNT,
    STAT_VPN_PORT_ALLOC_MISS_COUNT,
    STAT_XDP_PASS_COUNT,
    STAT_UDP_HEADER_ERROR_COUNT,
    STAT_VPN_HEADER_ERROR_COUNT,
    STAT_VPN_INNER_IP_ERROR_COUNT,
    STAT_VPN_NON_ICMP_COUNT,
    STAT_VPN_INNER_ICMP_ERROR_COUNT,
    STAT_VPN_NO_EGRESS_IP_COUNT,
    STAT_VPN_ADJUST_HEAD_ERROR_COUNT,
    STAT_VPN_NEW_ETH_ERROR_COUNT,
    STAT_VPN_NEW_IP_ERROR_COUNT,
    STAT_VPN_FIB_LOOKUP_ERROR_COUNT,
    STAT_VPN_DNAT_FIB_LOOKUP_ERROR_COUNT,
    STAT_NON_IPV4_PASS_COUNT,
    STAT_IPV4_FRAGMENT_PASS_COUNT,
    STAT_MAX_COUNT
};

#endif
