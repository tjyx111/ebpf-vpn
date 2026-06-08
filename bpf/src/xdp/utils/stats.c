#include <xdp/utils/stats.h>

extern volatile __u64 stat_counters[256];

static __always_inline int inc_pkt_stats(STATS_TYPE_T type)
{
    __u32 index = STAT_MAX_COUNT;

    switch (type) {
        case STATS_TYPE_TOTAL_PACKETS:
            index = STAT_TOTAL_PACKETS;
            break;
        case STATS_TYPE_UDP_ECHO:
            index = STAT_UDP_ECHO_COUNT;
            break;
        case STATS_TYPE_VPN:
            index = STAT_VPN_COUNT;
            break;
        case STATS_TYPE_VPN_ICMP_ECHO:
            index = STAT_VPN_ICMP_ECHO_COUNT;
            break;
        case STATS_TYPE_VPN_ICMP_SNAT:
            index = STAT_VPN_ICMP_SNAT_COUNT;
            break;
        case STATS_TYPE_XDP_PASS:
            index = STAT_XDP_PASS_COUNT;
            break;
        case STATS_TYPE_UDP_HEADER_ERROR:
            index = STAT_UDP_HEADER_ERROR_COUNT;
            break;
        case STATS_TYPE_VPN_HEADER_ERROR:
            index = STAT_VPN_HEADER_ERROR_COUNT;
            break;
        case STATS_TYPE_VPN_INNER_IP_ERROR:
            index = STAT_VPN_INNER_IP_ERROR_COUNT;
            break;
        case STATS_TYPE_VPN_NON_ICMP:
            index = STAT_VPN_NON_ICMP_COUNT;
            break;
        case STATS_TYPE_VPN_INNER_ICMP_ERROR:
            index = STAT_VPN_INNER_ICMP_ERROR_COUNT;
            break;
        case STATS_TYPE_VPN_NO_EGRESS_IP:
            index = STAT_VPN_NO_EGRESS_IP_COUNT;
            break;
        case STATS_TYPE_VPN_ADJUST_HEAD_ERROR:
            index = STAT_VPN_ADJUST_HEAD_ERROR_COUNT;
            break;
        case STATS_TYPE_VPN_NEW_ETH_ERROR:
            index = STAT_VPN_NEW_ETH_ERROR_COUNT;
            break;
        case STATS_TYPE_VPN_NEW_IP_ERROR:
            index = STAT_VPN_NEW_IP_ERROR_COUNT;
            break;
        case STATS_TYPE_VPN_FIB_LOOKUP_ERROR:
            index = STAT_VPN_FIB_LOOKUP_ERROR_COUNT;
            break;
    }

    if (index < 256) {
        __sync_fetch_and_add(&stat_counters[index], 1);
    }

    return 0;
}
