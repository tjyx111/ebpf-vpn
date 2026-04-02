#ifndef XDP_UDPECHO_H
#define XDP_UDPECHO_H

#include <linux/types.h>
#include <xdp/utils/csum.h>

#define MTU 1500

static __always_inline int xdp_udpecho(struct ethhdr *eth, struct iphdr *ip, struct udphdr *udp, void *data_end) {
    if (eth == NULL || ip == NULL || udp == NULL) {
        return XDP_PASS;
    }
    if ((void *)(udp + 1) > data_end) return XDP_PASS;

    // 交换MAC地址
    __u8 tmp_mac[6];
    __builtin_memcpy(tmp_mac, eth->h_dest, 6);
    __builtin_memcpy(eth->h_dest, eth->h_source, 6);
    __builtin_memcpy(eth->h_source, tmp_mac, 6);

    // 交换IP地址
    __u32 old_src_ip = ip->saddr;
    __u32 old_dst_ip = ip->daddr;
    ip->saddr = old_dst_ip;
    ip->daddr = old_src_ip;

    // 交换UDP端口
    __u16 old_src_port = udp->source;
    __u16 old_dst_port = udp->dest;
    udp->source = old_dst_port;
    udp->dest = old_src_port;
    
    // Recalculate checksum.
    udp->check = csum_diff4(old_dst_ip, ip->daddr, udp->check);
    udp->check = csum_diff4(old_src_ip, ip->saddr, udp->check);

    udp->check = csum_diff4(old_src_port, udp->source, udp->check);
    udp->check = csum_diff4(old_dst_port, udp->dest, udp->check);
    return XDP_TX;
}

#endif // XDP_UDPECHO_H