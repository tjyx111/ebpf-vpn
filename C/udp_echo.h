#ifndef XDP_UDPECHO_H
#define XDP_UDPECHO_H

#include <linux/types.h>

static __always_inline __u16 csum_fold_helper(__u64 csum)
{
    int i;
#pragma unroll
    for (i = 0; i < 4; i++) {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

static __always_inline __u16 ipv4_csum(struct iphdr *iph)
{
    iph->check = 0;
    unsigned long long csum = bpf_csum_diff(0, 0, (unsigned int *)iph, sizeof(struct iphdr), 0);
    return csum_fold_helper(csum);
}

static __always_inline __u16 udp_csum(struct iphdr *ip, struct udphdr *udp, void *data_end) {
    // 伪头部
    struct {
        __u32 src;
        __u32 dst;
        __u8  zero;
        __u8  proto;
        __u16 len;
    } pseudo = {
        .src = ip->saddr,
        .dst = ip->daddr,
        .zero = 0,
        .proto = IPPROTO_UDP,
        .len = udp->len
    };

    __u64 csum = 0;
    csum += bpf_csum_diff(0, 0, (__be32 *)&pseudo, sizeof(pseudo), 0);

    __wsum udp_csum = 0;
    __u16 udp_len = bpf_ntohs(udp->len);
    __u8 zero = 0;
    
    // 伪首部：使用修改后的源IP、目标IP
    udp_csum += (ip->saddr >> 16) + (ip->saddr & 0xFFFF);
    udp_csum += (ip->daddr >> 16) + (ip->daddr & 0xFFFF);
    udp_csum += (unsigned short)ip->protocol;
    udp_csum += udp->len;
    
    // UDP 头和数据
    __u16 *udp_ptr = (__u16 *)udp;
    for (int i = 0; i < udp_len / 2; i++) {
        udp_csum += udp_ptr[i];
    }
    
    // 如果 UDP 长度为奇数，处理最后一个字节
    if (udp_len % 2) {
        __u8 *last_byte = (__u8 *)udp + udp_len - 1;
        udp_csum += (*last_byte) << 8;
    }
    
    // 将进位加回到低位
    udp_csum = (udp_csum & 0xFFFF) + (udp_csum >> 16);
    udp_csum += (udp_csum >> 16);
    udp->check = ~((__u16)udp_csum);
    
    // 如果校验和为0，设置为0xFFFF
    if (udp->check == 0) {
        udp->check = 0xFFFF;
    }

    return ~csum;
}

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
    __u32 tmp_ip = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmp_ip;

    // 交换UDP端口
    __u16 tmp_port = udp->source;
    udp->source = udp->dest;
    udp->dest = tmp_port;

    // IP校验和
    ip->check = ipv4_csum(ip);

    // UDP校验和
    udp->check = 0;
    udp->check = udp_csum(ip, udp, data_end);

    return XDP_TX;
}

#endif // XDP_UDPECHO_H