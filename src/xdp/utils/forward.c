#include <xdp/utils/forward.h>

/**
 * Forwards an IPv4 packet from or back to the client.
 * 
 * @param rule A pointer to the forward rule.
 * @param conn A pointer to the connection.
 * @param stats A pointer to the stats map.
 * @param ctx A pointer to the xdp_md struct containing all packet information.
 * @param data A pointer to the data pointer.
 * @param data_end A pointer to the data end pointer.
 * @param eth A pointer to the ethernet header pointer.
 * @param iph A pointer to the IP header pointer.
 * @param tcph A pointer to the TCP header pointer.
 * @param udph A pointer to the UDP header pointer.
 * @param icmph A pointer to the ICMP header pointer.
 * 
 * @return XDP_TX (sends packet back out TX path).
 */
static __always_inline int fwd_packet(fwd_rule_val_t* rule, conn_val_t* conn, stats_t* stats, struct xdp_md* ctx, void** data, void** data_end, struct ethhdr** eth, struct iphdr** iph, struct tcphdr** tcph, struct udphdr** udph, struct icmphdr** icmph)
{
    // Swap IP addresses.
    u32 old_src_ip = (*iph)->saddr;
    u32 old_dst_ip = (*iph)->daddr;

    (*iph)->saddr = old_dst_ip;

    if (rule)
    {
        (*iph)->daddr = rule->dst_ip;
    }
    else
    {
        if (!*icmph)
        {
            (*iph)->daddr = conn->src_ip;
        }
    }

    // Handle ICMP protocol.
    if (*icmph)
    {
        if (rule)
        {
            // We'll want to add the client's unsigned 32-bit (4 bytes) IP address to the ICMP data so we know where to send it when it replies back.
            // First, let's add four bytes to the packet.
            if (bpf_xdp_adjust_tail(ctx, (int)sizeof(u32)))
            {
                return XDP_DROP;
            }

            // We need to redefine packet and check headers again.
            *data = (void *)(long)ctx->data;
            *data_end = (void *)(long)ctx->data_end;

            *eth = *data;

            if (*eth + 1 > (struct ethhdr *)*data_end)
            {
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                return XDP_DROP;
            }

            *iph = *data + sizeof(struct ethhdr);

            if (*iph + 1 > (struct iphdr *)*data_end)
            {
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                return XDP_DROP;
            }

            *icmph = *data + sizeof(struct ethhdr) + ((*iph)->ihl * 4);

            if (*icmph + 1 > (struct icmphdr *)*data_end)
            {
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                return XDP_DROP;
            }

            // Now let's add the new data.

            // Unfortunately, we can't start from the packet end (data_end) pointer. Therefore, we must calculate the length of the packet and use the data pointer. Thanks for the help, Srivats! (https://lore.kernel.org/bpf/CANzUK5-g9wLiwUF88em4uVzMja_aR4xj9yzMS_ZObNKjvX6C6g@mail.gmail.com/)
            unsigned int len = (*data_end - *data);

            if (*data + len > *data_end)
            {
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                return XDP_DROP;
            }

            unsigned int off = (len - sizeof(u32)) & 0x3fff;

            u32 *icmp_data = *data + off;

            if (icmp_data + 1 > (u32 *)*data_end)
            {
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                return XDP_DROP;
            }

            memcpy(icmp_data, &conn->src_ip, sizeof(u32));

            // We'll want to add four bytes to the IP header.
            (*iph)->tot_len = htons(ntohs((*iph)->tot_len) + sizeof(u32));

            // Recalculate ICMP checksum.
            (*icmph)->checksum = csum_diff4(0, conn->src_ip, (*icmph)->checksum);
        }
        else
        {
            // When sending packets back, we'll want to get the client IP address from the ICMP data (last four bytes).
            // First ensure the ICMP data is enough.
            if (*icmph + sizeof(u32) > (struct icmphdr *)*data_end)
            {
                inc_pkt_stats(stats, STATS_TYPE_PASSED);

                return XDP_PASS;
            }
            
            // Now access the data.
            unsigned int len = (*data_end - *data);

            if (*data + len > *data_end)
            {
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                return XDP_DROP;
            }

            unsigned int off = (len - sizeof(u32)) & 0x3fff;

            u32 *src_ip = *data + off;

            if (src_ip + 1 > (u32 *)*data_end)
            {
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                return XDP_DROP;
            }

            (*iph)->daddr = *src_ip;
            
            // Now we'll want to remove the additional four bytes we added when forwarding.
            if (bpf_xdp_adjust_tail(ctx, 0 - (int)sizeof(u32)))
            {
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                return XDP_DROP;
            }

            // We need to redefine packet and check headers again.
            *data = (void *)(long)ctx->data;
            *data_end = (void *)(long)ctx->data_end;

            *eth = *data;

            if (*eth + 1 > (struct ethhdr *)*data_end)
            {
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                return XDP_DROP;
            }

            *iph = *data + sizeof(struct ethhdr);

            if (*iph + 1 > (struct iphdr *)*data_end)
            {
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                return XDP_DROP;
            }

            *icmph = *data + sizeof(struct ethhdr) + ((*iph)->ihl * 4);

            if (*icmph + 1 > (struct icmphdr *)*data_end)
            {
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                return XDP_DROP;
            }

            // Remove four bytes from the IP header's total length.
            (*iph)->tot_len = htons(ntohs((*iph)->tot_len) - sizeof(u32));

            // Recalculate ICMP checksum.
            (*icmph)->checksum = csum_diff4((*iph)->daddr, 0, (*icmph)->checksum);
        }
    } else if (*tcph)
    {
        // Handle ports.
        u16 old_src_port = (*tcph)->source;
        u16 old_dst_port = (*tcph)->dest;

        if (rule)
        {
            (*tcph)->source = conn->port;
            (*tcph)->dest = rule->dst_port;
        }
        else
        {
            (*tcph)->source = conn->bind_port;
            (*tcph)->dest = conn->src_port;
        }
        
        // Recalculate checksum.
        (*tcph)->check = csum_diff4(old_src_ip, (*iph)->saddr, (*tcph)->check);
        (*tcph)->check = csum_diff4(old_src_port, (*tcph)->source, (*tcph)->check);

        (*tcph)->check = csum_diff4(old_dst_ip, (*iph)->daddr, (*tcph)->check);
        (*tcph)->check = csum_diff4(old_dst_port, (*tcph)->dest, (*tcph)->check);
    }
    else if (*udph)
    {
        // Handle ports.
        u16 old_src_port = (*udph)->source;
        u16 old_dst_port = (*udph)->dest;

        if (rule)
        {
            (*udph)->source = conn->port;
            (*udph)->dest = rule->dst_port;
        }
        else
        {
            (*udph)->source = conn->bind_port;
            (*udph)->dest = conn->src_port;
        }

        // Recalculate checksum.
        (*udph)->check = csum_diff4(old_dst_ip, (*iph)->daddr, (*udph)->check);
        (*udph)->check = csum_diff4(old_src_ip, (*iph)->saddr, (*udph)->check);

        (*udph)->check = csum_diff4(old_src_port, (*udph)->source, (*udph)->check);
        (*udph)->check = csum_diff4(old_dst_port, (*udph)->dest, (*udph)->check);
    }

    // Recalculate IP checksum and send packet back out TX path.
    update_iph_checksum(*iph);

#ifdef ENABLE_FIB_LOOKUPS
    struct bpf_fib_lookup params = {0};

    params.family = AF_INET;
    params.tos = (*iph)->tos;
    params.l4_protocol = (*iph)->protocol;
    params.tot_len = ntohs((*iph)->tot_len);
    params.ipv4_src = (*iph)->saddr;
    params.ipv4_dst = (*iph)->daddr;

    params.ifindex = ctx->ingress_ifindex;

    int fwd = bpf_fib_lookup(ctx, &params, sizeof(params), BPF_FIB_LOOKUP_DIRECT);

    if (fwd != BPF_FIB_LKUP_RET_SUCCESS)
    {
        inc_pkt_stats(stats, STATS_TYPE_DROPPED);

        return XDP_DROP;
    }

    *data = (void*)(long)ctx->data;
    *data_end = (void*)(long)ctx->data_end;

    *eth = *data;

    if (unlikely(*eth + 1 > (struct ethhdr*)*data_end))
    {
        inc_pkt_stats(stats, STATS_TYPE_DROPPED);

        return XDP_DROP;
    }

    *iph = *data + sizeof(struct ethhdr);

    if (*iph + 1 > (struct iphdr*)*data_end)
    {
        inc_pkt_stats(stats, STATS_TYPE_DROPPED);

        return XDP_DROP;
    }

    memcpy((*eth)->h_source, params.smac, ETH_ALEN);
    memcpy((*eth)->h_dest, params.dmac, ETH_ALEN);
#else
    // Swap ethernet source and destination MAC addresses.
    swap_eth(*eth);
#endif

    if (rule)
    {
        inc_pkt_stats(stats, STATS_TYPE_FORWARDED);
    }
#ifdef STATS_COUNT_FWD_BACK
    else
    {
        inc_pkt_stats(stats, STATS_TYPE_FORWARDED);
    }
#endif

    return XDP_TX;
}