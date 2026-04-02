#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/in.h>
#include <stdatomic.h>

 

#include <xdp/utils/forward.h>
#include <xdp/utils/port.h>
#include <xdp/utils/logging.h>
#include <xdp/utils/stats.h>
#include <xdp/utils/helpers.h>

#include <xdp/utils/maps.h>

struct 
{
    __uint(priority, 10);
    __uint(XDP_PASS, 1);
} XDP_RUN_CONFIG(xdp_prog_main);

SEC("xdp_prog")
int xdp_prog_main(struct xdp_md *ctx)
{
    // Initialize packet information.
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Lookup stats map.
    u32 stats_key = 0;

    stats_t* stats = bpf_map_lookup_elem(&map_stats, &stats_key);

    // Initialize Ethernet header.
    struct ethhdr *eth = data;

    // Check Ethernet header.
    if (unlikely(eth + 1 > (struct ethhdr *)data_end))
    {
        inc_pkt_stats(stats, STATS_TYPE_DROPPED);

        return XDP_DROP;
    }

    // If not IPv4, pass down network stack. Will be adding IPv6 support later on.
    if (unlikely(eth->h_proto != htons(ETH_P_IP)))
    {
        inc_pkt_stats(stats, STATS_TYPE_PASSED);

        return XDP_PASS;
    }

    // Initialize IP header.
    struct iphdr *iph = data + sizeof(struct ethhdr);

    // Check IP header.
    if (unlikely(iph + 1 > (struct iphdr *)data_end))
    {
        inc_pkt_stats(stats, STATS_TYPE_DROPPED);

        return XDP_DROP;
    }

    // We only support TCP, UDP, and ICMP for forwarding at this moment.
    if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP && iph->protocol != IPPROTO_ICMP)
    {
        inc_pkt_stats(stats, STATS_TYPE_PASSED);

        return XDP_PASS;
    }

    // Get layer-4 protocol information.
    struct udphdr *udph = NULL;
    struct tcphdr *tcph = NULL;
    struct icmphdr *icmph = NULL;

    switch (iph->protocol)
    {
        case IPPROTO_TCP:
            tcph = data + sizeof(struct ethhdr) + (iph->ihl * 4);

            if (tcph + 1 > (struct tcphdr *)data_end)
            {
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                return XDP_DROP;
            }

            break;

        case IPPROTO_UDP:
            udph = data + sizeof(struct ethhdr) + (iph->ihl * 4);

            if (udph + 1 > (struct udphdr *)data_end)
            {
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                return XDP_DROP;
            }

            break;

        case IPPROTO_ICMP:
            icmph = data + sizeof(struct ethhdr) + (iph->ihl * 4);

            if (icmph + 1 > (struct icmphdr *)data_end)
            {
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                return XDP_DROP;
            }

            break;
    }

    u16 src_port = (tcph) ? tcph->source : (udph) ? udph->source : 0;
    u16 dst_port = (tcph) ? tcph->dest : (udph) ? udph->dest : 0;

    // Construct forward key.
    fwd_rule_key_t rule_key = {0};
    
    rule_key.ip = iph->daddr;
    rule_key.port = dst_port;
    rule_key.protocol = iph->protocol;

    fwd_rule_val_t *rule = bpf_map_lookup_elem(&map_fwd_rules, &rule_key);

    if (rule)
    {
        // Ensure we aren't actually receiving replies back from the destination address on the same bind and source port. Or ICMP replies.
        if (iph->saddr == rule->dst_ip)
        {
            goto no_rule;
        }

        u64 now = bpf_ktime_get_ns();

        // Check if we have an existing connection.
        conn_key_t conn_key = {0};

        conn_key.src_ip = iph->saddr;
        conn_key.src_port = src_port;

        conn_key.bind_ip = iph->daddr;
        conn_key.bind_port = dst_port;

        conn_key.protocol = iph->protocol;

        conn_val_t* conn = bpf_map_lookup_elem(&map_connections, &conn_key);

        if (conn)
        {
            // Perform lookup on ports map and make sure we're still valid.
            port_key_t port_key = {0};
            port_key.bind_ip = iph->daddr;
            port_key.protocol = iph->protocol;

            port_key.port = conn->port;

            port_val_t* port_lookup = bpf_map_lookup_elem(&map_ports, &port_key);

            // If lookup fails, destroy connection.
            if (!port_lookup)
            {
                bpf_map_delete_elem(&map_connections, &conn_key);

                inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                return XDP_DROP;
            }

            // If the port lookup's source IP doesn't match the client's information, also destroy.
            if (port_lookup->src_ip != iph->saddr || port_lookup->src_port != src_port)
            {
                bpf_map_delete_elem(&map_connections, &conn_key);

                inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                return XDP_DROP;
            }

#ifdef CONNECTION_COUNTERS
            // Update connection stats.
            conn->count++;
            conn->last_seen = now;
#endif

            // Update port stats.
            port_lookup->count++;
            port_lookup->last_seen = now;

            // Forward the packet.
            return fwd_packet(rule, conn, stats, ctx, &data, &data_end, &eth, &iph, &tcph, &udph, &icmph);
        }
        else
        {
            u16 port_to_use = 0;

            port_key_t port_key = {0};
            port_key.bind_ip = iph->daddr;
            port_key.protocol = iph->protocol;

            if (!icmph)
            {
                port_ctx_t port_ctx = {0};
                port_ctx.last = UINT64_MAX;
                port_ctx.port_to_use = 0;
                port_ctx.port_key = port_key;

#ifdef USE_NEW_LOOP
                bpf_loop(MAX_PORTS, choose_port, &port_ctx, 0);
#else
                for (u16 i = MIN_PORT; i <= MAX_PORT; i++)
                {
                    if (choose_port(i - MIN_PORT, &port_ctx))
                    {
                        break;
                    }
                }
#endif
                port_to_use = port_ctx.port_to_use;
            }

            if (port_to_use > 0 || icmph)
            {
                // Firstly, create connection.
                conn_val_t new_conn = {0};
                new_conn.src_ip = iph->saddr;
                new_conn.src_port = src_port;

                new_conn.bind_port = dst_port;

#ifdef CONNECTION_COUNTERS
                new_conn.count = 1;
                new_conn.first_seen = now;
                new_conn.last_seen = now;
#endif
                
                new_conn.port = htons(port_to_use);

                bpf_map_update_elem(&map_connections, &conn_key, &new_conn, BPF_ANY);

                // Next, add to the port map.
                port_key.port = new_conn.port;

                port_val_t new_port = {0};
                new_port.src_ip = iph->saddr;
                new_port.src_port = src_port;

                new_port.bind_port = dst_port;

                new_port.count = 1;

                new_port.first_seen = now;
                new_port.last_seen = now;

                bpf_map_update_elem(&map_ports, &port_key, &new_port, BPF_ANY);

                int ret = fwd_packet(rule, &new_conn, stats, ctx, &data, &data_end, &eth, &iph, &tcph, &udph, &icmph);

#ifdef ENABLE_RULE_LOGGING
                if (ret == XDP_TX && rule->log)
                {
                    log_msg(now, new_conn.port, new_port.src_ip, src_port, rule_key.ip, dst_port, iph->protocol, rule->dst_ip, rule->dst_port);
                }
#endif

                return ret;
            }

            inc_pkt_stats(stats, STATS_TYPE_DROPPED);

            return XDP_DROP;
        }
    }
    else
    {
no_rule:;
        
        if (!icmph)
        {
            port_key_t port_key = {0};
            port_key.bind_ip = iph->daddr;
            port_key.protocol = iph->protocol;
            port_key.port = dst_port;

            // Find out what the client IP is.
            port_val_t* port_lookup = bpf_map_lookup_elem(&map_ports, &port_key);

            if (port_lookup)
            {
                // Perform connection lookup.
                conn_key_t conn_key = {0};
                conn_key.src_ip = port_lookup->src_ip;
                conn_key.src_port = port_lookup->src_port;

                conn_key.bind_ip = iph->daddr;
                conn_key.bind_port = port_lookup->bind_port;

                conn_key.protocol = iph->protocol;

                conn_val_t* conn = bpf_map_lookup_elem(&map_connections, &conn_key);

                if (conn)
                {
                    // Now forward packet back to actual client.
                    return fwd_packet(NULL, conn, stats, ctx, &data, &data_end, &eth, &iph, &tcph, &udph, &icmph);
                }
            }
        }
        else if (icmph->type == ICMP_ECHOREPLY)
        {
            // Handle ICMP replies.
            conn_val_t new_conn = {0};

            return fwd_packet(NULL, &new_conn, stats, ctx, &data, &data_end, &eth, &iph, &tcph, &udph, &icmph);
        }
    }

    inc_pkt_stats(stats, STATS_TYPE_PASSED);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

__uint(xsk_prog_version, XDP_DISPATCHER_VERSION) SEC(XDP_METADATA_SECTION);