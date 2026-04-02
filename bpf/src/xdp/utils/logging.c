#include <linux/ip.h>
#include <linux/ipv6.h>

#include <xdp/utils/helpers.h>
#include <xdp/utils/maps.h>

#ifdef ENABLE_RULE_LOGGING
/**
 * Logs a message to the forward rule ringbuffer map.
 * 
 * @param now The timestamp.
 * @param port The source port used for mapping the connection.
 * @param src_ip The source IP.
 * @param src_port The source port.
 * @param bind_ip The bind IP.
 * @param bind_port The bind port.
 * @param protocol The bind protocol.
 * @param dst_ip The destination IP.
 * @param dst_port The destination port.
 * 
 * @return always 0
 */
static __always_inline int log_msg(u64 now, u16 port, u32 src_ip, u16 src_port, u32 bind_ip, u16 bind_port, u8 protocol, u32 dst_ip, u16 dst_port)
{
    fwd_rule_log_event_t* e = bpf_ringbuf_reserve(&map_fwd_rules_log, sizeof(*e), 0);

    if (e)
    {
        e->ts = now;

        e->port = port;

        e->src_ip = src_ip;
        e->src_port = src_port;

        e->bind_ip = bind_ip;
        e->bind_port = bind_port;
        e->protocol = protocol;

        e->dst_ip = dst_ip;
        e->dst_port = dst_port;

        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}
#endif