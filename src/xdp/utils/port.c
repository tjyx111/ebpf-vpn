#include <xdp/utils/port.h>

/**
 * Chooses the next available source port.
 * 
 * @param idx The loop index.
 * @param data A pointer to a port context.
 * 
 * @return 1 to break the loop or 0 to continue the loop.
 */
static __always_inline long choose_port(u32 idx, void* data)
{
    port_ctx_t* ctx = data;

    u16 port = MIN_PORT + idx;

    ctx->port_key.port = htons(port);

    port_val_t *port_lookup = bpf_map_lookup_elem(&map_ports, &ctx->port_key);

    if (!port_lookup)
    {
        ctx->port_to_use = port;
        
        return 1;
    }

#ifdef RECYCLE_LAST_SEEN
    if (port_lookup->last_seen < ctx->last)
    {
        ctx->port_to_use = port;
        ctx->last = port_lookup->last_seen;
    }
#else
    if (port_lookup->count > 0)
    {
        u64 pps = (port_lookup->last_seen - port_lookup->first_seen) / port_lookup->count;
        if (ctx->last > pps)
        {
            ctx->port_to_use = port;
            ctx->last = pps;
        }
    }
#endif

    return 0;
}