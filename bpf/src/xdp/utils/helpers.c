#include <xdp/utils/helpers.h>

/**
 * Swaps the Ethernet source and destination MAC addresses.
 * 
 * @param eth A pointer to the Ethernet header (ethhdr) struct that points to the Ethernet header within the packet.
 * 
 * @return void
 */
static __always_inline void swap_eth(struct ethhdr* eth)
{
    u8 tmp[ETH_ALEN];

    memcpy(&tmp, eth->h_source, ETH_ALEN);
    memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    memcpy(eth->h_dest, &tmp, ETH_ALEN);
}