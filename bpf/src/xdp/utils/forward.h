#pragma once

 

#include <xdp/utils/maps.h>

#include <xdp/utils/stats.h>

#include <xdp/utils/helpers.h>
#include <xdp/utils/csum.h>

#ifndef AF_INET
#define AF_INET 2
#endif

static __always_inline int fwd_packet(fwd_rule_val_t* rule, conn_val_t* conn, stats_t* stats, struct xdp_md* ctx, void** data, void** data_end, struct ethhdr** eth, struct iphdr** iph, struct tcphdr** tcph, struct udphdr** udph, struct icmphdr** icmph);

// The source file is included directly below instead of compiled and linked as an object because when linking, there is no guarantee the compiler will inline the function (which is crucial for performance).
// I'd prefer not to include the function logic inside of the header file.
// More Info: https://stackoverflow.com/questions/24289599/always-inline-does-not-work-when-function-is-implemented-in-different-file
#include "forward.c"