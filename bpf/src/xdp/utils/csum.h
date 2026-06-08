#pragma once

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <xdp/utils/helpers.h>

static __always_inline u16 csum_fold_helper(u32 csum);
static __always_inline u32 csum_add(u32 add_end, u32 csum);
static __always_inline u32 csum_sub(u32 add_end, u32 csum);
static __always_inline void update_iph_checksum(struct iphdr *iph);
static __always_inline u16 csum_diff4(u32 from, u32 to, u16 csum);

#include "csum.c"
