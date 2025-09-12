#pragma once

 

#include <linux/bpf.h>

#include <xdp/xdp_helpers.h>
#include <xdp/prog_dispatcher.h>

#ifdef ENABLE_RULE_LOGGING
static __always_inline int log_msg(u64 now, u16 port, u32 src_ip, u16 src_port, u32 bind_ip, u16 bind_port, u8 protocol, u32 dst_ip, u16 dst_port);
#endif

// The source file is included directly below instead of compiled and linked as an object because when linking, there is no guarantee the compiler will inline the function (which is crucial for performance).
// I'd prefer not to include the function logic inside of the header file.
// More Info: https://stackoverflow.com/questions/24289599/always-inline-does-not-work-when-function-is-implemented-in-different-file
#include "logging.c"