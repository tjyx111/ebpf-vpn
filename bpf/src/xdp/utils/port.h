#pragma once

 

#include <xdp/utils/maps.h>

struct port_ctx
{
    u64 last;
    u16 port_to_use;
    port_key_t port_key;
} typedef port_ctx_t;

static __always_inline long choose_port(u32 idx, void* data);

// The source file is included directly below instead of compiled and linked as an object because when linking, there is no guarantee the compiler will inline the function (which is crucial for performance).
// I'd prefer not to include the function logic inside of the header file.
// More Info: https://stackoverflow.com/questions/24289599/always-inline-does-not-work-when-function-is-implemented-in-different-file
#include "port.c"