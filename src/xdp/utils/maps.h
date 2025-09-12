#pragma once

 

#include <xdp/utils/helpers.h>

struct 
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, stats_t);
} map_stats SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_FWD_RULES);
    __type(key, fwd_rule_key_t);
    __type(value, fwd_rule_val_t);
} map_fwd_rules SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, (MAX_BIND_IPS * MAX_PROTOCOLS) * MAX_PORTS);
    __type(key, conn_key_t);
    __type(value, conn_val_t);
} map_connections SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_BIND_IPS * MAX_PORTS);
    __type(key, port_key_t);
    __type(value, port_val_t);
} map_ports SEC(".maps");

#ifdef ENABLE_RULE_LOGGING
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} map_fwd_rules_log SEC(".maps");
#endif