// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2026 ebpf-vpn */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_ERROR_ENTRIES 1024

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* 错误类型定义 */
enum error_type {
	ERR_NULL_PTR = 1,
	ERR_OUT_OF_BOUNDS = 2,
	ERR_INVALID_MAP = 3,
	ERR_VERIFICATION_FAIL = 4,
	ERR_RUNTIME_ERROR = 5,
};

/* 错误事件结构 */
struct xdp_error_event {
	__u64 timestamp;
	__u32 cpu;
	__u32 pid;
	__u32 error_type;
	__u32 program_id;
	__u32 packet_len;
	__u64 error_addr;
	__u32 instruction;
};

/* 性能统计 */
struct xdp_perf_stats {
	__u64 total_packets;
	__u64 error_packets;
	__u64 last_error_time;
};

/* Map 和 Ring Buffer */
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct xdp_perf_stats));
	__uint(max_entries, 1);
} stats_map SEC(".maps");

/* 记录错误事件 */
static __always_inline void record_error(struct xdp_md *ctx,
					  enum error_type error_type,
					  __u64 error_addr,
					  __u32 instruction)
{
	struct xdp_error_event event = {};
	__u64 flags = BPF_F_CURRENT_CPU;

	/* 填充事件信息 */
	event.timestamp = bpf_ktime_get_ns();
	event.cpu = bpf_get_smp_processor_id();
	event.pid = bpf_get_current_pid_tgid() >> 32;
	event.error_type = error_type;
	event.packet_len = ctx->data_end - ctx->data;
	event.error_addr = error_addr;
	event.instruction = instruction;

	/* 获取 XDP 程序 ID */
	bpf_get_current_comm(&event.program_id, sizeof(event.program_id));

	/* 发送事件到用户空间 */
	bpf_perf_event_output(ctx, &events, flags, &event, sizeof(event));

	/* 更新统计 */
	__u32 key = 0;
	struct xdp_perf_stats *stats = bpf_map_lookup_elem(&stats_map, &key);
	if (stats) {
		__sync_fetch_and_add(&stats->error_packets, 1);
		stats->last_error_time = bpf_ktime_get_ns();
	}
}

/* XDP 错误监控程序 */
SEC("xdp")
int xdp_error_monitor(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	__u32 key = 0;
	struct xdp_perf_stats *stats;

	/* 更新总包数统计 */
	stats = bpf_map_lookup_elem(&stats_map, &key);
	if (stats) {
		__sync_fetch_and_add(&stats->total_packets, 1);
	}

	/* 检查数据包边界 */
	if (data > data_end) {
		record_error(ctx, ERR_OUT_OF_BOUNDS, (__u64)data, 0);
		return XDP_PASS;
	}

	/* 这里可以添加更多的检查逻辑 */
	/* 例如：检查特定的错误模式 */

	return XDP_PASS;
}

/* 追踪 BPF 程序运行时错误 */
SEC("fentry/bpf_throw")
int BPF_PROG(fentry_bpf_throw, __u64 cookie, __u64 addr, __u32 insn_idx)
{
	struct xdp_error_event event = {};
	__u64 flags = BPF_F_CURRENT_CPU;

	event.timestamp = bpf_ktime_get_ns();
	event.cpu = bpf_get_smp_processor_id();
	event.pid = bpf_get_current_pid_tgid() >> 32;
	event.error_type = ERR_RUNTIME_ERROR;
	event.error_addr = addr;
	event.instruction = insn_idx;

	/* 在 fentry 程序中，使用 NULL 作为 ctx */
	bpf_perf_event_output(NULL, &events, flags, &event, sizeof(event));

	return 0;
}
