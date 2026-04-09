#include <linux/bpf.h>
// 如果编译提示找不到 bpf_helpers.h，可以去掉这行，在这个基础程序中我们不需要复杂的 helper
// #include <bpf/bpf_helpers.h>

// 定义 SEC 宏
#define SEC(NAME) __attribute__((section(NAME), used))

SEC("xdp")
int xdp_pass_prog(struct xdp_md *ctx) {
    // 所有的包全部放行
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";