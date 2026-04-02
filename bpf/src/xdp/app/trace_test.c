#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "trace.h"

// 测试用例1：验证协议匹配
static void test_match_protocol() {
    struct iphdr ip = {
        .protocol = IPPROTO_UDP
    };
    struct filter_rule rule = {
        .protocol = IPPROTO_UDP
    };
    int result = match_filter_rule(&ip, NULL, NULL);
    assert(result == 1);
}

// 测试用例2：验证协议不匹配
static void test_mismatch_protocol() {
    struct iphdr ip = {
        .protocol = IPPROTO_TCP
    };
    struct filter_rule rule = {
        .protocol = IPPROTO_UDP
    };
    int result = match_filter_rule(&ip, NULL, NULL);
    assert(result == 0);
}

// 测试用例3：验证源IP匹配
static void test_match_src_ip() {
    struct iphdr ip = {
        .saddr = 0x01020304
    };
    struct filter_rule rule = {
        .src_ip = 0x01020304
    };
    int result = match_filter_rule(&ip, NULL, NULL);
    assert(result == 1);
}

// 测试用例4：验证源IP不匹配
static void test_mismatch_src_ip() {
    struct iphdr ip = {
        .saddr = 0x01020304
    };
    struct filter_rule rule = {
        .src_ip = 0x04030201
    };
    int result = match_filter_rule(&ip, NULL, NULL);
    assert(result == 0);
}

// 测试用例5：验证目的IP匹配
static void test_match_dst_ip() {
    struct iphdr ip = {
        .daddr = 0x01020304
    };
    struct filter_rule rule = {
        .dst_ip = 0x01020304
    };
    int result = match_filter_rule(&ip, NULL, NULL);
    assert(result == 1);
}

// 测试用例6：验证目的IP不匹配
static void test_mismatch_dst_ip() {
    struct iphdr ip = {
        .daddr = 0x01020304
    };
    struct filter_rule rule = {
        .dst_ip = 0x04030201
    };
    int result = match_filter_rule(&ip, NULL, NULL);
    assert(result == 0);
}

// 测试用例7：验证源端口匹配（UDP）
static void test_match_src_port_udp() {
    struct iphdr ip = {
        .protocol = IPPROTO_UDP
    };
    struct udphdr udp = {
        .source = bpf_htons(8080)
    };
    struct filter_rule rule = {
        .src_port = 8080
    };
    int result = match_filter_rule(&ip, &udp, NULL);
    assert(result == 1);
}

// 测试用例8：验证源端口不匹配（UDP）
static void test_mismatch_src_port_udp() {
    struct iphdr ip = {
        .protocol = IPPROTO_UDP
    };
    struct udphdr udp = {
        .source = bpf_htons(8080)
    };
    struct filter_rule rule = {
        .src_port = 9090
    };
    int result = match_filter_rule(&ip, &udp, NULL);
    assert(result == 0);
}

// 测试用例9：验证目的端口匹配（UDP）
static void test_match_dst_port_udp() {
    struct iphdr ip = {
        .protocol = IPPROTO_UDP
    };
    struct udphdr udp = {
        .dest = bpf_htons(8080)
    };
    struct filter_rule rule = {
        .dst_port = 8080
    };
    int result = match_filter_rule(&ip, &udp, NULL);
    assert(result == 1);
}

// 测试用例10：验证目的端口不匹配（UDP）
static void test_mismatch_dst_port_udp() {
    struct iphdr ip = {
        .protocol = IPPROTO_UDP
    };
    struct udphdr udp = {
        .dest = bpf_htons(8080)
    };
    struct filter_rule rule = {
        .dst_port = 9090
    };
    int result = match_filter_rule(&ip, &udp, NULL);
    assert(result == 0);
}

// 测试用例11：验证数据包边界检查
static void test_data_end_check() {
    struct iphdr ip = {
        .protocol = IPPROTO_UDP
    };
    struct udphdr udp = {
        .source = bpf_htons(8080),
        .dest = bpf_htons(8080)
    };
    void *data_end = (void *)(&udp + 1);
    struct filter_rule rule = {
        .src_port = 8080,
        .dst_port = 8080
    };
    int result = match_filter_rule(&ip, &udp, data_end);
    assert(result == 1);
}

// 测试用例12：验证数据包边界检查失败
static void test_data_end_check_fail() {
    struct iphdr ip = {
        .protocol = IPPROTO_UDP
    };
    struct udphdr udp = {
        .source = bpf_htons(8080),
        .dest = bpf_htons(8080)
    };
    void *data_end = (void *)(&udp); // 故意设置错误的边界
    struct filter_rule rule = {
        .src_port = 8080,
        .dst_port = 8080
    };
    int result = match_filter_rule(&ip, &udp, data_end);
    assert(result == 0);
}

int main() {
    test_match_protocol();
    test_mismatch_protocol();
    test_match_src_ip();
    test_mismatch_src_ip();
    test_match_dst_ip();
    test_mismatch_dst_ip();
    test_match_src_port_udp();
    test_mismatch_src_port_udp();
    test_match_dst_port_udp();
    test_mismatch_dst_port_udp();
    test_data_end_check();
    test_data_end_check_fail();
    return 0;
}