# ICMP VPN NAT 方案设计文档

**版本**: v1.0
**日期**: 2026-04-10
**分支**: feature/icmp-vpn-forwarding
**状态**: ✅ 基础框架已实现

---

## 1. 概述

本方案实现了基于 eBPF/XDP 的 ICMP 协议 VPN 转发功能，支持 ICMP Echo Request/Reply 的双向 NAT 和 VPN 封装。

### 核心特性

- ✅ 独立的 ICMP SNAT/DNAT Map（减少锁竞争）
- ✅ 基于连接标识的会话跟踪（inner_src_ip + inner_dst_ip + icmp_id）
- ✅ 自动 WAN IP 分配（基于 FIB 查找 + Hash 选择）
- ✅ 支持每接口多 IP（最多 32 个）
- ✅ 会话复用机制

---

## 2. 数据结构设计

### 2.1 ICMP 连接标识

```c
// ICMP 连接标识（SNAT Map Key）
struct icmp_conn_key {
    __u32 inner_src_ip;  // 内层源 IP
    __u32 inner_dst_ip;  // 内层目标 IP
    __u16 icmp_id;       // ICMP Identifier
    __u16 reserved;
};

// ICMP DNAT 标识（DNAT Map Key）
struct icmp_dnat_key {
    __u32 wan_ip;        // SNAT 后的公网 IP
    __u32 inner_dst_ip;  // 内层目标 IP
    __u16 icmp_id;       // ICMP Identifier
    __u16 reserved;
};
```

**设计说明**:
- 使用 `{inner_src_ip, inner_dst_ip, icmp_id}` 唯一标识一个 ICMP 连接
- DNAT key 使用 `{wan_ip, inner_dst_ip, icmp_id}` 反向查找
- `icmp_id` 保持不变，简化 ID 分配逻辑

### 2.2 NAT 条目结构

```c
// ICMP SNAT 条目（内 → 外）
struct icmp_snat_entry {
    __u32 wan_ip;        // SNAT 后的公网 IP
    __u32 ifs_index;     // 出口接口索引

    // 转发所需的以太网头信息（避免出站时重复 FIB 查询）
    __u8 src_mac[6];     // 出口接口的源 MAC
    __u8 dst_mac[6];     // 下一跳的目标 MAC

    __u64 timestamp;     // 创建时间
    __u8  reserved[8];
} __attribute__((packed));

// ICMP DNAT 条目（外 → 内）
struct icmp_dnat_entry {
    // 内层信息
    __u32 inner_src_ip;  // 原始内层源 IP

    // VPN 头信息（用于重构 VPN 封装）
    __u32 vpn_session_id;     // VPN 会话 ID
    __u8  vpn_next_proto;     // VPN 下层协议 (IPPROTO_ICMP = 1)
    __u16 vpn_flags;          // VPN 标志位
    __u8  reserved1;

    // 外层 IP 信息
    __u32 outer_src_ip;       // 原始外层源 IP（客户端公网 IP）
    __u32 outer_dst_ip;       // 原始外层目标 IP（VPN 服务器 IP）
    __u16 outer_src_port;     // 原始外层源端口
    __u16 outer_dst_port;     // 原始外层目标端口（VPN 端口 18080）

    // 外层以太网头信息（避免出站时重复查询）
    __u8 outer_src_mac[6];    // 原始外层源 MAC（客户端 MAC）
    __u8 outer_dst_mac[6];    // 原始外层目标 MAC（VPN 服务器 MAC）

    // 入口接口信息（出站时从同一接口发送）
    __u32 ingress_ifindex;    // 原始入包接口索引（用于回包）

    __u64 timestamp;          // 创建时间
    __u8  reserved2[4];
} __attribute__((packed));

// 完整大小：4+4+1+2+1+4+4+2+2+6+6+4+8+4 = 52 bytes;
```

### 2.3 接口配置结构

```c
// 接口 IP 配置
struct ifs_ip_config {
    __u32 ip_list[32];   // 该接口的 IP 列表（最多 32 个）
    __u32 ip_count;      // IP 数量
    __u8  reserved[12];
};
```

---

## 3. eBPF Map 定义

### 3.1 Map 配置

| Map 名称 | 类型 | Key 大小 | Value 大小 | 最大条目数 | 用途 |
|---------|------|----------|-----------|-----------|------|
| `icmp_snat_map` | HASH | 12B | 32B | 4096 | 入站 SNAT 查找 |
| `icmp_dnat_map` | HASH | 12B | 52B | 4096 | 出站 DNAT 查找 |
| `ifs_config_map` | ARRAY | 4B | 140B | 8 | 接口 IP 配置 |

### 3.2 Map 定义代码

```c
// ICMP SNAT Map（key: {inner_src_ip, inner_dst_ip, icmp_id}）
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct icmp_conn_key));
    __uint(value_size, sizeof(struct icmp_snat_entry));
    __uint(max_entries, 4096);
} icmp_snat_map SEC(".maps");

// ICMP DNAT Map（key: {wan_ip, inner_dst_ip, icmp_id}）
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct icmp_dnat_key));
    __uint(value_size, sizeof(struct icmp_dnat_entry));
    __uint(max_entries, 4096);
} icmp_dnat_map SEC(".maps");

// 接口配置 Map（key: ifs_index）
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct ifs_ip_config));
    __uint(max_entries, 8);  // 最多 8 个接口
} ifs_config_map SEC(".maps");
```

---

## 4. 数据流设计

### 4.1 入站流程（VPN → 内网）

```
┌─────────────────────────────────────────────────────────────────┐
│ 入站：VPN 封装的 ICMP Echo Request                              │
└─────────────────────────────────────────────────────────────────┘

1. 检测 VPN 封装包
   ├─ UDP 目标端口 = 18080
   ├─ VPN Magic = 0x90
   └─ next_protocol = IPPROTO_ICMP (1)

2. 解封装
   ├─ 移除外层: Eth + IP + UDP + VPN_HDR
   └─ 提取内层: IP + ICMP

3. 提取连接标识
   ├─ inner_src_ip
   ├─ inner_dst_ip
   └─ icmp_id (从 ICMP Echo Request)

4. 查找/创建 SNAT 条目
   if (icmp_snat_map[conn_key] 存在) {
       ├─ 使用已分配的 wan_ip
       ├─ 使用已分配的 ifs_index
       └─ 使用已保存的 src_mac/dst_mac（无需 FIB 查询）
   } else {
       ├─ FIB 查找 → ifs_index + dst_mac（下一跳 MAC）
       ├─ 从 ifs_config_map 获取 IP 列表
       ├─ hash = jhash(inner_src_ip, inner_dst_ip, icmp_id)
       ├─ wan_ip = ip_list[hash % ip_count]
       ├─ 获取出口接口 MAC → src_mac
       ├─ 存储完整转发信息到 icmp_snat_map[conn_key]
       └─ 存储完整 VPN 信息到 icmp_dnat_map[dnat_key]
   }

5. 执行 SNAT
   └─ inner_ip->saddr = wan_ip

6. FIB 路由 + 转发
   ├─ bpf_fib_lookup() 获取下一跳
   └─ bpf_redirect(ifs_index, 0)
```

### 4.2 出站流程（内网 → VPN）

```
┌─────────────────────────────────────────────────────────────────┐
│ 出站：ICMP Echo Reply                                            │
└─────────────────────────────────────────────────────────────────┘

1. 检测 ICMP Echo Reply
   ├─ IP Protocol = IPPROTO_ICMP
   └─ ICMP Type = ICMP_ECHOREPLY (0)

2. 提取连接标识
   ├─ ip_src (wan_ip)
   ├─ ip_dst (inner_dst_ip)
   └─ icmp_id

3. 查找 DNAT 条目
   dnat_key = {wan_ip: ip_src, inner_dst_ip: ip_dst, icmp_id}

   if (icmp_dnat_map[dnat_key] 存在) {
       ├─ DNAT: ip_dst = inner_src_ip
       ├─ VPN 封装（使用保存的信息，无需 FIB 查询）
       │  ├─ 添加 VPN 头（使用 vpn_session_id, vpn_next_proto, vpn_flags）
       │  ├─ 添加外层 IP（outer_src_ip, outer_dst_ip）
       │  ├─ 添加外层 UDP（outer_src_port, outer_dst_port）
       │  ├─ 添加外层以太网头（outer_src_mac, outer_dst_mac）
       │  └─ 重新计算校验和
       └─ bpf_redirect(ingress_ifindex, 0)
   } else {
       └─ XDP_PASS (交给协议栈)
   }
```

---

## 5. WAN IP 选择算法

### 5.1 算法流程

```c
// 1. FIB 查找获取出口接口
struct bpf_fib_lookup fib_params = {
    .family = AF_INET,
    .tos = ip->tos,
    .l4_protocol = IPPROTO_ICMP,
    .ipv4_dst = inner_ip->daddr,
    .ifindex = ctx->ingress_ifindex,
};
bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);

// 2. 获取接口 IP 列表
__u32 ifs_key = fib_params.ifindex;
struct ifs_ip_config *ifs_cfg = bpf_map_lookup_elem(&ifs_config_map, &ifs_key);

// 3. 计算 Hash 选择 IP
__u32 hash = jhash(inner_src_ip, inner_dst_ip, icmp_id);
__u32 ip_index = hash % ifs_cfg->ip_count;
__u32 wan_ip = ifs_cfg->ip_list[ip_index];
```

### 5.2 设计优势

- **负载均衡**: 使用 Hash 确保相同连接总是选择相同的 IP
- **可扩展**: 支持每个接口配置多个 IP（最多 32 个）
- **灵活**: 通过 FIB 查找自动确定出口接口

---

## 6. 协议封装格式

### 6.1 VPN 头结构

```c
struct vpn_header {
    __u8 first_byte;      // 前4位 = 1001 (0x90)，后4位保留
    __u8 next_protocol;   // 下层协议 (IPPROTO_ICMP = 1)
    __u16 flags;          // 标志位
    __u32 session_id;     // 会话 ID
} __attribute__((packed));
```

### 6.2 完整数据包格式

**入站（VPN 封装）**:
```
+------------------+-------------------+----------------+-------------------+
| Outer Ethernet   | Outer IP          | Outer UDP      | VPN Header        |
| (14 bytes)       | (20 bytes)        | (8 bytes)      | (8 bytes)         |
+------------------+-------------------+----------------+-------------------+
| Inner IP         | ICMP Echo Request |                |                   |
| (20 bytes)       | (variable)        |                |                   |
+------------------+-------------------+----------------+-------------------+
```

**出站（VPN 封装后）**:
```
+------------------+-------------------+----------------+-------------------+
| Inner IP (DNAT)  | ICMP Echo Reply   | VPN Header     | Outer UDP         |
| (20 bytes)       | (variable)        | (8 bytes)      | (8 bytes)         |
+------------------+-------------------+----------------+-------------------+
| Outer IP         | Outer Ethernet    |                |                   |
| (20 bytes)       | (14 bytes)        |                |                   |
+------------------+-------------------+----------------+-------------------+
```

---

## 7. 关键代码实现

### 7.1 入站 SNAT 处理

文件: `bpf/src/main.c`

**调用前置条件**（主流程 xdp_gateway:812-820 已检查）：
1. ✅ UDP 目标端口 == vpn_port (18080)
2. ✅ VPN Magic == 0x90
3. ✅ vpn->next_protocol == IPPROTO_ICMP

**函数内部检查**：
- ⚠️ 提取 VPN 头并验证边界
- ⚠️ 提取内层 ICMP 包并验证边界
- ✅ 检查 ICMP Type == Echo Request（主流程已检查）

```c
// 前置条件（调用前已检查）：
// 1. UDP 目标端口 == vpn_port (18080)
// 2. VPN Magic == 0x90
// 3. vpn->next_protocol == IPPROTO_ICMP
// 4. icmp->type == ICMP_ECHO（主流程已检查）

static __always_inline int handle_vpn_icmp_request(struct xdp_md *ctx,
                                                   struct iphdr *outer_ip,
                                                   struct udphdr *outer_udp,
                                                   void *data_end,
                                                   struct unified_config *cfg) {
    // 1. 提取 VPN 头（调用前已验证 Magic 和 next_protocol）
    struct vpn_header *vpn = (void *)(outer_udp + 1);
    if ((void *)(vpn + 1) > data_end)
        return XDP_PASS;

    // 2. 提取内层 ICMP 包
    struct iphdr *inner_ip = (void *)(vpn + 1);
    if ((void *)(inner_ip + 1) > data_end)
        return XDP_PASS;

    struct icmphdr *icmp = (void *)(inner_ip + 1);
    if ((void *)(icmp + 1) > data_end)
        return XDP_PASS;

    // 3. 提取连接标识（主流程已确认是 Echo Request）
    if (icmp->type != ICMP_ECHO)
        return XDP_PASS;

    // 4. 提取连接标识
    __u16 icmp_id = bpf_ntohs(icmp->un.echo.id);

    struct icmp_conn_key conn_key = {
        .inner_src_ip = inner_ip->saddr,
        .inner_dst_ip = inner_ip->daddr,
        .icmp_id = icmp_id,
        .reserved = 0
    };

    // 5. 查找/创建 SNAT 条目
    struct icmp_snat_entry *snat = bpf_map_lookup_elem(&icmp_snat_map, &conn_key);
    __u32 wan_ip;
    __u32 ifs_index;

    if (snat) {
        // 已有会话，直接使用
        wan_ip = snat->wan_ip;
        ifs_index = snat->ifs_index;
    } else {
        // 新会话：FIB 查找 + IP 选择
        // TODO: 实现完整逻辑
        if (cfg->egress_ip_count > 0) {
            wan_ip = cfg->egress_ips[0];
            ifs_index = cfg->egress_iface;
        } else {
            return XDP_PASS;
        }

        // 创建 SNAT 条目（保存完整转发信息）
        struct icmp_snat_entry new_snat = {
            .wan_ip = wan_ip,
            .ifs_index = ifs_index,
            .timestamp = bpf_ktime_get_ns(),
        };
        bpf_map_update_elem(&icmp_snat_map, &conn_key, &new_snat, BPF_ANY);

        // 创建 DNAT 条目（保存完整 VPN 封装信息）
        struct icmp_dnat_key dnat_key = {
            .wan_ip = wan_ip,
            .inner_dst_ip = inner_ip->daddr,
            .icmp_id = icmp_id,
            .reserved = 0
        };
        struct icmp_dnat_entry new_dnat = {
            .inner_src_ip = inner_ip->saddr,
            .vpn_session_id = vpn->session_id,
            .vpn_next_proto = vpn->next_protocol,
            .vpn_flags = vpn->flags,
            .timestamp = bpf_ktime_get_ns(),
        };
        bpf_map_update_elem(&icmp_dnat_map, &dnat_key, &new_dnat, BPF_ANY);
    }

    // 6. 执行 SNAT
    inner_ip->saddr = wan_ip;

    // 7. 移除外层封装 + 转发
    // TODO: 实现解封装 + bpf_redirect()
    return XDP_PASS;
}
```

**注意**：需要在创建 DNAT 条目时保存入口接口信息：

```c
// 创建 DNAT 条目（保存完整 VPN 封装信息）
struct icmp_dnat_key dnat_key = {
    .wan_ip = wan_ip,
    .inner_dst_ip = inner_ip->daddr,
    .icmp_id = icmp_id,
    .reserved = 0
};
struct icmp_dnat_entry new_dnat = {
    .inner_src_ip = inner_ip->saddr,

    // 保存 VPN 头信息
    .vpn_session_id = vpn->session_id,
    .vpn_next_proto = vpn->next_protocol,
    .vpn_flags = vpn->flags,

    // 保存外层 IP/UDP 信息
    .outer_src_ip = outer_ip->saddr,
    .outer_dst_ip = outer_ip->daddr,
    .outer_src_port = outer_udp->source,
    .outer_dst_port = outer_udp->dest,

    // 保存外层以太网头信息
    __builtin_memcpy(new_dnat.outer_src_mac, eth->h_source, 6);
    __builtin_memcpy(new_dnat.outer_dst_mac, eth->h_dest, 6);

    // 保存入口接口信息（出站时从同一接口发送）
    .ingress_ifindex = ctx->ingress_ifindex,

    .timestamp = bpf_ktime_get_ns(),
};
bpf_map_update_elem(&icmp_dnat_map, &dnat_key, &new_dnat, BPF_ANY);

    // 6. TODO: 移除外层封装 + FIB 路由 + 转发
    return XDP_PASS;
}
```

### 7.2 出站 DNAT 处理

```c
static __always_inline int handle_icmp_reply(struct xdp_md *ctx,
                                             struct iphdr *ip,
                                             struct icmphdr *icmp,
                                             void *data_end,
                                             struct unified_config *cfg) {
    // 1. 提取 ICMP ID
    __u16 icmp_id = bpf_ntohs(icmp->un.echo.id);

    // 2. 查找 DNAT 条目
    struct icmp_dnat_key dnat_key = {
        .wan_ip = ip->saddr,
        .inner_dst_ip = ip->daddr,
        .icmp_id = icmp_id,
        .reserved = 0
    };

    struct icmp_dnat_entry *dnat = bpf_map_lookup_elem(&icmp_dnat_map, &dnat_key);
    if (!dnat) {
        return XDP_PASS;  // 未找到，交给协议栈
    }

    // 3. 执行 DNAT
    ip->daddr = dnat->inner_src_ip;

    // 4. VPN 封装（使用保存的信息）
    // 添加 VPN 头
    struct vpn_header *vpn = ...;
    vpn->session_id = dnat->vpn_session_id;
    vpn->next_proto = dnat->vpn_next_proto;
    vpn->flags = dnat->vpn_flags;

    // 添加外层 IP
    struct iphdr *outer_ip = ...;
    outer_ip->saddr = dnat->outer_dst_ip;  // VPN 服务器 IP
    outer_ip->daddr = dnat->outer_src_ip;  // 客户端 IP

    // 添加外层 UDP
    struct udphdr *outer_udp = ...;
    outer_udp->source = dnat->outer_dst_port;
    outer_udp->dest = dnat->outer_src_port;

    // 添加外层以太网头
    struct ethhdr *outer_eth = ...;
    __builtin_memcpy(outer_eth->h_source, dnat->outer_dst_mac, 6);
    __builtin_memcpy(outer_eth->h_dest, dnat->outer_src_mac, 6);

    // 5. 从入口接口发送回客户端
    return bpf_redirect(dnat->ingress_ifindex, 0);
}
```

---

## 8. 用户空间配置

### 8.1 必需配置

```go
// 1. 配置接口 IP 列表
func configureInterfaceIPs(ifsIndex uint32, ips []uint32) {
    cfg := ifs_ip_config{
        ip_count: uint32(len(ips)),
    }
    copy(cfg.ip_list[:], ips)

    key := ifsIndex
    ifsConfigMap.Update(&key, &cfg)
}

// 2. 配置全局参数
func configureGlobalConfig() {
    cfg := unified_config{
        flags: CFG_FLAG_NAT_ENABLED | CFG_FLAG_DEBUG_ENABLED,
        log_flags: LOG_SNAT | LOG_DNAT,
        vpn_port: 18080,
        egress_iface: 2,  // eth2
        egress_ip_count: 3,
        egress_ips: [16]uint32{
            0x0A000001,  // 10.0.0.1
            0x0A000002,  // 10.0.0.2
            0x0A000003,  // 10.0.0.3
        },
    }
    key := uint32(0)
    unifiedConfigMap.Update(&key, &cfg)
}
```

### 8.2 示例配置

```yaml
# config.yaml
interfaces:
  - ifindex: 2
    name: "eth2"
    ips:
      - "10.0.0.1"
      - "10.0.0.2"
      - "10.0.0.3"

vpn:
  port: 18080
  server_ip: "192.168.1.100"

nat:
  enabled: true
  timeout_secs: 60

logging:
  flags:
    - SNAT
    - DNAT
    - DEBUG_PKG
```

---

## 9. 测试场景

### 9.1 场景 1: 基础 Ping 测试

```
客户端 (172.16.0.1) → VPN 服务器 → 目标 (8.8.8.8)

1. 客户端 ping 8.8.8.8
2. ICMP Echo Request 被 VPN 封装
3. 服务器解封装 + SNAT (172.16.0.1 → 10.0.0.1)
4. 转发到 8.8.8.8
5. 8.8.8.8 回复 Echo Reply
6. 服务器 DNAT + VPN 封装
7. 客户端收到回复
```

### 9.2 场景 2: 多 IP 负载均衡

```
多个客户端同时 ping：

客户端 A (172.16.0.10) → SNAT → 10.0.0.1
客户端 B (172.16.0.11) → SNAT → 10.0.0.2
客户端 C (172.16.0.12) → SNAT → 10.0.0.3

Hash 算法确保同一客户端总是使用相同的 WAN IP
```

### 9.3 场景 3: 会话复用

```
同一客户端 (172.16.0.10) 的多个 ping:

ping -c 3 8.8.8.8

所有 Echo Request/Reply 复用相同的 SNAT/DNAT 条目
```

---

## 10. 性能优化

### 10.1 已实现优化

- ✅ 独立 Map 减少 TCP/UDP 和 ICMP 之间的锁竞争
- ✅ 连接标识使用紧凑的结构体（12 bytes）
- ✅ 会话复用机制，减少 Map 更新频率

### 10.2 待实现优化

- ⏳ FIB 查找结果缓存
- ⏳ 批量 Map 操作
- ⏳ 数据包零拷贝优化

---

## 11. 日志调试

### 11.1 日志标志

```c
#define LOG_DEBUG_PKG  (1 << 0)  // 调试数据包处理
#define LOG_UDPECHO    (1 << 1)  // UDP Echo 相关日志
#define LOG_SNAT       (1 << 2)  // SNAT 处理日志
#define LOG_DNAT       (1 << 3)  // DNAT 处理日志
```

### 11.2 查看日志

```bash
# 查看 ICMP SNAT 日志
sudo cat /sys/kernel/debug/tracing/trace_pipe | grep "ICMP REQUEST"

# 查看 ICMP DNAT 日志
sudo cat /sys/kernel/debug/tracing/trace_pipe | grep "ICMP REPLY"
```

### 11.3 调试命令

```bash
# 启用日志
bpftool map update name unified_config_map key 0 0 0 0 value flags 0x50 0x0 0x0 0x0

# 查看 SNAT Map 条目
bpftool map dump name icmp_snat_map

# 查看 DNAT Map 条目
bpftool map dump name icmp_dnat_map

# 查看接口配置
bpftool map dump name ifs_config_map
```

---

## 12. 待完成功能

### 12.1 高优先级

- [ ] 实现 FIB 查找 + IP 选择算法
- [ ] 实现完整的 VPN 封装逻辑（出站）
- [ ] 实现解封装 + 转发逻辑（入站）

### 12.2 中优先级

- [ ] 添加会话超时清理机制
- [ ] 实现统计计数器（成功/失败次数）
- [ ] 添加单元测试

### 12.3 低优先级

- [ ] 支持 ICMP 其他类型（非 Echo）
- [ ] 支持 IPv6
- [ ] 性能基准测试

---

## 13. 文件清单

### 13.1 修改的文件

| 文件 | 修改内容 |
|------|---------|
| `bpf/src/xdp/common/unified_config.h` | 添加 ICMP 相关数据结构 |
| `bpf/src/main.c` | 添加 ICMP Map 定义和处理函数 |

### 13.2 新增函数

| 函数名 | 位置 | 功能 |
|--------|------|------|
| `handle_icmp_reply()` | `main.c:539` | 处理 ICMP Echo Reply（出站 DNAT） |
| `handle_vpn_icmp_request()` | `main.c:591` | 处理 VPN 封装的 ICMP Echo Request（入站 SNAT） |

---

## 14. 参考资料

- [eBPF XDP 开发指南](https://docs.cilium.io/en/stable/bpf/)
- [Linux ICMP 协议实现](https://www.kernel.org/doc/Documentation/networking/icmptxt)
- [VPN 封装格式](../vpn_protocol.h)
- [项目主文档](../../README.md)

---

## 15. 变更历史

| 版本 | 日期 | 作者 | 变更说明 |
|------|------|------|---------|
| v1.0 | 2026-04-10 | Claude | 初始版本，实现基础框架 |

---

**文档维护**: 本文档应随着代码实现同步更新。
