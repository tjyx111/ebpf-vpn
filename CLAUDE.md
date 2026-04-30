# ebpf-vpn 项目关键决策与约束

**项目:** ebpf-vpn
**工作目录:** /root/lbs/private/ebpf-vpn
**主要分支:** main
**文档版本:** v1.0 (2026-04-30)

---

## 项目关键决策

### 1. 架构设计决策

#### 决策 1.1: 双 XDP 程序架构
**日期**: 2026-04-08
**决策**: 使用两个独立的 XDP 程序分别处理入站和出站流量
**原因**:
- 入站和出站处理逻辑差异大，分离后更易维护
- 可以独立升级和调试每个程序
- 符合 Unix 哲学：单一职责

**影响**:
- 入站网关 (`xdp_vpn_gateway`) 负责 VPN 解封装 + SNAT + 路由转发
- 出站封装 (`xdp_vpn_encap`) 负责 DNAT + VPN 封装
- 两个程序通过 FIB 路由和 DNAT Map 协同工作

#### 决策 1.2: VPN 端口选择
**日期**: 2026-04-08
**决策**: 使用 UDP 端口 18080 作为 VPN 封装端口
**原因**:
- 避免与常见服务端口冲突
- UDP 性能优于 TCP，适合 VPN 场景
- 易于记忆和识别

#### 决策 1.3: 配置通过 Map 动态加载
**日期**: 2026-04-08
**决策**: 使用 eBPF Map 存储配置，支持运行时动态更新
**原因**:
- 避免重新编译 XDP 程序
- 支持热更新配置
- 用户空间程序可以轻松调整参数

#### 决策 1.4: 配置文件使用小端序，网络处理转换为大端序
**日期**: 2026-04-30
**决策**: 配置文件中的 IP 地址和端口使用小端序（便于人类阅读），Go 加载配置后自动转换为大端序用于网络报文处理
**原因**:
- **配置文件可读性**: 小端序的 IP 和端口更符合人类阅读习惯（例如：192.168.1.1，8080）
- **网络协议标准**: 网络报文中的 IP 地址和端口使用大端序（网络字节序），与数据包字段对比时无需转换
- **性能优化**: 在 eBPF 程序中直接对比大端序值，避免字节序转换开销
- **错误减少**: 自动转换减少手动配置错误的可能性

**影响**:
- 配置文件 (`config.toml`) 中 IP 和端口使用人类友好的小端序格式
- Go 配置加载器 (`internal/config/loader.go`) 负责将网络相关配置转换为大端序
- eBPF Map 中存储的 IP 和端口为大端序，可直接与网络报文字段对比
- 新增网络相关配置时，必须在 Go 加载器中添加端序转换逻辑

**示例**:
```toml
# config.toml (小端序，便于人类阅读)
[vpn.server]
listen_ip = "0.0.0.0"        # 字符串格式
listen_port = 18080          # 小端序整数

# Go 加载器转换后
listen_ip = 0x00000000       # 大端序 uint32
listen_port = 0x4690         # 大端序 uint16 (18080 的大端序)
```

#### 决策 1.5: 修复端序相关的代码问题
**日期**: 2026-04-30
**决策**: 修复抓包规则端口判断的多余端序转换，以及配置类型不匹配问题
**原因**:
- **trace.h 端口判断错误**: 抓包规则端口已经是大端序，错误地使用了 `bpf_htons()` 再次转换，导致端口匹配失败
- **类型不匹配**: Go 端 `UDPEchoPort` 使用 `uint32`，C 端使用 `__u16`，可能导致截断和对齐问题

**修复内容**:
1. **trace.h 第76-78行**: 移除 `bpf_htons()` 转换，直接对比大端序端口
   ```c
   // 修复前（错误）
   if (rule->src_port && hdr->source != bpf_htons(rule->src_port))
   if (rule->dst_port && hdr->dest != bpf_htons(rule->dst_port))

   // 修复后（正确）
   if (rule->src_port && hdr->source != rule->src_port)
   if (rule->dst_port && hdr->dest != rule->dst_port)
   ```
2. **loader.go 第42行**: 将 `UDPEchoPort` 类型从 `uint32` 改为 `uint16`，与 C 端保持一致

**影响**:
- 抓包规则的端口过滤功能现在可以正常工作
- UDP Echo 端口配置类型统一，避免潜在的类型转换问题
- 确保所有网络相关配置的大端序处理一致性

---

## 项目特定约束

### 1. 代码结构约束

- **XDP 程序文件位置**: 必须放在 `bpf/src/xdp/app/` 目录
- **通用头文件位置**: 必须放在 `bpf/src/xdp/common/` 目录
- **加载器入口**: `cmd/xdp-loader/main.go`
- **配置文件格式**: TOML (`config.toml`)

### 2. 性能约束

- **XDP 程序必须使用 FIB 路由查找**，避免硬编码路由表
- **避免在 XDP 程序中使用循环**，防止 eBPF 验证器拒绝
- **数据包处理必须在 64 个 eBPF 指令内完成**，确保高性能
- **使用 per-CPU Map 减少锁竞争**

### 3. 兼容性约束

- **支持内核版本**: 5.10+
- **网卡驱动必须支持 XDP**: 要求 `ndo_xdp_xmit` 驱动支持
- **必须处理两种 XDP 模式**: native (SKB) 和 offloaded

### 4. 安全约束

- **所有数据包必须进行边界检查**，使用 `bpf_probe_read_kernel()`
- **验证器必须通过**: 不能有未验证的指针访问
- **SNAT/DNAT 规则必须校验**: 防止地址欺骗

### 5. 配置端序约束

- **配置文件使用小端序**: IP 地址和端口在配置文件中使用人类友好的格式
  - IP 地址使用字符串格式（如 "192.168.1.1"）或点分十进制
  - 端口使用普通整数（如 8080）
- **Go 加载器必须转换**: 在 `internal/config/loader.go` 中将网络相关配置转换为大端序
  - IP 地址字符串 → 大端序 `uint32`（使用 `binary.BigEndian` 或标准库）
  - 端口整数 → 大端序 `uint16`（使用 `binary.BigEndian.PutUint16()`）
- **eBPF Map 存储大端序**: 所有写入 eBPF Map 的网络字段必须是大端序
- **对比时无需转换**: eBPF 程序中从数据包读取的字段本身就是大端序，可直接与 Map 中的值对比
- **新增配置必遵守**: 添加新的网络相关配置字段时，必须遵守此端序转换规则

**端序转换示例**:
```go
// 小端序（配置文件） → 大端序（eBPF Map）
import (
    "encoding/binary"
    "net"
)

// IP 地址转换
ipStr := "192.168.1.1"
ip := net.ParseIP(ipStr).To4()
ipUint32 := binary.BigEndian.Uint32(ip)  // 大端序

// 端口转换
port := 18080  // 小端序
portBytes := make([]byte, 2)
binary.BigEndian.PutUint16(portBytes, uint16(port))  // 转为大端序
portUint16 := binary.BigEndian.Uint16(portBytes)
```

---

## XDP 程序架构说明

### 入站网关 (`xdp_vpn_gateway` / `xdp_vpn_gateway_fixed`)

**功能**: VPN 解封装 + SNAT + 路由转发

**处理流程**:
1. 检查是否是 VPN 封装包 (UDP 端口 18080)
2. 移除外层封装 (Eth + IP + UDP + VPN_HDR)
3. 执行 SNAT (源地址转换)
4. FIB 路由查找
5. 重定向到出站网卡

**关键代码**:
```c
if (iph->protocol == IPPROTO_UDP &&
    udph->dest == VPN_PORT &&
    valid_vpn_header) {
    return bpf_redirect_map();  // 解封装 + SNAT + 转发
}
return XDP_PASS;
```

### 出站封装 (`xdp_vpn_encap`)

**功能**: DNAT + VPN 封装

**处理流程**:
1. 检查 DNAT 规则表
2. 执行 DNAT (目标地址转换)
3. 添加 VPN 封装头
4. 使用 XDP_TX 发送

**关键代码**:
```c
if (dnat_map[iph->daddr] 存在) {
    return XDP_TX;  // DNAT + VPN 封装 + 回包
}
return XDP_PASS;
```

---

## 配置项说明

### 功能开关 (flags)
- `CFG_FLAG_UDP_ECHO_ENABLED (0x01)` - 启用 UDP Echo
- `CFG_FLAG_CAPTURE_ENABLED (0x02)` - 启用抓包
- `CFG_FLAG_VPN_ENABLED (0x04)` - 启用 VPN 处理

### 抓包规则
- 支持按协议、端口过滤
- 数据通过 Ring Buffer 上传到用户空间

---

## 关键代码文件

- `bpf/src/xdp/app/xdp_vpn_gateway.c` - 入站网关 (原版)
- `bpf/src/xdp/app/xdp_vpn_gateway_fixed.c` - 入站网关 (修复版)
- `bpf/src/xdp/app/xdp_vpn_encap.c` - 出站封装
- `bpf/src/xdp/common/vpn_protocol.h` - VPN 协议定义
- `bpf/src/xdp/common/vpn_config.h` - VPN 配置结构
- `bpf/src/xdp/common/unified_config.h` - 统一配置 Map
- `cmd/xdp-loader/main.go` - XDP 程序加载器

---

## 开发规范

### 添加新功能流程
1. 先在全局约束的"设计优先原则"指导下，与用户确认设计方案
2. 更新此文档的"项目关键决策"部分，记录决策原因
3. 如有新的约束，添加到"项目特定约束"部分
4. 编写代码并测试

### 修改现有功能流程
1. 查阅"项目关键决策"，理解原始设计意图
2. 如需修改决策，记录新决策并说明原因
3. 确保不违反"项目特定约束"
4. 编写代码并测试

---

**注意**: 本文件在项目级加载，在全局约束 (`/root/.claude/custom_instructions.md`) 之后生效。
