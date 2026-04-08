# Claude 项目配置

**项目:** ebpf-vpn
**工作目录:** /root/lbs/private/ebpf-vpn
**主要分支:** main
**文档版本:** v2.3 (2026-04-08)

---

## 项目工作流程约束

在 /root/lbs/private/ebpf-vpn 项目中工作时，必须遵守以下约束：

### 1. 设计优先原则 ⚠️

**修改任何代码前，必须先与用户确认以下信息：**

- **数据流** - 数据如何在各层/模块间流转
- **函数参数** - 函数输入输出参数定义
- **结构体** - 数据结构定义和内存布局
- **Map 定义** - eBPF Map 的键值类型和用途
- **处理逻辑** - 具体的处理流程和分支条件

用户确认设计方案后，方可进行编码。

### 2. 文件创建约束

- **不要主动创建任何文档** - 不得创建 README、说明文档等文件
- **不要主动创建任何脚本** - 不得创建辅助脚本、构建脚本等
- **创建新目录/文件前必须询问** - 在新建任何文件或目录前必须先征求用户同意

### 3. 代码质量约束

- **确保代码可回滚** - 修改任何功能前需考虑回滚方案
- **以专家角度提供建议** - 基于技术最佳实践给出专业意见
- **敏捷迭代** - 每次只专注完成一个具体需求，小步快跑

---

## 架构概览

### XDP 程序架构

本系统使用两个独立的 XDP 程序分别处理入站和出站流量：

#### 1. 入站网关 (`xdp_vpn_gateway` / `xdp_vpn_gateway_fixed`)
- **功能**: VPN 解封装 + SNAT + 路由转发
- **处理流程**:
  1. 检查是否是 VPN 封装包 (UDP 端口 18080)
  2. 移除外层封装 (Eth + IP + UDP + VPN_HDR)
  3. 执行 SNAT (源地址转换)
  4. FIB 路由查找
  5. 重定向到出站网卡

#### 2. 出站封装 (`xdp_vpn_encap`)
- **功能**: DNAT + VPN 封装
- **处理流程**:
  1. 检查 DNAT 规则表
  2. 执行 DNAT (目标地址转换)
  3. 添加 VPN 封装头
  4. 使用 XDP_TX 发送

### 判断逻辑

**入站网关**:
```c
if (iph->protocol == IPPROTO_UDP &&
    udph->dest == VPN_PORT &&
    valid_vpn_header) {
    // 解封装 + SNAT + 转发
    return bpf_redirect_map();
}
// 否则放行
return XDP_PASS;
```

**出站封装**:
```c
if (dnat_map[iph->daddr] 存在) {
    // DNAT + VPN 封装 + 回包
    return XDP_TX;
}
// 否则放行
return XDP_PASS;
```

### 配置项说明

**功能开关 (flags)**:
- `CFG_FLAG_UDP_ECHO_ENABLED (0x01)` - 启用 UDP Echo
- `CFG_FLAG_CAPTURE_ENABLED (0x02)` - 启用抓包
- `CFG_FLAG_VPN_ENABLED (0x04)` - 启用 VPN 处理

**抓包规则**:
- 支持按协议、端口过滤
- 数据通过 Ring Buffer 上传到用户空间

### 关键代码文件

- `bpf/src/xdp/app/xdp_vpn_gateway.c` - 入站网关 (原版)
- `bpf/src/xdp/app/xdp_vpn_gateway_fixed.c` - 入站网关 (修复版)
- `bpf/src/xdp/app/xdp_vpn_encap.c` - 出站封装
- `bpf/src/xdp/common/vpn_protocol.h` - VPN 协议定义
- `cmd/xdp-loader/main.go` - XDP 程序加载器
