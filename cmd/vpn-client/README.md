# VPN 测试客户端

基于 gVisor netstack 的 VPN 测试客户端，将 TCP 流量转换为 VPN 数据包并通过 UDP 发送。

## 功能特性

- 使用 gVisor netstack 实现完整的 TCP/IP 协议栈
- 拦截 IP 层数据包并进行 VPN 封装
- 通过 UDP 发送 VPN 数据包到目标服务器
- 支持配置化的网络参数和 VPN 会话管理

## 目录结构

```
cmd/vpn-client/
├── main.go          # 主程序入口
├── config.go        # 配置管理
├── config.toml      # 配置文件
├── vpn.go           # VPN 协议封装
├── udp_sender.go    # UDP 发送器
├── endpoint.go      # 自定义 LinkEndpoint
├── netstack.go      # gVisor 网络栈
├── go.mod           # Go 模块定义
└── Makefile         # 构建脚本
```

## 数据流

```
应用层 (Go TCP Client)
    ↓ Dial TCP
gVisor Netstack
    ├── TCP 协议栈
    ├── IP 协议栈
    └── 生成完整 IP 数据包
         ↓
VPN LinkEndpoint (拦截 IP 包)
    ├── 提取原始 IP 数据包
    ├── 添加 VPN Header (8 bytes)
    └── Payload = 原始 IP 包
         ↓
UDP Sender
    └── → 目标服务器:28080
         ↓
XDP 程序接收并处理
```

## VPN 协议格式

```
+----------------+----------------+----------------+----------------+
|  first_byte    | next_protocol  |     flags      |               |
|  0x90 (1001)   |  1 (IPv4)      |                |               |
+----------------+----------------+----------------+---------------+
|               session_id (4 bytes)                |               |
+---------------------------------------------------------------+
|                 Original IP Packet (Payload)                   |
|                                                               |
+---------------------------------------------------------------+
```

## 配置说明

编辑 `config.toml` 文件：

```toml
[client]
local_ip = "192.168.1.100"       # 本机 IP (gVisor netstack)
local_port_start = 10000         # 本地端口范围起始
local_port_end = 60000           # 本地端口范围结束

[target]
server_ip = "192.168.1.1"        # VPN 服务器 IP (XDP 所在机器)
server_port = 28080              # VPN 服务器 UDP 端口
tcp_target_ip = "10.0.0.1"       # TCP 目标 IP (通过 VPN 访问的服务)
tcp_target_port = 80             # TCP 目标端口

[vpn]
session_id = 12345               # VPN 会话 ID
timeout = 60                     # 超时时间(秒)

[logging]
enabled = true
level = "debug"
```

## 编译和运行

### 安装依赖

```bash
cd cmd/vpn-client
go mod download
go mod tidy
```

### 编译

```bash
# 使用 Makefile
make build

# 或者直接编译
cd vpn-client && go build -o ../../bin/vpn-client .
```

### 运行

```bash
# 使用 Makefile
make run

# 或者直接运行
./bin/vpn-client -config=cmd/vpn-client/config.toml
```

### 交叉编译

```bash
make build-linux
make build-windows
make build-darwin
```

## 测试场景

### 场景 1: 基本连接测试

客户端连接到目标服务器的 TCP 端口，发送测试数据：

```bash
./bin/vpn-client -config=config.toml
```

程序会：
1. 建立 TCP 连接到 `tcp_target_ip:tcp_target_port`
2. 发送测试数据 "Hello from VPN Client!"
3. 接收服务器响应
4. 打印统计信息

### 场景 2: 与 XDP 程序联调

1. 在服务器端启动 XDP 程序
2. 配置 VPN 服务器 IP 和端口
3. 运行客户端发送 VPN 封装的数据包
4. 观察 XDP 程序的日志输出

### 场景 3: 压力测试

修改 `main.go` 发送大量数据包，观察性能统计。

## 依赖

- Go 1.21+
- gVisor netstack
- toml (配置解析)

## 故障排查

1. **连接失败**
   - 检查 `server_ip` 和 `server_port` 是否正确
   - 确认网络连通性
   - 检查防火墙设置

2. **数据包未发送**
   - 查看 UDP 发送统计信息
   - 检查 `session_id` 配置
   - 确认 VPN 封装是否正确

3. **接收无响应**
   - 检查 XDP 程序是否正确解封装
   - 查看服务器端日志
   - 验证路由配置

## 统计信息

程序运行时会定期打印统计信息：

```
[STATS] Endpoint: 100 packets sent, 15000 bytes, 0 dropped | Sender: 100 packets sent, 0 errors, last send: 2024-01-01 12:00:00
```

## License

MIT License
