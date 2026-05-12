# Rust XDP UDP Echo Demo

最简单的 Rust XDP UDP Echo 示例，监听端口 28080。

## 功能

- 在 lo 网卡上拦截 UDP 数据包
- 检查目标端口是否为 28080
- 交换源/目的 MAC、IP、端口
- 通过 XDP_TX 从原接口返回数据包

## 构建

```bash
# 确保已安装 Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# 安装 Aya 工具
cargo install aya-cli

# 构建 eBPF 程序
cd xdp-prog
cargo build --release

# 构建加载程序
cd ../xdp-loader
cargo build --release
```

## 运行

```bash
# 加载 XDP 程序到 lo 网卡
sudo ./target/release/xdp-loader

# 测试 UDP Echo
nc -u 127.0.0.1 28080
# 输入文本后回车，会立即收到回显
```

## 调试

```bash
# 查看 BPF 日志
sudo cat /sys/kernel/debug/tracing/trace_pipe

# 查看 XDP 程序状态
sudo bpftool net show dev lo
```

## 清理

```bash
# 卸载 XDP 程序
sudo ip link set lo xdpgeneric off
```
