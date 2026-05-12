# 🦀 Rust XDP UDP Echo - 快速开始

## ⚠️ 前置要求

### 1. 安装 Rust
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

### 2. 安装 eBPF 开发依赖
```bash
sudo apt update
sudo apt install -y \
    clang \
    llvm \
    libelf-dev \
    linux-headers-$(uname -r)
```

### 3. 安装 Aya 工具
```bash
cargo install aya-cli
```

## 🚀 三步运行

### 步骤 1: 构建
```bash
cd rust-xdp-demo
make build
```

### 步骤 2: 运行
```bash
make run
```

你会看到：
```
🚀 Rust XDP UDP Echo Loader
📡 接口: lo
🎯 UDP 端口: 28080
✅ XDP 程序加载成功!
📝 监听地址: 127.0.0.1:28080
```

### 步骤 3: 测试
在另一个终端：
```bash
nc -u 127.0.0.1 28080
```

输入任意文本，会立即收到回显！

## 📊 代码对比

| 特性 | Rust XDP | C XDP (你的代码) |
|------|----------|------------------|
| 代码行数 | 60 行 | 150+ 行 |
| 类型安全 | ✅ 编译时检查 | ❌ 运行时检查 |
| 内存安全 | ✅ 无泄漏风险 | ❌ 手动管理 |
| 开发体验 | ✅ IDE 自动补全 | ⚠️ 有限 |

## 🔧 调试

查看 BPF 日志：
```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe | grep udp_echo
```

## 📚 学习资源

- **Aya 文档**: https://aya-rs.dev/book/
- **示例代码**: https://github.com/aya-rs/aya-examples
- **Discord 社区**: https://discord.gg/4atVJH3

## 🎯 核心代码

**XDP 程序** (`xdp-prog/src/main.rs`):
```rust
#[xdp]
pub fn udp_echo(ctx: XdpContext) -> u32 {
    let eth = ctx.eth()?;
    let ip = ctx.ip()?;
    let udp = ctx.udp()?;

    // 交换源/目的
    *eth.src_addr = eth.dst_addr;
    *ip.src_addr = ip.dst_addr;
    *udp.source = udp.dest;

    Ok(xdp::XDP_TX)
}
```

就这么简单！🎉
