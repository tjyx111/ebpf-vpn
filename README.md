# ebpf-vpn

## 环境
- ubuntu24.02
- uname -r
  - 6.8.0-71-generic
- ethtool -i eth0
  - driver: virtio_net
  - version: 1.0.0

## 安装依赖
### 安装核心编译工具链
sudo apt install -y \
    clang \
    llvm \
    gcc \
    make

### 安装 eBPF 开发库
sudo apt install -y \
    libbpf-dev \
    libbpf1 \
    linux-headers-$(uname -r) \
    linux-tools-$(uname -r) \
    linux-tools-generic

- apt install build-essential linux-headers-$(uname -r)
- apt install linux-libc-dev libc6-dev gcc-multilib

### 编译测试程序
- clang -g -O2 -target bpf -c xdp_accept.c -o xdp_accept.o
  - 
  ```
    不加 -g 编译 eBPF 程序时，生成的 .o 文件不会包含 BTF（BPF Type Format）调试信息。
    现代内核和 libbpf 默认要求带有 BTF 的对象文件，以便类型检查和 map 自动推断。
    如果没有 BTF，加载时就会报错：libbpf: BTF is required, but is missing or corrupted.
  ```

### 卸载驱动
- ip link set dev ens34 xdp off

### 加载驱动
- ip link set dev ens34 xdp obj xdp_accept.o sec xdp
- 
  ```
  2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 xdp qdisc mq state UP mode DEFAULT group default qlen 1000
    link/ether 52:54:00:cc:bd:e1 brd ff:ff:ff:ff:ff:ff
    prog/xdp id 374 name xdp_firewall tag 548a4000dd379a20 jited 
    altname enp0s5
    altname ens5
  ```

## 如何使用
### 调试日志
1. 程序中打印
  - bpf_trace_printk("UDP Echo: port %d\n", sizeof("UDP Echo: port %d\n"), UDP_ECHO_PORT);
  - 
2. 查看日志
  - cat /sys/kernel/debug/tracing/trace_pipe

### 关于循环使用
- bpf禁用大循环，循环必须有明确的界限

### 关于多核
- 每个CPU核心都可能被分配到网卡的一个或多个RX队列
- 每个核心上的XDP程序是独立执行的
1. 数据包根据五元组被hash到不同的网卡队列
2. 不同的网卡队列根据亲和性被不同cpu核心处理
3. 不同cpu核心都会运行独立的xdp程序
4. 数据包可能会被不同核心处理