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
- ip link set dev eth0 xdp off

### 加载驱动
- ip link set dev eth0 xdp obj xdp_accept.o sec xdp