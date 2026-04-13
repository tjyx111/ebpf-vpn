# XDP 常用命令

## 查看 XDP 程序状态

### 查看指定网卡上的 XDP 程序
```bash
ip link show lo
```

### 查看所有 XDP 链接
```bash
bpftool net show
```

### 查看指定网卡上的 XDP 详情
```bash
bpftool net show | grep -A5 lo
```

## 卸载 XDP 程序

### 方法一：通过 ip 命令（普通模式）
```bash
ip link set dev <网卡名> xdpgeneric off
```

### 方法二：通过 ip 命令（驱动模式）
```bash
ip link set dev <网卡名> xdp off
```

### 方法三：强制卸载
```bash
ip link set dev <网卡名> xdpgeneric off force
```

### 方法四：通过 bpftool（推荐，适用于 link 模式）

1. 查找 XDP link ID
```bash
bpftool link list
```

2. 删除对应的 link
```bash
bpftool link detach id <link_id>
```

## 完整示例：卸载 lo 接口上的 XDP

```bash
# 1. 查看 XDP 状态
bpftool net show | grep -A5 lo

# 2. 查找 link ID（假设显示 id 51）
bpftool link list | grep -B2 51

# 3. 卸载 link（假设 link id 是 8）
bpftool link detach id 8

# 4. 验证卸载成功
ip link show lo
```

## 加载 XDP 程序

### Generic 模式（不依赖驱动）
```bash
ip link set dev <网卡名> xdpgeneric pinned <path/to/program.o>
```

### 原生模式（需要网卡驱动支持）
```bash
ip link set dev <网卡名> xdp pinned <path/to/program.o>
```

### Offload 模式（卸载到网卡硬件）
```bash
ip link set dev <网卡名> xdpdrv pinned <path/to/program.o>
```

## 查看 BPF 程序信息

### 列出所有 BPF 程序
```bash
bpftool prog show
```

### 查看 XDP 程序详情
```bash
bpftool prog show xdp
```

### 查看指定程序详情
```bash
bpftool prog dump xlated id <prog_id>
```
