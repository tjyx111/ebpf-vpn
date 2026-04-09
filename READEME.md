### 编译xdp
- `cd bpf/src && clang -O2 -target bpf -c xdp_pass.c -o xdp_pass.o`

### 测试网卡是否支持xdp驱动
- `ip link set dev enp0s8 xdpgeneric obj xdp_pass.o sec xdp`
- `ip link set dev enp0s8 xdpgeneric off`