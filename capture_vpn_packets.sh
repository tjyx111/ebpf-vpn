#!/bin/bash
# 捕获 VPN 数据包脚本（dst port 18080）
# 用法: sudo ./capture_vpn_packets.sh [接口名称] [pcap文件路径]

IFACE=${1:-eth0}
PCAP_FILE=${2:-vpn_18080_capture.pcap}

echo "=========================================="
echo "  VPN 数据包捕获工具"
echo "=========================================="
echo "接口: $IFACE"
echo "PCAP 文件: $PCAP_FILE"
echo "抓包规则: UDP dst port 18080"
echo "=========================================="
echo ""

# 检查是否有 root 权限
if [ "$EUID" -ne 0 ]; then
    echo "错误: 需要 root 权限运行此脚本"
    echo "请使用: sudo $0 $IFACE $PCAP_FILE"
    exit 1
fi

# 检查 xdp-loader 是否存在
if [ ! -f "./xdp-loader" ]; then
    echo "错误: 找不到 xdp-loader"
    echo "请先运行: go build -o xdp-loader ./cmd/xdp-loader"
    exit 1
fi

echo "启动 XDP 程序并捕获数据包..."
echo "按 Ctrl+C 停止捕获"
echo ""

# 启动 xdp-loader
sudo ./xdp-loader \
    --iface "$IFACE" \
    --config config.toml \
    --pcap "$PCAP_FILE"
