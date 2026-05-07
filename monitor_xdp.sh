#!/bin/bash
# XDP 程序监控脚本

set -euo pipefail

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 配置
MONITOR_INTERVAL=5
LOG_FILE="/var/log/xdp-monitor.log"
METRICS_DIR="/var/run/xdp-metrics"

# 创建必要的目录
sudo mkdir -p "$METRICS_DIR"
sudo touch "$LOG_FILE"

echo_info() {
    echo -e "${GREEN}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

echo_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG_FILE"
}

echo_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

# 1. 检查 XDP 程序是否已加载
check_xdp_loaded() {
    local interface=$1
    if ip link show "$interface" 2>/dev/null | grep -q "xdp"; then
        return 0
    else
        return 1
    fi
}

# 2. 获取 XDP 程序统计信息
get_xdp_stats() {
    local interface=$1

    echo_info "=== XDP 程序统计 ($interface) ==="

    # 使用 bpftool 获取统计信息
    if command -v bpftool &> /dev/null; then
        bpftool prog show | grep -A 20 "xdp" || echo_warn "未找到 XDP 程序"
    fi

    # 获取网卡统计
    echo -e "\n网卡统计:"
    ip -s link show "$interface" | grep -E "RX|TX"
}

# 3. 检查 eBPF Map 状态
check_bpf_maps() {
    echo_info "=== eBPF Map 状态 ==="

    if command -v bpftool &> /dev/null; then
        echo -e "\n配置 Map:"
        bpftool map list | grep -i config || echo_warn "未找到配置 Map"

        echo -e "\n统计 Map:"
        bpftool map list | grep -i stats || echo_warn "未找到统计 Map"
    fi
}

# 4. 检查内核日志中的 XDP 相关错误
check_kernel_logs() {
    echo_info "=== 内核日志中的 XDP 错误 ==="

    # 查找最近的 XDP 相关错误
    dmesg -T | grep -i "xdp\|bpf\|ebpf" | tail -20 || echo_warn "未找到相关日志"
}

# 5. 检查 XDP 程序运行时错误
check_xdp_errors() {
    echo_info "=== XDP 运行时错误 ==="

    # 检查是否在 bpf_trace 中记录了错误
    if [ -f /sys/kernel/debug/tracing/trace_pipe ]; then
        timeout 2 cat /sys/kernel/debug/tracing/trace_pipe 2>/dev/null | grep -i "bpf\|xdp" || true
    fi
}

# 6. 监控 XDP 性能指标
monitor_xdp_performance() {
    local interface=$1
    local metrics_file="$METRICS_DIR/xdp_metrics.txt"

    echo_info "=== XDP 性能指标 ==="

    # 获取 XDP 动作统计
    local xdp_stats=$(bpftool prog show 2>/dev/null | grep -A 5 "xdp_" || echo "")

    if [ -n "$xdp_stats" ]; then
        echo "$xdp_stats"
        echo "$xdp_stats" > "$metrics_file"
    else
        echo_warn "无法获取 XDP 统计信息"
    fi

    # 计算丢包率
    local rx_packets=$(ip -s link show "$interface" | grep "RX:" | awk '{print $2}')
    local rx_dropped=$(ip -s link show "$interface" | grep "RX:" | awk '{print $4}')

    if [ "$rx_packets" -gt 0 ]; then
        local drop_rate=$(echo "scale=2; $rx_dropped * 100 / $rx_packets" | bc)
        echo "丢包率: ${drop_rate}%"
    fi
}

# 7. 检查系统资源
check_system_resources() {
    echo_info "=== 系统资源 ==="

    # CPU 使用率
    echo "CPU 使用率:"
    top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1"%"}'

    # 内存使用率
    echo -e "\n内存使用率:"
    free -h | grep Mem

    # 网卡队列
    echo -e "\n网卡队列状态:"
    ethtool -S eth0 2>/dev/null | grep -E "rx_queue|tx_queue" | head -20 || echo_warn "无法获取网卡队列信息"
}

# 8. 生成诊断报告
generate_report() {
    local interface=$1
    local report_file="$METRICS_DIR/xdp_report_$(date +%Y%m%d_%H%M%S).txt"

    {
        echo "XDP 程序诊断报告"
        echo "生成时间: $(date)"
        echo "接口: $interface"
        echo "=========================================="
        echo ""

        check_xdp_loaded "$interface" && echo "✓ XDP 程序已加载" || echo "✗ XDP 程序未加载"
        echo ""

        get_xdp_stats "$interface"
        echo ""

        check_bpf_maps
        echo ""

        check_kernel_logs
        echo ""

        check_system_resources

    } > "$report_file"

    echo_info "诊断报告已生成: $report_file"
    cat "$report_file"
}

# 主监控循环
main() {
    local interface=${1:-eth0}
    local single_run=${2:-false}

    echo_info "开始监控 XDP 程序 (接口: $interface)"
    echo_info "监控间隔: ${MONITOR_INTERVAL}秒"
    echo_info "日志文件: $LOG_FILE"
    echo_info "按 Ctrl+C 停止监控"
    echo ""

    if [ "$single_run" = "true" ]; then
        generate_report "$interface"
        exit 0
    fi

    while true; do
        clear
        echo "=========================================="
        echo "  XDP 程序监控 - $(date +%H:%M:%S)"
        echo "=========================================="
        echo ""

        check_xdp_loaded "$interface" || echo_warn "XDP 程序未加载!"
        echo ""

        get_xdp_stats "$interface"
        echo ""

        check_xdp_errors
        echo ""

        monitor_xdp_performance "$interface"
        echo ""

        sleep "$MONITOR_INTERVAL"
    done
}

# 帮助信息
show_help() {
    cat << EOF
用法: $0 [选项] [接口]

选项:
    -h, --help          显示帮助信息
    -o, --once          只运行一次并生成报告
    -i, --interface     指定网络接口 (默认: eth0)
    -r, --report        生成诊断报告

示例:
    $0                  # 持续监控 eth0
    $0 -o               # 运行一次检查
    $0 -i eth1 -o       # 检查 eth1 接口
    $0 -r               # 生成完整诊断报告

EOF
}

# 参数解析
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -o|--once)
            single_run=true
            shift
            ;;
        -i|--interface)
            interface="$2"
            shift 2
            ;;
        -r|--report)
            generate_report "${interface:-eth0}"
            exit 0
            ;;
        *)
            interface="$1"
            shift
            ;;
    esac
done

# 检查必要的命令
for cmd in bpftool ip; do
    if ! command -v $cmd &> /dev/null; then
        echo_error "缺少必要命令: $cmd"
        echo "请安装: apt install iproute2 linux-tools-$(uname -r)"
        exit 1
    fi
done

# 启动监控
main "${interface:-eth0}" "${single_run:-false}"
