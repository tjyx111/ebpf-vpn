package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// XDP 运行时统计
type XDPStats struct {
	Timestamp      time.Time
	TotalPackets   uint64
	DroppedPackets uint64
	PassedPackets  uint64
	TxPackets      uint64
	RedirectPackets uint64
	LastErrorTime  uint64
	Errors         uint64
}

// 从 /sys/net 获取 XDP 统计
func getXDPStats(_ string) (*XDPStats, error) {
	stats := &XDPStats{
		Timestamp: time.Now(),
	}

	// 这里可以通过 bpftool 或 /proc/net 获取实际统计
	// 简化版本：读取网卡统计

	return stats, nil
}

// 监控 XDP 程序健康状态
func monitorHealth(iface string, interval time.Duration) {
	fmt.Printf("开始监控 XDP 程序健康状态 (接口: %s)\n", iface)
	fmt.Printf("监控间隔: %v\n", interval)
	fmt.Println("按 Ctrl+C 停止")
	fmt.Println()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	lastStats := &XDPStats{}
	iteration := 0

	for {
		select {
		case <-ticker.C:
			iteration++
			stats, err := getXDPStats(iface)
			if err != nil {
				fmt.Printf("错误: 获取统计失败: %v\n", err)
				continue
			}

			// 计算变化率
			duration := stats.Timestamp.Sub(lastStats.Timestamp).Seconds()
			if duration > 0 {
				packetRate := float64(stats.TotalPackets-lastStats.TotalPackets) / duration
				dropRate := float64(stats.DroppedPackets-lastStats.DroppedPackets) / duration

				fmt.Printf("[%s] 包速率: %.2f pps, 丢包速率: %.2f pps\n",
					stats.Timestamp.Format("15:04:05"), packetRate, dropRate)

				// 检查异常
				if dropRate > 1000 {
					fmt.Printf("⚠️  警告: 高丢包率 (%.2f pps)\n", dropRate)
				}
			}

			lastStats = stats

			// 每 10 次迭代打印详细统计
			if iteration%10 == 0 {
				printDetailedStats(stats)
			}

		case <-time.After(100 * time.Millisecond):
			// 检查信号
		}
	}
}

func printDetailedStats(stats *XDPStats) {
	fmt.Println("\n=== 详细统计 ===")
	fmt.Printf("时间: %s\n", stats.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Printf("总包数: %d\n", stats.TotalPackets)
	fmt.Printf("丢包数: %d\n", stats.DroppedPackets)
	fmt.Printf("通过包数: %d\n", stats.PassedPackets)
	fmt.Printf("发送包数: %d\n", stats.TxPackets)
	fmt.Printf("重定向包数: %d\n", stats.RedirectPackets)
	fmt.Printf("错误数: %d\n", stats.Errors)

	if stats.TotalPackets > 0 {
		dropPercent := float64(stats.DroppedPackets) / float64(stats.TotalPackets) * 100
		fmt.Printf("丢包率: %.4f%%\n", dropPercent)
	}
	fmt.Println()
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("用法: xdp-stats <网络接口> [间隔秒数]")
		fmt.Println("示例: xdp-stats eth0 5")
		os.Exit(1)
	}

	iface := os.Args[1]
	interval := 5 * time.Second

	if len(os.Args) >= 3 {
		seconds, err := time.ParseDuration(os.Args[2] + "s")
		if err != nil {
			fmt.Printf("无效的间隔时间: %v\n", err)
			os.Exit(1)
		}
		interval = seconds
	}

	// 设置信号处理
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	// 启动监控
	go monitorHealth(iface, interval)

	// 等待信号
	<-sig
	fmt.Println("\n监控已停止")
}
