package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" bpf ../../bpf/src/monitor/xdp_monitor.c -- -I../../bpf/src/include

type XdpErrorEvent struct {
	Timestamp   uint64
	CPU         uint32
	PID         uint32
	ErrorType   uint32
	ProgramID   uint32
	PacketLen   uint32
	ErrorAddr   uint64
	Instruction uint32
}

const (
	ErrorTypeNullPtr          = 1
	ErrorTypeOutOfBounds      = 2
	ErrorTypeInvalidMap       = 3
	ErrorTypeVerificationFail = 4
	ErrorTypeRuntimeError     = 5
)

var errorTypeNames = map[uint32]string{
	ErrorTypeNullPtr:          "空指针访问",
	ErrorTypeOutOfBounds:      "数组越界",
	ErrorTypeInvalidMap:       "无效的 Map 访问",
	ErrorTypeVerificationFail: "验证器失败",
	ErrorTypeRuntimeError:     "运行时错误",
}

type MonitorStats struct {
	totalPackets    uint64
	errorPackets    uint64
	lastErrorTime   time.Time
	errorCountByType map[uint32]uint64
	mu              sync.Mutex
	startTime       time.Time
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("用法: xdp-monitor <网络接口>")
		fmt.Println("示例: xdp-monitor eth0")
		os.Exit(1)
	}

	ifaceName := os.Args[1]

	// 加载 eBPF 程序
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("加载 eBPF 程序失败: %v", err)
	}
	defer objs.Close()

	// 附加到网络接口
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpErrorMonitor,
		Interface: -1, // 监控所有接口
	})
	if err != nil {
		log.Fatalf("附加 XDP 程序失败: %v", err)
	}
	defer l.Close()

	fmt.Printf("✓ XDP 监控程序已启动 (接口: %s)\n", ifaceName)
	fmt.Println("监控以下错误类型:")
	for _, name := range errorTypeNames {
		fmt.Printf("  - %s\n", name)
	}
	fmt.Println("\n按 Ctrl+C 停止监控...")

	// 创建性能计数器读取器
	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("创建 perf reader 失败: %v", err)
	}
	defer rd.Close()

	// 统计信息
	stats := &MonitorStats{
		errorCountByType: make(map[uint32]uint64),
		startTime:        time.Now(),
	}

	// 启动统计打印协程
	go printStats(stats)

	// 处理中断信号
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	// 读取事件
	go func() {
		for {
			select {
			case <-sig:
				fmt.Println("\n\n收到中断信号，正在停止监控...")
				printFinalStats(stats)
				os.Exit(0)
			default:
			}

			record, err := rd.Read()
			if err != nil {
				if err == perf.ErrClosed {
					return
				}
				log.Printf("读取事件失败: %v", err)
				continue
			}

			stats.mu.Lock()
			stats.totalPackets++

			// 解析事件
			var event XdpErrorEvent
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("解析事件失败: %v", err)
				stats.mu.Unlock()
				continue
			}

			// 处理错误事件
			if event.ErrorType > 0 {
				stats.errorPackets++
				stats.lastErrorTime = time.Now()
				stats.errorCountByType[event.ErrorType]++

				errorName := errorTypeNames[event.ErrorType]
				if errorName == "" {
					errorName = "未知错误"
				}

				fmt.Printf("\n[错误检测] %s\n", errorName)
				fmt.Printf("  时间: %s\n", time.Unix(int64(event.Timestamp), 0).Format("2006-01-02 15:04:05"))
				fmt.Printf("  CPU: %d\n", event.CPU)
				fmt.Printf("  程序 ID: %d\n", event.ProgramID)
				fmt.Printf("  包长度: %d\n", event.PacketLen)
				if event.ErrorAddr > 0 {
					fmt.Printf("  错误地址: 0x%x\n", event.ErrorAddr)
				}
				if event.Instruction > 0 {
					fmt.Printf("  指令偏移: %d\n", event.Instruction)
				}
			}

			stats.mu.Unlock()
		}
	}()

	// 等待信号
	<-sig
}

func printStats(stats *MonitorStats) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		stats.mu.Lock()
		total := stats.totalPackets
		errors := stats.errorPackets
		lastError := stats.lastErrorTime
		errorCounts := make(map[uint32]uint64)
		for k, v := range stats.errorCountByType {
			errorCounts[k] = v
		}
		stats.mu.Unlock()

		fmt.Printf("\n=== 监控统计 (%s) ===\n", time.Now().Format("15:04:05"))
		fmt.Printf("总包数: %d\n", total)
		fmt.Printf("错误包数: %d\n", errors)

		if total > 0 {
			errorRate := float64(errors) / float64(total) * 100
			fmt.Printf("错误率: %.4f%%\n", errorRate)
		}

		if !lastError.IsZero() {
			fmt.Printf("最后错误时间: %s (距离现在 %s)\n",
				lastError.Format("15:04:05"),
				time.Since(lastError).Round(time.Second))
		}

		if len(errorCounts) > 0 {
			fmt.Println("\n错误类型统计:")
			for errType, count := range errorCounts {
				name := errorTypeNames[errType]
				if name == "" {
					name = fmt.Sprintf("未知(%d)", errType)
				}
				fmt.Printf("  %s: %d\n", name, count)
			}
		}
	}
}

func printFinalStats(stats *MonitorStats) {
	stats.mu.Lock()
	defer stats.mu.Unlock()

	fmt.Println("\n=== 最终统计报告 ===")
	fmt.Printf("监控时长: %s\n", time.Since(stats.startTime))
	fmt.Printf("总包数: %d\n", stats.totalPackets)
	fmt.Printf("错误包数: %d\n", stats.errorPackets)

	if stats.totalPackets > 0 {
		errorRate := float64(stats.errorPackets) / float64(stats.totalPackets) * 100
		fmt.Printf("平均错误率: %.4f%%\n", errorRate)
	}

	if len(stats.errorCountByType) > 0 {
		fmt.Println("\n错误类型统计:")
		for errType, count := range stats.errorCountByType {
			name := errorTypeNames[errType]
			if name == "" {
				name = fmt.Sprintf("未知(%d)", errType)
			}
			fmt.Printf("  %s: %d\n", name, count)
		}
	}
}
