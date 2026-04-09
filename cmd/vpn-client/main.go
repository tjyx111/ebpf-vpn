package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
)

var (
	configPath = flag.String("config", "config.toml", "配置文件路径")
)

func main() {
	flag.Parse()

	// 加载配置
	cfg, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}

	if cfg.Logging.Enabled {
		log.Printf("启动 VPN 客户端")
		log.Printf("目标服务器: %s:%d", cfg.Target.ServerIP, cfg.Target.ServerPort)
		log.Printf("TCP 目标: %s:%d", cfg.Target.TcpTargetIP, cfg.Target.TcpTargetPort)
		log.Printf("Session ID: %d", cfg.VPN.SessionID)
	}

	// 创建网络栈
	ns, err := NewNetstack(cfg)
	if err != nil {
		log.Fatalf("创建网络栈失败: %v", err)
	}
	defer ns.Close()

	if cfg.Logging.Enabled {
		log.Printf("网络栈创建成功")
	}

	// 创建上下文
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 启动统计打印
	if cfg.Logging.Enabled {
		go printStats(ctx, ns, time.Second*5)
	}

	// 建立 TCP 连接
	if cfg.Logging.Enabled {
		log.Printf("正在连接 TCP 目标: %s:%d", cfg.Target.TcpTargetIP, cfg.Target.TcpTargetPort)
	}

	ep, err := ns.DialTCP(cfg.Target.TcpTargetIP, cfg.Target.TcpTargetPort)
	if err != nil {
		log.Fatalf("TCP 连接失败: %v", err)
	}
	defer ep.Close()

	if cfg.Logging.Enabled {
		log.Printf("TCP 连接成功")
	}

	// 发送测试数据
	testData := []byte("Hello from VPN Client!\n")
	if _, err := ep.Write(testData, tcpip.WriteOptions{}); err != nil {
		log.Fatalf("发送数据失败: %v", err)
	}

	if cfg.Logging.Enabled {
		log.Printf("已发送测试数据: %s", testData)
	}

	// 读取响应
	buf := make([]byte, 1500)
	for {
		n, err := ep.Read(buf, tcpip.ReadOptions{
			NeedWaiter: true,
		})
		if err != nil {
			log.Printf("读取数据失败: %v", err)
			break
		}

		if n > 0 {
			if cfg.Logging.Enabled {
				log.Printf("收到响应: %s", string(buf[:n]))
			}
			break
		}
	}

	// 等待退出信号
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	log.Printf("按 Ctrl+C 退出...")
	<-sigCh

	if cfg.Logging.Enabled {
		endpointStats, senderStats := ns.GetStats()
		log.Printf("统计信息:")
		log.Printf("  %s", endpointStats)
		log.Printf("  %s", senderStats)
	}

	log.Printf("VPN 客户端退出")
}

// printStats 定期打印统计信息
func printStats(ctx context.Context, ns *Netstack, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			endpointStats, senderStats := ns.GetStats()
			fmt.Printf("[STATS] %s | %s\n", endpointStats, senderStats)
		}
	}
}
