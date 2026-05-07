package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"ebpf-vpn/internal/config"
	"ebpf-vpn/internal/logging"
	"ebpf-vpn/internal/packet"
	"ebpf-vpn/internal/xdp"

	"github.com/cilium/ebpf"
	"github.com/fsnotify/fsnotify"
)

var (
	ifaceName  = flag.String("iface", "eth0", "Network interface to attach XDP program")
	configPath = flag.String("config", "config.toml", "Path to configuration file")
	pcapFile   = flag.String("pcap", "", "Path to PCAP file for packet capture (empty to disable)")
)

func main() {
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)

	log.Printf("Starting XDP loader on interface %s...", *ifaceName)
	log.Printf("Using config file: %s", *configPath)

	// 加载初始配置
	cfg, err := config.LoadFromFile(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	log.Printf("Loaded config: UDP echo port=%d, MTU=%d, Flags=0x%02x, Mirror rate=%d, Capture enabled=%d, Dump pkg flags=0x%02x, Capture rules=%d, LogFlags=0x%02x",
		cfg.UnifiedConfig.UDPEchoPort, cfg.UnifiedConfig.MTU, cfg.UnifiedConfig.Flags, cfg.UnifiedConfig.MirrorSampleRate,
		cfg.UnifiedConfig.CaptureEnabled, cfg.UnifiedConfig.DumpPkgFlags, len(cfg.CaptureRules), cfg.UnifiedConfig.LogFlags)

	// 加载 XDP 程序
	program, err := xdp.Load(*ifaceName)
	if err != nil {
		log.Fatalf("Failed to load XDP program: %v", err)
	}
	defer program.Close()

	// 同步统一配置到 eBPF Map
	if err := cfg.UnifiedConfig.SyncToMap(program.UnifiedConfigMap()); err != nil {
		log.Fatalf("Failed to sync config to map: %v", err)
	}
	log.Println("Config synced to eBPF map")

	// 同步抓包规则到 eBPF Map
	if err := cfg.SyncCaptureRulesToMap(program.CaptureRuleMap()); err != nil {
		log.Fatalf("Failed to sync capture rules to map: %v", err)
	}
	log.Printf("Synced %d capture rules to eBPF map", len(cfg.CaptureRules))

	// 创建日志记录器
	logger := logging.NewLogger(cfg.UnifiedConfig.LogFlags)

	// 启动 Ring Buffer 消费者
	// 只有当配置文件中启用抓包且指定了 pcap 文件时才写入 pcap 文件
	pcapFilePath := ""
	if cfg.UnifiedConfig.CaptureEnabled == 1 && *pcapFile != "" {
		pcapFilePath = *pcapFile
	}
	consumer, err := packet.NewConsumer(program.EventsRingbuf(), logger, pcapFilePath)
	if err != nil {
		log.Fatalf("Failed to create packet consumer: %v", err)
	}
	consumer.Start()
	defer consumer.Stop()
	if pcapFilePath != "" {
		log.Printf("Packet consumer started (PCAP: %s)", pcapFilePath)
	} else {
		log.Println("Packet consumer started (PCAP disabled)")
	}

	// 启动 Debug Ring Buffer 消费者
	debugConsumer, err := packet.NewDebugConsumer(program.DebugEvents(), logger)
	if err != nil {
		log.Printf("Failed to create debug consumer: %v", err)
	} else {
		debugConsumer.Start()
		defer debugConsumer.Stop()
		log.Println("Debug consumer started")
	}

	// 启动配置热加载
	stopWatcher := make(chan struct{})
	go watchConfig(*configPath, program.UnifiedConfigMap(), program.CaptureRuleMap(), stopWatcher)
	defer close(stopWatcher)

	log.Println("XDP loader is running. Press Ctrl+C to stop...")

	// 等待信号
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	log.Println("Shutting down...")
}

// watchConfig 监听配置文件变化并热加载
func watchConfig(path string, configMap *ebpf.Map, captureRuleMap *ebpf.Map, stop chan struct{}) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("Failed to create config watcher: %v", err)
		return
	}
	defer watcher.Close()

	if err := watcher.Add(path); err != nil {
		log.Printf("Failed to watch config file: %v", err)
		return
	}

	log.Println("Config watcher started")

	for {
		select {
		case <-stop:
			log.Println("Stopping config watcher...")
			return
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}

			// 只处理写入事件
			if event.Op&fsnotify.Write == fsnotify.Write {
				log.Printf("Config file changed, reloading: %s", event.Name)

				cfg, err := config.LoadFromFile(path)
				if err != nil {
					log.Printf("Failed to reload config: %v", err)
					continue
				}

				if err := cfg.UnifiedConfig.SyncToMap(configMap); err != nil {
					log.Printf("Failed to sync new config: %v", err)
					continue
				}

				if err := cfg.SyncCaptureRulesToMap(captureRuleMap); err != nil {
					log.Printf("Failed to sync capture rules: %v", err)
					continue
				}

				log.Printf("Config reloaded: UDP echo port=%d, MTU=%d, Flags=0x%02x, Mirror rate=%d, Capture enabled=%d, Dump pkg flags=0x%02x, Capture rules=%d, LogFlags=0x%02x",
					cfg.UnifiedConfig.UDPEchoPort, cfg.UnifiedConfig.MTU, cfg.UnifiedConfig.Flags, cfg.UnifiedConfig.MirrorSampleRate,
					cfg.UnifiedConfig.CaptureEnabled, cfg.UnifiedConfig.DumpPkgFlags, len(cfg.CaptureRules), cfg.UnifiedConfig.LogFlags)
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Printf("Watcher error: %v", err)
		}
	}
}
