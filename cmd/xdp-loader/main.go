package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"ebpf-vpn/internal/config"
	"ebpf-vpn/internal/stats"
	"ebpf-vpn/internal/xdp"

	"github.com/cilium/ebpf"
	"github.com/fsnotify/fsnotify"
)

var (
	ifaceName     = flag.String("iface", "eth0", "Network interface to attach XDP program")
	configPath    = flag.String("config", "config.toml", "Path to configuration file")
	statusFile    = flag.String("status", "status.log", "Path to status log file")
	statsInterval = flag.Duration("stats-interval", 5*time.Second, "Statistics reporting interval")
)

func main() {
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	cfg, err := config.LoadFromFile(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	program, err := xdp.Load(*ifaceName)
	if err != nil {
		log.Fatalf("Failed to load XDP program: %v", err)
	}
	defer program.Close()

	if err := cfg.UnifiedConfig.SyncToMap(program.UnifiedConfigMap()); err != nil {
		log.Fatalf("Failed to sync config: %v", err)
	}
	logConfig("Loaded config", cfg)

	stopWatcher := make(chan struct{})
	go watchConfig(*configPath, program.UnifiedConfigMap(), stopWatcher)
	defer close(stopWatcher)

	statsReporter := stats.NewReporter(program, *statusFile, *statsInterval)
	statsReporter.Start()
	defer statsReporter.Stop()

	log.Printf("XDP loader is running on %s. Press Ctrl+C to stop.", *ifaceName)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	log.Println("Shutting down...")
}

func watchConfig(path string, configMap *ebpf.Map, stop chan struct{}) {
	configPath, err := filepath.Abs(path)
	if err != nil {
		log.Printf("Failed to resolve config path: %v", err)
		return
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("Failed to create config watcher: %v", err)
		return
	}
	defer watcher.Close()

	if err := watcher.Add(filepath.Dir(configPath)); err != nil {
		log.Printf("Failed to watch config file: %v", err)
		return
	}

	for {
		select {
		case <-stop:
			return
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if filepath.Clean(event.Name) != configPath {
				continue
			}
			if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename|fsnotify.Chmod) == 0 {
				continue
			}
			time.Sleep(50 * time.Millisecond)

			cfg, err := config.LoadFromFile(configPath)
			if err != nil {
				log.Printf("Failed to reload config: %v", err)
				continue
			}
			if err := cfg.UnifiedConfig.SyncToMap(configMap); err != nil {
				log.Printf("Failed to sync config: %v", err)
				continue
			}
			logConfig("Reloaded config", cfg)
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Printf("Config watcher error: %v", err)
		}
	}
}

func logConfig(prefix string, cfg *config.Config) {
	uc := cfg.UnifiedConfig
	log.Printf("%s: udp_echo_port=%d, vpn_port=%d, mtu=%d, flags=0x%02x, egress_ips=%d",
		prefix, uc.UDPEchoPort, uc.VPNPort, uc.MTU, uc.Flags, uc.EgressIPCount)
}
