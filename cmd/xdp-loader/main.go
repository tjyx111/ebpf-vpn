package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"ebpf-vpn/internal/config"
	"ebpf-vpn/internal/pcap"
	"ebpf-vpn/internal/stats"
	"ebpf-vpn/internal/xdp"

	"github.com/cilium/ebpf"
	"github.com/fsnotify/fsnotify"
)

const (
	ipLocalPortRangeKey   = "net.ipv4.ip_local_port_range"
	ipLocalPortRangeValue = "50001 60000"
	sysctlPersistPath     = "/etc/sysctl.d/99-ebpf-vpn.conf"
)

var (
	ifaceName     = flag.String("iface", "eth0", "Network interface(s) to attach XDP program, comma-separated")
	configPath    = flag.String("config", "config.toml", "Path to configuration file")
	statusFile    = flag.String("status", "status.log", "Path to status log file")
	statsInterval = flag.Duration("stats-interval", 5*time.Second, "Statistics reporting interval")
	dnatPcapPath  = flag.String("dnat-pcap", "", "Path to write DNAT ICMP reply packets as pcap; disabled when empty")
)

func main() {
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	if err := ensureSystemPortRange(); err != nil {
		log.Fatalf("Failed to configure system port range: %v", err)
	}

	cfg, err := config.LoadFromFile(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	program, err := xdp.Load(*ifaceName)
	if err != nil {
		log.Fatalf("Failed to load XDP program: %v", err)
	}
	defer program.Close()

	if err := cfg.UnifiedConfig.SyncToMaps(program.UnifiedConfigMap(), program.EgressIPMap()); err != nil {
		log.Fatalf("Failed to sync config: %v", err)
	}
	logConfig("Loaded config", cfg)

	stopWatcher := make(chan struct{})
	go watchConfig(*configPath, program.UnifiedConfigMap(), program.EgressIPMap(), stopWatcher)
	defer close(stopWatcher)

	statsReporter := stats.NewReporter(program, *statusFile, *statsInterval)
	statsReporter.Start()
	defer statsReporter.Stop()

	if *dnatPcapPath != "" {
		recorder, err := pcap.NewRecorder(program.DnatCaptureEvents(), *dnatPcapPath)
		if err != nil {
			log.Fatalf("Failed to start DNAT pcap recorder: %v", err)
		}
		recorder.Start()
		defer recorder.Close()
		log.Printf("DNAT pcap recorder is writing to %s", *dnatPcapPath)
	}

	log.Printf("XDP loader is running on %s. Press Ctrl+C to stop.", *ifaceName)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	log.Println("Shutting down...")
}

func ensureSystemPortRange() error {
	persistConfig := ipLocalPortRangeKey + " = " + ipLocalPortRangeValue + "\n"
	if err := os.WriteFile(sysctlPersistPath, []byte(persistConfig), 0644); err != nil {
		return err
	}

	cmd := exec.Command("sysctl", "-w", ipLocalPortRangeKey+"="+ipLocalPortRangeValue)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, string(output))
	}
	log.Printf("Configured %s=%s", ipLocalPortRangeKey, ipLocalPortRangeValue)
	return nil
}

func watchConfig(path string, configMap *ebpf.Map, egressIPMap *ebpf.Map, stop chan struct{}) {
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
			if err := cfg.UnifiedConfig.SyncToMaps(configMap, egressIPMap); err != nil {
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
