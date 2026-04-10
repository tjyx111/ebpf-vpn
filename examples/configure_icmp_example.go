package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"ebpf-vpn/internal/config"
)

// 示例：配置 ICMP VPN NAT
func main() {
	// 假设已经加载了 eBPF 程序并获取了 Map
	// program, _ := xdp.Load("eth0")
	// ifsConfigMap := program.IfsConfigMap()

	// 示例1：配置接口 IP 列表
	err := configureInterfaceIPsExample(nil, 2, []string{
		"10.0.0.1",
		"10.0.0.2",
		"10.0.0.3",
	})
	if err != nil {
		log.Printf("Error: %v", err)
	}

	// 示例2：加载包含 ICMP 配置的 TOML
	cfg, err := config.LoadFromFile("config_with_icmp.toml")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	log.Printf("Loaded config: NAT enabled=%v, LogFlags=0x%02x",
		cfg.UnifiedConfig.Flags&0x10 != 0,
		cfg.UnifiedConfig.LogFlags)
}

// configureInterfaceIPsExample 配置接口 IP 列表
func configureInterfaceIPsExample(ifsConfigMap *ebpf.Map, ifsIndex uint32, ipStrings []string) error {
	// 将字符串 IP 转换为 uint32
	ips := make([]uint32, 0, len(ipStrings))
	for _, ipStr := range ipStrings {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return fmt.Errorf("invalid IP address: %s", ipStr)
		}

		ip = ip.To4()
		if ip == nil {
			return fmt.Errorf("not an IPv4 address: %s", ipStr)
		}

		ips = append(ips, binary.BigEndian.Uint32(ip))
	}

	// 调用配置函数
	// return config.ConfigureInterfaceIPs(ifsConfigMap, ifsIndex, ips)

	fmt.Printf("Would configure interface %d with IPs: %v\n", ifsIndex, ipStrings)
	return nil
}
