package config

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"

	"github.com/BurntSushi/toml"
	"github.com/cilium/ebpf"
)

type TOMLConfig struct {
	Network struct {
		UDPEchoPort uint16 `toml:"udp_echo_port"`
		MTU         uint32 `toml:"mtu"`
	} `toml:"network"`
	Features struct {
		UDPEchoEnabled bool `toml:"udp_echo_enabled"`
	} `toml:"features"`
	VPN struct {
		Port      uint16   `toml:"port"`
		EgressIPs []string `toml:"egress_ips"`
	} `toml:"vpn"`
}

type UnifiedConfig struct {
	Flags         uint8
	UDPEchoPort   uint16
	VPNPort       uint16
	MTU           uint32
	EgressIPCount uint8
	EgressIPs     [16]uint32
}

type Config struct {
	UnifiedConfig *UnifiedConfig
}

func LoadFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var tomlCfg TOMLConfig
	if err := toml.Unmarshal(data, &tomlCfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	return &Config{UnifiedConfig: convertToUnifiedConfig(&tomlCfg)}, nil
}

func convertToUnifiedConfig(tomlCfg *TOMLConfig) *UnifiedConfig {
	cfg := &UnifiedConfig{
		UDPEchoPort: tomlCfg.Network.UDPEchoPort,
		VPNPort:     tomlCfg.VPN.Port,
		MTU:         tomlCfg.Network.MTU,
	}

	if tomlCfg.Features.UDPEchoEnabled {
		cfg.Flags |= 1 << 0
	}

	for i, ipStr := range tomlCfg.VPN.EgressIPs {
		if i >= len(cfg.EgressIPs) {
			break
		}
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		cfg.EgressIPs[i] = ipToUint32(ip)
		cfg.EgressIPCount++
	}

	return cfg
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}

func (c *UnifiedConfig) SyncToMap(configMap *ebpf.Map) error {
	if configMap == nil {
		return fmt.Errorf("config map is nil")
	}

	key := uint32(0)
	value := make([]byte, 80)

	value[0] = c.Flags
	binary.BigEndian.PutUint16(value[4:6], c.UDPEchoPort)
	binary.BigEndian.PutUint16(value[6:8], c.VPNPort)
	binary.LittleEndian.PutUint32(value[8:12], c.MTU)
	value[12] = c.EgressIPCount

	for i, ip := range c.EgressIPs {
		binary.BigEndian.PutUint32(value[16+i*4:20+i*4], ip)
	}

	return configMap.Put(&key, value)
}
