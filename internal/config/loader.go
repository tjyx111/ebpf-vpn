package config

import (
	"encoding/binary"
	"fmt"
	"math/bits"
	"net"
	"os"
	"sort"

	"github.com/BurntSushi/toml"
	"github.com/cilium/ebpf"
)

const maxEgressIPs = 63

type TOMLConfig struct {
	Network struct {
		UDPEchoPort uint16 `toml:"udp_echo_port"`
		MTU         uint32 `toml:"mtu"`
	} `toml:"network"`
	Features struct {
		UDPEchoEnabled     bool `toml:"udp_echo_enabled"`
		DNATCaptureEnabled bool `toml:"dnat_capture_enabled"`
	} `toml:"features"`
	VPN struct {
		Port             uint16   `toml:"port"`
		EgressIPs        []string `toml:"egress_ips"`
		EgressInterfaces []string `toml:"egress_interfaces"`
	} `toml:"vpn"`
}

type UnifiedConfig struct {
	Flags         uint8
	UDPEchoPort   uint16
	VPNPort       uint16
	MTU           uint32
	EgressIPCount uint8
	EgressIPs     [maxEgressIPs]uint32
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
	if tomlCfg.Features.DNATCaptureEnabled {
		cfg.Flags |= 1 << 1
	}

	egressIPs := make([]uint32, 0, maxEgressIPs)
	addEgressIP := func(ip net.IP) {
		ip = ip.To4()
		if ip == nil {
			return
		}
		ipValue := ipToUint32(ip)
		for _, existing := range egressIPs {
			if existing == ipValue {
				return
			}
		}
		egressIPs = append(egressIPs, ipValue)
	}

	for _, ipStr := range tomlCfg.VPN.EgressIPs {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		addEgressIP(ip)
	}

	for _, ifaceName := range tomlCfg.VPN.EgressInterfaces {
		ip, err := firstInterfaceIPv4(ifaceName)
		if err != nil {
			continue
		}
		addEgressIP(ip)
	}

	sort.Slice(egressIPs, func(i, j int) bool {
		return egressIPs[i] < egressIPs[j]
	})
	if len(egressIPs) > len(cfg.EgressIPs) {
		egressIPs = egressIPs[:len(cfg.EgressIPs)]
	}
	for i, ip := range egressIPs {
		cfg.EgressIPs[i] = ip
		cfg.EgressIPCount++
	}

	return cfg
}

func firstInterfaceIPv4(name string) (net.IP, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		ip = ip.To4()
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		return ip, nil
	}
	return nil, fmt.Errorf("no IPv4 address found on interface %s", name)
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}

func (c *UnifiedConfig) SyncToMap(configMap *ebpf.Map) error {
	return c.SyncToMaps(configMap, nil)
}

func (c *UnifiedConfig) SyncToMaps(configMap *ebpf.Map, egressIPMap *ebpf.Map) error {
	if configMap == nil {
		return fmt.Errorf("config map is nil")
	}

	key := uint32(0)
	value := make([]byte, 16+len(c.EgressIPs)*4)

	value[0] = c.Flags
	binary.BigEndian.PutUint16(value[4:6], c.UDPEchoPort)
	binary.BigEndian.PutUint16(value[6:8], c.VPNPort)
	binary.LittleEndian.PutUint32(value[8:12], c.MTU)
	value[12] = c.EgressIPCount

	for i, ip := range c.EgressIPs {
		binary.BigEndian.PutUint32(value[16+i*4:20+i*4], ip)
	}

	if err := configMap.Put(&key, value); err != nil {
		return err
	}
	if egressIPMap != nil {
		return c.syncEgressIPsToMap(egressIPMap)
	}
	return nil
}

func (c *UnifiedConfig) syncEgressIPsToMap(egressIPMap *ebpf.Map) error {
	for i := range c.EgressIPs {
		key := uint32(i)
		value := uint32(0)
		if i < int(c.EgressIPCount) {
			value = bits.ReverseBytes32(c.EgressIPs[i])
		}
		if err := egressIPMap.Put(&key, &value); err != nil {
			return fmt.Errorf("sync egress ip %d: %w", i, err)
		}
	}
	return nil
}
