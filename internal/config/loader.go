package config

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/cilium/ebpf"
)

// VpnConfig 对应 C 端的 vpn_config 结构
type VpnConfig struct {
	UDPEchoPort      uint32
	MTU              uint32
	Flags            uint8
	MirrorSampleRate uint8
	Reserved         [2]uint8
}

// CaptureRuleTOML TOML 配置文件中的抓包规则
type CaptureRuleTOML struct {
	Name     string `toml:"name"`
	SrcIP    string `toml:"src_ip,omitempty"`
	DstIP    string `toml:"dst_ip,omitempty"`
	SrcPort  uint16 `toml:"src_port,omitempty"`
	DstPort  uint16 `toml:"dst_port,omitempty"`
	Protocol string `toml:"protocol,omitempty"` // tcp, udp, icmp, any
}

// CaptureRule 对应 C 端的 capture_rule 结构
type CaptureRule struct {
	SrcIP       uint32
	SrcIPMask   uint32
	DstIP       uint32
	DstIPMask   uint32
	SrcPort     uint16
	SrcPortMask uint16
	DstPort     uint16
	DstPortMask uint16
	Protocol    uint8
	Reserved    [6]uint8
}

// TOMLConfig TOML 配置文件结构
type TOMLConfig struct {
	Network struct {
		UDPEchoPort uint32 `toml:"udp_echo_port"`
		MTU         uint32 `toml:"mtu"`
	} `toml:"network"`
	Features struct {
		TraceEnabled      bool `toml:"trace_enabled"`
		AfXdpRedirect     bool `toml:"afxdp_redirect"`
		UDPEchoEnabled    bool `toml:"udp_echo_enabled"`
		ForwardingEnabled bool `toml:"forwarding_enabled"`
		NATEnabled        bool `toml:"nat_enabled"`
		MirrorEnabled     bool `toml:"mirror_enabled"`
	} `toml:"features"`
	Tracing struct {
		MirrorSampleRate uint8 `toml:"mirror_sample_rate"`
	} `toml:"tracing"`
	CaptureRules []CaptureRuleTOML `toml:"capture_rules"`
}

// Config 包含 VPN 配置和抓包规则
type Config struct {
	VpnConfig     *VpnConfig
	CaptureRules  []CaptureRule
}

// LoadFromFile 从 TOML 文件加载配置
func LoadFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var tomlCfg TOMLConfig
	if err := toml.Unmarshal(data, &tomlCfg); err != nil {
		return nil, fmt.Errorf("failed to parse TOML: %w", err)
	}

	cfg := &Config{
		VpnConfig: convertToVpnConfig(&tomlCfg),
	}

	// 解析抓包规则
	for _, rule := range tomlCfg.CaptureRules {
		captureRule, err := parseCaptureRule(rule)
		if err != nil {
			return nil, fmt.Errorf("failed to parse capture rule '%s': %w", rule.Name, err)
		}
		cfg.CaptureRules = append(cfg.CaptureRules, *captureRule)
	}

	return cfg, nil
}

// convertToVpnConfig 将 TOML 配置转换为 VpnConfig
func convertToVpnConfig(tomlCfg *TOMLConfig) *VpnConfig {
	cfg := &VpnConfig{
		UDPEchoPort:      tomlCfg.Network.UDPEchoPort,
		MTU:              tomlCfg.Network.MTU,
		MirrorSampleRate: tomlCfg.Tracing.MirrorSampleRate,
		Reserved:         [2]uint8{0, 0},
	}

	// 设置标志位
	if tomlCfg.Features.TraceEnabled {
		cfg.Flags |= 1 << 0 // CFG_FLAG_TRACE_ENABLED
	}
	if tomlCfg.Features.AfXdpRedirect {
		cfg.Flags |= 1 << 1 // CFG_FLAG_AFXDP_REDIRECT
	}
	if tomlCfg.Features.UDPEchoEnabled {
		cfg.Flags |= 1 << 2 // CFG_FLAG_UDP_ECHO_ENABLED
	}
	if tomlCfg.Features.ForwardingEnabled {
		cfg.Flags |= 1 << 3 // CFG_FLAG_FORWARDING_ENABLED
	}
	if tomlCfg.Features.NATEnabled {
		cfg.Flags |= 1 << 4 // CFG_FLAG_NAT_ENABLED
	}
	if tomlCfg.Features.MirrorEnabled {
		cfg.Flags |= 1 << 5 // CFG_FLAG_MIRROR_ENABLED
	}

	return cfg
}

// parseCaptureRule 将 TOML 抓包规则转换为 CaptureRule 结构
func parseCaptureRule(tomlRule CaptureRuleTOML) (*CaptureRule, error) {
	rule := &CaptureRule{
		SrcPort:     tomlRule.SrcPort,
		SrcPortMask: 0xFFFF, // 默认匹配所有位
		DstPort:     tomlRule.DstPort,
		DstPortMask: 0xFFFF,
		Protocol:    0,      // 默认匹配所有协议
		Reserved:    [6]uint8{0, 0, 0, 0, 0, 0},
	}

	// 如果端口为 0，表示不限制端口（掩码设为 0）
	if tomlRule.SrcPort == 0 {
		rule.SrcPortMask = 0
	}
	if tomlRule.DstPort == 0 {
		rule.DstPortMask = 0
	}

	// 解析源 IP
	if tomlRule.SrcIP != "" {
		ip, ipNet, err := net.ParseCIDR(tomlRule.SrcIP)
		if err == nil {
			// CIDR 格式
			rule.SrcIP = ipToUint32(ip)
			rule.SrcIPMask = ipNetToUint32Mask(ipNet)
		} else {
			// 简化格式：纯 IP 地址
			ip := net.ParseIP(tomlRule.SrcIP)
			if ip == nil {
				return nil, fmt.Errorf("invalid src_ip: %s", tomlRule.SrcIP)
			}
			rule.SrcIP = ipToUint32(ip)
			rule.SrcIPMask = 0xFFFFFFFF // 精确匹配
		}
	}

	// 解析目标 IP
	if tomlRule.DstIP != "" {
		ip, ipNet, err := net.ParseCIDR(tomlRule.DstIP)
		if err == nil {
			// CIDR 格式
			rule.DstIP = ipToUint32(ip)
			rule.DstIPMask = ipNetToUint32Mask(ipNet)
		} else {
			// 简化格式：纯 IP 地址
			ip := net.ParseIP(tomlRule.DstIP)
			if ip == nil {
				return nil, fmt.Errorf("invalid dst_ip: %s", tomlRule.DstIP)
			}
			rule.DstIP = ipToUint32(ip)
			rule.DstIPMask = 0xFFFFFFFF // 精确匹配
		}
	}

	// 解析协议
	if tomlRule.Protocol != "" && strings.ToLower(tomlRule.Protocol) != "any" {
		switch strings.ToLower(tomlRule.Protocol) {
		case "tcp":
			rule.Protocol = 6 // IPPROTO_TCP
		case "udp":
			rule.Protocol = 17 // IPPROTO_UDP
		case "icmp":
			rule.Protocol = 1 // IPPROTO_ICMP
		default:
			return nil, fmt.Errorf("invalid protocol: %s (must be tcp, udp, icmp, or any)", tomlRule.Protocol)
		}
	}

	return rule, nil
}

// ipToUint32 将 net.IP 转换为 uint32（网络字节序）
func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}

// ipNetToUint32Mask 将 net.IPNet 转换为 uint32 掩码（网络字节序）
func ipNetToUint32Mask(ipNet *net.IPNet) uint32 {
	mask := ipNet.Mask
	if len(mask) != 4 {
		return 0
	}
	return binary.BigEndian.Uint32(mask)
}

// SyncToMap 将配置同步到 eBPF Map
func (c *VpnConfig) SyncToMap(configMap *ebpf.Map) error {
	if configMap == nil {
		return fmt.Errorf("configMap is nil")
	}

	key := uint32(0) // CFG_KEY

	// 将 VpnConfig 转换为字节
	value := make([]byte, 12) // sizeof(vpn_config) = 4+4+1+1+2 = 12
	binary.LittleEndian.PutUint32(value[0:4], c.UDPEchoPort)
	binary.LittleEndian.PutUint32(value[4:8], c.MTU)
	value[8] = c.Flags
	value[9] = c.MirrorSampleRate
	value[10] = c.Reserved[0]
	value[11] = c.Reserved[1]

	return configMap.Put(&key, value)
}

// SyncCaptureRulesToMap 将抓包规则同步到 eBPF Map
func (c *Config) SyncCaptureRulesToMap(captureRuleMap *ebpf.Map) error {
	if captureRuleMap == nil {
		return fmt.Errorf("captureRuleMap is nil")
	}

	const maxRules = 16
	const ruleSize = 31 // sizeof(capture_rule) = 4+4+4+4+2+2+2+2+1+6 = 31
	emptyValue := make([]byte, ruleSize) // 空规则，全零

	// 遍历所有槽位
	for i := uint32(0); i < maxRules; i++ {
		key := i

		if i < uint32(len(c.CaptureRules)) {
			// 写入配置的规则
			rule := c.CaptureRules[i]

			// 将 CaptureRule 转换为字节（使用网络字节序 BigEndian）
			value := make([]byte, ruleSize)
			binary.BigEndian.PutUint32(value[0:4], rule.SrcIP)
			binary.BigEndian.PutUint32(value[4:8], rule.SrcIPMask)
			binary.BigEndian.PutUint32(value[8:12], rule.DstIP)
			binary.BigEndian.PutUint32(value[12:16], rule.DstIPMask)
			binary.BigEndian.PutUint16(value[16:18], rule.SrcPort)
			binary.BigEndian.PutUint16(value[18:20], rule.SrcPortMask)
			binary.BigEndian.PutUint16(value[20:22], rule.DstPort)
			binary.BigEndian.PutUint16(value[22:24], rule.DstPortMask)
			value[24] = rule.Protocol
			for j := 0; j < 6; j++ {
				value[25+j] = rule.Reserved[j]
			}

			if err := captureRuleMap.Put(&key, value); err != nil {
				return fmt.Errorf("failed to write rule %d: %w", i, err)
			}
		} else {
			// 清空未使用的槽位（写入空规则）
			if err := captureRuleMap.Put(&key, emptyValue); err != nil {
				return fmt.Errorf("failed to clear rule slot %d: %w", i, err)
			}
		}
	}

	return nil
}
