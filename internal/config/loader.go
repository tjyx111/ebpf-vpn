package config

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/cilium/ebpf"
)

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
		UDPEchoPort uint16 `toml:"udp_echo_port"`
		MTU         uint32 `toml:"mtu"`
	} `toml:"network"`
	Features struct {
		TraceEnabled   bool `toml:"trace_enabled"`
		AfXdpRedirect  bool `toml:"afxdp_redirect"`
		UDPEchoEnabled bool `toml:"udp_echo_enabled"`
		NATEnabled     bool `toml:"nat_enabled"`
		DebugEnabled   bool `toml:"debug_enabled"`
	} `toml:"features"`
	Tracing struct {
		MirrorSampleRate uint8 `toml:"mirror_sample_rate"`
		LogFlags         uint32 `toml:"log_flags"`
	} `toml:"tracing"`
	Capture struct {
		Enabled      bool   `toml:"enabled"`
		DumpPkgFlags uint8  `toml:"dump_pkg_flags"`
	} `toml:"capture"`
	CaptureRules []CaptureRuleTOML `toml:"capture_rules"`
	NAT         struct {
		VPNServerIP   string   `toml:"vpn_server_ip"`
		VPNPort       uint16   `toml:"vpn_port"`
		PortStart     uint16   `toml:"port_start"`
		PortEnd       uint16   `toml:"port_end"`
		ReservedPorts []uint16 `toml:"reserved_ports"`
		Timeout       int      `toml:"timeout"`
		IngressIface   uint8    `toml:"ingress_iface"`
		EgressIface    uint8    `toml:"egress_iface"`
		EgressIPs     []string `toml:"egress_ips"`
	} `toml:"nat"`
}

// UnifiedConfig 对应 C 端的 unified_config 结构
type UnifiedConfig struct {
	Flags            uint8
	Reserved1        [3]uint8
	LogFlags         uint32 // 日志标志位
	UDPEchoPort      uint16
	Reserved2        uint16
	MTU              uint32
	MirrorSampleRate uint8
	Reserved3        [3]uint8
	TimeoutNS        uint64
	VPNServerIP      uint32
	VPNPort          uint16
	PortStart        uint16
	PortEnd          uint16
	ReservedPorts    [8]uint16
	ReservedCount    uint16
	IngressIface     uint8
	EgressIface      uint8
	EgressIPCount    uint8
	Reserved4        uint8
	EgressIPs        [16]uint32
	CaptureEnabled   uint8  // 是否开启抓包功能
	DumpPkgFlags     uint8  // 抓包标志位
	Reserved5        [10]uint8
}

// Config 包含统一配置和抓包规则
type Config struct {
	UnifiedConfig *UnifiedConfig
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
		UnifiedConfig: convertToUnifiedConfig(&tomlCfg),
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

// convertToUnifiedConfig 将 TOML 配置转换为 UnifiedConfig
func convertToUnifiedConfig(tomlCfg *TOMLConfig) *UnifiedConfig {
	cfg := &UnifiedConfig{
		UDPEchoPort:      tomlCfg.Network.UDPEchoPort,
		MTU:              tomlCfg.Network.MTU,
		MirrorSampleRate: tomlCfg.Tracing.MirrorSampleRate,
		LogFlags:         tomlCfg.Tracing.LogFlags,
		CaptureEnabled:   boolToUint8(tomlCfg.Capture.Enabled),
		DumpPkgFlags:     tomlCfg.Capture.DumpPkgFlags,
		Reserved1:        [3]uint8{0, 0, 0},
		Reserved2:        0,
		Reserved3:        [3]uint8{0, 0, 0},
		Reserved4:        0,
		Reserved5:        [10]uint8{},
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
	if tomlCfg.Features.NATEnabled {
		cfg.Flags |= 1 << 4 // CFG_FLAG_NAT_ENABLED
	}
	if tomlCfg.Features.DebugEnabled {
		cfg.Flags |= 1 << 6 // CFG_FLAG_DEBUG_ENABLED
	}

	// NAT 配置
	cfg.TimeoutNS = uint64(tomlCfg.NAT.Timeout) * 1000000000 // 转换为纳秒
	cfg.VPNPort = tomlCfg.NAT.VPNPort
	cfg.PortStart = tomlCfg.NAT.PortStart
	cfg.PortEnd = tomlCfg.NAT.PortEnd
	cfg.IngressIface = tomlCfg.NAT.IngressIface
	cfg.EgressIface = tomlCfg.NAT.EgressIface
	cfg.EgressIPCount = uint8(len(tomlCfg.NAT.EgressIPs))
	cfg.ReservedCount = uint16(len(tomlCfg.NAT.ReservedPorts))

	// 解析 VPN 服务器 IP
	if tomlCfg.NAT.VPNServerIP != "" {
		ip := net.ParseIP(tomlCfg.NAT.VPNServerIP)
		if ip != nil {
			cfg.VPNServerIP = ipToUint32(ip)
		}
	}

	// 解析预留端口
	for i, port := range tomlCfg.NAT.ReservedPorts {
		if i >= 8 {
			break
		}
		cfg.ReservedPorts[i] = port
	}

	// 解析公网 IP 列表
	for i, ipStr := range tomlCfg.NAT.EgressIPs {
		if i >= 16 {
			break
		}
		ip := net.ParseIP(ipStr)
		if ip != nil {
			cfg.EgressIPs[i] = ipToUint32(ip)
		}
	}

	return cfg
}

// boolToUint8 将 bool 转换为 uint8 (true=1, false=0)
func boolToUint8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
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

// SyncToMap 将统一配置同步到 eBPF Map
func (c *UnifiedConfig) SyncToMap(configMap *ebpf.Map) error {
	if configMap == nil {
		return fmt.Errorf("configMap is nil")
	}

	key := uint32(0) // CFG_KEY

	// 将 UnifiedConfig 转换为字节
	// sizeof(unified_config) = 136 字节 (C 结构体使用 __attribute__((packed)))
	value := make([]byte, 136)

	offset := 0
	value[offset] = c.Flags
	offset += 4 // flags + reserved1

	binary.LittleEndian.PutUint32(value[offset:offset+4], c.LogFlags)
	offset += 4 // log_flags

	binary.BigEndian.PutUint16(value[offset:offset+2], c.UDPEchoPort)
	offset += 4 // udp_echo_port + reserved2

	binary.LittleEndian.PutUint32(value[offset:offset+4], c.MTU)
	offset += 4

	value[offset] = c.MirrorSampleRate
	offset += 4 // mirror_sample_rate + reserved3

	binary.LittleEndian.PutUint64(value[offset:offset+8], c.TimeoutNS)
	offset += 8

	binary.BigEndian.PutUint32(value[offset:offset+4], c.VPNServerIP)
	offset += 4

	binary.BigEndian.PutUint16(value[offset:offset+2], c.VPNPort)
	offset += 2
	binary.BigEndian.PutUint16(value[offset:offset+2], c.PortStart)
	offset += 2
	binary.BigEndian.PutUint16(value[offset:offset+2], c.PortEnd)
	offset += 2

	// 预留端口
	for i := 0; i < 8; i++ {
		binary.BigEndian.PutUint16(value[offset+i*2:offset+i*2+2], c.ReservedPorts[i])
	}
	offset += 16

	binary.LittleEndian.PutUint16(value[offset:offset+2], c.ReservedCount)
	offset += 2

	value[offset] = c.IngressIface
	offset++
	value[offset] = c.EgressIface
	offset++
	value[offset] = c.EgressIPCount
	offset += 2 // egress_ip_count + reserved4

	// 公网 IP 列表
	for i := 0; i < 16; i++ {
		binary.BigEndian.PutUint32(value[offset+i*4:offset+i*4+4], c.EgressIPs[i])
	}
	offset += 64

	// 抓包配置
	value[offset] = c.CaptureEnabled
	offset++
	value[offset] = c.DumpPkgFlags
	offset++

	// reserved5 已经是零值，无需写入

	return configMap.Put(&key, value)
}

// SyncCaptureRulesToMap 将抓包规则同步到 eBPF Map
func (c *Config) SyncCaptureRulesToMap(captureRuleMap *ebpf.Map) error {
	if captureRuleMap == nil {
		return fmt.Errorf("captureRuleMap is nil")
	}

	const maxRules = 16
	const ruleSize = 31 // sizeof(capture_rule) = 4+4+4+4+2+2+2+2+1+6 = 31

	// 限制最多 16 条规则
	ruleCount := len(c.CaptureRules)
	if ruleCount > maxRules {
		log.Printf("Warning: too many capture rules (%d), only first %d will be used", ruleCount, maxRules)
		ruleCount = maxRules
	}

	// 先清空所有槽位（写入全零，表示未设置）
	emptyValue := make([]byte, ruleSize)
	for i := uint32(0); i < maxRules; i++ {
		if err := captureRuleMap.Put(&i, emptyValue); err != nil {
			return fmt.Errorf("failed to clear rule slot %d: %w", i, err)
		}
	}

	// 写入配置的规则
	for i := 0; i < ruleCount; i++ {
		rule := c.CaptureRules[i]
		key := uint32(i)

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
		// reserved[0] 作为标志位：1 表示规则已设置
		value[25] = 1
		for j := 1; j < 6; j++ {
			value[25+j] = rule.Reserved[j-1]
		}

		if err := captureRuleMap.Put(&key, value); err != nil {
			return fmt.Errorf("failed to write rule %d: %w", i, err)
		}
	}

	log.Printf("Synced %d capture rules to eBPF map", ruleCount)
	return nil
}
