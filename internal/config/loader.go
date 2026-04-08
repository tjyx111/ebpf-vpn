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

// Config 包含 VPN 配置、抓包规则和 NAT 配置
type Config struct {
	VpnConfig     *VpnConfig
	CaptureRules  []CaptureRule
	NATConfig     *NATConfig
}

// NATConfig 对应 C 端的 vpn_global_config 结构
type NATConfig struct {
	TimeoutNS      uint64
	VPNServerIP    uint32
	VPNPort        uint16
	PortStart      uint16
	PortEnd        uint16
	ReservedPorts [32]uint16
	ReservedCount  uint16
	IngressIface   uint8
	EgressIface    uint8
	EgressIPCount   uint8
	Reserved       [3]uint8
	EgressIPs      [16]uint32
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

	// 解析 NAT 配置
	natConfig, err := parseNATConfig(&tomlCfg.NAT)
	if err != nil {
		return nil, fmt.Errorf("failed to parse NAT config: %w", err)
	}
	cfg.NATConfig = natConfig

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

// parseNATConfig 解析 NAT 配置
func parseNATConfig(tomlCfg *struct {
	VPNServerIP   string   `toml:"vpn_server_ip"`
	VPNPort       uint16   `toml:"vpn_port"`
	PortStart     uint16   `toml:"port_start"`
	PortEnd       uint16   `toml:"port_end"`
	ReservedPorts []uint16 `toml:"reserved_ports"`
	Timeout       int      `toml:"timeout"`
	IngressIface   uint8    `toml:"ingress_iface"`
	EgressIface    uint8    `toml:"egress_iface"`
	EgressIPs     []string `toml:"egress_ips"`
}) (*NATConfig, error) {
	cfg := &NATConfig{
		PortStart:     tomlCfg.PortStart,
		PortEnd:       tomlCfg.PortEnd,
		TimeoutNS:      uint64(tomlCfg.Timeout) * 1000000000, // 转换为纳秒
		VPNPort:       tomlCfg.VPNPort,
		IngressIface:   tomlCfg.IngressIface,
		EgressIface:    tomlCfg.EgressIface,
		EgressIPCount:   uint8(len(tomlCfg.EgressIPs)),
		ReservedCount:  uint16(len(tomlCfg.ReservedPorts)),
	}

	// 解析 VPN 服务器 IP
	if tomlCfg.VPNServerIP != "" {
		ip := net.ParseIP(tomlCfg.VPNServerIP)
		if ip == nil {
			return nil, fmt.Errorf("invalid vpn_server_ip: %s", tomlCfg.VPNServerIP)
		}
		cfg.VPNServerIP = ipToUint32(ip)
	}

	// 解析预留端口
	for i, port := range tomlCfg.ReservedPorts {
		if i >= 32 {
			break
		}
		cfg.ReservedPorts[i] = port
	}

	// 解析公网 IP 列表
	for i, ipStr := range tomlCfg.EgressIPs {
		if i >= 16 {
			break
		}
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return nil, fmt.Errorf("invalid egress_ip[%d]: %s", i, ipStr)
		}
		cfg.EgressIPs[i] = ipToUint32(ip)
	}

	return cfg, nil
}

// SyncNATConfig 将 NAT 配置同步到 eBPF Map
func (c *Config) SyncNATConfig(vpnConfigMap *ebpf.Map) error {
	if vpnConfigMap == nil {
		return fmt.Errorf("vpnConfigMap is nil")
	}
	if c.NATConfig == nil {
		return fmt.Errorf("NATConfig is nil")
	}

	// 将 NATConfig 转换为字节（使用网络字节序 BigEndian）
	value := make([]byte, 256) // sizeof(vpn_global_config) = 256 字节
	binary.BigEndian.PutUint64(value[0:8], c.NATConfig.TimeoutNS)
	binary.BigEndian.PutUint32(value[8:12], c.NATConfig.VPNServerIP)
	binary.BigEndian.PutUint16(value[12:14], c.NATConfig.VPNPort)
	binary.BigEndian.PutUint16(value[14:16], c.NATConfig.PortStart)
	binary.BigEndian.PutUint16(value[16:18], c.NATConfig.PortEnd)

	// 写入预留端口
	for i := 0; i < 32; i++ {
		binary.BigEndian.PutUint16(value[18+i*2:18+i*2+2], c.NATConfig.ReservedPorts[i])
	}
	binary.BigEndian.PutUint16(value[18+64:18+64+2], c.NATConfig.ReservedCount)

	// 写入网卡配置
	value[82] = c.NATConfig.IngressIface
	value[83] = c.NATConfig.EgressIface
	value[84] = c.NATConfig.EgressIPCount

	// 写入公网 IP 列表
	for i := 0; i < 16; i++ {
		binary.BigEndian.PutUint32(value[88+i*4:88+i*4+4], c.NATConfig.EgressIPs[i])
	}

	key := uint32(0)
	return vpnConfigMap.Put(&key, value)
}
