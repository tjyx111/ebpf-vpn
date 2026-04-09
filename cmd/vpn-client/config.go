package main

import (
	"fmt"
	"os"
	"time"

	"github.com/BurntSushi/toml"
)

// Config VPN 客户端配置
type Config struct {
	Client  ClientConfig  `toml:"client"`
	Target  TargetConfig  `toml:"target"`
	VPN     VPNConfig     `toml:"vpn"`
	Logging LoggingConfig `toml:"logging"`
}

// ClientConfig 客户端配置
type ClientConfig struct {
	LocalIP        string `toml:"local_ip"`
	LocalPortStart uint16 `toml:"local_port_start"`
	LocalPortEnd   uint16 `toml:"local_port_end"`
}

// TargetConfig 目标配置
type TargetConfig struct {
	ServerIP     string `toml:"server_ip"`
	ServerPort   uint16 `toml:"server_port"`
	TcpTargetIP  string `toml:"tcp_target_ip"`
	TcpTargetPort uint16 `toml:"tcp_target_port"`
}

// VPNConfig VPN 配置
type VPNConfig struct {
	SessionID uint32 `toml:"session_id"`
	Timeout   uint32 `toml:"timeout"` // 秒
}

// LoggingConfig 日志配置
type LoggingConfig struct {
	Enabled bool   `toml:"enabled"`
	Level   string `toml:"level"`
}

// LoadConfig 加载配置文件
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	return &cfg, nil
}

// GetTimeoutDuration 获取超时时间
func (c *VPNConfig) GetTimeoutDuration() time.Duration {
	return time.Duration(c.Timeout) * time.Second
}
