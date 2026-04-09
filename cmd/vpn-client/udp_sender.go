package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// UDPSender UDP 发送器
// 负责将封装后的 VPN 数据包通过 UDP 发送到目标服务器
type UDPSender struct {
	conn        *net.UDPConn
	serverAddr  *net.UDPAddr
	mu          sync.Mutex
	sendCount   uint64
	errorCount  uint64
	lastSend    time.Time
}

// NewUDPSender 创建 UDP 发送器
func NewUDPSender(serverIP string, serverPort uint16) (*UDPSender, error) {
	// 解析目标地址
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", serverIP, serverPort))
	if err != nil {
		return nil, fmt.Errorf("resolve UDP addr: %w", err)
	}

	// 创建本地 UDP socket (使用任意端口)
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, fmt.Errorf("listen UDP: %w", err)
	}

	// 设置发送缓冲区
	if err := conn.SetWriteBuffer(1024 * 1024); err != nil {
		return nil, fmt.Errorf("set write buffer: %w", err)
	}

	sender := &UDPSender{
		conn:       conn,
		serverAddr: addr,
		lastSend:   time.Now(),
	}

	return sender, nil
}

// Send 发送 VPN 数据包
func (s *UDPSender) Send(vpnPacket []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 发送数据
	n, err := s.conn.WriteToUDP(vpnPacket, s.serverAddr)
	if err != nil {
		s.errorCount++
		return fmt.Errorf("write UDP: %w", err)
	}

	if n != len(vpnPacket) {
		s.errorCount++
		return fmt.Errorf("partial write: %d/%d", n, len(vpnPacket))
	}

	s.sendCount++
	s.lastSend = time.Now()

	return nil
}

// SendIPPacket 发送 IP 数据包（自动封装）
func (s *UDPSender) SendIPPacket(ipPacket []byte, sessionID uint32) error {
	// VPN 封装
	vpnPacket, err := Encapsulate(ipPacket, sessionID)
	if err != nil {
		return fmt.Errorf("encapsulate: %w", err)
	}

	// 发送
	return s.Send(vpnPacket)
}

// GetStats 获取统计信息
func (s *UDPSender) GetStats() (sendCount, errorCount uint64, lastSend time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.sendCount, s.errorCount, s.lastSend
}

// Close 关闭 UDP 发送器
func (s *UDPSender) Close() error {
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

// BuildUDPPacket 构建 UDP 数据包（可选，如果需要手动构建）
// 用于调试或特殊场景
func BuildUDPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) ([]byte, error) {
	// UDP 头部 (8 字节)
	udpHdr := make([]byte, header.UDPMinimumSize)
	binary.BigEndian.PutUint16(udpHdr[0:2], srcPort)
	binary.BigEndian.PutUint16(udpHdr[2:4], dstPort)
	binary.BigEndian.PutUint16(udpHdr[4:6], uint16(header.UDPMinimumSize+len(payload)))
	binary.BigEndian.PutUint16(udpHdr[6:8], 0) // checksum (可选)

	// 组合 UDP 头部和载荷
	packet := make([]byte, len(udpHdr)+len(payload))
	copy(packet, udpHdr)
	copy(packet[len(udpHdr):], payload)

	return packet, nil
}
