package main

import (
	"encoding/binary"
	"fmt"
)

// VPNHeader VPN 头部结构 (8 字节)
//
//	+--------+--------+--------+--------+--------+--------+--------+--------+
//	|                        |                  |                                   |
//	|   first_byte (0x90)   |  next_protocol   |            flags                  |
//	|                        |                  |                                   |
//	+--------+--------+--------+--------+--------+--------+--------+--------+
//	|                                   |                                               |
//	|        session_id (4 bytes)       |                                               |
//	|                                   |                                               |
//	+-----------------------------------+-----------------------------------------------+
type VPNHeader struct {
	FirstByte    uint8  // 高4位 = 1001 (0x90)，低4位保留
	NextProtocol uint8  // 下层协议 (1 = IPv4)
	Flags        uint16 // 标志位
	SessionID    uint32 // 会话 ID
}

const (
	VPNMagicValue = 0x90 // 高4位: 1001
	VPNProtoIPv4  = 1    // IPv4
	VPNHeaderSize = 8    // VPN 头部大小
)

// NewVPNHeader 创建 VPN 头部
func NewVPNHeader(sessionID uint32) *VPNHeader {
	return &VPNHeader{
		FirstByte:    VPNMagicValue,
		NextProtocol: VPNProtoIPv4,
		Flags:        0,
		SessionID:    sessionID,
	}
}

// Serialize 序列化 VPN 头部
func (h *VPNHeader) Serialize() []byte {
	buf := make([]byte, VPNHeaderSize)
	buf[0] = h.FirstByte
	buf[1] = h.NextProtocol
	binary.BigEndian.PutUint16(buf[2:4], h.Flags)
	binary.BigEndian.PutUint32(buf[4:8], h.SessionID)
	return buf
}

// Encapsulate VPN 封装
// 将原始 IP 数据包封装到 VPN 载荷中
func Encapsulate(ipPacket []byte, sessionID uint32) ([]byte, error) {
	if len(ipPacket) == 0 {
		return nil, fmt.Errorf("empty IP packet")
	}

	// 创建 VPN 头部
	header := NewVPNHeader(sessionID)

	// 组合: VPN Header + IP Packet
	vpnPacket := make([]byte, VPNHeaderSize+len(ipPacket))
	copy(vpnPacket[:VPNHeaderSize], header.Serialize())
	copy(vpnPacket[VPNHeaderSize:], ipPacket)

	return vpnPacket, nil
}

// Decapsulate VPN 解封装
// 从 VPN 数据包中提取原始 IP 数据包
func Decapsulate(vpnPacket []byte) ([]byte, *VPNHeader, error) {
	if len(vpnPacket) < VPNHeaderSize {
		return nil, nil, fmt.Errorf("invalid VPN packet: too short")
	}

	// 解析 VPN 头部
	header := &VPNHeader{
		FirstByte:    vpnPacket[0],
		NextProtocol: vpnPacket[1],
		Flags:        binary.BigEndian.Uint16(vpnPacket[2:4]),
		SessionID:    binary.BigEndian.Uint32(vpnPacket[4:8]),
	}

	// 验证 Magic 值
	if header.FirstByte&0xF0 != VPNMagicValue {
		return nil, nil, fmt.Errorf("invalid VPN packet: bad magic")
	}

	// 提取 IP 数据包
	ipPacket := vpnPacket[VPNHeaderSize:]
	if len(ipPacket) == 0 {
		return nil, nil, fmt.Errorf("empty IP packet in VPN payload")
	}

	return ipPacket, header, nil
}
