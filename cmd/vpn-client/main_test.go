package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// 测试 VPN 封装格式
func testVPNEncapsulation() {
	fmt.Println("=== VPN 封装格式测试 ===")
	fmt.Println()

	// 1. 创建一个模拟的 IP 数据包
	ipPacket := createMockIPPacket()
	fmt.Printf("原始 IP 包 (%d bytes):\n", len(ipPacket))
	printPacket(ipPacket, "  ")
	fmt.Println()

	// 2. VPN 封装
	sessionID := uint32(12345)
	vpnPacket, err := Encapsulate(ipPacket, sessionID)
	if err != nil {
		log.Fatalf("VPN 封装失败: %v", err)
	}

	fmt.Printf("VPN 封装后的包 (%d bytes):\n", len(vpnPacket))
	printPacket(vpnPacket, "  ")
	fmt.Println()

	// 3. 解析 VPN 头部
	vpnHeader, err := parseVPNHeader(vpnPacket)
	if err != nil {
		log.Fatalf("解析 VPN 头部失败: %v", err)
	}

	fmt.Println("VPN 头部解析:")
	fmt.Printf("  First Byte:     0x%02x (Magic: 0x%02x)\n", vpnHeader.FirstByte, vpnHeader.FirstByte&0xF0)
	fmt.Printf("  Next Protocol:  %d (IPv4)\n", vpnHeader.NextProtocol)
	fmt.Printf("  Flags:          0x%04x\n", vpnHeader.Flags)
	fmt.Printf("  Session ID:     %d\n", vpnHeader.SessionID)
	fmt.Println()

	// 4. 验证解封装
	decapIP, decapHeader, err := Decapsulate(vpnPacket)
	if err != nil {
		log.Fatalf("解封装失败: %v", err)
	}

	fmt.Println("解封装验证:")
	fmt.Printf("  解封装后的 IP 包大小: %d bytes\n", len(decapIP))
	fmt.Printf("  Session ID 匹配: %v\n", decapHeader.SessionID == sessionID)
	fmt.Printf("  协议正确: %v\n", decapHeader.NextProtocol == VPNProtoIPv4)
	fmt.Printf("  Magic 正确: %v\n", decapHeader.FirstByte&0xF0 == VPNMagicValue)
	fmt.Println()

	// 5. UDP 包结构分析（如果在真实 UDP 中发送）
	fmt.Println("=== UDP 包结构分析 ===")
	fmt.Println("如果通过 UDP 发送，完整的包结构如下:")
	fmt.Printf("  UDP Header   : 8 bytes (SrcPort + DstPort + Length + Checksum)\n")
	fmt.Printf("  VPN Header   : 8 bytes (Magic + Proto + Flags + SessionID)\n")
	fmt.Printf("  IP Payload   : %d bytes (原始 IP 包)\n", len(ipPacket))
	fmt.Printf("  Total        : %d bytes\n", 8+len(vpnPacket))
	fmt.Println()
}

// 创建模拟的 IP 数据包
func createMockIPPacket() []byte {
	// IP 头部 (20 bytes minimum)
	ip := header.IPv4Packet(make([]byte, 40)) // 20 bytes IP + 20 bytes TCP

	// IP 头部
	ip.Encode(0x45,                     // Version/IHL
		64,                              // TOS
		40,                              // Total Length
		0,                               // ID
		0,                               // Flags/Fragment
		64,                              // TTL
		6,                               // Protocol (TCP)
		0,                               // Checksum (先填0)
		[]byte{192, 168, 99, 100},       // Src IP
		[]byte{192, 168, 99, 99})        // Dst IP

	// 计算并设置校验和
	ip.SetChecksum(^ip.CalculateChecksum())

	// TCP 头部 (20 bytes)
	tcp := ip[header.IPv4MinimumSize:]
	tcp[0] = 0x12 // Src Port high
	tcp[1] = 0x34 // Src Port low (4660)
	tcp[2] = 0x1F // Dst Port high (8080 = 0x1F90)
	tcp[3] = 0x90 // Dst Port low
	tcp[4] = 0x00 // Seq Num
	tcp[5] = 0x00
	tcp[6] = 0x00
	tcp[7] = 0x01
	tcp[8] = 0x00 // Ack Num
	tcp[9] = 0x00
	tcp[10] = 0x00
	tcp[11] = 0x00
	tcp[12] = 0x50 // Header Length + Flags (20 bytes + SYN)
	tcp[13] = 0x02 // Flags (SYN)
	tcp[14] = 0x20 // Window
	tcp[15] = 0x00
	tcp[16] = 0x00 // Checksum
	tcp[17] = 0x00
	tcp[18] = 0x00 // Urgent
	tcp[19] = 0x00

	return []byte(ip)
}

// 解析 VPN 头部
func parseVPNHeader(vpnPacket []byte) (*VPNHeader, error) {
	if len(vpnPacket) < VPNHeaderSize {
		return nil, fmt.Errorf("VPN packet too short: %d bytes", len(vpnPacket))
	}

	return &VPNHeader{
		FirstByte:    vpnPacket[0],
		NextProtocol: vpnPacket[1],
		Flags:        uint16(vpnPacket[2])<<8 | uint16(vpnPacket[3]),
		SessionID:    uint32(vpnPacket[4])<<24 | uint32(vpnPacket[5])<<16 |
			uint32(vpnPacket[6])<<8 | uint32(vpnPacket[7]),
	}, nil
}

// 打印数据包
func printPacket(data []byte, indent string) {
	// 打印十六进制和 ASCII
	for i := 0; i < len(data); i += 16 {
		// 偏移量
		fmt.Printf("%s%04x: ", indent, i)

		// 十六进制
		for j := 0; j < 16; j++ {
			if i+j < len(data) {
				fmt.Printf("%02x ", data[i+j])
			} else {
				fmt.Print("   ")
			}
			if j == 7 {
				fmt.Print(" ")
			}
		}

		// ASCII
		fmt.Print(" |")
		for j := 0; j < 16 && i+j < len(data); j++ {
			b := data[i+j]
			if b >= 32 && b <= 126 {
				fmt.Printf("%c", b)
			} else {
				fmt.Print(".")
			}
		}
		fmt.Println("|")
	}
}

// 打印 VPN 包结构
func printVPNPacketStructure(vpnPacket []byte) {
	fmt.Println("VPN 包结构分析:")
	fmt.Println("┌─────────────────────────────────────────────────────────┐")
	fmt.Println("│ UDP Header (8 bytes)                                    │")
	fmt.Println("│  - Src Port: xxxx                                       │")
	fmt.Println("│  - Dst Port: 18080                                      │")
	fmt.Println("├─────────────────────────────────────────────────────────┤")
	fmt.Println("│ VPN Header (8 bytes)                                    │")
	fmt.Printf("│  - Magic: 0x%02x (1001)                                  \n", vpnPacket[0])
	fmt.Printf("│  - Protocol: %d (IPv4)                                   \n", vpnPacket[1])
	fmt.Printf("│  - Flags: 0x%04x                                         \n", uint16(vpnPacket[2])<<8|uint16(vpnPacket[3]))
	fmt.Printf("│  - Session ID: %d                                        \n", uint32(vpnPacket[4])<<24|uint32(vpnPacket[5])<<16|uint32(vpnPacket[6])<<8|uint32(vpnPacket[7]))
	fmt.Println("├─────────────────────────────────────────────────────────┤")
	fmt.Printf("│ IP Payload (%d bytes)                                    \n", len(vpnPacket)-8)
	fmt.Println("│  - Original IP Packet                                   │")
	fmt.Println("└─────────────────────────────────────────────────────────┘")
}
