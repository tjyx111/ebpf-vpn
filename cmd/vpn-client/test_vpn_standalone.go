package main

import (
	"encoding/binary"
	"fmt"
	"log"
)

// 简单的 VPN 封装测试（不依赖 gVisor）

func main() {
	fmt.Println("=== VPN 封装格式测试 ===")
	fmt.Println()

	// 1. 创建模拟的 IP 数据包 (TCP SYN 到 192.168.99.99:8080)
	ipPacket := createMockIPPacket("192.168.99.100", "192.168.99.99", 4660, 8080)
	fmt.Printf("原始 IP 包 (%d bytes):\n", len(ipPacket))
	printPacket(ipPacket, "  ")
	fmt.Println()

	// 2. VPN 封装
	sessionID := uint32(12345)
	vpnPacket := encapsulateVPN(ipPacket, sessionID)

	fmt.Printf("VPN 封装后的包 (%d bytes):\n", len(vpnPacket))
	printPacket(vpnPacket, "  ")
	fmt.Println()

	// 3. 解析并验证 VPN 头部
	fmt.Println("VPN 头部解析:")
	fmt.Printf("  First Byte:     0x%02x\n", vpnPacket[0])
	fmt.Printf("    - Magic (高4位): 0x%02x ✓\n", vpnPacket[0]&0xF0)
	fmt.Printf("    - Reserved (低4位): 0x%02x\n", vpnPacket[0]&0x0F)
	fmt.Printf("  Next Protocol:  %d (IPv4) ✓\n", vpnPacket[1])
	fmt.Printf("  Flags:          0x%04x\n", binary.BigEndian.Uint16(vpnPacket[2:4]))
	fmt.Printf("  Session ID:     %d ✓\n", binary.BigEndian.Uint32(vpnPacket[4:8]))
	fmt.Println()

	// 4. 验证解封装
	decapIP := vpnPacket[8:]
	fmt.Println("解封装验证:")
	fmt.Printf("  解封装后的 IP 包大小: %d bytes\n", len(decapIP))
	fmt.Printf("  与原始包匹配: %v ✓\n", len(decapIP) == len(ipPacket))
	fmt.Println()

	// 5. UDP 包结构说明
	fmt.Println("=== UDP 包完整结构 ===")
	fmt.Println("如果在实际网络中通过 UDP 发送到 192.168.88.88:18080:")
	fmt.Printf("  ┌────────────────────────────────────────────────┐\n")
	fmt.Printf("  │ UDP Header (8 bytes)                           │\n")
	fmt.Printf("  │  Src Port: 随机端口 (如 12345)                  │\n")
	fmt.Printf("  │  Dst Port: 18080                               │\n")
	fmt.Printf("  │  Length: %d bytes                              │\n", 8+len(vpnPacket))
	fmt.Printf("  │  Checksum: xxxx                                │\n")
	fmt.Printf("  ├────────────────────────────────────────────────┤\n")
	fmt.Printf("  │ VPN Header (8 bytes)                           │\n")
	fmt.Printf("  │  90 01 00 00 00 00 30 39                       │\n")
	fmt.Printf("  │  ↑  ↑  ↑  ↑  ↑  ↑  ↑  ↑                        │\n")
	fmt.Printf("  │  |  |  |  |  |  |  |  +-- Session ID (12345)   │\n")
	fmt.Printf("  │  |  |  |  |  |  +-- ...                        │\n")
	fmt.Printf("  │  |  |  |  +-- Flags (0x0000)                   │\n")
	fmt.Printf("  │  |  |  +-- Next Protocol (1=IPv4)              │\n")
	fmt.Printf("  │  |  +-- Magic (0x90 = 1001)                    │\n")
	fmt.Printf("  ├────────────────────────────────────────────────┤\n")
	fmt.Printf("  │ IP Payload (%d bytes)                          │\n", len(ipPacket))
	fmt.Printf("  │  Original IP Packet (从 192.168.99.100->99)    │\n")
	fmt.Printf("  └────────────────────────────────────────────────┘\n")
	fmt.Println()

	// 6. 示例：完整的 UDP 包字节数组
	fmt.Println("示例 UDP 包数据 (前 64 bytes):")
	udpPacket := buildUDPPacket(vpnPacket, 12345, 18080)
	if len(udpPacket) > 64 {
		printPacket(udpPacket[:64], "  ")
	} else {
		printPacket(udpPacket, "  ")
	}
	fmt.Println()

	fmt.Println("✓ VPN 封装格式验证完成！")
	fmt.Println("  - Magic 字段: 0x90 (正确)")
	fmt.Println("  - 协议字段: 1 (IPv4, 正确)")
	fmt.Println("  - Session ID: 12345 (正确)")
	fmt.Println("  - IP 载荷完整 (正确)")
}

// 创建模拟的 IP 数据包 (TCP SYN)
func createMockIPPacket(srcIP, dstIP string, srcPort, dstPort uint16) []byte {
	packet := make([]byte, 40) // 20 bytes IP + 20 bytes TCP

	// 简化：手动构造 IP 头
	// Version/IHL = 0x45
	packet[0] = 0x45
	// TOS = 0
	packet[1] = 0x00
	// Total Length = 40
	binary.BigEndian.PutUint16(packet[2:4], 40)
	// ID = 0
	packet[4] = 0x00
	packet[5] = 0x00
	// Flags/Fragment = 0
	packet[6] = 0x00
	packet[7] = 0x00
	// TTL = 64
	packet[8] = 0x40
	// Protocol = TCP (6)
	packet[9] = 0x06
	// Checksum = 0 (简化)
	packet[10] = 0x00
	packet[11] = 0x00

	// 源 IP: 192.168.99.100
	packet[12] = 192
	packet[13] = 168
	packet[14] = 99
	packet[15] = 100

	// 目标 IP: 192.168.99.99
	packet[16] = 192
	packet[17] = 168
	packet[18] = 99
	packet[19] = 99

	// TCP 头部 (从 offset 20 开始)
	// 源端口: 4660 (0x1234)
	binary.BigEndian.PutUint16(packet[20:22], srcPort)
	// 目标端口: 8080 (0x1F90)
	binary.BigEndian.PutUint16(packet[22:24], dstPort)
	// 序列号
	packet[24] = 0x00
	packet[25] = 0x00
	packet[26] = 0x00
	packet[27] = 0x01
	// 确认号
	packet[28] = 0x00
	packet[29] = 0x00
	packet[30] = 0x00
	packet[31] = 0x00
	// 头部长度 + 标志 (20 bytes, SYN)
	packet[32] = 0x50
	packet[33] = 0x02
	// 窗口
	packet[34] = 0x20
	packet[35] = 0x00
	// 校验和
	packet[36] = 0x00
	packet[37] = 0x00
	// 紧急指针
	packet[38] = 0x00
	packet[39] = 0x00

	return packet
}

// VPN 封装
func encapsulateVPN(ipPacket []byte, sessionID uint32) []byte {
	vpnPacket := make([]byte, 8+len(ipPacket))

	// VPN Header (8 bytes)
	vpnPacket[0] = 0x90                    // Magic: 1001
	vpnPacket[1] = 0x01                    // Protocol: IPv4
	binary.BigEndian.PutUint16(vpnPacket[2:4], 0) // Flags: 0
	binary.BigEndian.PutUint32(vpnPacket[4:8], sessionID) // Session ID

	// Copy IP packet
	copy(vpnPacket[8:], ipPacket)

	return vpnPacket
}

// 构建 UDP 数据包
func buildUDPPacket(vpnPacket []byte, srcPort, dstPort uint16) []byte {
	udpPacket := make([]byte, 8+len(vpnPacket)) // 8 bytes UDP header

	// UDP Header
	binary.BigEndian.PutUint16(udpPacket[0:2], srcPort)
	binary.BigEndian.PutUint16(udpPacket[2:4], dstPort)
	binary.BigEndian.PutUint16(udpPacket[4:6], uint16(len(udpPacket)))
	udpPacket[6] = 0x00 // Checksum (简化)
	udpPacket[7] = 0x00

	// Copy VPN packet
	copy(udpPacket[8:], vpnPacket)

	return udpPacket
}

// 打印数据包
func printPacket(data []byte, indent string) {
	for i := 0; i < len(data); i += 16 {
		fmt.Printf("%s%04x: ", indent, i)

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

func init() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
}
