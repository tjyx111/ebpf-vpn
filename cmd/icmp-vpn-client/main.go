package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"
)

const (
	VPNPort       = 18080
	VPNMagicValue = 0x90
	VPNProtoIPv4  = 1
	VPNHeaderSize = 8
	SessionID     = 12345
)

// VPNHeader VPN 头部结构
type VPNHeader struct {
	FirstByte    uint8
	NextProtocol uint8
	Flags        uint16
	SessionID    uint32
}

func main() {
	fmt.Println("=== ICMP VPN 测试客户端 ===")
	fmt.Println("发送目标: 8.8.8.8")
	fmt.Println("VPN 服务器: 127.0.0.1:18080")
	fmt.Println("Session ID:", SessionID)
	fmt.Println()

	// 创建 UDP 连接到本地 lo 接口
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:18080")
	if err != nil {
		log.Fatalf("解析地址失败: %v", err)
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		log.Fatalf("创建 UDP 连接失败: %v", err)
	}
	defer conn.Close()

	fmt.Println("UDP 连接已建立:", conn.LocalAddr().String(), "->", conn.RemoteAddr().String())
	fmt.Println()

	// 创建 ICMP Echo Request 包（目标 8.8.8.8）
	icmpPacket := createICMPPacket("8.8.8.8")
	fmt.Printf("ICMP 包创建成功 (%d bytes)\n", len(icmpPacket))
	printPacket(icmpPacket, "  ")
	fmt.Println()

	// 封装到 VPN
	vpnPacket := encapsulateVPN(icmpPacket, SessionID)
	fmt.Printf("VPN 封装后 (%d bytes)\n", len(vpnPacket))
	printPacket(vpnPacket[:min(64, len(vpnPacket))], "  ")
	fmt.Println()

	// 发送数据包
	fmt.Printf("发送 VPN 包到 %s...\n", conn.RemoteAddr().String())
	_, err = conn.Write(vpnPacket)
	if err != nil {
		log.Fatalf("发送失败: %v", err)
	}
	fmt.Println("发送成功！")
	fmt.Println()

	// 等待响应
	fmt.Println("等待响应...")
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		log.Printf("读取响应失败: %v", err)
		fmt.Println()
		fmt.Println("注意: 如果 XDP 程序正确处理了 SNAT，应该能看到相关日志输出")
		fmt.Println("请检查 'sudo cat /sys/kernel/debug/tracing/trace_pipe' 的输出")
		return
	}

	fmt.Printf("收到响应 (%d bytes)\n", n)
	printPacket(buf[:min(64, n)], "  ")
}

// createICMPPacket 创建 ICMP Echo Request 包
func createICMPPacket(dstIP string) []byte {
	// IP 头部 (20 bytes)
	ipHeader := make([]byte, 20)

	// Version/IHL
	ipHeader[0] = 0x45
	// TOS
	ipHeader[1] = 0x00
	// Total Length (稍后计算)
	binary.BigEndian.PutUint16(ipHeader[2:4], 0)
	// ID
	binary.BigEndian.PutUint16(ipHeader[4:6], 12345)
	// Flags/Fragment
	ipHeader[6] = 0x40
	ipHeader[7] = 0x00
	// TTL
	ipHeader[8] = 64
	// Protocol (ICMP = 1)
	ipHeader[9] = 0x01
	// Checksum (稍后计算)
	ipHeader[10] = 0x00
	ipHeader[11] = 0x00

	// Source IP (127.0.0.1)
	ipHeader[12] = 127
	ipHeader[13] = 0
	ipHeader[14] = 0
	ipHeader[15] = 1

	// Destination IP (8.8.8.8)
	ipHeader[16] = 8
	ipHeader[17] = 8
	ipHeader[18] = 8
	ipHeader[19] = 8

	// ICMP Header (8 bytes) + Data
	icmpHeader := make([]byte, 8+12) // 8 bytes header + 12 bytes data

	// Type (Echo Request = 8)
	icmpHeader[0] = 8
	// Code
	icmpHeader[1] = 0
	// Checksum (稍后计算)
	icmpHeader[2] = 0
	icmpHeader[3] = 0
	// ID
	binary.BigEndian.PutUint16(icmpHeader[4:6], 1)
	// Sequence
	binary.BigEndian.PutUint16(icmpHeader[6:8], 1)

	// Data (payload)
	data := []byte("Hello ICMP!")
	copy(icmpHeader[8:], data)

	// 计算 ICMP 校验和
	icmpChecksum := calculateChecksum(icmpHeader)
	binary.BigEndian.PutUint16(icmpHeader[2:4], icmpChecksum)

	// 组合 IP 包
	ipPacket := make([]byte, 20+len(icmpHeader))
	copy(ipPacket, ipHeader)
	copy(ipPacket[20:], icmpHeader)

	// 计算总长度
	binary.BigEndian.PutUint16(ipPacket[2:4], uint16(len(ipPacket)))

	// 计算 IP 校验和
	ipChecksum := calculateChecksum(ipPacket[:20])
	binary.BigEndian.PutUint16(ipPacket[10:12], ipChecksum)

	return ipPacket
}

// encapsulateVPN 封装 VPN
func encapsulateVPN(ipPacket []byte, sessionID uint32) []byte {
	vpnPacket := make([]byte, VPNHeaderSize+len(ipPacket))

	// VPN Header (8 bytes)
	vpnPacket[0] = VPNMagicValue                          // Magic: 1001
	vpnPacket[1] = VPNProtoIPv4                           // Protocol: IPv4
	binary.BigEndian.PutUint16(vpnPacket[2:4], 0)         // Flags: 0
	binary.BigEndian.PutUint32(vpnPacket[4:8], sessionID) // Session ID

	// Copy IP packet
	copy(vpnPacket[8:], ipPacket)

	return vpnPacket
}

// calculateChecksum 计算校验和
func calculateChecksum(data []byte) uint16 {
	sum := uint32(0)

	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}

	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}

	for sum>>16 > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	return ^uint16(sum)
}

// printPacket 打印数据包
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func init() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
}
