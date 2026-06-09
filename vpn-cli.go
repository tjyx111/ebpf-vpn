package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"time"
)

const (
	VPNMagicValue = 0x90
	VPNProtoIPv4  = 1
	VPNHeaderSize = 8
)

// VPNHeader VPN 头部结构
type VPNHeader struct {
	FirstByte    uint8
	NextProtocol uint8
	Flags        uint16
	SessionID    uint32
}

func main() {
	// 命令行参数
	vpnServer := flag.String("vpn-server", "192.168.56.103:17878", "VPN 服务器地址 (IP:Port)")
	targetIP := flag.String("target", "8.8.8.8", "目标 IP 地址")
	sourceIP := flag.String("source", "10.192.1.1", "源 IP 地址 (内层 IP)")
	sessionID := flag.Uint("session-id", 12345, "Session ID")
	timeout := flag.Duration("timeout", 5*time.Second, "等待响应的超时时间")
	count := flag.Int("count", 1, "发送包的数量 (0 表示持续发送)")
	interval := flag.Duration("interval", 1*time.Second, "发送间隔")

	flag.Parse()

	fmt.Println("=== ICMP VPN 测试客户端 ===")
	fmt.Printf("发送目标: %s\n", *targetIP)
	fmt.Printf("源地址: %s\n", *sourceIP)
	fmt.Printf("VPN 服务器: %s\n", *vpnServer)
	fmt.Printf("Session ID: %d\n", *sessionID)
	fmt.Printf("发送数量: %d\n", *count)
	if *count > 1 || *count == 0 {
		fmt.Printf("发送间隔: %v\n", *interval)
	}
	fmt.Println()

	// 解析 VPN 服务器地址
	vpnAddr, err := net.ResolveUDPAddr("udp", *vpnServer)
	if err != nil {
		log.Fatalf("解析 VPN 服务器地址失败: %v", err)
	}

	// 创建 UDP 连接
	conn, err := net.DialUDP("udp", nil, vpnAddr)
	if err != nil {
		log.Fatalf("创建 UDP 连接失败: %v", err)
	}
	defer conn.Close()

	fmt.Printf("UDP 连接已建立: %s -> %s\n", conn.LocalAddr().String(), conn.RemoteAddr().String())
	fmt.Println()

	// 发送 ICMP 包
	for i := 0; *count == 0 || i < *count; i++ {
		if i > 0 {
			time.Sleep(*interval)
		}

		// 创建 ICMP Echo Request 包
		sequence := uint16(i + 1)
		icmpPacket := createICMPPacket(*sourceIP, *targetIP, sequence)
		fmt.Printf("[%d] ICMP 包创建成功 (%d bytes)\n", i+1, len(icmpPacket))
		if *count == 1 || i == 0 {
			printPacket(icmpPacket, "  ")
			fmt.Println()
		}

		// 封装到 VPN
		vpnPacket := encapsulateVPN(icmpPacket, uint32(*sessionID))
		fmt.Printf("[%d] VPN 封装后 (%d bytes)\n", i+1, len(vpnPacket))
		if *count == 1 || i == 0 {
			printPacket(vpnPacket[:min(64, len(vpnPacket))], "  ")
			fmt.Println()
		}

		// 发送数据包
		fmt.Printf("[%d] 发送 VPN 包到 %s...\n", i+1, conn.RemoteAddr().String())
		_, err = conn.Write(vpnPacket)
		if err != nil {
			log.Fatalf("发送失败: %v", err)
		}
		fmt.Printf("[%d] 发送成功！\n", i+1)
		fmt.Println()

		// 等待响应
		fmt.Printf("[%d] 等待响应...\n", i+1)
		conn.SetReadDeadline(time.Now().Add(*timeout))

		buf := make([]byte, 1500)
		n, err := conn.Read(buf)
		if err != nil {
			log.Printf("[%d] 读取响应失败: %v", i+1, err)
			fmt.Println()
			fmt.Println("注意: 如果 XDP 程序正确处理了 SNAT，应该能看到相关日志输出")
			fmt.Println("请检查 'sudo cat /sys/kernel/debug/tracing/trace_pipe' 的输出")
			continue
		}

		fmt.Printf("[%d] 收到响应 (%d bytes)\n", i+1, n)
		printPacket(buf[:min(64, n)], "  ")
		fmt.Println()
	}
}

// createICMPPacket 创建 ICMP Echo Request 包
func createICMPPacket(srcIP, dstIP string, sequence uint16) []byte {
	// 解析 IP 地址
	srcIPAddr := net.ParseIP(srcIP)
	dstIPAddr := net.ParseIP(dstIP)
	if srcIPAddr == nil {
		log.Fatalf("无效的源 IP 地址: %s", srcIP)
	}
	if dstIPAddr == nil {
		log.Fatalf("无效的目标 IP 地址: %s", dstIP)
	}

	srcIPAddr = srcIPAddr.To4()
	dstIPAddr = dstIPAddr.To4()

	// IP 头部 (20 bytes)
	ipHeader := make([]byte, 20)

	// Version/IHL
	ipHeader[0] = 0x45
	// TOS
	ipHeader[1] = 0x00
	// Total Length (稍后计算)
	binary.BigEndian.PutUint16(ipHeader[2:4], 0)
	// ID
	binary.BigEndian.PutUint16(ipHeader[4:6], uint16(sequence))
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

	// Source IP
	copy(ipHeader[12:16], srcIPAddr)

	// Destination IP
	copy(ipHeader[16:20], dstIPAddr)

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
	binary.BigEndian.PutUint16(icmpHeader[6:8], sequence)

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
