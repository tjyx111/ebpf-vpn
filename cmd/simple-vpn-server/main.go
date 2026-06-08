package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
)

const (
	VPNMagicValue = 0x90
	VPNProtoIPv4  = 1
	VPNHeaderSize = 8
)

func main() {
	port := flag.Int("port", 18080, "监听端口")
	flag.Parse()

	fmt.Printf("=== 简单 VPN 测试服务器 ===\n")
	fmt.Printf("监听端口: %d\n", *port)
	fmt.Println()

	// 创建 UDP 监听
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("解析地址失败: %v", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("监听失败: %v", err)
	}
	defer conn.Close()

	fmt.Printf("UDP 服务器已启动，监听: %s\n", conn.LocalAddr().String())
	fmt.Println("等待客户端连接...")
	fmt.Println()

	buf := make([]byte, 1500)
	for {
		// 读取数据
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("读取失败: %v", err)
			continue
		}

		fmt.Printf("=== 收到包 from %s (%d bytes) ===\n", clientAddr.String(), n)
		printPacket(buf[:n], "  ")

		// 检查是否是 VPN 包
		if n < VPNHeaderSize {
			fmt.Println("包太短，不是 VPN 包")
			continue
		}

		// 检查 VPN magic
		if buf[0]>>4 != 0x09 { // VPN_MAGIC_MASK = 0xF0, VPN_MAGIC_VALUE = 0x90
			fmt.Println("不是 VPN 包（magic 不匹配）")
			continue
		}

		fmt.Println("检测到 VPN 包！")

		// 提取 VPN 头部
		sessionID := binary.BigEndian.Uint32(buf[4:8])
		fmt.Printf("  Session ID: %d\n", sessionID)

		// 提取内层 IP 包
		if n < VPNHeaderSize+20 {
			fmt.Println("包太短，无法解析内层 IP")
			continue
		}

		ipPacket := buf[VPNHeaderSize:n]
		protocol := ipPacket[9]
		srcIP := net.IPv4(ipPacket[12], ipPacket[13], ipPacket[14], ipPacket[15])
		dstIP := net.IPv4(ipPacket[16], ipPacket[17], ipPacket[18], ipPacket[19])

		fmt.Printf("  内层 IP: %s -> %s, Protocol: %d\n", srcIP, dstIP, protocol)

		// 如果是 ICMP，打印详细信息
		if protocol == 1 && n >= VPNHeaderSize+20+8 {
			icmpPacket := ipPacket[20:]
			icmpType := icmpPacket[0]
			icmpCode := icmpPacket[1]
			icmpSeq := binary.BigEndian.Uint16(icmpPacket[6:8])

			fmt.Printf("  ICMP: Type=%d, Code=%d, Seq=%d\n", icmpType, icmpCode, icmpSeq)

			// 如果是 Echo Request，构造 Echo Reply
			if icmpType == 8 { // Echo Request
				fmt.Println("  构造 ICMP Echo Reply...")

				// 修改 ICMP 头部
				replyICMP := make([]byte, len(icmpPacket))
				copy(replyICMP, icmpPacket)
				replyICMP[0] = 0 // Echo Reply
				replyICMP[2] = 0 // 清空校验和
				replyICMP[3] = 0

				// 重新计算 ICMP 校验和
				checksum := calculateChecksum(replyICMP)
				binary.BigEndian.PutUint16(replyICMP[2:4], checksum)

				// 构造 IP 包（交换源和目标 IP）
				replyIP := make([]byte, len(ipPacket))
				copy(replyIP, ipPacket)

				// 交换源和目标 IP
				copy(replyIP[12:16], ipPacket[16:20])
				copy(replyIP[16:20], ipPacket[12:16])

				// 修改 IP 头部
				replyIP[8] = 64   // TTL
				replyIP[10] = 0  // 清空校验和
				replyIP[11] = 0

				// 重新计算 IP 校验和
				ipChecksum := calculateChecksum(replyIP[:20])
				binary.BigEndian.PutUint16(replyIP[10:12], ipChecksum)

				// 组合回复
				replyPacket := make([]byte, VPNHeaderSize+len(replyIP))

				// VPN 头部
				replyPacket[0] = VPNMagicValue
				replyPacket[1] = VPNProtoIPv4
				binary.BigEndian.PutUint16(replyPacket[2:4], 0)
				binary.BigEndian.PutUint32(replyPacket[4:8], sessionID)

				// 复制 IP 包
				copy(replyPacket[VPNHeaderSize:], replyIP)

				// 发送回复
				fmt.Printf("  发送回复 (%d bytes)\n", len(replyPacket))
				printPacket(replyPacket, "    ")

				_, err = conn.WriteToUDP(replyPacket, clientAddr)
				if err != nil {
					log.Printf("发送失败: %v", err)
				} else {
					fmt.Println("  发送成功！")
				}
			}
		}

		fmt.Println()
	}
}

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
