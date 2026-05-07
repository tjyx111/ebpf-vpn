package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: pcap-reader <pcap-file>")
		fmt.Println("Example: pcap-reader vpn_18080_capture.pcap")
		os.Exit(1)
	}

	filename := os.Args[1]
	file, err := os.Open(filename)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	// 读取 PCAP 全局头部
	header := make([]byte, 24)
	if _, err := file.Read(header); err != nil {
		fmt.Printf("Error reading header: %v\n", err)
		os.Exit(1)
	}

	// 验证 Magic Number
	magic := binary.LittleEndian.Uint32(header[0:4])
	if magic != 0xa1b2c3d4 && magic != 0xd4c3b2a1 {
		fmt.Printf("Invalid PCAP file: magic=0x%x\n", magic)
		os.Exit(1)
	}

	fmt.Printf("========================================\n")
	fmt.Printf("  PCAP 文件分析器\n")
	fmt.Printf("========================================\n")
	fmt.Printf("文件: %s\n", filename)
	fmt.Printf("Magic: 0x%x\n", magic)

	if magic == 0xd4c3b2a1 {
		fmt.Println("字节序: 大端序（需要交换）")
	} else {
		fmt.Println("字节序: 小端序")
	}

	versionMajor := binary.LittleEndian.Uint16(header[4:6])
	versionMinor := binary.LittleEndian.Uint16(header[6:8])
	fmt.Printf("版本: %d.%d\n", versionMajor, versionMinor)

	snaplen := binary.LittleEndian.Uint32(header[16:20])
	fmt.Printf("捕获长度: %d bytes\n", snaplen)

	network := binary.LittleEndian.Uint32(header[20:24])
	fmt.Printf("链路层类型: %d (", network)
	switch network {
	case 1:
		fmt.Print("Ethernet")
	case 113:
		fmt.Print("Linux Cooked")
	default:
		fmt.Print("Unknown")
	}
	fmt.Println(")")
	fmt.Printf("========================================\n\n")

	packetCount := 0
	totalBytes := uint64(0)

	for {
		// 读取包头（16 字节）
		pktHeader := make([]byte, 16)
		n, err := file.Read(pktHeader)
		if err != nil || n != 16 {
			break
		}

		// 解析时间戳
		tsSec := binary.LittleEndian.Uint32(pktHeader[0:4])
		tsUsec := binary.LittleEndian.Uint32(pktHeader[4:8])
		inclLen := binary.LittleEndian.Uint32(pktHeader[8:12])
		origLen := binary.LittleEndian.Uint32(pktHeader[12:16])

		timestamp := time.Unix(int64(tsSec), int64(tsUsec)*1000)

		// 读取包数据
		packetData := make([]byte, inclLen)
		n, err = file.Read(packetData)
		if err != nil || n != int(inclLen) {
			break
		}

		packetCount++
		totalBytes += uint64(inclLen)

		// 显示前 5 个包的详细信息
		if packetCount <= 5 {
			fmt.Printf("包 #%d\n", packetCount)
			fmt.Printf("  时间: %s\n", timestamp.Format("2006-01-02 15:04:05.000"))
			fmt.Printf("  长度: %d bytes (原始: %d bytes)\n", inclLen, origLen)

			// 解析以太网头
			if len(packetData) >= 14 {
				fmt.Printf("  以太网: %02x:%02x:%02x:%02x:%02x:%02x -> ",
					packetData[6], packetData[7], packetData[8], packetData[9], packetData[10], packetData[11])
				fmt.Printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
					packetData[0], packetData[1], packetData[2], packetData[3], packetData[4], packetData[5])

				ethType := binary.BigEndian.Uint16(packetData[12:14])
				fmt.Printf("  EthType: 0x%04x\n", ethType)

				// 解析 IP 头
				if ethType == 0x0800 && len(packetData) >= 14+20 {
					ipHeader := packetData[14:]
					protocol := ipHeader[9]
					srcIP := fmt.Sprintf("%d.%d.%d.%d", ipHeader[12], ipHeader[13], ipHeader[14], ipHeader[15])
					dstIP := fmt.Sprintf("%d.%d.%d.%d", ipHeader[16], ipHeader[17], ipHeader[18], ipHeader[19])

					var protoStr string
					switch protocol {
					case 1:
						protoStr = "ICMP"
					case 6:
						protoStr = "TCP"
					case 17:
						protoStr = "UDP"
					default:
						protoStr = fmt.Sprintf("PROTO(%d)", protocol)
					}

					fmt.Printf("  IP: %s -> %s | %s\n", srcIP, dstIP, protoStr)

					// 解析 UDP 头
					if protocol == 17 && len(packetData) >= 14+20+8 {
						udpHeader := ipHeader[20:]
						srcPort := binary.BigEndian.Uint16(udpHeader[0:2])
						dstPort := binary.BigEndian.Uint16(udpHeader[2:4])
						fmt.Printf("  UDP: %d -> %d\n", srcPort, dstPort)

						// 检查是否是 VPN 端口
						if dstPort == 18080 || srcPort == 18080 {
							fmt.Printf("  *** VPN 流量检测到 (端口 18080) ***\n")

							// 检查 VPN Header
							if len(packetData) >= 14+20+8+8 {
								vpnHeader := udpHeader[8:]
								magic := vpnHeader[0] & 0xF0
								if magic == 0x90 {
									fmt.Printf("  VPN Magic: 0x%02x ✓\n", vpnHeader[0])
									fmt.Printf("  VPN Protocol: %d\n", vpnHeader[1])
									sessionID := binary.BigEndian.Uint32(vpnHeader[4:8])
									fmt.Printf("  Session ID: %d\n", sessionID)
								}
							}
						}
					}
				}
			}
			fmt.Println()
		}
	}

	fmt.Printf("========================================\n")
	fmt.Printf("总计: %d 个数据包, %d bytes\n", packetCount, totalBytes)
	fmt.Printf("========================================\n")
}
