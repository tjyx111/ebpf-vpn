package packet

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"ebpf-vpn/internal/logging"
)

// DebugEvent 对应 C 端的 debug_event 结构（packed，80字节）
type DebugEvent struct {
	// 外层以太网头
	OuterSrcMac [6]byte
	OuterDstMac [6]byte

	// 外层 IP
	OuterSrcIP     uint32
	OuterDstIP     uint32
	OuterProtocol  uint8
	OuterSrcPort   uint16
	OuterDstPort   uint16

	// VPN 头
	VpnFirstByte  uint8
	VpnNextProto  uint8
	VpnFlags      uint16
	VpnSessionID  uint32

	// 内层 IP
	InnerSrcIP    uint32
	InnerDstIP    uint32
	InnerProtocol uint8
	InnerSrcPort  uint16
	InnerDstPort  uint16

	// 路由信息
	FibIfindex  uint32 // 出接口索引
	FibSrcMac   [6]byte
	FibDstMac   [6]byte
	FibResult   int32

	Timestamp uint64
}

// TraceEvent 对应 C 端的 trace_event 结构
type TraceEvent struct {
	PktLen     uint32
	PktRealLen uint32
	PacketData [1500]byte
	XdpAction  uint32
}

// Consumer Ring Buffer 消费器
type Consumer struct {
	reader *ringbuf.Reader
	done   chan struct{}
	logger *logging.Logger
}

// NewConsumer 创建新的消费者
func NewConsumer(ringbufMap *ebpf.Map, logger *logging.Logger) (*Consumer, error) {
	rd, err := ringbuf.NewReader(ringbufMap)
	if err != nil {
		return nil, fmt.Errorf("failed to create ringbuf reader: %w", err)
	}

	return &Consumer{
		reader: rd,
		done:   make(chan struct{}),
		logger: logger,
	}, nil
}

// Start 启动消费 goroutine
func (c *Consumer) Start() {
	go c.consume()
}

// Stop 停止消费
func (c *Consumer) Stop() {
	close(c.done)
}

// consume 消费 Ring Buffer 事件
func (c *Consumer) consume() {
	defer c.reader.Close()

	for {
		select {
		case <-c.done:
			log.Println("Stopping packet consumer...")
			return
		default:
		}

		// 读取事件
		rec, err := c.reader.Read()
		if err != nil {
			if err == ringbuf.ErrClosed {
				return
			}
			continue
		}

		// 解析事件
		if len(rec.RawSample) < 12 {
			continue
		}

		event := (*TraceEvent)(unsafe.Pointer(&rec.RawSample[0]))
		c.logPacket(event)
	}
}

// logPacket 格式化输出数据包信息
func (c *Consumer) logPacket(event *TraceEvent) {
	// 检查日志开关（对应 C 端的 LOG_DEBUG_PKG）
	if !c.logger.DebugPkgEnabled() {
		return
	}
	packet := event.PacketData[:event.PktLen]

	if len(packet) < 14 {
		return
	}

	// 解析以太网头
	ethType := binary.BigEndian.Uint16(packet[12:14])
	if ethType != 0x0800 { // 不是 IPv4
		return
	}

	if len(packet) < 14+20 {
		return
	}

	// 解析 IP 头
	ipHeader := packet[14:]
	version := ipHeader[0] >> 4
	if version != 4 {
		return
	}

	protocol := ipHeader[9]
	srcIP := net.IP(ipHeader[12:16]).String()
	dstIP := net.IP(ipHeader[16:20]).String()

	var srcPort, dstPort uint16
	var protoStr string

	switch protocol {
	case 6: // TCP
		protoStr = "TCP"
		if len(packet) >= 14+20+20 {
			srcPort = binary.BigEndian.Uint16(ipHeader[20:22])
			dstPort = binary.BigEndian.Uint16(ipHeader[22:24])
		}
	case 17: // UDP
		protoStr = "UDP"
		if len(packet) >= 14+20+8 {
			srcPort = binary.BigEndian.Uint16(ipHeader[20:22])
			dstPort = binary.BigEndian.Uint16(ipHeader[22:24])
		}
	case 1: // ICMP
		protoStr = "ICMP"
	default:
		protoStr = fmt.Sprintf("PROTO(%d)", protocol)
	}

	xdpAction := xdpActionToString(event.XdpAction)

	log.Printf("[PACKET] %s %s:%d -> %s:%d | len=%d | action=%s",
		protoStr, srcIP, srcPort, dstIP, dstPort,
		event.PktRealLen, xdpAction)
}

// xdpActionToString 将 XDP action 转换为字符串
func xdpActionToString(action uint32) string {
	switch action {
	case 0:
		return "XDP_ABORTED"
	case 1:
		return "XDP_DROP"
	case 2:
		return "XDP_PASS"
	case 3:
		return "XDP_TX"
	case 4:
		return "XDP_REDIRECT"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", action)
	}
}

// DebugConsumer Debug 事件 Ring Buffer 消费器
type DebugConsumer struct {
	reader *ringbuf.Reader
	done   chan struct{}
	logger *logging.Logger
}

// NewDebugConsumer 创建新的 Debug 消费者
func NewDebugConsumer(ringbufMap *ebpf.Map, logger *logging.Logger) (*DebugConsumer, error) {
	rd, err := ringbuf.NewReader(ringbufMap)
	if err != nil {
		return nil, fmt.Errorf("failed to create debug ringbuf reader: %w", err)
	}

	return &DebugConsumer{
		reader: rd,
		done:   make(chan struct{}),
		logger: logger,
	}, nil
}

// Start 启动消费 goroutine
func (c *DebugConsumer) Start() {
	go c.consume()
}

// Stop 停止消费
func (c *DebugConsumer) Stop() {
	close(c.done)
}

// consume 消费 Debug Ring Buffer 事件
func (c *DebugConsumer) consume() {
	defer c.reader.Close()

	// C 端实际大小（通过 unsafe.Sizeof 获取的 Go 大小可能与 C 端不一致）
	const expectedSize = 74

	for {
		select {
		case <-c.done:
			log.Println("Stopping debug consumer...")
			return
		default:
		}

		// 读取事件
		rec, err := c.reader.Read()
		if err != nil {
			if err == ringbuf.ErrClosed {
				return
			}
			continue
		}

		// 解析事件
		if len(rec.RawSample) < expectedSize {
			continue
		}

		event := (*DebugEvent)(unsafe.Pointer(&rec.RawSample[0]))
		c.logDebugEvent(event)
	}
}

// logDebugEvent 格式化输出 Debug 事件
func (c *DebugConsumer) logDebugEvent(event *DebugEvent) {
	// 检查日志开关（对应 C 端的 LOG_DEBUG_PKG）
	if !c.logger.DebugPkgEnabled() {
		return
	}
	// 转换 MAC 地址为字符串
	outerSrcMac := macToString(event.OuterSrcMac[:])
	outerDstMac := macToString(event.OuterDstMac[:])
	fibSrcMac := macToString(event.FibSrcMac[:])
	fibDstMac := macToString(event.FibDstMac[:])

	// 转换 IP 地址为字符串
	outerSrcIP := intToIP(event.OuterSrcIP)
	outerDstIP := intToIP(event.OuterDstIP)
	innerSrcIP := intToIP(event.InnerSrcIP)
	innerDstIP := intToIP(event.InnerDstIP)

	// 协议类型
	outerProto := protocolToString(event.OuterProtocol)
	innerProto := protocolToString(event.InnerProtocol)

	// FIB 结果
	fibResult := fibResultToString(event.FibResult)

	log.Printf("[DEBUG] ========== PACKET START ==========")
	log.Printf("[DEBUG] Outer: %s -> %s | %s %s:%d -> %s:%d",
		outerSrcMac, outerDstMac,
		outerProto, outerSrcIP, event.OuterSrcPort, outerDstIP, event.OuterDstPort)

	log.Printf("[DEBUG] VPN Header: magic=0x%02x, proto=%d, flags=0x%04x, session=%d",
		event.VpnFirstByte, event.VpnNextProto, event.VpnFlags, event.VpnSessionID)

	log.Printf("[DEBUG] Inner: %s %s:%d -> %s:%d",
		innerProto, innerSrcIP, event.InnerSrcPort, innerDstIP, event.InnerDstPort)

	log.Printf("[DEBUG] FIB Lookup: %s", fibResult)
	if event.FibResult == 0 {
		log.Printf("[DEBUG] FIB -> ifindex=%d, src_mac=%s, dst_mac=%s",
			event.FibIfindex, fibSrcMac, fibDstMac)
	}

	log.Printf("[DEBUG] Timestamp: %d ns", event.Timestamp)
	log.Printf("[DEBUG] ========== PACKET END ============\n")
}

// macToString 将 MAC 字节数组转换为字符串
func macToString(mac []byte) string {
	if len(mac) != 6 {
		return "??"
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

// intToIP 将 uint32 IP 地址转换为字符串
func intToIP(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		(ip>>24)&0xFF, (ip>>16)&0xFF, (ip>>8)&0xFF, ip&0xFF)
}

// protocolToString 将协议号转换为字符串
func protocolToString(proto uint8) string {
	switch proto {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	default:
		return fmt.Sprintf("PROTO(%d)", proto)
	}
}

// fibResultToString 将 FIB 查询结果转换为字符串
func fibResultToString(result int32) string {
	switch result {
	case 0:
		return "SUCCESS"
	case -1:
		return "ERR_FAILED"
	case -2:
		return "ERR_NO_NEIGH"
	case -3:
		return "ERR_IPV6_DISABLED"
	default:
		return fmt.Sprintf("ERR(%d)", result)
	}
}
