package packet

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

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
}

// NewConsumer 创建新的消费者
func NewConsumer(ringbufMap *ebpf.Map) (*Consumer, error) {
	rd, err := ringbuf.NewReader(ringbufMap)
	if err != nil {
		return nil, fmt.Errorf("failed to create ringbuf reader: %w", err)
	}

	return &Consumer{
		reader: rd,
		done:   make(chan struct{}),
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
