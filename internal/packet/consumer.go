package packet

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unsafe"

	"ebpf-vpn/internal/logging"
	"ebpf-vpn/internal/pcap"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

// LogEvent 对应 C 端的 log_event 结构
type LogEvent struct {
	LogFlag uint32
	DataLen uint16
	Reserved uint16
	LogData [1024]byte
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
	reader     *ringbuf.Reader
	done       chan struct{}
	logger     *logging.Logger
	pcapWriter *pcap.Writer
}

// NewConsumer 创建新的消费者
func NewConsumer(ringbufMap *ebpf.Map, logger *logging.Logger, pcapFile string) (*Consumer, error) {
	rd, err := ringbuf.NewReader(ringbufMap)
	if err != nil {
		return nil, fmt.Errorf("failed to create ringbuf reader: %w", err)
	}

	c := &Consumer{
		reader: rd,
		done:   make(chan struct{}),
		logger: logger,
	}

	// 如果指定了 pcap 文件，创建 pcap 写入器
	if pcapFile != "" {
		writer, err := pcap.NewWriter(pcapFile)
		if err != nil {
			rd.Close()
			return nil, fmt.Errorf("failed to create pcap writer: %w", err)
		}
		c.pcapWriter = writer
		log.Printf("PCAP writing enabled: %s", pcapFile)
	}

	return c, nil
}

// Start 启动消费 goroutine
func (c *Consumer) Start() {
	go c.consume()
}

// Stop 停止消费
func (c *Consumer) Stop() {
	close(c.done)
	if c.pcapWriter != nil {
		if err := c.pcapWriter.Close(); err != nil {
			log.Printf("Error closing pcap writer: %v", err)
		} else {
			log.Printf("PCAP file closed successfully")
		}
	}
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

	// 写入 pcap 文件（如果启用）- 不依赖日志开关
	if c.pcapWriter != nil && len(packet) > 0 {
		c.pcapWriter.Write(packet)
	}

	// 检查日志开关（对应 C 端的 LOG_DEBUG_PKG）
	if !c.logger.DebugPkgEnabled() {
		return
	}

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

// LogConsumer 日志 Ring Buffer 消费器
type LogConsumer struct {
	reader     *ringbuf.Reader
	done       chan struct{}
	logFile    *os.File
	logDir     string
	mu         sync.Mutex
}

// NewLogConsumer 创建新的日志消费者
func NewLogConsumer(ringbufMap *ebpf.Map, logDir string) (*LogConsumer, error) {
	rd, err := ringbuf.NewReader(ringbufMap)
	if err != nil {
		return nil, fmt.Errorf("failed to create log ringbuf reader: %w", err)
	}

	// 创建日志目录
	if err := os.MkdirAll(logDir, 0755); err != nil {
		rd.Close()
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	return &LogConsumer{
		reader:  rd,
		done:    make(chan struct{}),
		logDir:  logDir,
	}, nil
}

// Start 启动消费 goroutine
func (c *LogConsumer) Start() {
	go c.consume()
}

// Stop 停止消费
func (c *LogConsumer) Stop() {
	close(c.done)
	if c.logFile != nil {
		c.logFile.Close()
	}
}

// consume 消费日志 Ring Buffer 事件
func (c *LogConsumer) consume() {
	defer c.reader.Close()

	const unifiedLogFileName = "unified.log"

	for {
		select {
		case <-c.done:
			log.Println("Stopping log consumer...")
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
		if len(rec.RawSample) < 8 { // 至少需要 log_flag + data_len
			continue
		}

		event := (*LogEvent)(unsafe.Pointer(&rec.RawSample[0]))

		// 写入统一日志文件，带 LogFlag 前缀
		c.writeLog(unifiedLogFileName, event.LogFlag, event.LogData[:event.DataLen])
	}
}

// logFlagToString 将日志标志位转换为字符串前缀
func logFlagToString(logFlag uint32) string {
	switch logFlag {
	case 1 << 0:
		return "[DEBUG_PKT]"
	case 1 << 2:
		return "[SNAT]"
	case 1 << 3:
		return "[DNAT]"
	case 1 << 4:
		return "[CFG]"
	case 1 << 7:
		return "[ICMP]"
	default:
		return fmt.Sprintf("[FLAG_%d]", logFlag)
	}
}

// writeLog 写入日志到文件（带日志轮转）
func (c *LogConsumer) writeLog(filename string, logFlag uint32, data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	const maxLogSize = 100 * 1024 * 1024 // 100MB
	const maxLogFiles = 5

	// 关闭之前的文件（如果文件名改变）
	if c.logFile != nil && filepath.Base(c.logFile.Name()) != filename {
		c.logFile.Close()
		c.logFile = nil
	}

	// 打开日志文件（如果还没打开）
	if c.logFile == nil {
		logPath := filepath.Join(c.logDir, filename)
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Printf("Failed to open log file %s: %v", logPath, err)
			return
		}
		c.logFile = f
	}

	// 检查文件大小，如果超过限制则进行轮转
	info, err := c.logFile.Stat()
	if err == nil {
		if info.Size() >= maxLogSize {
			// 关闭当前文件
			c.logFile.Close()
			c.logFile = nil

			// 执行日志轮转
			c.rotateLog(filename, maxLogFiles, maxLogSize)
		}
	}

	// 重新打开文件（轮转后）
	if c.logFile == nil {
		logPath := filepath.Join(c.logDir, filename)
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Printf("Failed to open log file %s after rotation: %v", logPath, err)
			return
		}
		c.logFile = f
	}

	// 写入日志数据
	timestamp := time.Now().Format("2006-01-02 15:04:05.000")
	logPrefix := logFlagToString(logFlag)
	logLine := fmt.Sprintf("[%s] %s %s\n", timestamp, logPrefix, string(data))

	if _, err := c.logFile.WriteString(logLine); err != nil {
		log.Printf("Failed to write log: %v", err)
	}

	// 立即刷新到磁盘
	c.logFile.Sync()
}

// rotateLog 执行日志轮转
func (c *LogConsumer) rotateLog(filename string, maxFiles int, maxLogSize int64) {
	logPath := filepath.Join(c.logDir, filename)

	// 删除最旧的日志文件（.5）
	oldFile5 := logPath + ".5"
	os.Remove(oldFile5)

	// 重命名 .4 → .5
	for i := maxFiles - 1; i >= 1; i-- {
		oldFile := logPath + fmt.Sprintf(".%d", i)
		newFile := logPath + fmt.Sprintf(".%d", i+1)

		if err := os.Rename(oldFile, newFile); err != nil && !os.IsNotExist(err) {
			log.Printf("Warning: failed to rotate log file %s: %v", oldFile, err)
		}
	}

	// 重命名当前文件 → .1
	if err := os.Rename(logPath, logPath+".1"); err != nil && !os.IsNotExist(err) {
		log.Printf("Warning: failed to rotate log file %s: %v", logPath, err)
	}

	log.Printf("Log rotated: %s (max %d files, %dMB each)\n", filename, maxFiles, maxLogSize/(1024*1024))
}
