package pcap

import (
	"encoding/binary"
	"fmt"
	"os"
	"time"
)

// Writer PCAP 文件写入器
type Writer struct {
	file       *os.File
	packetChan chan []byte
	done       chan struct{}
}

// NewWriter 创建新的 PCAP 写入器
func NewWriter(filename string) (*Writer, error) {
	file, err := os.Create(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to create pcap file: %w", err)
	}

	// 写入 PCAP 全局头部
	if err := writeGlobalHeader(file); err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to write pcap header: %w", err)
	}

	w := &Writer{
		file:       file,
		packetChan: make(chan []byte, 1000),
		done:       make(chan struct{}),
	}

	// 启动写入 goroutine
	go w.writeLoop()

	return w, nil
}

// writeGlobalHeader 写入 PCAP 全局头部（24 字节）
func writeGlobalHeader(file *os.File) error {
	header := make([]byte, 24)

	// Magic Number (0xa1b2c3d4: 大端序)
	binary.LittleEndian.PutUint32(header[0:4], 0xa1b2c3d4)

	// Version 2.4
	binary.LittleEndian.PutUint16(header[4:6], 2)
	binary.LittleEndian.PutUint16(header[6:8], 4)

	// GMT to local correction
	binary.LittleEndian.PutUint32(header[8:12], 0)

	// Accuracy of timestamps
	binary.LittleEndian.PutUint32(header[12:16], 0)

	// Max length of captured packets (snaplen)
	binary.LittleEndian.PutUint32(header[16:20], 65535)

	// Data link type (1 = Ethernet)
	binary.LittleEndian.PutUint32(header[20:24], 1)

	_, err := file.Write(header)
	return err
}

// writePacketHeader 写入 PCAP 包头部（16 字节）
func writePacketHeader(file *os.File, packetData []byte) error {
	header := make([]byte, 16)

	// Timestamp (seconds and microseconds)
	now := time.Now()
	tsSec := now.Unix()
	tsUsec := now.UnixMicro() % 1000000

	binary.LittleEndian.PutUint32(header[0:4], uint32(tsSec))
	binary.LittleEndian.PutUint32(header[4:8], uint32(tsUsec))

	// Incl_len (实际捕获长度)
	binary.LittleEndian.PutUint32(header[8:12], uint32(len(packetData)))

	// Orig_len (原始包长度)
	binary.LittleEndian.PutUint32(header[12:16], uint32(len(packetData)))

	_, err := file.Write(header)
	if err != nil {
		return err
	}

	// 写入包数据
	_, err = file.Write(packetData)
	return err
}

// Write 异步写入数据包（非阻塞）
func (w *Writer) Write(packetData []byte) {
	select {
	case w.packetChan <- packetData:
		// 成功发送到队列
	default:
		// 队列满，丢弃包
		fmt.Println("Warning: pcap write queue full, dropping packet")
	}
}

// writeLoop 写入循环（在单独的 goroutine 中运行）
func (w *Writer) writeLoop() {
	for {
		select {
		case <-w.done:
			// 处理剩余的包
			for len(w.packetChan) > 0 {
				packetData := <-w.packetChan
				if err := writePacketHeader(w.file, packetData); err != nil {
					fmt.Printf("Error writing packet: %v\n", err)
				}
			}
			return
		case packetData := <-w.packetChan:
			if err := writePacketHeader(w.file, packetData); err != nil {
				fmt.Printf("Error writing packet: %v\n", err)
			}
		}
	}
}

// Close 关闭写入器
func (w *Writer) Close() error {
	close(w.done)

	// 等待写入循环完成（最多等待 5 秒）
	timeout := time.After(5 * time.Second)
	done := make(chan struct{})

	go func() {
		// writeLoop 会检测到 done 关闭并退出
		time.Sleep(100 * time.Millisecond)
		close(done)
	}()

	select {
	case <-done:
		// 正常退出
	case <-timeout:
		fmt.Println("Warning: pcap writer close timeout")
	}

	if w.file != nil {
		return w.file.Close()
	}
	return nil
}

// Sync 刷新文件缓冲区到磁盘
func (w *Writer) Sync() error {
	if w.file != nil {
		return w.file.Sync()
	}
	return nil
}
