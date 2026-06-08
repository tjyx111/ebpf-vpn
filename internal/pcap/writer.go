package pcap

import (
	"encoding/binary"
	"fmt"
	"os"
	"sync"
	"time"
)

const (
	pcapMagic        = 0xa1b2c3d4
	pcapVersionMajor = 2
	pcapVersionMinor = 4
	linkTypeEthernet = 1
	defaultSnapLen   = 65535
)

type Writer struct {
	mu sync.Mutex
	f  *os.File
}

func NewWriter(path string) (*Writer, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("create pcap: %w", err)
	}

	w := &Writer{f: f}
	if err := w.writeHeader(); err != nil {
		_ = f.Close()
		return nil, err
	}
	return w, nil
}

func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	return err
}

func (w *Writer) WritePacket(ts time.Time, packet []byte, originalLen uint32) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.f == nil {
		return fmt.Errorf("pcap writer is closed")
	}

	header := struct {
		TsSec   uint32
		TsUsec  uint32
		InclLen uint32
		OrigLen uint32
	}{
		TsSec:   uint32(ts.Unix()),
		TsUsec:  uint32(ts.Nanosecond() / 1000),
		InclLen: uint32(len(packet)),
		OrigLen: originalLen,
	}
	if err := binary.Write(w.f, binary.LittleEndian, header); err != nil {
		return fmt.Errorf("write packet header: %w", err)
	}
	if _, err := w.f.Write(packet); err != nil {
		return fmt.Errorf("write packet data: %w", err)
	}
	return nil
}

func (w *Writer) writeHeader() error {
	header := struct {
		Magic        uint32
		VersionMajor uint16
		VersionMinor uint16
		Thiszone     int32
		Sigfigs      uint32
		SnapLen      uint32
		Network      uint32
	}{
		Magic:        pcapMagic,
		VersionMajor: pcapVersionMajor,
		VersionMinor: pcapVersionMinor,
		SnapLen:      defaultSnapLen,
		Network:      linkTypeEthernet,
	}
	if err := binary.Write(w.f, binary.LittleEndian, header); err != nil {
		return fmt.Errorf("write pcap header: %w", err)
	}
	return nil
}
