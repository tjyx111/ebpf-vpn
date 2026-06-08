package pcap

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

const (
	dnatCaptureHeaderLen = 24
)

type Recorder struct {
	reader *ringbuf.Reader
	writer *Writer
	done   chan struct{}
	once   sync.Once
}

func NewRecorder(events *ebpf.Map, path string) (*Recorder, error) {
	reader, err := ringbuf.NewReader(events)
	if err != nil {
		return nil, fmt.Errorf("open ringbuf reader: %w", err)
	}

	writer, err := NewWriter(path)
	if err != nil {
		_ = reader.Close()
		return nil, err
	}

	return &Recorder{
		reader: reader,
		writer: writer,
		done:   make(chan struct{}),
	}, nil
}

func (r *Recorder) Start() {
	go func() {
		defer close(r.done)
		var record ringbuf.Record
		for {
			if err := r.reader.ReadInto(&record); err != nil {
				if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, os.ErrClosed) || errors.Is(err, io.EOF) {
					return
				}
				log.Printf("DNAT pcap recorder read error: %v", err)
				continue
			}

			if err := r.writeRecord(record.RawSample); err != nil {
				log.Printf("DNAT pcap recorder write error: %v", err)
			}
		}
	}()
}

func (r *Recorder) Close() error {
	var err error
	r.once.Do(func() {
		err = r.reader.Close()
		<-r.done
		if closeErr := r.writer.Close(); err == nil {
			err = closeErr
		}
	})
	return err
}

func (r *Recorder) writeRecord(sample []byte) error {
	if len(sample) < dnatCaptureHeaderLen {
		return fmt.Errorf("short capture event: %d bytes", len(sample))
	}

	packetLen := binary.LittleEndian.Uint32(sample[12:16])
	capLen := binary.LittleEndian.Uint32(sample[16:20])
	packetStart := dnatCaptureHeaderLen
	packetEnd := packetStart + int(capLen)
	if capLen > packetLen || packetEnd > len(sample) {
		return fmt.Errorf("invalid capture lengths: packet=%d cap=%d sample=%d", packetLen, capLen, len(sample))
	}

	return r.writer.WritePacket(time.Now(), sample[packetStart:packetEnd], packetLen)
}
