package main

import (
	"bytes"
	"ebpf-vpn/gosrc/config"
	"encoding/binary"
	"log"
	"net"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type PacketInfo struct {
	SrcIP   uint32
	DstIP   uint32
	SrcPort uint16
	DstPort uint16
	Length  uint16
}

func setTraceFlag(configMap *ebpf.Map) error {
	key := uint32(1)   // key_trace
	value := uint32(1) // 打开 trace
	return configMap.Update(&key, &value, ebpf.UpdateAny)
}

type TraceEvent struct {
	PktLen     uint32
	PktRealLen uint32
	Raw        [1500]byte
	XdpAction  uint32
}

type FilterRule struct {
	SrcIP    uint32
	DstIP    uint32
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
	_        [3]byte // 填充对齐，保证结构体大小与 C 端一致
}

const UDP_ECHO_PORT = 28080

func main() {
	xdpObj := "./build/xdp/xdp.o"
	// 加载编译好的 xdp_accept.o
	spec, err := ebpf.LoadCollectionSpec(xdpObj)
	if err != nil {
		log.Fatalf("failed to load spec: %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("failed to create collection: %v", err)
	}
	defer coll.Close()

	// 获取网卡接口
	iface, err := net.InterfaceByName("ens34") // 替换为你的网卡名
	if err != nil {
		log.Fatalf("failed to get interface: %v", err)
	}

	// 将 XDP 程序 attach 到网卡
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   coll.Programs["xdp_firewall"],
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("failed to attach XDP program: %v", err)
	}
	defer xdpLink.Close()

	configMap := coll.Maps["config_map"]

	// udp_echo程序的监听port
	err = config.SetUdpEchoPort(configMap, UDP_ECHO_PORT)
	if err != nil {
		log.Fatalf("Failed to set UDP echo port: %v", err)
	}
	log.Printf("Set UDP echo port to %d\n", UDP_ECHO_PORT)

	eventsRingbuf, ok := coll.Maps["events_ringbuf"]
	if !ok {
		log.Fatalf("events_ringbuf map not found")
	}

	rd, err := ringbuf.NewReader(eventsRingbuf)
	if err != nil {
		log.Fatalf("failed to create ringbuf reader: %v", err)
	}
	defer rd.Close()

	// 创建 pcap 文件
	f, err := os.Create("output.pcap")
	if err != nil {
		log.Fatalf("failed to create pcap file: %v", err)
	}
	defer f.Close()
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(1500, layers.LinkTypeEthernet)

	// 打开抓包开关
	err = setTraceFlag(configMap)
	if err != nil {
		log.Fatalf("Failed to set trace flag: %v", err)
	}

	// 设置过滤规则
	rule := FilterRule{
		SrcIP:    0,
		DstIP:    0,  // 不过滤目标IP
		SrcPort:  0,  // 过滤源端口
		DstPort:  0,  // 不过滤目标端口
		Protocol: 17, // IPPROTO_UDP
	}

	key := uint32(0)
	filterRuleMap := coll.Maps["filter_rule_map"]
	err = filterRuleMap.Update(&key, &rule, ebpf.UpdateAny)
	if err != nil {
		log.Fatalf("Failed to set filter rule: %v", err)
	}

	for {
		record, err := rd.Read()
		if err != nil {
			log.Fatalf("ringbuf read error: %v", err)
		}

		var evt TraceEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &evt); err != nil {
			log.Printf("Error parsing trace event: %v", err)
			continue
		}

		pkt := evt.Raw[:evt.PktLen]
		w.WritePacket(gopacket.CaptureInfo{
			Timestamp:     time.Now(),
			CaptureLength: int(evt.PktLen),
			Length:        int(evt.PktLen),
		}, pkt)
	}
}
