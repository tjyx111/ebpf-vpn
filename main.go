package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
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

// 转换 IP 为 uint32（网络字节序）
func ipToUint32(ip string) uint32 {
	return binary.BigEndian.Uint32(net.ParseIP(ip).To4())
}

func txMonitor() {
	// 移除内存限制
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Failed to remove memlock:", err)
	}

	// 加载 eBPF 程序
	spec, err := ebpf.LoadCollectionSpec("monitor.o")
	if err != nil {
		log.Fatal("Failed to load eBPF program:", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatal("Failed to create collection:", err)
	}
	defer coll.Close()

	// 获取网卡接口
	iface, err := net.InterfaceByName("ens34")
	if err != nil {
		log.Fatal("Failed to get interface:", err)
	}

	// 附加到 TC ingress
	l, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   coll.Programs["monitor_udp"],
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		log.Fatal("Failed to attach TC program:", err)
	}
	defer l.Close()

	// 创建 perf event reader
	rd, err := perf.NewReader(coll.Maps["events"], os.Getpagesize())
	if err != nil {
		log.Fatal("Failed to create perf reader:", err)
	}
	defer rd.Close()

	fmt.Printf("Monitoring UDP port 18082 on ens34...\n")
	fmt.Printf("%-15s %-6s %-15s %-6s %-6s\n", "SRC_IP", "SPORT", "DST_IP", "DPORT", "LEN")

	// 处理信号
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				log.Printf("Error reading perf event: %v", err)
				continue
			}

			var info PacketInfo
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &info); err != nil {
				log.Printf("Error parsing packet info: %v", err)
				continue
			}

			srcIP := make([]byte, 4)
			dstIP := make([]byte, 4)
			binary.BigEndian.PutUint32(srcIP, info.SrcIP)
			binary.BigEndian.PutUint32(dstIP, info.DstIP)

			fmt.Printf("%-15s %-6d %-15s %-6d %-6d\n",
				net.IP(srcIP).String(), info.SrcPort,
				net.IP(dstIP).String(), info.DstPort,
				info.Length)
		}
	}()

	<-sig
	fmt.Println("\nShutting down...")
}

type icmpEvent struct {
	Src uint32
	Dst uint32
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

func main() {
	// 加载编译好的 xdp_accept.o
	spec, err := ebpf.LoadCollectionSpec("./C/xdp_accept.o")
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
	configMap := coll.Maps["config_map"]
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
		// packet := gopacket.NewPacket(pkt, layers.LayerTypeEthernet, gopacket.Default)
		// fmt.Println(packet)

		w.WritePacket(gopacket.CaptureInfo{
			Timestamp:     time.Now(),
			CaptureLength: int(evt.PktLen),
			Length:        int(evt.PktLen),
		}, pkt)
	}
}
