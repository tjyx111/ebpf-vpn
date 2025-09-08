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

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

type PacketInfo struct {
	SrcIP   uint32
	DstIP   uint32
	SrcPort uint16
	DstPort uint16
	Length  uint16
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

func xdpMonitor() {

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
	iface, err := net.InterfaceByName("eth0") // 替换为你的网卡名
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

	events, ok := coll.Maps["events"]
	if !ok {
		log.Fatalf("events map not found")
	}

	reader, err := perf.NewReader(events, os.Getpagesize())
	if err != nil {
		log.Fatalf("failed to create perf reader: %v", err)
	}
	defer reader.Close()

	// sig := make(chan os.Signal, 1)
	// signal.Notify(sig, os.Interrupt)

	fmt.Println("Listening for ICMP events...")
	for {
		// select {
		// // case <-sig:
		// // 	fmt.Println("Exiting...")
		// // 	return
		// default:
		record, err := reader.Read()
		if err != nil {
			log.Fatalf("failed to read from perf buffer: %v", err)
		}
		fmt.Printf("Read %d bytes\n", len(record.RawSample))
		if record.LostSamples != 0 {
			fmt.Printf("Lost %d samples\n", record.LostSamples)
			continue
		}
		var evt icmpEvent
		if len(record.RawSample) >= 8 {
			evt.Src = binary.LittleEndian.Uint32(record.RawSample[0:4])
			evt.Dst = binary.LittleEndian.Uint32(record.RawSample[4:8])
			fmt.Printf("ICMP src: %d.%d.%d.%d dst: %d.%d.%d.%d\n",
				evt.Src>>24, (evt.Src>>16)&0xff, (evt.Src>>8)&0xff, evt.Src&0xff,
				evt.Dst>>24, (evt.Dst>>16)&0xff, (evt.Dst>>8)&0xff, evt.Dst&0xff)
		}
	}
	// }
}
