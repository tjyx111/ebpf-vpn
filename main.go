package main

import (
	"ebpf-vpn/gosrc/config"
	"log"
	"net"
	"os"
	"time"

	"github.com/asavie/xdp"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
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

func setRedirctToAfxdpFlag(configMap *ebpf.Map) error {
	key := uint32(2)   // key_redirect_to_afxdp
	value := uint32(1) // 打开 redirect to afxdp
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
	netIfsName := "ens34" // 替换为你的网卡名
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
	iface, err := net.InterfaceByName(netIfsName) // 替换为你的网卡名
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

	// eventsRingbuf, ok := coll.Maps["events_ringbuf"]
	// if !ok {
	// 	log.Fatalf("events_ringbuf map not found")
	// }

	// rd, err := ringbuf.NewReader(eventsRingbuf)
	// if err != nil {
	// 	log.Fatalf("failed to create ringbuf reader: %v", err)
	// }
	// defer rd.Close()

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

	// 打开重定向到 AF_XDP socket 的开关
	err = setRedirctToAfxdpFlag(configMap)
	if err != nil {
		log.Fatalf("Failed to set redirect to afxdp flag: %v", err)
	}

	// 设置过滤规则
	rule := FilterRule{
		SrcIP:    0,
		DstIP:    0, // 不过滤目标IP
		SrcPort:  0, // 过滤源端口
		DstPort:  0, // 不过滤目标端口
		Protocol: 1, // IPPROTO_UDP
	}

	key := uint32(0)
	filterRuleMap := coll.Maps["filter_rule_map"]
	err = filterRuleMap.Update(&key, &rule, ebpf.UpdateAny)
	if err != nil {
		log.Fatalf("Failed to set filter rule: %v", err)
	}

	// 创建 AF_XDP socket
	xdpMapKey := 0
	socket, err := xdp.NewSocket(iface.Index, xdpMapKey, &xdp.DefaultSocketOptions)
	if err != nil {
		log.Fatalf("failed to create AF_XDP socket: %v", err)
	}
	defer socket.Close()
	log.Printf("AF_XDP socket created on interface %s idx %d xdp_map_key %d\n", netIfsName, iface.Index, xdpMapKey)
	// 将 socket 添加到 xsks_map（如果使用AF_XDP重定向）
	xsksMap := coll.Maps["xsks_map"]
	if xsksMap != nil {
		queueID := uint32(0)
		socketFD := uint32(socket.FD())
		err = xsksMap.Update(&queueID, &socketFD, ebpf.UpdateAny)
		if err != nil {
			log.Fatalf("failed to update xsks_map: %v", err)
		}
	}

	// 接收数据包
	go func() {
		freeSlots := socket.NumFreeFillSlots()
		if freeSlots <= 0 {
			panic("no free slots in fill ring")
		}
		descs := socket.GetDescs(freeSlots)
		socket.Fill(descs)
		for {
			log.Printf("Polling for packets...")
			numRx, _, err := socket.Poll(-1)
			if err != nil {
				log.Fatalf("poll error: %v", err)
			}
			log.Printf("Poll returned: numRx=%d", numRx)
			// 4. 接收数据包
			rxDescs := socket.Receive(numRx)

			// 5. 处理数据包
			for _, desc := range rxDescs {
				log.Printf("received packet of length %d", desc.Len)
				pkt := socket.GetFrame(desc) // 获取实际的数据包内容
				// 处理数据包
				w.WritePacket(gopacket.CaptureInfo{
					Timestamp:     time.Now(),
					CaptureLength: len(pkt),
					Length:        len(pkt),
				}, pkt)
			}
			socket.Fill(rxDescs)
		}
	}()
	select {}
}

// func AfXdp(ifName string, collection *ebpf.Collection, rxQueueIndex int) error {
// 	// 1. 获取网络接口，例如 eth0
// 	iface, _ := netlink.LinkByName(ifName)

// 	// 2. 加载编译好的XDP程序并获取其中的 xsks_map
// 	xsksMap := collection.Maps["xsks_map"] // 获取Go程序中的map表示

// 	// 3. 创建XDP socket并绑定到相同的队列索引（index）
// 	xsk, err := xdp.NewSocket(iface.Attrs().Index, rxQueueIndex, nil)
// 	if err != nil {
// 		return err
// 	}

// 	// 4. 将socket的文件描述符放入xsks_map的对应index（queueID）处
// 	//    这样XDP程序中的 bpf_redirect_map 才能找到它
// 	key := uint32(rxQueueIndex)                      // map的key就是index
// 	value := uint32(xsk.FD())                        // map的value是socket的文件描述符
// 	err = xsksMap.Update(key, value, ebpf.UpdateAny) // 将键值对插入map
// 	if err != nil {
// 		return err
// 	}

// 	xsk.Receive() // 启动接收数据包
// 	return nil
// }
