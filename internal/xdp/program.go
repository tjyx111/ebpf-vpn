package xdp

import (
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"ebpf-vpn/internal/bpf"
)

// Program XDP 程序管理器
type Program struct {
	objs     *bpf.BpfObjects
	link     link.Link
	ifaceIdx int
}

// Load 加载 XDP 程序到指定网卡
func Load(ifaceName string) (*Program, error) {
	// 查找网卡
	iface, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to find interface %s: %w", ifaceName, err)
	}

	// 加载 eBPF 程序
	objs := &bpf.BpfObjects{}
	if err := bpf.LoadBpfObjects(objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "/sys/fs/bpf",
		},
	}); err != nil {
		return nil, fmt.Errorf("failed to load BPF objects: %w", err)
	}

	// 附加 XDP 程序到网卡
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpGateway,
		Interface: iface.Attrs().Index,
	})
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("failed to attach XDP program: %w", err)
	}

	log.Printf("XDP program loaded on interface %s (index: %d)", ifaceName, iface.Attrs().Index)

	return &Program{
		objs:     objs,
		link:     l,
		ifaceIdx: iface.Attrs().Index,
	}, nil
}

// Close 卸载 XDP 程序
func (p *Program) Close() error {
	log.Println("Unloading XDP program...")

	if p.link != nil {
		if err := p.link.Close(); err != nil {
			log.Printf("Warning: failed to detach XDP program: %v", err)
		}
	}

	if p.objs != nil {
		if err := p.objs.Close(); err != nil {
			return fmt.Errorf("failed to close BPF objects: %w", err)
		}
	}

	return nil
}

// UnifiedConfigMap 获取统一配置 Map
func (p *Program) UnifiedConfigMap() *ebpf.Map {
	return p.objs.UnifiedConfigMap
}

// CaptureRuleMap 获取抓包规则 Map
func (p *Program) CaptureRuleMap() *ebpf.Map {
	return p.objs.CaptureRuleMap
}

// EventsRingbuf 获取事件 Ring Buffer
func (p *Program) EventsRingbuf() *ebpf.Map {
	return p.objs.EventsRingbuf
}

// XsksMap 获取 AF_XDP socket Map
func (p *Program) XsksMap() *ebpf.Map {
	return p.objs.XsksMap
}
