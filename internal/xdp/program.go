package xdp

import (
	"fmt"
	"log"

	"ebpf-vpn/internal/bpf"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
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

// ReadStatCounters 读取统计计数器全局变量（实现 stats.StatsReader 接口）
func (p *Program) ReadStatCounters() ([256]uint64, error) {
	var counters [256]uint64

	// 从 BPF 全局变量读取
	// 使用 Get 方法读取全局变量的值
	if err := p.objs.StatCounters.Get(&counters); err != nil {
		return [256]uint64{}, fmt.Errorf("failed to read stat_counters: %w", err)
	}

	return counters, nil
}
