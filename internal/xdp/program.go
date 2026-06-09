package xdp

import (
	"fmt"
	"log"
	"strings"

	"ebpf-vpn/internal/bpf"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
)

// Program XDP 程序管理器
type Program struct {
	objs     *bpf.BpfObjects
	links    []link.Link
	ifaceIdx []int
}

// Load 加载 XDP 程序到一个或多个网卡，ifaceNames 使用逗号分隔。
func Load(ifaceNames string) (*Program, error) {
	objs := &bpf.BpfObjects{}
	if err := bpf.LoadBpfObjects(objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "/sys/fs/bpf",
		},
	}); err != nil {
		return nil, fmt.Errorf("failed to load BPF objects: %w", err)
	}

	program := &Program{objs: objs}
	for _, ifaceName := range strings.Split(ifaceNames, ",") {
		ifaceName = strings.TrimSpace(ifaceName)
		if ifaceName == "" {
			continue
		}

		iface, err := netlink.LinkByName(ifaceName)
		if err != nil {
			program.Close()
			return nil, fmt.Errorf("failed to find interface %s: %w", ifaceName, err)
		}

		l, err := link.AttachXDP(link.XDPOptions{
			Program:   objs.XdpGateway,
			Interface: iface.Attrs().Index,
		})
		if err != nil {
			program.Close()
			return nil, fmt.Errorf("failed to attach XDP program to %s: %w", ifaceName, err)
		}

		program.links = append(program.links, l)
		program.ifaceIdx = append(program.ifaceIdx, iface.Attrs().Index)
		log.Printf("XDP program loaded on interface %s (index: %d)", ifaceName, iface.Attrs().Index)
	}

	if len(program.links) == 0 {
		program.Close()
		return nil, fmt.Errorf("no valid interfaces provided")
	}

	return program, nil
}

// Close 卸载 XDP 程序
func (p *Program) Close() error {
	log.Println("Unloading XDP program...")

	for _, l := range p.links {
		if err := l.Close(); err != nil {
			log.Printf("Warning: failed to detach XDP program: %v", err)
		}
	}
	p.links = nil

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

// EgressIPMap 获取排序后的 egress IP 查找 Map。
func (p *Program) EgressIPMap() *ebpf.Map {
	return p.objs.EgressIpMap
}

// DnatCaptureEvents 获取 DNAT 回包抓包 ringbuf。
func (p *Program) DnatCaptureEvents() *ebpf.Map {
	return p.objs.DnatCaptureEvents
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
