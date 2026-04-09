package main

import (
	"fmt"
	"net"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// Netstack gVisor 网络栈
type Netstack struct {
	stack       *stack.Stack
	endpoint    *VPNLinkEndpoint
	sender      *UDPSender
	localIP     tcpip.Address
	localPort   tcpip.Port
	nicID       tcpip.NICID
}

// NewNetstack 创建新的网络栈
func NewNetstack(cfg *Config) (*Netstack, error) {
	// 创建 UDP 发送器
	sender, err := NewUDPSender(cfg.Target.ServerIP, cfg.Target.ServerPort)
	if err != nil {
		return nil, fmt.Errorf("create UDP sender: %w", err)
	}

	// 创建 VPN Link Endpoint
	mtu := uint32(1500) // 默认 MTU
	endpoint := NewVPNLinkEndpoint(sender, cfg.VPN.SessionID, mtu)

	// 创建网络栈
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocol{ipv4.NewProtocol()},
		TransportProtocols: []stack.TransportProtocol{tcp.NewProtocol(), udp.NewProtocol()},
	})

	// 解析本地 IP
	ip := net.ParseIP(cfg.Client.LocalIP).To4()
	if ip == nil {
		sender.Close()
		return nil, fmt.Errorf("invalid local IP: %s", cfg.Client.LocalIP)
	}

	localAddr := tcpip.Address(ip)

	// 创建 NIC (网络接口)
	nicID := tcpip.NICID(1)
	if err := s.CreateNIC(nicID, endpoint); err != nil {
		sender.Close()
		return nil, fmt.Errorf("create NIC: %w", err)
	}

	// 配置 NIC 地址
	protocolAddr := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: localAddr.WithPrefix(),
	}

	if err := s.AddProtocolAddress(nicID, protocolAddr, stack.AddressProperties{}); err != nil {
		s.Close()
		sender.Close()
		return nil, fmt.Errorf("add protocol address: %w", err)
	}

	// 设置路由表 (所有流量都通过我们的 NIC)
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: tcpip.AddressSubnet{},
			NIC:         nicID,
		},
	})

	ns := &Netstack{
		stack:     s,
		endpoint:  endpoint,
		sender:    sender,
		localIP:   localAddr,
		localPort: cfg.Client.LocalPortStart, // 临时使用
		nicID:     nicID,
	}

	return ns, nil
}

// DialTCP 建立 TCP 连接
func (ns *Netstack) DialTCP(dstIP string, dstPort uint16) (tcpip.Endpoint, *tcpip.Error) {
	// 解析目标地址
	ip := net.ParseIP(dstIP).To4()
	if ip == nil {
		return nil, &tcpip.ErrInvalidEndpointState{}
	}

	fullAddr := tcpip.FullAddress{
		NIC:  ns.nicID,
		Addr: tcpip.Address(ip),
		Port: dstPort,
	}

	// 创建 TCP endpoint
	ep, err := ns.stack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber)
	if err != nil {
		return nil, err
	}

	// 连接
	if err := ep.Connect(fullAddr); err != nil {
		ep.Close()
		return nil, err
	}

	return ep, nil
}

// Close 关闭网络栈
func (ns *Netstack) Close() {
	if ns.stack != nil {
		ns.stack.RemoveNIC(ns.nicID)
		ns.stack.Close()
	}
	if ns.endpoint != nil {
		ns.endpoint.Close()
	}
	if ns.sender != nil {
		ns.sender.Close()
	}
}

// GetStats 获取统计信息
func (ns *Netstack) GetStats() (endpointStats, senderStats string) {
	packetsSent, bytesSent, packetsDropped := ns.endpoint.GetStats()
	endpointStats = fmt.Sprintf("Endpoint: %d packets sent, %d bytes, %d dropped",
		packetsSent, bytesSent, packetsDropped)

	sendCount, errorCount, lastSend := ns.sender.GetStats()
	senderStats = fmt.Sprintf("Sender: %d packets sent, %d errors, last send: %v",
		sendCount, errorCount, lastSend)

	return
}
