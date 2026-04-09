package main

import (
	"fmt"
	"net"
	"sync"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// VPNLinkEndpoint 自定义 LinkEndpoint
// 拦截 gVisor netstack 发出的数据包，封装后通过 UDP 发送
type VPNLinkEndpoint struct {
	stack.LinkEndpoint

	mu        sync.Mutex
	sender    *UDPSender
	sessionID uint32
	closed    bool

	// 统计
	packetsSent     uint64
	bytesSent       uint64
	packetsDropped  uint64
}

// NewVPNLinkEndpoint 创建 VPN LinkEndpoint
func NewVPNLinkEndpoint(sender *UDPSender, sessionID uint32, mtu uint32) *VPNLinkEndpoint {
	// 创建最小化的底层 endpoint
	minimalEP := stack.NewLinkEndpoint(stack.LinkEndpointConfig{
		Mtu: mtu,
	})

	ep := &VPNLinkEndpoint{
		LinkEndpoint: minimalEP,
		sender:       sender,
		sessionID:    sessionID,
	}

	return ep
}

// WritePacket 拦截数据包发送
// gVisor netstack 在发送数据时会调用此方法
func (ep *VPNLinkEndpoint) WritePacket(r stack.RouteInfo, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) *tcpip.Error {
	ep.mu.Lock()
	defer ep.mu.Lock()

	if ep.closed {
		return &tcpip.ErrClosedForSend{}
	}

	// 提取完整的网络层 (IP) 数据包
	ipPacket := pkt.ToView().AsSlice()
	if len(ipPacket) == 0 {
		ep.packetsDropped++
		return &tcpip.ErrInvalidEndpointState{}
	}

	// 验证是 IPv4
	if protocol != header.IPv4ProtocolNumber {
		ep.packetsDropped++
		return &tcpip.ErrNotSupported{}
	}

	// 通过 UDP 发送 VPN 封装的包
	if err := ep.sender.SendIPPacket(ipPacket, ep.sessionID); err != nil {
		ep.packetsDropped++
		return tcpip.ErrWouldBlock // 或者其他适当的错误
	}

	// 更新统计
	ep.packetsSent++
	ep.bytesSent += uint64(len(ipPacket))

	return nil
}

// WritePackets 批量发送数据包
func (ep *VPNLinkEndpoint) WritePackets(list stack.PacketBufferList) (int, *tcpip.Error) {
	n := 0
	for _, pkt := range list.AsSlice() {
		if err := ep.WritePacket(stack.RouteInfo{}, header.IPv4ProtocolNumber, pkt); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// Attach 被附加到栈时调用
func (ep *VPNLinkEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	// 不需要处理接收的包（单向发送）
}

// IsAttached 检查是否已附加
func (ep *VPNLinkEndpoint) IsAttached() bool {
	return false
}

// Capabilities 返回端点能力
func (ep *VPNLinkEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityNone
}

// MaxHeaderLength 返回最大头部长度
func (ep *VPNLinkEndpoint) MaxHeaderLength() uint16 {
	return 0
}

// LinkAddress 返回 MAC 地址
func (ep *VPNLinkEndpoint) LinkAddress() tcpip.LinkAddress {
	return "" // 无 MAC 地址
}

// MTU 返回 MTU
func (ep *VPNLinkEndpoint) MTU() uint32 {
	return ep.LinkEndpoint.MTU()
}

// SetLinkAddress 设置 MAC 地址 (空实现)
func (ep *VPNLinkEndpoint) SetLinkAddress(addr tcpip.LinkAddress) {
	// 不需要 MAC 地址
}

// Wait 等待 (空实现)
func (ep *VPNLinkEndpoint) Wait() {
	// 不需要等待
}

// ARPHardwareType 返回 ARP 硬件类型
func (ep *VPNLinkEndpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareTypeLoopback
}

// AddHeader 添加头部 (空实现)
func (ep *VPNLinkEndpoint) AddHeader(pkt *stack.PacketBuffer) {
	// 不需要添加链路层头部
}

// ParseHeader 解析头部 (空实现)
func (ep *VPNLinkEndpoint) ParseHeader(pkt *stack.PacketBuffer) bool {
	return true
}

// Close 关闭端点
func (ep *VPNLinkEndpoint) Close() {
	ep.mu.Lock()
	defer ep.mu.Unlock()

	ep.closed = true
	if ep.sender != nil {
		ep.sender.Close()
	}
}

// GetStats 获取统计信息
func (ep *VPNLinkEndpoint) GetStats() (packetsSent, bytesSent, packetsDropped uint64) {
	ep.mu.Lock()
	defer ep.mu.Unlock()

	return ep.packetsSent, ep.bytesSent, ep.packetsDropped
}
