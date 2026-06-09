package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const (
	vpnMagicValue = 0x90
	vpnProtoIPv4  = 1
	vpnHeaderSize = 8
)

type appTun struct {
	ep        *channel.Endpoint
	stack     *stack.Stack
	outgoing  chan []byte
	closeOnce sync.Once
}

type UdpEchoData struct {
	Msg      string
	Time     time.Time
	PkgID    uint32
	WorkerID int
	Seq      int
}

type clientConfig struct {
	vpnAddr       *net.UDPAddr
	localIPBase   netip.Addr
	mtu           int
	sessionIDBase uint32
	mode          string
	remoteAddr    netip.AddrPort
	payload       string
	timeout       time.Duration
	sendInterval  time.Duration
	readResponse  bool
	workers       int
	duration      time.Duration
}

type workerResult struct {
	id       int
	localIP  netip.Addr
	session  uint32
	sent     int
	received int
	errors   int
}

type trafficCounters struct {
	tx       atomic.Uint64
	rx       atomic.Uint64
	errors   atomic.Uint64
	minTTLNS atomic.Int64
	maxTTLNS atomic.Int64
}

func (c *trafficCounters) observeTTL(ttl time.Duration) {
	ns := ttl.Nanoseconds()
	if ns <= 0 {
		return
	}

	for {
		current := c.minTTLNS.Load()
		if current != 0 && current <= ns {
			break
		}
		if c.minTTLNS.CompareAndSwap(current, ns) {
			break
		}
	}
	for {
		current := c.maxTTLNS.Load()
		if current >= ns {
			break
		}
		if c.maxTTLNS.CompareAndSwap(current, ns) {
			break
		}
	}
}

func GenPayload(msg string, workerID, seq int) []byte {
	echoData := UdpEchoData{
		Msg:      msg,
		Time:     time.Now(),
		PkgID:    uint32(time.Now().UnixNano()),
		WorkerID: workerID,
		Seq:      seq,
	}
	jsonData, err := json.Marshal(echoData)
	if err != nil {
		panic(fmt.Sprintf("failed to marshal payload: %v", err))
	}
	return jsonData
}

func reportCounterDeltas(ctx context.Context, counters *trafficCounters, interval time.Duration, done chan<- struct{}) {
	defer close(done)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var lastTx uint64
	var lastRx uint64
	var lastErrors uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tx := counters.tx.Load()
			rx := counters.rx.Load()
			errors := counters.errors.Load()
			minTTL := time.Duration(counters.minTTLNS.Swap(0))
			maxTTL := time.Duration(counters.maxTTLNS.Swap(0))
			log.Printf("counter_delta interval=%s tx=%d rx=%d errors=%d ttl_min=%s ttl_max=%s",
				interval, tx-lastTx, rx-lastRx, errors-lastErrors, minTTL, maxTTL)
			lastTx = tx
			lastRx = rx
			lastErrors = errors
		}
	}
}

func observePayloadTTL(counters *trafficCounters, payload []byte, now time.Time) {
	var echoData UdpEchoData
	if err := json.Unmarshal(payload, &echoData); err != nil || echoData.Time.IsZero() {
		return
	}
	counters.observeTTL(now.Sub(echoData.Time))
}

func main() {
	vpnServer := flag.String("vpn-server", "192.168.56.103:17878", "VPN server UDP address")
	localIP := flag.String("local-ip", "10.192.1.1", "Local IPv4 address inside the app netstack")
	mtu := flag.Int("mtu", 1400, "Virtual MTU")
	sessionID := flag.Uint("session-id", 12345, "VPN session ID")
	mode := flag.String("mode", "tcp", "Traffic mode: tcp or udp")
	remote := flag.String("remote", "8.217.11.128:18080", "Remote TCP/UDP address")
	payload := flag.String("payload", "", "Payload for TCP/UDP test")
	timeout := flag.Duration("timeout", 5*time.Second, "TCP/UDP read timeout")
	sendInterval := flag.Duration("send-interval", 0, "Delay between sends in each worker")
	readResponse := flag.Bool("read-response", true, "Read echo response after each send")
	workers := flag.Int("workers", 1, "Number of parallel workers")
	duration := flag.Duration("duration", 0, "Run duration before stopping continuous workers")
	flag.Parse()

	vpnAddr, err := net.ResolveUDPAddr("udp", *vpnServer)
	if err != nil {
		log.Fatalf("resolve VPN server: %v", err)
	}
	localAddr, err := netip.ParseAddr(*localIP)
	if err != nil {
		log.Fatalf("parse local IP: %v", err)
	}
	remoteAddr, err := netip.ParseAddrPort(*remote)
	if err != nil {
		log.Fatalf("parse remote: %v", err)
	}
	if *workers <= 0 {
		log.Fatalf("workers must be > 0")
	}
	modeValue := strings.ToLower(*mode)
	if *duration <= 0 {
		log.Fatalf("duration must be > 0")
	}

	cfg := clientConfig{
		vpnAddr:       vpnAddr,
		localIPBase:   localAddr,
		mtu:           *mtu,
		sessionIDBase: uint32(*sessionID),
		mode:          modeValue,
		remoteAddr:    remoteAddr,
		payload:       *payload,
		timeout:       *timeout,
		sendInterval:  *sendInterval,
		readResponse:  *readResponse,
		workers:       *workers,
		duration:      *duration,
	}
	if cfg.mode != "tcp" && cfg.mode != "udp" {
		log.Fatalf("unknown mode %q", cfg.mode)
	}

	signalCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	ctx, cancel := context.WithTimeout(signalCtx, cfg.duration)
	defer cancel()

	results := make(chan workerResult, cfg.workers)
	counters := &trafficCounters{}
	reportDone := make(chan struct{})
	go reportCounterDeltas(ctx, counters, time.Second, reportDone)

	var workersWG sync.WaitGroup
	start := time.Now()
	for workerID := 0; workerID < cfg.workers; workerID++ {
		workersWG.Add(1)
		go func(id int) {
			defer workersWG.Done()
			results <- runWorker(ctx, cfg, id, counters)
		}(workerID)
	}

	workersWG.Wait()
	cancel()
	<-reportDone
	close(results)

	totalSent := 0
	totalReceived := 0
	totalErrors := 0
	for result := range results {
		totalSent += result.sent
		totalReceived += result.received
		totalErrors += result.errors
		log.Printf("worker=%d local=%s session=%d sent=%d received=%d errors=%d",
			result.id, result.localIP, result.session, result.sent, result.received, result.errors)
	}
	elapsed := time.Since(start)
	log.Printf("summary workers=%d mode=%s remote=%s sent=%d received=%d errors=%d counter_tx=%d counter_rx=%d counter_errors=%d elapsed=%s duration=%s send_interval=%s read_response=%t",
		cfg.workers, cfg.mode, cfg.remoteAddr, totalSent, totalReceived, totalErrors,
		counters.tx.Load(), counters.rx.Load(), counters.errors.Load(), elapsed, cfg.duration, cfg.sendInterval, cfg.readResponse)
}

func frameTCPPayload(payload []byte) []byte {
	if len(payload) == 0 || payload[len(payload)-1] == '\n' {
		return payload
	}
	framed := make([]byte, 0, len(payload)+1)
	framed = append(framed, payload...)
	framed = append(framed, '\n')
	return framed
}

func runWorker(ctx context.Context, cfg clientConfig, workerID int, counters *trafficCounters) workerResult {
	localIP, err := addIPv4(cfg.localIPBase, workerID)
	result := workerResult{
		id:      workerID,
		localIP: localIP,
		session: cfg.sessionIDBase + uint32(workerID),
	}
	if err != nil {
		log.Printf("worker=%d local IP allocation failed: %v", workerID, err)
		result.errors++
		return result
	}

	tun, err := newAppTun(localIP, cfg.mtu)
	if err != nil {
		log.Printf("worker=%d create app netstack: %v", workerID, err)
		result.errors++
		return result
	}
	defer tun.Close()

	conn, err := net.DialUDP("udp", nil, cfg.vpnAddr)
	if err != nil {
		log.Printf("worker=%d connect VPN server: %v", workerID, err)
		result.errors++
		return result
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		tunToVPN(stop, tun.outgoing, conn, result.session)
	}()
	go func() {
		defer wg.Done()
		vpnToTun(stop, conn, tun)
	}()
	defer func() {
		close(stop)
		_ = conn.Close()
		tun.Close()
		wg.Wait()
	}()

	log.Printf("worker=%d app netstack VPN client: local=%s mtu=%d session=%d server=%s mode=%s remote=%s",
		workerID, localIP, cfg.mtu, result.session, conn.RemoteAddr(), cfg.mode, cfg.remoteAddr)

	switch cfg.mode {
	case "tcp":
		runTCPRequests(ctx, tun.stack, cfg, workerID, &result, counters)
	case "udp":
		runUDPRequests(ctx, tun.stack, cfg, workerID, &result, counters)
	}
	return result
}

func runTCPRequests(ctx context.Context, s *stack.Stack, cfg clientConfig, workerID int, result *workerResult, counters *trafficCounters) {
	dialCtx := ctx
	if cfg.timeout > 0 {
		var cancel context.CancelFunc
		dialCtx, cancel = context.WithTimeout(ctx, cfg.timeout)
		defer cancel()
	}

	conn, err := gonet.DialContextTCP(dialCtx, s, fullAddress(cfg.remoteAddr), ipv4.ProtocolNumber)
	if err != nil {
		result.errors++
		counters.errors.Add(1)
		log.Printf("worker=%d tcp connect failed: %v", workerID, err)
		return
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	for seq := 0; ; seq++ {
		if err := ctx.Err(); err != nil {
			return
		}
		if cfg.timeout > 0 {
			_ = conn.SetDeadline(time.Now().Add(cfg.timeout))
		}

		payload := frameTCPPayload(GenPayload(cfg.payload, workerID, seq))
		if _, err := conn.Write(payload); err != nil {
			result.errors++
			counters.errors.Add(1)
			log.Printf("worker=%d seq=%d tcp write failed: %v", workerID, seq, err)
			return
		}
		result.sent++
		counters.tx.Add(1)

		if cfg.readResponse {
			response, err := reader.ReadBytes('\n')
			if err != nil {
				result.errors++
				counters.errors.Add(1)
				log.Printf("worker=%d seq=%d tcp read failed: %v", workerID, seq, err)
				return
			}
			result.received++
			counters.rx.Add(1)
			observePayloadTTL(counters, response, time.Now())
			if seq == 0 {
				log.Printf("worker=%d tcp response %d bytes:\n%s", workerID, len(response), printable(response))
			}
		}

		if !waitSendInterval(ctx, cfg.sendInterval) {
			return
		}
	}
}

func runUDPRequests(ctx context.Context, s *stack.Stack, cfg clientConfig, workerID int, result *workerResult, counters *trafficCounters) {
	rfa := fullAddress(cfg.remoteAddr)
	conn, err := gonet.DialUDP(s, nil, &rfa, ipv4.ProtocolNumber)
	if err != nil {
		result.errors++
		log.Printf("worker=%d udp connect failed: %v", workerID, err)
		return
	}

	var txCount atomic.Uint64
	var rxCount atomic.Uint64
	var errorCount atomic.Uint64
	recvDone := make(chan struct{})
	if cfg.readResponse {
		go receiveUDPResponses(ctx, conn, cfg, workerID, &rxCount, &errorCount, counters, recvDone)
	} else {
		close(recvDone)
	}
	defer func() {
		_ = conn.Close()
		<-recvDone
		result.sent += int(txCount.Load())
		result.received += int(rxCount.Load())
		result.errors += int(errorCount.Load())
	}()

	for seq := 0; ; seq++ {
		if err := ctx.Err(); err != nil {
			return
		}
		if cfg.timeout > 0 {
			_ = conn.SetWriteDeadline(time.Now().Add(cfg.timeout))
		}

		payload := GenPayload(cfg.payload, workerID, seq)
		if _, err := conn.Write(payload); err != nil {
			if ctx.Err() != nil || isClosedErr(err) {
				return
			}
			errorCount.Add(1)
			counters.errors.Add(1)
			log.Printf("worker=%d seq=%d udp write failed: %v", workerID, seq, err)
			continue
		}
		txCount.Add(1)
		counters.tx.Add(1)

		if !waitSendInterval(ctx, cfg.sendInterval) {
			return
		}
	}
}

func receiveUDPResponses(ctx context.Context, conn *gonet.UDPConn, cfg clientConfig, workerID int, rxCount, errorCount *atomic.Uint64, counters *trafficCounters, done chan<- struct{}) {
	defer close(done)

	buf := make([]byte, 4096)
	for {
		if err := ctx.Err(); err != nil {
			return
		}
		if cfg.timeout > 0 {
			_ = conn.SetReadDeadline(time.Now().Add(cfg.timeout))
		}

		n, err := conn.Read(buf)
		if err != nil {
			if ctx.Err() != nil || isClosedErr(err) {
				return
			}
			if isTimeoutErr(err) {
				continue
			}
			errorCount.Add(1)
			counters.errors.Add(1)
			log.Printf("worker=%d udp read failed: %v", workerID, err)
			continue
		}

		rx := rxCount.Add(1)
		counters.rx.Add(1)
		observePayloadTTL(counters, buf[:n], time.Now())
		if rx == 1 {
			log.Printf("worker=%d udp response %d bytes:\n%s", workerID, n, printable(buf[:n]))
		}
	}
}

func waitSendInterval(ctx context.Context, interval time.Duration) bool {
	if interval <= 0 {
		return true
	}
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func addIPv4(base netip.Addr, offset int) (netip.Addr, error) {
	if !base.Is4() {
		return netip.Addr{}, fmt.Errorf("%s is not an IPv4 address", base)
	}
	if offset < 0 {
		return netip.Addr{}, fmt.Errorf("negative offset %d", offset)
	}
	octets := base.As4()
	value := uint32(octets[0])<<24 | uint32(octets[1])<<16 | uint32(octets[2])<<8 | uint32(octets[3])
	next := value + uint32(offset)
	if next < value {
		return netip.Addr{}, fmt.Errorf("IPv4 address overflow: base=%s offset=%d", base, offset)
	}
	return netip.AddrFrom4([4]byte{
		byte(next >> 24),
		byte(next >> 16),
		byte(next >> 8),
		byte(next),
	}), nil
}

func newAppTun(localAddr netip.Addr, mtu int) (*appTun, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4},
		HandleLocal:        true,
	})
	sackEnabledOpt := tcpip.TCPSACKEnabled(true)
	if tcpipErr := s.SetTransportProtocolOption(tcp.ProtocolNumber, &sackEnabledOpt); tcpipErr != nil {
		return nil, fmt.Errorf("enable TCP SACK: %s", tcpipErr)
	}

	ep := channel.New(1024, uint32(mtu), "")
	tun := &appTun{
		ep:       ep,
		stack:    s,
		outgoing: make(chan []byte, 1024),
	}
	ep.AddNotify(tun)

	if tcpipErr := s.CreateNIC(1, ep); tcpipErr != nil {
		return nil, fmt.Errorf("CreateNIC: %s", tcpipErr)
	}
	protoAddr := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFromSlice(localAddr.AsSlice()).WithPrefix(),
	}
	if tcpipErr := s.AddProtocolAddress(1, protoAddr, stack.AddressProperties{}); tcpipErr != nil {
		return nil, fmt.Errorf("AddProtocolAddress(%s): %s", localAddr, tcpipErr)
	}
	s.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})

	return tun, nil
}

func (t *appTun) WriteNotify() {
	for {
		pkt := t.ep.Read()
		if pkt.IsNil() {
			return
		}
		view := pkt.ToView()
		pkt.DecRef()

		packet := make([]byte, view.Size())
		if _, err := view.Read(packet); err != nil && err != io.EOF {
			continue
		}
		select {
		case t.outgoing <- packet:
		default:
			log.Printf("drop outgoing packet: channel full")
		}
	}
}

func (t *appTun) InjectIPv4(packet []byte) {
	pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(packet),
	})
	t.ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
}

func (t *appTun) Close() {
	t.closeOnce.Do(func() {
		t.stack.RemoveNIC(1)
		t.ep.Close()
	})
}

func tunToVPN(stop <-chan struct{}, outgoing <-chan []byte, conn *net.UDPConn, sessionID uint32) {
	for {
		select {
		case <-stop:
			return
		case packet := <-outgoing:
			if len(packet) == 0 || packet[0]>>4 != 4 {
				continue
			}
			if _, err := conn.Write(encapsulateVPN(packet, sessionID)); err != nil {
				if isClosedErr(err) {
					return
				}
				log.Printf("write VPN UDP: %v", err)
			}
		}
	}
}

func vpnToTun(stop <-chan struct{}, conn *net.UDPConn, tun *appTun) {
	buf := make([]byte, 65535)
	for {
		select {
		case <-stop:
			return
		default:
		}

		n, err := conn.Read(buf)
		if err != nil {
			if isClosedErr(err) {
				return
			}
			log.Printf("read VPN UDP: %v", err)
			continue
		}
		inner, ok := decapsulateVPN(buf[:n])
		if !ok {
			continue
		}
		tun.InjectIPv4(inner)
	}
}

func runTCP(ctx context.Context, s *stack.Stack, remote netip.AddrPort, payload []byte, timeout time.Duration) error {
	dialCtx := ctx
	if timeout > 0 {
		var cancel context.CancelFunc
		dialCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	conn, err := gonet.DialContextTCP(dialCtx, s, fullAddress(remote), ipv4.ProtocolNumber)
	if err != nil {
		return err
	}
	defer conn.Close()

	if timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}
	if len(payload) > 0 {
		if _, err := conn.Write(payload); err != nil {
			return err
		}
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	log.Printf("tcp response %d bytes:\n%s", n, printable(buf[:n]))
	return nil
}

func runUDP(s *stack.Stack, remote netip.AddrPort, payload []byte, timeout time.Duration) error {
	rfa := fullAddress(remote)
	conn, err := gonet.DialUDP(s, nil, &rfa, ipv4.ProtocolNumber)
	if err != nil {
		return err
	}
	defer conn.Close()

	if timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}
	if _, err := conn.Write(payload); err != nil {
		return err
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	log.Printf("udp response %d bytes:\n%s", n, printable(buf[:n]))
	return nil
}

func fullAddress(addr netip.AddrPort) tcpip.FullAddress {
	return tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(addr.Addr().AsSlice()),
		Port: addr.Port(),
	}
}

func encapsulateVPN(ipPacket []byte, sessionID uint32) []byte {
	packet := make([]byte, vpnHeaderSize+len(ipPacket))
	packet[0] = vpnMagicValue
	packet[1] = vpnProtoIPv4
	binary.BigEndian.PutUint16(packet[2:4], 0)
	binary.BigEndian.PutUint32(packet[4:8], sessionID)
	copy(packet[vpnHeaderSize:], ipPacket)
	return packet
}

func decapsulateVPN(packet []byte) ([]byte, bool) {
	if len(packet) <= vpnHeaderSize {
		return nil, false
	}
	if packet[0]&0xf0 != vpnMagicValue || packet[1] != vpnProtoIPv4 {
		return nil, false
	}
	inner := packet[vpnHeaderSize:]
	if len(inner) == 0 || inner[0]>>4 != 4 {
		return nil, false
	}
	return append([]byte(nil), inner...), true
}

func printable(data []byte) []byte {
	if bytes.IndexFunc(data, func(r rune) bool {
		return r < 0x09 || (r > 0x0d && r < 0x20)
	}) >= 0 {
		return []byte(fmt.Sprintf("% x", data))
	}
	return data
}

func isClosedErr(err error) bool {
	return strings.Contains(err.Error(), "use of closed network connection")
}

func isTimeoutErr(err error) bool {
	netErr, ok := err.(net.Error)
	return ok && netErr.Timeout()
}
