# AGENTS.md

## Project Role

This repository is an eBPF/XDP VPN datapath experiment with a Go control plane.

Codex should treat this file as the durable project instruction source. Keep it concise and operational: prefer commands, invariants, verification steps, and current architecture facts over narrative notes.

## Current Milestone

ICMP NAT forwarding precursor is validated.

Known-good runtime config:

```toml
[network]
udp_echo_port = 28080
mtu = 1500

[features]
udp_echo_enabled = true

[vpn]
port = 18080
egress_ips = ["192.168.75.191"]
```

Validated path:

- Ingress interface: `enp0s8`
- Ingress IP: `192.168.56.103`
- VPN UDP port: `18080`
- Egress interface selected by FIB: `enp0s17`
- Egress IP: `192.168.75.191`
- Windows Wireshark captured the SNATed ICMP packet.
- DNAT return packets are re-encapsulated as UDP/VPN replies to the VPN client.
- `dnat-icmp-reply.pcap` captures DNAT packets after re-encapsulation.
- Capture artifact currently present: `./icmpSnat.pcapng`

## Architecture

- `cmd/xdp-loader/main.go`
  - Loads config.
  - Attaches XDP.
  - Hot-reloads config.
  - Starts status reporting.

- `internal/config/loader.go`
  - Parses `config.toml`.
  - Packs `unified_config` for BPF.
  - Writes `unified_config_map`.

- `internal/xdp/program.go`
  - Loads generated BPF objects.
  - Attaches `xdp_gateway` to one or more comma-separated interfaces.
  - Reads `stat_counters`.

- `internal/pcap`
  - Reads DNAT capture ringbuf events.
  - Writes Ethernet pcap files for Wireshark inspection.

- `internal/stats/forward_stats.go`
  - Converts BPF counters to status JSON.

- `bpf/src/main.c`
  - XDP entrypoint.
  - UDP echo path.
  - VPN ICMP SNAT path.
  - ICMP DNAT return encapsulation path.

- `bpf/src/xdp/common/unified_config.h`
  - Shared BPF config layout.
  - VPN header.
  - Counter indexes.

- `cmd/icmp-vpn-client/main.go`
  - Test client for VPN-encapsulated ICMP.

## Implemented

- XDP attach and detach.
- Config load and hot reload.
- UDP echo.
- VPN packet detection.
- ICMP-only source-IP SNAT:
  - Parse outer Ethernet/IP/UDP/VPN.
  - Parse inner IPv4 ICMP.
  - Remove outer encapsulation.
  - Rewrite inner source IP to `vpn.egress_ips[0]`.
  - Recalculate IPv4 checksum.
  - Use `bpf_fib_lookup()`.
  - Send with `bpf_redirect()`.
- ICMP echo-reply DNAT:
  - Match replies by egress IP, remote IP, and ICMP ID.
  - Rewrite inner destination IP back to the original inner source IP.
  - Re-encapsulate as outer IPv4/UDP/VPN.
  - Send back to the original VPN client via the recorded ingress interface.
- DNAT pcap capture:
  - `-dnat-pcap=<path>` writes re-encapsulated DNAT packets to pcap.
  - `./run.sh` writes `dnat-icmp-reply.pcap`.

## Not Implemented Yet

- Session map.
- ICMP ID translation.
- TCP/UDP NAT.
- Port allocation.
- Timeout cleanup.

Do not claim general NAT forwarding is complete until TCP/UDP NAT, port allocation,
and timeout cleanup are implemented.

## Required Commands

After BPF C, BPF map, BPF variable, or shared struct changes:

```bash
go generate ./internal/bpf
```

Before reporting implementation complete:

```bash
go test ./...
make build
```

For datapath changes, also load the XDP program at least once. Compile success is not enough; verifier/load success matters.

## Runtime Checks

Run:

```bash
./run.sh
```

Confirm XDP attach:

```bash
ip link show enp0s8
```

Expected signal:

```text
xdpgeneric
prog/xdp ... name xdp_gateway
```

Check status:

```bash
cat /var/log/ebpf-status.log
```

Successful ICMP SNAT should increase:

```json
"STAT_VPN_COUNT"
"STAT_VPN_ICMP_ECHO_COUNT"
"STAT_VPN_ICMP_SNAT_COUNT"
```

Successful ICMP DNAT return encapsulation should increase:

```json
"STAT_VPN_ICMP_DNAT_COUNT"
```

Successful ICMP SNAT should not increase:

```json
"STAT_VPN_FIB_LOOKUP_ERROR_COUNT"
"STAT_VPN_DNAT_FIB_LOOKUP_ERROR_COUNT"
"STAT_VPN_ADJUST_HEAD_ERROR_COUNT"
"STAT_VPN_NEW_ETH_ERROR_COUNT"
"STAT_VPN_NEW_IP_ERROR_COUNT"
```

`tcpdump` on the egress interface may not see XDP-redirected packets because the path can bypass skb/AF_PACKET hooks. Prefer external capture, XDP tracepoints, or NIC TX counters.

Useful tracepoints:

```bash
sudo sh -c '
echo 1 > /sys/kernel/debug/tracing/events/xdp/xdp_redirect/enable
echo 1 > /sys/kernel/debug/tracing/events/xdp/xdp_redirect_err/enable
cat /sys/kernel/debug/tracing/trace_pipe
'
```

Disable tracepoints:

```bash
sudo sh -c '
echo 0 > /sys/kernel/debug/tracing/events/xdp/xdp_redirect/enable
echo 0 > /sys/kernel/debug/tracing/events/xdp/xdp_redirect_err/enable
'
```

## Future Port Allocation Direction

Observed host ephemeral range:

```text
net.ipv4.ip_local_port_range = 50000 60000
```

Recommended first TCP/UDP NAT pool:

```toml
port_start = 20000
port_end = 49999
reserved_ports = [22, 80, 443, 18080, 28080]
```

Start with globally unique external ports per protocol and egress IP. Add endpoint-dependent reuse later only after the DNAT path is correct.

## Working Rules

- Do not modify `CLAUDE.md`.
- Keep changes scoped to the requested feature.
- Prefer existing helper files under `bpf/src/xdp/utils` when adding C datapath logic.
- Do not leave running XDP programs after tests; detach by stopping the loader cleanly.
- Do not treat `tcpdump` absence on egress as proof of failure for XDP redirect.
