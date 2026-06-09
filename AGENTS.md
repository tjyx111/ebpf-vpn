# AGENTS.md

## Project Role

This repository is an eBPF/XDP VPN datapath experiment with a Go control plane.

Codex should treat this file as the durable project instruction source. Keep it concise and operational: prefer commands, invariants, verification steps, and current architecture facts over narrative notes.

## Current Milestone

ICMP NAT forwarding precursor is validated.

VPN TUN client continuous traffic generator is implemented.

Current local runtime config:

```toml
[network]
udp_echo_port = 18080
mtu = 1500

[features]
udp_echo_enabled = true
dnat_capture_enabled = true

[vpn]
port = 17878
egress_interfaces = ["enp0s17"]
```

Previously validated ICMP path:

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
  - Experimental TCP/UDP L4 SNAT/DNAT path with fixed NAT port pool.

- `bpf/src/xdp/common/unified_config.h`
  - Shared BPF config layout.
  - VPN header.
  - Counter indexes.

- `cmd/icmp-vpn-client/main.go`
  - Removed legacy ICMP-only test client.

- `cmd/vpn-tun-client/main.go`
  - gVisor netstack client for TCP/UDP tests over VPN UDP encapsulation.
  - Allocates one local app-netstack IP and VPN session per worker.
  - Runs continuously until `-duration` expires or the process receives a stop signal.
  - Sends at `-send-interval` per worker.
  - Uses shared atomic `trafficCounters` for Tx/Rx/error totals.
  - Logs 1-second Tx/Rx/error deltas plus min/max TTL derived from echoed payload timestamps.

- `vpn-cli.go`
  - Standalone ICMP VPN packet helper.
  - Not built by `make build`.

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
- Experimental TCP/UDP L4 NAT:
  - Uses `l4_snat_map` and `l4_dnat_map`.
  - Allocates external ports from BPF constants `NAT_PORT_START=20000` through `NAT_PORT_END=50000`.
  - Tracks `STAT_VPN_L4_SNAT_COUNT`, `STAT_VPN_L4_DNAT_COUNT`, `STAT_VPN_PORT_ALLOC_MISS_COUNT`, `STAT_VPN_FRAGMENT_PASS_COUNT`, and `STAT_VPN_MTU_PASS_COUNT`.
  - This is not yet a complete general NAT milestone.
- VPN TUN client:
  - `cmd/vpn-tun-client` supports `-mode=tcp|udp`.
  - `-duration=<dur>` is required and controls process lifetime.
  - `-workers=<n>` starts parallel app-netstack workers.
  - `-send-interval=<dur>` controls per-worker send pacing; `0` sends as fast as possible.
  - `-read-response` enables response reads and TTL measurement.
  - Runtime stats log every second as `counter_delta interval=1s tx=<n> rx=<n> errors=<n> ttl_min=<dur> ttl_max=<dur>`.
  - `make build` builds the loader and root `./vpn-tun-client` binary.

## Not Implemented Yet

- Session map.
- ICMP ID translation.
- TCP/UDP NAT validation.
- Configurable port allocation policy.
- Timeout cleanup.

Do not claim general NAT forwarding is complete until TCP/UDP NAT is validated,
configurable port allocation policy is implemented, and timeout cleanup exists.

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

For the VPN TUN client submodule, also run:

```bash
cd cmd/vpn-tun-client && go test ./...
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

Run the VPN TUN client:

```bash
./vpn-tun-client -mode=udp -duration=30s -workers=4 -send-interval=10ms
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
