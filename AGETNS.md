# AGETNS.md

This file exists because the user explicitly requested `AGETNS.md`.

Codex's standard project instruction filename is `AGENTS.md`. Keep the canonical, durable guidance in:

- `./AGENTS.md`

Use this file as a compatibility summary for the current milestone.

## Current ICMP SNAT Milestone

The current working config is:

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

Validated result:

- The XDP loader runs from `./run.sh`.
- Ingress interface: `enp0s8`.
- Ingress VPN IP: `192.168.56.103`.
- VPN UDP port: `18080`.
- Egress interface selected by FIB: `enp0s17`.
- Egress IP: `192.168.75.191`.
- Windows Wireshark captured the SNATed ICMP packet.

Capture artifact:

- User referred to it as `./icmpSnat.pcap`.
- Current workspace artifact observed earlier: `./icmpSnat.pcapng`.

## Current Data Path

Implemented:

- Parse outer Ethernet/IP/UDP/VPN.
- Parse inner IPv4 ICMP.
- Remove outer encapsulation.
- Rewrite inner source IP to `vpn.egress_ips[0]`.
- Recalculate IPv4 checksum.
- Run `bpf_fib_lookup()`.
- Send through `bpf_redirect()`.

Not implemented yet:

- DNAT return path.
- Session map.
- ICMP ID translation.
- TCP/UDP NAT.
- Port allocation.
- Reply encapsulation back to the VPN client.

## Verification Counters

Successful ICMP SNAT should increase:

```json
"STAT_VPN_COUNT"
"STAT_VPN_ICMP_ECHO_COUNT"
"STAT_VPN_ICMP_SNAT_COUNT"
```

Successful path should not increase:

```json
"STAT_VPN_FIB_LOOKUP_ERROR_COUNT"
"STAT_VPN_ADJUST_HEAD_ERROR_COUNT"
"STAT_VPN_NEW_ETH_ERROR_COUNT"
"STAT_VPN_NEW_IP_ERROR_COUNT"
```

`tcpdump` on the egress interface may miss XDP-redirected packets because the XDP redirect path can bypass skb/AF_PACKET hooks. External Wireshark capture, XDP tracepoints, or NIC TX counters are better validation signals.

For full project guidance, use `AGENTS.md`.
