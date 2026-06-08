#!/bin/bash
set -e
make build
./ebpf-vpn -iface=enp0s8,enp0s17 -config=config.toml -status=/var/log/ebpf-status.log -stats-interval=3s -dnat-pcap=dnat-icmp-reply.pcap
# ./ebpf-vpn -iface=lo -config=config.toml -status=/var/log/ebpf-status.log -stats-interval=3s
