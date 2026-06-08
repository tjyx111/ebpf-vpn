#!/bin/bash
set -e
make build
./ebpf-vpn -iface=enp0s17 -config=config.toml -status=/var/log/ebpf-status.log -stats-interval=3s
# ./ebpf-vpn -iface=lo -config=config.toml -status=/var/log/ebpf-status.log -stats-interval=3s
