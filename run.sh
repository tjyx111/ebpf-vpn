#!/bin/bash
set -e
make build
./ebpf-vpn -iface=lo -pcap=/tmp/vpn_capture.pcap