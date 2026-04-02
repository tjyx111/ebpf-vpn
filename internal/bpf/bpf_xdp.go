package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" bpf ../../bpf/src/main.c -- -I../../bpf/src -I../../bpf/src/xdp/app -I../../bpf/src/xdp/utils -I../../bpf/src/xdp/common
