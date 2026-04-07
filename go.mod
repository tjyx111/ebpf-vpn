module ebpf-vpn

go 1.23.0

toolchain go1.24.7

require (
	github.com/BurntSushi/toml v1.6.0
	github.com/cilium/ebpf v0.19.0
	github.com/fsnotify/fsnotify v1.9.0
	github.com/vishvananda/netlink v1.3.1
)

require (
	github.com/vishvananda/netns v0.0.5 // indirect
	golang.org/x/sys v0.31.0 // indirect
)
