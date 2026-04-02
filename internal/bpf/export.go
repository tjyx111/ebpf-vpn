package bpf

import "github.com/cilium/ebpf"

// BpfObjects contains all objects after they have been loaded into the kernel.
// This is an exported wrapper around the internal bpfObjects type.
type BpfObjects = bpfObjects

// LoadBpfObjects loads bpf and converts it into a struct.
// This is an exported wrapper around the internal loadBpfObjects function.
func LoadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	return loadBpfObjects(obj, opts)
}

// BpfMaps contains all maps after they have been loaded into the kernel.
type BpfMaps = bpfMaps

// BpfPrograms contains all programs after they have been loaded into the kernel.
type BpfPrograms = bpfPrograms
