package config

import (
	"fmt"

	"github.com/cilium/ebpf"
)

const (
	CONFIG_COUNT = 128
)

func Help(configMap *ebpf.Map) string {
	// 读取所有配置项
	if configMap == nil {
		return "configMap is nil"
	}
	msg := ""
	for key := uint32(0); key < CONFIG_COUNT; key++ {
		var value uint32
		err := configMap.Lookup(&key, &value)
		if err == nil {
			msg += fmt.Sprintf("Key: %d, Value: %d\n", key, value)
		}
	}
	return msg
}

func SetUdpEchoPort(configMap *ebpf.Map, port uint32) error {
	if configMap == nil {
		return fmt.Errorf("configMap is nil")
	}
	key := uint32(0) // key_port
	value := port
	return configMap.Update(&key, &value, ebpf.UpdateAny)
}
