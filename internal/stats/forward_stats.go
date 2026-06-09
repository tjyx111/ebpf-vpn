package stats

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

const (
	STAT_TOTAL_PACKETS = iota
	STAT_UDP_ECHO_COUNT
	STAT_VPN_COUNT
	STAT_VPN_ICMP_ECHO_COUNT
	STAT_VPN_ICMP_SNAT_COUNT
	STAT_VPN_ICMP_DNAT_COUNT
	STAT_VPN_ICMP_DNAT_MISS_COUNT
	STAT_VPN_L4_SNAT_COUNT
	STAT_VPN_L4_DNAT_COUNT
	STAT_VPN_FRAGMENT_PASS_COUNT
	STAT_VPN_MTU_PASS_COUNT
	STAT_VPN_PORT_ALLOC_MISS_COUNT
	STAT_XDP_PASS_COUNT
	STAT_UDP_HEADER_ERROR_COUNT
	STAT_VPN_HEADER_ERROR_COUNT
	STAT_VPN_INNER_IP_ERROR_COUNT
	STAT_VPN_NON_ICMP_COUNT
	STAT_VPN_INNER_ICMP_ERROR_COUNT
	STAT_VPN_NO_EGRESS_IP_COUNT
	STAT_VPN_ADJUST_HEAD_ERROR_COUNT
	STAT_VPN_NEW_ETH_ERROR_COUNT
	STAT_VPN_NEW_IP_ERROR_COUNT
	STAT_VPN_FIB_LOOKUP_ERROR_COUNT
	STAT_VPN_DNAT_FIB_LOOKUP_ERROR_COUNT
	STAT_NON_IPV4_PASS_COUNT
	STAT_IPV4_FRAGMENT_PASS_COUNT
)

type ForwardStats struct {
	STAT_TOTAL_PACKETS                   uint64 `json:"STAT_TOTAL_PACKETS"`
	STAT_UDP_ECHO_COUNT                  uint64 `json:"STAT_UDP_ECHO_COUNT"`
	STAT_VPN_COUNT                       uint64 `json:"STAT_VPN_COUNT"`
	STAT_VPN_ICMP_ECHO_COUNT             uint64 `json:"STAT_VPN_ICMP_ECHO_COUNT"`
	STAT_VPN_ICMP_SNAT_COUNT             uint64 `json:"STAT_VPN_ICMP_SNAT_COUNT"`
	STAT_VPN_ICMP_DNAT_COUNT             uint64 `json:"STAT_VPN_ICMP_DNAT_COUNT"`
	STAT_VPN_ICMP_DNAT_MISS_COUNT        uint64 `json:"STAT_VPN_ICMP_DNAT_MISS_COUNT"`
	STAT_VPN_L4_SNAT_COUNT               uint64 `json:"STAT_VPN_L4_SNAT_COUNT"`
	STAT_VPN_L4_DNAT_COUNT               uint64 `json:"STAT_VPN_L4_DNAT_COUNT"`
	STAT_VPN_FRAGMENT_PASS_COUNT         uint64 `json:"STAT_VPN_FRAGMENT_PASS_COUNT"`
	STAT_VPN_MTU_PASS_COUNT              uint64 `json:"STAT_VPN_MTU_PASS_COUNT"`
	STAT_VPN_PORT_ALLOC_MISS_COUNT       uint64 `json:"STAT_VPN_PORT_ALLOC_MISS_COUNT"`
	STAT_XDP_PASS_COUNT                  uint64 `json:"STAT_XDP_PASS_COUNT"`
	STAT_UDP_HEADER_ERROR_COUNT          uint64 `json:"STAT_UDP_HEADER_ERROR_COUNT"`
	STAT_VPN_HEADER_ERROR_COUNT          uint64 `json:"STAT_VPN_HEADER_ERROR_COUNT"`
	STAT_VPN_INNER_IP_ERROR_COUNT        uint64 `json:"STAT_VPN_INNER_IP_ERROR_COUNT"`
	STAT_VPN_NON_ICMP_COUNT              uint64 `json:"STAT_VPN_NON_ICMP_COUNT"`
	STAT_VPN_INNER_ICMP_ERROR_COUNT      uint64 `json:"STAT_VPN_INNER_ICMP_ERROR_COUNT"`
	STAT_VPN_NO_EGRESS_IP_COUNT          uint64 `json:"STAT_VPN_NO_EGRESS_IP_COUNT"`
	STAT_VPN_ADJUST_HEAD_ERROR_COUNT     uint64 `json:"STAT_VPN_ADJUST_HEAD_ERROR_COUNT"`
	STAT_VPN_NEW_ETH_ERROR_COUNT         uint64 `json:"STAT_VPN_NEW_ETH_ERROR_COUNT"`
	STAT_VPN_NEW_IP_ERROR_COUNT          uint64 `json:"STAT_VPN_NEW_IP_ERROR_COUNT"`
	STAT_VPN_FIB_LOOKUP_ERROR_COUNT      uint64 `json:"STAT_VPN_FIB_LOOKUP_ERROR_COUNT"`
	STAT_VPN_DNAT_FIB_LOOKUP_ERROR_COUNT uint64 `json:"STAT_VPN_DNAT_FIB_LOOKUP_ERROR_COUNT"`
	STAT_NON_IPV4_PASS_COUNT             uint64 `json:"STAT_NON_IPV4_PASS_COUNT"`
	STAT_IPV4_FRAGMENT_PASS_COUNT        uint64 `json:"STAT_IPV4_FRAGMENT_PASS_COUNT"`
}

type StatsReader interface {
	ReadStatCounters() ([256]uint64, error)
}

type Reporter struct {
	reader     StatsReader
	outputFile string
	interval   time.Duration
	stopChan   chan struct{}
}

func NewReporter(reader StatsReader, outputFile string, interval time.Duration) *Reporter {
	return &Reporter{
		reader:     reader,
		outputFile: outputFile,
		interval:   interval,
		stopChan:   make(chan struct{}),
	}
}

func (r *Reporter) Start() {
	ticker := time.NewTicker(r.interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := r.Report(); err != nil {
					fmt.Printf("Failed to report stats: %v\n", err)
				}
			case <-r.stopChan:
				return
			}
		}
	}()
}

func (r *Reporter) Stop() {
	close(r.stopChan)
}

func (r *Reporter) Report() error {
	counters, err := r.reader.ReadStatCounters()
	if err != nil {
		return fmt.Errorf("read stats: %w", err)
	}
	return r.WriteToFile(arrayToForwardStats(counters))
}

func (r *Reporter) WriteToFile(stats ForwardStats) error {
	data, err := json.MarshalIndent(stats, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal stats: %w", err)
	}
	if err := os.WriteFile(r.outputFile, data, 0644); err != nil {
		return fmt.Errorf("write stats file: %w", err)
	}
	return nil
}

func arrayToForwardStats(counters [256]uint64) ForwardStats {
	return ForwardStats{
		STAT_TOTAL_PACKETS:                   counters[STAT_TOTAL_PACKETS],
		STAT_UDP_ECHO_COUNT:                  counters[STAT_UDP_ECHO_COUNT],
		STAT_VPN_COUNT:                       counters[STAT_VPN_COUNT],
		STAT_VPN_ICMP_ECHO_COUNT:             counters[STAT_VPN_ICMP_ECHO_COUNT],
		STAT_VPN_ICMP_SNAT_COUNT:             counters[STAT_VPN_ICMP_SNAT_COUNT],
		STAT_VPN_ICMP_DNAT_COUNT:             counters[STAT_VPN_ICMP_DNAT_COUNT],
		STAT_VPN_ICMP_DNAT_MISS_COUNT:        counters[STAT_VPN_ICMP_DNAT_MISS_COUNT],
		STAT_VPN_L4_SNAT_COUNT:               counters[STAT_VPN_L4_SNAT_COUNT],
		STAT_VPN_L4_DNAT_COUNT:               counters[STAT_VPN_L4_DNAT_COUNT],
		STAT_VPN_FRAGMENT_PASS_COUNT:         counters[STAT_VPN_FRAGMENT_PASS_COUNT],
		STAT_VPN_MTU_PASS_COUNT:              counters[STAT_VPN_MTU_PASS_COUNT],
		STAT_VPN_PORT_ALLOC_MISS_COUNT:       counters[STAT_VPN_PORT_ALLOC_MISS_COUNT],
		STAT_XDP_PASS_COUNT:                  counters[STAT_XDP_PASS_COUNT],
		STAT_UDP_HEADER_ERROR_COUNT:          counters[STAT_UDP_HEADER_ERROR_COUNT],
		STAT_VPN_HEADER_ERROR_COUNT:          counters[STAT_VPN_HEADER_ERROR_COUNT],
		STAT_VPN_INNER_IP_ERROR_COUNT:        counters[STAT_VPN_INNER_IP_ERROR_COUNT],
		STAT_VPN_NON_ICMP_COUNT:              counters[STAT_VPN_NON_ICMP_COUNT],
		STAT_VPN_INNER_ICMP_ERROR_COUNT:      counters[STAT_VPN_INNER_ICMP_ERROR_COUNT],
		STAT_VPN_NO_EGRESS_IP_COUNT:          counters[STAT_VPN_NO_EGRESS_IP_COUNT],
		STAT_VPN_ADJUST_HEAD_ERROR_COUNT:     counters[STAT_VPN_ADJUST_HEAD_ERROR_COUNT],
		STAT_VPN_NEW_ETH_ERROR_COUNT:         counters[STAT_VPN_NEW_ETH_ERROR_COUNT],
		STAT_VPN_NEW_IP_ERROR_COUNT:          counters[STAT_VPN_NEW_IP_ERROR_COUNT],
		STAT_VPN_FIB_LOOKUP_ERROR_COUNT:      counters[STAT_VPN_FIB_LOOKUP_ERROR_COUNT],
		STAT_VPN_DNAT_FIB_LOOKUP_ERROR_COUNT: counters[STAT_VPN_DNAT_FIB_LOOKUP_ERROR_COUNT],
		STAT_NON_IPV4_PASS_COUNT:             counters[STAT_NON_IPV4_PASS_COUNT],
		STAT_IPV4_FRAGMENT_PASS_COUNT:        counters[STAT_IPV4_FRAGMENT_PASS_COUNT],
	}
}
