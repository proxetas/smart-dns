package main

import (
	"sync"
	"time"

	"github.com/go-ping/ping"
)

// Host struct with a map to store IP addresses and their latencies
type Host struct {
	mutex sync.Mutex
	cache map[string]int64
}

// NewHost creates a new Host instance
func NewHost() *Host {
	return &Host{
		cache: make(map[string]int64),
	}
}

// Get retrieves the latency for a given IP. If the IP is not in the cache, it performs a "ping" (simulated)
func (h *Host) Get(ip string) int64 {
	h.mutex.Lock()
	if latency, found := h.cache[ip]; found {
		h.mutex.Unlock()
		return latency
	}
	h.mutex.Unlock()

	pinger, err := ping.NewPinger(ip)

	latency := int64(1000000)
	if err != nil {

		h.mutex.Lock()
		h.cache[ip] = latency
		h.mutex.Unlock()

		return latency
	}

	pinger.Count = 1
	pinger.Timeout = 1 * time.Second
	err = pinger.Run()

	if err != nil {

		h.mutex.Lock()
		h.cache[ip] = latency
		h.mutex.Unlock()

		return latency
	}

	stats := pinger.Statistics()
	latency = stats.AvgRtt.Microseconds()

	h.mutex.Lock()
	h.cache[ip] = latency
	h.mutex.Unlock()

	return latency
}
