package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type OptimizedA struct {
	IP         string
	Latency    int64
	Name       string
	expiration time.Time
}

func (o *OptimizedA) Expired() bool {
	return time.Now().After(o.expiration)
}

func (o *OptimizedA) IsEmpty() bool {
	return o.IP == ""
}

func (o *OptimizedA) GetRR() (dns.RR, error) {
	result, err := dns.NewRR(fmt.Sprintf("%s A %s", o.Name, o.IP))
	if err == nil {
		result.Header().Ttl = uint32(time.Until(o.expiration).Seconds())
	}

	return result, err
}

type OptimizedRecords struct {
	mutex sync.Mutex
	cache map[string]*OptimizedA
}

func NewOptimizedRecords() *OptimizedRecords {
	return &OptimizedRecords{
		cache: make(map[string]*OptimizedA),
	}
}

func (o *OptimizedRecords) Get(query string) *OptimizedA {
	defer o.mutex.Unlock()
	o.mutex.Lock()
	if record, found := o.cache[query]; found {
		if !record.Expired() {
			return record
		}
	}

	return &OptimizedA{}
}

func (o *OptimizedRecords) Set(query string, record *OptimizedA) {
	defer o.mutex.Unlock()
	o.mutex.Lock()
	o.cache[query] = record
}
