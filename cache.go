package main

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

func getRRValue(rr dns.RR) string {
	switch v := rr.(type) {
	case *dns.A:
		return v.A.String()
	case *dns.AAAA:
		return v.AAAA.String()
	case *dns.CNAME:
		return v.Target
	case *dns.TXT:
		return strings.Join(v.Txt, ",")
	case *dns.MX:
		return fmt.Sprintf("%s %d", v.Mx, v.Preference)
	case *dns.NS:
		return v.Ns
	default:
		return rr.Header().String()
	}
}

func RREquals(a dns.RR, b dns.RR) bool {
	if a.Header().Rrtype != b.Header().Rrtype {
		return false
	}

	return getRRValue(a) == getRRValue(b)
}

type CachedRecord struct {
	record     dns.RR
	expiration time.Time
}

func (c *CachedRecord) Expired() bool {
	return time.Now().After(c.expiration)
}

type DnsCacheNode struct {
	mutex           sync.Mutex
	cache           map[string]*DnsCacheNode
	name            string
	records         []CachedRecord
	optimizedRecord CachedRecord
}

func (d *DnsCacheNode) AddRecord(record dns.RR) {
	if record.Header().Rrtype == dns.TypeOPT {
		return
	}

	record_name := record.Header().Name
	if d.name == record_name {
		ttl := record.Header().Ttl
		for _, r := range d.records {
			if RREquals(record, r.record) {
				r.expiration = time.Now().Add(time.Duration(ttl) * time.Second)
				return
			}
		}

		d.mutex.Lock()
		d.records = append(d.records, CachedRecord{
			record:     record,
			expiration: time.Now().Add(time.Duration(ttl) * time.Second),
		})
		d.mutex.Unlock()
	} else if innerD, exists := d.cache[record_name]; exists {
		innerD.AddRecord(record)
	} else {
		d.mutex.Lock()
		d.cache[record_name] = NewDnsCacheNode(record_name)
		d.mutex.Unlock()
		d.cache[record_name].AddRecord(record)
	}
}

func (d *DnsCacheNode) SetOptimizedRecord(record dns.RR) {
	if d.name == record.Header().Name {
		d.mutex.Lock()
		d.optimizedRecord = CachedRecord{record: record, expiration: time.Now().Add(time.Duration(record.Header().Ttl) * time.Second)}
		d.mutex.Unlock()
	} else if innerD, exists := d.cache[record.Header().Name]; exists {
		innerD.SetOptimizedRecord(record)
	} else {
		d.mutex.Lock()
		d.cache[record.Header().Name] = NewDnsCacheNode(record.Header().Name)
		d.mutex.Unlock()
		d.cache[record.Header().Name].SetOptimizedRecord(record)
	}
}

func (d *DnsCacheNode) GetOptimizedRecord(name string) *CachedRecord {
	if d.name == name {
		if !d.optimizedRecord.Expired() {
			return &d.optimizedRecord
		}
	}

	if innerD, exists := d.cache[name]; exists {
		return innerD.GetOptimizedRecord(name)
	}

	return nil
}

func (d *DnsCacheNode) GetCacheNode(name string) *DnsCacheNode {
	if d.name == name {
		return d
	}

	if inner, exists := d.cache[name]; exists {
		return inner
	}

	defer d.mutex.Unlock()
	d.mutex.Lock()

	d.cache[name] = NewDnsCacheNode(name)
	return d.cache[name]
}

func (d *DnsCacheNode) GetRecords(qtype uint16, qname string) []CachedRecord {
	if d.name == qname {
		if qtype == dns.TypeA && d.optimizedRecord != (CachedRecord{}) && !time.Now().After(d.optimizedRecord.expiration) {
			return []CachedRecord{d.optimizedRecord}
		}
		expired := []int{}

		d.mutex.Lock()
		results := []CachedRecord{}
		for i, r := range d.records {
			if r.Expired() {
				expired = append(expired, i)
				continue
			}

			if r.record.Header().Rrtype == qtype {
				record, err := dns.NewRR(r.record.String())
				if err != nil {
					record.Header().Ttl = uint32(time.Until(r.expiration).Seconds())
					results = append(results, CachedRecord{record: record, expiration: r.expiration})
				}
			}
		}

		for j := len(expired) - 1; j >= 0; j-- {
			i := expired[j]
			d.records = append(d.records[:i], d.records[i+1:]...)
		}

		d.mutex.Unlock()
		return results
	} else if innerD, exists := d.cache[qname]; exists {
		return innerD.GetRecords(qtype, qname)
	}

	return []CachedRecord{}
}

func NewDnsCacheNode(name string) *DnsCacheNode {
	return &DnsCacheNode{
		cache:           make(map[string]*DnsCacheNode),
		name:            name,
		records:         []CachedRecord{},
		optimizedRecord: CachedRecord{},
	}
}
