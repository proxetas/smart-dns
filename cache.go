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
	case *dns.HTTPS:
		return fmt.Sprintf("%s %d", v.Header().Name, v.Priority)
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
	defer d.mutex.Unlock()
	d.mutex.Lock()

	ttl := record.Header().Ttl
	record_name := record.Header().Name
	if d.name == record_name {
		for _, r := range d.records {
			if RREquals(record, r.record) {
				r.expiration = time.Now().Add(time.Duration(ttl) * time.Second)
				return
			}
		}

		d.records = append(d.records, CachedRecord{
			record:     record,
			expiration: time.Now().Add(time.Duration(ttl) * time.Second),
		})
	}

	innerD, exists := d.cache[record_name]
	if exists {
		innerD.AddRecord(record)
		return
	}

	newCacheNode := NewDnsCacheNode(record_name)
	newCacheNode.records = append(newCacheNode.records, CachedRecord{
		record:     record,
		expiration: time.Now().Add(time.Duration(ttl) * time.Second),
	})

	d.cache[record_name] = newCacheNode
}

func (d *DnsCacheNode) SetOptimizedRecord(record dns.RR) {
	if d.name == record.Header().Name {
		d.mutex.Lock()
		d.optimizedRecord = CachedRecord{record: record, expiration: time.Now().Add(time.Duration(record.Header().Ttl) * time.Second)}
		d.mutex.Unlock()
		return
	}

	d.mutex.Lock()
	innerD, exists := d.cache[record.Header().Name]
	d.mutex.Unlock()
	if exists {
		innerD.SetOptimizedRecord(record)
		return
	}

	newNode := NewDnsCacheNode(record.Header().Name)
	newNode.optimizedRecord = CachedRecord{record: record, expiration: time.Now().Add(time.Duration(record.Header().Ttl) * time.Second)}

	d.mutex.Lock()
	d.cache[record.Header().Name] = newNode
	d.mutex.Unlock()

}

func (d *DnsCacheNode) GetOptimizedRecord(name string) *CachedRecord {
	defer d.mutex.Unlock()
	d.mutex.Lock()

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
	defer d.mutex.Unlock()
	d.mutex.Lock()

	if d.name == name {
		return d
	}

	if inner, exists := d.cache[name]; exists {
		return inner
	}

	d.cache[name] = NewDnsCacheNode(name)
	return d.cache[name]
}

func (d *DnsCacheNode) GetRecords(qtype uint16, qname string) []CachedRecord {
	if d.name == qname {
		expired := []int{}

		defer d.mutex.Unlock()
		d.mutex.Lock()
		results := []CachedRecord{}
		for i, r := range d.records {
			if r.Expired() {
				expired = append(expired, i)
				continue
			}

			if r.record.Header().Rrtype == qtype {
				record, err := dns.NewRR(r.record.String())
				if err == nil {
					record.Header().Ttl = uint32(time.Until(r.expiration).Seconds())
					results = append(results, CachedRecord{record: record, expiration: r.expiration})
				}
			}
		}

		for j := len(expired) - 1; j >= 0; j-- {
			i := expired[j]
			d.records = append(d.records[:i], d.records[i+1:]...)
		}

		return results
	} else if innerD, exists := d.cache[qname]; exists {
		return innerD.GetRecords(qtype, qname)
	}

	return []CachedRecord{}
}

// func (d *DnsCacheNode) AnswerQuestion(question dns.Question) []dns.RR {

// }

func NewDnsCacheNode(name string) *DnsCacheNode {
	return &DnsCacheNode{
		cache:           make(map[string]*DnsCacheNode),
		name:            name,
		records:         []CachedRecord{},
		optimizedRecord: CachedRecord{},
		mutex:           sync.Mutex{},
	}
}
