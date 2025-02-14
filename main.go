package main

import (
	"fmt"
	"log"
	"net"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type ResolveTask struct {
	writer  dns.ResponseWriter
	request *dns.Msg
	config  *Config
}

func write_response(writer dns.ResponseWriter, req *dns.Msg, answers []dns.RR, additional []dns.RR, authorative []dns.RR) {
	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.Authoritative = false
	msg.RecursionAvailable = true
	msg.Answer = answers
	msg.Extra = additional
	msg.Ns = authorative
	writer.WriteMsg(msg)
}

// TODO: add upstream strategies: parallel, sequential, round-robin
func dns_resolver(nameservers []string, req *dns.Msg) *chan *dns.Msg {
	responses := make(chan *dns.Msg)
	var subwg sync.WaitGroup
	subwg.Add(len(nameservers) + 1)
	for _, nameserver := range nameservers {
		go func(resp chan *dns.Msg, req *dns.Msg, nameserver string, group *sync.WaitGroup) {
			defer group.Done()
			client := new(dns.Client)
			if !strings.Contains(nameserver, ":") {
				nameserver += ":53"
			}
			result, _, err := client.Exchange(req, nameserver)
			if err != nil {
				resp <- nil
			} else {
				resp <- result
			}
		}(responses, req, nameserver, &subwg)
	}

	return &responses
}

type RecordWithLatency struct {
	record  *dns.A
	latency int64
}

func sort_by_latency(records []*dns.A, hosts *Host) []*dns.A {
	var wg sync.WaitGroup
	wg.Add(len(records) + 1)
	result_chan := make(chan *RecordWithLatency)
	results := []*RecordWithLatency{}

	for _, record := range records {
		go func(record *dns.A, result chan *RecordWithLatency, wg *sync.WaitGroup) {
			defer wg.Done()
			result <- &RecordWithLatency{latency: hosts.Get(record.A.String()), record: record}
		}(record, result_chan, &wg)
	}

	for range records {
		results = append(results, <-result_chan)
	}

	sort.Slice(results, func(i int, j int) bool {
		return results[i].latency < results[j].latency
	})

	sorted := []*dns.A{}
	for _, r := range results {
		sorted = append(sorted, r.record)
	}

	return sorted
}

func try_send_optimized(req *dns.Msg, resp dns.ResponseWriter, cache *DnsCacheNode, remoteIP string) (bool, *CachedRecord) {
	if len(req.Question) == 1 && req.Question[0].Qtype == dns.TypeA {
		cnames := cache.GetRecords(dns.TypeCNAME, req.Question[0].Name)

		if len(cnames) > 0 {
			answers := []dns.RR{cnames[0].record}
			if cname, ok := cnames[0].record.(*dns.CNAME); ok {
				cname_cache := cache.GetCacheNode(cname.Target)
				optimized_record := cname_cache.GetOptimizedRecord(cname.Target)
				if optimized_record != nil {
					answers = append(answers, optimized_record.record)
					write_response(resp, req, answers, nil, nil)
					if optimizedRecordA, ok := optimized_record.record.(*dns.A); ok {
						log_action(req, remoteIP, "optimized", optimizedRecordA.A.String())
					}

					return true, optimized_record
				}
			}

			return false, nil
		}

		optimized_record := cache.GetOptimizedRecord(req.Question[0].Name)
		if optimized_record != nil {
			record := optimized_record.record
			record.Header().Ttl = uint32(time.Until(optimized_record.expiration).Seconds())
			answers := []dns.RR{optimized_record.record}
			write_response(resp, req, answers, nil, nil)
			if optimizedRecordA, ok := optimized_record.record.(*dns.A); ok {
				log_action(req, remoteIP, "optimized", optimizedRecordA.A.String())
			}
			return true, optimized_record
		}
	}

	return false, nil
}

func try_send_cached(req *dns.Msg, resp dns.ResponseWriter, cache *DnsCacheNode, remoteIP string) (bool, []CachedRecord) {
	//note: although dns supports multiple questions, typically only one question is sent at a time
	//so we only use the first question as source for the cache node
	records := cache.GetRecords(req.Question[0].Qtype, req.Question[0].Name)

	if req.Question[0].Qtype == dns.TypeA {
		cnames := cache.GetRecords(dns.TypeCNAME, req.Question[0].Name)

		if len(cnames) > 0 {
			records = append(records, cnames[0])
			cname, ok := cnames[0].record.(*dns.CNAME)
			if ok {
				alias_cache := cache.GetCacheNode(cname.Target)
				alias_records := alias_cache.GetRecords(req.Question[0].Qtype, cname.Target)
				//we have a cname but no A record
				if len(alias_records) == 0 {
					return false, nil
				}
				records = append(records, alias_records...)
			}
		}
	}

	if len(records) > 0 {
		rr_records := []dns.RR{}
		for _, record := range records {
			rr_records = append(rr_records, record.record)
		}
		write_response(resp, req, rr_records, nil, nil)
		log_action(req, remoteIP, "cached", getRRValue(rr_records[0]))
		return true, records
	}

	return false, nil
}

func getQTypeLabel(qtype uint16) string {
	switch qtype {
	case dns.TypeA:
		return "A"
	case dns.TypeAAAA:
		return "AAAA"
	case dns.TypeNS:
		return "NS"
	case dns.TypeMX:
		return "MX"
	case dns.TypeHTTPS:
		return "HTTPS"
	case dns.TypeEUI64:
		return "EUI64"
	case dns.TypePTR:
		return "PTR"
	default:
		return "?" + fmt.Sprintf("%d", qtype)
	}
}

func log_action(req *dns.Msg, remoteIP string, responseType string, responseInfo string) {
	question := req.Question[0]

	log.Printf("[%s] Q [%s] %s -> %s :: %s", remoteIP, getQTypeLabel(question.Qtype), question.Name, responseType, responseInfo)
}

func try_predefined(req *dns.Msg, resp dns.ResponseWriter, config *Config) bool {
	if entry, exists := config.Addresses[strings.TrimRight(req.Question[0].Name, ".")]; exists {
		aRecord := &dns.A{
			Hdr: dns.RR_Header{
				Name:   req.Question[0].Name, // The domain name
				Rrtype: dns.TypeA,            // A record type
				Class:  dns.ClassINET,        // Internet class
				Ttl:    3600,                 // Time to live in seconds
			},
			A: net.ParseIP(entry),
		}
		write_response(resp, req, []dns.RR{aRecord}, nil, nil)
		return true
	}

	return false
}

func request_worker(tasks <-chan ResolveTask, hosts *Host, root *DnsCacheNode, wg *sync.WaitGroup, requestLock *RequestLock) {
	defer wg.Done()

	for task := range tasks {
		sentPredefined := try_predefined(task.request, task.writer, task.config)

		if sentPredefined {
			continue
		}

		cache := root.GetCacheNode(task.request.Question[0].Name)
		requestKey := fmt.Sprintf("%d%s", task.request.Question[0].Qtype, task.request.Question[0].Name)
		remoteIP := strings.Split(task.writer.RemoteAddr().String(), ":")[0]

		requestLock.Lock(requestKey)
		sentOptimized, optimizedRecord := try_send_optimized(task.request, task.writer, cache, remoteIP)
		if sentOptimized && time.Until(optimizedRecord.expiration).Seconds() > float64(task.config.Queries.RecacheTTL) {
			requestLock.Unlock(requestKey)
			continue
		}

		sentCached := false
		cachedRecords := []CachedRecord{}
		if !sentOptimized {
			sentCached, cachedRecords = try_send_cached(task.request, task.writer, cache, remoteIP)
		}

		if sentCached {
			needs_recache := false
			for _, cachedRecord := range cachedRecords {
				if time.Until(cachedRecord.expiration).Seconds() < float64(task.config.Queries.RecacheTTL) {
					needs_recache = true
					break
				}
			}

			if !needs_recache {
				requestLock.Unlock(requestKey)
				continue
			}
		}

		if !sentCached && !sentOptimized {
			// we dont have cached records and recursion was denied -> fail
			if !task.request.RecursionDesired {
				//TODO: implement authorative/zone
				dns.HandleFailed(task.writer, task.request)
				requestLock.Unlock(requestKey)
				continue
			}
		}

		// send upstream
		responses := *dns_resolver(task.config.Nameservers, task.request)
		first := <-responses

		sentResponse := sentOptimized || sentCached

		if first != nil && !sentResponse {
			sentResponse = true
			task.writer.WriteMsg(first)
			response_value := ""
			if len(first.Answer) > 0 {
				response_value = getRRValue(first.Answer[0])
			}
			log_action(task.request, remoteIP, "proxied", response_value)
		}

		results := make([]*dns.Msg, 0, len(task.config.Nameservers)+1)
		results = append(results, first)

		for i := 1; i < len(task.config.Nameservers); i++ {
			results = append(results, <-responses)
		}

		ARecordMap := make(map[string]*dns.A)

		for _, result := range results {
			if result != nil {
				if !sentResponse {
					task.writer.WriteMsg(result)
					sentResponse = true
					log_action(task.request, remoteIP, "proxied", getRRValue(result.Answer[0]))
				}

				for _, answer := range result.Answer {
					if a, ok := answer.(*dns.A); ok {
						key := fmt.Sprintf("%s%s", a.A.String(), a.Header().Name)
						ARecordMap[key] = a
					}
					cache.AddRecord(answer)
				}

				for _, ns := range result.Ns {
					cache.AddRecord(ns)
				}

				for _, extra := range result.Extra {
					cache.AddRecord(extra)
				}
			}
		}

		if !sentResponse {
			dns.HandleFailed(task.writer, task.request)
			log_action(task.request, remoteIP, "failed", "")
			requestLock.Unlock(requestKey)
			continue
		}
		var ARecords []*dns.A
		for _, val := range ARecordMap {
			ARecords = append(ARecords, val)
		}
		skip_ping := false
		if sentOptimized {
			for _, a_record := range ARecords {
				if RREquals(a_record, optimizedRecord.record) {
					optimizedRecord.expiration = time.Now().Add(time.Duration(a_record.Header().Ttl) * time.Second)
					skip_ping = true
					break
				}
			}
		}

		if !skip_ping {
			if len(ARecords) > 0 {
				fastSortedRecords := sort_by_latency(ARecords, hosts)
				cache.SetOptimizedRecord(fastSortedRecords[0])
			}
		}
		requestLock.Unlock(requestKey)
	}
}

type RequestLock struct {
	lock     sync.Mutex
	requests map[string]*sync.Mutex
}

func (r *RequestLock) Lock(key string) {
	r.lock.Lock()
	lock, exists := r.requests[key]
	if !exists {
		lock = &sync.Mutex{}
		r.requests[key] = lock
	}
	r.lock.Unlock()

	lock.Lock()
}

func (r *RequestLock) Unlock(key string) {
	r.lock.Lock()
	lock, exists := r.requests[key]
	r.lock.Unlock()
	if exists {
		lock.Unlock()
	} else {
		fmt.Println("Unlocking non-existent key")
	}
}

func NewRequestLock() *RequestLock {
	return &RequestLock{
		requests: make(map[string]*sync.Mutex),
	}
}

func main() {
	config, err := loadConfig()

	if err != nil {
		log.Fatalf("Failed to load config: %s\n", err.Error())
		return
	}

	resolverTasks := make(chan ResolveTask)
	var wg sync.WaitGroup
	host := NewHost()
	cache := NewDnsCacheNode(".")
	requestLock := NewRequestLock()

	//start 1 worker
	workers := runtime.NumCPU() * 2
	// workers := 1
	for range workers {
		wg.Add(1)
		go request_worker(resolverTasks, host, cache, &wg, requestLock)
	}

	log.Printf("spawned %d workers", workers)

	// Create a new DNS server
	dns.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		resolverTasks <- ResolveTask{writer: w, request: r, config: config}
	})

	// Start listening for DNS requests on port 5353
	addr := fmt.Sprintf("%s:%d", config.Server.Address, config.Server.Port)
	go func() {
		server := &dns.Server{Addr: addr, Net: "udp"}
		defer server.Shutdown()

		log.Printf("Starting DNS server on %s UDP", addr)

		err = server.ListenAndServe()
	}()

	go func() {
		server := &dns.Server{Addr: addr, Net: "tcp"}
		defer server.Shutdown()

		log.Printf("Starting DNS server on %s TCP", addr)

		err = server.ListenAndServe()
	}()

	select {}
}
