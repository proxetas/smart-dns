package main

import (
	"fmt"
	"log"
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

func try_send_optimized(req *dns.Msg, resp dns.ResponseWriter, cache *DnsCacheNode) (bool, *CachedRecord) {
	if len(req.Question) == 1 && req.Question[0].Qtype == dns.TypeA {
		optimizedRecord := cache.GetOptimizedRecord(req.Question[0].Name)
		if optimizedRecord != nil {
			record := optimizedRecord.record
			record.Header().Ttl = uint32(time.Until(optimizedRecord.expiration).Seconds())
			answers := []dns.RR{optimizedRecord.record}
			write_response(resp, req, answers, nil, nil)
			if optimizedRecordA, ok := optimizedRecord.record.(*dns.A); ok {
				fmt.Printf("Q from %s for %s -> optimized response %s sent\n", resp.RemoteAddr().String(), req.Question[0].Name, optimizedRecordA.A)
			}
			return true, optimizedRecord
		}
	}

	return false, nil
}

func try_send_cached(req *dns.Msg, resp dns.ResponseWriter, cache *DnsCacheNode) (bool, []CachedRecord) {
	//note: although dns supports multiple questions, typically only one question is sent at a time
	//so we only use the first question as source for the cache node
	records := cache.GetRecords(req.Question[0].Qtype, req.Question[0].Name)

	if len(records) > 0 {
		rr_records := []dns.RR{}
		for _, record := range records {
			rr_records = append(rr_records, record.record)
		}
		write_response(resp, req, rr_records, nil, nil)
		fmt.Printf("Q from %s for %s -> cached response sent\n", resp.RemoteAddr().String(), req.Question[0].Name)
		return true, records
	}

	return false, nil
}

func request_worker(tasks <-chan ResolveTask, hosts *Host, root *DnsCacheNode, wg *sync.WaitGroup) {
	defer wg.Done()

	for task := range tasks {
		cache := root.GetCacheNode(task.request.Question[0].Name)

		sentOptimized, optimizedRecord := try_send_optimized(task.request, task.writer, cache)
		if sentOptimized && time.Until(optimizedRecord.expiration).Seconds() > float64(task.config.Queries.RecacheTTL) {
			continue
		}

		sentCached := false
		cachedRecords := []CachedRecord{}
		if !sentOptimized {
			sentCached, cachedRecords = try_send_cached(task.request, task.writer, cache)
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
				continue
			}
		}

		if !sentCached && !sentOptimized {
			// we dont have cached records and recursion was denied -> fail
			if !task.request.RecursionDesired {
				//TODO: implement authorative/zone
				dns.HandleFailed(task.writer, task.request)
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
			fmt.Printf("Q from %s for %s -> proxied response sent\n", task.writer.RemoteAddr().String(), task.request.Question[0].Name)
		}

		results := make([]*dns.Msg, 0, len(task.config.Nameservers)+1)
		results = append(results, first)

		for i := 1; i < len(task.config.Nameservers); i++ {
			results = append(results, <-responses)
		}

		fmt.Printf("optimizing %s...\n", task.request.Question[0].Name)
		var ARecords []*dns.A

		for _, result := range results {
			if result != nil {
				if !sentResponse {
					task.writer.WriteMsg(result)
					sentResponse = true
					fmt.Printf("Q from %s for %s -> upstream response sent\n", task.writer.RemoteAddr().String(), task.request.Question[0].Name)
				}

				for _, answer := range result.Answer {
					if a, ok := answer.(*dns.A); ok {
						ARecords = append(ARecords, a)
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
			fmt.Printf("Q from %s for %s -> failed", task.writer.RemoteAddr().String(), task.request.Question[0].Name)
			continue
		}

		skip_ping := false
		if sentOptimized {
			for _, a_record := range ARecords {
				if RREquals(a_record, optimizedRecord.record) {
					optimizedRecord.expiration = time.Now().Add(time.Duration(a_record.Header().Ttl) * time.Second)
					fmt.Printf("extended expiration for optimized record %s -> %s\n", task.request.Question[0].Name, a_record.A)
					skip_ping = true
					break
				}
			}
		}

		if !skip_ping {
			fastSortedRecords := sort_by_latency(ARecords, hosts)
			fmt.Printf("optimized record for %s -> %s\n", task.request.Question[0].Name, fastSortedRecords[0].A)
			cache.SetOptimizedRecord(fastSortedRecords[0])
		}
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

	//start 1 worker
	wg.Add(1)
	go request_worker(resolverTasks, host, cache, &wg)

	// Create a new DNS server
	dns.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		resolverTasks <- ResolveTask{writer: w, request: r, config: config}
	})

	// Start listening for DNS requests on port 5353
	addr := fmt.Sprintf("%s:%d", config.Server.Address, config.Server.Port)
	server := &dns.Server{Addr: addr, Net: "udp"}
	log.Printf("Starting DNS server on %s", addr)

	err = server.ListenAndServe()
	defer server.Shutdown()

	if err != nil {
		log.Fatalf("Failed to start server: %s\n", err.Error())
	}
}
