package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
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

func dns_resolver(tasks <-chan ResolveTask, hosts *Host, optimizedRecords *OptimizedRecords, wg *sync.WaitGroup) {
	defer wg.Done()

	// Worker loop: Continuously receive tasks from the channel
	responses := make(chan *dns.Msg)
	var subwg sync.WaitGroup

	for task := range tasks {
		//if 1 question and of type A, check if we have optimized version
		if len(task.request.Question) == 1 && task.request.Question[0].Qtype == dns.TypeA {
			optimizedRecord := optimizedRecords.Get(task.request.Question[0].Name)
			if !optimizedRecord.IsEmpty() {
				answer, err := optimizedRecord.GetRR()
				if err == nil {
					answers := []dns.RR{answer}
					write_response(task.writer, task.request, answers, nil, nil)
					fmt.Printf("Q from %s for %s -> optimized response %s sent\n", task.writer.RemoteAddr().String(), task.request.Question[0].Name, optimizedRecord.IP)
					continue
				}
			}
		}

		if !task.request.RecursionDesired {
			dns.HandleFailed(task.writer, task.request)
			continue
		}

		subwg.Add(len(task.config.Nameservers))
		for _, nameserver := range task.config.Nameservers {
			go func(resp chan *dns.Msg, req *dns.Msg, nameserver string, group *sync.WaitGroup) {
				defer group.Done()
				client := new(dns.Client)
				//If not nameserver contains ":" then add ":53"
				if !strings.Contains(nameserver, ":") {
					nameserver += ":53"
				}
				result, _, err := client.Exchange(req, nameserver)
				if err != nil {
					resp <- nil
				} else {
					resp <- result
				}
			}(responses, task.request, nameserver, &subwg)
		}

		first := <-responses
		sentResponse := false

		if first != nil {
			sentResponse = true
			task.writer.WriteMsg(first)
			fmt.Printf("Q from %s for %s -> proxied response sent\n", task.writer.RemoteAddr().String(), task.request.Question[0].Name)
		}

		results := make([]*dns.Msg, 0, len(task.config.Nameservers)+1)
		results = append(results, first)

		for i := 1; i < len(task.config.Nameservers); i++ {
			results = append(results, <-responses)
		}

		if !sentResponse {
			for _, response := range results {
				if response != nil {
					task.writer.WriteMsg(response)
					sentResponse = true
					fmt.Printf("Q from %s for %s -> proxied response sent\n", task.writer.RemoteAddr().String(), task.request.Question[0].Name)
					break
				}
			}
		}

		if !sentResponse {
			dns.HandleFailed(task.writer, task.request)
			fmt.Printf("Q from %s for %s -> failed", task.writer.RemoteAddr().String(), task.request.Question[0].Name)
			continue
		}

		fmt.Printf("optimizing %s...\n", task.request.Question[0].Name)
		var ARecordIPs []string
		var ARecords []*dns.A

		for _, result := range results {
			for _, answer := range result.Answer {
				if a, ok := answer.(*dns.A); ok {
					ARecordIPs = append(ARecordIPs, a.A.String())
					ARecords = append(ARecords, a)
				}
			}
		}

		type PingResult struct {
			index   int
			Latency int64
		}

		var latencies []PingResult
		var latencyChannel = make(chan PingResult)

		for i, ip := range ARecordIPs {
			subwg.Add(1)
			go func(wg *sync.WaitGroup, index int, ip string, result chan PingResult) {
				defer wg.Done()
				result <- PingResult{index: index, Latency: hosts.Get(ip)}
			}(&subwg, i, ip, latencyChannel)
		}

		for i := 0; i < len(ARecordIPs); i++ {
			latencies = append(latencies, <-latencyChannel)
		}

		var fastestLatency int64 = latencies[0].Latency
		var fastestARecord *dns.A = ARecords[latencies[0].index]
		var fastestIp string = ARecordIPs[latencies[0].index]

		for _, latency := range latencies {
			if latency.Latency < fastestLatency {
				fastestIp = ARecordIPs[latency.index]
				fastestLatency = latency.Latency
				fastestARecord = ARecords[latency.index]
			}
		}

		optimizedRecord := OptimizedA{
			IP:         fastestIp,
			Latency:    fastestLatency,
			Name:       fastestARecord.Header().Name,
			expiration: time.Now().Add(time.Second * time.Duration(fastestARecord.Hdr.Ttl)),
		}

		fmt.Printf("optimized record for %s -> %s %dms\n", task.request.Question[0].Name, fastestIp, fastestLatency/1000)
		optimizedRecords.Set(fastestARecord.Header().Name, &optimizedRecord)
	}
}

type Config struct {
	Server struct {
		Port    int    `yaml:"port"`
		Address string `yaml:"address"`
	} `yaml:"server"`
	Nameservers []string `yaml:"nameservers"`
}

// loadConfig reads the config from the file and parses it into a Config struct
func loadConfig() (*Config, error) {
	// Path to the configuration file
	configFile := "./config.yml"

	// Check if the file exists
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		fmt.Printf("Error: Config file '%s' not found\n", configFile)
		return nil, err
	}

	// Read the file contents
	data, err := os.ReadFile(configFile)
	if err != nil {
		fmt.Printf("Error: Failed to read config file '%s': %v\n", configFile, err)
		return nil, err
	}

	// Parse the YAML into the Config struct
	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		fmt.Printf("Error: Failed to parse config file '%s': %v\n", configFile, err)
		return nil, err
	}

	return &config, nil
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
	optimizedRecords := NewOptimizedRecords()

	//start 1 worker
	wg.Add(1)
	go dns_resolver(resolverTasks, host, optimizedRecords, &wg)

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
