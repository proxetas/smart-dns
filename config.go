package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server struct {
		Port    int    `yaml:"port"`
		Address string `yaml:"address"`
	} `yaml:"server"`
	Nameservers []string `yaml:"nameservers"`
	Queries     struct {
		RecacheTTL int `yaml:"recache_ttl"`
	}
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
