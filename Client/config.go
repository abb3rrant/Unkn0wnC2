package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// Config holds the client configuration
type Config struct {
	ServerDomain     string `json:"server_domain"`
	DNSServer        string `json:"dns_server"`
	QueryType        string `json:"query_type"`
	Encoding         string `json:"encoding"`
	EncryptionKey    string `json:"encryption_key"`
	Timeout          int    `json:"timeout"`
	MaxCommandLength int    `json:"max_command_length"`
	RetryAttempts    int    `json:"retry_attempts"`
	SleepMin         int    `json:"sleep_min"`
	SleepMax         int    `json:"sleep_max"`
}

// LoadConfig loads configuration from config.json file
func LoadConfig() (*Config, error) {
	config := &Config{
		ServerDomain:     "secwolf.net",
		DNSServer:        "",
		QueryType:        "TXT",
		Encoding:         "aes-gcm-base36",
		EncryptionKey:    "MySecretC2Key123!@#DefaultChange",
		Timeout:          10,
		MaxCommandLength: 800, // Increased for larger results
		RetryAttempts:    3,
		SleepMin:         5,
		SleepMax:         15,
	}

	file, err := os.Open("config.json")
	if err != nil {
		// Return default config if file doesn't exist
		fmt.Println("[!] Config file not found, using defaults")
		return config, nil
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(config); err != nil {
		return nil, fmt.Errorf("failed to parse config.json: %v", err)
	}

	return config, nil
}

// SaveConfig saves the current configuration to config.json
func (c *Config) SaveConfig() error {
	file, err := os.Create("config.json")
	if err != nil {
		return fmt.Errorf("failed to create config.json: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(c); err != nil {
		return fmt.Errorf("failed to save config: %v", err)
	}

	return nil
}
