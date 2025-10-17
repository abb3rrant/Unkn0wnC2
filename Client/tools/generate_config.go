package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// BuildConfig represents the configuration read from build_config.json
type BuildConfig struct {
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

func main() {
	// Read build_config.json from parent directory
	data, err := os.ReadFile("../build_config.json")
	if err != nil {
		fmt.Printf("Error reading build_config.json: %v\n", err)
		os.Exit(1)
	}

	var config BuildConfig
	if err := json.Unmarshal(data, &config); err != nil {
		fmt.Printf("Error parsing build_config.json: %v\n", err)
		os.Exit(1)
	}

	// Generate Go source code with embedded configuration
	goCode := fmt.Sprintf(`package main

// This file is auto-generated at build time
// DO NOT EDIT MANUALLY

// embeddedConfig contains the configuration embedded at build time
var embeddedConfig = Config{
	ServerDomain:     %q,
	DNSServer:        %q,
	QueryType:        %q,
	Encoding:         %q,
	EncryptionKey:    %q,
	Timeout:          %d,
	MaxCommandLength: %d,
	RetryAttempts:    %d,
	SleepMin:         %d,
	SleepMax:         %d,
}

// getConfig returns the embedded configuration
func getConfig() Config {
	return embeddedConfig
}
`,
		config.ServerDomain,
		config.DNSServer,
		config.QueryType,
		config.Encoding,
		config.EncryptionKey,
		config.Timeout,
		config.MaxCommandLength,
		config.RetryAttempts,
		config.SleepMin,
		config.SleepMax,
	)

	// Write the generated configuration to config.go in parent directory
	if err := os.WriteFile("../config.go", []byte(goCode), 0644); err != nil {
		fmt.Printf("Error writing config.go: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Configuration embedded successfully!")
	fmt.Printf("Server Domain: %s\n", config.ServerDomain)
	fmt.Printf("Encryption Key: %s\n", strings.Repeat("*", len(config.EncryptionKey)))
	fmt.Printf("Sleep Interval: %d-%d seconds\n", config.SleepMin, config.SleepMax)
}
