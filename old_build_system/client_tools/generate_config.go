package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// FullBuildConfig represents the complete nested structure from build_config.json
type FullBuildConfig struct {
	Client struct {
		ServerDomain        string   `json:"server_domain"`
		DNSDomains          []string `json:"dns_domains"`
		DomainSelectionMode string   `json:"domain_selection_mode"`
		DNSServer           string   `json:"dns_server"`
		QueryType           string   `json:"query_type"`
		Encoding            string   `json:"encoding"`
		Timeout             int      `json:"timeout"`
		MaxCommandLength    int      `json:"max_command_length"`
		RetryAttempts       int      `json:"retry_attempts"`
		SleepMin            int      `json:"sleep_min"`
		SleepMax            int      `json:"sleep_max"`
		ExfilJitterMinMs    int      `json:"exfil_jitter_min_ms"`
		ExfilJitterMaxMs    int      `json:"exfil_jitter_max_ms"`
		ExfilChunksPerBurst int      `json:"exfil_chunks_per_burst"`
		ExfilBurstPauseMs   int      `json:"exfil_burst_pause_ms"`
	} `json:"client"`
	Security struct {
		EncryptionKey string `json:"encryption_key"`
	} `json:"security"`
}

func main() {
	// Read build_config.json from root directory (two levels up from tools/)
	data, err := os.ReadFile("../../build_config.json")
	if err != nil {
		fmt.Printf("Error reading build_config.json: %v\n", err)
		os.Exit(1)
	}

	var config FullBuildConfig
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
	ServerDomain:         %q,
	DNSDomains:          %#v,
	DomainSelectionMode: %q,
	DNSServer:            %q,
	QueryType:            %q,
	Encoding:             %q,
	EncryptionKey:        %q,
	Timeout:              %d,
	MaxCommandLength:     %d,
	RetryAttempts:        %d,
	SleepMin:             %d,
	SleepMax:             %d,
	ExfilJitterMinMs:     %d,
	ExfilJitterMaxMs:     %d,
	ExfilChunksPerBurst:  %d,
	ExfilBurstPauseMs:    %d,
}

// getConfig returns the embedded configuration
func getConfig() Config {
	return embeddedConfig
}
`,
		config.Client.ServerDomain,
		config.Client.DNSDomains,
		config.Client.DomainSelectionMode,
		config.Client.DNSServer,
		config.Client.QueryType,
		config.Client.Encoding,
		config.Security.EncryptionKey,
		config.Client.Timeout,
		config.Client.MaxCommandLength,
		config.Client.RetryAttempts,
		config.Client.SleepMin,
		config.Client.SleepMax,
		config.Client.ExfilJitterMinMs,
		config.Client.ExfilJitterMaxMs,
		config.Client.ExfilChunksPerBurst,
		config.Client.ExfilBurstPauseMs,
	)

	// Write the generated configuration to config.go in parent directory
	if err := os.WriteFile("../config.go", []byte(goCode), 0644); err != nil {
		fmt.Printf("Error writing config.go: %v\n", err)
		os.Exit(1)
	}

	// Show configuration summary with consistent formatting
	domains := config.Client.DNSDomains
	if len(domains) == 0 {
		domains = []string{config.Client.ServerDomain}
	}
	fmt.Printf("  DNS Domains:         %v\n", domains)
	if len(config.Client.DNSDomains) > 1 {
		mode := config.Client.DomainSelectionMode
		if mode == "" {
			mode = "random"
		}
		fmt.Printf("  Selection Mode:      %s\n", mode)
	}
	fmt.Printf("  Encryption Key:      %s\n", strings.Repeat("*", len(config.Security.EncryptionKey)))
	fmt.Printf("  Check-in Interval:   %d-%d seconds\n", config.Client.SleepMin, config.Client.SleepMax)
	fmt.Printf("  Exfil Jitter:        %d-%dms\n", config.Client.ExfilJitterMinMs, config.Client.ExfilJitterMaxMs)
	fmt.Printf("  Exfil Chunks/Burst:  %d\n", config.Client.ExfilChunksPerBurst)
	fmt.Printf("  Exfil Burst Pause:   %dms\n", config.Client.ExfilBurstPauseMs)
}
