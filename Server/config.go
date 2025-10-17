package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// Config holds runtime settings for the DNS server.
// - BindAddr: IP address/interface to bind (e.g., "0.0.0.0" or "127.0.0.1")
// - BindPort: UDP port to listen on (e.g., 53)
// - Domain: the domain we're authoritative for (e.g., "secwolf.net")
// - NS1, NS2: name server hostnames for this domain
// - ForwardDNS: whether to forward non-authoritative queries to upstream DNS
// - UpstreamDNS: upstream DNS server to forward queries to (e.g., "8.8.8.8:53")
// - EncryptionKey: AES key for C2 traffic encryption
// - Debug: enable detailed logging for troubleshooting
type Config struct {
	BindAddr      string `json:"bind_addr"`
	BindPort      int    `json:"bind_port"`
	SvrAddr       string `json:"server_address"`
	Domain        string `json:"domain"`
	NS1           string `json:"ns1"`
	NS2           string `json:"ns2"`
	ForwardDNS    bool   `json:"forward_dns"`
	UpstreamDNS   string `json:"upstream_dns"`
	EncryptionKey string `json:"encryption_key"`
	Debug         bool   `json:"debug"`
}

// DefaultConfig returns sensible defaults for local development.
func DefaultConfig() Config {
	return Config{
		BindAddr:      "0.0.0.0",
		BindPort:      53,
		SvrAddr:       "98.90.218.70",
		Domain:        "secwolf.net",
		NS1:           "ns1.secwolf.net",
		NS2:           "ns2.secwolf.net",
		ForwardDNS:    true,
		UpstreamDNS:   "8.8.8.8:53",
		EncryptionKey: "MySecretC2Key123!@#DefaultChange",
		Debug:         false,
	}
}

// LoadConfig attempts to load configuration from a JSON file.
// If DNS_CONFIG env var is set, it will use that path; otherwise "config.json" in cwd.
// Missing or partial files fall back to defaults or embedded config if available.
func LoadConfig() (Config, error) {
	var cfg Config

	// Try to load embedded configuration first (if available from build)
	if embeddedConfig, hasEmbedded := tryLoadEmbeddedConfig(); hasEmbedded {
		cfg = embeddedConfig
	} else {
		// Fall back to defaults if no embedded config
		cfg = DefaultConfig()
	}

	path := os.Getenv("DNS_CONFIG")
	if path == "" {
		path = "config.json"
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// No file present: return base config (embedded or defaults)
			return cfg, nil
		}
		return cfg, fmt.Errorf("open config: %w", err)
	}

	var fileCfg Config
	if err := json.Unmarshal(data, &fileCfg); err != nil {
		return cfg, fmt.Errorf("decode config: %w", err)
	}

	// Merge: only overwrite base config if provided in file
	if fileCfg.BindAddr != "" {
		cfg.BindAddr = fileCfg.BindAddr
	}
	if fileCfg.BindPort != 0 {
		cfg.BindPort = fileCfg.BindPort
	}
	if fileCfg.SvrAddr != "" {
		cfg.SvrAddr = fileCfg.SvrAddr
	}
	if fileCfg.Domain != "" {
		cfg.Domain = fileCfg.Domain
	}
	if fileCfg.NS1 != "" {
		cfg.NS1 = fileCfg.NS1
	}
	if fileCfg.NS2 != "" {
		cfg.NS2 = fileCfg.NS2
	}
	// For boolean fields, use the loaded value only if explicitly set
	if fileCfg.ForwardDNS != cfg.ForwardDNS {
		cfg.ForwardDNS = fileCfg.ForwardDNS
	}
	if fileCfg.Debug != cfg.Debug {
		cfg.Debug = fileCfg.Debug
	}
	if fileCfg.UpstreamDNS != "" {
		cfg.UpstreamDNS = fileCfg.UpstreamDNS
	}
	if fileCfg.EncryptionKey != "" {
		cfg.EncryptionKey = fileCfg.EncryptionKey
	}

	return cfg, nil
}

// tryLoadEmbeddedConfig attempts to load embedded configuration
// Returns the config and true if embedded config is available, otherwise returns empty config and false
// tryLoadEmbeddedConfig attempts to load embedded configuration
// Returns the config and true if embedded config is available, otherwise returns empty config and false
// tryLoadEmbeddedConfig attempts to load embedded configuration
// Returns the config and true if embedded config is available, otherwise returns empty config and false
// tryLoadEmbeddedConfig attempts to load embedded configuration
// Returns the config and true if embedded config is available, otherwise returns empty config and false
func tryLoadEmbeddedConfig() (Config, bool) {
	// Embedded configuration from build time
	embeddedConfig := Config{
		BindAddr:      "172.26.13.62",
		BindPort:      53,
		SvrAddr:       "98.90.218.70",
		Domain:        "secwolf.net",
		NS1:           "ns1.secwolf.net",
		NS2:           "ns2.secwolf.net",
		ForwardDNS:    true,
		UpstreamDNS:   "8.8.8.8:53",
		EncryptionKey: "MySecretC2Key123!@#DefaultChange",
		Debug:         false,
	}
	return embeddedConfig, true
}
