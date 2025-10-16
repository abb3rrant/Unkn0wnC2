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
// Missing or partial files fall back to defaults.
func LoadConfig() (Config, error) {
	cfg := DefaultConfig()

	path := os.Getenv("DNS_CONFIG")
	if path == "" {
		path = "config.json"
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// No file present: return defaults
			return cfg, nil
		}
		return cfg, fmt.Errorf("open config: %w", err)
	}

	var fileCfg Config
	if err := json.Unmarshal(data, &fileCfg); err != nil {
		return cfg, fmt.Errorf("decode config: %w", err)
	}

	// Merge: only overwrite defaults if provided
	if fileCfg.BindAddr != "" {
		cfg.BindAddr = fileCfg.BindAddr
	}
	if fileCfg.BindPort != 0 {
		cfg.BindPort = fileCfg.BindPort
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
	// For boolean fields, use the loaded value (false if not specified)
	cfg.ForwardDNS = fileCfg.ForwardDNS
	cfg.Debug = fileCfg.Debug
	if fileCfg.UpstreamDNS != "" {
		cfg.UpstreamDNS = fileCfg.UpstreamDNS
	}
	if fileCfg.EncryptionKey != "" {
		cfg.EncryptionKey = fileCfg.EncryptionKey
	}

	return cfg, nil
}
