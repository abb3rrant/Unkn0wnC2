// Package main defines data structures and types for the Unkn0wnC2 client.
// This file contains configuration structures and other type definitions
// used throughout the client codebase.
package main

// Config holds the client configuration - embedded at build time
type Config struct {
	ServerDomain        string   // Legacy single domain (for backward compatibility)
	DNSDomains          []string // Multiple DNS C2 domains (new multi-domain support)
	DomainSelectionMode string   // Mode: "random", "round-robin", "failover" (default: "random")
	DNSServer           string
	QueryType           string
	Encoding            string
	EncryptionKey       string
	Timeout             int
	MaxCommandLength    int
	RetryAttempts       int
	SleepMin            int
	SleepMax            int
	ExfilJitterMinMs    int
	ExfilJitterMaxMs    int
	ExfilChunksPerBurst int
	ExfilBurstPauseMs   int
}

// GetDomains returns the list of domains to use
// Prioritizes DNSDomains array, falls back to ServerDomain for backward compatibility
func (c *Config) GetDomains() []string {
	if len(c.DNSDomains) > 0 {
		return c.DNSDomains
	}
	if c.ServerDomain != "" {
		return []string{c.ServerDomain}
	}
	return []string{}
}

// GetSelectionMode returns the domain selection mode, defaulting to "random"
func (c *Config) GetSelectionMode() string {
	if c.DomainSelectionMode == "" {
		return "random"
	}
	return c.DomainSelectionMode
}

// Note: The actual configuration values are generated at build time
// in config.go by the generate_config.go tool
