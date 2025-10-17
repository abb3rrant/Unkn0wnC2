// Package main defines data structures and types for the Unkn0wnC2 client.
// This file contains configuration structures and other type definitions
// used throughout the client codebase.
package main

// Config holds the client configuration - embedded at build time
type Config struct {
	ServerDomain     string
	DNSServer        string
	QueryType        string
	Encoding         string
	EncryptionKey    string
	Timeout          int
	MaxCommandLength int
	RetryAttempts    int
	SleepMin         int
	SleepMax         int
}

// Note: The actual configuration values are generated at build time
// in config.go by the generate_config.go tool
