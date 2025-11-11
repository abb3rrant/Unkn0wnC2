// Package main implements configuration management for the Unkn0wnC2 Master Server.
// This file handles loading configuration for the central command server that
// orchestrates multiple DNS C2 servers and provides the WebUI interface.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// Config holds runtime settings for the Master server
type Config struct {
	BindAddr         string           `json:"bind_addr"`         // Address to bind HTTPS server (e.g., "0.0.0.0")
	BindPort         int              `json:"bind_port"`         // HTTPS port (default: 443)
	TLSCert          string           `json:"tls_cert"`          // Path to TLS certificate
	TLSKey           string           `json:"tls_key"`           // Path to TLS key
	DatabasePath     string           `json:"database_path"`     // Path to master SQLite database
	WebRoot          string           `json:"web_root"`          // Path to web UI files directory
	SourceDir        string           `json:"source_dir"`        // Path to source code directory for building
	EncryptionKey    string           `json:"encryption_key"`    // Global encryption key for all C2 communications
	Debug            bool             `json:"debug"`             // Enable debug logging
	JWTSecret        string           `json:"jwt_secret"`        // Secret for JWT token signing
	SessionTimeout   int              `json:"session_timeout"`   // Session timeout in minutes (default: 60)
	DNSServers       []DNSServerAuth  `json:"dns_servers"`       // Pre-registered DNS servers
	AdminCredentials AdminCredentials `json:"admin_credentials"` // Initial admin credentials
}

// DNSServerAuth holds authentication configuration for DNS servers
type DNSServerAuth struct {
	ID      string `json:"id"`      // Unique DNS server identifier
	Domain  string `json:"domain"`  // DNS domain this server handles
	APIKey  string `json:"api_key"` // API key for authentication
	Address string `json:"address"` // Expected IP address (optional)
	Enabled bool   `json:"enabled"` // Whether this DNS server is enabled
}

// AdminCredentials holds initial admin user credentials
type AdminCredentials struct {
	Username string `json:"username"` // Default admin username
	Password string `json:"password"` // Default admin password (will be hashed)
}

// DefaultConfig returns sensible defaults for Master server
func DefaultConfig() Config {
	return Config{
		BindAddr:       "0.0.0.0",
		BindPort:       8443, // 8443 for non-root, 443 for production with proper permissions
		TLSCert:        "/opt/unkn0wnc2/certs/master.crt",
		TLSKey:         "/opt/unkn0wnc2/certs/master.key",
		DatabasePath:   "/opt/unkn0wnc2/master.db",
		WebRoot:        "/opt/unkn0wnc2/web",
		SourceDir:      "/opt/unkn0wnc2/src",
		Debug:          false,
		JWTSecret:      "CHANGE_THIS_SECRET_IN_PRODUCTION",
		SessionTimeout: 60,
		DNSServers:     []DNSServerAuth{},
		AdminCredentials: AdminCredentials{
			Username: "admin",
			Password: "Unkn0wnC2@2025", // Will be hashed on first run
		},
	}
}

// LoadConfig attempts to load configuration from a JSON file or environment
// Falls back to defaults if file not present
func LoadConfig(configPath string) (Config, error) {
	cfg := DefaultConfig()

	// Use provided path, or check environment, or use default
	path := configPath
	if path == "" {
		path = os.Getenv("MASTER_CONFIG")
		if path == "" {
			path = "master_config.json"
		}
	}

	// Try to read config file
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// No file present, use defaults
			return cfg, nil
		}
		return cfg, fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse JSON config
	var fileCfg Config
	if err := json.Unmarshal(data, &fileCfg); err != nil {
		return cfg, fmt.Errorf("failed to parse config JSON: %w", err)
	}

	// Merge: only overwrite defaults if provided in file
	if fileCfg.BindAddr != "" {
		cfg.BindAddr = fileCfg.BindAddr
	}
	if fileCfg.BindPort != 0 {
		cfg.BindPort = fileCfg.BindPort
	}
	if fileCfg.TLSCert != "" {
		cfg.TLSCert = fileCfg.TLSCert
	}
	if fileCfg.TLSKey != "" {
		cfg.TLSKey = fileCfg.TLSKey
	}
	if fileCfg.DatabasePath != "" {
		cfg.DatabasePath = fileCfg.DatabasePath
	}
	if fileCfg.WebRoot != "" {
		cfg.WebRoot = fileCfg.WebRoot
	}
	if fileCfg.SourceDir != "" {
		cfg.SourceDir = fileCfg.SourceDir
	}
	if fileCfg.EncryptionKey != "" {
		cfg.EncryptionKey = fileCfg.EncryptionKey
	}
	if fileCfg.JWTSecret != "" {
		cfg.JWTSecret = fileCfg.JWTSecret
	}
	if fileCfg.SessionTimeout != 0 {
		cfg.SessionTimeout = fileCfg.SessionTimeout
	}
	if fileCfg.Debug {
		cfg.Debug = true
	}
	if len(fileCfg.DNSServers) > 0 {
		cfg.DNSServers = fileCfg.DNSServers
	}
	if fileCfg.AdminCredentials.Username != "" {
		cfg.AdminCredentials = fileCfg.AdminCredentials
	}

	// Environment variable overrides
	if jwtSecret := os.Getenv("MASTER_JWT_SECRET"); jwtSecret != "" {
		cfg.JWTSecret = jwtSecret
	}
	if adminPass := os.Getenv("MASTER_ADMIN_PASSWORD"); adminPass != "" {
		cfg.AdminCredentials.Password = adminPass
	}

	return cfg, nil
}

// ValidateConfig checks if the configuration is valid
func ValidateConfig(cfg Config) error {
	// Check for production security issues
	if cfg.JWTSecret == "CHANGE_THIS_SECRET_IN_PRODUCTION" {
		return errors.New("SECURITY WARNING: Using default JWT secret! Set jwt_secret in config or MASTER_JWT_SECRET environment variable")
	}

	// Check for weak JWT secrets
	if len(cfg.JWTSecret) < 32 {
		return fmt.Errorf("SECURITY ERROR: JWT secret too short (%d bytes). Minimum 32 bytes required. Generate a secure secret with: openssl rand -base64 32", len(cfg.JWTSecret))
	}

	// Check for example JWT secrets from the example config
	weakSecrets := []string{"!QAZ78fobh$*NC", "your-secret-key", "changeme", "secret", "password"}
	for _, weak := range weakSecrets {
		if cfg.JWTSecret == weak {
			return fmt.Errorf("SECURITY ERROR: Using example/weak JWT secret! Generate a secure secret with: openssl rand -base64 32")
		}
	}

	if cfg.AdminCredentials.Password == "Unkn0wnC2@2025" {
		fmt.Println("WARNING: Using default admin password! Change this immediately in production")
	}

	// Validate DNS server API keys
	for i, server := range cfg.DNSServers {
		if server.APIKey == "" {
			return fmt.Errorf("SECURITY ERROR: DNS server #%d (%s) has empty API key", i+1, server.ID)
		}
		if server.APIKey == "GENERATE_SECURE_API_KEY_HERE" || server.APIKey == "example-api-key-dns1-CHANGE-ME" || server.APIKey == "example-api-key-dns2-CHANGE-ME" {
			return fmt.Errorf("SECURITY ERROR: DNS server #%d (%s) using example API key. Generate a secure key with: openssl rand -base64 32", i+1, server.ID)
		}
		if len(server.APIKey) < 16 {
			return fmt.Errorf("SECURITY ERROR: DNS server #%d (%s) API key too short (%d bytes). Minimum 16 bytes required", i+1, server.ID, len(server.APIKey))
		}
	}

	// Validate TLS certificate paths exist
	if _, err := os.Stat(cfg.TLSCert); os.IsNotExist(err) {
		return fmt.Errorf("TLS certificate not found: %s", cfg.TLSCert)
	}
	if _, err := os.Stat(cfg.TLSKey); os.IsNotExist(err) {
		return fmt.Errorf("TLS key not found: %s", cfg.TLSKey)
	}

	// Validate port
	if cfg.BindPort < 1 || cfg.BindPort > 65535 {
		return fmt.Errorf("invalid bind port: %d (must be 1-65535)", cfg.BindPort)
	}

	return nil
}

// SaveConfig saves the current configuration to a file
func SaveConfig(cfg Config, path string) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// GenerateSecureSecret generates a cryptographically secure random string
// suitable for use as JWT secret or API keys. Returns a base64-encoded string.
func GenerateSecureSecret(length int) (string, error) {
	if length < 32 {
		return "", fmt.Errorf("secret length must be at least 32 bytes")
	}

	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	return base64.StdEncoding.EncodeToString(bytes), nil
}

// GenerateExampleConfig creates an example configuration file
func GenerateExampleConfig(path string) error {
	cfg := DefaultConfig()

	// Add example DNS servers
	cfg.DNSServers = []DNSServerAuth{
		{
			ID:      "dns1",
			Domain:  "example.net",
			APIKey:  "example-api-key-dns1-CHANGE-ME",
			Address: "1.2.3.4",
			Enabled: true,
		},
		{
			ID:      "dns2",
			Domain:  "example.com",
			APIKey:  "example-api-key-dns2-CHANGE-ME",
			Address: "",
			Enabled: false,
		},
	}

	return SaveConfig(cfg, path)
}
