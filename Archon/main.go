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
		fmt.Printf("✓ Overriding bind address: %s\n", *bindAddr)
	}
	if *bindPort != 0 {
		cfg.BindPort = *bindPort
		fmt.Printf("✓ Overriding bind port: %d\n", *bindPort)
	}

	// Validate configuration
	if err := ValidateConfig(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Configuration validation failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Configuration loaded from: %s\n", *configPath)
	fmt.Printf("Bind address: %s:%d\n", cfg.BindAddr, cfg.BindPort)
	fmt.Printf("TLS Certificate: %s\n", cfg.TLSCert)
	fmt.Printf("Database: %s\n", cfg.DatabasePath)
	fmt.Printf("Debug mode: %v\n", cfg.Debug)
	fmt.Println()

	// Verify or generate TLS certificate with IP SANs for the bind address
	fmt.Println("Checking TLS certificate...")
	needsGeneration := false
	
	// Check if certificate exists and has correct IP SAN
	if _, err := os.Stat(cfg.TLSCert); os.IsNotExist(err) {
		fmt.Println("✗ TLS certificate not found")
		needsGeneration = true
	} else if _, err := os.Stat(cfg.TLSKey); os.IsNotExist(err) {
		fmt.Println("✗ TLS private key not found")
		needsGeneration = true
	} else {
		// Certificate exists, verify it has the correct IP SAN
		hasIPSAN, err := VerifyCertHasIPSAN(cfg.TLSCert, cfg.BindAddr)
		if err != nil {
			fmt.Printf("✗ Failed to verify certificate: %v\n", err)
			needsGeneration = true
		} else if !hasIPSAN {
			fmt.Printf("✗ Certificate does not contain IP SAN for %s\n", cfg.BindAddr)
			needsGeneration = true
		} else {
			fmt.Printf("✓ TLS certificate valid with IP SAN for %s\n", cfg.BindAddr)
		}
	}

	// Generate new certificate if needed
	if needsGeneration {
		fmt.Printf("Generating new TLS certificate for %s...\n", cfg.BindAddr)
		if err := GenerateSelfSignedCert(cfg.BindAddr, cfg.TLSCert, cfg.TLSKey); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to generate TLS certificate: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ Generated TLS certificate with IP SAN: %s\n", cfg.BindAddr)
		fmt.Printf("  Certificate: %s\n", cfg.TLSCert)
		fmt.Printf("  Private Key: %s\n", cfg.TLSKey)
		fmt.Println()
	}
	fmt.Println()

	// Initialize database
	fmt.Println("Initializing database...")
	db, err := NewMasterDatabase(cfg.DatabasePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	// Check if initial admin setup is needed
	if err := initializeAdmin(db, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize admin: %v\n", err)
		os.Exit(1)
	}

	// Register pre-configured DNS servers
	if err := registerConfiguredDNSServers(db, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to register DNS servers: %v\n", err)
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

	// TODO: Setup WebSocket endpoint for real-time updates
	// router.HandleFunc("/ws", handleWebSocket).Methods("GET")

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
		fmt.Printf("\n%s==================================================%s\n", ColorGreen, ColorReset)
		fmt.Printf("%sArchon Server v%s%s\n", ColorGreen, version, ColorReset)
		fmt.Printf("Build: %s (commit: %s)\n", buildDate, gitCommit)
		fmt.Printf("%s==================================================%s\n", ColorGreen, ColorReset)
		fmt.Printf("HTTPS Server listening on: https://%s\n", addr)
		fmt.Printf("TLS enabled with certificate: %s\n", cfg.TLSCert)
		fmt.Printf("Database: %s\n", cfg.DatabasePath)
		fmt.Printf("DNS Servers registered: %d\n", len(cfg.DNSServers))

		// Display registered DNS servers
		if len(cfg.DNSServers) > 0 {
			fmt.Println("\nRegistered DNS Servers:")
			for _, dns := range cfg.DNSServers {
				status := "✓"
				if !dns.Enabled {
					status = "✗"
				}
				fmt.Printf("  %s %s - %s (%s)\n", status, dns.ID, dns.Domain, dns.Address)
			}
		}

		fmt.Println()
		fmt.Printf("%sPress Ctrl+C to shutdown gracefully%s\n", ColorYellow, ColorReset)
		fmt.Println()

		// Start HTTPS server
		if err := srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "Failed to start HTTPS server: %v\n", err)
			os.Exit(1)
		}
	}()

	// Start periodic database cleanup (runs every 6 hours)
	go func() {
		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()

		// Run initial cleanup after 1 hour
		time.Sleep(1 * time.Hour)

		for {
			if cfg.Debug {
				fmt.Println("[Cleanup] Running database maintenance...")
			}

			// Cleanup completed tasks older than 30 days
			if count, err := db.CleanupOldTasks(30); err == nil && count > 0 {
				fmt.Printf("[Cleanup] ✓ Removed %d old completed tasks\n", count)
			} else if err != nil && cfg.Debug {
				fmt.Printf("[Cleanup] Warning: Failed to cleanup old tasks: %v\n", err)
			}

			// Cleanup inactive beacons older than 60 days
			if count, err := db.CleanupInactiveBeacons(60); err == nil && count > 0 {
				fmt.Printf("[Cleanup] ✓ Removed %d inactive beacons\n", count)
			} else if err != nil && cfg.Debug {
				fmt.Printf("[Cleanup] Warning: Failed to cleanup inactive beacons: %v\n", err)
			}

			// Cleanup completed stager sessions older than 7 days
			if count, err := db.CleanupCompletedStagerSessions(7); err == nil && count > 0 {
				fmt.Printf("[Cleanup] ✓ Removed %d old stager sessions\n", count)
			} else if err != nil && cfg.Debug {
				fmt.Printf("[Cleanup] Warning: Failed to cleanup stager sessions: %v\n", err)
			}

			// Expire stale pending tasks (pending for 48+ hours)
			// For long-term engagements (30min+ callbacks), this prevents queue buildup
			if count, err := db.CleanupStalePendingTasks(48); err == nil && count > 0 {
				fmt.Printf("[Cleanup] ✓ Expired %d stale pending tasks (pending >48hrs)\n", count)
			} else if err != nil && cfg.Debug {
				fmt.Printf("[Cleanup] Warning: Failed to cleanup stale pending tasks: %v\n", err)
			}

			// Detect partial results (sent tasks with incomplete chunks after 6 hours)
			// Alerts operators to beacons that died mid-exfiltration
			if count, err := db.DetectPartialResults(6); err == nil && count > 0 {
				fmt.Printf("[Cleanup] Detected %d tasks with partial results (incomplete chunks >6hrs)\n", count)
			} else if err != nil && cfg.Debug {
				fmt.Printf("[Cleanup] Warning: Failed to detect partial results: %v\n", err)
			}

			// Cleanup expired and revoked sessions
			// Prevents session table bloat and ensures proper authentication state
			if count, err := db.CleanupExpiredSessions(); err == nil && count > 0 {
				fmt.Printf("[Cleanup] ✓ Removed %d expired/revoked sessions\n", count)
			} else if err != nil && cfg.Debug {
				fmt.Printf("[Cleanup] Warning: Failed to cleanup sessions: %v\n", err)
			}

			// Wait for next tick
			<-ticker.C
		}
	}()

	// Wait for interrupt signal for graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	fmt.Println("\nShutting down Archon Server...")

	// Create shutdown context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown HTTP server gracefully
	if err := srv.Shutdown(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Server shutdown error: %v\n", err)
	}

	// Close database connection
	if err := db.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "Database close error: %v\n", err)
	}

	fmt.Println("✓ Archon Server stopped gracefully")
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
		// Check if error string contains "UNIQUE constraint" or "constraint failed"
		errStr := err.Error()
		if strings.Contains(errStr, "UNIQUE constraint") || strings.Contains(errStr, "constraint failed") {
			fmt.Println("✓ Admin account already exists")
			return nil
		}
		return fmt.Errorf("failed to create admin account: %w", err)
	}

	fmt.Printf("✓ Created admin account: %s\n", cfg.AdminCredentials.Username)
	fmt.Printf("Default password is set - please change it after first login!\n")

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
			fmt.Printf("Warning: Failed to register DNS server %s: %v\n", dnsConfig.ID, err)
			continue
		}

		if cfg.Debug {
			fmt.Printf("✓ Registered DNS server: %s (%s)\n", dnsConfig.ID, dnsConfig.Domain)
		}
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
