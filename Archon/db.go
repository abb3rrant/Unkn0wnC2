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
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

const (
	// MasterDatabaseSchemaVersion tracks the current schema version
	MasterDatabaseSchemaVersion = 11
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
	db          *sql.DB
	mutex       sync.RWMutex
	taskCounter int // Auto-increment counter for task IDs (TXXXX format)
}

// NewMasterDatabase creates a new master database connection and initializes schema
func NewMasterDatabase(dbPath string) (*MasterDatabase, error) {
	if dbPath == "" {
		dbPath = "master.db"
	}

	// Open database connection
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool - CRITICAL for high-throughput operations
	// With batched result submissions, we need enough connections to handle:
	// - Multiple DNS servers submitting batches concurrently
	// - Operator API requests
	// - DNS server check-ins
	// - Task syncs
	db.SetMaxOpenConns(50)   // Increased from 10 for batched result handling
	db.SetMaxIdleConns(25)   // Keep more idle connections ready
	db.SetConnMaxLifetime(0) // No limit, reuse connections indefinitely

	database := &MasterDatabase{
		db: db,
	}

	// Initialize schema
	if err := database.initSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	dbLogAlways("Database initialized: %s\n", dbPath)
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

	// Record schema version
	_, err := d.db.Exec(`
		INSERT INTO schema_version (version, applied_at, description)
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
	d.mutex.RLock()
	defer d.mutex.RUnlock()

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
	d.mutex.Lock()
	defer d.mutex.Unlock()

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
			// All chunks received, trigger reassembly
			go func() {
				d.mutex.Lock()
				defer d.mutex.Unlock()
				d.reassembleTaskResultUnlocked(taskID, totalChunks)
				d.clearPendingCompletionUnlocked(taskID)
			}()
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

// clearPendingCompletionUnlocked removes pending completion tracking (must hold mutex)
func (d *MasterDatabase) clearPendingCompletionUnlocked(taskID string) {
	d.db.Exec(`DELETE FROM pending_task_completions WHERE task_id = ?`, taskID)
}

// reassembleTaskResultUnlocked attempts to reassemble a task result (must hold mutex)
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
	dbLogAlways("✓ Reassembled task %s from recovered chunks (%d bytes)\n", taskID, len(result))
}

// ReceiveMissingExfilChunks processes missing exfil chunks sent by a DNS server
func (d *MasterDatabase) ReceiveMissingExfilChunks(sessionID string, chunks map[int][]byte, dnsServerID string) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	for chunkIndex, data := range chunks {
		_, err := d.db.Exec(`
			INSERT OR IGNORE INTO exfil_chunks 
			(session_id, chunk_index, data, dns_server_id, received_at)
			VALUES (?, ?, ?, ?, ?)
		`, sessionID, chunkIndex, data, dnsServerID, time.Now().Unix())
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
			dbLogAlways("✓ All %d exfil chunks received for session %s from missing chunk recovery\n", totalChunks, sessionID)
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
	d.mutex.Lock()
	defer d.mutex.Unlock()

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
	d.mutex.RLock()
	defer d.mutex.RUnlock()

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
	d.mutex.Lock()
	defer d.mutex.Unlock()

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
func (d *MasterDatabase) GetDNSServers() ([]map[string]interface{}, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	rows, err := d.db.Query(`
		SELECT id, domain, address, status, first_seen, last_checkin, beacon_count, task_count
		FROM dns_servers
		ORDER BY domain ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var servers []map[string]interface{}
	for rows.Next() {
		var id, domain, address, status string
		var firstSeen, lastCheckin int64
		var beaconCount, taskCount int

		err := rows.Scan(&id, &domain, &address, &status, &firstSeen, &lastCheckin, &beaconCount, &taskCount)
		if err != nil {
			return nil, err
		}

		servers = append(servers, map[string]interface{}{
			"id":           id,
			"domain":       domain,
			"address":      address,
			"status":       status,
			"first_seen":   time.Unix(firstSeen, 0),
			"last_checkin": time.Unix(lastCheckin, 0),
			"beacon_count": beaconCount,
			"task_count":   taskCount,
		})
	}

	return servers, rows.Err()
}

// GetActiveDNSServers retrieves only active DNS servers
func (d *MasterDatabase) GetActiveDNSServers() ([]map[string]interface{}, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

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

	var servers []map[string]interface{}
	for rows.Next() {
		var id, domain, address, status string
		var firstSeen, lastCheckin int64
		var beaconCount, taskCount int

		err := rows.Scan(&id, &domain, &address, &status, &firstSeen, &lastCheckin, &beaconCount, &taskCount)
		if err != nil {
			return nil, err
		}

		servers = append(servers, map[string]interface{}{
			"id":           id,
			"domain":       domain,
			"address":      address,
			"status":       status,
			"first_seen":   time.Unix(firstSeen, 0),
			"last_checkin": time.Unix(lastCheckin, 0),
			"beacon_count": beaconCount,
			"task_count":   taskCount,
		})
	}

	return servers, rows.Err()
}

// Beacon operations

// UpsertBeacon inserts or updates a beacon (from DNS server reports)
func (d *MasterDatabase) UpsertBeacon(beaconID, hostname, username, os, arch, ipAddress, dnsServerID string, firstSeen, lastSeen time.Time) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	firstSeenUnix := firstSeen.Unix()
	lastSeenUnix := lastSeen.Unix()
	now := time.Now().Unix()

	// Try to insert first
	_, err := d.db.Exec(`
		INSERT INTO beacons (id, hostname, username, os, arch, ip_address, dns_server_id, first_seen, last_seen, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			hostname = excluded.hostname,
			username = excluded.username,
			os = excluded.os,
			arch = excluded.arch,
			ip_address = excluded.ip_address,
			dns_server_id = excluded.dns_server_id,
			last_seen = excluded.last_seen,
			status = 'active',
			updated_at = excluded.updated_at
	`, beaconID, hostname, username, os, arch, ipAddress, dnsServerID, firstSeenUnix, lastSeenUnix, now, now)

	return err
}

// RecordBeaconDNSContact tracks that a beacon contacted a specific DNS server
// This is called whenever a beacon checks in to a DNS server
func (d *MasterDatabase) RecordBeaconDNSContact(beaconID, dnsServerID, dnsDomain string) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	now := time.Now().Unix()

	// Upsert the contact record
	_, err := d.db.Exec(`
		INSERT INTO beacon_dns_contacts (beacon_id, dns_server_id, dns_domain, first_contact, last_contact, contact_count)
		VALUES (?, ?, ?, ?, ?, 1)
		ON CONFLICT(beacon_id, dns_server_id) DO UPDATE SET
			last_contact = excluded.last_contact,
			contact_count = contact_count + 1
	`, beaconID, dnsServerID, dnsDomain, now, now)

	return err
}

// GetBeaconDNSContacts retrieves all DNS servers a beacon has contacted
func (d *MasterDatabase) GetBeaconDNSContacts(beaconID string) ([]map[string]interface{}, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

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

	var contacts []map[string]interface{}
	for rows.Next() {
		var dnsServerID, dnsDomain, dnsStatus sql.NullString
		var firstContact, lastContact, contactCount int64

		err := rows.Scan(&dnsServerID, &dnsDomain, &firstContact, &lastContact, &contactCount, &dnsStatus)
		if err != nil {
			return nil, err
		}

		contacts = append(contacts, map[string]interface{}{
			"dns_server_id": dnsServerID.String,
			"dns_domain":    dnsDomain.String,
			"first_contact": time.Unix(firstContact, 0).Format(time.RFC3339),
			"last_contact":  time.Unix(lastContact, 0).Format(time.RFC3339),
			"contact_count": contactCount,
			"dns_status":    dnsStatus.String,
		})
	}

	return contacts, nil
}

// GetDNSServerBeacons retrieves all beacons that have contacted a specific DNS server
func (d *MasterDatabase) GetDNSServerBeacons(dnsServerID string, minutesThreshold int) ([]map[string]interface{}, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

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

	var beacons []map[string]interface{}
	for rows.Next() {
		var beaconID, hostname, username, os string
		var lastContact, contactCount int64

		err := rows.Scan(&beaconID, &hostname, &username, &os, &lastContact, &contactCount)
		if err != nil {
			return nil, err
		}

		beacons = append(beacons, map[string]interface{}{
			"beacon_id":     beaconID,
			"hostname":      hostname,
			"username":      username,
			"os":            os,
			"last_contact":  time.Unix(lastContact, 0).Format(time.RFC3339),
			"contact_count": contactCount,
		})
	}

	return beacons, nil
}

// GetActiveBeacons retrieves beacons active within the last N minutes
func (d *MasterDatabase) GetActiveBeacons(minutesThreshold int) ([]map[string]interface{}, error) {
	return d.GetActiveBeaconsPaginated(minutesThreshold, 0, 0)
}

// GetActiveBeaconsPaginated retrieves active beacons with pagination support
func (d *MasterDatabase) GetActiveBeaconsPaginated(minutesThreshold, limit, offset int) ([]map[string]interface{}, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	threshold := time.Now().Add(-time.Duration(minutesThreshold) * time.Minute).Unix()

	query := `
		SELECT id, hostname, username, os, arch, ip_address, dns_server_id, first_seen, last_seen, status
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

	var beacons []map[string]interface{}
	for rows.Next() {
		var id, hostname, username, os, arch, ipAddress, dnsServerID, status string
		var firstSeen, lastSeen int64

		err := rows.Scan(&id, &hostname, &username, &os, &arch, &ipAddress, &dnsServerID, &firstSeen, &lastSeen, &status)
		if err != nil {
			return nil, err
		}

		beacons = append(beacons, map[string]interface{}{
			"id":            id,
			"hostname":      hostname,
			"username":      username,
			"os":            os,
			"arch":          arch,
			"ip_address":    ipAddress,
			"dns_server_id": dnsServerID,
			"first_seen":    time.Unix(firstSeen, 0).Format(time.RFC3339),
			"last_seen":     time.Unix(lastSeen, 0).Format(time.RFC3339),
			"status":        status,
		})
	}

	return beacons, rows.Err()
}

// GetBeacon retrieves details for a specific beacon by ID
func (d *MasterDatabase) GetBeacon(beaconID string) (map[string]interface{}, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	var id, hostname, username, os, arch, ipAddress, dnsServerID, status string
	var firstSeen, lastSeen int64

	err := d.db.QueryRow(`
		SELECT id, hostname, username, os, arch, ip_address, dns_server_id, first_seen, last_seen, status
		FROM beacons
		WHERE id = ?
	`, beaconID).Scan(&id, &hostname, &username, &os, &arch, &ipAddress, &dnsServerID, &firstSeen, &lastSeen, &status)

	if err == sql.ErrNoRows {
		return nil, nil // Beacon not found
	}
	if err != nil {
		return nil, err
	}

	beacon := map[string]interface{}{
		"id":            id,
		"hostname":      hostname,
		"username":      username,
		"os":            os,
		"arch":          arch,
		"ip_address":    ipAddress,
		"dns_server_id": dnsServerID,
		"first_seen":    time.Unix(firstSeen, 0).Format(time.RFC3339),
		"last_seen":     time.Unix(lastSeen, 0).Format(time.RFC3339),
		"status":        status,
	}

	return beacon, nil
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
				dbLog("Task %s status: sent → exfiltrating (first chunk received)\n", taskID)
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

		if err != sql.ErrNoRows {
			// Already have complete result (probably from DNS server that assembled it)
			dbLog("Task %s already has complete result (id=%d), skipping reassembly\n", taskID, existingID)
			return nil
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
			dbLogAlways("✓ All %d chunks received for task %s, triggering async reassembly...\n", totalChunks, taskID)
			done := make(chan struct{})
			go func() {
				defer func() {
					if r := recover(); r != nil {
						dbLogAlways("❌ PANIC in reassembleChunkedResult for task %s: %v\n", taskID, r)
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
				dbLogAlways("⚠️  Reassembly timeout for task %s after 30s\n", taskID)
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
			dbLogAlways("⚠️  Warning: Task %s has %d chunks but expected %d (duplicate chunks from load balancing?)\n",
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

	if err != sql.ErrNoRows {
		// Already assembled, skip
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
		dbLogAlways("❌ Incomplete chunks for task %s: have %d unique chunks, need %d\n",
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
		// Ignore foreign key errors - 'master-assembled' is not a real DNS server
		if !strings.Contains(err.Error(), "FOREIGN KEY constraint failed") {
			dbLogAlways("❌ Error storing assembled result: %v\n", err)

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
		}
		return
	}

	// Mark task as completed
	d.markTaskCompleted(taskID)

	dbLogAlways("✅ Reassembly complete for task %s: %d chunks combined → %d bytes total\n",
		taskID, totalChunks, completeResult.Len())

	// Verify task status was updated
	var taskStatus string
	if err := d.db.QueryRow("SELECT status FROM tasks WHERE id = ?", taskID).Scan(&taskStatus); err == nil {
		dbLog("Task %s status is now: %s\n", taskID, taskStatus)
		if taskStatus != "completed" {
			dbLogAlways("⚠️  WARNING: Task %s status is '%s' instead of 'completed'!\n", taskID, taskStatus)
		}
	}
}

// GetTaskResult retrieves the complete result for a task
func (d *MasterDatabase) GetTaskResult(taskID string) (string, bool, error) {
	// NOTE: Caller must hold mutex (either RLock or Lock)
	// Do not acquire mutex here to avoid deadlock

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
	d.mutex.RLock()
	defer d.mutex.RUnlock()

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
	d.mutex.Lock()
	defer d.mutex.Unlock()

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
	originalSize, compressedSize, base64Size, chunkSize, totalChunks int, createdBy string) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	now := time.Now().Unix()

	// Convert empty string to NULL for created_by to avoid foreign key constraint issues
	var createdByVal interface{}
	if createdBy == "" {
		createdByVal = nil
	} else {
		createdByVal = createdBy
	}

	fmt.Printf("[DB] Saving client binary: id=%s, filename=%s, os=%s, arch=%s, chunks=%d\n",
		id, filename, os, arch, totalChunks)

	_, err := d.db.Exec(`
		INSERT INTO client_binaries (id, filename, os, arch, version, original_size, compressed_size, 
			base64_size, chunk_size, total_chunks, base64_data, dns_domains, created_at, created_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, id, filename, os, arch, version, originalSize, compressedSize, base64Size, chunkSize,
		totalChunks, base64Data, dnsDomains, now, createdByVal)

	if err != nil {
		fmt.Printf("[DB] ERROR saving client binary: %v\n", err)
		return err
	}

	fmt.Printf("[DB] ✓ Client binary saved successfully: %s\n", id)
	return nil
}

// GetClientBinaries retrieves all stored client binaries
func (d *MasterDatabase) GetClientBinaries() ([]map[string]interface{}, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

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

	var binaries []map[string]interface{}
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

		binaries = append(binaries, map[string]interface{}{
			"id":              id,
			"filename":        filename,
			"os":              os,
			"arch":            arch,
			"version":         version,
			"original_size":   originalSize,
			"compressed_size": compressedSize,
			"base64_size":     base64Size,
			"chunk_size":      chunkSize,
			"total_chunks":    totalChunks,
			"dns_domains":     dnsDomains,
			"created_at":      createdAt,
			"created_by":      createdByStr,
		})
	}

	fmt.Printf("[DB] Query complete: found %d binaries\n", len(binaries))
	return binaries, rows.Err()
}

// GetClientBinary retrieves a specific client binary by ID
func (d *MasterDatabase) GetClientBinary(id string) (map[string]interface{}, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	var filename, os, arch, version, base64Data, dnsDomains, createdBy string
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
		return nil, err
	}

	return map[string]interface{}{
		"id":              id,
		"filename":        filename,
		"os":              os,
		"arch":            arch,
		"version":         version,
		"original_size":   originalSize,
		"compressed_size": compressedSize,
		"base64_size":     base64Size,
		"chunk_size":      chunkSize,
		"total_chunks":    totalChunks,
		"base64_data":     base64Data,
		"dns_domains":     dnsDomains,
		"created_at":      createdAt,
		"created_by":      createdBy,
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

	d.mutex.Lock()
	defer d.mutex.Unlock()

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

	d.mutex.RLock()
	defer d.mutex.RUnlock()

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
	d.mutex.Lock()
	defer d.mutex.Unlock()

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
	d.mutex.Lock()
	defer d.mutex.Unlock()

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
	d.mutex.RLock()
	defer d.mutex.RUnlock()

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

	d.mutex.RLock()
	defer d.mutex.RUnlock()

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
	d.mutex.Lock()
	defer d.mutex.Unlock()

	_, err := d.db.Exec("DELETE FROM client_binaries WHERE id = ?", id)
	return err
}

// Stager Session operations

// CreateStagerSession creates a new stager deployment session
func (d *MasterDatabase) CreateStagerSession(id, stagerIP, os, arch, clientBinaryID, initiatedByDNS string, totalChunks int) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

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
	d.mutex.Lock()
	defer d.mutex.Unlock()

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
func (d *MasterDatabase) GetStagerSession(sessionID string) (map[string]interface{}, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

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
		return nil, err
	}

	return map[string]interface{}{
		"id":               id,
		"stager_ip":        stagerIP,
		"os":               os,
		"arch":             arch,
		"client_binary_id": clientBinaryID,
		"total_chunks":     totalChunks,
		"chunks_delivered": chunksDelivered,
		"initiated_by_dns": initiatedByDNS,
		"created_at":       createdAt,
		"last_activity":    lastActivity,
		"completed":        completed,
		"completed_at":     completedAt,
	}, nil
}

// GetCachedChunkCount returns the number of cached chunks for a client binary
func (d *MasterDatabase) GetCachedChunkCount(clientBinaryID string) (int, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

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
	d.mutex.Lock()
	defer d.mutex.Unlock()

	now := time.Now().Unix()
	_, err := d.db.Exec("UPDATE stager_sessions SET last_activity = ? WHERE id = ?", now, sessionID)
	return err
}

// CompleteStagerSession marks a stager session as completed
func (d *MasterDatabase) CompleteStagerSession(sessionID string) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

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
	d.mutex.Lock()
	defer d.mutex.Unlock()

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
	d.mutex.Lock()
	defer d.mutex.Unlock()

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
	d.mutex.Lock()
	defer d.mutex.Unlock()

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
	d.mutex.RLock()
	defer d.mutex.RUnlock()

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
	d.mutex.Lock()
	defer d.mutex.Unlock()

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
func (d *MasterDatabase) GetStagerChunksForDNSServer(sessionID, dnsServerID string) ([]map[string]interface{}, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

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

	var chunks []map[string]interface{}
	for rows.Next() {
		var chunkIndex, delivered int
		var chunkData string
		var deliveredAt int64

		if err := rows.Scan(&chunkIndex, &chunkData, &delivered, &deliveredAt); err != nil {
			continue
		}

		chunks = append(chunks, map[string]interface{}{
			"chunk_index":  chunkIndex,
			"chunk_data":   chunkData,
			"delivered":    delivered,
			"delivered_at": deliveredAt,
		})
	}

	return chunks, rows.Err()
}

// GetStagerSessions retrieves all stager sessions
func (d *MasterDatabase) GetStagerSessions(limit int) ([]map[string]interface{}, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

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

	var sessions []map[string]interface{}
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

		session := map[string]interface{}{
			"id":               id,
			"stager_ip":        stagerIP,
			"os":               os,
			"arch":             arch,
			"total_chunks":     totalChunks,
			"chunks_delivered": chunksDelivered,
			"created_at":       createdAt,
			"last_activity":    lastActivity,
			"completed":        completed == 1,
		}

		if initiatedByDNS.Valid {
			session["initiated_by_dns"] = initiatedByDNS.String
		}
		if completedAt.Valid {
			session["completed_at"] = completedAt.Int64
		}
		if filename.Valid {
			session["client_filename"] = filename.String
		}
		if version.Valid {
			session["client_version"] = version.String
		}

		sessions = append(sessions, session)
	}

	return sessions, rows.Err()
}

// Operator operations

// CreateOperator creates a new operator account
func (d *MasterDatabase) CreateOperator(id, username, password, role, email string) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

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
	d.mutex.RLock()
	defer d.mutex.RUnlock()

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
		d.mutex.Lock()
		defer d.mutex.Unlock()
		d.db.Exec(`
			UPDATE operators SET last_login = ?, login_count = login_count + 1 WHERE id = ?
		`, time.Now().Unix(), id)
	}()

	return id, role, nil
}

// GetAllOperators returns all operator accounts
func (d *MasterDatabase) GetAllOperators() ([]map[string]interface{}, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	rows, err := d.db.Query(`
		SELECT id, username, role, email, created_at, last_login, login_count, is_active
		FROM operators
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var operators []map[string]interface{}
	for rows.Next() {
		var id, username, role string
		var email sql.NullString
		var createdAt, loginCount int64
		var lastLogin sql.NullInt64
		var isActive int

		if err := rows.Scan(&id, &username, &role, &email, &createdAt, &lastLogin, &loginCount, &isActive); err != nil {
			continue
		}

		operator := map[string]interface{}{
			"id":          id,
			"username":    username,
			"role":        role,
			"email":       email.String,
			"created_at":  time.Unix(createdAt, 0).Format(time.RFC3339),
			"login_count": loginCount,
			"is_active":   isActive == 1,
		}

		if lastLogin.Valid {
			operator["last_login"] = time.Unix(lastLogin.Int64, 0).Format(time.RFC3339)
		} else {
			operator["last_login"] = nil
		}

		operators = append(operators, operator)
	}

	return operators, nil
}

// GetOperator retrieves a single operator by ID
func (d *MasterDatabase) GetOperator(operatorID string) (map[string]interface{}, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

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
			return nil, fmt.Errorf("operator not found")
		}
		return nil, err
	}

	operator := map[string]interface{}{
		"id":          id,
		"username":    username,
		"role":        role,
		"email":       email.String,
		"created_at":  time.Unix(createdAt, 0).Format(time.RFC3339),
		"login_count": loginCount,
		"is_active":   isActive == 1,
	}

	if lastLogin.Valid {
		operator["last_login"] = time.Unix(lastLogin.Int64, 0).Format(time.RFC3339)
	} else {
		operator["last_login"] = nil
	}

	return operator, nil
}

// UpdateOperator updates operator details (not password)
func (d *MasterDatabase) UpdateOperator(operatorID, username, role, email string) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	_, err := d.db.Exec(`
		UPDATE operators 
		SET username = ?, role = ?, email = ?
		WHERE id = ?
	`, username, role, email, operatorID)

	return err
}

// UpdateOperatorPassword changes an operator's password
func (d *MasterDatabase) UpdateOperatorPassword(operatorID, newPassword string) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

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
	d.mutex.Lock()
	defer d.mutex.Unlock()

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
	d.mutex.Lock()
	defer d.mutex.Unlock()

	_, err := d.db.Exec(`DELETE FROM operators WHERE id = ?`, operatorID)
	return err
}

// CheckUsernameExists checks if a username is already taken
func (d *MasterDatabase) CheckUsernameExists(username string) (bool, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

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
	d.mutex.Lock()
	defer d.mutex.Unlock()

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
// Must be called with mutex held by caller
func (d *MasterDatabase) generateTaskID() string {
	d.taskCounter++
	return fmt.Sprintf("T%04d", d.taskCounter)
}

// GetEnabledDNSDomains returns a list of all enabled DNS domains
func (d *MasterDatabase) GetEnabledDNSDomains() ([]string, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

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
	d.mutex.Lock()
	defer d.mutex.Unlock()

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

	// Create task WITHOUT assigned_dns_server (available to all)
	_, err = d.db.Exec(`
		INSERT INTO tasks (id, beacon_id, command, status, created_by, created_at, updated_at)
		VALUES (?, ?, ?, 'pending', ?, ?, ?)
	`, taskID, beaconID, command, createdBy, now, now)

	if err != nil {
		return "", fmt.Errorf("failed to create task: %w", err)
	}

	return taskID, nil
}

// GetTasksForDNSServer retrieves pending tasks for beacons that have contacted this DNS server
// Returns ALL pending tasks regardless of which server will deliver them (Shadow Mesh)
func (d *MasterDatabase) GetTasksForDNSServer(dnsServerID string) ([]map[string]interface{}, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	// Get ALL pending tasks for beacons that have ever contacted this DNS server
	// This allows any DNS server to deliver tasks for beacons in its rotation
	rows, err := d.db.Query(`
		SELECT DISTINCT t.id, t.beacon_id, t.command, t.status, t.created_at
		FROM tasks t
		INNER JOIN beacon_dns_contacts bdc ON t.beacon_id = bdc.beacon_id
		WHERE bdc.dns_server_id = ? 
		  AND t.status = 'pending'
		ORDER BY t.created_at ASC
	`, dnsServerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []map[string]interface{}
	for rows.Next() {
		var id, beaconID, command, status string
		var createdAt int64

		if err := rows.Scan(&id, &beaconID, &command, &status, &createdAt); err != nil {
			continue
		}

		tasks = append(tasks, map[string]interface{}{
			"id":         id,
			"beacon_id":  beaconID,
			"command":    command,
			"status":     status,
			"created_at": time.Unix(createdAt, 0).Format(time.RFC3339),
		})
	}

	return tasks, rows.Err()
}

// GetCompletedTasksForSync retrieves completed/failed/partial tasks for DNS server sync
// This allows DNS servers to clear beacon.CurrentTask when Master completes task reassembly
func (d *MasterDatabase) GetCompletedTasksForSync(dnsServerID string) ([]map[string]interface{}, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	// Get ALL task status changes (sent/exfiltrating/completed/failed/partial)
	// This ensures all DNS servers stay synchronized even when beacons rotate
	rows, err := d.db.Query(`
		SELECT id, beacon_id, status
		FROM tasks
		WHERE assigned_dns_server = ? 
		  AND status != 'pending'
		  AND (synced_at IS NULL OR synced_at < updated_at)
		ORDER BY updated_at ASC
		LIMIT 100
	`, dnsServerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []map[string]interface{}
	for rows.Next() {
		var id, beaconID, status string

		if err := rows.Scan(&id, &beaconID, &status); err != nil {
			continue
		}

		tasks = append(tasks, map[string]interface{}{
			"id":        id,
			"beacon_id": beaconID,
			"status":    status,
		})
	}

	return tasks, rows.Err()
}

// MarkTasksAsSynced marks tasks as synced to DNS servers (so we don't send them again)
func (d *MasterDatabase) MarkTasksAsSynced(taskIDs []string) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if len(taskIDs) == 0 {
		return nil
	}

	// Build placeholders for SQL IN clause
	placeholders := make([]string, len(taskIDs))
	args := make([]interface{}, len(taskIDs))
	for i, id := range taskIDs {
		placeholders[i] = "?"
		args[i] = id
	}

	query := fmt.Sprintf(`
		UPDATE tasks 
		SET synced_at = ?
		WHERE id IN (%s)
	`, strings.Join(placeholders, ","))

	// Prepend the timestamp to args
	args = append([]interface{}{time.Now().Unix()}, args...)

	_, err := d.db.Exec(query, args...)
	return err
}

// GetAllTasks retrieves all tasks with their status
func (d *MasterDatabase) GetAllTasks(limit int) ([]map[string]interface{}, error) {
	return d.GetAllTasksPaginated(limit, 0)
}

// GetAllTasksPaginated retrieves tasks with pagination support
func (d *MasterDatabase) GetAllTasksPaginated(limit, offset int) ([]map[string]interface{}, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

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

	var tasks []map[string]interface{}
	for rows.Next() {
		var id, beaconID, command, status string
		var hostname, username, os sql.NullString
		var createdAt int64
		var completedAt sql.NullInt64

		if err := rows.Scan(&id, &beaconID, &command, &status, &createdAt, &completedAt,
			&hostname, &username, &os); err != nil {
			continue
		}

		task := map[string]interface{}{
			"id":         id,
			"beacon_id":  beaconID,
			"command":    command,
			"status":     status,
			"created_at": time.Unix(createdAt, 0).Format(time.RFC3339),
		}

		if completedAt.Valid {
			task["completed_at"] = time.Unix(completedAt.Int64, 0).Format(time.RFC3339)
		}

		if hostname.Valid {
			task["hostname"] = hostname.String
		}
		if username.Valid {
			task["username"] = username.String
		}
		if os.Valid {
			task["os"] = os.String
		}

		// Add progress for in-progress tasks (sent/exfiltrating)
		if status == "sent" || status == "exfiltrating" {
			progress, err := d.GetTaskProgressFromResults(id)
			if err == nil && progress != nil {
				task["progress"] = progress
			}
		}

		tasks = append(tasks, task)
	}

	return tasks, rows.Err()
}

// CountActiveBeacons returns the total count of active beacons
func (d *MasterDatabase) CountActiveBeacons(minutesThreshold int) (int, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

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
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	var count int
	err := d.db.QueryRow("SELECT COUNT(*) FROM tasks").Scan(&count)
	return count, err
}

// GetTaskWithResult retrieves a task and its result if completed
func (d *MasterDatabase) GetTaskWithResult(taskID string) (map[string]interface{}, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

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
			return nil, fmt.Errorf("task not found")
		}
		return nil, err
	}

	task := map[string]interface{}{
		"id":        id,
		"beacon_id": beaconID,
		"command":   command,
		"status":    status,
	}

	if createdBy.Valid {
		task["created_by"] = createdBy.String
	}
	if createdAt.Valid {
		task["created_at"] = time.Unix(createdAt.Int64, 0).Format(time.RFC3339)
	}
	if sentAt.Valid {
		task["sent_at"] = time.Unix(sentAt.Int64, 0).Format(time.RFC3339)
	}
	if completedAt.Valid {
		task["completed_at"] = time.Unix(completedAt.Int64, 0).Format(time.RFC3339)
	}

	// Get result if task is completed
	if status == "completed" {
		result, isComplete, err := d.GetTaskResult(taskID)
		if err == nil && isComplete {
			task["result"] = result
			task["result_size"] = len(result)
		}
	} else if status == "sent" || status == "exfiltrating" {
		// Task is in progress, calculate progress from actual received chunks
		progress, err := d.GetTaskProgressFromResults(taskID)
		if err == nil && progress != nil {
			task["progress"] = progress
		}
	}

	return task, nil
}

// MarkTasksSent marks tasks as 'sent' after they are retrieved by a DNS server
func (d *MasterDatabase) MarkTasksSent(taskIDs []string) error {
	if len(taskIDs) == 0 {
		return nil
	}

	d.mutex.Lock()
	defer d.mutex.Unlock()

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
	d.mutex.Lock()
	defer d.mutex.Unlock()

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
func (d *MasterDatabase) GetTaskProgress(taskID string) (map[string]interface{}, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

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
		return map[string]interface{}{
			"task_id":         taskID,
			"received_chunks": 0,
			"total_chunks":    0,
			"progress":        0,
			"status":          "pending",
		}, nil
	}
	if err != nil {
		return nil, err
	}

	progress := 0
	if totalExpected > 0 {
		progress = (totalReceived * 100) / totalExpected
		if progress > 100 {
			progress = 100 // Cap at 100% in case of duplicates
		}
	}

	return map[string]interface{}{
		"task_id":         taskID,
		"received_chunks": totalReceived,
		"total_chunks":    totalExpected,
		"progress":        progress,
		"status":          status,
	}, nil
}

// GetTaskProgressFromResults calculates actual progress from task_results table
// This is the authoritative source for progress as it reflects what the Master has received
// With distributed chunks, this aggregates data from all DNS servers
func (d *MasterDatabase) GetTaskProgressFromResults(taskID string) (map[string]interface{}, error) {
	// NOTE: Caller must hold mutex (either RLock or Lock)
	// Do not acquire mutex here to avoid deadlock

	// First check if we have a complete result
	var completeExists int
	err := d.db.QueryRow(`
		SELECT COUNT(*) FROM task_results
		WHERE task_id = ? AND chunk_index = 0 AND is_complete = 1
	`, taskID).Scan(&completeExists)

	if err != nil {
		return nil, err
	}

	if completeExists > 0 {
		// Task is complete
		return map[string]interface{}{
			"task_id":         taskID,
			"received_chunks": -1, // Not applicable for complete
			"total_chunks":    -1,
			"progress":        100,
			"status":          "complete",
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
		return nil, err
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
		return map[string]interface{}{
			"task_id":         taskID,
			"received_chunks": 0,
			"total_chunks":    0,
			"progress":        0,
			"status":          "pending",
		}, nil
	}

	// Count unique chunks received (excluding metadata chunk at index 0)
	var receivedChunks int
	err = d.db.QueryRow(`
		SELECT COUNT(DISTINCT chunk_index) FROM task_results
		WHERE task_id = ? AND chunk_index > 0
	`, taskID).Scan(&receivedChunks)

	if err != nil {
		return nil, err
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

	return map[string]interface{}{
		"task_id":         taskID,
		"received_chunks": receivedChunks,
		"total_chunks":    int(totalExpected.Int64),
		"progress":        progress,
		"status":          status,
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
			dbLogAlways("✓ Task %s marked as completed\n", taskID)
		}
	}
}

// MarkTaskCompleteFromBeacon is called when DNS server receives RESULT_COMPLETE message
// This signals that the beacon has finished sending all chunks successfully
// For multi-chunk results, this triggers final reassembly if not already done
func (d *MasterDatabase) MarkTaskCompleteFromBeacon(taskID, beaconID string, totalChunks int) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

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

			dbLogAlways("✓ Task %s assembled and marked as completed (%d bytes)\n", taskID, len(assembledResult))
			d.clearPendingCompletion(taskID)
		} else {
			dbLog("Waiting for remaining chunks for task %s (%d/%d received)\n", taskID, receivedChunks, totalChunks)
			// Return success - we'll wait for more chunks to arrive
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
			if err.Error() == "sql: no rows in result set" {
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

		dbLogAlways("✓ Task %s marked as completed (%d bytes)\n", taskID, resultSize)
		d.clearPendingCompletion(taskID)
	}

	return nil
}

// LogAuditEvent logs an operator action to the audit log
func (d *MasterDatabase) LogAuditEvent(operatorID, action, targetType, targetID, details, ipAddress string) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	_, err := d.db.Exec(`
		INSERT INTO audit_log (operator_id, action, target_type, target_id, details, ip_address, timestamp)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, operatorID, action, targetType, targetID, details, ipAddress, time.Now().Unix())

	return err
}

// GetDatabaseStats returns master database statistics
func (d *MasterDatabase) GetDatabaseStats() (map[string]interface{}, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	stats := make(map[string]interface{})

	// Count DNS servers
	var dnsServerCount, activeDNSServerCount int
	if err := d.db.QueryRow("SELECT COUNT(*) FROM dns_servers").Scan(&dnsServerCount); err != nil {
		dnsServerCount = 0
	}
	if err := d.db.QueryRow("SELECT COUNT(*) FROM dns_servers WHERE status = 'active'").Scan(&activeDNSServerCount); err != nil {
		activeDNSServerCount = 0
	}
	stats["dns_servers"] = dnsServerCount
	stats["active_dns_servers"] = activeDNSServerCount

	// Count beacons
	var beaconCount, activeBeaconCount int
	if err := d.db.QueryRow("SELECT COUNT(*) FROM beacons").Scan(&beaconCount); err != nil {
		beaconCount = 0
	}
	cutoff := time.Now().Add(-24 * time.Hour).Unix()
	if err := d.db.QueryRow("SELECT COUNT(*) FROM beacons WHERE last_seen > ? AND status = 'active'", cutoff).Scan(&activeBeaconCount); err != nil {
		activeBeaconCount = 0
	}
	stats["beacons"] = beaconCount
	stats["active_beacons"] = activeBeaconCount

	// Count tasks
	var taskCount int
	if err := d.db.QueryRow("SELECT COUNT(*) FROM tasks").Scan(&taskCount); err != nil {
		taskCount = 0
	}
	stats["tasks"] = taskCount

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
		stats["tasks_by_status"] = tasksByStatus
	}

	// Count operators
	var operatorCount int
	if err := d.db.QueryRow("SELECT COUNT(*) FROM operators WHERE is_active = 1").Scan(&operatorCount); err != nil {
		operatorCount = 0
	}
	stats["operators"] = operatorCount

	// Recent audit events
	var auditEventCount int
	if err := d.db.QueryRow("SELECT COUNT(*) FROM audit_log WHERE timestamp > ?", cutoff).Scan(&auditEventCount); err != nil {
		auditEventCount = 0
	}
	stats["recent_audit_events"] = auditEventCount

	// Count stager sessions
	var stagerSessionCount, completedStagerCount int
	if err := d.db.QueryRow("SELECT COUNT(*) FROM stager_sessions").Scan(&stagerSessionCount); err != nil {
		stagerSessionCount = 0
	}
	if err := d.db.QueryRow("SELECT COUNT(*) FROM stager_sessions WHERE completed = 1").Scan(&completedStagerCount); err != nil {
		completedStagerCount = 0
	}
	stats["stager_sessions"] = stagerSessionCount
	stats["completed_stager_sessions"] = completedStagerCount

	// Count exfil transfers
	var exfilTransferCount, completedExfilCount int
	if err := d.db.QueryRow("SELECT COUNT(*) FROM exfil_transfers").Scan(&exfilTransferCount); err != nil {
		exfilTransferCount = 0
	}
	if err := d.db.QueryRow("SELECT COUNT(*) FROM exfil_transfers WHERE status = 'complete'").Scan(&completedExfilCount); err != nil {
		completedExfilCount = 0
	}
	stats["exfil_transfers"] = exfilTransferCount
	stats["completed_exfil_transfers"] = completedExfilCount

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
	d.mutex.RLock()
	defer d.mutex.RUnlock()

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
	d.mutex.Lock()
	defer d.mutex.Unlock()

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
func (d *MasterDatabase) GetPendingStagerCaches(dnsServerID string) ([]map[string]interface{}, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

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

	var caches []map[string]interface{}
	for rows.Next() {
		var id int
		var clientBinaryID, base64Data string
		var totalChunks int

		if err := rows.Scan(&id, &clientBinaryID, &base64Data, &totalChunks); err != nil {
			return nil, err
		}

		// Split base64 data into chunks (DNS-safe size)
		const chunkSize = 370
		var chunks []string
		for i := 0; i < len(base64Data); i += chunkSize {
			end := i + chunkSize
			if end > len(base64Data) {
				end = len(base64Data)
			}
			chunks = append(chunks, base64Data[i:end])
		}

		caches = append(caches, map[string]interface{}{
			"id":               id,
			"client_binary_id": clientBinaryID,
			"total_chunks":     totalChunks,
			"chunks":           chunks,
		})
	}

	return caches, rows.Err()
}

// MarkStagerCacheDelivered marks cache tasks as delivered
func (d *MasterDatabase) MarkStagerCacheDelivered(cacheIDs []int) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

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
	d.mutex.Lock()
	defer d.mutex.Unlock()

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
	d.mutex.RLock()
	defer d.mutex.RUnlock()

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
	d.mutex.Lock()
	defer d.mutex.Unlock()

	_, err := d.db.Exec(`
UPDATE domain_updates
SET delivered = 1
WHERE dns_server_id = ? AND delivered = 0
`, dnsServerID)

	return err
}

// GetAllActiveDomains returns all domains from active DNS servers
func (d *MasterDatabase) GetAllActiveDomains() ([]string, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

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
func (d *MasterDatabase) GetAllDNSServers() ([]map[string]interface{}, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	rows, err := d.db.Query(`
SELECT id, domain, status FROM dns_servers
WHERE status = 'active'
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var servers []map[string]interface{}
	for rows.Next() {
		var id, domain, status string
		if err := rows.Scan(&id, &domain, &status); err != nil {
			return nil, err
		}
		servers = append(servers, map[string]interface{}{
			"id":     id,
			"domain": domain,
			"status": status,
		})
	}

	return servers, rows.Err()
}

// DeleteTask removes a task and its associated data (results, progress)
// This allows operators to cancel pending tasks or clean up completed/failed tasks
func (d *MasterDatabase) DeleteTask(taskID string) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

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
	d.mutex.Lock()
	defer d.mutex.Unlock()

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
	d.mutex.Lock()
	defer d.mutex.Unlock()

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

// CleanupOldTasks removes completed/failed tasks older than the specified days
// This helps maintain database performance and reduces disk usage
func (d *MasterDatabase) CleanupOldTasks(olderThanDays int) (int, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	cutoff := time.Now().AddDate(0, 0, -olderThanDays).Unix()

	// Get task IDs to delete
	rows, err := d.db.Query(`
		SELECT id FROM tasks 
		WHERE (status = 'complete' OR status = 'failed' OR status = 'timeout')
		AND completed_at < ?
	`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("failed to query old tasks: %w", err)
	}

	var taskIDs []string
	for rows.Next() {
		var taskID string
		if err := rows.Scan(&taskID); err != nil {
			rows.Close()
			return 0, fmt.Errorf("failed to scan task ID: %w", err)
		}
		taskIDs = append(taskIDs, taskID)
	}
	rows.Close()

	if len(taskIDs) == 0 {
		return 0, nil
	}

	// Delete in transaction
	tx, err := d.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	count := 0
	for _, taskID := range taskIDs {
		// Delete task results
		if _, err := tx.Exec("DELETE FROM task_results WHERE task_id = ?", taskID); err != nil {
			return count, fmt.Errorf("failed to delete task results: %w", err)
		}

		// Delete task progress
		if _, err := tx.Exec("DELETE FROM task_progress WHERE task_id = ?", taskID); err != nil {
			return count, fmt.Errorf("failed to delete task progress: %w", err)
		}

		// Delete the task
		result, err := tx.Exec("DELETE FROM tasks WHERE id = ?", taskID)
		if err != nil {
			return count, fmt.Errorf("failed to delete task: %w", err)
		}

		rows, _ := result.RowsAffected()
		count += int(rows)
	}

	if err := tx.Commit(); err != nil {
		return count, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return count, nil
}

// CleanupInactiveBeacons removes beacons that haven't checked in for the specified days
// This helps clean up orphaned beacons from compromised/decommissioned systems
func (d *MasterDatabase) CleanupInactiveBeacons(inactiveDays int) (int, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	cutoff := time.Now().AddDate(0, 0, -inactiveDays).Unix()

	// Get beacon IDs to delete (only inactive status)
	rows, err := d.db.Query(`
		SELECT id FROM beacons 
		WHERE last_seen < ? AND status != 'active'
	`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("failed to query inactive beacons: %w", err)
	}

	var beaconIDs []string
	for rows.Next() {
		var beaconID string
		if err := rows.Scan(&beaconID); err != nil {
			rows.Close()
			return 0, fmt.Errorf("failed to scan beacon ID: %w", err)
		}
		beaconIDs = append(beaconIDs, beaconID)
	}
	rows.Close()

	if len(beaconIDs) == 0 {
		return 0, nil
	}

	// Delete in transaction
	tx, err := d.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	count := 0
	for _, beaconID := range beaconIDs {
		// Get task IDs for cleanup
		taskRows, err := tx.Query("SELECT id FROM tasks WHERE beacon_id = ?", beaconID)
		if err != nil {
			return count, fmt.Errorf("failed to query tasks: %w", err)
		}

		var taskIDs []string
		for taskRows.Next() {
			var taskID string
			if err := taskRows.Scan(&taskID); err != nil {
				taskRows.Close()
				return count, fmt.Errorf("failed to scan task ID: %w", err)
			}
			taskIDs = append(taskIDs, taskID)
		}
		taskRows.Close()

		// Delete task data
		for _, taskID := range taskIDs {
			if _, err := tx.Exec("DELETE FROM task_results WHERE task_id = ?", taskID); err != nil {
				return count, fmt.Errorf("failed to delete task results: %w", err)
			}
			if _, err := tx.Exec("DELETE FROM task_progress WHERE task_id = ?", taskID); err != nil {
				return count, fmt.Errorf("failed to delete task progress: %w", err)
			}
		}

		// Delete tasks
		if _, err := tx.Exec("DELETE FROM tasks WHERE beacon_id = ?", beaconID); err != nil {
			return count, fmt.Errorf("failed to delete tasks: %w", err)
		}

		// Delete beacon
		result, err := tx.Exec("DELETE FROM beacons WHERE id = ?", beaconID)
		if err != nil {
			return count, fmt.Errorf("failed to delete beacon: %w", err)
		}

		rows, _ := result.RowsAffected()
		count += int(rows)
	}

	if err := tx.Commit(); err != nil {
		return count, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return count, nil
}

// CleanupCompletedStagerSessions removes completed stager sessions older than specified days
func (d *MasterDatabase) CleanupCompletedStagerSessions(olderThanDays int) (int, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

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
	d.mutex.Lock()
	defer d.mutex.Unlock()

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

// Session Management

// CreateSession stores a new JWT session in the database
func (d *MasterDatabase) CreateSession(sessionID, operatorID, jti, tokenHash, ipAddress, userAgent string, expiresAt int64) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	now := time.Now().Unix()

	_, err := d.db.Exec(`
		INSERT INTO sessions (id, operator_id, jti, token_hash, created_at, expires_at, last_activity, ip_address, user_agent, is_revoked)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
	`, sessionID, operatorID, jti, tokenHash, now, expiresAt, now, ipAddress, userAgent)

	return err
}

// IsSessionRevoked checks if a session with the given JTI is revoked
func (d *MasterDatabase) IsSessionRevoked(jti string) (bool, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	var isRevoked bool
	err := d.db.QueryRow(`
		SELECT is_revoked FROM sessions WHERE jti = ?
	`, jti).Scan(&isRevoked)

	if err == sql.ErrNoRows {
		// Session doesn't exist in DB - treat as not revoked (allows backward compatibility)
		return false, nil
	}

	return isRevoked, err
}

// RevokeSessionByJTI marks a session as revoked by its JTI
func (d *MasterDatabase) RevokeSessionByJTI(jti string) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	_, err := d.db.Exec(`
		UPDATE sessions SET is_revoked = 1 WHERE jti = ?
	`, jti)

	return err
}

// CleanupExpiredSessions removes expired and revoked sessions from the database
// This prevents session table bloat and ensures proper authentication state
func (d *MasterDatabase) CleanupExpiredSessions() (int, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	now := time.Now().Unix()

	// Delete sessions that are expired OR revoked
	result, err := d.db.Exec(`
		DELETE FROM sessions
		WHERE expires_at < ? OR is_revoked = 1
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
	d.mutex.Lock()
	defer d.mutex.Unlock()

	cutoff := time.Now().Add(-time.Duration(sentHours) * time.Hour).Unix()

	// Find tasks that have been 'sent' for too long with incomplete chunks
	// A task is incomplete if: total_chunks > 0 AND received_chunks < total_chunks
	result, err := d.db.Exec(`
		UPDATE tasks 
		SET status = 'partial',
		    completed_at = ?
		WHERE status = 'sent'
		  AND delivered_at < ?
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
