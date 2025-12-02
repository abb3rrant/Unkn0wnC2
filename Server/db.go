// Package main implements the database layer for the Unkn0wnC2 server.
// This provides persistent storage for beacons, tasks, and results using SQLite.
package main

import (
	"database/sql"
	"fmt"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const (
	// DatabaseFileName is the default database file name
	DatabaseFileName = "c2_data.db"

	// DatabaseSchemaVersion tracks the current schema version
	DatabaseSchemaVersion = 3
)

// Database wraps the SQL database connection and provides C2-specific operations
type Database struct {
	db    *sql.DB
	mutex sync.RWMutex
}

// ExfilSessionRecord represents the persisted metadata for a dedicated exfiltration session
type ExfilSessionRecord struct {
	SessionID      string
	JobID          string
	FileName       string
	FileSize       int64
	TotalChunks    int
	ReceivedChunks int
	Status         string
	Note           string
	ClientIP       string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	LastChunkAt    time.Time
}

// NewDatabase creates a new database connection and initializes the schema
func NewDatabase(dbPath string) (*Database, error) {
	if dbPath == "" {
		dbPath = DatabaseFileName
	}

	// Open database connection
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(1) // SQLite works best with single writer
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	database := &Database{
		db: db,
	}

	// Initialize schema
	if err := database.initSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	logf("[DB] Database initialized: %s", dbPath)
	return database, nil
}

// Close closes the database connection
func (d *Database) Close() error {
	if d.db != nil {
		return d.db.Close()
	}
	return nil
}

// initSchema creates the database schema if it doesn't exist
func (d *Database) initSchema() error {
	// Enable foreign keys and WAL mode
	pragmas := []string{
		"PRAGMA foreign_keys = ON",
		"PRAGMA journal_mode = WAL",
		"PRAGMA synchronous = NORMAL",
		"PRAGMA cache_size = -64000",
		"PRAGMA auto_vacuum = INCREMENTAL",
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
	if currentVersion < DatabaseSchemaVersion {
		if err := d.applyMigrations(currentVersion); err != nil {
			return fmt.Errorf("failed to apply migrations: %w", err)
		}
	}

	return nil
}

// applyMigrations applies database schema migrations
func (d *Database) applyMigrations(fromVersion int) error {
	logf("[DB] Applying migrations from version %d to %d", fromVersion, DatabaseSchemaVersion)

	// Migration 1: Initial schema
	if fromVersion < 1 {
		if err := d.migration1InitialSchema(); err != nil {
			return fmt.Errorf("migration 1 failed: %w", err)
		}
	}

	if fromVersion < 2 {
		if err := d.migration2ExfilSchema(); err != nil {
			return fmt.Errorf("migration 2 failed: %w", err)
		}
	}

	if fromVersion < 3 {
		if err := d.migration3ExfilSync(); err != nil {
			return fmt.Errorf("migration 3 failed: %w", err)
		}
	}

	// Record schema version
	_, err := d.db.Exec(`
		INSERT INTO schema_version (version, applied_at, description)
		VALUES (?, ?, ?)
	`, DatabaseSchemaVersion, time.Now().Unix(), "Database schema initialized")

	return err
}

// migration1InitialSchema creates the initial database schema
func (d *Database) migration1InitialSchema() error {
	schema := `
	-- Beacons table
	CREATE TABLE IF NOT EXISTS beacons (
		id TEXT PRIMARY KEY,
		hostname TEXT NOT NULL,
		username TEXT NOT NULL,
		os TEXT NOT NULL,
		arch TEXT NOT NULL,
		ip_address TEXT,
		first_seen INTEGER NOT NULL,
		last_seen INTEGER NOT NULL,
		status TEXT DEFAULT 'active',
		metadata TEXT,
		created_at INTEGER NOT NULL,
		updated_at INTEGER NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_beacons_last_seen ON beacons(last_seen);
	CREATE INDEX IF NOT EXISTS idx_beacons_status ON beacons(status);
	CREATE INDEX IF NOT EXISTS idx_beacons_hostname ON beacons(hostname);

	-- Tasks table
	CREATE TABLE IF NOT EXISTS tasks (
		id TEXT PRIMARY KEY,
		beacon_id TEXT NOT NULL,
		command TEXT NOT NULL,
		status TEXT NOT NULL DEFAULT 'pending',
		created_at INTEGER NOT NULL,
		sent_at INTEGER,
		completed_at INTEGER,
		result_size INTEGER DEFAULT 0,
		chunk_count INTEGER DEFAULT 0,
		metadata TEXT,
		FOREIGN KEY (beacon_id) REFERENCES beacons(id) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS idx_tasks_beacon_id ON tasks(beacon_id);
	CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
	CREATE INDEX IF NOT EXISTS idx_tasks_created_at ON tasks(created_at);
	CREATE INDEX IF NOT EXISTS idx_tasks_beacon_status ON tasks(beacon_id, status);

	-- Task results table
	CREATE TABLE IF NOT EXISTS task_results (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		task_id TEXT NOT NULL,
		beacon_id TEXT NOT NULL,
		result_data TEXT NOT NULL,
		received_at INTEGER NOT NULL,
		chunk_index INTEGER DEFAULT 0,
		total_chunks INTEGER DEFAULT 1,
		is_complete INTEGER DEFAULT 1,
		FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE,
		FOREIGN KEY (beacon_id) REFERENCES beacons(id) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS idx_task_results_task_id ON task_results(task_id);
	CREATE INDEX IF NOT EXISTS idx_task_results_beacon_id ON task_results(beacon_id);
	CREATE INDEX IF NOT EXISTS idx_task_results_received_at ON task_results(received_at);
	CREATE INDEX IF NOT EXISTS idx_task_results_complete ON task_results(task_id, is_complete);

	-- Stager chunk cache (pre-loaded from Master for instant responses)
	CREATE TABLE IF NOT EXISTS stager_chunk_cache (
		client_binary_id TEXT NOT NULL,
		chunk_index INTEGER NOT NULL,
		chunk_data TEXT NOT NULL,
		cached_at INTEGER NOT NULL,
		PRIMARY KEY (client_binary_id, chunk_index)
	);

	CREATE INDEX IF NOT EXISTS idx_stager_cache_binary ON stager_chunk_cache(client_binary_id);
	`

	_, err := d.db.Exec(schema)
	return err
}

// migration2ExfilSchema introduces tables for dedicated exfiltration sessions and chunks
func (d *Database) migration2ExfilSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS exfil_sessions (
		session_id TEXT PRIMARY KEY,
		job_id TEXT,
		file_name TEXT,
		file_size INTEGER,
		total_chunks INTEGER,
		received_chunks INTEGER DEFAULT 0,
		status TEXT DEFAULT 'receiving',
		note TEXT,
		client_ip TEXT,
		created_at INTEGER NOT NULL,
		updated_at INTEGER NOT NULL,
		last_chunk_at INTEGER
	);

	CREATE TABLE IF NOT EXISTS exfil_chunks (
		session_id TEXT NOT NULL,
		chunk_index INTEGER NOT NULL,
		data BLOB NOT NULL,
		received_at INTEGER NOT NULL,
		PRIMARY KEY (session_id, chunk_index),
		FOREIGN KEY (session_id) REFERENCES exfil_sessions(session_id) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS idx_exfil_sessions_status ON exfil_sessions(status);
	CREATE INDEX IF NOT EXISTS idx_exfil_sessions_updated ON exfil_sessions(updated_at);
	CREATE INDEX IF NOT EXISTS idx_exfil_chunks_session ON exfil_chunks(session_id);
	`

	_, err := d.db.Exec(schema)
	return err
}

// migration3ExfilSync adds a synced column to exfil_chunks to track Master upload status
func (d *Database) migration3ExfilSync() error {
	// Add synced column to exfil_chunks
	_, err := d.db.Exec(`
		ALTER TABLE exfil_chunks ADD COLUMN synced INTEGER DEFAULT 0;
		CREATE INDEX IF NOT EXISTS idx_exfil_chunks_synced ON exfil_chunks(synced);
	`)
	return err
}

// Beacon database operations

// SaveBeacon inserts or updates a beacon in the database
func (d *Database) SaveBeacon(beacon *Beacon) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	now := time.Now().Unix()

	firstSeen := beacon.FirstSeen
	if firstSeen.IsZero() {
		// Fall back to last seen or now so we always persist something sensible
		firstSeen = beacon.LastSeen
		if firstSeen.IsZero() {
			firstSeen = time.Unix(now, 0)
		}
	}

	lastSeen := beacon.LastSeen
	if lastSeen.IsZero() {
		lastSeen = time.Unix(now, 0)
	}

	// Serialize metadata to JSON
	metadata := "{}"
	if beacon.TaskQueue != nil {
		// Don't serialize task queue in metadata, it's managed separately
		metadata = "{}"
	}

	_, err := d.db.Exec(`
		INSERT INTO beacons (id, hostname, username, os, arch, ip_address, first_seen, last_seen, status, metadata, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			hostname = excluded.hostname,
			username = excluded.username,
			os = excluded.os,
			arch = excluded.arch,
			ip_address = excluded.ip_address,
			last_seen = excluded.last_seen,
			status = 'active',
			updated_at = excluded.updated_at
	`, beacon.ID, beacon.Hostname, beacon.Username, beacon.OS, beacon.Arch,
		beacon.IPAddress, firstSeen.Unix(), lastSeen.Unix(),
		metadata, now, now)

	return err
}

// GetBeacon retrieves a beacon by ID
func (d *Database) GetBeacon(id string) (*Beacon, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	var beacon Beacon
	var firstSeen, lastSeen, createdAt, updatedAt int64
	var metadata string
	var status string

	err := d.db.QueryRow(`
		SELECT id, hostname, username, os, arch, ip_address, first_seen, last_seen, status, metadata, created_at, updated_at
		FROM beacons WHERE id = ?
	`, id).Scan(&beacon.ID, &beacon.Hostname, &beacon.Username, &beacon.OS, &beacon.Arch,
		&beacon.IPAddress, &firstSeen, &lastSeen, &status, &metadata, &createdAt, &updatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // Beacon not found
		}
		return nil, err
	}

	beacon.FirstSeen = time.Unix(firstSeen, 0)
	beacon.LastSeen = time.Unix(lastSeen, 0)
	beacon.TaskQueue = []Task{} // Initialize empty task queue

	return &beacon, nil
}

// GetAllBeacons retrieves all beacons from the database
func (d *Database) GetAllBeacons() ([]*Beacon, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	rows, err := d.db.Query(`
		SELECT id, hostname, username, os, arch, ip_address, first_seen, last_seen, status
		FROM beacons
		ORDER BY last_seen DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var beacons []*Beacon
	for rows.Next() {
		var beacon Beacon
		var firstSeen, lastSeen int64
		var status string

		err := rows.Scan(&beacon.ID, &beacon.Hostname, &beacon.Username, &beacon.OS, &beacon.Arch,
			&beacon.IPAddress, &firstSeen, &lastSeen, &status)
		if err != nil {
			return nil, err
		}

		beacon.FirstSeen = time.Unix(firstSeen, 0)
		beacon.LastSeen = time.Unix(lastSeen, 0)
		beacon.TaskQueue = []Task{} // Initialize empty task queue
		beacons = append(beacons, &beacon)
	}

	return beacons, rows.Err()
}

// GetActiveBeacons retrieves beacons that have checked in recently
func (d *Database) GetActiveBeacons(since time.Duration) ([]*Beacon, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	cutoff := time.Now().Add(-since).Unix()

	rows, err := d.db.Query(`
		SELECT id, hostname, username, os, arch, ip_address, first_seen, last_seen, status
		FROM beacons
		WHERE last_seen > ? AND status = 'active'
		ORDER BY last_seen DESC
	`, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var beacons []*Beacon
	for rows.Next() {
		var beacon Beacon
		var firstSeen, lastSeen int64
		var status string

		err := rows.Scan(&beacon.ID, &beacon.Hostname, &beacon.Username, &beacon.OS, &beacon.Arch,
			&beacon.IPAddress, &firstSeen, &lastSeen, &status)
		if err != nil {
			return nil, err
		}

		beacon.LastSeen = time.Unix(lastSeen, 0)
		beacon.TaskQueue = []Task{}
		beacons = append(beacons, &beacon)
	}

	return beacons, rows.Err()
}

// UpdateBeaconStatus updates a beacon's status
func (d *Database) UpdateBeaconStatus(beaconID, status string) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	_, err := d.db.Exec(`
		UPDATE beacons SET status = ?, updated_at = ? WHERE id = ?
	`, status, time.Now().Unix(), beaconID)

	return err
}

// DeleteBeacon removes a beacon from the database
func (d *Database) DeleteBeacon(id string) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	_, err := d.db.Exec("DELETE FROM beacons WHERE id = ?", id)
	return err
}

// Task database operations

// SaveTask inserts or updates a task in the database
func (d *Database) SaveTask(task *Task) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	var sentAt, completedAt *int64
	if task.SentAt != nil {
		ts := task.SentAt.Unix()
		sentAt = &ts
	}
	if task.Status == "completed" || task.Status == "failed" {
		ts := time.Now().Unix()
		completedAt = &ts
	}

	metadata := "{}"

	_, err := d.db.Exec(`
		INSERT INTO tasks (id, beacon_id, command, status, created_at, sent_at, completed_at, result_size, chunk_count, metadata)
		VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, ?)
		ON CONFLICT(id) DO UPDATE SET
			status = excluded.status,
			sent_at = excluded.sent_at,
			completed_at = excluded.completed_at
	`, task.ID, task.BeaconID, task.Command, task.Status, task.CreatedAt.Unix(), sentAt, completedAt, metadata)

	return err
}

// GetTask retrieves a task by ID
func (d *Database) GetTask(id string) (*Task, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	var task Task
	var createdAt int64
	var sentAt, completedAt sql.NullInt64

	err := d.db.QueryRow(`
		SELECT id, beacon_id, command, status, created_at, sent_at, completed_at
		FROM tasks WHERE id = ?
	`, id).Scan(&task.ID, &task.BeaconID, &task.Command, &task.Status, &createdAt, &sentAt, &completedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	task.CreatedAt = time.Unix(createdAt, 0)
	if sentAt.Valid {
		t := time.Unix(sentAt.Int64, 0)
		task.SentAt = &t
	}

	return &task, nil
}

// GetTasksForBeacon retrieves all tasks for a specific beacon
func (d *Database) GetTasksForBeacon(beaconID string) ([]*Task, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	rows, err := d.db.Query(`
		SELECT id, beacon_id, command, status, created_at, sent_at, completed_at
		FROM tasks
		WHERE beacon_id = ?
		ORDER BY created_at DESC
	`, beaconID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []*Task
	for rows.Next() {
		var task Task
		var createdAt int64
		var sentAt, completedAt sql.NullInt64

		err := rows.Scan(&task.ID, &task.BeaconID, &task.Command, &task.Status, &createdAt, &sentAt, &completedAt)
		if err != nil {
			return nil, err
		}

		task.CreatedAt = time.Unix(createdAt, 0)
		if sentAt.Valid {
			t := time.Unix(sentAt.Int64, 0)
			task.SentAt = &t
		}

		tasks = append(tasks, &task)
	}

	return tasks, rows.Err()
}

// GetPendingTasksForBeacon retrieves pending tasks for a beacon
func (d *Database) GetPendingTasksForBeacon(beaconID string) ([]*Task, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	rows, err := d.db.Query(`
		SELECT id, beacon_id, command, status, created_at, sent_at
		FROM tasks
		WHERE beacon_id = ? AND status = 'pending'
		ORDER BY created_at ASC
	`, beaconID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []*Task
	for rows.Next() {
		var task Task
		var createdAt int64
		var sentAt sql.NullInt64

		err := rows.Scan(&task.ID, &task.BeaconID, &task.Command, &task.Status, &createdAt, &sentAt)
		if err != nil {
			return nil, err
		}

		task.CreatedAt = time.Unix(createdAt, 0)
		if sentAt.Valid {
			t := time.Unix(sentAt.Int64, 0)
			task.SentAt = &t
		}

		tasks = append(tasks, &task)
	}

	return tasks, rows.Err()
}

// GetAllTasks retrieves all tasks from the database
func (d *Database) GetAllTasks() ([]*Task, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	rows, err := d.db.Query(`
		SELECT id, beacon_id, command, status, created_at, sent_at, completed_at
		FROM tasks
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []*Task
	for rows.Next() {
		var task Task
		var createdAt int64
		var sentAt, completedAt sql.NullInt64

		err := rows.Scan(&task.ID, &task.BeaconID, &task.Command, &task.Status, &createdAt, &sentAt, &completedAt)
		if err != nil {
			return nil, err
		}

		task.CreatedAt = time.Unix(createdAt, 0)
		if sentAt.Valid {
			t := time.Unix(sentAt.Int64, 0)
			task.SentAt = &t
		}

		tasks = append(tasks, &task)
	}

	return tasks, rows.Err()
}

// UpdateTaskStatus updates a task's status
func (d *Database) UpdateTaskStatus(taskID, status string) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	var completedAt *int64
	if status == "completed" || status == "failed" {
		ts := time.Now().Unix()
		completedAt = &ts
	}

	_, err := d.db.Exec(`
		UPDATE tasks SET status = ?, completed_at = ? WHERE id = ?
	`, status, completedAt, taskID)

	return err
}

// Task Result database operations

// SaveTaskResult stores a task result in the database
func (d *Database) SaveTaskResult(taskID, beaconID, resultData string, chunkIndex, totalChunks int) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	// Use transaction for atomic operation
	tx, err := d.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback() // Will be ignored if tx.Commit() succeeds

	isComplete := 0
	if totalChunks == 1 || chunkIndex == totalChunks-1 {
		isComplete = 1
	}

	// Insert task result
	_, err = tx.Exec(`
		INSERT INTO task_results (task_id, beacon_id, result_data, received_at, chunk_index, total_chunks, is_complete)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, taskID, beaconID, resultData, time.Now().Unix(), chunkIndex, totalChunks, isComplete)

	if err != nil {
		return fmt.Errorf("failed to insert task result: %w", err)
	}

	// Update task result size
	_, err = tx.Exec(`
		UPDATE tasks SET result_size = result_size + ?, chunk_count = ? WHERE id = ?
	`, len(resultData), totalChunks, taskID)

	if err != nil {
		return fmt.Errorf("failed to update task: %w", err)
	}

	// Commit transaction
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// GetTaskResult retrieves the complete result for a task
func (d *Database) GetTaskResult(taskID string) (string, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	rows, err := d.db.Query(`
		SELECT result_data, chunk_index
		FROM task_results
		WHERE task_id = ?
		ORDER BY chunk_index ASC
	`, taskID)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	var result string
	for rows.Next() {
		var chunk string
		var index int
		if err := rows.Scan(&chunk, &index); err != nil {
			return "", err
		}
		result += chunk
	}

	return result, rows.Err()
}

// GetTaskWithResult retrieves a task and its result
func (d *Database) GetTaskWithResult(taskID string) (*Task, string, error) {
	task, err := d.GetTask(taskID)
	if err != nil || task == nil {
		return task, "", err
	}

	result, err := d.GetTaskResult(taskID)
	if err != nil {
		return task, "", err
	}

	return task, result, nil
}

// GetTasksByStatus retrieves all tasks with a specific status
// Supports optional limit for pagination
func (d *Database) GetTasksByStatus(status string, limit int) ([]*Task, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	query := `
		SELECT id, beacon_id, command, status, created_at, sent_at
		FROM tasks
		WHERE status = ?
		ORDER BY created_at DESC
	`

	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}

	rows, err := d.db.Query(query, status)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []*Task
	for rows.Next() {
		task := &Task{}
		var sentAt sql.NullInt64

		err := rows.Scan(
			&task.ID,
			&task.BeaconID,
			&task.Command,
			&task.Status,
			&task.CreatedAt,
			&sentAt,
		)
		if err != nil {
			return nil, err
		}

		// Convert nullable timestamp
		if sentAt.Valid {
			t := time.Unix(sentAt.Int64, 0)
			task.SentAt = &t
		}

		tasks = append(tasks, task)
	}

	return tasks, rows.Err()
}

// GetAllTasksWithLimit retrieves all tasks with optional limit
// Used for task history queries
func (d *Database) GetAllTasksWithLimit(limit int) ([]*Task, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	query := `
		SELECT id, beacon_id, command, status, created_at, sent_at
		FROM tasks
		ORDER BY created_at DESC
	`

	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}

	rows, err := d.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []*Task
	for rows.Next() {
		task := &Task{}
		var sentAt sql.NullInt64

		err := rows.Scan(
			&task.ID,
			&task.BeaconID,
			&task.Command,
			&task.Status,
			&task.CreatedAt,
			&sentAt,
		)
		if err != nil {
			return nil, err
		}

		// Convert nullable timestamp
		if sentAt.Valid {
			t := time.Unix(sentAt.Int64, 0)
			task.SentAt = &t
		}

		tasks = append(tasks, task)
	}

	return tasks, rows.Err()
}

// CleanupOldData removes old data from the database
func (d *Database) CleanupOldData(days int) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	cutoff := time.Now().AddDate(0, 0, -days).Unix()

	// Delete old tasks
	_, err := d.db.Exec("DELETE FROM tasks WHERE created_at < ? AND status IN ('completed', 'failed')", cutoff)
	if err != nil {
		return fmt.Errorf("failed to cleanup tasks: %w", err)
	}

	// Delete old task results (cascade should handle this, but just in case)
	_, err = d.db.Exec("DELETE FROM task_results WHERE received_at < ?", cutoff)
	if err != nil {
		return fmt.Errorf("failed to cleanup task results: %w", err)
	}

	return nil
}

// GetDatabaseStats returns statistics about the database
func (d *Database) GetDatabaseStats() (map[string]int64, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	stats := make(map[string]int64)

	// Count beacons
	var count int64
	if err := d.db.QueryRow("SELECT COUNT(*) FROM beacons").Scan(&count); err != nil {
		return nil, err
	}
	stats["beacons"] = count

	// Count active beacons (last 5 mins)
	activeCutoff := time.Now().Add(-5 * time.Minute).Unix()
	if err := d.db.QueryRow("SELECT COUNT(*) FROM beacons WHERE last_seen > ?", activeCutoff).Scan(&count); err != nil {
		return nil, err
	}
	stats["active_beacons"] = count

	// Count tasks
	if err := d.db.QueryRow("SELECT COUNT(*) FROM tasks").Scan(&count); err != nil {
		return nil, err
	}
	stats["tasks"] = count

	return stats, nil
}

// CacheStagerChunks stores stager chunks in the database for quick retrieval
func (d *Database) CacheStagerChunks(clientBinaryID string, chunks []string) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	now := time.Now().Unix()

	// Clear existing cache for this binary
	_, err = tx.Exec("DELETE FROM stager_chunk_cache WHERE client_binary_id = ?", clientBinaryID)
	if err != nil {
		return err
	}

	// Insert new chunks
	stmt, err := tx.Prepare("INSERT INTO stager_chunk_cache (client_binary_id, chunk_index, chunk_data, cached_at) VALUES (?, ?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	for i, chunk := range chunks {
		if _, err := stmt.Exec(clientBinaryID, i, chunk, now); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// GetCachedStagerChunks retrieves all cached stager chunks for local delivery
func (d *Database) GetCachedStagerChunks() ([]string, bool) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	rows, err := d.db.Query(`
		SELECT chunk_data FROM stager_chunk_cache
		ORDER BY client_binary_id, chunk_index
		LIMIT 1000
	`)
	if err != nil {
		return nil, false
	}
	defer rows.Close()

	var chunks []string
	for rows.Next() {
		var chunk string
		if err := rows.Scan(&chunk); err != nil {
			continue
		}
		chunks = append(chunks, chunk)
	}

	return chunks, len(chunks) > 0
}

// GetCachedStagerChunk retrieves a specific cached stager chunk by index
func (d *Database) GetCachedStagerChunk(clientBinaryID string, chunkIndex int) (string, bool) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	var chunk string
	err := d.db.QueryRow(`
		SELECT chunk_data FROM stager_chunk_cache
		WHERE client_binary_id = ? AND chunk_index = ?
	`, clientBinaryID, chunkIndex).Scan(&chunk)

	if err != nil {
		return "", false
	}
	return chunk, true
}

// GetCachedBinaryInfo returns info about the most recent cached binary
func (d *Database) GetCachedBinaryInfo() (clientBinaryID string, totalChunks int, found bool) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	err := d.db.QueryRow(`
		SELECT client_binary_id, COUNT(*) as chunk_count
		FROM stager_chunk_cache
		GROUP BY client_binary_id
		ORDER BY cached_at DESC
		LIMIT 1
	`).Scan(&clientBinaryID, &totalChunks)

	if err != nil {
		return "", 0, false
	}
	return clientBinaryID, totalChunks, true
}

// GetLocalTaskChunks retrieves locally stored chunks for a task that Master is missing
func (d *Database) GetLocalTaskChunks(taskID string, chunkIndices []int) map[int][]byte {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	result := make(map[int][]byte)
	for _, idx := range chunkIndices {
		var chunk []byte
		err := d.db.QueryRow(`
			SELECT chunk_data FROM task_result_chunks
			WHERE task_id = ? AND chunk_index = ?
		`, taskID, idx).Scan(&chunk)
		if err == nil && len(chunk) > 0 {
			result[idx] = chunk
		}
	}
	return result
}

// GetLocalExfilChunks retrieves locally stored chunks for an exfil session that Master is missing
func (d *Database) GetLocalExfilChunks(sessionID string, tag string, chunkIndices []int) map[int][]byte {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	result := make(map[int][]byte)
	for _, idx := range chunkIndices {
		var chunk []byte
		// First try direct session_id lookup
		err := d.db.QueryRow(`
			SELECT data FROM exfil_chunks
			WHERE session_id = ? AND chunk_index = ?
		`, sessionID, idx).Scan(&chunk)
		if err == nil && len(chunk) > 0 {
			result[idx] = chunk
			continue
		}
		
		// Try tag-based storage (orphan chunks stored as tag_XXX)
		if tag != "" {
			tagSessionID := fmt.Sprintf("tag_%s", tag)
			err = d.db.QueryRow(`
				SELECT data FROM exfil_chunks
				WHERE session_id = ? AND chunk_index = ?
			`, tagSessionID, idx).Scan(&chunk)
			if err == nil && len(chunk) > 0 {
				result[idx] = chunk
			}
		}
	}
	return result
}

// MarkExfilChunkSynced marks a chunk as successfully uploaded to Master
func (d *Database) MarkExfilChunkSynced(sessionID string, chunkIndex int) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	_, err := d.db.Exec(`
		UPDATE exfil_chunks SET synced = 1
		WHERE session_id = ? AND chunk_index = ?
	`, sessionID, chunkIndex)

	return err
}

// Exfil session operations

// UpsertExfilSession creates or updates metadata for a dedicated exfiltration session
func (d *Database) UpsertExfilSession(session *ExfilSessionRecord) error {
	if session == nil {
		return fmt.Errorf("session record is nil")
	}

	d.mutex.Lock()
	defer d.mutex.Unlock()

	createdAt := session.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now()
	}
	updatedAt := session.UpdatedAt
	if updatedAt.IsZero() {
		updatedAt = time.Now()
	}
	var lastChunk interface{}
	if session.LastChunkAt.IsZero() {
		lastChunk = nil
	} else {
		lastChunk = session.LastChunkAt.Unix()
	}

	_, err := d.db.Exec(`
		INSERT INTO exfil_sessions (
			session_id, job_id, file_name, file_size, total_chunks,
			received_chunks, status, note, client_ip,
			created_at, updated_at, last_chunk_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(session_id) DO UPDATE SET
			job_id = COALESCE(excluded.job_id, exfil_sessions.job_id),
			file_name = COALESCE(excluded.file_name, exfil_sessions.file_name),
			file_size = CASE WHEN excluded.file_size > 0 THEN excluded.file_size ELSE exfil_sessions.file_size END,
			total_chunks = CASE WHEN excluded.total_chunks > 0 THEN excluded.total_chunks ELSE exfil_sessions.total_chunks END,
			received_chunks = MAX(exfil_sessions.received_chunks, excluded.received_chunks),
			status = COALESCE(excluded.status, exfil_sessions.status),
			note = COALESCE(excluded.note, exfil_sessions.note),
			client_ip = COALESCE(excluded.client_ip, exfil_sessions.client_ip),
			updated_at = excluded.updated_at,
			last_chunk_at = COALESCE(excluded.last_chunk_at, exfil_sessions.last_chunk_at)
	`,
		session.SessionID,
		session.JobID,
		session.FileName,
		session.FileSize,
		session.TotalChunks,
		session.ReceivedChunks,
		session.Status,
		session.Note,
		session.ClientIP,
		createdAt.Unix(),
		updatedAt.Unix(),
		lastChunk,
	)

	return err
}

// RecordExfilChunk persists a chunk and returns true if it was newly inserted
func (d *Database) RecordExfilChunk(sessionID string, chunkIndex uint32, data []byte) (bool, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	tx, err := d.db.Begin()
	if err != nil {
		return false, fmt.Errorf("failed to begin txn: %w", err)
	}

	now := time.Now().Unix()
	res, err := tx.Exec(`
		INSERT INTO exfil_chunks (session_id, chunk_index, data, received_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(session_id, chunk_index) DO NOTHING
	`, sessionID, chunkIndex, data, now)
	if err != nil {
		tx.Rollback()
		return false, fmt.Errorf("failed to insert chunk: %w", err)
	}

	rows, err := res.RowsAffected()
	if err != nil {
		tx.Rollback()
		return false, err
	}
	inserted := rows > 0

	if inserted {
		if _, err := tx.Exec(`
			UPDATE exfil_sessions
			SET received_chunks = received_chunks + 1,
				updated_at = ?,
				last_chunk_at = ?
			WHERE session_id = ?
		`, now, now, sessionID); err != nil {
			tx.Rollback()
			return false, fmt.Errorf("failed to update session counters: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return false, err
	}

	return inserted, nil
}

// UpdateExfilSessionStatus updates the status field for a session
func (d *Database) UpdateExfilSessionStatus(sessionID, status string) error {
	if sessionID == "" {
		return fmt.Errorf("session ID is required")
	}

	d.mutex.Lock()
	defer d.mutex.Unlock()

	_, err := d.db.Exec(`
		UPDATE exfil_sessions
		SET status = ?, updated_at = ?
		WHERE session_id = ?
	`, status, time.Now().Unix(), sessionID)

	return err
}

// GetUnsyncedExfilChunks retrieves all chunks that haven't been uploaded to Master
func (d *Database) GetUnsyncedExfilChunks(limit int) ([]map[string]interface{}, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	rows, err := d.db.Query(`
		SELECT c.session_id, c.chunk_index, c.data, s.job_id, s.file_name, s.file_size, s.total_chunks
		FROM exfil_chunks c
		JOIN exfil_sessions s ON c.session_id = s.session_id
		WHERE c.synced = 0
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var chunks []map[string]interface{}
	for rows.Next() {
		var sessionID, jobID, fileName string
		var chunkIndex, totalChunks int
		var fileSize int64
		var data []byte

		if err := rows.Scan(&sessionID, &chunkIndex, &data, &jobID, &fileName, &fileSize, &totalChunks); err != nil {
			return nil, err
		}

		chunks = append(chunks, map[string]interface{}{
			"session_id":   sessionID,
			"chunk_index":  chunkIndex,
			"data":         data,
			"job_id":       jobID,
			"file_name":    fileName,
			"file_size":    fileSize,
			"total_chunks": totalChunks,
		})
	}

	return chunks, rows.Err()
}

// GetUnsyncedExfilChunksForSession retrieves unsynced chunks for a specific session
func (d *Database) GetUnsyncedExfilChunksForSession(sessionID string, limit int) ([]map[string]interface{}, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	if limit <= 0 {
		limit = 10000
	}

	rows, err := d.db.Query(`
		SELECT c.session_id, c.chunk_index, c.data, s.job_id, s.file_name, s.file_size, s.total_chunks
		FROM exfil_chunks c
		JOIN exfil_sessions s ON c.session_id = s.session_id
		WHERE c.session_id = ? AND c.synced = 0
		ORDER BY c.chunk_index
		LIMIT ?
	`, sessionID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var chunks []map[string]interface{}
	for rows.Next() {
		var sessID, jobID, fileName string
		var chunkIndex, totalChunks int
		var fileSize int64
		var data []byte

		if err := rows.Scan(&sessID, &chunkIndex, &data, &jobID, &fileName, &fileSize, &totalChunks); err != nil {
			return nil, err
		}

		chunks = append(chunks, map[string]interface{}{
			"session_id":   sessID,
			"chunk_index":  chunkIndex,
			"data":         data,
			"job_id":       jobID,
			"file_name":    fileName,
			"file_size":    fileSize,
			"total_chunks": totalChunks,
		})
	}

	return chunks, rows.Err()
}
