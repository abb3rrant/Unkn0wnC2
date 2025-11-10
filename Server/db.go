// Package main implements the database layer for the Unkn0wnC2 server.
// This provides persistent storage for beacons, tasks, and results using SQLite.
package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const (
	// DatabaseFileName is the default database file name
	DatabaseFileName = "c2_data.db"

	// DatabaseSchemaVersion tracks the current schema version
	DatabaseSchemaVersion = 1
)

// Database wraps the SQL database connection and provides C2-specific operations
type Database struct {
	db    *sql.DB
	mutex sync.RWMutex
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

// Beacon database operations

// SaveBeacon inserts or updates a beacon in the database
func (d *Database) SaveBeacon(beacon *Beacon) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	now := time.Now().Unix()

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
		beacon.IPAddress, beacon.LastSeen.Unix(), beacon.LastSeen.Unix(),
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

	err := d.db.QueryRow(`
		SELECT id, hostname, username, os, arch, ip_address, first_seen, last_seen, status, metadata, created_at, updated_at
		FROM beacons WHERE id = ?
	`, id).Scan(&beacon.ID, &beacon.Hostname, &beacon.Username, &beacon.OS, &beacon.Arch,
		&beacon.IPAddress, &firstSeen, &lastSeen, &metadata, &metadata, &createdAt, &updatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // Beacon not found
		}
		return nil, err
	}

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

// Utility functions

// GetDatabaseStats returns database statistics
func (d *Database) GetDatabaseStats() (map[string]interface{}, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	stats := make(map[string]interface{})

	// Count beacons
	var beaconCount int
	err := d.db.QueryRow("SELECT COUNT(*) FROM beacons").Scan(&beaconCount)
	if err != nil {
		return nil, err
	}
	stats["beacons"] = beaconCount

	// Count active beacons (last 24 hours)
	var activeBeaconCount int
	cutoff := time.Now().Add(-24 * time.Hour).Unix()
	err = d.db.QueryRow("SELECT COUNT(*) FROM beacons WHERE last_seen > ? AND status = 'active'", cutoff).Scan(&activeBeaconCount)
	if err != nil {
		return nil, err
	}
	stats["active_beacons"] = activeBeaconCount

	// Count tasks
	var taskCount int
	err = d.db.QueryRow("SELECT COUNT(*) FROM tasks").Scan(&taskCount)
	if err != nil {
		return nil, err
	}
	stats["tasks"] = taskCount

	// Count by status
	rows, err := d.db.Query("SELECT status, COUNT(*) FROM tasks GROUP BY status")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	tasksByStatus := make(map[string]int)
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return nil, err
		}
		tasksByStatus[status] = count
	}
	stats["tasks_by_status"] = tasksByStatus

	// Database file size
	var pageCount, pageSize int
	err = d.db.QueryRow("PRAGMA page_count").Scan(&pageCount)
	if err == nil {
		d.db.QueryRow("PRAGMA page_size").Scan(&pageSize)
		stats["db_size_bytes"] = pageCount * pageSize
	}

	return stats, nil
}

// CleanupOldData removes old completed tasks and inactive beacons
func (d *Database) CleanupOldData(retentionDays int) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	cutoff := time.Now().AddDate(0, 0, -retentionDays).Unix()

	// Delete old completed tasks
	result, err := d.db.Exec(`
		DELETE FROM tasks
		WHERE status = 'completed' AND completed_at < ?
	`, cutoff)
	if err != nil {
		return err
	}

	deleted, _ := result.RowsAffected()
	if deleted > 0 {
		logf("[DB] Cleaned up %d old completed tasks", deleted)
	}

	// Mark inactive beacons
	result, err = d.db.Exec(`
		UPDATE beacons
		SET status = 'inactive'
		WHERE last_seen < ? AND status = 'active'
	`, cutoff)
	if err != nil {
		return err
	}

	updated, _ := result.RowsAffected()
	if updated > 0 {
		logf("[DB] Marked %d beacons as inactive", updated)
	}

	return nil
}

// ExportBeaconData exports beacon data as JSON for backup/analysis
func (d *Database) ExportBeaconData(beaconID string) ([]byte, error) {
	beacon, err := d.GetBeacon(beaconID)
	if err != nil {
		return nil, err
	}

	tasks, err := d.GetTasksForBeacon(beaconID)
	if err != nil {
		return nil, err
	}

	export := map[string]interface{}{
		"beacon": beacon,
		"tasks":  tasks,
	}

	return json.MarshalIndent(export, "", "  ")
}

// Stager Chunk Cache Operations

// CacheChunk stores a single chunk in local cache for instant retrieval
func (d *Database) CacheChunk(sessionID string, chunkIndex int, chunkData string) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	_, err := d.db.Exec(`
		INSERT OR REPLACE INTO stager_chunk_cache (client_binary_id, chunk_index, chunk_data, cached_at)
		VALUES (?, ?, ?, ?)
	`, sessionID, chunkIndex, chunkData, time.Now().Unix())

	return err
}

// GetCachedChunk retrieves a chunk from local cache
func (d *Database) GetCachedChunk(sessionID string, chunkIndex int) (string, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	var chunkData string
	err := d.db.QueryRow(`
		SELECT chunk_data FROM stager_chunk_cache
		WHERE client_binary_id = ? AND chunk_index = ?
	`, sessionID, chunkIndex).Scan(&chunkData)

	if err == sql.ErrNoRows {
		return "", fmt.Errorf("chunk not found in cache")
	}

	return chunkData, err
}

// GetCachedBinaryID returns the client_binary_id for any cached binary (typically only one)
func (d *Database) GetCachedBinaryID() (string, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	var clientBinaryID string
	err := d.db.QueryRow(`
		SELECT DISTINCT client_binary_id FROM stager_chunk_cache LIMIT 1
	`).Scan(&clientBinaryID)

	if err == sql.ErrNoRows {
		return "", fmt.Errorf("no cached chunks available")
	}

	return clientBinaryID, err
}

// GetCachedChunkByBinaryID gets a chunk by client_binary_id and chunk index
func (d *Database) GetCachedChunkByBinaryID(clientBinaryID string, chunkIndex int) (string, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	var chunkData string
	err := d.db.QueryRow(`
		SELECT chunk_data FROM stager_chunk_cache
		WHERE client_binary_id = ? AND chunk_index = ?
	`, clientBinaryID, chunkIndex).Scan(&chunkData)

	if err == sql.ErrNoRows {
		return "", fmt.Errorf("chunk %d not found in cache for binary %s", chunkIndex, clientBinaryID)
	}

	return chunkData, err
}

// CacheStagerChunks stores chunks in local cache for instant retrieval (batch operation)
func (d *Database) CacheStagerChunks(clientBinaryID string, chunks []string) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	tx, err := d.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Clear existing cache for this binary
	_, err = tx.Exec(`DELETE FROM stager_chunk_cache WHERE client_binary_id = ?`, clientBinaryID)
	if err != nil {
		return fmt.Errorf("failed to clear old cache: %w", err)
	}

	// Insert all chunks
	stmt, err := tx.Prepare(`
		INSERT INTO stager_chunk_cache (client_binary_id, chunk_index, chunk_data, cached_at)
		VALUES (?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	now := time.Now().Unix()
	for i, chunkData := range chunks {
		_, err = stmt.Exec(clientBinaryID, i, chunkData, now)
		if err != nil {
			return fmt.Errorf("failed to cache chunk %d: %w", i, err)
		}
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	logf("[DB] Cached %d chunks for client binary: %s", len(chunks), clientBinaryID)
	return nil
}

// GetCachedChunkCount returns the number of cached chunks for a binary
func (d *Database) GetCachedChunkCount(clientBinaryID string) (int, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	var count int
	err := d.db.QueryRow(`
		SELECT COUNT(*) FROM stager_chunk_cache WHERE client_binary_id = ?
	`, clientBinaryID).Scan(&count)

	return count, err
}

// ClearStagerCache removes all cached chunks (for cleanup/maintenance)
func (d *Database) ClearStagerCache() error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	result, err := d.db.Exec(`DELETE FROM stager_chunk_cache`)
	if err != nil {
		return err
	}

	deleted, _ := result.RowsAffected()
	logf("[DB] Cleared %d cached chunks", deleted)
	return nil
}
