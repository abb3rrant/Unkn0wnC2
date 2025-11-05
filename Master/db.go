// Package main implements the database layer for the Unkn0wnC2 Master Server.
// This provides persistent storage for DNS servers, aggregated beacons, tasks,
// results, operators, and audit logging using SQLite.
package main

import (
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

const (
	// MasterDatabaseSchemaVersion tracks the current schema version
	MasterDatabaseSchemaVersion = 1
)

// MasterDatabase wraps the SQL database connection for the master server
type MasterDatabase struct {
	db    *sql.DB
	mutex sync.RWMutex
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

	// Configure connection pool
	db.SetMaxOpenConns(10) // Master server handles more concurrent operations
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(0)

	database := &MasterDatabase{
		db: db,
	}

	// Initialize schema
	if err := database.initSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	fmt.Printf("[Master DB] Database initialized: %s\n", dbPath)
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
	// Enable foreign keys and WAL mode
	pragmas := []string{
		"PRAGMA foreign_keys = ON",
		"PRAGMA journal_mode = WAL",
		"PRAGMA synchronous = NORMAL",
		"PRAGMA cache_size = -64000",
		"PRAGMA auto_vacuum = INCREMENTAL",
		"PRAGMA busy_timeout = 5000", // 5 second timeout for busy database
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
	fmt.Printf("[Master DB] Applying migrations from version %d to %d\n", fromVersion, MasterDatabaseSchemaVersion)

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
	`, MasterDatabaseSchemaVersion, time.Now().Unix(), "Master server schema initialized")

	return err
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

	-- Tasks table (centralized task management)
	CREATE TABLE IF NOT EXISTS tasks (
		id TEXT PRIMARY KEY,
		beacon_id TEXT NOT NULL,
		command TEXT NOT NULL,
		status TEXT NOT NULL DEFAULT 'pending',
		assigned_dns_server TEXT NOT NULL,
		created_by TEXT,
		created_at INTEGER NOT NULL,
		sent_at INTEGER,
		completed_at INTEGER,
		result_size INTEGER DEFAULT 0,
		chunk_count INTEGER DEFAULT 0,
		metadata TEXT,
		FOREIGN KEY (beacon_id) REFERENCES beacons(id) ON DELETE CASCADE,
		FOREIGN KEY (assigned_dns_server) REFERENCES dns_servers(id) ON DELETE CASCADE,
		FOREIGN KEY (created_by) REFERENCES operators(id) ON DELETE SET NULL
	);

	CREATE INDEX IF NOT EXISTS idx_tasks_beacon_id ON tasks(beacon_id);
	CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
	CREATE INDEX IF NOT EXISTS idx_tasks_created_at ON tasks(created_at);
	CREATE INDEX IF NOT EXISTS idx_tasks_assigned_dns ON tasks(assigned_dns_server);
	CREATE INDEX IF NOT EXISTS idx_tasks_created_by ON tasks(created_by);
	CREATE INDEX IF NOT EXISTS idx_tasks_status_created ON tasks(status, created_at DESC);

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
		FOREIGN KEY (dns_server_id) REFERENCES dns_servers(id) ON DELETE CASCADE
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
		chunk_size INTEGER NOT NULL DEFAULT 403,
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

	// Use INSERT OR REPLACE to handle domain uniqueness constraint
	_, err = d.db.Exec(`
		INSERT INTO dns_servers (id, domain, address, api_key_hash, status, first_seen, last_checkin, created_at, updated_at)
		VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?)
		ON CONFLICT(domain) DO UPDATE SET
			id = excluded.id,
			address = excluded.address,
			api_key_hash = excluded.api_key_hash,
			last_checkin = excluded.last_checkin,
			updated_at = excluded.updated_at
	`, id, domain, address, string(apiKeyHash), now, now, now, now)

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

// GetActiveBeacons retrieves beacons active within the last N minutes
func (d *MasterDatabase) GetActiveBeacons(minutesThreshold int) ([]map[string]interface{}, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	threshold := time.Now().Add(-time.Duration(minutesThreshold) * time.Minute).Unix()

	rows, err := d.db.Query(`
		SELECT id, hostname, username, os, arch, ip_address, dns_server_id, first_seen, last_seen, status
		FROM beacons
		WHERE last_seen >= ? AND status = 'active'
		ORDER BY last_seen DESC
	`, threshold)
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
func (d *MasterDatabase) SaveResultChunk(taskID, beaconID, dnsServerID string, chunkIndex, totalChunks int, data string) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	now := time.Now().Unix()

	// Determine if this is a complete result
	isComplete := 0
	if chunkIndex == 0 {
		// Either single-chunk (totalChunks=1) or assembled result (totalChunks>1)
		isComplete = 1

		// If this is an assembled result from a DNS server, store it and we're done
		if totalChunks > 1 {
			// This is a DNS server sending us the complete assembled result
			// Check if we already have it
			var existingID int
			err := d.db.QueryRow(`
				SELECT id FROM task_results 
				WHERE task_id = ? AND chunk_index = 0 AND total_chunks = ? AND is_complete = 1
				LIMIT 1
			`, taskID, totalChunks).Scan(&existingID)

			if err == sql.ErrNoRows {
				// Store the complete result
				_, err = d.db.Exec(`
					INSERT INTO task_results (task_id, beacon_id, dns_server_id, result_data, received_at, chunk_index, total_chunks, is_complete)
					VALUES (?, ?, ?, ?, ?, 0, ?, 1)
				`, taskID, beaconID, dnsServerID, data, now, totalChunks)

				if err == nil {
					fmt.Printf("[Master DB] Received complete assembled result from %s: task %s, %d chunks, %d bytes\n",
						dnsServerID, taskID, totalChunks, len(data))
					// Mark task as completed
					d.markTaskCompleted(taskID)
				}
				return err
			}
			// Already have complete result, skip duplicate
			return nil
		}
	}

	// Insert the chunk (for single-chunk results or individual chunks from multi-chunk results)
	_, err := d.db.Exec(`
		INSERT INTO task_results (task_id, beacon_id, dns_server_id, result_data, received_at, chunk_index, total_chunks, is_complete)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, taskID, beaconID, dnsServerID, data, now, chunkIndex, totalChunks, isComplete)

	if err != nil {
		return err
	}

	// Update task status to "exfiltrating" when first chunk arrives (unless it's already completed)
	if chunkIndex > 0 || (chunkIndex == 0 && totalChunks == 1) {
		var currentStatus string
		err := d.db.QueryRow("SELECT status FROM tasks WHERE id = ?", taskID).Scan(&currentStatus)
		if err == nil && currentStatus == "sent" {
			_, err = d.db.Exec("UPDATE tasks SET status = ? WHERE id = ?", "exfiltrating", taskID)
			if err == nil {
				fmt.Printf("[Master DB] Task %s status: sent → exfiltrating (first chunk received)\n", taskID)
			}
		}
	}

	// If this was a complete single-chunk result, mark task as completed
	if isComplete == 1 && totalChunks == 1 {
		d.markTaskCompleted(taskID)
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
			return nil
		}

		// Count how many individual chunks we have for this task
		var chunkCount int
		err = d.db.QueryRow(`
			SELECT COUNT(DISTINCT chunk_index) 
			FROM task_results 
			WHERE task_id = ? AND chunk_index > 0
		`, taskID).Scan(&chunkCount)

		if err == nil && chunkCount == totalChunks {
			// We have all chunks! Reassemble them (call directly, we already hold the lock)
			fmt.Printf("[Master DB] All %d chunks received for task %s, reassembling...\n", totalChunks, taskID)
			d.reassembleChunkedResultLocked(taskID, beaconID, totalChunks)
		}
	}

	return nil
}

// reassembleChunkedResultLocked combines all chunks into a complete result
// Must be called with d.mutex already locked
func (d *MasterDatabase) reassembleChunkedResultLocked(taskID, beaconID string, totalChunks int) {
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
		fmt.Printf("[Master DB] Error fetching chunks for reassembly: %v\n", err)
		return
	}
	defer rows.Close()

	// Build chunk map (handle potential duplicates from multiple DNS servers)
	chunks := make(map[int]string)
	for rows.Next() {
		var index int
		var data string
		if err := rows.Scan(&index, &data); err != nil {
			fmt.Printf("[Master DB] Error scanning chunk: %v\n", err)
			return
		}
		// If we have multiple copies of same chunk from different servers, just use first one
		if _, exists := chunks[index]; !exists {
			chunks[index] = data
		}
	}

	// Verify we have all chunks
	if len(chunks) != totalChunks {
		fmt.Printf("[Master DB] Incomplete chunks for task %s: have %d unique chunks, need %d\n",
			taskID, len(chunks), totalChunks)
		return
	}

	// Reassemble in order
	var completeResult strings.Builder
	for i := 1; i <= totalChunks; i++ {
		data, exists := chunks[i]
		if !exists {
			fmt.Printf("[Master DB] Missing chunk %d for task %s\n", i, taskID)
			return
		}
		completeResult.WriteString(data)
	}

	// Store the complete result with chunk_index=0 to indicate it's the assembled version
	now := time.Now().Unix()
	_, err = d.db.Exec(`
		INSERT INTO task_results (task_id, beacon_id, dns_server_id, result_data, received_at, chunk_index, total_chunks, is_complete)
		VALUES (?, ?, 'master-assembled', ?, ?, 0, ?, 1)
	`, taskID, beaconID, completeResult.String(), now, totalChunks)

	if err != nil {
		fmt.Printf("[Master DB] Error storing assembled result: %v\n", err)
		return
	}

	// Mark task as completed
	d.markTaskCompleted(taskID)

	fmt.Printf("[Master DB] ✓ Reassembled result for task %s: %d chunks, %d bytes\n",
		taskID, totalChunks, completeResult.Len())
}

// GetTaskResult retrieves the complete result for a task
func (d *MasterDatabase) GetTaskResult(taskID string) (string, bool, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	// First try to get the complete assembled result (chunk_index = 0, is_complete = 1)
	var resultData string
	var isComplete int

	err := d.db.QueryRow(`
		SELECT result_data, is_complete 
		FROM task_results 
		WHERE task_id = ? AND chunk_index = 0 AND is_complete = 1
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

// Client Binary operations

// SaveClientBinary stores a pre-built client binary with chunks for stager deployment
func (d *MasterDatabase) SaveClientBinary(id, filename, os, arch, version, base64Data, dnsDomains string,
	originalSize, compressedSize, base64Size, chunkSize, totalChunks int, createdBy string) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	now := time.Now().Unix()

	_, err := d.db.Exec(`
		INSERT INTO client_binaries (id, filename, os, arch, version, original_size, compressed_size, 
			base64_size, chunk_size, total_chunks, base64_data, dns_domains, created_at, created_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, id, filename, os, arch, version, originalSize, compressedSize, base64Size, chunkSize,
		totalChunks, base64Data, dnsDomains, now, createdBy)

	return err
}

// GetClientBinaries retrieves all stored client binaries
func (d *MasterDatabase) GetClientBinaries() ([]map[string]interface{}, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	rows, err := d.db.Query(`
		SELECT id, filename, os, arch, version, original_size, compressed_size, 
			base64_size, chunk_size, total_chunks, dns_domains, created_at, created_by
		FROM client_binaries
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var binaries []map[string]interface{}
	for rows.Next() {
		var id, filename, os, arch, version, dnsDomains, createdBy string
		var originalSize, compressedSize, base64Size, chunkSize, totalChunks int
		var createdAt int64

		err := rows.Scan(&id, &filename, &os, &arch, &version, &originalSize, &compressedSize,
			&base64Size, &chunkSize, &totalChunks, &dnsDomains, &createdAt, &createdBy)
		if err != nil {
			continue
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
			"created_by":      createdBy,
		})
	}

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

	_, err := d.db.Exec(`
		INSERT INTO stager_sessions (id, stager_ip, os, arch, client_binary_id, total_chunks, 
			initiated_by_dns, created_at, last_activity)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, id, stagerIP, os, arch, clientBinaryID, totalChunks, initiatedByDNS, now, now)

	return err
}

// UpsertClientBinary inserts or updates a client binary record (for filesystem-loaded beacons)
func (d *MasterDatabase) UpsertClientBinary(id, filename, os, arch string, originalSize, compressedSize, base64Size, totalChunks int, base64Data, dnsDomains string) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	now := time.Now().Unix()

	_, err := d.db.Exec(`
		INSERT INTO client_binaries (id, filename, os, arch, original_size, compressed_size, base64_size, 
			chunk_size, total_chunks, base64_data, dns_domains, created_at, version)
		VALUES (?, ?, ?, ?, ?, ?, ?, 403, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			filename = excluded.filename,
			os = excluded.os,
			arch = excluded.arch,
			original_size = excluded.original_size,
			compressed_size = excluded.compressed_size,
			base64_size = excluded.base64_size,
			total_chunks = excluded.total_chunks,
			base64_data = excluded.base64_data,
			dns_domains = excluded.dns_domains
	`, id, filename, os, arch, originalSize, compressedSize, base64Size, totalChunks, base64Data, dnsDomains, now, "filesystem")

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

// MarkStagerChunkDelivered marks a chunk as delivered
func (d *MasterDatabase) MarkStagerChunkDelivered(sessionID string, chunkIndex int) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	now := time.Now().Unix()

	// Mark chunk as delivered
	_, err := d.db.Exec(`
		UPDATE stager_chunk_assignments 
		SET delivered = 1, delivered_at = ? 
		WHERE session_id = ? AND chunk_index = ?
	`, now, sessionID, chunkIndex)

	if err != nil {
		return err
	}

	// Update session chunks_delivered count
	_, err = d.db.Exec(`
		UPDATE stager_sessions 
		SET chunks_delivered = chunks_delivered + 1, last_activity = ?
		WHERE id = ?
	`, now, sessionID)

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
		var id, stagerIP, os, arch, initiatedByDNS, filename, version string
		var totalChunks, chunksDelivered, completed int
		var createdAt, lastActivity, completedAt int64

		err := rows.Scan(&id, &stagerIP, &os, &arch, &totalChunks, &chunksDelivered,
			&initiatedByDNS, &createdAt, &lastActivity, &completed, &completedAt,
			&filename, &version)

		if err != nil {
			continue
		}

		sessions = append(sessions, map[string]interface{}{
			"id":               id,
			"stager_ip":        stagerIP,
			"os":               os,
			"arch":             arch,
			"total_chunks":     totalChunks,
			"chunks_delivered": chunksDelivered,
			"initiated_by_dns": initiatedByDNS,
			"created_at":       createdAt,
			"last_activity":    lastActivity,
			"completed":        completed,
			"completed_at":     completedAt,
			"client_filename":  filename,
			"client_version":   version,
		})
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
			return "", "", fmt.Errorf("invalid credentials")
		}
		return "", "", err
	}

	if isActive != 1 {
		return "", "", fmt.Errorf("account disabled")
	}

	// Verify password
	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password))
	if err != nil {
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
		taskID := generateTaskID()

		// Insert task
		_, err := d.db.Exec(`
			INSERT INTO tasks (id, beacon_id, command, status, assigned_dns_server, created_by, created_at)
			VALUES (?, ?, ?, 'pending', ?, ?, ?)
		`, taskID, beaconID, command, dnsServerID, createdBy, now)

		if err == nil {
			created++
		}
	}

	if created == 0 {
		return fmt.Errorf("no tasks created (no active beacons)")
	}

	return nil
}

// generateTaskID creates a unique task identifier
func generateTaskID() string {
	return fmt.Sprintf("task_%d_%d", time.Now().UnixNano(), randomInt(10000, 99999))
}

func randomInt(min, max int) int {
	return min + int(time.Now().UnixNano()%(int64(max-min)))
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
func (d *MasterDatabase) CreateTask(beaconID, command, createdBy string) (string, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	// Get the beacon's assigned DNS server
	var dnsServerID string
	err := d.db.QueryRow(`
		SELECT dns_server_id FROM beacons WHERE id = ? AND status = 'active'
	`, beaconID).Scan(&dnsServerID)

	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("beacon not found or inactive")
		}
		return "", fmt.Errorf("failed to get beacon info: %w", err)
	}

	// Generate task ID
	taskID := generateTaskID()
	now := time.Now().Unix()

	// Create task
	_, err = d.db.Exec(`
		INSERT INTO tasks (id, beacon_id, command, status, assigned_dns_server, created_by, created_at)
		VALUES (?, ?, ?, 'pending', ?, ?, ?)
	`, taskID, beaconID, command, dnsServerID, createdBy, now)

	if err != nil {
		return "", fmt.Errorf("failed to create task: %w", err)
	}

	return taskID, nil
}

// GetTasksForDNSServer retrieves pending tasks assigned to a DNS server's beacons
func (d *MasterDatabase) GetTasksForDNSServer(dnsServerID string) ([]map[string]interface{}, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	rows, err := d.db.Query(`
		SELECT id, beacon_id, command, status, created_at
		FROM tasks
		WHERE assigned_dns_server = ? AND status = 'pending'
		ORDER BY created_at ASC
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

// GetAllTasks retrieves all tasks with their status
func (d *MasterDatabase) GetAllTasks(limit int) ([]map[string]interface{}, error) {
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

		tasks = append(tasks, task)
	}

	return tasks, rows.Err()
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
	} else if status == "sent" {
		// Task is in progress, calculate progress from actual received chunks
		progress, err := d.GetTaskProgressFromResults(taskID)
		if err == nil {
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
	d.mutex.RLock()
	defer d.mutex.RUnlock()

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
	var totalExpected sql.NullInt64
	err = d.db.QueryRow(`
		SELECT MAX(total_chunks) FROM task_results
		WHERE task_id = ? AND total_chunks > 1
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
	_, err := d.db.Exec(`
		UPDATE tasks 
		SET status = 'completed', completed_at = ?
		WHERE id = ? AND status != 'completed'
	`, now, taskID)

	if err != nil {
		fmt.Printf("[Master DB] Error marking task %s as completed: %v\n", taskID, err)
	}
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

	return stats, nil
}
