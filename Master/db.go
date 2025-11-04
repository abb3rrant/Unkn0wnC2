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

	_, err = d.db.Exec(`
		INSERT INTO dns_servers (id, domain, address, api_key_hash, status, first_seen, last_checkin, created_at, updated_at)
		VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			domain = excluded.domain,
			address = excluded.address,
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
func (d *MasterDatabase) UpdateDNSServerCheckin(dnsServerID string) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	_, err := d.db.Exec(`
		UPDATE dns_servers SET last_checkin = ?, updated_at = ? WHERE id = ?
	`, time.Now().Unix(), time.Now().Unix(), dnsServerID)

	return err
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
func (d *MasterDatabase) UpsertBeacon(beaconID, hostname, username, os, arch, ipAddress, dnsServerID string) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	now := time.Now().Unix()

	// Try to insert first
	_, err := d.db.Exec(`
		INSERT INTO beacons (id, hostname, username, os, arch, ip_address, dns_server_id, first_seen, last_seen, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')
		ON CONFLICT(id) DO UPDATE SET
			hostname = excluded.hostname,
			username = excluded.username,
			os = excluded.os,
			arch = excluded.arch,
			ip_address = excluded.ip_address,
			dns_server_id = excluded.dns_server_id,
			last_seen = excluded.last_seen,
			status = 'active'
	`, beaconID, hostname, username, os, arch, ipAddress, dnsServerID, now, now)

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
			// We have all chunks! Reassemble them
			fmt.Printf("[Master DB] All %d chunks received for task %s, reassembling...\n", totalChunks, taskID)
			go d.reassembleChunkedResult(taskID, beaconID, totalChunks)
		}
	}

	return nil
}

// reassembleChunkedResult combines all chunks into a complete result
func (d *MasterDatabase) reassembleChunkedResult(taskID, beaconID string, totalChunks int) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

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
	d.db.QueryRow("SELECT COUNT(*) FROM dns_servers").Scan(&dnsServerCount)
	d.db.QueryRow("SELECT COUNT(*) FROM dns_servers WHERE status = 'active'").Scan(&activeDNSServerCount)
	stats["dns_servers"] = dnsServerCount
	stats["active_dns_servers"] = activeDNSServerCount

	// Count beacons
	var beaconCount, activeBeaconCount int
	d.db.QueryRow("SELECT COUNT(*) FROM beacons").Scan(&beaconCount)
	cutoff := time.Now().Add(-24 * time.Hour).Unix()
	d.db.QueryRow("SELECT COUNT(*) FROM beacons WHERE last_seen > ? AND status = 'active'", cutoff).Scan(&activeBeaconCount)
	stats["beacons"] = beaconCount
	stats["active_beacons"] = activeBeaconCount

	// Count tasks
	var taskCount int
	d.db.QueryRow("SELECT COUNT(*) FROM tasks").Scan(&taskCount)
	stats["tasks"] = taskCount

	// Tasks by status
	rows, err := d.db.Query("SELECT status, COUNT(*) FROM tasks GROUP BY status")
	if err == nil {
		defer rows.Close()
		tasksByStatus := make(map[string]int)
		for rows.Next() {
			var status string
			var count int
			rows.Scan(&status, &count)
			tasksByStatus[status] = count
		}
		stats["tasks_by_status"] = tasksByStatus
	}

	// Count operators
	var operatorCount int
	d.db.QueryRow("SELECT COUNT(*) FROM operators WHERE is_active = 1").Scan(&operatorCount)
	stats["operators"] = operatorCount

	// Recent audit events
	var auditEventCount int
	d.db.QueryRow("SELECT COUNT(*) FROM audit_log WHERE timestamp > ?", cutoff).Scan(&auditEventCount)
	stats["recent_audit_events"] = auditEventCount

	return stats, nil
}
