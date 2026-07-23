package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// Helper function to create a test task directly in the database
// bypassing FK checks (for isolated unit testing)
func createTestTask(db *MasterDatabase, taskID, beaconID, command string) error {
	now := time.Now().Unix()
	_, err := db.db.Exec(`
		INSERT INTO tasks (id, beacon_id, command, status, created_at, updated_at)
		VALUES (?, ?, ?, 'pending', ?, ?)
	`, taskID, beaconID, command, now, now)
	return err
}

// Helper function to create a test beacon directly in the database
func createTestBeacon(db *MasterDatabase, beaconID string) error {
	now := time.Now().Unix()
	_, err := db.db.Exec(`
		INSERT INTO beacons (id, hostname, username, os, arch, ip_address, dns_server_id, first_seen, last_seen, status, created_at, updated_at)
		VALUES (?, 'testhost', 'testuser', 'linux', 'amd64', '192.168.1.100', 'dns-server-A', ?, ?, 'active', ?, ?)
	`, beaconID, now, now, now, now)
	return err
}

// TestGetTasksForDNSServer verifies that all pending tasks are returned to any DNS server
// regardless of beacon_dns_contacts (Shadow Mesh fix)
func TestGetTasksForDNSServer(t *testing.T) {
	// Create temp database
	tmpDB := "test_tasks_" + time.Now().Format("20060102150405") + ".db"
	defer os.Remove(tmpDB)

	db, err := NewMasterDatabase(tmpDB)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Create a beacon directly
	beaconID := "test-beacon-001"
	if err := createTestBeacon(db, beaconID); err != nil {
		t.Fatalf("Failed to create beacon: %v", err)
	}

	// Create a task directly
	taskID := "T0001"
	if err := createTestTask(db, taskID, beaconID, "whoami"); err != nil {
		t.Fatalf("Failed to create task: %v", err)
	}

	// DNS Server A (which has seen the beacon) should see the task
	tasksA, err := db.GetTasksForDNSServer("dns-server-A")
	if err != nil {
		t.Fatalf("GetTasksForDNSServer failed for server A: %v", err)
	}
	if len(tasksA) != 1 {
		t.Errorf("Expected 1 task for dns-server-A, got %d", len(tasksA))
	}

	// DNS Server B (which has NEVER seen the beacon) should ALSO see the task
	// This is the Shadow Mesh fix - before the fix, this would return 0 tasks
	tasksB, err := db.GetTasksForDNSServer("dns-server-B")
	if err != nil {
		t.Fatalf("GetTasksForDNSServer failed for server B: %v", err)
	}
	if len(tasksB) != 1 {
		t.Errorf("SHADOW MESH BUG: Expected 1 task for dns-server-B (new server), got %d", len(tasksB))
	}

	// Verify task ID matches
	if len(tasksB) > 0 && tasksB[0].ID != taskID {
		t.Errorf("Task ID mismatch: expected %s, got %s", taskID, tasksB[0].ID)
	}
}

// TestGetCompletedTasksForSync verifies that completed tasks are synced to all DNS servers
// regardless of assigned_dns_server (Shadow Mesh fix)
func TestGetCompletedTasksForSync(t *testing.T) {
	tmpDB := "test_sync_" + time.Now().Format("20060102150405") + ".db"
	defer os.Remove(tmpDB)

	db, err := NewMasterDatabase(tmpDB)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Create a beacon and task directly
	beaconID := "test-beacon-002"
	if err := createTestBeacon(db, beaconID); err != nil {
		t.Fatalf("Failed to create beacon: %v", err)
	}

	taskID := "T0002"
	if err := createTestTask(db, taskID, beaconID, "id"); err != nil {
		t.Fatalf("Failed to create task: %v", err)
	}

	// Mark task as 'sent' directly (bypass MarkTaskDelivered to avoid FK issues)
	now := time.Now().Unix()
	_, err = db.db.Exec(`UPDATE tasks SET status = 'sent', sent_at = ?, updated_at = ? WHERE id = ?`,
		now, now, taskID)
	if err != nil {
		t.Fatalf("Failed to update task status: %v", err)
	}

	// DNS Server B should see the status change even though it didn't deliver the task
	// This is the fix - before, assigned_dns_server=NULL meant no server saw updates
	tasksB, err := db.GetCompletedTasksForSync("dns-server-B")
	if err != nil {
		t.Fatalf("GetCompletedTasksForSync failed: %v", err)
	}

	// Should have 1 task with status 'sent'
	if len(tasksB) != 1 {
		t.Errorf("SHADOW MESH BUG: Expected 1 task status update for dns-server-B, got %d", len(tasksB))
	}

	if len(tasksB) > 0 {
		if tasksB[0].TaskID != taskID {
			t.Errorf("Task ID mismatch: expected %s, got %s", taskID, tasksB[0].TaskID)
		}
		if tasksB[0].Status != "sent" {
			t.Errorf("Task status mismatch: expected 'sent', got %s", tasksB[0].Status)
		}
	}
}

// TestMarkTaskDeliveredAtomicity verifies that only one DNS server can claim a task
// Note: This test creates a DNS server record first to satisfy FK constraints
func TestMarkTaskDeliveredAtomicity(t *testing.T) {
	tmpDB := "test_atomic_" + time.Now().Format("20060102150405") + ".db"
	defer os.Remove(tmpDB)

	db, err := NewMasterDatabase(tmpDB)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Create DNS servers to satisfy FK constraints
	now := time.Now().Unix()
	db.db.Exec(`INSERT INTO dns_servers (id, domain, address, api_key_hash, status, first_seen, last_checkin, created_at, updated_at)
		VALUES ('dns-server-A', 'a.example.com', '1.1.1.1', 'hash-a', 'active', ?, ?, ?, ?)`, now, now, now, now)
	db.db.Exec(`INSERT INTO dns_servers (id, domain, address, api_key_hash, status, first_seen, last_checkin, created_at, updated_at)
		VALUES ('dns-server-B', 'b.example.com', '2.2.2.2', 'hash-b', 'active', ?, ?, ?, ?)`, now, now, now, now)

	// Create a beacon and task directly
	beaconID := "test-beacon-003"
	if err := createTestBeacon(db, beaconID); err != nil {
		t.Fatalf("Failed to create beacon: %v", err)
	}

	taskID := "T0003"
	if err := createTestTask(db, taskID, beaconID, "hostname"); err != nil {
		t.Fatalf("Failed to create task: %v", err)
	}

	// First server claims the task
	claimed1, err := db.MarkTaskDelivered(taskID, "dns-server-A")
	if err != nil {
		t.Fatalf("First MarkTaskDelivered failed: %v", err)
	}
	if !claimed1 {
		t.Error("First server should have claimed the task")
	}

	// Second server tries to claim the same task - should fail
	claimed2, err := db.MarkTaskDelivered(taskID, "dns-server-B")
	if err != nil {
		t.Fatalf("Second MarkTaskDelivered failed: %v", err)
	}
	if claimed2 {
		t.Error("ATOMICITY BUG: Second server should NOT have claimed the task")
	}
}

// TestTaskStatusConsistency verifies task status values are consistent
func TestTaskStatusConsistency(t *testing.T) {
	tmpDB := "test_status_" + time.Now().Format("20060102150405") + ".db"
	defer os.Remove(tmpDB)

	db, err := NewMasterDatabase(tmpDB)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Create DNS server to satisfy FK constraint
	now := time.Now().Unix()
	db.db.Exec(`INSERT INTO dns_servers (id, domain, address, api_key_hash, status, first_seen, last_checkin, created_at, updated_at)
		VALUES ('dns-server-A', 'a.example.com', '1.1.1.1', 'hash-a', 'active', ?, ?, ?, ?)`, now, now, now, now)

	// Create a beacon and task directly
	beaconID := "test-beacon-005"
	if err := createTestBeacon(db, beaconID); err != nil {
		t.Fatalf("Failed to create beacon: %v", err)
	}

	taskID := "T0005"
	if err := createTestTask(db, taskID, beaconID, "pwd"); err != nil {
		t.Fatalf("Failed to create task: %v", err)
	}

	// Check initial status is 'pending'
	var status string
	err = db.db.QueryRow("SELECT status FROM tasks WHERE id = ?", taskID).Scan(&status)
	if err != nil {
		t.Fatalf("Failed to query task: %v", err)
	}
	if status != "pending" {
		t.Errorf("Expected initial status 'pending', got '%s'", status)
	}

	// Mark as delivered - status should be 'sent'
	db.MarkTaskDelivered(taskID, "dns-server-A")
	db.db.QueryRow("SELECT status FROM tasks WHERE id = ?", taskID).Scan(&status)
	if status != "sent" {
		t.Errorf("Expected status 'sent' after delivery, got '%s'", status)
	}

	// Valid task statuses for the tasks table
	validStatuses := map[string]bool{
		"pending":      true,
		"sent":         true,
		"exfiltrating": true,
		"completed":    true, // NOT 'complete' - that's for exfil_transfers
		"failed":       true,
		"timeout":      true,
		"partial":      true,
	}

	if !validStatuses[status] {
		t.Errorf("Invalid task status '%s'", status)
	}
}

func newTestDB(t *testing.T) (*MasterDatabase, func()) {
	t.Helper()
	tmpDB := "test_typed_" + t.Name() + "_" + time.Now().Format("20060102150405") + ".db"
	db, err := NewMasterDatabase(tmpDB)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	return db, func() {
		db.Close()
		os.Remove(tmpDB)
	}
}

func TestGetBeaconReturnsTypedStruct(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	beaconID := "typed-beacon-001"
	if err := createTestBeacon(db, beaconID); err != nil {
		t.Fatalf("Failed to create beacon: %v", err)
	}

	beacon, err := db.GetBeacon(beaconID)
	if err != nil {
		t.Fatalf("GetBeacon failed: %v", err)
	}

	if beacon.ID != beaconID {
		t.Errorf("ID: expected %s, got %s", beaconID, beacon.ID)
	}
	if beacon.Hostname != "testhost" {
		t.Errorf("Hostname: expected testhost, got %s", beacon.Hostname)
	}
	if beacon.Username != "testuser" {
		t.Errorf("Username: expected testuser, got %s", beacon.Username)
	}
	if beacon.OS != "linux" {
		t.Errorf("OS: expected linux, got %s", beacon.OS)
	}
	if beacon.Status != "active" {
		t.Errorf("Status: expected active, got %s", beacon.Status)
	}

	// Timestamps should be RFC3339 formatted
	if _, err := time.Parse(time.RFC3339, beacon.FirstSeen); err != nil {
		t.Errorf("FirstSeen not RFC3339: %s (%v)", beacon.FirstSeen, err)
	}
	if _, err := time.Parse(time.RFC3339, beacon.LastSeen); err != nil {
		t.Errorf("LastSeen not RFC3339: %s (%v)", beacon.LastSeen, err)
	}
}

func TestGetBeaconNotFound(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	beacon, err := db.GetBeacon("nonexistent")
	if err != nil {
		t.Fatalf("GetBeacon should not error for missing beacon: %v", err)
	}
	if beacon.ID != "" {
		t.Errorf("Expected empty Beacon for not found, got ID=%s", beacon.ID)
	}
}

func TestGetDNSServersReturnsTypedStruct(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	now := time.Now().Unix()
	db.db.Exec(`INSERT INTO dns_servers (id, domain, address, api_key_hash, status, first_seen, last_checkin, created_at, updated_at)
		VALUES ('dns-1', 'c2.example.com', '10.0.0.1', 'hash', 'active', ?, ?, ?, ?)`, now, now, now, now)

	servers, err := db.GetDNSServers()
	if err != nil {
		t.Fatalf("GetDNSServers failed: %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("Expected 1 server, got %d", len(servers))
	}

	s := servers[0]
	if s.ID != "dns-1" {
		t.Errorf("ID: expected dns-1, got %s", s.ID)
	}
	if s.Domain != "c2.example.com" {
		t.Errorf("Domain: expected c2.example.com, got %s", s.Domain)
	}
	if s.Status != "active" {
		t.Errorf("Status: expected active, got %s", s.Status)
	}
	if _, err := time.Parse(time.RFC3339, s.FirstSeen); err != nil {
		t.Errorf("FirstSeen not RFC3339: %s", s.FirstSeen)
	}
}

func TestGetAllBeaconsPaginated(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	for i := 0; i < 5; i++ {
		if err := createTestBeacon(db, "beacon-page-"+string(rune('a'+i))); err != nil {
			t.Fatalf("Failed to create beacon %d: %v", i, err)
		}
	}

	beacons, err := db.GetAllBeaconsPaginated(3, 0)
	if err != nil {
		t.Fatalf("GetAllBeaconsPaginated failed: %v", err)
	}
	if len(beacons) != 3 {
		t.Errorf("Expected 3 beacons (limit), got %d", len(beacons))
	}

	beacons2, err := db.GetAllBeaconsPaginated(10, 3)
	if err != nil {
		t.Fatalf("GetAllBeaconsPaginated offset failed: %v", err)
	}
	if len(beacons2) != 2 {
		t.Errorf("Expected 2 beacons (offset=3), got %d", len(beacons2))
	}
}

func TestGetOperatorReturnsTypedStruct(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	opID := "op-typed-001"
	if err := db.CreateOperator(opID, "testop", "password123", "operator", "test@test.com"); err != nil {
		t.Fatalf("Failed to create operator: %v", err)
	}

	op, err := db.GetOperator(opID)
	if err != nil {
		t.Fatalf("GetOperator failed: %v", err)
	}
	if op.ID != opID {
		t.Errorf("ID: expected %s, got %s", opID, op.ID)
	}
	if op.Username != "testop" {
		t.Errorf("Username: expected testop, got %s", op.Username)
	}
	if op.Role != "operator" {
		t.Errorf("Role: expected operator, got %s", op.Role)
	}
	if !op.IsActive {
		t.Error("Expected operator to be active")
	}
}

func TestGetAllOperators(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	db.CreateOperator("op1", "alice", "pass1", "admin", "")
	db.CreateOperator("op2", "bob", "pass2", "operator", "")

	ops, err := db.GetAllOperators()
	if err != nil {
		t.Fatalf("GetAllOperators failed: %v", err)
	}
	if len(ops) != 2 {
		t.Errorf("Expected 2 operators, got %d", len(ops))
	}
}

func TestGetTaskWithResultReturnsTypedStruct(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	beaconID := "beacon-task-typed"
	if err := createTestBeacon(db, beaconID); err != nil {
		t.Fatalf("Failed to create beacon: %v", err)
	}

	taskID := "T9001"
	if err := createTestTask(db, taskID, beaconID, "whoami"); err != nil {
		t.Fatalf("Failed to create task: %v", err)
	}

	task, err := db.GetTaskWithResult(taskID)
	if err != nil {
		t.Fatalf("GetTaskWithResult failed: %v", err)
	}

	if task.ID != taskID {
		t.Errorf("ID: expected %s, got %s", taskID, task.ID)
	}
	if task.BeaconID != beaconID {
		t.Errorf("BeaconID: expected %s, got %s", beaconID, task.BeaconID)
	}
	if task.Command != "whoami" {
		t.Errorf("Command: expected whoami, got %s", task.Command)
	}
	if task.Status != "pending" {
		t.Errorf("Status: expected pending, got %s", task.Status)
	}
}

func TestGetDatabaseStatsReturnsTypedStruct(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	createTestBeacon(db, "stats-beacon-1")
	createTestBeacon(db, "stats-beacon-2")
	createTestTask(db, "T-STATS-1", "stats-beacon-1", "id")

	stats, err := db.GetDatabaseStats()
	if err != nil {
		t.Fatalf("GetDatabaseStats failed: %v", err)
	}

	if stats.Beacons != 2 {
		t.Errorf("Beacons: expected 2, got %d", stats.Beacons)
	}
	if stats.Tasks != 1 {
		t.Errorf("Tasks: expected 1, got %d", stats.Tasks)
	}
}

func TestGetBeaconDomains(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	beaconID := "beacon-domain-test"
	createTestBeacon(db, beaconID)

	now := time.Now().Unix()
	db.db.Exec(`INSERT INTO dns_servers (id, domain, address, api_key_hash, status, first_seen, last_checkin, created_at, updated_at)
		VALUES ('dns-dom-1', 'c2.test.com', '10.0.0.1', 'hash', 'active', ?, ?, ?, ?)`, now, now, now, now)

	db.db.Exec(`INSERT INTO beacon_domains (beacon_id, domain, active, added_at)
		VALUES (?, 'c2.test.com', 1, ?)`, beaconID, now)

	domains, err := db.GetBeaconDomains(beaconID)
	if err != nil {
		t.Fatalf("GetBeaconDomains failed: %v", err)
	}
	if len(domains) != 1 {
		t.Fatalf("Expected 1 domain, got %d", len(domains))
	}
	if domains[0].Domain != "c2.test.com" {
		t.Errorf("Domain: expected c2.test.com, got %s", domains[0].Domain)
	}
	if !domains[0].Active {
		t.Error("Expected domain to be active")
	}
}

func TestBuildConfigJSONFlattensExtra(t *testing.T) {
	bc := BuildConfig{
		BinaryID:   "bin-001",
		BuildID:    "build-001",
		OS:         "linux",
		Arch:       "amd64",
		DNSDomains: "c2.test.com",
		CreatedAt:  "2025-01-01T00:00:00Z",
		Extra: map[string]interface{}{
			"sleep_min":      10,
			"sleep_max":      30,
			"beacon_name":    "test-beacon",
			"payload_format": "hex",
		},
	}

	data, err := json.Marshal(bc)
	if err != nil {
		t.Fatalf("Failed to marshal BuildConfig: %v", err)
	}

	var flat map[string]interface{}
	if err := json.Unmarshal(data, &flat); err != nil {
		t.Fatalf("Failed to unmarshal BuildConfig JSON: %v", err)
	}

	// Fixed fields should be at top level
	if flat["binary_id"] != "bin-001" {
		t.Errorf("binary_id: expected bin-001, got %v", flat["binary_id"])
	}
	if flat["os"] != "linux" {
		t.Errorf("os: expected linux, got %v", flat["os"])
	}

	// Extra fields should be flattened to top level (not nested under "extra")
	if flat["sleep_min"] != float64(10) {
		t.Errorf("sleep_min: expected 10, got %v", flat["sleep_min"])
	}
	if flat["beacon_name"] != "test-beacon" {
		t.Errorf("beacon_name: expected test-beacon, got %v", flat["beacon_name"])
	}

	// Should NOT have an "extra" key
	if _, hasExtra := flat["extra"]; hasExtra {
		t.Error("BuildConfig JSON should not have 'extra' key - fields should be flat")
	}
}

func TestBeaconWithBuildConfigJSON(t *testing.T) {
	bc := BuildConfig{
		BinaryID: "bin-002",
		BuildID:  "build-002",
		OS:       "windows",
		Arch:     "amd64",
		Extra: map[string]interface{}{
			"sleep_min": 5,
		},
	}
	beacon := Beacon{
		ID:          "beacon-json-test",
		Hostname:    "DESKTOP-ABC",
		Status:      "active",
		BuildConfig: &bc,
	}

	data, err := json.Marshal(beacon)
	if err != nil {
		t.Fatalf("Failed to marshal Beacon: %v", err)
	}

	jsonStr := string(data)
	if !strings.Contains(jsonStr, `"build_config"`) {
		t.Error("Beacon JSON should contain build_config when set")
	}
	if !strings.Contains(jsonStr, `"sleep_min"`) {
		t.Error("build_config should contain flattened extra fields")
	}
}

func TestBeaconWithoutBuildConfigOmitted(t *testing.T) {
	beacon := Beacon{
		ID:       "beacon-no-bc",
		Hostname: "test",
		Status:   "active",
	}

	data, err := json.Marshal(beacon)
	if err != nil {
		t.Fatalf("Failed to marshal Beacon: %v", err)
	}

	if strings.Contains(string(data), "build_config") {
		t.Error("Beacon JSON should omit build_config when nil")
	}
}

func TestCompletedTaskSyncJSONUsesID(t *testing.T) {
	task := CompletedTaskSync{
		TaskID:   "T0099",
		BeaconID: "beacon-sync",
		Status:   "completed",
	}

	data, err := json.Marshal(task)
	if err != nil {
		t.Fatalf("Failed to marshal CompletedTaskSync: %v", err)
	}

	var m map[string]interface{}
	json.Unmarshal(data, &m)

	// Must serialize as "id" to match Server's TaskResponse struct
	if m["id"] != "T0099" {
		t.Errorf("Expected 'id' field with value T0099, got %v", m["id"])
	}
	if _, hasTaskID := m["task_id"]; hasTaskID {
		t.Error("Should not have 'task_id' field - must use 'id' for DNS server compat")
	}
}

func TestGetStagerSessions(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	now := time.Now().Unix()
	db.db.Exec(`INSERT INTO dns_servers (id, domain, address, api_key_hash, status, first_seen, last_checkin, created_at, updated_at)
		VALUES ('dns-stager', 'stager.test.com', '10.0.0.1', 'hash', 'active', ?, ?, ?, ?)`, now, now, now, now)

	// client_binaries row needed for FK
	if _, err := db.db.Exec(`INSERT INTO client_binaries (id, filename, os, arch, version, original_size, compressed_size, base64_size, chunk_size, total_chunks, base64_data, dns_domains, created_at)
		VALUES ('cb-001', 'client.bin', 'linux', 'amd64', '1.0', 1000, 500, 700, 370, 2, 'data', 'stager.test.com', ?)`, now); err != nil {
		t.Fatalf("Failed to insert client_binary: %v", err)
	}

	if _, err := db.db.Exec(`INSERT INTO stager_sessions (id, stager_ip, os, arch, client_binary_id, total_chunks, chunks_delivered, created_at, last_activity, completed, initiated_by_dns)
		VALUES ('stager-001', '192.168.1.50', 'linux', 'amd64', 'cb-001', 100, 50, ?, ?, 0, 'dns-stager')`, now, now); err != nil {
		t.Fatalf("Failed to insert stager_session: %v", err)
	}

	sessions, err := db.GetStagerSessions(10)
	if err != nil {
		t.Fatalf("GetStagerSessions failed: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("Expected 1 session, got %d", len(sessions))
	}

	s := sessions[0]
	if s.ID != "stager-001" {
		t.Errorf("ID: expected stager-001, got %s", s.ID)
	}
	if s.TotalChunks != 100 {
		t.Errorf("TotalChunks: expected 100, got %d", s.TotalChunks)
	}
	if s.Completed {
		t.Error("Expected session to not be completed")
	}
}
