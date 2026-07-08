package main

import (
	"os"
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
	if len(tasksB) > 0 && tasksB[0]["id"] != taskID {
		t.Errorf("Task ID mismatch: expected %s, got %s", taskID, tasksB[0]["id"])
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
		if tasksB[0]["id"] != taskID {
			t.Errorf("Task ID mismatch: expected %s, got %s", taskID, tasksB[0]["id"])
		}
		if tasksB[0]["status"] != "sent" {
			t.Errorf("Task status mismatch: expected 'sent', got %s", tasksB[0]["status"])
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
