package main

import (
	"strings"
	"testing"
	"time"
)

// TestFailTasksForDeadBeacons covers the ledger: work queued to a beacon that then
// dies must end as failed with a reason, not pending forever.
func TestFailTasksForDeadBeacons(t *testing.T) {
	db := newTestProfileDB(t)

	old := time.Now().Add(-2 * time.Hour)
	fresh := time.Now()

	if err := db.UpsertBeacon("beacon-dead", "host", "user", "linux", "amd64", "10.0.0.5",
		"dns-server-A", old, old, "", "", "", "", nil); err != nil {
		t.Fatalf("seed dead beacon: %v", err)
	}
	if err := db.UpsertBeacon("beacon-live", "host", "user", "linux", "amd64", "10.0.0.6",
		"dns-server-A", fresh, fresh, "", "", "", "", nil); err != nil {
		t.Fatalf("seed live beacon: %v", err)
	}

	deadTask, err := db.CreateTask("beacon-dead", "whoami", "")
	if err != nil {
		t.Fatalf("create task for dead beacon: %v", err)
	}
	liveTask, err := db.CreateTask("beacon-live", "whoami", "")
	if err != nil {
		t.Fatalf("create task for live beacon: %v", err)
	}

	failed, err := db.FailTasksForDeadBeacons()
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if failed != 1 {
		t.Fatalf("swept %d tasks, want 1", failed)
	}

	var status string
	if err := db.db.QueryRow(`SELECT status FROM tasks WHERE id = ?`, deadTask).Scan(&status); err != nil {
		t.Fatalf("read dead task: %v", err)
	}
	if status != "failed" {
		t.Fatalf("dead beacon task status = %q, want failed", status)
	}

	var reason string
	if err := db.db.QueryRow(`SELECT result_data FROM task_results WHERE task_id = ?`, deadTask).Scan(&reason); err != nil {
		t.Fatalf("read reason: %v", err)
	}
	if !strings.Contains(reason, "has not checked in since") {
		t.Errorf("reason does not explain the failure: %q", reason)
	}

	if err := db.db.QueryRow(`SELECT status FROM tasks WHERE id = ?`, liveTask).Scan(&status); err != nil {
		t.Fatalf("read live task: %v", err)
	}
	if status != "pending" {
		t.Fatalf("live beacon task status = %q, want pending (the sweep cancelled a live beacon's work)", status)
	}
}
