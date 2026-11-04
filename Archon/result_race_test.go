package main

import (
	"testing"
	"time"
)

// OBS-1 regression: a RESULT_COMPLETE that arrives before the single data chunk
// (mesh ordering) must not finalize the task as an empty result, and the data
// that lands afterwards must still be preserved and complete the task.
func TestResultNotLostWhenCompletionArrivesBeforeData(t *testing.T) {
	db := newTestProfileDB(t)
	if err := db.UpsertBeacon("beacon-race", "host", "user", "linux", "amd64", "10.0.0.5",
		"dns-server-A", time.Now(), time.Now(), "", "", "", "", nil); err != nil {
		t.Fatalf("UpsertBeacon: %v", err)
	}
	taskID, err := db.CreateTask("beacon-race", "echo race-ok", "")
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	// The task was delivered to the beacon (status sent) before it ran.
	if _, err := db.db.Exec(`UPDATE tasks SET status = 'sent' WHERE id = ?`, taskID); err != nil {
		t.Fatal(err)
	}

	// Completion signal arrives before any DATA chunk (a different relay).
	if err := db.MarkTaskCompleteFromBeacon(taskID, "beacon-race", 1); err != nil {
		t.Fatalf("MarkTaskCompleteFromBeacon: %v", err)
	}

	// The completion signal alone must not finalize the task as complete-empty.
	task, err := db.GetTaskWithResult(taskID)
	if err != nil {
		t.Fatal(err)
	}
	if task.Status == "completed" {
		t.Fatalf("task finalized as completed before its data arrived (result lost path)")
	}

	// The data chunk arrives later and must be preserved and complete the task.
	if err := db.SaveResultChunk(taskID, "beacon-race", "dns-1", 1, 1, "RACE_RESULT_OK"); err != nil {
		t.Fatalf("SaveResultChunk: %v", err)
	}
	task, err = db.GetTaskWithResult(taskID)
	if err != nil {
		t.Fatal(err)
	}
	if task.Status != "completed" {
		t.Fatalf("status = %q, want completed after late data", task.Status)
	}
	if task.Result != "RACE_RESULT_OK" {
		t.Fatalf("result = %q, want RACE_RESULT_OK (completion-before-data must not lose the payload)", task.Result)
	}
}
