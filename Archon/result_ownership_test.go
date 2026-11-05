package main

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The Master must reject a result or completion whose beacon_id does not match
// the task's beacon, so listeners can relay without a local task copy.
func TestResultHandlersEnforceBeaconOwnership(t *testing.T) {
	db := newTestProfileDB(t)
	now := time.Now()
	if err := db.UpsertBeacon("b1", "h", "u", "linux", "amd64", "10.0.0.1", "dns-1",
		now, now, "", "", "", "", nil); err != nil {
		t.Fatalf("UpsertBeacon: %v", err)
	}
	taskID, err := db.CreateTask("b1", "printf ok", "")
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}

	api := &APIServer{db: db}

	do := func(path, body string) int {
		req := httptest.NewRequest("POST", path, strings.NewReader(body))
		rec := httptest.NewRecorder()
		if strings.Contains(path, "complete") {
			api.handleResultComplete(rec, req)
		} else {
			api.handleSubmitResult(rec, req)
		}
		return rec.Code
	}

	submit := func(beacon string) string {
		return fmt.Sprintf(`{"task_id":"%s","beacon_id":"%s","chunk_index":1,"total_chunks":1,"data":"OK"}`, taskID, beacon)
	}
	complete := func(beacon string) string {
		return fmt.Sprintf(`{"task_id":"%s","beacon_id":"%s","total_chunks":1}`, taskID, beacon)
	}

	if code := do("/api/dns-server/result", submit("b2")); code != 403 {
		t.Errorf("submit mismatched beacon: code=%d, want 403", code)
	}
	if code := do("/api/dns-server/result", submit("b1")); code != 200 {
		t.Errorf("submit matching beacon: code=%d, want 200", code)
	}
	if code := do("/api/dns-server/result/complete", complete("b2")); code != 403 {
		t.Errorf("complete mismatched beacon: code=%d, want 403", code)
	}
	if code := do("/api/dns-server/result/complete", complete("b1")); code != 200 {
		t.Errorf("complete matching beacon: code=%d, want 200", code)
	}
}
