package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestRequireLiveBeacon covers the guard that stops tasks being queued to a
// process that no longer exists: a dead beacon's record stays behind, and a task
// accepted for it sits pending forever.
func TestRequireLiveBeacon(t *testing.T) {
	db := newTestProfileDB(t)
	if err := createTestBeacon(db, "beacon-dead"); err != nil {
		t.Fatalf("seed beacon: %v", err)
	}
	api := NewAPIServer(db, Config{})

	// Recent check-in: allowed.
	now := time.Now()
	if err := db.UpsertBeacon("beacon-live", "host", "user", "linux", "amd64", "10.0.0.5",
		"dns-server-A", now, now, "", "", "", "", nil); err != nil {
		t.Fatalf("seed live beacon: %v", err)
	}
	recorder := httptest.NewRecorder()
	if !api.requireLiveBeacon(recorder, "beacon-live", "a task") {
		t.Fatalf("a beacon that just checked in was refused: %s", recorder.Body.String())
	}

	// Silent for an hour: refused, with the consequence named.
	old := time.Now().Add(-1 * time.Hour)
	if err := db.UpsertBeacon("beacon-dead", "host", "user", "linux", "amd64", "10.0.0.6",
		"dns-server-A", old, old, "", "", "", "", nil); err != nil {
		t.Fatalf("seed dead beacon: %v", err)
	}
	recorder = httptest.NewRecorder()
	if api.requireLiveBeacon(recorder, "beacon-dead", "a task") {
		t.Fatal("a beacon silent for an hour accepted a task")
	}
	if recorder.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", recorder.Code)
	}
	if !containsAll(recorder.Body.String(), "has not checked in", "never be delivered") {
		t.Errorf("body does not explain the outcome: %s", recorder.Body.String())
	}
}

// TestBeaconCheckinWindowFollowsBuildSleep pins the window to the beacon's own
// poll interval: a beacon that sleeps for an hour is not dead after ten minutes.
func TestBeaconCheckinWindowFollowsBuildSleep(t *testing.T) {
	db := newTestProfileDB(t)
	api := NewAPIServer(db, Config{})

	// No build record: the default sleep window, scaled like a real one.
	want := defaultSleepWindow * checkinWindowFactor
	if got := api.beaconCheckinWindow("unknown"); got != want {
		t.Fatalf("window for an unknown build = %s, want %s", got, want)
	}
}

func containsAll(haystack string, needles ...string) bool {
	for _, needle := range needles {
		if !strings.Contains(haystack, needle) {
			return false
		}
	}
	return true
}
