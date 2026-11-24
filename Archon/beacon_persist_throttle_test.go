package main

import (
	"testing"
	"time"
)

// The coalescing gate must write the first report, suppress a 5s follow-up,
// always allow registration traffic, and resume after the interval.
func TestShouldPersistBeaconCoalesces(t *testing.T) {
	id := "test-beacon-coalesce"

	if !shouldPersistBeacon(id, false) {
		t.Fatal("first report must persist")
	}
	if shouldPersistBeacon(id, false) {
		t.Error("immediate follow-up must be suppressed")
	}
	if !shouldPersistBeacon(id, true) {
		t.Error("registration traffic must never be dropped")
	}

	// simulate the interval elapsing
	beaconPersistGate.Lock()
	beaconPersistGate.last[id] = time.Now().Add(-beaconPersistInterval - time.Second)
	beaconPersistGate.Unlock()

	if !shouldPersistBeacon(id, false) {
		t.Error("report after the interval must persist")
	}

	// distinct beacons are tracked independently
	if !shouldPersistBeacon("test-beacon-other", false) {
		t.Error("a new beacon must persist immediately")
	}
}

// Fast pollers must not produce unbounded map growth per unique beacon id.
func TestBeaconPersistGateTracksPerBeacon(t *testing.T) {
	beaconPersistGate.Lock()
	n := len(beaconPersistGate.last)
	beaconPersistGate.Unlock()

	shouldPersistBeacon("test-beacon-third", false)

	beaconPersistGate.Lock()
	after := len(beaconPersistGate.last)
	beaconPersistGate.Unlock()

	if after != n+1 {
		t.Errorf("expected one new entry, got %d -> %d", n, after)
	}
}
