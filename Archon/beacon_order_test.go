package main

import (
	"testing"
	"time"
)

// TestBeaconListOrderIsStableWhileBeaconsPoll pins the dashboard behaviour: rows
// are ordered by when a beacon first registered, so a poll that updates last_seen
// does not reshuffle the table under the operator.
func TestBeaconListOrderIsStableWhileBeaconsPoll(t *testing.T) {
	db := newTestProfileDB(t)

	base := time.Now().Add(-2 * time.Hour)
	seed := func(id, name string, firstSeen time.Time, lastSeen time.Time) {
		t.Helper()
		if err := db.UpsertBeacon(id, name+"-host", "user", "linux", "amd64", "10.0.0.9",
			"listener-1", firstSeen, lastSeen, name, "", "", "", nil); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}

	// Registered in this order, but the third one polls most recently.
	seed("b-one", "one", base, base.Add(1*time.Minute))
	seed("b-two", "two", base.Add(10*time.Minute), base.Add(11*time.Minute))
	seed("b-three", "three", base.Add(20*time.Minute), time.Now())

	order := func() []string {
		t.Helper()
		beacons, err := db.GetAllBeaconsPaginated(50, 0)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		ids := make([]string, 0, len(beacons))
		for _, b := range beacons {
			ids = append(ids, b.ID)
		}
		return ids
	}

	before := order()
	want := []string{"b-one", "b-two", "b-three"}
	if len(before) != len(want) {
		t.Fatalf("got %d beacons, want %d", len(before), len(want))
	}
	for i := range want {
		if before[i] != want[i] {
			t.Fatalf("order = %v, want registration order %v", before, want)
		}
	}

	// The first beacon polls again and becomes the most recently seen. Under the
	// old last_seen ordering it would jump to the top.
	fresh := time.Now().Add(2 * time.Second)
	if err := db.UpsertBeacon("b-one", "one-host", "user", "linux", "amd64", "10.0.0.9",
		"listener-1", base, fresh, "one", "", "", "", nil); err != nil {
		t.Fatalf("update b-one: %v", err)
	}

	after := order()
	for i := range want {
		if after[i] != want[i] {
			t.Fatalf("order changed after a poll: %v, want %v", after, want)
		}
	}
}
