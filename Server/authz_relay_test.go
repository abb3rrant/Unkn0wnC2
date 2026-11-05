package main

import "testing"

// A listener must relay a result for a task it has not synced yet (Shadow Mesh /
// dual), while still rejecting a result for a task it knows belongs to another
// beacon. Master enforces ownership authoritatively.
func TestAuthorizeBeaconControl_RelaysUnknownLocalTask(t *testing.T) {
	c2 := NewC2Manager(false, "test-key", StagerJitter{}, "", "test.domain")
	c2.beacons["b1"] = &Beacon{ID: "b1", Encoding: "aes-gcm-base36"}
	c2.tasks["T1"] = &Task{ID: "T1", BeaconID: "other"}
	c2.tasks["T2"] = &Task{ID: "T2", BeaconID: "b1"}

	cases := []struct {
		name  string
		parts []string
		want  bool
	}{
		{"unknown local task -> relay", []string{"RESULT_META", "b1", "T999", "10", "1", "ts"}, true},
		{"known task of another beacon -> reject", []string{"RESULT_META", "b1", "T1", "10", "1", "ts"}, false},
		{"known own task -> allow", []string{"RESULT_META", "b1", "T2", "10", "1", "ts"}, true},
		{"unknown beacon -> reject", []string{"RESULT_META", "b2", "T999", "10", "1", "ts"}, false},
		{"too short -> reject", []string{"RESULT_META"}, false},
	}
	for _, c := range cases {
		if got := c2.authorizeBeaconControl(c.parts, true); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
