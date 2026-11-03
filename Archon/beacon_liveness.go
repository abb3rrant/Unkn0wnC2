package main

import (
	"fmt"
	"net/http"
	"time"
)

// Beacon liveness gate.
//
// A beacon is a process: when it dies, its record stays behind. Tasking a dead
// beacon is not a failure the operator can see — Archon accepts the task, the
// listener fetches it, and it sits pending forever because nothing polls for it.
// The same applies to a transport change or a BOF: the dashboard reports the
// change queued while the beacon it was meant for no longer exists.
//
// So tasking is refused when a beacon has not checked in for longer than its own
// poll window. The window is generous by design: a beacon that sleeps for an hour
// is still live, and the threshold follows its build. This is not a heartbeat
// timeout, only a guard against addressing the dead.

const (
	// minCheckinWindow is the floor, used for builds with no sleep configuration
	// and for beacons whose build was never recorded.
	minCheckinWindow = 10 * time.Minute
	// checkinWindowFactor multiplies the beacon's maximum sleep interval: one
	// missed deadline is normal (a poll can land either side of the timer), three
	// in a row is not.
	checkinWindowFactor = 3
	// defaultSleepWindow applies when the build says nothing.
	defaultSleepWindow = 10 * time.Minute
)

// beaconCheckinWindow returns how long a beacon may be silent before it is treated
// as gone.
func (api *APIServer) beaconCheckinWindow(beaconID string) time.Duration {
	sleepMax := time.Duration(0)
	if beacon, err := api.db.GetBeacon(beaconID); err == nil && beacon.BuildID != "" {
		if config, err := api.db.GetBuildConfigByBuildID(beacon.BuildID); err == nil {
			if seconds, ok := config.Extra["sleep_max"].(float64); ok && seconds > 0 {
				sleepMax = time.Duration(seconds) * time.Second
			}
		}
	}
	if sleepMax <= 0 {
		sleepMax = defaultSleepWindow
	}

	window := sleepMax * checkinWindowFactor
	if window < minCheckinWindow {
		window = minCheckinWindow
	}
	return window
}

// requireLiveBeacon writes a 409 and returns false when the beacon has been silent
// for longer than its poll window.
//
// action is what the caller was trying to do, so the message names the consequence
// rather than just the state.
func (api *APIServer) requireLiveBeacon(w http.ResponseWriter, beaconID, action string) bool {
	beacon, err := api.db.GetBeacon(beaconID)
	if err != nil || beacon.ID == "" {
		api.sendError(w, http.StatusNotFound, fmt.Sprintf("no beacon with id %q", beaconID))
		return false
	}
	// LastSeen is an RFC3339 string; a beacon that has never reported has none.
	lastSeen, err := time.Parse(time.RFC3339, beacon.LastSeen)
	if err != nil {
		return true
	}

	window := api.beaconCheckinWindow(beaconID)
	silent := time.Since(lastSeen)
	if silent <= window {
		return true
	}

	api.sendError(w, http.StatusConflict, fmt.Sprintf(
		"beacon %s has not checked in for %s (window %s); %s would never be delivered — it is a dead process, not a sleeping one",
		beaconID, silent.Round(time.Second), window.Round(time.Second), action))
	return false
}
