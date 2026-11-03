package main

import (
	"fmt"
	"strings"
	"time"
)

// migration21AddBeaconHTTPListeners records which HTTP listeners a beacon is using.
//
// The build config states what a beacon was built with, but an operator can move a
// live beacon between listeners with a transport push. Without somewhere to write
// that, the dashboard would show the build-time answer forever - and a beacon that
// had been moved to HTTP would still look DNS-only, which is exactly the case that
// decides whether a BOF may run.
func (d *MasterDatabase) migration21AddBeaconHTTPListeners() error {
	if _, err := d.db.Exec(`
		CREATE TABLE IF NOT EXISTS beacon_http_listeners (
			beacon_id TEXT NOT NULL,
			profile_name TEXT NOT NULL,
			updated_at INTEGER NOT NULL,
			PRIMARY KEY (beacon_id, profile_name)
		)
	`); err != nil {
		return err
	}
	if err := d.addColumnIfMissing("beacons", "transport", "TEXT"); err != nil {
		return err
	}
	// When a transport was requested but no beacon report has confirmed it yet.
	// The dashboard reads this so it can say "pending" instead of claiming a
	// change that may never land.
	return d.addColumnIfMissing("beacons", "transport_pending_since", "INTEGER DEFAULT 0")
}

// SetBeaconHTTPListeners replaces a beacon's listener selection and records the
// transport it was moved to. An empty selection with mode dns is recorded too: it
// is the statement "this beacon is DNS-only", which gates BOF execution.
func (d *MasterDatabase) SetBeaconHTTPListeners(beaconID string, names []string, mode string) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(`DELETE FROM beacon_http_listeners WHERE beacon_id = ?`, beaconID); err != nil {
		return fmt.Errorf("clear listeners for %s: %w", beaconID, err)
	}

	now := time.Now().Unix()
	for _, name := range names {
		if _, err := tx.Exec(`
			INSERT INTO beacon_http_listeners (beacon_id, profile_name, updated_at)
			VALUES (?, ?, ?)
		`, beaconID, name, now); err != nil {
			return fmt.Errorf("record listener %s for %s: %w", name, beaconID, err)
		}
	}

	// Recorded as pending: the task is queued, not applied. A beacon report from
	// the requested transport is what clears this.
	if _, err := tx.Exec(`UPDATE beacons SET transport = ?, transport_pending_since = ?, updated_at = ? WHERE id = ?`, mode, now, now, beaconID); err != nil {
		return fmt.Errorf("record transport for %s: %w", beaconID, err)
	}

	return tx.Commit()
}

// GetBeaconHTTPListeners returns the recorded selection. The second result reports
// whether anything was recorded at all, so a caller can fall back to build-time
// information for beacons that predate this record.
func (d *MasterDatabase) GetBeaconHTTPListeners(beaconID string) ([]string, string, bool) {
	var transport string
	err := d.db.QueryRow(`SELECT COALESCE(transport, '') FROM beacons WHERE id = ?`, beaconID).Scan(&transport)
	if err != nil || transport == "" {
		return nil, "", false
	}

	rows, err := d.db.Query(`SELECT profile_name FROM beacon_http_listeners WHERE beacon_id = ? ORDER BY profile_name`, beaconID)
	if err != nil {
		return nil, transport, true
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			continue
		}
		names = append(names, name)
	}
	return names, transport, true
}

// ConfirmBeaconTransport clears the pending marker when a beacon reports from the
// transport that was requested. A report from a different transport leaves it in
// place: the change has not landed.
func (d *MasterDatabase) ConfirmBeaconTransport(beaconID, reported string) error {
	reported = strings.ToLower(strings.TrimSpace(reported))
	if reported == "" {
		return nil
	}
	var recorded string
	if err := d.db.QueryRow(`SELECT COALESCE(transport, '') FROM beacons WHERE id = ?`, beaconID).Scan(&recorded); err != nil {
		return nil
	}
	recorded = strings.ToLower(strings.TrimSpace(recorded))
	if recorded != reported {
		return nil
	}
	_, err := d.db.Exec(`UPDATE beacons SET transport_pending_since = 0 WHERE id = ? AND transport_pending_since != 0`, beaconID)
	return err
}

// BeaconTransportPending reports whether a requested transport is still waiting to
// be confirmed by a beacon report.
func (d *MasterDatabase) BeaconTransportPending(beaconID string) bool {
	var pending int64
	if err := d.db.QueryRow(`SELECT COALESCE(transport_pending_since, 0) FROM beacons WHERE id = ?`, beaconID).Scan(&pending); err != nil {
		return false
	}
	return pending > 0
}

// migration25AddTransportPending adds the pending marker to databases created
// before it existed. Same drift the token counter had: a migration that already
// ran will not run again.
func (d *MasterDatabase) migration25AddTransportPending() error {
	return d.addColumnIfMissing("beacons", "transport_pending_since", "INTEGER DEFAULT 0")
}
