package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Wraith beacons are built outside Archon, so their payload template is not in
// any build config. Wraith announces "WRAITH#" and declares its template at
// runtime (CHK_META), and the listener then has what it needs to decode that
// beacon's queries.
//
// The catalog exists so operators can talk about those layouts. Each distinct
// template gets the next number, and the beacon is labelled WRAITH#N. A rebuild
// that keeps the same layout lands on the same number; a different layout gets
// the next one. Nothing about the numbering is known to the beacon: it only ever
// sends "WRAITH#", because it cannot see other beacons or this table.

// wraithBeaconPrefix marks a beacon built outside Archon. The beacon sends it
// bare; the number is assigned here.
const wraithBeaconPrefix = "WRAITH#"

// WraithConfig is one distinct externally-built layout.
type WraithConfig struct {
	ID            int64  `json:"id"`
	Label         string `json:"label"`
	PayloadFormat string `json:"payload_format"`
	FirstSeen     int64  `json:"first_seen"`
	LastSeen      int64  `json:"last_seen"`
	BeaconCount   int    `json:"beacon_count"`
}

// migration27AddWraithConfigs creates the layout catalog. payload_format is
// unique, so two builds with the same template share one number.
func (d *MasterDatabase) migration27AddWraithConfigs() error {
	_, err := d.db.Exec(`
		CREATE TABLE IF NOT EXISTS wraith_configs (
			id INTEGER PRIMARY KEY,
			payload_format TEXT NOT NULL UNIQUE,
			first_seen INTEGER NOT NULL,
			last_seen INTEGER NOT NULL
		);
	`)
	return err
}

// RegisterWraithConfig returns the stable number for a template, inserting a new
// one when the layout has not been seen before.
//
// The number is assigned explicitly (max+1) inside a transaction. AUTOINCREMENT
// cannot be used: SQLite allocates a rowid before it checks the uniqueness
// constraint, so every report for an existing layout would inflate the count.
func (d *MasterDatabase) RegisterWraithConfig(payloadFormat string) (int64, error) {
	payloadFormat = strings.TrimSpace(payloadFormat)
	if payloadFormat == "" {
		return 0, fmt.Errorf("empty payload format")
	}

	now := time.Now().Unix()

	tx, err := d.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("failed to begin wraith config tx: %w", err)
	}
	defer tx.Rollback()

	var id int64
	err = tx.QueryRow(`SELECT id FROM wraith_configs WHERE payload_format = ?`, payloadFormat).Scan(&id)
	switch {
	case err == nil:
		if _, err := tx.Exec(`UPDATE wraith_configs SET last_seen = ? WHERE id = ?`, now, id); err != nil {
			return 0, fmt.Errorf("failed to touch wraith config: %w", err)
		}
	case err == sql.ErrNoRows:
		if err := tx.QueryRow(`SELECT COALESCE(MAX(id), 0) + 1 FROM wraith_configs`).Scan(&id); err != nil {
			return 0, fmt.Errorf("failed to allocate wraith config number: %w", err)
		}
		if _, err := tx.Exec(`
			INSERT INTO wraith_configs (id, payload_format, first_seen, last_seen)
			VALUES (?, ?, ?, ?)
		`, id, payloadFormat, now, now); err != nil {
			return 0, fmt.Errorf("failed to insert wraith config: %w", err)
		}
	default:
		return 0, fmt.Errorf("failed to read wraith config: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("failed to commit wraith config: %w", err)
	}
	return id, nil
}

// WraithConfigForFormat returns the number for a template without creating one.
func (d *MasterDatabase) WraithConfigForFormat(payloadFormat string) (int64, bool) {
	var id int64
	if err := d.db.QueryRow(`SELECT id FROM wraith_configs WHERE payload_format = ?`, strings.TrimSpace(payloadFormat)).Scan(&id); err != nil {
		return 0, false
	}
	return id, true
}

// ListWraithConfigs returns every catalogued layout with a live beacon count.
func (d *MasterDatabase) ListWraithConfigs() ([]WraithConfig, error) {
	rows, err := d.db.Query(`
		SELECT w.id, w.payload_format, w.first_seen, w.last_seen,
		       (SELECT COUNT(*) FROM beacons b WHERE b.beacon_name = 'WRAITH#' || w.id)
		FROM wraith_configs w
		ORDER BY w.id
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to list wraith configs: %w", err)
	}
	defer rows.Close()

	var configs []WraithConfig
	for rows.Next() {
		var c WraithConfig
		if err := rows.Scan(&c.ID, &c.PayloadFormat, &c.FirstSeen, &c.LastSeen, &c.BeaconCount); err != nil {
			return nil, fmt.Errorf("failed to scan wraith config: %w", err)
		}
		c.Label = fmt.Sprintf("WRAITH#%d", c.ID)
		configs = append(configs, c)
	}
	return configs, rows.Err()
}

// handleListWraithConfigs exposes the catalog to the operator UI.
func (api *APIServer) handleListWraithConfigs(w http.ResponseWriter, r *http.Request) {
	configs, err := api.db.ListWraithConfigs()
	if err != nil {
		api.sendError(w, 500, "failed to list wraith configs")
		return
	}
	if configs == nil {
		configs = []WraithConfig{}
	}
	api.sendSuccess(w, "wraith configs", map[string]interface{}{
		"configs": configs,
		"count":   len(configs),
	})
}
