package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// Migration 23 adds single-use bootstrap tokens for HTTP listener updates.
//
// A transport update used to carry the whole listener profile in the task, which
// on DNS means dozens of subdomain-labelled chunks. The task now carries a URL and
// a token; the beacon fetches the profile over HTTP and the token is spent on
// first use. The payload is stored here so the task itself stays short.
func (d *MasterDatabase) migration23AddHTTPProfileTokens() error {
	_, err := d.db.Exec(`
		CREATE TABLE IF NOT EXISTS http_profile_tokens (
			token TEXT PRIMARY KEY,
			beacon_id TEXT NOT NULL,
			profile_name TEXT NOT NULL DEFAULT '',
			listener_id TEXT NOT NULL DEFAULT '',
			payload TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL,
			used_at INTEGER,
			uses INTEGER NOT NULL DEFAULT 0
		)
	`)
	if err != nil {
		return err
	}
	_, err = d.db.Exec(`CREATE INDEX IF NOT EXISTS idx_http_profile_tokens_beacon ON http_profile_tokens(beacon_id)`)
	return err
}

// HTTPProfileTokenTTL is how long a bootstrap token stays usable.
//
// It has to outlive the beacon's sleep interval, which is operator-controlled and
// can be hours: a token that expires before the beacon collects the task turns a
// successful "Apply" into a silent no-op, because the fetch then 404s and the
// beacon keeps its old transport while the dashboard claims the new one.
const HTTPProfileTokenTTL = 6 * time.Hour

// HTTPProfileTokenUses is how many times one token may be redeemed.
//
// One was too strict: Archon consumes the token before the beacon has the
// payload, so a dropped connection between beacon and listener lost the update
// permanently. A small allowance keeps the hand-off resilient without making a
// captured token useful for long — it is still bound to one beacon and dies with
// the TTL.
const HTTPProfileTokenUses = 3

// ErrTokenInvalid covers unknown, expired, already-used and wrong-beacon tokens.
// They are deliberately indistinguishable to the caller.
var ErrTokenInvalid = errors.New("bootstrap token is invalid or expired")

// IssueHTTPProfileToken stores a payload against a new single-use token.
func (d *MasterDatabase) IssueHTTPProfileToken(beaconID, profileName, listenerID, payload string) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	token := hex.EncodeToString(raw)

	now := time.Now().Unix()
	_, err := d.db.Exec(`
		INSERT INTO http_profile_tokens (token, beacon_id, profile_name, listener_id, payload, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, token, beaconID, profileName, listenerID, payload, now, now+int64(HTTPProfileTokenTTL.Seconds()))
	if err != nil {
		return "", fmt.Errorf("store token: %w", err)
	}
	return token, nil
}

// ConsumeHTTPProfileToken returns the payload for a token and marks it spent.
//
// Single use is enforced in the UPDATE itself rather than by a read-then-write, so
// two concurrent fetches cannot both succeed. When beaconID is non-empty the token
// must belong to that beacon.
func (d *MasterDatabase) ConsumeHTTPProfileToken(token, beaconID string) (string, error) {
	now := time.Now().Unix()

	query := `
		UPDATE http_profile_tokens
		SET used_at = ?, uses = uses + 1
		WHERE token = ? AND uses < ? AND expires_at > ?
	`
	args := []interface{}{now, token, HTTPProfileTokenUses, now}
	if beaconID != "" {
		query += " AND beacon_id = ?"
		args = append(args, beaconID)
	}
	query += " RETURNING payload"

	var payload string
	if err := d.db.QueryRow(query, args...).Scan(&payload); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrTokenInvalid
		}
		return "", err
	}
	return payload, nil
}

// PurgeHTTPProfileTokens removes spent and expired tokens. Housekeeping only: no
// correctness depends on it, because the consume query already refuses them.
func (d *MasterDatabase) PurgeHTTPProfileTokens() error {
	now := time.Now().Unix()
	_, err := d.db.Exec(`DELETE FROM http_profile_tokens WHERE expires_at <= ? OR uses >= ?`, now, HTTPProfileTokenUses)
	return err
}
