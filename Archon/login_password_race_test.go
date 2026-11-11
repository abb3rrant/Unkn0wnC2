package main

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestStaleVerifiedLoginCannotCreateSessionAfterPasswordReset(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "race.db")
	db, err := NewMasterDatabase(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.db.Close()

	if err := db.CreateOperator("race-user", "race-user", "old-password", "operator", ""); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateOperator("other-user", "other-user", "other-password", "operator", ""); err != nil {
		t.Fatal(err)
	}
	resetDB, err := NewMasterDatabase(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer resetDB.Close()

	id, _, oldHash, err := db.VerifyOperatorCredentialsSnapshot("race-user", "old-password")
	if err != nil {
		t.Fatal(err)
	}
	if err := resetDB.UpdateOperatorPassword(id, "new-password"); err != nil {
		t.Fatal(err)
	}

	if err := db.CreateSessionForVerifiedCredentials("stale-session", id, oldHash, "stale-jti", "token-hash", "", "", time.Now().Add(time.Hour).Unix()); err == nil {
		t.Fatal("stale verified credentials were allowed to create a session")
	}
	if got := countSessionsForTest(t, db.db, id); got != 0 {
		t.Fatalf("stale login inserted %d session(s), want zero", got)
	}

	freshID, _, freshHash, err := db.VerifyOperatorCredentialsSnapshot("race-user", "new-password")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.CreateSessionForVerifiedCredentials("fresh-session", freshID, freshHash, "fresh-jti", "token-hash", "", "", time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatalf("fresh credentials could not create session: %v", err)
	}

	otherID, _, otherHash, err := db.VerifyOperatorCredentialsSnapshot("other-user", "other-password")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.CreateSessionForVerifiedCredentials("other-session", otherID, otherHash, "other-jti", "token-hash", "", "", time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatalf("unrelated account credentials were affected: %v", err)
	}
	if got := countSessionsForTest(t, db.db, id); got != 1 {
		t.Fatalf("fresh session count = %d, want 1", got)
	}
	if got := countSessionsForTest(t, db.db, otherID); got != 1 {
		t.Fatalf("other account session count = %d, want 1", got)
	}
}

func countSessionsForTest(t *testing.T, db *sql.DB, operatorID string) int {
	t.Helper()
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE operator_id = ? AND is_revoked = 0`, operatorID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}
