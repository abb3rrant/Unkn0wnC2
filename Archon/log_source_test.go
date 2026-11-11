package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLogLookupPreservesRequestedSource(t *testing.T) {
	root := t.TempDir()
	active := filepath.Join(root, "active")
	local := filepath.Join(root, "logs")
	for _, dir := range []string{active, local} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	previous := appLogger
	appLogger = &Logger{logDir: active}
	t.Cleanup(func() { appLogger = previous })
	t.Chdir(root)
	write := func(path, marker string) {
		t.Helper()
		if err := os.WriteFile(path, []byte("[2026-01-01 00:00:00] [INFO] "+marker+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(active, "archon.log"), "controller-only")
	write(filepath.Join(active, "dns-configured.log"), "configured-server")
	write(filepath.Join(local, "dns-local.log"), "local-same-server")
	// A directory at a log filename produces a deterministic read error,
	// independent of test-user permissions. Do not hide it with local fallback.
	if err := os.Mkdir(filepath.Join(active, "dns-read-error.log"), 0700); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(local, "dns-read-error.log"), "must-not-fallback")
	today := time.Now().Format("2006-01-02")
	write(filepath.Join(local, "archon-"+today+".log"), "local-controller")
	api := NewAPIServer(nil, Config{})
	for _, tc := range []struct {
		kind         string
		status       int
		marker, file string
	}{
		{"dns-missing", http.StatusNotFound, "", ""},
		{"dns-read-error", http.StatusInternalServerError, "", ""},
		{"unknown", http.StatusBadRequest, "", ""},
		{"dns-../archon", http.StatusBadRequest, "", ""},
		{"dns-..\\archon", http.StatusBadRequest, "", ""},
		{"dns-configured", http.StatusOK, "configured-server", "dns-configured.log"},
		{"dns-local", http.StatusOK, "local-same-server", "dns-local.log"},
		{"archon", http.StatusOK, "controller-only", "archon.log"},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			rec := httptest.NewRecorder()
			api.handleGetLogs(rec, httptest.NewRequest("GET", "/api/logs?type="+url.QueryEscape(tc.kind)+"&lines=10", nil))
			if rec.Code != tc.status {
				t.Fatalf("status=%d want=%d", rec.Code, tc.status)
			}
			if tc.status != http.StatusOK {
				return
			}
			var body struct {
				File    string     `json:"file"`
				Entries []LogEntry `json:"entries"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body.File != tc.file || len(body.Entries) != 1 || body.Entries[0].Message != tc.marker {
				t.Fatalf("wrong log provenance: file=%s entries=%v", body.File, body.Entries)
			}
		})
	}
	if err := os.Remove(filepath.Join(active, "archon.log")); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	api.handleGetLogs(rec, httptest.NewRequest("GET", "/api/logs?type=archon", nil))
	var body struct {
		File    string     `json:"file"`
		Entries []LogEntry `json:"entries"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK || body.File != "archon-"+today+".log" || len(body.Entries) != 1 || body.Entries[0].Message != "local-controller" {
		t.Fatal("same-source local controller fallback failed")
	}
}
