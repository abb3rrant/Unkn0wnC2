package main

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestLogMetadataRenderingTreatsAllFieldsAsText(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node.js required for executable DOM regression")
	}
	if out, err := exec.Command(node, "testdata/log_rendering.cjs").CombinedOutput(); err != nil {
		t.Fatalf("log-rendering regression: %v\n%s", err, out)
	}
}

func TestForwardedLogLevelsAreCanonicalBeforePersistence(t *testing.T) {
	dir := t.TempDir()
	previous := appLogger
	appLogger = &Logger{logDir: dir, logger: log.New(io.Discard, "", 0)}
	t.Cleanup(func() { appLogger = previous })
	api := NewAPIServer(nil, Config{})
	req := httptest.NewRequest("POST", "/api/dns-server/logs", strings.NewReader(`{"dns_server_id":"fixture","entries":[{"timestamp":"fixture-time","level":"<em>inert-marker</em>","message":"plain fixture"},{"timestamp":"fixture-time","level":"warning","message":"warning fixture"}]}`))
	rec := httptest.NewRecorder()
	api.handleDNSServerLogs(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	body, err := os.ReadFile(filepath.Join(dir, "dns-fixture.log"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "<em>") || !strings.Contains(string(body), "[INFO] plain fixture") || !strings.Contains(string(body), "[WARN] warning fixture") {
		t.Fatalf("forwarded levels were not normalized: %s", body)
	}
}
