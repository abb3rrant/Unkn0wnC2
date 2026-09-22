package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// occupyPort binds a port so a profile naming it cannot bind, and returns the
// held listener with the port number.
func occupyPort(t *testing.T) (net.Listener, int) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to occupy a port: %v", err)
	}
	return listener, listener.Addr().(*net.TCPAddr).Port
}

// writeProfileFile writes a profile JSON file into dir for the startup paths.
func writeProfileFile(t *testing.T, dir, name string, mutate func(*HTTPProfile)) *HTTPProfile {
	t.Helper()

	profile := DefaultHTTPProfile()
	profile.Name = name
	profile.Scheme = "http"
	profile.BindAddr = "127.0.0.1"
	profile.BindPort = freePort(t)
	if mutate != nil {
		mutate(&profile)
	}

	if err := profile.Validate(); err != nil {
		t.Fatalf("test profile is invalid: %v", err)
	}
	raw, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".json"), raw, 0644); err != nil {
		t.Fatal(err)
	}
	return &profile
}

// withTestC2Manager swaps the process-wide C2Manager for the duration of a test.
// startHTTPListeners is startup code and reads the global, so this is the
// smallest seam that exercises the real function.
func withTestC2Manager(t *testing.T) *C2Manager {
	t.Helper()
	previous := c2Manager
	c2Manager = NewC2Manager(false, "startup-key", StagerJitter{}, ":memory:", "example.com")
	t.Cleanup(func() { c2Manager = previous })
	return c2Manager
}

// TestStartHTTPListeners_StartsAndServes asserts startup wires listeners up, that
// they answer real requests, and that shutdown takes them down.
func TestStartHTTPListeners_StartsAndServes(t *testing.T) {
	c2 := withTestC2Manager(t)

	dir := t.TempDir()
	profile := writeProfileFile(t, dir, "startup", nil)

	cfg := DefaultConfig()
	// The builder supplies the profile directory; point it at the temp dir.
	cfg.HTTPProfileDir = dir
	cfg.Debug = false

	listeners, err := startHTTPListeners(cfg)
	if err != nil {
		t.Fatalf("startHTTPListeners() error = %v", err)
	}
	if len(listeners) != 1 {
		t.Fatalf("started %d listeners, want 1", len(listeners))
	}

	baseURL := "http://" + listeners[0].Addr()
	key := c2.GetEncryptionKey()

	status, response := sendMessage(t, baseURL, profile, key, "POST", "/api/v1/ping",
		"CHK|startupbeacon|host1|user1|linux|amd64|1758500000")
	if status != profile.Status.OK || response != "ACK" {
		t.Fatalf("register over a startup listener = (%d, %q), want (200, ACK)", status, response)
	}
	if beacons := c2.GetBeacons(); len(beacons) != 1 {
		t.Fatalf("startup listener did not reach the C2 manager: %d beacons", len(beacons))
	}

	// Shutdown must actually stop serving.
	stopHTTPListeners(listeners)
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(baseURL + "/api/v1/sync?d=x")
	if err == nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		t.Fatalf("listener still answered after shutdown with status %d", resp.StatusCode)
	}
}

// TestStartHTTPListeners_MissingDirectoryDisablesTransport asserts HTTP is opt-in:
// a missing profile directory is not an error and starts nothing, so a DNS-only
// deployment is unaffected.
func TestStartHTTPListeners_MissingDirectoryDisablesTransport(t *testing.T) {
	withTestC2Manager(t)

	cfg := DefaultConfig()
	cfg.HTTPProfileDir = filepath.Join(t.TempDir(), "absent")

	listeners, err := startHTTPListeners(cfg)
	if err != nil {
		t.Fatalf("startHTTPListeners() error = %v, want nil for a missing directory", err)
	}
	if len(listeners) != 0 {
		t.Fatalf("started %d listeners, want 0", len(listeners))
	}
}

// TestStartHTTPListeners_EmptyDirectoryDisablesTransport covers the deployed case
// where the directory exists but no profiles have been installed yet.
func TestStartHTTPListeners_EmptyDirectoryDisablesTransport(t *testing.T) {
	withTestC2Manager(t)

	cfg := DefaultConfig()
	cfg.HTTPProfileDir = t.TempDir()

	listeners, err := startHTTPListeners(cfg)
	if err != nil {
		t.Fatalf("startHTTPListeners() error = %v, want nil", err)
	}
	if len(listeners) != 0 {
		t.Fatalf("started %d listeners, want 0", len(listeners))
	}
}

// TestStartHTTPListeners_SkipsDisabledProfiles asserts an operator can park a
// profile without deleting it.
func TestStartHTTPListeners_SkipsDisabledProfiles(t *testing.T) {
	withTestC2Manager(t)

	dir := t.TempDir()
	writeProfileFile(t, dir, "parked", func(p *HTTPProfile) { p.Enabled = false })
	writeProfileFile(t, dir, "live", nil)

	cfg := DefaultConfig()
	cfg.HTTPProfileDir = dir

	listeners, err := startHTTPListeners(cfg)
	if err != nil {
		t.Fatalf("startHTTPListeners() error = %v", err)
	}
	if len(listeners) != 1 {
		t.Fatalf("started %d listeners, want 1 (the enabled one)", len(listeners))
	}
	if listeners[0].profileName != "live" {
		t.Fatalf("started profile %q, want %q", listeners[0].profileName, "live")
	}
	stopHTTPListeners(listeners)
}

// TestStartHTTPListeners_InvalidProfileFailsStartup asserts a broken profile is
// fatal. Skipping it silently would leave the operator believing a listener was
// up while beacons failed to reach it.
func TestStartHTTPListeners_InvalidProfileFailsStartup(t *testing.T) {
	withTestC2Manager(t)

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "broken.json"), []byte(`{"bind_port":99999}`), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := DefaultConfig()
	cfg.HTTPProfileDir = dir

	if _, err := startHTTPListeners(cfg); err == nil {
		t.Fatal("startHTTPListeners() accepted an invalid profile, want a startup error")
	}
}

// TestStartHTTPListeners_PartialFailureStopsStarted asserts a listener that
// cannot start does not leave earlier ones running unmanaged.
func TestStartHTTPListeners_PartialFailureStopsStarted(t *testing.T) {
	withTestC2Manager(t)

	// Occupy a port so the profile that names it cannot bind.
	blocker, blockedPort := occupyPort(t)
	defer blocker.Close()

	dir := t.TempDir()
	good := writeProfileFile(t, dir, "a-good", nil)
	writeProfileFile(t, dir, "z-clash", func(p *HTTPProfile) { p.BindPort = blockedPort })

	cfg := DefaultConfig()
	cfg.HTTPProfileDir = dir

	listeners, err := startHTTPListeners(cfg)
	if err == nil {
		stopHTTPListeners(listeners)
		t.Fatal("startHTTPListeners() succeeded despite an unbindable profile, want an error")
	}

	// The profile that did start must have been released, so its port is free
	// again. Without that, a restart would fail on a port nobody is serving.
	rebind, rebindErr := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", good.BindPort))
	if rebindErr != nil {
		t.Fatalf("port %d is still held after a failed startup: %v", good.BindPort, rebindErr)
	}
	rebind.Close()
}
