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

// writeProfileFile writes a profile JSON file into dir for the local-profile paths.
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

// occupyPort binds a port so a profile naming it cannot bind.
func occupyPort(t *testing.T) (net.Listener, int) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to occupy a port: %v", err)
	}
	return listener, listener.Addr().(*net.TCPAddr).Port
}

// remoteProfile builds an in-memory profile of the kind Archon assigns.
func remoteProfile(t *testing.T, name string, mutate func(*HTTPProfile)) *HTTPProfile {
	t.Helper()

	profile := DefaultHTTPProfile()
	profile.Name = name
	profile.Scheme = "http"
	profile.BindAddr = "127.0.0.1"
	profile.BindPort = freePort(t)
	if mutate != nil {
		mutate(&profile)
	}
	return &profile
}

// withTestC2Manager swaps the process-wide C2Manager for the duration of a test.
func withTestC2Manager(t *testing.T) *C2Manager {
	t.Helper()
	previous := c2Manager
	c2Manager = NewC2Manager(false, "startup-key", StagerJitter{}, ":memory:", "example.com")
	t.Cleanup(func() { c2Manager = previous })
	return c2Manager
}

// withCleanRegistry clears the process-wide registry after a test.
func withCleanRegistry(t *testing.T) {
	t.Helper()
	t.Cleanup(StopHTTPListeners)
}

// =============================================================================
// Startup
// =============================================================================

// TestStartHTTPTransport_StartsAndServes asserts startup wires listeners up, that
// they answer real requests, and that shutdown takes them down.
func TestStartHTTPTransport_StartsAndServes(t *testing.T) {
	c2 := withTestC2Manager(t)
	withCleanRegistry(t)

	dir := t.TempDir()
	profile := writeProfileFile(t, dir, "startup", nil)

	cfg := DefaultConfig()
	cfg.HTTPProfileDir = dir
	cfg.Debug = false

	if err := startHTTPTransport(cfg); err != nil {
		t.Fatalf("startHTTPTransport() error = %v", err)
	}
	if httpRegistry == nil {
		t.Fatal("no registry was created")
	}

	statuses := httpRegistry.Status()
	if len(statuses) != 1 || !statuses[0].Running {
		t.Fatalf("status = %+v, want one running listener", statuses)
	}
	if statuses[0].Source != profileSourceFile {
		t.Errorf("source = %q, want %q", statuses[0].Source, profileSourceFile)
	}

	baseURL := "http://" + statuses[0].Addr
	key := c2.GetEncryptionKey()

	status, response := sendMessage(t, baseURL, profile, key, "POST", "/api/v1/ping",
		"CHK|startupbeacon|host1|user1|linux|amd64|1758500000")
	if status != profile.Status.OK || response != "ACK" {
		t.Fatalf("register over a startup listener = (%d, %q), want (200, ACK)", status, response)
	}
	if beacons := c2.GetBeacons(); len(beacons) != 1 {
		t.Fatalf("startup listener did not reach the C2 manager: %d beacons", len(beacons))
	}

	StopHTTPListeners()

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(baseURL + "/api/v1/sync?d=x")
	if err == nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		t.Fatalf("listener still answered after shutdown with status %d", resp.StatusCode)
	}
}

// TestStartHTTPTransport_MissingDirectoryDisablesTransport asserts HTTP is opt-in: a
// missing profile directory is not an error and starts nothing.
func TestStartHTTPTransport_MissingDirectoryDisablesTransport(t *testing.T) {
	withTestC2Manager(t)
	withCleanRegistry(t)

	cfg := DefaultConfig()
	cfg.HTTPProfileDir = filepath.Join(t.TempDir(), "absent")

	if err := startHTTPTransport(cfg); err != nil {
		t.Fatalf("startHTTPTransport() error = %v, want nil for a missing directory", err)
	}
	// The registry still exists: a server with no local profile files must remain
	// able to receive assignments, which is the whole point of the control plane
	// path. What must not happen is a local listener appearing.
	if httpRegistry == nil {
		t.Fatal("no registry was created, so assignments could never be applied")
	}
	for _, status := range httpRegistry.Status() {
		if status.Running {
			t.Errorf("profile %q is running with no local profiles configured", status.Name)
		}
	}

	// No configured directory means the transport was never asked for. The previous
	// phase left a registry behind, so shut it down first to test this in isolation.
	StopHTTPListeners()

	cfg.HTTPProfileDir = ""
	if err := startHTTPTransport(cfg); err != nil {
		t.Fatalf("startHTTPTransport() with no directory error = %v", err)
	}
	if httpRegistry != nil {
		t.Fatal("a registry was created with no configured directory")
	}
}

// TestStartHTTPTransport_ReportsDisabledProfiles asserts a parked profile is known
// but not serving, which is what the control plane displays.
func TestStartHTTPTransport_ReportsDisabledProfiles(t *testing.T) {
	withTestC2Manager(t)
	withCleanRegistry(t)

	dir := t.TempDir()
	writeProfileFile(t, dir, "parked", func(p *HTTPProfile) { p.Enabled = false })
	writeProfileFile(t, dir, "live", nil)

	cfg := DefaultConfig()
	cfg.HTTPProfileDir = dir
	if err := startHTTPTransport(cfg); err != nil {
		t.Fatalf("startHTTPTransport() error = %v", err)
	}

	byName := map[string]HTTPListenerStatus{}
	for _, status := range httpRegistry.Status() {
		byName[status.Name] = status
	}

	if !byName["live"].Running {
		t.Errorf("enabled profile is not running: %+v", byName["live"])
	}
	if byName["parked"].Running {
		t.Errorf("disabled profile is running: %+v", byName["parked"])
	}
	if byName["parked"].Enabled {
		t.Errorf("disabled profile is reported as enabled: %+v", byName["parked"])
	}
}

// TestStartHTTPTransport_InvalidProfileFailsStartup asserts a broken local profile is
// fatal. Skipping it silently would leave the operator believing a listener was up.
func TestStartHTTPTransport_InvalidProfileFailsStartup(t *testing.T) {
	withTestC2Manager(t)
	withCleanRegistry(t)

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "broken.json"), []byte(`{"bind_port":99999}`), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := DefaultConfig()
	cfg.HTTPProfileDir = dir

	if err := startHTTPTransport(cfg); err == nil {
		t.Fatal("startHTTPTransport() accepted an invalid local profile, want a startup error")
	}
}

// TestStartHTTPTransport_UnbindableLocalProfileFailsStartup asserts a local profile
// that cannot bind is fatal, and that anything already bound is released first.
func TestStartHTTPTransport_UnbindableLocalProfileFailsStartup(t *testing.T) {
	withTestC2Manager(t)
	withCleanRegistry(t)

	blocker, blockedPort := occupyPort(t)
	defer blocker.Close()

	dir := t.TempDir()
	good := writeProfileFile(t, dir, "a-good", nil)
	writeProfileFile(t, dir, "z-clash", func(p *HTTPProfile) { p.BindPort = blockedPort })

	cfg := DefaultConfig()
	cfg.HTTPProfileDir = dir

	if err := startHTTPTransport(cfg); err == nil {
		t.Fatal("startHTTPTransport() succeeded despite an unbindable profile, want an error")
	}

	// The listener that did start must have been released, so a restart works.
	rebind, rebindErr := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", good.BindPort))
	if rebindErr != nil {
		t.Fatalf("port %d is still held after a failed startup: %v", good.BindPort, rebindErr)
	}
	rebind.Close()
}

// =============================================================================
// Assigned profiles
// =============================================================================

// TestHTTPRegistry_ApplyRemoteStartsUpdatesAndStops covers the point of the registry:
// an assignment starts a listener, a change to it is applied, and removing the
// assignment stops it.
func TestHTTPRegistry_ApplyRemoteStartsUpdatesAndStops(t *testing.T) {
	c2 := withTestC2Manager(t)

	store := NewHTTPProfileStore(t.TempDir())
	registry := NewHTTPRegistry(store, c2, false)
	defer registry.Shutdown()

	profile := remoteProfile(t, "cdn-assets", nil)

	// Assigned: starts.
	result, err := registry.ApplyRemote([]*HTTPProfile{profile})
	if err != nil {
		t.Fatalf("ApplyRemote() error = %v", err)
	}
	if len(result.Started) != 1 || result.Started[0] != "cdn-assets" {
		t.Fatalf("result = %+v, want cdn-assets started", result)
	}

	statuses := registry.Status()
	if len(statuses) != 1 || !statuses[0].Running {
		t.Fatalf("status = %+v, want one running listener", statuses)
	}
	if statuses[0].Source != profileSourceRemote {
		t.Errorf("source = %q, want %q", statuses[0].Source, profileSourceRemote)
	}
	baseURL := "http://" + statuses[0].Addr
	key := c2.GetEncryptionKey()

	// It serves.
	if status, response := sendMessage(t, baseURL, profile, key, "POST", "/api/v1/ping",
		"CHK|remote1|h|u|linux|amd64|1758500000"); status != profile.Status.OK || response != "ACK" {
		t.Fatalf("register = (%d, %q), want (200, ACK)", status, response)
	}

	// An assignment change that does not touch the socket applies without a restart,
	// because the listener reads the live profile per request.
	updated := remoteProfile(t, "cdn-assets", func(p *HTTPProfile) {
		p.BindPort = profile.BindPort
		p.URIs = URITable{
			Register: []string{"/rotated/ping"},
			Task:     []string{"/rotated/sync"},
			Result:   []string{"/rotated/report"},
			Ack:      []string{"/rotated/ack"},
		}
	})

	result, err = registry.ApplyRemote([]*HTTPProfile{updated})
	if err != nil {
		t.Fatalf("ApplyRemote() error = %v", err)
	}
	if len(result.Started)+len(result.Restarted)+len(result.Stopped) != 0 {
		t.Fatalf("a URI-only change caused a restart: %+v", result)
	}

	// The rotated URI serves and the retired one does not.
	if status, _ := sendMessage(t, baseURL, updated, key, "POST", "/rotated/ping",
		"CHK|remote1|h|u|linux|amd64|1758500001"); status != updated.Status.OK {
		t.Fatalf("rotated URI rejected: status %d", status)
	}
	if status, _ := sendMessage(t, baseURL, updated, key, "POST", "/api/v1/ping",
		"CHK|remote1|h|u|linux|amd64|1758500002"); status != updated.Status.NotFound {
		t.Fatalf("retired URI still routed: status %d", status)
	}

	// A bind change restarts the listener.
	moved := remoteProfile(t, "cdn-assets", nil)
	result, err = registry.ApplyRemote([]*HTTPProfile{moved})
	if err != nil {
		t.Fatalf("ApplyRemote() error = %v", err)
	}
	if len(result.Restarted) != 1 {
		t.Fatalf("result = %+v, want one restart for a bind change", result)
	}

	// Detaching stops it.
	result, err = registry.ApplyRemote(nil)
	if err != nil {
		t.Fatalf("ApplyRemote() error = %v", err)
	}
	if len(result.Stopped) != 1 || result.Stopped[0] != "cdn-assets" {
		t.Fatalf("result = %+v, want cdn-assets stopped", result)
	}

	for _, status := range registry.Status() {
		if status.Running {
			t.Errorf("listener %q is still running after detach", status.Name)
		}
	}
}

// TestHTTPRegistry_ApplyRemoteRejectsUnusableProfiles asserts an assignment that
// cannot start is reported, without taking down the others or the server.
func TestHTTPRegistry_ApplyRemoteRejectsUnusableProfiles(t *testing.T) {
	c2 := withTestC2Manager(t)

	store := NewHTTPProfileStore(t.TempDir())
	registry := NewHTTPRegistry(store, c2, false)
	defer registry.Shutdown()

	blocker, blockedPort := occupyPort(t)
	defer blocker.Close()

	good := remoteProfile(t, "a-good", nil)
	clashing := remoteProfile(t, "z-clash", func(p *HTTPProfile) { p.BindPort = blockedPort })

	result, err := registry.ApplyRemote([]*HTTPProfile{good, clashing})
	if err == nil {
		t.Fatal("ApplyRemote() reported no error for an unbindable assignment")
	}

	if len(result.Started) != 1 || result.Started[0] != "a-good" {
		t.Fatalf("result = %+v, want a-good started despite the other failing", result)
	}
	if len(result.Failed) != 1 || result.Failed[0] != "z-clash" {
		t.Fatalf("result = %+v, want z-clash reported as failed", result)
	}

	var reported HTTPListenerStatus
	for _, status := range registry.Status() {
		if status.Name == "z-clash" {
			reported = status
		}
	}
	if reported.Running {
		t.Error("failed listener is reported as running")
	}
	if reported.Error == "" {
		t.Error("failed listener has no error for the operator to read")
	}
}

// TestHTTPRegistry_ApplyRemoteRejectsInvalidDocument asserts a malformed assignment is
// refused at the door, so it cannot replace a working profile.
func TestHTTPRegistry_ApplyRemoteRejectsInvalidDocument(t *testing.T) {
	c2 := withTestC2Manager(t)

	store := NewHTTPProfileStore(t.TempDir())
	registry := NewHTTPRegistry(store, c2, false)
	defer registry.Shutdown()

	broken := remoteProfile(t, "broken", func(p *HTTPProfile) { p.BindPort = 99999 })

	if _, err := registry.ApplyRemote([]*HTTPProfile{broken}); err == nil {
		t.Fatal("ApplyRemote() accepted an invalid assignment")
	}

	for _, status := range registry.Status() {
		if status.Running {
			t.Errorf("listener %q started from an invalid document", status.Name)
		}
	}
}

// TestHTTPRegistry_AssignedProfileWinsOverFile asserts the control plane owns a name
// it assigns: a file of the same name is ignored rather than shadowing it.
func TestHTTPRegistry_AssignedProfileWinsOverFile(t *testing.T) {
	c2 := withTestC2Manager(t)

	dir := t.TempDir()
	fileProfile := writeProfileFile(t, dir, "shared-name", nil)

	store := NewHTTPProfileStore(dir)
	if err := store.Load(); err != nil {
		t.Fatal(err)
	}

	registry := NewHTTPRegistry(store, c2, false)
	defer registry.Shutdown()

	assigned := remoteProfile(t, "shared-name", nil)
	if _, err := registry.ApplyRemote([]*HTTPProfile{assigned}); err != nil {
		t.Fatalf("ApplyRemote() error = %v", err)
	}

	for _, status := range registry.Status() {
		if status.Name != "shared-name" {
			continue
		}
		if status.Source != profileSourceRemote {
			t.Errorf("source = %q, want the assignment to win", status.Source)
		}
		if status.Addr == fileProfile.ListenerAddr() {
			t.Errorf("the file profile is serving (%s), want the assigned one", status.Addr)
		}
	}

	// Detaching drops the name rather than falling back to the file.
	if _, err := registry.ApplyRemote(nil); err != nil {
		t.Fatal(err)
	}
	if source := store.Source("shared-name"); source != "" {
		t.Errorf("after detach the profile source is %q, want it gone", source)
	}
}

// TestHTTPRegistry_DisabledAssignmentIsStopped asserts an assigned profile with
// enabled:false is known but not serving, so an operator can park one without
// detaching it.
func TestHTTPRegistry_DisabledAssignmentIsStopped(t *testing.T) {
	c2 := withTestC2Manager(t)

	store := NewHTTPProfileStore(t.TempDir())
	registry := NewHTTPRegistry(store, c2, false)
	defer registry.Shutdown()

	live := remoteProfile(t, "cdn-assets", nil)
	if _, err := registry.ApplyRemote([]*HTTPProfile{live}); err != nil {
		t.Fatal(err)
	}

	parked := remoteProfile(t, "cdn-assets", func(p *HTTPProfile) {
		p.BindPort = live.BindPort
		p.Enabled = false
	})
	result, err := registry.ApplyRemote([]*HTTPProfile{parked})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Stopped) != 1 {
		t.Fatalf("result = %+v, want the parked profile stopped", result)
	}

	for _, status := range registry.Status() {
		if status.Running {
			t.Errorf("parked assignment %q is still running", status.Name)
		}
		if status.Enabled {
			t.Errorf("parked assignment %q reports enabled", status.Name)
		}
	}
}
