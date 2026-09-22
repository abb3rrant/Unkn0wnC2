package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestHTTPProfileDefaults_ValidateOK asserts the shipped defaults are a valid
// profile, so a profile file that omits every field still yields a listener.
func TestHTTPProfileDefaults_ValidateOK(t *testing.T) {
	p := DefaultHTTPProfile()
	if err := p.Validate(); err != nil {
		t.Fatalf("DefaultHTTPProfile().Validate() = %v, want nil", err)
	}
}

// TestHTTPProfileValidate_Table covers each rejection path so an operator sees a
// precise message instead of a listener that fails at request time.
func TestHTTPProfileValidate_Table(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*HTTPProfile)
		wantErr string
	}{
		{
			name:    "bind port zero",
			mutate:  func(p *HTTPProfile) { p.BindPort = 0 },
			wantErr: "BindPort must be in range",
		},
		{
			name:    "bind port too high",
			mutate:  func(p *HTTPProfile) { p.BindPort = 70000 },
			wantErr: "BindPort must be in range",
		},
		{
			name:    "unknown scheme",
			mutate:  func(p *HTTPProfile) { p.Scheme = "ftp" },
			wantErr: "Scheme must be",
		},
		{
			name:    "no task uri",
			mutate:  func(p *HTTPProfile) { p.URIs.Task = nil },
			wantErr: "URIs.Task must have at least one path",
		},
		{
			name:    "relative uri",
			mutate:  func(p *HTTPProfile) { p.URIs.Task = []string{"sync"} },
			wantErr: "must start with",
		},
		{
			name:    "uri with query string",
			mutate:  func(p *HTTPProfile) { p.URIs.Ack = []string{"/ack?x=1"} },
			wantErr: "must not contain whitespace",
		},
		{
			name:    "bad method",
			mutate:  func(p *HTTPProfile) { p.Methods.Task = "DELETE" },
			wantErr: "Methods.task must be",
		},
		{
			name:    "bad request encoding",
			mutate:  func(p *HTTPProfile) { p.RequestBody.Encoding = "rot13" },
			wantErr: "RequestBody.Encoding must be one of",
		},
		{
			name:    "empty response field",
			mutate:  func(p *HTTPProfile) { p.ResponseBody.Field = "" },
			wantErr: "ResponseBody.Field must be non-empty",
		},
		{
			name:    "padding range inverted",
			mutate:  func(p *HTTPProfile) { p.RequestBody.PadMin, p.RequestBody.PadMax = 64, 8 },
			wantErr: "PadMax",
		},
		{
			name:    "bad auth mode",
			mutate:  func(p *HTTPProfile) { p.Auth.Mode = "basic" },
			wantErr: "Auth.Mode must be",
		},
		{
			name:    "auth header empty",
			mutate:  func(p *HTTPProfile) { p.Auth.Header = "" },
			wantErr: "Auth.Header must be non-empty",
		},
		{
			name:    "bad sig encoding",
			mutate:  func(p *HTTPProfile) { p.Auth.SigEncoding = "base32" },
			wantErr: "Auth.SigEncoding must be",
		},
		{
			name:    "bad status code",
			mutate:  func(p *HTTPProfile) { p.Status.NotFound = 42 },
			wantErr: "Status.NotFound must be a valid HTTP status code",
		},
		{
			name:    "header with newline",
			mutate:  func(p *HTTPProfile) { p.Headers = []HeaderEntry{{Name: "X-A", Value: "a\r\nInjected: 1"}} },
			wantErr: "contains a line break",
		},
		{
			name:    "header empty name",
			mutate:  func(p *HTTPProfile) { p.Headers = []HeaderEntry{{Name: "  ", Value: "v"}} },
			wantErr: "empty name",
		},
		{
			name:    "https without cert",
			mutate:  func(p *HTTPProfile) { p.Scheme = "https"; p.TLS.CertFile, p.TLS.KeyFile = "", "" },
			wantErr: "TLS.CertFile and TLS.KeyFile are required",
		},
		{
			name:    "bad tls min version",
			mutate:  func(p *HTTPProfile) { p.Scheme = "https"; p.TLS.MinVersion = "1.0" },
			wantErr: "TLS.MinVersion must be",
		},
		{
			name:    "bad max body",
			mutate:  func(p *HTTPProfile) { p.MaxBodyBytes = 0 },
			wantErr: "MaxBodyBytes must be positive",
		},
		{
			name:    "jitter inverted",
			mutate:  func(p *HTTPProfile) { p.Jitter.MinMs, p.Jitter.MaxMs = 500, 100 },
			wantErr: "Jitter.MaxMs",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := DefaultHTTPProfile()
			// A valid https profile needs cert paths before mutation.
			p.TLS.CertFile = "/tmp/listener.crt"
			p.TLS.KeyFile = "/tmp/listener.key"
			tc.mutate(&p)

			err := p.Validate()
			if err == nil {
				t.Fatalf("Validate() = nil, want error containing %q", tc.wantErr)
			}
			if !contains(err.Error(), tc.wantErr) {
				t.Fatalf("Validate() = %q, want it to contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// TestHTTPProfileValidate_HTTPSWithCertPathsOK covers the production shape: an
// HTTPS profile naming a generated cert/key pair and its pinned SPKI.
func TestHTTPProfileValidate_HTTPSWithCertPathsOK(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, spki, err := GenerateListenerCert("edge", dir, "cdn.example.com")
	if err != nil {
		t.Fatalf("GenerateListenerCert() error = %v", err)
	}

	p := DefaultHTTPProfile()
	p.Scheme = "https"
	p.TLS = ProfileTLS{CertFile: certPath, KeyFile: keyPath, SPKISHA256: spki, MinVersion: "1.3"}

	if err := p.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil for a complete HTTPS profile", err)
	}
}

// TestLoadHTTPProfile_SparseAppliesDefaults asserts a profile file containing only
// a couple of fields is still a valid, fully-populated listener.
func TestLoadHTTPProfile_SparseAppliesDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sparse.json")

	// http scheme avoids requiring cert files, exercising the opt-out path.
	if err := os.WriteFile(path, []byte(`{"scheme":"http","bind_port":8080}`), 0644); err != nil {
		t.Fatal(err)
	}

	p, err := LoadHTTPProfile(path)
	if err != nil {
		t.Fatalf("LoadHTTPProfile() error = %v", err)
	}

	if p.Name != "sparse" {
		t.Errorf("Name = %q, want %q (file stem)", p.Name, "sparse")
	}
	if p.BindPort != 8080 {
		t.Errorf("BindPort = %d, want 8080", p.BindPort)
	}
	if p.BindAddr != defaultHTTPBindAddr {
		t.Errorf("BindAddr = %q, want %q", p.BindAddr, defaultHTTPBindAddr)
	}
	if p.Methods.Task != "GET" {
		t.Errorf("Methods.Task = %q, want GET (default)", p.Methods.Task)
	}
	if len(p.URIs.Task) == 0 {
		t.Error("URIs.Task empty, want default path")
	}
	if p.Auth.Mode != authHMACSHA256 {
		t.Errorf("Auth.Mode = %q, want %q", p.Auth.Mode, authHMACSHA256)
	}
}

// TestLoadHTTPProfiles_MissingDirIsNotAnError asserts HTTP transport is opt-in:
// a server with no profile directory still starts.
func TestLoadHTTPProfiles_MissingDirIsNotAnError(t *testing.T) {
	profiles, err := LoadHTTPProfiles(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatalf("LoadHTTPProfiles() error = %v, want nil", err)
	}
	if len(profiles) != 0 {
		t.Fatalf("got %d profiles, want 0", len(profiles))
	}
}

// TestHTTPProfileStore_LoadAndHotReload asserts a changed profile is picked up
// without a restart, and that a broken edit leaves the previous one live.
func TestHTTPProfileStore_LoadAndHotReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "edge.json")

	write := func(content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}

	write(`{"name":"edge","scheme":"http","bind_port":8080,"uris":{"task":["/one"]}}`)

	store := NewHTTPProfileStore(dir)
	if err := store.Load(); err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	profile, ok := store.Get("edge")
	if !ok {
		t.Fatal("profile \"edge\" not found after Load()")
	}
	if got := profile.URIs.Task; len(got) != 1 || got[0] != "/one" {
		t.Fatalf("URIs.Task = %v, want [/one]", got)
	}

	// A no-op reload must not report changes.
	applied, rejected := store.Reload()
	if applied != 0 || rejected != 0 {
		t.Fatalf("unchanged Reload() = (%d applied, %d rejected), want (0, 0)", applied, rejected)
	}

	// Rotate the URI: this is the operator-facing hot-reload path.
	write(`{"name":"edge","scheme":"http","bind_port":8080,"uris":{"task":["/two","/three"]}}`)
	applied, rejected = store.Reload()
	if applied != 1 || rejected != 0 {
		t.Fatalf("changed Reload() = (%d applied, %d rejected), want (1, 0)", applied, rejected)
	}
	profile, _ = store.Get("edge")
	if got := profile.URIs.Task; len(got) != 2 || got[0] != "/two" {
		t.Fatalf("after reload URIs.Task = %v, want [/two /three]", got)
	}

	// A broken edit must be rejected and must NOT take the listener down.
	write(`{"name":"edge","bind_port":99999,"uris":{"task":["/bad"]}}`)
	applied, rejected = store.Reload()
	if applied != 0 || rejected != 1 {
		t.Fatalf("invalid Reload() = (%d applied, %d rejected), want (0, 1)", applied, rejected)
	}
	profile, ok = store.Get("edge")
	if !ok {
		t.Fatal("profile disappeared after a rejected edit")
	}
	if got := profile.URIs.Task; len(got) != 2 || got[0] != "/two" {
		t.Fatalf("after rejected edit URIs.Task = %v, want the previous [/two /three]", got)
	}
}

// TestHTTPProfileOperationForPath asserts request routing, including trailing
// slash normalization and method sensitivity.
func TestHTTPProfileOperationForPath(t *testing.T) {
	p := DefaultHTTPProfile()
	p.URIs = URITable{
		Register: []string{"/api/v1/ping"},
		Task:     []string{"/api/v1/sync", "/assets/sync"},
		Result:   []string{"/api/v1/report"},
		Ack:      []string{"/api/v1/ack"},
	}

	tests := []struct {
		method string
		path   string
		want   string
	}{
		{"POST", "/api/v1/ping", "register"},
		{"GET", "/api/v1/sync", "task"},
		{"GET", "/api/v1/sync/", "task"}, // trailing slash normalized
		{"GET", "/assets/sync", "task"},  // second URI for the same operation
		{"POST", "/api/v1/report", "result"},
		{"GET", "/api/v1/ack", "ack"},
		{"POST", "/api/v1/sync", ""},      // wrong method for the path
		{"GET", "/api/v1/nope", ""},       // unknown path
		{"GET", "/", ""},                  // root must not match everything
		{"GET", "/api/v1/sync/extra", ""}, // no prefix matching
	}

	for _, tc := range tests {
		if got := p.OperationForPath(tc.method, tc.path); got != tc.want {
			t.Errorf("OperationForPath(%q, %q) = %q, want %q", tc.method, tc.path, got, tc.want)
		}
	}
}

// TestGenerateListenerCert_SPKIMatches asserts the generated cert's pinned SPKI
// equals what a fresh parse of the written file produces, so a beacon pinning
// the value from the profile can verify the listener.
func TestGenerateListenerCert_SPKIMatches(t *testing.T) {
	dir := t.TempDir()

	certPath, keyPath, spki, err := GenerateListenerCert("cdn", dir, "cdn.example.com")
	if err != nil {
		t.Fatalf("GenerateListenerCert() error = %v", err)
	}

	if _, err := os.Stat(certPath); err != nil {
		t.Fatalf("certificate not written: %v", err)
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("key not written: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("key permissions = %o, want 600", perm)
	}

	recomputed, err := SPKISHA256FromPEMFile(certPath)
	if err != nil {
		t.Fatalf("SPKISHA256FromPEMFile() error = %v", err)
	}
	if recomputed != spki {
		t.Errorf("SPKI mismatch: returned %q, recomputed %q", spki, recomputed)
	}
	if spki == "" {
		t.Error("SPKI is empty")
	}
}

// TestGenerateListenerCert_RejectsEmptyName guards the caller contract.
func TestGenerateListenerCert_RejectsEmptyName(t *testing.T) {
	if _, _, _, err := GenerateListenerCert("", t.TempDir(), "x"); err == nil {
		t.Fatal("GenerateListenerCert(\"\") = nil error, want rejection")
	}
}

// contains is a local substring helper to keep assertions free of extra imports.
func contains(haystack, needle string) bool {
	if needle == "" {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
