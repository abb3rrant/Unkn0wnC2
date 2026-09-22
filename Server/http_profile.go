// Package main implements malleable HTTP/HTTPS listener profiles for the
// Unkn0wnC2 DNS server.
//
// A profile is the HTTP-transport equivalent of the per-phase malleable DNS
// configuration: it describes how the listener looks on the wire (URIs, method,
// header set and order, user-agent pool, body codec, status codes) and how
// requests are authenticated. Profiles live as JSON files on disk and are
// hot-reloaded, so an operator can rotate URIs without restarting a listener.
//
// See docs/http-transport.md for the full field reference.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Body codecs accepted by HTTPProfileRequestBody/ResponseBody.
const (
	codecRaw          = "raw"
	codecBase64       = "base64"
	codecBase36       = "base36"
	codecAESGCMBase64 = "aes-gcm-base64"
	codecAESGCMBase36 = "aes-gcm-base36"
)

// Auth modes accepted by HTTPProfileAuth.
const (
	authHMACSHA256  = "hmac-sha256"
	authSharedHeadr = "shared-header"
	authNone        = "none"
)

// Default values used when a profile omits a field.
//
// The default scheme is plain "http": a profile that omits cert material cannot
// be a working HTTPS listener, so HTTPS is an explicit choice that must name its
// certificate. The installer generates a self-signed cert per listener and the
// shipped example profile uses HTTPS.
const (
	defaultHTTPBindAddr    = "0.0.0.0"
	defaultHTTPBindPort    = 8443
	defaultScheme          = "http"
	defaultHTTPNotFound    = 404
	defaultHTTPOK          = 200
	defaultHTTPEmpty       = 204
	defaultHTTPMaxBody     = 1048576 // 1 MiB
	defaultHTTPTLSVersion  = "1.2"
	defaultHTTPRetryAfter  = 60
	defaultHTTPTaskURI     = "/api/v1/sync"
	defaultHTTPRegisterURI = "/api/v1/ping"
	defaultHTTPResultURI   = "/api/v1/report"
	defaultHTTPAckURI      = "/api/v1/ack"
	defaultHTTPAuthHeader  = "X-Sig"
)

// URITable maps each protocol operation to one or more request paths. Multiple
// paths per operation let an operator rotate URIs without rebuilding beacons.
type URITable struct {
	Register []string `json:"register"`
	Task     []string `json:"task"`
	Result   []string `json:"result"`
	Ack      []string `json:"ack"`
}

// MethodTable maps each protocol operation to its HTTP method.
type MethodTable struct {
	Register string `json:"register"`
	Task     string `json:"task"`
	Result   string `json:"result"`
	Ack      string `json:"ack"`
}

// HeaderEntry is one request header. Order in the profile is the order the
// beacon emits headers in, which is a wire-visible property.
type HeaderEntry struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// BodyCodec describes how a request or response body is encoded.
type BodyCodec struct {
	Encoding   string `json:"encoding"`
	Field      string `json:"field"`         // JSON field carrying the payload
	ErrorField string `json:"error_field"`   // JSON field carrying an error string
	PaddingFld string `json:"padding_field"` // JSON field carrying random padding
	PadMin     int    `json:"pad_min"`
	PadMax     int    `json:"pad_max"`
}

// ProfileTLS describes the listener certificate and its pinned SPKI.
type ProfileTLS struct {
	CertFile   string `json:"cert_file"`
	KeyFile    string `json:"key_file"`
	SPKISHA256 string `json:"spki_sha256"` // base64(SHA-256(SubjectPublicKeyInfo))
	MinVersion string `json:"min_version"`
}

// ProfileAuth describes beacon request authentication.
type ProfileAuth struct {
	Mode        string `json:"mode"` // hmac-sha256 | shared-header | none
	Header      string `json:"header"`
	SigEncoding string `json:"sig_encoding"` // hex | base64
	MaxSkewSecs int    `json:"max_skew_secs"`
}

// ProfileStatus maps protocol outcomes to HTTP status codes.
type ProfileStatus struct {
	OK       int `json:"ok"`
	Empty    int `json:"empty"`
	NotFound int `json:"not_found"`
	Error    int `json:"error"`
}

// ProfileJitter adds a random delay before responding, in milliseconds.
type ProfileJitter struct {
	MinMs int `json:"min_ms"`
	MaxMs int `json:"max_ms"`
}

// HTTPProfile is one malleable HTTP/HTTPS listener.
type HTTPProfile struct {
	Name         string        `json:"name"`
	Enabled      bool          `json:"enabled"`
	BindAddr     string        `json:"bind_addr"`
	BindPort     int           `json:"bind_port"`
	Scheme       string        `json:"scheme"` // http | https
	HostHeader   string        `json:"host_header"`
	TLS          ProfileTLS    `json:"tls"`
	URIs         URITable      `json:"uris"`
	Methods      MethodTable   `json:"methods"`
	UserAgents   []string      `json:"user_agents"`
	Headers      []HeaderEntry `json:"headers"`
	RequestBody  BodyCodec     `json:"request_body"`
	ResponseBody BodyCodec     `json:"response_body"`
	Auth         ProfileAuth   `json:"auth"`
	Status       ProfileStatus `json:"status"`
	Jitter       ProfileJitter `json:"jitter"`
	MaxBodyBytes int64         `json:"max_body_bytes"`

	// SourcePath is where this profile was loaded from. Not serialized.
	SourcePath string `json:"-"`
}

// DefaultHTTPProfile returns a profile with every field populated to a working
// default, so a partially-specified profile file still yields a valid listener.
func DefaultHTTPProfile() HTTPProfile {
	return HTTPProfile{
		Name:       "default",
		Enabled:    true,
		BindAddr:   defaultHTTPBindAddr,
		BindPort:   defaultHTTPBindPort,
		Scheme:     defaultScheme,
		HostHeader: "",
		TLS: ProfileTLS{
			MinVersion: defaultHTTPTLSVersion,
		},
		URIs: URITable{
			Register: []string{defaultHTTPRegisterURI},
			Task:     []string{defaultHTTPTaskURI},
			Result:   []string{defaultHTTPResultURI},
			Ack:      []string{defaultHTTPAckURI},
		},
		Methods: MethodTable{
			Register: "POST",
			Task:     "GET",
			Result:   "POST",
			Ack:      "GET",
		},
		RequestBody: BodyCodec{
			Encoding:   codecAESGCMBase36,
			Field:      "d",
			PaddingFld: "p",
			PadMin:     0,
			PadMax:     32,
		},
		ResponseBody: BodyCodec{
			Encoding:   codecAESGCMBase36,
			Field:      "d",
			ErrorField: "e",
		},
		Auth: ProfileAuth{
			Mode:        authHMACSHA256,
			Header:      defaultHTTPAuthHeader,
			SigEncoding: "hex",
			MaxSkewSecs: 300,
		},
		Status: ProfileStatus{
			OK:       defaultHTTPOK,
			Empty:    defaultHTTPEmpty,
			NotFound: defaultHTTPNotFound,
			Error:    500,
		},
		MaxBodyBytes: defaultHTTPMaxBody,
	}
}

// applyDefaults fills unset fields from DefaultHTTPProfile. Called before
// Validate so a sparse profile is valid rather than rejected.
func (p *HTTPProfile) applyDefaults() {
	d := DefaultHTTPProfile()

	if p.BindAddr == "" {
		p.BindAddr = d.BindAddr
	}
	if p.BindPort == 0 {
		p.BindPort = d.BindPort
	}
	if p.Scheme == "" {
		p.Scheme = d.Scheme
	}
	if p.Name == "" {
		p.Name = d.Name
	}
	if len(p.UserAgents) == 0 {
		p.UserAgents = d.UserAgents
	}
	if p.MaxBodyBytes == 0 {
		p.MaxBodyBytes = d.MaxBodyBytes
	}

	if p.Methods.Register == "" {
		p.Methods.Register = d.Methods.Register
	}
	if p.Methods.Task == "" {
		p.Methods.Task = d.Methods.Task
	}
	if p.Methods.Result == "" {
		p.Methods.Result = d.Methods.Result
	}
	if p.Methods.Ack == "" {
		p.Methods.Ack = d.Methods.Ack
	}

	if p.RequestBody.Encoding == "" {
		p.RequestBody.Encoding = d.RequestBody.Encoding
	}
	if p.RequestBody.Field == "" {
		p.RequestBody.Field = d.RequestBody.Field
	}
	if p.RequestBody.PaddingFld == "" {
		p.RequestBody.PaddingFld = d.RequestBody.PaddingFld
	}
	if p.ResponseBody.Encoding == "" {
		p.ResponseBody.Encoding = d.ResponseBody.Encoding
	}
	if p.ResponseBody.Field == "" {
		p.ResponseBody.Field = d.ResponseBody.Field
	}
	if p.ResponseBody.ErrorField == "" {
		p.ResponseBody.ErrorField = d.ResponseBody.ErrorField
	}

	if p.Auth.Mode == "" {
		p.Auth.Mode = d.Auth.Mode
	}
	if p.Auth.Header == "" {
		p.Auth.Header = d.Auth.Header
	}
	if p.Auth.SigEncoding == "" {
		p.Auth.SigEncoding = d.Auth.SigEncoding
	}
	if p.Auth.MaxSkewSecs == 0 {
		p.Auth.MaxSkewSecs = d.Auth.MaxSkewSecs
	}

	if p.Status.OK == 0 {
		p.Status.OK = d.Status.OK
	}
	if p.Status.Empty == 0 {
		p.Status.Empty = d.Status.Empty
	}
	if p.Status.NotFound == 0 {
		p.Status.NotFound = d.Status.NotFound
	}
	if p.Status.Error == 0 {
		p.Status.Error = d.Status.Error
	}

	if p.TLS.MinVersion == "" {
		p.TLS.MinVersion = d.TLS.MinVersion
	}
}

// Validate checks a profile for required fields and sensible values. It returns
// a descriptive error for the first invalid field so the operator sees exactly
// what to fix, and is shared by the listener and the Archon profile API.
func (p *HTTPProfile) Validate() error {
	if p.BindPort < 1 || p.BindPort > 65535 {
		return fmt.Errorf("BindPort must be in range [1, 65535], got %d", p.BindPort)
	}
	switch p.Scheme {
	case "http", "https":
	default:
		return fmt.Errorf("Scheme must be \"http\" or \"https\", got %q", p.Scheme)
	}
	if p.MaxBodyBytes < 1 {
		return fmt.Errorf("MaxBodyBytes must be positive, got %d", p.MaxBodyBytes)
	}
	if p.Jitter.MinMs < 0 || p.Jitter.MaxMs < 0 {
		return fmt.Errorf("Jitter values must be non-negative")
	}
	if p.Jitter.MaxMs > 0 && p.Jitter.MaxMs < p.Jitter.MinMs {
		return fmt.Errorf("Jitter.MaxMs (%d) must be >= Jitter.MinMs (%d)", p.Jitter.MaxMs, p.Jitter.MinMs)
	}

	if len(p.URIs.Register) == 0 {
		return fmt.Errorf("URIs.Register must have at least one path")
	}
	if len(p.URIs.Task) == 0 {
		return fmt.Errorf("URIs.Task must have at least one path")
	}
	if len(p.URIs.Result) == 0 {
		return fmt.Errorf("URIs.Result must have at least one path")
	}
	if len(p.URIs.Ack) == 0 {
		return fmt.Errorf("URIs.Ack must have at least one path")
	}
	for op, paths := range map[string][]string{
		"register": p.URIs.Register,
		"task":     p.URIs.Task,
		"result":   p.URIs.Result,
		"ack":      p.URIs.Ack,
	} {
		for _, path := range paths {
			if err := validateURIPath(path); err != nil {
				return fmt.Errorf("URIs.%s: %w", op, err)
			}
		}
	}

	for op, method := range map[string]string{
		"register": p.Methods.Register,
		"task":     p.Methods.Task,
		"result":   p.Methods.Result,
		"ack":      p.Methods.Ack,
	} {
		switch strings.ToUpper(method) {
		case "GET", "POST", "PUT", "HEAD":
		default:
			return fmt.Errorf("Methods.%s must be GET, POST, PUT or HEAD, got %q", op, method)
		}
	}

	if err := validateCodec("RequestBody", p.RequestBody); err != nil {
		return err
	}
	if err := validateCodec("ResponseBody", p.ResponseBody); err != nil {
		return err
	}
	if p.RequestBody.PadMin < 0 || p.RequestBody.PadMax < 0 {
		return fmt.Errorf("RequestBody padding values must be non-negative")
	}
	if p.RequestBody.PadMax < p.RequestBody.PadMin {
		return fmt.Errorf("RequestBody.PadMax (%d) must be >= PadMin (%d)", p.RequestBody.PadMax, p.RequestBody.PadMin)
	}

	switch p.Auth.Mode {
	case authHMACSHA256, authSharedHeadr, authNone:
	default:
		return fmt.Errorf("Auth.Mode must be %q, %q or %q, got %q",
			authHMACSHA256, authSharedHeadr, authNone, p.Auth.Mode)
	}
	if p.Auth.Mode != authNone {
		if p.Auth.Header == "" {
			return fmt.Errorf("Auth.Header must be non-empty when Auth.Mode is %q", p.Auth.Mode)
		}
		switch p.Auth.SigEncoding {
		case "hex", "base64":
		default:
			return fmt.Errorf("Auth.SigEncoding must be \"hex\" or \"base64\", got %q", p.Auth.SigEncoding)
		}
		if p.Auth.MaxSkewSecs < 0 {
			return fmt.Errorf("Auth.MaxSkewSecs must be non-negative")
		}
	}

	for name, code := range map[string]int{
		"Status.OK":       p.Status.OK,
		"Status.Empty":    p.Status.Empty,
		"Status.NotFound": p.Status.NotFound,
		"Status.Error":    p.Status.Error,
	} {
		if code < 100 || code > 599 {
			return fmt.Errorf("%s must be a valid HTTP status code, got %d", name, code)
		}
	}

	for i, h := range p.Headers {
		if strings.TrimSpace(h.Name) == "" {
			return fmt.Errorf("Headers[%d] has an empty name", i)
		}
		if strings.ContainsAny(h.Name, ":\r\n") {
			return fmt.Errorf("Headers[%d] name %q contains illegal characters", i, h.Name)
		}
		if strings.ContainsAny(h.Value, "\r\n") {
			return fmt.Errorf("Headers[%d] value contains a line break", i)
		}
	}

	for i, ua := range p.UserAgents {
		if strings.ContainsAny(ua, "\r\n") {
			return fmt.Errorf("UserAgents[%d] contains a line break", i)
		}
	}

	if p.Scheme == "https" {
		if p.TLS.CertFile == "" || p.TLS.KeyFile == "" {
			return fmt.Errorf("TLS.CertFile and TLS.KeyFile are required when Scheme is \"https\"")
		}
		switch p.TLS.MinVersion {
		case "1.2", "1.3":
		default:
			return fmt.Errorf("TLS.MinVersion must be \"1.2\" or \"1.3\", got %q", p.TLS.MinVersion)
		}
	}

	return nil
}

// validateURIPath requires an absolute path with no whitespace or query string.
func validateURIPath(path string) error {
	if path == "" {
		return fmt.Errorf("empty path")
	}
	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("path %q must start with \"/\"", path)
	}
	if strings.ContainsAny(path, " \t\r\n?#") {
		return fmt.Errorf("path %q must not contain whitespace, a query string or a fragment", path)
	}
	return nil
}

// validateCodec checks a body codec's encoding and JSON field names.
func validateCodec(label string, c BodyCodec) error {
	switch c.Encoding {
	case codecRaw, codecBase64, codecBase36, codecAESGCMBase64, codecAESGCMBase36:
	default:
		return fmt.Errorf("%s.Encoding must be one of %s, %s, %s, %s, %s; got %q",
			label, codecRaw, codecBase64, codecBase36, codecAESGCMBase64, codecAESGCMBase36, c.Encoding)
	}
	if c.Field == "" {
		return fmt.Errorf("%s.Field must be non-empty", label)
	}
	for name, field := range map[string]string{
		label + ".Field":      c.Field,
		label + ".ErrorField": c.ErrorField,
		label + ".PaddingFld": c.PaddingFld,
	} {
		if field == "" {
			continue
		}
		if strings.ContainsAny(field, " \t\r\n\"\\{}[],:") {
			return fmt.Errorf("%s name %q is not a valid JSON key", name, field)
		}
	}
	return nil
}

// ListenerAddr returns the host:port the listener should bind to.
func (p *HTTPProfile) ListenerAddr() string {
	return net.JoinHostPort(p.BindAddr, fmt.Sprintf("%d", p.BindPort))
}

// AllURIs returns every configured path, used to reject non-matching requests
// uniformly and to document the surface in the UI.
func (p *HTTPProfile) AllURIs() []string {
	var out []string
	out = append(out, p.URIs.Register...)
	out = append(out, p.URIs.Task...)
	out = append(out, p.URIs.Result...)
	out = append(out, p.URIs.Ack...)
	return out
}

// OperationForPath maps a request path and method to a protocol operation
// ("register", "task", "result", "ack") or "" when nothing matches. Used by the
// listener to route, and by authorization code that must know the operation.
func (p *HTTPProfile) OperationForPath(method, path string) string {
	// Trailing slashes are normalized so "/sync/" and "/sync" behave the same.
	normalized := strings.TrimSuffix(path, "/")
	if normalized == "" {
		normalized = "/"
	}

	table := []struct {
		op     string
		paths  []string
		method string
	}{
		{"register", p.URIs.Register, p.Methods.Register},
		{"task", p.URIs.Task, p.Methods.Task},
		{"result", p.URIs.Result, p.Methods.Result},
		{"ack", p.URIs.Ack, p.Methods.Ack},
	}

	for _, entry := range table {
		if !strings.EqualFold(method, entry.method) {
			continue
		}
		for _, candidate := range entry.paths {
			cand := strings.TrimSuffix(candidate, "/")
			if cand == "" {
				cand = "/"
			}
			if cand == normalized {
				return entry.op
			}
		}
	}
	return ""
}

// LoadHTTPProfile reads and validates a single profile file.
func LoadHTTPProfile(path string) (*HTTPProfile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read profile %s: %w", path, err)
	}

	// Start from defaults so a sparse profile file is still valid.
	p := DefaultHTTPProfile()
	// Name defaults to the file stem so listings are useful without a name field.
	base := filepath.Base(path)
	p.Name = strings.TrimSuffix(base, filepath.Ext(base))

	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("failed to parse profile %s: %w", path, err)
	}

	p.SourcePath = path
	p.applyDefaults()

	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("invalid profile %s: %w", path, err)
	}
	return &p, nil
}

// LoadHTTPProfiles loads every *.json profile in a directory, sorted by name so
// startup order is deterministic. A directory that does not exist yields an
// empty set rather than an error: HTTP transport is opt-in.
func LoadHTTPProfiles(dir string) ([]*HTTPProfile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read profile directory %s: %w", dir, err)
	}

	var paths []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !strings.EqualFold(filepath.Ext(entry.Name()), ".json") {
			continue
		}
		paths = append(paths, filepath.Join(dir, entry.Name()))
	}
	sort.Strings(paths)

	var profiles []*HTTPProfile
	for _, path := range paths {
		p, err := LoadHTTPProfile(path)
		if err != nil {
			return nil, err
		}
		profiles = append(profiles, p)
	}
	return profiles, nil
}

// fileStamp is the identity of a profile file at a point in time.
type fileStamp struct {
	ModTime time.Time
	Size    int64
}

// HTTPProfileStore holds the live profiles and hot-reloads them from disk.
//
// Reload swaps in new profiles under a lock. A profile that fails to parse or
// validate is rejected and the previously loaded version stays live, so a bad
// edit can never take a listener down.
type HTTPProfileStore struct {
	dir      string
	mu       sync.RWMutex
	profiles map[string]*HTTPProfile
	stamps   map[string]fileStamp
	// sources records whether a profile came from a file on this host or was
	// delivered by Archon. A remote profile wins over a file of the same name, so
	// an operator editing files cannot silently override what the control plane
	// assigned to this listener.
	sources map[string]string
}

// Profile sources.
const (
	profileSourceFile   = "file"
	profileSourceRemote = "remote"
)

// NewHTTPProfileStore creates an empty store for a directory.
func NewHTTPProfileStore(dir string) *HTTPProfileStore {
	return &HTTPProfileStore{
		dir:      dir,
		profiles: make(map[string]*HTTPProfile),
		stamps:   make(map[string]fileStamp),
		sources:  make(map[string]string),
	}
}

// Dir returns the directory the store watches.
func (s *HTTPProfileStore) Dir() string {
	return s.dir
}

// Get returns a live profile by name. The returned pointer is immutable: reloads
// swap the map entry rather than mutating a profile in place.
func (s *HTTPProfileStore) Get(name string) (*HTTPProfile, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.profiles[name]
	return p, ok
}

// List returns all live profiles sorted by name.
func (s *HTTPProfileStore) List() []*HTTPProfile {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]*HTTPProfile, 0, len(s.profiles))
	for _, p := range s.profiles {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Load reads the directory once and populates the store. Called at startup, so
// errors here are fatal to the HTTP transport and are returned to the caller.
func (s *HTTPProfileStore) Load() error {
	profiles, err := LoadHTTPProfiles(s.dir)
	if err != nil {
		return err
	}

	stamps := make(map[string]fileStamp, len(profiles))
	byName := make(map[string]*HTTPProfile, len(profiles))

	s.mu.RLock()
	existingSources := s.sources
	s.mu.RUnlock()

	sources := make(map[string]string, len(profiles))
	for _, p := range profiles {
		// A profile delivered by Archon survives a directory reload.
		if existingSources[p.Name] == profileSourceRemote {
			if existing, ok := s.Get(p.Name); ok {
				byName[p.Name] = existing
				sources[p.Name] = profileSourceRemote
				continue
			}
		}
		byName[p.Name] = p
		sources[p.Name] = profileSourceFile
		if info, err := os.Stat(p.SourcePath); err == nil {
			stamps[p.SourcePath] = fileStamp{ModTime: info.ModTime(), Size: info.Size()}
		}
	}

	// Remote profiles with no file behind them are not in `profiles`, so carry
	// them over explicitly.
	for name, source := range existingSources {
		if source != profileSourceRemote {
			continue
		}
		if _, present := byName[name]; present {
			continue
		}
		if existing, ok := s.Get(name); ok {
			byName[name] = existing
			sources[name] = profileSourceRemote
		}
	}

	s.mu.Lock()
	s.profiles = byName
	s.stamps = stamps
	s.sources = sources
	s.mu.Unlock()
	return nil
}

// Reload re-reads files whose mtime or size changed and reports how many profiles
// were swapped and how many were rejected. Rejections are logged and the old
// profile remains live.
func (s *HTTPProfileStore) Reload() (applied int, rejected int) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		if !os.IsNotExist(err) {
			logf("[HTTP] Profile reload failed to read %s: %v", s.dir, err)
		}
		return 0, 0
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.EqualFold(filepath.Ext(entry.Name()), ".json") {
			continue
		}
		path := filepath.Join(s.dir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			continue
		}

		stamp := fileStamp{ModTime: info.ModTime(), Size: info.Size()}

		s.mu.RLock()
		previous, seen := s.stamps[path]
		s.mu.RUnlock()
		if seen && previous == stamp {
			continue
		}

		profile, err := LoadHTTPProfile(path)
		if err != nil {
			logf("[HTTP] Rejecting changed profile %s (keeping previous): %v", path, err)
			rejected++
			// Record the stamp so a persistently broken file is not re-logged
			// on every tick; the next edit will be noticed.
			s.mu.Lock()
			s.stamps[path] = stamp
			s.mu.Unlock()
			continue
		}

		s.mu.Lock()
		if s.sources[profile.Name] == profileSourceRemote {
			// Archon owns this name; the file is ignored until the assignment is
			// removed. Record the stamp so the file is not re-read every tick.
			s.stamps[path] = stamp
			s.mu.Unlock()
			logf("[HTTP] Ignoring file %s: profile %q is assigned by the control plane", path, profile.Name)
			continue
		}
		s.profiles[profile.Name] = profile
		s.sources[profile.Name] = profileSourceFile
		s.stamps[path] = stamp
		s.mu.Unlock()

		logf("[HTTP] Reloaded profile %q from %s", profile.Name, path)
		applied++
	}
	return applied, rejected
}

// SPKISHA256 returns base64(SHA-256(SubjectPublicKeyInfo)) for a certificate,
// the value a beacon pins. Deriving it from the parsed cert rather than the raw
// DER keeps it stable across re-encodings of the same key.
func SPKISHA256(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// SPKISHA256FromPEMFile loads a PEM certificate and returns its pinned SPKI hash.
func SPKISHA256FromPEMFile(certPath string) (string, error) {
	pemBytes, err := os.ReadFile(certPath)
	if err != nil {
		return "", fmt.Errorf("failed to read certificate %s: %w", certPath, err)
	}
	cert, err := parseFirstCertificate(pemBytes)
	if err != nil {
		return "", err
	}
	return SPKISHA256(cert), nil
}

// GenerateListenerCert writes a self-signed certificate and its 0600 key into
// dir, returning both paths and the pinned SPKI hash. This mirrors the cert
// layout the installer already uses for the master cert
// (/opt/unkn0wnc2/certs), so operators have one place to look.
func GenerateListenerCert(name, dir, hostHeader string) (certPath, keyPath, spkiB64 string, err error) {
	if name == "" {
		return "", "", "", fmt.Errorf("certificate name must be non-empty")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", "", "", fmt.Errorf("failed to create cert directory %s: %w", dir, err)
	}

	commonName := hostHeader
	if commonName == "" {
		commonName = name
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate key: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate serial: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if ip := net.ParseIP(commonName); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else if commonName != "" {
		template.DNSNames = append(template.DNSNames, commonName)
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to parse generated certificate: %w", err)
	}

	certPath = filepath.Join(dir, "http-"+name+".crt")
	keyPath = filepath.Join(dir, "http-"+name+".key")

	certPEM := pemEncodeBlock("CERTIFICATE", der)
	keyPEM := pemEncodeBlock("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(priv))

	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return "", "", "", fmt.Errorf("failed to write certificate: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return "", "", "", fmt.Errorf("failed to write key: %w", err)
	}

	return certPath, keyPath, SPKISHA256(cert), nil
}

// parseFirstCertificate decodes the first CERTIFICATE block in PEM data.
func parseFirstCertificate(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in certificate data")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	return cert, nil
}

// pemEncodeBlock wraps DER bytes in a single PEM block.
func pemEncodeBlock(blockType string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
}

// Source returns where a live profile came from.
func (s *HTTPProfileStore) Source(name string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if source, ok := s.sources[name]; ok {
		return source
	}
	return ""
}

// UpsertRemote installs a profile delivered by Archon, replacing any file profile
// with the same name. The profile is validated here as well as on the way in, so a
// document that reached this process by any route still has to be usable before it
// can affect a listener.
func (s *HTTPProfileStore) UpsertRemote(profile *HTTPProfile) error {
	if profile == nil {
		return fmt.Errorf("profile is required")
	}
	if profile.Name == "" {
		return fmt.Errorf("profile has no name")
	}
	profile.applyDefaults()
	if err := profile.Validate(); err != nil {
		return fmt.Errorf("assigned profile %q is invalid: %w", profile.Name, err)
	}
	profile.SourcePath = ""

	s.mu.Lock()
	s.profiles[profile.Name] = profile
	s.sources[profile.Name] = profileSourceRemote
	s.mu.Unlock()

	return nil
}

// RemoveRemote drops a profile that the control plane no longer assigns. A file
// profile of the same name is not restored until the next reload, which is
// deliberate: the assignment is authoritative for as long as it exists.
func (s *HTTPProfileStore) RemoveRemote(name string) {
	s.mu.Lock()
	if s.sources[name] == profileSourceRemote {
		delete(s.profiles, name)
		delete(s.sources, name)
	}
	s.mu.Unlock()
}

// RemoteNames lists the profiles currently assigned by the control plane.
func (s *HTTPProfileStore) RemoteNames() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	names := make([]string, 0, len(s.sources))
	for name, source := range s.sources {
		if source == profileSourceRemote {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}
