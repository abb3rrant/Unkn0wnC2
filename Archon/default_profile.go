package main

import (
	"encoding/json"
	"fmt"
)

// The default profile exists so an operator does not start from an empty profile
// list and a blank editor. It is a complete, valid profile - every field the
// listener and the beacon read is stated rather than left to a default, so what
// the operator sees in the editor is what goes on the wire.
//
// It is deliberately plain HTTP on 8445:
//
//   - HTTPS needs a certificate *and* the SPKI pin of that certificate. Archon
//     cannot know the pin of a certificate that lives on a listener host, so a
//     shipped HTTPS default could only be a document that fails at startup with a
//     pin mismatch. A broken default is worse than no default.
//   - 8445 is already the port the Docker compose stack publishes for its first
//     listener, and it is not Archon's own 8443.
//
// beacon_host is the one field that cannot be right for every deployment: it is
// where beacons dial, not where the listener binds. It ships pointing at loopback
// so the profile is usable immediately in a local or container test, and the
// Profiles page says plainly that it has to be repointed for a real deployment.
const (
	defaultHTTPProfileName     = "default"
	defaultHTTPProfileBindPort = 8445
	defaultHTTPProfileBeacon   = "127.0.0.1:8445"
)

// defaultProfileHeader is one ordered request or response header entry.
type defaultProfileHeader struct {
	Name       string   `json:"name"`
	Value      string   `json:"value"`
	Operations []string `json:"operations,omitempty"`
}

// defaultProfileDocument is the profile written to disk and stored in Archon. The
// field order here is the order written to the document, which matters because
// request_headers is an authoritative wire-order template.
type defaultProfileDocumentShape struct {
	Name         string `json:"name"`
	Enabled      bool   `json:"enabled"`
	BindAddr     string `json:"bind_addr"`
	BindPort     int    `json:"bind_port"`
	Scheme       string `json:"scheme"`
	HostHeader   string `json:"host_header"`
	BeaconHost   string `json:"beacon_host"`
	BeaconScheme string `json:"beacon_scheme"`

	URIs struct {
		Register []string `json:"register"`
		Task     []string `json:"task"`
		Result   []string `json:"result"`
		Ack      []string `json:"ack"`
	} `json:"uris"`

	Methods struct {
		Register string `json:"register"`
		Task     string `json:"task"`
		Result   string `json:"result"`
		Ack      string `json:"ack"`
	} `json:"methods"`

	UserAgents          []string               `json:"user_agents"`
	RequestHeaders      []defaultProfileHeader `json:"request_headers"`
	ResponseHeaders     []defaultProfileHeader `json:"response_headers"`
	OmitResponseHeaders []string               `json:"omit_response_headers"`

	RequestBody struct {
		Encoding   string `json:"encoding"`
		Field      string `json:"field"`
		PaddingFld string `json:"padding_field"`
		PadMin     int    `json:"pad_min"`
		PadMax     int    `json:"pad_max"`
	} `json:"request_body"`

	ResponseBody struct {
		Encoding   string `json:"encoding"`
		Field      string `json:"field"`
		ErrorField string `json:"error_field"`
	} `json:"response_body"`

	Auth struct {
		Mode        string `json:"mode"`
		Header      string `json:"header"`
		SigEncoding string `json:"sig_encoding"`
		MaxSkewSecs int    `json:"max_skew_secs"`
	} `json:"auth"`

	Status struct {
		OK       int `json:"ok"`
		Empty    int `json:"empty"`
		NotFound int `json:"not_found"`
		Error    int `json:"error"`
	} `json:"status"`

	Jitter struct {
		MinMs int `json:"min_ms"`
		MaxMs int `json:"max_ms"`
	} `json:"jitter"`

	MaxBodyBytes int64 `json:"max_body_bytes"`
}

// defaultHTTPProfileDocument returns the shipped default profile as pretty JSON.
func defaultHTTPProfileDocument() string {
	var document defaultProfileDocumentShape

	document.Name = defaultHTTPProfileName
	document.Enabled = true
	document.BindAddr = "0.0.0.0"
	document.BindPort = defaultHTTPProfileBindPort
	document.Scheme = "http"
	document.HostHeader = ""
	document.BeaconHost = defaultHTTPProfileBeacon
	// The served listener stays plain http (Cloudflare terminates TLS); the beacon
	// DIALS https to the operator's Cloudflare-fronted hostname. Set beacon_host to
	// that hostname (e.g. cdn.example.com:443) once and builds from this profile are
	// HTTPS through Cloudflare with no certificate to manage.
	document.BeaconScheme = "https"

	document.URIs.Register = []string{"/api/v1/ping"}
	document.URIs.Task = []string{"/api/v1/sync"}
	document.URIs.Result = []string{"/api/v1/report"}
	document.URIs.Ack = []string{"/api/v1/ack"}

	document.Methods.Register = "POST"
	document.Methods.Task = "GET"
	document.Methods.Result = "POST"
	document.Methods.Ack = "GET"

	document.UserAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
	}

	// Authoritative request-header template: order is the literal wire order, and
	// only these lines are written. Host and Content-Length are mandatory for the
	// operations that carry a body, and the auth header must carry {{auth}}, which
	// is what the Archon and listener validators enforce.
	bodyOps := []string{"register", "result"}
	document.RequestHeaders = []defaultProfileHeader{
		{Name: "Host", Value: "{{host}}"},
		{Name: "Accept", Value: "application/json, text/plain, */*"},
		{Name: "Accept-Language", Value: "en-US,en;q=0.9"},
		{Name: "User-Agent", Value: "{{user_agent}}"},
		{Name: "Content-Type", Value: "application/json", Operations: bodyOps},
		{Name: "Content-Length", Value: "{{content_length}}", Operations: bodyOps},
		{Name: "X-Sig", Value: "{{auth}}"},
		{Name: "Connection", Value: "close"},
	}

	document.ResponseHeaders = []defaultProfileHeader{
		{Name: "Content-Type", Value: "{{content_type}}"},
		{Name: "Cache-Control", Value: "private, max-age=0"},
		{Name: "X-Request-Type", Value: "{{operation}}"},
	}
	document.OmitResponseHeaders = []string{"Date"}

	document.RequestBody.Encoding = "aes-gcm-base36"
	document.RequestBody.Field = "d"
	document.RequestBody.PaddingFld = "p"
	document.RequestBody.PadMin = 0
	document.RequestBody.PadMax = 32

	document.ResponseBody.Encoding = "aes-gcm-base36"
	document.ResponseBody.Field = "d"
	document.ResponseBody.ErrorField = "e"

	document.Auth.Mode = "hmac-sha256"
	document.Auth.Header = "X-Sig"
	document.Auth.SigEncoding = "hex"
	document.Auth.MaxSkewSecs = 60

	document.Status.OK = 200
	document.Status.Empty = 204
	document.Status.NotFound = 404
	document.Status.Error = 500

	document.Jitter.MinMs = 0
	document.Jitter.MaxMs = 250

	document.MaxBodyBytes = 1048576

	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		// A struct of literals cannot fail to marshal; keep the signature simple.
		return "{}"
	}
	return string(encoded)
}

// EnsureDefaultHTTPProfile seeds the shipped default profile when Archon has no
// profiles at all. It reports whether it inserted anything.
//
// Seeding only happens on an empty table: a deployment that deleted the default
// on purpose must not find it back on the next restart, and a profile list that
// already has hand-authored entries must not gain one.
func (d *MasterDatabase) EnsureDefaultHTTPProfile() (bool, error) {
	var count int
	if err := d.db.QueryRow(`SELECT COUNT(*) FROM http_profiles`).Scan(&count); err != nil {
		return false, fmt.Errorf("count HTTP profiles: %w", err)
	}
	if count > 0 {
		return false, nil
	}

	document, err := normalizeHTTPProfileDocument(defaultHTTPProfileName, defaultHTTPProfileDocument())
	if err != nil {
		// The shipped document must always be storable; failing here means the
		// template and the validator have drifted apart.
		return false, fmt.Errorf("default HTTP profile is not valid: %w", err)
	}
	if err := d.SaveHTTPProfile(defaultHTTPProfileName, document); err != nil {
		return false, err
	}
	return true, nil
}
