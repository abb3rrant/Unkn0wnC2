// Package main stores and serves malleable HTTP listener profiles.
//
// Archon is the store and the delivery path, not the enforcement point. The
// listener validates a profile again when it loads one, and it is the authority:
// a profile that passes here but is rejected there fails as a listener that
// refuses to start. Archon's validation exists to catch the mistakes early, while
// an operator is looking at a form, instead of at deploy time.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// HTTPProfileRecord is one stored listener profile.
type HTTPProfileRecord struct {
	Name      string    `json:"name"`
	Document  string    `json:"document"`
	UpdatedAt time.Time `json:"updated_at"`
}

// httpProfileNamePattern keeps a profile name usable as a filename, because the
// DNS server derives a profile's name from its file stem. A name that cannot be a
// filename would produce a listener whose reported name differs from the one the
// operator stored.
var httpProfileNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// Recognised body codecs, matching the listener and the beacon.
var httpProfileEncodings = map[string]bool{
	"raw":            true,
	"base64":         true,
	"base36":         true,
	"aes-gcm-base64": true,
	"aes-gcm-base36": true,
}

// httpProfileDocument is the subset of a profile Archon validates. Unknown fields
// are preserved as written, because the document is stored and shipped verbatim;
// this type exists only to read the values that need checking.
type httpProfileDocument struct {
	Name       string `json:"name"`
	Enabled    *bool  `json:"enabled"`
	BindPort   int    `json:"bind_port"`
	BindAddr   string `json:"bind_addr"`
	Scheme     string `json:"scheme"`
	HostHeader string `json:"host_header"`
	BeaconHost string `json:"beacon_host"`
	TLS        struct {
		CertFile   string `json:"cert_file"`
		KeyFile    string `json:"key_file"`
		SPKISHA256 string `json:"spki_sha256"`
	} `json:"tls"`
	URIs                map[string][]string `json:"uris"`
	Methods             map[string]string   `json:"methods"`
	UserAgents          []string            `json:"user_agents"`
	Headers             []HTTPHeaderSpec    `json:"headers"`
	RequestHeaders      []HTTPHeaderSpec    `json:"request_headers"`
	ResponseHeaders     []HTTPHeaderSpec    `json:"response_headers"`
	OmitResponseHeaders []string            `json:"omit_response_headers"`
	Auth                struct {
		Mode   string `json:"mode"`
		Header string `json:"header"`
	} `json:"auth"`
	RequestBody struct {
		Encoding string `json:"encoding"`
	} `json:"request_body"`
	ResponseBody struct {
		Encoding string `json:"encoding"`
	} `json:"response_body"`
}

// migration19AddHTTPProfiles stores malleable HTTP listener profiles so they can
// be authored, kept and handed to a build from one place.
func (d *MasterDatabase) migration19AddHTTPProfiles() error {
	_, err := d.db.Exec(`
		CREATE TABLE IF NOT EXISTS http_profiles (
			name TEXT PRIMARY KEY,
			document TEXT NOT NULL,
			updated_at INTEGER NOT NULL
		)
	`)
	return err
}

// SaveHTTPProfile stores a profile document, replacing any previous version.
func (d *MasterDatabase) SaveHTTPProfile(name, document string) error {
	if _, err := d.db.Exec(`
		INSERT INTO http_profiles (name, document, updated_at)
		VALUES (?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET document = excluded.document, updated_at = excluded.updated_at
	`, name, document, time.Now().Unix()); err != nil {
		return fmt.Errorf("failed to save HTTP profile %q: %w", name, err)
	}
	return nil
}

// GetHTTPProfile returns one stored profile.
func (d *MasterDatabase) GetHTTPProfile(name string) (*HTTPProfileRecord, error) {
	var record HTTPProfileRecord
	var updatedAt int64

	err := d.db.QueryRow(`
		SELECT name, document, updated_at FROM http_profiles WHERE name = ?
	`, name).Scan(&record.Name, &record.Document, &updatedAt)

	if err != nil {
		return nil, err
	}
	record.UpdatedAt = time.Unix(updatedAt, 0)
	return &record, nil
}

// ListHTTPProfiles returns every stored profile, newest first.
func (d *MasterDatabase) ListHTTPProfiles() ([]HTTPProfileRecord, error) {
	rows, err := d.db.Query(`
		SELECT name, document, updated_at FROM http_profiles ORDER BY name
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to list HTTP profiles: %w", err)
	}
	defer rows.Close()

	records := []HTTPProfileRecord{}
	for rows.Next() {
		var record HTTPProfileRecord
		var updatedAt int64
		if err := rows.Scan(&record.Name, &record.Document, &updatedAt); err != nil {
			return nil, fmt.Errorf("failed to read HTTP profile row: %w", err)
		}
		record.UpdatedAt = time.Unix(updatedAt, 0)
		records = append(records, record)
	}
	return records, rows.Err()
}

// DeleteHTTPProfile removes a stored profile.
func (d *MasterDatabase) DeleteHTTPProfile(name string) error {
	if _, err := d.db.Exec(`DELETE FROM http_profiles WHERE name = ?`, name); err != nil {
		return fmt.Errorf("failed to delete HTTP profile %q: %w", name, err)
	}
	return nil
}

func validateArchonHeaderName(name string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("has an empty name")
	}
	const separators = "()<>@,;:\\\"/[]?={} \t"
	for _, char := range name {
		if char < 33 || char > 126 || strings.ContainsRune(separators, char) {
			return fmt.Errorf("name %q contains an illegal character", name)
		}
	}
	return nil
}

func validateArchonHeaders(label string, headers []HTTPHeaderSpec, allowed map[string]bool) error {
	for i, header := range headers {
		if err := validateArchonHeaderName(header.Name); err != nil {
			return fmt.Errorf("%s[%d] %w", label, i, err)
		}
		if strings.ContainsAny(header.Value, "\r\n") {
			return fmt.Errorf("%s[%d].value contains a line break", label, i)
		}
		for _, operation := range header.Operations {
			switch strings.ToLower(operation) {
			case "register", "task", "result", "ack":
			default:
				return fmt.Errorf("%s[%d] has unknown operation %q", label, i, operation)
			}
		}
		rest := header.Value
		for {
			start := strings.Index(rest, "{{")
			if start < 0 {
				break
			}
			end := strings.Index(rest[start+2:], "}}")
			if end < 0 {
				return fmt.Errorf("%s[%d] has an unterminated template", label, i)
			}
			name := rest[start+2 : start+2+end]
			if !allowed[name] {
				return fmt.Errorf("%s[%d] uses unknown template %q", label, i, "{{"+name+"}}")
			}
			rest = rest[start+2+end+2:]
		}
	}
	return nil
}

func archonHeaderApplies(header HTTPHeaderSpec, operation string) bool {
	if len(header.Operations) == 0 {
		return true
	}
	for _, candidate := range header.Operations {
		if strings.EqualFold(candidate, operation) {
			return true
		}
	}
	return false
}

func validateArchonAuthoritativeHeaders(profile httpProfileDocument) error {
	if len(profile.RequestHeaders) == 0 {
		return nil
	}
	has := func(operation, name, token string) bool {
		for _, header := range profile.RequestHeaders {
			if archonHeaderApplies(header, operation) && strings.EqualFold(header.Name, name) &&
				(token == "" || strings.Contains(header.Value, token)) {
				return true
			}
		}
		return false
	}
	authMode := profile.Auth.Mode
	if authMode == "" {
		authMode = "hmac-sha256"
	}
	authHeader := profile.Auth.Header
	if authHeader == "" {
		authHeader = "X-Sig"
	}
	for _, operation := range []string{"register", "task", "result", "ack"} {
		if !has(operation, "Host", "") {
			return fmt.Errorf("request_headers must provide Host for %s", operation)
		}
		if authMode != "none" && !has(operation, authHeader, "{{auth}}") {
			return fmt.Errorf("request_headers must provide %s with {{auth}} for %s", authHeader, operation)
		}
		method := strings.ToUpper(profile.Methods[operation])
		if method == "" {
			if operation == "task" || operation == "ack" {
				method = "GET"
			} else {
				method = "POST"
			}
		}
		if method != "GET" && method != "HEAD" && !has(operation, "Content-Length", "{{content_length}}") {
			return fmt.Errorf("request_headers must provide Content-Length with {{content_length}} for %s", operation)
		}
	}
	for _, header := range profile.RequestHeaders {
		if strings.Contains(header.Value, "{{user_agent}}") && len(profile.UserAgents) == 0 {
			return fmt.Errorf("request_headers uses {{user_agent}} but user_agents is empty")
		}
	}
	return nil
}

// normalizeHTTPProfileDocument validates a profile and returns the document that
// should be stored.
//
// It pins the document's name field to the record name, so the file an operator
// downloads has a stem matching the profile's own name. A profile whose name
// disagreed with its filename would load under a different name than the one it
// was saved as, which is the kind of mismatch that costs an afternoon.
func normalizeHTTPProfileDocument(name, document string) (string, error) {
	if !httpProfileNamePattern.MatchString(name) {
		return "", fmt.Errorf("profile name %q must be 1-64 characters of letters, digits, dot, dash or underscore, and start with a letter or digit", name)
	}

	var parsed httpProfileDocument
	if err := json.Unmarshal([]byte(document), &parsed); err != nil {
		return "", fmt.Errorf("profile document is not valid JSON: %w", err)
	}

	if parsed.Name != "" && parsed.Name != name {
		return "", fmt.Errorf("profile document names itself %q but is being saved as %q; the two must match because the listener takes a profile's name from its filename", parsed.Name, name)
	}

	if parsed.BindPort != 0 && (parsed.BindPort < 1 || parsed.BindPort > 65535) {
		return "", fmt.Errorf("bind_port must be in range [1, 65535], got %d", parsed.BindPort)
	}

	switch strings.ToLower(parsed.Scheme) {
	case "", "http", "https":
	default:
		return "", fmt.Errorf("scheme must be \"http\" or \"https\", got %q", parsed.Scheme)
	}
	if strings.ContainsAny(parsed.HostHeader, "\r\n") {
		return "", fmt.Errorf("host_header contains a line break")
	}
	if strings.ContainsAny(parsed.BeaconHost, "\r\n") {
		return "", fmt.Errorf("beacon_host contains a line break")
	}

	// Every operation the beacon routes to needs somewhere to go.
	for _, operation := range []string{"register", "task", "result", "ack"} {
		paths := parsed.URIs[operation]
		if len(paths) == 0 {
			return "", fmt.Errorf("uris.%s needs at least one path", operation)
		}
		for _, path := range paths {
			if !strings.HasPrefix(path, "/") {
				return "", fmt.Errorf("uris.%s path %q must start with \"/\"", operation, path)
			}
		}
	}

	if strings.EqualFold(parsed.Scheme, "https") {
		if parsed.TLS.CertFile == "" || parsed.TLS.KeyFile == "" {
			return "", fmt.Errorf("tls.cert_file and tls.key_file are required for an https listener")
		}
		if parsed.TLS.SPKISHA256 == "" {
			return "", fmt.Errorf("tls.spki_sha256 is required for an https listener; without a pin the beacon cannot verify it")
		}
	}

	for label, encoding := range map[string]string{
		"request_body.encoding":  parsed.RequestBody.Encoding,
		"response_body.encoding": parsed.ResponseBody.Encoding,
	} {
		if encoding != "" && !httpProfileEncodings[encoding] {
			return "", fmt.Errorf("%s must be one of raw, base64, base36, aes-gcm-base64, aes-gcm-base36; got %q", label, encoding)
		}
	}

	switch parsed.Auth.Mode {
	case "", "hmac-sha256", "shared-header", "none":
	default:
		return "", fmt.Errorf("auth.mode must be \"hmac-sha256\", \"shared-header\" or \"none\", got %q", parsed.Auth.Mode)
	}
	if parsed.Auth.Header != "" {
		if err := validateArchonHeaderName(parsed.Auth.Header); err != nil {
			return "", fmt.Errorf("auth.header %w", err)
		}
	}

	requestTemplates := map[string]bool{
		"host": true, "user_agent": true, "content_type": true, "content_length": true,
		"auth": true, "method": true, "path": true, "request_target": true, "operation": true,
	}
	responseTemplates := map[string]bool{
		"content_type": true, "content_length": true, "operation": true, "status": true,
	}
	if err := validateArchonHeaders("headers", parsed.Headers, map[string]bool{}); err != nil {
		return "", err
	}
	if err := validateArchonHeaders("request_headers", parsed.RequestHeaders, requestTemplates); err != nil {
		return "", err
	}
	if err := validateArchonHeaders("response_headers", parsed.ResponseHeaders, responseTemplates); err != nil {
		return "", err
	}
	if err := validateArchonAuthoritativeHeaders(parsed); err != nil {
		return "", err
	}
	for i, name := range parsed.OmitResponseHeaders {
		if err := validateArchonHeaderName(name); err != nil {
			return "", fmt.Errorf("omit_response_headers[%d] %w", i, err)
		}
	}

	// Re-serialise the typed view so the stored document always carries the name,
	// while the caller's other fields (headers, padding, status codes) pass through
	// untouched.
	var generic map[string]interface{}
	if err := json.Unmarshal([]byte(document), &generic); err != nil {
		return "", fmt.Errorf("profile document is not a JSON object: %w", err)
	}
	generic["name"] = name

	normalized, err := json.MarshalIndent(generic, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to serialise profile document: %w", err)
	}
	return string(normalized), nil
}

// transportUpdatePayload builds the task payload a beacon applies at runtime. It
// is exactly the document shape the beacon's ApplyUpdate expects, and reuses the
// stored listener list so a runtime change and a build cannot disagree.
func buildTransportUpdatePayload(mode string, listeners []HTTPListenerSpec, fallbackAfterFailures, retryBackoffSecs int) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(mode))
	switch normalized {
	case "dns", "http", "dual":
	default:
		return "", fmt.Errorf("mode must be \"dns\", \"http\" or \"dual\", got %q", mode)
	}

	if normalized != "dns" && len(listeners) == 0 {
		return "", fmt.Errorf("mode %q needs at least one listener", normalized)
	}

	payload, err := json.Marshal(map[string]interface{}{
		"mode":                    normalized,
		"listeners":               listeners,
		"fallback_after_failures": fallbackAfterFailures,
		"retry_backoff_secs":      retryBackoffSecs,
	})
	if err != nil {
		return "", fmt.Errorf("failed to serialise transport update: %w", err)
	}
	return string(payload), nil
}

// queueTransportUpdate creates an update_transport task for one beacon.
//
// This rides the same fire-and-forget channel as update_domains, which the client
// applies without sending a result: a reply would travel on whichever transport
// the update just replaced.
func (api *APIServer) queueTransportUpdate(beaconID, payload string) error {
	command := "update_transport:" + payload
	if _, err := api.db.CreateTask(beaconID, command, ""); err != nil {
		return fmt.Errorf("failed to queue transport update for beacon %s: %w", beaconID, err)
	}
	return nil
}

// httpProfileNameFromRequest reads the profile name from the path, falling back to
// a query parameter so the same handler serves both route shapes.
func httpProfileNameFromRequest(r *http.Request) string {
	if vars := mux.Vars(r); vars != nil {
		if name := vars["name"]; name != "" {
			return name
		}
	}
	return r.URL.Query().Get("name")
}

// =============================================================================
// API handlers
// =============================================================================

// handleListHTTPProfiles returns every stored profile.
func (api *APIServer) handleListHTTPProfiles(w http.ResponseWriter, r *http.Request) {
	records, err := api.db.ListHTTPProfiles()
	if err != nil {
		api.sendError(w, 500, "failed to list HTTP profiles")
		return
	}
	api.sendSuccess(w, "http profiles", map[string]interface{}{
		"profiles": records,
		"count":    len(records),
	})
}

// handleGetHTTPProfile returns one profile by name.
func (api *APIServer) handleGetHTTPProfile(w http.ResponseWriter, r *http.Request) {
	name := httpProfileNameFromRequest(r)
	if name == "" {
		api.sendError(w, 400, "name is required")
		return
	}

	record, err := api.db.GetHTTPProfile(name)
	if err != nil {
		api.sendError(w, 404, fmt.Sprintf("no HTTP profile named %q", name))
		return
	}

	api.sendSuccess(w, "http profile", map[string]interface{}{
		"name":       record.Name,
		"document":   record.Document,
		"updated_at": record.UpdatedAt,
	})
}

// handleSaveHTTPProfile creates or replaces a profile.
func (api *APIServer) handleSaveHTTPProfile(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name     string `json:"name"`
		Document string `json:"document"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.sendError(w, 400, "invalid request body")
		return
	}

	normalized, err := normalizeHTTPProfileDocument(req.Name, req.Document)
	if err != nil {
		// The message is the operator's only feedback on a bad document, so it is
		// passed through rather than flattened to "invalid profile".
		api.sendError(w, 400, err.Error())
		return
	}

	if err := api.db.SaveHTTPProfile(req.Name, normalized); err != nil {
		api.sendError(w, 500, "failed to save HTTP profile")
		return
	}

	operatorID := r.Header.Get("X-Operator-ID")
	api.db.LogAuditEvent(operatorID, "http_profile_save", "http_profile", req.Name,
		fmt.Sprintf("Saved HTTP listener profile %s", req.Name), r.RemoteAddr)

	api.sendSuccess(w, "http profile saved", map[string]interface{}{
		"name":     req.Name,
		"document": normalized,
	})
}

// handleDeleteHTTPProfile removes a profile.
func (api *APIServer) handleDeleteHTTPProfile(w http.ResponseWriter, r *http.Request) {
	name := httpProfileNameFromRequest(r)
	if name == "" {
		api.sendError(w, 400, "name is required")
		return
	}

	if err := api.db.DeleteHTTPProfile(name); err != nil {
		api.sendError(w, 500, "failed to delete HTTP profile")
		return
	}

	operatorID := r.Header.Get("X-Operator-ID")
	api.db.LogAuditEvent(operatorID, "http_profile_delete", "http_profile", name,
		fmt.Sprintf("Deleted HTTP listener profile %s", name), r.RemoteAddr)

	api.sendSuccess(w, "http profile deleted", map[string]interface{}{"name": name})
}

// handlePushTransportUpdate moves live beacons between transports.
//
// The payload is validated before anything is queued, so a bad mode cannot reach
// half the fleet and leave it there.
func (api *APIServer) handlePushTransportUpdate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BeaconID              string             `json:"beacon_id"`
		All                   bool               `json:"all"`
		Mode                  string             `json:"mode"`
		Listeners             []HTTPListenerSpec `json:"listeners"`
		FallbackAfterFailures int                `json:"fallback_after_failures"`
		RetryBackoffSecs      int                `json:"retry_backoff_secs"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.sendError(w, 400, "invalid request body")
		return
	}

	payload, err := buildTransportUpdatePayload(req.Mode, req.Listeners, req.FallbackAfterFailures, req.RetryBackoffSecs)
	if err != nil {
		api.sendError(w, 400, err.Error())
		return
	}

	// Resolve the targets before queueing anything.
	var targets []string
	if req.All {
		beacons, err := api.db.GetAllBeaconsPaginated(1000, 0)
		if err != nil {
			api.sendError(w, 500, "failed to list beacons")
			return
		}
		for _, beacon := range beacons {
			targets = append(targets, beacon.ID)
		}
	} else {
		if req.BeaconID == "" {
			api.sendError(w, 400, "beacon_id is required unless all is true")
			return
		}
		targets = append(targets, req.BeaconID)
	}

	if len(targets) == 0 {
		api.sendError(w, 400, "no beacons matched the request")
		return
	}

	queued := []string{}
	for _, beaconID := range targets {
		if err := api.queueTransportUpdate(beaconID, payload); err != nil {
			// One beacon failing must not stop the rest, but it is reported rather
			// than swallowed: a partial push is something the operator needs to know.
			log.Printf("[TRANSPORT] %v", err)
			continue
		}
		queued = append(queued, beaconID)
	}

	operatorID := r.Header.Get("X-Operator-ID")
	api.db.LogAuditEvent(operatorID, "transport_push", "beacon", strings.Join(queued, ","),
		fmt.Sprintf("Queued transport update (mode %s) for %d beacon(s)", req.Mode, len(queued)), r.RemoteAddr)

	api.sendSuccess(w, "transport update queued", map[string]interface{}{
		"mode":    req.Mode,
		"queued":  queued,
		"failed":  len(targets) - len(queued),
		"payload": payload,
	})
}
