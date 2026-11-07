// Package main hosts operator-supplied static sites on HTTP listener profiles.
//
// A profile describes the C2 wire shape; a cover site is what a casual visitor
// sees when they open the same host:port in a browser. The site belongs to the
// profile so every listener that serves that profile presents the same front,
// and it travels to the listener with the same sync that delivers the profile.
//
// The site is only ever served for requests that do NOT match a C2 URI. The
// listener checks the profile's operation table first, so a cover site can never
// shadow tasking, result or bootstrap traffic.
package main

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"strings"
	"time"
	"unicode"

	"github.com/gorilla/mux"
)

const (
	// A cover site may double as a payload host (a smuggled image carrying a
	// beacon can be tens of megabytes), so the limits are sized for a real
	// delivery chain rather than a brochure site. They are still bounded: the
	// listener keeps the site in memory and Archon decodes the upload before
	// storing it.
	//
	// Base64 inflates by 4/3; the body cap leaves room for JSON framing and the
	// per-file paths, so an over-limit upload is rejected by the per-file/total
	// checks rather than by a truncated decode.
	maxSiteUploadBody = 384 << 20
	maxSiteTotalBytes = 256 << 20
	maxSiteFiles      = 500
)

// siteUploadLimits bounds one cover-site upload. Variable so tests can exercise
// the boundaries without allocating tens of megabytes.
type siteUploadLimits struct {
	MaxFiles      int
	MaxFileBytes  int
	MaxTotalBytes int
}

// defaultSiteUploadLimits is deliberately generous for a payload image that
// carries a beacon: 128 MB per file, 256 MB per profile.
var defaultSiteUploadLimits = siteUploadLimits{
	MaxFiles:      500,
	MaxFileBytes:  128 << 20,
	MaxTotalBytes: 256 << 20,
}

// siteContentTypes is the allow-list. Static hosting never executes anything,
// but restricting extensions keeps an operator from turning the profile into a
// file drop and makes the served Content-Type unambiguous.
var siteContentTypes = map[string]string{
	".html":        "text/html; charset=utf-8",
	".htm":         "text/html; charset=utf-8",
	".css":         "text/css; charset=utf-8",
	".js":          "text/javascript; charset=utf-8",
	".mjs":         "text/javascript; charset=utf-8",
	".json":        "application/json",
	".map":         "application/json",
	".txt":         "text/plain; charset=utf-8",
	".xml":         "application/xml",
	".svg":         "image/svg+xml",
	".png":         "image/png",
	".jpg":         "image/jpeg",
	".jpeg":        "image/jpeg",
	".gif":         "image/gif",
	".webp":        "image/webp",
	".avif":        "image/avif",
	".ico":         "image/x-icon",
	".pdf":         "application/pdf",
	".woff":        "font/woff",
	".woff2":       "font/woff2",
	".ttf":         "font/ttf",
	".eot":         "application/vnd.ms-fontobject",
	".webmanifest": "application/manifest+json",
}

// HTTPSiteUploadFile is one file as the operator's browser sends it: the path
// relative to the picked folder, and the file's bytes base64-encoded.
type HTTPSiteUploadFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// HTTPSiteFileRecord is one stored file. Content is not serialized to the
// operator (the UI only needs the listing); the DNS-server fetch encodes it
// explicitly.
type HTTPSiteFileRecord struct {
	Path        string `json:"path"`
	Content     []byte `json:"-"`
	ContentType string `json:"content_type"`
	Size        int    `json:"size"`
	UpdatedAt   int64  `json:"updated_at"`
}

// HTTPSiteSummary is what the operator UI reads back.
type HTTPSiteSummary struct {
	Files      []HTTPSiteFileRecord `json:"files"`
	TotalBytes int                  `json:"total_bytes"`
	UpdatedAt  int64                `json:"updated_at"`
	LimitBytes int                  `json:"limit_bytes"`
	FileLimit  int                  `json:"file_limit"`
}

// migration26AddHTTPProfileSites stores the cover site attached to an HTTP
// profile. One row per file keeps a partial replacement impossible: the save is
// a transaction and always replaces the whole set.
func (d *MasterDatabase) migration26AddHTTPProfileSites() error {
	if _, err := d.db.Exec(`
		CREATE TABLE IF NOT EXISTS http_profile_site_files (
			profile_name TEXT NOT NULL,
			path TEXT NOT NULL,
			content BLOB NOT NULL,
			content_type TEXT NOT NULL,
			updated_at INTEGER NOT NULL,
			PRIMARY KEY (profile_name, path)
		)
	`); err != nil {
		return err
	}
	_, err := d.db.Exec(`CREATE INDEX IF NOT EXISTS idx_http_site_profile ON http_profile_site_files(profile_name)`)
	return err
}

// normalizeSitePath canonicalizes an uploaded path and rejects anything that
// could escape the site root or produce an ambiguous lookup key.
//
// The returned value always starts with "/" so the listener can look a request
// path up directly. Space is allowed because real folders contain it; control
// characters, quote/angle brackets, query and fragment markers, and percent are
// not, since those either break the URL mapping or invite HTML injection through
// the path echo.
func normalizeSitePath(raw string) (string, error) {
	candidate := strings.TrimSpace(strings.ReplaceAll(raw, "\\", "/"))
	for strings.HasPrefix(candidate, "./") {
		candidate = strings.TrimPrefix(candidate, "./")
	}
	candidate = strings.TrimPrefix(candidate, "/")
	if candidate == "" {
		return "", fmt.Errorf("empty file path")
	}
	if len(candidate) > 180 {
		return "", fmt.Errorf("path %q is longer than 180 characters", raw)
	}
	if strings.ContainsAny(candidate, "\x00\r\n\t?#%:") {
		return "", fmt.Errorf("path %q contains a disallowed character", raw)
	}

	segments := strings.Split(candidate, "/")
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." {
			return "", fmt.Errorf("path %q contains an empty or relative segment", raw)
		}
		if len(segment) > 100 {
			return "", fmt.Errorf("path segment %q is longer than 100 characters", segment)
		}
		for _, r := range segment {
			if r < 0x20 || r == 0x7f {
				return "", fmt.Errorf("path %q contains a control character", raw)
			}
			if unicode.IsLetter(r) || unicode.IsDigit(r) {
				continue
			}
			switch r {
			case ' ', '.', '_', '-', '+', '~', '@', '(', ')', ',', '&', '\'', '!', '$', '=', ';':
				continue
			}
			return "", fmt.Errorf("path %q contains an unsupported character %q", raw, r)
		}
	}

	if path.Clean(candidate) != candidate {
		return "", fmt.Errorf("path %q is not clean (double slash or trailing slash)", raw)
	}
	return "/" + candidate, nil
}

// siteContentTypeFor maps a stored path to its Content-Type, rejecting
// extensions outside the allow-list.
func siteContentTypeFor(sitePath string) (string, bool) {
	contentType, ok := siteContentTypes[strings.ToLower(path.Ext(sitePath))]
	return contentType, ok
}

// decodeSiteContent accepts standard or unpadded base64.
func decodeSiteContent(encoded string) ([]byte, error) {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		// An empty file is legitimate in a static site (a placeholder, a marker).
		return []byte{}, nil
	}
	if decoded, err := base64.StdEncoding.DecodeString(encoded); err == nil {
		return decoded, nil
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(encoded); err == nil {
		return decoded, nil
	}
	return nil, fmt.Errorf("content is not valid base64")
}

// validateSiteFiles normalizes, decodes and bounds one upload, returning the
// records to store. index.html is required because the listener maps "/" to it;
// a site without one would present a 404 at the front door.
func validateSiteFiles(files []HTTPSiteUploadFile) ([]HTTPSiteFileRecord, error) {
	return validateSiteFilesWithLimits(files, defaultSiteUploadLimits)
}

func validateSiteFilesWithLimits(files []HTTPSiteUploadFile, limits siteUploadLimits) ([]HTTPSiteFileRecord, error) {
	if len(files) == 0 {
		return nil, fmt.Errorf("no files were uploaded")
	}
	if len(files) > limits.MaxFiles {
		return nil, fmt.Errorf("too many files (%d); the limit is %d", len(files), limits.MaxFiles)
	}

	seen := make(map[string]bool, len(files))
	records := make([]HTTPSiteFileRecord, 0, len(files))
	total := 0
	hasIndex := false
	now := time.Now().UnixNano()

	for _, file := range files {
		sitePath, err := normalizeSitePath(file.Path)
		if err != nil {
			return nil, err
		}
		if seen[sitePath] {
			return nil, fmt.Errorf("duplicate file path %q", sitePath)
		}
		seen[sitePath] = true

		content, err := decodeSiteContent(file.Content)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", sitePath, err)
		}
		if len(content) > limits.MaxFileBytes {
			return nil, fmt.Errorf("%s is %d bytes; the per-file limit is %d", sitePath, len(content), limits.MaxFileBytes)
		}
		total += len(content)
		if total > limits.MaxTotalBytes {
			return nil, fmt.Errorf("site exceeds the %d-byte total limit", limits.MaxTotalBytes)
		}

		contentType, ok := siteContentTypeFor(sitePath)
		if !ok {
			return nil, fmt.Errorf("%s: unsupported file type (allowed: html, css, js, json, images, fonts, pdf, txt, xml)", sitePath)
		}
		if sitePath == "/index.html" {
			hasIndex = true
		}
		records = append(records, HTTPSiteFileRecord{
			Path:        sitePath,
			Content:     content,
			ContentType: contentType,
			Size:        len(content),
			UpdatedAt:   now,
		})
	}

	if !hasIndex {
		return nil, fmt.Errorf("the folder must contain index.html at its root")
	}
	return records, nil
}

// SaveHTTPProfileSite replaces a profile's site in one transaction.
func (d *MasterDatabase) SaveHTTPProfileSite(profileName string, files []HTTPSiteFileRecord) error {
	tx, err := d.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin site save: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(`DELETE FROM http_profile_site_files WHERE profile_name = ?`, profileName); err != nil {
		return fmt.Errorf("failed to clear previous site: %w", err)
	}
	stmt, err := tx.Prepare(`
		INSERT INTO http_profile_site_files (profile_name, path, content, content_type, updated_at)
		VALUES (?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare site insert: %w", err)
	}
	defer stmt.Close()

	for _, file := range files {
		if _, err := stmt.Exec(profileName, file.Path, file.Content, file.ContentType, file.UpdatedAt); err != nil {
			return fmt.Errorf("failed to store %s: %w", file.Path, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit site: %w", err)
	}
	return nil
}

// HTTPProfileSiteFiles returns the stored files ordered by path.
func (d *MasterDatabase) HTTPProfileSiteFiles(profileName string) ([]HTTPSiteFileRecord, error) {
	rows, err := d.db.Query(`
		SELECT path, content, content_type, updated_at
		FROM http_profile_site_files
		WHERE profile_name = ?
		ORDER BY path
	`, profileName)
	if err != nil {
		return nil, fmt.Errorf("failed to load site for %q: %w", profileName, err)
	}
	defer rows.Close()

	files := []HTTPSiteFileRecord{}
	for rows.Next() {
		var record HTTPSiteFileRecord
		if err := rows.Scan(&record.Path, &record.Content, &record.ContentType, &record.UpdatedAt); err != nil {
			return nil, err
		}
		record.Size = len(record.Content)
		files = append(files, record)
	}
	return files, rows.Err()
}

// HTTPProfileSiteRevision is the newest file timestamp, or 0 when there is no
// site. Assignments carry it so a listener can fetch a changed site on sync.
func (d *MasterDatabase) HTTPProfileSiteRevision(profileName string) int64 {
	var revision sql.NullInt64
	if err := d.db.QueryRow(
		`SELECT MAX(updated_at) FROM http_profile_site_files WHERE profile_name = ?`,
		profileName,
	).Scan(&revision); err != nil || !revision.Valid {
		return 0
	}
	return revision.Int64
}

// DeleteHTTPProfileSite removes a profile's site.
func (d *MasterDatabase) DeleteHTTPProfileSite(profileName string) error {
	if _, err := d.db.Exec(`DELETE FROM http_profile_site_files WHERE profile_name = ?`, profileName); err != nil {
		return fmt.Errorf("failed to delete site for %q: %w", profileName, err)
	}
	return nil
}

// =============================================================================
// Handlers
// =============================================================================

func (api *APIServer) handleGetHTTPProfileSite(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	if _, err := api.db.GetHTTPProfile(name); err != nil {
		api.sendError(w, http.StatusNotFound, fmt.Sprintf("no HTTP profile named %q", name))
		return
	}

	files, err := api.db.HTTPProfileSiteFiles(name)
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to load site")
		return
	}
	total := 0
	for i := range files {
		files[i].Content = nil
		total += files[i].Size
	}
	api.sendSuccess(w, "site", HTTPSiteSummary{
		Files:      files,
		TotalBytes: total,
		UpdatedAt:  api.db.HTTPProfileSiteRevision(name),
		LimitBytes: maxSiteTotalBytes,
		FileLimit:  maxSiteFiles,
	})
}

func (api *APIServer) handleSaveHTTPProfileSite(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	if _, err := api.db.GetHTTPProfile(name); err != nil {
		api.sendError(w, http.StatusNotFound, fmt.Sprintf("no HTTP profile named %q", name))
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxSiteUploadBody)
	var req struct {
		Files []HTTPSiteUploadFile `json:"files"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.sendError(w, http.StatusBadRequest, "invalid site upload: "+err.Error())
		return
	}

	records, err := validateSiteFiles(req.Files)
	if err != nil {
		api.sendError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := api.db.SaveHTTPProfileSite(name, records); err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to store site")
		return
	}

	operatorID := r.Header.Get("X-Operator-ID")
	api.db.LogAuditEvent(operatorID, "http_profile_site_save", "http_profile", name,
		fmt.Sprintf("Uploaded cover site to HTTP profile %s (%d files)", name, len(records)), r.RemoteAddr)

	api.sendSuccess(w, "site saved", map[string]interface{}{
		"name":        name,
		"files":       len(records),
		"total_bytes": totalSiteBytes(records),
		"revision":    api.db.HTTPProfileSiteRevision(name),
	})
}

func (api *APIServer) handleDeleteHTTPProfileSite(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	if _, err := api.db.GetHTTPProfile(name); err != nil {
		api.sendError(w, http.StatusNotFound, fmt.Sprintf("no HTTP profile named %q", name))
		return
	}
	if err := api.db.DeleteHTTPProfileSite(name); err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to delete site")
		return
	}

	operatorID := r.Header.Get("X-Operator-ID")
	api.db.LogAuditEvent(operatorID, "http_profile_site_delete", "http_profile", name,
		fmt.Sprintf("Deleted cover site from HTTP profile %s", name), r.RemoteAddr)

	api.sendSuccess(w, "site deleted", map[string]interface{}{"name": name})
}

// handleFetchHTTPProfileSite hands a listener the site for a profile it actually
// serves. It sits behind the DNS-server API key middleware; the server ID comes
// from the authenticated header, and the assignment is re-checked so one
// listener cannot pull another's site by name.
func (api *APIServer) handleFetchHTTPProfileSite(w http.ResponseWriter, r *http.Request) {
	dnsServerID := r.Header.Get("X-DNS-Server-ID")
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if dnsServerID == "" || name == "" {
		api.sendError(w, http.StatusBadRequest, "dns_server_id and name are required")
		return
	}

	assigned, err := api.db.GetAssignedHTTPProfileNames(dnsServerID)
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to read assignments")
		return
	}
	allowed := false
	for _, assignedName := range assigned {
		if assignedName == name {
			allowed = true
			break
		}
	}
	if !allowed {
		api.sendError(w, http.StatusForbidden, fmt.Sprintf("profile %q is not assigned to this listener", name))
		return
	}

	files, err := api.db.HTTPProfileSiteFiles(name)
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to load site")
		return
	}

	type wireFile struct {
		Path        string `json:"path"`
		ContentType string `json:"content_type"`
		Content     string `json:"content"`
	}
	wireFiles := make([]wireFile, 0, len(files))
	for _, file := range files {
		wireFiles = append(wireFiles, wireFile{
			Path:        file.Path,
			ContentType: file.ContentType,
			Content:     base64.StdEncoding.EncodeToString(file.Content),
		})
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"name":     name,
		"revision": api.db.HTTPProfileSiteRevision(name),
		"files":    wireFiles,
	})
}

func totalSiteBytes(files []HTTPSiteFileRecord) int {
	total := 0
	for _, file := range files {
		total += file.Size
	}
	return total
}
