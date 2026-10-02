// Package main assigns HTTP listener profiles to DNS servers and delivers them.
//
// A DNS server is a listener: it answers DNS always, and additionally serves the
// HTTP/HTTPS profiles assigned to it. Archon is where those assignments live, so an
// operator attaches a profile to a listener once and the listener applies it — no
// copying files to a host, no restart.
//
// The server's own report of what is actually running comes back on the check-in, so
// the listener page can show reality rather than intent.
package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// HTTPProfileAssignment is one profile delivered to a DNS server. Revision is the
// profile's stored updated_at, which lets a server (and an operator reading a log)
// tell which version of a document it received.
type HTTPProfileAssignment struct {
	Name     string          `json:"name"`
	Revision int64           `json:"revision"`
	Document json.RawMessage `json:"document"`
}

// HTTPListenerStatus is the reported state of one listener on a DNS server.
//
// This is the wire shape Server/http_registry.go sends in its check-in stats, kept as
// the counterpart type rather than shared code (the two are separate Go modules). The
// field names are pinned by tests on both sides, so a rename cannot silently make the
// listener page show nothing.
type HTTPListenerStatus struct {
	Name    string `json:"name"`
	Addr    string `json:"addr"`
	Scheme  string `json:"scheme"`
	Source  string `json:"source"`
	Running bool   `json:"running"`
	Enabled bool   `json:"enabled"`
	Error   string `json:"error,omitempty"`
}

// migration20AddHTTPProfileAssignments records which profiles each DNS server serves,
// and stores the listener state that server reports.
func (d *MasterDatabase) migration20AddHTTPProfileAssignments() error {
	if _, err := d.db.Exec(`
		CREATE TABLE IF NOT EXISTS http_profile_assignments (
			dns_server_id TEXT NOT NULL,
			profile_name TEXT NOT NULL,
			assigned_at INTEGER NOT NULL,
			PRIMARY KEY (dns_server_id, profile_name)
		)
	`); err != nil {
		return err
	}

	if _, err := d.db.Exec(`CREATE INDEX IF NOT EXISTS idx_http_assignments_server ON http_profile_assignments(dns_server_id)`); err != nil {
		return err
	}

	// The column is added idempotently: a database created before this migration has
	// no http_listeners column, and one created after will.
	return d.addColumnIfMissing("dns_servers", "http_listeners", "TEXT")
}

// addColumnIfMissing adds a column when the table does not already have it.
func (d *MasterDatabase) addColumnIfMissing(table, column, definition string) error {
	rows, err := d.db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return fmt.Errorf("failed to inspect %s: %w", table, err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			cid        int
			name       string
			ctype      string
			notNull    int
			defaultVal sql.NullString
			primaryKey int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &defaultVal, &primaryKey); err != nil {
			return fmt.Errorf("failed to read %s columns: %w", table, err)
		}
		if name == column {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	if _, err := d.db.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, definition)); err != nil {
		return fmt.Errorf("failed to add %s.%s: %w", table, column, err)
	}
	return nil
}

// AssignHTTPProfile attaches a profile to a DNS server. Re-assigning is idempotent, so
// a UI double-click does not produce an error the operator has to interpret.
func (d *MasterDatabase) AssignHTTPProfile(dnsServerID, profileName string) error {
	if _, err := d.db.Exec(`
		INSERT INTO http_profile_assignments (dns_server_id, profile_name, assigned_at)
		VALUES (?, ?, ?)
		ON CONFLICT(dns_server_id, profile_name) DO NOTHING
	`, dnsServerID, profileName, time.Now().Unix()); err != nil {
		return fmt.Errorf("failed to assign profile %q to %s: %w", profileName, dnsServerID, err)
	}
	return nil
}

// UnassignHTTPProfile detaches a profile from a DNS server.
func (d *MasterDatabase) UnassignHTTPProfile(dnsServerID, profileName string) error {
	if _, err := d.db.Exec(`
		DELETE FROM http_profile_assignments WHERE dns_server_id = ? AND profile_name = ?
	`, dnsServerID, profileName); err != nil {
		return fmt.Errorf("failed to unassign profile %q from %s: %w", profileName, dnsServerID, err)
	}
	return nil
}

// GetAssignedHTTPProfileNames lists the profiles assigned to a DNS server.
func (d *MasterDatabase) GetAssignedHTTPProfileNames(dnsServerID string) ([]string, error) {
	rows, err := d.db.Query(`
		SELECT profile_name FROM http_profile_assignments WHERE dns_server_id = ? ORDER BY profile_name
	`, dnsServerID)
	if err != nil {
		return nil, fmt.Errorf("failed to list assignments for %s: %w", dnsServerID, err)
	}
	defer rows.Close()

	names := []string{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, rows.Err()
}

// GetAssignedHTTPProfiles returns the assigned profiles with their documents, which is
// what a DNS server fetches.
//
// An assignment whose profile has been deleted is skipped rather than reported as an
// error: deleting a profile while it is assigned is a normal thing for an operator to
// do, and the server will simply stop serving it.
func (d *MasterDatabase) GetAssignedHTTPProfiles(dnsServerID string) ([]HTTPProfileAssignment, error) {
	rows, err := d.db.Query(`
		SELECT a.profile_name, p.document, p.updated_at
		FROM http_profile_assignments a
		JOIN http_profiles p ON p.name = a.profile_name
		WHERE a.dns_server_id = ?
		ORDER BY a.profile_name
	`, dnsServerID)
	if err != nil {
		return nil, fmt.Errorf("failed to load assigned profiles for %s: %w", dnsServerID, err)
	}
	defer rows.Close()

	assignments := []HTTPProfileAssignment{}
	for rows.Next() {
		var (
			name     string
			document string
			revision int64
		)
		if err := rows.Scan(&name, &document, &revision); err != nil {
			return nil, err
		}
		assignments = append(assignments, HTTPProfileAssignment{
			Name:     name,
			Revision: revision,
			Document: json.RawMessage(document),
		})
	}
	return assignments, rows.Err()
}

// SetDNSServerHTTPListeners stores the listener state a DNS server reported.
func (d *MasterDatabase) SetDNSServerHTTPListeners(dnsServerID, document string) error {
	if _, err := d.db.Exec(`
		UPDATE dns_servers SET http_listeners = ?, updated_at = ? WHERE id = ?
	`, document, time.Now().Unix(), dnsServerID); err != nil {
		return fmt.Errorf("failed to record listener state for %s: %w", dnsServerID, err)
	}
	return nil
}

// GetDNSServerHTTPListeners returns the last reported listener state, decoded.
func (d *MasterDatabase) GetDNSServerHTTPListeners(dnsServerID string) []HTTPListenerStatus {
	var document sql.NullString
	if err := d.db.QueryRow(`SELECT http_listeners FROM dns_servers WHERE id = ?`, dnsServerID).Scan(&document); err != nil {
		return []HTTPListenerStatus{}
	}
	if !document.Valid || strings.TrimSpace(document.String) == "" {
		return []HTTPListenerStatus{}
	}

	var statuses []HTTPListenerStatus
	if err := json.Unmarshal([]byte(document.String), &statuses); err != nil {
		// A malformed report is not worth surfacing as an error to the UI; an empty
		// list is the honest answer for "nothing usable was reported".
		return []HTTPListenerStatus{}
	}
	return statuses
}

// =============================================================================
// Handlers
// =============================================================================

// handleFetchAssignedHTTPProfiles serves a DNS server the profiles assigned to it.
// It sits behind the DNS-server API key middleware, so the server ID is trusted.
func (api *APIServer) handleFetchAssignedHTTPProfiles(w http.ResponseWriter, r *http.Request) {
	dnsServerID := r.Header.Get("X-DNS-Server-ID")
	if dnsServerID == "" {
		api.sendError(w, http.StatusBadRequest, "missing dns_server_id")
		return
	}

	assignments, err := api.db.GetAssignedHTTPProfiles(dnsServerID)
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to load assigned profiles")
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"message":  "assigned profiles",
		"profiles": assignments,
	})
}

// handleAssignHTTPProfile attaches a stored profile to a DNS server.
func (api *APIServer) handleAssignHTTPProfile(w http.ResponseWriter, r *http.Request) {
	dnsServerID := mux.Vars(r)["id"]
	if dnsServerID == "" {
		api.sendError(w, http.StatusBadRequest, "listener id is required")
		return
	}

	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.sendError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		api.sendError(w, http.StatusBadRequest, "name is required")
		return
	}

	// The profile must exist, or the assignment would deliver nothing and the
	// operator would have to guess why.
	if _, err := api.db.GetHTTPProfile(req.Name); err != nil {
		api.sendError(w, http.StatusNotFound, fmt.Sprintf("no HTTP profile named %q", req.Name))
		return
	}

	if err := api.db.AssignHTTPProfile(dnsServerID, req.Name); err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to assign profile")
		return
	}

	operatorID := r.Header.Get("X-Operator-ID")
	api.db.LogAuditEvent(operatorID, "http_profile_assign", "dns_server", dnsServerID,
		fmt.Sprintf("Assigned HTTP profile %s to listener %s", req.Name, dnsServerID), r.RemoteAddr)

	api.sendSuccess(w, "profile assigned", map[string]interface{}{
		"dns_server_id": dnsServerID,
		"name":          req.Name,
	})
}

// handleUnassignHTTPProfile detaches a profile from a DNS server.
func (api *APIServer) handleUnassignHTTPProfile(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	dnsServerID := vars["id"]
	profileName := vars["name"]

	if dnsServerID == "" || profileName == "" {
		api.sendError(w, http.StatusBadRequest, "listener id and profile name are required")
		return
	}

	if err := api.db.UnassignHTTPProfile(dnsServerID, profileName); err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to unassign profile")
		return
	}

	operatorID := r.Header.Get("X-Operator-ID")
	api.db.LogAuditEvent(operatorID, "http_profile_unassign", "dns_server", dnsServerID,
		fmt.Sprintf("Unassigned HTTP profile %s from listener %s", profileName, dnsServerID), r.RemoteAddr)

	api.sendSuccess(w, "profile unassigned", map[string]interface{}{
		"dns_server_id": dnsServerID,
		"name":          profileName,
	})
}

// handleGetListener returns one listener with its assigned profiles and the state it
// last reported, which is what the listener page renders.
func (api *APIServer) handleGetListener(w http.ResponseWriter, r *http.Request) {
	dnsServerID := mux.Vars(r)["id"]
	if dnsServerID == "" {
		api.sendError(w, http.StatusBadRequest, "listener id is required")
		return
	}

	servers, err := api.db.GetDNSServers()
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to load listeners")
		return
	}

	var found *DNSServer
	for i := range servers {
		if servers[i].ID == dnsServerID {
			found = &servers[i]
			break
		}
	}
	if found == nil {
		api.sendError(w, http.StatusNotFound, fmt.Sprintf("no listener with id %q", dnsServerID))
		return
	}

	assigned, err := api.db.GetAssignedHTTPProfileNames(dnsServerID)
	if err != nil {
		assigned = []string{}
	}

	api.sendSuccess(w, "listener", map[string]interface{}{
		"listener":           found,
		"assigned_profiles":  assigned,
		"reported_listeners": api.db.GetDNSServerHTTPListeners(dnsServerID),
		"available_profiles": api.listHTTPProfileNames(),
	})
}

// listHTTPProfileNames returns the stored profile names, for the assignment picker.
func (api *APIServer) listHTTPProfileNames() []string {
	records, err := api.db.ListHTTPProfiles()
	if err != nil {
		return []string{}
	}
	names := make([]string, 0, len(records))
	for _, record := range records {
		names = append(names, record.Name)
	}
	sort.Strings(names)
	return names
}
