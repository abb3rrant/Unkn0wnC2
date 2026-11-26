package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Capabilities understood by the token model. The MCP server is the primary
// consumer: a token minted for it can only reach routes its capability list
// covers, and an unmapped route requires "admin" rather than falling open.
var knownCapabilities = map[string]bool{
	"admin":             true,
	"beacons:read":      true,
	"tasks:read":        true,
	"tasks:write":       true,
	"results:read":      true,
	"builds:read":       true,
	"builds:write":      true,
	"listeners:read":    true,
	"listeners:write":   true,
	"operators:write":   true,
	"logs:read":         true,
	"exfil:read":        true,
	"engagements:write": true,
}

// requiredCapability maps a request to the capability it needs. Anything not
// listed requires "admin": a new route must opt in deliberately rather than
// being reachable by every token by default.
func requiredCapability(method, path string) string {
	p := strings.TrimPrefix(path, "/api")

	switch {
	case strings.HasPrefix(p, "/tokens"):
		return "admin"
	case strings.HasPrefix(p, "/operators"):
		return "operators:write"
	case strings.HasPrefix(p, "/engagements"):
		return "engagements:write"
	case strings.HasPrefix(p, "/builder"), strings.HasPrefix(p, "/builds"):
		if method == http.MethodGet {
			return "builds:read"
		}
		return "builds:write"
	case strings.HasPrefix(p, "/listeners"), strings.HasPrefix(p, "/http-profiles"),
		strings.HasPrefix(p, "/http/profiles"), strings.HasPrefix(p, "/profiles"):
		if method == http.MethodGet {
			return "listeners:read"
		}
		return "listeners:write"
	case strings.HasPrefix(p, "/logs"):
		return "logs:read"
	case strings.HasPrefix(p, "/exfil"):
		return "exfil:read"
	case strings.HasPrefix(p, "/tasks"):
		if method == http.MethodGet {
			if strings.HasSuffix(p, "/result") {
				return "results:read"
			}
			return "tasks:read"
		}
		return "tasks:write"
	case strings.HasPrefix(p, "/beacons"):
		if method == http.MethodGet {
			return "beacons:read"
		}
		// tasking a beacon is a write: /beacons/{id}/task
		if strings.HasSuffix(p, "/task") || strings.Contains(p, "/task") {
			return "tasks:write"
		}
		return "beacons:read"
	}
	return "admin"
}

// hasCapability reports whether the token's capability list satisfies need.
// "admin" is a superset; there are no wildcards, so a token cannot accidentally
// widen its own scope.
func hasCapability(caps []string, need string) bool {
	if need == "" {
		return true
	}
	for _, c := range caps {
		if c == "admin" || c == need {
			return true
		}
	}
	return false
}

// handleCreateAPIToken mints a scoped, non-interactive token for the MCP server.
// It is only reachable from an authenticated admin browser session: the route
// requires the "admin" capability, which only a cookie session (no caps) or an
// admin token holds.
func (api *APIServer) handleCreateAPIToken(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Operator-Role") != "admin" {
		api.sendError(w, http.StatusForbidden, "admin role required to mint tokens")
		return
	}

	var req struct {
		Name         string   `json:"name"`
		Caps         []string `json:"caps"`
		TTLHours     int      `json:"ttl_hours"`
		Egress       string   `json:"egress"`
		EngagementID string   `json:"engagement_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.sendError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.Caps) == 0 {
		api.sendError(w, http.StatusBadRequest, "caps is required: a token with no capabilities cannot do anything")
		return
	}
	for _, c := range req.Caps {
		if !knownCapabilities[c] {
			api.sendError(w, http.StatusBadRequest, fmt.Sprintf("unknown capability: %s", c))
			return
		}
	}

	// 24h is the ceiling, not the default: a shorter-lived token is the only
	// thing limiting damage if it leaks, since destructive calls have no
	// confirmation step.
	if req.TTLHours <= 0 {
		req.TTLHours = 24
	}
	if req.TTLHours > 24 {
		api.sendError(w, http.StatusBadRequest, "ttl_hours cannot exceed 24")
		return
	}

	// Default to the conservative egress: truncated results only. "full" must be
	// asked for explicitly and is intended for local model routes.
	if req.Egress == "" {
		req.Egress = "truncated"
	}
	if req.Egress != "truncated" && req.Egress != "full" && req.Egress != "local-only" {
		api.sendError(w, http.StatusBadRequest, "egress must be truncated, full, or local-only")
		return
	}

	operatorID := r.Header.Get("X-Operator-ID")
	username := r.Header.Get("X-Operator-Username")
	role := r.Header.Get("X-Operator-Role")

	expiresAt := time.Now().Add(time.Duration(req.TTLHours) * time.Hour)
	jti := generateID()

	claims := &Claims{
		OperatorID: operatorID,
		Username:   username,
		Role:       role,
		JTI:        jti,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   operatorID,
		},
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(api.jwtSecret)
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to sign token")
		return
	}

	if err := api.db.CreateAPISession(generateID(), operatorID, jti, sha256Hash(signed),
		req.Caps, req.Egress, req.EngagementID, expiresAt.Unix()); err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to persist token")
		return
	}

	_ = api.db.LogAuditEvent(operatorID, "token.create", "api_token", jti,
		fmt.Sprintf("name=%s caps=%v egress=%s engagement=%s", req.Name, req.Caps, req.Egress, req.EngagementID),
		r.RemoteAddr)

	api.sendJSON(w, map[string]interface{}{
		"token":         signed,
		"jti":           jti,
		"expires_at":    expiresAt.UTC(),
		"caps":          req.Caps,
		"egress":        req.Egress,
		"engagement_id": req.EngagementID,
		"note":          "store this now; it is not retrievable later",
	})
}

// handleRevokeAPIToken revokes a token immediately. The middleware re-resolves
// the session row on every request, so the next call fails without waiting for
// JWT expiry.
func (api *APIServer) handleRevokeAPIToken(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Operator-Role") != "admin" {
		api.sendError(w, http.StatusForbidden, "admin role required")
		return
	}
	jti := strings.TrimPrefix(r.URL.Path, "/api/tokens/")
	if jti == "" {
		api.sendError(w, http.StatusBadRequest, "jti is required")
		return
	}
	if err := api.db.RevokeSessionByJTI(jti); err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to revoke token")
		return
	}
	_ = api.db.LogAuditEvent(r.Header.Get("X-Operator-ID"), "token.revoke", "api_token", jti, "", r.RemoteAddr)
	api.sendJSON(w, map[string]interface{}{"success": true, "jti": jti, "revoked": true})
}
