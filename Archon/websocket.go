// Package main implements WebSocket functionality for real-time updates
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
)

// WebSocketHub manages WebSocket connections and broadcasting
type WebSocketHub struct {
	clients    map[*WebSocketClient]bool
	broadcast  chan WSMessage
	register   chan *WebSocketClient
	unregister chan *WebSocketClient
	mutex      sync.RWMutex
}

// WebSocketClient represents a connected WebSocket client
type WebSocketClient struct {
	hub      *WebSocketHub
	conn     *websocket.Conn
	send     chan []byte
	userID   string
	username string
}

// WSMessage represents a WebSocket message
type WSMessage struct {
	Type    string      `json:"type"`
	Payload interface{} `json:"payload"`
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins for now; tighten in production
	},
}

// Global WebSocket hub
var wsHub *WebSocketHub

// NewWebSocketHub creates a new WebSocket hub
func NewWebSocketHub() *WebSocketHub {
	return &WebSocketHub{
		clients:    make(map[*WebSocketClient]bool),
		broadcast:  make(chan WSMessage, 256),
		register:   make(chan *WebSocketClient),
		unregister: make(chan *WebSocketClient),
	}
}

// Run starts the WebSocket hub
func (h *WebSocketHub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mutex.Lock()
			h.clients[client] = true
			h.mutex.Unlock()
			LogDebug("WebSocket client connected: %s", client.username)

		case client := <-h.unregister:
			h.mutex.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
			h.mutex.Unlock()
			LogDebug("WebSocket client disconnected: %s", client.username)

		case message := <-h.broadcast:
			data, err := json.Marshal(message)
			if err != nil {
				LogError("Failed to marshal WebSocket message: %v", err)
				continue
			}

			h.mutex.RLock()
			for client := range h.clients {
				select {
				case client.send <- data:
				default:
					close(client.send)
					delete(h.clients, client)
				}
			}
			h.mutex.RUnlock()
		}
	}
}

// Broadcast sends a message to all connected clients
func (h *WebSocketHub) Broadcast(msgType string, payload interface{}) {
	h.broadcast <- WSMessage{Type: msgType, Payload: payload}
}

// ClientCount returns the number of connected clients
func (h *WebSocketHub) ClientCount() int {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	return len(h.clients)
}

// readPump reads messages from the WebSocket connection
func (c *WebSocketClient) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()

	c.conn.SetReadLimit(4096)
	c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				LogDebug("WebSocket error: %v", err)
			}
			break
		}

		// Handle incoming messages from client
		var msg WSMessage
		if err := json.Unmarshal(message, &msg); err != nil {
			continue
		}

		// Process client messages if needed (e.g., subscribe to specific events)
		LogDebug("WebSocket message from %s: %s", c.username, msg.Type)
	}
}

// writePump sends messages to the WebSocket connection
func (c *WebSocketClient) writePump() {
	ticker := time.NewTicker(30 * time.Second)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			// Batch pending messages
			n := len(c.send)
			for i := 0; i < n; i++ {
				w.Write([]byte{'\n'})
				w.Write(<-c.send)
			}

			if err := w.Close(); err != nil {
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// handleWebSocket handles WebSocket upgrade requests
func (api *APIServer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Verify authentication from cookie
	cookie, err := r.Cookie("session_token")
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Parse and validate token
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(cookie.Value, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return api.jwtSecret, nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		LogError("WebSocket upgrade failed: %v", err)
		return
	}

	client := &WebSocketClient{
		hub:      wsHub,
		conn:     conn,
		send:     make(chan []byte, 256),
		userID:   claims.OperatorID,
		username: claims.Username,
	}

	wsHub.register <- client

	go client.writePump()
	go client.readPump()
}

// BroadcastBeaconUpdate broadcasts a beacon update to all clients
func BroadcastBeaconUpdate(beacon interface{}) {
	if wsHub != nil {
		wsHub.Broadcast("beacon_update", beacon)
	}
}

// BroadcastTaskUpdate broadcasts a task update to all clients
func BroadcastTaskUpdate(task interface{}) {
	if wsHub != nil {
		wsHub.Broadcast("task_update", task)
	}
}

// BroadcastExfilUpdate broadcasts an exfil update to all clients
func BroadcastExfilUpdate(exfil interface{}) {
	if wsHub != nil {
		wsHub.Broadcast("exfil_update", exfil)
	}
}

// BroadcastStagerUpdate broadcasts a stager session update to all clients
func BroadcastStagerUpdate(stager interface{}) {
	if wsHub != nil {
		wsHub.Broadcast("stager_update", stager)
	}
}

// BroadcastDNSServerUpdate broadcasts a DNS server update to all clients
func BroadcastDNSServerUpdate(server interface{}) {
	if wsHub != nil {
		wsHub.Broadcast("dns_server_update", server)
	}
}

// BroadcastNotification broadcasts a general notification to all clients
func BroadcastNotification(message string, notifType string) {
	if wsHub != nil {
		wsHub.Broadcast("notification", map[string]string{
			"message": message,
			"type":    notifType,
		})
	}
}

// InitWebSocketHub initializes the global WebSocket hub
func InitWebSocketHub() {
	wsHub = NewWebSocketHub()
	go wsHub.Run()
	LogInfo("WebSocket hub initialized")
}

// ==========================================
// Log Viewing API
// ==========================================

// LogEntry represents a parsed log line
type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Message   string `json:"message"`
	Raw       string `json:"raw"`
}

// handleGetLogs returns log file contents
func (api *APIServer) handleGetLogs(w http.ResponseWriter, r *http.Request) {
	logType := r.URL.Query().Get("type") // "archon" or "dns-server"
	lines := r.URL.Query().Get("lines")
	if lines == "" {
		lines = "100"
	}

	numLines := 100
	fmt.Sscanf(lines, "%d", &numLines)
	if numLines > 1000 {
		numLines = 1000
	}
	if numLines < 10 {
		numLines = 10
	}

	logDir := "/opt/unkn0wnc2/logs"
	var logFile string
	today := time.Now().Format("2006-01-02")

	switch logType {
	case "archon":
		// Try today's dated log file first, then fallback to archon.log
		logFile = filepath.Join(logDir, fmt.Sprintf("archon-%s.log", today))
	case "dns-server":
		// Could be multiple DNS servers - get the latest or specified
		serverID := r.URL.Query().Get("server_id")
		if serverID != "" {
			logFile = filepath.Join(logDir, fmt.Sprintf("dns-server-%s.log", serverID))
		} else {
			logFile = filepath.Join(logDir, "dns-server.log")
		}
	default:
		logFile = filepath.Join(logDir, fmt.Sprintf("archon-%s.log", today))
	}

	entries, err := readLogFile(logFile, numLines)
	if err != nil {
		// Try alternative paths - undated version
		altLogFile := filepath.Join(logDir, "archon.log")
		entries, err = readLogFile(altLogFile, numLines)
		if err != nil {
			// Try ./logs directory
			altLogDir := "./logs"
			altLogFile = filepath.Join(altLogDir, fmt.Sprintf("archon-%s.log", today))
			entries, err = readLogFile(altLogFile, numLines)
			if err != nil {
				api.sendJSON(w, map[string]interface{}{
					"success": true,
					"entries": []LogEntry{},
					"message": fmt.Sprintf("Log file not found or empty: %s", filepath.Base(logFile)),
				})
				return
			}
		}
	}

	api.sendJSON(w, map[string]interface{}{
		"success": true,
		"entries": entries,
		"file":    filepath.Base(logFile),
		"count":   len(entries),
	})
}

// readLogFile reads the last N lines from a log file
func readLogFile(filename string, numLines int) ([]LogEntry, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Get file size
	stat, err := file.Stat()
	if err != nil {
		return nil, err
	}

	// For small files, read everything
	if stat.Size() < 1024*1024 { // Less than 1MB
		return readAllLines(file, numLines)
	}

	// For large files, seek to approximate position
	return readTailLines(file, stat.Size(), numLines)
}

// readAllLines reads all lines from a file and returns the last N
func readAllLines(file *os.File, numLines int) ([]LogEntry, error) {
	var lines []string
	scanner := bufio.NewScanner(file)
	
	// Use larger buffer for long lines
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Get last N lines
	start := len(lines) - numLines
	if start < 0 {
		start = 0
	}

	entries := make([]LogEntry, 0, numLines)
	for _, line := range lines[start:] {
		entries = append(entries, parseLogLine(line))
	}

	return entries, nil
}

// readTailLines reads approximately the last N lines from a large file
func readTailLines(file *os.File, fileSize int64, numLines int) ([]LogEntry, error) {
	// Estimate bytes per line (assume ~200 bytes average)
	estimatedBytes := int64(numLines * 250)
	if estimatedBytes > fileSize {
		estimatedBytes = fileSize
	}

	// Seek to estimated position
	startPos := fileSize - estimatedBytes
	if startPos < 0 {
		startPos = 0
	}

	_, err := file.Seek(startPos, io.SeekStart)
	if err != nil {
		return nil, err
	}

	// Skip partial first line if we didn't start at beginning
	if startPos > 0 {
		reader := bufio.NewReader(file)
		reader.ReadLine() // Discard partial line
	}

	return readAllLines(file, numLines)
}

// parseLogLine parses a log line into structured format
func parseLogLine(line string) LogEntry {
	entry := LogEntry{Raw: line}

	// Try to parse common log format: [2024-01-15 10:30:45] [INFO] message
	if len(line) > 25 && line[0] == '[' {
		// Extract timestamp
		if idx := strings.Index(line[1:], "]"); idx > 0 {
			entry.Timestamp = line[1 : idx+1]
			line = strings.TrimSpace(line[idx+2:])
		}

		// Extract level
		if len(line) > 2 && line[0] == '[' {
			if idx := strings.Index(line[1:], "]"); idx > 0 {
				entry.Level = strings.ToLower(line[1 : idx+1])
				entry.Message = strings.TrimSpace(line[idx+2:])
				return entry
			}
		}
	}

	// Fallback: just use the raw line as message
	entry.Message = line
	return entry
}

// handleListLogFiles returns available log files
func (api *APIServer) handleListLogFiles(w http.ResponseWriter, r *http.Request) {
	logDirs := []string{"/opt/unkn0wnc2/logs", "./logs"}

	var files []map[string]interface{}
	seen := make(map[string]bool)

	for _, logDir := range logDirs {
		entries, err := os.ReadDir(logDir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() || seen[entry.Name()] {
				continue
			}
			if !strings.HasSuffix(entry.Name(), ".log") {
				continue
			}

			info, err := entry.Info()
			if err != nil {
				continue
			}

			seen[entry.Name()] = true
			files = append(files, map[string]interface{}{
				"name":     entry.Name(),
				"size":     info.Size(),
				"modified": info.ModTime(),
				"path":     filepath.Join(logDir, entry.Name()),
			})
		}
	}

	api.sendJSON(w, map[string]interface{}{
		"success": true,
		"files":   files,
	})
}

// handleGetInfrastructure returns infrastructure map data
func (api *APIServer) handleGetInfrastructure(w http.ResponseWriter, r *http.Request) {
	// Get Archon info
	archon := map[string]interface{}{
		"id":      "archon",
		"type":    "archon",
		"name":    "Archon Master",
		"address": fmt.Sprintf("%s:%d", api.config.BindAddr, api.config.BindPort),
		"status":  "online",
	}

	// Get DNS servers
	dnsServers, err := api.db.GetAllDNSServers()
	if err != nil {
		dnsServers = []map[string]interface{}{}
	}

	// Transform DNS servers for map
	var dnsNodes []map[string]interface{}
	for _, server := range dnsServers {
		node := map[string]interface{}{
			"id":           server["id"],
			"type":         "dns-server",
			"name":         server["domain"],
			"address":      server["address"],
			"status":       server["status"],
			"last_checkin": server["last_checkin"],
		}
		dnsNodes = append(dnsNodes, node)
	}

	// Get beacons (use 30 minute threshold to get recently active ones)
	beacons, err := api.db.GetActiveBeaconsPaginated(30, 100, 0)
	if err != nil {
		beacons = []map[string]interface{}{}
	}

	// Transform beacons for map
	var beaconNodes []map[string]interface{}
	for _, beacon := range beacons {
		// Handle last_seen which could be int64, float64, or other types from SQLite
		var lastSeen int64
		switch v := beacon["last_seen"].(type) {
		case int64:
			lastSeen = v
		case float64:
			lastSeen = int64(v)
		case int:
			lastSeen = int64(v)
		default:
			lastSeen = 0
		}
		
		status := "offline"
		if time.Now().Unix()-lastSeen < 300 {
			status = "online"
		}

		node := map[string]interface{}{
			"id":        beacon["id"],
			"type":      "beacon",
			"name":      beacon["hostname"],
			"address":   beacon["ip_address"],
			"status":    status,
			"os":        beacon["os"],
			"user":      beacon["username"],
			"last_seen": beacon["last_seen"],
		}
		beaconNodes = append(beaconNodes, node)
	}

	// Build connections
	var connections []map[string]interface{}

	// Connect DNS servers to Archon
	for _, dns := range dnsNodes {
		connections = append(connections, map[string]interface{}{
			"from": "archon",
			"to":   dns["id"],
			"type": "dns-server",
		})
	}

	// Connect beacons to DNS servers (based on contact history if available)
	// For simplicity, connect each beacon to all DNS servers
	for _, beacon := range beaconNodes {
		for _, dns := range dnsNodes {
			connections = append(connections, map[string]interface{}{
				"from": dns["id"],
				"to":   beacon["id"],
				"type": "beacon",
			})
		}
	}

	api.sendJSON(w, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"archon":      archon,
			"dns_servers": dnsNodes,
			"beacons":     beaconNodes,
			"connections": connections,
		},
	})
}

// handleBulkTaskAction handles bulk operations on tasks
func (api *APIServer) handleBulkTaskAction(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TaskIDs []string `json:"task_ids"`
		Action  string   `json:"action"` // "delete", "fail", "cancel"
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.sendError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if len(req.TaskIDs) == 0 {
		api.sendError(w, http.StatusBadRequest, "No task IDs provided")
		return
	}

	var successCount, failCount int

	for _, taskID := range req.TaskIDs {
		var err error
		switch req.Action {
		case "delete":
			err = api.db.DeleteTask(taskID)
		case "fail":
			err = api.db.UpdateTaskStatus(taskID, "failed")
		case "cancel":
			err = api.db.UpdateTaskStatus(taskID, "cancelled")
		default:
			err = fmt.Errorf("unknown action: %s", req.Action)
		}

		if err != nil {
			failCount++
		} else {
			successCount++
		}
	}

	api.sendJSON(w, map[string]interface{}{
		"success":       true,
		"success_count": successCount,
		"fail_count":    failCount,
		"message":       fmt.Sprintf("%s completed: %d succeeded, %d failed", req.Action, successCount, failCount),
	})
}

// handleBulkBeaconTask sends a task to multiple beacons
func (api *APIServer) handleBulkBeaconTask(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BeaconIDs []string `json:"beacon_ids"`
		Command   string   `json:"command"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.sendError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if len(req.BeaconIDs) == 0 {
		api.sendError(w, http.StatusBadRequest, "No beacon IDs provided")
		return
	}

	if req.Command == "" {
		api.sendError(w, http.StatusBadRequest, "Command is required")
		return
	}

	// Get operator info from request headers (set by auth middleware)
	createdBy := r.Header.Get("X-Operator-Username")
	if createdBy == "" {
		createdBy = "operator"
	}

	var successCount, failCount int
	var taskIDs []string

	for _, beaconID := range req.BeaconIDs {
		taskID, err := api.db.CreateTask(beaconID, req.Command, createdBy)
		if err != nil {
			failCount++
			continue
		}
		taskIDs = append(taskIDs, taskID)
		successCount++

		// Broadcast task creation
		BroadcastTaskUpdate(map[string]interface{}{
			"task_id":   taskID,
			"beacon_id": beaconID,
			"command":   req.Command,
			"status":    "pending",
		})
	}

	api.sendJSON(w, map[string]interface{}{
		"success":       true,
		"task_ids":      taskIDs,
		"success_count": successCount,
		"fail_count":    failCount,
		"message":       fmt.Sprintf("Tasks created: %d succeeded, %d failed", successCount, failCount),
	})
}
