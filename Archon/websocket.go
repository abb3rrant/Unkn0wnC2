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
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true
		}
		host := r.Host
		if host == "" {
			host = r.URL.Host
		}
		return strings.Contains(origin, host)
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
					// Cannot delete from map under RLock — send to unregister channel instead
					go func(c *WebSocketClient) {
						h.unregister <- c
					}(client)
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
			if err := w.Close(); err != nil {
				return
			}

			// Send remaining queued messages as separate frames
			n := len(c.send)
			for i := 0; i < n; i++ {
				w, err := c.conn.NextWriter(websocket.TextMessage)
				if err != nil {
					return
				}
				w.Write(<-c.send)
				if err := w.Close(); err != nil {
					return
				}
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

	if claims.JTI != "" {
		isRevoked, err := api.db.IsSessionRevoked(claims.JTI)
		if err != nil || isRevoked {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
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

// BroadcastLog broadcasts a log entry to all connected clients for live log viewing.
// WebSocket-related messages are excluded to avoid feedback loops and noise.
func BroadcastLog(level, message string) {
	if wsHub == nil {
		return
	}
	if strings.Contains(message, "WebSocket") {
		return
	}
	wsHub.Broadcast("log_entry", map[string]string{
		"timestamp": time.Now().Format("2006-01-02 15:04:05"),
		"level":     strings.ToLower(level),
		"message":   message,
	})
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

	switch {
	case logType == "archon" || logType == "":
		logFile = filepath.Join(logDir, fmt.Sprintf("archon-%s.log", today))
	case strings.HasPrefix(logType, "dns-"):
		sanitized := filepath.Base(logType)
		logFile = filepath.Join(logDir, sanitized+".log")
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

	// Filter out WebSocket noise and get last N meaningful lines
	var filtered []string
	for _, line := range lines {
		if strings.Contains(line, "WebSocket") {
			continue
		}
		filtered = append(filtered, line)
	}

	start := len(filtered) - numLines
	if start < 0 {
		start = 0
	}

	entries := make([]LogEntry, 0, numLines)
	for _, line := range filtered[start:] {
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
		_, _, _ = reader.ReadLine()
		// bufio read-ahead consumed more than the partial line;
		// seek to the actual position after the discarded line
		buffered := reader.Buffered()
		currentPos, _ := file.Seek(0, io.SeekCurrent)
		file.Seek(currentPos-int64(buffered), io.SeekStart)
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

	// Get all beacons for complete infrastructure view
	// Use large threshold (525600 min = 1 year) to include all beacons, not just recent
	beacons, err := api.db.GetActiveBeaconsPaginated(525600, 500, 0)
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

		// Determine online status based on last_seen timestamp only
		// A beacon is online if it checked in within the last 10 minutes
		// This is more reliable than the DB status field which isn't updated to 'offline'
		status := "offline"
		secondsSinceLastSeen := time.Now().Unix() - lastSeen
		if lastSeen > 0 && secondsSinceLastSeen < 600 { // 10 minutes
			status = "online"
		}

		node := map[string]interface{}{
			"id":             beacon["id"],
			"type":           "beacon",
			"name":           beacon["hostname"],
			"hostname":       beacon["hostname"],
			"address":        beacon["ip_address"],
			"ip_address":     beacon["ip_address"],
			"status":         status,
			"os":             beacon["os"],
			"arch":           beacon["arch"],
			"user":           beacon["username"],
			"username":       beacon["username"],
			"last_seen":      beacon["last_seen"],
			"first_seen":     beacon["first_seen"],
			"beacon_name":    beacon["beacon_name"],
			"build_id":       beacon["build_id"],
			"payload_format": beacon["payload_format"],
			"encoding":       beacon["encoding"],
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

	// Connect beacons to DNS servers using actual contact history
	beaconDNSLinks, err := api.db.GetAllBeaconDNSConnections()
	if err != nil {
		// Fallback: connect each beacon to all DNS servers
		for _, beacon := range beaconNodes {
			for _, dns := range dnsNodes {
				connections = append(connections, map[string]interface{}{
					"from": dns["id"],
					"to":   beacon["id"],
					"type": "beacon",
				})
			}
		}
	} else {
		// Build set of beacon IDs in this response for filtering
		beaconIDSet := make(map[interface{}]bool)
		for _, b := range beaconNodes {
			beaconIDSet[b["id"]] = true
		}
		dnsIDSet := make(map[interface{}]bool)
		for _, d := range dnsNodes {
			dnsIDSet[d["id"]] = true
		}

		for _, link := range beaconDNSLinks {
			bID := link["beacon_id"]
			dID := link["dns_server_id"]
			// Only include connections for beacons and DNS servers in this response
			if beaconIDSet[bID] && dnsIDSet[dID] {
				connections = append(connections, map[string]interface{}{
					"from": dID,
					"to":   bID,
					"type": "beacon",
				})
			}
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

	// Validate command length - DNS TXT responses have size limits
	if len(req.Command) > MaxTaskCommandLength {
		api.sendError(w, http.StatusBadRequest,
			fmt.Sprintf("command too long: %d characters (max %d). DNS TXT records have size limits.",
				len(req.Command), MaxTaskCommandLength))
		return
	}

	// Verify database is initialized
	if api.db == nil {
		api.sendError(w, http.StatusInternalServerError, "Database not initialized")
		return
	}

	// Get operator info from request headers (set by auth middleware)
	createdBy := r.Header.Get("X-Operator-ID")
	if createdBy == "" {
		createdBy = r.Header.Get("X-Operator-Username")
	}

	var successCount, failCount int
	var taskIDs []string
	var lastError error

	for _, beaconID := range req.BeaconIDs {
		taskID, err := api.db.CreateTask(beaconID, req.Command, createdBy)
		if err != nil {
			lastError = err
			failCount++
			// Always log bulk task failures for debugging
			fmt.Printf("[API] Bulk task creation failed for beacon %s: %v\n", beaconID, err)
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

	// If all failed, return an error with details
	if successCount == 0 && failCount > 0 {
		errMsg := "All tasks failed to create"
		if lastError != nil {
			errMsg = fmt.Sprintf("All tasks failed: %v", lastError)
		}
		api.sendError(w, http.StatusInternalServerError, errMsg)
		return
	}

	api.sendJSON(w, map[string]interface{}{
		"success":       true,
		"task_ids":      taskIDs,
		"success_count": successCount,
		"fail_count":    failCount,
		"message":       fmt.Sprintf("Tasks created: %d succeeded, %d failed", successCount, failCount),
	})
}
