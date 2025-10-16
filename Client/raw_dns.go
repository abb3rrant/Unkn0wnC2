package main

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"
)

// DNSHeader represents a DNS message header
type DNSHeader struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

// DNSQuestion represents a DNS question
type DNSQuestion struct {
	Name  string
	Type  uint16
	Class uint16
}

// buildDNSQuery constructs a raw DNS query packet
func buildDNSQuery(domain string, qtype uint16) []byte {
	// Create header
	header := DNSHeader{
		ID:      uint16(rand.Intn(65536)),
		Flags:   0x0100, // Standard query with recursion desired
		QDCount: 1,
		ANCount: 0,
		NSCount: 0,
		ARCount: 0,
	}

	var packet []byte

	// Add header (12 bytes)
	packet = append(packet, byte(header.ID>>8), byte(header.ID))
	packet = append(packet, byte(header.Flags>>8), byte(header.Flags))
	packet = append(packet, byte(header.QDCount>>8), byte(header.QDCount))
	packet = append(packet, byte(header.ANCount>>8), byte(header.ANCount))
	packet = append(packet, byte(header.NSCount>>8), byte(header.NSCount))
	packet = append(packet, byte(header.ARCount>>8), byte(header.ARCount))

	// Add question section
	// Encode domain name as labels
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		// Split long labels into multiple 63-character segments
		if len(label) > 63 {
			for len(label) > 0 {
				segmentLen := len(label)
				if segmentLen > 63 {
					segmentLen = 63
				}
				segment := label[:segmentLen]
				packet = append(packet, byte(len(segment)))
				packet = append(packet, []byte(segment)...)
				label = label[segmentLen:]
			}
		} else {
			packet = append(packet, byte(len(label)))
			packet = append(packet, []byte(label)...)
		}
	}
	packet = append(packet, 0) // End of name

	// Add QTYPE (2 bytes)
	packet = append(packet, byte(qtype>>8), byte(qtype))

	// Add QCLASS (2 bytes) - IN = 1
	packet = append(packet, 0, 1)

	return packet
}

// parseDNSResponse parses a raw DNS response
func parseDNSResponse(packet []byte) ([]string, error) {
	if len(packet) < 12 {
		return nil, fmt.Errorf("packet too short")
	}

	// Parse header
	ancount := binary.BigEndian.Uint16(packet[6:8])
	rcode := packet[3] & 0x0F

	if rcode != 0 {
		return nil, fmt.Errorf("DNS error code: %d", rcode)
	}

	if ancount == 0 {
		return nil, fmt.Errorf("no answers")
	}

	var results []string

	// Skip to answer section (after question)
	pos := 12

	// Skip question section
	for pos < len(packet) {
		if packet[pos] == 0 {
			pos += 5 // Skip null byte + QTYPE + QCLASS
			break
		}
		if packet[pos] >= 192 { // Compression pointer
			pos += 6 // Skip pointer + QTYPE + QCLASS
			break
		}
		pos += int(packet[pos]) + 1
	}

	// Parse answer records
	for i := 0; i < int(ancount) && pos < len(packet); i++ {
		// Skip name field
		if pos >= len(packet) {
			break
		}
		if packet[pos] >= 192 { // Compression pointer
			pos += 2
		} else {
			for pos < len(packet) && packet[pos] != 0 {
				pos += int(packet[pos]) + 1
			}
			pos++ // Skip null terminator
		}

		if pos+10 > len(packet) {
			break
		}

		// Parse record type, class, TTL, and data length
		rtype := binary.BigEndian.Uint16(packet[pos : pos+2])
		pos += 8 // Skip TYPE, CLASS, TTL
		rdlen := binary.BigEndian.Uint16(packet[pos : pos+2])
		pos += 2

		if pos+int(rdlen) > len(packet) {
			break
		}

		// Extract data based on type
		switch rtype {
		case 1: // A record
			if rdlen == 4 {
				ip := net.IP(packet[pos : pos+4])
				results = append(results, ip.String())
			}
		case 16: // TXT record
			// TXT records are length-prefixed strings
			// Multiple strings can be present, but we'll concatenate them
			txtPos := pos
			txtEnd := pos + int(rdlen)
			var txtParts []string

			for txtPos < txtEnd {
				if txtPos >= len(packet) {
					break
				}
				strLen := int(packet[txtPos])
				txtPos++
				if txtPos+strLen > txtEnd || txtPos+strLen > len(packet) {
					break
				}
				txtParts = append(txtParts, string(packet[txtPos:txtPos+strLen]))
				txtPos += strLen
			}

			if len(txtParts) > 0 {
				results = append(results, strings.Join(txtParts, ""))
			}
		}

		pos += int(rdlen)
	}

	return results, nil
}

// sendRawDNSQuery sends a raw DNS query to a specific server
func (c *DNSClient) sendRawDNSQuery(domain string, qtype uint16, server string) ([]string, error) {
	// Build DNS query
	query := buildDNSQuery(domain, qtype)

	// Connect to DNS server
	conn, err := net.Dial("udp", server)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to DNS server %s: %v", server, err)
	}
	defer conn.Close()

	// Set timeout
	timeout := time.Duration(c.config.Timeout) * time.Second
	conn.SetDeadline(time.Now().Add(timeout))

	// Send query
	_, err = conn.Write(query)
	if err != nil {
		return nil, fmt.Errorf("failed to send query: %v", err)
	}

	// Read response
	buffer := make([]byte, 512)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	// Parse response
	result, parseErr := parseDNSResponse(buffer[:n])
	if parseErr != nil {
		return nil, parseErr
	}

	return result, nil
}
