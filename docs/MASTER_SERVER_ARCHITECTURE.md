# Master Server Architecture Design
**Date:** November 4, 2025  
**Branch:** feature-shadow-mesh  
**Status:** Planning Phase

---

## 🎯 Overview

Transform Unkn0wnC2 from single-server to distributed master/lieutenant architecture:
- **Master Server**: Central command with WebUI, HTTPS API, aggregated database
- **DNS Servers**: Multiple authoritative DNS servers (lieutenants) handling beacon C2
- **Clients**: Connect to multiple DNS domains randomly for resilience

---

## 🏛️ Architecture

### Current Architecture
```
┌─────────┐
│ Client  │
└────┬────┘
     │ DNS (Port 53)
     ▼
┌─────────────────┐
│   DNS Server    │
│  (Authoritative)│
│  + C2 Manager   │
│  + Console      │
│  + SQLite DB    │
└─────────────────┘
```

### New Architecture
```
                    ┌──────────────────────────────┐
                    │     Master Server            │
                    │  - WebUI (React/Vue)         │
                    │  - HTTPS API                 │
                    │  - Master Database (SQLite)  │
                    │  - Multi-user Support        │
                    │  - Aggregated Data           │
                    └───────┬──────────────────────┘
                            │ HTTPS (encrypted)
          ┌─────────────────┼─────────────────┐
          │                 │                 │
    ┌─────▼─────┐     ┌─────▼─────┐     ┌───▼───────┐
    │DNS Server1│     │DNS Server2│     │DNS Server3│
    │secwolf.net│     │example.com│     │  test.org │
    │Port 53    │     │Port 53    │     │Port 53    │
    │Local DB   │     │Local DB   │     │Local DB   │
    └─────▲─────┘     └─────▲─────┘     └─────▲─────┘
          │                 │                 │
          └─────────────────┼─────────────────┘
                    DNS (Port 53)
                            │
                      ┌─────▼─────┐
                      │  Clients  │
                      │(Round-robin│
                      │ to N DNS)  │
                      └───────────┘
```

---

## 📊 Component Breakdown

### 1. Master Server (NEW)
**Port:** 443 (HTTPS)  
**Purpose:** Central command and control, team collaboration

**Features:**
- ✨ Modern WebUI (React/Next.js)
- 🔐 Multi-user authentication
- 📊 Aggregated data from all DNS servers
- 🎯 Unified beacon view across all domains
- 📈 Dashboard with statistics
- 🔔 Real-time notifications
- 🗂️ Centralized task management
- 📝 Operator logs and audit trail
- 🌐 HTTPS API for DNS servers

**Database:** Master SQLite
```sql
-- Master database stores aggregated data
CREATE TABLE dns_servers (
    id TEXT PRIMARY KEY,
    domain TEXT,
    address TEXT,
    last_checkin TIMESTAMP,
    status TEXT
);

CREATE TABLE beacons (
    id TEXT PRIMARY KEY,
    hostname TEXT,
    username TEXT,
    os TEXT,
    arch TEXT,
    dns_server_id TEXT,  -- Which DNS server registered it
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    FOREIGN KEY (dns_server_id) REFERENCES dns_servers(id)
);

CREATE TABLE tasks (
    id TEXT PRIMARY KEY,
    beacon_id TEXT,
    command TEXT,
    status TEXT,
    created_by TEXT,  -- Operator who created it
    created_at TIMESTAMP,
    assigned_dns_server TEXT,
    FOREIGN KEY (beacon_id) REFERENCES beacons(id)
);

CREATE TABLE results (
    id INTEGER PRIMARY KEY,
    task_id TEXT,
    chunk_index INTEGER,
    total_chunks INTEGER,
    data TEXT,
    received_at TIMESTAMP,
    FOREIGN KEY (task_id) REFERENCES tasks(id)
);

CREATE TABLE operators (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE,
    password_hash TEXT,
    role TEXT,  -- admin, operator, viewer
    created_at TIMESTAMP,
    last_login TIMESTAMP
);

CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY,
    operator_id TEXT,
    action TEXT,
    target TEXT,
    timestamp TIMESTAMP,
    FOREIGN KEY (operator_id) REFERENCES operators(id)
);
```

**API Endpoints:**
```
POST   /api/auth/login          - Operator login
POST   /api/auth/logout         - Operator logout

GET    /api/dns-servers         - List all DNS servers
GET    /api/dns-servers/:id     - Get DNS server details
POST   /api/dns-servers         - Register new DNS server
DELETE /api/dns-servers/:id     - Remove DNS server

GET    /api/beacons             - List all beacons (aggregated)
GET    /api/beacons/:id         - Get beacon details
POST   /api/beacons/:id/task    - Create task for beacon

GET    /api/tasks               - List all tasks
GET    /api/tasks/:id           - Get task details
GET    /api/tasks/:id/result    - Get task result

POST   /api/dns-server/checkin  - DNS server check-in
POST   /api/dns-server/beacon   - Report new beacon
POST   /api/dns-server/result   - Submit task result
GET    /api/dns-server/tasks    - Get pending tasks for DNS server
```

### 2. DNS Servers (Modified)
**Port:** 53 (DNS)  
**Purpose:** Handle beacon C2, optionally report to master

**Dual Mode Operation:**
- **Standalone Mode**: Console enabled - operates as independent C2 server (current behavior)
- **Distributed Mode**: Console disabled - runs headless, reports to master

**Changes:**
- Keep console interface for standalone mode
- Add HTTPS client for master communication (when configured)
- Keep local SQLite for resilience in both modes
- Report beacons/results to master (distributed mode only)
- Poll master for tasks (distributed mode only)

**New Configuration:**
```json
{
  "dns_server": {
    "domain": "secwolf.net",
    "bind_addr": "0.0.0.0",
    "bind_port": 53,
    "master_server": "",  // Empty = Standalone, URL = Distributed
    "master_api_key": "dns-server-secret-key",
    "checkin_interval": 30,
    "local_db": "dns_server.db"
  }
}
```

**Standalone Mode Behavior (master_server = ""):**
1. Beacon checks in via DNS → Store locally
2. Operator manages via console (existing behavior)
3. Tasks created via console commands
4. Results viewed via console
5. Full independent C2 server

**Distributed Mode Behavior (master_server configured):**
1. Beacon checks in via DNS → Store locally
2. Send beacon info to master via HTTPS
3. Poll master every 30s for new tasks
4. Receive result chunks → Store locally + send to master
5. If master unreachable, continue operating (resilience)
6. Console disabled - runs as headless service

### 3. Clients (Modified)
**Purpose:** Connect to multiple DNS domains randomly

**New Configuration:**
```json
{
  "client": {
    "dns_domains": [
      "secwolf.net",
      "example.com", 
      "test.org"
    ],
    "selection_mode": "random",  // random, round-robin, failover
    "dns_server": "",
    "query_type": "TXT",
    "encoding": "aes-gcm-base36",
    "encryption_key": "shared-key-123",
    "timeout": 10,
    "max_command_length": 400,
    "retry_attempts": 3,
    "sleep_min": 60,
    "sleep_max": 120
  }
}
```

**New Behavior:**
1. On check-in: Randomly select DNS domain from list
2. Send check-in to selected domain
3. If domain fails, try next in list
4. On result exfiltration: Use SAME domain that sent task
5. Store "current domain" per task to ensure chunked results go to same place

**Challenge:** Multi-domain result aggregation
- Problem: Client sends chunk 1 to secwolf.net, chunk 2 to example.com
- Solution: Task ID includes domain hint, OR client sticks to one domain per task

---

## 🔐 Security

### Master ↔ DNS Server Communication
- **Encryption:** TLS 1.3 (HTTPS)
- **Authentication:** API keys per DNS server
- **Data:** Encrypted beacon data (double encryption)

### DNS Server ↔ Client Communication
- **Encryption:** AES-GCM + Base36 (existing)
- **Authentication:** None (DNS C2 design)

### Master Server Access
- **Authentication:** Username/password + session tokens
- **Authorization:** Role-based (admin, operator, viewer)
- **Audit:** All actions logged

---

## 📁 New Directory Structure

```
Unkn0wnC2/
├── Master/                    # NEW: Master/Team Server
│   ├── main.go
│   ├── api/
│   │   ├── auth.go
│   │   ├── beacons.go
│   │   ├── tasks.go
│   │   ├── dns_servers.go
│   │   └── websocket.go       # Real-time updates
│   ├── db/
│   │   ├── master_db.go
│   │   └── schema.go
│   ├── models/
│   │   ├── beacon.go
│   │   ├── task.go
│   │   ├── operator.go
│   │   └── dns_server.go
│   ├── web/                   # WebUI
│   │   ├── src/
│   │   │   ├── components/
│   │   │   ├── pages/
│   │   │   ├── store/
│   │   │   └── App.tsx
│   │   ├── public/
│   │   ├── package.json
│   │   └── vite.config.ts
│   └── go.mod
├── Server/                    # Modified: DNS Server (Lieutenant)
│   ├── main.go               # Remove console, add master client
│   ├── c2_manager.go         # Keep C2 logic
│   ├── master_client.go      # NEW: Communicate with master
│   ├── db.go                 # Keep local DB
│   └── ...
├── Client/                    # Modified: Multi-domain support
│   ├── main.go               # Add domain selection
│   ├── dns_client.go         # Add multi-domain logic
│   └── config.go             # Add dns_domains array
└── build_config.json          # Updated structure
```

---

## 🔄 Data Flow

### Beacon Registration
```
1. Client → DNS Server (secwolf.net)
   CHK|beacon123|hostname|user|linux

2. DNS Server → Local DB
   INSERT beacon123

3. DNS Server → Master Server (HTTPS)
   POST /api/dns-server/beacon
   {
     "dns_server_id": "dns1",
     "beacon_id": "beacon123",
     "hostname": "target-01",
     "username": "admin",
     "os": "linux",
     "arch": "x64"
   }

4. Master Server → Master DB
   INSERT beacon123 (dns_server_id = dns1)

5. Master Server → WebUI (WebSocket)
   {type: "beacon_new", beacon: {...}}
```

### Task Creation
```
1. Operator → WebUI
   Create task: "whoami" for beacon123

2. WebUI → Master Server
   POST /api/beacons/beacon123/task
   {command: "whoami"}

3. Master Server → Master DB
   INSERT task T1001 (assigned_dns_server = dns1)

4. DNS Server → Master Server (polling)
   GET /api/dns-server/tasks?dns_id=dns1
   Response: [{task_id: "T1001", beacon_id: "beacon123", command: "whoami"}]

5. DNS Server → Local DB
   INSERT task T1001 to beacon123 queue

6. Client → DNS Server
   CHK|beacon123|...
   Response: TASK|T1001|whoami

7. Client → DNS Server
   RESULT|beacon123|T1001|output

8. DNS Server → Master Server
   POST /api/dns-server/result
   {task_id: "T1001", beacon_id: "beacon123", result: "admin"}

9. Master Server → WebUI (WebSocket)
   {type: "task_complete", task_id: "T1001", result: "admin"}
```

### Multi-Domain Client Behavior
```
Check-in 1: Client selects secwolf.net (random)
  → Receives task T1001 from secwolf.net
  → Stores: T1001 → secwolf.net mapping

Result 1: Client sends to secwolf.net (same as task source)
  → RESULT_META|...|T1001
  → DATA|...|T1001|chunk1
  → DATA|...|T1001|chunk2

Check-in 2: Client selects example.com (random)
  → Receives task T1002 from example.com
  → Stores: T1002 → example.com mapping

Result 2: Client sends to example.com
  → Ensures chunked results go to correct domain
```

---

## 🎨 WebUI Design

### Dashboard
- Total beacons (across all DNS servers)
- Active beacons (last 5 minutes)
- Tasks pending/completed
- DNS server status grid
- Recent activity feed

### Beacons View
- Table with: ID, Hostname, User, OS, DNS Server, Last Seen
- Filter by DNS server
- Search by hostname/user
- Click beacon → detail view with task history

### Tasks View
- Table with: Task ID, Beacon, Command, Status, Created By, Time
- Filter by status (pending/sent/completed/failed)
- Real-time status updates

### DNS Servers View
- Card grid showing each DNS server
- Status: Online/Offline
- Beacon count per server
- Last check-in time
- Click to view server-specific beacons

### Settings
- User management (admin only)
- DNS server registration
- API key management
- Audit log viewer

---

## 🚀 Implementation Phases

### Phase 1: Master Server Backend (Week 1-2)
- [ ] Create Master/ directory structure
- [ ] Implement master database schema
- [ ] Build HTTPS API server
- [ ] Implement authentication/authorization
- [ ] Create DNS server registration system
- [ ] Build task aggregation logic
- [ ] Implement WebSocket for real-time updates

### Phase 2: DNS Server Modifications (Week 2-3)
- [ ] Remove console interface
- [ ] Add master_client.go for HTTPS communication
- [ ] Implement check-in to master
- [ ] Implement task polling from master
- [ ] Implement result reporting to master
- [ ] Add resilience (work offline if master down)
- [ ] Test multi-DNS-server setup

### Phase 3: Client Modifications (Week 3)
- [ ] Add dns_domains array to config
- [ ] Implement domain selection (random/round-robin)
- [ ] Add task-to-domain mapping
- [ ] Ensure chunked results go to correct domain
- [ ] Add failover logic
- [ ] Test multi-domain behavior

### Phase 4: WebUI Development (Week 4-5)
- [ ] Set up React/Next.js project
- [ ] Build authentication UI
- [ ] Create dashboard
- [ ] Build beacons management view
- [ ] Build tasks management view
- [ ] Build DNS servers view
- [ ] Implement WebSocket real-time updates
- [ ] Add settings/admin panel

### Phase 5: Integration & Testing (Week 6)
- [ ] End-to-end testing
- [ ] Multi-DNS-server testing
- [ ] Load testing
- [ ] Security audit
- [ ] Documentation
- [ ] Deployment guides

---

## 🔧 Configuration Changes

### build_config.json (NEW structure)
```json
{
  "project": {
    "name": "Unkn0wnC2",
    "version": "0.3.0-shadow-mesh",
    "description": "Distributed DNS C2 Framework"
  },
  "master_server": {
    "bind_addr": "0.0.0.0",
    "bind_port": 443,
    "tls_cert": "/path/to/cert.pem",
    "tls_key": "/path/to/key.pem",
    "database": "master.db",
    "session_secret": "change-this-secret",
    "admin_username": "admin",
    "admin_password": "change-this-password"
  },
  "dns_servers": [
    {
      "id": "dns1",
      "domain": "secwolf.net",
      "bind_addr": "172.26.13.62",
      "bind_port": 53,
      "master_url": "https://master.example.com",
      "api_key": "dns-server-1-secret-key"
    },
    {
      "id": "dns2",
      "domain": "example.com",
      "bind_addr": "10.0.0.5",
      "bind_port": 53,
      "master_url": "https://master.example.com",
      "api_key": "dns-server-2-secret-key"
    }
  ],
  "client": {
    "dns_domains": ["secwolf.net", "example.com", "test.org"],
    "selection_mode": "random",
    "encryption_key": "shared-encryption-key-123",
    "query_type": "TXT",
    "timeout": 10,
    "sleep_min": 60,
    "sleep_max": 120
  }
}
```

---

## 🎯 Key Benefits

1. **Scalability**: Add unlimited DNS servers
2. **Resilience**: Multiple C2 channels, offline operation
3. **Team Collaboration**: Multi-user WebUI
4. **Stealth**: DNS servers only expose port 53
5. **Centralization**: Unified view of all operations
6. **Load Distribution**: Beacons distributed across domains
7. **Failover**: Client can switch domains
8. **Professional**: Modern WebUI vs terminal console

---

## ⚠️ Challenges & Solutions

### Challenge 1: Result Chunk Aggregation
**Problem:** Client sends chunks to different domains randomly
**Solution:** Client stores task-to-domain mapping, sends all chunks for a task to same domain

### Challenge 2: Master Server Downtime
**Problem:** DNS servers can't report data if master is down
**Solution:** DNS servers continue operating with local DB, sync when master returns

### Challenge 3: Task Routing
**Problem:** How does master know which DNS server has which beacon?
**Solution:** Master tracks beacon-to-DNS-server mapping in database

### Challenge 4: Duplicate Beacons
**Problem:** Same beacon might register with multiple DNS servers
**Solution:** Master uses beacon ID as primary key, updates last_seen and dns_server_id

### Challenge 5: Security
**Problem:** Master server is single point of failure
**Solution:** Strong authentication, rate limiting, audit logging, TLS

---

## 📝 Next Steps

1. **Review & Approval**: Get stakeholder buy-in on architecture
2. **Set Up Development Environment**: Create Master/ directory structure
3. **Start Phase 1**: Build master server backend
4. **Parallel Work**: Can modify DNS server while building master
5. **Testing Infrastructure**: Set up multi-server test environment

---

**Status:** 📋 **PLANNING COMPLETE - READY FOR IMPLEMENTATION**

