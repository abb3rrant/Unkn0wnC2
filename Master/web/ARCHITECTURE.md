# Web Interface Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         BROWSER                                  │
│                                                                   │
│  ┌─────────────────┐         ┌──────────────────────┐          │
│  │  /login         │         │   /dashboard         │          │
│  │  (login.html)   │────────▶│   (dashboard.html)   │          │
│  │                 │  Auth   │                      │          │
│  │  • Username     │  Success│  • Beacon List       │          │
│  │  • Password     │         │  • DNS Server List   │          │
│  │  • JWT Token    │         │  • Statistics        │          │
│  └────────┬────────┘         │  • Auto-refresh      │          │
│           │                   └──────────┬───────────┘          │
│           │                              │                       │
│           │  POST /api/auth/login        │  GET /api/beacons    │
│           │  {username, password}        │  Authorization:      │
│           │                              │  Bearer <JWT>        │
│           │  Response:                   │                      │
│           │  {token, expires_at}         │  GET /api/dns-servers│
│           │                              │  Authorization:      │
│           ▼                              ▼  Bearer <JWT>        │
└─────────────────────────────────────────────────────────────────┘
            │                              │
            │         HTTPS (TLS)          │
            ▼                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    MASTER SERVER (Port 8443)                     │
│                                                                   │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                   Gorilla Mux Router                        │ │
│  │                                                             │ │
│  │  Web UI Routes:                                             │ │
│  │    GET  /              → Redirect to /login                │ │
│  │    GET  /login         → Serve login.html                  │ │
│  │    GET  /dashboard     → Serve dashboard.html              │ │
│  │                                                             │ │
│  │  Public API:                                                │ │
│  │    POST /api/auth/login  → handleLogin()                   │ │
│  │                                                             │ │
│  │  Protected API (JWT Required):                             │ │
│  │    GET  /api/beacons        → handleListBeacons()          │ │
│  │    GET  /api/dns-servers    → handleListDNSServers()       │ │
│  │    POST /api/auth/logout    → handleLogout()               │ │
│  │                                                             │ │
│  │  DNS Server API (API Key Required):                        │ │
│  │    POST /api/dns-server/checkin  → handleDNSServerCheckin()│ │
│  │    POST /api/dns-server/beacon   → handleBeaconReport()    │ │
│  │    POST /api/dns-server/result   → handleSubmitResult()    │ │
│  └─────────────────────┬──────────────────────────────────────┘ │
│                        │                                         │
│  ┌────────────────────┴─────────────────────────────────────┐  │
│  │                   JWT Middleware                          │  │
│  │  • Verify Bearer token                                    │  │
│  │  • Check signature with jwtSecret                         │  │
│  │  • Validate expiration                                    │  │
│  │  • Extract claims (operator_id, username, role)           │  │
│  └────────────────────┬──────────────────────────────────────┘  │
│                       │                                          │
│  ┌────────────────────▼──────────────────────────────────────┐  │
│  │                  API Server                               │  │
│  │                                                           │  │
│  │  handleLogin():                                           │  │
│  │    1. Verify credentials with database                    │  │
│  │    2. Generate JWT token (HMAC-SHA256)                    │  │
│  │    3. Set expiration (session_timeout)                    │  │
│  │    4. Return {token, expires_at, operator}               │  │
│  │                                                           │  │
│  │  handleListBeacons():                                     │  │
│  │    1. Verify JWT middleware passed                        │  │
│  │    2. Query GetActiveBeacons(30 minutes)                 │  │
│  │    3. Return {beacons: [...]}                            │  │
│  │                                                           │  │
│  │  handleListDNSServers():                                  │  │
│  │    1. Verify JWT middleware passed                        │  │
│  │    2. Query GetDNSServers()                              │  │
│  │    3. Return {servers: [...]}                            │  │
│  └────────────────────┬──────────────────────────────────────┘  │
│                       │                                          │
│  ┌────────────────────▼──────────────────────────────────────┐  │
│  │              Master Database (SQLite)                     │  │
│  │                                                           │  │
│  │  Tables:                                                  │  │
│  │  • operators       - User accounts (username, password)   │  │
│  │  • dns_servers     - Registered DNS servers              │  │
│  │  • beacons         - Active beacons (aggregated)         │  │
│  │  • tasks           - Pending/completed tasks             │  │
│  │  • task_results    - Task output data                    │  │
│  │  • audit_log       - Operator actions                    │  │
│  │  • sessions        - Active JWT sessions                 │  │
│  │                                                           │  │
│  │  Functions:                                               │  │
│  │  • VerifyOperatorCredentials()                           │  │
│  │  • GetActiveBeacons()                                    │  │
│  │  • GetDNSServers()                                       │  │
│  │  • UpsertBeacon()                                        │  │
│  │  • UpdateDNSServerCheckin()                              │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                       ▲
                       │ HTTPS (API Key Auth)
                       │
        ┌──────────────┴───────────────┐
        │                              │
┌───────▼────────┐          ┌─────────▼────────┐
│  DNS Server 1  │          │  DNS Server 2    │
│  (Lieutenant)  │          │  (Lieutenant)    │
│                │          │                  │
│  • Check-in    │          │  • Check-in      │
│  • Report      │          │  • Report        │
│    beacons     │          │    beacons       │
│  • Submit      │          │  • Submit        │
│    results     │          │    results       │
└────────────────┘          └──────────────────┘
```

## Data Flow Examples

### 1. Login Flow
```
User → Browser → POST /api/auth/login
                  {username: "admin", password: "***"}
                  
                  ↓
                  
Master → Database → VerifyOperatorCredentials()
                   → Generate JWT token
                   
                   ↓
                   
Browser ← 200 OK   {token: "eyJhbGc...", expires_at: "2024-..."}
        → Store in localStorage
        → Redirect to /dashboard
```

### 2. Dashboard Load Flow
```
Browser → Check localStorage for token
          ↓ (found)
          GET /api/beacons
          Header: Authorization: Bearer eyJhbGc...
          
          ↓
          
Master  → JWT Middleware validates token
        → handleListBeacons()
        → Database.GetActiveBeacons(30)
        
        ↓
        
Browser ← 200 OK {beacons: [{id: "abc123", hostname: "target1", ...}]}
        → Render beacon table
```

### 3. DNS Server Check-in Flow
```
DNS Server → POST /api/dns-server/checkin
             {dns_server_id: "dns-1", api_key: "***", status: "active"}
             
             ↓
             
Master     → dnsServerAuthMiddleware validates API key
           → handleDNSServerCheckin()
           → Database.UpdateDNSServerCheckin()
           
           ↓
           
Dashboard  → Next auto-refresh (10s)
           → GET /api/dns-servers
           → See updated last_checkin timestamp
```

## Security Layers

```
┌─────────────────────────────────────────┐
│  Layer 1: Transport Security            │
│  • TLS 1.2/1.3 encryption               │
│  • Valid certificates required           │
│  • HTTPS only (no HTTP fallback)        │
└───────────────┬─────────────────────────┘
                │
┌───────────────▼─────────────────────────┐
│  Layer 2: Authentication                 │
│  • JWT tokens (HMAC-SHA256)             │
│  • Token expiration (configurable)       │
│  • Credentials hashed (bcrypt)          │
└───────────────┬─────────────────────────┘
                │
┌───────────────▼─────────────────────────┐
│  Layer 3: Authorization                  │
│  • JWT middleware for operator routes    │
│  • API key middleware for DNS routes     │
│  • Role-based access (future)           │
└───────────────┬─────────────────────────┘
                │
┌───────────────▼─────────────────────────┐
│  Layer 4: Audit Logging                  │
│  • All operator actions logged          │
│  • Failed login attempts tracked        │
│  • Task creation/execution recorded     │
└──────────────────────────────────────────┘
```

## Component Responsibilities

### Browser (Frontend)
- User interface rendering
- JWT token storage (localStorage)
- API request authentication (Bearer token)
- Auto-refresh data polling
- Error handling and display

### Master Server (Backend)
- TLS termination
- Route handling (web + API)
- JWT generation and validation
- API key validation
- Database operations
- DNS server coordination

### Master Database
- Operator credentials storage
- Beacon aggregation from multiple DNS servers
- Task queue management
- Result chunk assembly
- Audit trail
- DNS server registration

### DNS Servers (Lieutenant)
- Check-in to master regularly
- Report local beacons to master
- Fetch tasks from master
- Submit results to master
- Handle DNS queries
- Execute C2 operations
