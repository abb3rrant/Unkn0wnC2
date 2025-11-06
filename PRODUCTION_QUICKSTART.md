# Unkn0wnC2 Production Deployment Quick Reference

## 🚀 Quick Start

### 1. Generate Secure Credentials
```bash
# JWT Secret (32+ bytes required)
openssl rand -base64 48 > jwt_secret.txt

# API Key (16+ bytes required)
openssl rand -base64 24 > api_key.txt
```

### 2. Update Master Configuration
Edit `Master/master_config.example.json`:
```json
{
  "jwt_secret": "<paste from jwt_secret.txt>",
  "api_key": "<paste from api_key.txt>",
  "listen_addr": ":8443",
  "db_path": "./unkn0wn.db",
  "tls_cert": "./certs/server.crt",
  "tls_key": "./certs/server.key"
}
```

### 3. Build All Components
```bash
# DNS Server (port 53)
cd Server && go build -o dns-server . && cd ..

# Master Server (port 8443)
cd Master && go build -o master . && cd ..

# Client Beacon
cd Client && go build -o dns-c2-client . && cd ..

# Stager (Linux x64)
cd Stager && make DNS_SERVER=<your-dns-ip> C2_DOMAINS=<your-domain> linux-x64 && cd ..
```

---

## 🔒 Security Features

### Rate Limiting (NEW)
- **Authentication**: 5 requests/min per IP
- **API Endpoints**: 100 requests/min per IP
- **DNS Queries**: 1000 requests/min per IP

### JWT/API Key Validation (NEW)
- **JWT Secret**: Minimum 32 bytes enforced
- **API Key**: Minimum 16 bytes enforced
- Automatic validation on startup

### Self-Destruct (NEW)
```bash
# Via Master API
curl -X POST https://master:8443/api/tasks \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"beacon_id": "123", "command": "self_destruct"}'

# Result: Beacon removed from DB, binary deleted after 3 seconds
```

---

## ⚡ Performance Features

### Compression (NEW)
- **Automatic**: Outputs >1KB compressed with gzip
- **Threshold**: Only if compressed < 80% of original
- **Bandwidth Savings**: 60-80% on large outputs

### Pagination (NEW)
```bash
# Get beacons with pagination
curl "https://master:8443/api/beacons?limit=50&offset=0" \
  -H "Authorization: Bearer $TOKEN"

# Response includes metadata
{
  "metadata": {
    "total": 1523,
    "limit": 50,
    "offset": 0,
    "count": 50
  },
  "beacons": [...]
}
```

### Weighted Domain Selection (NEW)
Client automatically routes to fastest domain based on:
- **Latency**: Exponential moving average
- **Success Rate**: Per-domain counters
- **Score**: `1.0 / (latency_ms + 1) + (success_rate * 100)`

Configure in `Client/config.go`:
```go
SelectionMode: "weighted"  // random, round-robin, failover, weighted
```

---

## 🛠️ Operational Features

### Data Retention (NEW)
Automatic cleanup runs every 6 hours:
- **Tasks**: Deleted after 30 days
- **Inactive Beacons**: Deleted after 60 days
- **Stager Sessions**: Deleted after 7 days (completed only)

Override defaults in `Master/main.go`:
```go
const (
    taskRetentionDays    = 30
    beaconRetentionDays  = 60
    stagerRetentionDays  = 7
)
```

### Delete Endpoints (NEW)
```bash
# Delete specific task
curl -X DELETE https://master:8443/api/tasks/456 \
  -H "Authorization: Bearer $TOKEN"

# Delete beacon (cascades to tasks)
curl -X DELETE https://master:8443/api/beacons/123 \
  -H "Authorization: Bearer $TOKEN"
```

### Enhanced Diagnostics (NEW)

#### Stager Debug Mode
```bash
# Build with debug output
make DEBUG_MODE=1 C2_DOMAINS=test.example.com linux-x64

# Output includes:
# - MD5 checksum of downloaded binary
# - Binary format verification (ELF/PE)
# - Detailed DNS error messages
# - Retry attempt tracking
```

#### Client Task Timeout (NEW)
- **Timeout**: 5 minutes per command
- **Detection**: Distinguishes timeout from normal errors
- **Output**: "Command execution timed out after 5 minutes"

---

## 📊 Monitoring & Troubleshooting

### DNS Server Memory
```bash
# Check memory usage
ps aux | grep dns-server

# Memory cleanup runs every 5 minutes
# - Recent messages: 5-minute sliding window
# - Cached responses: 5-minute sliding window
# - Max 1000 entries each
```

### Master Server Health
```bash
# Check rate limiter status (blocked IPs)
curl https://master:8443/api/health \
  -H "Authorization: Bearer $TOKEN"

# Check database size
ls -lh Master/unkn0wn.db

# Manual cleanup (if needed)
sqlite3 Master/unkn0wn.db "DELETE FROM tasks WHERE created_at < datetime('now', '-30 days')"
```

### Client Diagnostics
```go
// Enable debug logging in Client/main.go
logf("Weighted domain selected: %s (score: %.2f)", domain, score)
```

### Stager Troubleshooting

#### No TXT Records
```
[!] ERROR: No TXT records in DNS response
[!] This could mean:
[!]   - Domain not configured on C2 server
[!]   - DNS query reached wrong server
[!]   - Server not returning TXT records
```
**Fix**: Verify DNS server IP and domain configuration

#### Binary Verification Failed
```
[!] ERROR: Binary verification failed - invalid executable format
[!] First 8 bytes: 1f 8b 08 00 00 00 00 00
```
**Fix**: Check server-side compression/encoding

#### DNS Query Failures
```
[!] ERROR: All 5 DNS query attempts failed for domain: secwolf.net
[!] Possible causes:
[!]   - DNS server unreachable (8.8.8.8:53)
[!]   - Network filtering/firewall blocking DNS
```
**Fix**: Test DNS connectivity with `dig @8.8.8.8 test.secwolf.net TXT`

---

## 🔧 Configuration Examples

### Production Master Config
```json
{
  "jwt_secret": "aX9k2mN8qP5vL1sT4wB7yC3hF6rG9dE0jU8nM2lK5xV7",
  "api_key": "pQ3wR7tY2uI9oP5aS1dF4gH",
  "listen_addr": ":8443",
  "db_path": "/var/lib/unkn0wn/unkn0wn.db",
  "tls_cert": "/etc/unkn0wn/server.crt",
  "tls_key": "/etc/unkn0wn/server.key"
}
```

### Production DNS Server Config
```json
{
  "listen": ":53",
  "master_url": "https://master.internal:8443",
  "api_key": "pQ3wR7tY2uI9oP5aS1dF4gH",
  "upstream_dns": "8.8.8.8:53",
  "c2_domains": ["c2.example.com", "cdn.example.org"]
}
```

### Production Client Config
```go
const (
    DomainSelectionMode = "weighted"
    CheckInInterval     = 60  // seconds
    JitterPercent       = 20  // 20% jitter
)

var C2Domains = []string{
    "c2.example.com",
    "cdn.example.org",
    "api.example.net",
}
```

### Production Stager Build
```bash
# Multi-domain with production DNS
make \
  DNS_SERVER=10.0.0.53 \
  C2_DOMAINS=c2.example.com,cdn.example.org,api.example.net \
  DEBUG_MODE=0 \
  linux-x64

# Single domain with debug
make \
  DNS_SERVER=1.1.1.1 \
  C2_DOMAINS=test.example.com \
  DEBUG_MODE=1 \
  linux-x64
```

---

## 🎯 Performance Tuning

### High-Traffic Deployments (10K+ Beacons)

#### Master Server
```go
// Increase rate limits for legitimate traffic
auth := NewRateLimiter(10, 1*time.Minute)    // 10/min (was 5)
api := NewRateLimiter(500, 1*time.Minute)    // 500/min (was 100)
dns := NewRateLimiter(5000, 1*time.Minute)   // 5000/min (was 1000)
```

#### DNS Server
```go
// Increase cache sizes
const (
    maxRecentMessages   = 5000   // (was 1000)
    maxCachedResponses  = 5000   // (was 1000)
    cleanupWindow       = 3*time.Minute  // (was 5)
)
```

#### Database
```bash
# Verify indexes (should already exist)
sqlite3 unkn0wn.db ".indices"

# Expected output:
# idx_beacons_active
# idx_tasks_status  
# idx_stager_active
```

### Low-Bandwidth Deployments

#### Client
```go
// Reduce compression threshold for more aggressive compression
const compressionThreshold = 512  // 512 bytes (was 1024)
```

#### DNS Server
```go
// Reduce chunk size for smaller DNS packets
const maxChunkSize = 128  // 128 bytes (was 200)
```

---

## 📋 Pre-Deployment Checklist

### Security
- [ ] JWT secret ≥32 bytes
- [ ] API key ≥16 bytes
- [ ] TLS certificates valid
- [ ] Rate limiting tested
- [ ] Self-destruct tested

### Performance
- [ ] Pagination tested with 1000+ records
- [ ] Compression tested on large outputs
- [ ] Weighted routing shows latency improvements
- [ ] Memory cleanup verified over 24 hours

### Reliability
- [ ] Task timeout tested (5-minute commands)
- [ ] Stager retry limit verified (5 attempts)
- [ ] MD5 verification tested with corrupt binary
- [ ] Error messages provide actionable info

### Operational
- [ ] Cleanup scheduler runs every 6 hours
- [ ] Delete endpoints tested
- [ ] Audit logs capture operator actions
- [ ] Diagnostics tested in failure scenarios

---

## 🚨 Emergency Procedures

### Mass Beacon Cleanup
```bash
# Self-destruct all beacons (use with caution!)
for beacon_id in $(curl -s https://master:8443/api/beacons -H "Authorization: Bearer $TOKEN" | jq -r '.beacons[].id'); do
  curl -X POST https://master:8443/api/tasks \
    -H "Authorization: Bearer $TOKEN" \
    -d "{\"beacon_id\": \"$beacon_id\", \"command\": \"self_destruct\"}"
  sleep 1
done
```

### Rate Limit Reset
```bash
# Restart Master to clear rate limiter state
systemctl restart unkn0wn-master

# Or modify rate limits in Master/api.go and rebuild
```

### Database Backup
```bash
# Backup before cleanup
sqlite3 Master/unkn0wn.db ".backup unkn0wn_backup_$(date +%Y%m%d).db"

# Restore if needed
sqlite3 Master/unkn0wn.db ".restore unkn0wn_backup_20240101.db"
```

---

## 📚 Additional Resources

- **Architecture**: See `agent_docs/ARCHITECTURE.md`
- **Deployment**: See `agent_docs/DEPLOYMENT.md`
- **Testing**: See `test_stager_workflow.md`
- **Full Summary**: See `COMPREHENSIVE_IMPROVEMENTS_SUMMARY.md`

---

*Last Updated: 2024*  
*Framework: Unkn0wnC2 DNS C2*  
*Status: ✅ Production Ready*
