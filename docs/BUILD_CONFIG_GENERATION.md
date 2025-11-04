# Build Configuration Generation

## Overview

The build script now properly generates all component configuration files from the main `build_config.json` file. This ensures a single source of truth for all deployment configurations.

## What Gets Generated

### Distributed Mode

When building in distributed mode (`--mode distributed`), the build script generates:

1. **Master Server Configuration** (`build/configs/master_config.json`)
   - JWT secret from `deployment.master.jwt_secret`
   - Bind address and port
   - TLS certificate paths
   - Admin credentials
   - Database path
   - DNS servers array with unique API keys

2. **DNS Server Configurations** (one per server: `build/configs/dns_server_<id>_config.json`)
   - Server-specific bind address and port
   - Domain configuration
   - NS records
   - DNS forwarding settings
   - **Master integration**:
     - `master_server`: URL to master server
     - `master_api_key`: Unique API key for authentication
     - `master_server_id`: Server identifier

### Standalone Mode

In standalone mode, no special configuration generation occurs - the DNS server is built with its static `Server/config.json`.

## API Key Generation

Each DNS server receives a **unique API key** generated at build time:

```bash
# Generate 32-character hexadecimal API key
API_KEY=$(openssl rand -hex 16)
```

This key is:
1. Added to the master config's `dns_servers` array
2. Added to the corresponding DNS server's config as `master_api_key`
3. Used for authentication when the DNS server communicates with the master

## Configuration Files Location

After building, configuration files are placed in:
```
build/
├── configs/
│   ├── master_config.json                    # Master server config
│   ├── dns_server_dns-1_config.json          # DNS server 1 config
│   ├── dns_server_dns-2_config.json          # DNS server 2 config
│   └── dns_server_dns-3_config.json          # DNS server 3 config (if 3 servers)
├── master-server-linux                        # Master binary
├── dns-server-dns-1                           # DNS server 1 binary
├── dns-server-dns-2                           # DNS server 2 binary
└── dns-server-dns-3                           # DNS server 3 binary (if 3 servers)
```

## Deployment

When deploying:

1. **Copy the master binary and config together**:
   ```bash
   scp build/master-server-linux user@master:/opt/unkn0wn/
   scp build/configs/master_config.json user@master:/opt/unkn0wn/master_config.json
   ```

2. **Copy each DNS server binary with its matching config**:
   ```bash
   # Server 1
   scp build/dns-server-dns-1 user@server1:/opt/unkn0wn/dns-server
   scp build/configs/dns_server_dns-1_config.json user@server1:/opt/unkn0wn/config.json
   
   # Server 2
   scp build/dns-server-dns-2 user@server2:/opt/unkn0wn/dns-server
   scp build/configs/dns_server_dns-2_config.json user@server2:/opt/unkn0wn/config.json
   ```

3. **Run the binaries**:
   ```bash
   # On master server
   cd /opt/unkn0wn
   ./master-server-linux
   
   # On each DNS server
   cd /opt/unkn0wn
   ./dns-server
   ```

## Configuration Flow

```
build_config.json (single source of truth)
    ↓
build.sh (reads configuration)
    ↓
    ├─→ Generate master_config.json
    │   └─→ Extract JWT secret, bind settings, admin creds
    │       └─→ Generate unique API keys for each DNS server
    │
    └─→ For each DNS server:
        ├─→ Generate unique API key
        ├─→ Create dns_server_<id>_config.json
        │   └─→ Include master URL, API key, server ID
        └─→ Build binary with generated config
```

## Security Considerations

1. **JWT Secret**: Now properly sourced from `build_config.json` instead of being hardcoded
2. **Unique API Keys**: Each DNS server has a different API key, preventing credential reuse
3. **Single Source**: All sensitive configuration in one place (`build_config.json`)
4. **No Defaults**: Master server will fail to start if JWT secret is missing

## Build Steps (Distributed Mode)

The build process for distributed mode:

1. **[1/7]** Embed configuration from `build_config.json`
2. **[2/7]** **Generate configuration files** (NEW)
   - Create `build/configs/` directory
   - Generate `master_config.json` with JWT secret
   - Generate unique API key for each DNS server
   - Generate per-server config files with master integration
3. **[3/7]** Build Master Server
4. **[4/7]** Build DNS Servers (one per domain)
5. **[5/7]** Update Client Configuration (multi-domain)
6. **[6/7]** Build Clients (Linux & Windows)
7. **[7/7]** Build Stager

## Troubleshooting

### "JWT secret not set" error
- **Cause**: `deployment.master.jwt_secret` missing from `build_config.json`
- **Fix**: Add a strong random secret to your config:
  ```bash
  openssl rand -base64 32
  ```

### DNS server can't authenticate with master
- **Cause**: API key mismatch or missing
- **Fix**: 
  1. Check `build/configs/master_config.json` contains the server in `dns_servers` array
  2. Check `build/configs/dns_server_<id>_config.json` has matching `master_api_key`
  3. Rebuild to regenerate fresh API keys

### Config files not generated
- **Cause**: `jq` not installed
- **Fix**: 
  ```bash
  # Debian/Ubuntu
  apt install jq
  
  # macOS
  brew install jq
  ```

### Wrong config deployed to server
- **Cause**: Config file mismatch during deployment
- **Fix**: Always deploy matching pairs:
  - `dns-server-dns-1` → `dns_server_dns-1_config.json`
  - `dns-server-dns-2` → `dns_server_dns-2_config.json`

## Example build_config.json (Distributed)

```json
{
  "deployment": {
    "mode": "distributed",
    "master": {
      "bind_addr": "0.0.0.0",
      "bind_port": 8443,
      "tls_cert": "/etc/certs/master.crt",
      "tls_key": "/etc/certs/master.key",
      "jwt_secret": "your-very-strong-secret-here-32-chars-min",
      "session_timeout": 3600,
      "database_path": "./master.db",
      "admin_username": "admin",
      "admin_password": "changeme",
      "debug": true
    },
    "dns_servers": [
      {
        "id": "dns-1",
        "domain": "secwolf.net",
        "bind_addr": "0.0.0.0",
        "bind_port": 53,
        "ns1": "ns1.secwolf.net",
        "ns2": "ns2.secwolf.net",
        "forward_dns": true,
        "upstream_dns": "8.8.8.8:53",
        "debug": true
      },
      {
        "id": "dns-2",
        "domain": "example.com",
        "bind_addr": "0.0.0.0",
        "bind_port": 53,
        "ns1": "ns1.example.com",
        "ns2": "ns2.example.com",
        "forward_dns": true,
        "upstream_dns": "8.8.8.8:53",
        "debug": true
      }
    ]
  }
}
```

## Configuration Generation Code

The configuration generation happens in `build.sh` at lines ~170-260. Key operations:

1. **Create configs directory**:
   ```bash
   mkdir -p build/configs
   ```

2. **Generate unique API keys**:
   ```bash
   API_KEY=$(openssl rand -hex 16)
   ```

3. **Build master config using jq**:
   ```bash
   jq -n --arg jwt_secret "$JWT_SECRET" ... > build/configs/master_config.json
   ```

4. **Build per-server configs using jq**:
   ```bash
   jq -n --arg master_api_key "$API_KEY" ... > build/configs/dns_server_${ID}_config.json
   ```

## Validation

After building, verify configurations:

```bash
# Check master config has JWT secret
jq '.jwt_secret' build/configs/master_config.json

# Check master config has DNS servers with unique API keys
jq '.dns_servers' build/configs/master_config.json

# Check each DNS server config has master integration
jq '.master_server, .master_api_key, .master_server_id' build/configs/dns_server_dns-1_config.json
```

All API keys should be different, and each DNS server's API key should match its entry in the master config.
