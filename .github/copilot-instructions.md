# Unkn0wnC2 - AI Coding Instructions

## Project Overview
This is a DNS-based Command & Control (C2) framework that operates as an authoritative DNS server for stealth communications. The system uses encrypted DNS queries to tunnel C2 traffic, blending with legitimate DNS operations.

## Architecture Components

### Server (`Server/`)
- **`main.go`**: Authoritative DNS server handling both legitimate DNS and C2 traffic
- **`c2_manager.go`**: Core C2 logic managing beacons, tasks, and chunked data reassembly  
- **`console.go`**: Interactive management console with commands: `beacons`, `task <id> <cmd>`, `tasks`, `result <task_id>`
- **`crypto.go`**: AES-GCM encryption + Base36 encoding for DNS-safe C2 data
- **`config.go`**: Configuration management with JSON file support and environment overrides

### Clients
- **`Client/`**: Original client with external `config.json` dependency
- **`New_Client/`**: Standalone client with embedded configuration via build-time code generation

## Critical Protocol Details

### DNS Communication Flow
1. **Subdomain Encoding**: C2 data encrypted (AES-GCM) → Base36 encoded → split into 62-char DNS labels
2. **Cache Busting**: Timestamp subdomains prevent DNS resolver caching: `<data>.<timestamp>.domain.net`
3. **Traffic Blending**: Legitimate DNS queries forwarded to upstream (8.8.8.8) for stealth
4. **Two-Phase Chunking**: Large results use `RESULT_META` → multiple `DATA` chunks for reliable exfiltration

### Message Format (Pipe-Delimited, Encrypted Before Encoding)
- **Check-in**: `CHK|beaconID|hostname|username|os`
- **Task Distribution**: `TASK|taskID|command`
- **Result Exfiltration**: `RESULT|beaconID|taskID|output` (small) or `RESULT_META|beaconID|taskID|size|chunks` + `DATA|beaconID|taskID|index|chunk`

## Development Patterns

### Configuration Management
- **Server**: Uses `DefaultConfig()` + JSON file overlay pattern in `config.go`
- **New_Client**: Build-time config embedding via `tools/generate_config.go` → `config.go`
- **Critical**: Encryption keys must match between server and all clients

### Build Process
- **Server**: `cd Server && go build -o dns-server .`
- **Client**: `cd Client && go build -o dns-client .` (requires runtime `config.json`)
- **New_Client**: Run `build.bat`/`build.sh` (embeds `build_config.json` at compile time)

### Beacon Management
- Beacons auto-register on first check-in with 4-char MD5-based ID
- Task queue per beacon with status tracking: `pending` → `sent` → `completed`
- Randomized check-in intervals (sleep_min to sleep_max) for OPSEC

### Error Handling Conventions
- **Server**: Debug logging controlled by `cfg.Debug` flag
- **Clients**: Silent failures for stealth (especially New_Client)
- **DNS Parsing**: Legitimate traffic detection via subdomain pattern analysis

## Key Implementation Notes

### Crypto Layer (`crypto.go`)
- **AES Key Derivation**: SHA256 hash of passphrase string
- **Encoding Pipeline**: `Data` → `AES-GCM` → `Base36` → `DNS Labels (62 chars max)`
- **Backward Compatibility**: `legacyDecodeBeaconData()` fallback for migration

### DNS Server Logic (`main.go`)
- **Query Processing**: Parse DNS packet → Extract subdomain → Decrypt/decode → Route to C2Manager
- **Response Generation**: C2 response → Encrypt/encode → TXT record format
- **Zone Management**: Auto-populate NS/A records from config for domain legitimacy

### Console Interface
Essential commands for C2 operations:
```
beacons          # List all active beacons
task <id> <cmd>  # Queue command for beacon
tasks            # Show all task statuses  
result <task_id> # Display completed task output
```

## Common Development Tasks

### Adding New Message Types
1. Add case in `c2_manager.go:processBeaconQuery()`
2. Implement handler function following `handleCheckin()` pattern
3. Update client parsing logic in relevant `main.go`

### Configuration Changes
- **Server**: Update `DefaultConfig()` and JSON schema in `config.go`
- **New_Client**: Modify `BuildConfig` struct in `tools/generate_config.go`

### Debugging DNS Issues
- Enable debug mode: `cfg.Debug = true` or `-d` flag
- Check subdomain pattern matching in `isLegitimateSubdomain()`
- Verify encryption key consistency across components

### Testing
- **Local Testing**: Set `bind_addr: "127.0.0.1"` and `domain: "test.local"`
- **Network Testing**: Requires proper DNS delegation and glue records
- **Encryption Testing**: Use matching keys and verify Base36 encoding/decoding

## Security Considerations
- Change default encryption key: `"MySecretC2Key123!@#DefaultChange"`
- Enable DNS forwarding (`forward_dns: true`) for traffic blending
- Use realistic domain names and NS records for operational security
- Implement proper domain delegation with registrar glue records

## Development Roadmap & Requirements

### Security & Key Management
- **Build-time Key Generation**: Encryption keys should be generated at build time rather than using defaults
- **DNS Infrastructure**: Server acts as authoritative DNS for domain, forwarding legitimate queries to 8.8.8.8

### Planned Features
- **File Upload/Download**: Implement file transfer capabilities through DNS protocol
- **Lightweight Stager**: Super lightweight client that calls server with `STG|DEPLOY|UNKN0WN` encoded domain to retrieve compressed full client via TXT response
- **Beacon Health Checks**: Implement beacon and task health monitoring
- **Cross-Platform Clients**: Support Windows and Linux client builds

### Production Requirements
- **Automated Builds**: Implement automated build pipelines for production-ready tooling
- **Minimal Client Logging**: Clients should have no logging for operational security
- **Strategic Server Logging**: Server should log only essential events:
  - New beacon registered
  - Task sent/completed/failed
  - Beacon declared dead
  - Debug flag available for verbose logging (all DNS requests and handling)

### Current Maintenance Focus
- Maintain existing DNS C2 functionality
- Preserve authoritative DNS server operation with legitimate traffic forwarding
- Keep beacon management and task distribution stable