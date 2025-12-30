# Agent Context: Unkn0wnC2

## Overview

Unkn0wnC2 is a DNS-based Command & Control framework for Red Team adversary emulation. It uses DNS TXT queries for C2 communications with AES-GCM encryption and Base36 encoding.

## Architecture

```
┌─────────────┐     DNS TXT      ┌─────────────┐      HTTPS       ┌─────────────┐
│   Beacon    │ ───────────────► │ DNS Server  │ ───────────────► │   Archon    │
│  (Client)   │ ◄─────────────── │  (Server)   │ ◄─────────────── │  (Master)   │
└─────────────┘                  └─────────────┘                  └─────────────┘
      │                                │                                │
      │                                │                                │
┌─────────────┐                  ┌─────────────┐                  ┌─────────────┐
│   Stager    │                  │  Database   │                  │   WebUI     │
│     (C)     │                  │  (SQLite)   │                  │             │
└─────────────┘                  └─────────────┘                  └─────────────┘
```

## Components

| Directory | Language | Purpose |
|-----------|----------|---------|
| `Archon/` | Go | Master server - WebUI, API, operator management, binary builder |
| `Server/` | Go | DNS server - Handles C2 traffic, caches stager chunks, forwards to Archon |
| `Client/` | Go | Beacon agent - Executes commands, exfiltrates data over DNS |
| `Stager/` | C | Lightweight loader - Downloads beacon via DNS in chunks |
| `exfil-client/` | Rust | Standalone file exfiltration tool |
| `tools/builder/` | Go | Build utilities |

## Key Features

### Shadow Mesh
Multi-domain support allowing beacons to use multiple DNS servers. Domains can be added/removed dynamically without restarting beacons.

### Malleable Timing
Configurable timing parameters to evade detection:
- `sleep_min/max` - Beacon check-in intervals
- `jitter_min/max_ms` - Random delay between bursts
- `chunks_per_burst` - Chunks requested rapidly before pause
- `burst_pause_ms` - Pause between bursts

### Encryption Pipeline
- **Beacon**: Plaintext → AES-GCM → Base36 → DNS labels
- **Stager**: Plaintext → Base36 (no encryption, smaller binary)

## Protocol Messages

### Beacon → Server
| Type | Format | Purpose |
|------|--------|---------|
| CHK | `CHK\|id\|host\|user\|os\|arch` | Check-in, poll for tasks |
| RESULT_META | `RESULT_META\|id\|taskID\|size\|chunks` | Announce chunked result |
| DATA | `DATA\|id\|taskID\|idx\|chunk` | Submit result chunk |
| RESULT_COMPLETE | `RESULT_COMPLETE\|id\|taskID\|chunks` | Signal completion |

### Stager → Server
| Type | Format | Purpose |
|------|--------|---------|
| STG | `STG\|ip\|os\|arch` | Initialize stager session |
| CHUNK | `CHUNK\|idx\|ip\|sessionID` | Request specific chunk |

### Server → Client
| Type | Format | Purpose |
|------|--------|---------|
| TASK | `TASK\|taskID\|command` | Deliver task |
| ACK | `ACK` | Acknowledge (no tasks) |
| META | `META\|sessionID\|totalChunks` | Stager session info |
| CHUNK | `CHUNK\|base64data` | Stager chunk data |

## Database Schema (Server)

Key tables in `Server/db.go`:
- `beacons` - Registered beacon info
- `tasks` - Task queue and results
- `stager_chunk_cache` - Cached stager binary chunks
- `exfil_sessions` - Exfil client uploads
- `exfil_chunks` - Exfil data chunks

## Configuration

### Server (DNS)
Embedded at build time via `config.json`:
- `domain` - Authoritative domain
- `encryption_key` - AES key (shared with beacon)
- `master_server` - Archon URL
- `stager_jitter` - Timing configuration

### Archon (Master)
`master_config.json`:
- `bind_addr/port` - Listen address
- `session_timeout` - Operator session TTL
- `operators` - User credentials

## Common Issues

### Stager Dies with Slow Timings (FIXED 2025-12-10)
**Status**: Fixed and validated - tested to 50+ chunks with slow timings.

**Cause 1**: Race condition in stager chunk cache - DELETE + INSERT during refresh caused brief unavailability.
**Fix**: Changed to `INSERT OR REPLACE` (atomic upsert) in `Server/db.go`.

**Cause 2**: Stager didn't handle RETRY/transient errors from DNS server.
**Fix**: Added per-chunk retry loop in `Stager/stager.c` to handle:
- `RETRY` responses (cache not synced yet)
- Empty/malformed responses (transient network issues)
- Retry with exponential backoff before giving up

**Cause 3**: Progress reporting only happened every 100 chunks - too infrequent for slow timings.
**Fix**: Changed to report every 10 chunks in `Server/c2_manager.go` (all code paths).

### Session Timeouts
- `StagerSessionTimeout` = 3 hours (Server/constants.go)
- `ExfilSessionTimeout` = 15 minutes
- Sessions are recreated from cache if expired

### Progress Reporting
Stager progress reported to Master every 10 chunks (configurable in `c2_manager.go` line ~2278).

## Build Commands

```bash
# Build all components
./build.sh

# Manual builds
cd Server && go build -o dns-server .
cd Archon && go build -o unkn0wnc2 .
cd Stager && make
cd exfil-client && cargo build --release
```

## Builder UI Options

Operators build components via Archon WebUI (`/builder`). Available options:

### Beacon Client
| Option | Values | Effect |
|--------|--------|--------|
| Platform | linux, windows | Target OS |
| Architecture | amd64, 386, arm64, armv7l, arm | Target arch |
| Static Linking | ✓/✗ | CGO_ENABLED=0 for static |
| Check-in Interval | min/max seconds | Sleep between check-ins |

### Exfil Client
| Option | Values | Effect |
|--------|--------|--------|
| Platform | linux, windows | Target OS |
| Architecture | amd64, 386, arm64, armv7l, arm | Target arch |
| Static Linking | ✓/✗ | musl (static) vs glibc (dynamic) |
| Use TXT Records | ✓/✗ | TXT ACK vs A record IP+1 ACK |
| Jitter | min/max ms | Delay between chunks |
| Chunks Per Burst | count | Rapid chunks before pause |
| Burst Pause | ms | Pause between bursts |

### Stager
| Option | Values | Effect |
|--------|--------|--------|
| Client Binary | dropdown | Pre-built beacon to stage |
| Platform | linux, windows | Target OS |
| Architecture | amd64, 386, arm64, armv7l, arm | Target arch |
| Static Linking | ✓/✗ | -static flag for gcc |
| Payload URL | URL (optional) | HTTP fallback instead of DNS |

## Testing

```bash
cd Server && go test -v
cd Client && go test -v
```

## File Locations

| File | Purpose |
|------|---------|
| `Server/c2_manager.go` | Core C2 logic, message processing |
| `Server/dns.go` | DNS parsing, exfil frame handling |
| `Server/db.go` | SQLite operations, caching |
| `Server/constants.go` | Timeouts, limits, protocol constants |
| `Server/main.go` | DNS server entry, Master sync |
| `Archon/api.go` | REST API handlers |
| `Archon/db.go` | Master database operations |
| `Stager/stager.c` | C stager implementation |

## Recent Changes (2025-12)

### Shadow Mesh Task ID Sync (FIXED)
**Problem**: Tasks assigned via one DNS server weren't visible to others in Shadow Mesh.
**Fix**: Added `masterTaskIDs` map to track Master↔Local task ID mapping. All DNS servers now sync task IDs from Master and can forward results correctly.

### Exfil ACK Modes (Configurable)
**Change**: Exfil client now supports both A record and TXT record ACK modes.
- **A Records (default)**: ACK = server IP + 1 (e.g., server `1.2.3.4` → ACK `1.2.3.5`)
- **TXT Records (optional)**: ACK = "ACK" text, NACK = "NACK" text
- Operators choose mode via "Use TXT Records" checkbox in builder UI

### Static Linking Options (NEW)
**Change**: Build UI now offers static vs dynamic linking for all components.
- **Beacon Client (Go)**: `CGO_ENABLED=0` for static, `CGO_ENABLED=1` for dynamic
- **Exfil Client (Rust)**: musl targets for static, glibc targets for dynamic
- **Stager (C)**: `-static` flag for static linking
- Default: Static (works on any glibc version, slightly larger binaries)
- Operators toggle via "Static Linking" checkbox in builder UI

### Memory Leak Fixes
- `masterTaskIDs` - Now cleaned up when tasks complete
- `pendingLabelChunks` - Cleared after assembly to prevent unbounded growth

### Report Page Enhancements
- Shows total history (not just active sessions)
- Added timeline view showing chronological events
- Filter by event type: Beacons, Tasks, Exfils, Stagers

### DNS Abuse Prevention (Rate Limiting)
**Problem**: DNS servers were being abused by bots for resolution (amplification attacks).
**Fix**: Added `ForwardingRateLimiter` in `Server/main.go`:
- Threshold: 50 queries/sec (configurable)
- Pause duration: 60 seconds when exceeded
- Only affects forwarding to upstream - C2 comms unaffected
- Removed open resolver fallback (random IP for unknown queries)

### Test Coverage
Comprehensive test suite in `Server/server_test.go`:
- Crypto (AES-GCM, Base36 encoding)
- Beacon registration, tasking, result processing
- Stager session creation, message parsing
- Exfil frame processing, tag tracking
- DNS parsing helpers
- Rate limiter functionality
- Full integration workflow

## Related Docs

- `docs/TTPS.md` - MITRE ATT&CK mapping
- `docs/common-dns-detections.md` - IDS evasion reference
