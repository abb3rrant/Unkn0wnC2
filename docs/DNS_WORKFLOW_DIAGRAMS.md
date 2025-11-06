# DNS Workflow Diagrams - Detailed Scenarios

**Date:** November 6, 2025  
**Purpose:** Comprehensive visual diagrams for all DNS communication patterns

---

## 1. Complete Beacon Lifecycle

```mermaid
stateDiagram-v2
    [*] --> Initialization
    Initialization --> FirstCheckin: Beacon starts
    FirstCheckin --> ReceiveDomains: CHK message
    ReceiveDomains --> ActiveBeacon: DOMAINS response
    ActiveBeacon --> CheckingIn: Regular check-ins (60-120s)
    CheckingIn --> TaskReceived: TASK response
    CheckingIn --> CheckingIn: ACK (no tasks)
    TaskReceived --> ExecutingCommand: Execute command
    ExecutingCommand --> ExfiltratingResult: Command complete
    ExfiltratingResult --> SingleChunk: Result < 50 bytes
    ExfiltratingResult --> MultiChunk: Result > 50 bytes
    SingleChunk --> ActiveBeacon: RESULT sent
    MultiChunk --> SendMetadata: Phase 1
    SendMetadata --> SendChunks: Phase 2
    SendChunks --> ActiveBeacon: All chunks sent
    ActiveBeacon --> [*]: Self-destruct command
```

---

## 2. DNS Query Path - Network Level

```mermaid
graph TB
    subgraph "Beacon Network"
        B[Beacon<br/>192.168.1.100]
    end
    
    subgraph "DNS Resolution Chain"
        LR[Local Resolver<br/>192.168.1.1]
        ISP[ISP Recursive<br/>8.8.8.8]
        ROOT[Root Server<br/>.net]
        TLD[TLD Server<br/>.net NS]
    end
    
    subgraph "C2 Infrastructure"
        DNS1[DNS Server 1<br/>secwolf.net]
        DNS2[DNS Server 2<br/>errantshield.com]
        DNS3[DNS Server 3<br/>cryptshield.org]
        MASTER[Master Server<br/>C2 Control]
    end
    
    B -->|1. Query| LR
    LR -->|2. Recursive| ISP
    ISP -->|3. Root lookup| ROOT
    ROOT -->|4. .net NS| TLD
    TLD -->|5. Domain NS| DNS1
    TLD -->|5. Domain NS| DNS2
    TLD -->|5. Domain NS| DNS3
    
    DNS1 <-->|Chunk forwarding| MASTER
    DNS2 <-->|Chunk forwarding| MASTER
    DNS3 <-->|Chunk forwarding| MASTER
    
    DNS1 -->|6. Response| ISP
    ISP -->|7. Cache + Forward| LR
    LR -->|8. Response| B
    
    style B fill:#f96,stroke:#333,stroke-width:3px
    style MASTER fill:#96f,stroke:#333,stroke-width:3px
    style DNS1 fill:#9f6,stroke:#333,stroke-width:2px
    style DNS2 fill:#9f6,stroke:#333,stroke-width:2px
    style DNS3 fill:#9f6,stroke:#333,stroke-width:2px
```

---

## 3. Shadow Mesh in Action - Query Distribution

```mermaid
sequenceDiagram
    participant Beacon
    participant secwolf.net
    participant errantshield.com
    participant cryptshield.org
    participant Master
    
    Note over Beacon: Check-in #1
    Beacon->>Beacon: selectDomain() → secwolf.net
    Beacon->>secwolf.net: CHK query
    secwolf.net-->>Beacon: TASK response
    
    Note over Beacon: Execute task, result = 200 bytes (4 chunks)
    Beacon->>Beacon: Send RESULT_META
    Beacon->>Beacon: selectDomain() → errantshield.com<br/>(excludes last: secwolf.net)
    Beacon->>errantshield.com: RESULT_META
    errantshield.com-->>Beacon: ACK
    
    Note over Beacon: Chunk 1
    Beacon->>Beacon: selectDomain() → cryptshield.org<br/>(excludes last: errantshield.com)
    Beacon->>cryptshield.org: DATA|chunk1
    cryptshield.org->>Master: Forward chunk1
    cryptshield.org-->>Beacon: ACK
    
    Note over Beacon: Chunk 2
    Beacon->>Beacon: selectDomain() → secwolf.net<br/>(excludes last: cryptshield.org)
    Beacon->>secwolf.net: DATA|chunk2
    secwolf.net->>Master: Forward chunk2
    secwolf.net-->>Beacon: ACK
    
    Note over Beacon: Chunk 3
    Beacon->>Beacon: selectDomain() → errantshield.com<br/>(excludes last: secwolf.net)
    Beacon->>errantshield.com: DATA|chunk3
    errantshield.com->>Master: Forward chunk3
    errantshield.com-->>Beacon: ACK
    
    Note over Beacon: Chunk 4
    Beacon->>Beacon: selectDomain() → cryptshield.org<br/>(excludes last: errantshield.com)
    Beacon->>cryptshield.org: DATA|chunk4
    cryptshield.org->>Master: Forward chunk4
    cryptshield.org-->>Beacon: ACK
    
    Note over Master: Reassemble from 3 different sources
    Master->>Master: Collect: chunk1(DNS3) + chunk2(DNS1)<br/>+ chunk3(DNS2) + chunk4(DNS3)
    Master->>Master: Task status: completed
    
    rect rgb(200, 255, 200)
        Note over secwolf.net,cryptshield.org: All DNS servers notified<br/>beacon.CurrentTask cleared
        Master->>secwolf.net: Task completed
        Master->>errantshield.com: Task completed
        Master->>cryptshield.org: Task completed
    end
```

---

## 4. Encryption/Encoding Pipeline - Detailed

```mermaid
flowchart TD
    subgraph "Beacon: Prepare Message"
        A1[Command: CHK|abc1|host|user|linux] --> A2[Add Timestamp]
        A2 --> A3[CHK|abc1|host|user|linux|1730937600]
    end
    
    subgraph "AES-GCM Encryption"
        A3 --> B1[Generate Random Nonce: 12 bytes]
        B1 --> B2[AES-GCM-256 Seal]
        B2 --> B3[nonce||ciphertext||tag]
        B3 --> B4[Total: 12 + len + 16 bytes]
    end
    
    subgraph "Base36 Encoding"
        B4 --> C1[Bytes to BigInt]
        C1 --> C2[BigInt.Text36]
        C2 --> C3[Lowercase string: 0-9a-z only]
    end
    
    subgraph "DNS Label Splitting"
        C3 --> D1[Total length check]
        D1 --> D2{Length > 62?}
        D2 -->|Yes| D3[Split: chars0-61]
        D2 -->|No| D5[Single label]
        D3 --> D4[Remaining chars]
        D4 --> D2
        D5 --> D6[labels array]
        D3 --> D6
    end
    
    subgraph "DNS Query Construction"
        D6 --> E1[Join labels with dots]
        E1 --> E2[Append timestamp]
        E2 --> E3[Append domain]
        E3 --> E4[Final FQDN]
        E4 --> E5[TXT query packet]
    end
    
    E5 --> F[Send to DNS]
    
    style B2 fill:#f9f,stroke:#333,stroke-width:3px
    style C2 fill:#bbf,stroke:#333,stroke-width:3px
    style E4 fill:#9f9,stroke:#333,stroke-width:3px
```

**Example with Real Data:**
```
Input:     "CHK|abc1|hostname|username|linux"
           ↓ Add timestamp
Timestamped: "CHK|abc1|hostname|username|linux|1730937600"
           ↓ AES-GCM encrypt (with random nonce)
Encrypted: [12-byte nonce][ciphertext][16-byte tag]
           = 0x3f8a9b2c1d5e... (52 bytes)
           ↓ Base36 encode
Base36:    "8xk2m9p4qr7n3l5k8w9t2v6h4j3g7f5d9s8a1k0m..."
           (length ~84 chars)
           ↓ Split into 62-char labels
Labels:    ["8xk2m9p4qr7n3l5k8w9t2v6h4j3g7f5d9s8a1k0m...(62)",
            "2b4x9k7l3m5n8p..."]
           ↓ Join and add domain
Query:     "8xk2m9p4qr...k0m.2b4x9k7l...p.1730937600.secwolf.net"
           ↓ DNS TXT query
```

---

## 5. Server-Side Processing Flow

```mermaid
flowchart TD
    A[Receive UDP Packet] --> B[Parse DNS Header]
    B --> C{Valid header?}
    C -->|No| Z[Drop packet]
    C -->|Yes| D[Parse Questions]
    
    D --> E{Questions == 1?}
    E -->|No| Z
    E -->|Yes| F[Extract QNAME]
    
    F --> G[Split by dots]
    G --> H[Identify domain suffix]
    H --> I{Our domain?}
    I -->|No| J{Forward DNS enabled?}
    J -->|Yes| K[Forward to 8.8.8.8]
    J -->|No| L[REFUSED]
    I -->|Yes| M[Extract subdomain]
    
    M --> N{Legitimate name?}
    N -->|Yes ns1, www, etc| O[Return static record]
    N -->|No| P[Check last label]
    
    P --> Q{Numeric timestamp?}
    Q -->|Yes| R[Remove timestamp]
    Q -->|No| S[Keep all labels]
    R --> T[Join labels]
    S --> T
    
    T --> U{Looks like Base36?}
    U -->|No| Z
    U -->|Yes| V[Base36 decode]
    
    V --> W{Decode success?}
    W -->|No| Z
    W -->|Yes| X[Try AES-GCM decrypt]
    
    X --> Y{Decrypt success?}
    Y -->|Yes| AA[Parse as beacon message]
    Y -->|No| AB[Try plain decode - stager]
    
    AA --> AC{Message type?}
    AC -->|CHK| AD[handleCheckin]
    AC -->|RESULT| AE[handleResult]
    AC -->|DATA| AF[handleData]
    AC -->|RESULT_META| AG[handleResultMeta]
    
    AD --> AH[Format response]
    AE --> AH
    AF --> AH
    AG --> AH
    
    AH --> AI[Encrypt response]
    AI --> AJ[Base36 encode]
    AJ --> AK[Build TXT record]
    AK --> AL[Build DNS response]
    AL --> AM[Send UDP response]
    
    AB --> AN[handleStagerRequest]
    AN --> AO[Plain Base36 response]
    AO --> AK
    
    style X fill:#f9f,stroke:#333,stroke-width:3px
    style V fill:#bbf,stroke:#333,stroke-width:3px
    style AC fill:#9f6,stroke:#333,stroke-width:3px
```

---

## 6. Chunk Reassembly at Master

```mermaid
flowchart TD
    subgraph "DNS Server 1"
        D1[Receive chunk 1] --> M1[Forward to Master]
        D1B[Receive chunk 4] --> M1B[Forward to Master]
    end
    
    subgraph "DNS Server 2"
        D2[Receive chunk 2] --> M2[Forward to Master]
        D2B[Receive chunk 5] --> M2B[Forward to Master]
    end
    
    subgraph "DNS Server 3"
        D3[Receive chunk 3] --> M3[Forward to Master]
    end
    
    subgraph "Master Server"
        M1 --> DB[(Task DB)]
        M1B --> DB
        M2 --> DB
        M2B --> DB
        M3 --> DB
        
        DB --> CHK{All chunks<br/>received?}
        CHK -->|No| WAIT[Wait for more]
        CHK -->|Yes| SORT[Sort by chunk index]
        
        SORT --> JOIN[Join chunks]
        JOIN --> RES[Complete result]
        RES --> SAVE[Save to task]
        SAVE --> STATUS[Update: completed]
        
        STATUS --> NOTIFY[Notify all DNS servers]
    end
    
    subgraph "Notification"
        NOTIFY --> N1[DNS1: Clear CurrentTask]
        NOTIFY --> N2[DNS2: Clear CurrentTask]
        NOTIFY --> N3[DNS3: Clear CurrentTask]
    end
    
    style DB fill:#96f,stroke:#333,stroke-width:3px
    style RES fill:#9f6,stroke:#333,stroke-width:3px
```

---

## 7. Error Scenarios and Recovery

### 7.1 Chunk Lost During Transmission

```mermaid
sequenceDiagram
    participant Beacon
    participant DNS1
    participant DNS2
    participant Master
    
    Note over Beacon: Send 5 chunks total
    
    Beacon->>DNS1: Chunk 1
    DNS1->>Master: Forward chunk 1 ✓
    DNS1-->>Beacon: ACK
    
    Beacon->>DNS2: Chunk 2
    Note over DNS2: Network error!
    DNS2--xBeacon: Timeout
    
    Note over Beacon: Retry chunk 2
    Beacon->>DNS2: Chunk 2 (retry)
    DNS2->>Master: Forward chunk 2 ✓
    DNS2-->>Beacon: ACK
    
    Beacon->>DNS1: Chunk 3
    DNS1->>Master: Forward chunk 3 ✓
    DNS1-->>Beacon: ACK
    
    Beacon->>DNS2: Chunk 4
    DNS2->>Master: Forward chunk 4 ✓
    DNS2-->>Beacon: ACK
    
    Beacon->>DNS1: Chunk 5
    DNS1->>Master: Forward chunk 5 ✓
    DNS1-->>Beacon: ACK
    
    Note over Master: All 5 chunks received<br/>after retry
    Master->>Master: Reassemble complete
```

### 7.2 DNS Server Failure During Chunking

```mermaid
sequenceDiagram
    participant Beacon
    participant DNS1
    participant DNS2
    participant DNS3
    participant Master
    
    Beacon->>DNS1: Chunk 1
    DNS1->>Master: Forward ✓
    DNS1-->>Beacon: ACK
    
    Note over DNS2: Server crash!
    
    Beacon->>DNS2: Chunk 2
    Note over Beacon: All retries fail
    Beacon->>Beacon: Mark DNS2 failed
    
    Note over Beacon: Failover to different domain
    Beacon->>DNS3: Chunk 2 (failover)
    DNS3->>Master: Forward ✓
    DNS3-->>Beacon: ACK
    
    Beacon->>DNS1: Chunk 3
    DNS1->>Master: Forward ✓
    DNS1-->>Beacon: ACK
    
    Note over Beacon: DNS2 still excluded
    Beacon->>DNS3: Chunk 4
    DNS3->>Master: Forward ✓
    DNS3-->>Beacon: ACK
    
    Note over Master: Received from DNS1 + DNS3 only
    Master->>Master: Reassemble complete
```

### 7.3 Partial Result Timeout

```mermaid
sequenceDiagram
    participant Beacon
    participant DNS Server
    participant Master
    
    Beacon->>DNS Server: RESULT_META (5 chunks)
    DNS Server->>DNS Server: Create ExpectedResult
    DNS Server-->>Beacon: ACK
    
    Beacon->>DNS Server: Chunk 1
    DNS Server->>Master: Forward
    DNS Server-->>Beacon: ACK
    
    Beacon->>DNS Server: Chunk 2
    DNS Server->>Master: Forward
    DNS Server-->>Beacon: ACK
    
    Note over Beacon: Network failure!<br/>Beacon goes offline
    
    Note over DNS Server: Wait 30 minutes...
    
    DNS Server->>DNS Server: Timeout expired
    DNS Server->>DNS Server: Count received: 2/5
    DNS Server->>DNS Server: Save partial result
    DNS Server->>DNS Server: Update status: partial
    DNS Server->>Master: Report partial result
    
    Note over Master: UI shows:<br/>"Partial (2/5 chunks)"
```

---

## 8. Timing and Jitter Diagram

```mermaid
gantt
    title Beacon Communication Timeline (with OPSEC jitter)
    dateFormat X
    axisFormat %S
    
    section Check-ins
    Check-in 1 (CHK)           :0, 1
    Sleep (87s)                :1, 87
    Check-in 2 (CHK → TASK)    :88, 1
    
    section Task Execution
    Execute command            :89, 45
    
    section Exfiltration
    Send RESULT_META           :134, 1
    Jitter pause               :135, 2
    Chunk 1                    :137, 1
    Jitter pause               :138, 3
    Chunk 2                    :141, 1
    Jitter pause               :142, 2
    Chunk 3                    :144, 1
    Jitter pause               :145, 4
    Chunk 4                    :149, 1
    Jitter pause               :150, 2
    Chunk 5                    :152, 1
    Burst pause (10 chunks)    :153, 5
    Chunk 6                    :158, 1
    
    section Next Check-in
    Sleep (95s)                :159, 95
    Check-in 3 (CHK)           :254, 1
```

**Timing Breakdown:**
- Check-in intervals: 60-120s (randomized)
- Chunk jitter: 1-5s between chunks
- Burst pause: 5s every 10 chunks
- Total stealth: Unpredictable timing patterns

---

## 9. Complete Protocol State Machine

```mermaid
stateDiagram-v2
    [*] --> Idle
    
    Idle --> Encrypting: Send command
    Encrypting --> Encoding: AES-GCM done
    Encoding --> DomainSelect: Base36 done
    DomainSelect --> QueryBuild: Domain selected
    QueryBuild --> Sending: FQDN constructed
    
    Sending --> WaitResponse: UDP sent
    WaitResponse --> Receiving: Response arrived
    WaitResponse --> Retry: Timeout
    
    Retry --> DomainSelect: Attempt < 3
    Retry --> FailoverDomain: Attempt = 3
    FailoverDomain --> QueryBuild: New domain
    
    Receiving --> Decoding: Packet valid
    Decoding --> Decrypting: Base36 decoded
    Decrypting --> Parsing: AES-GCM decrypted
    Parsing --> Success: Valid response
    
    Success --> Idle: Done
    
    Receiving --> Retry: Invalid packet
    Decoding --> Retry: Decode error
    Decrypting --> Retry: Decrypt error
    
    note right of Encrypting
        AES-GCM with random nonce
        + SHA256-derived key
    end note
    
    note right of DomainSelect
        Shadow Mesh:
        Excludes last domain
        Random/RoundRobin/Weighted
    end note
    
    note right of Retry
        Exponential backoff:
        1s, 4s, 9s (max 10s)
    end note
```

---

## 10. DNS Packet Structure

```mermaid
graph TD
    subgraph "DNS Request Packet"
        H[Header: 12 bytes]
        Q[Question Section]
        H --> Q
        
        subgraph "Header"
            H1[ID: 2 bytes]
            H2[Flags: 2 bytes<br/>QR=0 RD=1]
            H3[QDCOUNT: 1]
            H4[ANCOUNT: 0]
            H5[NSCOUNT: 0]
            H6[ARCOUNT: 0]
        end
        
        subgraph "Question"
            Q1[QNAME: variable<br/>e.g. label1.label2.timestamp.domain]
            Q2[QTYPE: 16 TXT]
            Q3[QCLASS: 1 IN]
        end
    end
    
    subgraph "DNS Response Packet"
        RH[Header: 12 bytes]
        RQ[Question: echoed]
        RA[Answer Section]
        RH --> RQ
        RQ --> RA
        
        subgraph "Response Header"
            RH1[ID: same]
            RH2[Flags: 2 bytes<br/>QR=1 AA=1]
            RH3[QDCOUNT: 1]
            RH4[ANCOUNT: 1]
        end
        
        subgraph "Answer"
            RA1[NAME: compressed ptr]
            RA2[TYPE: 16 TXT]
            RA3[CLASS: 1 IN]
            RA4[TTL: 1 sec]
            RA5[RDLENGTH: variable]
            RA6[RDATA: TXT strings<br/>Length-prefixed]
        end
    end
    
    style H fill:#f96,stroke:#333,stroke-width:2px
    style RH fill:#9f6,stroke:#333,stroke-width:2px
    style Q1 fill:#bbf,stroke:#333,stroke-width:2px
    style RA6 fill:#bbf,stroke:#333,stroke-width:2px
```

**Packet Size Constraints:**
- UDP: 512 bytes recommended, 1500 bytes max (MTU)
- DNS Header: 12 bytes fixed
- QNAME: ~200 bytes (our queries)
- Answer: ~300 bytes (our responses)
- **Total:** Typically < 512 bytes (fits in single UDP packet)

---

## Summary

These diagrams illustrate:

✅ **Complete beacon lifecycle** from first check-in to self-destruct  
✅ **Network-level DNS resolution** showing all hops  
✅ **Shadow Mesh in action** with domain rotation  
✅ **Encryption pipeline** with real data examples  
✅ **Server-side processing** from packet to response  
✅ **Master reassembly** from distributed chunks  
✅ **Error scenarios** with retry and failover  
✅ **Timing patterns** with OPSEC jitter  
✅ **Protocol state machine** for client/server  
✅ **DNS packet structure** at byte level  

All workflows verified and working correctly! 🎉

---

*Generated by GitHub Copilot - November 6, 2025*
