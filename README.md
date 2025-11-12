# 🕵️ Unkn0wnC2
DNS-based Command & Control framework utilizing multiple authoritative DNS servers and encrypted C2 communications.

This DNS C2 implementation's strengths comes from it's malleable C2 timing and mesh architecture. 

Many C2s can utilize DNS for covert communications, but the exfil/task timings aren't usually adjustable without changing code directly. This C2 allows you to change the timing of exfil during the build process. Keeping your exfil slow is key to staying stealthy as common C2s send outputs/exfil quickly, alerting Blue Teams on large ammounts of DNS traffic in a short period of time. All DNS C2s utilize 1 domain per beacon, while this implementation can utilize many, and also alows for domains to dynamically be added to existing beacons mid operation.

![Unkn0wnC2](assets/unkn0wnc2.png)

---

## ⚠️ Legal Disclaimer

**FOR AUTHORIZED SECURITY TESTING ONLY**

This software is provided for educational and authorized security testing purposes only. Users must:

- Obtain explicit written authorization before deployment
- Comply with all applicable local, state, and federal laws
- Use only in controlled environments with proper authorization
- Understand that unauthorized access to computer systems is illegal

**The author is not responsible for misuse or illegal activity. Use at your own risk.**

---
## 🚀 Quick Deployment

1. **Clone this repo**
```bash
git clone https://github.com/abb3rrant/Unkn0wnC2
cd Unkn0wnC2
```

2. **Run the build script**
```bash
sudo chmod +x build.sh
sudo ./build.sh
```
> This will:
> - Compile and install the Archon server to `/usr/bin/unkn0wnc2`
> - Auto-generate secure credentials (displayed once)
> - Create TLS certificates for the Archon server
> - Install all dependencies for building and Archon WebUI to `/opt/unkn0wnc2/`

3. **Save the admin password in the build scripts output, this will be used to access the WebUI.**

3. **Start the Archon Server**
```bash
sudo unkn0wnc2 --bind-addr <interface IP to bind to> --bind-port <port>
```

4. **Access web UI: `https://<server-ip>:<port>/`**  

5. **Change admin password and create operators**


5. **Build components (DNS servers, clients, stagers) through the web interface.**

---

## 🏗️ Protocol Architecture

### Communication Flow
![Communications Flow](assets/communication_flow.png)

### 🔐 Encoding Pipeline

![Encoding Pipeline](assets/encoding_pipeline.png)

### 📨 Message Format

![Message Format](assets/message_format.png)

### 🎭 Authoritative DNS Server Logic Flow

![Authoritative DNS Server Logic Flow](assets/logic_flow.png)

### Malleable Timing (stager / client / exfil)

This project exposes several timing parameters that are intentionally malleable to tune stealth vs throughput. Defaults are set in build_config.json and in the Stager build defaults.

Key parameters and defaults (units):

- Stager
  - jitter_min_ms = 1000 (1.0 s)
  - jitter_max_ms = 2000 (2.0 s)
  - chunks_per_burst = 5
  - burst_pause_ms = 12000 (12 s)
  - retry_delay_seconds = 3
  - max_retries = 5

- Client check-in
  - sleep_min = 60 (60 s)
  - sleep_max = 120 (120 s)

- Client exfil
  - exfil_jitter_min_ms = 10000 (10 s)
  - exfil_jitter_max_ms = 30000 (30 s)
  - exfil_chunks_per_burst = 5
  - exfil_burst_pause_ms = 120000 (120 s)

How the pieces interact (approximate calculations):
- Number of bursts for N chunks: bursts = ceil(N / chunks_per_burst)
- Average jitter (ms) = (jitter_min_ms + jitter_max_ms) / 2
- Stager total time ≈ N * RTT_seconds_per_chunk + bursts * ((avg_jitter_ms + burst_pause_ms) / 1000)
  - Example (stager defaults, 100 chunks): avg_jitter = 1.5 s, burst pause = 12 s → per-burst pause ≈ 13.5 s
    - bursts = 20 → pause_time ≈ 270 s
    - transfer_time ≈ 100 s → total ≈ 370 s (~6 min 10 s)

- Exfil (client) will be significantly slower with larger jitter/pause values:
  - Example (exfil defaults, 100 chunks): avg_jitter = 20 s, burst pause = 120 s → per-burst pause ≈ 140 s
    - bursts = 20 → pause_time ≈ 2800 s (~46 min 40 s)
    - transfer_time ≈ 100 s → total ≈ 2900 s (~48 min 20 s)

### Build Output
```
build/
├── dns-server-linux
├── dns-client-linux
├── dns-client-windows.exe
└── Stager
    ├── stager-linux-x64
    └── stager-windows-x64.exe
```

---

## 🎮 C2 Console Commands

```
beacons              List all active beacons
task <id> <cmd>      Queue command for beacon
tasks                Show all tasks and status
result <task_id>     Display task output
history <id> [n]     Show task history for beacon (default: 50)
search <status> [n]  Search tasks by status (pending/sent/completed/failed)
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

**Version:** 0.2.0  
**License:** Use for authorized security testing only  

---


