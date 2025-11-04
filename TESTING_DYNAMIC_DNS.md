# Testing Dynamic DNS Server Distribution

## Overview
This document describes how to test the dynamic DNS server distribution feature, which allows beacons to automatically learn about new DNS servers as they're added to the infrastructure.

## What Was Implemented

### ✅ UI Changes
1. **Black/Red Theme**: Changed accent color from green to red throughout the UI
2. **Stranger Things Font**: Applied horror-style fonts (Nosifer, Creepster) to main headings
3. **Dashboard Cleanup**: Removed beacon count column from DNS servers table

### ✅ Dynamic DNS Distribution System

#### Master Server (`Master/`)
- **Database Methods**:
  - `GetEnabledDNSDomains()`: Returns list of active DNS domains
  - `CreateBroadcastTask(command, createdBy)`: Creates task for all active beacons
  - `UpdateDNSServerCheckin(dnsServerID)`: Returns `(isFirstCheckin bool, error)`

- **API Handler** (`api.go:handleDNSServerCheckin`):
  - Detects first checkin from new DNS server
  - Automatically broadcasts domain list to all active beacons
  - Creates `update_domains:[...]` tasks with JSON array of domains

#### Client (`Client/main.go`)
- **Command Handler**:
  - Detects `update_domains:` prefix in task commands
  - Parses JSON array of domains
  - Updates internal domain rotation list
  - Sends acknowledgment: "domains_updated"

## Test Procedure

### Prerequisites
1. Master server running with TLS certificates
2. At least 2 DNS servers initially deployed (e.g., dns-1, dns-2)
3. At least 1 beacon deployed and checking in

### Test Steps

#### 1. Initial Setup
```bash
# Start Master server
cd build
./master-server-linux

# Verify Master is running
curl -k https://127.0.0.1:8443/health
```

#### 2. Deploy Initial DNS Servers
```bash
# On DNS server 1 (secwolf.net)
./dns-server-dns-1

# On DNS server 2 (errantshield.com)
./dns-server-dns-2

# Both should check in successfully
```

#### 3. Deploy Beacon
```bash
# On target machine
./dns-client-linux

# Beacon should:
# - Check in via one of the existing domains
# - Show up in Master dashboard
# - Rotate between secwolf.net and errantshield.com
```

#### 4. Add Third DNS Server
```bash
# Build a new DNS server (e.g., dns-3 for newdomain.com)
# Edit build_config.json to add:
{
  "deployment": {
    "dns_servers": [
      { "id": "dns-1", "domain": "secwolf.net", ... },
      { "id": "dns-2", "domain": "errantshield.com", ... },
      { "id": "dns-3", "domain": "newdomain.com", "bind_addr": "10.0.0.3", "bind_port": 53 }
    ]
  }
}

# Rebuild
./build.sh

# Deploy new server
./dns-server-dns-3
```

#### 5. Verify Domain Broadcast

**On Master Server Console:**
```
Watch for log messages:
[Master] 🔄 Broadcasting domain update to all beacons (new server: dns-3)
[Master] Updated domains: [secwolf.net errantshield.com newdomain.com]
```

**Check Master Database:**
```bash
sqlite3 master.db "SELECT id, beacon_id, command, status FROM tasks WHERE command LIKE 'update_domains:%' ORDER BY created_at DESC LIMIT 5;"

# Should show:
# task_xxx | beacon-id | update_domains:["secwolf.net","errantshield.com","newdomain.com"] | pending
```

#### 6. Verify Beacon Receives Update

**Monitor DNS Server Logs:**
```
Watch for DNS queries from beacon that include:
- Task polling query (will receive update_domains task)
- Result exfiltration with "domains_updated" acknowledgment
```

**Monitor Beacon Behavior:**
After receiving the update task, the beacon should start rotating through all 3 domains:
- secwolf.net (original)
- errantshield.com (original)
- newdomain.com (NEW - dynamically added)

#### 7. Verify Domain Rotation

**Check DNS Server Logs:**
```bash
# Monitor dns-3 (newdomain.com) logs
# Beacon should start making DNS queries to the new domain

# You should see:
[C2] Check-in from beacon: beacon-id (user@hostname)
```

## Expected Results

### ✅ Success Criteria

1. **Master Server**:
   - Detects first checkin from new DNS server
   - Creates broadcast task for all active beacons
   - Task contains JSON array of all enabled domains

2. **Beacon**:
   - Receives `update_domains:[...]` task
   - Parses domain list successfully
   - Updates internal domain rotation
   - Sends "domains_updated" acknowledgment
   - Starts using new domain in rotation

3. **DNS Server**:
   - New server receives beacon check-ins
   - Can serve tasks to beacons
   - Properly reports beacons to Master

### ❌ Failure Scenarios

**If beacon doesn't update domains:**
- Check Master debug logs: Is broadcast task created?
- Check tasks table: Does task exist with correct command?
- Check DNS server: Is task being distributed to beacons?
- Check beacon: Is it polling for tasks?

**If new DNS server not reachable:**
- Verify DNS records: Is NS record configured?
- Check firewall: Is port 53 open?
- Verify build config: Is domain correct?

## Debug Commands

### Master Server
```bash
# Enable debug mode
# Edit master_config.json: "debug": true

# Check tasks
sqlite3 master.db "SELECT * FROM tasks WHERE command LIKE 'update_domains:%';"

# Check beacons
sqlite3 master.db "SELECT id, hostname, last_seen FROM beacons;"

# Check DNS servers
sqlite3 master.db "SELECT id, domain, status, last_checkin FROM dns_servers;"
```

### DNS Server
```bash
# Check if receiving tasks from Master
# Look for:
[Master Client] Polling tasks from master...
[Master Client] Received X tasks

# Check if tasks are being distributed
grep "update_domains" /path/to/dns-server.log
```

### Beacon (if debug enabled)
```bash
# Look for:
# - Task received: update_domains:[...]
# - Domains updated: [list]
# - Beacon using new domains in rotation
```

## Performance Considerations

- **Broadcast Latency**: Tasks created within seconds of new server checkin
- **Task Distribution**: DNS servers poll Master every 30 seconds
- **Beacon Polling**: Beacons check in every SleepMin-SleepMax interval
- **Total Propagation Time**: Typically 1-3 minutes from new server checkin to beacon domain update

## Security Notes

- Beacons only update domains from authenticated Master server
- Domain updates require valid task ID from Master
- DNS servers authenticate with Master via API key
- All communications over encrypted DNS or HTTPS

## Troubleshooting

### Issue: Beacon not receiving update task
**Solution**: 
1. Verify beacon is active (last_seen < 30 minutes)
2. Check if task was created in Master database
3. Verify DNS server is polling Master for tasks
4. Check network connectivity between components

### Issue: Beacon receives task but doesn't update
**Solution**:
1. Check task command format: `update_domains:["domain1","domain2"]`
2. Verify JSON parsing in beacon code
3. Check for errors in beacon logs (if debug enabled)

### Issue: New DNS server checkin doesn't trigger broadcast
**Solution**:
1. Verify this is truly first checkin (last_checkin was 0)
2. Check Master debug logs for broadcast attempt
3. Verify GetEnabledDNSDomains returns all domains

## Next Steps After Testing

If testing is successful:

1. **Production Deployment**:
   - Deploy with proper TLS certificates
   - Configure DNS records for all domains
   - Set appropriate beacon sleep intervals
   - Disable debug logging

2. **Scaling**:
   - Add more DNS servers as needed
   - Beacons automatically learn new domains
   - No client redeployment required

3. **Monitoring**:
   - Watch Master dashboard for DNS server status
   - Monitor beacon distribution across servers
   - Track task success rates

## Architecture Benefits

This dynamic distribution system provides:

- ✅ **Resilience**: No single point of failure
- ✅ **Scalability**: Add DNS servers without touching beacons
- ✅ **Flexibility**: Change infrastructure on the fly
- ✅ **Stealth**: Beacons rotate through multiple domains
- ✅ **Load Balancing**: Distribute beacons across all servers

## Files Modified

- `Master/db.go`: Database methods for domain management
- `Master/api.go`: DNS server checkin handler with broadcast
- `Client/main.go`: Task parsing and domain update handler
- `Master/web/login.html`: UI theme update
- `Master/web/dashboard.html`: UI theme and table updates

---

**Test Status**: Ready for testing (Task 8)
**Last Updated**: November 4, 2025
