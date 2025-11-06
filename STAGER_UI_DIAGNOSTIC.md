# Stager UI Diagnostic Checklist

## Changes Made

### 1. Master/api.go - Line 1538
**Added `api_key` field to StagerContactRequest struct**
```go
type StagerContactRequest struct {
    DNSServerID    string `json:"dns_server_id"`
    ApiKey         string `json:"api_key"`      // ← ADDED THIS
    ClientBinaryID string `json:"client_binary_id"`
    StagerIP       string `json:"stager_ip"`
    OS             string `json:"os"`
    Arch           string `json:"arch"`
}
```

### 2. Master/db.go - Lines 1257-1295
**Fixed NULL value handling in GetStagerSessions**
- Changed to use `sql.NullString` and `sql.NullInt64` for nullable columns
- Converted `completed` from integer to boolean
- Only include optional fields in response when they have values

## Verification Steps

### Step 1: Verify Master Server is Using New Code
```bash
cd /mnt/c/Users/rcoop/GitHub/Unkn0wnC2/Master

# Check if master binary is newer than source files
ls -ltr main.go api.go db.go master

# If source files are newer, rebuild
go build -o master

# Restart Master service (adjust command based on your setup)
sudo systemctl restart unkn0wnc2-master
# OR
sudo killall master && sudo ./master &
```

### Step 2: Check Master Logs
```bash
# Watch for startup messages
tail -f /opt/unkn0wnc2/master.log

# Look for:
# - "Master Server started on :443"
# - "Database initialized"
# - Any error messages
```

### Step 3: Verify Database Schema
```bash
sqlite3 /opt/unkn0wnc2/master.db << EOF
-- Check if stager_sessions table exists and has correct structure
.schema stager_sessions

-- Count existing sessions
SELECT COUNT(*) as session_count FROM stager_sessions;

-- Show most recent sessions
SELECT id, stager_ip, os, arch, total_chunks, chunks_delivered, 
       datetime(created_at, 'unixepoch') as created,
       completed
FROM stager_sessions 
ORDER BY created_at DESC 
LIMIT 5;
EOF
```

### Step 4: Test API Endpoint Directly

#### Get Auth Token
```bash
# Login to get token (replace credentials)
TOKEN=$(curl -sk -X POST https://100.100.1.4:443/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"your_password"}' \
  | jq -r '.data.token')

echo "Token: $TOKEN"
```

#### Query Sessions API
```bash
# Test the stager sessions endpoint
curl -sk -H "Authorization: Bearer $TOKEN" \
     https://100.100.1.4:443/api/stager/sessions \
     | jq .
```

**Expected Response:**
```json
[
  {
    "id": "stg_a1b2",
    "stager_ip": "192.168.1.100",
    "os": "linux",
    "arch": "x64",
    "total_chunks": 50,
    "chunks_delivered": 25,
    "created_at": 1699200000,
    "last_activity": 1699200100,
    "completed": false,
    "initiated_by_dns": "dns-98-90-218-70"
  }
]
```

### Step 5: Deploy New Stager to Trigger Workflow

```bash
# On target machine, run the stager
./stager-linux-x64
```

**Watch DNS Server Logs:**
```bash
tail -f /opt/unkn0wnc2/server.log

# Look for:
# [C2] 🚀 STG: Stager contacted us! IP=...
# [Master Client] 📞 Reported stager contact to Master...
```

**Watch Master Logs:**
```bash
tail -f /opt/unkn0wnc2/master.log

# Look for:
# [API] 📞 Stager contact: 192.168.1.100 (linux/x64) contacted DNS server...
# [API] 🚀 Stager session created from cache contact: stg_xxxx | Stager: 192.168.1.100...
```

### Step 6: Check UI in Browser
1. Open https://100.100.1.4:443/stager
2. Enable auto-refresh toggle
3. Verify sessions appear in table
4. Check that progress updates as chunks are delivered

## Troubleshooting

### Issue: Still Getting 400 Error

**Symptoms:**
- DNS server logs show "request failed with status 400"
- Master logs don't show "Stager session created" messages

**Diagnosis:**
```bash
# Check if Master was rebuilt
cd /mnt/c/Users/rcoop/GitHub/Unkn0wnC2/Master
stat master
stat api.go

# api.go should be OLDER than master binary
```

**Fix:**
```bash
go build -o master
sudo systemctl restart unkn0wnc2-master
```

### Issue: Sessions Created But Not Showing in UI

**Symptoms:**
- Master logs show "Stager session created" 
- Database has records
- UI shows "No stager sessions yet"

**Diagnosis:**
```bash
# Check if sessions exist in database
sqlite3 /opt/unkn0wnc2/master.db "SELECT COUNT(*) FROM stager_sessions;"

# Test API endpoint directly (see Step 4)
```

**Possible Causes:**
1. **Browser cache** - Hard refresh (Ctrl+Shift+R)
2. **Auth token expired** - Logout and login again
3. **CORS/Network issue** - Check browser console for errors
4. **Query error** - Check Master logs for database errors

### Issue: NULL Value Errors in Logs

**Symptoms:**
- Master logs show SQL errors like "scanning NULL"
- GetStagerSessions returns empty array despite database having records

**Fix:**
This should be fixed by the changes to Master/db.go. If still occurring:
```bash
# Verify the fix was applied
cd /mnt/c/Users/rcoop/GitHub/Unkn0wnC2/Master
grep -A 5 "sql.NullString" db.go

# Should show the new NULL handling code
```

### Issue: completed Field Shows as Integer Not Boolean

**Symptoms:**
- UI logic for filtering/displaying completed sessions doesn't work
- JavaScript console shows `completed: 1` instead of `completed: true`

**Fix:**
Verify the line in Master/db.go (around line 1287):
```go
"completed":        completed == 1,  // Converts integer to boolean
```

## Expected Workflow Summary

1. **Stager Contacts DNS Server**
   - Sends STG query
   - DNS checks cache → finds binary

2. **DNS Reports to Master**
   - POST /api/dns-server/stager/contact
   - Payload: `{dns_server_id, api_key, client_binary_id, stager_ip, os, arch}`
   - Master authenticates via middleware
   - Master decodes into StagerContactRequest
   - Master creates session in database
   - Returns: `{session_id: "stg_xxxx"}`

3. **DNS Serves Chunks**
   - DNS serves META (base36 encoded metadata)
   - Stager requests CHUNK_0, CHUNK_1, etc.
   - DNS serves from cache
   - After each chunk, DNS calls POST /api/dns-server/stager/progress

4. **Master Updates Progress**
   - Increments chunks_delivered counter
   - Updates last_activity timestamp
   - When chunks_delivered == total_chunks, marks completed

5. **UI Displays Sessions**
   - GET /api/stager/sessions returns all sessions
   - JavaScript renders table with live progress
   - Auto-refresh polls every 3 seconds

## Quick Test Script

```bash
#!/bin/bash
# Quick test of stager session workflow

echo "=== Stager Session Diagnostic ==="
echo

echo "1. Checking Master service..."
if pgrep -f "master" > /dev/null; then
    echo "✅ Master is running"
else
    echo "❌ Master is NOT running"
fi
echo

echo "2. Checking database..."
SESSION_COUNT=$(sqlite3 /opt/unkn0wnc2/master.db \
    "SELECT COUNT(*) FROM stager_sessions;")
echo "   Sessions in database: $SESSION_COUNT"
echo

echo "3. Checking recent sessions..."
sqlite3 /opt/unkn0wnc2/master.db << EOF
.mode column
.headers on
SELECT id, stager_ip, total_chunks, chunks_delivered, 
       CASE WHEN completed = 1 THEN 'YES' ELSE 'NO' END as done
FROM stager_sessions 
ORDER BY created_at DESC 
LIMIT 3;
EOF
echo

echo "4. Testing API endpoint..."
TOKEN=$(curl -sk -X POST https://100.100.1.4:443/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"your_password"}' 2>/dev/null \
  | jq -r '.data.token')

if [ -n "$TOKEN" ] && [ "$TOKEN" != "null" ]; then
    echo "✅ Got auth token"
    
    SESSIONS=$(curl -sk -H "Authorization: Bearer $TOKEN" \
         https://100.100.1.4:443/api/stager/sessions 2>/dev/null)
    
    SESSION_API_COUNT=$(echo "$SESSIONS" | jq 'length')
    echo "   Sessions from API: $SESSION_API_COUNT"
    
    if [ "$SESSION_API_COUNT" -gt 0 ]; then
        echo "✅ API returning sessions"
    else
        echo "⚠️  API returning empty array"
        echo "   Response: $SESSIONS"
    fi
else
    echo "❌ Could not get auth token"
fi
echo

echo "=== End Diagnostic ==="
```

Save as `/tmp/test_stager_ui.sh` and run:
```bash
chmod +x /tmp/test_stager_ui.sh
/tmp/test_stager_ui.sh
```
