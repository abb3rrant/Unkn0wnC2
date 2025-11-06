# Stager Session Workflow Test

## Expected Flow

### 1. Stager Makes First Contact (STG Request)
- Stager sends STG query to DNS server
- DNS server checks cache for binary
- If found, DNS server calls `/api/dns-server/stager/contact` to Master

### 2. Master Creates Session
**Request from DNS Server:**
```json
{
  "dns_server_id": "dns-98-90-218-70",
  "api_key": "<api_key>",
  "client_binary_id": "<binary_id>",
  "stager_ip": "192.168.1.100",
  "os": "linux",
  "arch": "x64"
}
```

**Master Response:**
```json
{
  "status": "success",
  "message": "contact recorded",
  "data": {
    "session_id": "stg_a1b2"
  }
}
```

**Master Actions:**
- Validates authentication via middleware
- Decodes request into StagerContactRequest struct
- Gets chunk count from cached binary
- Creates session in stager_sessions table
- Returns session_id to DNS server

### 3. DNS Server Serves Chunks
- DNS serves META response (base36 encoded)
- Stager requests chunks via CHUNK queries
- DNS serves chunks from cache
- DNS reports progress to Master: `/api/dns-server/stager/progress`

### 4. UI Displays Sessions
**API Endpoint:** `GET /api/stager/sessions`

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
    "initiated_by_dns": "dns-98-90-218-70",
    "created_at": 1699200000,
    "last_activity": 1699200100,
    "completed": false
  }
]
```

## Potential Issues

### Issue 1: Master Not Restarted
- **Symptom**: Still getting 400 errors
- **Solution**: Rebuild and restart Master server

### Issue 2: Database Schema Mismatch
- **Symptom**: Sessions table doesn't exist or has wrong columns
- **Solution**: Check Master logs for initialization errors

### Issue 3: Authentication Failure
- **Symptom**: 401 Unauthorized errors
- **Solution**: Verify DNS server has correct api_key in config

### Issue 4: Binary Not in Cache
- **Symptom**: No sessions created
- **Solution**: Verify DNS server checked in and received cache task

## Testing Commands

### 1. Check if Master is Running
```bash
ps aux | grep master
```

### 2. Check Master Logs
```bash
tail -f /opt/unkn0wnc2/master.log
```

### 3. Check if Sessions Table Exists
```bash
sqlite3 /opt/unkn0wnc2/master.db "SELECT sql FROM sqlite_master WHERE name='stager_sessions';"
```

### 4. Query Sessions Directly
```bash
sqlite3 /opt/unkn0wnc2/master.db "SELECT * FROM stager_sessions ORDER BY created_at DESC LIMIT 5;"
```

### 5. Test API Endpoint (from local machine)
```bash
curl -H "Authorization: Bearer <token>" \
     https://100.100.1.4:443/api/stager/sessions
```

### 6. Check DNS Server Logs
Look for:
- "Stager contact:" messages (when STG received)
- "Reported stager contact to Master" messages
- Any error messages about Master API calls

## Fixed in This Session

1. ✅ Added `api_key` field to `StagerContactRequest` struct
2. ✅ Fixed NULL value handling in `GetStagerSessions` query
3. ✅ Converted `completed` integer to boolean for JavaScript compatibility
4. ✅ Made optional fields only appear when they have values

## Next Steps

1. Rebuild Master server: `cd Master && go build -o master`
2. Restart Master service
3. Deploy a new stager to trigger the workflow
4. Check UI at https://100.100.1.4:443/stager
5. Verify session appears and progress updates
