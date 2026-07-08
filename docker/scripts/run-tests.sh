#!/bin/bash
set -e

ARCHON_URL="${ARCHON_URL:-https://172.20.0.10:8443}"
ADMIN_PASS="${ADMIN_PASSWORD:-TestAdmin2026!}"
COOKIE_JAR="/tmp/test-cookies.txt"
PASSED=0
FAILED=0
TOTAL=0

red()   { echo -e "\033[31m$1\033[0m"; }
green() { echo -e "\033[32m$1\033[0m"; }
yellow(){ echo -e "\033[33m$1\033[0m"; }

pass() { PASSED=$((PASSED + 1)); TOTAL=$((TOTAL + 1)); green "  PASS: $1"; }
fail() { FAILED=$((FAILED + 1)); TOTAL=$((TOTAL + 1)); red   "  FAIL: $1 — $2"; }

# Authenticate with retries (SQLite contention under load)
login() {
    for attempt in $(seq 1 10); do
        HTTP_CODE=$(curl -ks -c "$COOKIE_JAR" \
            -X POST "${ARCHON_URL}/api/auth/login" \
            -H "Content-Type: application/json" \
            -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASS}\"}" \
            -o /dev/null -w "%{http_code}")
        if [ "$HTTP_CODE" = "200" ]; then
            CSRF_TOKEN=$(grep csrf_token "$COOKIE_JAR" | awk '{print $NF}')
            return 0
        fi
        sleep 2
    done
    return 1
}

api_get() {
    curl -ks -b "$COOKIE_JAR" -H "X-CSRF-Token: ${CSRF_TOKEN}" "${ARCHON_URL}$1"
}

api_post() {
    curl -ks -b "$COOKIE_JAR" \
        -H "Content-Type: application/json" \
        -H "X-CSRF-Token: ${CSRF_TOKEN}" \
        -X POST "${ARCHON_URL}$1" -d "$2"
}

# Wait for a task result, return the result string
wait_result() {
    local task_id="$1"
    local timeout_iters="${2:-12}"
    for i in $(seq 1 "$timeout_iters"); do
        RESULT_DATA=$(api_get "/api/tasks/${task_id}" | jq -r '.result // empty')
        if [ -n "$RESULT_DATA" ]; then
            echo "$RESULT_DATA"
            return 0
        fi
        sleep 5
    done
    return 1
}

echo ""
echo "========================================="
echo "  unkn0wnc2 Integration Test Suite"
echo "========================================="
echo ""

# Wait for all services
yellow "[Test] Waiting for services to stabilize..."
sleep 15

if ! login; then
    red "FATAL: Could not authenticate with Archon"
    exit 1
fi

# =========================================
# Test 1: Archon is running
# =========================================
echo ""
yellow "--- Archon Health ---"

HEALTH=$(curl -ks -o /dev/null -w "%{http_code}" "${ARCHON_URL}/login")
if [ "$HEALTH" = "200" ]; then
    pass "Archon web UI reachable"
else
    fail "Archon web UI" "HTTP ${HEALTH}"
fi

# =========================================
# Test 2: Go Beacon check-in
# =========================================
echo ""
yellow "--- Go Beacon Check-in ---"

BEACON_FOUND=false
BEACON_ID=""
for i in $(seq 1 12); do
    BEACONS=$(api_get "/api/beacons")
    # API returns {"beacons":[...]} not {"data":[...]}
    BEACON_COUNT=$(echo "$BEACONS" | jq -r '.beacons | length // 0')
    if [ "$BEACON_COUNT" -ge 1 ]; then
        BEACON_FOUND=true
        BEACON_ID=$(echo "$BEACONS" | jq -r ".beacons[0].id")
        break
    fi
    sleep 5
done

if [ "$BEACON_FOUND" = true ]; then
    BEACON_HOST=$(echo "$BEACONS" | jq -r ".beacons[] | select(.id == \"${BEACON_ID}\") | .hostname // \"unknown\"")
    BEACON_OS=$(echo "$BEACONS" | jq -r ".beacons[] | select(.id == \"${BEACON_ID}\") | .os // \"unknown\"")
    pass "Go beacon checked in (${BEACON_COUNT} beacon(s))"
    echo "       Beacon ID: ${BEACON_ID}, Host: ${BEACON_HOST} (${BEACON_OS})"
else
    fail "Go beacon check-in" "no beacons appeared within 60s"
fi

# =========================================
# Test 3: Go beacon task execution
# =========================================
echo ""
yellow "--- Go Beacon Task Execution ---"

if [ "$BEACON_FOUND" = true ]; then
    TASK_RESP=$(api_post "/api/beacons/${BEACON_ID}/task" "{\"beacon_id\":\"${BEACON_ID}\",\"command\":\"whoami\"}")
    TASK_ID=$(echo "$TASK_RESP" | jq -r '.data.task_id // empty')

    if [ -n "$TASK_ID" ]; then
        pass "Task created (${TASK_ID})"
        RESULT_DATA=$(wait_result "$TASK_ID")
        if [ -n "$RESULT_DATA" ]; then
            pass "Task result received: $(echo "$RESULT_DATA" | head -1 | tr -d '\n')"
        else
            fail "Task result" "no result after 60s"
        fi
    else
        fail "Task creation" "$(echo "$TASK_RESP" | jq -r '.error // .message // "unknown"')"
    fi
else
    fail "Task execution" "skipped (no beacon)"
fi

# =========================================
# Test 4: Shadow Mesh (multi-beacon sync)
# =========================================
echo ""
yellow "--- Shadow Mesh ---"

login
BEACONS_FINAL=$(api_get "/api/beacons")
FINAL_COUNT=$(echo "$BEACONS_FINAL" | jq -r '.beacons | length // 0')

if [ "$FINAL_COUNT" -ge 1 ]; then
    pass "Shadow Mesh: Archon sees ${FINAL_COUNT} beacon(s)"
else
    fail "Shadow Mesh" "expected >= 1 beacon, got ${FINAL_COUNT}"
fi

# Start the mesh beacon (uses dns2)
MESH_BINARY="/opt/unkn0wnc2/builds/beacon-mesh"
if [ -x "$MESH_BINARY" ]; then
    "$MESH_BINARY" &
    MESH_PID=$!
    echo "       Started mesh beacon (PID: ${MESH_PID})"

    MESH_FOUND=false
    for i in $(seq 1 12); do
        login
        BEACONS3=$(api_get "/api/beacons")
        BEACON_COUNT3=$(echo "$BEACONS3" | jq -r '.beacons | length // 0')
        if [ "$BEACON_COUNT3" -ge 2 ]; then
            MESH_FOUND=true
            break
        fi
        sleep 5
    done

    if [ "$MESH_FOUND" = true ]; then
        pass "Mesh beacon via DNS2 (${BEACON_COUNT3} total beacons)"
    else
        fail "Mesh beacon" "mesh beacon not seen after 60s (count: ${BEACON_COUNT3})"
    fi

    kill "$MESH_PID" 2>/dev/null || true
else
    fail "Mesh beacon binary" "not found at ${MESH_BINARY}"
fi

# =========================================
# Summary
# =========================================
echo ""
echo "========================================="
if [ "$FAILED" -eq 0 ]; then
    green "  ALL TESTS PASSED (${PASSED}/${TOTAL})"
else
    red   "  ${FAILED} FAILED, ${PASSED} passed (${TOTAL} total)"
fi
echo "========================================="
echo ""

exit "$FAILED"
