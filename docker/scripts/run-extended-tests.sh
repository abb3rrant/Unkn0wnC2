#!/bin/bash
set -e

# Extended E2E test suite: DNS comms malleability, edge cases, all phase configs
# Tests A-record polling, unencrypted, staged registration, large exfil,
# rapid tasks, and domain failover for the Go beacon.

ARCHON_URL="${ARCHON_URL:-https://172.20.0.10:8443}"
ADMIN_PASS="${ADMIN_PASSWORD:-TestAdmin2026!}"
COOKIE_JAR="/tmp/ext-test-cookies.txt"
BUILDS_DIR="/opt/unkn0wnc2/builds"
PIDS=()
PASSED=0
FAILED=0
SKIPPED=0
TOTAL=0

red()   { echo -e "\033[31m$1\033[0m"; }
green() { echo -e "\033[32m$1\033[0m"; }
yellow(){ echo -e "\033[33m$1\033[0m"; }

pass() { PASSED=$((PASSED + 1)); TOTAL=$((TOTAL + 1)); green "  PASS: $1"; }
fail() { FAILED=$((FAILED + 1)); TOTAL=$((TOTAL + 1)); red   "  FAIL: $1 — $2"; }
skip() { SKIPPED=$((SKIPPED + 1)); TOTAL=$((TOTAL + 1)); yellow "  SKIP: $1"; }

cleanup() {
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
}
trap cleanup EXIT

login() {
    for attempt in $(seq 1 20); do
        HTTP_CODE=$(curl -ks -c "$COOKIE_JAR" \
            -X POST "${ARCHON_URL}/api/auth/login" \
            -H "Content-Type: application/json" \
            -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASS}\"}" \
            -o /dev/null -w "%{http_code}" 2>/dev/null) || true
        if [ "$HTTP_CODE" = "200" ]; then
            CSRF_TOKEN=$(grep csrf_token "$COOKIE_JAR" 2>/dev/null | awk '{print $NF}') || true
            if [ -n "$CSRF_TOKEN" ]; then
                return 0
            fi
        fi
        sleep 3
    done
    return 1
}

api_get() {
    local tmpf="/tmp/api_resp.$$"
    local code
    code=$(curl -ks -b "$COOKIE_JAR" -H "X-CSRF-Token: ${CSRF_TOKEN}" \
        "${ARCHON_URL}$1" -o "$tmpf" -w "%{http_code}" 2>/dev/null) || true
    if [ "$code" = "401" ] || [ "$code" = "403" ]; then
        login >/dev/null 2>&1 || true
        curl -ks -b "$COOKIE_JAR" -H "X-CSRF-Token: ${CSRF_TOKEN}" \
            "${ARCHON_URL}$1" -o "$tmpf" 2>/dev/null || true
    fi
    cat "$tmpf" 2>/dev/null || true
    rm -f "$tmpf"
}

api_post() {
    local tmpf="/tmp/api_resp.$$"
    local code
    code=$(curl -ks -b "$COOKIE_JAR" \
        -H "Content-Type: application/json" \
        -H "X-CSRF-Token: ${CSRF_TOKEN}" \
        -X POST "${ARCHON_URL}$1" -d "$2" -o "$tmpf" -w "%{http_code}" 2>/dev/null) || true
    if [ "$code" = "401" ] || [ "$code" = "403" ]; then
        login >/dev/null 2>&1 || true
        curl -ks -b "$COOKIE_JAR" \
            -H "Content-Type: application/json" \
            -H "X-CSRF-Token: ${CSRF_TOKEN}" \
            -X POST "${ARCHON_URL}$1" -d "$2" -o "$tmpf" 2>/dev/null || true
    fi
    cat "$tmpf" 2>/dev/null || true
    rm -f "$tmpf"
}

wait_result() {
    local task_id="$1"
    local timeout_iters="${2:-12}"
    for i in $(seq 1 "$timeout_iters"); do
        local STATUS RESULT_DATA
        STATUS=$(api_get "/api/tasks/${task_id}" | jq -r '.status // ""' 2>/dev/null) || true
        if [ "$STATUS" = "completed" ] || [ "$STATUS" = "failed" ]; then
            RESULT_DATA=$(api_get "/api/tasks/${task_id}" | jq -r '.result // ""' 2>/dev/null) || true
            echo "$RESULT_DATA"
            return 0
        fi
        sleep 5
    done
    return 1
}

# Wait for a beacon with a specific name to appear, return its ID
wait_beacon() {
    local beacon_name="$1"
    local timeout_iters="${2:-24}"
    for i in $(seq 1 "$timeout_iters"); do
        local BEACONS BEACON_COUNT
        BEACONS=$(api_get "/api/beacons") || true
        BEACON_COUNT=$(echo "$BEACONS" | jq -r '.beacons | length // 0' 2>/dev/null) || true
        BEACON_COUNT=${BEACON_COUNT:-0}
        for j in $(seq 0 $((BEACON_COUNT - 1))); do
            local B_NAME
            B_NAME=$(echo "$BEACONS" | jq -r ".beacons[$j].beacon_name // \"\"" 2>/dev/null) || true
            if [ "$B_NAME" = "$beacon_name" ]; then
                echo "$BEACONS" | jq -r ".beacons[$j].id" 2>/dev/null || true
                return 0
            fi
        done
        sleep 5
    done
    echo ""
    return 0
}

# Start a beacon binary in the background
start_beacon() {
    local binary="$1"
    local label="$2"
    if [ ! -x "$binary" ]; then
        echo ""
        return 1
    fi
    "$binary" >/dev/null 2>&1 &
    local pid=$!
    PIDS+=("$pid")
    echo "$pid"
}

# Run a task on a beacon and verify result (always returns 0 for set -e safety)
run_task_test() {
    local beacon_id="$1"
    local command="$2"
    local expect_pattern="$3"
    local label="$4"
    local timeout="${5:-12}"

    local TASK_RESP TASK_ID RESULT
    TASK_RESP=$(api_post "/api/beacons/${beacon_id}/task" \
        "{\"beacon_id\":\"${beacon_id}\",\"command\":\"${command}\"}") || true
    TASK_ID=$(echo "$TASK_RESP" | jq -r '.data.task_id // empty' 2>/dev/null) || true

    if [ -z "$TASK_ID" ]; then
        local err_msg
        err_msg=$(echo "$TASK_RESP" | jq -r '.error // .message // "unknown"' 2>/dev/null) || true
        fail "${label}" "task creation failed: ${err_msg}"
        return 0
    fi

    # wait_result returns 0 once the task reaches a terminal state; it may
    # legitimately return an empty result (e.g. zero-output commands like
    # "true" or bare "echo"), so detect timeout via the exit code, not output.
    if ! RESULT=$(wait_result "$TASK_ID" "$timeout"); then
        fail "${label}" "no result after timeout"
        return 0
    fi

    if [ -n "$expect_pattern" ]; then
        if echo "$RESULT" | grep -qi "$expect_pattern"; then
            pass "${label}: $(echo "$RESULT" | head -1 | cut -c1-60 | tr -d '\n')"
        else
            fail "${label}" "unexpected result: $(echo "$RESULT" | head -1 | cut -c1-60 | tr -d '\n')"
        fi
    else
        pass "${label}"
    fi
    return 0
}

echo ""
echo "========================================="
echo "  unkn0wnc2 Extended E2E Test Suite"
echo "  DNS Comms Malleability + Edge Cases"
echo "========================================="
echo ""

yellow "[Ext] Waiting for services..."
sleep 10

if ! login; then
    red "FATAL: Could not authenticate with Archon"
    exit 1
fi

# Record initial beacon count
INITIAL_BEACONS=$(api_get "/api/beacons" | jq -r '.beacons | length // 0')
echo "  Initial beacon count: ${INITIAL_BEACONS}"

# =========================================
# SECTION 1: A-RECORD POLLING
# =========================================
echo ""
echo "========================================="
yellow "  SECTION 1: A-Record Polling"
echo "========================================="

# --- Go Client: A-record poll ---
echo ""
yellow "--- Go Client: A-Record Poll ---"

if [ -x "${BUILDS_DIR}/beacon-a-record" ]; then
    AREC_PID=$(start_beacon "${BUILDS_DIR}/beacon-a-record" "Go A-record")
    echo "  Started Go A-record beacon (PID: ${AREC_PID})"

    AREC_ID=$(wait_beacon "test-a-record" 24)
    if [ -n "$AREC_ID" ]; then
        pass "Go A-record beacon checked in (ID: ${AREC_ID})"
        run_task_test "$AREC_ID" "whoami" "" "Go A-record task exec" 18
        run_task_test "$AREC_ID" "id" "uid=" "Go A-record shell (id)" 18
    else
        fail "Go A-record beacon" "did not check in within 120s"
    fi
else
    skip "Go A-record client binary not found"
fi

# =========================================
# SECTION 2: UNENCRYPTED COMMS (BASE36)
# =========================================
echo ""
echo "========================================="
yellow "  SECTION 2: Unencrypted Comms (Base36)"
echo "========================================="

# --- Go Client: Unencrypted ---
echo ""
yellow "--- Go Client: Unencrypted ---"

if [ -x "${BUILDS_DIR}/beacon-unencrypted" ]; then
    UNENC_PID=$(start_beacon "${BUILDS_DIR}/beacon-unencrypted" "Go unencrypted")
    echo "  Started Go unencrypted beacon (PID: ${UNENC_PID})"

    UNENC_ID=$(wait_beacon "test-unencrypted" 24)
    if [ -n "$UNENC_ID" ]; then
        pass "Go unencrypted beacon checked in (ID: ${UNENC_ID})"
        run_task_test "$UNENC_ID" "whoami" "" "Go unencrypted task exec" 18
        run_task_test "$UNENC_ID" "id" "uid=" "Go unencrypted shell (id)" 18
    else
        fail "Go unencrypted beacon" "did not check in within 120s"
    fi
else
    skip "Go unencrypted client binary not found"
fi

# =========================================
# SECTION 3: STAGED REGISTRATION
# =========================================
echo ""
echo "========================================="
yellow "  SECTION 3: Staged Registration"
echo "========================================="

echo ""
yellow "--- Go Client: Staged Registration ---"

if [ -x "${BUILDS_DIR}/beacon-staged" ]; then
    STAGED_PID=$(start_beacon "${BUILDS_DIR}/beacon-staged" "Go staged")
    echo "  Started Go staged-reg beacon (PID: ${STAGED_PID})"

    STAGED_ID=$(wait_beacon "test-staged" 24)
    if [ -n "$STAGED_ID" ]; then
        pass "Go staged-reg beacon checked in (ID: ${STAGED_ID})"
        run_task_test "$STAGED_ID" "whoami" "" "Go staged-reg task exec" 18
    else
        fail "Go staged-reg beacon" "did not check in within 120s"
    fi
else
    skip "Go staged-reg client binary not found"
fi

# =========================================
# SECTION 4: EDGE CASES (using baseline beacons)
# =========================================
echo ""
echo "========================================="
yellow "  SECTION 4: Edge Cases"
echo "========================================="

# Refresh session before edge case tests
login >/dev/null 2>&1 || true
BEACONS=$(api_get "/api/beacons") || true
BEACON_COUNT=$(echo "$BEACONS" | jq -r '.beacons | length // 0' 2>/dev/null) || true
BEACON_COUNT=${BEACON_COUNT:-0}

# Find the Go baseline beacon
GO_BASE_ID=""
for j in $(seq 0 $((BEACON_COUNT - 1))); do
    B_NAME=$(echo "$BEACONS" | jq -r ".beacons[$j].beacon_name // \"\"" 2>/dev/null) || true
    B_ID=$(echo "$BEACONS" | jq -r ".beacons[$j].id" 2>/dev/null) || true
    if [ "$B_NAME" = "test-beacon" ] && [ -z "$GO_BASE_ID" ]; then
        GO_BASE_ID="$B_ID"
    fi
done

# --- Edge Case 1: Large result exfiltration ---
echo ""
yellow "--- Edge Case: Large Result Exfiltration ---"

if [ -n "$GO_BASE_ID" ]; then
    # Generate output larger than a single DNS response (forces chunked exfil)
    run_task_test "$GO_BASE_ID" "find /usr -type f -name '*.so' 2>/dev/null | head -50" "" \
        "Go large exfil (find /usr)" 24
else
    skip "Go large exfil: no baseline Go beacon"
fi

# --- Edge Case 2: Rapid consecutive tasks ---
echo ""
yellow "--- Edge Case: Rapid Consecutive Tasks ---"

if [ -n "$GO_BASE_ID" ]; then
    RAPID_OK=0
    RAPID_FAIL=0
    RAPID_TASKS=()

    for i in 1 2 3; do
        RESP=$(api_post "/api/beacons/${GO_BASE_ID}/task" "{\"beacon_id\":\"${GO_BASE_ID}\",\"command\":\"echo rapid-${i}\"}")
        TID=$(echo "$RESP" | jq -r '.data.task_id // empty')
        if [ -n "$TID" ]; then
            RAPID_TASKS+=("$TID")
        fi
    done

    echo "  Queued ${#RAPID_TASKS[@]} rapid tasks, waiting for results..."
    for tid in "${RAPID_TASKS[@]}"; do
        RES=$(wait_result "$tid" 18)
        if [ -n "$RES" ] && echo "$RES" | grep -q "rapid-"; then
            RAPID_OK=$((RAPID_OK + 1))
        else
            RAPID_FAIL=$((RAPID_FAIL + 1))
        fi
    done

    if [ "$RAPID_FAIL" -eq 0 ]; then
        pass "Go rapid tasks: ${RAPID_OK}/${#RAPID_TASKS[@]} completed"
    else
        fail "Go rapid tasks" "${RAPID_FAIL}/${#RAPID_TASKS[@]} failed"
    fi
else
    skip "Go rapid tasks: no baseline Go beacon"
fi

# --- Edge Case 3: Empty/whitespace output ---
echo ""
yellow "--- Edge Case: Minimal Output Commands ---"

if [ -n "$GO_BASE_ID" ]; then
    run_task_test "$GO_BASE_ID" "echo" "" "Go empty echo" 18
    run_task_test "$GO_BASE_ID" "true" "" "Go 'true' (zero output)" 18
fi

# --- Edge Case 4: Special characters in output ---
echo ""
yellow "--- Edge Case: Special Characters ---"

if [ -n "$GO_BASE_ID" ]; then
    run_task_test "$GO_BASE_ID" "echo 'hello world | pipe & ampersand'" "hello world" \
        "Go special chars" 18
fi

# --- Edge Case 5: Multi-domain failover ---
echo ""
yellow "--- Edge Case: Shadow Mesh Beacon Count ---"

login >/dev/null 2>&1 || true
FINAL_BEACONS=$(api_get "/api/beacons") || true
FINAL_COUNT=$(echo "$FINAL_BEACONS" | jq -r '.beacons | length // 0' 2>/dev/null) || true
FINAL_COUNT=${FINAL_COUNT:-0}
EXPECTED_MIN=$((INITIAL_BEACONS + 3))

if [ "$FINAL_COUNT" -ge "$EXPECTED_MIN" ]; then
    pass "All test beacons visible: ${FINAL_COUNT} total (started with ${INITIAL_BEACONS})"
else
    fail "Beacon count" "expected >=${EXPECTED_MIN}, got ${FINAL_COUNT}"
fi

# List all beacons for reference
echo ""
yellow "--- All Registered Beacons ---"
for j in $(seq 0 $((FINAL_COUNT - 1))); do
    B_NAME=$(echo "$FINAL_BEACONS" | jq -r ".beacons[$j].beacon_name // \"unknown\"" 2>/dev/null) || true
    B_ID=$(echo "$FINAL_BEACONS" | jq -r ".beacons[$j].id // \"?\"" 2>/dev/null) || true
    B_OS=$(echo "$FINAL_BEACONS" | jq -r ".beacons[$j].os // \"?\"" 2>/dev/null) || true
    B_HOST=$(echo "$FINAL_BEACONS" | jq -r ".beacons[$j].hostname // \"?\"" 2>/dev/null) || true
    echo "  [$j] ${B_NAME} (${B_ID}) ${B_OS} @ ${B_HOST}"
done

# =========================================
# Summary
# =========================================
echo ""
echo "========================================="
if [ "$FAILED" -eq 0 ]; then
    green "  ALL TESTS PASSED (${PASSED} passed, ${SKIPPED} skipped / ${TOTAL} total)"
else
    red   "  ${FAILED} FAILED, ${PASSED} passed, ${SKIPPED} skipped (${TOTAL} total)"
fi
echo "========================================="
echo ""

exit "$FAILED"
