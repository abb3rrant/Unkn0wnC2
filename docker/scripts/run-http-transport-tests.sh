#!/bin/bash
# End-to-end checks for the malleable HTTP/HTTPS transport.
#
# This runs against the deployed Archon, HTTPS listener, and a real HTTP-only
# beacon built by Archon's API from the same profile the listener loads. A
# successful check-in proves TLS/SPKI, request encoding, authentication, and the
# profile's enforced authoritative request headers agree across all processes.
# A benign command/result round trip proves task delivery and result submission.

ARCHON_URL="${ARCHON_URL:-https://172.20.0.10:8443}"
ADMIN_PASS="${ADMIN_PASSWORD:?ADMIN_PASSWORD is required}"
LISTENER_URL="${LISTENER_URL:-https://172.20.0.11:8443}"
COOKIE_JAR="/tmp/http-transport-cookies.txt"
PASSED=0
FAILED=0
TOTAL=0

red()   { echo -e "\033[31m$1\033[0m"; }
green() { echo -e "\033[32m$1\033[0m"; }

pass() { PASSED=$((PASSED + 1)); TOTAL=$((TOTAL + 1)); green "  PASS: $1"; }
fail() { FAILED=$((FAILED + 1)); TOTAL=$((TOTAL + 1)); red   "  FAIL: $1 — $2"; }

login() {
    for _ in $(seq 1 10); do
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

api_post() {
    curl -ks -b "$COOKIE_JAR" \
        -H "Content-Type: application/json" \
        -H "X-CSRF-Token: ${CSRF_TOKEN}" \
        -X POST "${ARCHON_URL}$1" -d "$2"
}

# api_post_raw takes a body output path first, because a few checks need the raw
# error message rather than the parsed payload.
api_post_raw() {
    local out="$1"
    local endpoint="$2"
    local body="$3"
    curl -ks -b "$COOKIE_JAR" \
        -H "Content-Type: application/json" \
        -H "X-CSRF-Token: ${CSRF_TOKEN}" \
        -X POST "${ARCHON_URL}${endpoint}" -d "$body" \
        -o "$out" -w "%{http_code}"
}

api_get() {
    curl -ks -b "$COOKIE_JAR" -H "X-CSRF-Token: ${CSRF_TOKEN}" "${ARCHON_URL}$1"
}

wait_listener() {
    for _ in $(seq 1 30); do
        local code
        code=$(curl -ks --connect-timeout 2 --max-time 3 -o /dev/null -w "%{http_code}" "${LISTENER_URL}/not/a/route" || true)
        if [ "$code" != "000" ]; then
            return 0
        fi
        sleep 2
    done
    return 1
}

wait_result() {
    local task_id="$1"
    for _ in $(seq 1 40); do
        local task status
        task=$(api_get "/api/tasks/${task_id}")
        status=$(echo "$task" | jq -r '.status // ""')
        if [ "$status" = "completed" ] || [ "$status" = "failed" ]; then
            echo "$task" | jq -r '.result // ""'
            return 0
        fi
        sleep 3
    done
    return 1
}

echo ""
echo "========================================="
echo "  HTTP Transport E2E Tests"
echo "========================================="

if ! login; then
    red "  FATAL: could not authenticate with Archon"
    exit 1
fi

# ---------------------------------------------------------------------------
# Listener behaviour as a prober sees it
# ---------------------------------------------------------------------------
echo ""
echo "[Listener]"

if ! wait_listener; then
    red "  FATAL: HTTPS listener did not become ready"
    exit 1
fi

# An unmatched path must return the profile's not-found status with an empty body,
# so a scanner cannot tell a wrong path from a wrong signature.
RESPONSE=$(curl -ks -o /tmp/listener-body.txt -w "%{http_code}" "${LISTENER_URL}/not/a/route")
if [ "$RESPONSE" = "404" ]; then
    pass "unmatched path returns 404"
else
    fail "unmatched path returns 404" "got ${RESPONSE}"
fi

if [ ! -s /tmp/listener-body.txt ]; then
    pass "unmatched path returns an empty body"
else
    fail "unmatched path returns an empty body" "body was $(wc -c < /tmp/listener-body.txt) bytes"
fi

# A configured path without a signature must look identical to an unmatched one.
RESPONSE=$(curl -ks -D /tmp/listener-headers.txt -o /tmp/listener-body2.txt -w "%{http_code}" "${LISTENER_URL}/api/v1/sync?d=x")
if [ "$RESPONSE" = "404" ]; then
    pass "unsigned request is indistinguishable from a missing endpoint"
else
    fail "unsigned request is indistinguishable from a missing endpoint" "got ${RESPONSE}"
fi

if grep -qi '^X-Request-Type: task' /tmp/listener-headers.txt && ! grep -qi '^Date:' /tmp/listener-headers.txt; then
    pass "custom response header is present and Date is omitted"
else
    fail "custom response profile" "$(tr '\r\n' ' ' < /tmp/listener-headers.txt)"
fi

# ---------------------------------------------------------------------------
# Real HTTP-only beacon check-in and command/result path
# ---------------------------------------------------------------------------
echo ""
echo "[HTTP-only beacon]"

HTTP_BEACON_ID=""
for _ in $(seq 1 20); do
    BEACONS=$(api_get "/api/beacons")
    HTTP_BEACON_ID=$(echo "$BEACONS" | jq -r 'first(.beacons[]? | select(.beacon_name == "http-e2e-beacon") | .id) // ""')
    if [ -n "$HTTP_BEACON_ID" ]; then
        break
    fi
    sleep 3
done

if [ -n "$HTTP_BEACON_ID" ]; then
    pass "HTTP-only beacon checked in through the custom HTTPS profile"
else
    fail "HTTP-only beacon check-in" "http-e2e-beacon did not appear within 60 seconds"
fi

if [ -n "$HTTP_BEACON_ID" ]; then
    TASK_RESPONSE=$(api_post "/api/beacons/${HTTP_BEACON_ID}/task" "{\"beacon_id\":\"${HTTP_BEACON_ID}\",\"command\":\"printf HTTP_E2E_OK\"}")
    TASK_ID=$(echo "$TASK_RESPONSE" | jq -r '.data.task_id // empty')
    if [ -n "$TASK_ID" ]; then
        RESULT=$(wait_result "$TASK_ID") || RESULT=""
        if [ "$RESULT" = "HTTP_E2E_OK" ]; then
            pass "HTTP-only task and result completed through Archon"
        else
            fail "HTTP-only task and result" "expected HTTP_E2E_OK, got ${RESULT:-no result}"
        fi
    else
        fail "HTTP-only task creation" "$(echo "$TASK_RESPONSE" | head -c 200)"
    fi
else
    fail "HTTP-only task and result" "skipped because the beacon did not check in"
fi

# ---------------------------------------------------------------------------
# Archon profile API
# ---------------------------------------------------------------------------
echo ""
echo "[Profile API]"

PROFILE_DOCUMENT='{
  "scheme": "http",
  "bind_port": 8443,
  "beacon_host": "172.20.0.11:8443",
  "uris": {
    "register": ["/api/v1/ping"],
    "task": ["/api/v1/sync"],
    "result": ["/api/v1/report"],
    "ack": ["/api/v1/ack"]
  }
}'

SAVE=$(api_post "/api/http/profiles" "{\"name\":\"e2e-check\",\"document\":$(echo "$PROFILE_DOCUMENT" | jq -Rs .)}")
if echo "$SAVE" | jq -e '.data.name == "e2e-check"' >/dev/null 2>&1; then
    pass "profile saves through the API"
else
    fail "profile saves through the API" "$(echo "$SAVE" | head -c 200)"
fi

# A profile missing an operation must be rejected, and the message must name the
# field so the operator knows what to fix.
api_post_raw "/tmp/bad.json" "/api/http/profiles" '{"name":"e2e-bad","document":"{\"scheme\":\"http\",\"uris\":{\"task\":[\"/x\"]}}"}'
if grep -q "uris.register" /tmp/bad.json; then
    pass "an incomplete profile is rejected with a field-specific message"
else
    fail "an incomplete profile is rejected with a field-specific message" "$(head -c 200 /tmp/bad.json)"
fi

# https without a pin would let no beacon verify the listener, so it is refused.
api_post_raw "/tmp/nopin.json" "/api/http/profiles" '{"name":"e2e-nopin","document":"{\"scheme\":\"https\",\"tls\":{\"cert_file\":\"/c.crt\",\"key_file\":\"/c.key\"},\"uris\":{\"register\":[\"/a\"],\"task\":[\"/b\"],\"result\":[\"/c\"],\"ack\":[\"/d\"]}}"}'
if grep -q "spki_sha256" /tmp/nopin.json; then
    pass "an https profile without a pin is rejected"
else
    fail "an https profile without a pin is rejected" "$(head -c 200 /tmp/nopin.json)"
fi

LIST=$(api_get "/api/http/profiles")
if echo "$LIST" | jq -e '.data.profiles | length >= 1' >/dev/null 2>&1; then
    pass "profiles list back"
else
    fail "profiles list back" "$(echo "$LIST" | head -c 200)"
fi

api_get "/api/http/profiles/e2e-check" > /dev/null
DELETED=$(curl -ks -b "$COOKIE_JAR" -H "X-CSRF-Token: ${CSRF_TOKEN}" \
    -X DELETE "${ARCHON_URL}/api/http/profiles/e2e-check" -o /dev/null -w "%{http_code}")
if [ "$DELETED" = "200" ]; then
    pass "profile deletes through the API"
else
    fail "profile deletes through the API" "got ${DELETED}"
fi

# ---------------------------------------------------------------------------
# Runtime transport push
# ---------------------------------------------------------------------------
echo ""
echo "[Transport push]"

PUSH=$(api_post "/api/http/transport" '{"all":true,"mode":"dual","fallback_after_failures":3,"retry_backoff_secs":60,"listeners":[{"name":"e2e","scheme":"http","host":"172.20.0.11:8443","uris":{"register":["/api/v1/ping"],"task":["/api/v1/sync"],"result":["/api/v1/report"],"ack":["/api/v1/ack"]}}]}')
if echo "$PUSH" | jq -e '.data.mode == "dual"' >/dev/null 2>&1; then
    pass "transport push is accepted"
else
    fail "transport push is accepted" "$(echo "$PUSH" | head -c 200)"
fi

QUEUED=$(echo "$PUSH" | jq -r '.data.queued | length' 2>/dev/null)
if [ "${QUEUED:-0}" -ge 1 ]; then
    pass "transport push queues a task per beacon (${QUEUED})"
else
    fail "transport push queues a task per beacon" "queued ${QUEUED:-none} (is a beacon running?)"
fi

# An unknown mode must be refused before anything is queued, so a typo cannot reach
# half the fleet and stay there.
REJECTED=$(curl -ks -b "$COOKIE_JAR" \
    -H "Content-Type: application/json" \
    -H "X-CSRF-Token: ${CSRF_TOKEN}" \
    -X POST "${ARCHON_URL}/api/http/transport" \
    -d '{"all":true,"mode":"carrier-pigeon"}' \
    -o /tmp/mode.json -w "%{http_code}")
if [ "$REJECTED" = "400" ]; then
    pass "an unknown transport mode is refused"
else
    fail "an unknown transport mode is refused" "got ${REJECTED}"
fi

# ---------------------------------------------------------------------------
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