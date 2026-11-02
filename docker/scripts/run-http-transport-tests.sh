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
DEFAULT_LISTENER_URL="${DEFAULT_LISTENER_URL:-http://172.20.0.12:8444}"
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
            [ "$status" = "completed" ] && return 0
            return 2
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
        OUTCOME=0
        RESULT=$(wait_result "$TASK_ID") || OUTCOME=$?
        if [ "$OUTCOME" -eq 0 ] && [ "$RESULT" = "HTTP_E2E_OK" ]; then
            pass "HTTP-only task and result completed through Archon"
        elif [ "$OUTCOME" -eq 2 ]; then
            fail "HTTP-only task and result" "task failed: ${RESULT:-no result text}"
        else
            fail "HTTP-only task and result" "expected HTTP_E2E_OK, got ${RESULT:-no result} (outcome ${OUTCOME})"
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

# The push is applied to live beacons, so it has to describe a listener that can
# actually serve them. A made-up spec (an http:// address for an HTTPS listener,
# for instance) moves every beacon onto a transport that cannot answer, and an
# HTTP-only beacon with no DNS domains has no way back. The spec is projected from
# the profile the listener is actually serving.
PUSH_PROFILE_FILE="/opt/unkn0wnc2/profiles/cdn-assets.json"
if [ -r "$PUSH_PROFILE_FILE" ]; then
    PUSH_LISTENER=$(jq '{
        name,
        scheme,
        host: .beacon_host,
        host_header,
        spki_sha256: (.tls.spki_sha256 // ""),
        uris,
        methods,
        user_agents,
        headers,
        request_headers,
        request_body,
        response_body,
        auth,
        timeout_secs: 15,
        max_body_bytes
    }' "$PUSH_PROFILE_FILE")
else
    PUSH_LISTENER='{}'
    fail "transport push uses a servable listener" "profile unavailable at ${PUSH_PROFILE_FILE}"
fi

PUSH=$(api_post "/api/http/transport" "{\"all\":true,\"mode\":\"dual\",\"fallback_after_failures\":3,\"retry_backoff_secs\":60,\"listeners\":[${PUSH_LISTENER}]}")
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

# A beacon that accepted the push must still task afterwards: the point of a
# runtime transport change is that it leaves the beacon reachable, not merely that
# the request was accepted.
if [ -n "$HTTP_BEACON_ID" ]; then
    sleep 10
    TASK_RESPONSE=$(api_post "/api/beacons/${HTTP_BEACON_ID}/task" "{\"beacon_id\":\"${HTTP_BEACON_ID}\",\"command\":\"printf PUSH_OK\"}")
    TASK_ID=$(echo "$TASK_RESPONSE" | jq -r '.data.task_id // empty')
    OUTCOME=1
    RESULT=""
    if [ -n "$TASK_ID" ]; then
        OUTCOME=0
        RESULT=$(wait_result "$TASK_ID") || OUTCOME=$?
    fi
    if [ "$OUTCOME" -eq 0 ] && [ "$RESULT" = "PUSH_OK" ]; then
        pass "a beacon still tasks after the transport push"
    else
        fail "a beacon still tasks after the transport push" "expected PUSH_OK, got ${RESULT:-no result} (outcome ${OUTCOME})"
    fi
else
    fail "a beacon still tasks after the transport push" "skipped: no HTTP beacon"
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
# Shipped default profile over plain HTTP
# ---------------------------------------------------------------------------
echo ""
echo "[Default profile]"

TEMPLATE=$(api_get "/api/http/profile-template")
if echo "$TEMPLATE" | jq -e '.data.document | length > 0' >/dev/null 2>&1; then
    pass "the shipped default profile template is served"
else
    fail "the shipped default profile template is served" "$(echo "$TEMPLATE" | head -c 200)"
fi

# Archon seeds this on an empty profile table, so a fresh install has something to
# assign. Its document must be the same one the editor loads.
SEEDED=$(api_get "/api/http/profiles/default" | jq -r '.data.document // empty' 2>/dev/null)
TEMPLATE_DOC=$(echo "$TEMPLATE" | jq -r '.data.document // empty')
if [ -n "$SEEDED" ] && [ "$(echo "$SEEDED" | jq -S .)" = "$(echo "$TEMPLATE_DOC" | jq -S .)" ]; then
    pass "the seeded default profile matches the served template"
else
    fail "the seeded default profile matches the served template" "seeded=${SEEDED:0:80}"
fi

# The same document must pass the save path an operator uses, or the default is
# not actually storable. The name is pinned to the document (the listener takes a
# profile name from its filename), so a copy is saved under its own name rather
# than overwriting the seeded record.
SAVE_DOC=$(echo "$TEMPLATE_DOC" | jq '.name = "default-check"')
SAVE_DEFAULT=$(api_post "/api/http/profiles" "{\"name\":\"default-check\",\"document\":$(echo "$SAVE_DOC" | jq -Rs .)}")
if echo "$SAVE_DEFAULT" | jq -e '.data.name == "default-check"' >/dev/null 2>&1; then
    pass "the default profile passes the save path unchanged"
else
    fail "the default profile passes the save path unchanged" "$(echo "$SAVE_DEFAULT" | head -c 200)"
fi
curl -ks -b "$COOKIE_JAR" -H "X-CSRF-Token: ${CSRF_TOKEN}" \
    -X DELETE "${ARCHON_URL}/api/http/profiles/default-check" -o /dev/null

# A plain-HTTP listener on 8444 serves the same default document.
DEFAULT_READY=0
for _ in $(seq 1 30); do
    CODE=$(curl -s --connect-timeout 2 --max-time 3 -o /dev/null -w "%{http_code}" \
        "${DEFAULT_LISTENER_URL}/not/a/route" || true)
    if [ "$CODE" != "000" ]; then
        DEFAULT_READY=1
        break
    fi
    sleep 2
done
if [ "$DEFAULT_READY" -eq 1 ] && [ "$CODE" = "404" ]; then
    pass "the default profile's plain-HTTP listener answers a probe with its not-found status"
else
    fail "the default profile's plain-HTTP listener answers a probe" "code=${CODE:-none}"
fi

DEFAULT_BEACON_ID=""
for _ in $(seq 1 30); do
    BEACONS=$(api_get "/api/beacons")
    DEFAULT_BEACON_ID=$(echo "$BEACONS" | jq -r 'first(.beacons[]? | select(.beacon_name == "default-profile-beacon") | .id) // ""')
    if [ -n "$DEFAULT_BEACON_ID" ]; then
        break
    fi
    sleep 3
done

if [ -n "$DEFAULT_BEACON_ID" ]; then
    pass "a beacon built from the default profile checked in over plain HTTP"
else
    fail "a beacon built from the default profile checked in over plain HTTP" "default-profile-beacon did not appear"
fi

if [ -n "$DEFAULT_BEACON_ID" ]; then
    TASK_RESPONSE=$(api_post "/api/beacons/${DEFAULT_BEACON_ID}/task" "{\"beacon_id\":\"${DEFAULT_BEACON_ID}\",\"command\":\"printf DEFAULT_E2E_OK\"}")
    TASK_ID=$(echo "$TASK_RESPONSE" | jq -r '.data.task_id // empty')
    if [ -n "$TASK_ID" ]; then
        OUTCOME=0
        RESULT=$(wait_result "$TASK_ID") || OUTCOME=$?
        if [ "$OUTCOME" -eq 0 ] && [ "$RESULT" = "DEFAULT_E2E_OK" ]; then
            pass "task and result completed over plain HTTP with the default profile"
        else
            fail "task and result over plain HTTP with the default profile" "expected DEFAULT_E2E_OK, got ${RESULT:-no result} (outcome ${OUTCOME})"
        fi
    else
        fail "task creation on the default-profile beacon" "$(echo "$TASK_RESPONSE" | head -c 200)"
    fi
else
    fail "task and result over plain HTTP with the default profile" "skipped because the beacon did not check in"
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