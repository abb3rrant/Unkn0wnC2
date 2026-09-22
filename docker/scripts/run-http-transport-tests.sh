#!/bin/bash
# End-to-end checks for the malleable HTTP/HTTPS transport.
#
# Scope, honestly: this covers the listener's externally visible behaviour and the
# Archon API that drives it. It does not run a beacon over HTTP, because that needs
# a build whose transport is HTTP, which the setup step in this compose file does
# not produce. The wire format between beacon and listener is covered instead by
# testdata/http_transport_vectors.json, asserted by both modules' unit tests.
#
# Requires an *enabled* profile to be present on dns1 before the service starts.
# Adding a new profile file needs a restart (a listener has to bind its port);
# editing an existing one hot-reloads.

ARCHON_URL="${ARCHON_URL:-https://172.20.0.10:8443}"
ADMIN_PASS="${ADMIN_PASSWORD:-TestAdmin2026!}"
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
RESPONSE=$(curl -ks -o /tmp/listener-body2.txt -w "%{http_code}" "${LISTENER_URL}/api/v1/sync?d=x")
if [ "$RESPONSE" = "404" ]; then
    pass "unsigned request is indistinguishable from a missing endpoint"
else
    fail "unsigned request is indistinguishable from a missing endpoint" "got ${RESPONSE}"
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