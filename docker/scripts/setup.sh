#!/bin/bash
set -e

ARCHON_URL="${ARCHON_URL:-https://172.20.0.10:8443}"
ADMIN_USER="admin"
ADMIN_PASS="${ADMIN_PASSWORD:-TestAdmin2026!}"
COOKIE_JAR="/tmp/cookies.txt"
BUILDS_DIR="/opt/unkn0wnc2/builds"

echo "=== unkn0wnc2 Docker Setup ==="
echo "[Setup] Archon: ${ARCHON_URL}"

# Wait for Archon to be fully ready
echo "[Setup] Waiting for Archon..."
for i in $(seq 1 60); do
    if curl -ks "${ARCHON_URL}/login" -o /dev/null 2>/dev/null; then
        echo "[Setup] Archon is ready"
        break
    fi
    if [ "$i" -eq 60 ]; then
        echo "[Setup] ERROR: Archon did not start in time"
        exit 1
    fi
    sleep 2
done

# Login and capture cookies (session_token + csrf_token)
echo "[Setup] Authenticating..."
LOGIN_RESP=$(curl -ks -c "$COOKIE_JAR" \
    -X POST "${ARCHON_URL}/api/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}" \
    -w "\n%{http_code}")

HTTP_CODE=$(echo "$LOGIN_RESP" | tail -1)
if [ "$HTTP_CODE" != "200" ]; then
    echo "[Setup] ERROR: Login failed (HTTP ${HTTP_CODE})"
    echo "$LOGIN_RESP"
    exit 1
fi

CSRF_TOKEN=$(grep csrf_token "$COOKIE_JAR" | awk '{print $NF}')
echo "[Setup] Authenticated (CSRF token obtained)"

# Helper: authenticated POST with CSRF
api_post() {
    local endpoint="$1"
    local data="$2"
    curl -ks -b "$COOKIE_JAR" \
        -X POST "${ARCHON_URL}${endpoint}" \
        -H "Content-Type: application/json" \
        -H "X-CSRF-Token: ${CSRF_TOKEN}" \
        -d "$data"
}

# Helper: authenticated GET
api_get() {
    local endpoint="$1"
    curl -ks -b "$COOKIE_JAR" \
        -X GET "${ARCHON_URL}${endpoint}" \
        -H "X-CSRF-Token: ${CSRF_TOKEN}"
}

# --------------------------------------------------------
# Build DNS Server 1
# --------------------------------------------------------
echo ""
echo "[Setup] Building DNS Server 1 (172.20.0.11)..."
DNS1_RESP=$(api_post "/api/builder/dns-server" "{
    \"domain\": \"alpha.test\",
    \"server_address\": \"172.20.0.11\",
    \"ns1\": \"ns1.alpha.test\",
    \"ns2\": \"ns2.alpha.test\",
    \"upstream_dns\": \"8.8.8.8:53\",
    \"forward_dns\": true
}")

DNS1_FILE=$(echo "$DNS1_RESP" | jq -r '.data.filename // empty')
if [ -z "$DNS1_FILE" ]; then
    echo "[Setup] ERROR: DNS Server 1 build failed"
    echo "$DNS1_RESP" | jq .
    exit 1
fi
echo "[Setup] DNS Server 1 built: ${DNS1_FILE}"

# Copy to well-known location for dns1 container
cp "${BUILDS_DIR}/dns-server/${DNS1_FILE}" "${BUILDS_DIR}/dns-server-1"
chmod +x "${BUILDS_DIR}/dns-server-1"

# --------------------------------------------------------
# Build DNS Server 2
# --------------------------------------------------------
echo "[Setup] Building DNS Server 2 (172.20.0.12)..."
DNS2_RESP=$(api_post "/api/builder/dns-server" "{
    \"domain\": \"bravo.test\",
    \"server_address\": \"172.20.0.12\",
    \"ns1\": \"ns1.bravo.test\",
    \"ns2\": \"ns2.bravo.test\",
    \"upstream_dns\": \"8.8.8.8:53\",
    \"forward_dns\": true
}")

DNS2_FILE=$(echo "$DNS2_RESP" | jq -r '.data.filename // empty')
if [ -z "$DNS2_FILE" ]; then
    echo "[Setup] ERROR: DNS Server 2 build failed"
    echo "$DNS2_RESP" | jq .
    exit 1
fi
echo "[Setup] DNS Server 2 built: ${DNS2_FILE}"

cp "${BUILDS_DIR}/dns-server/${DNS2_FILE}" "${BUILDS_DIR}/dns-server-2"
chmod +x "${BUILDS_DIR}/dns-server-2"

# --------------------------------------------------------
# Build Linux Client (beacon)
# --------------------------------------------------------
# Detect container architecture for native builds
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  GOARCH="amd64" ;;
    aarch64) GOARCH="arm64" ;;
    armv7l)  GOARCH="armv7l" ;;
    *)       GOARCH="amd64" ;;
esac
echo "[Setup] Detected architecture: ${ARCH} -> ${GOARCH}"

echo "[Setup] Building Linux client (beacon)..."
CLIENT_RESP=$(api_post "/api/builder/client" "{
    \"dns_domains\": [\"alpha.test\"],
    \"platform\": \"linux\",
    \"architecture\": \"${GOARCH}\",
    \"sleep_min\": 5,
    \"sleep_max\": 10,
    \"exfil_jitter_min_ms\": 100,
    \"exfil_jitter_max_ms\": 500,
    \"exfil_chunks_per_burst\": 10,
    \"exfil_burst_pause_ms\": 1000,
    \"resolver\": \"172.20.0.11:53\",
    \"beacon_name\": \"test-beacon\",
    \"staged_registration\": false,
    \"static_link\": true
}")

CLIENT_FILE=$(echo "$CLIENT_RESP" | jq -r '.data.filename // empty')
BUILD_ID=$(echo "$CLIENT_RESP" | jq -r '.data.build_id // empty')
if [ -z "$CLIENT_FILE" ]; then
    echo "[Setup] ERROR: Client build failed"
    echo "$CLIENT_RESP" | jq .
    exit 1
fi
echo "[Setup] Client built: ${CLIENT_FILE} (BuildID: ${BUILD_ID})"

cp "${BUILDS_DIR}/client/${CLIENT_FILE}" "${BUILDS_DIR}/beacon"
chmod +x "${BUILDS_DIR}/beacon"

# --------------------------------------------------------
# Build second client for multi-DNS test (uses both resolvers via system DNS)
# --------------------------------------------------------
echo "[Setup] Building multi-DNS client (Shadow Mesh test)..."
CLIENT2_RESP=$(api_post "/api/builder/client" "{
    \"dns_domains\": [\"bravo.test\"],
    \"platform\": \"linux\",
    \"architecture\": \"${GOARCH}\",
    \"sleep_min\": 5,
    \"sleep_max\": 10,
    \"exfil_jitter_min_ms\": 100,
    \"exfil_jitter_max_ms\": 500,
    \"exfil_chunks_per_burst\": 10,
    \"exfil_burst_pause_ms\": 1000,
    \"resolver\": \"172.20.0.12:53\",
    \"beacon_name\": \"mesh-beacon\",
    \"staged_registration\": false,
    \"static_link\": true
}")

CLIENT2_FILE=$(echo "$CLIENT2_RESP" | jq -r '.data.filename // empty')
BUILD2_ID=$(echo "$CLIENT2_RESP" | jq -r '.data.build_id // empty')
if [ -z "$CLIENT2_FILE" ]; then
    echo "[Setup] ERROR: Multi-DNS client build failed"
    echo "$CLIENT2_RESP" | jq .
    exit 1
fi
echo "[Setup] Multi-DNS client built: ${CLIENT2_FILE} (BuildID: ${BUILD2_ID})"

cp "${BUILDS_DIR}/client/${CLIENT2_FILE}" "${BUILDS_DIR}/beacon-mesh"
chmod +x "${BUILDS_DIR}/beacon-mesh"

# --------------------------------------------------------
# Build Go client: A-record polling
# --------------------------------------------------------
echo "[Setup] Building Go client (A-record poll)..."
AREC_RESP=$(api_post "/api/builder/client" "{
    \"dns_domains\": [\"alpha.test\"],
    \"platform\": \"linux\",
    \"architecture\": \"${GOARCH}\",
    \"sleep_min\": 5,
    \"sleep_max\": 8,
    \"resolver\": \"172.20.0.11:53\",
    \"beacon_name\": \"test-a-record\",
    \"static_link\": true,
    \"poll_phase\": {
        \"query_type\": \"A\",
        \"a_record_task_ip\": \"127.0.0.2\"
    }
}")
AREC_FILE=$(echo "$AREC_RESP" | jq -r '.data.filename // empty')
if [ -n "$AREC_FILE" ]; then
    cp "${BUILDS_DIR}/client/${AREC_FILE}" "${BUILDS_DIR}/beacon-a-record"
    chmod +x "${BUILDS_DIR}/beacon-a-record"
    echo "[Setup] A-record Go client built: ${AREC_FILE}"
else
    echo "[Setup] WARNING: A-record Go client build failed (non-fatal)"
    echo "$AREC_RESP" | jq .
fi

# --------------------------------------------------------
# Build Go client: unencrypted (base36 only)
# --------------------------------------------------------
echo "[Setup] Building Go client (unencrypted)..."
UNENC_RESP=$(api_post "/api/builder/client" "{
    \"dns_domains\": [\"alpha.test\"],
    \"platform\": \"linux\",
    \"architecture\": \"${GOARCH}\",
    \"sleep_min\": 5,
    \"sleep_max\": 8,
    \"resolver\": \"172.20.0.11:53\",
    \"beacon_name\": \"test-unencrypted\",
    \"static_link\": true,
    \"encrypted\": false
}")
UNENC_FILE=$(echo "$UNENC_RESP" | jq -r '.data.filename // empty')
if [ -n "$UNENC_FILE" ]; then
    cp "${BUILDS_DIR}/client/${UNENC_FILE}" "${BUILDS_DIR}/beacon-unencrypted"
    chmod +x "${BUILDS_DIR}/beacon-unencrypted"
    echo "[Setup] Unencrypted Go client built: ${UNENC_FILE}"
else
    echo "[Setup] WARNING: Unencrypted Go client build failed (non-fatal)"
    echo "$UNENC_RESP" | jq .
fi

# --------------------------------------------------------
# Build Go client: staged registration
# --------------------------------------------------------
echo "[Setup] Building Go client (staged registration)..."
STAGED_RESP=$(api_post "/api/builder/client" "{
    \"dns_domains\": [\"alpha.test\"],
    \"platform\": \"linux\",
    \"architecture\": \"${GOARCH}\",
    \"sleep_min\": 5,
    \"sleep_max\": 8,
    \"resolver\": \"172.20.0.11:53\",
    \"beacon_name\": \"test-staged\",
    \"static_link\": true,
    \"staged_registration\": true
}")
STAGED_FILE=$(echo "$STAGED_RESP" | jq -r '.data.filename // empty')
if [ -n "$STAGED_FILE" ]; then
    cp "${BUILDS_DIR}/client/${STAGED_FILE}" "${BUILDS_DIR}/beacon-staged"
    chmod +x "${BUILDS_DIR}/beacon-staged"
    echo "[Setup] Staged Go client built: ${STAGED_FILE}"
else
    echo "[Setup] WARNING: Staged Go client build failed (non-fatal)"
    echo "$STAGED_RESP" | jq .
fi

# --------------------------------------------------------
# Summary
# --------------------------------------------------------
echo ""
echo "=== Setup Complete ==="
echo "  Archon:         ${ARCHON_URL}"
echo "  DNS Server 1:   172.20.0.11:53 (alpha.test)"
echo "  DNS Server 2:   172.20.0.12:53 (bravo.test)"
echo "  Beacon (Go):    172.20.0.20 -> dns1 (BuildID: ${BUILD_ID})"
echo "  Beacon (mesh):  -> dns2 (BuildID: ${BUILD2_ID})"
echo ""
echo "  Extended test beacons:"
echo "    beacon-a-record     Go   A-record poll"
echo "    beacon-unencrypted  Go   base36 (no AES)"
echo "    beacon-staged       Go   staged registration"
echo ""
echo "  Login:          admin / ${ADMIN_PASS}"
echo "  Web UI:         https://localhost:8443"
echo ""
