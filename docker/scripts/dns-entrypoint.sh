#!/bin/bash
set -e

BINARY="/opt/unkn0wnc2/builds/${SERVER_BINARY:-dns-server-1}"

echo "[DNS] Waiting for binary: ${BINARY}"
for i in $(seq 1 120); do
    if [ -x "$BINARY" ]; then
        echo "[DNS] Binary found"
        break
    fi
    if [ "$i" -eq 120 ]; then
        echo "[DNS] ERROR: Binary not found after 120s"
        exit 1
    fi
    sleep 1
done

# Small delay to let Archon fully stabilize
sleep 2

echo "[DNS] Starting DNS server (${SERVER_BINARY})..."
exec "$BINARY" -d -bind-addr 0.0.0.0 -bind-port 53
