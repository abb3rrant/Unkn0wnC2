#!/bin/bash
set -e

BINARY="/opt/unkn0wnc2/builds/beacon"

echo "[Client] Waiting for beacon binary..."
for i in $(seq 1 120); do
    if [ -x "$BINARY" ]; then
        echo "[Client] Binary found"
        break
    fi
    if [ "$i" -eq 120 ]; then
        echo "[Client] ERROR: Binary not found after 120s"
        exit 1
    fi
    sleep 1
done

# Wait for DNS server to be accepting queries
echo "[Client] Waiting for DNS server (172.20.0.11:53)..."
for i in $(seq 1 30); do
    if dig @172.20.0.11 alpha.test A +short +timeout=2 >/dev/null 2>&1; then
        echo "[Client] DNS server responding"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "[Client] WARNING: DNS server not responding, starting anyway"
    fi
    sleep 2
done

echo "[Client] Starting beacon..."
exec "$BINARY"
