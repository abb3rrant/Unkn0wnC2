#!/bin/bash
set -e

CONFIG_PATH="/opt/unkn0wnc2/master_config.json"

# Generate config if it doesn't exist
if [ ! -f "$CONFIG_PATH" ]; then
    cat > "$CONFIG_PATH" <<EOF
{
  "bind_addr": "0.0.0.0",
  "bind_port": 8443,
  "tls_cert": "/opt/unkn0wnc2/certs/master.crt",
  "tls_key": "/opt/unkn0wnc2/certs/master.key",
  "database_path": "/opt/unkn0wnc2/data/master.db",
  "web_root": "/opt/unkn0wnc2/web",
  "source_dir": "/opt/unkn0wnc2/src",
  "encryption_key": "${ENCRYPTION_KEY}",
  "jwt_secret": "${JWT_SECRET}",
  "session_timeout": 480,
  "debug": true,
  "dns_servers": [],
  "admin_credentials": {
    "username": "admin",
    "password": "${ADMIN_PASSWORD}"
  }
}
EOF
    chmod 600 "$CONFIG_PATH"
    echo "[Archon] Generated config"
fi

mkdir -p /opt/unkn0wnc2/data /opt/unkn0wnc2/logs

echo "[Archon] Starting master server..."
exec /usr/bin/unkn0wnc2 -config "$CONFIG_PATH" -debug
