#!/bin/bash
#
# Unkn0wnC2 Master Installation Script
# 
# This script:
# 1. Compiles the Master server binary
# 2. Installs to /opt/unkn0wnc2/ (config, certs, web files)
# 3. Installs binary to /usr/bin/unkn0wnc2
# 4. Master server includes web UI for building DNS servers, clients, and stagers
#
# USAGE:
#   sudo bash build.sh
#

set -e

VERSION="0.3.0"
BUILD_DATE=$(date -u '+%Y-%m-%d')
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${RED}"
cat << "EOF"
  _    _       _           ___                    _____ ___  
 | |  | |     | |         / _ \                  / ____|__ \ 
 | |  | |_ __ | | ___ __ | | | |_      ___ __   | |       ) |
 | |  | | '_ \| |/ / '_ \| | | \ \ /\ / / '_ \  | |      / / 
 | |__| | | | |   <| | | | |_| |\ V  V /| | | | | |____ / /_ 
  \____/|_| |_|_|\_\_| |_|\___/  \_/\_/ |_| |_|  \_____|____|
EOF
echo -e "${NC}"
echo -e "${GREEN}Unkn0wnC2 Master Installation${NC}"
echo -e "${GREEN}Version: ${VERSION}${NC}"
echo ""

# Check for root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Error: This script must be run as root${NC}"
    echo "Usage: sudo bash build.sh"
    exit 1
fi

# Build flags
LDFLAGS="-s -w -X main.version=${VERSION} -X main.buildDate=${BUILD_DATE} -X main.gitCommit=${GIT_COMMIT}"
BUILDFLAGS="-trimpath"

echo -e "${YELLOW}[1/5] Building Master Server...${NC}"
cd Master
go build ${BUILDFLAGS} -ldflags="${LDFLAGS}" -o unkn0wnc2 .
if [ $? -ne 0 ]; then
    echo -e "${RED}Failed to build Master server${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Master server compiled: $(du -h unkn0wnc2 | cut -f1)${NC}"
echo ""

echo -e "${YELLOW}[2/5] Creating directory structure...${NC}"
mkdir -p /opt/unkn0wnc2/{certs,web,configs,builders}
echo -e "${GREEN}✓ Created /opt/unkn0wnc2/${NC}"
echo ""

echo -e "${YELLOW}[3/5] Installing files...${NC}"

# Install binary
install -m 755 unkn0wnc2 /usr/bin/unkn0wnc2
echo -e "${GREEN}✓ Installed binary to /usr/bin/unkn0wnc2${NC}"

# Copy web files
cp -r web/* /opt/unkn0wnc2/web/
echo -e "${GREEN}✓ Copied web interface files${NC}"

# Generate secure credentials
JWT_SECRET=$(openssl rand -hex 32)
ADMIN_PASSWORD=$(openssl rand -base64 16 | tr -d '/+=' | cut -c1-16)

# Create default config if it doesn't exist
if [ ! -f /opt/unkn0wnc2/master_config.json ]; then
    cat > /opt/unkn0wnc2/master_config.json << EOFCONFIG
{
  "bind_addr": "0.0.0.0",
  "bind_port": 8443,
  "tls_cert": "/opt/unkn0wnc2/certs/master.crt",
  "tls_key": "/opt/unkn0wnc2/certs/master.key",
  "database_path": "/opt/unkn0wnc2/master.db",
  "web_root": "/opt/unkn0wnc2/web",
  "jwt_secret": "${JWT_SECRET}",
  "session_timeout": 480,
  "admin_credentials": {
    "username": "admin",
    "password": "${ADMIN_PASSWORD}"
  },
  "debug": false
}
EOFCONFIG
    echo -e "${GREEN}✓ Created config with secure credentials${NC}"
    
    # Save credentials for display at end
    echo "${ADMIN_PASSWORD}" > /tmp/unkn0wnc2_admin_pass
else
    echo -e "${YELLOW}! Config already exists, keeping existing credentials${NC}"
    ADMIN_PASSWORD="<existing password from config>"
fi

cd ..
echo ""

echo -e "${YELLOW}[4/5] Generating TLS certificates...${NC}"
if [ ! -f /opt/unkn0wnc2/certs/master.crt ]; then
    openssl req -x509 -newkey rsa:4096 -nodes \
        -keyout /opt/unkn0wnc2/certs/master.key \
        -out /opt/unkn0wnc2/certs/master.crt \
        -days 365 \
        -subj "/C=US/ST=State/L=City/O=Unkn0wnC2/CN=master" \
        2>/dev/null
    
    chmod 600 /opt/unkn0wnc2/certs/master.key
    chmod 644 /opt/unkn0wnc2/certs/master.crt
    
    echo -e "${GREEN}✓ Generated self-signed TLS certificate (valid 365 days)${NC}"
else
    echo -e "${YELLOW}! Certificates already exist, skipping${NC}"
fi
echo ""

echo -e "${YELLOW}[5/5] Setting permissions...${NC}"
chown -R root:root /opt/unkn0wnc2
chmod 755 /opt/unkn0wnc2
chmod 600 /opt/unkn0wnc2/master_config.json
echo -e "${GREEN}✓ Permissions set${NC}"
echo ""

echo -e "${GREEN}════════════════════════════════════${NC}"
echo -e "${GREEN}Installation Complete!${NC}"
echo -e "${GREEN}════════════════════════════════════${NC}"
echo ""

# Display generated credentials if new install
if [ -f /tmp/unkn0wnc2_admin_pass ]; then
    ADMIN_PASSWORD=$(cat /tmp/unkn0wnc2_admin_pass)
    echo -e "${CYAN}╔════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║     ADMIN CREDENTIALS (SAVE THESE!)    ║${NC}"
    echo -e "${CYAN}╠════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC} Username: ${GREEN}admin${NC}                          ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC} Password: ${GREEN}${ADMIN_PASSWORD}${NC}                  ${CYAN}║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}⚠  These credentials will NOT be shown again!${NC}"
    echo -e "${YELLOW}⚠  Change password after first login via web UI${NC}"
    echo ""
    rm -f /tmp/unkn0wnc2_admin_pass
fi

echo -e "${CYAN}USAGE:${NC}"
echo "  Start Master Server:"
echo "    unkn0wnc2 --bind-addr <ip> --bind-port <port>"
echo ""
echo "  Example:"
echo "    unkn0wnc2 --bind-addr 0.0.0.0 --bind-port 8443"
echo ""
echo -e "${CYAN}WEB INTERFACE:${NC}"
echo "  Access at: https://<your-ip>:8443/"
echo "  Login with the credentials shown above"
echo ""
echo -e "${CYAN}BUILDER:${NC}"
echo "  Navigate to the Builder page in the web interface to:"
echo "  - Build DNS servers with custom domains"
echo "  - Generate clients with configured DNS servers"
echo "  - Create stagers with timing parameters"
echo ""
echo -e "${CYAN}FILES INSTALLED:${NC}"
echo "  Binary:       /usr/bin/unkn0wnc2"
echo "  Config:       /opt/unkn0wnc2/master_config.json"
echo "  Certificates: /opt/unkn0wnc2/certs/"
echo "  Web Files:    /opt/unkn0wnc2/web/"
echo "  Database:     /opt/unkn0wnc2/master.db (created on first run)"
echo ""
