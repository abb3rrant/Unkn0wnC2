#!/bin/bash
#
# Unkn0wnC2 Update Script
#
# This script updates an existing Unkn0wnC2 installation:
# 1. Stops the unkn0wnc2 service
# 2. Rebuilds the Archon binary
# 3. Updates files in /opt/unkn0wnc2/
# 4. Optionally restarts the service
#
# USAGE:
#   sudo bash update.sh
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION=$(cat "${SCRIPT_DIR}/VERSION" | tr -d '[:space:]')
BUILD_DATE=$(date -u '+%Y-%m-%d')
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${RED}"
cat <<"EOF"
  _    _       _           ___                    _____ ___  
 | |  | |     | |         / _ \                  / ____|__ \ 
 | |  | |_ __ | | ___ __ | | | |_      ___ __   | |       ) |
 | |  | | '_ \| |/ / '_ \| | | \ \ /\ / / '_ \  | |      / / 
 | |__| | | | |   <| | | | |_| |\ V  V /| | | | | |____ / /_ 
  \____/|_| |_|_|\_\_| |_|\___/  \_/\_/ |_| |_|  \_____|____|
EOF
echo -e "${NC}"
echo -e "${CYAN}Unkn0wnC2 Archon Update${NC}"
echo -e "${CYAN}Version: ${VERSION}${NC}"
echo ""

# Check for root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Error: This script must be run as root${NC}"
  echo "Usage: sudo bash update.sh"
  exit 1
fi

# Check if unkn0wnc2 is installed
if [ ! -d "/opt/unkn0wnc2" ]; then
  echo -e "${RED}Error: /opt/unkn0wnc2 not found${NC}"
  echo "Please run build.sh first to perform initial installation"
  exit 1
fi

if [ ! -f "/usr/bin/unkn0wnc2" ]; then
  echo -e "${RED}Error: /usr/bin/unkn0wnc2 not found${NC}"
  echo "Please run build.sh first to perform initial installation"
  exit 1
fi

echo -e "${YELLOW}[1/5] Stopping unkn0wnc2 service...${NC}"
if systemctl is-active --quiet unkn0wnc2 2>/dev/null; then
  systemctl stop unkn0wnc2
  echo -e "${GREEN}✓ Service stopped${NC}"
  SERVICE_WAS_RUNNING=true
else
  echo -e "${YELLOW}! Service was not running${NC}"
  SERVICE_WAS_RUNNING=false
fi
echo ""

echo -e "${YELLOW}[2/5] Building Archon Server...${NC}"

# Build flags
LDFLAGS="-s -w -X main.version=${VERSION} -X main.buildDate=${BUILD_DATE} -X main.gitCommit=${GIT_COMMIT}"
BUILDFLAGS="-trimpath"

cd "${SCRIPT_DIR}/Archon"
go build ${BUILDFLAGS} -ldflags="${LDFLAGS}" -o unkn0wnc2 .
if [ $? -ne 0 ]; then
  echo -e "${RED}Failed to build Archon server${NC}"
  if [ "$SERVICE_WAS_RUNNING" = true ]; then
    echo -e "${YELLOW}Attempting to restart service with old binary...${NC}"
    systemctl start unkn0wnc2
  fi
  exit 1
fi
echo -e "${GREEN}✓ Archon server compiled: $(du -h unkn0wnc2 | cut -f1)${NC}"
echo ""

echo -e "${YELLOW}[3/5] Updating binary...${NC}"
install -m 755 unkn0wnc2 /usr/bin/unkn0wnc2
echo -e "${GREEN}✓ Updated /usr/bin/unkn0wnc2${NC}"
echo ""

echo -e "${YELLOW}[4/5] Updating files...${NC}"

# Update web files
cp -r "${SCRIPT_DIR}/Archon/web/"* /opt/unkn0wnc2/web/
echo -e "${GREEN}✓ Updated web interface files${NC}"

# Update source files for builder (Server, Client, Stager)
cd "${SCRIPT_DIR}"
cp -r Server Client Stager /opt/unkn0wnc2/src/
echo -e "${GREEN}✓ Updated source files${NC}"

# Set permissions
chown -R root:root /opt/unkn0wnc2/web
chown -R root:root /opt/unkn0wnc2/src
echo -e "${GREEN}✓ Permissions set${NC}"
echo ""

echo -e "${YELLOW}[5/5] Service restart...${NC}"

if [ "$SERVICE_WAS_RUNNING" = true ]; then
  read -p "Service was running before update. Restart now? [Y/n] " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Nn]$ ]]; then
    echo -e "${YELLOW}! Service not restarted. Start manually with:${NC}"
    echo "    sudo systemctl start unkn0wnc2"
  else
    systemctl start unkn0wnc2
    sleep 2
    if systemctl is-active --quiet unkn0wnc2; then
      echo -e "${GREEN}✓ Service restarted successfully${NC}"
    else
      echo -e "${RED}✗ Service failed to start. Check logs:${NC}"
      echo "    sudo journalctl -u unkn0wnc2 -n 50"
    fi
  fi
else
  read -p "Start unkn0wnc2 service now? [y/N] " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    systemctl start unkn0wnc2
    sleep 2
    if systemctl is-active --quiet unkn0wnc2; then
      echo -e "${GREEN}✓ Service started successfully${NC}"
    else
      echo -e "${RED}✗ Service failed to start. Check logs:${NC}"
      echo "    sudo journalctl -u unkn0wnc2 -n 50"
    fi
  else
    echo -e "${YELLOW}! Service not started. Start manually with:${NC}"
    echo "    sudo systemctl start unkn0wnc2"
  fi
fi
echo ""

echo -e "${GREEN}════════════════════════════════════${NC}"
echo -e "${GREEN}Update Complete!${NC}"
echo -e "${GREEN}════════════════════════════════════${NC}"
echo ""
echo -e "${CYAN}Updated files:${NC}"
echo "  Binary:       /usr/bin/unkn0wnc2"
echo "  Web Files:    /opt/unkn0wnc2/web/"
echo "  Source Files: /opt/unkn0wnc2/src/"
echo "    Go:         Server, Client, Stager"
echo ""
echo -e "${CYAN}Preserved files (not modified):${NC}"
echo "  Config:       /opt/unkn0wnc2/master_config.json"
echo "  Database:     /opt/unkn0wnc2/master.db"
echo "  Certificates: /opt/unkn0wnc2/certs/"
echo "  Builds:       /opt/unkn0wnc2/builds/"
echo ""
echo -e "${YELLOW}Note: Existing beacons/clients may need to be rebuilt${NC}"
echo -e "${YELLOW}if protocol changes were made in this update.${NC}"
echo ""
