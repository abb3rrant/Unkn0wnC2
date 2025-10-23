#!/bin/bash
#
# Production Build Script for Unkn0wnC2
# Builds optimized, stripped binaries for deployment
#

set -e  # Exit on error

VERSION="0.1.0"
BUILD_DATE=$(date -u '+%Y-%m-%d_%H:%M:%S_UTC')
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}Unkn0wnC2 Production Build${NC}"
echo -e "${GREEN}Version: ${VERSION}${NC}"
echo -e "${GREEN}================================${NC}"
echo ""

# Build flags for maximum optimization and minimal binary size
LDFLAGS="-s -w -X main.version=${VERSION} -X main.buildDate=${BUILD_DATE} -X main.gitCommit=${GIT_COMMIT}"
BUILDFLAGS="-trimpath"

# Create build directory
mkdir -p build/production

echo -e "${YELLOW}[1/5] Building Server (Linux)...${NC}"
cd Server
GOOS=linux GOARCH=amd64 go build ${BUILDFLAGS} -ldflags="${LDFLAGS}" -o ../build/production/dns-server-linux .
echo -e "${GREEN}✓ Server built: $(du -h ../build/production/dns-server-linux | cut -f1)${NC}"
cd ..

echo -e "${YELLOW}[2/5] Building Client (Linux)...${NC}"
cd Client
GOOS=linux GOARCH=amd64 go build ${BUILDFLAGS} -ldflags="${LDFLAGS}" -o ../build/production/dns-client-linux .
echo -e "${GREEN}✓ Linux client built: $(du -h ../build/production/dns-client-linux | cut -f1)${NC}"
cd ..

echo -e "${YELLOW}[3/5] Building Client (Windows)...${NC}"
cd Client
GOOS=windows GOARCH=amd64 go build ${BUILDFLAGS} -ldflags="${LDFLAGS}" -o ../build/production/dns-client-windows.exe .
echo -e "${GREEN}✓ Windows client built: $(du -h ../build/production/dns-client-windows.exe | cut -f1)${NC}"
cd ..

echo -e "${YELLOW}[4/5] Building Stager (Linux)...${NC}"
cd Stager
make clean > /dev/null 2>&1 || true
make CFLAGS="-O3 -s -DDEBUG_MODE=0" > /dev/null
cp stager-linux-x64 ../build/production/
echo -e "${GREEN}✓ Stager built: $(du -h ../build/production/stager-linux-x64 | cut -f1)${NC}"
cd ..

echo -e "${YELLOW}[5/5] Optional: UPX Compression...${NC}"
if command -v upx &> /dev/null; then
    read -p "Apply UPX compression? (reduces size but may trigger AV) [y/N]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "  Compressing binaries with UPX..."
        upx --lzma --best build/production/dns-client-linux 2>/dev/null || true
        upx --lzma --best build/production/dns-client-windows.exe 2>/dev/null || true
        upx --lzma --best build/production/stager-linux-x64 2>/dev/null || true
        echo -e "${GREEN}  ✓ UPX compression complete${NC}"
    else
        echo "  Skipping UPX compression (better for OPSEC)"
    fi
else
    echo "  UPX not found - skipping compression (install with: apt install upx-ucl)"
fi

echo ""
echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}Production Build Complete!${NC}"
echo -e "${GREEN}================================${NC}"
echo ""
echo "Build artifacts in: build/production/"
echo ""
ls -lh build/production/
echo ""
echo -e "${YELLOW}⚠️  DEPLOYMENT CHECKLIST:${NC}"
echo "  [ ] Change encryption key (server config.json + client build_config.json)"
echo "  [ ] Configure domain and NS records"
echo "  [ ] Set proper bind address for server"
echo "  [ ] Disable debug mode in production"
echo "  [ ] Review OPSEC considerations in README.md"
echo ""
echo -e "${GREEN}Ready for deployment!${NC}"
