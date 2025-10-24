#!/bin/bash
#
# Production Build Script for Unkn0wnC2 DNS C2 Framework
# 
# This script builds optimized, stripped binaries for production deployment:
#   1. Embeds configuration from build_config.json into server binary
#   2. Builds server with production LDFLAGS (-s -w for stripping)
#   3. Builds Linux and Windows clients
#   4. Builds stager with configured jitter timing
#   5. Optional UPX compression for reduced binary size
#
# BEFORE RUNNING:
#   - Update build_config.json with your domain and network settings
#   - Change encryption_key from default value
#   - Review stager timing configuration for your OPSEC requirements
#
# USAGE:
#   bash build_production.sh
#
# OUTPUT:
#   All binaries will be in build/production/
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

# Check if build_config.json exists
if [ ! -f "build_config.json" ]; then
    echo -e "${RED}Error: build_config.json not found${NC}"
    exit 1
fi

echo -e "${YELLOW}[1/5] Embedding configuration from build_config.json...${NC}"
# Build and run the builder tool to embed config
cd tools/builder
go build -o ../../build-tool .
cd ../..

echo "  Running builder tool to embed configuration..."
./build-tool

# Clean up build-tool
rm -f build-tool build-tool.exe
echo -e "${GREEN}✓ Configuration embedded into source files${NC}"
echo ""

echo -e "${YELLOW}[2/5] Building Server (Linux) with optimizations...${NC}"
cd Server
GOOS=linux GOARCH=amd64 go build ${BUILDFLAGS} -ldflags="${LDFLAGS}" -o ../build/production/dns-server-linux .
echo -e "${GREEN}✓ Server built: $(du -h ../build/production/dns-server-linux | cut -f1)${NC}"
cd ..

echo -e "${YELLOW}[3/5] Building Client (Linux)...${NC}"
cd Client
GOOS=linux GOARCH=amd64 go build ${BUILDFLAGS} -ldflags="${LDFLAGS}" -o ../build/production/dns-client-linux .
echo -e "${GREEN}✓ Linux client built: $(du -h ../build/production/dns-client-linux | cut -f1)${NC}"
cd ..

echo -e "${YELLOW}[4/5] Building Client (Windows)...${NC}"
cd Client
GOOS=windows GOARCH=amd64 go build ${BUILDFLAGS} -ldflags="${LDFLAGS}" -o ../build/production/dns-client-windows.exe .
echo -e "${GREEN}✓ Windows client built: $(du -h ../build/production/dns-client-windows.exe | cut -f1)${NC}"
cd ..

echo -e "${YELLOW}[5/5] Building Stager (Linux) with jitter config...${NC}"
# Show stager config being used
if command -v jq &> /dev/null && [ -f "build_config.json" ]; then
    STAGER_JITTER_MIN=$(jq -r '.stager.jitter_min_ms // 100' build_config.json)
    STAGER_JITTER_MAX=$(jq -r '.stager.jitter_max_ms // 500' build_config.json)
    STAGER_CHUNKS=$(jq -r '.stager.chunks_per_burst // 10' build_config.json)
    STAGER_BURST=$(jq -r '.stager.burst_pause_ms // 2000' build_config.json)
    echo "  Expected Config: ${STAGER_JITTER_MIN}-${STAGER_JITTER_MAX}ms jitter, ${STAGER_CHUNKS} chunks/burst, ${STAGER_BURST}ms burst pause"
    echo ""
fi

cd Stager
make clean > /dev/null 2>&1 || true

# Build stager using build.sh (production mode - no debug)
# Do NOT suppress output so we can see what config is being compiled
echo "  Building stager from config..."
if bash build.sh; then
    # Copy from build directory (where build.sh puts it)
    if [ -f "../build/stager/stager-linux-x64" ]; then
        cp ../build/stager/stager-linux-x64 ../build/production/
        echo -e "${GREEN}✓ Stager built: $(du -h ../build/production/stager-linux-x64 | cut -f1)${NC}"
    else
        echo -e "${RED}✗ Stager binary not found at expected location${NC}"
        cd ..
        exit 1
    fi
else
    echo -e "${RED}✗ Stager build failed${NC}"
    cd ..
    exit 1
fi
cd ..

echo ""
echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}Optional: UPX Compression${NC}"
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

# Show compiled configuration summary
if command -v jq &> /dev/null && [ -f "build_config.json" ]; then
    echo -e "${YELLOW}COMPILED CONFIGURATION SUMMARY:${NC}"
    echo "────────────────────────────────────────"
    echo "Server:"
    jq -r '.server | "  Domain: \(.domain)\n  Bind: \(.bind_addr):\(.bind_port)\n  NS1: \(.ns1)\n  NS2: \(.ns2)"' build_config.json
    echo ""
    echo "Stager Timing:"
    STAGER_MIN=$(jq -r '.stager.jitter_min_ms' build_config.json)
    STAGER_MAX=$(jq -r '.stager.jitter_max_ms' build_config.json)
    STAGER_CHUNKS=$(jq -r '.stager.chunks_per_burst' build_config.json)
    STAGER_BURST=$(jq -r '.stager.burst_pause_ms' build_config.json)
    echo "  Jitter: ${STAGER_MIN}-${STAGER_MAX}ms ($(( STAGER_MIN / 1000 ))s-$(( STAGER_MAX / 1000 ))s)"
    echo "  Burst: ${STAGER_CHUNKS} chunks per burst"
    echo "  Pause: ${STAGER_BURST}ms ($(( STAGER_BURST / 1000 ))s) between bursts"
    TOTAL_MIN=$((STAGER_MIN + STAGER_BURST))
    TOTAL_MAX=$((STAGER_MAX + STAGER_BURST))
    echo "  Total delay between bursts: $(( TOTAL_MIN / 1000 ))s-$(( TOTAL_MAX / 1000 ))s"
    echo ""
fi

echo -e "${YELLOW}⚠️  DEPLOYMENT CHECKLIST:${NC}"
echo "  [ ] Change encryption key (server config.json + client build_config.json)"
echo "  [ ] Configure domain and NS records"
echo "  [ ] Set proper bind address for server"
echo "  [ ] Disable debug mode in production"
echo "  [ ] Review OPSEC considerations in README.md"
echo ""
echo -e "${GREEN}Ready for deployment!${NC}"
