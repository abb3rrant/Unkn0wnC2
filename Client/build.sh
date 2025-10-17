#!/bin/bash

# Build script for standalone DNS C2 client
# This script embeds configuration at build time for a standalone executable

echo "Building standalone DNS C2 client..."

# Check if build_config.json exists
if [ ! -f "build_config.json" ]; then
    echo "ERROR: build_config.json not found!"
    echo "Please create build_config.json with your configuration."
    exit 1
fi

# Generate embedded config
echo "Generating embedded configuration..."
cd tools
go run generate_config.go
cd ..

# Build the client
echo "Compiling client..."
go build -ldflags="-s -w" -o dns-client .

if [ $? -eq 0 ]; then
    echo ""
    echo "✓ Build successful!"
    echo "✓ Standalone client: dns-client"
    echo "✓ Configuration embedded at build time"
    echo ""
    echo "The client is now standalone and does not require external config files."
else
    echo ""
    echo "✗ Build failed!"
    exit 1
fi