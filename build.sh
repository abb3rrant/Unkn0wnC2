#!/bin/bash

# Unkn0wnC2 Build Script
# Builds all components for deployment

set -e  # Exit on any error

echo "=== Unkn0wnC2 Build System ==="
echo ""

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "Error: Go is not installed or not in PATH"
    exit 1
fi

echo "Go version: $(go version)"
echo ""

# Check if build_config.json exists
if [ ! -f "build_config.json" ]; then
    echo "Error: build_config.json not found in current directory"
    echo "Make sure you're running this from the project root"
    exit 1
fi

# Build the build tool first
echo "Building build tool..."
cd tools/builder
go build -o ../../build-tool .
cd ../..

if [ ! -f "build-tool" ] && [ ! -f "build-tool.exe" ]; then
    echo "Error: Failed to build build tool"
    exit 1
fi

echo "✓ Build tool created successfully"
echo ""

# Run the build tool
echo "Running build process..."
if [ -f "build-tool.exe" ]; then
    ./build-tool.exe
else
    ./build-tool
fi

echo ""
echo "=== Build Complete ==="

# Show build contents
if [ -d "build" ]; then
    echo ""
    echo "Build output:"
    ls -la build/
    echo ""
    
    # Show deployment info if it exists
    if [ -f "build/deployment_info.json" ]; then
        echo "Deployment information:"
        cat build/deployment_info.json | head -20
        echo ""
    fi
    
    echo "Build artifacts are ready in the 'build' directory"
else
    echo "Warning: Build directory not found"
fi

# Clean up build tool
if [ -f "build-tool" ]; then
    rm build-tool
fi
if [ -f "build-tool.exe" ]; then
    rm build-tool.exe
fi

echo "Done!"