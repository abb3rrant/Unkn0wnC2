#!/bin/bash
#
# Unkn0wnC2 Master Installation Script
#
# This script:
# 1. Compiles the Master server binary
# 2. Installs to /opt/unkn0wnc2/ (config, certs, web files)
# 3. Installs binary to /usr/bin/unkn0wnc2
# 4. Master server includes web UI for building DNS servers, clients, and stagers
#
# USAGE:
#   sudo bash build.sh
#

set -e

VERSION="0.5.0"
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
echo -e "${GREEN}Unkn0wnC2 Archon Installation${NC}"
echo -e "${GREEN}Version: ${VERSION}${NC}"
echo ""

# Check for root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Error: This script must be run as root${NC}"
  echo "Usage: sudo bash build.sh"
  exit 1
fi

# Ensure cargo/rustup installed under either root or the invoking sudo user are in PATH
maybe_source_cargo_env() {
  local env_file="$1"
  if [ -f "$env_file" ]; then
    # shellcheck disable=SC1090
    . "$env_file"
  fi
}

append_path_if_dir() {
  local dir="$1"
  if [ -d "$dir" ] && [[ ":$PATH:" != *":$dir:"* ]]; then
    PATH="$dir:$PATH"
  fi
}

maybe_source_cargo_env "/root/.cargo/env"
append_path_if_dir "/root/.cargo/bin"

if [ -n "$SUDO_USER" ]; then
  maybe_source_cargo_env "/home/$SUDO_USER/.cargo/env"
  append_path_if_dir "/home/$SUDO_USER/.cargo/bin"
fi

echo -e "${YELLOW}[0/5] Checking build dependencies...${NC}"

# Check for required commands
MISSING_DEPS=()
NEEDS_RUSTUP=false

# Go compiler
if ! command -v go &>/dev/null; then
  MISSING_DEPS+=("go (Go compiler)")
fi

# Rust toolchain
if ! command -v cargo &>/dev/null; then
  MISSING_DEPS+=("cargo (Rust toolchain)")
fi
if ! command -v rustup &>/dev/null; then
  MISSING_DEPS+=("rustup (Rust toolchain manager)")
  NEEDS_RUSTUP=true
fi

# GCC for Linux stager builds
if ! command -v gcc &>/dev/null; then
  MISSING_DEPS+=("gcc (GNU C compiler)")
fi

# MinGW for Windows builds (64-bit and 32-bit)
if ! command -v x86_64-w64-mingw32-gcc &>/dev/null; then
  MISSING_DEPS+=("x86_64-w64-mingw32-gcc (MinGW 64-bit cross-compiler)")
fi
if ! command -v i686-w64-mingw32-gcc &>/dev/null; then
  MISSING_DEPS+=("i686-w64-mingw32-gcc (MinGW 32-bit cross-compiler)")
fi

# ARM cross-compilers for Linux
if ! command -v arm-linux-gnueabihf-gcc &>/dev/null; then
  MISSING_DEPS+=("arm-linux-gnueabihf-gcc (ARM cross-compiler for armv7l)")
fi
if ! command -v aarch64-linux-gnu-gcc &>/dev/null; then
  MISSING_DEPS+=("aarch64-linux-gnu-gcc (ARM64 cross-compiler)")
fi

# Clang for macOS stager builds (native on macOS, optional on Linux)
if ! command -v clang &>/dev/null; then
  MISSING_DEPS+=("clang (C compiler for macOS stager builds)")
fi

# OpenSSL for certificate generation
if ! command -v openssl &>/dev/null; then
  MISSING_DEPS+=("openssl")
fi

# Check for zlib development headers (required for Linux stager)
if ! gcc -E -x c - </dev/null 2>&1 | grep -q "include.*zlib.h" &&
  ! [ -f /usr/include/zlib.h ] &&
  ! [ -f /usr/local/include/zlib.h ]; then
  MISSING_DEPS+=("zlib1g-dev (zlib development headers)")
fi

# If any dependencies are missing, show install commands
if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
  echo -e "${RED}✗ Missing required dependencies:${NC}"
  for dep in "${MISSING_DEPS[@]}"; do
    echo -e "${RED}  - ${dep}${NC}"
  done
  echo ""
  echo -e "${YELLOW}Install missing dependencies with:${NC}"
  echo ""

  # Detect package manager and show appropriate command
  if command -v apt-get &>/dev/null; then
    echo -e "${GREEN}  sudo apt-get update${NC}"
    INSTALL_CMD="sudo apt-get install -y"
    PACKAGES=()

    for dep in "${MISSING_DEPS[@]}"; do
      case "$dep" in
      *"Go compiler"*)
        PACKAGES+=("golang-go")
        ;;
      *"Rust toolchain"*)
        PACKAGES+=("cargo")
        ;;
      *"GNU C compiler"*)
        PACKAGES+=("gcc" "build-essential")
        ;;
      *"MinGW 64-bit"*)
        PACKAGES+=("gcc-mingw-w64-x86-64")
        ;;
      *"MinGW 32-bit"*)
        PACKAGES+=("gcc-mingw-w64-i686")
        ;;
      *"ARM cross-compiler for armv7l"*)
        PACKAGES+=("gcc-arm-linux-gnueabihf")
        ;;
      *"ARM64 cross-compiler"*)
        PACKAGES+=("gcc-aarch64-linux-gnu")
        ;;
      *"clang"*)
        PACKAGES+=("clang")
        ;;
      *"openssl"*)
        PACKAGES+=("openssl")
        ;;
      *"zlib"*)
        PACKAGES+=("zlib1g-dev")
        ;;
      esac
    done

    echo -e "${GREEN}  ${INSTALL_CMD} ${PACKAGES[@]}${NC}"

  elif command -v yum &>/dev/null; then
    echo -e "${GREEN}  sudo yum install -y golang gcc gcc-c++ mingw64-gcc mingw32-gcc gcc-arm-linux-gnu gcc-aarch64-linux-gnu clang openssl zlib-devel${NC}"

  elif command -v brew &>/dev/null; then
    echo -e "${GREEN}  # macOS with Homebrew${NC}"
    BREW_PACKAGES=()

    for dep in "${MISSING_DEPS[@]}"; do
      case "$dep" in
      *"Go compiler"*)
        BREW_PACKAGES+=("go")
        ;;
      *"Rust toolchain"*)
        BREW_PACKAGES+=("rust")
        ;;
      *"GNU C compiler"*)
        BREW_PACKAGES+=("gcc")
        ;;
      *"MinGW 64-bit"* | *"MinGW 32-bit"*)
        BREW_PACKAGES+=("mingw-w64")
        ;;
      *"ARM cross-compiler"* | *"ARM64 cross-compiler"*)
        echo -e "${YELLOW}  # Note: ARM cross-compilers for Linux require manual setup on macOS${NC}"
        echo -e "${YELLOW}  # Consider using Docker or a Linux VM for ARM Linux builds${NC}"
        ;;
      *"clang"*)
        echo -e "${YELLOW}  # clang is included with Xcode Command Line Tools${NC}"
        echo -e "${GREEN}  xcode-select --install${NC}"
        ;;
      *"openssl"*)
        BREW_PACKAGES+=("openssl")
        ;;
      *"zlib"*)
        BREW_PACKAGES+=("zlib")
        ;;
      esac
    done

    if [ ${#BREW_PACKAGES[@]} -gt 0 ]; then
      echo -e "${GREEN}  brew install ${BREW_PACKAGES[@]}${NC}"
    fi

  else
    echo -e "${YELLOW}  Please install the missing dependencies using your system's package manager${NC}"
  fi

  if [ "$NEEDS_RUSTUP" = true ]; then
    echo ""
    echo -e "${YELLOW}Rustup is required to manage the cross-compilation targets.${NC}"
    echo -e "${YELLOW}Install it with:${NC} ${GREEN}curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh${NC}"
  fi

  echo ""
  exit 1
fi

echo -e "${GREEN}✓ All build dependencies present${NC}"
echo -e "${GREEN}  - Go compiler: $(go version | awk '{print $3}')${NC}"
if command -v cargo &>/dev/null; then
  echo -e "${GREEN}  - Cargo: $(cargo --version | awk '{print $2}')${NC}"
fi
if command -v rustup &>/dev/null; then
  echo -e "${GREEN}  - Rustup: $(rustup --version | awk '{print $2}')${NC}"
fi
echo -e "${GREEN}  - GCC: $(gcc --version | head -1 | awk '{print $NF}')${NC}"
if command -v x86_64-w64-mingw32-gcc &>/dev/null; then
  echo -e "${GREEN}  - MinGW (64-bit): $(x86_64-w64-mingw32-gcc --version | head -1 | awk '{print $NF}')${NC}"
fi
if command -v i686-w64-mingw32-gcc &>/dev/null; then
  echo -e "${GREEN}  - MinGW (32-bit): $(i686-w64-mingw32-gcc --version | head -1 | awk '{print $NF}')${NC}"
fi
if command -v arm-linux-gnueabihf-gcc &>/dev/null; then
  echo -e "${GREEN}  - ARM (armv7l): $(arm-linux-gnueabihf-gcc --version | head -1 | awk '{print $NF}')${NC}"
fi
if command -v aarch64-linux-gnu-gcc &>/dev/null; then
  echo -e "${GREEN}  - ARM64: $(aarch64-linux-gnu-gcc --version | head -1 | awk '{print $NF}')${NC}"
fi
if command -v clang &>/dev/null; then
  echo -e "${GREEN}  - Clang: $(clang --version | head -1 | awk '{print $NF}')${NC}"
fi
echo -e "${GREEN}  - OpenSSL: $(openssl version | awk '{print $2}')${NC}"
echo -e "${GREEN}  - zlib: available${NC}"
echo ""

REQUIRED_RUST_TARGETS=(
  "x86_64-unknown-linux-gnu"
  "i686-unknown-linux-gnu"
  "aarch64-unknown-linux-gnu"
  "armv7-unknown-linux-gnueabihf"
  "arm-unknown-linux-gnueabihf"
  "x86_64-pc-windows-gnu"
  "i686-pc-windows-gnu"
)

# Add macOS targets only when running on macOS (cross-compile not supported from Linux)
if [ "$(uname -s)" = "Darwin" ]; then
  REQUIRED_RUST_TARGETS+=(
    "x86_64-apple-darwin"
    "aarch64-apple-darwin"
  )
fi

if command -v rustup &>/dev/null; then
  echo -e "${YELLOW}Validating Rust targets...${NC}"
  INSTALLED_TARGETS=$(rustup target list --installed)
  MISSING_RUST_TARGETS=()

  for target in "${REQUIRED_RUST_TARGETS[@]}"; do
    if ! grep -Fqx "$target" <<<"$INSTALLED_TARGETS"; then
      MISSING_RUST_TARGETS+=("$target")
    fi
  done

  if [ ${#MISSING_RUST_TARGETS[@]} -gt 0 ]; then
    echo -e "${RED}✗ Missing Rust targets:${NC}"
    for target in "${MISSING_RUST_TARGETS[@]}"; do
      echo -e "${RED}  - ${target}${NC}"
    done
    echo ""
    echo -e "${YELLOW}Install them with:${NC} ${GREEN}rustup target add ${MISSING_RUST_TARGETS[*]}${NC}"
    echo ""
    exit 1
  fi

  echo -e "${GREEN}✓ All required Rust targets installed${NC}"
  echo ""
fi

# Build flags
LDFLAGS="-s -w -X main.version=${VERSION} -X main.buildDate=${BUILD_DATE} -X main.gitCommit=${GIT_COMMIT}"
BUILDFLAGS="-trimpath"

echo -e "${YELLOW}[1/7] Building Archon Server...${NC}"
cd Archon
go build ${BUILDFLAGS} -ldflags="${LDFLAGS}" -o unkn0wnc2 .
if [ $? -ne 0 ]; then
  echo -e "${RED}Failed to build Archon server${NC}"
  exit 1
fi
echo -e "${GREEN}✓ Archon server compiled: $(du -h unkn0wnc2 | cut -f1)${NC}"
echo ""

echo -e "${YELLOW}[2/7] Creating directory structure...${NC}"
mkdir -p /opt/unkn0wnc2/{certs,web,configs,builders,builds/dns-server,builds/client,builds/stager,builds/exfil,src}
echo -e "${GREEN}✓ Created /opt/unkn0wnc2/${NC}"
echo ""

echo -e "${YELLOW}[3/7] Installing files...${NC}"

# Install binary
install -m 755 unkn0wnc2 /usr/bin/unkn0wnc2
echo -e "${GREEN}✓ Installed binary to /usr/bin/unkn0wnc2${NC}"

# Copy web files
cp -r web/* /opt/unkn0wnc2/web/
echo -e "${GREEN}✓ Copied web interface files${NC}"

# Copy source files for building components
cd ..
cp -r Server Client Stager exfil-client /opt/unkn0wnc2/src/
echo -e "${GREEN}✓ Copied source files for builder${NC}"
if command -v cargo &>/dev/null; then
  echo -e "${YELLOW}  ↳ Priming Rust crate cache (cargo fetch --locked)${NC}"
  if pushd /opt/unkn0wnc2/src/exfil-client >/dev/null; then
    if cargo fetch --locked; then
      echo -e "${GREEN}  ✓ Rust dependencies prefetched${NC}"
    else
      echo -e "${RED}  ✗ Failed to prefetch Rust dependencies${NC}"
      popd >/dev/null
      exit 1
    fi
    popd >/dev/null
  fi
fi
cd Archon

# Generate secure credentials
JWT_SECRET=$(openssl rand -hex 32)
ADMIN_PASSWORD=$(openssl rand -base64 16 | tr -d '/+=' | cut -c1-16)
ENCRYPTION_KEY=$(openssl rand -hex 16) # 32 character hex string for AES-256

# Create default config if it doesn't exist
if [ ! -f /opt/unkn0wnc2/master_config.json ]; then
  cat >/opt/unkn0wnc2/master_config.json <<EOFCONFIG
{
  "bind_addr": "0.0.0.0",
  "bind_port": 8443,
  "tls_cert": "/opt/unkn0wnc2/certs/master.crt",
  "tls_key": "/opt/unkn0wnc2/certs/master.key",
  "database_path": "/opt/unkn0wnc2/master.db",
  "web_root": "/opt/unkn0wnc2/web",
  "source_dir": "/opt/unkn0wnc2/src",
  "encryption_key": "${ENCRYPTION_KEY}",
  "jwt_secret": "${JWT_SECRET}",
  "session_timeout": 480,
  "admin_credentials": {
    "username": "admin",
    "password": "${ADMIN_PASSWORD}"
  },
  "debug": false
}
EOFCONFIG
  echo -e "${GREEN}✓ Created config with secure credentials${NC}"

  # Save credentials for display at end
  echo "${ADMIN_PASSWORD}" >/tmp/unkn0wnc2_admin_pass
else
  echo -e "${YELLOW}! Config already exists, keeping existing credentials${NC}"
  ADMIN_PASSWORD="<existing password from config>"
fi

cd ..
echo ""

echo -e "${YELLOW}[4/7] Generating TLS certificates...${NC}"
if [ ! -f /opt/unkn0wnc2/certs/master.crt ]; then
  openssl req -x509 -newkey rsa:4096 -nodes \
    -keyout /opt/unkn0wnc2/certs/master.key \
    -out /opt/unkn0wnc2/certs/master.crt \
    -days 365 \
    -subj "/C=US/ST=State/L=City/O=Unkn0wnC2/CN=master" \
    2>/dev/null

  chmod 600 /opt/unkn0wnc2/certs/master.key
  chmod 644 /opt/unkn0wnc2/certs/master.crt

  echo -e "${GREEN}✓ Generated self-signed TLS certificate (valid 365 days)${NC}"
else
  echo -e "${YELLOW}! Certificates already exist, skipping${NC}"
fi
echo ""

echo -e "${YELLOW}[5/7] Setting permissions...${NC}"
chown -R root:root /opt/unkn0wnc2
chmod 755 /opt/unkn0wnc2
chmod 600 /opt/unkn0wnc2/master_config.json
echo -e "${GREEN}✓ Permissions set${NC}"
echo ""

echo -e "${YELLOW}[6/7] Verifying builder environment...${NC}"

# Verify source files are in place
SOURCE_CHECK=true
for component in Server Client Stager exfil-client; do
  if [ ! -d "/opt/unkn0wnc2/src/${component}" ]; then
    echo -e "${RED}✗ Missing source: ${component}${NC}"
    SOURCE_CHECK=false
  else
    echo -e "${GREEN}✓ Source available: ${component}${NC}"
  fi
done

# Verify build directories exist
for build_type in dns-server client stager exfil; do
  if [ ! -d "/opt/unkn0wnc2/builds/${build_type}" ]; then
    echo -e "${RED}✗ Missing build directory: ${build_type}${NC}"
    SOURCE_CHECK=false
  fi
done

if [ "$SOURCE_CHECK" = true ]; then
  echo -e "${GREEN}✓ Builder environment ready${NC}"
else
  echo -e "${RED}✗ Builder environment incomplete${NC}"
  exit 1
fi
echo ""

echo -e "${YELLOW}[7/7] Creating systemd service file...${NC}"

# Create systemd service file
cat >/etc/systemd/system/unkn0wnc2.service <<'EOFSERVICE'
[Unit]
Description=Unkn0wnC2 Archon Master Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/unkn0wnc2
ExecStart=/usr/bin/unkn0wnc2 --bind-addr 0.0.0.0 --bind-port 8443
Restart=on-failure
RestartSec=5s

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=unkn0wnc2

[Install]
WantedBy=multi-user.target
EOFSERVICE

chmod 644 /etc/systemd/system/unkn0wnc2.service
systemctl daemon-reload
echo -e "${GREEN}✓ Created systemd service file${NC}"
echo -e "${GREEN}✓ Service: /etc/systemd/system/unkn0wnc2.service${NC}"
echo ""

echo -e "${GREEN}════════════════════════════════════${NC}"
echo -e "${GREEN}Installation Complete!${NC}"
echo -e "${GREEN}════════════════════════════════════${NC}"
echo ""

# Display generated credentials if new install
if [ -f /tmp/unkn0wnc2_admin_pass ]; then
  ADMIN_PASSWORD=$(cat /tmp/unkn0wnc2_admin_pass)
  ENCRYPTION_KEY=$(grep '"encryption_key"' /opt/unkn0wnc2/master_config.json | cut -d'"' -f4)
  echo -e "${CYAN}╔═════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${CYAN}║                       ADMIN CREDENTIALS                     ║${NC}"
  echo -e "${CYAN}╠═════════════════════════════════════════════════════════════╣${NC}"
  echo -e "${CYAN}║${NC} Username: ${GREEN}admin${NC}                                             ${CYAN}║${NC}"
  echo -e "${CYAN}║${NC} Password: ${GREEN}${ADMIN_PASSWORD}${NC}                                  ${CYAN}║${NC}"
  echo -e "${CYAN}╠═════════════════════════════════════════════════════════════╣${NC}"
  echo -e "${CYAN}║${NC} Encryption Key: ${GREEN}${ENCRYPTION_KEY}${NC}            ${CYAN}║${NC}"
  echo -e "${CYAN}╚═════════════════════════════════════════════════════════════╝${NC}"
  echo ""
  echo -e "${YELLOW}These credentials will NOT be shown again!${NC}"
  echo -e "${YELLOW}Change password after first login via web UI${NC}"
  echo ""
  rm -f /tmp/unkn0wnc2_admin_pass
fi

echo -e "${CYAN}USAGE:${NC}"
echo "  Start Archon Server manually:"
echo "    unkn0wnc2 --bind-addr <ip> --bind-port <port>"
echo ""
echo "  Or use systemd service:"
echo "    sudo vim /etc/systemd/system/unkn0wnc2.service  # Customize bind address/port"
echo "    sudo systemctl daemon-reload # Reload Systemd"
echo "    sudo systemctl enable --now unkn0wnc2 # Enable on boot and start the service"
echo ""
echo -e "${CYAN}WEB INTERFACE:${NC}"
echo "  Access at: https://<your-ip>:8443/"
echo "  Login with the credentials shown above"
echo ""
echo -e "${CYAN}BUILDER:${NC}"
echo "  Navigate to the Builder page in the web interface to:"
echo "  - Build DNS servers with custom domains"
echo "  - Generate clients with configured DNS servers"
echo "  - Create stagers with timing parameters"
echo ""
echo -e "${CYAN}FILES INSTALLED:${NC}"
echo "  Binary:       /usr/bin/unkn0wnc2"
echo "  Config:       /opt/unkn0wnc2/master_config.json"
echo "  Certificates: /opt/unkn0wnc2/certs/"
echo "  Web Files:    /opt/unkn0wnc2/web/"
echo "  Database:     /opt/unkn0wnc2/master.db (created on first run)"
echo "  Service:      /etc/systemd/system/unkn0wnc2.service"
echo ""

