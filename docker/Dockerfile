FROM golang:1.24-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    gcc-mingw-w64-x86-64 \
    gcc-aarch64-linux-gnu \
    gcc-arm-linux-gnueabihf \
    zlib1g-dev \
    openssl \
    jq \
    curl \
    ca-certificates \
    sqlite3 \
    dnsutils \
    procps \
    wget \
    && rm -rf /var/lib/apt/lists/*

COPY . /src

# Build Archon
RUN VERSION=$(cat /src/VERSION | tr -d '[:space:]') && \
    BUILD_DATE=$(date -u '+%Y-%m-%d') && \
    GIT_COMMIT="docker" && \
    cd /src/Archon && CGO_ENABLED=1 go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X main.buildDate=${BUILD_DATE} -X main.gitCommit=${GIT_COMMIT}" \
    -o /usr/bin/unkn0wnc2 .

# Set up /opt/unkn0wnc2 directory structure (mirrors build.sh)
RUN mkdir -p /opt/unkn0wnc2/certs \
    /opt/unkn0wnc2/web \
    /opt/unkn0wnc2/configs \
    /opt/unkn0wnc2/builds/dns-server \
    /opt/unkn0wnc2/builds/client \
    /opt/unkn0wnc2/builds/stager \
    /opt/unkn0wnc2/builds/exfil \
    /opt/unkn0wnc2/src \
    /opt/unkn0wnc2/logs

# Copy web UI
RUN cp -r /src/Archon/web/* /opt/unkn0wnc2/web/

# Copy source for builder
RUN cp -r /src/Server /src/Client /src/Stager /src/exfil-client /opt/unkn0wnc2/src/

# Generate TLS certs
RUN openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout /opt/unkn0wnc2/certs/master.key \
    -out /opt/unkn0wnc2/certs/master.crt \
    -days 365 -subj "/CN=archon" 2>/dev/null && \
    chmod 600 /opt/unkn0wnc2/certs/master.key

# Copy scripts
COPY docker/scripts/ /scripts/
RUN chmod +x /scripts/*.sh

WORKDIR /opt/unkn0wnc2
