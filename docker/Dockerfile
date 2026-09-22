FROM --platform=linux/amd64 golang:1.25.14-bookworm@sha256:c268a04d59aea0b180ed9946a658cfab9e7b3391dc90eed6e4969ccff98c851f

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
    /opt/unkn0wnc2/src \
    /opt/unkn0wnc2/profiles \
    /opt/unkn0wnc2/logs

# Copy web UI
RUN cp -r /src/Archon/web/* /opt/unkn0wnc2/web/

# Copy source for builder (Server, Client, Stager).
RUN cp -r /src/Server /src/Client /src/Stager /opt/unkn0wnc2/src/

# Generate TLS certs
RUN openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout /opt/unkn0wnc2/certs/master.key \
    -out /opt/unkn0wnc2/certs/master.crt \
    -days 365 -subj "/CN=archon" 2>/dev/null && \
    chmod 600 /opt/unkn0wnc2/certs/master.key

# Generate the malleable HTTP listener certificate and its SPKI pin.
#
# The pin is computed the same way the beacon verifies it: SHA-256 over the
# certificate's DER SubjectPublicKeyInfo, base64 encoded. The listener checks its
# own certificate against this pin at startup, so a wrong recipe would fail the
# build's first listener rather than silently serving something beacons reject.
RUN openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout /opt/unkn0wnc2/certs/http-cdn-assets.key \
    -out /opt/unkn0wnc2/certs/http-cdn-assets.crt \
    -days 365 -subj "/CN=cdn.example.com" 2>/dev/null && \
    chmod 600 /opt/unkn0wnc2/certs/http-cdn-assets.key && \
    SPKI=$(openssl x509 -in /opt/unkn0wnc2/certs/http-cdn-assets.crt -pubkey -noout \
        | openssl pkey -pubin -outform der 2>/dev/null \
        | openssl dgst -sha256 -binary | openssl base64 -A) && \
    jq --arg pin "$SPKI" \
        '.tls.spki_sha256 = $pin | .enabled = false | .beacon_host = "172.20.0.11:8443"' \
        /src/Server/profiles/cdn-assets.json.example \
        > /opt/unkn0wnc2/profiles/cdn-assets.json && \
    echo "HTTP listener pin: $SPKI"

# Ship the profile reference beside the generated profile, so the format is
# discoverable from inside the container.
RUN cp /src/docs/http-transport.md /opt/unkn0wnc2/profiles/README.md

# Copy scripts
COPY docker/scripts/ /scripts/
RUN chmod +x /scripts/*.sh

WORKDIR /opt/unkn0wnc2
