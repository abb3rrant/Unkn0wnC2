# Release process

Unkn0wnC2 releases are built from a clean, committed tree. The release script refuses uncommitted or untracked input so the binary, source bundle, checksum, SBOM, and Git commit cannot silently disagree.

## Required tools

- Go 1.25.14 or newer.
- GNU tar and `sha256sum`.
- Syft 1.38.2 for the CycloneDX SBOM.

Install the pinned SBOM generator without changing this repository's module graph:

```bash
GOTOOLCHAIN=local go install github.com/anchore/syft/cmd/syft@v1.38.2
```

## Build

```bash
./scripts/build-release.sh
sha256sum -c dist/SHA256SUMS
```

The script builds static Linux amd64 and arm64 Archon binaries with read-only modules, `-trimpath`, VCS stamping disabled, and version metadata from `VERSION` and the current commit. Archives are normalized to the commit timestamp, numeric owner/group zero, and sorted paths. Each archive has a CycloneDX JSON SBOM.

Artifacts are written to `dist/`:

- `Unkn0wnC2-v<version>-linux-amd64.tar.gz`
- `Unkn0wnC2-v<version>-linux-amd64.sbom.cdx.json`
- `Unkn0wnC2-v<version>-linux-arm64.tar.gz`
- `Unkn0wnC2-v<version>-linux-arm64.sbom.cdx.json`
- `SHA256SUMS`

## Production container

`docker/Dockerfile.release` builds the linux/amd64 Archon service from an
architecture-specific, digest-pinned Go 1.25.14 base. The runtime keeps the Go
toolchain and cross-compilers because Archon builds listener and beacon
artifacts. It runs Archon as UID/GID 10001; source and web assets remain
root-owned and read-only while build, profile, data, log, and Go cache paths are
writable by that account.

```bash
VERSION=$(tr -d '[:space:]' < VERSION)
COMMIT=$(git rev-parse HEAD)
BUILD_DATE=$(date -u -d "@$(git show -s --format=%ct HEAD)" +%Y-%m-%d)
docker build --pull=false \
  --build-arg VERSION="$VERSION" \
  --build-arg GIT_COMMIT="$COMMIT" \
  --build-arg BUILD_DATE="$BUILD_DATE" \
  -f docker/Dockerfile.release \
  -t "unkn0wnc2:${VERSION}" .
```

Mount `/config/master_config.json` and its referenced TLS certificate/key into
the container. Persist `/opt/unkn0wnc2/data`, `/opt/unkn0wnc2/builds`, and
`/opt/unkn0wnc2/profiles`. Never bake credentials or private keys into the
image. Record the final image digest and generate a container-image SBOM before
publishing it.

## Release gate

Before tagging or publishing:

1. Confirm CI passed at the exact candidate commit.
2. Run all module tests, race tests, vet, staticcheck, `govulncheck`, and Gitleaks.
3. Build the archives twice from clean checkouts and compare archive SHA-256 values.
4. Smoke-test the native archive, production container, and remote Docker E2E topology.
5. Verify `SHA256SUMS` and validate both SBOMs as CycloneDX JSON.
6. Merge through the normal PR path.
7. Tag only the merged commit, then attach all five files to the release.

`docker/Dockerfile` and `docker/docker-compose.yml` are an integration-test
topology, not a production image. The topology requires caller-supplied test
secrets and starts multiple services. Publish only an image built from
`docker/Dockerfile.release`.
