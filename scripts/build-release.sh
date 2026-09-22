#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
OUT=${1:-"${ROOT}/dist"}
SYFT_BIN=${SYFT_BIN:-syft}
GO_BIN=${GO_BIN:-go}

fail() {
  printf 'release build: %s\n' "$*" >&2
  exit 1
}

command -v git >/dev/null 2>&1 || fail "git is required"
command -v tar >/dev/null 2>&1 || fail "GNU tar is required"
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required"
command -v "${GO_BIN}" >/dev/null 2>&1 || fail "Go 1.25.14 or newer is required"
command -v "${SYFT_BIN}" >/dev/null 2>&1 || fail "syft is required to generate the CycloneDX SBOM"

cd "${ROOT}"
if [ -n "$(git status --porcelain --untracked-files=normal)" ]; then
  fail "the release tree must be clean and committed"
fi

VERSION=$(tr -d '[:space:]' < VERSION)
[[ "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]] || fail "VERSION is not a semantic version: ${VERSION}"
COMMIT=$(git rev-parse HEAD)
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git show -s --format=%ct "${COMMIT}")}
[[ "${SOURCE_DATE_EPOCH}" =~ ^[0-9]+$ ]] || fail "SOURCE_DATE_EPOCH must be an integer"
BUILD_DATE=$(date -u -d "@${SOURCE_DATE_EPOCH}" '+%Y-%m-%d')

GO_VERSION=$(${GO_BIN} env GOVERSION)
MIN_GO_VERSION=go1.25.14
if ! printf '%s\n%s\n' "${MIN_GO_VERSION}" "${GO_VERSION}" | sort -V -C; then
  fail "Go 1.25.14 or newer is required, found ${GO_VERSION}"
fi

for module in Archon Client Server tools/builder; do
  (
    cd "${module}"
    "${GO_BIN}" mod verify
    "${GO_BIN}" mod tidy -diff
  )
done

rm -rf "${OUT}"
mkdir -p "${OUT}"
TMP=$(mktemp -d "${TMPDIR:-/tmp}/unkn0wnc2-release.XXXXXX")
trap 'rm -rf "${TMP}"' EXIT

LDFLAGS="-s -w -X main.version=${VERSION} -X main.buildDate=${BUILD_DATE} -X main.gitCommit=${COMMIT}"
TARGETS=(linux-amd64 linux-arm64)

for target in "${TARGETS[@]}"; do
  GOOS=${target%-*}
  GOARCH=${target#*-}
  BASE="Unkn0wnC2-v${VERSION}-${target}"
  STAGE="${TMP}/${BASE}"
  mkdir -p "${STAGE}/bin"

  git archive "${COMMIT}" -- \
    Archon/web Client Server Stager docs docker/Dockerfile.release \
    VERSION LICENSE README.md RELEASING.md TESTING.md build.sh update.sh \
    | tar -x -C "${STAGE}"

  (
    cd Archon
    CGO_ENABLED=0 GOOS="${GOOS}" GOARCH="${GOARCH}" \
      "${GO_BIN}" build -mod=readonly -trimpath -buildvcs=false \
      -ldflags="${LDFLAGS}" -o "${STAGE}/bin/unkn0wnc2" .
  )
  chmod 0755 "${STAGE}/bin/unkn0wnc2" "${STAGE}/build.sh" "${STAGE}/update.sh"

  cat > "${STAGE}/RELEASE-METADATA" <<EOF
version=${VERSION}
commit=${COMMIT}
source_date_epoch=${SOURCE_DATE_EPOCH}
build_date=${BUILD_DATE}
go_version=${GO_VERSION}
target=${target}
EOF

  "${SYFT_BIN}" "dir:${STAGE}" -q -o "cyclonedx-json=${OUT}/${BASE}.sbom.cdx.json"

  ARCHIVE="${OUT}/${BASE}.tar.gz"
  tar --sort=name --mtime="@${SOURCE_DATE_EPOCH}" --owner=0 --group=0 --numeric-owner \
    -C "${TMP}" -czf "${ARCHIVE}" "${BASE}"
done

(
  cd "${OUT}"
  sha256sum ./*.tar.gz ./*.sbom.cdx.json > SHA256SUMS
)

printf 'Release artifacts written to %s\n' "${OUT}"
printf 'Version: %s\nCommit: %s\n' "${VERSION}" "${COMMIT}"
