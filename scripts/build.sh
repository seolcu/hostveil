#!/usr/bin/env bash
# Reproducible build for hostveil.
# Records the git tag, commit, and build date into the binary via -ldflags.
# -trimpath strips absolute paths; -buildvcs=false disables VCS stamping
# (we record the values ourselves below).
set -euo pipefail

cd "$(dirname "$0")/.."

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo v3.0.0)}"
COMMIT="${COMMIT:-$(git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)}"
BUILT="${BUILT:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
PKG="github.com/seolcu/hostveil/internal/version"

OUT_DIR="${OUT_DIR:-./dist}"
mkdir -p "$OUT_DIR"

LDFLAGS=(
  "-s"
  "-w"
  "-X ${PKG}.Version=${VERSION}"
  "-X ${PKG}.Commit=${COMMIT}"
  "-X ${PKG}.Built=${BUILT}"
)

go build \
  -trimpath \
  -buildvcs=false \
  -ldflags "${LDFLAGS[*]}" \
  -o "${OUT_DIR}/hostveil" \
  ./cmd/hostveil

# Record the build artifact's hash so a CI rerun can verify reproducibility.
sha256sum "${OUT_DIR}/hostveil" | tee "${OUT_DIR}/hostveil.sha256"
echo "hostveil ${VERSION} (commit ${COMMIT}, built ${BUILT})"
