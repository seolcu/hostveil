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
# SC-009 requires that two builds with the same inputs produce the same hash.
sha256sum "${OUT_DIR}/hostveil" | tee "${OUT_DIR}/hostveil.sha256"

# If REFERENCE_SHA256 is provided (CI), compare. Build is non-reproducible
# only if the values differ AND we did not pass REFERENCE_FORCE=1.
if [ -n "${REFERENCE_SHA256:-}" ]; then
  ACTUAL="$(sha256sum "${OUT_DIR}/hostveil" | awk '{print $1}')"
  if [ "${ACTUAL}" != "${REFERENCE_SHA256}" ]; then
    echo "REPRODUCIBILITY FAIL: actual=${ACTUAL} reference=${REFERENCE_SHA256}" >&2
    echo "(this can be intentional; bump via REFERENCE_FORCE=1)" >&2
    if [ "${REFERENCE_FORCE:-0}" != "1" ]; then
      exit 1
    fi
  fi
fi

echo "hostveil ${VERSION} (commit ${COMMIT}, built ${BUILT})"
