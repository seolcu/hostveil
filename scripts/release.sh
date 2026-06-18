#!/usr/bin/env bash
# Release script for hostveil v3.x.
#
# Tags the repo, builds the cross-platform binaries, signs them,
# and prepares a SHA-256SUMS file for the release tracker.
#
# Usage:
#   VERSION=v3.0.0 scripts/release.sh
#
# Requires: git, go >= 1.22, gpg (for signing), sha256sum, and (for
# the v3.x release tracker) gh (the GitHub CLI).
set -euo pipefail

cd "$(dirname "$0")/.."

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo v3.0.0)}"
DIST_DIR="dist-${VERSION}"
mkdir -p "${DIST_DIR}"

echo "==> Building hostveil ${VERSION}"
echo "    (cross-compile to linux/amd64 and linux/arm64)"

for arch in amd64 arm64; do
  GOOS=linux GOARCH="${arch}" ./scripts/build.sh
  mv dist/hostveil "${DIST_DIR}/hostveil-${VERSION}-linux-${arch}"
  mv dist/hostveil.sha256 "${DIST_DIR}/hostveil-${VERSION}-linux-${arch}.sha256"
done

# Build the variant binaries (noai / notui / noweb) for amd64
for variant in noai notui noweb; do
  echo "==> Building variant: ${variant}"
  go build -tags "${variant}" -trimpath -buildvcs=false \
    -ldflags "-X github.com/seolcu/hostveil/internal/version.Version=${VERSION}" \
    -o "${DIST_DIR}/hostveil-${VERSION}-linux-amd64-${variant}" \
    ./cmd/hostveil
done

echo "==> Computing SHA-256SUMS"
(cd "${DIST_DIR}" && sha256sum * > SHA256SUMS)
cat "${DIST_DIR}/SHA256SUMS"

if command -v gpg >/dev/null && [[ -n "${GPG_KEY:-}" ]]; then
  echo "==> Signing SHA256SUMS with gpg"
  gpg --armor --detach-sign --sign-with "${GPG_KEY}" \
    --output "${DIST_DIR}/SHA256SUMS.asc" "${DIST_DIR}/SHA256SUMS"
fi

if command -v gh >/dev/null; then
  echo "==> Creating git tag ${VERSION}"
  git tag -s -a "${VERSION}" -m "hostveil ${VERSION}"
  echo "==> To push the tag: git push origin ${VERSION}"
  echo "==> To upload the artifacts: gh release create ${VERSION} ${DIST_DIR}/*"
else
  echo "gh (GitHub CLI) not found; manually upload the contents of ${DIST_DIR}/ to the release tracker."
fi

echo "==> Done. Artifacts in ${DIST_DIR}/"
ls -la "${DIST_DIR}/"
