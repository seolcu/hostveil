#!/usr/bin/env bash
set -euo pipefail

VERSION=""
VERSION_EXPLICIT=false
SKIP_TRIVY=false
FORCE=false

usage() {
  cat <<'EOF'
Usage: install.sh [options]

Options:
  --version vX.Y.Z   Install a specific hostveil release (v prefix optional)
  --no-trivy         Skip the optional trivy (image CVE scanner) install
  --no-deps          Install hostveil only (same as --no-trivy)
  --yes, -y          Non-interactive mode (install optional dependencies)
  --help, -h         Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      if [[ $# -lt 2 ]]; then
        echo "ERROR: --version requires a value" >&2
        usage >&2
        exit 1
      fi
      VERSION="${2#v}"
      VERSION_EXPLICIT=true
      shift 2
      ;;
    --no-trivy) SKIP_TRIVY=true; shift ;;
    --no-deps) SKIP_TRIVY=true; shift ;;
    --yes|-y) FORCE=true; shift ;;
    --help|-h) usage; exit 0 ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ "$VERSION_EXPLICIT" == true && -z "$VERSION" ]]; then
  echo "ERROR: --version requires a non-empty version (e.g. v2.6.0)" >&2
  exit 1
fi

# ─── OS / ARCH ────────────────────────────────────────────────────────────
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *)
    echo "Unsupported architecture: $ARCH" >&2
    exit 1
    ;;
esac
case "$OS" in
  linux|darwin) ;;
  *)
    echo "Unsupported OS: $OS" >&2
    exit 1
    ;;
esac

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# ─── HELPERS ──────────────────────────────────────────────────────────────
github_latest_tag() {
  local repo=$1
  local url tag
  url=$(curl -fsSL --retry 3 -o /dev/null -w '%{url_effective}' \
    "https://github.com/${repo}/releases/latest") || return 1
  tag=${url##*/}
  tag=${tag#v}
  if [[ -z "$tag" || "$tag" == "latest" ]]; then
    return 1
  fi
  echo "$tag"
}

sha256_hash() {
  if command -v sha256sum &>/dev/null; then
    sha256sum "$1" 2>/dev/null | awk '{print $1}'
  elif command -v shasum &>/dev/null; then
    shasum -a 256 "$1" 2>/dev/null | awk '{print $1}'
  else
    echo ""
  fi
}

require_sha256() {
  local file=$1
  local actual
  actual=$(sha256_hash "$file")
  if [[ -z "$actual" ]]; then
    echo "  ERROR: no sha256 tool available to verify ${file##*/}" >&2
    exit 1
  fi
  echo "$actual"
}

install_packages() {
  case "$PM" in
    apt) apt install -y "$@" ;;
    dnf) dnf install -y "$@" ;;
    yum) yum install -y "$@" ;;
    pacman) pacman -S --noconfirm "$@" ;;
    apk) apk add "$@" ;;
    zypper) zypper install -y "$@" ;;
    brew) brew install "$@" ;;
    *)
      echo "  • $1: no package manager found, skipping (install manually)"
      return 1
      ;;
  esac
}

package_available() {
  local pkg=$1
  case "$PM" in
    apt) apt-cache show "$pkg" >/dev/null 2>&1 ;;
    *) return 0 ;;
  esac
}

# ─── PACKAGE MANAGER ──────────────────────────────────────────────────────
PM=""
if command -v apt &>/dev/null; then PM="apt"
elif command -v dnf &>/dev/null; then PM="dnf"
elif command -v yum &>/dev/null; then PM="yum"
elif command -v pacman &>/dev/null; then PM="pacman"
elif command -v apk &>/dev/null; then PM="apk"
elif command -v zypper &>/dev/null; then PM="zypper"
elif command -v brew &>/dev/null; then PM="brew"
fi

# ─── OPTIONAL DEPENDENCY: TRIVY ───────────────────────────────────────────
# Trivy enables image CVE scanning. hostveil works fully without it, so it
# is entirely optional and can be added later.
DEP_TRIVY=true
if ! $FORCE && [[ -t 0 ]]; then
  printf "  Install Trivy for optional image CVE scanning? [Y/n] "
  IFS= read -r answer
  case "$answer" in
    n|N|no|NO) DEP_TRIVY=false ;;
  esac
fi

# ─── INSTALL DEPENDENCIES ─────────────────────────────────────────────────
install_tool() {
  local name=$1 && shift
  if command -v "$name" &>/dev/null; then
    echo "  • $name: already installed"
    return 0
  fi
  if [[ -z "$PM" ]]; then
    echo "  • $name: no package manager found, skipping (install manually)"
    return 0
  fi
  if package_available "$name"; then
    echo "  • $name: installing via $PM..."
    if install_packages "$@"; then
      return 0
    fi
    echo "  • $name: package install failed, trying binary download..."
  else
    echo "  • $name: not in $PM repos, downloading binary..."
  fi

  case "$name" in
    trivy)
      TRIVY_VER=$(github_latest_tag aquasecurity/trivy) || {
        echo "  ERROR: failed to determine latest trivy version" >&2
        return 1
      }
      case "$OS" in linux) TRIVY_OS="Linux" ;; darwin) TRIVY_OS="Darwin" ;; esac
      case "$ARCH" in amd64) TRIVY_ARCH="64bit" ;; arm64) TRIVY_ARCH="ARM64" ;; esac
      curl -fsSL --retry 3 \
        "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VER}/trivy_${TRIVY_VER}_${TRIVY_OS}-${TRIVY_ARCH}.tar.gz" \
        -o "${TMPDIR}/trivy.tar.gz"
      tar xzf "${TMPDIR}/trivy.tar.gz" -C "$TMPDIR" || {
        echo "  ERROR: trivy extraction failed" >&2
        return 1
      }
      TRIVY_BIN=$(find "$TMPDIR" -name 'trivy' -type f 2>/dev/null | head -1)
      if [[ -n "$TRIVY_BIN" ]]; then
        sudo install -m 755 "$TRIVY_BIN" /usr/bin/trivy
      else
        echo "  ERROR: trivy binary not found after extraction" >&2
        return 1
      fi
      ;;
  esac
}

if [[ "$SKIP_TRIVY" != true && "$DEP_TRIVY" == true ]]; then
  # Trivy is optional: a failed install must not abort hostveil's install.
  install_tool trivy trivy || echo "  ⚠ trivy not installed; CVE scanning will be skipped"
fi

# ─── INSTALL HOSTVEIL ────────────────────────────────────────────────────
if [[ -z "$VERSION" ]]; then
  VERSION=$(github_latest_tag seolcu/hostveil) || true
  if [[ -z "$VERSION" ]]; then
    echo "  ERROR: failed to determine latest hostveil version" >&2
    echo "  Try again later or specify a version with --version vX.Y.Z" >&2
    exit 1
  fi
fi

echo "  • hostveil: downloading v${VERSION}..."
TAR="hostveil-${OS}-${ARCH}.tar.gz"
URL="https://github.com/seolcu/hostveil/releases/download/v${VERSION}/${TAR}"
curl -fsSL --retry 3 "$URL" -o "${TMPDIR}/${TAR}" || {
  echo "  ERROR: download failed for ${URL}" >&2
  exit 1
}

echo "  • hostveil: verifying checksum..."
CHECKSUM_URL="https://github.com/seolcu/hostveil/releases/download/v${VERSION}/hostveil-checksums.txt"
if curl -fsSL --retry 3 "$CHECKSUM_URL" -o "${TMPDIR}/hostveil-checksums.txt"; then
  EXPECTED=$(grep "${TAR}" "${TMPDIR}/hostveil-checksums.txt" 2>/dev/null | awk '{print $1}')
  if [[ -n "$EXPECTED" ]]; then
    ACTUAL=$(require_sha256 "${TMPDIR}/${TAR}")
    if [[ "$EXPECTED" != "$ACTUAL" ]]; then
      echo "  ERROR: checksum mismatch for ${TAR}" >&2
      echo "    expected: $EXPECTED" >&2
      echo "    actual:   $ACTUAL" >&2
      exit 1
    fi
    echo "  ✓ checksum verified"
  else
    echo "  ⚠ ${TAR} not listed in checksums file, skipping verification"
  fi
else
  echo "  ⚠ checksums file not available, skipping verification"
fi

tar xzf "${TMPDIR}/${TAR}" -C "$TMPDIR" || {
  echo "  ERROR: extraction failed" >&2
  exit 1
}
sudo install -m 755 "${TMPDIR}/hostveil" /usr/bin/hostveil || {
  echo "  ERROR: install failed" >&2
  exit 1
}

if ! hostveil --version >/dev/null 2>&1; then
  echo "  ERROR: hostveil installed but --version check failed" >&2
  exit 1
fi

echo ""
echo "  hostveil v${VERSION} installed ($(hostveil --version))."
echo "  Run: hostveil"
