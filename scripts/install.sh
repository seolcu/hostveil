#!/usr/bin/env bash
set -euo pipefail

VERSION=""
SKIP_TRIVY=false
SKIP_LYNIS=false
FORCE=false

usage() {
  cat <<'EOF'
Usage: install.sh [options]

Options:
  --version vX.Y.Z   Install a specific hostveil release (v prefix optional)
  --no-trivy         Skip trivy installation
  --no-lynis         Skip lynis installation
  --no-deps          Skip trivy and lynis (hostveil only)
  --yes, -y          Non-interactive mode (install all dependencies)
  --help, -h         Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      VERSION="${2#v}"
      shift 2
      ;;
    --no-trivy) SKIP_TRIVY=true; shift ;;
    --no-lynis) SKIP_LYNIS=true; shift ;;
    --no-deps) SKIP_TRIVY=true; SKIP_LYNIS=true; shift ;;
    --yes|-y) FORCE=true; shift ;;
    --help|-h) usage; exit 0 ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

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

# ─── INTERACTIVE CHECKBOX ─────────────────────────────────────────────────
DEP_TRIVY=true
DEP_LYNIS=true

if $FORCE; then
  DEP_TRIVY=true
  DEP_LYNIS=true
elif ! [[ -t 0 ]]; then
  DEP_TRIVY=true
  DEP_LYNIS=true
else
  prompt_deps() {
    local sel=$1
    printf "\033[2J\033[H"
    echo "  hostveil installer"
    echo ""
    echo "  Select dependencies (Space to toggle, Enter to confirm):"
    echo ""
    local items=("trivy" "lynis")
    local descs=("Compose/IaC + CVE scanner" "Host hardening auditor")
    for i in 0 1; do
      local marker="${items[$i]}"
      local checked=false
      [[ $i == 0 ]] && checked=$DEP_TRIVY
      [[ $i == 1 ]] && checked=$DEP_LYNIS
      local box="[ ]"
      $checked && box="[*]"
      local ptr="  "
      [[ $sel == $i ]] && ptr=" >"
      printf "%s %s %s    %s\n" "$ptr" "$box" "${items[$i]}" "${descs[$i]}"
    done
    echo ""
    echo "  ↑/↓ navigate · Space toggle · Enter install"
  }

  sel=0
  prompt_deps $sel
  while true; do
    IFS= read -rsn1 key
    if [[ $key == " " ]]; then
      [[ $sel == 0 ]] && DEP_TRIVY=$([ "$DEP_TRIVY" = true ] && echo false || echo true)
      [[ $sel == 1 ]] && DEP_LYNIS=$([ "$DEP_LYNIS" = true ] && echo false || echo true)
      prompt_deps $sel
    elif [[ $key == $'\x1b' ]]; then
      read -rsn2 key2
      if [[ $key2 == "[A" && $sel -gt 0 ]]; then sel=$((sel-1)); prompt_deps $sel
      elif [[ $key2 == "[B" && $sel -lt 1 ]]; then sel=$((sel+1)); prompt_deps $sel
      fi
    elif [[ $key == "" || $key == $'\n' ]]; then
      break
    fi
  done
  printf "\033[2J\033[H"
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
    lynis)
      LYNIS_VER=$(github_latest_tag CISOfy/lynis) || {
        echo "  ERROR: failed to determine latest lynis version" >&2
        return 1
      }
      curl -fsSL --retry 3 \
        "https://github.com/CISOfy/lynis/archive/refs/tags/${LYNIS_VER}.tar.gz" \
        -o "${TMPDIR}/lynis.tar.gz"
      tar xzf "${TMPDIR}/lynis.tar.gz" -C "$TMPDIR" || {
        echo "  ERROR: lynis extraction failed" >&2
        return 1
      }
      LYNIS_DIR=$(find "$TMPDIR" -maxdepth 1 -name 'lynis-*' -type d 2>/dev/null | head -1)
      if [[ -n "$LYNIS_DIR" ]]; then
        sudo rm -rf /usr/share/lynis
        sudo mv "$LYNIS_DIR" /usr/share/lynis
        sudo ln -sf /usr/share/lynis/lynis /usr/bin/lynis
        sudo chmod +x /usr/share/lynis/lynis
      else
        echo "  ERROR: lynis directory not found after extraction" >&2
        return 1
      fi
      ;;
  esac
}

if [[ "$SKIP_TRIVY" != true && "$DEP_TRIVY" == true ]]; then
  install_tool trivy trivy || exit 1
fi
if [[ "$SKIP_LYNIS" != true && "$DEP_LYNIS" == true ]]; then
  install_tool lynis lynis || exit 1
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
