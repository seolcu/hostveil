#!/usr/bin/env bash
set -euo pipefail

VERSION=""
SKIP_TRIVY=false
SKIP_LYNIS=false
FORCE=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --no-trivy) SKIP_TRIVY=true; shift ;;
    --no-lynis) SKIP_LYNIS=true; shift ;;
    --yes|-y) FORCE=true; shift ;;
    --help|-h) echo "Usage: $0 [--version vX.Y.Z] [--no-trivy] [--no-lynis] [--yes]"; exit 0 ;;
    *) echo "Unknown: $1"; exit 1 ;;
  esac
done

# ─── OS / ARCH ────────────────────────────────────────────────────────────
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in x86_64|amd64) ARCH="amd64" ;; aarch64|arm64) ARCH="arm64" ;; *)
  echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac
case "$OS" in linux|darwin) ;; *)
  echo "Unsupported OS: $OS"; exit 1 ;;
esac

# ─── SHA256 helper (portable) ─────────────────────────────────────────────
sha256_hash() {
  if command -v sha256sum &>/dev/null; then
    sha256sum "$1" 2>/dev/null | cut -d' ' -f1
  elif command -v shasum &>/dev/null; then
    shasum -a 256 "$1" 2>/dev/null | cut -d' ' -f1
  else
    echo ""
  fi
}

# ─── PACKAGE MANAGER ──────────────────────────────────────────────────────
PM=""
PM_INSTALL=""
if command -v apt &>/dev/null; then PM="apt"; PM_INSTALL="apt install -y"
elif command -v dnf &>/dev/null; then PM="dnf"; PM_INSTALL="dnf install -y"
elif command -v yum &>/dev/null; then PM="yum"; PM_INSTALL="yum install -y"
elif command -v pacman &>/dev/null; then PM="pacman"; PM_INSTALL="pacman -S --noconfirm"
elif command -v apk &>/dev/null; then PM="apk"; PM_INSTALL="apk add"
elif command -v zypper &>/dev/null; then PM="zypper"; PM_INSTALL="zypper install -y"
elif command -v brew &>/dev/null; then PM="brew"; PM_INSTALL="brew install"
fi

# ─── INTERACTIVE CHECKBOX ─────────────────────────────────────────────────
DEP_TRIVY=true
DEP_LYNIS=true

if $FORCE; then
  DEP_TRIVY=true; DEP_LYNIS=true
elif ! [[ -t 0 ]]; then
  DEP_TRIVY=true; DEP_LYNIS=true
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
    return
  fi
  if [[ -z "$PM" ]]; then
    echo "  • $name: no package manager found, skipping (install manually)"
    return
  fi
  local pkg_exists=true
  if [[ "$PM" == "apt" ]]; then
    apt-cache show "$name" >/dev/null 2>&1 || pkg_exists=false
  fi
  if $pkg_exists; then
    echo "  • $name: installing via $PM..."
    $PM_INSTALL "$@" 2>/dev/null && return
  fi
  echo "  • $name: fallback to binary download..."
  case "$name" in
    trivy)
      curl -fsSL --retry 3 "https://github.com/aquasecurity/trivy/releases/latest/download/trivy_${VERSION}_${OS}-${ARCH}.tar.gz" -o "/tmp/trivy.tar.gz"
      tar xzf "/tmp/trivy.tar.gz" -C /tmp || { echo "  ERROR: trivy extraction failed"; return; }
      TRIVY_BIN=$(find /tmp -name 'trivy' -type f 2>/dev/null | head -1)
      if [[ -n "$TRIVY_BIN" ]]; then
        sudo install -m 755 "$TRIVY_BIN" /usr/bin/trivy
      else
        echo "  ERROR: trivy binary not found after extraction"
      fi
      rm -f "/tmp/trivy.tar.gz" ;;
    lynis)
      LYNIS_VER=$(curl -fsSL --retry 3 https://api.github.com/repos/CISOfy/lynis/releases/latest | grep '"tag_name":' | sed 's/.*"\([^"]*\)".*/\1/')
      curl -fsSL --retry 3 "https://github.com/CISOfy/lynis/archive/refs/tags/${LYNIS_VER}.tar.gz" -o "/tmp/lynis.tar.gz"
      tar xzf "/tmp/lynis.tar.gz" -C /tmp || { echo "  ERROR: lynis extraction failed"; return; }
      LYNIS_DIR=$(find /tmp -maxdepth 1 -name 'lynis-*' -type d 2>/dev/null | head -1)
      if [[ -n "$LYNIS_DIR" ]]; then
        sudo rm -rf /usr/share/lynis
        sudo mv "$LYNIS_DIR" /usr/share/lynis
        sudo ln -sf /usr/share/lynis/lynis /usr/bin/lynis
        sudo chmod +x /usr/share/lynis/lynis
      else
        echo "  ERROR: lynis directory not found after extraction"
      fi
      rm -f "/tmp/lynis.tar.gz" ;;
  esac
}

[[ "$SKIP_TRIVY" != true && "$DEP_TRIVY" == true ]] && install_tool trivy trivy
[[ "$SKIP_LYNIS" != true && "$DEP_LYNIS" == true ]] && install_tool lynis lynis

# ─── INSTALL HOSTVEIL ────────────────────────────────────────────────────
if [[ -z "$VERSION" ]]; then
  VERSION=$(curl -fsSL --retry 3 https://api.github.com/repos/seolcu/hostveil/releases/latest \
    | grep '"tag_name":' | sed 's/.*"v\([^"]*\)".*/\1/')
  if [[ -z "$VERSION" ]]; then
    echo "  ERROR: failed to determine latest version (GitHub API rate limit?)"
    echo "  Try again later or specify a version with --version vX.Y.Z"
    exit 1
  fi
fi

echo "  • hostveil: downloading v${VERSION}..."
TAR="hostveil-${OS}-${ARCH}.tar.gz"
URL="https://github.com/seolcu/hostveil/releases/download/v${VERSION}/${TAR}"
curl -fsSL --retry 3 "$URL" -o "/tmp/${TAR}" || { echo "  ERROR: download failed"; exit 1; }

echo "  • hostveil: verifying checksum..."
CHECKSUM_URL="https://github.com/seolcu/hostveil/releases/download/v${VERSION}/hostveil-checksums.txt"
curl -fsSL --retry 3 "$CHECKSUM_URL" -o "/tmp/hostveil-checksums.txt" 2>/dev/null || true
EXPECTED=$(grep "${TAR}" /tmp/hostveil-checksums.txt 2>/dev/null | cut -d' ' -f1)
if [[ -n "$EXPECTED" ]]; then
  ACTUAL=$(sha256_hash "/tmp/${TAR}")
  if [[ "$EXPECTED" != "$ACTUAL" ]]; then
    echo "  ERROR: checksum mismatch for ${TAR}"
    echo "    expected: $EXPECTED"
    echo "    actual:   $ACTUAL"
    rm -f "/tmp/${TAR}" "/tmp/hostveil-checksums.txt"
    exit 1
  fi
  echo "  ✓ checksum verified"
  rm -f "/tmp/hostveil-checksums.txt"
else
  echo "  ⚠ checksums file not available, skipping verification"
fi

tar xzf "/tmp/${TAR}" -C /tmp || { echo "  ERROR: extraction failed"; exit 1; }
sudo install -m 755 "/tmp/hostveil" /usr/bin/hostveil || { echo "  ERROR: install failed"; exit 1; }
rm -f "/tmp/${TAR}" "/tmp/hostveil"

echo ""
echo "  hostveil v${VERSION} installed."
echo "  Run: hostveil"
