#!/usr/bin/env bash
set -euo pipefail

VERSION=""
SKIP_TRIVY=false
SKIP_LYNIS=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --no-trivy) SKIP_TRIVY=true; shift ;;
    --no-lynis) SKIP_LYNIS=true; shift ;;
    --help|-h) echo "Usage: $0 [--version vX.Y.Z] [--no-trivy] [--no-lynis]"; exit 0 ;;
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

if ! [[ -t 0 ]]; then
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
  echo "  • $name: installing via $PM..."
  $PM_INSTALL "$@" 2>/dev/null || echo "  • $name: fallback to binary download..."
  if ! command -v "$name" &>/dev/null; then
    case "$name" in
      trivy)
        curl -fsSL "https://github.com/aquasecurity/trivy/releases/latest/download/trivy_${VERSION}_${OS}-${ARCH}.tar.gz" | tar xz -C /tmp
        sudo install -m 755 /tmp/trivy /usr/bin/trivy ;;
      lynis)
        curl -fsSL "https://github.com/CISOfy/lynis/archive/refs/tags/3.1.6.tar.gz" | tar xz -C /tmp
        sudo install -m 755 /tmp/lynis-3.1.6/lynis /usr/bin/lynis ;;
    esac
  fi
}

[[ "$SKIP_TRIVY" != true && "$DEP_TRIVY" == true ]] && install_tool trivy trivy
[[ "$SKIP_LYNIS" != true && "$DEP_LYNIS" == true ]] && install_tool lynis lynis

# ─── INSTALL HOSTVEIL ────────────────────────────────────────────────────
if [[ -z "$VERSION" ]]; then
  VERSION=$(curl -fsSL https://api.github.com/repos/seolcu/hostveil/releases/latest \
    | grep '"tag_name":' | sed 's/.*"v\([^"]*\)".*/\1/')
fi

echo "  • hostveil: downloading v${VERSION}..."
TAR="hostveil-${OS}-${ARCH}.tar.gz"
URL="https://github.com/seolcu/hostveil/releases/download/v${VERSION}/${TAR}"
curl -fsSL "$URL" -o "/tmp/${TAR}"
tar xzf "/tmp/${TAR}" -C /tmp
sudo install -m 755 "/tmp/hostveil" /usr/bin/hostveil
rm -f "/tmp/${TAR}" "/tmp/hostveil"

echo ""
echo "  hostveil v${VERSION} installed."
echo "  Run: hostveil"
