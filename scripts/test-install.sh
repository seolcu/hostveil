#!/usr/bin/env bash
# scripts/test-install.sh — Test install.sh across Linux distributions via Docker
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PASS=0
FAIL=0
FAILED=()

# ── Colors (disable if not a tty) ─────────────────────────────────────────
if [ -t 1 ]; then
    GREEN='\033[32m'; RED='\033[31m'; BOLD='\033[1m'; RESET='\033[0m'
else
    GREEN=''; RED=''; BOLD=''; RESET=''
fi

# ── Prerequisites ─────────────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
    echo "Error: Docker is required to run installer tests"
    echo "Install from https://docs.docker.com/get-docker/"
    exit 1
fi

if [ ! -f "$SCRIPT_DIR/install.sh" ]; then
    echo "Error: install.sh not found at $SCRIPT_DIR/install.sh"
    exit 1
fi

# ── Test runner ───────────────────────────────────────────────────────────
# Arguments: image name setup_commands install_commands verify_commands
run() {
    local image=$1 name=$2 setup=$3 install=$4 verify=$5
    local log rc

    log=$(mktemp /tmp/hostveil-install-test-XXXXXX)

    printf "  [%s] %-27s " "$image" "$name"

    rc=0
    timeout 300 docker run --rm \
        -v "$SCRIPT_DIR/install.sh:/install.sh:ro" \
        "$image" \
        /bin/sh -c "
            $setup
            set -e
            echo '=== INSTALL ==='
            $install
            echo '=== VERIFY ==='
            $verify
            echo '=== PASS ==='
        " > "$log" 2>&1 || rc=$?

    if [ "$rc" -eq 0 ]; then
        echo -e "${GREEN}✓${RESET}"
        PASS=$((PASS + 1))
    else
        echo -e "${RED}✗${RESET}"
        [ "$rc" -eq 124 ] && echo "      (timeout after 300s)"
        # Show last relevant output (skip Docker pull progress)
        grep -v '^docker:' "$log" | tail -20 | sed 's/^/      /'
        FAIL=$((FAIL + 1))
        FAILED+=("$image / $name")
    fi

    rm -f "$log"
}

# ── Docker image setup ────────────────────────────────────────────────────
IMAGES=(
    "ubuntu:24.04"
    "debian:bookworm-slim"
    "fedora:latest"
    "archlinux:latest"
    "alpine:latest"
    "opensuse/tumbleweed:latest"
)

echo "Pulling Docker images..."
for img in "${IMAGES[@]}"; do
    (docker pull "$img" >/dev/null 2>&1 || true) &
done
wait
echo

# ── Setup helpers (distro-specific bootstrap) ─────────────────────────────
APT_SETUP='apt-get update -qq && apt-get install -y -qq curl sudo >/dev/null 2>&1'
DNF_SETUP='dnf install -y curl sudo >/dev/null 2>&1'
ARCH_SETUP='pacman-key --init 2>/dev/null || true; pacman -Sy --noconfirm curl sudo >/dev/null 2>&1'
APK_SETUP='apk add --no-cache bash curl sudo >/dev/null 2>&1'
ZYPPER_SETUP='zypper --non-interactive install curl sudo gawk >/dev/null 2>&1'

# ── Tests ──────────────────────────────────────────────────────────────────
echo "Running tests..."
echo

# --- Ubuntu 24.04 (apt) ---
run "ubuntu:24.04" "fresh install" "$APT_SETUP" \
    'bash /install.sh --yes' \
    'command -v trivy  || { echo "MISSING: trivy";  exit 1; }
     command -v lynis  || { echo "MISSING: lynis";  exit 1; }
     command -v hostveil || { echo "MISSING: hostveil"; exit 1; }'

run "ubuntu:24.04" "--no-trivy" "$APT_SETUP" \
    'bash /install.sh --yes --no-trivy' \
    'if command -v trivy 2>/dev/null; then echo "UNEXPECTED: trivy found"; exit 1; fi
     command -v lynis  || { echo "MISSING: lynis";  exit 1; }
     command -v hostveil || { echo "MISSING: hostveil"; exit 1; }'

run "ubuntu:24.04" "--no-lynis" "$APT_SETUP" \
    'bash /install.sh --yes --no-lynis' \
    'command -v trivy  || { echo "MISSING: trivy";  exit 1; }
     if command -v lynis 2>/dev/null; then echo "UNEXPECTED: lynis found"; exit 1; fi
     command -v hostveil || { echo "MISSING: hostveil"; exit 1; }'

# --- Debian (apt) ---
run "debian:bookworm-slim" "fresh install" "$APT_SETUP" \
    'bash /install.sh --yes' \
    'command -v trivy  || { echo "MISSING: trivy";  exit 1; }
     command -v lynis  || { echo "MISSING: lynis";  exit 1; }
     command -v hostveil || { echo "MISSING: hostveil"; exit 1; }'

# --- Fedora (dnf) ---
run "fedora:latest" "fresh install" "$DNF_SETUP" \
    'bash /install.sh --yes' \
    'command -v trivy  || { echo "MISSING: trivy";  exit 1; }
     command -v lynis  || { echo "MISSING: lynis";  exit 1; }
     command -v hostveil || { echo "MISSING: hostveil"; exit 1; }'

# --- Arch Linux (pacman) ---
run "archlinux:latest" "fresh install" "$ARCH_SETUP" \
    'bash /install.sh --yes' \
    'command -v trivy  || { echo "MISSING: trivy";  exit 1; }
     command -v lynis  || { echo "MISSING: lynis";  exit 1; }
     command -v hostveil || { echo "MISSING: hostveil"; exit 1; }'

# --- Alpine (apk) ---
run "alpine:latest" "fresh install" "$APK_SETUP" \
    'bash /install.sh --yes' \
    'command -v trivy  || { echo "MISSING: trivy";  exit 1; }
     command -v lynis  || { echo "MISSING: lynis";  exit 1; }
     command -v hostveil || { echo "MISSING: hostveil"; exit 1; }'

# --- openSUSE (zypper) ---
run "opensuse/tumbleweed:latest" "fresh install" "$ZYPPER_SETUP" \
    'bash /install.sh --yes' \
    'command -v trivy  || { echo "MISSING: trivy";  exit 1; }
     command -v lynis  || { echo "MISSING: lynis";  exit 1; }
     command -v hostveil || { echo "MISSING: hostveil"; exit 1; }'

# ── Summary ────────────────────────────────────────────────────────────────
echo
if [ "$FAIL" -eq 0 ]; then
    echo -e "${GREEN}${BOLD}All $PASS tests passed${RESET}"
else
    echo -e "${RED}${BOLD}$FAIL tests failed, $PASS passed${RESET}"
    echo "Failed:"
    for t in "${FAILED[@]}"; do
        echo "  • $t"
    done
    exit 1
fi
