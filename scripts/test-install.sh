#!/usr/bin/env bash
# scripts/test-install.sh — Test install.sh across Linux distributions via Docker
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_SH="$SCRIPT_DIR/install.sh"
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
if [ ! -f "$INSTALL_SH" ]; then
    echo "Error: install.sh not found at $INSTALL_SH"
    exit 1
fi

TEST_TIMEOUT_SECONDS="${HOSTVEIL_INSTALL_TEST_TIMEOUT_SECONDS:-420}"
PINNED_VERSION="${HOSTVEIL_INSTALL_TEST_VERSION:-2.6.0}"
RUN_DOCKER="${HOSTVEIL_INSTALL_TEST_DOCKER:-1}"

pass() {
    printf "  %-40s ${GREEN}✓${RESET}\n" "$1"
    PASS=$((PASS + 1))
}

fail() {
    local name=$1
    shift
    printf "  %-40s ${RED}✗${RESET}\n" "$name"
    for line in "$@"; do
        echo "      $line"
    done
    FAIL=$((FAIL + 1))
    FAILED+=("$name")
}

# ── Local tests (no Docker) ───────────────────────────────────────────────
echo "Running local installer tests..."
echo

if bash -n "$INSTALL_SH"; then
    pass "bash syntax check"
else
    fail "bash syntax check"
fi

if bash "$INSTALL_SH" --help >/dev/null 2>&1; then
    pass "--help exits 0"
else
    fail "--help exits 0"
fi

if bash "$INSTALL_SH" --bad-flag >/dev/null 2>&1; then
    fail "unknown flag exits non-zero" "expected exit 1"
else
    pass "unknown flag exits non-zero"
fi

if cd "$SCRIPT_DIR" && sha256sum -c install.sh.sha256 >/dev/null 2>&1; then
    pass "install.sh.sha256 matches install.sh"
else
    fail "install.sh.sha256 matches install.sh" "run: cd scripts && sha256sum install.sh > install.sh.sha256"
fi

# ── Docker test runner ────────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
    echo
    echo "Docker not available — skipping cross-distro installer matrix"
    echo
    if [ "$FAIL" -eq 0 ]; then
        echo -e "${GREEN}${BOLD}All $PASS local tests passed${RESET}"
        exit 0
    fi
    echo -e "${RED}${BOLD}$FAIL local tests failed, $PASS passed${RESET}"
    exit 1
fi

if [ "$RUN_DOCKER" != "1" ]; then
    echo
    echo "Docker matrix skipped (HOSTVEIL_INSTALL_TEST_DOCKER=$RUN_DOCKER)"
    echo
    if [ "$FAIL" -eq 0 ]; then
        echo -e "${GREEN}${BOLD}All $PASS tests passed${RESET}"
        exit 0
    fi
    exit 1
fi

run() {
    local image=$1 name=$2 setup=$3 install=$4 verify=$5
    local log rc label="${image} / ${name}"

    log=$(mktemp /tmp/hostveil-install-test-XXXXXX)

    printf "  [%s] %-27s " "$image" "$name"

    rc=0
    timeout "$TEST_TIMEOUT_SECONDS" docker run --rm \
        -v "$INSTALL_SH:/install.sh:ro" \
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
        [ "$rc" -eq 124 ] && echo "      (timeout after ${TEST_TIMEOUT_SECONDS}s)"
        grep -v '^docker:' "$log" | tail -20 | sed 's/^/      /'
        FAIL=$((FAIL + 1))
        FAILED+=("$label")
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

echo
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

HOSTVEIL_VERIFY='command -v hostveil || { echo "MISSING: hostveil"; exit 1; }
     hostveil --version >/dev/null || { echo "hostveil --version failed"; exit 1; }'

DEPS_VERIFY='command -v trivy  || { echo "MISSING: trivy";  exit 1; }
     command -v lynis  || { echo "MISSING: lynis";  exit 1; }'

# ── Tests ──────────────────────────────────────────────────────────────────
echo "Running Docker installer tests..."
echo

# --- Ubuntu 24.04 (apt) ---
run "ubuntu:24.04" "fresh install" "$APT_SETUP" \
    'bash /install.sh --yes' \
    "${DEPS_VERIFY}
     ${HOSTVEIL_VERIFY}"

run "ubuntu:24.04" "--no-trivy" "$APT_SETUP" \
    'bash /install.sh --yes --no-trivy' \
    'if command -v trivy 2>/dev/null; then echo "UNEXPECTED: trivy found"; exit 1; fi
     command -v lynis  || { echo "MISSING: lynis";  exit 1; }
     '"${HOSTVEIL_VERIFY}"

run "ubuntu:24.04" "--no-lynis" "$APT_SETUP" \
    'bash /install.sh --yes --no-lynis' \
    'command -v trivy  || { echo "MISSING: trivy";  exit 1; }
     if command -v lynis 2>/dev/null; then echo "UNEXPECTED: lynis found"; exit 1; fi
     '"${HOSTVEIL_VERIFY}"

run "ubuntu:24.04" "--no-deps" "$APT_SETUP" \
    'bash /install.sh --yes --no-deps' \
    'if command -v trivy 2>/dev/null; then echo "UNEXPECTED: trivy found"; exit 1; fi
     if command -v lynis 2>/dev/null; then echo "UNEXPECTED: lynis found"; exit 1; fi
     '"${HOSTVEIL_VERIFY}"

run "ubuntu:24.04" "pinned version" "$APT_SETUP" \
    "bash /install.sh --yes --no-deps --version v${PINNED_VERSION}" \
    "hostveil --version | grep -q '${PINNED_VERSION}' || { echo \"expected v${PINNED_VERSION}\"; exit 1; }"

run "ubuntu:24.04" "existing trivy" \
    "${APT_SETUP} && apt-get install -y -qq trivy >/dev/null 2>&1 || true" \
    'bash /install.sh --yes --no-lynis' \
    'command -v trivy || { echo "MISSING: trivy"; exit 1; }
     if command -v lynis 2>/dev/null; then echo "UNEXPECTED: lynis found"; exit 1; fi
     '"${HOSTVEIL_VERIFY}"

# --- Debian (apt) ---
run "debian:bookworm-slim" "fresh install" "$APT_SETUP" \
    'bash /install.sh --yes' \
    "${DEPS_VERIFY}
     ${HOSTVEIL_VERIFY}"

run "debian:bookworm-slim" "--no-deps" "$APT_SETUP" \
    'bash /install.sh --yes --no-deps' \
    'if command -v trivy 2>/dev/null; then echo "UNEXPECTED: trivy found"; exit 1; fi
     if command -v lynis 2>/dev/null; then echo "UNEXPECTED: lynis found"; exit 1; fi
     '"${HOSTVEIL_VERIFY}"

# --- Fedora (dnf) ---
run "fedora:latest" "fresh install" "$DNF_SETUP" \
    'bash /install.sh --yes' \
    "${DEPS_VERIFY}
     ${HOSTVEIL_VERIFY}"

run "fedora:latest" "--no-deps" "$DNF_SETUP" \
    'bash /install.sh --yes --no-deps' \
    'if command -v trivy 2>/dev/null; then echo "UNEXPECTED: trivy found"; exit 1; fi
     if command -v lynis 2>/dev/null; then echo "UNEXPECTED: lynis found"; exit 1; fi
     '"${HOSTVEIL_VERIFY}"

# --- Arch Linux (pacman) ---
run "archlinux:latest" "fresh install" "$ARCH_SETUP" \
    'bash /install.sh --yes' \
    "${DEPS_VERIFY}
     ${HOSTVEIL_VERIFY}"

# --- Alpine (apk) ---
run "alpine:latest" "fresh install" "$APK_SETUP" \
    'bash /install.sh --yes' \
    "${DEPS_VERIFY}
     ${HOSTVEIL_VERIFY}"

run "alpine:latest" "--no-deps" "$APK_SETUP" \
    'bash /install.sh --yes --no-deps' \
    'if command -v trivy 2>/dev/null; then echo "UNEXPECTED: trivy found"; exit 1; fi
     if command -v lynis 2>/dev/null; then echo "UNEXPECTED: lynis found"; exit 1; fi
     '"${HOSTVEIL_VERIFY}"

# --- openSUSE (zypper) ---
run "opensuse/tumbleweed:latest" "fresh install" "$ZYPPER_SETUP" \
    'bash /install.sh --yes' \
    "${DEPS_VERIFY}
     ${HOSTVEIL_VERIFY}"

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
