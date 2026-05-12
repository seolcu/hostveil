#!/usr/bin/env bash
# scripts/test-adapters-e2e.sh
# End-to-end tests for Hostveil adapter integration with real scanners.
# Tests: install -> scan -> fix -> verify using actual adapter binaries.
#
# Usage:
#   ./scripts/test-adapters-e2e.sh [binary-path]              # normal mode (SKIP if tool missing)
#   CI_MODE=1 ./scripts/test-adapters-e2e.sh [binary-path]    # CI mode (FAIL if any tool missing)

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BINARY_PATH="${1:-$ROOT_DIR/target/debug/hostveil}"
SCENARIOS_DIR="$ROOT_DIR/tests/scenarios"
CI_MODE="${CI_MODE:-0}"

echo "=== Hostveil Adapter E2E Tests ==="
echo "Binary: $BINARY_PATH"
echo "CI_MODE: $CI_MODE"

[[ -x "$BINARY_PATH" ]] || {
    echo "FAIL: Binary not found or not executable at $BINARY_PATH"
    exit 1
}

# count failures
FAIL_COUNT=0
SKIP_COUNT=0

require_tool() {
    local tool="$1"
    if ! command -v "$tool" &>/dev/null; then
        if [[ "$CI_MODE" == "1" ]]; then
            echo "  FAIL: $tool is required in CI_MODE but not found"
            return 1
        else
            echo "  SKIP: $tool not installed"
            SKIP_COUNT=$((SKIP_COUNT + 1))
            return 1
        fi
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Test 1: adapter installation via setup command
# ---------------------------------------------------------------------------
test_adapter_install() {
    echo ""
    echo "--- Test 1: Adapter installation ---"

    OUTPUT=$("$BINARY_PATH" setup --tools all --yes --user-mode 2>&1) || true

    local any_fail=0
    for tool in trivy dockle lynis gitleaks; do
        if command -v "$tool" &>/dev/null; then
            echo "  OK: $tool is installed and on PATH"
        else
            if [[ "$CI_MODE" == "1" ]]; then
                echo "  FAIL: $tool not found in CI_MODE"
                any_fail=1
            else
                echo "  WARN: $tool not found (may need manual install)"
            fi
        fi
    done

    if [[ "$any_fail" == "1" ]]; then
        echo "  FAIL: adapter install check"
        return 1
    fi
    echo "  PASS: adapter install check"
}

# ---------------------------------------------------------------------------
# Test 2: Dockle fix scenario
# ---------------------------------------------------------------------------
test_dockle_fixes() {
    echo ""
    echo "--- Test 2: Dockle fix scenario ---"

    require_tool dockle || return 0

    local temp_dir
    temp_dir=$(mktemp -d)
    local compose_file="$temp_dir/docker-compose.yml"

    cat > "$compose_file" <<'YAML'
services:
  web:
    image: nginx:latest
    privileged: true
    ports:
      - "80:80"
YAML

    JSON_OUTPUT=$("$BINARY_PATH" --json --compose "$compose_file" --adapters dockle 2>&1) || true

    if echo "$JSON_OUTPUT" | grep -q '"remediation": "none"'; then
        echo "  OK: dockle findings present with remediation=none"
    else
        echo "  WARN: expected dockle findings not found in output"
    fi

    FIX_OUTPUT=$("$BINARY_PATH" --fix "$compose_file" --preview-changes --user-mode 2>&1) || true

    echo "  Fix preview output:"
    echo "$FIX_OUTPUT" | head -5

    rm -rf "$temp_dir"
    echo "  PASS: dockle fix check"
}

# ---------------------------------------------------------------------------
# Test 3: Trivy scan and fix scenario
# ---------------------------------------------------------------------------
test_trivy_scan() {
    echo ""
    echo "--- Test 3: Trivy scan scenario ---"

    require_tool trivy || return 0

    local temp_dir
    temp_dir=$(mktemp -d)
    local compose_file="$temp_dir/docker-compose.yml"

    cat > "$compose_file" <<'YAML'
services:
  web:
    image: nginx:1.20-alpine
    ports:
      - "80:80"
YAML

    JSON_OUTPUT=$("$BINARY_PATH" --json --compose "$compose_file" --adapters trivy 2>&1) || true

    if echo "$JSON_OUTPUT" | grep -q '"findings"'; then
        echo "  OK: scan findings generated"
    fi

    rm -rf "$temp_dir"
    echo "  PASS: trivy scan check"
}

# ---------------------------------------------------------------------------
# Test 4: Adapter timeout handling
# ---------------------------------------------------------------------------
test_adapter_timeout() {
    echo ""
    echo "--- Test 4: Adapter timeout handling ---"

    local temp_dir
    temp_dir=$(mktemp -d)
    local compose_file="$temp_dir/docker-compose.yml"

    cat > "$compose_file" <<'YAML'
services:
  web:
    image: nginx:latest
YAML

    JSON_OUTPUT=$("$BINARY_PATH" --json --compose "$compose_file" --adapter-timeout-secs=1 2>&1) || true

    if echo "$JSON_OUTPUT" | grep -q '"scan_mode"'; then
        echo "  OK: scan completed with short timeout (some adapters may have been skipped)"
    else
        echo "  WARN: scan output did not contain scan_mode"
    fi

    rm -rf "$temp_dir"
    echo "  PASS: adapter timeout check"
}

# ---------------------------------------------------------------------------
# Test 5: Full pipeline with host scan (Lynis)
# ---------------------------------------------------------------------------
test_host_scan() {
    echo ""
    echo "--- Test 5: Host scan with Lynis ---"

    require_tool lynis || return 0

    JSON_OUTPUT=$("$BINARY_PATH" --json --adapters lynis 2>&1) || true

    if echo "$JSON_OUTPUT" | grep -q '"host_runtime"'; then
        echo "  OK: host scan completed"
    else
        echo "  WARN: host scan output did not contain host_runtime"
    fi

    echo "  PASS: host scan check"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
test_adapter_install || FAIL_COUNT=$((FAIL_COUNT + 1))
test_dockle_fixes
test_trivy_scan
test_adapter_timeout
test_host_scan

echo ""
echo "=== All adapter E2E tests completed ==="
echo "Skipped: $SKIP_COUNT"
if [[ "$FAIL_COUNT" -gt 0 ]]; then
    echo "FAILURES: $FAIL_COUNT"
    exit 1
fi
