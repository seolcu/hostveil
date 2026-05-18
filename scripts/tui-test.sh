#!/usr/bin/env bash
# tmux-based TUI test harness with comprehensive E2E scenarios
# Usage: scripts/tui-test.sh [scenario-name]
# Environment: HOSTVEIL_BINARY (default: ./hostveil), COMPOSE (default: tests/...)

set -euo pipefail

HOSTVEIL="${HOSTVEIL_BINARY:-./hostveil}"
COMPOSE="${COMPOSE:-tests/scenarios/vaultwarden-domain/docker-compose.yml}"
GOLDEN_DIR="testdata/golden"
SESSION="hostveil-test"
PASS=0
FAIL=0

cleanup() {
  tmux kill-session -t "$SESSION" 2>/dev/null || true
}
trap cleanup EXIT

mkdir -p "$GOLDEN_DIR"

# Fix terminal size for reproducible golden files
export TERM=xterm-256color

start_app() {
  cleanup
  tmux new-session -d -x 80 -y 24 -s "$SESSION" "$HOSTVEIL --compose $COMPOSE 2>/dev/null; bash"
  sleep 2
}

capture() {
  tmux capture-pane -t "$SESSION" -p
}

send_key() {
  tmux send-keys -t "$SESSION" "$1"
}

assert_snapshot() {
  local name="$1"
  local golden="${GOLDEN_DIR}/${name}.txt"
  capture > "/tmp/tui-${name}.txt"

  if [ -f "$golden" ]; then
    if diff -q "/tmp/tui-${name}.txt" "$golden" >/dev/null 2>&1; then
      echo "  ✓ $name matches golden"
      PASS=$((PASS+1))
    else
      echo "  ✗ $name differs from golden"
      diff "/tmp/tui-${name}.txt" "$golden" | head -10
      FAIL=$((FAIL+1))
    fi
  else
    cp "/tmp/tui-${name}.txt" "$golden"
    echo "  → Created golden: $name"
    PASS=$((PASS+1))
  fi
}

echo "=== Hostveil TUI E2E Tests ==="
echo ""

# Test 1: Overview screen loads
echo "[Test 1] Overview screen"
start_app
assert_snapshot "overview-load"
send_key "q"
sleep 0.5

# Test 2: Navigate to Findings
echo "[Test 2] Navigate to Findings (key 2)"
start_app
send_key "2"
sleep 1
assert_snapshot "findings-list"
send_key "q"
sleep 0.5

# Test 3: Navigate to History
echo "[Test 3] Navigate to History (key 3)"
start_app
send_key "3"
sleep 1
assert_snapshot "history-view"
send_key "q"
sleep 0.5

# Test 4: Findings severity filter (press s to cycle)
echo "[Test 4] Findings severity filter"
start_app
send_key "2"
sleep 0.5
send_key "s"
sleep 0.5
assert_snapshot "findings-filter-severity"
send_key "q"
sleep 0.5

# Test 5: Open finding detail
echo "[Test 5] Finding detail view"
start_app
send_key "2"
sleep 0.5
send_key "enter"
sleep 1
assert_snapshot "finding-detail"
send_key "q"
sleep 0.5

# Test 6: Settings modal
echo "[Test 6] Settings modal"
start_app
send_key "S"
sleep 1
assert_snapshot "settings-modal"
send_key "q"
sleep 0.5

# Test 7: Help overlay
echo "[Test 7] Help overlay"
start_app
send_key "?"
sleep 1
assert_snapshot "help-overlay"
send_key "q"
sleep 0.5

# Test 8: Host triage mode
echo "[Test 8] Host triage (h key from overview)"
start_app
sleep 1
send_key "h"
sleep 1
assert_snapshot "host-triage"
send_key "q"
sleep 0.5

# Test 9: Reset filters
echo "[Test 9] Reset findings filters"
start_app
send_key "2"
sleep 0.5
send_key "s"; sleep 0.2
send_key "s"; sleep 0.2
send_key "R"
sleep 0.5
assert_snapshot "filters-reset"
send_key "q"
sleep 0.5

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
exit $FAIL
