#!/usr/bin/env bash
# tmux-based TUI test harness
# Usage: scripts/tui-test.sh [test-name]
# Environment: HOSTVEIL_BINARY (default: ./hostveil)

set -euo pipefail

HOSTVEIL="${HOSTVEIL_BINARY:-./hostveil}"
COMPOSE="${COMPOSE:-tests/scenarios/vaultwarden-domain/docker-compose.yml}"
GOLDEN_DIR="testdata/golden"
SESSION="hostveil-test"

cleanup() {
  tmux kill-session -t "$SESSION" 2>/dev/null || true
}
trap cleanup EXIT

mkdir -p "$GOLDEN_DIR"

run_test() {
  local name="$1"
  local delay="${2:-2}"
  local golden="${GOLDEN_DIR}/${name}.txt"

  echo "=== Running test: $name ==="

  cleanup
  tmux new-session -d -s "$SESSION" \
    "$HOSTVEIL --compose $COMPOSE 2>/dev/null; bash"

  sleep "$delay"

  # Capture screen
  tmux capture-pane -t "$SESSION" -p > "/tmp/tui-output.txt"

  # Send quit
  tmux send-keys -t "$SESSION" "q" 2>/dev/null || true
  sleep 0.5

  if [ -f "$golden" ]; then
    if diff -q "/tmp/tui-output.txt" "$golden" >/dev/null 2>&1; then
      echo "  ✓ $name matches golden file"
    else
      echo "  ✗ $name differs from golden file"
      diff "/tmp/tui-output.txt" "$golden" | head -20
      return 1
    fi
  else
    cp "/tmp/tui-output.txt" "$golden"
    echo "  → Created golden file: $golden"
  fi
}

# Test: Overview screen loads
run_test "overview-load" 3

# Test: Navigate to Findings
cleanup
tmux new-session -d -s "$SESSION" \
  "$HOSTVEIL --compose $COMPOSE 2>/dev/null; bash"
sleep 2
tmux send-keys -t "$SESSION" "2"
sleep 1
tmux capture-pane -t "$SESSION" -p > "/tmp/tui-findings.txt"
tmux send-keys -t "$SESSION" "q" 2>/dev/null || true
sleep 0.5

golden="${GOLDEN_DIR}/findings-list.txt"
if [ -f "$golden" ]; then
  if diff -q "/tmp/tui-findings.txt" "$golden" >/dev/null 2>&1; then
    echo "  ✓ findings-list matches golden file"
  else
    echo "  ✗ findings-list differs from golden file"
    diff "/tmp/tui-findings.txt" "$golden" | head -20
    exit 1
  fi
else
  cp "/tmp/tui-findings.txt" "$golden"
  echo "  → Created golden file: $golden"
fi

# Test: Navigate to History
cleanup
tmux new-session -d -s "$SESSION" \
  "$HOSTVEIL --compose $COMPOSE 2>/dev/null; bash"
sleep 2
tmux send-keys -t "$SESSION" "3"
sleep 1
tmux capture-pane -t "$SESSION" -p > "/tmp/tui-history.txt"
tmux send-keys -t "$SESSION" "q" 2>/dev/null || true
sleep 0.5

golden="${GOLDEN_DIR}/history.txt"
if [ -f "$golden" ]; then
  if diff -q "/tmp/tui-history.txt" "$golden" >/dev/null 2>&1; then
    echo "  ✓ history matches golden file"
  else
    echo "  ✗ history differs from golden file"
    diff "/tmp/tui-history.txt" "$golden" | head -20
    exit 1
  fi
else
  cp "/tmp/tui-history.txt" "$golden"
  echo "  → Created golden file: $golden"
fi

echo ""
echo "All tests passed!"
