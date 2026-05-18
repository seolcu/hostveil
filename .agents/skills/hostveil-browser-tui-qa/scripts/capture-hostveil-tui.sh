#!/usr/bin/env bash
set -euo pipefail

COMPOSE="tests/scenarios/vaultwarden-domain/docker-compose.yml"
OUT_DIR="hostveil-screenshots"
PORT="8080"
LOG_FILE="/tmp/hostveil-serve.log"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --compose)
      COMPOSE="${2:?missing value for --compose}"
      shift 2
      ;;
    --out)
      OUT_DIR="${2:?missing value for --out}"
      shift 2
      ;;
    --port)
      PORT="${2:?missing value for --port}"
      shift 2
      ;;
    --log)
      LOG_FILE="${2:?missing value for --log}"
      shift 2
      ;;
    -h|--help)
      printf 'Usage: %s [--compose FILE] [--out DIR] [--port PORT] [--log FILE]\n' "$0"
      exit 0
      ;;
    *)
      printf 'unknown argument: %s\n' "$1" >&2
      exit 2
      ;;
  esac
done

if ! command -v agent-browser >/dev/null 2>&1; then
  printf 'agent-browser is required but was not found in PATH\n' >&2
  exit 1
fi

if ! command -v ttyd >/dev/null 2>&1; then
  printf 'ttyd is required but was not found in PATH\n' >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
rm -f "$LOG_FILE"

go build -o hostveil ./cmd/hostveil/

cleanup() {
  agent-browser close >/dev/null 2>&1 || true
  if [[ -n "${SERVER_PID:-}" ]]; then
    kill "$SERVER_PID" >/dev/null 2>&1 || true
  fi
  pkill -f "ttyd.*hostveil" >/dev/null 2>&1 || true
}
trap cleanup EXIT

setsid -f ./hostveil --serve --port "$PORT" --compose "$COMPOSE" > "$LOG_FILE" 2>&1
sleep 3

URL="$(grep -Eo 'http://127\.0\.0\.1:[0-9]+/' "$LOG_FILE" | tail -n 1 || true)"
if [[ -z "$URL" ]]; then
  printf 'failed to parse hostveil URL from %s\n' "$LOG_FILE" >&2
  sed -n '1,80p' "$LOG_FILE" >&2
  exit 1
fi

SERVER_PID="$(pgrep -f "hostveil --serve" | tail -n 1 || true)"

printf 'Opening %s\n' "$URL"
agent-browser open "$URL"
agent-browser set viewport 1280 720
agent-browser wait 2500
agent-browser snapshot -i
agent-browser click @e1

agent-browser screenshot "$OUT_DIR/01-overview.png"
agent-browser press 2
agent-browser wait 700
agent-browser screenshot "$OUT_DIR/02-findings-list.png"
agent-browser press Enter
agent-browser wait 700
agent-browser screenshot "$OUT_DIR/03-findings-detail.png"
agent-browser press h
agent-browser wait 300
agent-browser press s
agent-browser wait 700
agent-browser screenshot "$OUT_DIR/04-findings-severity-filter.png"
agent-browser press 3
agent-browser wait 700
agent-browser screenshot "$OUT_DIR/05-history.png"
agent-browser press '?'
agent-browser wait 700
agent-browser screenshot "$OUT_DIR/06-help.png"
agent-browser press '?'
agent-browser wait 300
agent-browser press S
agent-browser wait 700
agent-browser screenshot "$OUT_DIR/07-settings.png"
agent-browser press right
agent-browser wait 500
agent-browser screenshot "$OUT_DIR/08-settings-theme-changed.png"
agent-browser press S
agent-browser wait 500
agent-browser press 1
agent-browser wait 700
agent-browser screenshot "$OUT_DIR/09-overview-theme-changed.png"
agent-browser press h
agent-browser wait 700
agent-browser screenshot "$OUT_DIR/10-host-triage.png"
agent-browser press 1
agent-browser wait 500
agent-browser set viewport 720 720
agent-browser wait 1000
agent-browser screenshot "$OUT_DIR/11-overview-narrow.png"

printf 'Captured screenshots in %s\n' "$OUT_DIR"
