#!/usr/bin/env bash
# hostveil test environment — unified entry point
#
# Usage:
#   ./docker/run.sh up              Start environment, build hostveil
#   ./docker/run.sh down            Stop and fully reset (containers + volumes)
#   ./docker/run.sh stop            Pause (no reset, keeps data)
#   ./docker/run.sh hostveil [...]  Build + run hostveil inside container
#   ./docker/run.sh sh              Open interactive shell in container
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

cmd="${1:-up}"
shift || true

# ── helpers ────────────────────────────────────────────────────────────────
free_port() {
    local port="${1:-8787}"
    local pids=""
    if command -v lsof >/dev/null 2>&1; then
        pids=$(lsof -ti :"$port" 2>/dev/null || true)
    fi
    if [ -n "$pids" ]; then
        echo "  Port $port in use by PID(s):$(echo $pids) — freeing"
        for pid in $pids; do
            kill "$pid" 2>/dev/null || true
        done
        sleep 1
        for pid in $pids; do
            kill -9 "$pid" 2>/dev/null || true
        done
    fi
}

# ── up ────────────────────────────────────────────────────────────────────
up() {
    echo "  hostveil test env — starting"
    echo ""

    free_port 8787
    docker compose down --remove-orphans -v 2>/dev/null || true

    for attempt in 1 2 3; do
        if out=$(docker compose up -d --build --remove-orphans 2>&1); then
            break
        fi
        if echo "$out" | grep -q "address already in use"; then
            echo "  Port conflict, retrying in 3s... (attempt $attempt/3)"
            free_port 8787
            sleep 3
        else
            echo "$out"
            exit 1
        fi
        if [ "$attempt" = "3" ]; then
            docker compose up -d --build --remove-orphans
        fi
    done

    echo "  Waiting for Docker daemon..."
    for i in {1..30}; do
      docker compose exec -w /hostveil test-host docker info >/dev/null 2>&1 && break
      sleep 1
    done

    # Verify mount
    docker compose exec -w /hostveil test-host ls go.mod >/dev/null 2>&1 || {
        echo "  ERROR: /hostveil mount failed"
        exit 1
    }

    # Start compose project
    docker compose exec test-host sh -c "
        cd /opt/compose/vuln-project && docker compose up -d 2>/dev/null
    " || true

    # Build hostveil
    echo "  Building hostveil..."
    docker compose exec -w /hostveil test-host sh -c "
        go build -buildvcs=false -o hostveil ./cmd/hostveil
    " && echo "  Build complete."

    echo ""
    echo "  Ready. Try:"
    echo "    ./docker/run.sh hostveil serve"
    echo "    ./docker/run.sh hostveil tui-web    # TUI + Web UI"
    echo "    ./docker/run.sh hostveil           # TUI"
    echo "    ./docker/run.sh sh                 # interactive shell"
    echo ""
}

# ── down ──────────────────────────────────────────────────────────────────
down() {
    echo "  hostveil test env — full reset"
    free_port 8787
    docker compose down --remove-orphans -v 2>/dev/null || true
    echo "  Done."
}

# ── stop ──────────────────────────────────────────────────────────────────
stop() {
    echo "  hostveil test env — stopping"
    free_port 8787
    docker compose stop 2>/dev/null || true
    echo "  Done (data preserved)."
}

# ── hostveil ──────────────────────────────────────────────────────────────
run_hostveil() {
    # Ensure container is running
    if ! docker compose ps --status running 2>/dev/null | grep -q test-host; then
        echo "  Container not running. Starting..."
        up
        sleep 3
    fi
    : "${TERM:=xterm-256color}"
    : "${COLORTERM:=truecolor}"

    # Rebuild if needed
    if [ -f "../hostveil" ]; then
      BIN_AGE=$(stat -c%Y "../hostveil" 2>/dev/null || echo 0)
      SRC_AGE=$(find .. \( -name '*.go' -o -path '../internal/web/assets/*' \) -newer "../hostveil" -exec stat -c%Y {} \; | sort -rn | head -1 || echo 0)
      if [ "${SRC_AGE:-0}" -gt "$BIN_AGE" ]; then
        echo "  Rebuilding..."
        docker compose exec -e TERM="$TERM" -e COLORTERM="$COLORTERM" -w /hostveil test-host go build -buildvcs=false -o hostveil ./cmd/hostveil
      fi
    else
      docker compose exec -e TERM="$TERM" -e COLORTERM="$COLORTERM" -w /hostveil test-host go build -buildvcs=false -o hostveil ./cmd/hostveil
    fi

    # Auto-add --addr 0.0.0.0:8787 for serve/web/tui-web inside container
    local args=("$@")
    if [[ "${#args[@]}" -gt 0 ]]; then
      local cmd="${args[0]}"
      if [[ "$cmd" == "serve" || "$cmd" == "web" || "$cmd" == "tui-web" ]] && [[ "$*" != *"--addr"* ]]; then
        args+=(--addr "0.0.0.0:8787")
      fi
    fi

    # Run
    docker compose exec -e TERM="$TERM" -e COLORTERM="$COLORTERM" -w /hostveil test-host ./hostveil "${args[@]}"
}

# ── shell ─────────────────────────────────────────────────────────────────
shell() {
    if ! docker compose ps --status running 2>/dev/null | grep -q test-host; then
        echo "  Starting..."
        up
        sleep 3
    fi
    : "${TERM:=xterm-256color}"
    : "${COLORTERM:=truecolor}"
    docker compose exec -e TERM="$TERM" -e COLORTERM="$COLORTERM" -w /hostveil test-host sh
}

# ── dispatch ──────────────────────────────────────────────────────────────
case "$cmd" in
    up)        up ;;
    down)      down ;;
    stop)      stop ;;
    hostveil)  run_hostveil "$@" ;;
    sh|shell)  shell ;;
    *)
        echo "Usage: $0 {up|down|stop|hostveil|sh} [args...]"
        exit 1
        ;;
esac
