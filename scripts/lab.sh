#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB_COMPOSE="$ROOT_DIR/docker/lab/compose.yml"

usage() {
  cat <<'EOF'
Hostveil self-hosting lab environment.

Usage:
  lab.sh up       Start lab (scanner + all target services)
  lab.sh down     Stop all lab services
  lab.sh shell    Enter lab container
  lab.sh run      Run hostveil inside lab (auto-discovers compose files)
  lab.sh serve    Run hostveil --serve (http://localhost:9090/) for browser QA

Services can also be started individually:
  docker compose -f docker/lab/vaultwarden/compose.yml up -d
  docker compose -f docker/lab/jellyfin/compose.yml up -d
  docker compose -f docker/lab/gitea/compose.yml up -d
  docker compose -f docker/lab/nextcloud/compose.yml up -d
  docker compose -f docker/lab/nginx/compose.yml up -d
EOF
}

ensure_docker() {
  command -v docker >/dev/null 2>&1 || {
    echo "error: docker is required" >&2
    exit 1
  }
}

cmd_up() {
  echo "Starting lab scanner..."
  docker compose -f "$LAB_COMPOSE" up -d --build

  echo "Starting target services..."
  for svc in vaultwarden jellyfin gitea nextcloud nginx; do
    compose="$ROOT_DIR/docker/lab/$svc/compose.yml"
    if [ -f "$compose" ]; then
      echo "  $svc..."
      docker compose -f "$compose" up -d
    fi
  done

  echo ""
  echo "Lab is running."
  echo "  lab.sh shell    -> enter lab container"
  echo "  lab.sh run      -> hostveil (auto-discover)"
  echo "  lab.sh serve    -> hostveil --serve (http://localhost:9090/)"
}

cmd_down() {
  docker compose -f "$LAB_COMPOSE" down --remove-orphans 2>/dev/null || true
  for svc in vaultwarden jellyfin gitea nextcloud nginx; do
    compose="$ROOT_DIR/docker/lab/$svc/compose.yml"
    [ -f "$compose" ] && docker compose -f "$compose" down --remove-orphans 2>/dev/null || true
  done
  docker network rm hostveil-lab 2>/dev/null || true
}

cmd_shell() {
  docker compose -f "$LAB_COMPOSE" up -d --build
  docker compose -f "$LAB_COMPOSE" exec -e TERM=${TERM:-xterm-256color} -e COLORTERM=${COLORTERM:-truecolor} lab bash
}

cmd_run() {
  docker compose -f "$LAB_COMPOSE" exec -e TERM=${TERM:-xterm-256color} -e COLORTERM=${COLORTERM:-truecolor} lab bash -c \
    'cd /workspace && go run ./cmd/hostveil/'
}

cmd_serve() {
  docker compose -f "$LAB_COMPOSE" exec -e TERM=${TERM:-xterm-256color} -e COLORTERM=${COLORTERM:-truecolor} lab bash -c \
    'cd /workspace && go run ./cmd/hostveil/ --serve --port 9090'
}

main() {
  ensure_docker
  case "${1:-help}" in
    up)    cmd_up ;;
    down)  cmd_down ;;
    shell) cmd_shell ;;
    run)   cmd_run ;;
    serve) cmd_serve ;;
    help|-h|--help) usage ;;
    *)     echo "unknown command: $1"; usage; exit 1 ;;
  esac
}

main "$@"
