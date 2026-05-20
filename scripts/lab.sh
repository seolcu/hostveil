#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB_COMPOSE="$ROOT_DIR/docker/lab/compose.yml"

usage() {
  cat <<'EOF'
Hostveil self-hosting lab environment.

Usage:
  lab.sh up             Start lab (scanner + all target services)
  lab.sh down           Stop all lab services
  lab.sh shell          Enter lab container
  lab.sh run            Run hostveil inside lab (auto-discovers compose files)
  lab.sh serve          Run hostveil --serve (http://localhost:9090/) for browser QA
  lab.sh serve-detached Run hostveil --serve in detached mode inside the lab

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
  # Kill any previous instance (ttyd + hostveil) before taking the port
  docker compose -f "$LAB_COMPOSE" exec lab bash -c \
    'pkill -f "[h]ostveil.*--serve" 2>/dev/null; pkill -f "ttyd.*9090" 2>/dev/null' || true
  sleep 1
  cmd_build_in_lab
  docker compose -f "$LAB_COMPOSE" exec -e TERM=${TERM:-xterm-256color} -e COLORTERM=${COLORTERM:-truecolor} lab bash -c \
    'cd /workspace && ./hostveil --serve --port 9090'
}

cmd_build_in_lab() {
  echo "Building hostveil binary inside the lab..."
  docker compose -f "$LAB_COMPOSE" exec lab bash -c \
    'cd /workspace && go build -buildvcs=false -o hostveil ./cmd/hostveil/'
}

cmd_serve_detached() {
  # Kill any previous instance (ttyd + hostveil)
  docker compose -f "$LAB_COMPOSE" exec lab bash -c \
    'pkill -f "[h]ostveil.*--serve" 2>/dev/null; pkill -f "ttyd.*9090" 2>/dev/null' || true
  sleep 1

  cmd_build_in_lab

  LOG_PATH="/workspace/hostveil-serve.log"
  docker compose -f "$LAB_COMPOSE" exec -d \
    -e TERM=${TERM:-xterm-256color} \
    -e COLORTERM=${COLORTERM:-truecolor} \
    lab bash -c \
    "cd /workspace && ./hostveil --serve --port 9090 > ${LOG_PATH} 2>&1"

  # Wait until the server is actually listening on the port
  echo "Waiting for hostveil --serve to become ready..."
  local retries=20
  local ready=false
  for i in $(seq 1 $retries); do
    if docker compose -f "$LAB_COMPOSE" exec lab bash -c \
      'curl -s -o /dev/null --connect-timeout 1 http://127.0.0.1:9090/' 2>/dev/null; then
      ready=true
      break
    fi
    sleep 1
  done

  if [ "$ready" = true ]; then
    echo "hostveil --serve is ready on http://127.0.0.1:9090/"
  else
    echo "Warning: could not verify hostveil --serve started (timeout)." >&2
    echo "  Log: docker compose -f ${LAB_COMPOSE} exec lab cat ${LOG_PATH}" >&2
  fi
}

main() {
  ensure_docker
  case "${1:-help}" in
    up)    cmd_up ;;
    down)  cmd_down ;;
    shell) cmd_shell ;;
    run)   cmd_run ;;
    serve) cmd_serve ;;
    serve-detached) cmd_serve_detached ;;
    help|-h|--help) usage ;;
    *)     echo "unknown command: $1"; usage; exit 1 ;;
  esac
}

main "$@"
