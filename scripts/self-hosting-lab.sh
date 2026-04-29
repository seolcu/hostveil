#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/docker-compose.lab.yml"
TARGET_COMPOSE_FILE="$ROOT_DIR/docker/lab/self-hosting-stack.yml"
PROJECT_NAME="hostveil-lab"
TMP_COMPOSE_FILE=""

cleanup() {
  if [[ -n "${TMP_COMPOSE_FILE:-}" && -f "$TMP_COMPOSE_FILE" ]]; then
    rm -f "$TMP_COMPOSE_FILE"
  fi
}
trap cleanup EXIT

usage() {
  cat <<'EOF'
Manage the Hostveil self-hosting lab.

Usage:
  scripts/self-hosting-lab.sh up
  scripts/self-hosting-lab.sh down
  scripts/self-hosting-lab.sh reset
  scripts/self-hosting-lab.sh ps
  scripts/self-hosting-lab.sh logs [SERVICE]
  scripts/self-hosting-lab.sh shell
  scripts/self-hosting-lab.sh check

Common flow:
  scripts/self-hosting-lab.sh up
  scripts/self-hosting-lab.sh shell
  # inside the lab container:
  cargo run -- --user-mode --compose docker/lab/self-hosting-stack.yml
  cargo run -- --user-mode --json --compose docker/lab/self-hosting-stack.yml --adapters none
  cargo run -- --json --compose docker/lab/self-hosting-stack.yml --host-root / --adapters trivy,dockle,lynis

The lab intentionally contains insecure Compose patterns. Do not expose it beyond localhost.
EOF
}

generate_safe_compose() {
  TMP_COMPOSE_FILE=$(mktemp)
  sed 's/"0\.0\.0\.0:/"127.0.0.1:/g' "$TARGET_COMPOSE_FILE" > "$TMP_COMPOSE_FILE"
}

compose() {
  local target_file="${TMP_COMPOSE_FILE:-$TARGET_COMPOSE_FILE}"
  docker compose -p "$PROJECT_NAME" \
    -f "$COMPOSE_FILE" \
    -f "$target_file" \
    "$@"
}

ensure_docker() {
  command -v docker >/dev/null 2>&1 || {
    printf 'error: docker is required\n' >&2
    exit 1
  }
  docker compose version >/dev/null 2>&1 || {
    printf 'error: docker compose is required\n' >&2
    exit 1
  }
}

ensure_up() {
  generate_safe_compose
  compose up -d --build lab vaultwarden jellyfin gitea nextcloud nextcloud-db exposed-nginx
}

print_hints() {
  printf '\nLab is running. Enter the shell with:\n'
  printf '  scripts/self-hosting-lab.sh shell\n\n'
  printf 'Common commands inside the lab:\n'
  printf '  cargo run -- --user-mode --compose docker/lab/self-hosting-stack.yml\n'
  printf '  cargo run -- --user-mode --json --compose docker/lab/self-hosting-stack.yml --adapters none\n'
  printf '  cargo run -- --json --compose docker/lab/self-hosting-stack.yml --host-root / --adapters trivy,dockle,lynis\n'
  printf '  cargo run -- --user-mode --fix docker/lab/self-hosting-stack.yml --preview-changes\n\n'
}

main() {
  local command="${1:-help}"
  shift || true

  ensure_docker

  case "$command" in
    up)
      ensure_up
      print_hints
      ;;
    down)
      docker compose -p "$PROJECT_NAME" down --remove-orphans
      ;;
    reset)
      docker compose -p "$PROJECT_NAME" down --remove-orphans --volumes
      ;;
    ps)
      ensure_up
      compose ps
      ;;
    logs)
      ensure_up
      if [[ $# -gt 0 ]]; then
        compose logs -f "$1"
      else
        compose logs -f
      fi
      ;;
    shell)
      ensure_up
      compose exec lab bash
      ;;
    check)
      ensure_up
      compose exec lab bash -lc 'cd /workspace && cargo run -- --user-mode --version'
      ;;
    -h|--help|help)
      usage
      ;;
    *)
      printf 'error: unknown command: %s\n\n' "$command" >&2
      usage >&2
      exit 1
      ;;
  esac
}

main "$@"
