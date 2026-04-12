#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/compose.dev.yml"

usage() {
  cat <<'EOF'
Manage the hostveil development and multi-distro lab containers.

Usage:
  scripts/dev-env.sh up [service...]
  scripts/dev-env.sh down
  scripts/dev-env.sh ps
  scripts/dev-env.sh logs SERVICE
  scripts/dev-env.sh shell [service]
  scripts/dev-env.sh exec SERVICE -- COMMAND [ARG...]
  scripts/dev-env.sh setup SERVICE [tool-list]
  scripts/dev-env.sh scan SERVICE

Services:
  dev
  fedora-lab
  rocky-lab
  ubuntu-lab
  debian-lab

Examples:
  scripts/dev-env.sh up dev
  scripts/dev-env.sh shell dev
  scripts/dev-env.sh up fedora-lab
  scripts/dev-env.sh setup fedora-lab lynis,trivy,fail2ban
  scripts/dev-env.sh setup ubuntu-lab lynis,trivy
  scripts/dev-env.sh scan rocky-lab
EOF
}

compose() {
  docker compose --profile labs -f "$COMPOSE_FILE" "$@"
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

require_service() {
  [[ $# -ge 1 ]] || {
    printf 'error: missing service name\n' >&2
    exit 1
  }
}

ensure_service_up() {
  local service="$1"
  compose up -d "$service"
}

run_setup() {
  local service="$1"
  local tools="${2:-}"

  ensure_service_up "$service"

  if [[ -n "$tools" ]]; then
    compose exec "$service" bash -c "cd /workspace && cargo run -- setup --yes --tools '$tools'"
  else
    compose exec "$service" bash -c 'cd /workspace && cargo run -- setup --yes'
  fi
}

run_scan() {
  local service="$1"

  ensure_service_up "$service"
  compose exec "$service" bash -c 'cd /workspace && cargo run -- --json --host-root /'
}

main() {
  local command="${1:-}"
  shift || true

  ensure_docker

  case "$command" in
    up)
      if [[ $# -eq 0 ]]; then
        compose up -d --build dev
      else
        compose up -d --build "$@"
      fi
      ;;
    down)
      compose down --remove-orphans
      ;;
    ps)
      compose ps
      ;;
    logs)
      require_service "$@"
      compose logs -f "$1"
      ;;
    shell)
      local service="${1:-dev}"
      ensure_service_up "$service"
      compose exec "$service" bash
      ;;
    exec)
      require_service "$@"
      local service="$1"
      shift
      [[ "${1:-}" == "--" ]] && shift
      [[ $# -ge 1 ]] || {
        printf 'error: missing command for exec\n' >&2
        exit 1
      }
      ensure_service_up "$service"
      compose exec "$service" "$@"
      ;;
    setup)
      require_service "$@"
      run_setup "$1" "${2:-}"
      ;;
    scan)
      require_service "$@"
      run_scan "$1"
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
