#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV_COMPOSE_FILE="$ROOT_DIR/compose.dev.yml"
SELFHOST_COMPOSE_FILE="$ROOT_DIR/docker-compose.lab.yml"
SELFHOST_TARGET_COMPOSE_FILE="$ROOT_DIR/docker/lab/self-hosting-stack.yml"
SELFHOST_PROJECT_NAME="hostveil-lab"
TMP_COMPOSE_FILE=""

cleanup() {
  if [[ -n "${TMP_COMPOSE_FILE:-}" && -f "$TMP_COMPOSE_FILE" ]]; then
    rm -f "$TMP_COMPOSE_FILE"
  fi
}
trap cleanup EXIT

main_usage() {
  cat <<'EOF'
Unified Docker workflow entrypoint for hostveil.

Usage:
  scripts/lab.sh dev COMMAND [ARGS...]
  scripts/lab.sh host COMMAND [ARGS...]
  scripts/lab.sh selfhost COMMAND [ARGS...]

Groups:
  dev       Rust development shell and generic workspace commands
  host      Multi-distro setup and host scan validation labs
  selfhost  Self-hosting lab, ttyd shell, and TUI UX validation

Examples:
  scripts/lab.sh dev up
  scripts/lab.sh dev shell
  scripts/lab.sh host up ubuntu-lab
  scripts/lab.sh host setup ubuntu-lab lynis,trivy
  scripts/lab.sh host scan rocky-lab
  scripts/lab.sh selfhost up
  scripts/lab.sh selfhost shell
  scripts/lab.sh selfhost ux fix-auto-preview
EOF
}

dev_usage() {
  cat <<'EOF'
Development container workflow.

Usage:
  scripts/lab.sh dev up [service...]
  scripts/lab.sh dev down
  scripts/lab.sh dev ps
  scripts/lab.sh dev logs [service]
  scripts/lab.sh dev shell [service]
  scripts/lab.sh dev exec SERVICE -- COMMAND [ARG...]

Default service:
  dev
EOF
}

host_usage() {
  cat <<'EOF'
Multi-distro host validation workflow.

Usage:
  scripts/lab.sh host up SERVICE...
  scripts/lab.sh host down
  scripts/lab.sh host ps
  scripts/lab.sh host logs SERVICE
  scripts/lab.sh host shell SERVICE
  scripts/lab.sh host exec SERVICE -- COMMAND [ARG...]
  scripts/lab.sh host setup SERVICE [tool-list]
  scripts/lab.sh host scan SERVICE

Services:
  fedora-lab
  rocky-lab
  ubuntu-lab
  debian-lab
EOF
}

selfhost_usage() {
  cat <<'EOF'
Self-hosting Compose and TUI workflow.

Usage:
  scripts/lab.sh selfhost up
  scripts/lab.sh selfhost down
  scripts/lab.sh selfhost reset
  scripts/lab.sh selfhost ps
  scripts/lab.sh selfhost logs [service]
  scripts/lab.sh selfhost shell
  scripts/lab.sh selfhost check
  scripts/lab.sh selfhost ux [scenario...]

Examples:
  scripts/lab.sh selfhost up
  scripts/lab.sh selfhost shell
  scripts/lab.sh selfhost check
  scripts/lab.sh selfhost ux
  scripts/lab.sh selfhost ux navigation-deep fix-review-input
EOF
}

legacy_dev_usage() {
  cat <<'EOF'
Compatibility wrapper for scripts/dev-env.sh.
Official entrypoint: scripts/lab.sh

Equivalent commands:
  scripts/dev-env.sh up dev            -> scripts/lab.sh dev up
  scripts/dev-env.sh shell dev         -> scripts/lab.sh dev shell
  scripts/dev-env.sh up ubuntu-lab     -> scripts/lab.sh host up ubuntu-lab
  scripts/dev-env.sh setup ubuntu-lab  -> scripts/lab.sh host setup ubuntu-lab
  scripts/dev-env.sh scan rocky-lab    -> scripts/lab.sh host scan rocky-lab
EOF
}

legacy_selfhost_usage() {
  cat <<'EOF'
Compatibility wrapper for scripts/self-hosting-lab.sh.
Official entrypoint: scripts/lab.sh selfhost

Equivalent commands:
  scripts/self-hosting-lab.sh up       -> scripts/lab.sh selfhost up
  scripts/self-hosting-lab.sh shell    -> scripts/lab.sh selfhost shell
  scripts/self-hosting-lab.sh check    -> scripts/lab.sh selfhost check
  scripts/self-hosting-lab.sh logs     -> scripts/lab.sh selfhost logs
  scripts/self-hosting-lab.sh reset    -> scripts/lab.sh selfhost reset
  scripts/tui-ux-check.sh              -> scripts/lab.sh selfhost ux
EOF
}

ensure_docker() {
  command -v docker >/dev/null 2>&1 || {
    printf 'error: docker is required\nnext: install Docker, then run: scripts/lab.sh --help\n' >&2
    exit 1
  }
  docker compose version >/dev/null 2>&1 || {
    printf 'error: docker compose is required\nnext: install Docker Compose, then run: scripts/lab.sh --help\n' >&2
    exit 1
  }
}

require_arg() {
  local name="$1"
  local value="${2:-}"
  [[ -n "$value" ]] || {
    printf 'error: missing %s\nnext: run scripts/lab.sh --help\n' "$name" >&2
    exit 1
  }
}

validate_host_service() {
  case "$1" in
    fedora-lab|rocky-lab|ubuntu-lab|debian-lab) ;;
    *)
      printf 'error: unsupported host lab service: %s\nnext: run scripts/lab.sh host help\n' "$1" >&2
      exit 1
      ;;
  esac
}

dev_compose() {
  docker compose --profile labs -f "$DEV_COMPOSE_FILE" "$@"
}

selfhost_generate_safe_compose() {
  TMP_COMPOSE_FILE="$(mktemp)"
  sed 's/"0\.0\.0\.0:/"127.0.0.1:/g' "$SELFHOST_TARGET_COMPOSE_FILE" > "$TMP_COMPOSE_FILE"
}

selfhost_compose() {
  local target_file="${TMP_COMPOSE_FILE:-$SELFHOST_TARGET_COMPOSE_FILE}"
  docker compose -p "$SELFHOST_PROJECT_NAME" \
    -f "$SELFHOST_COMPOSE_FILE" \
    -f "$target_file" \
    "$@"
}

ensure_dev_service_up() {
  local service="$1"
  dev_compose up -d "$service"
}

ensure_host_service_up() {
  local service="$1"
  validate_host_service "$service"
  dev_compose up -d "$service"
}

ensure_selfhost_up() {
  selfhost_generate_safe_compose
  selfhost_compose up -d --build lab vaultwarden jellyfin gitea nextcloud nextcloud-db exposed-nginx
}

print_selfhost_hints() {
  printf '\nSelf-hosting lab is running.\n'
  printf 'Primary commands:\n'
  printf '  scripts/lab.sh selfhost shell\n'
  printf '  scripts/lab.sh selfhost check\n'
  printf '  scripts/lab.sh selfhost ux\n\n'
  printf 'Inside the lab shell:\n'
  printf '  cargo run -- --user-mode --compose docker/lab/self-hosting-stack.yml\n'
  printf '  cargo run -- --user-mode --json --compose docker/lab/self-hosting-stack.yml --adapters none\n'
  printf '  cargo run -- --json --compose docker/lab/self-hosting-stack.yml --host-root / --adapters trivy,dockle,lynis\n\n'
}

run_dev_group() {
  local command="${1:-help}"
  shift || true

  case "$command" in
    up)
      if [[ $# -eq 0 ]]; then
        dev_compose up -d --build dev
      else
        dev_compose up -d --build "$@"
      fi
      ;;
    down)
      dev_compose down --remove-orphans
      ;;
    ps)
      dev_compose ps
      ;;
    logs)
      if [[ $# -eq 0 ]]; then
        dev_compose logs -f dev
      else
        dev_compose logs -f "$1"
      fi
      ;;
    shell)
      local service="${1:-dev}"
      ensure_dev_service_up "$service"
      dev_compose exec "$service" bash
      ;;
    exec)
      local service="${1:-}"
      require_arg "service name" "$service"
      shift
      [[ "${1:-}" == "--" ]] && shift
      [[ $# -ge 1 ]] || {
        printf 'error: missing command for exec\nnext: run scripts/lab.sh dev help\n' >&2
        exit 1
      }
      ensure_dev_service_up "$service"
      dev_compose exec "$service" "$@"
      ;;
    help|-h|--help)
      dev_usage
      ;;
    *)
      printf 'error: unknown dev command: %s\nnext: run scripts/lab.sh dev help\n' "$command" >&2
      exit 1
      ;;
  esac
}

run_host_group() {
  local command="${1:-help}"
  shift || true

  case "$command" in
    up)
      [[ $# -ge 1 ]] || {
        printf 'error: host up requires at least one service\nnext: run scripts/lab.sh host help\n' >&2
        exit 1
      }
      for service in "$@"; do
        validate_host_service "$service"
      done
      dev_compose up -d --build "$@"
      ;;
    down)
      dev_compose down --remove-orphans
      ;;
    ps)
      dev_compose ps
      ;;
    logs)
      local service="${1:-}"
      require_arg "service name" "$service"
      validate_host_service "$service"
      dev_compose logs -f "$service"
      ;;
    shell)
      local service="${1:-}"
      require_arg "service name" "$service"
      ensure_host_service_up "$service"
      dev_compose exec "$service" bash
      ;;
    exec)
      local service="${1:-}"
      require_arg "service name" "$service"
      validate_host_service "$service"
      shift
      [[ "${1:-}" == "--" ]] && shift
      [[ $# -ge 1 ]] || {
        printf 'error: missing command for exec\nnext: run scripts/lab.sh host help\n' >&2
        exit 1
      }
      ensure_host_service_up "$service"
      dev_compose exec "$service" "$@"
      ;;
    setup)
      local service="${1:-}"
      local tools="${2:-}"
      require_arg "service name" "$service"
      ensure_host_service_up "$service"
      if [[ -n "$tools" ]]; then
        dev_compose exec "$service" bash -c "cd /workspace && cargo run -- setup --yes --tools '$tools'"
      else
        dev_compose exec "$service" bash -c 'cd /workspace && cargo run -- setup --yes'
      fi
      ;;
    scan)
      local service="${1:-}"
      require_arg "service name" "$service"
      ensure_host_service_up "$service"
      dev_compose exec "$service" bash -c 'cd /workspace && cargo run -- --json --host-root /'
      ;;
    help|-h|--help)
      host_usage
      ;;
    *)
      printf 'error: unknown host command: %s\nnext: run scripts/lab.sh host help\n' "$command" >&2
      exit 1
      ;;
  esac
}

run_selfhost_group() {
  local command="${1:-help}"
  shift || true

  case "$command" in
    up)
      ensure_selfhost_up
      print_selfhost_hints
      ;;
    down)
      docker compose -p "$SELFHOST_PROJECT_NAME" down --remove-orphans
      ;;
    reset)
      docker compose -p "$SELFHOST_PROJECT_NAME" down --remove-orphans --volumes
      ;;
    ps)
      ensure_selfhost_up
      selfhost_compose ps
      ;;
    logs)
      ensure_selfhost_up
      if [[ $# -gt 0 ]]; then
        selfhost_compose logs -f "$1"
      else
        selfhost_compose logs -f
      fi
      ;;
    shell)
      ensure_selfhost_up
      selfhost_compose exec lab bash
      ;;
    check)
      ensure_selfhost_up
      selfhost_compose exec lab bash -lc 'cd /workspace && cargo run -- --user-mode --version'
      ;;
    ux)
      "$ROOT_DIR/scripts/tui-ux-check.sh" "$@"
      ;;
    help|-h|--help)
      selfhost_usage
      ;;
    *)
      printf 'error: unknown selfhost command: %s\nnext: run scripts/lab.sh selfhost help\n' "$command" >&2
      exit 1
      ;;
  esac
}

run_compat_dev_env() {
  local command="${1:-help}"
  shift || true

  case "$command" in
    up)
      if [[ $# -eq 0 || "${1:-}" == "dev" ]]; then
        run_dev_group up "${@:-}"
      else
        run_host_group up "$@"
      fi
      ;;
    down)
      dev_compose down --remove-orphans
      ;;
    ps)
      dev_compose ps
      ;;
    logs)
      local service="${1:-}"
      require_arg "service name" "$service"
      if [[ "$service" == "dev" ]]; then
        run_dev_group logs "$service"
      else
        run_host_group logs "$service"
      fi
      ;;
    shell)
      local service="${1:-dev}"
      if [[ "$service" == "dev" ]]; then
        run_dev_group shell "$service"
      else
        run_host_group shell "$service"
      fi
      ;;
    exec)
      local service="${1:-}"
      require_arg "service name" "$service"
      shift
      if [[ "$service" == "dev" ]]; then
        run_dev_group exec "$service" "$@"
      else
        run_host_group exec "$service" "$@"
      fi
      ;;
    setup)
      run_host_group setup "$@"
      ;;
    scan)
      run_host_group scan "$@"
      ;;
    help|-h|--help)
      legacy_dev_usage
      printf '\n'
      dev_usage
      printf '\n'
      host_usage
      ;;
    *)
      printf 'error: unknown command: %s\nnext: run scripts/dev-env.sh --help\n' "$command" >&2
      exit 1
      ;;
  esac
}

run_compat_selfhost() {
  local command="${1:-help}"
  shift || true

  case "$command" in
    help|-h|--help)
      legacy_selfhost_usage
      printf '\n'
      selfhost_usage
      ;;
    *)
      run_selfhost_group "$command" "$@"
      ;;
  esac
}

main() {
  local group="${1:-help}"
  shift || true

  ensure_docker

  case "$group" in
    dev)
      run_dev_group "$@"
      ;;
    host)
      run_host_group "$@"
      ;;
    selfhost)
      run_selfhost_group "$@"
      ;;
    __compat_dev_env)
      run_compat_dev_env "$@"
      ;;
    __compat_selfhost)
      run_compat_selfhost "$@"
      ;;
    help|-h|--help)
      main_usage
      ;;
    *)
      printf 'error: unknown lab group: %s\nnext: run scripts/lab.sh --help\n' "$group" >&2
      exit 1
      ;;
  esac
}

main "$@"
