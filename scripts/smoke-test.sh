#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BINARY_PATH="${1:-$ROOT_DIR/target/debug/hostveil}"
# Keep smoke outputs deterministic across developer locales; allow explicit override.
HOSTVEIL_TEST_LOCALE="${HOSTVEIL_TEST_LOCALE:-en}"
export HOSTVEIL_LOCALE="$HOSTVEIL_TEST_LOCALE"
# Keep smoke scans deterministic and avoid optional external scanner execution.
export HOSTVEIL_ADAPTERS="${HOSTVEIL_ADAPTERS:-none}"

[[ -x "$BINARY_PATH" ]] || {
  printf 'error: binary is not executable: %s\n' "$BINARY_PATH" >&2
  exit 1
}

TMP_HOST_ROOT="$(mktemp -d)"
TMP_COMPOSE_ROOT="$(mktemp -d)"
cleanup() {
  rm -rf "$TMP_HOST_ROOT"
  rm -rf "$TMP_COMPOSE_ROOT"
}
trap cleanup EXIT

COMPOSE_FIXTURE="$TMP_COMPOSE_ROOT/docker-compose.yml"
cat > "$COMPOSE_FIXTURE" <<'YAML'
services:
  web:
    build: .
    privileged: true
    ports:
      - "8080:80"
YAML

mkdir -p "$TMP_HOST_ROOT/etc/ssh" "$TMP_HOST_ROOT/proc" "$TMP_HOST_ROOT/var/run"
printf 'PermitRootLogin yes\nPasswordAuthentication yes\n' > "$TMP_HOST_ROOT/etc/ssh/sshd_config"
printf 'alpha-smoke\n' > "$TMP_HOST_ROOT/etc/hostname"
printf '3600.00 0.00\n' > "$TMP_HOST_ROOT/proc/uptime"
printf '0.10 0.20 0.30 1/100 123\n' > "$TMP_HOST_ROOT/proc/loadavg"
touch "$TMP_HOST_ROOT/var/run/docker.sock"
chmod 666 "$TMP_HOST_ROOT/var/run/docker.sock"

VERSION_OUTPUT="$($BINARY_PATH --version)"
printf '%s\n' "$VERSION_OUTPUT" | grep -q '^hostveil '

$BINARY_PATH --help --user-mode | grep -q -- '--version'
$BINARY_PATH --help --user-mode | grep -q -- '--adapters'
$BINARY_PATH --help --user-mode | grep -q -- 'hostveil upgrade'
$BINARY_PATH --help --user-mode | grep -q -- 'hostveil auto-upgrade enable'
HOSTVEIL_LOCALE=ko $BINARY_PATH --help --user-mode | grep -q '사용법'
$BINARY_PATH --json --user-mode | grep -q '"scan_mode": "live"'
$BINARY_PATH --json --compose "$COMPOSE_FIXTURE" --user-mode | grep -q '"findings"'
$BINARY_PATH --json --host-root "$TMP_HOST_ROOT" --user-mode | grep -q '"host_runtime"'
$BINARY_PATH --quick-fix "$COMPOSE_FIXTURE" --preview-changes --user-mode | grep -q 'Preview only: no files were modified.'
HOSTVEIL_LOCALE=ko $BINARY_PATH --quick-fix "$COMPOSE_FIXTURE" --preview-changes --user-mode | grep -q '미리보기 전용'
$BINARY_PATH --fix "$COMPOSE_FIXTURE" --preview-changes --user-mode | grep -q 'Preview only: no files were modified.'

set +e
UPGRADE_OUTPUT="$($BINARY_PATH upgrade --user-mode 2>&1 >/dev/null)"
UPGRADE_STATUS=$?
set -e

[[ $UPGRADE_STATUS -ne 0 ]]
printf '%s\n' "$UPGRADE_OUTPUT" | grep -q 'installed hostveil wrapper'

set +e
BARE_OUTPUT="$($BINARY_PATH --user-mode 2>&1 >/dev/null)"
BARE_STATUS=$?
set -e

[[ $BARE_STATUS -ne 0 ]]
printf '%s\n' "$BARE_OUTPUT" | grep -q 'requires a terminal'

printf 'Smoke tests passed for %s\n' "$BINARY_PATH"
