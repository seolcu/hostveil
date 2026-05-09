#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB_COMPOSE_FILE="$ROOT_DIR/docker-compose.lab.yml"
PROJECT_NAME="hostveil-lab"
OUTPUT_ROOT="${HOSTVEIL_TUI_UX_OUTPUT:-$ROOT_DIR/target/tui-ux}"
LAB_TMP_ROOT="/tmp/hostveil-tui-ux"
DEFAULT_SCENARIOS=(navigation settings fix narrow)
SCENARIOS=("$@")
CURRENT_VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT_DIR/src/Cargo.toml" | head -n 1)"

usage() {
  cat <<'EOF'
Automated TUI UX validation for hostveil using the self-hosting lab.

Official entrypoint:
  scripts/lab.sh selfhost ux [scenario...]

Usage:
  scripts/tui-ux-check.sh
  scripts/tui-ux-check.sh navigation
  scripts/tui-ux-check.sh settings fix

Scenarios:
  navigation   Overview -> Findings -> detail navigation -> back -> exit
  settings     Settings modal keyboard workflow and persisted config check
  fix          Findings -> fix review -> apply -> rescan verification
  narrow       Narrow terminal render and findings drill-down

Artifacts:
  target/tui-ux/<scenario>/
EOF
}

require_commands() {
  command -v docker >/dev/null 2>&1 || {
    printf 'error: docker is required\n' >&2
    exit 1
  }
  command -v tmux >/dev/null 2>&1 || {
    printf 'error: tmux is required\n' >&2
    exit 1
  }
}

compose_lab_exec() {
  docker compose -p "$PROJECT_NAME" -f "$LAB_COMPOSE_FILE" exec "$@"
}

compose_lab_exec_t() {
  docker compose -p "$PROJECT_NAME" -f "$LAB_COMPOSE_FILE" exec -T "$@"
}

ensure_lab_up() {
  docker compose -p "$PROJECT_NAME" -f "$LAB_COMPOSE_FILE" up -d --build lab >/dev/null
}

build_lab_binary() {
  compose_lab_exec_t lab bash -lc 'cd /workspace && cargo build --quiet'
}

prepare_lab_dir() {
  local remote_dir="$1"
  compose_lab_exec_t lab bash -lc "mkdir -p '$remote_dir'"
}

prepare_temp_compose() {
  local scenario="$1"
  local source_path="$2"
  local remote_dir="$LAB_TMP_ROOT/$scenario"
  local remote_compose="$remote_dir/docker-compose.yml"

  prepare_lab_dir "$remote_dir"
  compose_lab_exec_t lab bash -lc "cp '$source_path' '$remote_compose'"
  printf '%s\n' "$remote_compose"
}

export_lab_file() {
  local remote_path="$1"
  local local_path="$2"
  if compose_lab_exec_t lab test -f "$remote_path"; then
    compose_lab_exec_t lab cat "$remote_path" > "$local_path"
  fi
}

capture_json_scan() {
  local remote_compose="$1"
  local output_path="$2"
  compose_lab_exec_t lab bash -lc \
    "cd /workspace && HOSTVEIL_LOCALE=en /workspace/target/debug/hostveil --user-mode --json --compose '$remote_compose' --adapters none" \
    > "$output_path"
}

count_findings() {
  local json_path="$1"
  perl -0ne 'my $count = () = /"id":\s*"/g; print "$count\n";' "$json_path"
}

assert_contains() {
  local path="$1"
  local needle="$2"
  grep -Fq -- "$needle" "$path" || {
    printf 'error: expected %s to contain: %s\n' "$path" "$needle" >&2
    exit 1
  }
}

assert_not_contains() {
  local path="$1"
  local needle="$2"
  if grep -Fq -- "$needle" "$path"; then
    printf 'error: expected %s to not contain: %s\n' "$path" "$needle" >&2
    exit 1
  fi
}

start_tmux_session() {
  local session="$1"
  local cols="$2"
  local rows="$3"
  local remote_compose="$4"
  local remote_home="$5"

  compose_lab_exec_t lab bash -lc "mkdir -p '$remote_home/.config'"

  local cmd
  printf -v cmd "%q " \
    docker compose -p "$PROJECT_NAME" -f "$LAB_COMPOSE_FILE" exec \
    -e "HOME=$remote_home" \
    -e "XDG_CONFIG_HOME=$remote_home/.config" \
    -e "HOSTVEIL_LOCALE=en" \
    -e "HOSTVEIL_ADAPTERS=none" \
    lab \
    bash -lc \
    "cd /workspace && /workspace/target/debug/hostveil --user-mode --compose '$remote_compose' --adapters none"
  tmux new-session -d -x "$cols" -y "$rows" -s "$session"
  tmux send-keys -t "$session" "${cmd% }" Enter
}

kill_tmux_session() {
  local session="$1"
  tmux has-session -t "$session" 2>/dev/null && tmux kill-session -t "$session"
}

capture_pane() {
  local session="$1"
  local output_dir="$2"
  local step="$3"
  tmux capture-pane -p -J -t "$session" > "$output_dir/$step.txt"
  tmux capture-pane -e -p -J -t "$session" > "$output_dir/$step.ansi"
}

wait_for_text() {
  local session="$1"
  local needle="$2"
  local attempts="${3:-60}"

  for _ in $(seq 1 "$attempts"); do
    if tmux capture-pane -p -J -t "$session" | grep -Fq -- "$needle"; then
      return 0
    fi
    sleep 0.5
  done

  printf 'error: session %s did not render expected text: %s\n' "$session" "$needle" >&2
  tmux capture-pane -p -J -t "$session" >&2 || true
  exit 1
}

wait_for_hostveil_stop() {
  local remote_compose="$1"
  local attempts="${2:-30}"
  local binary_pattern
  binary_pattern="^/workspace/target/debug/hostveil --user-mode --compose ${remote_compose//\//\\/} --adapters none$"

  for _ in $(seq 1 "$attempts"); do
    if compose_lab_exec_t lab bash -lc "! ps -eo command= | grep -E -- '$binary_pattern' >/dev/null"; then
      return 0
    fi
    sleep 0.5
  done

  printf 'error: hostveil did not stop for compose target %s\n' "$remote_compose" >&2
  exit 1
}

send_keys() {
  local session="$1"
  shift
  tmux send-keys -t "$session" "$@"
  sleep 0.4
}

append_report() {
  local report_path="$1"
  shift
  printf '%s\n' "$*" >> "$report_path"
}

run_navigation_scenario() {
  local scenario="navigation"
  local output_dir="$OUTPUT_ROOT/$scenario"
  local session="hostveil-ux-$scenario-$$"
  local report="$output_dir/report.txt"
  local remote_compose
  remote_compose="$(prepare_temp_compose "$scenario" "/workspace/docker/lab/self-hosting-stack.yml")"

  rm -rf "$output_dir"
  mkdir -p "$output_dir"
  : > "$report"

  start_tmux_session "$session" 120 40 "$remote_compose" "$LAB_TMP_ROOT/home-$scenario"
  trap 'kill_tmux_session "$session"' RETURN

  wait_for_text "$session" "Linux Self-Hosting Security Dashboard"
  capture_pane "$session" "$output_dir" "01-overview"
  send_keys "$session" 2
  wait_for_text "$session" "Findings"
  capture_pane "$session" "$output_dir" "02-findings-list"
  send_keys "$session" Down
  send_keys "$session" Down
  send_keys "$session" Tab
  send_keys "$session" PageDown
  capture_pane "$session" "$output_dir" "03-findings-detail"
  send_keys "$session" q
  wait_for_text "$session" "Linux Self-Hosting Security Dashboard"
  capture_pane "$session" "$output_dir" "04-overview-return"
  send_keys "$session" q
  wait_for_hostveil_stop "$remote_compose"
  kill_tmux_session "$session"
  trap - RETURN

  assert_contains "$output_dir/01-overview.txt" "Linux Self-Hosting Security Dashboard"
  assert_contains "$output_dir/02-findings-list.txt" "Findings"
  assert_contains "$output_dir/03-findings-detail.txt" "How to Fix"
  assert_contains "$output_dir/04-overview-return.txt" "Action Queue"

  append_report "$report" "navigation: pass"
  append_report "$report" "captures: 01-overview, 02-findings-list, 03-findings-detail, 04-overview-return"
}

run_settings_scenario() {
  local scenario="settings"
  local output_dir="$OUTPUT_ROOT/$scenario"
  local session="hostveil-ux-$scenario-$$"
  local report="$output_dir/report.txt"
  local remote_home="$LAB_TMP_ROOT/home-$scenario"
  local remote_compose
  remote_compose="$(prepare_temp_compose "$scenario" "/workspace/docker/lab/self-hosting-stack.yml")"

  rm -rf "$output_dir"
  mkdir -p "$output_dir"
  : > "$report"

  start_tmux_session "$session" 120 40 "$remote_compose" "$remote_home"
  trap 'kill_tmux_session "$session"' RETURN

  wait_for_text "$session" "Linux Self-Hosting Security Dashboard"
  send_keys "$session" s
  wait_for_text "$session" "Theme"
  capture_pane "$session" "$output_dir" "01-settings-open"
  send_keys "$session" 2
  send_keys "$session" Right
  send_keys "$session" 3
  send_keys "$session" Right
  capture_pane "$session" "$output_dir" "02-settings-adjusted"
  send_keys "$session" Enter
  wait_for_text "$session" "hostveil v$CURRENT_VERSION"
  capture_pane "$session" "$output_dir" "03-overview-after-settings"
  send_keys "$session" q
  wait_for_hostveil_stop "$remote_compose"
  kill_tmux_session "$session"
  trap - RETURN

  compose_lab_exec_t lab bash -lc "cat '$remote_home/.config/hostveil/config.json'" > "$output_dir/config.json"

  assert_contains "$output_dir/01-settings-open.txt" "Locale"
  assert_contains "$output_dir/02-settings-adjusted.txt" "언어: ko"
  assert_contains "$output_dir/03-overview-after-settings.txt" "LANG KO"
  assert_contains "$output_dir/config.json" "\"layout\""
  assert_contains "$output_dir/config.json" "\"locale\""

  append_report "$report" "settings: pass"
  append_report "$report" "saved settings: $output_dir/config.json"
}

run_fix_scenario() {
  local scenario="fix"
  local output_dir="$OUTPUT_ROOT/$scenario"
  local session="hostveil-ux-$scenario-$$"
  local report="$output_dir/report.txt"
  local remote_home="$LAB_TMP_ROOT/home-$scenario"
  local remote_compose
  remote_compose="$(prepare_temp_compose "$scenario" "/workspace/docker/lab/self-hosting-stack.yml")"
  local remote_backup="${remote_compose%.yml}.yml.bak"

  rm -rf "$output_dir"
  mkdir -p "$output_dir"
  : > "$report"

  capture_json_scan "$remote_compose" "$output_dir/before.json"
  start_tmux_session "$session" 120 40 "$remote_compose" "$remote_home"
  trap 'kill_tmux_session "$session"' RETURN

  wait_for_text "$session" "Linux Self-Hosting Security Dashboard"
  capture_pane "$session" "$output_dir" "01-overview"
  send_keys "$session" 2
  wait_for_text "$session" "Findings"
  capture_pane "$session" "$output_dir" "02-findings-before-fix"
  send_keys "$session" Down
  send_keys "$session" f
  wait_for_text "$session" "Fix Review"
  capture_pane "$session" "$output_dir" "03-fix-review"
  send_keys "$session" PageDown
  capture_pane "$session" "$output_dir" "04-fix-review-scrolled"
  send_keys "$session" Enter
  wait_for_text "$session" "Linux Self-Hosting Security Dashboard"
  capture_pane "$session" "$output_dir" "05-overview-after-fix"
  send_keys "$session" q
  wait_for_hostveil_stop "$remote_compose"
  kill_tmux_session "$session"
  trap - RETURN

  export_lab_file "$remote_compose" "$output_dir/docker-compose.yml"
  export_lab_file "$remote_backup" "$output_dir/docker-compose.yml.bak"
  capture_json_scan "$remote_compose" "$output_dir/after.json"

  local before_count after_count
  before_count="$(count_findings "$output_dir/before.json")"
  after_count="$(count_findings "$output_dir/after.json")"

  assert_contains "$output_dir/before.json" '"id": "permissions.privileged"'
  assert_not_contains "$output_dir/after.json" '"id": "permissions.privileged"'
  assert_contains "$output_dir/03-fix-review.txt" "Fix Review"
  assert_contains "$output_dir/03-fix-review.txt" "replace privileged mode with a minimal NET_BIND_SERVICE capability review"
  assert_contains "$output_dir/docker-compose.yml" "cap_add:"
  assert_not_contains "$output_dir/docker-compose.yml" "privileged: true"
  assert_contains "$output_dir/docker-compose.yml.bak" "privileged: true"
  assert_contains "$output_dir/docker-compose.yml" '      - "127.0.0.1:8081:80"'
  assert_contains "$output_dir/docker-compose.yml" '      - "0.0.0.0:3012:3012"'
  assert_contains "$output_dir/docker-compose.yml" '      - jellyfin-config:/config'
  assert_contains "$output_dir/docker-compose.yml" '      - nextcloud-db:/var/lib/postgresql/data'
  assert_not_contains "$output_dir/docker-compose.yml" 'vaultwarden-data: null'
  assert_not_contains "$output_dir/docker-compose.yml" 'jellyfin-config: null'
  assert_not_contains "$output_dir/docker-compose.yml" 'nextcloud-db: null'

  if (( after_count >= before_count )); then
    printf 'error: expected finding count to decrease after fix (before=%s after=%s)\n' "$before_count" "$after_count" >&2
    exit 1
  fi

  diff -u "$output_dir/docker-compose.yml.bak" "$output_dir/docker-compose.yml" > "$output_dir/fix.diff" || true

  append_report "$report" "fix: pass"
  append_report "$report" "before findings: $before_count"
  append_report "$report" "after findings: $after_count"
  append_report "$report" "artifacts: before.json after.json docker-compose.yml docker-compose.yml.bak fix.diff"
}

run_narrow_scenario() {
  local scenario="narrow"
  local output_dir="$OUTPUT_ROOT/$scenario"
  local session="hostveil-ux-$scenario-$$"
  local report="$output_dir/report.txt"
  local remote_compose
  remote_compose="$(prepare_temp_compose "$scenario" "/workspace/docker/lab/self-hosting-stack.yml")"

  rm -rf "$output_dir"
  mkdir -p "$output_dir"
  : > "$report"

  start_tmux_session "$session" 60 20 "$remote_compose" "$LAB_TMP_ROOT/home-$scenario"
  trap 'kill_tmux_session "$session"' RETURN

  wait_for_text "$session" "Server Status"
  capture_pane "$session" "$output_dir" "01-overview-narrow"
  send_keys "$session" 2
  wait_for_text "$session" "Findings"
  capture_pane "$session" "$output_dir" "02-findings-narrow"
  send_keys "$session" Enter
  capture_pane "$session" "$output_dir" "03-detail-narrow"
  send_keys "$session" q
  wait_for_text "$session" "Linux Self-Hosting Security Dashboard"
  send_keys "$session" q
  wait_for_hostveil_stop "$remote_compose"
  kill_tmux_session "$session"
  trap - RETURN

  assert_contains "$output_dir/01-overview-narrow.txt" "Server Status"
  assert_contains "$output_dir/02-findings-narrow.txt" "S sev | x src | v svc | m rem | o sort"
  assert_contains "$output_dir/03-detail-narrow.txt" "Detail [detail focus]"
  assert_contains "$output_dir/03-detail-narrow.txt" "Container mounts a sensitive host path"

  append_report "$report" "narrow: pass"
  append_report "$report" "terminal: 60x20"
}

run_selected_scenarios() {
  local requested=("${SCENARIOS[@]}")
  if [[ ${#requested[@]} -eq 0 || -z "${requested[0]}" ]]; then
    requested=("${DEFAULT_SCENARIOS[@]}")
  fi

  for scenario in "${requested[@]}"; do
    case "$scenario" in
      navigation) run_navigation_scenario ;;
      settings) run_settings_scenario ;;
      fix) run_fix_scenario ;;
      narrow) run_narrow_scenario ;;
      -h|--help|help) usage; exit 0 ;;
      *)
        printf 'error: unknown scenario: %s\n' "$scenario" >&2
        usage >&2
        exit 1
        ;;
    esac
  done
}

main() {
  if [[ ${#SCENARIOS[@]} -gt 0 ]]; then
    case "${SCENARIOS[0]}" in
      -h|--help|help)
        usage
        exit 0
        ;;
    esac
  fi

  require_commands
  mkdir -p "$OUTPUT_ROOT"
  ensure_lab_up
  build_lab_binary
  run_selected_scenarios
  printf 'TUI UX checks passed. Artifacts: %s\n' "$OUTPUT_ROOT"
}

main
