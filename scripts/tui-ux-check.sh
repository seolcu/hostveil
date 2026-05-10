#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB_COMPOSE_FILE="$ROOT_DIR/docker-compose.lab.yml"
PROJECT_NAME="hostveil-lab"
OUTPUT_ROOT="${HOSTVEIL_TUI_UX_OUTPUT:-$ROOT_DIR/target/tui-ux}"
LAB_TMP_ROOT="/tmp/hostveil-tui-ux"
DEFAULT_SCENARIOS=(
  overview-idle
  navigation-deep
  host-triage
  settings-persist
  help-search
  fix-auto-preview
  fix-review-choice
  fix-review-input
  fix-review-cancel
  narrow-layout
)
SCENARIOS=("$@")
CURRENT_VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT_DIR/src/Cargo.toml" | head -n 1)"

usage() {
  cat <<'EOF'
Automated TUI UX validation for hostveil using the self-hosting lab.

Official entrypoint:
  scripts/lab.sh selfhost ux [scenario...]

Usage:
  scripts/tui-ux-check.sh
  scripts/tui-ux-check.sh overview-idle navigation-deep
  scripts/tui-ux-check.sh fix-auto-preview fix-review-input

Scenarios:
  overview-idle       Overview idle render after a 10 second wait
  navigation-deep     Overview -> Findings -> detail navigation -> back -> exit
  host-triage         Host-only findings view and filter cycling
  settings-persist    Settings modal keyboard workflow and persisted config check
  help-search         Help overlay and findings search modal workflow
  fix-auto-preview    Automatic fix review -> apply -> rescan verification
  fix-review-choice   Review flow with a choice modal before fix review/apply
  fix-review-input    Review flow with secret input modal before fix review/apply
  fix-review-cancel   Cancel during a review prompt and verify no file changes
  narrow-layout       Narrow terminal render and findings drill-down
  navigation          Compatibility alias for navigation-deep
  settings            Compatibility alias for settings-persist
  fix                 Compatibility alias for fix-auto-preview
  narrow              Compatibility alias for narrow-layout

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

prepare_temp_compose_from_text() {
  local scenario="$1"
  local content="$2"
  local remote_dir="$LAB_TMP_ROOT/$scenario"
  local remote_compose="$remote_dir/docker-compose.yml"

  prepare_lab_dir "$remote_dir"
  printf '%s\n' "$content" | compose_lab_exec_t lab bash -lc "cat > '$remote_compose'"
  printf '%s\n' "$remote_compose"
}

export_lab_file() {
  local remote_path="$1"
  local local_path="$2"
  if compose_lab_exec_t lab test -f "$remote_path"; then
    compose_lab_exec_t lab cat "$remote_path" > "$local_path"
  fi
}

find_remote_backup() {
  local remote_compose="$1"
  local remote_dir remote_name remote_stem remote_ext
  remote_dir="$(dirname "$remote_compose")"
  remote_name="$(basename "$remote_compose")"
  remote_stem="${remote_name%.*}"
  remote_ext="${remote_name##*.}"

  compose_lab_exec_t lab bash -lc "
    find '$remote_dir' -maxdepth 1 -type f -name '${remote_stem}-*.bak.${remote_ext}' | sort | tail -n 1
  "
}

export_lab_backup() {
  local remote_compose="$1"
  local local_path="$2"
  local remote_backup
  remote_backup="$(find_remote_backup "$remote_compose")"
  if [[ -n "$remote_backup" ]]; then
    export_lab_file "$remote_backup" "$local_path"
  fi
}

assert_file_exists() {
  local path="$1"
  [[ -f "$path" ]] || {
    printf 'error: expected file to exist: %s\n' "$path" >&2
    exit 1
  }
}

assert_file_missing() {
  local path="$1"
  [[ ! -e "$path" ]] || {
    printf 'error: expected file to be absent: %s\n' "$path" >&2
    exit 1
  }
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

wait_for_any_text() {
  local session="$1"
  local attempts="${2:-60}"
  shift 2

  for _ in $(seq 1 "$attempts"); do
    local content
    content="$(tmux capture-pane -p -J -t "$session")"
    for needle in "$@"; do
      if grep -Fq -- "$needle" <<<"$content"; then
        return 0
      fi
    done
    sleep 0.5
  done

  printf 'error: session %s did not render any expected text: %s\n' "$session" "$*" >&2
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

run_overview_idle_scenario() {
  local scenario="overview-idle"
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
  sleep 10
  capture_pane "$session" "$output_dir" "01-overview-idle"
  send_keys "$session" q
  wait_for_hostveil_stop "$remote_compose"
  kill_tmux_session "$session"
  trap - RETURN

  assert_contains "$output_dir/01-overview-idle.txt" "Linux Self-Hosting Security Dashboard"
  assert_contains "$output_dir/01-overview-idle.txt" "Action Queue"
  assert_contains "$output_dir/01-overview-idle.txt" "Server Status"

  append_report "$report" "overview-idle: pass"
  append_report "$report" "wait: 10s"
}

run_navigation_deep_scenario() {
  local scenario="navigation-deep"
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

  append_report "$report" "navigation-deep: pass"
  append_report "$report" "captures: 01-overview, 02-findings-list, 03-findings-detail, 04-overview-return"
}

run_host_triage_scenario() {
  local scenario="host-triage"
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
  send_keys "$session" h
  wait_for_text "$session" "Findings"
  wait_for_text "$session" "Host triage mode"
  capture_pane "$session" "$output_dir" "01-host-findings"
  send_keys "$session" x
  send_keys "$session" m
  send_keys "$session" v
  send_keys "$session" o
  send_keys "$session" r
  capture_pane "$session" "$output_dir" "02-host-filters-reset"
  send_keys "$session" q
  wait_for_text "$session" "Linux Self-Hosting Security Dashboard"
  send_keys "$session" q
  wait_for_hostveil_stop "$remote_compose"
  kill_tmux_session "$session"
  trap - RETURN

  assert_contains "$output_dir/01-host-findings.txt" "Host triage mode"
  assert_contains "$output_dir/01-host-findings.txt" "Findings [list focus]"
  assert_contains "$output_dir/02-host-filters-reset.txt" "rem:all"

  append_report "$report" "host-triage: pass"
}

run_settings_persist_scenario() {
  local scenario="settings-persist"
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

  append_report "$report" "settings-persist: pass"
  append_report "$report" "saved settings: $output_dir/config.json"
}

run_help_search_scenario() {
  local scenario="help-search"
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
  send_keys "$session" 2
  wait_for_text "$session" "Findings"
  send_keys "$session" '?'
  wait_for_text "$session" "Keyboard Shortcuts"
  capture_pane "$session" "$output_dir" "01-help-open"
  send_keys "$session" Escape
  wait_for_text "$session" "Findings"
  send_keys "$session" /
  wait_for_text "$session" "Search Findings"
  capture_pane "$session" "$output_dir" "02-search-open"
  send_keys "$session" adminer
  send_keys "$session" Enter
  capture_pane "$session" "$output_dir" "03-search-applied"
  send_keys "$session" Escape
  send_keys "$session" q
  send_keys "$session" q
  wait_for_hostveil_stop "$remote_compose"
  kill_tmux_session "$session"
  trap - RETURN

  assert_contains "$output_dir/01-help-open.txt" "Keyboard Shortcuts"
  assert_contains "$output_dir/02-search-open.txt" "Search Findings"
  assert_contains "$output_dir/02-search-open.txt" "Search findings by title, description, subject, or fix:"
  assert_contains "$output_dir/03-search-applied.txt" "Findings"

  append_report "$report" "help-search: pass"
}

run_fix_auto_preview_scenario() {
  local scenario="fix-auto-preview"
  local output_dir="$OUTPUT_ROOT/$scenario"
  local session="hostveil-ux-$scenario-$$"
  local report="$output_dir/report.txt"
  local compose_text
  compose_text="$(cat <<'EOF'
services:
  app:
    image: alpine:3.20
    user: "1000:1000"
    privileged: true
    ports:
      - "127.0.0.1:8080:80"
EOF
)"
  local remote_compose
  remote_compose="$(prepare_temp_compose_from_text "$scenario" "$compose_text")"

  rm -rf "$output_dir"
  mkdir -p "$output_dir"
  : > "$report"

  capture_json_scan "$remote_compose" "$output_dir/before.json"
  start_tmux_session "$session" 120 40 "$remote_compose" "$LAB_TMP_ROOT/home-$scenario"
  trap 'kill_tmux_session "$session"' RETURN

  wait_for_text "$session" "Linux Self-Hosting Security Dashboard"
  capture_pane "$session" "$output_dir" "01-overview"
  send_keys "$session" 2
  wait_for_text "$session" "Findings"
  capture_pane "$session" "$output_dir" "02-findings-before-fix"
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
  export_lab_backup "$remote_compose" "$output_dir/docker-compose.yml.bak"
  capture_json_scan "$remote_compose" "$output_dir/after.json"

  local before_count after_count
  before_count="$(count_findings "$output_dir/before.json")"
  after_count="$(count_findings "$output_dir/after.json")"

  assert_contains "$output_dir/before.json" '"id": "permissions.privileged"'
  assert_not_contains "$output_dir/after.json" '"id": "permissions.privileged"'
  assert_contains "$output_dir/03-fix-review.txt" "Fix Review"
  assert_contains "$output_dir/03-fix-review.txt" "NET_BIND_SERVICE"
  assert_contains "$output_dir/docker-compose.yml" "cap_add:"
  assert_not_contains "$output_dir/docker-compose.yml" "privileged: true"
  assert_contains "$output_dir/docker-compose.yml.bak" "privileged: true"
  assert_contains "$output_dir/docker-compose.yml" "NET_BIND_SERVICE"

  if (( after_count >= before_count )); then
    printf 'error: expected finding count to decrease after fix (before=%s after=%s)\n' "$before_count" "$after_count" >&2
    exit 1
  fi

  diff -u "$output_dir/docker-compose.yml.bak" "$output_dir/docker-compose.yml" > "$output_dir/fix.diff" || true

  append_report "$report" "fix-auto-preview: pass"
  append_report "$report" "before findings: $before_count"
  append_report "$report" "after findings: $after_count"
  append_report "$report" "artifacts: before.json after.json docker-compose.yml docker-compose.yml.bak fix.diff"
}

run_fix_review_choice_scenario() {
  local scenario="fix-review-choice"
  local output_dir="$OUTPUT_ROOT/$scenario"
  local session="hostveil-ux-$scenario-$$"
  local report="$output_dir/report.txt"
  local compose_text
  compose_text="$(cat <<'EOF'
services:
  server:
    image: gitea/gitea:1.21.11
    user: "1000:1000"
    ports:
      - "127.0.0.1:3000:3000"
      - "127.0.0.1:2222:22"
    environment:
      - GITEA__security__SECRET_KEY=secret123
      - GITEA__security__INTERNAL_TOKEN=token456
EOF
)"
  local remote_compose
  remote_compose="$(prepare_temp_compose_from_text "$scenario" "$compose_text")"
  local remote_env="$LAB_TMP_ROOT/$scenario/.env"

  rm -rf "$output_dir"
  mkdir -p "$output_dir"
  : > "$report"

  capture_json_scan "$remote_compose" "$output_dir/before.json"
  start_tmux_session "$session" 120 40 "$remote_compose" "$LAB_TMP_ROOT/home-$scenario"
  trap 'kill_tmux_session "$session"' RETURN

  wait_for_text "$session" "Linux Self-Hosting Security Dashboard"
  send_keys "$session" 2
  wait_for_text "$session" "Findings"
  send_keys "$session" f
  wait_for_text "$session" "Choose a review path"
  capture_pane "$session" "$output_dir" "01-choice-modal"
  send_keys "$session" Enter
  wait_for_any_text "$session" 30 "Fix Review" "Findings" "Linux Self-Hosting Security Dashboard"
  capture_pane "$session" "$output_dir" "02-review-after-choice"
  if grep -Fq "Fix Review" "$output_dir/02-review-after-choice.txt"; then
    send_keys "$session" Enter
    wait_for_any_text "$session" 30 "Findings" "Linux Self-Hosting Security Dashboard"
  fi
  capture_pane "$session" "$output_dir" "03-findings-after-apply"
  send_keys "$session" q
  send_keys "$session" q
  wait_for_hostveil_stop "$remote_compose"
  kill_tmux_session "$session"
  trap - RETURN

  export_lab_file "$remote_compose" "$output_dir/docker-compose.yml"
  export_lab_backup "$remote_compose" "$output_dir/docker-compose.yml.bak"
  export_lab_file "$remote_env" "$output_dir/.env"
  capture_json_scan "$remote_compose" "$output_dir/after.json"

  assert_contains "$output_dir/01-choice-modal.txt" "Choose a review path"
  assert_contains "$output_dir/02-review-after-choice.txt" "Fix Review"
  assert_contains "$output_dir/.env" "GITEA__security__SECRET_KEY=secret123"
  assert_contains "$output_dir/docker-compose.yml" '${GITEA__security__SECRET_KEY}'
  assert_file_exists "$output_dir/docker-compose.yml.bak"
  assert_not_contains "$output_dir/after.json" '"id": "service.gitea.inline_security_secrets"'

  append_report "$report" "fix-review-choice: pass"
}

run_fix_review_input_scenario() {
  local scenario="fix-review-input"
  local output_dir="$OUTPUT_ROOT/$scenario"
  local session="hostveil-ux-$scenario-$$"
  local report="$output_dir/report.txt"
  local compose_text
  compose_text="$(cat <<'EOF'
services:
  postgres:
    image: postgres:16.3
    user: "1000:1000"
EOF
)"
  local remote_compose
  remote_compose="$(prepare_temp_compose_from_text "$scenario" "$compose_text")"
  local remote_env="$LAB_TMP_ROOT/$scenario/.env"

  rm -rf "$output_dir"
  mkdir -p "$output_dir"
  : > "$report"

  capture_json_scan "$remote_compose" "$output_dir/before.json"
  start_tmux_session "$session" 120 40 "$remote_compose" "$LAB_TMP_ROOT/home-$scenario"
  trap 'kill_tmux_session "$session"' RETURN

  wait_for_text "$session" "Linux Self-Hosting Security Dashboard"
  send_keys "$session" 2
  wait_for_text "$session" "Findings"
  send_keys "$session" f
  wait_for_text "$session" "Provide a secret value"
  capture_pane "$session" "$output_dir" "01-secret-modal"
  send_keys "$session" Enter
  wait_for_any_text "$session" 30 "Fix Review" "Findings" "Linux Self-Hosting Security Dashboard"
  capture_pane "$session" "$output_dir" "02-review-after-input"
  if grep -Fq "Fix Review" "$output_dir/02-review-after-input.txt"; then
    send_keys "$session" Enter
    wait_for_any_text "$session" 30 "Findings" "Linux Self-Hosting Security Dashboard"
  fi
  send_keys "$session" q
  send_keys "$session" q
  wait_for_hostveil_stop "$remote_compose"
  kill_tmux_session "$session"
  trap - RETURN

  export_lab_file "$remote_compose" "$output_dir/docker-compose.yml"
  export_lab_backup "$remote_compose" "$output_dir/docker-compose.yml.bak"
  export_lab_file "$remote_env" "$output_dir/.env"
  capture_json_scan "$remote_compose" "$output_dir/after.json"

  assert_contains "$output_dir/01-secret-modal.txt" "Provide a secret value"
  assert_contains "$output_dir/01-secret-modal.txt" "Tab toggles masking. Ctrl-R generates a new value."
  assert_contains "$output_dir/02-review-after-input.txt" "Fix Review"
  assert_contains "$output_dir/docker-compose.yml" '${POSTGRES_PASSWORD}'
  assert_contains "$output_dir/.env" "POSTGRES_PASSWORD="
  assert_not_contains "$output_dir/after.json" '"id": "service.postgres.password_missing"'
  if grep -Fq -- "$(cut -d= -f2- "$output_dir/.env")" "$output_dir/02-review-after-input.txt"; then
    printf 'error: secret value leaked into review capture\n' >&2
    exit 1
  fi

  append_report "$report" "fix-review-input: pass"
}

run_fix_review_cancel_scenario() {
  local scenario="fix-review-cancel"
  local output_dir="$OUTPUT_ROOT/$scenario"
  local session="hostveil-ux-$scenario-$$"
  local report="$output_dir/report.txt"
  local compose_text
  compose_text="$(cat <<'EOF'
services:
  postgres:
    image: postgres:16.3
    user: "1000:1000"
EOF
)"
  local remote_compose
  remote_compose="$(prepare_temp_compose_from_text "$scenario" "$compose_text")"
  local remote_env="$LAB_TMP_ROOT/$scenario/.env"

  rm -rf "$output_dir"
  mkdir -p "$output_dir"
  : > "$report"

  export_lab_file "$remote_compose" "$output_dir/docker-compose.before.yml"
  start_tmux_session "$session" 120 40 "$remote_compose" "$LAB_TMP_ROOT/home-$scenario"
  trap 'kill_tmux_session "$session"' RETURN

  wait_for_text "$session" "Linux Self-Hosting Security Dashboard"
  send_keys "$session" 2
  wait_for_text "$session" "Findings"
  send_keys "$session" f
  wait_for_text "$session" "Provide a secret value"
  capture_pane "$session" "$output_dir" "01-secret-modal-before-cancel"
  send_keys "$session" q
  wait_for_text "$session" "Findings"
  capture_pane "$session" "$output_dir" "02-findings-after-cancel"
  send_keys "$session" q
  send_keys "$session" q
  wait_for_hostveil_stop "$remote_compose"
  kill_tmux_session "$session"
  trap - RETURN

  export_lab_file "$remote_compose" "$output_dir/docker-compose.after.yml"
  export_lab_backup "$remote_compose" "$output_dir/docker-compose.yml.bak"
  export_lab_file "$remote_env" "$output_dir/.env"

  assert_contains "$output_dir/01-secret-modal-before-cancel.txt" "Provide a secret value"
  assert_file_missing "$output_dir/docker-compose.yml.bak"
  assert_file_missing "$output_dir/.env"
  diff -u "$output_dir/docker-compose.before.yml" "$output_dir/docker-compose.after.yml" >/dev/null

  append_report "$report" "fix-review-cancel: pass"
}

run_narrow_layout_scenario() {
  local scenario="narrow-layout"
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

  append_report "$report" "narrow-layout: pass"
  append_report "$report" "terminal: 60x20"
}

run_selected_scenarios() {
  local requested=("${SCENARIOS[@]}")
  if [[ ${#requested[@]} -eq 0 || -z "${requested[0]}" ]]; then
    requested=("${DEFAULT_SCENARIOS[@]}")
  fi

  for scenario in "${requested[@]}"; do
    case "$scenario" in
      overview-idle) run_overview_idle_scenario ;;
      navigation-deep|navigation) run_navigation_deep_scenario ;;
      host-triage) run_host_triage_scenario ;;
      settings-persist|settings) run_settings_persist_scenario ;;
      help-search) run_help_search_scenario ;;
      fix-auto-preview|fix) run_fix_auto_preview_scenario ;;
      fix-review-choice) run_fix_review_choice_scenario ;;
      fix-review-input) run_fix_review_input_scenario ;;
      fix-review-cancel) run_fix_review_cancel_scenario ;;
      narrow-layout|narrow) run_narrow_layout_scenario ;;
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
