#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BINARY_PATH="${1:-$ROOT_DIR/target/debug/hostveil}"
INSTALLER_PATH="$ROOT_DIR/scripts/install.sh"
REAL_BASH="$(command -v bash)"

[[ -x "$BINARY_PATH" ]] || {
  printf 'error: binary is not executable: %s\n' "$BINARY_PATH" >&2
  exit 1
}

detect_target() {
  case "$(uname -m)" in
    x86_64|amd64)
      printf '%s\n' "x86_64-unknown-linux-gnu"
      ;;
    aarch64|arm64)
      printf '%s\n' "aarch64-unknown-linux-gnu"
      ;;
    *)
      printf 'error: unsupported architecture: %s\n' "$(uname -m)" >&2
      exit 1
      ;;
  esac
}

EXPECTED_VERSION="$($BINARY_PATH --version)"
TARGET_TRIPLE="$(detect_target)"

assert_file_contains() {
  local path="$1"
  local pattern="$2"

  grep -Fq -- "$pattern" "$path" || {
    printf 'error: %s did not contain expected text: %s\n' "$path" "$pattern" >&2
    exit 1
  }
}

create_release_fixture() {
  local release_dir="$1"
  local tag="$2"
  local checksum_prefix="$3"
  local archive_name="hostveil-${tag}-${TARGET_TRIPLE}.tar.gz"

  mkdir -p "$release_dir/package"
  cp "$BINARY_PATH" "$release_dir/package/hostveil"
  cp "$ROOT_DIR/README.md" "$ROOT_DIR/LICENSE" "$release_dir/package/"
  tar -C "$release_dir/package" -czf "$release_dir/$archive_name" hostveil README.md LICENSE

  local checksum
  checksum="$(sha256sum "$release_dir/$archive_name" | awk '{print $1}')"
  printf '%s  %s%s\n' "$checksum" "$checksum_prefix" "$archive_name" > "$release_dir/SHA256SUMS"
}

create_releases_api_fixture() {
  local api_dir="$1"
  local tag="$2"

  mkdir -p "$api_dir"
  cat > "$api_dir/releases.json" <<EOF
[
  {
    "tag_name": "$tag"
  }
]
EOF
  cat > "$api_dir/latest.json" <<EOF
{
  "tag_name": "$tag"
}
EOF
}

run_install_case() {
  local checksum_prefix="$1"
  local case_dir
  local release_dir
  local install_dir
  local state_home
  local metadata_path
  local manager_path

  case_dir="$(mktemp -d)"
  release_dir="$case_dir/release"
  install_dir="$case_dir/install/bin"
  state_home="$case_dir/state"
  metadata_path="$state_home/hostveil/install.env"
  manager_path="$state_home/hostveil/manage.sh"

  create_release_fixture "$release_dir" "v0.0.0-test" "$checksum_prefix"

  XDG_STATE_HOME="$state_home" \
    HOSTVEIL_DOWNLOAD_BASE_URL="file://$release_dir" \
    HOSTVEIL_INSTALLER_URL="file://$INSTALLER_PATH" \
    bash "$INSTALLER_PATH" --version v0.0.0-test --to "$install_dir"

  [[ -x "$install_dir/hostveil" ]] || {
    printf 'error: wrapper install is missing for checksum prefix %s\n' "$checksum_prefix" >&2
    exit 1
  }
  [[ -x "$install_dir/hostveil-bin" ]] || {
    printf 'error: payload binary is missing for checksum prefix %s\n' "$checksum_prefix" >&2
    exit 1
  }
  [[ -x "$manager_path" ]] || {
    printf 'error: local lifecycle manager was not saved for checksum prefix %s\n' "$checksum_prefix" >&2
    exit 1
  }
  [[ "$($install_dir/hostveil --version)" == "$EXPECTED_VERSION" ]] || {
    printf 'error: installed wrapper returned an unexpected version for checksum prefix %s\n' "$checksum_prefix" >&2
    exit 1
  }

  assert_file_contains "$metadata_path" 'HOSTVEIL_META_INSTALLED_TAG=v0.0.0-test'
  assert_file_contains "$metadata_path" 'HOSTVEIL_META_AUTO_UPGRADE=enabled'

  rm -rf "$case_dir"
}

run_latest_install_case() {
  local case_dir
  local release_dir
  local api_dir
  local install_dir

  case_dir="$(mktemp -d)"
  release_dir="$case_dir/release"
  api_dir="$case_dir/api"
  install_dir="$case_dir/install/bin"

  create_release_fixture "$release_dir" "v0.0.1-test" ""
  create_releases_api_fixture "$api_dir" "v0.0.1-test"

  XDG_STATE_HOME="$case_dir/state" \
    HOSTVEIL_DOWNLOAD_BASE_URL="file://$release_dir" \
    HOSTVEIL_RELEASES_API_URL="file://$api_dir/releases.json" \
    HOSTVEIL_LATEST_STABLE_API_URL="file://$api_dir/latest.json" \
    HOSTVEIL_INSTALLER_URL="file://$INSTALLER_PATH" \
    bash "$INSTALLER_PATH" --channel preview --to "$install_dir"

  [[ "$($install_dir/hostveil --version)" == "$EXPECTED_VERSION" ]] || {
    printf 'error: latest install did not install the expected binary\n' >&2
    exit 1
  }

  rm -rf "$case_dir"
}

run_login_path_detection_case() {
  local case_dir
  local release_dir
  local install_dir
  local fake_bin_dir
  local output_path

  case_dir="$(mktemp -d)"
  release_dir="$case_dir/release"
  install_dir="$case_dir/install/bin"
  fake_bin_dir="$case_dir/fake-bin"
  output_path="$case_dir/install.log"

  create_release_fixture "$release_dir" "v0.0.5-test" ""
  mkdir -p "$fake_bin_dir"
  cat > "$fake_bin_dir/bash" <<EOF
#!$(printf '%s' "$REAL_BASH")
if [[ "\$1" == "-lc" ]]; then
  printf '%s' "\${HOSTVEIL_FAKE_LOGIN_PATH:-}"
  exit 0
fi

exec $(printf '%q' "$REAL_BASH") "\$@"
EOF
  chmod 0755 "$fake_bin_dir/bash"

  PATH="$fake_bin_dir:/usr/bin:/bin" \
    HOSTVEIL_FAKE_LOGIN_PATH="$install_dir:/usr/bin:/bin" \
    XDG_STATE_HOME="$case_dir/state" \
    HOSTVEIL_DOWNLOAD_BASE_URL="file://$release_dir" \
    HOSTVEIL_INSTALLER_URL="file://$INSTALLER_PATH" \
    "$REAL_BASH" "$INSTALLER_PATH" --version v0.0.5-test --to "$install_dir" \
    > "$output_path"

  if grep -Fq -- 'not currently on PATH' "$output_path"; then
    printf 'error: installer warned even though the login PATH already included the install dir\n' >&2
    exit 1
  fi

  rm -rf "$case_dir"
}

run_current_path_detection_case() {
  local case_dir
  local release_dir
  local install_dir
  local output_path

  case_dir="$(mktemp -d)"
  release_dir="$case_dir/release"
  install_dir="$case_dir/install/bin"
  output_path="$case_dir/install.log"

  create_release_fixture "$release_dir" "v0.0.6-test" ""

  PATH="$install_dir:/usr/bin:/bin" \
    XDG_STATE_HOME="$case_dir/state" \
    HOSTVEIL_DOWNLOAD_BASE_URL="file://$release_dir" \
    HOSTVEIL_INSTALLER_URL="file://$INSTALLER_PATH" \
    bash "$INSTALLER_PATH" --version v0.0.6-test --to "$install_dir" \
    > "$output_path"

  if grep -Fq -- 'not currently on PATH' "$output_path"; then
    printf 'error: installer warned even though the current shell PATH already included the install dir\n' >&2
    exit 1
  fi

  rm -rf "$case_dir"
}

run_upgrade_auto_uninstall_case() {
  local case_dir
  local release_one
  local release_two
  local release_three
  local release_four
  local api_three
  local api_four
  local install_dir
  local state_home
  local metadata_path
  local manager_path

  case_dir="$(mktemp -d)"
  release_one="$case_dir/release-one"
  release_two="$case_dir/release-two"
  release_three="$case_dir/release-three"
  release_four="$case_dir/release-four"
  api_three="$case_dir/api-three"
  api_four="$case_dir/api-four"
  install_dir="$case_dir/install/bin"
  state_home="$case_dir/state"
  metadata_path="$state_home/hostveil/install.env"
  manager_path="$state_home/hostveil/manage.sh"

  create_release_fixture "$release_one" "v0.0.1-test" ""
  create_release_fixture "$release_two" "v0.0.2-test" ""
  create_release_fixture "$release_three" "v0.0.3-test" ""
  create_release_fixture "$release_four" "v0.0.4-test" ""
  create_releases_api_fixture "$api_three" "v0.0.3-test"
  create_releases_api_fixture "$api_four" "v0.0.4-test"

  XDG_STATE_HOME="$state_home" \
    HOSTVEIL_DOWNLOAD_BASE_URL="file://$release_one" \
    HOSTVEIL_INSTALLER_URL="file://$INSTALLER_PATH" \
    bash "$INSTALLER_PATH" --version v0.0.1-test --to "$install_dir"

  assert_file_contains "$metadata_path" 'HOSTVEIL_META_INSTALLED_TAG=v0.0.1-test'
  assert_file_contains "$metadata_path" 'HOSTVEIL_META_AUTO_UPGRADE=enabled'
  rm -f "$metadata_path"

  PATH="$install_dir:$PATH" \
    XDG_STATE_HOME="$state_home" \
    HOSTVEIL_DOWNLOAD_BASE_URL="file://$release_two" \
    HOSTVEIL_INSTALLER_URL="file://$INSTALLER_PATH" \
    hostveil upgrade --version v0.0.2-test

  [[ -x "$manager_path" ]] || {
    printf 'error: lifecycle manager was not restored during upgrade fallback\n' >&2
    exit 1
  }
  assert_file_contains "$metadata_path" 'HOSTVEIL_META_INSTALLED_TAG=v0.0.2-test'
  assert_file_contains "$metadata_path" 'HOSTVEIL_META_AUTO_UPGRADE=enabled'

  XDG_STATE_HOME="$state_home" \
    HOSTVEIL_DOWNLOAD_BASE_URL="file://$release_three" \
    HOSTVEIL_RELEASES_API_URL="file://$api_three/releases.json" \
    HOSTVEIL_LATEST_STABLE_API_URL="file://$api_three/latest.json" \
    HOSTVEIL_INSTALLER_URL="file://$INSTALLER_PATH" \
    "$install_dir/hostveil" --version >/dev/null

  assert_file_contains "$metadata_path" 'HOSTVEIL_META_INSTALLED_TAG=v0.0.3-test'

  XDG_STATE_HOME="$state_home" \
    PATH="$install_dir:$PATH" \
    hostveil auto-upgrade disable
  assert_file_contains "$metadata_path" 'HOSTVEIL_META_AUTO_UPGRADE=disabled'

  XDG_STATE_HOME="$state_home" \
    HOSTVEIL_DOWNLOAD_BASE_URL="file://$release_four" \
    HOSTVEIL_RELEASES_API_URL="file://$api_four/releases.json" \
    HOSTVEIL_LATEST_STABLE_API_URL="file://$api_four/latest.json" \
    HOSTVEIL_INSTALLER_URL="file://$INSTALLER_PATH" \
    "$install_dir/hostveil" --version >/dev/null

  assert_file_contains "$metadata_path" 'HOSTVEIL_META_INSTALLED_TAG=v0.0.3-test'

  XDG_STATE_HOME="$state_home" \
    PATH="$install_dir:$PATH" \
    hostveil auto-upgrade enable
  assert_file_contains "$metadata_path" 'HOSTVEIL_META_AUTO_UPGRADE=enabled'

  XDG_STATE_HOME="$state_home" \
    HOSTVEIL_DOWNLOAD_BASE_URL="file://$release_four" \
    HOSTVEIL_RELEASES_API_URL="file://$api_four/releases.json" \
    HOSTVEIL_LATEST_STABLE_API_URL="file://$api_four/latest.json" \
    HOSTVEIL_INSTALLER_URL="file://$INSTALLER_PATH" \
    "$install_dir/hostveil" --version >/dev/null

  assert_file_contains "$metadata_path" 'HOSTVEIL_META_INSTALLED_TAG=v0.0.4-test'

  XDG_STATE_HOME="$state_home" \
    PATH="$install_dir:$PATH" \
    hostveil uninstall

  [[ ! -e "$install_dir/hostveil" ]] || {
    printf 'error: wrapper still exists after uninstall\n' >&2
    exit 1
  }
  [[ ! -e "$install_dir/hostveil-bin" ]] || {
    printf 'error: payload binary still exists after uninstall\n' >&2
    exit 1
  }
  [[ ! -e "$manager_path" ]] || {
    printf 'error: lifecycle manager still exists after uninstall\n' >&2
    exit 1
  }
  [[ ! -e "$metadata_path" ]] || {
    printf 'error: install metadata still exists after uninstall\n' >&2
    exit 1
  }

  rm -rf "$case_dir"
}

run_post_install_setup_handoff_case() {
  local case_dir
  local release_dir
  local install_dir
  local setup_log
  local archive_name
  local checksum

  case_dir="$(mktemp -d)"
  release_dir="$case_dir/release"
  install_dir="$case_dir/install/bin"
  setup_log="$case_dir/setup.log"
  archive_name="hostveil-v0.0.9-test-${TARGET_TRIPLE}.tar.gz"

  mkdir -p "$release_dir/package"
  cat > "$release_dir/package/hostveil" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

case "${1:-}" in
  --version)
    printf 'hostveil 0.0.9-test\n'
    ;;
  setup)
    printf '%s\n' "$*" > "${HOSTVEIL_SETUP_LOG:?}"
    ;;
  *)
    printf 'fake hostveil received: %s\n' "$*"
    ;;
esac
EOF
  chmod 0755 "$release_dir/package/hostveil"
  cp "$ROOT_DIR/README.md" "$ROOT_DIR/LICENSE" "$release_dir/package/"
  tar -C "$release_dir/package" -czf "$release_dir/$archive_name" hostveil README.md LICENSE
  checksum="$(sha256sum "$release_dir/$archive_name" | awk '{print $1}')"
  printf '%s  %s\n' "$checksum" "$archive_name" > "$release_dir/SHA256SUMS"

  HOSTVEIL_SETUP_LOG="$setup_log" \
    XDG_STATE_HOME="$case_dir/state" \
    HOSTVEIL_DOWNLOAD_BASE_URL="file://$release_dir" \
    HOSTVEIL_INSTALLER_URL="file://$INSTALLER_PATH" \
    bash "$INSTALLER_PATH" --version v0.0.9-test --to "$install_dir" --with-tools lynis,trivy

  assert_file_contains "$setup_log" 'setup --yes --tools lynis,trivy'

  rm -rf "$case_dir"
}

run_install_case ""
run_install_case "dist/"
run_latest_install_case
run_login_path_detection_case
run_current_path_detection_case
run_upgrade_auto_uninstall_case
run_post_install_setup_handoff_case

printf 'Installer tests passed for %s\n' "$BINARY_PATH"
