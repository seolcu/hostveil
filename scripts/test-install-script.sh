#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BINARY_PATH="${1:-$ROOT_DIR/target/debug/hostveil}"
INSTALLER_PATH="$ROOT_DIR/scripts/install.sh"

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

run_case() {
  local checksum_prefix="$1"
  local case_dir
  local release_dir
  local install_dir
  local target
  local archive_name
  local expected_version

  case_dir="$(mktemp -d)"
  release_dir="$case_dir/release"
  install_dir="$case_dir/install/bin"
  target="$(detect_target)"
  archive_name="hostveil-v0.0.0-test-${target}.tar.gz"
  expected_version="$($BINARY_PATH --version)"

  mkdir -p "$release_dir/package" "$install_dir"
  cp "$BINARY_PATH" "$release_dir/package/hostveil"
  cp "$ROOT_DIR/README.md" "$ROOT_DIR/LICENSE" "$release_dir/package/"
  tar -C "$release_dir/package" -czf "$release_dir/$archive_name" hostveil README.md LICENSE

  local checksum
  checksum="$(sha256sum "$release_dir/$archive_name" | awk '{print $1}')"
  printf '%s  %s%s\n' "$checksum" "$checksum_prefix" "$archive_name" > "$release_dir/SHA256SUMS"

  HOSTVEIL_DOWNLOAD_BASE_URL="file://$release_dir" \
    bash "$INSTALLER_PATH" --version v0.0.0-test --to "$install_dir"

  [[ -x "$install_dir/hostveil" ]] || {
    printf 'error: installed binary is missing for checksum prefix %s\n' "$checksum_prefix" >&2
    exit 1
  }

  [[ "$($install_dir/hostveil --version)" == "$expected_version" ]] || {
    printf 'error: installed version mismatch for checksum prefix %s\n' "$checksum_prefix" >&2
    exit 1
  }

  rm -rf "$case_dir"
}

run_case ""
run_case "dist/"

printf 'Installer tests passed for %s\n' "$BINARY_PATH"
