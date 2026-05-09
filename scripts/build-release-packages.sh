#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CRATE_DIR="$ROOT_DIR/src"
TARGET_TRIPLE="${1:-}"
OUTPUT_DIR="${2:-$ROOT_DIR/target/package-assets}"

require_arg() {
  local name="$1"
  local value="${2:-}"
  [[ -n "$value" ]] || {
    printf 'error: missing %s\n' "$name" >&2
    exit 1
  }
}

detect_default_target() {
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

package_arches() {
  case "$1" in
    x86_64-unknown-linux-gnu)
      printf 'amd64 x86_64\n'
      ;;
    aarch64-unknown-linux-gnu)
      printf 'arm64 aarch64\n'
      ;;
    *)
      printf 'error: unsupported package target: %s\n' "$1" >&2
      exit 1
      ;;
  esac
}

require_tool() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'error: required tool is not installed: %s\n' "$1" >&2
    exit 1
  }
}

resolve_output_dir() {
  local output_dir="$1"

  case "$output_dir" in
    /*)
      printf '%s\n' "$output_dir"
      ;;
    *)
      printf '%s\n' "$ROOT_DIR/$output_dir"
      ;;
  esac
}

version_from_cargo() {
  sed -n 's/^version = "\([^"]*\)"$/\1/p' "$CRATE_DIR/Cargo.toml" | head -n 1
}

stage_built_binary() {
  local target_triple="$1"
  local root_binary="$ROOT_DIR/target/$target_triple/release/hostveil"
  local crate_binary="$CRATE_DIR/target/$target_triple/release/hostveil"

  [[ -x "$root_binary" ]] || {
    printf 'error: release binary is missing for %s: %s\n' "$target_triple" "$root_binary" >&2
    exit 1
  }

  mkdir -p "$(dirname "$crate_binary")"
  cp "$root_binary" "$crate_binary"
}

TARGET_TRIPLE="${TARGET_TRIPLE:-$(detect_default_target)}"
require_arg "target triple" "$TARGET_TRIPLE"
require_tool cargo
OUTPUT_DIR="$(resolve_output_dir "$OUTPUT_DIR")"

VERSION="$(version_from_cargo)"
require_arg "Cargo version" "$VERSION"
read -r DEB_ARCH RPM_ARCH < <(package_arches "$TARGET_TRIPLE")

mkdir -p "$OUTPUT_DIR"
stage_built_binary "$TARGET_TRIPLE"

pushd "$CRATE_DIR" >/dev/null
cargo deb --no-build --target "$TARGET_TRIPLE" --output "$OUTPUT_DIR/hostveil_${VERSION}_${DEB_ARCH}.deb"
cargo generate-rpm --target "$TARGET_TRIPLE" -o "$OUTPUT_DIR/hostveil-${VERSION}-1.${RPM_ARCH}.rpm"
popd >/dev/null

printf 'Built package assets in %s\n' "$OUTPUT_DIR"
