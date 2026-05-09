#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_ARCH="${1:-}"
OUTPUT_DIR="${2:-$ROOT_DIR/target/package-assets}"
IMAGE_TAG_BASE="${HOSTVEIL_RPM_BUILDER_IMAGE:-hostveil-rpm-builder}"

require_arg() {
  local name="$1"
  local value="${2:-}"
  [[ -n "$value" ]] || {
    printf 'error: missing %s\n' "$name" >&2
    exit 1
  }
}

require_tool() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'error: required tool is not installed: %s\n' "$1" >&2
    exit 1
  }
}

detect_default_arch() {
  case "$(uname -m)" in
    x86_64|amd64)
      printf '%s\n' "x86_64"
      ;;
    aarch64|arm64)
      printf '%s\n' "aarch64"
      ;;
    *)
      printf 'error: unsupported architecture: %s\n' "$(uname -m)" >&2
      exit 1
      ;;
  esac
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

rpm_target_config() {
  case "$1" in
    x86_64|amd64)
      printf '%s %s %s\n' "x86_64-unknown-linux-gnu" "linux/amd64" "x86_64"
      ;;
    aarch64|arm64)
      printf '%s %s %s\n' "aarch64-unknown-linux-gnu" "linux/arm64" "aarch64"
      ;;
    *)
      printf 'error: unsupported RPM release architecture: %s\n' "$1" >&2
      exit 1
      ;;
  esac
}

relative_to_root() {
  local absolute="$1"

  case "$absolute" in
    "$ROOT_DIR")
      printf '.\n'
      ;;
    "$ROOT_DIR"/*)
      printf '%s\n' "${absolute#"$ROOT_DIR"/}"
      ;;
    *)
      printf 'error: output directory must be inside repository root: %s\n' "$absolute" >&2
      exit 1
      ;;
  esac
}

TARGET_ARCH="${TARGET_ARCH:-$(detect_default_arch)}"
HOST_ARCH="$(detect_default_arch)"
OUTPUT_DIR="$(resolve_output_dir "$OUTPUT_DIR")"
require_arg "target architecture" "$TARGET_ARCH"
require_tool docker

read -r TARGET_TRIPLE DOCKER_PLATFORM RPM_ARCH < <(rpm_target_config "$TARGET_ARCH")
OUTPUT_DIR_REL="$(relative_to_root "$OUTPUT_DIR")"
IMAGE_TAG="${IMAGE_TAG_BASE}:${RPM_ARCH}"
RPM_TARGET_DIR_REL="target/rocky-rpm/${RPM_ARCH}"

mkdir -p "$OUTPUT_DIR"

if [[ "$HOST_ARCH" == "$TARGET_ARCH" ]]; then
  docker build \
    -t "$IMAGE_TAG" \
    -f "$ROOT_DIR/docker/release/rpm-builder.Dockerfile" \
    "$ROOT_DIR"

  docker run --rm \
    --user "$(id -u):$(id -g)" \
    -e HOME=/tmp \
    -e CARGO_TARGET_DIR="/workspace/${RPM_TARGET_DIR_REL}" \
    -v "$ROOT_DIR:/workspace" \
    -w /workspace \
    "$IMAGE_TAG" \
    bash -lc "rm -rf \"/workspace/${RPM_TARGET_DIR_REL}\" && cargo build --release --workspace --target \"$TARGET_TRIPLE\" && ./scripts/build-release-packages.sh \"$TARGET_TRIPLE\" \"$OUTPUT_DIR_REL\" rpm"
else
  docker buildx version >/dev/null 2>&1 || {
    printf 'error: docker buildx is required for cross-architecture RPM builds (%s host -> %s target)\n' "$HOST_ARCH" "$TARGET_ARCH" >&2
    exit 1
  }

  docker buildx build \
    --load \
    --platform "$DOCKER_PLATFORM" \
    -t "$IMAGE_TAG" \
    -f "$ROOT_DIR/docker/release/rpm-builder.Dockerfile" \
    "$ROOT_DIR"

  docker run --rm \
    --platform "$DOCKER_PLATFORM" \
    --user "$(id -u):$(id -g)" \
    -e HOME=/tmp \
    -e CARGO_TARGET_DIR="/workspace/${RPM_TARGET_DIR_REL}" \
    -v "$ROOT_DIR:/workspace" \
    -w /workspace \
    "$IMAGE_TAG" \
    bash -lc "rm -rf \"/workspace/${RPM_TARGET_DIR_REL}\" && cargo build --release --workspace --target \"$TARGET_TRIPLE\" && ./scripts/build-release-packages.sh \"$TARGET_TRIPLE\" \"$OUTPUT_DIR_REL\" rpm"
fi

printf 'Built Rocky 9-compatible RPM assets in %s\n' "$OUTPUT_DIR"
